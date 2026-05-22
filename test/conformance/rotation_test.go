//go:build conformance

package conformance

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// masterKeyV1 and masterKeyV2 are deterministic 32-byte AES-256 test keys.
// They are not secret — they exist only inside ephemeral test containers.
var (
	masterKeyV1 = bytes.Repeat([]byte{0x01}, 32)
	masterKeyV2 = bytes.Repeat([]byte{0x02}, 32)
)

// makeKMv1 returns an InMemoryKeyManager with only version 1 active.
func makeKMv1(t *testing.T) crypto.KeyManager {
	t.Helper()
	km, err := crypto.NewInMemoryKeyManager(masterKeyV1)
	if err != nil {
		t.Fatalf("makeKMv1: %v", err)
	}
	return km
}

// makeKMv2 returns an InMemoryKeyManager with version 1 retained (for
// unwrap) and version 2 as the active (wrap) version.
func makeKMv2(t *testing.T) crypto.KeyManager {
	t.Helper()
	km, err := crypto.NewInMemoryKeyManager(masterKeyV1,
		crypto.WithMemoryVersions([]struct {
			Version int
			Key     []byte
		}{
			{Version: 1, Key: masterKeyV1},
			{Version: 2, Key: masterKeyV2},
		}),
	)
	if err != nil {
		t.Fatalf("makeKMv2: %v", err)
	}
	return km
}

// testRotationDualRead verifies the critical correctness property of key
// rotation: objects encrypted with the old key version remain readable after
// the gateway is reconfigured with a new active key version.
//
// Scenario:
//  1. Gateway-A uses InMemoryKeyManager v1 (only version 1 active).
//  2. Upload an object through Gateway-A — the DEK is wrapped with key v1,
//     and x-amz-meta-encryption-key-version=1 is stored in object metadata.
//  3. Gateway-B uses InMemoryKeyManager v2 (version 2 active, version 1
//     retained for unwrap). This simulates the post-rotation state.
//  4. Read the object through Gateway-B — UnwrapKey must fall back to key
//     v1, decrypt the object, and return the original plaintext.
func testRotationDualRead(t *testing.T, inst provider.Instance) {
	t.Helper()

	// Step 1 + 2: seed with key version 1.
	gwOld := harness.StartGateway(t, inst,
		harness.WithKeyManager(makeKMv1(t)),
	)
	plaintext := bytes.Repeat([]byte("rotate-me"), 512)
	key := uniqueKey(t)
	put(t, gwOld, inst.Bucket, key, plaintext)

	// Step 3 + 4: read through a gateway configured with the rotated key set.
	// Gateway-B has v2 as active; v1 is kept so old objects can be unwrapped.
	gwNew := harness.StartGateway(t, inst,
		harness.WithKeyManager(makeKMv2(t)),
	)
	got := get(t, gwNew, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("rotation dual-read: content mismatch after key rotation "+
			"(got %d bytes, want %d bytes)", len(got), len(plaintext))
	}
}

// testRotationOldKeyUnreadableAfterRemoval verifies that if an operator
// intentionally removes the old key version from the key manager, objects
// encrypted with that version become unreadable (correct fail-closed
// behaviour). This is the complement to the dual-read window test.
func testRotationOldKeyUnreadableAfterRemoval(t *testing.T, inst provider.Instance) {
	t.Helper()

	// Encrypt with key v1.
	gwOld := harness.StartGateway(t, inst, harness.WithKeyManager(makeKMv1(t)))
	key := uniqueKey(t)
	put(t, gwOld, inst.Bucket, key, []byte("secret data"))

	// New gateway has ONLY key v2 — key v1 material is gone.
	kmV2Only, err := crypto.NewInMemoryKeyManager(masterKeyV2)
	if err != nil {
		t.Fatalf("NewInMemoryKeyManager v2-only: %v", err)
	}
	gwV2Only := harness.StartGateway(t, inst, harness.WithKeyManager(kmV2Only))

	resp, err := gwV2Only.HTTPClient().Get(objectURL(gwV2Only, inst.Bucket, key))
	if err != nil {
		t.Fatalf("GET after key removal: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// The gateway must refuse to decrypt (return an error status, not 200).
	if resp.StatusCode == http.StatusOK {
		t.Errorf("expected decryption failure when old key v1 is removed, got 200 OK")
	}
}

// testRotationMetric verifies that the kms_rotated_reads_total Prometheus
// counter is incremented when the gateway decrypts an object that was
// encrypted with an older key version.
func testRotationMetric(t *testing.T, inst provider.Instance) {
	t.Helper()

	// Encrypt with v1.
	gwOld := harness.StartGateway(t, inst, harness.WithKeyManager(makeKMv1(t)))
	key := uniqueKey(t)
	put(t, gwOld, inst.Bucket, key, []byte("metric-check"))

	// Read with v2-active gateway; its isolated Prometheus registry is
	// accessible via gw.Metrics.
	gwNew := harness.StartGateway(t, inst, harness.WithKeyManager(makeKMv2(t)))
	_ = get(t, gwNew, inst.Bucket, key)

	// Scrape /metrics and look for kms_rotated_reads_total > 0.
	metricsResp, err := gwNew.HTTPClient().Get(gwNew.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer metricsResp.Body.Close()
	body, _ := io.ReadAll(metricsResp.Body)
	if !strings.Contains(string(body), "kms_rotated_reads_total") {
		t.Errorf("kms_rotated_reads_total not present in /metrics output")
	}

	// Also assert via the in-process registry (no scraping ambiguity).
	rotatedReads := testutil.CollectAndCount(gwNew.Metrics, "kms_rotated_reads_total")
	if rotatedReads == 0 {
		t.Errorf("kms_rotated_reads_total counter has no samples after reading a v1 object through a v2 gateway")
	}

	// Verify exact label values and counter value using GatherAndCompare.
	// Labels: key_version=<version used>, active_version=<current active version>.
	expected := `
# HELP kms_rotated_reads_total Total number of decryption operations using rotated (non-active) key versions
# TYPE kms_rotated_reads_total counter
kms_rotated_reads_total{active_version="2",key_version="1"} 1
`
	if err := testutil.GatherAndCompare(gwNew.Metrics, strings.NewReader(expected),
		"kms_rotated_reads_total"); err != nil {
		t.Errorf("kms_rotated_reads_total mismatch: %v", err)
	}
}
