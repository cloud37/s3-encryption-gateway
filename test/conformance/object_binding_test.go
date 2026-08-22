//go:build conformance

package conformance

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func testSEC42_KeyManagerBackendRelocationFailsClosed(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(makeAESKEKManager(t)), harness.WithChunking(false))
	backend := newS3Client(t, inst)
	source, destination := uniqueKey(t), uniqueKey(t)
	plain := []byte("SEC42 KeyManager relocation")
	put(t, gw, inst.Bucket, source, plain)
	if got := get(t, gw, inst.Bucket, source); !bytes.Equal(got, plain) {
		t.Fatal("KeyManager source round-trip failed")
	}
	copyBackendObject(t, backend, inst.Bucket, source, destination)
	requireGatewayFailureWithoutPlaintext(t, gw, inst.Bucket, destination, plain)
}

func testSEC42_BufferedObject_BackendKeySubstitutionFailsClosed(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithChunking(false))
	backend := newS3Client(t, inst)
	source, destination := uniqueKey(t), uniqueKey(t)
	plain := []byte("SEC42 buffered substitution")
	put(t, gw, inst.Bucket, source, plain)
	copyBackendObject(t, backend, inst.Bucket, source, destination)
	requireGatewayFailureWithoutPlaintext(t, gw, inst.Bucket, destination, plain)
}

func testSEC42_ChunkedV2_BackendKeySubstitutionFailsClosed(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithChunking(true))
	backend := newS3Client(t, inst)
	source, destination := uniqueKey(t), uniqueKey(t)
	plain := bytes.Repeat([]byte("SEC42 chunked substitution"), 4096)
	put(t, gw, inst.Bucket, source, plain)
	copyBackendObject(t, backend, inst.Bucket, source, destination)
	requireGatewayFailureWithoutPlaintext(t, gw, inst.Bucket, destination, plain)
	requireGatewayRangeFailureWithoutPlaintext(t, gw, inst.Bucket, destination, "bytes=0-99", plain[:100])
}

func testSEC42_CopyObject_RebindsDestination(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	backend := newS3Client(t, inst)
	source, destination := uniqueKey(t), uniqueKey(t)
	plain := []byte("SEC42 gateway copy destination")
	put(t, gw, inst.Bucket, source, plain)
	req, _ := http.NewRequest(http.MethodPut, objectURL(gw, inst.Bucket, destination), nil)
	req.Header.Set("x-amz-copy-source", fmt.Sprintf("/%s/%s", inst.Bucket, source))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CopyObject: status=%d", resp.StatusCode)
	}
	if got := get(t, gw, inst.Bucket, destination); !bytes.Equal(got, plain) {
		t.Fatal("destination plaintext mismatch")
	}
	// The gateway-produced destination is bound to its own key, not reusable at
	// a backend-relocated key.
	relocated := uniqueKey(t)
	copyBackendObject(t, backend, inst.Bucket, destination, relocated)
	requireGatewayFailureWithoutPlaintext(t, gw, inst.Bucket, relocated, plain)
}

func testSEC42_MigrationRewrite_LegacyObjectBindsDestination(t *testing.T, inst provider.Instance) {
	t.Helper()
	backend := newS3Client(t, inst)
	legacyKey, destination := uniqueKey(t), uniqueKey(t)
	// This frozen v1 fixture is deliberately unbound. Reading it and writing it
	// through the current gateway is the supported migration path.
	putSEC37V1Fixture(t, backend, inst.Bucket, legacyKey)
	gw := harness.StartGateway(t, inst, harness.WithChunking(false), harness.WithEncryptionPassword("test-encryption-password-123456"))
	plain := get(t, gw, inst.Bucket, legacyKey)
	put(t, gw, inst.Bucket, destination, plain)
	if got := get(t, gw, inst.Bucket, destination); !bytes.Equal(got, plain) {
		t.Fatal("rewritten destination mismatch")
	}
	relocated := uniqueKey(t)
	copyBackendObject(t, backend, inst.Bucket, destination, relocated)
	requireGatewayFailureWithoutPlaintext(t, gw, inst.Bucket, relocated, plain)
}
