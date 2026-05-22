//go:build conformance

package conformance

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testObjectLockRetention verifies that the gateway forwards
// x-amz-object-lock-mode and x-amz-object-lock-retain-until-date headers on
// PUT and that HEAD surfaces them.
func testObjectLockRetention(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	data := []byte("locked-retention")
	key := uniqueKey(t)

	retainUntil := time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)
	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, key), bytes.NewReader(data))
	req.Header.Set("x-amz-object-lock-mode", "GOVERNANCE")
	req.Header.Set("x-amz-object-lock-retain-until-date", retainUntil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("PUT with retention: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT with retention: status %d: %s", resp.StatusCode, string(body))
	}

	// The object must still decrypt correctly.
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("locked object round-trip mismatch")
	}

	// HEAD must surface the lock headers.
	req2, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
	resp2, err := gw.HTTPClient().Do(req2)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("HEAD after retention PUT: status %d", resp2.StatusCode)
	}
	if mode := resp2.Header.Get("x-amz-object-lock-mode"); !strings.EqualFold(mode, "GOVERNANCE") {
		t.Errorf("HEAD x-amz-object-lock-mode = %q, want GOVERNANCE", mode)
	}
}

// testObjectLockLegalHold verifies that x-amz-object-lock-legal-hold is
// forwarded and surfaced on HEAD.
func testObjectLockLegalHold(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	data := []byte("legal-hold-data")
	key := uniqueKey(t)

	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, key), bytes.NewReader(data))
	req.Header.Set("x-amz-object-lock-legal-hold", "ON")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("PUT with legal-hold: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT with legal-hold: status %d: %s", resp.StatusCode, string(body))
	}

	req2, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
	resp2, err := gw.HTTPClient().Do(req2)
	if err != nil {
		t.Fatalf("HEAD: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if hold := resp2.Header.Get("x-amz-object-lock-legal-hold"); !strings.EqualFold(hold, "ON") {
		t.Errorf("HEAD x-amz-object-lock-legal-hold = %q, want ON", hold)
	}
}

// testObjectLockBypassRefused verifies that the gateway refuses
// x-amz-bypass-governance-retention with 403 in every applicable operation.
func testObjectLockBypassRefused(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, []byte("bypass-test"))

	// DELETE with bypass header must be refused.
	req, _ := http.NewRequest("DELETE", objectURL(gw, inst.Bucket, key), nil)
	req.Header.Set("x-amz-bypass-governance-retention", "true")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("DELETE with bypass: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE with bypass-governance-retention: got status %d, want 403; body: %s",
			resp.StatusCode, string(body))
	}

	// PUT retention with bypass header.
	retainUntil := time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)
	putRetentionURL := fmt.Sprintf("%s?retention", objectURL(gw, inst.Bucket, key))
	retentionXML := fmt.Sprintf(`<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`,
		retainUntil)
	req2, _ := http.NewRequest("PUT", putRetentionURL, strings.NewReader(retentionXML))
	req2.Header.Set("Content-Type", "application/xml")
	req2.Header.Set("x-amz-bypass-governance-retention", "true")
	resp2, err := gw.HTTPClient().Do(req2)
	if err != nil {
		t.Fatalf("PUT retention with bypass: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("PUT retention with bypass-governance-retention: got status %d, want 403",
			resp2.StatusCode)
	}
}
