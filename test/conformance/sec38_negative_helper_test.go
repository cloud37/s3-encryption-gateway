//go:build conformance

package conformance

import (
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// TestSEC38_NonfatalMPUNegativeHelpers proves negative requests return their
// complete response tuple without terminating the conformance test.
func testSEC38_NonfatalMPUNegativeHelpers(t *testing.T, inst provider.Instance) {
	gw := harness.StartGateway(t, inst)
	key := uniqueKey(t)
	id := initiateMultipartUpload(t, gw, inst.Bucket, key)
	// Part numbers are one-based. This must fail validation before a backend
	// UploadPart is attempted, while still returning the complete S3 error tuple.
	status, body, etag := uploadPartNegative(t, gw, inst.Bucket, key, id, 0, []byte("negative"))
	if status < 400 || body == "" || etag != "" {
		t.Fatalf("negative upload tuple: status=%d body=%q etag=%q", status, body, etag)
	}
	status, body, etag = completeMultipartUploadNegative(t, gw, inst.Bucket, key, id, nil)
	if status < 400 || body == "" || etag != "" {
		t.Fatalf("negative complete tuple: status=%d body=%q etag=%q", status, body, etag)
	}
}
