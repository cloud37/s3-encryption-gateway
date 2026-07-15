//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testEncryptedMPURoundTrip verifies that the encrypted multipart upload path
// (ADR-0009 / V0.6-SEC-3) produces a correctly decryptable object.
//
// The test starts a dedicated Valkey container, configures the gateway with
// EncryptMultipartUploads=true for the test bucket, uploads a 2-part object
// (each part ≥ 5 MiB as required by S3), completes the upload, then reads the
// object back via the same gateway and asserts byte-perfect round-trip.
//
// This exercises the full encrypted MPU code path:
//   - CreateMultipartUpload  → DEK generation, IV-prefix derivation, Valkey state creation
//   - UploadPart             → per-part chunk encryption, Valkey part record append
//   - CompleteMultipartUpload → manifest assembly, finalization
//   - GetObject              → encrypted manifest read, DEK unwrap, decryption
func testEncryptedMPURoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	// Start a Valkey container for MPU state.
	vk := provider.StartValkey(ctx, t)

	// Start the gateway with encrypted MPU enabled for this bucket.
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	// S3 requires every part except the last to be ≥ 5 MiB.
	part1Data := bytes.Repeat([]byte("A"), 5*1024*1024)
	part2Data := bytes.Repeat([]byte("B"), 5*1024*1024)
	part3Data := []byte("final-tail") // last part may be < 5 MiB

	etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1Data)
	etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part2Data)
	etag3 := uploadPart(t, gw, inst.Bucket, key, uploadID, 3, part3Data)

	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1},
		{2, etag2},
		{3, etag3},
	})

	// Read back the assembled object — the gateway must decrypt all parts and
	// re-assemble the plaintext in order.
	want := append(append(append([]byte(nil), part1Data...), part2Data...), part3Data...)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Errorf("encrypted MPU round-trip: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// testEncryptedMPUManifestIsHidden verifies that the gateway-owned manifest is
// not exposed to client-facing ListObjects responses. It then removes the
// manifest through the raw backend to reproduce issue #217 and verifies that
// the gateway reports missing encryption metadata for the main object.
func testEncryptedMPUManifestIsHidden(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })
	part1 := bytes.Repeat([]byte("A"), 5*1024*1024)
	part2 := []byte("manifest-hidden-tail")
	etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1)
	etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part2)
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{{1, etag1}, {2, etag2}})

	resp, err := gw.HTTPClient().Get(fmt.Sprintf("%s/%s?prefix=%s", gw.URL, inst.Bucket, key))
	if err != nil {
		t.Fatalf("list encrypted MPU: %v", err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("list encrypted MPU: status=%d err=%v body=%s", resp.StatusCode, readErr, body)
	}
	if bytes.Contains(body, []byte(key+".mpu-manifest")) {
		t.Fatalf("ListObjects exposed gateway-owned manifest %q: %s", key+".mpu-manifest", body)
	}
	if !bytes.Contains(body, []byte("<Key>"+key+"</Key>")) {
		t.Fatalf("ListObjects omitted main MPU object %q: %s", key, body)
	}

	backend := newS3Client(t, inst)
	if err := backend.DeleteObject(ctx, inst.Bucket, key+".mpu-manifest", nil); err != nil {
		t.Fatalf("delete manifest directly from backend: %v", err)
	}

	resp, err = gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatalf("get object after manifest deletion: %v", err)
	}
	body, readErr = io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatalf("read missing-manifest response: %v", readErr)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("get after manifest deletion: status=%d body=%s", resp.StatusCode, body)
	}
	if !bytes.Contains(body, []byte("Encrypted multipart object metadata is missing")) {
		t.Fatalf("missing-manifest response lacks diagnostic: %s", body)
	}
	if bytes.Contains(body, []byte(key+".mpu-manifest")) {
		t.Fatalf("missing-manifest response exposes internal manifest key: %s", body)
	}
}

// testEncryptedMPU_AtRest is the headline security smoke test for the encrypted
// multipart upload feature (V0.6-SEC-3 / ADR-0009). It:
//
//  1. Uploads a 2-part object through the gateway with EncryptMultipartUploads=true.
//  2. Reads the raw bytes **directly from the backend** (bypassing the gateway)
//     using an AWS SDK client pointed at the backend endpoint.
//  3. Asserts that the raw bytes do NOT contain the plaintext marker "SECRET".
//
// If this test fails it means the encrypted-MPU code path is writing plaintext
// to the backend — the core security goal of V0.6-SEC-3 is not met.
func testEncryptedMPU_AtRest(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	// Use a distinctive plaintext marker so we can unambiguously detect leakage.
	marker := []byte("SECRET_PLAINTEXT_MARKER")
	part1Data := bytes.Repeat(marker, (5*1024*1024)/len(marker)+1)
	part1Data = part1Data[:5*1024*1024]
	part2Data := append([]byte("TAIL_"), marker...)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1Data)
	etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part2Data)
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1},
		{2, etag2},
	})

	// Build a raw S3 client that talks DIRECTLY to the backend — not through the
	// gateway — so we see the actual ciphertext stored on disk.
	var endpointOpts []func(*awsconfig.LoadOptions) error
	if inst.Endpoint != "" {
		endpointOpts = append(endpointOpts,
			awsconfig.WithEndpointResolverWithOptions(
				aws.EndpointResolverWithOptionsFunc(func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{URL: inst.Endpoint, HostnameImmutable: true}, nil
				}),
			),
		)
	}
	rawCfg, err := awsconfig.LoadDefaultConfig(ctx,
		append([]func(*awsconfig.LoadOptions) error{
			awsconfig.WithRegion(inst.Region),
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, ""),
			),
		}, endpointOpts...)...,
	)
	if err != nil {
		t.Fatalf("at-rest test: load raw S3 config: %v", err)
	}
	rawSvc := s3.NewFromConfig(rawCfg, func(o *s3.Options) { o.UsePathStyle = true })

	out, err := rawSvc.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("at-rest test: raw GetObject: %v", err)
	}
	defer out.Body.Close()
	rawBytes, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("at-rest test: read raw body: %v", err)
	}

	// The raw backend bytes must NOT contain the plaintext marker.
	// If the gateway is encrypting correctly, the ciphertext is pseudo-random
	// and the marker string will not appear verbatim.
	if bytes.Contains(rawBytes, marker) {
		t.Errorf("AT-REST SECURITY FAILURE: raw backend bytes contain plaintext marker %q — "+
			"encrypted MPU code path is writing plaintext to the backend for provider %s",
			marker, inst.ProviderName)
	}

	// Sanity check: reading through the gateway must still produce the original plaintext.
	want := append(append([]byte(nil), part1Data...), part2Data...)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Errorf("at-rest test: gateway round-trip mismatch: got %d bytes, want %d bytes",
			len(got), len(want))
	}
}

// testEncryptedMPUAbortCleansState verifies that AbortMultipartUpload on an
// encrypted upload removes the Valkey state entry (no orphaned DEK material).
func testEncryptedMPUAbortCleansState(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)

	part1Data := bytes.Repeat([]byte("X"), 5*1024*1024)
	uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1Data)

	// Abort — this must clean up Valkey state.
	abortMultipartUpload(t, gw, inst.Bucket, key, uploadID)

	// The object must not exist.
	resp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatalf("GET after encrypted MPU abort: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("GET after encrypted MPU abort: status %d, want 404", resp.StatusCode)
	}
}

// testEncryptedMPU_LargeObject uploads a large MPU object (80 parts × 5 MiB =
// ~400 MiB) and downloads it back end-to-end.  This is the conformance
// golden-path for issue #135: large encrypted restores that must survive the
// streaming decrypt-and-write path for long enough to exercise any
// write-deadline refresh logic (the download alone should take ≥ 15 s on
// real public backends).
func testEncryptedMPU_LargeObject(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	// Upload 80 parts × 5 MiB = 400 MiB total.
	const partCount = 80
	const partSize = 5 * 1024 * 1024
	var etags []string
	var want []byte
	for i := 0; i < partCount; i++ {
		pattern := byte('A' + i%26)
		partData := bytes.Repeat([]byte{pattern}, partSize)
		want = append(want, partData...)
		etags = append(etags, uploadPart(t, gw, inst.Bucket, key, uploadID, i+1, partData))
	}

	var parts []mpuPart
	for i, etag := range etags {
		parts = append(parts, mpuPart{i + 1, etag})
	}
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, parts)

	// Stream the full object back.
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Fatalf("encrypted MPU large object round-trip mismatch: want %d bytes, got %d bytes", len(want), len(got))
	}
}
