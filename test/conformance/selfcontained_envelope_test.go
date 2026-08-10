//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// selfContainedPlaintext is a fixed test payload used across all
// self-contained KEK envelope tests. Large enough to exercise at least one
// full AES-GCM chunk but small enough to keep tests fast.
var selfContainedPlaintext = bytes.Repeat([]byte("self-contained-envelope-test"), 512) // ~14 KiB

// makeAESKEKManager builds an AESKEKManager from a fresh random 32-byte key.
func makeAESKEKManager(t *testing.T) *crypto.AESKEKManager {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatalf("makeAESKEKManager: rand.Read: %v", err)
	}
	km, err := crypto.NewAESKEKManager(map[int][]byte{1: kek}, 1)
	if err != nil {
		t.Fatalf("makeAESKEKManager: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	return km
}

// makeRSAKEKManager generates a fresh 2048-bit RSA private key and wraps it
// in an RSAKEKManager. RSA-OAEP/SHA-256 is used for DEK wrapping.
func makeRSAKEKManager(t *testing.T) *crypto.RSAKEKManager {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("makeRSAKEKManager: GenerateKey: %v", err)
	}
	km, err := crypto.NewRSAKEKManager(privKey, 1)
	if err != nil {
		t.Fatalf("makeRSAKEKManager: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	return km
}

// newBypassS3Client creates an AWS SDK S3 client that speaks directly to the
// backend provider (inst.Endpoint) — bypassing the gateway entirely.
// This is used to prove that data stored on the backend is ciphertext, not
// plaintext.
func newBypassS3Client(t *testing.T, inst provider.Instance) *awss3.Client {
	t.Helper()
	ctx := context.Background()

	var endpointOpts []func(*awsconfig.LoadOptions) error
	if inst.Endpoint != "" {
		endpointOpts = append(endpointOpts,
			awsconfig.WithEndpointResolverWithOptions(
				aws.EndpointResolverWithOptionsFunc(
					func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
						return aws.Endpoint{URL: inst.Endpoint, HostnameImmutable: true}, nil
					},
				),
			),
		)
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		append([]func(*awsconfig.LoadOptions) error{
			awsconfig.WithRegion(inst.Region),
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, ""),
			),
		}, endpointOpts...)...,
	)
	if err != nil {
		t.Fatalf("newBypassS3Client: LoadDefaultConfig: %v", err)
	}
	return awss3.NewFromConfig(cfg, func(o *awss3.Options) { o.UsePathStyle = true })
}

// testSelfContained_AES_EnvelopeRoundTrip verifies the full envelope
// encryption / decryption path using the self-contained AES-256-GCM KEK:
//
//  1. Generate a random 32-byte KEK wrapped in an AESKEKManager.
//  2. Start an in-process gateway wired with that KeyManager.
//  3. PUT an object → gateway generates a fresh DEK, wraps it with the AES
//     KEK, and stores the wrapped DEK in S3 object metadata.
//  4. GET the same object → gateway unwraps the DEK, decrypts the ciphertext.
//  5. Assert the retrieved plaintext is byte-perfect.
func testSelfContained_AES_EnvelopeRoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()

	km := makeAESKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, selfContainedPlaintext)

	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, selfContainedPlaintext) {
		t.Errorf("AES envelope round-trip: content mismatch (got %d bytes, want %d)",
			len(got), len(selfContainedPlaintext))
	}
}

// testSelfContained_AES_StandardMetadataRoundTrip covers the production path
// reported in issue #236: self-contained envelope encryption must preserve
// standard object headers, not only user metadata and plaintext bytes.
func testSelfContained_AES_StandardMetadataRoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()

	km := makeAESKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))
	key := uniqueKey(t)

	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, key), bytes.NewReader([]byte("self-contained metadata")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "max-age=3600")
	req.Header.Set("Content-Disposition", `attachment; filename="object.json"`)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("self-contained metadata PUT: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("self-contained metadata PUT: status %d", resp.StatusCode)
	}

	// Inspect backend metadata directly as well as the gateway response. This
	// catches the original regression where Cache-Control and Content-Disposition
	// were persisted in gateway metadata but MetaContentType was omitted.
	rawClient := newBypassS3Client(t, inst)
	rawHead, err := rawClient.HeadObject(context.Background(), &awss3.HeadObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("self-contained metadata backend HEAD: %v", err)
	}
	t.Logf("backend metadata: %#v", rawHead.Metadata)
	if rawHead.ContentType == nil || *rawHead.ContentType != "application/octet-stream" {
		t.Errorf("backend ciphertext ContentType = %q, want application/octet-stream", aws.ToString(rawHead.ContentType))
	}
	if rawHead.Metadata["encryption-content-type"] != "application/json" {
		t.Errorf("backend encryption-content-type = %q, want application/json", rawHead.Metadata["encryption-content-type"])
	}

	assertStandardMetadata := func(t *testing.T, resp *http.Response) {
		t.Helper()
		for header, want := range map[string]string{
			"Content-Type":        "application/json",
			"Cache-Control":       "max-age=3600",
			"Content-Disposition": `attachment; filename="object.json"`,
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
	}

	headReq, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
	headResp, err := gw.HTTPClient().Do(headReq)
	if err != nil {
		t.Fatalf("self-contained metadata HEAD: %v", err)
	}
	defer headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("self-contained metadata HEAD: status %d", headResp.StatusCode)
	}
	t.Run("HEAD", func(t *testing.T) { assertStandardMetadata(t, headResp) })

	getReq, _ := http.NewRequest("GET", objectURL(gw, inst.Bucket, key), nil)
	getResp, err := gw.HTTPClient().Do(getReq)
	if err != nil {
		t.Fatalf("self-contained metadata GET: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("self-contained metadata GET: status %d", getResp.StatusCode)
	}
	t.Run("GET", func(t *testing.T) { assertStandardMetadata(t, getResp) })
}

// testSelfContained_AES_CopyObjectStandardMetadata verifies that CopyObject
// inherits plaintext metadata recovered from a self-contained encrypted source.
func testSelfContained_AES_CopyObjectStandardMetadata(t *testing.T, inst provider.Instance) {
	t.Helper()
	km := makeAESKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))
	srcKey, dstKey := uniqueKey(t), uniqueKey(t)
	data := []byte("self-contained copy metadata")

	putReq, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, srcKey), bytes.NewReader(data))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("Cache-Control", "max-age=99")
	putReq.Header.Set("Content-Disposition", `attachment; filename="copy.json"`)
	putResp, err := gw.HTTPClient().Do(putReq)
	if err != nil {
		t.Fatalf("source PUT: %v", err)
	}
	io.Copy(io.Discard, putResp.Body)
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("source PUT: status %d", putResp.StatusCode)
	}

	copyReq, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, dstKey), nil)
	copyReq.Header.Set("x-amz-copy-source", "/"+inst.Bucket+"/"+srcKey)
	copyResp, err := gw.HTTPClient().Do(copyReq)
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	io.Copy(io.Discard, copyResp.Body)
	copyResp.Body.Close()
	if copyResp.StatusCode != http.StatusOK {
		t.Fatalf("CopyObject: status %d", copyResp.StatusCode)
	}

	assertHeaders := func(t *testing.T, resp *http.Response) {
		t.Helper()
		for header, want := range map[string]string{
			"Content-Type":        "application/json",
			"Cache-Control":       "max-age=99",
			"Content-Disposition": `attachment; filename="copy.json"`,
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
	}

	headReq, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, dstKey), nil)
	headResp, err := gw.HTTPClient().Do(headReq)
	if err != nil {
		t.Fatalf("copied object HEAD: %v", err)
	}
	defer headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("copied object HEAD: status %d", headResp.StatusCode)
	}
	assertHeaders(t, headResp)

	getResp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, dstKey))
	if err != nil {
		t.Fatalf("copied object GET: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("copied object GET: status %d", getResp.StatusCode)
	}
	assertHeaders(t, getResp)
	got, _ := io.ReadAll(getResp.Body)
	if !bytes.Equal(got, data) {
		t.Errorf("copied object body = %q, want %q", got, data)
	}
}

// testSelfContained_AES_ChunkedCopyObjectStandardMetadata covers the chunked
// self-contained path used by production deployments in issue #236.
func testSelfContained_AES_ChunkedCopyObjectStandardMetadata(t *testing.T, inst provider.Instance) {
	t.Helper()
	km := makeAESKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km), harness.WithChunking(true))
	srcKey, dstKey := uniqueKey(t), uniqueKey(t)
	data := []byte("chunked self-contained copy metadata")

	putReq, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, srcKey), bytes.NewReader(data))
	putReq.Header.Set("Content-Type", "image/png")
	putReq.Header.Set("Cache-Control", "max-age=99")
	putReq.Header.Set("Content-Disposition", `inline; filename="probe.png"`)
	putResp, err := gw.HTTPClient().Do(putReq)
	if err != nil {
		t.Fatalf("chunked source PUT: %v", err)
	}
	io.Copy(io.Discard, putResp.Body)
	putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		t.Fatalf("chunked source PUT: status %d", putResp.StatusCode)
	}

	copyReq, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, dstKey), nil)
	copyReq.Header.Set("x-amz-copy-source", "/"+inst.Bucket+"/"+srcKey)
	copyResp, err := gw.HTTPClient().Do(copyReq)
	if err != nil {
		t.Fatalf("chunked CopyObject: %v", err)
	}
	io.Copy(io.Discard, copyResp.Body)
	copyResp.Body.Close()
	if copyResp.StatusCode != http.StatusOK {
		t.Fatalf("chunked CopyObject: status %d", copyResp.StatusCode)
	}

	assertHeaders := func(t *testing.T, resp *http.Response) {
		t.Helper()
		for header, want := range map[string]string{
			"Content-Type":        "image/png",
			"Cache-Control":       "max-age=99",
			"Content-Disposition": `inline; filename="probe.png"`,
		} {
			if got := resp.Header.Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
	}

	headReq, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, dstKey), nil)
	headResp, err := gw.HTTPClient().Do(headReq)
	if err != nil {
		t.Fatalf("chunked copied HEAD: %v", err)
	}
	defer headResp.Body.Close()
	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("chunked copied HEAD: status %d", headResp.StatusCode)
	}
	assertHeaders(t, headResp)

	getResp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, dstKey))
	if err != nil {
		t.Fatalf("chunked copied GET: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("chunked copied GET: status %d", getResp.StatusCode)
	}
	assertHeaders(t, getResp)
	got, _ := io.ReadAll(getResp.Body)
	if !bytes.Equal(got, data) {
		t.Errorf("chunked copied body = %q, want %q", got, data)
	}
}

// testSelfContained_AES_AWSCLICopyMetadata reproduces the exact AWS CLI
// server-side copy workflow reported in issue #236.
func testSelfContained_AES_AWSCLICopyMetadata(t *testing.T, inst provider.Instance) {
	t.Helper()
	km := makeAESKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))
	env := sdkTestEnv{
		Endpoint:  gw.URL,
		Region:    inst.Region,
		AccessKey: inst.AccessKey,
		SecretKey: inst.SecretKey,
		Bucket:    inst.Bucket,
		Key:       compatUniqueKey(t),
	}
	if err := runToolContainer(context.Background(), t, &awscliCopyMetadataRunner{}, env); err != nil {
		t.Fatalf("awscli copy metadata: %v", err)
	}
}

// testSelfContained_AES_AtRest verifies that objects written through the
// self-contained AES KEK gateway are stored as ciphertext on the backend:
//
//  1. PUT an object through the gateway (AES KEK active).
//  2. Read the raw bytes from the backend S3 directly — bypassing the gateway.
//  3. Assert the raw bytes do NOT contain the known plaintext marker.
//  4. GET through the gateway and assert full plaintext is recovered.
func testSelfContained_AES_AtRest(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	const marker = "self-contained-envelope-test"

	km := makeAESKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, selfContainedPlaintext)

	// Bypass the gateway: read ciphertext directly from the backend.
	rawClient := newBypassS3Client(t, inst)
	out, err := rawClient.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("bypass GetObject: %v", err)
	}
	defer out.Body.Close()
	rawBytes, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("bypass ReadAll: %v", err)
	}

	// The backend must not contain the plaintext marker.
	if bytes.Contains(rawBytes, []byte(marker)) {
		t.Error("AES at-rest: backend contains plaintext marker — object was NOT encrypted")
	}

	// Gateway must still recover the full plaintext.
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, selfContainedPlaintext) {
		t.Errorf("AES at-rest: gateway round-trip failed (got %d bytes, want %d)",
			len(got), len(selfContainedPlaintext))
	}
}

// testSelfContained_AES_Rotation_DualRead verifies that after a KEK rotation,
// objects encrypted with the old version are still decryptable when the new
// manager retains the old key:
//
//  1. Write an object through a gateway with only key-version 1 (old KEK).
//  2. Spin up a new gateway with version 2 active but version 1 retained.
//  3. GET through the new gateway and assert the plaintext is recovered.
func testSelfContained_AES_Rotation_DualRead(t *testing.T, inst provider.Instance) {
	t.Helper()

	// Two deterministic, non-secret keys — only used in ephemeral test containers.
	kekV1 := bytes.Repeat([]byte{0xA1}, 32)
	kekV2 := bytes.Repeat([]byte{0xA2}, 32)

	// Gateway 1: version 1 only.
	kmV1, err := crypto.NewAESKEKManager(map[int][]byte{1: kekV1}, 1)
	if err != nil {
		t.Fatalf("NewAESKEKManager v1: %v", err)
	}
	t.Cleanup(func() { _ = kmV1.Close(context.Background()) })

	gw1 := harness.StartGateway(t, inst, harness.WithKeyManager(kmV1))
	key := uniqueKey(t)
	put(t, gw1, inst.Bucket, key, selfContainedPlaintext)

	// Gateway 2: version 2 active, version 1 retained for unwrap.
	kmV2, err := crypto.NewAESKEKManager(map[int][]byte{1: kekV1, 2: kekV2}, 2)
	if err != nil {
		t.Fatalf("NewAESKEKManager v2: %v", err)
	}
	t.Cleanup(func() { _ = kmV2.Close(context.Background()) })

	gw2 := harness.StartGateway(t, inst, harness.WithKeyManager(kmV2))

	got := get(t, gw2, inst.Bucket, key)
	if !bytes.Equal(got, selfContainedPlaintext) {
		t.Errorf("AES rotation dual-read: content mismatch (got %d bytes, want %d)",
			len(got), len(selfContainedPlaintext))
	}
}

// testSelfContained_RSA_EnvelopeRoundTrip verifies the full envelope
// encryption / decryption path using the self-contained RSA-OAEP/SHA-256 KEK:
//
//  1. Generate a fresh 2048-bit RSA private key.
//  2. Wrap it in an RSAKEKManager.
//  3. Start an in-process gateway wired with that KeyManager.
//  4. PUT → RSA-OAEP wraps the DEK in metadata.
//  5. GET → RSA-OAEP unwraps the DEK, AES-GCM decrypts the body.
//  6. Assert byte-perfect match.
func testSelfContained_RSA_EnvelopeRoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()

	km := makeRSAKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, selfContainedPlaintext)

	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, selfContainedPlaintext) {
		t.Errorf("RSA envelope round-trip: content mismatch (got %d bytes, want %d)",
			len(got), len(selfContainedPlaintext))
	}
}

// testSelfContained_AES_RangedGet_LargeChunked verifies byte-range reads on a
// multi-chunk object encrypted with an AES-256-GCM KEK.
//
// The object is 200 KiB (> 3× the 64 KiB default chunk size) so multiple
// chunked-AEAD blocks are exercised. Five sub-ranges are tested:
//   - a range within the first chunk
//   - a range crossing the first/second chunk boundary
//   - a range entirely within the second chunk
//   - a range crossing the second/third chunk boundary
//   - a range that spans all three chunks
func testSelfContained_AES_RangedGet_LargeChunked(t *testing.T, inst provider.Instance) {
	t.Helper()

	const objSize = 200 * 1024 // 200 KiB — spans 3 × 64 KiB chunks

	// Fill with a non-repeating pattern so any mis-alignment is immediately visible.
	plaintext := make([]byte, objSize)
	for i := range plaintext {
		plaintext[i] = byte(i & 0xFF)
	}

	km := makeAESKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, plaintext)

	const chunkSize = 64 * 1024 // default chunk boundary

	rangeTests := []struct {
		name       string
		start, end int64
	}{
		{"within-chunk-1", 0, 1023},
		{"cross-chunk-1-2", int64(chunkSize - 512), int64(chunkSize + 511)},
		{"within-chunk-2", int64(chunkSize), int64(2*chunkSize - 1)},
		{"cross-chunk-2-3", int64(2*chunkSize - 256), int64(2*chunkSize + 255)},
		{"span-all-chunks", 0, int64(objSize - 1)},
	}

	for _, rt := range rangeTests {
		rt := rt
		t.Run(rt.name, func(t *testing.T) {
			got := getRange(t, gw, inst.Bucket, key, rt.start, rt.end)
			want := plaintext[rt.start : rt.end+1]
			if !bytes.Equal(got, want) {
				t.Errorf("AES ranged-get [%d-%d]: got %d bytes, want %d bytes (content mismatch)",
					rt.start, rt.end, len(got), len(want))
			}
		})
	}
}

// testSelfContained_RSA_RangedGet verifies byte-range reads on an object
// encrypted with an RSA-OAEP/SHA-256 KEK.
//
// Uses a 200 KiB object to exercise multiple chunks. Three sub-ranges are
// tested to cover intra-chunk and cross-chunk cases.
func testSelfContained_RSA_RangedGet(t *testing.T, inst provider.Instance) {
	t.Helper()

	const objSize = 200 * 1024

	plaintext := make([]byte, objSize)
	for i := range plaintext {
		plaintext[i] = byte((i * 7) & 0xFF)
	}

	km := makeRSAKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, plaintext)

	const chunkSize = 64 * 1024

	rangeTests := []struct {
		name       string
		start, end int64
	}{
		{"first-512-bytes", 0, 511},
		{"cross-chunk-1-2", int64(chunkSize - 128), int64(chunkSize + 127)},
		{"last-512-bytes", int64(objSize - 512), int64(objSize - 1)},
	}

	for _, rt := range rangeTests {
		rt := rt
		t.Run(rt.name, func(t *testing.T) {
			got := getRange(t, gw, inst.Bucket, key, rt.start, rt.end)
			want := plaintext[rt.start : rt.end+1]
			if !bytes.Equal(got, want) {
				t.Errorf("RSA ranged-get [%d-%d]: got %d bytes, want %d bytes (content mismatch)",
					rt.start, rt.end, len(got), len(want))
			}
		})
	}
}

// testSelfContained_RSA_AtRest verifies that objects encrypted via the RSA KEK
// are stored as ciphertext on the backend (not readable in cleartext):
//
//  1. PUT an object through the gateway (RSA KEK active).
//  2. Bypass-read the raw bytes from the backend.
//  3. Assert the raw bytes do NOT contain the known plaintext marker.
//  4. GET through the gateway and assert full plaintext is recovered.
func testSelfContained_RSA_AtRest(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	const marker = "self-contained-envelope-test"

	km := makeRSAKEKManager(t)
	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, selfContainedPlaintext)

	// Bypass the gateway: read ciphertext directly from the backend.
	rawClient := newBypassS3Client(t, inst)
	out, err := rawClient.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("bypass GetObject: %v", err)
	}
	defer out.Body.Close()
	rawBytes, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("bypass ReadAll: %v", err)
	}

	// The backend must not contain the plaintext marker.
	if bytes.Contains(rawBytes, []byte(marker)) {
		t.Error("RSA at-rest: backend contains plaintext marker — object was NOT encrypted")
	}

	// Gateway must still recover the full plaintext.
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, selfContainedPlaintext) {
		t.Errorf("RSA at-rest: gateway round-trip failed (got %d bytes, want %d)",
			len(got), len(selfContainedPlaintext))
	}
}
