//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// newCompatS3Client creates an AWS SDK Go v2 S3 client routed through the
// gateway at the given URL.
func newCompatS3Client(t *testing.T, gw *harness.Gateway, inst provider.Instance) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(inst.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, ""),
		),
	)
	if err != nil {
		t.Fatalf("newCompatS3Client: %v", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String(gw.URL)
	})
}

// testCompatSmoke_AWSGoV2 exercises the full smoke-test baseline using the
// AWS SDK Go v2 in-process. This covers all 7 operations from §1.3.
func testCompatSmoke_AWSGoV2(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	client := newCompatS3Client(t, gw, inst)

	// PutObject (single, ≤ 5 MiB)
	payload := []byte("compat-test-data")
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
		Body:   bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: PutObject: %v", err)
	}

	// HeadObject
	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: HeadObject: %v", err)
	}
	if head.ContentLength == nil || *head.ContentLength != int64(len(payload)) {
		t.Errorf("AWSGoV2: HeadObject ContentLength = %v, want %d", head.ContentLength, len(payload))
	}

	// GetObject (full read)
	get, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: GetObject: %v", err)
	}
	gotBody, err := io.ReadAll(get.Body)
	get.Body.Close()
	if err != nil {
		t.Fatalf("AWSGoV2: GetObject read body: %v", err)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Fatalf("AWSGoV2: GetObject body mismatch: got %q, want %q", string(gotBody), string(payload))
	}

	// ListObjectsV2
	list, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(env.Bucket),
		Prefix: aws.String(env.Key),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: ListObjectsV2: %v", err)
	}
	found := false
	for _, obj := range list.Contents {
		if obj.Key != nil && *obj.Key == env.Key {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AWSGoV2: ListObjectsV2: key %q not found", env.Key)
	}

	// DeleteObject
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: DeleteObject: %v", err)
	}

	// Multipart (all providers with CapSDKAWSGoV2 also have CapMultipartUpload).
	mpKey := env.Key + "-mp"
	createResp, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(mpKey),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: CreateMultipartUpload: %v", err)
	}
	uploadID := *createResp.UploadId

	// Upload 3 parts (each exactly 5 MiB to satisfy S3 minimum part size).
	partSize := int64(5 * 1024 * 1024)
	partData := bytes.Repeat([]byte("A"), int(3*partSize))
	var completedParts []s3types.CompletedPart
	for i := int64(0); i < 3; i++ {
		partNum := int32(i + 1)
		partResp, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     aws.String(env.Bucket),
			Key:        aws.String(mpKey),
			PartNumber: aws.Int32(partNum),
			UploadId:   aws.String(uploadID),
			Body:       bytes.NewReader(partData[i*partSize : (i+1)*partSize]),
		})
		if err != nil {
			client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(env.Bucket),
				Key:      aws.String(mpKey),
				UploadId: aws.String(uploadID),
			})
			t.Fatalf("AWSGoV2: UploadPart %d: %v", partNum, err)
		}
		completedParts = append(completedParts, s3types.CompletedPart{
			PartNumber: aws.Int32(partNum),
			ETag:       partResp.ETag,
		})
	}

	_, err = client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(env.Bucket),
		Key:      aws.String(mpKey),
		UploadId: aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		t.Fatalf("AWSGoV2: CompleteMultipartUpload: %v", err)
	}

	// Verify round-trip on MPU object.
	mpGet, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(mpKey),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: MPU GetObject: %v", err)
	}
	mpBody, err := io.ReadAll(mpGet.Body)
	mpGet.Body.Close()
	if err != nil {
		t.Fatalf("AWSGoV2: MPU read body: %v", err)
	}
	expectedMP := partData[:3*partSize]
	if !bytes.Equal(mpBody, expectedMP) {
		t.Fatalf("AWSGoV2: MPU body mismatch: len(got)=%d, len(want)=%d", len(mpBody), len(expectedMP))
	}

	// Cleanup MPU object.
	client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(mpKey),
	})

	// CopyObject (all providers with CapSDKAWSGoV2 also have CapMultipartCopy).
	copyKey := env.Key + "-copy"
	// Re-upload source since we deleted it.
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
		Body:   bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: PutObject for copy source: %v", err)
	}

	_, err = client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(env.Bucket),
		Key:        aws.String(copyKey),
		CopySource: aws.String(fmt.Sprintf("%s/%s", env.Bucket, env.Key)),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: CopyObject: %v", err)
	}

	copyGet, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(copyKey),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: CopyObject GetObject: %v", err)
	}
	copyBody, err := io.ReadAll(copyGet.Body)
	copyGet.Body.Close()
	if err != nil {
		t.Fatalf("AWSGoV2: CopyObject read body: %v", err)
	}
	if !bytes.Equal(copyBody, payload) {
		t.Fatalf("AWSGoV2: CopyObject body mismatch")
	}

	// Cleanup copy and source.
	client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(copyKey),
	})
	client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
	})
}

// testCompatSmoke_Boto3 exercises the smoke-test baseline using boto3 (Python).
func testCompatSmoke_Boto3(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &boto3Runner{}, env); err != nil {
		t.Fatalf("boto3: %v", err)
	}
	_ = gw // gw is used indirectly via env.Endpoint
}

// testCompatSmoke_AWSCLI exercises the smoke-test baseline using awscli.
func testCompatSmoke_AWSCLI(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &awscliRunner{}, env); err != nil {
		t.Fatalf("awscli: %v", err)
	}
	_ = gw
}

// testCompatSmoke_S5cmd exercises the smoke-test baseline using s5cmd.
func testCompatSmoke_S5cmd(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &s5cmdRunner{}, env); err != nil {
		t.Fatalf("s5cmd: %v", err)
	}
	_ = gw
}

// testCompatSmoke_Rclone exercises the smoke-test baseline using rclone.
func testCompatSmoke_Rclone(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &rcloneRunner{}, env); err != nil {
		t.Fatalf("rclone: %v", err)
	}
	_ = gw
}

// testCompatSmoke_MinIOPy exercises the smoke-test baseline using minio-py.
func testCompatSmoke_MinIOPy(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &minioPyRunner{}, env); err != nil {
		t.Fatalf("minio-py: %v", err)
	}
	_ = gw
}

// testRcloneSyncCheck_SizeCache verifies the warm-cache path for issues #204
// and #207: objects uploaded through the gateway populate the Valkey size cache
// automatically, so rclone check --size-only sees correct plaintext sizes.
//
// This covers the steady-state case: deploy gateway with Valkey, upload via
// gateway, rclone check passes immediately.
func testRcloneSyncCheck_SizeCache(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	// Start a real Valkey container so the gateway size cache is active.
	vk := provider.StartValkey(ctx, t)

	// Start the gateway with the size cache wired via the shared Valkey pool.
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
	)

	// Use a unique prefix so parallel tests never collide in the same bucket.
	prefix := compatUniqueKey(t)

	env := sdkTestEnv{
		Endpoint:  gw.URL,
		Region:    inst.Region,
		AccessKey: inst.AccessKey,
		SecretKey: inst.SecretKey,
		Bucket:    inst.Bucket,
		Key:       prefix, // repurposed as the remote path prefix
	}

	if err := runToolContainer(ctx, t, &rcloneSyncCheckRunner{}, env); err != nil {
		t.Fatalf("rclone-sync-check: %v", err)
	}
}

// testRcloneSyncCheck_FallbackHead is the regression test for the specific
// failure reported in issue #207 comment: the user upgraded to 0.11.1, set
// LIST_SIZE_TRANSLATE_ENABLED=true and LIST_SIZE_TRANSLATE_FALLBACK_HEAD_ENABLED=true,
// but rclone check still reported "sizes differ".
//
// Root cause: loadFromEnv() never read the LIST_SIZE_TRANSLATE_* env vars —
// the env: struct tags were declared but not wired. The env vars were silently
// ignored, the fallback HEAD path never fired, and pre-existing objects
// (uploaded before 0.11.1 with a cold cache) always returned ciphertext sizes.
//
// This test reproduces that scenario:
//  1. Upload 15 objects directly to the backend (bypassing the gateway) so the
//     Valkey cache starts cold — simulating objects that existed before upgrade.
//  2. Start the gateway with Valkey + fallback HEAD enabled.
//  3. rclone sync downloads the objects and then rclone check --size-only
//     compares local sizes against the gateway listing. Without the fix the
//     env var is ignored, the fallback never fires, and check exits 1.
//     With the fix the env var is respected, the fallback HEAD resolves
//     plaintext sizes, and check exits 0.
func testRcloneSyncCheck_FallbackHead(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	// Start Valkey — cache starts empty (cold).
	vk := provider.StartValkey(ctx, t)

	// Start the gateway with Valkey + fallback HEAD enabled.
	// WithConfigMutator simulates the operator setting
	// LIST_SIZE_TRANSLATE_FALLBACK_HEAD_ENABLED=true after upgrade.
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithConfigMutator(func(cfg *config.Config) {
			cfg.ListSizeTranslate.FallbackHeadEnabled = true
			cfg.ListSizeTranslate.FallbackHeadConcurrency = 10
			cfg.ListSizeTranslate.FallbackHeadTimeout = 30 * time.Second
		}),
	)

	// Write the 15 files directly to the backend, bypassing the gateway.
	// This means the Valkey cache has no entries for them — exactly the
	// situation for objects that existed before the 0.11.1 upgrade.
	prefix := compatUniqueKey(t)
	directClient := newS3Client(t, inst)
	eng, err := crypto.NewEngine([]byte("test-encryption-password-123456"))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	type fileSpec struct {
		name string
		size int
	}
	files := []fileSpec{
		{"file-00.bin", 100}, {"file-01.bin", 1100}, {"file-02.bin", 2100},
		{"file-03.bin", 3100}, {"file-04.bin", 4100}, {"file-05.bin", 5100},
		{"file-06.bin", 6100}, {"file-07.bin", 7100}, {"file-08.bin", 8100},
		{"file-09.bin", 9100}, {"file-10.bin", 65536}, {"file-11.bin", 65537},
		{"file-12.bin", 131072}, {"file-13.bin", 131073}, {"file-14.txt", 18},
	}

	for _, f := range files {
		plaintext := make([]byte, f.size)
		for i := range plaintext {
			plaintext[i] = byte('a' + (i % 26))
		}
		key := prefix + "/" + f.name
		putEncryptedObject(t, directClient, eng, inst.Bucket, key, plaintext, nil)
	}

	// Run rclone sync (download from gateway) then rclone check --size-only.
	// The sync downloads the objects; check compares the local sizes against
	// what ListObjects returns. The fallback HEAD must fire for each cache-miss
	// to resolve the plaintext size — otherwise check sees ciphertext sizes.
	env := sdkTestEnv{
		Endpoint:  gw.URL,
		Region:    inst.Region,
		AccessKey: inst.AccessKey,
		SecretKey: inst.SecretKey,
		Bucket:    inst.Bucket,
		Key:       prefix,
	}

	if err := runToolContainer(ctx, t, &rcloneSyncCheckFallbackRunner{}, env); err != nil {
		t.Fatalf("rclone-sync-check-fallback: %v", err)
	}
}
