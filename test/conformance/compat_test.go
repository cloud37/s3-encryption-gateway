//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
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

// testRcloneSyncCheck_SizeCache is a full end-to-end regression test for
// issues #204 and #207.
//
// It reproduces the exact workflow reported by the issue author:
//  1. Start a gateway with a real Valkey size cache (CapSizeTranslation).
//  2. Run rclone sync from a local directory containing files of varying sizes
//     to the gateway. Each PUT warms the Valkey size cache automatically.
//  3. Run rclone check --size-only --one-way, which compares each local file's
//     size against the size returned by ListObjects. With the fix this exits 0;
//     without the fix it exits 1 with "sizes differ" for every encrypted object.
//
// The test gates on CapCLIRclone|CapSizeTranslation because it requires:
//   - Docker (for the rclone container and the Valkey container).
//   - A gateway with ListSizeTranslate wired (i.e. Valkey configured).
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
