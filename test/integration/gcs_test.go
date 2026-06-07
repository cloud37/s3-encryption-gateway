//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/require"
)

// TestGCS_PutGetList_RoundTrip runs a full PUT → GET → LIST → DELETE cycle
// against Google Cloud Storage's S3-compatible XML API.
//
// This is a manual-run test.  It requires the following environment variables:
//
//	GATEWAY_TEST_GCS_ENDPOINT    — e.g. "https://storage.googleapis.com"
//	GATEWAY_TEST_GCS_ACCESS_KEY  — HMAC access key
//	GATEWAY_TEST_GCS_SECRET_KEY  — HMAC secret key
//
// When credentials are absent, the test skips gracefully.
func TestGCS_PutGetList_RoundTrip(t *testing.T) {
	endpoint := os.Getenv("GATEWAY_TEST_GCS_ENDPOINT")
	accessKey := os.Getenv("GATEWAY_TEST_GCS_ACCESS_KEY")
	secretKey := os.Getenv("GATEWAY_TEST_GCS_SECRET_KEY")

	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skip("GCS: set GATEWAY_TEST_GCS_ENDPOINT, GATEWAY_TEST_GCS_ACCESS_KEY, and GATEWAY_TEST_GCS_SECRET_KEY")
	}

	ctx := context.Background()

	// Create S3 client pointing at GCS S3-compatible endpoint.
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	require.NoError(t, err)

	s3Client := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = false // GCS uses virtual-hosted-style
	})

	// Create test bucket.
	bucket := "s3-encryption-gateway-integration-" + fmt.Sprintf("%d", time.Now().UnixNano())
	_, err = s3Client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		// Best-effort cleanup.
		_, _ = s3Client.DeleteBucket(ctx, &awss3.DeleteBucketInput{Bucket: aws.String(bucket)})
	})

	// --- PUT ---
	objectKey := "test/roundtrip-gcs.txt"
	content := []byte("Hello GCS via S3-compatible API! " + time.Now().String())
	_, err = s3Client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(content),
		Metadata: map[string]string{
			// GCS requires lowercase metadata keys.
			"test-key": "test-value-gcs",
		},
	})
	require.NoError(t, err, "PutObject should succeed")

	// --- GET ---
	getOutput, err := s3Client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "GetObject should succeed")

	gotData, err := io.ReadAll(getOutput.Body)
	require.NoError(t, err)
	getOutput.Body.Close()
	require.Equal(t, content, gotData, "GET content should match PUT content")

	// GCS lowercases metadata keys automatically.
	require.Contains(t, getOutput.Metadata, "test-key",
		"metadata key should be present (GCS lowercases keys)")

	// --- LIST ---
	listOutput, err := s3Client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String("test/"),
	})
	require.NoError(t, err, "ListObjects should succeed")
	found := false
	for _, obj := range listOutput.Contents {
		if aws.ToString(obj.Key) == objectKey {
			found = true
			break
		}
	}
	require.True(t, found, "object should be listed under test/ prefix")

	// --- DELETE ---
	_, err = s3Client.DeleteObject(ctx, &awss3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err, "DeleteObject should succeed")

	// Verify deletion.
	_, err = s3Client.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	require.Error(t, err, "GetObject after delete should fail")
	require.True(t, strings.Contains(err.Error(), "NotFound") ||
		strings.Contains(err.Error(), "NoSuchKey"),
		"error should indicate object not found, got: %v", err)
}
