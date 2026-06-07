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
	tc "github.com/testcontainers/testcontainers-go"
	tcwait "github.com/testcontainers/testcontainers-go/wait"
)

// TestAzure_PutGetList_RoundTrip runs a full PUT → GET → LIST → DELETE cycle
// against an Azurite emulator container (Azure Blob Storage S3-compatible API).
//
// Requires Docker.  To use an external Azure endpoint instead, set:
//
//	GATEWAY_TEST_AZURE_ENDPOINT   — the S3-compatible endpoint URL
//	GATEWAY_TEST_AZURE_ACCESS_KEY — Azure access key
//	GATEWAY_TEST_AZURE_SECRET_KEY — Azure secret key
func TestAzure_PutGetList_RoundTrip(t *testing.T) {
	ctx := context.Background()

	var endpoint, accessKey, secretKey string

	if extEndpoint := os.Getenv("GATEWAY_TEST_AZURE_ENDPOINT"); extEndpoint != "" {
		// External Azure endpoint.
		endpoint = extEndpoint
		accessKey = os.Getenv("GATEWAY_TEST_AZURE_ACCESS_KEY")
		secretKey = os.Getenv("GATEWAY_TEST_AZURE_SECRET_KEY")
		if accessKey == "" || secretKey == "" {
			t.Skip("Azure external: set GATEWAY_TEST_AZURE_ACCESS_KEY and GATEWAY_TEST_AZURE_SECRET_KEY")
		}
	} else {
		// Start Azurite container.
		req := tc.ContainerRequest{
			Image:        "mcr.microsoft.com/azure-storage/azurite:latest",
			ExposedPorts: []string{"10000/tcp"},
			Env: map[string]string{
				"AZURITE_ACCOUNTS": "devstoreaccount1:Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
			},
			WaitingFor: tcwait.ForListeningPort("10000/tcp"),
		}
		c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
			ContainerRequest: req,
			Started:          true,
		})
		if err != nil {
			t.Skipf("Azure: Azurite container failed (Docker unavailable?): %v", err)
		}
		t.Cleanup(func() { _ = c.Terminate(context.Background()) })

		port, err := c.MappedPort(ctx, "10000/tcp")
		require.NoError(t, err)
		host, err := c.Host(ctx)
		require.NoError(t, err)
		endpoint = fmt.Sprintf("http://%s:%s", host, port.Port())
		accessKey = "devstoreaccount1"
		secretKey = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	}

	// Create S3 client pointing at the Azure S3-compatible endpoint.
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	require.NoError(t, err)

	s3Client := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	// Create test bucket.
	bucket := "azure-rt-" + fmt.Sprintf("%d", time.Now().UnixNano())
	_, err = s3Client.CreateBucket(ctx, &awss3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = s3Client.DeleteBucket(ctx, &awss3.DeleteBucketInput{Bucket: aws.String(bucket)})
	})

	// --- PUT ---
	objectKey := "test/roundtrip-object.txt"
	content := []byte("Hello Azure Blob Storage via S3-compatible API! " + time.Now().String())
	_, err = s3Client.PutObject(ctx, &awss3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   bytes.NewReader(content),
		Metadata: map[string]string{
			"test-key": "test-value",
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

	// Verify metadata.
	require.Equal(t, "test-value", getOutput.Metadata["test-key"], "metadata should be preserved")

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
		strings.Contains(err.Error(), "NoSuchKey") ||
		strings.Contains(err.Error(), "BlobNotFound"),
		"error should indicate object not found, got: %v", err)
}
