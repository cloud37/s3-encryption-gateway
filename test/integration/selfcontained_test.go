//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestSelfContained_AES_MinIO_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// Start MinIO container
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/minio/minio:latest",
		ExposedPorts: []string{"9000/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     "minioadmin",
			"MINIO_ROOT_PASSWORD": "minioadmin",
		},
		Cmd: []string{"server", "/data"},
		WaitingFor: wait.ForLog("API:").WithStartupTimeout(60 * time.Second),
	}
	minioC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	defer minioC.Terminate(ctx)

	mappedPort, err := minioC.MappedPort(ctx, "9000")
	require.NoError(t, err)
	endpoint := fmt.Sprintf("localhost:%s", mappedPort.Port())

	// Create AESKEKManager with two versions for rotation testing
	key1 := make([]byte, 32)
	_, err = rand.Read(key1)
	require.NoError(t, err)
	key2 := make([]byte, 32)
	_, err = rand.Read(key2)
	require.NoError(t, err)

	km, err := crypto.NewAESKEKManager(map[int][]byte{1: key1, 2: key2}, 1)
	require.NoError(t, err)
	defer km.Close(ctx)

	var rkm crypto.RotatableKeyManager = km

	// Create engine with key manager
	eng, err := crypto.NewEngineWithOpts([]byte("integration-test-password-abcdef"), nil, crypto.WithKeyManager(km))
	require.NoError(t, err)

	// Create S3 client
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin", "")),
	)
	require.NoError(t, err)

	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://" + endpoint)
		o.UsePathStyle = true
	})

	// Create test bucket
	bucket := "self-contained-test-" + fmt.Sprintf("%d", time.Now().UnixNano())
	_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		s3Client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	})

	objectKey := "test-object.dat"

	// PUT an object
	plaintext := []byte("Hello, Self-Contained Encryption! This is integration test data.")
	reader := bytes.NewReader(plaintext)
	encReader, metadata, err := eng.Encrypt(ctx, reader, map[string]string{
		"Content-Type": "application/octet-stream",
	})
	require.NoError(t, err)

	encData, err := io.ReadAll(encReader)
	require.NoError(t, err)

	s3Metadata := make(map[string]string)
	for k, v := range metadata {
		s3Metadata[k] = v
	}

	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(objectKey),
		Body:     bytes.NewReader(encData),
		Metadata: s3Metadata,
	})
	require.NoError(t, err)

	// GET and verify the object
	getOutput, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err)

	getMetadata := make(map[string]string)
	for k, v := range getOutput.Metadata {
		getMetadata[k] = v
	}

	encBody, err := io.ReadAll(getOutput.Body)
	require.NoError(t, err)
	getOutput.Body.Close()

	decReader, _, err := eng.Decrypt(ctx, bytes.NewReader(encBody), getMetadata)
	require.NoError(t, err)

	decData, err := io.ReadAll(decReader)
	require.NoError(t, err)
	require.Equal(t, plaintext, decData)

	// Rotate and verify old object still readable
	plan, err := rkm.PrepareRotation(ctx, nil)
	require.NoError(t, err)
	err = rkm.PromoteActiveVersion(ctx, plan)
	require.NoError(t, err)

	// New object should use new version
	newPlaintext := []byte("Post-rotation plaintext data")
	newReader := bytes.NewReader(newPlaintext)
	newEncReader, newMetadata, err := eng.Encrypt(ctx, newReader, map[string]string{
		"Content-Type": "application/octet-stream",
	})
	require.NoError(t, err)

	newEncData, err := io.ReadAll(newEncReader)
	require.NoError(t, err)

	newS3Metadata := make(map[string]string)
	for k, v := range newMetadata {
		newS3Metadata[k] = v
	}

	newObjectKey := "test-object-rotated.dat"
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(newObjectKey),
		Body:     bytes.NewReader(newEncData),
		Metadata: newS3Metadata,
	})
	require.NoError(t, err)

	// Old object still readable
	getOutput2, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	require.NoError(t, err)

	getMetadata2 := make(map[string]string)
	for k, v := range getOutput2.Metadata {
		getMetadata2[k] = v
	}

	encBody2, err := io.ReadAll(getOutput2.Body)
	require.NoError(t, err)
	getOutput2.Body.Close()

	decReader2, _, err := eng.Decrypt(ctx, bytes.NewReader(encBody2), getMetadata2)
	require.NoError(t, err)

	decData2, err := io.ReadAll(decReader2)
	require.NoError(t, err)
	require.Equal(t, plaintext, decData2)

	// New object also readable
	getOutput3, err := s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(newObjectKey),
	})
	require.NoError(t, err)

	getMetadata3 := make(map[string]string)
	for k, v := range getOutput3.Metadata {
		getMetadata3[k] = v
	}

	encBody3, err := io.ReadAll(getOutput3.Body)
	require.NoError(t, err)
	getOutput3.Body.Close()

	decReader3, _, err := eng.Decrypt(ctx, bytes.NewReader(encBody3), getMetadata3)
	require.NoError(t, err)

	decData3, err := io.ReadAll(decReader3)
	require.NoError(t, err)
	require.Equal(t, newPlaintext, decData3)
}
