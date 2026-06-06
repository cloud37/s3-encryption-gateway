package migrate

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// mockS3ForVerify is a minimal mock that satisfies S3Client.
type mockS3ForVerify struct {
	objects  map[string][]byte
	metadata map[string]map[string]string
}

func newMockS3ForVerify() *mockS3ForVerify {
	return &mockS3ForVerify{
		objects:  make(map[string][]byte),
		metadata: make(map[string]map[string]string),
	}
}

func (m *mockS3ForVerify) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *s3.ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	data, _ := io.ReadAll(reader)
	m.objects[bucket+"/"+key] = data
	m.metadata[bucket+"/"+key] = metadata
	return "", nil
}

func (m *mockS3ForVerify) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		return nil, nil, fmt.Errorf("not found")
	}
	meta := m.metadata[bucket+"/"+key]
	if meta == nil {
		meta = make(map[string]string)
	}
	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

func (m *mockS3ForVerify) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	meta, ok := m.metadata[bucket+"/"+key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return meta, nil
}

func (m *mockS3ForVerify) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	delete(m.objects, bucket+"/"+key)
	delete(m.metadata, bucket+"/"+key)
	return nil
}

func (m *mockS3ForVerify) ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) (s3.ListResult, error) {
	return s3.ListResult{}, nil
}

func (m *mockS3ForVerify) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *s3.ObjectLockInput) (string, map[string]string, error) {
	return "", nil, nil
}

func TestVerify_Success(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-password-verify-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	plaintext := []byte("hello verify world")
	encReader, meta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	cipherdata, _ := io.ReadAll(encReader)

	mock := newMockS3ForVerify()
	_, _ = mock.PutObject(context.Background(), "b", "k", bytes.NewReader(cipherdata), meta, nil, "", nil, "", "", "", "", "")

	if err := Verify(context.Background(), mock, eng, "b", "k", plaintext); err != nil {
		t.Errorf("Verify failed: %v", err)
	}
}

func TestVerify_Tampered(t *testing.T) {
	eng, err := crypto.NewEngineWithChunking([]byte("test-password-verify-1234"), nil, "", nil, true, crypto.DefaultChunkSize)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	plaintext := []byte("hello verify world")
	encReader, meta, err := eng.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	cipherdata, _ := io.ReadAll(encReader)
	// Tamper with 1 byte.
	cipherdata[10] ^= 0xFF

	mock := newMockS3ForVerify()
	_, _ = mock.PutObject(context.Background(), "b", "k", bytes.NewReader(cipherdata), meta, nil, "", nil, "", "", "", "", "")

	if err := Verify(context.Background(), mock, eng, "b", "k", plaintext); err == nil {
		t.Error("expected Verify to fail on tampered object")
	}
}
