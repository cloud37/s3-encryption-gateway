package s3

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// gcsMockClient implements Client for GCS shim unit tests.
// Only the methods needed by the tests are non-nil; all others are
// delegated to the embedded nil Client which panics on unexpected calls.
type gcsMockClient struct {
	Client
	putObjectFn func(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error)
	getObjectFn func(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error)
	copyObjectFn func(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *ObjectLockInput) (string, map[string]string, error)
	uploadPartFn func(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error)
}

func (m *gcsMockClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	if m.putObjectFn != nil {
		return m.putObjectFn(ctx, bucket, key, reader, metadata, contentLength, tags, lock, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
	}
	return "", errors.New("unexpected PutObject call")
}

func (m *gcsMockClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if m.getObjectFn != nil {
		return m.getObjectFn(ctx, bucket, key, versionID, rangeHeader)
	}
	return nil, nil, errors.New("unexpected GetObject call")
}

func (m *gcsMockClient) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *ObjectLockInput) (string, map[string]string, error) {
	if m.copyObjectFn != nil {
		return m.copyObjectFn(ctx, dstBucket, dstKey, srcBucket, srcKey, srcVersionID, metadata, lock)
	}
	return "", nil, errors.New("unexpected CopyObject call")
}

func (m *gcsMockClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	if m.uploadPartFn != nil {
		return m.uploadPartFn(ctx, bucket, key, uploadID, partNumber, reader, contentLength)
	}
	return "", errors.New("unexpected UploadPart call")
}

func TestGCSClient_PutObject_LowercasesMetadata(t *testing.T) {
	received := make(map[string]string)
	mock := &gcsMockClient{
		putObjectFn: func(_ context.Context, _, _ string, _ io.Reader, metadata map[string]string, _ *int64, _ string, _ *ObjectLockInput, _, _, _, _, _ string) (string, error) {
			received = metadata
			return `"etag123"`, nil
		},
	}
	c := &gcsClient{inner: mock}

	input := map[string]string{
		"X-Amz-Meta-Foo":       "bar",
		"X-Amz-Meta-Encryption": "aes256",
		"x-amz-meta-normal":    "ok",
	}
	_, err := c.PutObject(context.Background(), "b", "k", nil, input, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	for k, v := range received {
		if k != strings.ToLower(k) {
			t.Errorf("metadata key %q is not lowercase (value=%q)", k, v)
		}
	}
	if received["x-amz-meta-foo"] != "bar" {
		t.Errorf("expected received['x-amz-meta-foo'] = 'bar', got %q", received["x-amz-meta-foo"])
	}
	if received["x-amz-meta-encryption"] != "aes256" {
		t.Errorf("expected received['x-amz-meta-encryption'] = 'aes256', got %q", received["x-amz-meta-encryption"])
	}
	if received["x-amz-meta-normal"] != "ok" {
		t.Errorf("expected received['x-amz-meta-normal'] = 'ok', got %q", received["x-amz-meta-normal"])
	}
}

func TestGCSClient_GetObject_LowercasesReturnedMetadata(t *testing.T) {
	mock := &gcsMockClient{
		getObjectFn: func(_ context.Context, _, _ string, _ *string, _ *string) (io.ReadCloser, map[string]string, error) {
			return io.NopCloser(strings.NewReader("")), map[string]string{
				"X-Amz-Meta-Foo": "bar",
				"LAST-MODIFIED":  "Mon, 01 Jan 2024 00:00:00 GMT",
			}, nil
		},
	}
	c := &gcsClient{inner: mock}

	_, meta, err := c.GetObject(context.Background(), "b", "k", nil, nil)
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}

	for k := range meta {
		if k != strings.ToLower(k) {
			t.Errorf("metadata key %q is not lowercase", k)
		}
	}
	if meta["x-amz-meta-foo"] != "bar" {
		t.Errorf("expected meta['x-amz-meta-foo'] = 'bar', got %q", meta["x-amz-meta-foo"])
	}
}

func TestGCSClient_UploadPart_ExceedsPartLimit_ReturnsError(t *testing.T) {
	c := &gcsClient{inner: &gcsMockClient{}}

	_, err := c.UploadPart(context.Background(), "b", "k", "uploadID", 33, nil, nil)
	if err == nil {
		t.Fatal("expected error for part number 33, got nil")
	}
	if !strings.Contains(err.Error(), "InvalidArgument") {
		t.Errorf("expected InvalidArgument error, got: %v", err)
	}

	// Part 32 should be delegated (mock returns error for unexpected calls)
	_, err = c.UploadPart(context.Background(), "b", "k", "uploadID", 32, nil, nil)
	if err == nil {
		t.Fatal("expected error from mock for part 32 (unexpected UploadPart call)")
	}
}

func TestGCSClient_PutObject_NilMetadata(t *testing.T) {
	mock := &gcsMockClient{
		putObjectFn: func(_ context.Context, _, _ string, _ io.Reader, metadata map[string]string, _ *int64, _ string, _ *ObjectLockInput, _, _, _, _, _ string) (string, error) {
			if metadata != nil {
				t.Errorf("expected nil metadata, got %v", metadata)
			}
			return `"etag"`, nil
		},
	}
	c := &gcsClient{inner: mock}
	_, err := c.PutObject(context.Background(), "b", "k", nil, nil, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject with nil metadata: %v", err)
	}
}
