package s3

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// azureMockClient implements Client for Azure shim unit tests.
type azureMockClient struct {
	Client
	putObjectFn  func(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error)
	getObjectFn  func(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error)
	headObjectFn func(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error)
}

func (m *azureMockClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	if m.putObjectFn != nil {
		return m.putObjectFn(ctx, bucket, key, reader, metadata, contentLength, tags, lock, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
	}
	return "", errors.New("unexpected PutObject call")
}

func (m *azureMockClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if m.getObjectFn != nil {
		return m.getObjectFn(ctx, bucket, key, versionID, rangeHeader)
	}
	return nil, nil, errors.New("unexpected GetObject call")
}

func (m *azureMockClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	if m.headObjectFn != nil {
		return m.headObjectFn(ctx, bucket, key, versionID)
	}
	return nil, errors.New("unexpected HeadObject call")
}

func TestAzureClient_PutObject_MetadataTooLarge_ReturnsInvalidArgument(t *testing.T) {
	c := &azureClient{inner: &azureMockClient{}}

	// Build metadata exceeding 8 KiB.
	meta := make(map[string]string)
	var buf strings.Builder
	for buf.Len() < 8192 {
		buf.WriteString("x")
	}
	meta["key"] = buf.String()

	_, err := c.PutObject(context.Background(), "b", "k", nil, meta, nil, "", nil, "", "", "", "", "")
	if err == nil {
		t.Fatal("expected error for oversized metadata, got nil")
	}
	if !strings.Contains(err.Error(), "InvalidArgument") {
		t.Errorf("expected InvalidArgument error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "8 KiB") {
		t.Errorf("expected error to mention 8 KiB limit, got: %v", err)
	}
}

func TestAzureClient_PutObject_InvalidMetadataKey_ReturnsInvalidArgument(t *testing.T) {
	c := &azureClient{inner: &azureMockClient{}}

	// Slash is not a valid Azure metadata key character.
	meta := map[string]string{"invalid/key": "value"}
	_, err := c.PutObject(context.Background(), "b", "k", nil, meta, nil, "", nil, "", "", "", "", "")
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
	if !strings.Contains(err.Error(), "InvalidArgument") {
		t.Errorf("expected InvalidArgument error, got: %v", err)
	}
}

func TestAzureClient_PutObject_ValidMetadata_Succeeds(t *testing.T) {
	var capturedMeta map[string]string
	mock := &azureMockClient{
		putObjectFn: func(_ context.Context, _, _ string, _ io.Reader, metadata map[string]string, _ *int64, _ string, _ *ObjectLockInput, _, _, _, _, _ string) (string, error) {
			capturedMeta = metadata
			return `"etag"`, nil
		},
	}
	c := &azureClient{inner: mock}

	meta := map[string]string{"valid_key": "value", "another.meta$": "ok"}
	_, err := c.PutObject(context.Background(), "b", "k", nil, meta, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject with valid metadata: %v", err)
	}
	if capturedMeta["valid_key"] != "value" {
		t.Errorf("expected capturedMeta['valid_key'] = 'value', got %q", capturedMeta["valid_key"])
	}
}

func TestAzureClient_ObjectLock_ReturnsNotImplemented(t *testing.T) {
	c := &azureClient{inner: &azureMockClient{}}

	// Test all six Object Lock methods.
	tests := []struct {
		name string
		err  error
	}{
		{"PutObjectRetention", c.PutObjectRetention(context.Background(), "b", "k", nil, nil)},
		{"GetObjectRetention", func() error {
			_, err := c.GetObjectRetention(context.Background(), "b", "k", nil)
			return err
		}()},
		{"PutObjectLegalHold", c.PutObjectLegalHold(context.Background(), "b", "k", nil, "")},
		{"GetObjectLegalHold", func() error {
			_, err := c.GetObjectLegalHold(context.Background(), "b", "k", nil)
			return err
		}()},
		{"PutObjectLockConfiguration", c.PutObjectLockConfiguration(context.Background(), "b", nil)},
		{"GetObjectLockConfiguration", func() error {
			_, err := c.GetObjectLockConfiguration(context.Background(), "b")
			return err
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(tt.err.Error(), "not implemented") &&
				!strings.Contains(tt.err.Error(), "NotImplemented") &&
				!errors.Is(tt.err, ErrNotImplemented) {
				t.Errorf("expected NotImplemented error, got: %v", tt.err)
			}
		})
	}
}

func TestAzureClient_GetObject_BlobNotFound_MapsToNoSuchKey(t *testing.T) {
	mock := &azureMockClient{
		getObjectFn: func(_ context.Context, _, _ string, _ *string, _ *string) (io.ReadCloser, map[string]string, error) {
			return nil, nil, errors.New("BlobNotFound: the specified blob does not exist")
		},
	}
	c := &azureClient{inner: mock}

	_, _, err := c.GetObject(context.Background(), "b", "k", nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "NoSuchKey") {
		t.Errorf("expected NoSuchKey error, got: %v", err)
	}
}

func TestAzureClient_HeadObject_BlobNotFound_MapsToNoSuchKey(t *testing.T) {
	mock := &azureMockClient{
		headObjectFn: func(_ context.Context, _, _ string, _ *string) (map[string]string, error) {
			return nil, errors.New("BlobNotFound: the specified blob does not exist")
		},
	}
	c := &azureClient{inner: mock}

	_, err := c.HeadObject(context.Background(), "b", "k", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "NoSuchKey") {
		t.Errorf("expected NoSuchKey error, got: %v", err)
	}
}
