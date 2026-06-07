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


func TestAzureClient_PutObject_NilMetadata_Succeeds(t *testing.T) {
	var capturedMeta map[string]string
	mock := &azureMockClient{
		putObjectFn: func(_ context.Context, _, _ string, _ io.Reader, metadata map[string]string, _ *int64, _ string, _ *ObjectLockInput, _, _, _, _, _ string) (string, error) {
			capturedMeta = metadata
			return `"etag"`, nil
		},
	}
	c := &azureClient{inner: mock}

	_, err := c.PutObject(context.Background(), "b", "k", nil, nil, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject with nil metadata: %v", err)
	}
	if capturedMeta != nil {
		t.Errorf("expected nil metadata, got %v", capturedMeta)
	}
}

func TestAzureClient_PutObject_EmptyMetadata_Succeeds(t *testing.T) {
	mock := &azureMockClient{
		putObjectFn: func(_ context.Context, _, _ string, _ io.Reader, metadata map[string]string, _ *int64, _ string, _ *ObjectLockInput, _, _, _, _, _ string) (string, error) {
			return `"etag"`, nil
		},
	}
	c := &azureClient{inner: mock}

	_, err := c.PutObject(context.Background(), "b", "k", nil, map[string]string{}, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject with empty metadata: %v", err)
	}
}

func TestAzureClient_GetObject_NonAzureError_PassesThrough(t *testing.T) {
	mock := &azureMockClient{
		getObjectFn: func(_ context.Context, _, _ string, _ *string, _ *string) (io.ReadCloser, map[string]string, error) {
			return nil, nil, errors.New("some other error")
		},
	}
	c := &azureClient{inner: mock}

	_, _, err := c.GetObject(context.Background(), "b", "k", nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if strings.Contains(err.Error(), "NoSuchKey") {
		t.Errorf("expected non-NoSuchKey error, got NoSuchKey: %v", err)
	}
}

func TestAzureClient_HeadObject_NonAzureError_PassesThrough(t *testing.T) {
	mock := &azureMockClient{
		headObjectFn: func(_ context.Context, _, _ string, _ *string) (map[string]string, error) {
			return nil, errors.New("some other error")
		},
	}
	c := &azureClient{inner: mock}

	_, err := c.HeadObject(context.Background(), "b", "k", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if strings.Contains(err.Error(), "NoSuchKey") {
		t.Errorf("expected non-NoSuchKey error, got NoSuchKey: %v", err)
	}
}


func TestAzureClient_DelegatedMethods_PassThrough(t *testing.T) {
	// Verify that delegation methods pass through to the inner client.
	inner := &simpleInnerClient{}
	c := &azureClient{inner: inner}

	tests := []struct {
		name string
		err  error
	}{
		{"DeleteObject", c.DeleteObject(context.Background(), "b", "k", nil)},
		{"ListObjects", func() error {
			_, err := c.ListObjects(context.Background(), "b", "", ListOptions{})
			return err
		}()},
		{"CreateMultipartUpload", func() error {
			_, err := c.CreateMultipartUpload(context.Background(), "b", "k", nil, "", "", "", "", "")
			return err
		}()},
		{"UploadPart", func() error {
			_, err := c.UploadPart(context.Background(), "b", "k", "u", 1, nil, nil)
			return err
		}()},
		{"CompleteMultipartUpload", func() error {
			_, err := c.CompleteMultipartUpload(context.Background(), "b", "k", "u", nil, nil)
			return err
		}()},
		{"AbortMultipartUpload", c.AbortMultipartUpload(context.Background(), "b", "k", "u")},
		{"ListParts", func() error {
			_, err := c.ListParts(context.Background(), "b", "k", "u")
			return err
		}()},
		{"CopyObject", func() error {
			_, _, err := c.CopyObject(context.Background(), "db", "dk", "sb", "sk", nil, nil, nil)
			return err
		}()},
		{"UploadPartCopy", func() error {
			_, err := c.UploadPartCopy(context.Background(), "b", "k", "u", 1, "sb", "sk", nil, nil)
			return err
		}()},
		{"DeleteObjects", func() error {
			_, _, err := c.DeleteObjects(context.Background(), "b", nil)
			return err
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("expected error from inner client, got nil")
			}
			if !strings.Contains(tt.err.Error(), "not implemented") {
				t.Errorf("expected 'not implemented' error, got: %v", tt.err)
			}
		})
	}
}

func TestMapAzureError_Nil_ReturnsNil(t *testing.T) {
	if err := mapAzureError(nil); err != nil {
		t.Fatalf("mapAzureError(nil) = %v, want nil", err)
	}
}

func TestMapAzureError_NonAzureError_ReturnsSameError(t *testing.T) {
	original := errors.New("some random SDK error")
	mapped := mapAzureError(original)
	if !strings.Contains(mapped.Error(), "some random SDK error") {
		t.Errorf("expected original error message, got: %v", mapped)
	}
	if strings.Contains(mapped.Error(), "NoSuchKey") {
		t.Errorf("expected no NoSuchKey mapping, got: %v", mapped)
	}
}

func TestValidateAzureMetadata_Empty_ReturnsNil(t *testing.T) {
	if err := validateAzureMetadata(nil); err != nil {
		t.Fatalf("validateAzureMetadata(nil) = %v, want nil", err)
	}
	if err := validateAzureMetadata(map[string]string{}); err != nil {
		t.Fatalf("validateAzureMetadata(empty) = %v, want nil", err)
	}
}

func TestValidateAzureMetadata_BoundarySize_Valid(t *testing.T) {
	// Build metadata just under the 8 KiB limit.
	meta := make(map[string]string)
	meta["key"] = strings.Repeat("x", azureMaxMetadataBytes-4) // "key" = 3 bytes + value = 8188 = 8191 < 8192
	if err := validateAzureMetadata(meta); err != nil {
		t.Fatalf("expected no error for boundary-size metadata, got: %v", err)
	}
}

func TestNormalizeEndpoint_Realistic(t *testing.T) {
	// Verify the normalizeEndpoint function handles realistic inputs.
	// Empty string is not a realistic input; it's tested indirectly
	// via the factory test.
	tests := []struct {
		input    string
		expected string
	}{
		{"https://storage.googleapis.com", "https://storage.googleapis.com"},
		{"http://localhost:10000", "http://localhost:10000"},
		{"storage.googleapis.com", "https://storage.googleapis.com"},
		{"s3.amazonaws.com/", "https://s3.amazonaws.com"},
	}
	for _, tt := range tests {
		got := normalizeEndpoint(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
