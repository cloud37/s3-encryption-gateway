package s3

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

// simpleInnerClient implements Client with injectable function fields.
// All unimplemented methods return a "not implemented" error.
type simpleInnerClient struct {
	headObjectFn func(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error)
	putObjectFn  func(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error)
	getObjectFn  func(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error)
}

func (c *simpleInnerClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	if c.headObjectFn != nil {
		return c.headObjectFn(ctx, bucket, key, versionID)
	}
	return nil, errors.New("not implemented")
}

func (c *simpleInnerClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	if c.putObjectFn != nil {
		return c.putObjectFn(ctx, bucket, key, reader, metadata, contentLength, tags, lock, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
	}
	return "", errors.New("not implemented")
}

func (c *simpleInnerClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if c.getObjectFn != nil {
		return c.getObjectFn(ctx, bucket, key, versionID, rangeHeader)
	}
	return nil, nil, errors.New("not implemented")
}

func (c *simpleInnerClient) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	return errors.New("not implemented")
}

func (c *simpleInnerClient) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) (ListResult, error) {
	return ListResult{}, errors.New("not implemented")
}

func (c *simpleInnerClient) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	return "", errors.New("not implemented")
}

func (c *simpleInnerClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	return "", errors.New("not implemented")
}

func (c *simpleInnerClient) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart, lock *ObjectLockInput) (string, error) {
	return "", errors.New("not implemented")
}

func (c *simpleInnerClient) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return errors.New("not implemented")
}

func (c *simpleInnerClient) ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error) {
	return nil, errors.New("not implemented")
}

func (c *simpleInnerClient) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *ObjectLockInput) (string, map[string]string, error) {
	return "", nil, errors.New("not implemented")
}

func (c *simpleInnerClient) UploadPartCopy(ctx context.Context, dstBucket, dstKey, uploadID string, partNumber int32, srcBucket, srcKey string, srcVersionID *string, srcRange *CopyPartRange) (*CopyPartResult, error) {
	return nil, errors.New("not implemented")
}

func (c *simpleInnerClient) DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error) {
	return nil, nil, errors.New("not implemented")
}

func (c *simpleInnerClient) PutObjectRetention(ctx context.Context, bucket, key string, versionID *string, retention *RetentionConfig) error {
	return errors.New("not implemented")
}

func (c *simpleInnerClient) GetObjectRetention(ctx context.Context, bucket, key string, versionID *string) (*RetentionConfig, error) {
	return nil, errors.New("not implemented")
}

func (c *simpleInnerClient) PutObjectLegalHold(ctx context.Context, bucket, key string, versionID *string, status string) error {
	return errors.New("not implemented")
}

func (c *simpleInnerClient) GetObjectLegalHold(ctx context.Context, bucket, key string, versionID *string) (string, error) {
	return "", errors.New("not implemented")
}

func (c *simpleInnerClient) PutObjectLockConfiguration(ctx context.Context, bucket string, config *ObjectLockConfiguration) error {
	return errors.New("not implemented")
}

func (c *simpleInnerClient) GetObjectLockConfiguration(ctx context.Context, bucket string) (*ObjectLockConfiguration, error) {
	return nil, errors.New("not implemented")
}

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

func TestGCSClient_DelegatedMethods_PassThrough(t *testing.T) {
	// Verify that delegation methods pass through to the inner client.
	// Each method returns "not implemented" from simpleInnerClient, proving
	// the call was dispatched.
	inner := &simpleInnerClient{}
	c := &gcsClient{inner: inner}

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
		{"CompleteMultipartUpload", func() error {
			_, err := c.CompleteMultipartUpload(context.Background(), "b", "k", "u", nil, nil)
			return err
		}()},
		{"AbortMultipartUpload", c.AbortMultipartUpload(context.Background(), "b", "k", "u")},
		{"ListParts", func() error {
			_, err := c.ListParts(context.Background(), "b", "k", "u")
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
				t.Fatal("expected error from inner client, got nil")
			}
			if !strings.Contains(tt.err.Error(), "not implemented") {
				t.Errorf("expected 'not implemented' error, got: %v", tt.err)
			}
		})
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


func TestGCSClient_CopyObject_LowercasesMetadataAndSubstitutesLastModified(t *testing.T) {
	mock := &gcsMockClient{
		copyObjectFn: func(_ context.Context, _, _ string, _, _ string, _ *string, metadata map[string]string, _ *ObjectLockInput) (string, map[string]string, error) {
			// Return the input metadata plus an ETag.
			out := make(map[string]string, len(metadata)+1)
			for k, v := range metadata {
				out[k] = v
			}
			out["ETag"] = `"etag-copy"`
			return `"etag-copy"`, out, nil
		},
	}
	c := &gcsClient{inner: mock}

	etag, meta, err := c.CopyObject(context.Background(), "dst-b", "dst-k", "src-b", "src-k", nil, map[string]string{"X-Amz-Meta-Foo": "bar"}, nil)
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	if etag != `"etag-copy"` {
		t.Errorf("expected etag %q, got %q", `"etag-copy"`, etag)
	}
	// Metadata keys should be lowercased
	if meta["x-amz-meta-foo"] != "bar" {
		t.Errorf("expected lowercased metadata key 'x-amz-meta-foo'='bar', got %v", meta)
	}
	// LastModified should be substituted (since mock didn't return one)
	if _, ok := meta["last-modified"]; !ok {
		t.Errorf("expected last-modified to be substituted in metadata, got %v", meta)
	}
}

func TestGCSClient_CopyObject_PreservesExistingLastModified(t *testing.T) {
	existingTime := "Mon, 01 Jan 2024 00:00:00 GMT"
	mock := &gcsMockClient{
		copyObjectFn: func(_ context.Context, _, _ string, _, _ string, _ *string, metadata map[string]string, _ *ObjectLockInput) (string, map[string]string, error) {
			return `"etag-copy"`, map[string]string{
				"Last-Modified": existingTime,
			}, nil
		},
	}
	c := &gcsClient{inner: mock}

	_, meta, err := c.CopyObject(context.Background(), "dst-b", "dst-k", "src-b", "src-k", nil, nil, nil)
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}
	// The existing last-modified should be preserved (not substituted)
	if meta["last-modified"] != existingTime {
		t.Errorf("expected last-modified %q, got %q", existingTime, meta["last-modified"])
	}
}

func TestGCSClient_HeadObject_LowercasesMetadata(t *testing.T) {
	inner := &simpleInnerClient{
		headObjectFn: func(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
			return map[string]string{"X-Amz-Meta-Test": "value", "CONTENT-TYPE": "text/plain"}, nil
		},
	}
	c := &gcsClient{inner: inner}

	meta, err := c.HeadObject(context.Background(), "b", "k", nil)
	if err != nil {
		t.Fatalf("HeadObject: %v", err)
	}
	for k := range meta {
		if k != strings.ToLower(k) {
			t.Errorf("metadata key %q is not lowercase", k)
		}
	}
	if meta["x-amz-meta-test"] != "value" {
		t.Errorf("expected meta['x-amz-meta-test'] = 'value', got %q", meta["x-amz-meta-test"])
	}
	if meta["content-type"] != "text/plain" {
		t.Errorf("expected meta['content-type'] = 'text/plain', got %q", meta["content-type"])
	}
}
