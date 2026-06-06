package s3

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

// gcsClient wraps a Client and applies GCS S3-compatible API normalisation.
//
// GCS's XML API requires user-metadata keys to be lowercase; uppercase or
// mixed-case metadata keys are silently dropped.  The shim lowercases all
// metadata keys on PutObject and normalises returned metadata on GetObject
// and HeadObject.
//
// GCS limits multipart uploads to 32 parts.  The shim returns
// InvalidArgument when partNumber > 32.
//
// GCS's CopyObject response does not include LastModified in the
// CopyObjectResult body; the shim substitutes time.Now() when it is zero.
type gcsClient struct {
	inner Client
}

// newGCSClient constructs a GCS S3-compatible shim.
// The endpoint is normalised to https://storage.googleapis.com if not already
// set in cfg.Endpoint.
func newGCSClient(cfg *config.BackendConfig, opts ...ClientFactoryOption) (Client, error) {
	// Build a mutable copy so we don't mutate the caller's config.
	cfgCopy := *cfg
	if cfgCopy.Endpoint == "" {
		cfgCopy.Endpoint = "https://storage.googleapis.com"
	}
	cfgCopy.Type = config.BackendTypeS3 // force inner client to use default S3 path

	inner, err := NewClientFactory(&cfgCopy, opts...).GetClient()
	if err != nil {
		return nil, fmt.Errorf("gcs: construct inner client: %w", err)
	}
	return &gcsClient{inner: inner}, nil
}

// ---- overrides ----

func (c *gcsClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	return c.inner.PutObject(ctx, bucket, key, reader, lowercaseKeys(metadata), contentLength, tags, lock, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
}

func (c *gcsClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	body, meta, err := c.inner.GetObject(ctx, bucket, key, versionID, rangeHeader)
	if err != nil {
		return body, meta, err
	}
	return body, lowercaseKeys(meta), nil
}

func (c *gcsClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	meta, err := c.inner.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		return meta, err
	}
	return lowercaseKeys(meta), nil
}

func (c *gcsClient) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *ObjectLockInput) (string, map[string]string, error) {
	etag, resultMeta, err := c.inner.CopyObject(ctx, dstBucket, dstKey, srcBucket, srcKey, srcVersionID, lowercaseKeys(metadata), lock)
	if err != nil {
		return etag, resultMeta, err
	}
	resultMeta = lowercaseKeys(resultMeta)
	// GCS's XML API does not return LastModified in the CopyObjectResult body;
	// substitute time.Now() as the sentinel value.
	if _, ok := resultMeta["last-modified"]; !ok {
		resultMeta["last-modified"] = time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
	}
	return etag, resultMeta, nil
}

func (c *gcsClient) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	return c.inner.CreateMultipartUpload(ctx, bucket, key, lowercaseKeys(metadata), cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
}

func (c *gcsClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	if partNumber > 32 {
		return "", NewInvalidArgument("GCS S3-compatible API limits multipart uploads to 32 parts")
	}
	return c.inner.UploadPart(ctx, bucket, key, uploadID, partNumber, reader, contentLength)
}

func (c *gcsClient) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart, lock *ObjectLockInput) (string, error) {
	return c.inner.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts, lock)
}

// ---- delegated methods ----

func (c *gcsClient) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	return c.inner.DeleteObject(ctx, bucket, key, versionID)
}

func (c *gcsClient) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) (ListResult, error) {
	return c.inner.ListObjects(ctx, bucket, prefix, opts)
}

func (c *gcsClient) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return c.inner.AbortMultipartUpload(ctx, bucket, key, uploadID)
}

func (c *gcsClient) ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error) {
	return c.inner.ListParts(ctx, bucket, key, uploadID)
}

func (c *gcsClient) UploadPartCopy(ctx context.Context, dstBucket, dstKey, uploadID string, partNumber int32, srcBucket, srcKey string, srcVersionID *string, srcRange *CopyPartRange) (*CopyPartResult, error) {
	return c.inner.UploadPartCopy(ctx, dstBucket, dstKey, uploadID, partNumber, srcBucket, srcKey, srcVersionID, srcRange)
}

func (c *gcsClient) DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error) {
	return c.inner.DeleteObjects(ctx, bucket, keys)
}

func (c *gcsClient) PutObjectRetention(ctx context.Context, bucket, key string, versionID *string, retention *RetentionConfig) error {
	return c.inner.PutObjectRetention(ctx, bucket, key, versionID, retention)
}

func (c *gcsClient) GetObjectRetention(ctx context.Context, bucket, key string, versionID *string) (*RetentionConfig, error) {
	return c.inner.GetObjectRetention(ctx, bucket, key, versionID)
}

func (c *gcsClient) PutObjectLegalHold(ctx context.Context, bucket, key string, versionID *string, status string) error {
	return c.inner.PutObjectLegalHold(ctx, bucket, key, versionID, status)
}

func (c *gcsClient) GetObjectLegalHold(ctx context.Context, bucket, key string, versionID *string) (string, error) {
	return c.inner.GetObjectLegalHold(ctx, bucket, key, versionID)
}

func (c *gcsClient) PutObjectLockConfiguration(ctx context.Context, bucket string, config *ObjectLockConfiguration) error {
	return c.inner.PutObjectLockConfiguration(ctx, bucket, config)
}

func (c *gcsClient) GetObjectLockConfiguration(ctx context.Context, bucket string) (*ObjectLockConfiguration, error) {
	return c.inner.GetObjectLockConfiguration(ctx, bucket)
}

// ---- helpers ----

// lowercaseKeys returns a copy of m with all keys lowercased.
func lowercaseKeys(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}
