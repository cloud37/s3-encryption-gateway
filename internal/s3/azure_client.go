package s3

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

// azureClient wraps a Client and applies Azure Blob Storage S3-compatible
// API normalisation.
//
// Azure Blob's S3-compatible API has the following known differences:
//   - Aggregate user metadata is limited to 8 KiB per blob.
//   - Metadata keys may only contain alphanumeric characters, underscore (_),
//     dollar sign ($), and period (.).
//   - Error code "BlobNotFound" should be mapped to S3 "NoSuchKey".
//   - Object Lock operations are not supported.
type azureClient struct {
	inner Client
}

// azureMaxMetadataBytes is the maximum aggregate size of user-defined metadata
// key-value pairs for Azure Blob Storage (8 KiB).
const azureMaxMetadataBytes = 8192

// azureMetadataKeyRe matches valid Azure metadata key characters.
var azureMetadataKeyRe = regexp.MustCompile(`^[a-zA-Z0-9_$.]+$`)

// newAzureClient constructs an Azure Blob S3-compatible shim.
// The endpoint is assembled from cfg.Azure.AccountName if cfg.Endpoint is empty.
func newAzureClient(cfg *config.BackendConfig, opts ...ClientFactoryOption) (Client, error) {
	cfgCopy := *cfg
	if cfgCopy.Endpoint == "" && cfgCopy.Azure.AccountName != "" {
		cfgCopy.Endpoint = fmt.Sprintf("https://%s.blob.core.windows.net", cfgCopy.Azure.AccountName)
	}
	cfgCopy.Type = config.BackendTypeS3 // force inner client to use default S3 path

	inner, err := NewClientFactory(&cfgCopy, opts...).GetClient()
	if err != nil {
		return nil, fmt.Errorf("azure: construct inner client: %w", err)
	}
	return &azureClient{inner: inner}, nil
}

// ---- overrides ----

func (c *azureClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	if err := validateAzureMetadata(metadata); err != nil {
		return "", err
	}
	return c.inner.PutObject(ctx, bucket, key, reader, metadata, contentLength, tags, lock, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
}

func (c *azureClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	body, meta, err := c.inner.GetObject(ctx, bucket, key, versionID, rangeHeader)
	if err != nil {
		err = mapAzureError(err)
		return body, meta, err
	}
	return body, meta, nil
}

func (c *azureClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	meta, err := c.inner.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		return meta, mapAzureError(err)
	}
	return meta, nil
}

// ---- Object Lock - all return NotImplemented ----

func (c *azureClient) PutObjectRetention(ctx context.Context, bucket, key string, versionID *string, retention *RetentionConfig) error {
	return fmt.Errorf("Azure Blob Storage does not support S3 Object Lock: %w", ErrNotImplemented)
}

func (c *azureClient) GetObjectRetention(ctx context.Context, bucket, key string, versionID *string) (*RetentionConfig, error) {
	return nil, fmt.Errorf("Azure Blob Storage does not support S3 Object Lock: %w", ErrNotImplemented)
}

func (c *azureClient) PutObjectLegalHold(ctx context.Context, bucket, key string, versionID *string, status string) error {
	return fmt.Errorf("Azure Blob Storage does not support S3 Object Lock: %w", ErrNotImplemented)
}

func (c *azureClient) GetObjectLegalHold(ctx context.Context, bucket, key string, versionID *string) (string, error) {
	return "", fmt.Errorf("Azure Blob Storage does not support S3 Object Lock: %w", ErrNotImplemented)
}

func (c *azureClient) PutObjectLockConfiguration(ctx context.Context, bucket string, config *ObjectLockConfiguration) error {
	return fmt.Errorf("Azure Blob Storage does not support S3 Object Lock: %w", ErrNotImplemented)
}

func (c *azureClient) GetObjectLockConfiguration(ctx context.Context, bucket string) (*ObjectLockConfiguration, error) {
	return nil, fmt.Errorf("Azure Blob Storage does not support S3 Object Lock: %w", ErrNotImplemented)
}

// ---- delegated methods ----

func (c *azureClient) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	return c.inner.DeleteObject(ctx, bucket, key, versionID)
}

func (c *azureClient) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) (ListResult, error) {
	return c.inner.ListObjects(ctx, bucket, prefix, opts)
}

func (c *azureClient) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	return c.inner.CreateMultipartUpload(ctx, bucket, key, metadata, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
}

func (c *azureClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	return c.inner.UploadPart(ctx, bucket, key, uploadID, partNumber, reader, contentLength)
}

func (c *azureClient) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart, lock *ObjectLockInput) (string, error) {
	return c.inner.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts, lock)
}

func (c *azureClient) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return c.inner.AbortMultipartUpload(ctx, bucket, key, uploadID)
}

func (c *azureClient) ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error) {
	return c.inner.ListParts(ctx, bucket, key, uploadID)
}

func (c *azureClient) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *ObjectLockInput) (string, map[string]string, error) {
	return c.inner.CopyObject(ctx, dstBucket, dstKey, srcBucket, srcKey, srcVersionID, metadata, lock)
}

func (c *azureClient) UploadPartCopy(ctx context.Context, dstBucket, dstKey, uploadID string, partNumber int32, srcBucket, srcKey string, srcVersionID *string, srcRange *CopyPartRange) (*CopyPartResult, error) {
	return c.inner.UploadPartCopy(ctx, dstBucket, dstKey, uploadID, partNumber, srcBucket, srcKey, srcVersionID, srcRange)
}

func (c *azureClient) DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error) {
	return c.inner.DeleteObjects(ctx, bucket, keys)
}

// ---- helpers ----

// validateAzureMetadata checks that the aggregate metadata size does not exceed
// azureMaxMetadataBytes and that all keys contain only valid characters.
func validateAzureMetadata(metadata map[string]string) error {
	if len(metadata) == 0 {
		return nil
	}
	var total int
	for k, v := range metadata {
		if !azureMetadataKeyRe.MatchString(k) {
			return NewInvalidArgument(fmt.Sprintf("Azure metadata key %q contains invalid characters; only alphanumeric, underscore, dollar sign, and period are allowed", k))
		}
		total += len(k) + len(v)
	}
	if total > azureMaxMetadataBytes {
		return NewInvalidArgument(fmt.Sprintf("aggregate Azure metadata size (%d bytes) exceeds the 8 KiB limit", total))
	}
	return nil
}

// mapAzureError translates Azure-specific error codes to their S3 equivalents.
func mapAzureError(err error) error {
	if err == nil {
		return nil
	}
	// Azure Blob Storage returns "BlobNotFound" as the error code when a
	// blob does not exist.  Map this to the standard S3 NoSuchKey sentinel.
	// The exact error format depends on the SDK version; we check for the
	// substring since the smithy error code may appear in the message.
	if strings.Contains(err.Error(), "BlobNotFound") {
		return fmt.Errorf("NoSuchKey: %w", err)
	}
	return err
}
