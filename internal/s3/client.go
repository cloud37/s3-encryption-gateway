package s3

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/debug"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Client is the S3 backend client interface.
type Client interface {
	PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error)
	GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error)
	DeleteObject(ctx context.Context, bucket, key string, versionID *string) error
	HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error)
	ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) (ListResult, error)

	// Multipart upload operations
	CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error)
	UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error)
	CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart, lock *ObjectLockInput) (string, error)
	AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error
	ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error)

	// Copy and batch operations
	CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *ObjectLockInput) (string, map[string]string, error)
	UploadPartCopy(ctx context.Context, dstBucket, dstKey, uploadID string, partNumber int32, srcBucket, srcKey string, srcVersionID *string, srcRange *CopyPartRange) (*CopyPartResult, error)
	DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error)

	// Object Lock operations
	PutObjectRetention(ctx context.Context, bucket, key string, versionID *string, retention *RetentionConfig) error
	GetObjectRetention(ctx context.Context, bucket, key string, versionID *string) (*RetentionConfig, error)
	PutObjectLegalHold(ctx context.Context, bucket, key string, versionID *string, status string) error
	GetObjectLegalHold(ctx context.Context, bucket, key string, versionID *string) (string, error)
	PutObjectLockConfiguration(ctx context.Context, bucket string, config *ObjectLockConfiguration) error
	GetObjectLockConfiguration(ctx context.Context, bucket string) (*ObjectLockConfiguration, error)
}

// ObjectLockInput contains object lock parameters for put/copy operations.
type ObjectLockInput struct {
	Mode            string // "GOVERNANCE" | "COMPLIANCE" | ""
	RetainUntilDate *time.Time
	LegalHoldStatus string // "ON" | "OFF" | ""
}

// RetentionConfig represents the retention configuration for an object.
// XML tags follow the AWS S3 Retention schema so the struct can be
// Unmarshalled from PutObjectRetention request bodies and Marshalled
// into GetObjectRetention response bodies.
type RetentionConfig struct {
	XMLName         xml.Name  `xml:"Retention"`
	Mode            string    `xml:"Mode"`
	RetainUntilDate time.Time `xml:"RetainUntilDate"`
}

// ObjectLockConfiguration represents the object lock configuration for a bucket.
type ObjectLockConfiguration struct {
	XMLName           xml.Name  `xml:"ObjectLockConfiguration"`
	ObjectLockEnabled string    `xml:"ObjectLockEnabled,omitempty"`
	Rule              *LockRule `xml:"Rule,omitempty"`
}

// LockRule represents the default retention rule for a bucket.
type LockRule struct {
	DefaultRetention *DefaultRetention `xml:"DefaultRetention,omitempty"`
}

// DefaultRetention represents the default retention parameters for a bucket.
type DefaultRetention struct {
	Mode  string `xml:"Mode,omitempty"`
	Days  *int32 `xml:"Days,omitempty"`
	Years *int32 `xml:"Years,omitempty"` // exactly one of Days/Years
}

// ListOptions holds options for listing objects.
type ListOptions struct {
	Delimiter         string
	ContinuationToken string
	StartAfter        string
	MaxKeys           int32
}

// ListResult holds the result of a list operation.
type ListResult struct {
	Objects               []ObjectInfo
	CommonPrefixes        []string
	NextContinuationToken string
	IsTruncated           bool
}

// ObjectInfo holds information about an S3 object.
type ObjectInfo struct {
	Key          string
	Size         int64
	LastModified string
	ETag         string
	VersionID    string
}

// CompletedPart represents a completed part in a multipart upload.
type CompletedPart struct {
	PartNumber int32
	ETag       string
}

// PartInfo holds information about an upload part.
type PartInfo struct {
	PartNumber   int32
	ETag         string
	Size         int64
	LastModified string
}

// ObjectIdentifier identifies an object for deletion.
type ObjectIdentifier struct {
	Key       string
	VersionID string
}

// DeletedObject represents a successfully deleted object.
type DeletedObject struct {
	Key          string
	VersionID    string
	DeleteMarker bool
}

// ErrorObject represents an error during batch delete.
type ErrorObject struct {
	Key     string
	Code    string
	Message string
}

// CopyPartRange specifies a byte range for a copy operation.
type CopyPartRange struct {
	First int64
	Last  int64
}

// CopyPartResult holds the result of an UploadPartCopy operation.
type CopyPartResult struct {
	ETag         string
	LastModified time.Time
}

// s3Client implements the Client interface using AWS SDK v2.
type s3Client struct {
	client *s3.Client
	config *config.BackendConfig
	tracer trace.Tracer
}

// ClientFactory creates S3 clients, optionally with per-request credentials.
// V0.6-PERF-2: gains optional retry config (wired via ClientFactoryOption).
type ClientFactory struct {
	baseConfig     *config.BackendConfig
	retryConfig    config.BackendRetryConfig // normalised at construction
	retryerFactory *retryerFactory           // nil → use SDK default
	m              *metrics.Metrics          // nil → no retry metrics
	httpTransport  http.RoundTripper         // nil → use SDK default transport
}

// ClientFactoryOption is a functional option for NewClientFactory.
type ClientFactoryOption func(*ClientFactory)

// WithMetrics configures the factory to emit retry metrics via m.
// Pass nil to disable retry metrics (production default uses the gateway-wide
// Metrics instance).
func WithMetrics(m *metrics.Metrics) ClientFactoryOption {
	return func(f *ClientFactory) {
		f.m = m
	}
}

// WithHTTPTransport replaces the default http.RoundTripper used by the AWS SDK
// for all backend requests.  Use this in tests to inject fault-injection
// transports (e.g. FaultyRoundTripper) at the gateway→backend layer.
// Production code should never call this.
func WithHTTPTransport(rt http.RoundTripper) ClientFactoryOption {
	return func(f *ClientFactory) {
		f.httpTransport = rt
	}
}

// NewClientFactory creates a new client factory from base configuration.
// Functional options may be passed to configure retry metrics and other
// optional dependencies (V0.6-PERF-2 Phase D).
func NewClientFactory(cfg *config.BackendConfig, opts ...ClientFactoryOption) *ClientFactory {
	// Normalise the retry config (fills in defaults for zero values).
	rc := cfg.Retry
	rc.Normalize()

	f := &ClientFactory{
		baseConfig:  cfg,
		retryConfig: rc,
	}
	for _, opt := range opts {
		opt(f)
	}

	// Build the retryer factory if mode != "off".
	if rc.Mode != "off" {
		var onAttempt OnAttemptFn
		var onGiveUp OnGiveUpFn
		if f.m != nil {
			m := f.m // capture for closures
			onAttempt = func(op string, attempt int, reason string, delay time.Duration) {
				m.RecordBackendRetryWithMode(op, reason, rc.Mode)
				m.RecordBackendRetryBackoff(delay)
			}
			onGiveUp = func(op string, attempts int, reason string, _ error) {
				m.RecordBackendAttemptsPerRequest(op, attempts)
				m.RecordBackendRetryGiveUp(op, reason)
			}
		}
		f.retryerFactory = newRetryerFactory(rc, nil, onAttempt, onGiveUp)
	}

	return f
}

// GetClient returns a client using the base configured credentials.
func (f *ClientFactory) GetClient() (Client, error) {
	return f.GetClientWithCredentials(f.baseConfig.AccessKey, f.baseConfig.SecretKey)
}

// GetClientWithCredentials creates a new S3 client with specific credentials.
// Both accessKey and secretKey are required and must not be empty.
func (f *ClientFactory) GetClientWithCredentials(accessKey, secretKey string) (Client, error) {
	// Both credentials are required
	if accessKey == "" {
		return nil, fmt.Errorf("access key is required")
	}
	if secretKey == "" {
		return nil, fmt.Errorf("secret key is required")
	}

	// Use default region if not provided
	region := f.baseConfig.Region
	if region == "" {
		region = "us-east-1" // Default region for AWS SDK compatibility
	}

	// Build the list of aws.Config options.  The retryer is injected here so
	// every client created by this factory uses the gateway-configured retry
	// policy (V0.6-PERF-2 Phase D).
	awsConfigOpts := []func(*awsconfig.LoadOptions) error{
		// Inject a custom HTTP transport if one was supplied (used in tests for
		// fault injection at the gateway→backend layer — WithHTTPTransport).
		func() func(*awsconfig.LoadOptions) error {
			if f.httpTransport != nil {
				return awsconfig.WithHTTPClient(&http.Client{Transport: f.httpTransport})
			}
			return func(*awsconfig.LoadOptions) error { return nil }
		}(),
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKey,
			secretKey,
			"",
		)),
		// Disable automatic payload checksum computation. The gateway forwards
		// unseekable encrypted streams; aws-sdk-go-v2 >= v1.32 defaults to
		// computing a SHA-256 over the body which requires either seekability
		// or `aws-chunked+trailing-checksum` (only available over TLS).
		// Plaintext MinIO backends reject the latter, causing a PutObject /
		// UploadPart failure on any payload larger than the gateway buffers.
		// Use "when required" so the SDK only computes checksums when the
		// target operation mandates them (e.g. legal-hold), and relies on
		// SigV4's payload hash for integrity otherwise.
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		// Disable automatic response checksum validation for parity: MinIO may
		// not always return the x-amz-checksum-* headers the SDK expects.
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	}

	// Install the gateway custom retryer or NopRetryer for mode=off.
	// WithRetryer accepts a factory func so each request context gets a fresh
	// per-operation retry state (per §4.6 of the PERF-2 plan).
	if f.retryConfig.Mode == "off" {
		awsConfigOpts = append(awsConfigOpts, awsconfig.WithRetryer(func() aws.Retryer {
			return newNopRetryerV2()
		}))
	} else if f.retryerFactory != nil {
		rf := f.retryerFactory // capture
		awsConfigOpts = append(awsConfigOpts, awsconfig.WithRetryer(func() aws.Retryer {
			// The SDK calls this factory once per logical operation and uses the
			// returned retryer for all attempts in that operation.
			// We return a clone keyed to the empty operation name here; the SDK
			// does not call WithRetryer per-operation (it reuses the outer aws.Config).
			// The operation name is set on the returned retryer via the per-request
			// context in Phase C.  For now, "PutObject" is the safe fallback.
			return rf.Build("")
		}))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), awsConfigOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Configure S3 client options
	s3Options := []func(*s3.Options){}

	// Set custom endpoint if provided (for any S3-compatible provider)
	if f.baseConfig.Endpoint != "" {
		endpoint := normalizeEndpoint(f.baseConfig.Endpoint)

		// Validate endpoint URL
		if err := validateEndpoint(endpoint); err != nil {
			return nil, fmt.Errorf("invalid endpoint: %w", err)
		}

		s3Options = append(s3Options, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
		awsCfg.BaseEndpoint = aws.String(endpoint)
	}

	// Use path-style addressing if configured or if UseSSL is false (common for local/MinIO)
	if f.baseConfig.UsePathStyle || f.baseConfig.UseSSL == false {
		s3Options = append(s3Options, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Options...)

	return &s3Client{
		client: client,
		config: f.baseConfig,
		tracer: otel.Tracer("s3-encryption-gateway.s3"),
	}, nil
}

// NewClient creates a new S3 backend client (backward compatibility).
// It works with any S3-compatible API provider by configuring the endpoint.
func NewClient(cfg *config.BackendConfig) (Client, error) {
	factory := NewClientFactory(cfg)
	return factory.GetClient()
}

// ErrNotImplemented is returned by shim adapters when a backend does not
// support the requested S3 operation.  Callers should surface this as an
// HTTP NotImplemented (501) response.
var ErrNotImplemented = fmt.Errorf("operation not implemented by backend")

// NewInvalidArgument returns an error suitable for S3 InvalidArgument responses.
func NewInvalidArgument(message string) error {
	return fmt.Errorf("InvalidArgument: %s", message)
}

// NewBackendClient constructs the appropriate backend Client from cfg.
// Callers must not type-assert the returned Client; all behaviour is expressed
// through the Client interface.
//
// Invariants:
//   - Returns a non-nil Client on success.
//   - Returns an error if cfg.Type == "azure" and cfg.Azure.AccountName is empty
//     and cfg.Endpoint is empty.
//   - For "s3" and "gcs" the embedded ClientFactory handles credential
//     validation (access key and secret key must be non-empty).
//   - context.Context is not accepted because client construction is
//     synchronous; it is callers' responsibility to cancel with a deadline.
func NewBackendClient(cfg *config.BackendConfig, opts ...ClientFactoryOption) (Client, error) {
	switch cfg.Type {
	case "", config.BackendTypeS3:
		return NewClientFactory(cfg, opts...).GetClient()
	case config.BackendTypeGCS:
		return newGCSClient(cfg, opts...)
	case config.BackendTypeAzure:
		return newAzureClient(cfg, opts...)
	default:
		return nil, fmt.Errorf("unknown backend type %q", cfg.Type)
	}
}

// normalizeEndpoint normalizes the endpoint URL.
func normalizeEndpoint(endpoint string) string {
	endpoint = strings.TrimSpace(endpoint)

	// Add https:// if no scheme provided
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
	}

	// Remove trailing slash
	endpoint = strings.TrimSuffix(endpoint, "/")

	return endpoint
}

// validateEndpoint validates that an endpoint URL is well-formed.
func validateEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("endpoint must use http:// or https:// scheme")
	}

	if u.Host == "" {
		return fmt.Errorf("endpoint must include a hostname")
	}

	return nil
}

// PutObject uploads an object to S3.
func (c *s3Client) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	ctx, span := c.tracer.Start(ctx, "S3.PutObject",
		trace.WithAttributes(
			attribute.String("s3.bucket", bucket),
			attribute.String("s3.key", key),
		),
	)
	defer span.End()

	// Convert metadata - strip x-amz-meta- prefix as AWS SDK v2 adds it automatically
	// For custom endpoints (Ceph/Hetzner), the SDK should still handle this correctly
	convertedMeta := convertMetadata(metadata)

	// Debug: log critical encryption metadata values being sent to SDK
	// Check both full keys (if compaction didn't happen) and compacted keys
	if debug.Enabled() && len(convertedMeta) > 0 {
		// Try full keys first, then compacted keys
		keyMappings := map[string][]string{
			"salt":    {"encryption-key-salt", "s"},
			"iv":      {"encryption-iv", "i"},
			"algo":    {"encryption-algorithm", "a"},
			"wrapped": {"encryption-wrapped-key", "wk"},
			"kms-id":  {"encryption-kms-id", "kid"},
		}
		for name, keys := range keyMappings {
			for _, ck := range keys {
				if v, ok := convertedMeta[ck]; ok {
					slog.Debug("s3.PutObject metadata", "bucket", bucket, "key", key, "field", name, "len", len(v))
					break // Found it, move to next
				}
			}
		}
	}

	input := &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Body:     reader,
		Metadata: convertedMeta,
	}
	if contentLength != nil {
		input.ContentLength = contentLength
	}
	if tags != "" {
		input.Tagging = aws.String(tags)
	}
	if cannedACL != "" {
		input.ACL = types.ObjectCannedACL(cannedACL)
	}
	if grantFullControl != "" {
		input.GrantFullControl = aws.String(grantFullControl)
	}
	if grantRead != "" {
		input.GrantRead = aws.String(grantRead)
	}
	if grantReadACP != "" {
		input.GrantReadACP = aws.String(grantReadACP)
	}
	if grantWriteACP != "" {
		input.GrantWriteACP = aws.String(grantWriteACP)
	}

	// For non-seekable readers (e.g. streaming chunked encrypted data), the
	// SigV4 ComputePayloadSHA256 middleware would fail because it reads the
	// entire body to hash it then seeks back to the start.  Swap in the
	// UnsignedPayload middleware so the SDK uses "UNSIGNED-PAYLOAD" instead.
	// This is safe for S3-compatible backends (MinIO, Garage, SeaweedFS, etc.)
	// which do not enforce payload hash verification.
	var putOpts []func(*s3.Options)
	if _, seekable := reader.(io.Seeker); !seekable {
		putOpts = append(putOpts, s3.WithAPIOptions(
			v4.SwapComputePayloadSHA256ForUnsignedPayloadMiddleware,
		))
	}

	resp, err := c.client.PutObject(ctx, input, putOpts...)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("failed to put object %s/%s: %w", bucket, key, err)
	}

	span.SetStatus(codes.Ok, "")
	return aws.ToString(resp.ETag), nil
}

// GetObject retrieves an object from S3.
func (c *s3Client) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	ctx, span := c.tracer.Start(ctx, "S3.GetObject",
		trace.WithAttributes(
			attribute.String("s3.bucket", bucket),
			attribute.String("s3.key", key),
		),
	)
	defer span.End()

	input := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}

	if rangeHeader != nil && *rangeHeader != "" {
		input.Range = rangeHeader
	}

	result, err := c.client.GetObject(ctx, input)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return nil, nil, fmt.Errorf("failed to get object %s/%s: %w", bucket, key, err)
	}

	metadata := extractMetadata(result.Metadata)

	// Debug: log critical encryption metadata values for troubleshooting
	// Check both full keys and compacted keys (after expansion)
	if debug.Enabled() && len(metadata) > 0 {
		keyMappings := map[string][]string{
			"salt":    {"x-amz-meta-encryption-key-salt", "x-amz-meta-s"},
			"iv":      {"x-amz-meta-encryption-iv", "x-amz-meta-i"},
			"algo":    {"x-amz-meta-encryption-algorithm", "x-amz-meta-a"},
			"wrapped": {"x-amz-meta-encryption-wrapped-key", "x-amz-meta-wk"},
			"kms-id":  {"x-amz-meta-encryption-kms-id", "x-amz-meta-kid"},
		}
		for name, keys := range keyMappings {
			for _, ck := range keys {
				if v, ok := metadata[ck]; ok {
					slog.Debug("s3.GetObject metadata", "bucket", bucket, "key", key, "field", name, "len", len(v))
					break // Found it, move to next
				}
			}
		}
	}

	if result.VersionId != nil {
		metadata["x-amz-version-id"] = *result.VersionId
	}

	// Extract standard S3 response headers (same as HeadObject)
	if result.ContentLength != nil {
		metadata["Content-Length"] = fmt.Sprintf("%d", *result.ContentLength)
	}
	if result.ContentType != nil {
		metadata["Content-Type"] = *result.ContentType
	}
	if result.ETag != nil {
		metadata["ETag"] = *result.ETag
	}
	if result.LastModified != nil {
		metadata["Last-Modified"] = result.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT")
	}
	if result.AcceptRanges != nil {
		metadata["Accept-Ranges"] = *result.AcceptRanges
	}
	if result.ContentEncoding != nil {
		metadata["Content-Encoding"] = *result.ContentEncoding
	}

	if result.ObjectLockMode != "" {
		metadata["x-amz-object-lock-mode"] = string(result.ObjectLockMode)
	}
	if result.ObjectLockRetainUntilDate != nil {
		metadata["x-amz-object-lock-retain-until-date"] = result.ObjectLockRetainUntilDate.UTC().Format(time.RFC3339)
	}
	if result.ObjectLockLegalHoldStatus != "" {
		metadata["x-amz-object-lock-legal-hold"] = string(result.ObjectLockLegalHoldStatus)
	}

	span.SetStatus(codes.Ok, "")
	return result.Body, metadata, nil
}

// DeleteObject deletes an object from S3.
func (c *s3Client) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	ctx, span := c.tracer.Start(ctx, "S3.DeleteObject",
		trace.WithAttributes(
			attribute.String("s3.bucket", bucket),
			attribute.String("s3.key", key),
		),
	)
	defer span.End()

	input := &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}

	_, err := c.client.DeleteObject(ctx, input)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("failed to delete object %s/%s: %w", bucket, key, err)
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// HeadObject retrieves object metadata without the body.
func (c *s3Client) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}

	result, err := c.client.HeadObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to head object %s/%s: %w", bucket, key, err)
	}

	metadata := extractMetadata(result.Metadata)
	if result.VersionId != nil {
		metadata["x-amz-version-id"] = *result.VersionId
	}
	if result.ContentLength != nil {
		metadata["Content-Length"] = fmt.Sprintf("%d", *result.ContentLength)
	}
	if result.ContentType != nil {
		metadata["Content-Type"] = *result.ContentType
	}
	if result.ETag != nil {
		metadata["ETag"] = *result.ETag
	}
	if result.LastModified != nil {
		metadata["Last-Modified"] = result.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT")
	}

	if result.ObjectLockMode != "" {
		metadata["x-amz-object-lock-mode"] = string(result.ObjectLockMode)
	}
	if result.ObjectLockRetainUntilDate != nil {
		metadata["x-amz-object-lock-retain-until-date"] = result.ObjectLockRetainUntilDate.UTC().Format(time.RFC3339)
	}
	if result.ObjectLockLegalHoldStatus != "" {
		metadata["x-amz-object-lock-legal-hold"] = string(result.ObjectLockLegalHoldStatus)
	}

	return metadata, nil
}

// ListObjects lists objects in a bucket.
func (c *s3Client) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) (ListResult, error) {
	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(prefix),
	}

	if opts.Delimiter != "" {
		input.Delimiter = aws.String(opts.Delimiter)
	}
	if opts.ContinuationToken != "" {
		input.ContinuationToken = aws.String(opts.ContinuationToken)
	}
	if opts.StartAfter != "" {
		input.StartAfter = aws.String(opts.StartAfter)
	}
	if opts.MaxKeys > 0 {
		input.MaxKeys = aws.Int32(opts.MaxKeys)
	}

	result, err := c.client.ListObjectsV2(ctx, input)
	if err != nil {
		return ListResult{}, fmt.Errorf("failed to list objects in bucket %s: %w", bucket, err)
	}

	objects := make([]ObjectInfo, 0, len(result.Contents))
	for _, obj := range result.Contents {
		objects = append(objects, ObjectInfo{
			Key:          aws.ToString(obj.Key),
			Size:         aws.ToInt64(obj.Size),
			LastModified: aws.ToTime(obj.LastModified).Format("2006-01-02T15:04:05.000Z"),
			ETag:         aws.ToString(obj.ETag),
		})
	}

	commonPrefixes := make([]string, 0, len(result.CommonPrefixes))
	for _, cp := range result.CommonPrefixes {
		commonPrefixes = append(commonPrefixes, aws.ToString(cp.Prefix))
	}

	listResult := ListResult{
		Objects:               objects,
		CommonPrefixes:        commonPrefixes,
		NextContinuationToken: aws.ToString(result.NextContinuationToken),
		IsTruncated:           aws.ToBool(result.IsTruncated),
	}

	return listResult, nil
}

// convertMetadata converts our internal metadata map (keys like "x-amz-meta-foo")
// into the format expected by AWS SDK v2: keys WITHOUT the "x-amz-meta-" prefix.
// The SDK adds the prefix automatically when sending the request.
// Passing prefixed keys would produce headers like "x-amz-meta-x-amz-meta-foo",
// which many S3-compatible providers reject with InvalidArgument.
func convertMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}

	const prefix = "x-amz-meta-"
	result := make(map[string]string, len(metadata))
	for k, v := range metadata {
		// Strip the x-amz-meta- prefix if present
		if len(k) > len(prefix) && strings.EqualFold(k[:len(prefix)], prefix) {
			// Preserve the remainder as-is (providers normalize casing)
			result[k[len(prefix):]] = v
			continue
		}
		// For any non-standard keys (should be rare), pass through
		result[k] = v
	}
	return result
}

// extractMetadata extracts metadata from S3 response.
// AWS SDK v2 returns metadata keys WITHOUT the x-amz-meta- prefix (it strips it automatically).
// We add the prefix back for consistency with our internal representation.
func extractMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return make(map[string]string)
	}

	result := make(map[string]string, len(metadata))
	prefix := "x-amz-meta-"

	for k, v := range metadata {
		// Add x-amz-meta- prefix if not already present
		// SDK returns keys without prefix, but we use prefix internally
		// Use case-insensitive comparison as some S3 providers may normalize case
		if len(k) >= len(prefix) && strings.EqualFold(k[:len(prefix)], prefix) {
			// Already has prefix (shouldn't happen from SDK, but be safe)
			// Normalize to lowercase for consistency
			result[strings.ToLower(k)] = v
		} else {
			// Add prefix
			result[prefix+k] = v
		}
	}
	return result
}

// CreateMultipartUpload initiates a multipart upload.
func (c *s3Client) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	input := &s3.CreateMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		Metadata: convertMetadata(metadata),
	}
	if cannedACL != "" {
		input.ACL = types.ObjectCannedACL(cannedACL)
	}
	if grantFullControl != "" {
		input.GrantFullControl = aws.String(grantFullControl)
	}
	if grantRead != "" {
		input.GrantRead = aws.String(grantRead)
	}
	if grantReadACP != "" {
		input.GrantReadACP = aws.String(grantReadACP)
	}
	if grantWriteACP != "" {
		input.GrantWriteACP = aws.String(grantWriteACP)
	}

	result, err := c.client.CreateMultipartUpload(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to create multipart upload %s/%s: %w", bucket, key, err)
	}

	if result.UploadId == nil {
		return "", fmt.Errorf("upload ID not returned from backend")
	}

	return *result.UploadId, nil
}

// UploadPart uploads a part of a multipart upload.
func (c *s3Client) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	input := &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadID),
		PartNumber: aws.Int32(partNumber),
		Body:       reader,
	}

	if contentLength != nil {
		input.ContentLength = contentLength
	}

	result, err := c.client.UploadPart(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to upload part %d for %s/%s: %w", partNumber, bucket, key, err)
	}

	if result.ETag == nil {
		return "", fmt.Errorf("ETag not returned from backend")
	}

	return *result.ETag, nil
}

// CompleteMultipartUpload completes a multipart upload.
func (c *s3Client) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart, lock *ObjectLockInput) (string, error) {
	completedParts := make([]types.CompletedPart, len(parts))
	for i, p := range parts {
		completedParts[i] = types.CompletedPart{
			PartNumber: aws.Int32(p.PartNumber),
			ETag:       aws.String(p.ETag),
		}
	}

	input := &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	}

	result, err := c.client.CompleteMultipartUpload(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to complete multipart upload %s/%s: %w", bucket, key, err)
	}

	if lock != nil {
		if lock.Mode != "" && lock.RetainUntilDate != nil {
			err = c.PutObjectRetention(ctx, bucket, key, nil, &RetentionConfig{
				Mode:            lock.Mode,
				RetainUntilDate: *lock.RetainUntilDate,
			})
			if err != nil {
				return "", err
			}
		}
		if lock.LegalHoldStatus != "" {
			err = c.PutObjectLegalHold(ctx, bucket, key, nil, lock.LegalHoldStatus)
			if err != nil {
				return "", err
			}
		}
	}

	if result.ETag == nil {
		return "", fmt.Errorf("ETag not returned from backend")
	}

	return *result.ETag, nil
}

// AbortMultipartUpload aborts a multipart upload.
func (c *s3Client) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	input := &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	_, err := c.client.AbortMultipartUpload(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to abort multipart upload %s/%s: %w", bucket, key, err)
	}

	return nil
}

// ListParts lists the parts of a multipart upload.
func (c *s3Client) ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error) {
	input := &s3.ListPartsInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadID),
	}

	result, err := c.client.ListParts(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to list parts for %s/%s: %w", bucket, key, err)
	}

	parts := make([]PartInfo, 0, len(result.Parts))
	for _, p := range result.Parts {
		part := PartInfo{
			PartNumber: aws.ToInt32(p.PartNumber),
			ETag:       aws.ToString(p.ETag),
			Size:       aws.ToInt64(p.Size),
		}
		if p.LastModified != nil {
			part.LastModified = p.LastModified.Format("2006-01-02T15:04:05.000Z")
		}
		parts = append(parts, part)
	}

	return parts, nil
}

// CopyObject copies an object from source to destination.
func (c *s3Client) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *ObjectLockInput) (string, map[string]string, error) {
	copySource := fmt.Sprintf("%s/%s", srcBucket, srcKey)
	if srcVersionID != nil && *srcVersionID != "" {
		copySource = fmt.Sprintf("%s/%s?versionId=%s", srcBucket, srcKey, *srcVersionID)
	}

	input := &s3.CopyObjectInput{
		Bucket:     aws.String(dstBucket),
		Key:        aws.String(dstKey),
		CopySource: aws.String(copySource),
		Metadata:   convertMetadata(metadata),
	}
	if lock != nil {
		if lock.Mode != "" {
			input.ObjectLockMode = types.ObjectLockMode(lock.Mode)
		}
		if lock.RetainUntilDate != nil {
			input.ObjectLockRetainUntilDate = lock.RetainUntilDate
		}
		if lock.LegalHoldStatus != "" {
			input.ObjectLockLegalHoldStatus = types.ObjectLockLegalHoldStatus(lock.LegalHoldStatus)
		}
	}

	result, err := c.client.CopyObject(ctx, input)
	if err != nil {
		return "", nil, fmt.Errorf("failed to copy object from %s/%s to %s/%s: %w", srcBucket, srcKey, dstBucket, dstKey, err)
	}

	resultMetadata := make(map[string]string)
	if result.CopyObjectResult != nil {
		if result.CopyObjectResult.ETag != nil {
			resultMetadata["ETag"] = strings.Trim(*result.CopyObjectResult.ETag, "\"")
		}
		if result.CopyObjectResult.LastModified != nil {
			resultMetadata["Last-Modified"] = result.CopyObjectResult.LastModified.Format("Mon, 02 Jan 2006 15:04:05 GMT")
		}
	}

	etag := ""
	if result.CopyObjectResult != nil && result.CopyObjectResult.ETag != nil {
		etag = strings.Trim(*result.CopyObjectResult.ETag, "\"")
	}

	return etag, resultMetadata, nil
}

// UploadPartCopy copies a byte range from a source object to a part in a multipart upload.
func (c *s3Client) UploadPartCopy(ctx context.Context, dstBucket, dstKey, uploadID string, partNumber int32, srcBucket, srcKey string, srcVersionID *string, srcRange *CopyPartRange) (*CopyPartResult, error) {
	copySource := fmt.Sprintf("%s/%s", srcBucket, srcKey)
	if srcVersionID != nil && *srcVersionID != "" {
		copySource = fmt.Sprintf("%s/%s?versionId=%s", srcBucket, srcKey, *srcVersionID)
	}

	input := &s3.UploadPartCopyInput{
		Bucket:     aws.String(dstBucket),
		Key:        aws.String(dstKey),
		CopySource: aws.String(copySource),
		PartNumber: aws.Int32(partNumber),
		UploadId:   aws.String(uploadID),
	}

	// Set copy range if provided
	if srcRange != nil {
		rangeStr := fmt.Sprintf("bytes=%d-%d", srcRange.First, srcRange.Last)
		input.CopySourceRange = aws.String(rangeStr)
	}

	result, err := c.client.UploadPartCopy(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to copy object part from %s/%s to %s/%s: %w", srcBucket, srcKey, dstBucket, dstKey, err)
	}

	if result.CopyPartResult == nil {
		return nil, fmt.Errorf("unexpected nil CopyPartResult from S3")
	}

	etag := ""
	lastModified := time.Now() // Default to now; backend should provide this
	if result.CopyPartResult.ETag != nil {
		// Preserve quoting: AWS UploadPartCopy returns quoted ETags, and
		// CompleteMultipartUpload expects the same. Stripping here produced
		// an unquoted ETag that MinIO rejected as "Invalid ETag format".
		etag = *result.CopyPartResult.ETag
		// Ensure the ETag is quoted (some backends normalise differently).
		if len(etag) >= 2 && (etag[0] != '"' || etag[len(etag)-1] != '"') {
			etag = "\"" + strings.Trim(etag, "\"") + "\""
		}
	}
	if result.CopyPartResult.LastModified != nil {
		lastModified = *result.CopyPartResult.LastModified
	}

	return &CopyPartResult{
		ETag:         etag,
		LastModified: lastModified,
	}, nil
}

// DeleteObjects deletes multiple objects in a single request.
func (c *s3Client) DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error) {
	objects := make([]types.ObjectIdentifier, len(keys))
	for i, k := range keys {
		obj := types.ObjectIdentifier{
			Key: aws.String(k.Key),
		}
		if k.VersionID != "" {
			obj.VersionId = aws.String(k.VersionID)
		}
		objects[i] = obj
	}

	input := &s3.DeleteObjectsInput{
		Bucket: aws.String(bucket),
		Delete: &types.Delete{
			Objects: objects,
			Quiet:   aws.Bool(false), // Return both deleted and errors
		},
	}

	// MinIO (and many other S3-compatible backends on the 2024-era branch)
	// require Content-MD5 on the multi-delete payload. AWS SDK v2 no longer
	// auto-computes Content-MD5 since it moved to the x-amz-checksum-* family;
	// supply a finalize-stage middleware that reads the serialised body, hashes
	// it and injects the Content-MD5 header. This is a no-op against AWS
	// (AWS also accepts the header) and required against MinIO/Garage/RustFS
	// pinned to the conformance matrix tags.
	// See: https://github.com/aws/aws-sdk-go-v2/issues/2633
	result, err := c.client.DeleteObjects(ctx, input,
		func(o *s3.Options) {
			o.APIOptions = append(o.APIOptions, addContentMD5Middleware)
		})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to delete objects in bucket %s: %w", bucket, err)
	}

	deleted := make([]DeletedObject, 0, len(result.Deleted))
	for _, d := range result.Deleted {
		deletedObj := DeletedObject{
			Key: aws.ToString(d.Key),
		}
		if d.VersionId != nil {
			deletedObj.VersionID = *d.VersionId
		}
		if d.DeleteMarker != nil {
			deletedObj.DeleteMarker = *d.DeleteMarker
		}
		deleted = append(deleted, deletedObj)
	}

	errors := make([]ErrorObject, 0, len(result.Errors))
	for _, e := range result.Errors {
		errorObj := ErrorObject{
			Key: aws.ToString(e.Key),
		}
		if e.Code != nil {
			errorObj.Code = *e.Code
		}
		if e.Message != nil {
			errorObj.Message = *e.Message
		}
		errors = append(errors, errorObj)
	}

	return deleted, errors, nil
}

// PutObjectRetention sets the retention configuration for an object.
func (c *s3Client) PutObjectRetention(ctx context.Context, bucket, key string, versionID *string, retention *RetentionConfig) error {
	input := &s3.PutObjectRetentionInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}
	if retention != nil {
		input.Retention = &types.ObjectLockRetention{
			Mode:            types.ObjectLockRetentionMode(retention.Mode),
			RetainUntilDate: &retention.RetainUntilDate,
		}
	}
	_, err := c.client.PutObjectRetention(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put object retention %s/%s: %w", bucket, key, err)
	}
	return nil
}

// GetObjectRetention gets the retention configuration for an object.
func (c *s3Client) GetObjectRetention(ctx context.Context, bucket, key string, versionID *string) (*RetentionConfig, error) {
	input := &s3.GetObjectRetentionInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}
	result, err := c.client.GetObjectRetention(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object retention %s/%s: %w", bucket, key, err)
	}
	if result.Retention == nil {
		return nil, nil
	}
	return &RetentionConfig{
		Mode:            string(result.Retention.Mode),
		RetainUntilDate: *result.Retention.RetainUntilDate,
	}, nil
}

// PutObjectLegalHold sets the legal hold status for an object.
func (c *s3Client) PutObjectLegalHold(ctx context.Context, bucket, key string, versionID *string, status string) error {
	input := &s3.PutObjectLegalHoldInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}
	input.LegalHold = &types.ObjectLockLegalHold{
		Status: types.ObjectLockLegalHoldStatus(status),
	}
	_, err := c.client.PutObjectLegalHold(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put object legal hold %s/%s: %w", bucket, key, err)
	}
	return nil
}

// GetObjectLegalHold gets the legal hold status for an object.
func (c *s3Client) GetObjectLegalHold(ctx context.Context, bucket, key string, versionID *string) (string, error) {
	input := &s3.GetObjectLegalHoldInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}
	if versionID != nil && *versionID != "" {
		input.VersionId = versionID
	}
	result, err := c.client.GetObjectLegalHold(ctx, input)
	if err != nil {
		return "", fmt.Errorf("failed to get object legal hold %s/%s: %w", bucket, key, err)
	}
	if result.LegalHold == nil {
		return "", nil
	}
	return string(result.LegalHold.Status), nil
}

// PutObjectLockConfiguration sets the object lock configuration for a bucket.
func (c *s3Client) PutObjectLockConfiguration(ctx context.Context, bucket string, config *ObjectLockConfiguration) error {
	input := &s3.PutObjectLockConfigurationInput{
		Bucket: aws.String(bucket),
	}
	if config != nil {
		cfg := &types.ObjectLockConfiguration{
			ObjectLockEnabled: types.ObjectLockEnabled(config.ObjectLockEnabled),
		}
		if config.Rule != nil && config.Rule.DefaultRetention != nil {
			cfg.Rule = &types.ObjectLockRule{
				DefaultRetention: &types.DefaultRetention{
					Mode: types.ObjectLockRetentionMode(config.Rule.DefaultRetention.Mode),
				},
			}
			if config.Rule.DefaultRetention.Days != nil {
				cfg.Rule.DefaultRetention.Days = config.Rule.DefaultRetention.Days
			}
			if config.Rule.DefaultRetention.Years != nil {
				cfg.Rule.DefaultRetention.Years = config.Rule.DefaultRetention.Years
			}
		}
		input.ObjectLockConfiguration = cfg
	}
	_, err := c.client.PutObjectLockConfiguration(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to put object lock configuration for bucket %s: %w", bucket, err)
	}
	return nil
}

// GetObjectLockConfiguration gets the object lock configuration for a bucket.
func (c *s3Client) GetObjectLockConfiguration(ctx context.Context, bucket string) (*ObjectLockConfiguration, error) {
	input := &s3.GetObjectLockConfigurationInput{
		Bucket: aws.String(bucket),
	}
	result, err := c.client.GetObjectLockConfiguration(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get object lock configuration for bucket %s: %w", bucket, err)
	}
	if result.ObjectLockConfiguration == nil {
		return nil, nil
	}
	cfg := &ObjectLockConfiguration{
		ObjectLockEnabled: string(result.ObjectLockConfiguration.ObjectLockEnabled),
	}
	if result.ObjectLockConfiguration.Rule != nil && result.ObjectLockConfiguration.Rule.DefaultRetention != nil {
		cfg.Rule = &LockRule{
			DefaultRetention: &DefaultRetention{
				Mode: string(result.ObjectLockConfiguration.Rule.DefaultRetention.Mode),
			},
		}
		if result.ObjectLockConfiguration.Rule.DefaultRetention.Days != nil {
			cfg.Rule.DefaultRetention.Days = result.ObjectLockConfiguration.Rule.DefaultRetention.Days
		}
		if result.ObjectLockConfiguration.Rule.DefaultRetention.Years != nil {
			cfg.Rule.DefaultRetention.Years = result.ObjectLockConfiguration.Rule.DefaultRetention.Years
		}
	}
	return cfg, nil
}

// addContentMD5Middleware registers a finalize-stage smithy middleware that
// computes the MD5 digest of the request body and sets the Content-MD5 header.
// Used for DeleteObjects against S3-compatible backends that still require the
// legacy Content-MD5 integrity header (AWS SDK v2 migrated to x-amz-checksum-*
// and no longer auto-computes Content-MD5; MinIO pinned to 2024-11-07 and
// many other backends in that era only validate Content-MD5).
//
// This is idempotent — if Content-MD5 is already set (e.g. by another
// middleware), the existing value is preserved.
func addContentMD5Middleware(stack *middleware.Stack) error {
	return stack.Finalize.Add(middleware.FinalizeMiddlewareFunc("AddContentMD5",
		func(ctx context.Context, in middleware.FinalizeInput, next middleware.FinalizeHandler) (middleware.FinalizeOutput, middleware.Metadata, error) {
			req, ok := in.Request.(*smithyhttp.Request)
			if !ok {
				return next.HandleFinalize(ctx, in)
			}
			if req.Header.Get("Content-Md5") != "" || req.Header.Get("Content-MD5") != "" {
				return next.HandleFinalize(ctx, in)
			}
			stream := req.GetStream()
			if stream == nil {
				return next.HandleFinalize(ctx, in)
			}
			body, err := io.ReadAll(stream)
			if err != nil {
				return middleware.FinalizeOutput{}, middleware.Metadata{},
					fmt.Errorf("addContentMD5Middleware: read body: %w", err)
			}
			sum := md5.Sum(body)
			req.Header.Set("Content-Md5", base64.StdEncoding.EncodeToString(sum[:]))
			// Restore a seekable body so the SDK can sign and send it.
			if err := req.RewindStream(); err != nil {
				// Stream not seekable — rewind by replacing the stream.
				reqCopy, err := req.SetStream(newBytesReader(body))
				if err != nil {
					return middleware.FinalizeOutput{}, middleware.Metadata{},
						fmt.Errorf("addContentMD5Middleware: set stream: %w", err)
				}
				in.Request = reqCopy
			}
			return next.HandleFinalize(ctx, in)
		}), middleware.Before)
}

// bytesReader is a minimal seekable reader for the middleware above.
type bytesReader struct {
	b   []byte
	pos int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{b: b} }

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

func (r *bytesReader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = int64(r.pos) + offset
	case io.SeekEnd:
		abs = int64(len(r.b)) + offset
	default:
		return 0, fmt.Errorf("bytesReader.Seek: invalid whence")
	}
	if abs < 0 {
		return 0, fmt.Errorf("bytesReader.Seek: negative position")
	}
	r.pos = int(abs)
	return abs, nil
}

func (r *bytesReader) Close() error { return nil }

// http package is imported indirectly via smithyhttp; keep the unused import
// reference so go-lint does not prune it if the middleware becomes a no-op.
var _ = http.MethodPut
