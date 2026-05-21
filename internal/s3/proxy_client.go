package s3

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
)

// ProxyClient forwards HTTP requests to the backend with original headers intact.
// This is used when useClientCredentials is enabled and we receive Signature V4 requests,
// where the secret key is not available but the request is already signed.
type ProxyClient struct {
	backendURL *url.URL
	httpClient *http.Client
	config     *config.BackendConfig
}

// NewProxyClient creates a new proxy client that forwards requests to the backend.
func NewProxyClient(cfg *config.BackendConfig) (*ProxyClient, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		return nil, fmt.Errorf("backend endpoint is required")
	}

	backendURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid backend endpoint: %w", err)
	}

	// Normalize endpoint
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		endpoint = "https://" + endpoint
		backendURL, err = url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to parse normalized endpoint: %w", err)
		}
	}

	return &ProxyClient{
		backendURL: backendURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				// V1.0-SEC-F6: Enforce minimum TLS 1.2 and restricted cipher
				// suites consistent with the main S3 client and Cosmian KMS
				// client. The bare &http.Client{} default uses Go's
				// http.DefaultTransport which has no cipher restrictions.
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
					},
					CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
				},
				IdleConnTimeout:       90 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
				MaxIdleConnsPerHost:   10,
			},
		},
		config: cfg,
	}, nil
}

// ForwardRequest forwards an HTTP request to the backend, preserving original headers.
func (p *ProxyClient) ForwardRequest(ctx context.Context, originalReq *http.Request, method, bucket, key string, body io.Reader) (*http.Response, error) {
	// Build backend URL
	backendPath := fmt.Sprintf("/%s", bucket)
	if key != "" {
		backendPath = fmt.Sprintf("/%s/%s", bucket, key)
	}

	backendURL := &url.URL{
		Scheme:   p.backendURL.Scheme,
		Host:     p.backendURL.Host,
		Path:     backendPath,
		RawQuery: originalReq.URL.RawQuery, // Preserve query parameters
	}

	// Create request to backend
	req, err := http.NewRequestWithContext(ctx, method, backendURL.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend request: %w", err)
	}

	// Copy headers from original request (including Authorization)
	for k, v := range originalReq.Header {
		// Skip Host header - we'll set it to backend
		if strings.EqualFold(k, "Host") {
			continue
		}
		// Copy all other headers including Authorization
		req.Header[k] = v
	}

	// Set Host header to backend
	req.Host = backendURL.Host

	// Make request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to forward request to backend: %w", err)
	}

	return resp, nil
}

// PutObject forwards a PUT request to the backend.
func (p *ProxyClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput) error {
	return fmt.Errorf("ProxyClient.PutObject not implemented - use ForwardRequest in handler")
}

// GetObject forwards a GET request to the backend.
func (p *ProxyClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	return nil, nil, fmt.Errorf("ProxyClient.GetObject not implemented - use ForwardRequest in handler")
}

// DeleteObject forwards a DELETE request to the backend.
func (p *ProxyClient) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	return fmt.Errorf("ProxyClient.DeleteObject not implemented - use ForwardRequest in handler")
}

// HeadObject forwards a HEAD request to the backend.
func (p *ProxyClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	return nil, fmt.Errorf("ProxyClient.HeadObject not implemented - use ForwardRequest in handler")
}

// ListObjects forwards a LIST request to the backend.
func (p *ProxyClient) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error) {
	return nil, fmt.Errorf("ProxyClient.ListObjects not implemented - use ForwardRequest in handler")
}

// CreateMultipartUpload is not implemented
func (p *ProxyClient) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	return "", fmt.Errorf("ProxyClient.CreateMultipartUpload not implemented")
}

// UploadPart is not implemented
func (p *ProxyClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	return "", fmt.Errorf("ProxyClient.UploadPart not implemented")
}

// CompleteMultipartUpload is not implemented
func (p *ProxyClient) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []CompletedPart, lock *ObjectLockInput) (string, error) {
	return "", fmt.Errorf("ProxyClient.CompleteMultipartUpload not implemented")
}

// AbortMultipartUpload is not implemented
func (p *ProxyClient) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return fmt.Errorf("ProxyClient.AbortMultipartUpload not implemented")
}

// ListParts is not implemented
func (p *ProxyClient) ListParts(ctx context.Context, bucket, key, uploadID string) ([]PartInfo, error) {
	return nil, fmt.Errorf("ProxyClient.ListParts not implemented")
}

// CopyObject forwards a PUT request with x-amz-copy-source to the backend for a copy operation.
func (p *ProxyClient) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *ObjectLockInput) (string, map[string]string, error) {
	// Build copy source header
	copySource := fmt.Sprintf("%s/%s", srcBucket, srcKey)
	if srcVersionID != nil && *srcVersionID != "" {
		copySource = fmt.Sprintf("%s/%s?versionId=%s", srcBucket, srcKey, *srcVersionID)
	}

	// Build backend URL for destination
	backendPath := fmt.Sprintf("/%s/%s", dstBucket, dstKey)
	backendURL := &url.URL{
		Scheme: p.backendURL.Scheme,
		Host:   p.backendURL.Host,
		Path:   backendPath,
	}

	// Create PUT request with x-amz-copy-source header
	req, err := http.NewRequestWithContext(ctx, "PUT", backendURL.String(), nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create backend request: %w", err)
	}

	req.Header.Set("x-amz-copy-source", copySource)

	// Add metadata headers if provided
	for k, v := range metadata {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			req.Header.Set(k, v)
		}
	}

	// Make request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to forward copy request to backend: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode >= 400 {
		// V1.0-SEC-F5: Truncate the response body to avoid embedding
		// unbounded backend internals into error strings that propagate
		// to application logs. 1 KiB is enough for a useful status
		// message without leaking stack traces or infrastructure details.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}

	// Parse CopyObjectResult XML
	type CopyObjectResultXML struct {
		XMLName      xml.Name `xml:"CopyObjectResult"`
		ETag         string   `xml:"ETag"`
		LastModified string   `xml:"LastModified"`
	}

	var result CopyObjectResultXML
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", nil, fmt.Errorf("failed to parse copy object result: %w", err)
	}

	// Clean ETag by removing quotes
	etag := strings.Trim(result.ETag, "\"")

	// Build response metadata
	respMetadata := make(map[string]string)
	respMetadata["ETag"] = etag
	if result.LastModified != "" {
		respMetadata["Last-Modified"] = result.LastModified
	}

	return etag, respMetadata, nil
}

// UploadPartCopy forwards a PUT request with x-amz-copy-source for a multipart copy operation.
func (p *ProxyClient) UploadPartCopy(ctx context.Context, dstBucket, dstKey, uploadID string, partNumber int32, srcBucket, srcKey string, srcVersionID *string, srcRange *CopyPartRange) (*CopyPartResult, error) {
	// Build copy source header
	copySource := fmt.Sprintf("%s/%s", srcBucket, srcKey)
	if srcVersionID != nil && *srcVersionID != "" {
		copySource = fmt.Sprintf("%s/%s?versionId=%s", srcBucket, srcKey, *srcVersionID)
	}

	// Build backend URL for destination with multipart query params
	backendPath := fmt.Sprintf("/%s/%s", dstBucket, dstKey)
	backendQuery := fmt.Sprintf("partNumber=%d&uploadId=%s", partNumber, uploadID)
	backendURL := &url.URL{
		Scheme:   p.backendURL.Scheme,
		Host:     p.backendURL.Host,
		Path:     backendPath,
		RawQuery: backendQuery,
	}

	// Create PUT request with x-amz-copy-source header
	req, err := http.NewRequestWithContext(ctx, "PUT", backendURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create backend request: %w", err)
	}

	req.Header.Set("x-amz-copy-source", copySource)

	// Add copy source range if provided
	if srcRange != nil {
		rangeHeader := fmt.Sprintf("bytes=%d-%d", srcRange.First, srcRange.Last)
		req.Header.Set("x-amz-copy-source-range", rangeHeader)
	}

	// Make request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to forward upload part copy request to backend: %w", err)
	}
	defer resp.Body.Close()

	// Check for errors
	if resp.StatusCode >= 400 {
		// V1.0-SEC-F5: Truncate the response body to avoid embedding
		// unbounded backend internals into error strings that propagate
		// to application logs. 1 KiB is enough for a useful status
		// message without leaking stack traces or infrastructure details.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("backend returned %d: %s", resp.StatusCode, string(body))
	}

	// Parse CopyPartResult XML
	type CopyPartResultXML struct {
		XMLName      xml.Name `xml:"CopyPartResult"`
		ETag         string   `xml:"ETag"`
		LastModified string   `xml:"LastModified"`
	}

	var result CopyPartResultXML
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse upload part copy result: %w", err)
	}

	// Clean ETag by removing quotes
	etag := strings.Trim(result.ETag, "\"")

	// Parse LastModified timestamp
	lastModified := time.Now() // Default to now
	if result.LastModified != "" {
		// Try to parse the timestamp from backend response
		if parsed, err := time.Parse(time.RFC3339Nano, result.LastModified); err == nil {
			lastModified = parsed
		}
	}

	return &CopyPartResult{
		ETag:         etag,
		LastModified: lastModified,
	}, nil
}

// DeleteObjects is not implemented
func (p *ProxyClient) DeleteObjects(ctx context.Context, bucket string, keys []ObjectIdentifier) ([]DeletedObject, []ErrorObject, error) {
	return nil, nil, fmt.Errorf("ProxyClient.DeleteObjects not implemented")
}

// PutObjectRetention is not implemented
func (p *ProxyClient) PutObjectRetention(ctx context.Context, bucket, key string, versionID *string, retention *RetentionConfig) error {
	return fmt.Errorf("ProxyClient.PutObjectRetention not implemented - use ForwardRequest in handler")
}

// GetObjectRetention is not implemented
func (p *ProxyClient) GetObjectRetention(ctx context.Context, bucket, key string, versionID *string) (*RetentionConfig, error) {
	return nil, fmt.Errorf("ProxyClient.GetObjectRetention not implemented - use ForwardRequest in handler")
}

// PutObjectLegalHold is not implemented
func (p *ProxyClient) PutObjectLegalHold(ctx context.Context, bucket, key string, versionID *string, status string) error {
	return fmt.Errorf("ProxyClient.PutObjectLegalHold not implemented - use ForwardRequest in handler")
}

// GetObjectLegalHold is not implemented
func (p *ProxyClient) GetObjectLegalHold(ctx context.Context, bucket, key string, versionID *string) (string, error) {
	return "", fmt.Errorf("ProxyClient.GetObjectLegalHold not implemented - use ForwardRequest in handler")
}

// PutObjectLockConfiguration is not implemented
func (p *ProxyClient) PutObjectLockConfiguration(ctx context.Context, bucket string, config *ObjectLockConfiguration) error {
	return fmt.Errorf("ProxyClient.PutObjectLockConfiguration not implemented - use ForwardRequest in handler")
}

// GetObjectLockConfiguration is not implemented
func (p *ProxyClient) GetObjectLockConfiguration(ctx context.Context, bucket string) (*ObjectLockConfiguration, error) {
	return nil, fmt.Errorf("ProxyClient.GetObjectLockConfiguration not implemented - use ForwardRequest in handler")
}
