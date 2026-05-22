package api

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/cloud37/s3-encryption-gateway/internal/util"
)

// ipExtractor is the shared IP extractor instance configured with trusted proxies.
// It is set during server initialization via SetIPExtractor.
var ipExtractor atomic.Pointer[util.IPExtractor]

// SetIPExtractor sets the global IP extractor instance.
// This should be called once during server initialization.
func SetIPExtractor(extractor *util.IPExtractor) {
	ipExtractor.Store(extractor)
}

// getClientIP extracts the client IP address from the request.
// If an IP extractor is configured, it uses trusted proxy-aware extraction.
// Otherwise, falls back to the legacy behavior.
func getClientIP(r *http.Request) string {
	if ext := ipExtractor.Load(); ext != nil {
		return ext.GetClientIP(r)
	}

	// Fallback: use RemoteAddr directly (fail-safe)
	return util.ExtractIP(r.RemoteAddr)
}

// getRequestID extracts or generates a request ID from the request.
func getRequestID(r *http.Request) string {
	// Check for existing request ID header
	if rid := r.Header.Get("X-Request-ID"); rid != "" {
		return rid
	}

	// Could generate a new one, but for now return empty if not present
	return ""
}

// validateTags validates the x-amz-tagging header value.
// Format: URL-encoded key=value pairs, separated by &
// Limits: max 10 tags, key len 128, value len 256, specific charset
func validateTags(tagging string) error {
	if tagging == "" {
		return nil
	}

	tags, err := url.ParseQuery(tagging)
	if err != nil {
		return fmt.Errorf("invalid tagging format: %w", err)
	}

	// Count total tags (keys)
	if len(tags) > 10 {
		return fmt.Errorf("too many tags: max 10 allowed")
	}

	for k, vs := range tags {
		if len(k) > 128 {
			return fmt.Errorf("tag key too long: %s", k)
		}
		// Validate charset for key
		if !isValidTagChars(k) {
			return fmt.Errorf("invalid characters in tag key: %s", k)
		}

		for _, v := range vs {
			if len(v) > 256 {
				return fmt.Errorf("tag value too long: %s", v)
			}
			// Validate charset for value
			if !isValidTagChars(v) {
				return fmt.Errorf("invalid characters in tag value: %s", v)
			}
		}
	}
	return nil
}

// isValidTagChars checks if the string contains only allowed characters for S3 tags.
// Allowed: a-z, A-Z, 0-9, + - = . _ : /
func isValidTagChars(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '-' || c == '=' || c == '.' || c == '_' || c == ':' || c == '/') {
			return false
		}
	}
	return true
}

// ErrBackendNotConfigured is returned when the backend endpoint has not been configured.
var ErrBackendNotConfigured = errors.New("backend not configured")

// hopByHopHeaders lists HTTP headers that must not be forwarded by a proxy.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// copyProxyResponse copies the status code, filtered headers, and body from an
// upstream HTTP response to the client ResponseWriter. Hop-by-hop headers are
// stripped before copying.
func copyProxyResponse(w http.ResponseWriter, resp *http.Response) {
	for _, h := range hopByHopHeaders {
		resp.Header.Del(h)
	}
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// forwardToBackend creates and sends a request to the configured S3 backend.
// It builds the backend URL from h.config.Backend.Endpoint, preserves the
// original path and query, copies all headers (replacing Host with the backend
// hostname), and sets Content-Length if present. A minimal http.Client with
// TLS 1.2 minimum is used. The raw *http.Response is returned directly without
// writing to the ResponseWriter.
func (h *Handler) forwardToBackend(r *http.Request) (*http.Response, error) {
	if h.config == nil || h.config.Backend.Endpoint == "" {
		return nil, ErrBackendNotConfigured
	}

	u, err := url.Parse(h.config.Backend.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid backend endpoint: %w", err)
	}
	if u.Scheme == "" {
		if h.config.Backend.UseSSL {
			u.Scheme = "https"
		} else {
			u.Scheme = "http"
		}
	}
	u.Path = r.URL.Path
	u.RawQuery = r.URL.RawQuery

	var bodyBytes []byte
	if r.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		r.Body.Close()
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy request: %w", err)
	}
	proxyReq.Header = r.Header.Clone()
	proxyReq.Host = u.Host
	proxyReq.Header.Set("Host", u.Host)
	if len(bodyBytes) > 0 {
		proxyReq.ContentLength = int64(len(bodyBytes))
	}

	if proxyReq.Header.Get("Authorization") == "" && h.config.Backend.AccessKey != "" {
		bodyHash := sha256.Sum256(bodyBytes)
		payloadHash := hex.EncodeToString(bodyHash[:])

		credsProvider := credentials.NewStaticCredentialsProvider(h.config.Backend.AccessKey, h.config.Backend.SecretKey, "")
		credsVal, err := credsProvider.Retrieve(r.Context())
		if err != nil {
			return nil, fmt.Errorf("failed to get backend credentials: %v", err)
		}
		proxyReq.Header.Set("X-Amz-Content-Sha256", payloadHash)
		signer := v4.NewSigner()
		region := h.config.Backend.Region
		if region == "" {
			region = "us-east-1"
		}
		if err := signer.SignHTTP(r.Context(), credsVal, proxyReq, payloadHash, "s3", region, time.Now()); err != nil {
			return nil, fmt.Errorf("failed to sign backend request: %w", err)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{
		Transport: transport,
	}
	resp, err := client.Do(proxyReq) // #nosec G704 — S3 proxy: forward to configured backend
	if err != nil {
		return nil, fmt.Errorf("backend request failed: %w", err)
	}
	return resp, nil
}

// handlePassthrough is a generic passthrough wrapper that forwards a request to
// the backend and copies the response back to the client. On failure it writes
// an appropriate S3Error XML response and records a metric. On success it calls
// copyProxyResponse and records a metric with the response status code. If an
// audit logger is configured an audit event is emitted for every invocation.
func (h *Handler) handlePassthrough(w http.ResponseWriter, r *http.Request, operation, bucket, key string) {
	start := time.Now()

	resp, err := h.forwardToBackend(r)
	if err != nil {
		var s3Err *S3Error
		if errors.Is(err, ErrBackendNotConfigured) {
			s3Err = &S3Error{
				Code:       "InternalError",
				Message:    "We encountered an internal error. Please try again.",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
		} else {
			s3Err = &S3Error{
				Code:       "BadGateway",
				Message:    "The upstream S3 backend returned an error.",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadGateway,
			}
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		if h.auditLogger != nil {
			h.auditLogger.LogAccess(operation, bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), false, err, time.Since(start))
		}
		return
	}
	defer resp.Body.Close()

	copyProxyResponse(w, resp)
	h.metrics.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, resp.StatusCode, time.Since(start), resp.ContentLength)
	if h.auditLogger != nil {
		h.auditLogger.LogAccess(operation, bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
	}
}
