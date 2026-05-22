package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/util"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestTracingMiddleware_Redaction(t *testing.T) {
	// Create a test handler that records span attributes
	var recordedHeaders map[string]string
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In a real scenario, this would be done by the tracing framework
		// For testing, we'll simulate what the middleware does
		headers := make(map[string]string)
		for k, v := range r.Header {
			headers[strings.ToLower(k)] = strings.Join(v, ",")
		}
		recordedHeaders = headers
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Test with redaction enabled
	middleware := TracingMiddleware(true, nil)
	handler := middleware(testHandler)

	// Create a request with sensitive headers
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("X-Amz-Security-Token", "sensitive-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom-Header", "safe-value")

	// Execute request
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)

	// In the actual middleware, sensitive headers would be redacted in spans
	// For this test, we verify the middleware doesn't interfere with the request
	assert.Equal(t, "Bearer secret-token", recordedHeaders["authorization"])
	assert.Equal(t, "sensitive-token", recordedHeaders["x-amz-security-token"])
	assert.Equal(t, "application/json", recordedHeaders["content-type"])
}

func TestTracingMiddleware_NoRedaction(t *testing.T) {
	// Test with redaction disabled
	middleware := TracingMiddleware(false, nil)
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	handler := middleware(testHandler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Verify response
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTracingMiddleware_HTTPURL_NoQueryString(t *testing.T) {
	_, sr := setupTestTracer(t)

	middleware := TracingMiddleware(true, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Simulate a presigned URL with sensitive query parameters
	req := httptest.NewRequest("GET", "/bucket/object?X-Amz-Signature=abc123&X-Amz-Credential=secret", nil)
	req.URL.Scheme = "https"
	req.Host = "s3.example.com"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	ended := sr.Ended()
	assert.Len(t, ended, 1)

	httpURL := findSpanAttribute(ended, "http.url")
	assert.Equal(t, "https://s3.example.com/bucket/object", httpURL)
	assert.NotContains(t, httpURL, "X-Amz-Signature")
	assert.NotContains(t, httpURL, "X-Amz-Credential")
	assert.NotContains(t, httpURL, "?")
}

func TestTracingMiddleware_HTTPURL_RedactedQuery(t *testing.T) {
	_, sr := setupTestTracer(t)

	middleware := TracingMiddleware(true, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/bucket/object?versionId=123", nil)
	req.URL.Scheme = "http"
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	ended := sr.Ended()
	assert.Len(t, ended, 1)

	httpURL := findSpanAttribute(ended, "http.url")
	assert.Equal(t, "http://localhost:8080/bucket/object", httpURL)

	httpQuery := findSpanAttribute(ended, "http.query")
	assert.Equal(t, "[REDACTED]", httpQuery)
}

func TestTracingMiddleware_HTTPURL_NoRedaction_QueryVisible(t *testing.T) {
	_, sr := setupTestTracer(t)

	middleware := TracingMiddleware(false, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/bucket/object?versionId=123", nil)
	req.URL.Scheme = "http"
	req.Host = "localhost:8080"

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	ended := sr.Ended()
	assert.Len(t, ended, 1)

	httpURL := findSpanAttribute(ended, "http.url")
	assert.Equal(t, "http://localhost:8080/bucket/object", httpURL)

	httpQuery := findSpanAttribute(ended, "http.query")
	assert.Equal(t, "versionId=123", httpQuery)
}

func TestExtractBucketAndKey(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		bucket   string
		key      string
	}{
		{
			name:   "simple bucket and key",
			path:   "/mybucket/mykey",
			bucket: "mybucket",
			key:    "mykey",
		},
		{
			name:   "bucket only",
			path:   "/mybucket",
			bucket: "mybucket",
			key:    "",
		},
		{
			name:   "nested key",
			path:   "/mybucket/path/to/file.txt",
			bucket: "mybucket",
			key:    "path/to/file.txt",
		},
		{
			name:   "root path",
			path:   "/",
			bucket: "",
			key:    "",
		},
		{
			name:   "empty path",
			path:   "",
			bucket: "",
			key:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, key := extractBucketAndKey(tt.path)
			assert.Equal(t, tt.bucket, bucket)
			assert.Equal(t, tt.key, key)
		})
	}
}

func TestGetSpanName(t *testing.T) {
	tests := []struct {
		name   string
		method string
		bucket string
		key    string
		want   string
	}{
		{
			name:   "GET with key",
			method: "GET",
			bucket: "bucket",
			key:    "key",
			want:   "S3 GetObject",
		},
		{
			name:   "GET without key",
			method: "GET",
			bucket: "bucket",
			key:    "",
			want:   "S3 ListObjects",
		},
		{
			name:   "PUT",
			method: "PUT",
			bucket: "bucket",
			key:    "key",
			want:   "S3 PutObject",
		},
		{
			name:   "DELETE",
			method: "DELETE",
			bucket: "bucket",
			key:    "key",
			want:   "S3 DeleteObject",
		},
		{
			name:   "HEAD",
			method: "HEAD",
			bucket: "bucket",
			key:    "key",
			want:   "S3 HeadObject",
		},
		{
			name:   "POST with multipart",
			method: "POST",
			bucket: "bucket",
			key:    "multipart",
			want:   "S3 CompleteMultipartUpload",
		},
		{
			name:   "unknown method",
			method: "UNKNOWN",
			bucket: "bucket",
			key:    "key",
			want:   "HTTP UNKNOWN",
		},
		{
			name:   "no bucket",
			method: "GET",
			bucket: "",
			key:    "",
			want:   "HTTP GET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getSpanName(tt.method, tt.bucket, tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestGetRemoteAddr_NilExtractor(t *testing.T) {
	// No extractor configured → fail-safe fallback to RemoteAddr
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	got := getRemoteAddr(req, nil)
	assert.Equal(t, "192.168.1.100", got)
}

func TestGetRemoteAddr_TrustedProxy(t *testing.T) {
	extractor, err := util.NewIPExtractor([]string{"10.0.0.0/8"})
	assert.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	got := getRemoteAddr(req, extractor)
	assert.Equal(t, "203.0.113.1", got)
}

func TestGetRemoteAddr_UntrustedOrigin(t *testing.T) {
	extractor, err := util.NewIPExtractor([]string{"10.0.0.0/8"})
	assert.NoError(t, err)

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.99:54321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	got := getRemoteAddr(req, extractor)
	assert.Equal(t, "203.0.113.99", got)
}

func setupTestTracer(t *testing.T) (*sdktrace.TracerProvider, *tracetest.SpanRecorder) {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(sr),
	)
	oldTP := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(oldTP) })
	return tp, sr
}

func findSpanAttribute(spans []sdktrace.ReadOnlySpan, key string) string {
	for _, span := range spans {
		for _, attr := range span.Attributes() {
			if string(attr.Key) == key {
				return attr.Value.AsString()
			}
		}
	}
	return ""
}

func TestTracingMiddleware_SpanRemoteAddr_NilExtractor(t *testing.T) {
	_, sr := setupTestTracer(t)

	middleware := TracingMiddleware(true, nil)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	ended := sr.Ended()
	assert.Len(t, ended, 1)
	assert.Equal(t, "192.168.1.100", findSpanAttribute(ended, "http.remote_addr"))
}

func TestTracingMiddleware_SpanRemoteAddr_TrustedProxy(t *testing.T) {
	_, sr := setupTestTracer(t)

	extractor, err := util.NewIPExtractor([]string{"10.0.0.0/8"})
	assert.NoError(t, err)

	middleware := TracingMiddleware(true, extractor)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.1")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	ended := sr.Ended()
	assert.Len(t, ended, 1)
	assert.Equal(t, "203.0.113.1", findSpanAttribute(ended, "http.remote_addr"))
}

func TestTracingMiddleware_SpanRemoteAddr_UntrustedOrigin(t *testing.T) {
	_, sr := setupTestTracer(t)

	extractor, err := util.NewIPExtractor([]string{"10.0.0.0/8"})
	assert.NoError(t, err)

	middleware := TracingMiddleware(true, extractor)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.99:54321"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	ended := sr.Ended()
	assert.Len(t, ended, 1)
	assert.Equal(t, "203.0.113.99", findSpanAttribute(ended, "http.remote_addr"))
}
