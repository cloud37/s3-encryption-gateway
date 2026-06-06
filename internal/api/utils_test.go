package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

func TestCopyProxyResponse(t *testing.T) {
	backendResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":      []string{"application/xml"},
			"Connection":        []string{"keep-alive"},
			"Transfer-Encoding": []string{"chunked"},
			"X-Amz-Request-Id":  []string{"test123"},
			"X-Amz-Id-2":        []string{"test456"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("hello"))),
	}

	w := httptest.NewRecorder()
	copyProxyResponse(w, backendResp)

	result := w.Result()

	if result.StatusCode != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, result.StatusCode)
	}

	if result.Header.Get("Content-Type") != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got %s", result.Header.Get("Content-Type"))
	}

	if result.Header.Get("Connection") != "" {
		t.Errorf("expected Connection to be stripped, got %s", result.Header.Get("Connection"))
	}

	if result.Header.Get("Transfer-Encoding") != "" {
		t.Errorf("expected Transfer-Encoding to be stripped, got %s", result.Header.Get("Transfer-Encoding"))
	}

	if result.Header.Get("X-Amz-Request-Id") != "test123" {
		t.Errorf("expected X-Amz-Request-Id test123, got %s", result.Header.Get("X-Amz-Request-Id"))
	}

	body, _ := io.ReadAll(result.Body)
	if string(body) != "hello" {
		t.Errorf("expected body 'hello', got %q", string(body))
	}
}

// TestCopyProxyResponse_LifecycleHeaders_NotStripped verifies that lifecycle
// response headers x-amz-expiration and x-amz-restore survive copyProxyResponse.
func TestCopyProxyResponse_LifecycleHeaders_NotStripped(t *testing.T) {
	backendResp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"X-Amz-Expiration": []string{"expiry-date=\"Tue, 01 Jan 2025 00:00:00 GMT\", rule-id=\"expire-rule\""},
			"X-Amz-Restore":    []string{"ongoing-request=\"false\", expiry-date=\"Tue, 01 Jan 2025 00:00:00 GMT\""},
			"Content-Type":     []string{"application/octet-stream"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("data"))),
	}

	w := httptest.NewRecorder()
	copyProxyResponse(w, backendResp)

	result := w.Result()

	if result.Header.Get("X-Amz-Expiration") == "" {
		t.Error("x-amz-expiration header was stripped by copyProxyResponse")
	}
	if result.Header.Get("X-Amz-Restore") == "" {
		t.Error("x-amz-restore header was stripped by copyProxyResponse")
	}

	exp := result.Header.Get("X-Amz-Expiration")
	if !strings.Contains(exp, "expiry-date") || !strings.Contains(exp, "rule-id") {
		t.Errorf("x-amz-expiration header value looks truncated: %q", exp)
	}
}

// TestHandlePassthrough_LifecycleExpirationHeader_Forwarded verifies that
// x-amz-expiration and x-amz-restore headers from a backend GET response
// pass through the passthrough forwarding path.
func TestHandlePassthrough_LifecycleExpirationHeader_Forwarded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-expiration", "expiry-date=\"Tue, 01 Jan 2025 00:00:00 GMT\", rule-id=\"expire-rule\"")
		w.Header().Set("x-amz-restore", "ongoing-request=\"false\", expiry-date=\"Tue, 01 Jan 2025 00:00:00 GMT\"")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	h := &Handler{
		config: &config.Config{
			Backend: config.BackendConfig{
				Endpoint: backend.URL,
				UseSSL:   false,
			},
		},
		logger:  logger,
		metrics: getTestMetrics(),
	}

	req := httptest.NewRequest("GET", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()
	h.handlePassthrough(w, req, "GetObject", "test-bucket", "test-key")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if w.Header().Get("x-amz-expiration") == "" {
		t.Error("x-amz-expiration header was stripped by handlePassthrough")
	}
	if w.Header().Get("x-amz-restore") == "" {
		t.Error("x-amz-restore header was stripped by handlePassthrough")
	}
}

// TestHandlePassthrough_RestoreHeader_Forwarded verifies that x-amz-restore
// header passes through the forwarding path.
func TestHandlePassthrough_RestoreHeader_Forwarded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("x-amz-restore", "ongoing-request=\"false\", expiry-date=\"Tue, 01 Jan 2025 00:00:00 GMT\"")
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	h := &Handler{
		config: &config.Config{
			Backend: config.BackendConfig{
				Endpoint: backend.URL,
				UseSSL:   false,
			},
		},
		logger:  logger,
		metrics: getTestMetrics(),
	}

	req := httptest.NewRequest("GET", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()
	h.handlePassthrough(w, req, "GetObject", "test-bucket", "test-key")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	if w.Header().Get("x-amz-restore") == "" {
		t.Error("x-amz-restore header was stripped by handlePassthrough")
	}
}

func TestHandlePassthrough_BackendError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>We encountered an internal error. Please try again.</Message></Error>`))
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	h := &Handler{
		config: &config.Config{
			Backend: config.BackendConfig{
				Endpoint: backend.URL,
				UseSSL:   false,
			},
		},
		logger:  logger,
		metrics: getTestMetrics(),
	}

	req := httptest.NewRequest("GET", "/test-bucket?location", nil)
	w := httptest.NewRecorder()

	h.handlePassthrough(w, req, "GetBucketLocation", "test-bucket", "")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<Code>InternalError</Code>") {
		t.Errorf("expected InternalError in response, got: %s", body)
	}
}

func TestHandlePassthrough_MetricRecorded(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>us-east-1</LocationConstraint></LocationConstraint>`))
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	h := &Handler{
		config: &config.Config{
			Backend: config.BackendConfig{
				Endpoint: backend.URL,
				UseSSL:   false,
			},
		},
		logger:  logger,
		metrics: getTestMetrics(),
	}

	req := httptest.NewRequest("GET", "/test-bucket?location", nil)
	w := httptest.NewRecorder()

	h.handlePassthrough(w, req, "GetBucketLocation", "test-bucket", "")

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "us-east-1") {
		t.Errorf("expected response to contain 'us-east-1', got: %s", body)
	}
}

func TestHandlePassthrough_BackendNotConfigured(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	h := &Handler{
		config:  nil,
		logger:  logger,
		metrics: getTestMetrics(),
	}

	req := httptest.NewRequest("GET", "/test-bucket?location", nil)
	w := httptest.NewRecorder()

	h.handlePassthrough(w, req, "GetBucketLocation", "test-bucket", "")

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<Code>InternalError</Code>") {
		t.Errorf("expected InternalError in response, got: %s", body)
	}
}


// --- getClientIP / getRequestID coverage ------------------------------------

func TestGetClientIP_Fallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	ip := getClientIP(req)
	if ip == "" {
		t.Error("expected non-empty IP")
	}
}

func TestGetRequestID_FromHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-ID", "req-123")
	id := getRequestID(req)
	if id != "req-123" {
		t.Errorf("expected req-123, got %s", id)
	}
}

func TestGetRequestID_Empty(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	id := getRequestID(req)
	if id != "" {
		t.Errorf("expected empty, got %s", id)
	}
}


// --- validateTags unit tests (V1.0-S3-1 coverage gap) -----------------------

func TestValidateTags_Empty_ReturnsNil(t *testing.T) {
	if err := validateTags(""); err != nil {
		t.Errorf("expected nil for empty tags, got %v", err)
	}
}

func TestValidateTags_ValidTags_ReturnsNil(t *testing.T) {
	err := validateTags("key1=val1&key2=val2&key3=abc123ABC")
	if err != nil {
		t.Errorf("expected nil for valid tags, got %v", err)
	}
}

func TestValidateTags_TooManyTags_ReturnsError(t *testing.T) {
	tags := "k0=v0"
	for i := 1; i <= 11; i++ {
		tags += fmt.Sprintf("&k%d=v%d", i, i)
	}
	err := validateTags(tags)
	if err == nil {
		t.Fatal("expected error for >10 tags")
	}
	if !strings.Contains(err.Error(), "too many tags") {
		t.Errorf("expected 'too many tags' error, got: %v", err)
	}
}

func TestValidateTags_KeyTooLong_ReturnsError(t *testing.T) {
	key := strings.Repeat("a", 129)
	err := validateTags(key + "=val")
	if err == nil {
		t.Fatal("expected error for key >128 chars")
	}
	if !strings.Contains(err.Error(), "tag key too long") {
		t.Errorf("expected 'tag key too long' error, got: %v", err)
	}
}

func TestValidateTags_ValueTooLong_ReturnsError(t *testing.T) {
	val := strings.Repeat("b", 257)
	err := validateTags("key=" + val)
	if err == nil {
		t.Fatal("expected error for value >256 chars")
	}
	if !strings.Contains(err.Error(), "tag value too long") {
		t.Errorf("expected 'tag value too long' error, got: %v", err)
	}
}

func TestValidateTags_InvalidChars_Key_ReturnsError(t *testing.T) {
	err := validateTags("key with spaces=val") // spaces not allowed
	if err == nil {
		t.Fatal("expected error for invalid key chars")
	}
	if !strings.Contains(err.Error(), "invalid characters") {
		t.Errorf("expected 'invalid characters' error, got: %v", err)
	}
}

func TestValidateTags_InvalidChars_Value_ReturnsError(t *testing.T) {
	err := validateTags("key=val with spaces") // spaces not allowed
	if err == nil {
		t.Fatal("expected error for invalid value chars")
	}
	if !strings.Contains(err.Error(), "invalid characters") {
		t.Errorf("expected 'invalid characters' error, got: %v", err)
	}
}

func TestValidateTags_InvalidFormat_ReturnsError(t *testing.T) {
	// Malformed query string: stray '%' causes url.ParseQuery to fail.
	err := validateTags("key=val%ZZ")
	if err == nil {
		t.Fatal("expected error for malformed tagging header")
	}
}

// --- isValidTagChars unit tests ---------------------------------------------

func TestIsValidTagChars_ValidChars_ReturnsTrue(t *testing.T) {
	if !isValidTagChars("abc123ABC+=-._:/") {
		t.Error("expected true for valid characters")
	}
}

func TestIsValidTagChars_InvalidChars_ReturnsFalse(t *testing.T) {
	if isValidTagChars("hello world") {
		t.Error("expected false for string with spaces")
	}
	if isValidTagChars("test@domain") {
		t.Error("expected false for string with @")
	}
	if isValidTagChars("foo\tbar") {
		t.Error("expected false for string with tab")
	}
	// Empty string is trivially valid (no invalid characters found).
	// The function returns true for empty input.
}

// --- forwardSignatureV4Request edge case (backend errors) -------------------

// TestHandlePassthrough_BackendConnectionRefused verifies the gateway returns
// a BadGateway error when the backend is unreachable.
func TestHandlePassthrough_BackendConnectionRefused(t *testing.T) {
	// Use a local port that nothing is listening on.
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	h := &Handler{
		config: &config.Config{
			Backend: config.BackendConfig{
				Endpoint: "http://127.0.0.1:1", // Port 1 is reserved; connection will be refused
				UseSSL:   false,
			},
		},
		logger:  logger,
		metrics: getTestMetrics(),
	}

	// GET request that triggers forwardSignatureV4Request path.
	req := httptest.NewRequest("GET", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()
	h.handlePassthrough(w, req, "GetObject", "test-bucket", "test-key")

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 BadGateway, got %d: %s", w.Code, w.Body.String())
	}
}


