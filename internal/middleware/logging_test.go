package middleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

func TestLoggingMiddleware(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress log output during tests

	cfg := &config.LoggingConfig{
		AccessLogFormat: "default",
		RedactHeaders:   []string{"authorization"},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test"))
	})

	middleware := LoggingMiddleware(logger, cfg)
	wrapped := middleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestResponseWriter(t *testing.T) {
	w := httptest.NewRecorder()
	rw := &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	rw.WriteHeader(http.StatusNotFound)
	if rw.statusCode != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, rw.statusCode)
	}

	n, err := rw.Write([]byte("test"))
	if err != nil {
		t.Errorf("Write returned error: %v", err)
	}
	if n != 4 {
		t.Errorf("expected to write 4 bytes, wrote %d", n)
	}
	if rw.bytesWritten != 4 {
		t.Errorf("expected bytesWritten to be 4, got %d", rw.bytesWritten)
	}
}

func TestLoggingFormats(t *testing.T) {
	tests := []struct {
		name           string
		format         string
		redactHeaders  []string
		expectedFields map[string]bool // fields that should be present in log output
	}{
		{
			name:           "default format",
			format:         "default",
			redactHeaders:  []string{"authorization"},
			expectedFields: map[string]bool{"method": true, "path": true, "status": true, "duration_ms": true, "bytes": true},
		},
		{
			name:           "json format",
			format:         "json",
			redactHeaders:  []string{"authorization", "x-amz-security-token"},
			expectedFields: map[string]bool{"json": true},
		},
		{
			name:           "clf format",
			format:         "clf",
			redactHeaders:  []string{"authorization"},
			expectedFields: map[string]bool{"clf": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetLevel(logrus.InfoLevel)

			// Capture log output
			var capturedOutput string
			logger.SetOutput(&testWriter{output: &capturedOutput})
			logger.SetFormatter(&logrus.JSONFormatter{})

			cfg := &config.LoggingConfig{
				AccessLogFormat: tt.format,
				RedactHeaders:   tt.redactHeaders,
			}

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("test response"))
			})

			middleware := LoggingMiddleware(logger, cfg)
			wrapped := middleware(handler)

			req := httptest.NewRequest("GET", "/test?param=value", nil)
			req.Header.Set("User-Agent", "test-agent")
			req.Header.Set("Authorization", "Bearer secret-token")
			req.Header.Set("X-Amz-Security-Token", "sensitive-token")
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			wrapped.ServeHTTP(w, req)

			// Verify log output contains expected fields
			for field := range tt.expectedFields {
				if !strings.Contains(capturedOutput, field) {
					t.Errorf("expected log output to contain field %q, got: %s", field, capturedOutput)
				}
			}

			// For JSON format, verify redaction by checking the embedded JSON
			if tt.format == "json" {
				// The JSON is embedded in the logrus JSON output, so we just verify the format works
				if !strings.Contains(capturedOutput, `"json":`) {
					t.Errorf("expected JSON format output, got: %s", capturedOutput)
				}
				// Basic sanity check that redaction is happening
				if len(tt.redactHeaders) > 0 && !strings.Contains(capturedOutput, "[REDACTED]") {
					t.Errorf("expected some headers to be redacted, got: %s", capturedOutput)
				}
			}
		})
	}
}

func TestShouldRedactHeader(t *testing.T) {
	tests := []struct {
		headerName    string
		redactHeaders []string
		expected      bool
	}{
		{"authorization", []string{"authorization", "x-amz-security-token"}, true},
		{"x-amz-security-token", []string{"authorization", "x-amz-security-token"}, true},
		{"content-type", []string{"authorization", "x-amz-security-token"}, false},
		{"AUTHORIZATION", []string{"authorization"}, true}, // case insensitive
		{"user-agent", []string{}, false},                   // no redaction list
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%v", tt.headerName, tt.redactHeaders), func(t *testing.T) {
			result := shouldRedactHeader(tt.headerName, tt.redactHeaders)
			if result != tt.expected {
				t.Errorf("shouldRedactHeader(%q, %v) = %v, expected %v", tt.headerName, tt.redactHeaders, result, tt.expected)
			}
		})
	}
}

func TestCreateLogEntry(t *testing.T) {
	cfg := &config.LoggingConfig{
		AccessLogFormat: "json",
		RedactHeaders:   []string{"authorization", "x-amz-security-token"},
	}

	req := httptest.NewRequest("POST", "/bucket/key?version=1", nil)
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("X-Amz-Security-Token", "session-token")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent")
	req.RemoteAddr = "127.0.0.1:12345"

	rw := &responseWriter{
		ResponseWriter: httptest.NewRecorder(),
		statusCode:     http.StatusCreated,
		bytesWritten:   1024,
	}

	entry := createLogEntry(req, rw, 150*time.Millisecond, 512, cfg)

	// Verify basic fields
	if entry.Method != "POST" {
		t.Errorf("expected method POST, got %s", entry.Method)
	}
	if entry.Path != "/bucket/key" {
		t.Errorf("expected path /bucket/key, got %s", entry.Path)
	}
	if entry.Query != "version=1" {
		t.Errorf("expected query version=1, got %s", entry.Query)
	}
	if entry.Status != http.StatusCreated {
		t.Errorf("expected status %d, got %d", http.StatusCreated, entry.Status)
	}
	if entry.Bytes != 512 {
		t.Errorf("expected bytes 512, got %d", entry.Bytes)
	}
	if entry.DurationMs != 150 {
		t.Errorf("expected duration 150ms, got %d", entry.DurationMs)
	}

	// Verify headers for JSON format
	if entry.Headers == nil {
		t.Fatal("expected headers to be populated for JSON format")
	}

	if entry.Headers["authorization"] != "[REDACTED]" {
		t.Errorf("expected authorization header to be redacted, got %s", entry.Headers["authorization"])
	}
	if entry.Headers["x-amz-security-token"] != "[REDACTED]" {
		t.Errorf("expected x-amz-security-token header to be redacted, got %s", entry.Headers["x-amz-security-token"])
	}
	if entry.Headers["content-type"] != "application/json" {
		t.Errorf("expected content-type header to not be redacted, got %s", entry.Headers["content-type"])
	}
}

// TestRedactQueryString verifies redactQueryString covers all branches.
func TestRedactQueryString(t *testing.T) {
	// Empty query string.
	if got := redactQueryString(""); got != "" {
		t.Errorf("empty: got %q, want \"\"", got)
	}

	// Query with non-sensitive params.
	got := redactQueryString("prefix=foo&max-keys=10")
	if !strings.Contains(got, "prefix") || !strings.Contains(got, "max-keys") {
		t.Errorf("non-sensitive params should be preserved: %q", got)
	}

	// Query with sensitive param (x-amz-signature).
	got = redactQueryString("X-Amz-Signature=abc123&prefix=foo")
	if strings.Contains(got, "abc123") {
		t.Errorf("signature should be redacted: %q", got)
	}

	// Unparseable query string (contains '%' without valid hex).
	got = redactQueryString("a=%ZZ")
	if got != "[REDACTED]" {
		t.Errorf("unparseable query: got %q, want [REDACTED]", got)
	}
}

// TestLogJSON verifies the logJSON format path.
func TestLogJSON(t *testing.T) {
	output := ""
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(&testWriter{output: &output})

	entry := &LogEntry{
		Method:     "GET",
		Path:       "/test",
		Status:     200,
		DurationMs: 1,
		RemoteAddr: "127.0.0.1",
	}
	logJSON(logger, entry)
	// Just verify no panic.
	_ = output
}

// testWriter captures log output for testing
type testWriter struct {
	output *string
}

func (w *testWriter) Write(p []byte) (n int, err error) {
	*w.output += string(p)
	return len(p), nil
}
