package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
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
