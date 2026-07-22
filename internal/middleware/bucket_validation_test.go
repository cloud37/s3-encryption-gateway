package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func silentLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

// okHandler is a simple handler that records it was called and returns 200.
type okHandler struct {
	called bool
}

func (h *okHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called = true
	w.WriteHeader(http.StatusOK)
}

// TestBucketValidationMiddleware_NoBucketConfig verifies that when proxiedBucket
// is empty, all requests pass through without validation.
func TestBucketValidationMiddleware_NoBucketConfig(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("", silentLogger())(handler)

	tests := []string{
		"/any-bucket/key",
		"/other-bucket",
		"/",
		"/health",
	}

	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			handler.called = false
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, req)
			if !handler.called {
				t.Errorf("BucketValidationMiddleware with empty config should pass through %q", path)
			}
		})
	}
}

// TestBucketValidationMiddleware_AllowsConfiguredBucket verifies that requests
// to the configured proxied bucket are passed through.
func TestBucketValidationMiddleware_AllowsConfiguredBucket(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("my-bucket", silentLogger())(handler)

	paths := []string{
		"/my-bucket",
		"/my-bucket/key",
		"/my-bucket/path/to/key",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			handler.called = false
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Errorf("expected 200 for %q, got %d", path, w.Code)
			}
			if !handler.called {
				t.Errorf("expected handler to be called for %q", path)
			}
		})
	}
}

// TestBucketValidationMiddleware_DeniesOtherBucket verifies that requests to
// a bucket other than the configured one return 403 AccessDenied.
func TestBucketValidationMiddleware_DeniesOtherBucket(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("my-bucket", silentLogger())(handler)

	paths := []string{
		"/other-bucket",
		"/other-bucket/key",
		"/forbidden-bucket/prefix/key",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			handler.called = false
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("expected 403 for %q, got %d", path, w.Code)
			}
			if handler.called {
				t.Errorf("handler should NOT be called for denied path %q", path)
			}
		})
	}
}

// TestBucketValidationMiddleware_AllowsHealthEndpoints verifies that health
// check and metrics endpoints bypass bucket validation.
func TestBucketValidationMiddleware_AllowsHealthEndpoints(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("my-bucket", silentLogger())(handler)

	paths := []string{
		"/health",
		"/ready",
		"/live",
		"/metrics",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			handler.called = false
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, req)
			if !handler.called {
				t.Errorf("health/metrics endpoint %q should bypass bucket validation", path)
			}
		})
	}
}

// TestBucketValidationMiddleware_DeniesSystemEndpointPrefixes verifies that
// only exact system endpoint paths bypass single-bucket authorization.
func TestBucketValidationMiddleware_DeniesSystemEndpointPrefixes(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("my-bucket", silentLogger())(handler)

	paths := []string{
		"/metrics/custom",
		"/metrics-other-bucket/key",
		"/health-other-bucket/key",
		"/ready-other-bucket/key",
		"/live-other-bucket/key",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			handler.called = false
			req := httptest.NewRequest("GET", path, nil)
			w := httptest.NewRecorder()
			mw.ServeHTTP(w, req)

			if w.Code != http.StatusForbidden {
				t.Errorf("expected 403 for system endpoint prefix %q, got %d", path, w.Code)
			}
			if handler.called {
				t.Errorf("handler should NOT be called for system endpoint prefix %q", path)
			}
		})
	}
}

// TestBucketValidationMiddleware_DeniesEmptyBucket verifies that a request
// with no bucket in the path (root path) is denied in single-bucket mode.
func TestBucketValidationMiddleware_DeniesEmptyBucket(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("my-bucket", silentLogger())(handler)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for root path in single-bucket mode, got %d", w.Code)
	}
}

// TestBucketValidationMiddleware_DeniesWrongCopySource verifies that a copy
// request with a wrong copy-source bucket is denied.
func TestBucketValidationMiddleware_DeniesWrongCopySource(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("my-bucket", silentLogger())(handler)

	req := httptest.NewRequest("PUT", "/my-bucket/dst-key", nil)
	req.Header.Set("x-amz-copy-source", "other-bucket/src-key")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for wrong copy-source bucket, got %d", w.Code)
	}
	if handler.called {
		t.Error("handler should NOT be called when copy-source bucket is wrong")
	}
}

// TestBucketValidationMiddleware_AllowsMatchingCopySource verifies that a copy
// request with the correct copy-source bucket is allowed through.
func TestBucketValidationMiddleware_AllowsMatchingCopySource(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("my-bucket", silentLogger())(handler)

	req := httptest.NewRequest("PUT", "/my-bucket/dst-key", nil)
	req.Header.Set("x-amz-copy-source", "my-bucket/src-key")
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for matching copy-source bucket, got %d", w.Code)
	}
	if !handler.called {
		t.Error("handler should be called when copy-source bucket matches")
	}
}

// TestBucketValidationMiddleware_AccessDeniedXML verifies the error response
// is valid XML with AccessDenied code.
func TestBucketValidationMiddleware_AccessDeniedXML(t *testing.T) {
	handler := &okHandler{}
	mw := BucketValidationMiddleware("my-bucket", silentLogger())(handler)

	req := httptest.NewRequest("GET", "/wrong-bucket/key", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/xml") {
		t.Errorf("expected application/xml content type, got %q", ct)
	}

	body := w.Body.String()
	if !strings.Contains(body, "AccessDenied") {
		t.Errorf("expected AccessDenied in response body: %s", body)
	}
}
