package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

func TestHandlePassthroughWithBodyLimit_EmptyBody(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if len(body) != 0 {
			t.Errorf("body=%q", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	w := httptest.NewRecorder()
	h.handlePassthroughWithBodyLimit(w, httptest.NewRequest(http.MethodPut, "/abc", nil), "CreateBucket", "abc", "", 64)
	if w.Code != http.StatusNoContent || calls.Load() != 1 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestHandlePassthroughWithBodyLimit_BodyAndHeaders(t *testing.T) {
	body := []byte("<location>eu</location>")
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, body) {
			t.Errorf("body=%q", got)
		}
		if r.Header.Get("X-Test") != "yes" {
			t.Errorf("header missing")
		}
		w.Header().Set("X-Reply", "yes")
		w.WriteHeader(http.StatusCreated)
	}))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	req := httptest.NewRequest(http.MethodPut, "/abc?test=preserved", bytes.NewReader(body))
	req.Header.Set("X-Test", "yes")
	w := httptest.NewRecorder()
	h.handlePassthroughWithBodyLimit(w, req, "CreateBucket", "abc", "", 64)
	if w.Code != http.StatusCreated || w.Header().Get("X-Reply") != "yes" {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestHandlePassthroughWithBodyLimit_TooLargeIsLocalError(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/abc", strings.NewReader("12345"))
	h.handlePassthroughWithBodyLimit(w, req, "CreateBucket", "abc", "", 4)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<Code>InvalidRequest</Code>") || calls.Load() != 0 {
		t.Fatalf("status=%d body=%s calls=%d", w.Code, w.Body.String(), calls.Load())
	}
}

func TestHandlePassthroughWithBodyLimit_BackendUnavailableAndFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		endpoint string
		status   int
		code     string
	}{
		{name: "missing backend", endpoint: "", status: http.StatusInternalServerError, code: "InternalError"},
		{name: "backend failure", endpoint: "http://127.0.0.1:1", status: http.StatusBadGateway, code: "BadGateway"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := managementHandler(t, tc.endpoint, true)
			w := httptest.NewRecorder()
			h.handlePassthroughWithBodyLimit(w, httptest.NewRequest(http.MethodPut, "/abc", nil), "CreateBucket", "abc", "", 64)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), "<Code>"+tc.code+"</Code>") {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandlePassthroughWithBodyLimit_BackendS3Error(t *testing.T) {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("<Error><Code>BucketAlreadyExists</Code></Error>"))
	}))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	w := httptest.NewRecorder()
	h.handlePassthroughWithBodyLimit(w, httptest.NewRequest(http.MethodPut, "/abc", nil), "CreateBucket", "abc", "", 64)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "BucketAlreadyExists") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestHandlePassthroughWithBodyLimit_BodyReadErrorAuditsDataPlane(t *testing.T) {
	logger := &managementAuditLogger{}
	engine, err := crypto.NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithFeatures(nil, engine, logrus.New(), getTestMetrics(), nil, nil, logger, &config.Config{}, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/abc", nil)
	r.Body = errReaderRequestBody{}
	h.handlePassthroughWithBodyLimit(w, r, "PutObject", "abc", "key", 64)
	if w.Code != http.StatusBadRequest || len(logger.events) != 0 || logger.accessCalls != 1 {
		t.Fatalf("status=%d audit events=%d access calls=%d body=%s", w.Code, len(logger.events), logger.accessCalls, w.Body.String())
	}
}

type failingResponseWriter struct{ header http.Header }

func (w *failingResponseWriter) Header() http.Header       { return w.header }
func (w *failingResponseWriter) WriteHeader(int)           {}
func (w *failingResponseWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestHandlePassthroughWithBodyLimit_CopyFailureAuditsManagement(t *testing.T) {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend-body"))
	}))
	defer b.Close()
	logger := &managementAuditLogger{}
	engine, err := crypto.NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithFeatures(nil, engine, logrus.New(), getTestMetrics(), nil, nil, logger, &config.Config{Backend: config.BackendConfig{Endpoint: b.URL}}, nil)
	w := &failingResponseWriter{header: make(http.Header)}
	h.handlePassthroughWithBodyLimit(w, httptest.NewRequest(http.MethodPut, "/abc", nil), "CreateBucket", "abc", "", 64)
	if len(logger.events) != 1 || !logger.events[0].success || logger.accessCalls != 0 {
		t.Fatalf("events=%+v generic=%d", logger.events, logger.accessCalls)
	}
}
