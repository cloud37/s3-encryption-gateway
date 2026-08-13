package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// putBackend records what a minimal S3 backend saw: body uploads, and the
// metadata-only copy-to-self through which the unknown-length path persists the
// back-calculated plaintext size.
type putBackend struct {
	puts       atomic.Int32
	copies     atomic.Int32
	copiedSize atomic.Value // string; MetaOriginalSize on the last copy
}

func (b *putBackend) lastCopiedSize() string {
	s, _ := b.copiedSize.Load().(string)
	return s
}

// faultyPutBackend fails the first faultCount body uploads with a 500 and
// succeeds afterwards.
func faultyPutBackend(faultCount int32) (*httptest.Server, *putBackend) {
	b := &putBackend{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The copy-to-self carries no body, so it is not an upload attempt.
		if r.Method != http.MethodPut || r.Header.Get("X-Amz-Copy-Source") != "" {
			if r.Header.Get("X-Amz-Copy-Source") != "" {
				b.copies.Add(1)
				b.copiedSize.Store(r.Header.Get("X-Amz-Meta-Encryption-Original-Size"))
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `<CopyObjectResult><ETag>"copy-ok"</ETag></CopyObjectResult>`)
			return
		}
		// Drain the body so the backend observes the whole request, as a real
		// one would; a retry that never resends is then visibly short.
		_, _ = io.Copy(io.Discard, r.Body)
		if b.puts.Add(1) <= faultCount {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `<Error><Code>InternalError</Code><Message>injected</Message></Error>`)
			return
		}
		w.Header().Set("ETag", `"put-ok"`)
		w.WriteHeader(http.StatusOK)
	}))
	return srv, b
}

// newRetryHandler wires the real s3 client (not the mock) to the real handler so
// the request goes through the SDK middleware, which is the only place the
// rewind-on-retry contract is exercised.
func newRetryHandler(t *testing.T, backendURL string, chunked bool) (*mux.Router, *config.Config) {
	t.Helper()
	bcfg := &config.BackendConfig{
		Endpoint:     backendURL,
		Region:       "us-east-1",
		AccessKey:    "AKIATEST",
		SecretKey:    "secrettest",
		UsePathStyle: true,
		UseSSL:       false,
		Retry: config.BackendRetryConfig{
			InitialBackoff: time.Millisecond,
			MaxBackoff:     5 * time.Millisecond,
			Jitter:         "none",
		},
	}
	client, err := s3.NewBackendClient(bcfg)
	if err != nil {
		t.Fatalf("NewBackendClient: %v", err)
	}
	engine, err := crypto.NewEngineWithChunking([]byte("test-password-retry-123456"), "", nil, chunked, 0)
	if err != nil {
		t.Fatalf("NewEngineWithChunking: %v", err)
	}
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)

	cfg := newConfigWithMaxPartBuffer(64 << 20)
	cfg.Backend = *bcfg
	handler := NewHandlerWithFeatures(client, engine, logger, getTestMetrics(), nil, nil, nil, cfg, nil)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	return router, cfg
}

// A chunked-encrypted PUT produces a streaming, non-seekable ciphertext reader.
// Without buffering the SDK cannot rewind it, so a single transient backend 500
// fails the client request outright instead of being retried. This is the
// regression guard for that: the observed production failure was a ~3% PutObject
// error rate against a backend whose 500s the retry policy was meant to absorb.
func TestHandlePutObject_Chunked_SurvivesTransientBackend500(t *testing.T) {
	srv, backend := faultyPutBackend(1)
	defer srv.Close()
	router, _ := newRetryHandler(t, srv.URL, true)

	body := bytes.Repeat([]byte("m"), 4096)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/blob-key", bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	// handlePutObject reads the object size from the header, not r.ContentLength.
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 after the backend 500 is retried, got %d; body: %s", w.Code, w.Body.String())
	}
	if got := backend.puts.Load(); got != 2 {
		t.Errorf("expected 2 backend PUT attempts (1 fault + 1 retry), got %d", got)
	}
}

// A body with no Content-Length keeps streaming and stays single-attempt: the
// size is not known up front, so it cannot be checked against max_part_buffer
// without draining the source, and a drained source cannot go back to streaming.
// This is the characterisation of that trade-off — it fails if the body is ever
// buffered here, which would turn the request into 2 attempts and a 200.
func TestHandlePutObject_UnknownLength_StreamsSingleAttempt(t *testing.T) {
	srv, backend := faultyPutBackend(1)
	defer srv.Close()
	router, _ := newRetryHandler(t, srv.URL, true)

	body := bytes.Repeat([]byte("m"), 4096)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/blob-key", bytes.NewReader(body))
	req.ContentLength = -1
	req.Header.Del("Content-Length")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		t.Fatalf("expected the injected 500 to surface: an unknown-length body is not rewindable, so it cannot be retried")
	}
	if got := backend.puts.Load(); got != 1 {
		t.Errorf("expected the retry to abort before a second request reaches the backend, got %d attempts", got)
	}
}

// The unknown-length path measures the ciphertext with ciphertextCounter and
// back-calculates the plaintext size, persisting it via a metadata-only
// copy-to-self so HeadObject reports the right Content-Length. That arithmetic
// had no coverage; this pins it. 4096 plaintext + one 16-byte AEAD tag = 4112
// ciphertext, which must solve back to 4096.
func TestHandlePutObject_UnknownLength_RecordsPlaintextSize(t *testing.T) {
	srv, backend := faultyPutBackend(0)
	defer srv.Close()
	router, _ := newRetryHandler(t, srv.URL, true)

	body := bytes.Repeat([]byte("m"), 4096)
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/blob-key", bytes.NewReader(body))
	req.ContentLength = -1
	req.Header.Del("Content-Length")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if got := backend.copies.Load(); got != 1 {
		t.Fatalf("expected the metadata copy-to-self that persists the plaintext size, got %d copies", got)
	}
	if got := backend.lastCopiedSize(); got != strconv.Itoa(len(body)) {
		t.Errorf("MetaOriginalSize on the copy = %q, want %q", got, strconv.Itoa(len(body)))
	}
}
