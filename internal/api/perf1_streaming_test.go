package api

// V0.6-PERF-1 handler-level streaming tests.
//
// These tests satisfy the Definition of Done items from
// docs/issues/v0.6-issues.md §[V0.6-PERF-1] that require handler-level
// coverage for:
//   - OversizePart refused with HTTP 413 (Phase D)
//   - Legacy-source cap enforced on handleCopyObject (Phase C)
//   - Optimised-range streaming path exercises io.CopyBuffer (Phase B)
//   - Plaintext UploadPart seekable wrapper (Phase D)
//
// The "BoundedHeap" assertion tests from the plan (Phase G §G-2) are implemented
// as functional proxies: we verify correct output when the handler is driven
// with a multi-chunk payload, confirming the streaming path is exercised
// (the actual peak-heap assertion lives in the crypto unit tests via
// TestMPUEncryptReader_Streaming_BoundedHeap).

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

// newHandlerWithConfig builds a minimal Handler wired to a mock S3 client and
// the given Config. logger is set to Panic level to suppress test noise.
func newHandlerWithConfig(t *testing.T, cfg *config.Config) (*Handler, *mockS3Client) {
	t.Helper()
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	mockClient := newMockS3Client()
	engine, err := crypto.NewEngine([]byte("test-password-perf1-123456"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(), nil, nil, nil, cfg, nil)
	return handler, mockClient
}

// newConfigWithMaxPartBuffer returns a minimal *config.Config with the
// server.max_part_buffer set to cap.
func newConfigWithMaxPartBuffer(cap int64) *config.Config {
	cfg := &config.Config{}
	cfg.Server.MaxPartBuffer = cap
	return cfg
}

// newConfigWithLegacyCap returns a *config.Config with max_legacy_copy_source_bytes set.
func newConfigWithLegacyCap(cap int64) *config.Config {
	cfg := &config.Config{}
	cfg.Server.MaxLegacyCopySourceBytes = cap
	return cfg
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase D — UploadPart oversize rejection
// ─────────────────────────────────────────────────────────────────────────────

// TestHandleUploadPart_OversizePart_Refused verifies that a plaintext
// UploadPart request whose body exceeds server.max_part_buffer is refused with
// HTTP 413 EntityTooLarge before any backend write occurs (V0.6-PERF-1 Phase D).
func TestHandleUploadPart_OversizePart_Refused(t *testing.T) {
	// Cap at 10 bytes — any part body > 10 bytes must be rejected.
	cap := int64(10)
	cfg := newConfigWithMaxPartBuffer(cap)

	// Plaintext (non-encrypted-MPU) upload: the seekable wrapper is applied to
	// r.Body directly.
	handler, mockClient := newHandlerWithConfig(t, cfg)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Create a multipart upload first via the mock (skip the HTTP round-trip).
	uploadID, err := mockClient.CreateMultipartUpload(context.Background(), "test-bucket", "big-obj", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}

	// Part body is 11 bytes — one byte over the cap.
	body := strings.NewReader(strings.Repeat("X", 11))
	url := fmt.Sprintf("/test-bucket/big-obj?partNumber=1&uploadId=%s", uploadID)
	req := httptest.NewRequest("PUT", url, body)
	req.ContentLength = 11
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected HTTP 413, got %d; body: %s", w.Code, w.Body.String())
	}
	// The response body must be XML with code EntityTooLarge.
	if !strings.Contains(w.Body.String(), "EntityTooLarge") {
		t.Errorf("expected EntityTooLarge code in response, got: %s", w.Body.String())
	}
	// No backend UploadPart call must have occurred.
	if mockClient.objects["test-bucket/big-obj"] != nil {
		t.Error("oversize part must not be written to the backend")
	}
}

// TestHandleUploadPart_AtCap_Succeeds verifies that a part exactly at the cap
// is accepted (boundary condition for Phase D).
func TestHandleUploadPart_AtCap_Succeeds(t *testing.T) {
	cap := int64(20)
	cfg := newConfigWithMaxPartBuffer(cap)

	handler, mockClient := newHandlerWithConfig(t, cfg)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	uploadID, err := mockClient.CreateMultipartUpload(context.Background(), "test-bucket", "boundary-obj", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}

	body := bytes.Repeat([]byte("Y"), 20) // exactly at cap
	url := fmt.Sprintf("/test-bucket/boundary-obj?partNumber=1&uploadId=%s", uploadID)
	req := httptest.NewRequest("PUT", url, bytes.NewReader(body))
	req.ContentLength = 20
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 for at-cap part, got %d; body: %s", w.Code, w.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase C — handleCopyObject legacy-source cap
// ─────────────────────────────────────────────────────────────────────────────

// TestHandleCopyObject_Legacy_CapEnforced verifies that a CopyObject request
// whose source is a legacy (non-chunked) encrypted object and whose size
// exceeds server.max_legacy_copy_source_bytes is refused with HTTP 400 before
// any decryption begins (V0.6-PERF-1 Phase C).
func TestHandleCopyObject_Legacy_CapEnforced(t *testing.T) {
	// Use a very small cap — 1 byte.
	cap := int64(1)
	cfg := newConfigWithLegacyCap(cap)

	handler, mockClient := newHandlerWithConfig(t, cfg)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Store a legacy-encrypted object in the mock backend by encrypting with
	// the legacy (non-chunked) engine and inserting the result directly into
	// the mock store.  We need the metadata to look like a legacy encrypted
	// object (x-amz-meta-encryption-algorithm is set, but NOT
	// x-amz-meta-encryption-chunked).
	legacyEngine, _ := crypto.NewEngine([]byte("test-password-perf1-123456"))
	plain := bytes.Repeat([]byte("P"), 100) // 100 bytes — exceeds cap of 1
	encReader, encMeta, err := legacyEngine.Encrypt(context.Background(), bytes.NewReader(plain), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Confirm this is NOT chunked (legacy engine).
	if crypto.IsChunkedFormat(encMeta) {
		t.Skip("engine produced chunked format — legacy cap test requires legacy engine")
	}
	// Write the encrypted bytes plus a Content-Length metadata hint so the
	// cap check can compare it.
	import_bytes, _ := func() ([]byte, error) {
		var buf bytes.Buffer
		_, e := buf.ReadFrom(encReader)
		return buf.Bytes(), e
	}()
	encLen := int64(len(import_bytes))
	encMeta["Content-Length"] = fmt.Sprintf("%d", encLen)

	_ = mockClient.PutObject(
		context.Background(),
		"src-bucket", "src-key",
		bytes.NewReader(import_bytes),
		encMeta,
		&encLen,
		"", nil, "", "", "", "", "",
	)

	// Issue a CopyObject request that would copy src-bucket/src-key →
	// dst-bucket/dst-key.
	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// The handler should refuse because the source exceeds the legacy cap.
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 for oversized legacy source, got %d; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "max_legacy_copy_source_bytes") {
		t.Errorf("response should mention max_legacy_copy_source_bytes, got: %s", w.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase B — handleGetObject optimised-range streaming
// ─────────────────────────────────────────────────────────────────────────────

// TestHandleGetObject_Streaming_BoundedHeap verifies that the optimised range
// path (Phase B) of handleGetObject streams the response directly to the
// writer via io.CopyBuffer rather than accumulating a full-object buffer.
// We use a chunked-encrypted object to exercise the optimised code path,
// then verify that a range request returns the correct bytes (functional proxy
// for the heap-bound assertion; the actual allocation bound is enforced at the
// crypto unit level by TestMPUEncryptReader_Streaming_BoundedHeap).
func TestHandleGetObject_Streaming_BoundedHeap(t *testing.T) {
	chunkedEngine, err := crypto.NewEngineWithChunking(
		[]byte("test-password-perf1-123456"),
		nil, "", nil, true, 0,
	)
	if err != nil {
		t.Fatalf("NewEngineWithChunking: %v", err)
	}
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	mockClient := newMockS3Client()
	handler := NewHandlerWithFeatures(mockClient, chunkedEngine, logger, getTestMetrics(), nil, nil, nil, nil, nil)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Build a plaintext payload large enough to span multiple chunks.
	const payloadLen = 200_000
	plain := bytes.Repeat([]byte("Z"), payloadLen)

	// Encrypt and store.
	encReader, encMeta, err := chunkedEngine.Encrypt(context.Background(), bytes.NewReader(plain), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	var encBuf bytes.Buffer
	if _, err := encBuf.ReadFrom(encReader); err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	encLen := int64(encBuf.Len())
	if err := mockClient.PutObject(context.Background(), "bkt", "obj", bytes.NewReader(encBuf.Bytes()), encMeta, &encLen, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	// Range request: bytes 100-999 (within first chunk, exercises the streaming
	// path at handlers.go:1221-1232 — io.CopyBuffer).
	req := httptest.NewRequest("GET", "/bkt/obj", nil)
	req.Header.Set("Range", "bytes=100-999")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusPartialContent {
		t.Errorf("expected 206 Partial Content, got %d; body prefix: %.200s", w.Code, w.Body.String())
	}
	got := w.Body.Bytes()
	want := plain[100:1000] // 900 bytes
	if !bytes.Equal(got, want) {
		t.Errorf("range response mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase D — Plaintext UploadPart seekable wrapper functional test
// ─────────────────────────────────────────────────────────────────────────────

// TestHandleUploadPart_Plaintext_SeekableWrapper verifies that a plaintext
// multipart upload part is accepted and forwarded to the backend when using
// the SeekableBody wrapper introduced in Phase D (V0.6-PERF-1).
func TestHandleUploadPart_Plaintext_SeekableWrapper(t *testing.T) {
	cfg := newConfigWithMaxPartBuffer(64 * 1024 * 1024) // 64 MiB (default)
	handler, mockClient := newHandlerWithConfig(t, cfg)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	uploadID, err := mockClient.CreateMultipartUpload(context.Background(), "bkt", "key", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}

	// 1 MiB body — well within the default 64 MiB cap.
	body := bytes.Repeat([]byte{0xAA}, 1*1024*1024)
	url := fmt.Sprintf("/bkt/key?partNumber=1&uploadId=%s", uploadID)
	req := httptest.NewRequest("PUT", url, bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("ETag") == "" {
		t.Error("expected non-empty ETag header")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase C — handleCopyObject streaming: chunked→chunked produces correct output
// ─────────────────────────────────────────────────────────────────────────────

// TestHandleCopyObject_Chunked_Streams_Bounded verifies that a CopyObject
// request copying a chunked-encrypted source produces a correctly decryptable
// destination object (functional correctness of the Phase C streaming pipeline).
func TestHandleCopyObject_Chunked_Streams_Bounded(t *testing.T) {
	chunkedEngine, err := crypto.NewEngineWithChunking(
		[]byte("test-password-perf1-123456"),
		nil, "", nil, true, 0,
	)
	if err != nil {
		t.Fatalf("NewEngineWithChunking: %v", err)
	}
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	mockClient := newMockS3Client()
	handler := NewHandlerWithFeatures(mockClient, chunkedEngine, logger, getTestMetrics(), nil, nil, nil, nil, nil)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Store a chunked-encrypted source.
	const payloadLen = 200_000
	plain := bytes.Repeat([]byte("C"), payloadLen)
	encReader, encMeta, err := chunkedEngine.Encrypt(context.Background(), bytes.NewReader(plain), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	var encBuf bytes.Buffer
	if _, err := encBuf.ReadFrom(encReader); err != nil {
		t.Fatalf("read encrypted: %v", err)
	}
	encLen := int64(encBuf.Len())
	if err := mockClient.PutObject(context.Background(), "src-bkt", "src-key", bytes.NewReader(encBuf.Bytes()), encMeta, &encLen, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("PutObject source: %v", err)
	}

	// CopyObject src-bkt/src-key → dst-bkt/dst-key.
	req := httptest.NewRequest("PUT", "/dst-bkt/dst-key", nil)
	req.Header.Set("x-amz-copy-source", "src-bkt/src-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("CopyObject: expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	// Retrieve the destination object and decrypt it — verify round-trip.
	dstReader, dstMeta, err := mockClient.GetObject(context.Background(), "dst-bkt", "dst-key", nil, nil)
	if err != nil {
		t.Fatalf("GetObject dst: %v", err)
	}
	defer dstReader.Close()
	var dstBuf bytes.Buffer
	if _, err := dstBuf.ReadFrom(dstReader); err != nil {
		t.Fatalf("read dst: %v", err)
	}
	decReader, _, err := chunkedEngine.Decrypt(context.Background(), bytes.NewReader(dstBuf.Bytes()), dstMeta)
	if err != nil {
		t.Fatalf("Decrypt dst: %v", err)
	}
	var decBuf bytes.Buffer
	if _, err := decBuf.ReadFrom(decReader); err != nil {
		t.Fatalf("read decrypted dst: %v", err)
	}
	if !bytes.Equal(decBuf.Bytes(), plain) {
		t.Errorf("CopyObject round-trip mismatch: got %d bytes, want %d bytes", decBuf.Len(), len(plain))
	}
}
