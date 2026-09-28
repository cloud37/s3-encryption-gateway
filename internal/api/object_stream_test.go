package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

type failingObjectReader struct{ err error }

func (r failingObjectReader) Read([]byte) (int, error) { return 0, r.err }

func TestStreamObjectBody_IntegrityFailureRecordedOnce(t *testing.T) {
	h := &Handler{metrics: getTestMetrics()}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	w := httptest.NewRecorder()
	_, err := h.streamObjectBody(w, req, "bucket", "key", failingObjectReader{err: errors.New("AEAD authentication failed")})
	if err == nil {
		t.Fatal("expected stream error")
	}
}

func TestStreamObjectBody_NetworkFailureNotClassifiedAsIntegrity(t *testing.T) {
	h := &Handler{metrics: getTestMetrics()}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	w := httptest.NewRecorder()
	_, err := h.streamObjectBody(w, req, "bucket", "key", failingObjectReader{err: io.ErrClosedPipe})
	if err == nil {
		t.Fatal("expected stream error")
	}
}

func TestRecordObjectStreamFailure_NetworkAndCanceledContext(t *testing.T) {
	h := &Handler{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil).WithContext(ctx)
	h.recordObjectStreamFailure(r, "bucket", "key", io.ErrClosedPipe)
	h.recordObjectStreamFailure(r, "bucket", "key", errors.New("decryption failed"))
}

func TestRecordObjectStreamFailure_IntegrityEmitsOneMetricAndAudit(t *testing.T) {
	registry := prometheus.NewRegistry()
	auditLog := audit.NewLogger(10, nil)
	h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry), auditLogger: auditLog}
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	h.recordObjectStreamFailure(r, "bucket", "key", errors.New("decryption failed"))
	if got := metricSample(t, registry, "encryption_errors_total", `operation="decrypt"`, `error_type="object_integrity_failure"`); got != 1 {
		t.Fatalf("stream integrity metric=%v", got)
	}
	if got := metricSample(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="client_stream"`); got != 0 {
		t.Fatalf("integrity failure was counted as client stream error: %v", got)
	}
	if events := auditLog.GetEvents(); len(events) != 1 || events[0].Success {
		t.Fatalf("stream integrity audit events=%+v", events)
	}
}

func TestRecordObjectStreamFailure_NilErrorNoop(t *testing.T) {
	registry := prometheus.NewRegistry()
	h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry)}
	h.recordObjectStreamFailure(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), "bucket", "key", nil)
	if strings.Contains(scrapeMetrics(t, registry), `object_integrity_failure`) {
		t.Fatal("nil stream error changed integrity metric")
	}
}

func TestRecordObjectStreamFailure_ContextCanceledFailureSkipsIntegrityAccounting(t *testing.T) {
	registry := prometheus.NewRegistry()
	auditLog := audit.NewLogger(10, nil)
	h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry), auditLogger: auditLog}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil).WithContext(ctx)
	h.recordObjectStreamFailure(r, "bucket", "key", errors.New("decryption failed"))
	if len(auditLog.GetEvents()) != 0 {
		t.Fatalf("canceled stream emitted audit events: %+v", auditLog.GetEvents())
	}
	if got := metricSample(t, registry, "encryption_errors_total", `operation="decrypt"`, `error_type="object_integrity_failure"`); got != 0 {
		t.Fatalf("canceled stream integrity metric=%v", got)
	}
}

func TestRecordObjectStreamFailure_NetworkErrorCountsClientStreamOnce(t *testing.T) {
	registry := prometheus.NewRegistry()
	h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry)}
	h.recordObjectStreamFailure(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), "bucket", "key", syscall.EPIPE)
	if got := metricSample(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="client_stream"`); got != 1 {
		t.Fatalf("client stream error metric=%v, want exactly once", got)
	}
	if got := metricSample(t, registry, "encryption_errors_total", `operation="decrypt"`, `error_type="object_integrity_failure"`); got != 0 {
		t.Fatalf("network error counted as integrity failure: %v", got)
	}
}

func TestBoundedCacheCapture_LimitsAndMarksOverflow(t *testing.T) {
	capture := newBoundedCacheCapture(4)
	if _, err := io.Copy(capture, strings.NewReader("1234")); err != nil {
		t.Fatal(err)
	}
	if capture.Overflowed() || capture.String() != "1234" {
		t.Fatalf("exact-limit capture overflow=%t body=%q", capture.Overflowed(), capture.String())
	}
	if _, err := capture.Write([]byte("5")); err != nil {
		t.Fatal(err)
	}
	if !capture.Overflowed() {
		t.Fatal("oversized capture was not marked overflowed")
	}
}

func TestBoundedCacheCapture_ZeroLengthAndNegativeLimit(t *testing.T) {
	zero := newBoundedCacheCapture(0)
	if n, err := zero.Write(nil); err != nil || n != 0 || zero.Overflowed() {
		t.Fatalf("empty write = (%d,%v), overflow=%t", n, err, zero.Overflowed())
	}
	if n, err := zero.Write([]byte("x")); err != nil || n != 1 || !zero.Overflowed() {
		t.Fatalf("over-limit write = (%d,%v), overflow=%t", n, err, zero.Overflowed())
	}
	if cacheCaptureEligibility(-1, 1) || cacheCaptureEligibility(0, 0) || !cacheCaptureEligibility(0, 1) {
		t.Fatal("cache capture size eligibility mismatch")
	}
}

func TestStreamObjectBody_SuccessAndResponseWriteFailure(t *testing.T) {
	h := &Handler{}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	w := httptest.NewRecorder()
	n, err := h.streamObjectBody(w, req, "bucket", "key", strings.NewReader("streamed"))
	if err != nil || n != int64(len("streamed")) || w.Body.String() != "streamed" {
		t.Fatalf("stream result=(%d,%v) body=%q", n, err, w.Body.String())
	}
	failed := &writeErrorResponseWriter{ResponseWriter: httptest.NewRecorder(), err: io.ErrClosedPipe}
	if _, err := h.streamObjectBody(failed, req, "bucket", "key", strings.NewReader("body")); err == nil {
		t.Fatal("response write failure was hidden")
	}
}

func TestServeObjectBody_ResponseWriterFailureIsNotTamper(t *testing.T) {
	registry := prometheus.NewRegistry()
	auditLog := audit.NewLogger(10, nil)
	h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry), auditLogger: auditLog}
	w := &writeErrorResponseWriter{ResponseWriter: httptest.NewRecorder(), err: errors.New("AEAD authentication failed")}
	plan := objectReadPlan{
		Bucket: "bucket", Key: "key", Status: http.StatusOK, Headers: make(http.Header),
		Body: strings.NewReader("plaintext"), Class: crypto.ObjectClass{Encrypted: true},
		DecryptSuccess: &objectDecryptSuccess{Algorithm: crypto.AlgorithmAES256GCM},
	}
	if _, err := h.serveObjectBody(w, httptest.NewRequest(http.MethodGet, "/bucket/key", nil), plan); err == nil {
		t.Fatal("expected response writer failure")
	}
	if got := metricSample(t, registry, "encryption_errors_total", `operation="decrypt"`, `error_type="object_integrity_failure"`); got != 0 {
		t.Fatalf("writer failure recorded tamper metric=%v", got)
	}
	if got := metricSample(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="client_stream"`); got != 1 {
		t.Fatalf("writer failure client-stream metric=%v, want exactly once", got)
	}
	if got := metricTotal(t, registry, "http_requests_total", `method="GET"`, `path="/bucket/*"`); got != 1 {
		t.Fatalf("request accounting=%v, want exactly once", got)
	}
	if events := auditLog.GetEvents(); len(events) != 0 {
		t.Fatalf("writer failure emitted integrity audit events: %+v", events)
	}
}

func TestServeObjectBody_DecryptAccountingOccursAfterSuccessfulStreamOnly(t *testing.T) {
	t.Run("complete body records one success", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		auditLog := audit.NewLogger(10, nil)
		h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry), auditLogger: auditLog}
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		plan := objectReadPlan{
			Bucket: "bucket", Key: "key", Status: http.StatusOK,
			Headers: make(http.Header), Body: strings.NewReader("body"),
			Class:          crypto.ObjectClass{Encrypted: true},
			DecryptSuccess: &objectDecryptSuccess{Algorithm: crypto.AlgorithmAES256GCM, PlainSize: 4},
		}
		if _, err := h.serveObjectBody(httptest.NewRecorder(), r, plan); err != nil {
			t.Fatal(err)
		}
		if got := metricSample(t, registry, "encryption_operations_total", `operation="decrypt"`); got != 1 {
			t.Fatalf("decrypt success metric=%v, want one", got)
		}
		if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `status="OK"`); got != 1 {
			t.Fatalf("successful request metric=%v, want one", got)
		}
		events := auditLog.GetEvents()
		if len(events) != 1 || !events[0].Success {
			t.Fatalf("decrypt success audit events=%+v", events)
		}
	})

	t.Run("post-header failure records failure but no success", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		auditLog := audit.NewLogger(10, nil)
		h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry), auditLogger: auditLog}
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		body := io.MultiReader(strings.NewReader("partial"), failingObjectReader{err: errors.New("AEAD authentication failed")})
		plan := objectReadPlan{
			Bucket: "bucket", Key: "key", Status: http.StatusOK,
			Headers: make(http.Header), Body: body,
			Class:          crypto.ObjectClass{Encrypted: true},
			DecryptSuccess: &objectDecryptSuccess{Algorithm: crypto.AlgorithmAES256GCM, PlainSize: 99},
		}
		if _, err := h.serveObjectBody(httptest.NewRecorder(), r, plan); err == nil {
			t.Fatal("expected post-header body failure")
		}
		if got := metricSample(t, registry, "encryption_operations_total", `operation="decrypt"`); got != 0 {
			t.Fatalf("decrypt success metric=%v, want zero", got)
		}
		if got := metricSample(t, registry, "encryption_errors_total", `operation="decrypt"`, `error_type="object_integrity_failure"`); got != 1 {
			t.Fatalf("decrypt failure metric=%v, want one", got)
		}
		if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `status="Internal Server Error"`); got != 1 {
			t.Fatalf("failure request metric=%v, want one", got)
		}
		events := auditLog.GetEvents()
		if len(events) != 1 || events[0].Success {
			t.Fatalf("failure audit events=%+v", events)
		}
	})
}

func TestServeMPURangedGet_FailureWritesOneErrorAndMetric(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "range-error-writer-*")
	registry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(registry)
	meta := map[string]string{crypto.MetaMPUEncrypted: "v2"}
	request := httptest.NewRequest(http.MethodGet, "/bucket/object", nil)
	request = mux.SetURLVars(request, map[string]string{"bucket": "bucket", "key": "object"})
	request.Header.Set("Range", "bytes=0-1")
	w := httptest.NewRecorder()
	h.serveMPURangedGet(w, request, request.Context(), "bucket", "object", nil, meta, "bytes=0-1", h.s3Client, time.Now())
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "InternalError") {
		t.Fatalf("MPU ranged failure status=%d body=%q", w.Code, w.Body.String())
	}
	if strings.Count(w.Body.String(), "<Error>") != 1 {
		t.Fatalf("expected one error response, got %q", w.Body.String())
	}
	if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `status="Internal Server Error"`); got != 1 {
		t.Fatalf("failure HTTP metric=%v, want exactly one", got)
	}
	if got := metricSample(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="InternalError"`); got != 1 {
		t.Fatalf("failure S3 error metric=%v, want exactly one; metrics=%s", got, scrapeMetrics(t, registry))
	}
}

func TestServeMPURangedGet_PostHeaderTamperUsesSingleStreamAccounting(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "range-post-header-tamper-*")
	registry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(registry)
	auditLog := audit.NewLogger(10, nil)
	h.auditLogger = auditLog
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "range-post-header-tamper-bucket", "object"
	plain := bytes.Repeat([]byte("P"), crypto.DefaultChunkSize+32)
	doCompleteUpload(t, router, bucket, key, plain)
	// The first chunk is authenticated and written before the second chunk's
	// tag fails, exercising the committed-response accounting path.
	client.objects[bucket+"/"+key][crypto.DefaultChunkSize+16] ^= 1
	request := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	request.Header.Set("Range", "bytes=0-")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != http.StatusPartialContent || w.Body.Len() == 0 {
		t.Fatalf("post-header tamper response status=%d bytes=%d", w.Code, w.Body.Len())
	}
	if got := metricSample(t, registry, "encryption_errors_total", `error_type="object_integrity_failure"`, `operation="decrypt"`); got != 1 {
		t.Fatalf("integrity metric=%v, want exactly one", got)
	}
	if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `path="/range-post-header-tamper-bucket/*"`, `status="Internal Server Error"`); got != 1 {
		t.Fatalf("post-header failure HTTP metric=%v, want exactly one", got)
	}
	if got := metricTotal(t, registry, "http_requests_total", `method="GET"`, `path="/range-post-header-tamper-bucket/*"`); got != 1 {
		t.Fatalf("total HTTP request samples across statuses=%v, want exactly one", got)
	}
	if got := metricSample(t, registry, "s3_operation_errors_total", `error_type="client_stream"`, `operation="GetObject"`); got != 0 {
		t.Fatalf("tamper counted as network error: %v", got)
	}
	var tamperEvents int
	for _, event := range auditLog.GetEvents() {
		if event.Operation == "object_stream_integrity_failure" {
			tamperEvents++
		}
	}
	if tamperEvents != 1 {
		t.Fatalf("tamper audit event count=%d, events=%+v; want one integrity event", tamperEvents, auditLog.GetEvents())
	}
}

func TestServeMPURangedGet_FirstChunkTamperPrecedesSuccessHeaders(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "range-first-chunk-tamper-*")
	registry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(registry)
	auditLog := audit.NewLogger(10, nil)
	h.auditLogger = auditLog
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "range-first-chunk-tamper-bucket", "object"
	plain := bytes.Repeat([]byte("F"), crypto.DefaultChunkSize+32)
	doCompleteUpload(t, router, bucket, key, plain)
	client.objects[bucket+"/"+key][crypto.DefaultChunkSize/2] ^= 1

	request := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	request.Header.Set("Range", "bytes=0-")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "<Code>InternalError</Code>") {
		t.Fatalf("first ranged MPU chunk tamper response status=%d body=%q", w.Code, w.Body.String())
	}
	if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `path="/range-first-chunk-tamper-bucket/*"`, `status="Internal Server Error"`); got != 1 {
		t.Fatalf("pre-header tamper request metric=%v, want exactly one", got)
	}
	if got := metricSample(t, registry, "encryption_errors_total", `error_type="object_integrity_failure"`, `operation="decrypt"`); got != 1 {
		t.Fatalf("pre-header tamper metric=%v, want exactly one", got)
	}
	if got := metricTotal(t, registry, "http_requests_total", `method="GET"`, `path="/range-first-chunk-tamper-bucket/*"`); got != 1 {
		t.Fatalf("pre-header request accounting=%v, want exactly once", got)
	}
	var tamperEvents int
	for _, event := range auditLog.GetEvents() {
		if event.Operation == "object_stream_integrity_failure" {
			tamperEvents++
		}
	}
	if tamperEvents != 1 {
		t.Fatalf("pre-header tamper audit event count=%d, want exactly one", tamperEvents)
	}
}

func TestServeMPURangedGet_FirstChunkTruncationPrecedesSuccessHeaders(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "range-first-chunk-truncated-*")
	registry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(registry)
	auditLog := audit.NewLogger(10, nil)
	h.auditLogger = auditLog
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "range-first-chunk-truncated-bucket", "object"
	plain := bytes.Repeat([]byte("T"), crypto.DefaultChunkSize+32)
	doCompleteUpload(t, router, bucket, key, plain)

	client.mu.Lock()
	client.objects[bucket+"/"+key] = client.objects[bucket+"/"+key][:crypto.DefaultChunkSize/2]
	client.mu.Unlock()

	request := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	request.Header.Set("Range", "bytes=0-")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != http.StatusInternalServerError || strings.Count(w.Body.String(), "<Error>") != 1 || strings.Count(w.Body.String(), "<Code>InternalError</Code>") != 1 {
		t.Fatalf("first-chunk truncation response status=%d body=%q, want one InternalError XML", w.Code, w.Body.String())
	}
	if w.Header().Get("Content-Range") != "" || bytes.Contains(w.Body.Bytes(), []byte(strings.Repeat("T", 64))) {
		t.Fatalf("first-chunk truncation exposed successful range/plaintext: %q", w.Body.String())
	}
	if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `path="/range-first-chunk-truncated-bucket/*"`, `status="Internal Server Error"`); got != 1 {
		t.Fatalf("pre-header truncation request metric=%v, want exactly one", got)
	}
	if got := metricTotal(t, registry, "http_requests_total", `method="GET"`, `path="/range-first-chunk-truncated-bucket/*"`); got != 1 {
		t.Fatalf("pre-header truncation request accounting=%v, want exactly once", got)
	}
	if got := metricSample(t, registry, "encryption_errors_total", `error_type="object_integrity_failure"`, `operation="decrypt"`); got != 1 {
		t.Fatalf("pre-header truncation integrity metric=%v, want exactly one", got)
	}
	if got := metricSample(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="InternalError"`); got != 1 {
		t.Fatalf("pre-header truncation S3 error metric=%v, want exactly one", got)
	}
	if got := metricSample(t, registry, "encryption_operations_total", `operation="decrypt"`); got != 0 {
		t.Fatalf("pre-header truncation decrypt-success metric=%v, want zero", got)
	}
	var tamperEvents, decryptSuccessEvents int
	for _, event := range auditLog.GetEvents() {
		if event.Operation == "object_stream_integrity_failure" {
			tamperEvents++
		}
		if event.Operation == "decrypt" && event.Success {
			decryptSuccessEvents++
		}
	}
	if tamperEvents != 1 || decryptSuccessEvents != 0 {
		t.Fatalf("pre-header truncation integrity events=%d decrypt-success events=%d; all events=%+v", tamperEvents, decryptSuccessEvents, auditLog.GetEvents())
	}
}

func TestServeMPURangedGet_LaterChunkTruncationUsesSingleStreamAccounting(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "range-later-chunk-truncated-*")
	registry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(registry)
	auditLog := audit.NewLogger(10, nil)
	h.auditLogger = auditLog
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "range-later-chunk-truncated-bucket", "object"
	plain := bytes.Repeat([]byte("L"), 2*crypto.DefaultChunkSize+32)
	doCompleteUpload(t, router, bucket, key, plain)

	client.mu.Lock()
	firstCipherChunk := crypto.DefaultChunkSize + 16
	client.objects[bucket+"/"+key] = client.objects[bucket+"/"+key][:firstCipherChunk+crypto.DefaultChunkSize/2]
	client.mu.Unlock()

	request := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	request.Header.Set("Range", "bytes=0-")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), plain[:crypto.DefaultChunkSize]) {
		t.Fatalf("later-chunk truncation response status=%d bytes=%d, want committed 206 with first authenticated chunk (%d bytes)", w.Code, w.Body.Len(), crypto.DefaultChunkSize)
	}
	if got := metricSample(t, registry, "encryption_errors_total", `error_type="object_integrity_failure"`, `operation="decrypt"`); got != 1 {
		t.Fatalf("post-header truncation integrity metric=%v, want exactly one", got)
	}
	if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `path="/range-later-chunk-truncated-bucket/*"`, `status="Internal Server Error"`); got != 1 {
		t.Fatalf("post-header truncation failure request metric=%v, want exactly one", got)
	}
	if got := metricTotal(t, registry, "http_requests_total", `method="GET"`, `path="/range-later-chunk-truncated-bucket/*"`); got != 1 {
		t.Fatalf("post-header truncation request accounting=%v, want exactly once", got)
	}
	if got := metricSample(t, registry, "encryption_operations_total", `operation="decrypt"`); got != 0 {
		t.Fatalf("post-header truncation decrypt-success metric=%v, want zero", got)
	}
	var tamperEvents, decryptSuccessEvents int
	for _, event := range auditLog.GetEvents() {
		if event.Operation == "object_stream_integrity_failure" {
			tamperEvents++
		}
		if event.Operation == "decrypt" && event.Success {
			decryptSuccessEvents++
		}
	}
	if tamperEvents != 1 || decryptSuccessEvents != 0 {
		t.Fatalf("post-header truncation integrity events=%d decrypt-success events=%d; all events=%+v", tamperEvents, decryptSuccessEvents, auditLog.GetEvents())
	}
}

func TestServeMPURangedGet_LaterChunksUseSingleBodyOwner(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "range-single-body-owner-*")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "range-single-body-owner-bucket", "object"
	plain := bytes.Repeat([]byte("O"), 2*crypto.DefaultChunkSize+17)
	doCompleteUpload(t, router, bucket, key, plain)

	request := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	request.Header.Set("Range", "bytes=0-")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != http.StatusPartialContent || !bytes.Equal(w.Body.Bytes(), plain) {
		t.Fatalf("ranged MPU response status=%d bytes=%d, want 206 and %d plaintext bytes", w.Code, w.Body.Len(), len(plain))
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.rangedReadCount == 0 {
		t.Fatal("MPU ranged body did not fetch the planned ciphertext range")
	}
}

func TestServeMPURangedGet_SuccessUsesSingleRequestAccounting(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "range-success-accounting-*")
	registry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(registry)
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "range-success-accounting-bucket", "object"
	plain := bytes.Repeat([]byte("S"), crypto.DefaultChunkSize+32)
	doCompleteUpload(t, router, bucket, key, plain)
	request := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	request.Header.Set("Range", "bytes=0-")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != http.StatusPartialContent || w.Body.Len() != len(plain) {
		t.Fatalf("ranged response status=%d bytes=%d, want 206 and %d bytes", w.Code, w.Body.Len(), len(plain))
	}
	if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `path="/range-success-accounting-bucket/*"`, `status="Partial Content"`); got != 1 {
		t.Fatalf("successful ranged HTTP metric=%v, want exactly one", got)
	}
	if got := metricTotal(t, registry, "http_requests_total", `method="GET"`, `path="/range-success-accounting-bucket/*"`); got != 1 {
		t.Fatalf("successful total HTTP request samples across statuses=%v, want exactly one", got)
	}
}

func metricSample(t *testing.T, registry *prometheus.Registry, name string, labels ...string) float64 {
	t.Helper()
	for _, line := range strings.Split(scrapeMetrics(t, registry), "\n") {
		if !strings.HasPrefix(line, name+"{") {
			continue
		}
		matches := true
		for _, label := range labels {
			matches = matches && strings.Contains(line, label)
		}
		if !matches {
			continue
		}
		var sample float64
		if _, err := fmt.Sscanf(line[strings.LastIndex(line, "} ")+2:], "%f", &sample); err != nil {
			t.Fatalf("parse metric line %q: %v", line, err)
		}
		return sample
	}
	return 0
}

func metricTotal(t *testing.T, registry *prometheus.Registry, name string, labels ...string) float64 {
	t.Helper()
	var total float64
	for _, line := range strings.Split(scrapeMetrics(t, registry), "\n") {
		if !strings.HasPrefix(line, name+"{") {
			continue
		}
		matches := true
		for _, label := range labels {
			matches = matches && strings.Contains(line, label)
		}
		if !matches {
			continue
		}
		var sample float64
		if _, err := fmt.Sscanf(line[strings.LastIndex(line, "} ")+2:], "%f", &sample); err != nil {
			t.Fatalf("parse metric line %q: %v", line, err)
		}
		total += sample
	}
	return total
}

func scrapeMetrics(t *testing.T, registry *prometheus.Registry) string {
	t.Helper()
	response := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return response.Body.String()
}

func TestPlanObjectReadAndServeObjectBody(t *testing.T) {
	h := &Handler{}
	plan, err := makeObjectResponsePlan(objectResponseSource{Meta: map[string]string{"ETag": "plan-etag"}, BackendETag: "plan-etag", PlainSize: 4}, responseShape{Method: http.MethodGet}, http.StatusOK, strings.NewReader("body"), "bucket", "key")
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	n, err := h.serveObjectBody(w, httptest.NewRequest(http.MethodGet, "/bucket/key", nil), plan)
	if err != nil || n != 4 || w.Code != http.StatusOK || w.Body.String() != "body" || w.Header().Get("ETag") != "plan-etag" {
		t.Fatalf("served planned body n=%d status=%d headers=%v body=%q err=%v", n, w.Code, w.Header(), w.Body.String(), err)
	}
	if _, err := makeObjectResponsePlan(objectResponseSource{PlainSize: -1}, responseShape{Method: http.MethodGet}, http.StatusOK, strings.NewReader(""), "bucket", "key"); err != nil {
		t.Fatalf("unknown-size plan failed: %v", err)
	}
	if _, err := makeObjectResponsePlan(objectResponseSource{Class: crypto.ObjectClass{Encrypted: true}, Meta: map[string]string{crypto.MetaEncrypted: "true"}}, responseShape{Method: http.MethodGet}, http.StatusOK, strings.NewReader(""), "bucket", "key"); err != nil {
		t.Fatalf("encrypted-source plan failed: %v", err)
	}
	if _, err := makeObjectResponsePlan(objectResponseSource{}, responseShape{Method: http.MethodGet}, http.StatusOK, strings.NewReader(""), "", "key"); err == nil {
		t.Fatal("missing bucket was accepted by read planner")
	}
	if _, err := makeObjectResponsePlan(objectResponseSource{}, responseShape{Method: http.MethodGet}, http.StatusOK, strings.NewReader(""), "bucket", ""); err == nil {
		t.Fatal("missing key was accepted by read planner")
	}
	if _, err := makeObjectResponsePlan(objectResponseSource{Meta: map[string]string{"ETag": "only-source"}, BackendETag: "only-source", PlainSize: 1}, responseShape{Method: http.MethodGet}, http.StatusOK, strings.NewReader("x"), "bucket", "key"); err != nil {
		t.Fatalf("source-only read plan failed: %v", err)
	}
	if _, err := makeObjectResponsePlan(objectResponseSource{}, responseShape{}, http.StatusOK, strings.NewReader(""), "", "key"); err == nil {
		t.Fatal("empty bucket accepted by response plan")
	}
	if _, err := makeObjectResponsePlan(objectResponseSource{}, responseShape{}, http.StatusOK, strings.NewReader(""), "bucket", ""); err == nil {
		t.Fatal("empty key accepted by response plan")
	}
	if _, err := makeObjectResponsePlan(objectResponseSource{}, responseShape{}, http.StatusOK, strings.NewReader(""), "", "key"); err == nil {
		t.Fatal("response plan accepted an empty bucket")
	}
	if _, err := (&Handler{}).objectResponsePlan(objectResponseSource{}, responseShape{}, http.StatusOK, strings.NewReader(""), "", "key"); err == nil {
		t.Fatal("handler response plan accepted an empty bucket")
	}
	client := newMockS3Client()
	client.objects["bucket/key"] = []byte("plain")
	client.metadata["bucket/key"] = map[string]string{"Content-Length": "5", "ETag": "plain-etag"}
	h = &Handler{s3Client: client}
	rangeHeader := "bytes=1-3"
	decision, err := h.planObjectRead(context.Background(), client, "bucket", "key", nil, client.metadata["bucket/key"], &rangeHeader)
	if err != nil || decision.View == nil || decision.Class.Encrypted || !decision.isPassthroughRange() || decision.RangeStart != 1 || decision.RangeEnd != 3 || decision.RangeTotal != 5 || decision.BackendRange == nil {
		t.Fatalf("plaintext planning=%+v err=%v", decision, err)
	}
	mpuClient := newMockS3Client()
	mpuMeta := map[string]string{
		crypto.MetaMPUEncrypted:    "v2",
		crypto.MetaObjectBindingID: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		crypto.MetaFallbackPointer: "mpu" + crypto.MPUManifestSuffix,
	}
	mpuClient.metadata["bucket/mpu"] = mpuMeta
	mpuClient.objects["bucket/mpu"] = []byte("ciphertext")
	// MPU range planning also loads the authenticated manifest before allowing
	// the handler to select plaintext range semantics.
	mpuPlan, err := (&Handler{s3Client: mpuClient}).planObjectRead(context.Background(), mpuClient, "bucket", "mpu", nil, mpuMeta, &rangeHeader)
	if err == nil || !strings.Contains(err.Error(), "fetch manifest") {
		t.Fatalf("MPU planner did not own missing-manifest preflight: plan=%+v err=%v", mpuPlan, err)
	}
	if _, err := h.planObjectRead(context.Background(), client, "", "key", nil, nil, nil); err == nil {
		t.Fatal("missing bucket accepted by read planner")
	}
	if _, err := h.serveObjectBody(&writeErrorResponseWriter{ResponseWriter: httptest.NewRecorder(), err: io.ErrClosedPipe}, httptest.NewRequest(http.MethodGet, "/bucket/key", nil), objectReadPlan{Bucket: "bucket", Key: "key", Status: http.StatusOK, Body: strings.NewReader("fail")}); err == nil {
		t.Fatal("planned body writer error was hidden")
	}
}

func TestRawMetadataValue_RegistryCanonicalAndCompact(t *testing.T) {
	if got := rawMetadataValue(map[string]string{crypto.MetaOriginalSize: "7"}, crypto.MetaOriginalSize); got != "7" {
		t.Fatalf("canonical lookup=%q", got)
	}
	if got := rawMetadataValue(map[string]string{"x-amz-meta-os": "8"}, crypto.MetaOriginalSize); got != "8" {
		t.Fatalf("compact lookup=%q", got)
	}
	if got := rawMetadataValue(nil, "unregistered-key"); got != "" {
		t.Fatalf("unknown lookup=%q", got)
	}
}

func TestPlanObjectRead_OwnsClassificationSizeAndRange(t *testing.T) {
	client := newMockS3Client()
	client.objects["bucket/key"] = []byte("plain")
	client.metadata["bucket/key"] = map[string]string{"Content-Length": "5", "ETag": "plain-etag"}
	h := &Handler{s3Client: client}
	rangeHeader := "bytes=1-3"
	plan, err := h.planObjectRead(context.Background(), client, "bucket", "key", nil, client.metadata["bucket/key"], &rangeHeader)
	if err != nil {
		t.Fatal(err)
	}
	if plan.View == nil || plan.Class.Encrypted || !plan.isPassthroughRange() || plan.RangeStart != 1 || plan.RangeEnd != 3 || plan.RangeTotal != 5 || plan.BackendRange == nil || *plan.BackendRange != rangeHeader {
		t.Fatalf("plaintext plan=%+v", plan)
	}
	if _, err := h.planObjectRead(context.Background(), client, "", "key", nil, nil, nil); err == nil {
		t.Fatal("missing bucket accepted by read planner")
	}
	client.metadata["bucket/key"] = map[string]string{crypto.MetaMPUEncrypted: "unexpected"}
	if _, err := h.planObjectRead(context.Background(), client, "bucket", "key", nil, client.metadata["bucket/key"], &rangeHeader); err == nil {
		t.Fatal("unknown encrypted MPU marker accepted by read planner")
	}
}

func TestPlanObjectRead_LegacyChunkedRangeUsesFullFetch(t *testing.T) {
	for _, tc := range []struct {
		name      string
		metadata  map[string]string
		optimized bool
		fullFetch bool
	}{
		{"legacy full fetch", map[string]string{crypto.MetaEncrypted: "true", crypto.MetaChunkedFormat: "true", "Content-Length": "49200"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newMockS3Client()
			key := "object"
			client.objects["bucket/"+key] = make([]byte, 49200)
			client.metadata["bucket/"+key] = tc.metadata
			h, _, _ := newMPUTestHandler(t, "planner-"+strings.ReplaceAll(tc.name, " ", "-")+"-*")
			plan, err := h.planObjectRead(context.Background(), client, "bucket", key, nil, tc.metadata, ptr("bytes=1-200"))
			if err != nil {
				t.Fatal(err)
			}
			if plan.usesOptimizedRange() != tc.optimized || (plan.BackendRange == nil) != tc.fullFetch {
				t.Fatalf("plan=%+v", plan)
			}
		})
	}
}

func TestOptimizedEncryptedRange_PreflightsTamperedFirstChunk(t *testing.T) {
	client := newMockS3Client()
	engine, err := newAPIUnitChunkedEngine([]byte("optimized-range-password"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatal(err)
	}
	plain := makeByteRamp(crypto.MinChunkSize*3, 17)
	object := crypto.ObjectContext{Bucket: "optimized-range-bucket", Key: "object"}
	encReader, metadata, err := engine.Encrypt(context.Background(), object, bytes.NewReader(plain), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatal(err)
	}
	// Corrupt data in the chunk intersecting the planned optimized range.
	corruptAt := crypto.MinChunkSize + 17
	ciphertext[corruptAt] ^= 0x80
	metadata["Content-Length"] = strconv.Itoa(len(ciphertext))
	client.objects[object.Bucket+"/"+object.Key] = ciphertext
	client.metadata[object.Bucket+"/"+object.Key] = metadata
	h := NewHandler(client, engine, logrus.New(), getTestMetrics())
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	request := httptest.NewRequest(http.MethodGet, "/"+object.Bucket+"/"+object.Key, nil)
	request.Header.Set("Range", "bytes=17000-17100")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "InternalError") {
		t.Fatalf("tampered optimized range status=%d body=%q", w.Code, w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), plain[17000:17101]) {
		t.Fatal("tampered optimized range leaked plaintext")
	}
}

type writeErrorResponseWriter struct {
	http.ResponseWriter
	err error
}

func (w *writeErrorResponseWriter) Write([]byte) (int, error) { return 0, w.err }

func TestRecordObjectIntegrityFailure_HandlesNilOptionalDependencies(t *testing.T) {
	h := &Handler{}
	h.recordObjectIntegrityFailure(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), "bucket", "key", errors.New("auth failure"))
}

func TestLoadMPUManifestSize_ValidAndInvalidMetadata(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "manifest-size-*")
	ctx := context.Background()
	bucket, key := "manifest-size-bucket", "object"
	manifestKey := key + crypto.MPUManifestSuffix
	manifest := &crypto.MultipartManifest{Version: 1, Algorithm: crypto.AlgorithmAES256GCM, ChunkSize: crypto.DefaultChunkSize, TotalPlainSize: 29}
	plain, err := manifest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		t.Fatal(err)
	}
	reader, meta, err := engine.Encrypt(ctx, crypto.ObjectContext{Bucket: bucket, Key: manifestKey}, bytes.NewReader(plain), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	client.objects[bucket+"/"+manifestKey] = ciphertext
	client.metadata[bucket+"/"+manifestKey] = meta
	got, err := h.loadMPUManifestSize(ctx, client, bucket, key, map[string]string{crypto.MetaMPUEncrypted: "true"})
	if err != nil || got != manifest.TotalPlainSize {
		t.Fatalf("size=%d err=%v want %d", got, err, manifest.TotalPlainSize)
	}
	if _, err := h.loadMPUManifestSize(ctx, client, bucket, key, map[string]string{crypto.MetaMPUEncrypted: "invalid"}); err == nil {
		t.Fatal("invalid MPU marker accepted")
	}
	view, err := h.loadObjectView(bucket, key, nil, map[string]string{crypto.MetaMPUEncrypted: "true", crypto.MetaFallbackPointer: manifestKey})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.loadMPUManifest(ctx, client, bucket, key, view.Class); err != nil {
		t.Fatalf("load valid MPU manifest: %v", err)
	}
	missingClass := crypto.ObjectClass{Format: crypto.FormatMPUV1, Encrypted: true, ManifestKey: "missing-manifest" + crypto.MPUManifestSuffix}
	if _, err := h.loadMPUManifest(ctx, client, bucket, "missing-manifest", missingClass); err == nil || !strings.Contains(err.Error(), "fetch manifest") {
		t.Fatalf("missing manifest error=%v", err)
	}
}

func TestPlanFullObjectRead_UsesAuthoritativeMPUHeadSource(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "full-mpu-plan-*")
	ctx := context.Background()
	bucket, key := "full-mpu-plan-bucket", "object"
	manifestKey := key + crypto.MPUManifestSuffix
	manifest := &crypto.MultipartManifest{Version: 1, Algorithm: crypto.AlgorithmAES256GCM, ChunkSize: crypto.DefaultChunkSize, TotalPlainSize: 29}
	plain, err := manifest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		t.Fatal(err)
	}
	manifestReader, manifestMeta, err := engine.Encrypt(ctx, crypto.ObjectContext{Bucket: bucket, Key: manifestKey}, bytes.NewReader(plain), nil)
	if err != nil {
		t.Fatal(err)
	}
	manifestBody, err := io.ReadAll(manifestReader)
	if err != nil {
		t.Fatal(err)
	}
	client.objects[bucket+"/"+manifestKey], client.metadata[bucket+"/"+manifestKey] = manifestBody, manifestMeta
	client.objects[bucket+"/"+key] = []byte("encrypted-mpu-body")
	client.metadata[bucket+"/"+key] = map[string]string{crypto.MetaMPUEncrypted: "true", crypto.MetaFallbackPointer: manifestKey, "ETag": "backend-mpu-etag", "x-amz-meta-owner": "team"}
	readerMeta := map[string]string{crypto.MetaMPUEncrypted: "true", crypto.MetaFallbackPointer: manifestKey, "ETag": "backend-mpu-etag"}
	plan, err := h.planFullObjectRead(ctx, client, bucket, key, nil, readerMeta)
	if err != nil {
		t.Fatal(err)
	}
	if plan.View == nil || plan.isMPURange() || plan.Size.Size != 29 || plan.Source.Meta["x-amz-meta-owner"] != "team" {
		t.Fatalf("full MPU plan lost authoritative source/size: %+v", plan)
	}
}

func TestPlanObjectRead_PreservesMPURangeOverrideAndManifestOwner(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "mpu-range-plan-*")
	ctx := context.Background()
	bucket, key := "mpu-range-plan-bucket", "object"
	plain := bytes.Repeat([]byte("M"), sec42MPUPlainSize)
	router := sec42Router(t, h)
	doCompleteUpload(t, router, bucket, key, plain)
	rangeHeader := "bytes=0-10"
	plan, err := h.planObjectRead(ctx, client, bucket, key, nil, client.metadata[bucket+"/"+key], &rangeHeader)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.isMPURange() || plan.MPURange == nil || plan.MPUManifest == nil || plan.MPUDecrypt == nil || plan.BackendRange == nil || plan.Source.Decrypted == nil || plan.Size.Source != "mpu-manifest" || plan.Size.Size != int64(len(plain)) {
		t.Fatalf("MPU range plan lost its authenticated manifest override: %+v", plan)
	}
	wantRange := fmt.Sprintf("bytes=%d-%d", plan.MPURange.EncStart, plan.MPURange.EncEnd)
	if *plan.BackendRange != wantRange || plan.Source.PlainSize != int64(len(plain)) {
		t.Fatalf("MPU read decisions are not authoritative: backend range=%v source size=%d want range=%q size=%d", plan.BackendRange, plan.Source.PlainSize, wantRange, len(plain))
	}
}
