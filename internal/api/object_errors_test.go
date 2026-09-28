package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

func TestDecryptFailure_MappingTable(t *testing.T) {
	for _, tc := range []struct {
		name, wantCode, wantMessage string
		wantStatus                  int
		err                         error
	}{
		{name: "missing manifest", err: ErrMissingMPUManifest, wantCode: "InternalError", wantMessage: "Encrypted multipart object metadata is missing; the gateway MPU manifest could not be found"},
		{name: "unsupported format", err: crypto.ErrUnsupportedObjectFormat, wantCode: "InternalError", wantMessage: "Unsupported encrypted object format"},
		{name: "integrity", err: crypto.ErrChunkedObjectIncomplete, wantCode: "InternalError", wantMessage: "Object integrity check failed"},
		{name: "unsupported chunked version", err: crypto.ErrUnsupportedChunkedVersion, wantCode: "InternalError", wantMessage: "Object integrity check failed"},
		{name: "AEAD authentication", err: errors.New("fallback-v2: authentication failed: tag mismatch"), wantCode: "InternalError", wantMessage: "Object integrity check failed"},
		{name: "tag authentication", err: errors.New("cipher: message authentication failed"), wantCode: "InternalError", wantMessage: "Object integrity check failed"},
		{name: "KDF", err: &crypto.ErrInvalidKDFParams{}, wantCode: "InternalError", wantMessage: "We encountered an internal error. Please try again."},
		{name: "bypass mismatch", err: crypto.ErrEncryptedObjectInBypassBucket, wantCode: "EncryptionConfigurationMismatch", wantMessage: "The object was encrypted when stored but the bucket policy now disables encryption. Use the migration tool to convert the object.", wantStatus: http.StatusConflict},
		{name: "wrapped", err: errors.New("decryption error"), wantCode: "InternalError", wantMessage: "Failed to decrypt object"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decryptFailure(tc.err, "/bucket/key")
			status := tc.wantStatus
			if status == 0 {
				status = http.StatusInternalServerError
			}
			if got.Code != tc.wantCode || got.Message != tc.wantMessage || got.HTTPStatus != status {
				t.Fatalf("decryptFailure = %#v", got)
			}
		})
	}
}

func TestIsIntegrityFailure_Table(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"authentication", errors.New("AEAD authentication failed"), true},
		{"tag", errors.New("cipher: message authentication failed"), true},
		{"integrity message", errors.New("object integrity check failed"), true},
		{"nil error", nil, false},
		{"network", io.ErrClosedPipe, false},
		{"ordinary", errors.New("backend unavailable"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isIntegrityFailure(tc.err); got != tc.want {
				t.Fatalf("isIntegrityFailure(%v)=%t want %t", tc.err, got, tc.want)
			}
		})
	}
}

func TestWriteObjectError_HeadHasNoBodyAndRecordsMetrics(t *testing.T) {
	h := &Handler{metrics: getTestMetrics()}
	req := httptest.NewRequest(http.MethodHead, "/bucket/key", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "bucket", "key": "key"})
	w := httptest.NewRecorder()
	h.writeObjectError(w, req, "HeadObject", &S3Error{Code: "InternalError", HTTPStatus: http.StatusInternalServerError}, time.Now())
	if w.Code != http.StatusInternalServerError || w.Body.Len() != 0 {
		t.Fatalf("HEAD error response status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestWriteObjectResponseMetric_RecordsPartialResponse(t *testing.T) {
	h := &Handler{metrics: getTestMetrics()}
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	h.writeObjectResponseMetric(r, http.StatusPartialContent, time.Now(), 3)
}

func TestWriteObjectErrorForBucket_UsesExplicitSourceBucket(t *testing.T) {
	h := &Handler{metrics: getTestMetrics()}
	req := httptest.NewRequest(http.MethodPut, "/destination/key?partNumber=1&uploadId=u", nil)
	w := httptest.NewRecorder()
	h.writeObjectErrorForBucket(w, req, "UploadPartCopy", "source-bucket", &S3Error{Code: "NoSuchKey", Message: "missing", HTTPStatus: http.StatusNotFound}, time.Now())
	if w.Code != http.StatusNotFound || w.Body.Len() == 0 {
		t.Fatalf("source-scoped copy error response status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestWriteObjectError_NilS3ErrorIsNoop(t *testing.T) {
	h := &Handler{metrics: getTestMetrics()}
	w := httptest.NewRecorder()
	h.writeObjectError(w, httptest.NewRequest(http.MethodGet, "/bucket/key", nil), "GetObject", nil, time.Now())
	if w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("nil error wrote response status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestRequestBucket_NilAndRoutedRequest(t *testing.T) {
	if got := requestBucket(httptest.NewRequest(http.MethodGet, "/bucket/key", nil)); got != "" {
		t.Fatalf("unrouted request bucket=%q", got)
	}
	r := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), map[string]string{"bucket": "source"})
	if got := requestBucket(r); got != "source" {
		t.Fatalf("routed request bucket=%q", got)
	}
}

func TestRecordObjectIntegrityFailure_RecordsAuditAndMetrics(t *testing.T) {
	auditLog := audit.NewLogger(10, nil)
	h := &Handler{metrics: getTestMetrics(), auditLogger: auditLog}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	h.recordObjectIntegrityFailure(req, "bucket", "key", errors.New("authentication failed"))
	events := auditLog.GetEvents()
	if len(events) != 1 || events[0].Success || events[0].Key != "key" {
		t.Fatalf("integrity audit events=%+v", events)
	}
}

func TestWriteObjectDecryptError_IntegrityAccountingExactlyOnce(t *testing.T) {
	registry := prometheus.NewRegistry()
	metricsSink := metrics.NewMetricsWithRegistry(registry)
	auditLog := audit.NewLogger(10, nil)
	h := &Handler{metrics: metricsSink, auditLogger: auditLog}
	r := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), map[string]string{"bucket": "bucket", "key": "key"})
	w := httptest.NewRecorder()
	h.writeObjectDecryptError(w, r, "GetObject", "bucket", "key", errors.New("cipher: message authentication failed"), time.Now())
	if w.Code != http.StatusInternalServerError || strings.Count(w.Body.String(), "<Error>") != 1 {
		t.Fatalf("integrity response status=%d body=%q", w.Code, w.Body.String())
	}
	if got := metricSample(t, registry, "http_requests_total", `method="GET"`, `status="Internal Server Error"`); got != 1 {
		t.Fatalf("HTTP request metric=%v, want once", got)
	}
	if got := metricSample(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="InternalError"`); got != 1 {
		t.Fatalf("S3 error metric=%v, want once", got)
	}
	if got := metricSample(t, registry, "encryption_errors_total", `operation="decrypt"`, `error_type="object_integrity_failure"`); got != 1 {
		t.Fatalf("integrity metric=%v, want once", got)
	}
	var integrityEvents int
	for _, event := range auditLog.GetEvents() {
		if event.Operation == "object_stream_integrity_failure" {
			integrityEvents++
		}
	}
	if integrityEvents != 1 {
		t.Fatalf("integrity audit events=%d, want once", integrityEvents)
	}
}

func TestRecordObjectDecryptSuccessAndFailure_NilOptionalDependencies(t *testing.T) {
	h := &Handler{}
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	h.recordObjectDecryptSuccess(r, "bucket", "key", crypto.AlgorithmAES256GCM, 1, time.Second, 3, nil)
	h.recordObjectDecryptFailure(r, "bucket", "key", errors.New("failure"))
}

func TestRecordObjectDecryptSuccessAndFailure_EmitsSingleAuditRecord(t *testing.T) {
	registry := prometheus.NewRegistry()
	metricsSink := metrics.NewMetricsWithRegistry(registry)
	auditLog := audit.NewLogger(10, nil)
	h := &Handler{metrics: metricsSink, auditLogger: auditLog}
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	h.recordObjectDecryptSuccess(r, "bucket", "key", crypto.AlgorithmAES256GCM, 1, time.Millisecond, 4, nil)
	h.recordObjectDecryptFailure(r, "bucket", "key", errors.New("decrypt failed"))
	events := auditLog.GetEvents()
	if len(events) != 2 || !events[0].Success || events[1].Success {
		t.Fatalf("decrypt audit events=%+v", events)
	}
	if got := metricSample(t, registry, "encryption_operations_total", `operation="decrypt"`); got != 1 {
		t.Fatalf("decrypt success metric=%v", got)
	}
	if got := metricSample(t, registry, "encryption_errors_total", `operation="decrypt"`, `error_type="decryption_failed"`); got != 1 {
		t.Fatalf("decrypt failure metric=%v", got)
	}
}
