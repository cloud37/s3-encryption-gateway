package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
)

// objectBackendError preserves provenance across read planning, which can fail
// either acquiring backend data or authenticating it. Do not infer provenance
// from an SDK error interface: key managers can return SDK errors too.
type objectBackendError struct {
	bucket, key string
	err         error
}

func (e *objectBackendError) Error() string {
	return fmt.Sprintf("read backend object %s/%s: %v", e.bucket, e.key, e.err)
}
func (e *objectBackendError) Unwrap() error { return e.err }

func backendObjectError(bucket, key string, err error) error {
	if err == nil {
		return nil
	}
	return &objectBackendError{bucket: bucket, key: key, err: err}
}

// writeObjectBackendError handles only explicitly marked storage failures. It
// returns false for crypto/metadata errors so their existing policy is retained.
func (h *Handler) writeObjectBackendError(w http.ResponseWriter, r *http.Request, op string, err error, start time.Time) bool {
	var backendErr *objectBackendError
	if !errors.As(err, &backendErr) {
		return false
	}
	// Existing GET callers use both method and S3 operation names. Keep error
	// metrics identical to the initial object acquisition, including cache hits.
	if op == http.MethodGet {
		op = "GetObject"
	}
	if op == http.MethodHead {
		op = "HeadObject"
	}
	h.writeObjectErrorForBucket(w, r, op, backendErr.bucket, TranslateError(backendErr.err, backendErr.bucket, backendErr.key), start)
	if h.logger != nil {
		h.logger.WithError(err).WithFields(map[string]any{"bucket": backendErr.bucket, "key": backendErr.key, "operation": op}).Error("Failed to read backend object")
	}
	return true
}

func isIntegrityFailure(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "authentication failed") ||
		strings.Contains(message, "message authentication") ||
		strings.Contains(message, "integrity check failed")
}

func (h *Handler) writeObjectError(w http.ResponseWriter, r *http.Request, op string, s3Err *S3Error, start time.Time) {
	h.writeObjectErrorForBucket(w, r, op, requestBucket(r), s3Err, start)
}

func (h *Handler) writeObjectErrorForBucket(w http.ResponseWriter, r *http.Request, op, bucket string, s3Err *S3Error, start time.Time) {
	if s3Err == nil {
		return
	}
	if r.Method != http.MethodHead {
		s3Err.WriteXML(w)
	} else {
		w.WriteHeader(s3Err.HTTPStatus)
	}
	if h.metrics != nil {
		if s3Err.Code != "" {
			h.metrics.RecordS3Error(r.Context(), op, bucket, s3Err.Code)
		}
		h.metrics.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
	}
}

func requestBucket(r *http.Request) string {
	if vars := mux.Vars(r); vars != nil {
		return vars["bucket"]
	}
	return ""
}

func (h *Handler) writeObjectResponseMetric(r *http.Request, status int, start time.Time, bytesWritten int64) {
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, status, time.Since(start), bytesWritten)
	}
}

func (h *Handler) writeObjectIntegrityError(w http.ResponseWriter, r *http.Request, op, bucket, key string, err error, start time.Time) {
	h.recordObjectIntegrityFailure(r, bucket, key, err)
	h.writeObjectError(w, r, op, &S3Error{Code: "InternalError", Message: "Object integrity check failed", HTTPStatus: http.StatusInternalServerError}, start)
}

// writeObjectDecryptError is the single pre-header decrypt-failure path. Integrity
// failures use the same tamper metric/audit owner as post-header stream failures.
func (h *Handler) writeObjectDecryptError(w http.ResponseWriter, r *http.Request, op, bucket, key string, err error, start time.Time) {
	if h.writeObjectBackendError(w, r, op, err, start) {
		return
	}
	if isIntegrityFailure(err) || errors.Is(err, crypto.ErrChunkedObjectIncomplete) || errors.Is(err, crypto.ErrUnsupportedChunkedVersion) {
		h.writeObjectIntegrityError(w, r, op, bucket, key, err, start)
		return
	}
	h.recordObjectDecryptFailure(r, bucket, key, err)
	h.writeObjectError(w, r, op, decryptFailure(err, r.URL.Path), start)
}

func (h *Handler) recordObjectDecryptSuccess(r *http.Request, bucket, key, algorithm string, keyVersion int, duration time.Duration, plainSize int64, metadata map[string]interface{}) {
	if h.metrics != nil {
		h.metrics.RecordEncryptionOperation(r.Context(), "decrypt", duration, plainSize)
	}
	if h.auditLogger != nil {
		h.auditLogger.LogDecrypt(bucket, key, algorithm, keyVersion, true, nil, duration, metadata)
	}
}

func (h *Handler) recordObjectIntegrityFailure(r *http.Request, bucket, key string, err error) {
	if h.metrics != nil {
		h.metrics.RecordEncryptionError(r.Context(), "decrypt", "object_integrity_failure")
	}
	if h.auditLogger != nil {
		_ = h.auditLogger.Log(&audit.AuditEvent{
			EventType: audit.EventTypeMPUTamperDetected,
			Timestamp: time.Now().UTC(), Bucket: bucket, Key: key,
			Operation: "object_stream_integrity_failure", Success: false,
			Metadata: map[string]interface{}{"error_class": "integrity"},
		})
	}
	if err != nil && h.logger != nil {
		h.logger.WithError(err).WithFields(map[string]any{"bucket": bucket, "key": key}).Warn("object stream integrity failure")
	}
}

func (h *Handler) recordObjectDecryptFailure(r *http.Request, bucket, key string, err error) {
	if h.metrics != nil {
		h.metrics.RecordEncryptionError(r.Context(), "decrypt", "decryption_failed")
	}
	if h.auditLogger != nil {
		h.auditLogger.LogDecrypt(bucket, key, "", 0, false, err, 0, nil)
	}
}

func decryptFailure(err error, resource string) *S3Error {
	code, msg := "InternalError", "Failed to decrypt object"
	var invalidKDF *crypto.ErrInvalidKDFParams
	var costlyKDF *crypto.ErrKDFCostTooHigh
	switch {
	case errors.As(err, &invalidKDF), errors.As(err, &costlyKDF):
		msg = "We encountered an internal error. Please try again."
	case errors.Is(err, crypto.ErrEncryptedObjectInBypassBucket):
		code, msg = "EncryptionConfigurationMismatch", "The object was encrypted when stored but the bucket policy now disables encryption. Use the migration tool to convert the object."
	case errors.Is(err, ErrMissingMPUManifest):
		msg = "Encrypted multipart object metadata is missing; the gateway MPU manifest could not be found"
	case errors.Is(err, crypto.ErrChunkedObjectIncomplete), errors.Is(err, crypto.ErrUnsupportedChunkedVersion), isIntegrityFailure(err):
		msg = "Object integrity check failed"
	case errors.Is(err, crypto.ErrUnsupportedObjectFormat):
		msg = "Unsupported encrypted object format"
	}
	status := http.StatusInternalServerError
	if code == "EncryptionConfigurationMismatch" {
		status = http.StatusConflict
	}
	return &S3Error{Code: code, Message: msg, Resource: resource, HTTPStatus: status}
}
