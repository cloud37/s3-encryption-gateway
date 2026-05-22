// Package api — Object Lock subresource handlers (V0.6-S3-2).
//
// This file implements the six object-lock subresource endpoints
// (PUT/GET for object Retention, object LegalHold, and bucket
// ObjectLockConfiguration) plus the per-request header-extraction
// helper used by PutObject / CopyObject / CompleteMultipartUpload.
//
// Scope notes:
//   - Locks apply to the ciphertext stored in the backend. See ADR 0008.
//   - x-amz-bypass-governance-retention is unconditionally refused with
//     403 AccessDenied pending V0.6-CFG-1's admin-authorization primitive.
//     Refusal is case-insensitive and applies consistently across
//     PutObjectRetention, DeleteObject, and DeleteObjects entry points.
package api

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// maxObjectLockXMLBody bounds the request-body size for every subresource
// PUT. Retention and LockConfiguration XML payloads are small, fixed-shape
// structures; 100 KiB is generous.
const maxObjectLockXMLBody = 100 * 1024

// LegalHold is the wire representation of an object's legal-hold status.
// Exported so tests can construct it; kept local to the api package
// because callers interact via XML on the wire.
type LegalHold struct {
	XMLName xml.Name `xml:"LegalHold"`
	Status  string   `xml:"Status"`
}

// refuseBypassGovernanceRetention checks for the
// x-amz-bypass-governance-retention request header and, if present with
// a truthy value, writes a 403 AccessDenied response, emits an audit
// event with reason=admin_authorization_not_implemented, records the
// HTTP metric, and returns true.
//
// The check is case-insensitive: "true", "True", "TRUE" all refuse.
// RFC 9110 §5.6.2 permits tokens to be compared case-insensitively; S3
// itself canonicalises the header value, so mirror that here.
//
// When V0.6-CFG-1 introduces h.IsAdmin and
// PolicyManager.BucketDisallowsLockBypass, this helper is the single
// call-site to replace with the admin-gated decision.
func refuseBypassGovernanceRetention(w http.ResponseWriter, r *http.Request, h *Handler, bucket, key string, start time.Time) bool {
	raw := r.Header.Get("x-amz-bypass-governance-retention")
	if raw == "" {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(raw), "true") {
		// Any non-truthy value (including "false") is ignored: S3
		// treats only the exact string "true" as bypass-requesting.
		return false
	}
	s3Err := &S3Error{
		Code:       "AccessDenied",
		Message:    "Governance retention bypass is not enabled on this gateway.",
		Resource:   r.URL.Path,
		HTTPStatus: http.StatusForbidden,
	}
	s3Err.WriteXML(w)
	if h.auditLogger != nil {
		h.auditLogger.LogAccessWithMetadata(
			"bypass_governance_refused", bucket, key,
			getClientIP(r), r.UserAgent(), getRequestID(r),
			false, fmt.Errorf("bypass not authorised"), time.Since(start),
			map[string]interface{}{
				"reason":    "admin_authorization_not_implemented",
				"note":      "deferred to V0.6-CFG-1",
				"raw_value": raw,
			},
		)
	}
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
	}
	return true
}

// extractObjectLockInput parses the three x-amz-object-lock-* request
// headers into an ObjectLockInput. Returns (nil, nil) when none of the
// headers are present — caller treats that as "no lock requested".
//
// Validation:
//   - mode must be "GOVERNANCE" or "COMPLIANCE" (S3 canonical spelling)
//   - retain-until-date must be RFC 3339 and strictly in the future
//   - legal-hold must be "ON" or "OFF"
//
// Any validation failure returns (nil, *S3Error) with HTTP 400 so the
// caller can write the response directly.
func extractObjectLockInput(r *http.Request) (*s3.ObjectLockInput, *S3Error) {
	mode := r.Header.Get("x-amz-object-lock-mode")
	retainUntilStr := r.Header.Get("x-amz-object-lock-retain-until-date")
	legalHold := r.Header.Get("x-amz-object-lock-legal-hold")

	if mode == "" && retainUntilStr == "" && legalHold == "" {
		return nil, nil
	}

	input := &s3.ObjectLockInput{}

	if mode != "" {
		if mode != "GOVERNANCE" && mode != "COMPLIANCE" {
			return nil, &S3Error{Code: "InvalidArgument", Message: "Invalid x-amz-object-lock-mode", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		}
		input.Mode = mode
	}

	if retainUntilStr != "" {
		t, err := time.Parse(time.RFC3339, retainUntilStr)
		if err != nil {
			return nil, &S3Error{Code: "InvalidArgument", Message: "Invalid x-amz-object-lock-retain-until-date", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		}
		if !t.After(time.Now()) {
			return nil, &S3Error{Code: "InvalidArgument", Message: "Retain until date must be in the future", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		}
		input.RetainUntilDate = &t
	}

	if legalHold != "" {
		if legalHold != "ON" && legalHold != "OFF" {
			return nil, &S3Error{Code: "InvalidArgument", Message: "Invalid x-amz-object-lock-legal-hold", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		}
		input.LegalHoldStatus = legalHold
	}

	// Mode and retain-until-date are paired at the backend: AWS rejects
	// one without the other. Mirror that on the way in so we return a
	// clear 400 instead of relying on the backend error surface.
	if (input.Mode != "") != (input.RetainUntilDate != nil) {
		return nil, &S3Error{Code: "InvalidArgument", Message: "x-amz-object-lock-mode and x-amz-object-lock-retain-until-date must be specified together", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
	}

	return input, nil
}

// readLimitedBody reads up to maxObjectLockXMLBody bytes from the body
// and returns the bytes or a 400 MalformedXML S3Error on read failure.
func readLimitedBody(r *http.Request) ([]byte, *S3Error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxObjectLockXMLBody))
	if err != nil {
		return nil, &S3Error{Code: "MalformedXML", Message: "Unable to read request body", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
	}
	return body, nil
}

// decodeStrictXML decodes XML with the stdlib decoder configured strictly
// (defaults: entity expansion disabled, no DOCTYPE processing). Returns a
// user-friendly 400 MalformedXML on decode failure.
func decodeStrictXML(body []byte, into interface{}, resource string) *S3Error {
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = true
	if err := dec.Decode(into); err != nil {
		return &S3Error{Code: "MalformedXML", Message: "The XML you provided was not well-formed or did not validate against our published schema", Resource: resource, HTTPStatus: http.StatusBadRequest}
	}
	return nil
}

// handlePutObjectRetention PUT /{bucket}/{key}?retention
func (h *Handler) handlePutObjectRetention(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	if refuseBypassGovernanceRetention(w, r, h, bucket, key, start) {
		return
	}

	body, errBody := readLimitedBody(r)
	if errBody != nil {
		errBody.WriteXML(w)
		return
	}

	var req s3.RetentionConfig
	if errXML := decodeStrictXML(body, &req, r.URL.Path); errXML != nil {
		errXML.WriteXML(w)
		return
	}

	if req.Mode != "GOVERNANCE" && req.Mode != "COMPLIANCE" {
		s3Err := &S3Error{Code: "InvalidArgument", Message: "Retention Mode must be GOVERNANCE or COMPLIANCE", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		s3Err.WriteXML(w)
		return
	}
	if req.RetainUntilDate.IsZero() || !req.RetainUntilDate.After(time.Now()) {
		s3Err := &S3Error{Code: "InvalidArgument", Message: "Retain until date must be in the future", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		s3Err.WriteXML(w)
		return
	}

	versionID := r.URL.Query().Get("versionId")
	var vidPtr *string
	if versionID != "" {
		vidPtr = &versionID
	}

	if err := s3Client.PutObjectRetention(r.Context(), bucket, key, vidPtr, &req); err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAccess("put_object_retention", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
	}
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
	}
	w.WriteHeader(http.StatusOK)
}

// handleGetObjectRetention GET /{bucket}/{key}?retention
func (h *Handler) handleGetObjectRetention(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "GET", start)
		return
	}

	versionID := r.URL.Query().Get("versionId")
	var vidPtr *string
	if versionID != "" {
		vidPtr = &versionID
	}

	ret, err := s3Client.GetObjectRetention(r.Context(), bucket, key, vidPtr)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		return
	}

	if ret == nil {
		s3Err := &S3Error{Code: "NoSuchObjectLockConfiguration", Message: "Object Lock configuration does not exist for this object", Resource: r.URL.Path, HTTPStatus: http.StatusNotFound}
		s3Err.WriteXML(w)
		return
	}

	b, _ := xml.Marshal(ret)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(b)
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), int64(len(b)))
	}
}

// handlePutObjectLegalHold PUT /{bucket}/{key}?legal-hold
func (h *Handler) handlePutObjectLegalHold(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	body, errBody := readLimitedBody(r)
	if errBody != nil {
		errBody.WriteXML(w)
		return
	}

	var req LegalHold
	if errXML := decodeStrictXML(body, &req, r.URL.Path); errXML != nil {
		errXML.WriteXML(w)
		return
	}

	if req.Status != "ON" && req.Status != "OFF" {
		s3Err := &S3Error{Code: "InvalidArgument", Message: "LegalHold Status must be ON or OFF", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		s3Err.WriteXML(w)
		return
	}

	versionID := r.URL.Query().Get("versionId")
	var vidPtr *string
	if versionID != "" {
		vidPtr = &versionID
	}

	if err := s3Client.PutObjectLegalHold(r.Context(), bucket, key, vidPtr, req.Status); err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAccess("put_object_legal_hold", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
	}
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
	}
	w.WriteHeader(http.StatusOK)
}

// handleGetObjectLegalHold GET /{bucket}/{key}?legal-hold
func (h *Handler) handleGetObjectLegalHold(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "GET", start)
		return
	}

	versionID := r.URL.Query().Get("versionId")
	var vidPtr *string
	if versionID != "" {
		vidPtr = &versionID
	}

	status, err := s3Client.GetObjectLegalHold(r.Context(), bucket, key, vidPtr)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		return
	}

	if status == "" {
		s3Err := &S3Error{Code: "NoSuchObjectLockConfiguration", Message: "The specified object does not have a LegalHold configuration", Resource: r.URL.Path, HTTPStatus: http.StatusNotFound}
		s3Err.WriteXML(w)
		return
	}

	b, _ := xml.Marshal(LegalHold{Status: status})
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(b)
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), int64(len(b)))
	}
}

// handlePutObjectLockConfiguration PUT /{bucket}?object-lock
func (h *Handler) handlePutObjectLockConfiguration(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	body, errBody := readLimitedBody(r)
	if errBody != nil {
		errBody.WriteXML(w)
		return
	}

	var req s3.ObjectLockConfiguration
	if errXML := decodeStrictXML(body, &req, r.URL.Path); errXML != nil {
		errXML.WriteXML(w)
		return
	}

	// Validate: exactly one of Days/Years if DefaultRetention is set.
	if req.Rule != nil && req.Rule.DefaultRetention != nil {
		dr := req.Rule.DefaultRetention
		if dr.Mode != "" && dr.Mode != "GOVERNANCE" && dr.Mode != "COMPLIANCE" {
			s3Err := &S3Error{Code: "InvalidArgument", Message: "DefaultRetention Mode must be GOVERNANCE or COMPLIANCE", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
			s3Err.WriteXML(w)
			return
		}
		hasDays := dr.Days != nil
		hasYears := dr.Years != nil
		if hasDays && hasYears {
			s3Err := &S3Error{Code: "MalformedXML", Message: "DefaultRetention must specify exactly one of Days or Years, not both", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
			s3Err.WriteXML(w)
			return
		}
		if (hasDays && *dr.Days <= 0) || (hasYears && *dr.Years <= 0) {
			s3Err := &S3Error{Code: "InvalidArgument", Message: "DefaultRetention Days/Years must be positive", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
			s3Err.WriteXML(w)
			return
		}
	}

	if err := s3Client.PutObjectLockConfiguration(r.Context(), bucket, &req); err != nil {
		s3Err := TranslateError(err, bucket, "")
		s3Err.WriteXML(w)
		return
	}

	if h.auditLogger != nil {
		h.auditLogger.LogAccess("put_object_lock_configuration", bucket, "", getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
	}
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
	}
	w.WriteHeader(http.StatusOK)
}

// handleGetObjectLockConfiguration GET /{bucket}?object-lock
func (h *Handler) handleGetObjectLockConfiguration(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "GET", start)
		return
	}

	cfg, err := s3Client.GetObjectLockConfiguration(r.Context(), bucket)
	if err != nil {
		s3Err := TranslateError(err, bucket, "")
		s3Err.WriteXML(w)
		return
	}

	if cfg == nil {
		s3Err := &S3Error{Code: "ObjectLockConfigurationNotFoundError", Message: "Object Lock configuration does not exist for this bucket", Resource: r.URL.Path, HTTPStatus: http.StatusNotFound}
		s3Err.WriteXML(w)
		return
	}

	b, _ := xml.Marshal(cfg)
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(xml.Header))
	_, _ = w.Write(b)
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), int64(len(b)))
	}
}
