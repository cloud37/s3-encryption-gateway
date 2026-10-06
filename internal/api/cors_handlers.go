package api

import (
	"bufio"
	"context"
	"crypto/md5" // #nosec G501 G401 -- S3 Content-MD5 is required for wire compatibility and is not used for security or authentication
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
)

type corsPreflightDecision struct {
	allowed bool
	headers http.Header
}
type corsPreflightContextKey struct{}
type corsLifecycleAccountingOwnedContextKey struct{}

func markGatewayLifecycleAccountingOwned(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), corsLifecycleAccountingOwnedContextKey{}, true))
}

func gatewayLifecycleAccountingOwned(r *http.Request) bool {
	owned, _ := r.Context().Value(corsLifecycleAccountingOwnedContextKey{}).(bool)
	return owned
}

func (h *Handler) handleGatewayCreateBucketForward(w http.ResponseWriter, r *http.Request, bucket string) {
	recorder := &corsManagementRecorder{ResponseWriter: w}
	h.handlePassthroughWithBodyLimit(recorder, markGatewayLifecycleAccountingOwned(r), "CreateBucket", bucket, "", 64<<10)
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	if h.metrics != nil {
		h.metrics.RecordS3Operation(r.Context(), "CreateBucket", bucket, 0)
		h.metrics.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, status, 0, recorder.bytes)
		if status >= http.StatusBadRequest {
			h.metrics.RecordS3Error(r.Context(), "CreateBucket", bucket, strconv.Itoa(status))
		}
	}
	if h.auditLogger != nil {
		var auditErr error
		if status >= http.StatusBadRequest {
			auditErr = fmt.Errorf("CreateBucket failed with HTTP %d", status)
		}
		h.auditManagement(r, "CreateBucket", bucket, status < http.StatusBadRequest, auditErr)
	}
}

func (h *Handler) gatewayCORSMode() bool {
	return h.config != nil && config.EffectiveCORSMode(h.config.CORS.Mode) == "gateway"
}

func (h *Handler) checkCORSBucket(r *http.Request, bucket string) error {
	if err := ValidateBucketName(bucket); err != nil {
		return &S3Error{Code: "InvalidBucketName", Message: "The specified bucket is not valid", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
	}
	client, err := h.getS3Client(r)
	if err != nil {
		return err
	}
	_, err = client.ListObjects(r.Context(), bucket, "", s3.ListOptions{MaxKeys: 1})
	return err
}

func (h *Handler) writeCORSStoreError(w http.ResponseWriter, r *http.Request, operation, bucket string, err error) {
	if h.logger != nil {
		h.logger.WithError(err).WithField("bucket", bucket).Error("gateway CORS operation failed")
	}
	if errors.Is(err, ErrCORSNotFound) {
		h.writeObjectError(w, r, operation, &S3Error{Code: "NoSuchCORSConfiguration", Message: "The CORS configuration does not exist", Resource: r.URL.Path, HTTPStatus: http.StatusNotFound}, time.Now())
		return
	}
	if strings.EqualFold(operation, "CreateBucket") {
		if h.logger != nil {
			h.logger.WithError(err).WithField("bucket", bucket).Error("bucket existence probe was ambiguous; refusing creation and preserving CORS policy")
		}
		h.failGatewayBucketLifecycle(w, r, operation, bucket, err, false)
		return
	}
	if strings.EqualFold(operation, "DeleteBucket") {
		backendDeleted := r.Context().Value(corsLifecycleDeleteUpstreamSucceededKey{}) == true
		h.failGatewayBucketLifecycle(w, r, operation, bucket, err, backendDeleted)
		return
	}
	var s3Err *S3Error
	if errors.As(err, &s3Err) {
		h.writeObjectError(w, r, operation, s3Err, time.Now())
		return
	}
	if errors.Is(err, ErrCORSUnavailable) {
		h.writeObjectError(w, r, operation, &S3Error{Code: "ServiceUnavailable", Message: "The bucket CORS configuration store is unavailable", Resource: r.URL.Path, HTTPStatus: http.StatusServiceUnavailable}, time.Now())
		return
	}
	h.writeObjectError(w, r, operation, &S3Error{Code: "ServiceUnavailable", Message: "The bucket CORS configuration store is unavailable", Resource: r.URL.Path, HTTPStatus: http.StatusServiceUnavailable}, time.Now())
}

type corsLifecycleDeleteUpstreamSucceededKey struct{}

func markGatewayDeleteUpstreamSucceeded(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), corsLifecycleDeleteUpstreamSucceededKey{}, true))
}

func (h *Handler) failGatewayBucketLifecycle(w http.ResponseWriter, r *http.Request, operation, bucket string, err error, backendDeletionMayHaveSucceeded bool) {
	message := "The bucket lifecycle operation could not be completed because the backend or policy store is unavailable"
	if backendDeletionMayHaveSucceeded {
		message = "The bucket was deleted upstream but CORS policy cleanup failed; retry cleanup before reusing the bucket name"
	}
	if h.logger != nil {
		h.logger.WithError(err).WithFields(map[string]any{"bucket": bucket, "operation": operation}).Error(message)
	}
	h.writeObjectError(w, r, operation, &S3Error{Code: "ServiceUnavailable", Message: message, Resource: r.URL.Path, HTTPStatus: http.StatusServiceUnavailable}, time.Now())
	if h.metrics != nil {
		h.metrics.RecordS3Operation(r.Context(), operation, bucket, 0)
	}
	if h.auditLogger != nil {
		h.auditManagement(r, operation, bucket, false, err)
	}
}

func (h *Handler) handleGatewayGetBucketCors(w http.ResponseWriter, r *http.Request, bucket string) {
	if err := h.checkCORSBucket(r, bucket); err != nil {
		if h.logger != nil {
			h.logger.WithError(err).WithField("bucket", bucket).Error("gateway CORS bucket existence check failed")
		}
		h.corsBucketProbeResponse(w, r, "GetBucketCors", bucket, err)
		return
	}
	if h.corsStore == nil {
		h.writeCORSStoreError(w, r, "GetBucketCors", bucket, ErrCORSUnavailable)
		return
	}
	cfg, err := h.corsStore.Get(r.Context(), bucket)
	if err != nil {
		h.writeCORSStoreError(w, r, "GetBucketCors", bucket, err)
		return
	}
	if err := writeCORSXML(w, cfg); err != nil {
		h.writeObjectError(w, r, "GetBucketCors", &S3Error{Code: "InternalError", Message: "The stored CORS configuration is invalid", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}, time.Now())
	}
}

type corsManagementRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

var _ http.Flusher = (*corsManagementRecorder)(nil)
var _ http.Hijacker = (*corsManagementRecorder)(nil)
var _ http.Pusher = (*corsManagementRecorder)(nil)
var _ io.ReaderFrom = (*corsManagementRecorder)(nil)

func (w *corsManagementRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *corsManagementRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *corsManagementRecorder) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += int64(n)
	return n, err
}

func (w *corsManagementRecorder) WriteString(value string) (int, error) {
	return w.Write([]byte(value))
}

func (w *corsManagementRecorder) ReadFrom(reader io.Reader) (int64, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if readerFrom, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := readerFrom.ReadFrom(reader)
		w.bytes += n
		return n, err
	}
	n, err := io.Copy(struct{ io.Writer }{w}, reader)
	return n, err
}

func (w *corsManagementRecorder) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *corsManagementRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

func (w *corsManagementRecorder) Push(target string, options *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, options)
}

func (h *Handler) serveGatewayCORSManagement(w http.ResponseWriter, r *http.Request, operation string, handler func(http.ResponseWriter, *http.Request, string)) {
	bucket := mux.Vars(r)["bucket"]
	recorder := &corsManagementRecorder{ResponseWriter: w}
	handler(recorder, r, bucket)
	status := recorder.status
	if status == 0 {
		status = http.StatusOK
	}
	// Route middleware owns client request/byte counters. This management
	// boundary owns the operation metric and exactly one audit event; response
	// helpers own HTTP/error metrics on failures.
	if h.metrics != nil {
		h.metrics.RecordS3Operation(r.Context(), operation, bucket, 0)
		if status < http.StatusBadRequest {
			h.metrics.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, status, 0, recorder.bytes)
		}
	}
	if h.auditLogger != nil {
		var auditErr error
		if status >= http.StatusBadRequest {
			auditErr = fmt.Errorf("%s failed with HTTP %d", operation, status)
		}
		h.auditManagement(r, operation, bucket, status < http.StatusBadRequest, auditErr)
	}
}

func (h *Handler) handleGatewayPutBucketCors(w http.ResponseWriter, r *http.Request, bucket string) {
	if err := h.checkCORSBucket(r, bucket); err != nil {
		if h.logger != nil {
			h.logger.WithError(err).WithField("bucket", bucket).Error("gateway CORS bucket existence check failed")
		}
		h.corsBucketProbeResponse(w, r, "PutBucketCors", bucket, err)
		return
	}
	if h.corsStore == nil {
		h.writeCORSStoreError(w, r, "PutBucketCors", bucket, ErrCORSUnavailable)
		return
	}
	if r.ContentLength > maxCORSXMLBytes {
		h.writeCORSManagementError(w, r, "PutBucketCors", bucket, "EntityTooLarge", "The CORS configuration exceeds the maximum size", http.StatusRequestEntityTooLarge)
		return
	}
	var body []byte
	var err error
	if r.Body != nil {
		body, err = io.ReadAll(io.LimitReader(r.Body, maxCORSXMLBytes+1))
		_ = r.Body.Close()
	}
	if err != nil {
		h.writeCORSManagementError(w, r, "PutBucketCors", bucket, "MalformedXML", "The CORS configuration XML is invalid", http.StatusBadRequest)
		return
	}
	if len(body) > maxCORSXMLBytes {
		h.writeCORSManagementError(w, r, "PutBucketCors", bucket, "EntityTooLarge", "The CORS configuration exceeds the maximum size", http.StatusRequestEntityTooLarge)
		return
	}
	if md5Header := r.Header.Get("Content-MD5"); md5Header != "" {
		provided, decodeErr := base64.StdEncoding.DecodeString(md5Header)
		if decodeErr != nil || len(provided) != md5.Size {
			h.writeCORSManagementError(w, r, "PutBucketCors", bucket, "InvalidDigest", "The Content-MD5 you specified is not valid", http.StatusBadRequest)
			return
		}
		digest := md5.Sum(body)
		if !equalBytes(provided, digest[:]) {
			h.writeCORSManagementError(w, r, "PutBucketCors", bucket, "BadDigest", "The Content-MD5 you specified did not match what we received", http.StatusBadRequest)
			return
		}
	}
	cfg, err := parseCORSXML(body)
	if errors.Is(err, ErrCORSTooLarge) {
		h.writeCORSManagementError(w, r, "PutBucketCors", bucket, "EntityTooLarge", "The CORS configuration exceeds the maximum size", http.StatusRequestEntityTooLarge)
		return
	}
	if err != nil {
		h.writeCORSManagementError(w, r, "PutBucketCors", bucket, "MalformedXML", "The CORS configuration XML is invalid", http.StatusBadRequest)
		return
	}
	if err := h.corsStore.Put(r.Context(), bucket, cfg); err != nil {
		h.writeCORSStoreError(w, r, "PutBucketCors", bucket, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) handleGatewayDeleteBucketCors(w http.ResponseWriter, r *http.Request, bucket string) {
	if err := h.checkCORSBucket(r, bucket); err != nil {
		if h.logger != nil {
			h.logger.WithError(err).WithField("bucket", bucket).Error("gateway CORS bucket existence check failed")
		}
		h.corsBucketProbeResponse(w, r, "DeleteBucketCors", bucket, err)
		return
	}
	if h.corsStore == nil {
		h.writeCORSStoreError(w, r, "DeleteBucketCors", bucket, ErrCORSUnavailable)
		return
	}
	if err := h.corsStore.Delete(r.Context(), bucket); err != nil {
		h.writeCORSStoreError(w, r, "DeleteBucketCors", bucket, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) corsBucketProbeResponse(w http.ResponseWriter, r *http.Request, operation, bucket string, err error) {
	var apiErr interface{ ErrorCode() string }
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucket" {
		h.writeObjectError(w, r, operation, &S3Error{Code: "NoSuchBucket", Message: "The specified bucket does not exist", Resource: r.URL.Path, HTTPStatus: http.StatusNotFound}, time.Now())
		return
	}
	// A failed bucket probe is absence only for the provider's explicit
	// NoSuchBucket response. AccessDenied, throttling and ambiguous errors must
	// not erase stale policy or be surfaced as an authorization verdict.
	if strings.EqualFold(operation, "CreateBucket") {
		h.failGatewayBucketLifecycle(w, r, operation, bucket, err, false)
		return
	}
	h.writeObjectError(w, r, operation, &S3Error{Code: "ServiceUnavailable", Message: "The bucket CORS configuration store is unavailable", Resource: r.URL.Path, HTTPStatus: http.StatusServiceUnavailable}, time.Now())
}

func (h *Handler) handleGatewayCORSPreflight(w http.ResponseWriter, r *http.Request) {
	decision, _ := r.Context().Value(corsPreflightContextKey{}).(*corsPreflightDecision)
	addVary(w.Header(), "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers")
	origins := r.Header.Values("Origin")
	methods := r.Header.Values("Access-Control-Request-Method")
	if len(origins) != 1 || len(methods) != 1 {
		h.writeCORSPreflightError(w, r, "InvalidArgument", "The Origin and Access-Control-Request-Method headers must be valid single values", http.StatusBadRequest)
		return
	}
	if r.Header.Get("Origin") != strings.TrimSpace(origins[0]) || !validOriginHeader(origins[0]) {
		h.writeCORSPreflightError(w, r, "InvalidArgument", fmt.Sprintf("The Origin header is invalid (%q)", origins[0]), http.StatusBadRequest)
		return
	}
	if r.Header.Get("Access-Control-Request-Method") != strings.TrimSpace(methods[0]) || !validRequestedMethod(methods[0]) {
		h.writeCORSPreflightError(w, r, "InvalidArgument", "The Access-Control-Request-Method header is invalid", http.StatusBadRequest)
		return
	}
	requestedHeaders, ok := parseRequestedCORSHeaders(r.Header.Values("Access-Control-Request-Headers"))
	if !ok {
		h.writeCORSPreflightError(w, r, "InvalidArgument", "The Access-Control-Request-Headers header is invalid", http.StatusBadRequest)
		return
	}
	bucket := mux.Vars(r)["bucket"]
	if bucket == "" {
		bucket = strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)[0]
	}
	cfg, err := h.loadCORSConfiguration(r, bucket)
	if err != nil {
		if errors.Is(err, ErrCORSNotFound) {
			h.writeCORSPreflightError(w, r, "AccessDenied", "CORS request is not allowed", http.StatusForbidden)
		} else {
			h.writeCORSPreflightError(w, r, "ServiceUnavailable", "The bucket CORS configuration store is unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	origin, method := origins[0], methods[0]
	rule, matched := matchCORSRule(cfg, origin, method, requestedHeaders)
	if !matched {
		h.writeCORSPreflightError(w, r, "AccessDenied", "CORS request is not allowed", http.StatusForbidden)
		return
	}
	// The preflight response is gateway-owned. Do not let any upstream or
	// earlier middleware CORS fields become part of the retained decision.
	stripCORSResponseHeaders(w.Header())
	setCORSPreflightHeaders(w.Header(), rule, origin, method, requestedHeaders, h.config.CORS.AllowCredentials)
	if decision != nil {
		decision.headers = copyCORSResponseHeaders(w.Header())
		decision.allowed = true
	}
	if h.metrics != nil {
		h.metrics.RecordS3Operation(r.Context(), "CORSPreflight", corsBucketFromRequest(r), 0)
	}
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) writeCORSPreflightError(w http.ResponseWriter, r *http.Request, code, message string, status int) {
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), http.MethodOptions, r.URL.Path, status, 0, 0)
		h.metrics.RecordS3Error(r.Context(), "CORSPreflight", corsBucketFromRequest(r), code)
	}
	(&S3Error{Code: code, Message: message, Resource: r.URL.Path, HTTPStatus: status}).WriteXML(w)
}

func (h *Handler) writeCORSManagementError(w http.ResponseWriter, r *http.Request, operation, bucket string, code, message string, status int) {
	if h.metrics != nil {
		h.metrics.RecordHTTPRequest(r.Context(), r.Method, r.URL.Path, status, 0, 0)
		h.metrics.RecordS3Error(r.Context(), operation, bucket, code)
	}
	(&S3Error{Code: code, Message: message, Resource: r.URL.Path, HTTPStatus: status}).WriteXML(w)
}

func (h *Handler) loadCORSConfiguration(r *http.Request, bucket string) (*CORSConfiguration, error) {
	if h.corsStore == nil {
		return nil, ErrCORSUnavailable
	}
	if err := validateCORSBucket(bucket); err != nil {
		return nil, ErrCORSNotFound
	}
	cfg, err := h.corsStore.Get(r.Context(), bucket)
	if err == nil {
		return cfg, nil
	}
	if !errors.Is(err, ErrCORSNotFound) {
		return nil, err
	}
	fallback := h.config.CORS.Fallback
	if len(fallback.AllowedOrigins) == 0 || len(fallback.AllowedMethods) == 0 {
		return nil, ErrCORSNotFound
	}
	return &CORSConfiguration{Rules: []CORSRule{{AllowedOrigins: append([]string(nil), fallback.AllowedOrigins...), AllowedMethods: append([]string(nil), fallback.AllowedMethods...), AllowedHeaders: append([]string(nil), fallback.AllowedHeaders...), ExposeHeaders: append([]string(nil), fallback.ExposeHeaders...), MaxAgeSeconds: corsMaxAgePointer(fallback.MaxAgeSeconds)}}}, nil
}

func corsMaxAgePointer(age int) *int {
	if age <= 0 {
		return nil
	}
	return &age
}

func parseRequestedCORSHeaders(values []string) ([]string, bool) {
	if len(values) == 0 {
		return nil, true
	}
	if len(values) != 1 {
		return nil, false
	}
	parts := strings.Split(values[0], ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if hasCORSControl(part) {
			return nil, false
		}
		name := strings.TrimSpace(part)
		if name == "" || config.ValidateCORSFieldName(name) != nil {
			return nil, false
		}
		result = append(result, strings.ToLower(name))
	}
	return result, true
}

func setCORSPreflightHeaders(h http.Header, rule *CORSRule, origin, method string, requestedHeaders []string, credentials bool) {
	allowedOrigin := origin
	if len(rule.AllowedOrigins) == 1 && rule.AllowedOrigins[0] == "*" && !credentials {
		allowedOrigin = "*"
	}
	setCORSResponseHeader(h, "Access-Control-Allow-Origin", allowedOrigin)
	setCORSResponseHeader(h, "Access-Control-Allow-Methods", strings.Join(rule.AllowedMethods, ", "))
	if len(requestedHeaders) > 0 {
		setCORSResponseHeader(h, "Access-Control-Allow-Headers", strings.Join(requestedHeaders, ", "))
	}
	if len(rule.ExposeHeaders) > 0 {
		setCORSResponseHeader(h, "Access-Control-Expose-Headers", strings.Join(rule.ExposeHeaders, ", "))
	}
	if rule.MaxAgeSeconds != nil && *rule.MaxAgeSeconds > 0 {
		setCORSResponseHeader(h, "Access-Control-Max-Age", strconv.Itoa(*rule.MaxAgeSeconds))
	}
	if credentials {
		setCORSResponseHeader(h, "Access-Control-Allow-Credentials", "true")
	}
	_ = method
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func corsBucketFromRequest(r *http.Request) string {
	if bucket := mux.Vars(r)["bucket"]; bucket != "" {
		return bucket
	}
	return strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)[0]
}
