package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/cloud37/s3-encryption-gateway/internal/admin"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

// Handler handles HTTP requests for S3 operations.
type Handler struct {
	s3Client         s3.Client         // Legacy: kept for backward compatibility
	clientFactory    *s3.ClientFactory // New: factory for per-request clients
	encryptionEngine crypto.EncryptionEngine
	logger           *logrus.Logger
	metrics          *metrics.Metrics
	keyManager       crypto.KeyManager
	cache            cache.Cache
	auditLogger      audit.Logger
	config           *config.Config
	policyManager    *config.PolicyManager
	engineCache      *ttlEngineCache // TTL cache for per-policy engines (V1.0-SEC-20)
	mpuStateStore    mpu.StateStore  // nil when encrypted MPU is not configured
}

// NewHandler creates a new API handler (backward compatibility).
func NewHandler(s3Client s3.Client, encryptionEngine crypto.EncryptionEngine, logger *logrus.Logger, m *metrics.Metrics) *Handler {
	return NewHandlerWithFeatures(s3Client, encryptionEngine, logger, m, nil, nil, nil, nil, nil)
}

// NewHandlerWithFeatures creates a new API handler with Phase 5 features.
func NewHandlerWithFeatures(
	s3Client s3.Client,
	encryptionEngine crypto.EncryptionEngine,
	logger *logrus.Logger,
	m *metrics.Metrics,
	keyManager crypto.KeyManager,
	cache cache.Cache,
	auditLogger audit.Logger,
	config *config.Config,
	policyManager *config.PolicyManager,
) *Handler {
	h := &Handler{
		s3Client:         s3Client,
		encryptionEngine: encryptionEngine,
		logger:           logger,
		metrics:          m,
		keyManager:       keyManager,
		cache:            cache,
		auditLogger:      auditLogger,
		config:           config,
		policyManager:    policyManager,
	}
	// Create client factory for per-request credential support.
	// V0.6-PERF-2: inject metrics so the factory can emit retry counters.
	if config != nil {
		h.clientFactory = s3.NewClientFactory(&config.Backend, s3.WithMetrics(m))
	}
	if policyManager != nil {
		// Initialise the TTL cache with a 1-hour default TTL and 5-minute sweep.
		h.engineCache = newTTLEngineCache(1*time.Hour, 5*time.Minute)
	}
	return h
}

// WithMPUStateStore attaches an encrypted multipart state store to the handler.
// When non-nil, buckets with EncryptMultipartUploads=true will use this store.
func (h *Handler) WithMPUStateStore(store mpu.StateStore) {
	h.mpuStateStore = store
}

// Close stops the per-policy engine cache sweeper and calls Close() on every
// cached engine so that password bytes are zeroised (V1.0-SEC-20).
func (h *Handler) Close() {
	if h.engineCache != nil {
		h.engineCache.Stop()
		h.engineCache = nil
	}
}

// bucketEncryptsMPU reports whether the bucket's CURRENT policy requires
// encrypted multipart uploads. Only call this at CreateMultipartUpload time —
// subsequent UploadPart / Complete / Abort must use uploadStateEncrypted so
// that mid-upload policy flips do not affect in-flight uploads (ADR-0009
// §Security Considerations: "Policy snapshot captured at Create").
func (h *Handler) bucketEncryptsMPU(bucket string) bool {
	if h.policyManager == nil {
		return false
	}
	return h.policyManager.BucketEncryptsMultipart(bucket)
}

// uploadStateEncrypted fetches the Valkey UploadState for uploadID.
//
//   - (state, true, nil)  — upload is an encrypted MPU; use state.PolicySnapshot.
//   - (nil,   false, nil) — upload has no state record: this is a *plaintext*
//     MPU (created before Valkey was introduced, or on a bucket that doesn't
//     require encryption). Safe to take the plaintext branch.
//   - (nil,   false, err) — transient infrastructure failure (Valkey down,
//     timeout, etc). The caller MUST treat this as fail-closed and refuse
//     the request rather than silently downgrading to plaintext, because
//     the upload may actually be encrypted and we just can't tell right now.
//
// This is the correct decision predicate for UploadPart, CompleteMultipartUpload,
// and AbortMultipartUpload — it reads the PolicySnapshot stored at Create time
// rather than the live policy, preventing mid-upload policy flips from affecting
// in-flight encrypted uploads (ADR-0009 §Security Considerations).
func (h *Handler) uploadStateEncrypted(ctx context.Context, uploadID string) (*mpu.UploadState, bool, error) {
	if h.mpuStateStore == nil || h.keyManager == nil {
		// Infrastructure absent is structurally "not encrypted" — bucketEncryptsMPU
		// + mpuGuardMisconfig at request entry already produced a 503 if the
		// policy required encryption, so reaching here means plaintext is
		// allowed.
		return nil, false, nil
	}
	opStart := time.Now()
	state, err := h.mpuStateStore.Get(ctx, uploadID)
	if err != nil {
		if errors.Is(err, mpu.ErrUploadNotFound) {
			// Normal path for plaintext MPU — upload was never registered in Valkey.
			h.metrics.RecordMPUStateStoreOp("Get", "not_found", time.Since(opStart))
			return nil, false, nil
		}
		// Transient infra error (Valkey down, timeout). Do NOT downgrade
		// to plaintext silently — the upload may actually be encrypted and
		// proceeding plaintext would write unencrypted data to a destination
		// that the client thinks is encrypted. Caller must surface as 503.
		h.metrics.RecordMPUStateStoreOp("Get", "error", time.Since(opStart))
		return nil, false, err
	}
	h.metrics.RecordMPUStateStoreOp("Get", "success", time.Since(opStart))
	return state, state.PolicySnapshot.EncryptMultipartUploads, nil
}

// mpuEncryptionReady reports whether the infrastructure required for
// encrypted MPU is available (state store + key manager). Returns (false,
// reason) when anything is missing, letting callers produce a precise
// 503 response instead of silently falling through to plaintext uploads.
func (h *Handler) mpuEncryptionReady() (bool, string) {
	if h.mpuStateStore == nil {
		return false, "MPU state store not configured"
	}
	if h.keyManager == nil {
		return false, "KeyManager not configured"
	}
	return true, ""
}

// mpuGuardMisconfig writes a 503 ServiceUnavailable response if the bucket's
// policy requires encrypted MPU but the infrastructure (state store / key
// manager) is not ready. Returns true when the request has been handled (i.e.
// the caller should return immediately). Prevents silent security degradation.
func (h *Handler) mpuGuardMisconfig(w http.ResponseWriter, r *http.Request, bucket, method string, start time.Time) bool {
	if !h.bucketEncryptsMPU(bucket) {
		return false
	}
	ready, reason := h.mpuEncryptionReady()
	if ready {
		return false
	}
	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"reason": reason,
	}).Error("Bucket policy requires encrypted MPU but infrastructure is not ready; refusing with 503")
	s3Err := &S3Error{
		Code:       "ServiceUnavailable",
		Message:    "Encrypted multipart uploads are configured for this bucket but the required infrastructure is not available: " + reason,
		Resource:   r.URL.Path,
		HTTPStatus: http.StatusServiceUnavailable,
	}
	s3Err.WriteXML(w)
	h.metrics.RecordHTTPRequest(r.Context(), method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
	return true
}

func (h *Handler) currentKeyVersion(ctx context.Context) int {
	if h.keyManager == nil {
		return 0
	}
	version, err := h.keyManager.ActiveKeyVersion(ctx)
	if err != nil {
		h.logger.WithError(err).Debug("Failed to get active key version")
		return 0
	}
	return version
}

// IsAdmin returns true if the request arrived on the admin listener.
// This is the shared reusable predicate consumed by V0.6-S3-2 for
// object-lock passthrough admin-authz hooks.
func (h *Handler) IsAdmin(r *http.Request) bool {
	return admin.IsAdminRequest(r)
}

// RegisterRoutes registers all API routes.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/health", h.handleHealth).Methods("GET")
	r.HandleFunc("/healthz", h.handleHealth).Methods("GET") // k8s-convention alias
	r.HandleFunc("/ready", h.handleReady).Methods("GET")
	r.HandleFunc("/readyz", h.handleReady).Methods("GET") // k8s-convention alias
	r.HandleFunc("/live", h.handleLive).Methods("GET")
	r.HandleFunc("/livez", h.handleLive).Methods("GET") // k8s-convention alias

	r.HandleFunc("/", h.handleListBuckets).Methods("GET")

	// S3 API routes
	s3Router := r.PathPrefix("/").Subrouter()

	// Multipart upload routes (must be registered first to ensure query parameter matching)
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleCreateMultipartUpload).Methods("POST").Queries("uploads", "")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleCompleteMultipartUpload).Methods("POST").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleAbortMultipartUpload).Methods("DELETE").Queries("uploadId", "{uploadId}")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleListParts).Methods("GET").Queries("uploadId", "{uploadId}")

	// Multipart-specific PUT route
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleUploadPart).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}")

	// Object Lock subresources (object-level) — must be registered BEFORE the
	// generic GET/PUT/{bucket}/{key:.+} routes so gorilla/mux matches the
	// query-parameter-scoped handlers first. V0.6-S3-2.
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObjectRetention).Methods("GET").Queries("retention", "")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObjectRetention).Methods("PUT").Queries("retention", "")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObjectLegalHold).Methods("GET").Queries("legal-hold", "")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObjectLegalHold).Methods("PUT").Queries("legal-hold", "")

	// Object tagging subresources
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObjectTagging).Methods("GET").Queries("tagging", "")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObjectTagging).Methods("PUT").Queries("tagging", "")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleDeleteObjectTagging).Methods("DELETE").Queries("tagging", "")

	// Object ACL subresources
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObjectACL).Methods("GET").Queries("acl", "")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObjectACL).Methods("PUT").Queries("acl", "")

	// RestoreObject
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleRestoreObject).Methods("POST").Queries("restore", "")

	// SelectObjectContent (501 NotImplemented)
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleSelectObjectContent).Methods("POST").Queries("select", "")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleSelectObjectContent).Methods("POST").Queries("select-type", "2")

	// Object Lock configuration (bucket-level) — must be registered BEFORE
	// the generic /{bucket} GET/PUT routes.
	s3Router.HandleFunc("/{bucket}", h.handleGetObjectLockConfiguration).Methods("GET").Queries("object-lock", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutObjectLockConfiguration).Methods("PUT").Queries("object-lock", "")

	// CORS preflight
	s3Router.HandleFunc("/{bucket}", h.handleCORSPreflight).Methods("OPTIONS")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleCORSPreflight).Methods("OPTIONS")

	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucket).Methods("DELETE")

	// Bucket lifecycle subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketLifecycle).Methods("GET").Queries("lifecycle", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketLifecycle).Methods("PUT").Queries("lifecycle", "")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketLifecycle).Methods("DELETE").Queries("lifecycle", "")

	// Bucket policy subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketPolicy).Methods("GET").Queries("policy", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketPolicy).Methods("PUT").Queries("policy", "")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketPolicy).Methods("DELETE").Queries("policy", "")

	// Bucket CORS subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketCors).Methods("GET").Queries("cors", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketCors).Methods("PUT").Queries("cors", "")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketCors).Methods("DELETE").Queries("cors", "")

	// Bucket versioning subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketVersioning).Methods("GET").Queries("versioning", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketVersioning).Methods("PUT").Queries("versioning", "")

	// Bucket encryption subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketEncryption).Methods("GET").Queries("encryption", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketEncryption).Methods("PUT").Queries("encryption", "")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketEncryption).Methods("DELETE").Queries("encryption", "")

	// Bucket ACL subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketACL).Methods("GET").Queries("acl", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketACL).Methods("PUT").Queries("acl", "")

	// Bucket location
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketLocation).Methods("GET").Queries("location", "")

	// Bucket uploads listing (multipart)
	s3Router.HandleFunc("/{bucket}", h.handleListMultipartUploads).Methods("GET").Queries("uploads", "")

	// Bucket notification subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketNotification).Methods("GET").Queries("notification", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketNotification).Methods("PUT").Queries("notification", "")

	// Bucket replication subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketReplication).Methods("GET").Queries("replication", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketReplication).Methods("PUT").Queries("replication", "")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketReplication).Methods("DELETE").Queries("replication", "")

	// Bucket logging subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketLogging).Methods("GET").Queries("logging", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketLogging).Methods("PUT").Queries("logging", "")

	// Bucket requestPayment subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketRequestPayment).Methods("GET").Queries("requestPayment", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketRequestPayment).Methods("PUT").Queries("requestPayment", "")

	// Bucket website subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketWebsite).Methods("GET").Queries("website", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketWebsite).Methods("PUT").Queries("website", "")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketWebsite).Methods("DELETE").Queries("website", "")

	// Bucket inventory subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketInventory).Methods("GET").Queries("inventory", "")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketInventory).Methods("PUT").Queries("inventory", "")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketInventory).Methods("DELETE").Queries("inventory", "")

	// Bucket analytics subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketAnalytics).Methods("GET").Queries("analytics", "")

	// Bucket intelligent-tiering
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketIntelligentTiering).Methods("PUT").Queries("intelligent-tiering", "")

	// Generic S3 routes
	s3Router.HandleFunc("/{bucket}", h.handleListObjects).Methods("GET")
	s3Router.HandleFunc("/{bucket}", h.handleHeadBucket).Methods("HEAD")
	s3Router.HandleFunc("/{bucket}", h.handleCreateBucket).Methods("PUT")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObject).Methods("GET")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObject).Methods("PUT")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleDeleteObject).Methods("DELETE")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleHeadObject).Methods("HEAD")

	// Batch operations
	s3Router.HandleFunc("/{bucket}", h.handleDeleteObjects).Methods("POST").Queries("delete", "")
}

// writeS3ClientError writes an appropriate S3 error response for client
// initialization / authentication failures.
//
// SECURITY: This function MUST NOT embed err.Error() (or any substring of it)
// into the response body. Upstream error strings may contain sensitive
// diagnostic detail (e.g. computed HMAC signatures — see the history of
// ValidateSignatureV4). Classify the error via errors.Is against the typed
// sentinels defined in auth.go and return a fixed, opaque message per class.
// The raw err is logged by call sites for operator diagnostics.
func (h *Handler) writeS3ClientError(w http.ResponseWriter, r *http.Request, err error, method string, start time.Time) {
	s3Err := classifyAuthError(err, r.URL.Path)
	// Log the underlying error so operators retain diagnostic visibility even
	// though it is not returned to the client. Call sites already log with
	// WithError, but re-log at debug level here so a single grep on the
	// response classification correlates with the upstream detail.
	if err != nil {
		h.logger.WithError(err).WithField("response_code", s3Err.Code).Debug("auth error classified")
	}
	s3Err.WriteXML(w)
	h.metrics.RecordHTTPRequest(r.Context(), method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
}

// classifyAuthError maps an error returned from getS3Client to a fixed
// client-facing S3Error. It is deliberately total: every input produces a
// response without consulting err.Error(). Pure function, no I/O — kept
// separate so it can be unit-tested.
//
// This function intentionally returns three distinct S3
// error codes rather than collapsing all auth failures into a single opaque
// response. The distinct codes (SignatureDoesNotMatch, InvalidAccessKeyId,
// AccessDenied) are required by the S3 specification and are relied upon by AWS
// SDK clients for retry logic and user-facing diagnostics. The enumeration
// risk is mitigated by ensuring that err.Error() — which may contain computed
// HMAC signatures or other sensitive diagnostic detail — is NEVER included in
// the response body; only the fixed per-class message string is written to the
// wire. Regression coverage is provided by TestClassifyAuthError_Table and
// TestWriteS3ClientError_NoLeakRegression in auth_error_test.go.
func classifyAuthError(err error, resource string) *S3Error {
	switch {
	case errors.Is(err, ErrSignatureMismatch):
		return &S3Error{
			Code:       "SignatureDoesNotMatch",
			Message:    "The request signature we calculated does not match the signature you provided. Check your key and signing method.",
			Resource:   resource,
			HTTPStatus: http.StatusForbidden,
		}
	case errors.Is(err, ErrUnknownAccessKey):
		return &S3Error{
			Code:       "InvalidAccessKeyId",
			Message:    "The AWS access key ID you provided does not exist in our records.",
			Resource:   resource,
			HTTPStatus: http.StatusForbidden,
		}
	case errors.Is(err, ErrMissingCredentials):
		return &S3Error{
			Code:       "AccessDenied",
			Message:    "Missing or invalid credentials in request.",
			Resource:   resource,
			HTTPStatus: http.StatusForbidden,
		}
	default:
		// Unknown / server-side failure. Never echo err.Error().
		return &S3Error{
			Code:       "InternalError",
			Message:    "We encountered an internal error. Please try again.",
			Resource:   resource,
			HTTPStatus: http.StatusInternalServerError,
		}
	}
}

// forwardSignatureV4Request forwards a Signature V4 request directly to the backend,
// preserving the original Authorization header and other headers.
func (h *Handler) forwardSignatureV4Request(w http.ResponseWriter, r *http.Request, method, bucket, key string, start time.Time) {
	if h.config == nil || h.config.Backend.Endpoint == "" {
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Backend endpoint not configured",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Build backend URL
	backendEndpoint := h.config.Backend.Endpoint
	if !strings.HasPrefix(backendEndpoint, "http://") && !strings.HasPrefix(backendEndpoint, "https://") {
		if h.config.Backend.UseSSL {
			backendEndpoint = "https://" + backendEndpoint
		} else {
			backendEndpoint = "http://" + backendEndpoint
		}
	}
	backendEndpoint = strings.TrimSuffix(backendEndpoint, "/")

	// For Signature V4 forwarding, always use path-style addressing
	// This is more compatible when forwarding signed requests because:
	// 1. The Host header can remain as the gateway's hostname (for signature validation)
	// 2. The backend endpoint hostname is used for the actual connection
	// 3. Path-style is more forgiving with Host header mismatches
	backendPath := fmt.Sprintf("/%s", bucket)
	if key != "" {
		backendPath = fmt.Sprintf("/%s/%s", bucket, key)
	}
	backendURL := backendEndpoint + backendPath

	if r.URL.RawQuery != "" {
		if strings.Contains(backendURL, "?") {
			backendURL += "&" + r.URL.RawQuery
		} else {
			backendURL += "?" + r.URL.RawQuery
		}
	}

	// Create request to backend
	backendReq, err := http.NewRequestWithContext(r.Context(), method, backendURL, r.Body) // #nosec G704 — S3 proxy: forward to configured backend
	if err != nil {
		h.logger.WithError(err).Error("Failed to create backend request")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to forward request",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Extract backend hostname from URL
	backendURLParsed, err := url.Parse(backendURL)
	if err == nil {
		backendHostname := backendURLParsed.Host

		// For Signature V4, the signature includes the Host header
		// We need to use the backend's hostname, but this may cause signature validation to fail
		// Some S3-compatible backends are lenient and will accept it
		// Copy all headers from original request (including Authorization)
		for k, v := range r.Header {
			// Skip Host - we'll set it to backend hostname
			if strings.EqualFold(k, "Host") {
				continue
			}
			backendReq.Header[k] = v
		}

		// Set Host to backend hostname (without port if default)
		backendReq.Host = backendHostname
		h.logger.WithFields(logrus.Fields{
			"original_host": r.Host,
			"backend_host":  backendHostname,
		}).Debug("Setting Host header to backend hostname for Signature V4 forwarding")
	} else {
		// Fallback: preserve original Host if URL parsing fails
		originalHost := r.Host
		if originalHost == "" {
			originalHost = r.Header.Get("Host")
		}
		for k, v := range r.Header {
			backendReq.Header[k] = v
		}
		backendReq.Host = originalHost
	}

	// Set Content-Length if present
	if r.ContentLength > 0 {
		backendReq.ContentLength = r.ContentLength
	}

	// Log forwarding details for debugging
	originalHost := r.Host
	if originalHost == "" {
		originalHost = r.Header.Get("Host")
	}
	h.logger.WithFields(logrus.Fields{
		"backend_url":   backendURL,
		"original_host": originalHost,
		"backend_host":  backendReq.Host,
		"method":        method,
	}).Debug("Forwarding Signature V4 request to backend")

	// Make request to backend
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			// V1.0-SEC-F6: enforce minimum TLS 1.2 and restricted cipher
			// suites consistent with the main S3 client and Cosmian KMS
			// client. The bare &http.Client{} default uses Go's
			// http.DefaultTransport which has no cipher restrictions.
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
					tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				},
				CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
			},
			IdleConnTimeout:       90 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			MaxIdleConnsPerHost:   10,
		},
	}
	backendResp, err := httpClient.Do(backendReq) // #nosec G704 — S3 proxy: forward to configured backend
	if err != nil {
		h.logger.WithError(err).Error("Failed to forward request to backend")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to connect to backend",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadGateway,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), method, r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	defer backendResp.Body.Close()

	// Log backend response for debugging
	h.logger.WithFields(logrus.Fields{
		"status_code": backendResp.StatusCode,
		"backend_url": backendURL,
	}).Debug("Backend response received")

	// If backend returned an error, log the response body
	if backendResp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(backendResp.Body)
		backendResp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		h.logger.WithFields(logrus.Fields{
			"status_code": backendResp.StatusCode,
			"response":    string(bodyBytes),
		}).Warn("Backend returned error response")
	}

	// Check if response is encrypted (before copying headers)
	metadata := make(map[string]string)
	if backendResp.StatusCode >= 200 && backendResp.StatusCode < 300 && method == "GET" {
		for k, v := range backendResp.Header {
			if len(v) > 0 {
				// Convert header names to lowercase for metadata check
				metadata[strings.ToLower(k)] = v[0]
			}
		}
	}

	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get encryption engine")
		// Fallback to forwarding as-is if engine fails
		engine = h.encryptionEngine
	}

	isEncrypted := engine.IsEncrypted(metadata)
	var decMetadata map[string]string
	var decryptedReader io.Reader

	if isEncrypted && backendResp.StatusCode >= 200 && backendResp.StatusCode < 300 && method == "GET" {
		// Try to decrypt - read body first, then decrypt
		bodyBytes, err := io.ReadAll(backendResp.Body)
		if err == nil {
			decryptedReader, decMetadata, err = engine.Decrypt(r.Context(), bytes.NewReader(bodyBytes), metadata)
			if err != nil {
				h.logger.WithError(err).Warn("Failed to decrypt forwarded response, returning as-is")
				isEncrypted = false // Fall back to forwarding encrypted
				backendResp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			} else {
				backendResp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		} else {
			isEncrypted = false
		}
	}

	// Copy response headers (before WriteHeader)
	for k, v := range backendResp.Header {
		// Skip headers that shouldn't be forwarded
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		// Remove encryption metadata if we decrypted
		if isEncrypted && strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			continue
		}
		w.Header()[k] = v
	}

	// Update headers if we decrypted
	if isEncrypted && decMetadata != nil {
		if cl, ok := decMetadata["Content-Length"]; ok {
			w.Header().Set("Content-Length", cl)
		}
		// Add decrypted metadata
		for k, v := range decMetadata {
			if strings.HasPrefix(k, "x-amz-meta-") {
				w.Header().Set(k, v)
			}
		}
	}

	// Write status code
	w.WriteHeader(backendResp.StatusCode)

	// Write response body
	var proxyWriteTimeout time.Duration
	if h.config != nil {
		proxyWriteTimeout = h.config.Server.WriteTimeout
	}
	if isEncrypted && decryptedReader != nil {
		copyWithDeadlineRefresh(w, decryptedReader, proxyWriteTimeout)
	} else {
		copyWithDeadlineRefresh(w, backendResp.Body, proxyWriteTimeout)
	}

	// Record metrics - use 0 if ContentLength is unknown (-1)
	contentLength := backendResp.ContentLength
	if contentLength < 0 {
		contentLength = 0
	}
	h.metrics.RecordHTTPRequest(r.Context(), method, r.URL.Path, backendResp.StatusCode, time.Since(start), contentLength)
}

// getS3Client returns the configured backend S3 client.
// Authentication has already been validated by AuthMiddleware before this
// point; this function only needs to return the pre-configured client.
func (h *Handler) getS3Client(r *http.Request) (s3.Client, error) {
	if h.s3Client != nil {
		return h.s3Client, nil
	}
	if h.clientFactory != nil {
		return h.clientFactory.GetClient()
	}
	return nil, fmt.Errorf("no S3 client available")
}

// getEncryptionEngine returns the appropriate encryption engine for the bucket.
// It checks if a specific policy exists for the bucket and returns a configured engine,
// otherwise returns the default global engine.
func (h *Handler) getEncryptionEngine(bucket string) (crypto.EncryptionEngine, error) {
	if h.policyManager == nil {
		return h.encryptionEngine, nil
	}

	policy := h.policyManager.GetPolicyForBucket(bucket)
	if policy == nil {
		return h.encryptionEngine, nil
	}

	// Check cache first (key by policy ID)
	if h.engineCache != nil {
		if cached, ok := h.engineCache.Get(policy.ID); ok {
			return cached, nil
		}
	}

	// Create new engine based on policy
	// Use global config as base and apply policy overrides
	if h.config == nil {
		// Should not happen if properly initialized
		return h.encryptionEngine, nil
	}

	// Apply policy to a copy of config
	effectiveConfig := policy.ApplyToConfig(h.config)

	// Reconstruct components
	var compressionEngine crypto.CompressionEngine
	if effectiveConfig.Compression.Enabled {
		compressionEngine = crypto.NewCompressionEngine(
			effectiveConfig.Compression.Enabled,
			effectiveConfig.Compression.MinSize,
			effectiveConfig.Compression.ContentTypes,
			effectiveConfig.Compression.Algorithm,
			effectiveConfig.Compression.Level,
		)
	}

	// Use password from effective config
	// Note: If password came from file and wasn't in config struct, we might have issues if policy doesn't specify it.
	// We assume main.go populated config struct or policy provides it.
	password := effectiveConfig.Encryption.Password
	// Fallback logic for password if not in config (e.g. loaded from file directly to var in main)
	// This is a limitation: we need the base password in config struct for this to work if policy doesn't override it.

	chunkedMode := effectiveConfig.Encryption.ChunkedMode
	if !effectiveConfig.Encryption.ChunkedMode && effectiveConfig.Encryption.ChunkSize == 0 {
		chunkedMode = true
	}
	chunkSize := effectiveConfig.Encryption.ChunkSize
	if chunkSize == 0 {
		chunkSize = crypto.DefaultChunkSize
	}

	engine, err := crypto.NewEngineWithChunking(
		[]byte(password),
		compressionEngine,
		effectiveConfig.Encryption.PreferredAlgorithm,
		effectiveConfig.Encryption.SupportedAlgorithms,
		chunkedMode,
		chunkSize,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy engine: %w", err)
	}

	// Configure KeyManager
	if effectiveConfig.Encryption.KeyManager.Enabled {
		// If policy specifies different KM config, build new one
		if policy.Encryption != nil && (policy.Encryption.KeyManager.Enabled || policy.Encryption.KeyManager.Provider != "") {
			km, err := BuildKeyManager(&effectiveConfig.Encryption.KeyManager, h.logger)
			if err != nil {
				return nil, fmt.Errorf("failed to build policy key manager: %w", err)
			}
			crypto.SetKeyManager(engine, km)
		} else {
			// Reuse global key manager
			crypto.SetKeyManager(engine, h.keyManager)
		}
	}

	// Cache the new engine (atomically — if another goroutine raced us
	// and stored first, we close the redundant engine and return the winner).
	if h.engineCache != nil {
		engine = h.engineCache.GetOrStore(policy.ID, engine)
	}

	return engine, nil
}

// handleHealth handles health check requests.
func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	handler := metrics.HealthHandler()
	handler(w, r)
	h.metrics.RecordHTTPRequest(r.Context(), "GET", "/health", http.StatusOK, time.Since(start), 0)
}

// handleReady handles readiness check requests.
// It runs a health check against every configured dependency (KMS, Valkey state
// store) and returns 503 if any check fails, 200 otherwise. The response body
// includes a per-component "checks" map so Kubernetes and operators can see
// exactly which dependency is unhealthy.
func (h *Handler) handleReady(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Build the list of named dependency checks. Only add a check when the
	// dependency is actually configured — omitting it keeps the map clean for
	// deployments that don't use that optional feature.
	var checks []metrics.ReadyCheck
	if h.keyManager != nil {
		checks = append(checks, metrics.ReadyCheck{
			Name:  "kms",
			Check: h.keyManager.HealthCheck,
		})
	}
	if h.mpuStateStore != nil {
		checks = append(checks, metrics.ReadyCheck{
			Name: "valkey",
			Check: func(ctx context.Context) error {
				err := h.mpuStateStore.HealthCheck(ctx)
				h.metrics.SetMPUValkeyUp(err == nil)
				return err
			},
		})
	}

	// Wrap w so we can read back the status code for the metric without
	// re-running every health check a second time.
	rec := &statusRecorder{ResponseWriter: w, code: http.StatusOK}
	metrics.ReadinessHandler(checks...)(rec, r)
	h.metrics.RecordHTTPRequest(r.Context(), "GET", "/readyz", rec.code, time.Since(start), 0)
}

// statusRecorder wraps http.ResponseWriter to capture the written status code.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// handleLive handles liveness check requests.
func (h *Handler) handleLive(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	handler := metrics.LivenessHandler()
	handler(w, r)
	h.metrics.RecordHTTPRequest(r.Context(), "GET", "/live", http.StatusOK, time.Since(start), 0)
}

// handleGetObject handles GET object requests.
func (h *Handler) handleGetObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Starting GET object")

	if bucket == "" || key == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Extract version ID if provided
	var versionID *string
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		versionID = &vid
	}

	// Get range header if present
	var rangeHeader *string
	if rg := r.Header.Get("Range"); rg != "" {
		rangeHeader = &rg
	}

	// Get encryption engine for this bucket
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get encryption engine")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to load encryption configuration",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Check cache first if enabled and no range request
	if h.cache != nil && rangeHeader == nil && versionID == nil {
		if cachedEntry, ok := h.cache.Get(ctx, bucket, key); ok {
			// Serve from cache
			for k, v := range cachedEntry.Metadata {
				w.Header().Set(k, v)
			}
			w.WriteHeader(http.StatusOK)
			w.Write(cachedEntry.Data)
			h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), int64(len(cachedEntry.Data)))
			if h.auditLogger != nil {
				h.auditLogger.LogAccess("get", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
			}
			return
		}
	}

	// If Range is requested, optimize for chunked encryption format
	// For chunked encryption: calculate encrypted byte range and fetch only needed chunks
	// For legacy/buffered encryption: fetch full object, decrypt, then apply range
	var backendRange *string
	var useRangeOptimization bool
	var plaintextStart, plaintextEnd int64

	// Get S3 client (may use client credentials if enabled)
	// For Signature V4 requests, s3Client may be nil - we'll forward the request directly
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "GET", start)
		return
	}

	// If s3Client is nil, this indicates Signature V4 was detected and can't be handled
	if s3Client == nil && err == nil {
		// This shouldn't happen - getS3Client should return an error for Signature V4
		// But handle it gracefully just in case
		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Signature V4 requests are not supported. Please use query parameter authentication instead.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	if rangeHeader != nil {
		// Determine the backend byte range to request. The decision depends on
		// the encryption format of the object:
		//
		//  MPU-encrypted  → fetch entire concatenated ciphertext (backendRange=nil);
		//                    decryptMPUObject decrypts all parts then slices the
		//                    plaintext to the requested range.
		//  Chunked (single-PUT) → translate plaintext range to encrypted chunk range.
		//  Legacy / unencrypted  → forward the client range directly.
		//
		// IsEncrypted only knows MetaEncrypted; MPU objects carry MetaMPUEncrypted
		// instead. Both must be detected before falling through to the forward path,
		// otherwise the plaintext-space range is sent to the backend as a
		// ciphertext-space range, fetching the wrong bytes.
		headMeta, headErr := s3Client.HeadObject(ctx, bucket, key, versionID)
		if headErr == nil && headMeta[crypto.MetaMPUEncrypted] == "true" {
			// MPU-encrypted ranged GET: serve via a dedicated path that maps
			// the plaintext range to backend ciphertext offsets from the
			// manifest and fetches only those bytes.
			h.serveMPURangedGet(w, r, ctx, bucket, key, versionID, headMeta, *rangeHeader, s3Client, start)
			return
		} else if headErr == nil && engine.IsEncrypted(headMeta) {
			// Single-PUT chunked or legacy encrypted object.
			if crypto.IsChunkedFormat(headMeta) {
				// Get plaintext size for range parsing
				plaintextSize, err := crypto.GetPlaintextSizeFromMetadata(headMeta)
				if err == nil {
					// Parse range header to get plaintext byte range
					start, end, err := crypto.ParseHTTPRangeHeader(*rangeHeader, plaintextSize)
					if err == nil {
						plaintextStart, plaintextEnd = start, end
						// Calculate encrypted byte range for needed chunks
						encryptedStart, encryptedEnd, err := crypto.CalculateEncryptedRangeForPlaintextRange(headMeta, start, end)
						if err == nil {
							encryptedRange := fmt.Sprintf("bytes=%d-%d", encryptedStart, encryptedEnd)
							backendRange = &encryptedRange
							useRangeOptimization = true
							h.logger.WithFields(logrus.Fields{
								"bucket":          bucket,
								"key":             key,
								"plaintext_range": fmt.Sprintf("%d-%d", start, end),
								"encrypted_range": encryptedRange,
							}).Debug("Using optimized range request for chunked encryption")
						} else {
							h.logger.WithError(err).Warn("Failed to calculate encrypted range, falling back to full fetch")
							backendRange = nil
						}
					} else {
						h.logger.WithError(err).Warn("Failed to parse range header, falling back to full fetch")
						backendRange = nil
					}
				} else {
					h.logger.WithError(err).Warn("Failed to get plaintext size, falling back to full fetch")
					backendRange = nil
				}
			} else {
				// Legacy format: must fetch full object, decrypt, then apply range.
				backendRange = nil
			}
		} else {
			// Not encrypted or HEAD failed: forward range to backend as-is.
			backendRange = rangeHeader
		}
	}

	reader, metadata, err := s3Client.GetObject(ctx, bucket, key, versionID, backendRange)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to get object")
		h.metrics.RecordS3Error(r.Context(), "GetObject", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	defer reader.Close()

	// For MPU-encrypted objects, delegate to the MPU decrypt path.
	if metadata[crypto.MetaMPUEncrypted] == "true" {
		decryptStart := time.Now()
		decryptedReader, err := h.decryptMPUObject(ctx, bucket, key, metadata, reader, s3Client)
		decryptDuration := time.Since(decryptStart)
		if err != nil {
			h.metrics.RecordEncryptionError(r.Context(), "decrypt", "mpu_decryption_failed")
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
			}).Error("Failed to decrypt MPU object")
			s3Err := &S3Error{
				Code:       "InternalError",
				Message:    "Failed to decrypt multipart encrypted object",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		// Read the first chunk up front so any AEAD authentication failure
		// surfaces as a 5xx response rather than a 200 with partial/empty
		// bytes. `io.Copy` discards the error after WriteHeader, so we must
		// catch a tamper at the earliest point.
		firstChunk := make([]byte, crypto.DefaultChunkSize)
		n, firstErr := io.ReadFull(decryptedReader, firstChunk)
		if firstErr != nil && firstErr != io.EOF && firstErr != io.ErrUnexpectedEOF {
			h.logger.WithError(firstErr).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
			}).Error("MPU decrypt failed on first chunk (tamper or corruption)")
			h.metrics.RecordEncryptionError(r.Context(), "decrypt", "mpu_tamper_detected")
			if h.auditLogger != nil {
				h.auditLogger.Log(&audit.AuditEvent{
					EventType: audit.EventTypeMPUTamperDetected,
					Timestamp: time.Now().UTC(),
					Bucket:    bucket,
					Key:       key,
					Success:   false,
					Metadata:  map[string]interface{}{"status": "tamper_detected"},
				})
			}
			s3Err := &S3Error{
				Code:       "InternalError",
				Message:    "Object integrity check failed",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		firstChunk = firstChunk[:n]
		// Forward safe metadata headers.
		for k, v := range metadata {
			if k != crypto.MetaMPUEncrypted && k != crypto.MetaFallbackMode && k != crypto.MetaFallbackPointer && strings.ToLower(k) != "content-length" {
				w.Header().Set(k, v)
			}
		}
		w.WriteHeader(http.StatusOK)
		written, _ := w.Write(firstChunk)
		if firstErr == nil { // more data to stream
			var writeTimeout time.Duration
			if h.config != nil {
				writeTimeout = h.config.Server.WriteTimeout
			}
			extra, copyErr := copyWithDeadlineRefresh(w, decryptedReader, writeTimeout)
			if copyErr != nil {
				if isNetworkError(copyErr) {
					// Client disconnect or network timeout — not a tamper event.
					h.logger.WithError(copyErr).WithFields(logrus.Fields{
						"bucket": bucket,
						"key":    key,
					}).Warn("MPU stream aborted by network error after 200 OK")
				} else {
					// Can't change the status code after WriteHeader; log and
					// record a tamper metric so operators see the integrity
					// failure even though the client already got 200 headers.
					h.logger.WithError(copyErr).WithFields(logrus.Fields{
						"bucket": bucket,
						"key":    key,
					}).Error("MPU decrypt failed mid-stream after 200 OK; connection terminated")
					h.metrics.RecordEncryptionError(r.Context(), "decrypt", "mpu_tamper_detected_midstream")
					if h.auditLogger != nil {
						h.auditLogger.Log(&audit.AuditEvent{
							EventType: audit.EventTypeMPUTamperDetected,
							Timestamp: time.Now().UTC(),
							Bucket:    bucket,
							Key:       key,
							Success:   false,
							Metadata:  map[string]interface{}{"status": "tamper_detected_midstream"},
						})
					}
				}
			}
			written += int(extra)
		}
		h.metrics.RecordEncryptionOperation(r.Context(), "decrypt", decryptDuration, decryptedSizeForMPU(metadata))
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), int64(written))
		return
	}

	// Decrypt if encrypted
	decryptStart := time.Now()
	var decryptedReader io.Reader
	var decMetadata map[string]string

	if useRangeOptimization && engine.IsEncrypted(metadata) {
		// Use range-optimized decryption (only decrypts needed chunks).
		// The source reader is already positioned at the correct encrypted
		// byte range (backendRange was applied), so we need the variant
		// that does NOT skip leading chunks.
		if eng, ok := engine.(interface {
			DecryptRangeOptimized(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
		}); ok {
			decryptedReader, decMetadata, err = eng.DecryptRangeOptimized(r.Context(), reader, metadata, plaintextStart, plaintextEnd)
			if err != nil {
				h.logger.WithError(err).Error("Range-optimized decryption failed")
				h.metrics.RecordEncryptionError(r.Context(), "decrypt", "range_optimized_decryption_failed")
				s3Err := &S3Error{
					Code:       "InternalError",
					Message:    "Failed to decrypt object",
					Resource:   r.URL.Path,
					HTTPStatus: http.StatusInternalServerError,
				}
				s3Err.WriteXML(w)
				h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
				return
			}
		} else {
			// Engine doesn't support DecryptRangeOptimized, fall back
			h.logger.Warn("Engine doesn't support DecryptRangeOptimized, falling back to full decrypt")
			decryptedReader, decMetadata, err = engine.Decrypt(r.Context(), reader, metadata)
			useRangeOptimization = false
		}
	} else {
		// Standard decryption (full object)
		decryptedReader, decMetadata, err = engine.Decrypt(r.Context(), reader, metadata)
	}
	decryptDuration := time.Since(decryptStart)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to decrypt object")
		h.metrics.RecordEncryptionError(r.Context(), "decrypt", "decryption_failed")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to decrypt object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// For range optimization, we already have the exact range in decryptedReader
	// For non-optimized ranges, we need to buffer and apply range
	var decryptedData []byte
	var decryptedSize int64
	if rangeHeader != nil && *rangeHeader != "" && !useRangeOptimization {
		// Buffer for range processing (only if not using optimization)
		dd, err := io.ReadAll(decryptedReader)
		if err != nil {
			h.logger.WithError(err).Error("Failed to read decrypted data")
			s3Err := &S3Error{
				Code:       "InternalError",
				Message:    "Failed to read decrypted data",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
			if h.auditLogger != nil {
				alg := metadata[crypto.MetaAlgorithm]
				if alg == "" {
					alg = crypto.AlgorithmAES256GCM
				}
				h.auditLogger.LogDecrypt(bucket, key, alg, 0, false, err, decryptDuration, nil)
			}
			return
		}
		decryptedData = dd
		decryptedSize = int64(len(decryptedData))
	} else if useRangeOptimization {
		// For optimized range, the reader already contains only the range
		// But we still need to read it to send it
		decryptedSize = plaintextEnd - plaintextStart + 1
	} else {
		// Full-object decrypt (no range request): try to get plaintext size
		// from encryption metadata so the byte counter is accurate.
		if ps, err := crypto.GetPlaintextSizeFromMetadata(metadata); err == nil && ps > 0 {
			decryptedSize = ps
		}
	}
	h.metrics.RecordEncryptionOperation(r.Context(), "decrypt", decryptDuration, decryptedSize)

	// Get algorithm and key version from metadata for audit logging
	algorithm := metadata[crypto.MetaAlgorithm]
	if algorithm == "" {
		algorithm = crypto.AlgorithmAES256GCM
	}

	// Extract actual key version used for decryption from metadata
	keyVersionUsed := 0
	if kvStr, ok := metadata[crypto.MetaKeyVersion]; ok && kvStr != "" {
		if kv, err := strconv.Atoi(kvStr); err == nil {
			keyVersionUsed = kv
		}
	}

	// Get active key version and check for rotated read
	activeKeyVersion := 0
	if h.keyManager != nil {
		activeKeyVersion = h.currentKeyVersion(r.Context())
		// Track rotated read if key version used differs from active version
		if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
			h.metrics.RecordRotatedRead(r.Context(), keyVersionUsed, activeKeyVersion)
		}
	}

	// Use keyVersionUsed for audit logging (actual version used, not active)
	keyVersion := keyVersionUsed
	if keyVersion == 0 && h.keyManager != nil {
		// Fallback to active version if metadata doesn't have version
		keyVersion = activeKeyVersion
	}

	// Audit logging with metadata indicating rotated read if applicable
	auditMetadata := make(map[string]interface{})
	if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
		auditMetadata["rotated_read"] = true
		auditMetadata["key_version_used"] = keyVersionUsed
		auditMetadata["active_key_version"] = activeKeyVersion
	}
	if h.auditLogger != nil {
		h.auditLogger.LogDecrypt(bucket, key, algorithm, keyVersion, true, nil, decryptDuration, auditMetadata)
	}

	// Store in cache if enabled and no range/version request
	if h.cache != nil && rangeHeader == nil && versionID == nil {
		if err := h.cache.Set(ctx, bucket, key, decryptedData, decMetadata, 0); err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
			}).Warn("Failed to cache object")
		}
	}

	// Apply range request if present (after decryption) and set headers BEFORE WriteHeader
	outputData := decryptedData
	if rangeHeader != nil && *rangeHeader != "" {
		if useRangeOptimization {
			// V0.6-PERF-1 Phase B: Optimized range — stream directly to the
			// response writer without buffering the entire range into memory.
			// Content-Length is known from the plaintext range (already computed
			// above at decryptedSize). This eliminates one full-range allocation.

			// Get total size for Content-Range header
			totalSize, _ := crypto.GetPlaintextSizeFromMetadata(metadata)
			if totalSize == 0 {
				// Fallback to approximate from decryptedData if available
				totalSize = int64(len(decryptedData))
			}

			// Set decrypted metadata headers
			for k, v := range decMetadata {
				if !isEncryptionMetadata(k) {
					w.Header().Set(k, v)
				}
			}
			if versionID != nil && *versionID != "" {
				w.Header().Set("x-amz-version-id", *versionID)
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", plaintextStart, plaintextEnd, totalSize))
			w.Header().Set("Content-Length", fmt.Sprintf("%d", decryptedSize))
			w.WriteHeader(http.StatusPartialContent)

			// Stream range bytes directly — no intermediate buffer.
			pool := crypto.GetGlobalBufferPool()
			buf := pool.Get64K()
			defer pool.Put(buf)
			n64, copyErr := io.CopyBuffer(w, decryptedReader, buf)
			if copyErr != nil {
				h.logger.WithError(copyErr).Error("Failed to write optimized range data")
				// Headers already sent; log only.
			}
			h.metrics.RecordS3Operation(r.Context(), "GetObject", bucket, time.Since(start))
			h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusPartialContent, time.Since(start), n64)
			return
		} else {
			// Non-optimized: apply range to buffered data
			outputData, err = applyRangeRequest(decryptedData, *rangeHeader)
			if err != nil {
				s3Err := &S3Error{
					Code:       "InvalidRange",
					Message:    fmt.Sprintf("Invalid range request: %v", err),
					Resource:   r.URL.Path,
					HTTPStatus: http.StatusRequestedRangeNotSatisfiable,
				}
				s3Err.WriteXML(w)
				h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
				return
			}

			// Parse the original range to get correct Content-Range header
			rangeStart, rangeEnd, err := crypto.ParseHTTPRangeHeader(*rangeHeader, int64(len(decryptedData)))
			if err != nil {
				// This shouldn't happen since applyRangeRequest succeeded, but handle gracefully
				h.logger.WithError(err).Warn("Failed to parse range header for Content-Range")
				rangeStart, rangeEnd = 0, int64(len(outputData)-1)
			}

			// Set decrypted metadata headers
			for k, v := range decMetadata {
				if !isEncryptionMetadata(k) {
					w.Header().Set(k, v)
				}
			}
			if versionID != nil && *versionID != "" {
				w.Header().Set("x-amz-version-id", *versionID)
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rangeStart, rangeEnd, len(decryptedData)))
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(outputData)))
			w.WriteHeader(http.StatusPartialContent)
		}
	} else {
		// Set decrypted metadata headers and stream body
		for k, v := range decMetadata {
			if !isEncryptionMetadata(k) {
				w.Header().Set(k, v)
			}
		}
		if versionID != nil && *versionID != "" {
			w.Header().Set("x-amz-version-id", *versionID)
		}
		w.WriteHeader(http.StatusOK)
		var writeTimeout time.Duration
		if h.config != nil {
			writeTimeout = h.config.Server.WriteTimeout
		}
		n64, err := copyWithDeadlineRefresh(w, decryptedReader, writeTimeout)
		if err != nil {
			if isNetworkError(err) {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    key,
				}).Warn("Object stream aborted by network error after 200 OK")
			} else {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    key,
				}).Error("Failed to write response")
			}
			// Can't change status code after WriteHeader; still record the bytes sent.
			h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), n64)
			return
		}
		h.metrics.RecordS3Operation(r.Context(), "GetObject", bucket, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), n64)
		return
	}

	// For ranged responses, write buffered bytes
	n, err := w.Write(outputData)
	if err != nil {
		h.logger.WithError(err).Error("Failed to write response")
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), int64(n))
		return
	}

	h.metrics.RecordS3Operation(r.Context(), "GetObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), int64(n))
}

// handlePutObject handles PUT object requests.
func (h *Handler) handlePutObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("Starting PUT object")

	if bucket == "" || key == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	// Check if this is a copy operation
	copySource := r.Header.Get("x-amz-copy-source")
	if copySource != "" {
		// Handle copy operation (pass s3Client)
		h.handleCopyObject(w, r, bucket, key, copySource, start, s3Client)
		return
	}

	// Extract tagging header
	tagging := r.Header.Get("x-amz-tagging")
	if err := validateTags(tagging); err != nil {
		h.logger.WithError(err).Error("Invalid tagging header")
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    err.Error(),
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Extract canned ACL header (x-amz-acl) and fine-grained grant headers.
	// Forward verbatim to the backend; the gateway does not validate ACL values
	// because it is a transparent proxy and different backends support different
	// canned ACL strings (private, public-read, authenticated-read, etc.).
	cannedACL := r.Header.Get("x-amz-acl")
	grantFullControl := r.Header.Get("x-amz-grant-full-control")
	grantRead := r.Header.Get("x-amz-grant-read")
	grantReadACP := r.Header.Get("x-amz-grant-read-acp")
	grantWriteACP := r.Header.Get("x-amz-grant-write-acp")

	// Extract metadata from headers (preserve original metadata)
	// Only include x-amz-meta-* headers - standard headers should NOT be included
	// as they will cause S3 API errors when sent as metadata.
	//
	// Go canonicalises HTTP header keys on parse (X-Amz-Meta-Foo), so the
	// prefix comparison must be case-insensitive and the map key lower-cased
	// for consistency with the backend client and downstream metadata code.
	metadata := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
				metadata[strings.ToLower(k)] = v[0]
			}
		}
	}

	// Pass the original content length to the encryption engine via
	// Content-Length in the metadata map.  The engine reads this to
	// compute x-amz-meta-encryption-original-size, then
	// filterS3Metadata strips Content-Length (standard header) before
	// sending to S3.  For AWS Chunked Uploads we use
	// x-amz-decoded-content-length as that represents the actual object
	// size, while the HTTP Content-Length includes chunk overhead.
	var originalBytes int64
	decodedLen := r.Header.Get("x-amz-decoded-content-length")
	if decodedLen != "" {
		metadata["Content-Length"] = decodedLen
		if v, err := strconv.ParseInt(decodedLen, 10, 64); err == nil {
			originalBytes = v
		}
	} else if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
		metadata["Content-Length"] = contentLength
		if v, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
			originalBytes = v
		}
	}

	// Extract Content-Type for encryption engine (for compression decisions)
	// The encryption engine reads it from metadata, but we'll filter it out before S3
	// This is a temporary inclusion - filterS3Metadata will remove it
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream" // Default to match MinIO's behavior
	}
	metadata["Content-Type"] = contentType

	// Get encryption engine for this bucket
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get encryption engine")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to load encryption configuration",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Check for AWS Chunked Uploads
	// If detected, we must decode the stream to remove chunk metadata (signatures)
	// before encrypting, otherwise the encrypted content will be corrupted with metadata.
	// Check for any STREAMING- header value (e.g. STREAMING-AWS4-HMAC-SHA256-PAYLOAD or STREAMING-UNSIGNED-PAYLOAD-TRAILER)
	var inputReader io.Reader = r.Body
	contentSha256 := r.Header.Get("x-amz-content-sha256")
	if strings.HasPrefix(contentSha256, "STREAMING-") {
		inputReader = NewAwsChunkedReader(r.Body)
		h.logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
			"mode":   contentSha256,
		}).Debug("Detected AWS Chunked Upload, decoding stream before encryption")
	}

	// Encrypt the object
	encryptStart := time.Now()
	encryptedReader, encMetadata, err := engine.Encrypt(r.Context(), inputReader, metadata)
	encryptDuration := time.Since(encryptStart)

	// Get algorithm and key version for audit logging
	algorithm := encMetadata[crypto.MetaAlgorithm]
	if algorithm == "" {
		algorithm = crypto.AlgorithmAES256GCM
	}
	keyVersion := 0
	if h.keyManager != nil {
		keyVersion = h.currentKeyVersion(r.Context())
	}

	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to encrypt object")
		h.metrics.RecordEncryptionError(r.Context(), "encrypt", "encryption_failed")

		// Audit logging for failed encryption
		if h.auditLogger != nil {
			h.auditLogger.LogEncrypt(bucket, key, algorithm, keyVersion, false, err, encryptDuration, nil)
		}

		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to encrypt object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Audit logging for successful encryption
	if h.auditLogger != nil {
		h.auditLogger.LogEncrypt(bucket, key, algorithm, keyVersion, true, nil, encryptDuration, nil)
	}

	// Invalidate cache for this object if cache is enabled
	if h.cache != nil {
		h.cache.Delete(ctx, bucket, key)
	}

	// Record encryption metrics using original bytes
	h.metrics.RecordEncryptionOperation(r.Context(), "encrypt", encryptDuration, originalBytes)

	// Debug logging for metadata before upload
	h.logger.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"metadata_keys": len(encMetadata),
	}).Debug("Uploading encrypted object with metadata")

	// Log all metadata keys for debugging (don't log values for security)
	metadataKeys := make([]string, 0, len(encMetadata))
	for k := range encMetadata {
		metadataKeys = append(metadataKeys, k)
		// Check for potentially problematic values
		if v, ok := encMetadata[k]; ok && v == "0" {
			h.logger.WithFields(logrus.Fields{
				"metadata_key": k,
				"value":        v,
			}).Warn("Metadata contains zero value - may cause S3 rejection")
		}
	}
	h.logger.WithFields(logrus.Fields{
		"bucket":        bucket,
		"key":           key,
		"metadata_keys": metadataKeys,
	}).Debug("Metadata keys before filtering")

	// Filter out standard HTTP headers from metadata before sending to S3
	// S3 metadata should only contain x-amz-meta-* headers, not standard headers like Content-Length
	var filterKeys []string
	if h.config != nil {
		filterKeys = h.config.Backend.FilterMetadataKeys
	}
	s3Metadata := filterS3Metadata(encMetadata, filterKeys)

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    key,
	}).Debug("PUT object encrypted successfully")
	// Log filtered metadata keys and value sizes for debugging
	filteredKeys := make([]string, 0, len(s3Metadata))
	metadataSizes := make(map[string]int)
	for k, v := range s3Metadata {
		filteredKeys = append(filteredKeys, k)
		metadataSizes[k] = len(v)
		// S3 metadata values are limited to 2KB per AWS docs, but some providers may be stricter
		if len(v) > 2048 {
			h.logger.WithFields(logrus.Fields{
				"bucket":       bucket,
				"key":          key,
				"metadata_key": k,
				"value_size":   len(v),
			}).Warn("Metadata value exceeds 2KB - may cause S3 rejection")
		}
	}
	h.logger.WithFields(logrus.Fields{
		"bucket":         bucket,
		"key":            key,
		"metadata_keys":  filteredKeys,
		"metadata_sizes": metadataSizes,
	}).Debug("Metadata keys after filtering (being sent to S3)")

	// Compute encrypted content length for chunked mode if possible to avoid chunked transfer
	var contentLengthPtr *int64
	if encMetadata[crypto.MetaChunkedFormat] == "true" && originalBytes > 0 {
		// Determine chunk size from metadata
		chunkSize := crypto.DefaultChunkSize
		if csStr, ok := encMetadata[crypto.MetaChunkSize]; ok && csStr != "" {
			if cs, err := strconv.Atoi(csStr); err == nil && cs > 0 {
				chunkSize = cs
			}
		}
		// AEAD tag size for AES-GCM and ChaCha20-Poly1305 is 16 bytes
		const aeadTagSize = 16
		chunkCount := (originalBytes + int64(chunkSize) - 1) / int64(chunkSize)
		encLen := originalBytes + chunkCount*int64(aeadTagSize)
		contentLengthPtr = &encLen
	}

	// Extract lock headers
	lockInput, s3Err := extractObjectLockInput(r)
	if s3Err != nil {
		s3Err.WriteXML(w)
		return
	}

	// Upload encrypted object with filtered metadata (streaming)
	etag, err := s3Client.PutObject(ctx, bucket, key, encryptedReader, s3Metadata, contentLengthPtr, tagging, lockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":        bucket,
			"key":           key,
			"metadata_keys": metadataKeys,
		}).Error("Failed to put object")
		h.metrics.RecordS3Error(r.Context(), "PutObject", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation(r.Context(), "PutObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// isStandardMetadata checks if a header is a standard HTTP metadata header.
func isStandardMetadata(key string) bool {
	standardHeaders := map[string]bool{
		"Content-Type":        true,
		"Content-Length":      true,
		"ETag":                true,
		"Cache-Control":       true,
		"Expires":             true,
		"Content-Encoding":    true,
		"Content-Language":    true,
		"Content-Disposition": true,
		"Last-Modified":       true,
	}
	return standardHeaders[key]
}

// handleDeleteObject handles DELETE object requests.
func (h *Handler) handleDeleteObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// V0.6-S3-2: refuse x-amz-bypass-governance-retention unconditionally
	// pending V0.6-CFG-1 admin authorization. Consistent with the
	// PutObjectRetention path so clients see the same refusal regardless
	// of entry point.
	if refuseBypassGovernanceRetention(w, r, h, bucket, key, start) {
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "DELETE", start)
		return
	}

	// Extract version ID if provided
	var versionID *string
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		versionID = &vid
	}

	err = s3Client.DeleteObject(ctx, bucket, key, versionID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to delete object")
		h.metrics.RecordS3Error(r.Context(), "DeleteObject", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		if h.auditLogger != nil {
			h.auditLogger.LogAccess("delete", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), false, err, time.Since(start))
		}
		return
	}

	// Invalidate cache for deleted object
	if h.cache != nil {
		h.cache.Delete(ctx, bucket, key)
	}

	// Clean up MPU manifest companion object (best-effort).
	// Non-MPU objects have no manifest, so a 404 on the companion key is
	// expected and silently ignored. Manifest cleanup failures must NOT
	// propagate as primary delete errors — the object itself is already gone.
	manifestKey := key + ".mpu-manifest"
	if err := s3Client.DeleteObject(ctx, bucket, manifestKey, nil); err != nil {
		if isS3NotFoundError(err) {
			h.logger.WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    manifestKey,
			}).Debug("No MPU manifest to clean up (object was not an MPU-encrypted object)")
		} else {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    manifestKey,
			}).Warn("Failed to clean up MPU manifest companion object")
		}
	} else {
		h.logger.WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    manifestKey,
		}).Debug("Cleaned up MPU manifest companion object")
	}

	// Audit logging
	if h.auditLogger != nil {
		h.auditLogger.LogAccess("delete", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
	}

	w.WriteHeader(http.StatusNoContent)
	h.metrics.RecordS3Operation(r.Context(), "DeleteObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "DELETE", r.URL.Path, http.StatusNoContent, time.Since(start), 0)
}

// handleHeadObject handles HEAD object requests.
func (h *Handler) handleHeadObject(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "HEAD", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "HEAD", start)
		return
	}

	// Extract version ID if provided
	var versionID *string
	if vid := r.URL.Query().Get("versionId"); vid != "" {
		versionID = &vid
	}

	metadata, err := s3Client.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to head object")
		h.metrics.RecordS3Error(r.Context(), "HeadObject", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "HEAD", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Filter out encryption metadata and restore original metadata
	filteredMetadata := make(map[string]string)
	for k, v := range metadata {
		// Skip encryption-related metadata in response
		if !isEncryptionMetadata(k) {
			filteredMetadata[k] = v
		}
	}

	// Restore original size if available
	if originalSize, ok := metadata["x-amz-meta-encryption-original-size"]; ok {
		filteredMetadata["Content-Length"] = originalSize
	} else if originalSize, ok := metadata["x-amz-meta-original-content-length"]; ok {
		filteredMetadata["Content-Length"] = originalSize
	}

	// Restore original ETag if available
	if originalETag, ok := metadata["x-amz-meta-encryption-original-etag"]; ok {
		filteredMetadata["ETag"] = originalETag
	}

	// Set headers from filtered metadata
	for k, v := range filteredMetadata {
		w.Header().Set(k, v)
	}

	// Preserve version ID in response if present
	if versionID != nil && *versionID != "" {
		w.Header().Set("x-amz-version-id", *versionID)
	}

	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation(r.Context(), "HeadObject", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "HEAD", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// isEncryptionMetadata checks if a metadata key is related to encryption.
func isEncryptionMetadata(key string) bool {
	encryptionKeys := []string{
		"x-amz-meta-encryption-algorithm",
		"x-amz-meta-encryption-key-salt",
		"x-amz-meta-encryption-iv",
		"x-amz-meta-encryption-auth-tag",
		"x-amz-meta-encryption-original-size",
		"x-amz-meta-encryption-original-etag",
		"x-amz-meta-encryption-compression",
		"x-amz-meta-compression-enabled",
		"x-amz-meta-compression-algorithm",
		"x-amz-meta-compression-original-size",
		// Chunked encryption metadata
		"x-amz-meta-encryption-chunked",
		"x-amz-meta-encryption-chunk-size",
		"x-amz-meta-encryption-chunk-count",
		"x-amz-meta-encryption-manifest",
		"x-amz-meta-enc-iv-deriv",
		"x-amz-meta-enc-legacy-no-aad",
		// Original content length (set by gateway)
		"x-amz-meta-original-content-length",
	}
	for _, ek := range encryptionKeys {
		if key == ek {
			return true
		}
	}
	return false
}

func decryptedSizeForMPU(metadata map[string]string) int64 {
	if metadata == nil {
		return 0
	}
	// Prefer the canonical key written by the crypto engine.
	if sizeStr, ok := metadata[crypto.MetaOriginalSize]; ok && sizeStr != "" {
		if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil && size >= 0 {
			return size
		}
	}
	// Fall back to the legacy key for objects written before this cleanup.
	if sizeStr, ok := metadata["x-amz-meta-original-content-length"]; ok && sizeStr != "" {
		if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil && size >= 0 {
			return size
		}
	}
	return 0
}

// filterS3Metadata filters out standard HTTP headers from metadata map.
// S3 metadata should only contain x-amz-meta-* headers, not standard headers
// like Content-Length, Content-Type, ETag, etc. which some S3 providers reject.
// Additionally filters out any keys specified in filterKeys for backend compatibility.
func filterS3Metadata(metadata map[string]string, filterKeys []string) map[string]string {
	s3Metadata := make(map[string]string)

	// Create a set of keys to filter out for efficient lookup
	filterSet := make(map[string]bool)
	if filterKeys != nil {
		for _, key := range filterKeys {
			filterSet[key] = true
		}
	}
	for k, v := range metadata {
		// Only include x-amz-meta-* headers as S3 metadata

		// Skip keys that should be filtered out for backend compatibility
		if filterSet[k] {
			continue
		}
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			s3Metadata[k] = v
		} else if !isStandardMetadata(k) {
			// Include non-standard headers that aren't standard HTTP headers
			// (though typically only x-amz-meta-* should be here)
			s3Metadata[k] = v
		}
		// Explicitly exclude standard headers: Content-Length, Content-Type, ETag, etc.
	}
	return s3Metadata
}

// handleListObjects handles list objects requests.
func (h *Handler) handleListObjects(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "GET", start)
		return
	}

	prefix := r.URL.Query().Get("prefix")
	delimiter := r.URL.Query().Get("delimiter")
	continuationToken := r.URL.Query().Get("continuation-token")
	marker := r.URL.Query().Get("marker")
	maxKeys := int32(1000) // Default
	if mk := r.URL.Query().Get("max-keys"); mk != "" {
		if v, err := strconv.ParseInt(mk, 10, 32); err == nil {
			maxKeys = int32(v)
		}
	}

	opts := s3.ListOptions{
		Delimiter:         delimiter,
		ContinuationToken: continuationToken,
		StartAfter:        marker,
		MaxKeys:           maxKeys,
	}

	listResult, err := s3Client.ListObjects(ctx, bucket, prefix, opts)
	if err != nil {
		s3Err := TranslateError(err, bucket, "")
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"prefix": prefix,
		}).Error("Failed to list objects")
		h.metrics.RecordS3Error(r.Context(), "ListObjects", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// NOTE: ListObjects returns backend (ciphertext) sizes and ETags.
	// Per-object HEAD translation was removed because it caused an
	// N-fold latency explosion (one HEAD per listed object).
	// Accurate plaintext size and ETag are available via HeadObject
	// and GetObject, which decrypt the metadata on a per-object basis.
	// See docs/limitations.md (or README) for details.

	// Compute NextMarker for S3 API v1 clients.  When the response is
	// truncated, v1 clients need a key name to send as the next marker.
	// (v2 clients use the opaque NextContinuationToken instead.)
	nextMarker := ""
	if listResult.IsTruncated && len(listResult.Objects) > 0 {
		nextMarker = listResult.Objects[len(listResult.Objects)-1].Key
	}

	// Generate proper S3 ListBucketResult XML response
	xmlResponse := generateListObjectsXML(bucket, prefix, delimiter, listResult.Objects, listResult.CommonPrefixes, listResult.NextContinuationToken, nextMarker, listResult.IsTruncated, int(maxKeys))

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(xmlResponse))

	h.metrics.RecordS3Operation(r.Context(), "ListObjects", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), int64(len(xmlResponse)))
}

// handleHeadBucket handles HEAD bucket requests.
func (h *Handler) handleHeadBucket(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "HEAD", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "HEAD", start)
		return
	}

	// Use a minimal list request as a backend existence/accessibility check.
	_, err = s3Client.ListObjects(r.Context(), bucket, "", s3.ListOptions{MaxKeys: 1})
	if err != nil {
		s3Err := TranslateError(err, bucket, "")
		s3Err.WriteXML(w)
		// Log err here: TranslateError no longer echoes err into the response
		// body, so this is the only place the underlying diagnostic is
		// recorded for this code path.
		h.logger.WithError(err).WithField("bucket", bucket).Error("Failed to head bucket")
		h.metrics.RecordS3Error(r.Context(), "HeadBucket", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "HEAD", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation(r.Context(), "HeadBucket", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "HEAD", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleCreateBucket handles PUT bucket requests (bucket creation).
func (h *Handler) handleCreateBucket(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
	}).Debug("Handling bucket creation request")

	// Check if we should return BucketAlreadyExists or NotImplemented
	if h.config != nil && h.config.ProxiedBucket != "" {
		// Gateway is configured to proxy a specific bucket
		if h.config.ProxiedBucket == bucket {
			// This is the specific bucket the gateway manages
			h.logger.WithFields(logrus.Fields{
				"bucket":        bucket,
				"proxiedBucket": h.config.ProxiedBucket,
			}).Debug("Bucket matches configured proxied bucket - returning BucketAlreadyExists")

			s3Err := &S3Error{
				Code:       "BucketAlreadyExists",
				Message:    "The requested bucket name is not available. The bucket already exists.",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusConflict,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		} else {
			// Gateway is configured for a different bucket
			h.logger.WithFields(logrus.Fields{
				"bucket":        bucket,
				"proxiedBucket": h.config.ProxiedBucket,
			}).Debug("Bucket does not match configured proxied bucket - returning NotImplemented")

			s3Err := &S3Error{
				Code:       "NotImplemented",
				Message:    "Bucket creation is not supported for this bucket.",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusNotImplemented,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
	}

	// Gateway is not configured for a specific bucket (proxies all buckets)
	// Check if the bucket actually exists in the backend
	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
	}).Debug("Checking if bucket exists in backend")

	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
		}).Error("Failed to get S3 client to check bucket existence")

		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to check bucket existence.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Try to list objects in the bucket to check if it exists
	// Use a limit of 1 to minimize data transfer
	opts := s3.ListOptions{
		MaxKeys: 1,
	}
	_, err = s3Client.ListObjects(r.Context(), bucket, "", opts)
	if err != nil {
		// If listing fails, assume bucket doesn't exist and return NotImplemented
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
		}).Debug("Bucket does not exist or is not accessible - returning NotImplemented")

		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Bucket creation is not supported.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Bucket exists, return BucketAlreadyExists
	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
	}).Debug("Bucket exists in backend - returning BucketAlreadyExists")

	s3Err := &S3Error{
		Code:       "BucketAlreadyExists",
		Message:    "The requested bucket name is not available. The bucket already exists.",
		Resource:   r.URL.Path,
		HTTPStatus: http.StatusConflict,
	}
	s3Err.WriteXML(w)
	h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
}

// applyRangeRequest applies a Range header request to data.
func applyRangeRequest(data []byte, rangeHeader string) ([]byte, error) {
	// Parse Range header: "bytes=start-end" or "bytes=start-" or "bytes=-suffix"
	if len(rangeHeader) < 6 || rangeHeader[:6] != "bytes=" {
		return nil, fmt.Errorf("invalid range header format")
	}

	rangeSpec := rangeHeader[6:]
	dataLen := int64(len(data))

	var start, end int64
	if rangeSpec[0] == '-' {
		// Suffix range: "-suffix" means last N bytes
		suffix, err := strconv.ParseInt(rangeSpec[1:], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid suffix range: %w", err)
		}
		start = dataLen - suffix
		if start < 0 {
			start = 0
		}
		end = dataLen - 1
	} else {
		// Range: "start-end" or "start-"
		if strings.Contains(rangeSpec, "-") {
			parts := strings.Split(rangeSpec, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid range format")
			}
			var err error
			start, err = strconv.ParseInt(parts[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid start: %w", err)
			}
			if parts[1] == "" {
				end = dataLen - 1
			} else {
				end, err = strconv.ParseInt(parts[1], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("invalid end: %w", err)
				}
			}
		} else {
			return nil, fmt.Errorf("invalid range format")
		}
	}

	// Validate and saturate range.
	// S3 returns the available bytes when end exceeds the object size
	// (RFC 7233 §4.2).  An out-of-range start is still rejected.
	if start < 0 || start >= dataLen {
		return nil, fmt.Errorf("range not satisfiable: %d-%d (size: %d)", start, end, dataLen)
	}
	if end >= dataLen {
		end = dataLen - 1
	}
	if end < start {
		return nil, fmt.Errorf("range not satisfiable: %d-%d (size: %d)", start, end, dataLen)
	}

	return data[start : end+1], nil
}

// generateListObjectsXML generates S3-compatible ListBucketResult XML.
// maxKeys must be the requested page limit (not the number of returned
// objects) so that <MaxKeys> matches the S3 API contract.
func generateListObjectsXML(bucket, prefix, delimiter string, objects []s3.ObjectInfo, commonPrefixes []string, nextContinuationToken string, nextMarker string, isTruncated bool, maxKeys int) string {
	type xmlContents struct {
		Key          string `xml:"Key"`
		LastModified string `xml:"LastModified"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
		StorageClass string `xml:"StorageClass"`
	}
	type xmlCommonPrefix struct {
		Prefix string `xml:"Prefix"`
	}
	type listBucketResult struct {
		XMLName               xml.Name          `xml:"ListBucketResult"`
		Xmlns                 string            `xml:"xmlns,attr"`
		Name                  string            `xml:"Name"`
		Prefix                string            `xml:"Prefix,omitempty"`
		Delimiter             string            `xml:"Delimiter,omitempty"`
		MaxKeys               int               `xml:"MaxKeys"`
		IsTruncated           bool              `xml:"IsTruncated"`
		NextContinuationToken string            `xml:"NextContinuationToken,omitempty"`
		NextMarker            string            `xml:"NextMarker,omitempty"`
		Contents              []xmlContents     `xml:"Contents"`
		CommonPrefixes        []xmlCommonPrefix `xml:"CommonPrefixes"`
	}

	result := listBucketResult{
		Xmlns:                 "http://s3.amazonaws.com/doc/2006-03-01/",
		Name:                  bucket,
		Prefix:                prefix,
		Delimiter:             delimiter,
		MaxKeys:               maxKeys,
		IsTruncated:           isTruncated,
		NextContinuationToken: nextContinuationToken,
		NextMarker:            nextMarker,
	}

	for _, obj := range objects {
		result.Contents = append(result.Contents, xmlContents{
			Key:          obj.Key,
			LastModified: obj.LastModified,
			ETag:         obj.ETag,
			Size:         obj.Size,
			StorageClass: "STANDARD",
		})
	}

	for _, cp := range commonPrefixes {
		result.CommonPrefixes = append(result.CommonPrefixes, xmlCommonPrefix{Prefix: cp})
	}

	out, err := xml.Marshal(result)
	if err != nil {
		// Fallback: return a minimal valid error response; this should never happen
		// since all fields are basic strings/numbers with no unrepresentable types.
		return `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></ListBucketResult>`
	}
	return xml.Header + string(out)
}

// handleCreateMultipartUpload handles multipart upload initiation.
func (h *Handler) handleCreateMultipartUpload(w http.ResponseWriter, r *http.Request) {
	// Multipart uploads are now supported with chunked encryption
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]

	if bucket == "" || key == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Check if multipart uploads are disabled
	if h.config != nil && h.config.Server.DisableMultipartUploads {
		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Multipart uploads are disabled to ensure all data is encrypted. Use single-part uploads instead.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Fail closed if policy requires encrypted MPU but infra is missing.
	if h.mpuGuardMisconfig(w, r, bucket, "POST", start) {
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "POST", start)
		return
	}

	// Extract metadata from headers
	metadata := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			// Only include x-amz-meta-* headers as S3 metadata.
			// Standard headers should not be sent as metadata.
			// Case-insensitive match because Go canonicalises headers.
			if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
				metadata[strings.ToLower(k)] = v[0]
			}
		}
	}

	// Extract canned ACL header (x-amz-acl) and fine-grained grant headers
	// for CreateMultipartUpload. Forward verbatim to the backend.
	cannedACL := r.Header.Get("x-amz-acl")
	grantFullControl := r.Header.Get("x-amz-grant-full-control")
	grantRead := r.Header.Get("x-amz-grant-read")
	grantReadACP := r.Header.Get("x-amz-grant-read-acp")
	grantWriteACP := r.Header.Get("x-amz-grant-write-acp")

	// If encrypted MPU is enabled, pre-set markers in metadata so the final
	// object automatically carries the manifest pointer (metadata is frozen at
	// CreateMultipartUpload time on most S3 backends).
	if h.bucketEncryptsMPU(bucket) {
		metadata[crypto.MetaMPUEncrypted] = "true"
		metadata[crypto.MetaFallbackMode] = "mpu"
		metadata[crypto.MetaFallbackPointer] = key + ".mpu-manifest"
	}

	uploadID, err := s3Client.CreateMultipartUpload(ctx, bucket, key, metadata, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to create multipart upload")
		h.metrics.RecordS3Error(r.Context(), "CreateMultipartUpload", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// When EncryptMultipartUploads is enabled for this bucket, generate a
	// per-upload DEK and persist state to Valkey before returning to the client.
	if h.bucketEncryptsMPU(bucket) {
		opStart := time.Now()
		storeErr := h.initMPUEncryptionState(ctx, uploadID, bucket, key)
		if storeErr != nil {
			h.metrics.RecordMPUStateStoreOp("Create", "error", time.Since(opStart))
		} else {
			h.metrics.RecordMPUStateStoreOp("Create", "success", time.Since(opStart))
		}

		if storeErr != nil {
			// Roll back the backend upload that was already created.
			_ = s3Client.AbortMultipartUpload(ctx, bucket, key, uploadID)
			h.metrics.RecordMPUEncrypted("failed")
			h.logger.WithError(storeErr).WithFields(logrus.Fields{
				"bucket":   bucket,
				"key":      key,
				"uploadID": uploadID,
			}).Error("Failed to initialise MPU encryption state; backend upload aborted")
			s3Err := &S3Error{
				Code:       "ServiceUnavailable",
				Message:    "Multipart encryption state store unavailable",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusServiceUnavailable,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}

		h.metrics.RecordMPUEncrypted("success")
		if h.auditLogger != nil {
			h.auditLogger.Log(&audit.AuditEvent{
				EventType: audit.EventTypeMPUCreate,
				Timestamp: time.Now().UTC(),
				Bucket:    bucket,
				Key:       key,
				Success:   true,
				Metadata:  map[string]interface{}{"upload_id": uploadID},
			})
		}
	} else {
		h.metrics.RecordMPUEncrypted("plaintext")
	}

	// Return XML response with upload ID
	type InitiateMultipartUploadResult struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadId string   `xml:"UploadId"`
	}

	result := InitiateMultipartUploadResult{
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation(r.Context(), "CreateMultipartUpload", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// initMPUEncryptionState generates a DEK + IV prefix and persists UploadState
// to Valkey. Called only when BucketEncryptsMultipart(bucket)==true.
func (h *Handler) initMPUEncryptionState(ctx context.Context, uploadID, bucket, key string) error {
	// Generate 32-byte DEK.
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		return fmt.Errorf("failed to generate DEK: %w", err)
	}
	defer zeroBytes(dek)

	// Generate 12-byte IV prefix.
	var ivPrefix [12]byte
	if _, err := rand.Read(ivPrefix[:]); err != nil {
		return fmt.Errorf("failed to generate IV prefix: %w", err)
	}

	// A KeyManager is mandatory for encrypted MPU — bucketEncryptsMPU already
	// enforces this, but guard again here so a future refactor cannot bypass it
	// and silently store plaintext key material.
	if h.keyManager == nil {
		return fmt.Errorf("encrypted multipart uploads require a KeyManager; none is configured")
	}

	envelope, err := h.keyManager.WrapKey(ctx, dek, map[string]string{
		"bucket":   bucket,
		"key":      key,
		"uploadId": uploadID,
	})
	if err != nil {
		return fmt.Errorf("failed to wrap DEK: %w", err)
	}
	envJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to marshal key envelope: %w", err)
	}
	wrappedDEK := string(envJSON)
	kmsKeyID := envelope.KeyID
	kmsProvider := envelope.Provider
	kmsKeyVersion := envelope.KeyVersion

	algorithm := h.encryptionEngine.PreferredAlgorithm()
	if algorithm == "" {
		algorithm = crypto.AlgorithmAES256GCM
	}
	state := &mpu.UploadState{
		UploadID:       uploadID,
		Bucket:         bucket,
		Key:            key,
		UploadIDHash:   mpu.UploadIDHashB64(uploadID),
		WrappedDEK:     wrappedDEK,
		IVPrefixHex:    hex.EncodeToString(ivPrefix[:]),
		Algorithm:      algorithm,
		ChunkSize:      crypto.DefaultChunkSize,
		KMSKeyID:       kmsKeyID,
		KMSProvider:    kmsProvider,
		KMSKeyVersion:  kmsKeyVersion,
		PolicySnapshot: mpu.PolicySnapshot{EncryptMultipartUploads: true},
		CreatedAt:      time.Now().UTC(),
	}
	return h.mpuStateStore.Create(ctx, state)
}

// zeroBytes overwrites b with zeros.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// isNetworkError reports whether err is a client-side network error
// (timeout, connection reset, broken pipe) rather than a decryption or
// authentication failure.
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	// syscall-level connection errors.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	// net.OpError (includes TCP write/read timeouts).
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() || opErr.Temporary() {
			return true
		}
	}
	return false
}

// copyWithDeadlineRefresh wraps io.Copy and, when timeout > 0, extends the
// HTTP write deadline every timeout/2 interval while the copy is active.
// This prevents a fixed Server.WriteTimeout from killing long-running S3
// object streams.
func copyWithDeadlineRefresh(w http.ResponseWriter, src io.Reader, timeout time.Duration) (int64, error) {
	if timeout <= 0 {
		return io.Copy(w, src)
	}
	rc := http.NewResponseController(w)
	// Pre-flight: ensure the controller supports write deadlines.
	if err := rc.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		// Fallback: the underlying writer doesn't support deadline control.
		return io.Copy(w, src)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(timeout / 2)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rc.SetWriteDeadline(time.Now().Add(timeout))
			case <-done:
				return
			}
		}
	}()
	return io.Copy(w, src)
}

// CompleteMultipartUpload represents the XML structure for completing multipart uploads.
type CompleteMultipartUpload struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []struct {
		XMLName    xml.Name `xml:"Part"`
		PartNumber int32    `xml:"PartNumber"`
		ETag       string   `xml:"ETag"`
	} `xml:"Part"`
}

// parseCompleteMultipartUploadXML parses the CompleteMultipartUpload XML with security limits.
// It enforces size limits, validates part numbers and ETags, and provides clear error messages.
func (h *Handler) parseCompleteMultipartUploadXML(reader io.Reader) (*CompleteMultipartUpload, error) {

	// Read the entire request body with size limit to prevent DoS
	const maxXMLSize = 10 * 1024 * 1024 // 10MB limit for XML payload
	bodyBytes, err := io.ReadAll(io.LimitReader(reader, maxXMLSize))
	if err != nil {
		return nil, &S3Error{
			Code:       "InvalidRequest",
			Message:    "Failed to read request body",
			HTTPStatus: http.StatusBadRequest,
		}
	}

	// Check if we hit the size limit
	if len(bodyBytes) >= maxXMLSize {
		return nil, &S3Error{
			Code:       "InvalidRequest",
			Message:    "Request body too large",
			HTTPStatus: http.StatusRequestEntityTooLarge,
		}
	}

	// Parse XML with custom decoder that enforces limits
	decoder := xml.NewDecoder(bytes.NewReader(bodyBytes))

	// Set XML parsing limits
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		return nil, fmt.Errorf("charset reader not supported")
	}

	var completeReq CompleteMultipartUpload
	if err := decoder.Decode(&completeReq); err != nil {
		h.logger.WithError(err).Debug("XML parsing failed")
		return nil, &S3Error{
			Code:       "MalformedXML",
			Message:    "The XML you provided was not well-formed or did not validate against our published schema",
			HTTPStatus: http.StatusBadRequest,
		}
	}

	// Validate the parsed data
	if err := h.validateCompleteMultipartUploadRequest(&completeReq); err != nil {
		return nil, err
	}

	return &completeReq, nil
}

// validateCompleteMultipartUploadRequest validates the CompleteMultipartUpload request data.
func (h *Handler) validateCompleteMultipartUploadRequest(req *CompleteMultipartUpload) error {
	// Check for empty parts list
	if len(req.Parts) == 0 {
		return &S3Error{
			Code:       "InvalidArgument",
			Message:    "At least one part must be specified",
			HTTPStatus: http.StatusBadRequest,
		}
	}

	// Check for too many parts (AWS limit is 10,000 parts)
	const maxParts = 10000
	if len(req.Parts) > maxParts {
		return &S3Error{
			Code:       "InvalidArgument",
			Message:    fmt.Sprintf("Too many parts specified (maximum %d)", maxParts),
			HTTPStatus: http.StatusBadRequest,
		}
	}

	// Track seen part numbers to detect duplicates
	seenParts := make(map[int32]bool)
	var lastPartNumber int32 = -1

	for i, part := range req.Parts {
		// Validate part number
		if part.PartNumber < 1 || part.PartNumber > 10000 {
			return &S3Error{
				Code:       "InvalidArgument",
				Message:    fmt.Sprintf("Part number must be between 1 and 10000, got %d", part.PartNumber),
				HTTPStatus: http.StatusBadRequest,
			}
		}

		// Check for duplicate part numbers
		if seenParts[part.PartNumber] {
			return &S3Error{
				Code:       "InvalidArgument",
				Message:    fmt.Sprintf("Duplicate part number: %d", part.PartNumber),
				HTTPStatus: http.StatusBadRequest,
			}
		}
		seenParts[part.PartNumber] = true

		// Validate ETag format (should be quoted)
		if !isValidETag(part.ETag) {
			return &S3Error{
				Code:       "InvalidArgument",
				Message:    fmt.Sprintf("Invalid ETag format for part %d: %s", part.PartNumber, part.ETag),
				HTTPStatus: http.StatusBadRequest,
			}
		}

		// Check if parts are in ascending order (AWS requires this)
		if i > 0 && part.PartNumber < lastPartNumber {
			h.logger.WithFields(logrus.Fields{
				"part_number": part.PartNumber,
				"last_part":   lastPartNumber,
			}).Warn("Parts not in ascending order - AWS requires ascending part numbers")
		}
		lastPartNumber = part.PartNumber
	}

	return nil
}

// isValidETag validates ETag format (should be quoted and contain valid characters).
func isValidETag(etag string) bool {
	if len(etag) < 2 || !strings.HasPrefix(etag, "\"") || !strings.HasSuffix(etag, "\"") {
		return false
	}

	// Basic validation: should contain only hex digits, dashes, and quotes
	inner := etag[1 : len(etag)-1]
	for _, r := range inner {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || r == '-') {
			return false
		}
	}

	return len(inner) > 0
}

// handleUploadPart handles uploading a part in a multipart upload.
func (h *Handler) handleUploadPart(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]
	partNumberStr := vars["partNumber"]

	if bucket == "" || key == "" || uploadID == "" || partNumberStr == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Route UploadPartCopy to its own handler
	if r.Header.Get("x-amz-copy-source") != "" {
		h.handleUploadPartCopy(w, r)
		return
	}

	// Check if multipart uploads are disabled
	if h.config != nil && h.config.Server.DisableMultipartUploads {
		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Multipart uploads are disabled to ensure all data is encrypted. Use single-part uploads instead.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Fail closed if policy requires encrypted MPU but infra is missing.
	if h.mpuGuardMisconfig(w, r, bucket, "PUT", start) {
		return
	}

	partNumber, err := strconv.ParseInt(partNumberStr, 10, 32)
	if err != nil || partNumber < 1 {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Invalid part number",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	// Default: no encryption layer added here (plaintext parts per ADR 0002, or
	// encrypted per-upload DEK below when the upload has a Valkey state record).
	var encryptedReader io.Reader = r.Body
	var contentLengthPtr *int64
	// encMPUState is non-nil only for encrypted MPU parts; used after UploadPart
	// to record the PartRecord without a second Valkey round-trip.
	var encMPUState *mpu.UploadState
	var encMPUPlainLen int64
	var encMPUEncryptDuration time.Duration

	if uploadState, isEnc, stateErr := h.uploadStateEncrypted(ctx, uploadID); stateErr != nil {
		// Transient Valkey failure mid-upload — do NOT downgrade to plaintext.
		// The upload may be an encrypted MPU whose state we temporarily can't
		// read; proceeding plaintext would write unencrypted bytes under the
		// client's encrypted multipart upload (silent security degradation).
		h.logger.WithError(stateErr).WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadID":   uploadID,
			"partNumber": partNumber,
		}).Error("mpu.state.unavailable: cannot determine upload encryption status; failing closed")
		h.metrics.RecordS3Error(r.Context(), "UploadPart", bucket, "StateUnavailable")
		if h.auditLogger != nil {
			h.auditLogger.Log(&audit.AuditEvent{
				EventType: audit.EventTypeMPUValkeyUnavail,
				Timestamp: time.Now().UTC(),
				Bucket:    bucket,
				Key:       key,
				Success:   false,
				Metadata:  map[string]interface{}{"upload_id": uploadID, "status": "valkey_unavailable"},
			})
		}
		s3Err := &S3Error{
			Code:       "ServiceUnavailable",
			Message:    "Multipart encryption state store unavailable; retry the part upload",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusServiceUnavailable,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	} else if isEnc {
		// Encrypted multipart path — decision based on PolicySnapshot stored at
		// CreateMultipartUpload, not live policy (ADR-0009 §Security Considerations).
		// Determine the plaintext length for encryption metadata.
		// Handle STREAMING-* (AWS chunked encoding) by checking x-amz-decoded-content-length.
		var plainLen int64
		if decodedLen := r.Header.Get("x-amz-decoded-content-length"); decodedLen != "" {
			if v, e := strconv.ParseInt(decodedLen, 10, 64); e == nil && v >= 0 {
				plainLen = v
			}
		} else if r.ContentLength >= 0 {
			plainLen = r.ContentLength
		}

		// Pass the pre-fetched state to avoid a second Valkey round-trip inside encryptMPUPart.
		encryptStart := time.Now()
		encReader, encLen, err := h.encryptMPUPartWithState(ctx, bucket, uploadID, int32(partNumber), r.Body, plainLen, uploadState)
		encMPUEncryptDuration = time.Since(encryptStart)
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket":     bucket,
				"key":        key,
				"uploadID":   uploadID,
				"partNumber": partNumber,
			}).Error("Failed to encrypt MPU part")
			s3Err := &S3Error{
				Code:       "InternalError",
				Message:    "Failed to encrypt multipart upload part",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		// V0.6-PERF-1 Phase D: use a pooled seekable wrapper bounded by
		// MaxPartBuffer instead of io.ReadAll. This satisfies the AWS SDK V2
		// SigV4 seekable-body requirement while capping heap per part.
		maxBuf := effectiveMaxPartBuffer(h.config)
		sb, sbErr := s3.NewSeekableBody(encReader, maxBuf)
		if sbErr != nil {
			h.logger.WithError(sbErr).WithFields(logrus.Fields{
				"bucket":     bucket,
				"key":        key,
				"uploadID":   uploadID,
				"partNumber": partNumber,
			}).Error("Failed to buffer encrypted MPU part")
			code := "InternalError"
			status := http.StatusInternalServerError
			msg := "Failed to prepare multipart upload part"
			if _, isLarge := sbErr.(*s3.ErrPartTooLarge); isLarge {
				code = "EntityTooLarge"
				status = http.StatusRequestEntityTooLarge
				msg = sbErr.Error()
			}
			s3Err := &S3Error{Code: code, Message: msg, Resource: r.URL.Path, HTTPStatus: status}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		if sb.Len != encLen {
			h.logger.WithFields(logrus.Fields{
				"bucket":       bucket,
				"key":          key,
				"uploadID":     uploadID,
				"partNumber":   partNumber,
				"expected_len": encLen,
				"actual_len":   sb.Len,
			}).Error("Encrypted MPU part length mismatch")
			s3Err := &S3Error{
				Code:       "InternalError",
				Message:    "Failed to prepare multipart upload part",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		encryptedReader = sb
		contentLengthPtr = &encLen
		// Hoist state into outer scope so AppendPart can use it without a
		// second Valkey round-trip after UploadPart succeeds.
		encMPUState = uploadState
		encMPUPlainLen = plainLen
	} else {
		// Plaintext multipart path (ADR 0002): buffer to make body seekable for
		// the AWS SDK's retry behaviour.
		// V0.6-PERF-1 Phase D: use pooled seekable wrapper instead of io.ReadAll.
		maxBuf := effectiveMaxPartBuffer(h.config)
		sb, sbErr := s3.NewSeekableBody(r.Body, maxBuf)
		if sbErr != nil {
			h.logger.WithError(sbErr).Error("Failed to read multipart upload part")
			code := "InternalError"
			status := http.StatusInternalServerError
			msg := "Failed to read part data"
			if _, isLarge := sbErr.(*s3.ErrPartTooLarge); isLarge {
				code = "EntityTooLarge"
				status = http.StatusRequestEntityTooLarge
				msg = sbErr.Error()
			}
			s3Err := &S3Error{Code: code, Message: msg, Resource: r.URL.Path, HTTPStatus: status}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		encryptedReader = sb
		partSize := sb.Len
		contentLengthPtr = &partSize
	}

	etag, err := s3Client.UploadPart(ctx, bucket, key, uploadID, int32(partNumber), encryptedReader, contentLengthPtr)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadID":   uploadID,
			"partNumber": partNumber,
		}).Error("Failed to upload part")
		h.metrics.RecordS3Error(r.Context(), "UploadPart", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// After a successful UploadPart on an encrypted MPU, record the part metadata
	// in Valkey. encMPUState is non-nil only for the encrypted path; it was
	// populated inside the else-if branch above to avoid a second Valkey Get.
	//
	// Failure here is NOT silently swallowed: the backend part has been written
	// but the state record is absent, so a subsequent CompleteMultipartUpload
	// would produce a manifest with a missing part and fail. We must return 500
	// so the client retries (which idempotently overwrites the backend part) or
	// aborts the upload. Returning 200 here would be a silent data-loss path.
	if encMPUState != nil && contentLengthPtr != nil {
		chunkCount := int32((encMPUPlainLen + int64(crypto.DefaultChunkSize) - 1) / int64(crypto.DefaultChunkSize)) // #nosec G115 — max ~82k for 5 GiB parts, well within int32
		pr := mpu.PartRecord{
			PartNumber: int32(partNumber),
			ETag:       etag,
			PlainLen:   encMPUPlainLen,
			EncLen:     *contentLengthPtr,
			ChunkCount: chunkCount,
		}
		opStart := time.Now()
		appendErr := h.mpuStateStore.AppendPart(ctx, uploadID, pr)
		if appendErr != nil {
			h.metrics.RecordMPUStateStoreOp("AppendPart", "error", time.Since(opStart))
			h.metrics.RecordMPUPart("failed")
		} else {
			h.metrics.RecordMPUStateStoreOp("AppendPart", "success", time.Since(opStart))
			h.metrics.RecordMPUPart("success")
			h.metrics.RecordEncryptionOperation(r.Context(), "encrypt", encMPUEncryptDuration, encMPUPlainLen)
			if h.auditLogger != nil {
				h.auditLogger.Log(&audit.AuditEvent{
					EventType: audit.EventTypeMPUPart,
					Timestamp: time.Now().UTC(),
					Bucket:    bucket,
					Key:       key,
					Success:   true,
					Metadata:  map[string]interface{}{"upload_id": uploadID},
				})
			}
		}

		if appendErr != nil {
			h.logger.WithError(appendErr).WithFields(logrus.Fields{
				"bucket":     bucket,
				"key":        key,
				"uploadID":   uploadID,
				"partNumber": partNumber,
			}).Error("mpu.append_part.failure: backend part written but state not recorded; returning 500 so client retries")
			h.metrics.RecordS3Error(r.Context(), "AppendMPUPartState", bucket, "StateUnavailable")
			if h.auditLogger != nil {
				h.auditLogger.Log(&audit.AuditEvent{
					EventType: audit.EventTypeMPUValkeyUnavail,
					Timestamp: time.Now().UTC(),
					Bucket:    bucket,
					Key:       key,
					Success:   false,
					Metadata:  map[string]interface{}{"upload_id": uploadID},
				})
			}
			s3Err := &S3Error{
				Code:       "ServiceUnavailable",
				Message:    "Multipart encryption state store unavailable; retry the part upload",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusServiceUnavailable,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
	}

	w.Header().Set("ETag", etag)
	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation(r.Context(), "UploadPart", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleCompleteMultipartUpload handles completing a multipart upload.
func (h *Handler) handleCompleteMultipartUpload(w http.ResponseWriter, r *http.Request) {
	// Multipart uploads are now supported with chunked encryption
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]

	if bucket == "" || key == "" || uploadID == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Check if multipart uploads are disabled
	if h.config != nil && h.config.Server.DisableMultipartUploads {
		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Multipart uploads are disabled to ensure all data is encrypted. Use single-part uploads instead.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Fail closed if policy requires encrypted MPU but infra is missing.
	if h.mpuGuardMisconfig(w, r, bucket, "POST", start) {
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "POST", start)
		return
	}

	// Parse multipart upload completion XML with security limits
	completeReq, err := h.parseCompleteMultipartUploadXML(r.Body)
	if err != nil {
		var s3Err *S3Error
		if s3e, ok := err.(*S3Error); ok {
			s3Err = s3e
			s3Err.Resource = r.URL.Path
		} else {
			s3Err = &S3Error{
				Code:       "MalformedXML",
				Message:    "The XML you provided was not well-formed or did not validate against our published schema",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadRequest,
			}
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Convert to CompletedPart slice
	parts := make([]s3.CompletedPart, len(completeReq.Parts))
	for i, p := range completeReq.Parts {
		parts[i] = s3.CompletedPart{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
		}
	}

	lockInput, s3Err := extractObjectLockInput(r)
	if s3Err != nil {
		s3Err.WriteXML(w)
		return
	}

	// For encrypted MPU: consult the PolicySnapshot stored at Create time so
	// a policy flip mid-upload cannot cause the manifest to be skipped or
	// written for an upload that was never encrypted (ADR-0009).
	_, completeIsEnc, completeStateErr := h.uploadStateEncrypted(ctx, uploadID)
	if completeStateErr != nil {
		h.logger.WithError(completeStateErr).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("mpu.state.unavailable: cannot determine encryption state at Complete; failing closed")
		h.metrics.RecordS3Error(r.Context(), "CompleteMultipartUpload", bucket, "StateUnavailable")
		if h.auditLogger != nil {
			h.auditLogger.Log(&audit.AuditEvent{
				EventType: audit.EventTypeMPUValkeyUnavail,
				Timestamp: time.Now().UTC(),
				Bucket:    bucket,
				Key:       key,
				Success:   false,
				Metadata:  map[string]interface{}{"upload_id": uploadID, "status": "valkey_unavailable"},
			})
		}
		s3Err := &S3Error{
			Code:       "ServiceUnavailable",
			Message:    "Multipart encryption state store unavailable; retry the Complete call",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusServiceUnavailable,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	if completeIsEnc {
		if manifestErr := h.writeMPUManifestObject(ctx, uploadID, bucket, key, s3Client); manifestErr != nil {
			h.logger.WithError(manifestErr).WithFields(logrus.Fields{
				"bucket":   bucket,
				"key":      key,
				"uploadID": uploadID,
			}).Error("Failed to write MPU manifest companion object")
			s3Err := &S3Error{
				Code:       "InternalError",
				Message:    "Failed to write multipart encryption manifest",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}

		if h.auditLogger != nil {
			h.auditLogger.Log(&audit.AuditEvent{
				EventType: audit.EventTypeMPUComplete,
				Timestamp: time.Now().UTC(),
				Bucket:    bucket,
				Key:       key,
				Success:   true,
				Metadata:  map[string]interface{}{"upload_id": uploadID},
			})
		}
	}

	etag, err := s3Client.CompleteMultipartUpload(ctx, bucket, key, uploadID, parts, lockInput)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to complete multipart upload")
		h.metrics.RecordS3Error(r.Context(), "CompleteMultipartUpload", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Clean up Valkey state after successful completion.
	if completeIsEnc {
		if delErr := h.mpuStateStore.Delete(ctx, uploadID); delErr != nil {
			h.logger.WithError(delErr).WithField("uploadID", uploadID).
				Warn("Failed to delete MPU state after completion")
		}
	}

	// Return XML response
	type CompleteMultipartUploadResult struct {
		XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
		Location string   `xml:"Location"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		ETag     string   `xml:"ETag"`
	}

	result := CompleteMultipartUploadResult{
		Location: fmt.Sprintf("/%s/%s", bucket, key),
		Bucket:   bucket,
		Key:      key,
		ETag:     etag,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation(r.Context(), "CompleteMultipartUpload", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleAbortMultipartUpload handles aborting a multipart upload.
func (h *Handler) handleAbortMultipartUpload(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]

	if bucket == "" || key == "" || uploadID == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Check if multipart uploads are disabled
	if h.config != nil && h.config.Server.DisableMultipartUploads {
		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Multipart uploads are disabled to ensure all data is encrypted.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Fail closed if policy requires encrypted MPU but infra is missing.
	if h.mpuGuardMisconfig(w, r, bucket, "DELETE", start) {
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "DELETE", start)
		return
	}

	err = s3Client.AbortMultipartUpload(ctx, bucket, key, uploadID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to abort multipart upload")
		h.metrics.RecordS3Error(r.Context(), "AbortMultipartUpload", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "DELETE", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Delete Valkey state for encrypted MPU aborts using the PolicySnapshot so
	// a mid-upload policy flip cannot cause the state to be left orphaned.
	// On transient state-store failure we log and rely on TTL expiry to clean
	// up the orphan — backend abort has already succeeded so returning success
	// to the client is correct.
	_, abortIsEnc, abortStateErr := h.uploadStateEncrypted(ctx, uploadID)
	if abortStateErr != nil {
		h.logger.WithError(abortStateErr).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Warn("mpu.abort: state-store unavailable; backend abort succeeded, state will expire via TTL")
	} else if abortIsEnc {
		opStart := time.Now()
		delErr := h.mpuStateStore.Delete(ctx, uploadID)
		if delErr != nil {
			h.metrics.RecordMPUStateStoreOp("Delete", "error", time.Since(opStart))
			h.logger.WithError(delErr).WithFields(logrus.Fields{
				"bucket":   bucket,
				"key":      key,
				"uploadID": uploadID,
			}).Warn("mpu.abort.orphan: failed to delete MPU state after abort")
		} else {
			h.metrics.RecordMPUStateStoreOp("Delete", "success", time.Since(opStart))
		}

		if h.auditLogger != nil {
			h.auditLogger.Log(&audit.AuditEvent{
				EventType: audit.EventTypeMPUAbort,
				Timestamp: time.Now().UTC(),
				Bucket:    bucket,
				Key:       key,
				Success:   true,
				Metadata:  map[string]interface{}{"upload_id": uploadID},
			})
		}
	}

	w.WriteHeader(http.StatusNoContent)
	h.metrics.RecordS3Operation(r.Context(), "AbortMultipartUpload", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "DELETE", r.URL.Path, http.StatusNoContent, time.Since(start), 0)
}

// encryptMPUPart encrypts a single multipart part using the per-upload DEK
// schedule stored in Valkey. Returns an io.Reader of ciphertext and the exact
// encrypted byte count so the S3 SDK can set Content-Length correctly.
// encryptMPUPart fetches upload state from Valkey then encrypts one part.
// Prefer encryptMPUPartWithState when the state has already been fetched to
// avoid a redundant Valkey round-trip.
func (h *Handler) encryptMPUPart(ctx context.Context, bucket, uploadID string, partNumber int32, body io.Reader, plainLen int64) (io.Reader, int64, error) {
	opStart := time.Now()
	state, err := h.mpuStateStore.Get(ctx, uploadID)
	if err != nil {
		h.metrics.RecordMPUStateStoreOp("Get", "error", time.Since(opStart))
		return nil, 0, fmt.Errorf("encryptMPUPart: get state: %w", err)
	}
	h.metrics.RecordMPUStateStoreOp("Get", "success", time.Since(opStart))
	return h.encryptMPUPartWithState(ctx, bucket, uploadID, partNumber, body, plainLen, state)
}

// encryptMPUPartWithState encrypts one MPU part using a pre-fetched UploadState,
// avoiding a redundant Valkey Get when the caller already holds the state.
func (h *Handler) encryptMPUPartWithState(ctx context.Context, bucket, uploadID string, partNumber int32, body io.Reader, plainLen int64, state *mpu.UploadState) (io.Reader, int64, error) {
	ivPrefix, err := mpu.IVPrefixFromHex(state.IVPrefixHex)
	if err != nil {
		return nil, 0, fmt.Errorf("encryptMPUPart: decode iv prefix: %w", err)
	}
	dek, err := h.unwrapMPUDEK(ctx, state, bucket, uploadID)
	if err != nil {
		return nil, 0, fmt.Errorf("encryptMPUPart: unwrap DEK: %w", err)
	}
	defer zeroBytes(dek)

	uploadIDHash := crypto.UploadIDHash(uploadID)
	encReader, encLen, err := crypto.NewMPUPartEncryptReader(ctx, body, dek, uploadIDHash, ivPrefix, partNumber, state.ChunkSize, plainLen, state.Algorithm)
	if err != nil {
		return nil, 0, fmt.Errorf("encryptMPUPart: build encrypter: %w", err)
	}
	return encReader, encLen, nil
}

// serveMPURangedGet handles a ranged GET on an MPU-encrypted object.
// It fetches and decrypts the manifest, maps the plaintext range to the
// minimum backend byte range, fetches only those bytes, decrypts the affected
// chunks, and writes an HTTP 206 Partial Content response.
func (h *Handler) serveMPURangedGet(
	w http.ResponseWriter,
	r *http.Request,
	ctx context.Context,
	bucket, key string,
	versionID *string,
	headMeta map[string]string,
	rangeHeader string,
	s3Client s3.Client,
	start time.Time,
) {
	// ── 1. Fetch and decrypt manifest ────────────────────────────────────────
	manifestKey := headMeta[crypto.MetaFallbackPointer]
	if manifestKey == "" {
		manifestKey = key + ".mpu-manifest"
	}
	manifestReader, manifestMeta, err := s3Client.GetObject(ctx, bucket, manifestKey, nil, nil)
	if err != nil {
		s3Err := TranslateError(err, bucket, manifestKey)
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	defer manifestReader.Close()

	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: get engine")
		(&S3Error{Code: "InternalError", Message: "Failed to load encryption configuration", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}
	manifestPlainReader, _, err := engine.Decrypt(r.Context(), manifestReader, manifestMeta)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: decrypt manifest")
		(&S3Error{Code: "InternalError", Message: "Failed to decrypt manifest", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}
	manifestJSON, err := io.ReadAll(manifestPlainReader)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: read manifest")
		(&S3Error{Code: "InternalError", Message: "Failed to read manifest", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}
	manifest, err := crypto.UnmarshalMultipartManifest(manifestJSON)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: parse manifest")
		(&S3Error{Code: "InternalError", Message: "Invalid manifest", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	// ── 2. Parse plaintext range ─────────────────────────────────────────────
	pStart, pEnd, err := crypto.ParseHTTPRangeHeader(rangeHeader, manifest.TotalPlainSize)
	if err != nil {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", manifest.TotalPlainSize))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusRequestedRangeNotSatisfiable, time.Since(start), 0)
		return
	}

	// ── 3. Map plaintext range → backend ciphertext range ───────────────────
	rangeResult, err := manifest.EncRangeForPlaintextRange(pStart, pEnd)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: calc enc range")
		(&S3Error{Code: "InternalError", Message: "Range calculation failed", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	// ── 4. Fetch only the needed ciphertext bytes ────────────────────────────
	encRangeHdr := fmt.Sprintf("bytes=%d-%d", rangeResult.EncStart, rangeResult.EncEnd)
	objReader, _, err := s3Client.GetObject(ctx, bucket, key, versionID, &encRangeHdr)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	defer objReader.Close()

	ciphertext, err := io.ReadAll(objReader)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: read ciphertext")
		(&S3Error{Code: "InternalError", Message: "Failed to read object", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	// ── 5. Unwrap DEK ────────────────────────────────────────────────────────
	dek, err := h.unwrapMPUDEKFromManifest(ctx, manifest, bucket, key)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: unwrap DEK")
		(&S3Error{Code: "InternalError", Message: "Key unwrap failed", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}
	defer zeroBytes(dek)

	ivPrefix, err := hexToIVPrefix(manifest.IVPrefix)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: decode iv prefix")
		(&S3Error{Code: "InternalError", Message: "Manifest corrupt", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}
	uploadIDHash, err := decodeBase64ToFixed32(manifest.UploadIDHash)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: decode upload id hash")
		(&S3Error{Code: "InternalError", Message: "Manifest corrupt", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
		return
	}

	// ── 6. Decrypt affected chunks ───────────────────────────────────────────
	// ciphertext starts at byte rangeResult.EncStart which is the first byte of
	// chunk rangeResult.ChunkStart in part rangeResult.PartStartIdx.
	// Iterate through affected parts/chunks, consuming precise byte counts.
	const encTagSize = 16
	encChunkSize := manifest.ChunkSize + encTagSize

	var (
		plaintext     []byte
		bytesConsumed int
	)

	for pi := rangeResult.PartStartIdx; pi <= rangeResult.PartEndIdx; pi++ {
		part := manifest.Parts[pi]
		firstChunk := int32(0)
		if pi == rangeResult.PartStartIdx {
			firstChunk = rangeResult.ChunkStart
		}
		lastChunk := part.ChunkCount - 1
		if pi == rangeResult.PartEndIdx {
			lastChunk = rangeResult.ChunkEnd
		}

		// Precise byte count for these chunks within the part.
		var partCipherLen int
		isLastPartOfRange := pi == rangeResult.PartEndIdx
		if isLastPartOfRange && lastChunk == part.ChunkCount-1 {
			// Consuming through the last chunk of this part: use EncLen to get
			// the exact byte count (last chunk may be shorter than ChunkSize).
			partEncStart := int64(firstChunk) * int64(encChunkSize)
			partCipherLen = int(part.EncLen - partEncStart)
		} else {
			partCipherLen = int(lastChunk-firstChunk+1) * encChunkSize
		}

		if bytesConsumed+partCipherLen > len(ciphertext) {
			partCipherLen = len(ciphertext) - bytesConsumed
		}

		partCipher := ciphertext[bytesConsumed : bytesConsumed+partCipherLen]
		plain, err := crypto.DecryptMPUPartRange(partCipher, dek, uploadIDHash, ivPrefix, part.PartNumber, manifest.ChunkSize, firstChunk, manifest.Algorithm)
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket":     bucket,
				"key":        key,
				"part":       part.PartNumber,
				"firstChunk": firstChunk,
			}).Error("serveMPURangedGet: tamper detected")
			h.metrics.RecordEncryptionError(r.Context(), "decrypt", "mpu_tamper_detected")
			if h.auditLogger != nil {
				h.auditLogger.Log(&audit.AuditEvent{
					EventType: audit.EventTypeMPUTamperDetected,
					Timestamp: time.Now().UTC(),
					Bucket:    bucket,
					Key:       key,
					Success:   false,
					Metadata:  map[string]interface{}{"status": "tamper_detected_range"},
				})
			}
			(&S3Error{Code: "InternalError", Message: "Object integrity check failed", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}).WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusInternalServerError, time.Since(start), 0)
			return
		}
		plaintext = append(plaintext, plain...)
		bytesConsumed += partCipherLen
	}

	// ── 7. Slice to exact plaintext range ────────────────────────────────────
	// plaintext starts at the beginning of ChunkStart in PartStartIdx.
	var bufPlainStart int64
	for i := 0; i < rangeResult.PartStartIdx; i++ {
		bufPlainStart += manifest.Parts[i].PlainLen
	}
	bufPlainStart += int64(rangeResult.ChunkStart) * int64(manifest.ChunkSize)

	sliceStart := pStart - bufPlainStart
	sliceEnd := pEnd - bufPlainStart
	if sliceEnd >= int64(len(plaintext)) {
		sliceEnd = int64(len(plaintext)) - 1
	}
	plaintext = plaintext[sliceStart : sliceEnd+1]

	// ── 8. Write HTTP 206 response ───────────────────────────────────────────
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", pStart, pEnd, manifest.TotalPlainSize))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(plaintext)))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusPartialContent)
	written, _ := io.Copy(w, bytes.NewReader(plaintext))
	h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusPartialContent, time.Since(start), written)
}

// writeMPUManifestObject builds the MultipartManifest from Valkey state and
// writes it as a companion object at <key>.mpu-manifest. The final object's
// metadata carries x-amz-meta-encrypted-mpu=true and the pointer set at
// CreateMultipartUpload time.
func (h *Handler) writeMPUManifestObject(ctx context.Context, uploadID, bucket, key string, s3Client s3.Client) error {
	opStart := time.Now()
	state, err := h.mpuStateStore.Get(ctx, uploadID)
	if err != nil {
		h.metrics.RecordMPUStateStoreOp("Get", "error", time.Since(opStart))
		return fmt.Errorf("writeMPUManifest: get state: %w", err)
	}
	h.metrics.RecordMPUStateStoreOp("Get", "success", time.Since(opStart))

	// Sort parts by part number for determinism.
	sortedParts := sortedPartRecords(state.Parts)
	mpuParts := make([]crypto.MPUPartRecord, len(sortedParts))
	var totalPlain int64
	for i, p := range sortedParts {
		mpuParts[i] = crypto.MPUPartRecord{
			PartNumber: p.PartNumber,
			ETag:       p.ETag,
			PlainLen:   p.PlainLen,
			EncLen:     p.EncLen,
			ChunkCount: p.ChunkCount,
		}
		totalPlain += p.PlainLen
	}

	manifest := &crypto.MultipartManifest{
		Version:        1,
		Algorithm:      state.Algorithm,
		ChunkSize:      state.ChunkSize,
		IVPrefix:       state.IVPrefixHex,
		UploadIDHash:   state.UploadIDHash,
		WrappedDEK:     state.WrappedDEK,
		KMSKeyID:       state.KMSKeyID,
		KMSProvider:    state.KMSProvider,
		KMSKeyVersion:  state.KMSKeyVersion,
		Parts:          mpuParts,
		TotalPlainSize: totalPlain,
	}

	manifestJSON, err := manifest.Marshal()
	if err != nil {
		return fmt.Errorf("writeMPUManifest: marshal: %w", err)
	}

	h.metrics.ObserveMPUManifestBytes(len(manifestJSON))
	h.metrics.RecordMPUManifestStorage("fallback")

	// Encrypt the manifest before writing so iv_prefix, part layout, and the
	// wrapped DEK are not exposed in plaintext on the backend.
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		return fmt.Errorf("writeMPUManifest: get engine: %w", err)
	}
	manifestPlainLen := int64(len(manifestJSON))
	encryptStart := time.Now()
	encReader, encMeta, err := engine.Encrypt(ctx, bytes.NewReader(manifestJSON), map[string]string{
		"x-amz-meta-encryption-mpu-manifest": "true",
	})
	encryptDuration := time.Since(encryptStart)
	if err != nil {
		return fmt.Errorf("writeMPUManifest: encrypt manifest: %w", err)
	}
	h.metrics.RecordEncryptionOperation(ctx, "encrypt", encryptDuration, manifestPlainLen)

	// Buffer the encrypted output so we can set Content-Length precisely.
	encBytes, err := io.ReadAll(encReader)
	if err != nil {
		return fmt.Errorf("writeMPUManifest: read encrypted manifest: %w", err)
	}

	companionKey := key + ".mpu-manifest"
	encLen := int64(len(encBytes))
	_, err = s3Client.PutObject(ctx, bucket, companionKey, bytes.NewReader(encBytes), encMeta, &encLen, "", nil, "", "", "", "", "")
	return err
}

// unwrapMPUDEK unwraps the DEK stored in UploadState using the KeyManager.
// Returns an error if the KeyManager is absent — encrypted MPU state must
// never be readable without KMS cooperation (fail-closed).
func (h *Handler) unwrapMPUDEK(ctx context.Context, state *mpu.UploadState, bucket, uploadID string) ([]byte, error) {
	if h.keyManager == nil {
		return nil, fmt.Errorf("cannot decrypt MPU part: no KeyManager configured")
	}
	var env crypto.KeyEnvelope
	if err := json.Unmarshal([]byte(state.WrappedDEK), &env); err != nil {
		return nil, fmt.Errorf("unmarshal key envelope: %w", err)
	}
	return h.keyManager.UnwrapKey(ctx, &env, map[string]string{
		"bucket":   bucket,
		"uploadId": uploadID,
	})
}

// decryptMPUObject fetches and decrypts the manifest companion object, then
// returns a streaming io.Reader that decrypts the MPU ciphertext one AEAD
// chunk at a time. Memory overhead is O(ChunkSize) regardless of object size.
//
// The caller retains ownership of reader and must close it after the returned
// reader is fully consumed (the caller's defer reader.Close() handles this).
func (h *Handler) decryptMPUObject(ctx context.Context, bucket, key string, metadata map[string]string, reader io.ReadCloser, s3Client s3.Client) (io.Reader, error) {
	// Fetch and decrypt the manifest companion object.
	manifestKey := metadata[crypto.MetaFallbackPointer]
	if manifestKey == "" {
		manifestKey = key + ".mpu-manifest"
	}
	manifestReader, manifestMeta, err := s3Client.GetObject(ctx, bucket, manifestKey, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("decryptMPUObject: fetch manifest %q: %w", manifestKey, err)
	}
	defer manifestReader.Close()

	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		return nil, fmt.Errorf("decryptMPUObject: get engine: %w", err)
	}
	manifestPlainReader, _, err := engine.Decrypt(ctx, manifestReader, manifestMeta)
	if err != nil {
		return nil, fmt.Errorf("decryptMPUObject: decrypt manifest: %w", err)
	}
	manifestJSON, err := io.ReadAll(manifestPlainReader)
	if err != nil {
		return nil, fmt.Errorf("decryptMPUObject: read manifest: %w", err)
	}
	manifest, err := crypto.UnmarshalMultipartManifest(manifestJSON)
	if err != nil {
		return nil, fmt.Errorf("decryptMPUObject: parse manifest: %w", err)
	}

	dek, err := h.unwrapMPUDEKFromManifest(ctx, manifest, bucket, key)
	if err != nil {
		return nil, fmt.Errorf("decryptMPUObject: unwrap DEK: %w", err)
	}
	// dek is owned by the streaming reader from this point — do NOT zero here.

	ivPrefix, err := hexToIVPrefix(manifest.IVPrefix)
	if err != nil {
		zeroBytes(dek)
		return nil, fmt.Errorf("decryptMPUObject: decode iv prefix: %w", err)
	}
	uploadIDHash, err := decodeBase64ToFixed32(manifest.UploadIDHash)
	if err != nil {
		zeroBytes(dek)
		return nil, fmt.Errorf("decryptMPUObject: decode upload id hash: %w", err)
	}

	// Return a streaming reader — no full-object buffering.
	// dek is zeroed when the streaming reader encounters EOF or the caller
	// discards it (via the wrapper below).
	inner, err := crypto.NewMPUDecryptReader(reader, manifest, dek, uploadIDHash, ivPrefix, manifest.Algorithm)
	if err != nil {
		zeroBytes(dek)
		return nil, fmt.Errorf("decryptMPUObject: create decrypt reader: %w", err)
	}
	// Wrap with a closer that zeros the DEK when the stream ends or is abandoned.
	return &mpuDecryptCloser{Reader: inner, dek: dek}, nil
}

// mpuDecryptCloser wraps an io.Reader and zeros the DEK when the stream is
// exhausted or explicitly closed.
type mpuDecryptCloser struct {
	io.Reader
	dek    []byte
	zeroed bool
}

func (c *mpuDecryptCloser) Read(p []byte) (int, error) {
	n, err := c.Reader.Read(p)
	if err == io.EOF && !c.zeroed {
		zeroBytes(c.dek)
		c.zeroed = true
	}
	return n, err
}

func (c *mpuDecryptCloser) Close() error {
	if !c.zeroed {
		zeroBytes(c.dek)
		c.zeroed = true
	}
	return nil
}

// unwrapMPUDEKFromManifest unwraps the DEK stored in the manifest using the
// KeyManager. Returns an error if the KeyManager is absent — the wrapped DEK
// in the manifest must remain opaque without KMS cooperation.
func (h *Handler) unwrapMPUDEKFromManifest(ctx context.Context, manifest *crypto.MultipartManifest, bucket, key string) ([]byte, error) {
	if h.keyManager == nil {
		return nil, fmt.Errorf("cannot decrypt MPU object: no KeyManager configured")
	}
	var env crypto.KeyEnvelope
	if err := json.Unmarshal([]byte(manifest.WrappedDEK), &env); err != nil {
		return nil, fmt.Errorf("unmarshal key envelope: %w", err)
	}
	return h.keyManager.UnwrapKey(ctx, &env, map[string]string{
		"bucket": bucket,
		"key":    key,
	})
}

// hexToIVPrefix converts a hex string to a [12]byte IV prefix.
func hexToIVPrefix(h string) ([12]byte, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return [12]byte{}, fmt.Errorf("decode hex: %w", err)
	}
	if len(b) != 12 {
		return [12]byte{}, fmt.Errorf("expected 12 bytes, got %d", len(b))
	}
	var out [12]byte
	copy(out[:], b)
	return out, nil
}

// decodeBase64ToFixed32 decodes a base64 or base64url string into a [32]byte array.
func decodeBase64ToFixed32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := crypto.DecodeBase64Loose(s)
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// getS3ClientFromBucket returns an S3 client (uses clientFactory if available).
func (h *Handler) getS3ClientFromBucket(ctx context.Context, bucket string) (s3.Client, error) {
	if h.clientFactory != nil {
		return h.clientFactory.GetClient()
	}
	return h.s3Client, nil
}

// sortedPartRecords returns parts sorted by PartNumber ascending.
func sortedPartRecords(parts []mpu.PartRecord) []mpu.PartRecord {
	sorted := make([]mpu.PartRecord, len(parts))
	copy(sorted, parts)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].PartNumber < sorted[j-1].PartNumber; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return sorted
}

// handleListParts handles listing parts of a multipart upload.
func (h *Handler) handleListParts(w http.ResponseWriter, r *http.Request) {
	// Multipart uploads are now supported
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]

	if bucket == "" || key == "" || uploadID == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Check if multipart uploads are disabled
	if h.config != nil && h.config.Server.DisableMultipartUploads {
		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Multipart uploads are disabled to ensure all data is encrypted.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Fail closed if policy requires encrypted MPU but infra is missing.
	if h.mpuGuardMisconfig(w, r, bucket, "GET", start) {
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "GET", start)
		return
	}

	parts, err := s3Client.ListParts(ctx, bucket, key, uploadID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to list parts")
		h.metrics.RecordS3Error(r.Context(), "ListParts", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Generate XML response
	type ListPartsResult struct {
		XMLName  xml.Name `xml:"ListPartsResult"`
		Bucket   string   `xml:"Bucket"`
		Key      string   `xml:"Key"`
		UploadId string   `xml:"UploadId"`
		Parts    []struct {
			PartNumber   int32  `xml:"PartNumber"`
			ETag         string `xml:"ETag"`
			Size         int64  `xml:"Size"`
			LastModified string `xml:"LastModified"`
		} `xml:"Part"`
	}

	result := ListPartsResult{
		Bucket:   bucket,
		Key:      key,
		UploadId: uploadID,
		Parts: make([]struct {
			PartNumber   int32  `xml:"PartNumber"`
			ETag         string `xml:"ETag"`
			Size         int64  `xml:"Size"`
			LastModified string `xml:"LastModified"`
		}, len(parts)),
	}

	for i, p := range parts {
		result.Parts[i].PartNumber = p.PartNumber
		result.Parts[i].ETag = p.ETag
		result.Parts[i].Size = p.Size
		result.Parts[i].LastModified = p.LastModified
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation(r.Context(), "ListParts", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleCopyObject handles PUT Object Copy requests.
func (h *Handler) handleCopyObject(w http.ResponseWriter, r *http.Request, dstBucket, dstKey, copySource string, start time.Time, s3Client s3.Client) {
	// Parse copy source: format is "bucket/key" or "bucket/key?versionId=xxx"
	srcBucket, srcKey, srcVersionID, err := parseCopySource(copySource)
	if err != nil {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Invalid x-amz-copy-source header",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Extract tagging header
	tagging := r.Header.Get("x-amz-tagging")
	if err := validateTags(tagging); err != nil {
		h.logger.WithError(err).Error("Invalid tagging header")
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    err.Error(),
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Get source object (decrypt if encrypted)
	srcReader, srcMetadata, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		s3Err := TranslateError(err, srcBucket, srcKey)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"srcBucket": srcBucket,
			"srcKey":    srcKey,
			"dstBucket": dstBucket,
			"dstKey":    dstKey,
		}).Error("Failed to get source object for copy")
		h.metrics.RecordS3Error(r.Context(), "CopyObject", dstBucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}
	defer srcReader.Close()

	// Get source encryption engine
	srcEngine, err := h.getEncryptionEngine(srcBucket)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get source encryption engine")
		s3Err := &S3Error{Code: "InternalError", Message: "Failed to load encryption configuration", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// V0.6-PERF-1 Phase C: enforce legacy-source cap on handleCopyObject
	// (mirror of the guard added in V0.6-S3-1 for uploadPartCopyLegacy).
	// Legacy AEAD cannot be range-decrypted, so the engine buffers the whole
	// source internally inside Decrypt. Cap the allocation before we start.
	if srcEngine.IsEncrypted(srcMetadata) && !crypto.IsChunkedFormat(srcMetadata) {
		legacyCap := effectiveCopySourceCap(h.config)
		srcSizeHint := int64(0)
		if clStr, ok := srcMetadata["Content-Length"]; ok {
			if cl, perr := strconv.ParseInt(clStr, 10, 64); perr == nil {
				srcSizeHint = cl
			}
		}
		if srcSizeHint > 0 && srcSizeHint > legacyCap {
			h.logger.WithFields(logrus.Fields{
				"srcBucket": srcBucket,
				"srcKey":    srcKey,
				"size":      srcSizeHint,
				"cap":       legacyCap,
			}).Error("Legacy source too large for CopyObject; raise server.max_legacy_copy_source_bytes")
			s3Err := &S3Error{
				Code:       "InvalidRequest",
				Message:    fmt.Sprintf("Source object (%d bytes) exceeds server.max_legacy_copy_source_bytes (%d bytes). Migrate to chunked encryption or raise the limit.", srcSizeHint, legacyCap),
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadRequest,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
	}

	// Decrypt source if encrypted.
	// V0.6-PERF-1 Phase C: pass srcReader directly to Decrypt — the engine
	// already handles buffering for legacy AEAD and streams for chunked.
	// The intermediate decryptedData []byte allocation is eliminated here.
	decryptedReader, _, err := srcEngine.Decrypt(r.Context(), srcReader, srcMetadata)
	if err != nil {
		h.logger.WithError(err).Error("Failed to decrypt source object for copy")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to decrypt source object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Extract destination metadata from headers.
	// Case-insensitive x-amz-meta-* match — Go canonicalises headers to
	// X-Amz-Meta-Foo on parse, so strings.HasPrefix against the lowercase
	// prefix is the correct comparison.
	dstMetadata := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") || isStandardMetadata(k) {
				dstMetadata[strings.ToLower(k)] = v[0]
			}
		}
	}

	// Preserve Content-Type from source object if not specified in copy request
	if _, hasContentType := dstMetadata["Content-Type"]; !hasContentType {
		if srcContentType, ok := srcMetadata["Content-Type"]; ok {
			dstMetadata["Content-Type"] = srcContentType
		}
	}

	// Get destination encryption engine
	dstEngine, err := h.getEncryptionEngine(dstBucket)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get destination encryption engine")
		s3Err := &S3Error{Code: "InternalError", Message: "Failed to load encryption configuration", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// V0.6-PERF-1 Phase C: pass decryptedReader directly to Encrypt, eliminating
	// the intermediate decryptedData []byte allocation. The engine handles its
	// own buffering as needed for legacy vs chunked mode.
	encryptedReader, encMetadata, err := dstEngine.Encrypt(r.Context(), decryptedReader, dstMetadata)
	if err != nil {
		h.logger.WithError(err).Error("Failed to encrypt destination object")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to encrypt destination object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// V0.6-PERF-1: intentionally buffered — the engine returns a fully-sealed
	// ciphertext reader (legacy AEAD: single allocation inside engine.Encrypt;
	// chunked: backing bytes.Buffer from the chunked writer). We must call
	// io.ReadAll once here to obtain the exact byte count for PutObject's
	// ContentLength field; no additional copy of the plaintext or intermediate
	// decryptedData exists at this point. A full-pipeline io.Pipe (decode →
	// encode → PUT without buffering) requires the SDK to accept a non-seekable
	// body with a pre-computed CiphertextLen — deferred to V0.6-PERF-2 behind
	// a Backend.SupportsStreamingChecksums capability flag. See ADR 0006
	// addendum and docs/plans/V0.6-PERF-1-plan.md §4.4.
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		h.logger.WithError(err).Error("Failed to read encrypted destination object")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to read encrypted destination object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Filter out standard HTTP headers from metadata before sending to S3
	var filterKeys []string
	if h.config != nil {
		filterKeys = h.config.Backend.FilterMetadataKeys
	}
	s3Metadata := filterS3Metadata(encMetadata, filterKeys)

	lockInput, s3Err := extractObjectLockInput(r)
	if s3Err != nil {
		s3Err.WriteXML(w)
		return
	}

	// Upload encrypted copy with filtered metadata and known content length
	encLen := int64(len(encryptedData))
	_, err = s3Client.PutObject(ctx, dstBucket, dstKey, bytes.NewReader(encryptedData), s3Metadata, &encLen, tagging, lockInput, "", "", "", "", "")
	if err != nil {
		s3Err := TranslateError(err, dstBucket, dstKey)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"srcBucket": srcBucket,
			"srcKey":    srcKey,
			"dstBucket": dstBucket,
			"dstKey":    dstKey,
		}).Error("Failed to put copied object")
		h.metrics.RecordS3Error(r.Context(), "CopyObject", dstBucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Fetch ETag via HEAD to return accurate ETag
	headMeta, _ := s3Client.HeadObject(ctx, dstBucket, dstKey, nil)
	etag := headMeta["ETag"]

	// Return CopyObjectResult XML
	type CopyObjectResult struct {
		XMLName      xml.Name `xml:"CopyObjectResult"`
		ETag         string   `xml:"ETag"`
		LastModified string   `xml:"LastModified"`
	}

	result := CopyObjectResult{
		ETag:         etag,
		LastModified: time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation(r.Context(), "CopyObject", dstBucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// handleDeleteObjects handles batch delete requests.
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// V0.6-S3-2: refuse x-amz-bypass-governance-retention unconditionally
	// on the batch-delete path as well. Pending V0.6-CFG-1.
	if refuseBypassGovernanceRetention(w, r, h, bucket, "", start) {
		return
	}

	ctx := r.Context()

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "POST", start)
		return
	}

	// Parse Delete request XML
	type DeleteRequest struct {
		XMLName xml.Name `xml:"Delete"`
		Objects []struct {
			XMLName   xml.Name `xml:"Object"`
			Key       string   `xml:"Key"`
			VersionID string   `xml:"VersionId,omitempty"`
		} `xml:"Object"`
		Quiet bool `xml:"Quiet,omitempty"`
	}

	var deleteReq DeleteRequest
	if err := xml.NewDecoder(r.Body).Decode(&deleteReq); err != nil {
		s3Err := &S3Error{
			Code:       "MalformedXML",
			Message:    "The XML you provided was not well-formed or did not validate against our published schema",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Convert to ObjectIdentifier slice
	identifiers := make([]s3.ObjectIdentifier, len(deleteReq.Objects))
	for i, obj := range deleteReq.Objects {
		identifiers[i] = s3.ObjectIdentifier{
			Key:       obj.Key,
			VersionID: obj.VersionID,
		}
	}

	deleted, errors, err := s3Client.DeleteObjects(ctx, bucket, identifiers)
	if err != nil {
		s3Err := TranslateError(err, bucket, "")
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
		}).Error("Failed to delete objects")
		h.metrics.RecordS3Error(r.Context(), "DeleteObjects", bucket, s3Err.Code)
		h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Invalidate cache for deleted objects
	if h.cache != nil {
		for _, del := range deleted {
			h.cache.Delete(ctx, bucket, del.Key)
		}
	}

	// Clean up MPU manifest companion objects for successfully deleted keys
	// (best-effort). Non-MPU objects have no manifest, so 404s are expected
	// and silently ignored. Manifest cleanup failures must NOT propagate as
	// primary delete errors — the objects themselves are already gone.
	if len(deleted) > 0 {
		manifestKeys := make([]s3.ObjectIdentifier, 0, len(deleted))
		for _, del := range deleted {
			manifestKeys = append(manifestKeys, s3.ObjectIdentifier{
				Key: del.Key + ".mpu-manifest",
			})
		}
		manifestDeleted, manifestErrors, manifestErr := s3Client.DeleteObjects(ctx, bucket, manifestKeys)
		if manifestErr != nil {
			// Whole-batch failure — log and move on.
			h.logger.WithError(manifestErr).WithFields(logrus.Fields{
				"bucket": bucket,
				"count": len(manifestKeys),
			}).Warn("Failed to batch-delete MPU manifest companion objects")
		} else {
			for _, d := range manifestDeleted {
				h.logger.WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    d.Key,
				}).Debug("Cleaned up MPU manifest companion object")
			}
			for _, e := range manifestErrors {
				if e.Code == "NoSuchKey" || e.Code == "NotFound" {
					h.logger.WithFields(logrus.Fields{
						"bucket": bucket,
						"key":    e.Key,
					}).Debug("No MPU manifest to clean up (object was not an MPU-encrypted object)")
				} else {
					h.logger.WithFields(logrus.Fields{
						"bucket": bucket,
						"key":    e.Key,
						"code":   e.Code,
					}).Warn("Failed to clean up MPU manifest companion object")
				}
			}
		}
	}

	// Audit logging for batch delete
	if h.auditLogger != nil {
		for _, del := range deleted {
			h.auditLogger.LogAccess("delete", bucket, del.Key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
		}
		for _, errObj := range errors {
			h.auditLogger.LogAccess("delete", bucket, errObj.Key, getClientIP(r), r.UserAgent(), getRequestID(r), false, fmt.Errorf("%s: %s", errObj.Code, errObj.Message), time.Since(start))
		}
	}

	// Generate response XML
	type DeleteResult struct {
		XMLName xml.Name `xml:"DeleteResult"`
		Deleted []struct {
			XMLName      xml.Name `xml:"Deleted"`
			Key          string   `xml:"Key"`
			VersionID    string   `xml:"VersionId,omitempty"`
			DeleteMarker bool     `xml:"DeleteMarker,omitempty"`
		} `xml:"Deleted"`
		Errors []struct {
			XMLName xml.Name `xml:"Error"`
			Key     string   `xml:"Key"`
			Code    string   `xml:"Code"`
			Message string   `xml:"Message"`
		} `xml:"Error"`
	}

	result := DeleteResult{
		Deleted: make([]struct {
			XMLName      xml.Name `xml:"Deleted"`
			Key          string   `xml:"Key"`
			VersionID    string   `xml:"VersionId,omitempty"`
			DeleteMarker bool     `xml:"DeleteMarker,omitempty"`
		}, len(deleted)),
		Errors: make([]struct {
			XMLName xml.Name `xml:"Error"`
			Key     string   `xml:"Key"`
			Code    string   `xml:"Code"`
			Message string   `xml:"Message"`
		}, len(errors)),
	}

	for i, d := range deleted {
		result.Deleted[i].Key = d.Key
		if d.VersionID != "" {
			result.Deleted[i].VersionID = d.VersionID
		}
		if d.DeleteMarker {
			result.Deleted[i].DeleteMarker = true
		}
	}

	for i, e := range errors {
		result.Errors[i].Key = e.Key
		result.Errors[i].Code = e.Code
		result.Errors[i].Message = e.Message
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation(r.Context(), "DeleteObjects", bucket, time.Since(start))
	h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// parseCopySource extracts bucket, key, and version ID from an x-amz-copy-source header.
// Format: "bucket/key" or "bucket/key?versionId=xxx" or "/bucket/key" or "/bucket/key?versionId=xxx"
// Returns error if the format is invalid.
func parseCopySource(copySource string) (bucket, key string, versionID *string, err error) {
	// Remove leading slash if present
	if strings.HasPrefix(copySource, "/") {
		copySource = copySource[1:]
	}

	// Split on first "/" to separate bucket from key
	parts := strings.SplitN(copySource, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", nil, fmt.Errorf("invalid copy source format")
	}

	bucket = parts[0]
	keyWithVersion := parts[1]

	// Parse version ID if present
	if strings.Contains(keyWithVersion, "?versionId=") {
		keyParts := strings.SplitN(keyWithVersion, "?versionId=", 2)
		keyWithVersion = keyParts[0]
		if len(keyParts) > 1 && keyParts[1] != "" {
			versionID = &keyParts[1]
		}
	}

	// Remove leading slash from key if present
	key = strings.TrimPrefix(keyWithVersion, "/")

	return bucket, key, versionID, nil
}

// effectiveCopySourceCap returns the configured legacy-source cap for
// handleCopyObject, falling back to the default when unconfigured.
// V0.6-PERF-1 Phase C: mirrors effectiveMaxLegacyCopySourceBytes in
// upload_part_copy.go for the CopyObject handler.
func effectiveCopySourceCap(cfg *config.Config) int64 {
	if cfg != nil && cfg.Server.MaxLegacyCopySourceBytes > 0 {
		return cfg.Server.MaxLegacyCopySourceBytes
	}
	return config.DefaultMaxLegacyCopySourceBytes
}

// effectiveMaxPartBuffer returns the configured UploadPart body cap,
// falling back to the default when unconfigured.
// V0.6-PERF-1 Phase D.
func effectiveMaxPartBuffer(cfg *config.Config) int64 {
	if cfg != nil && cfg.Server.MaxPartBuffer > 0 {
		return cfg.Server.MaxPartBuffer
	}
	return config.DefaultMaxPartBuffer
}

// handleListBuckets handles GET / — ListBuckets.
func (h *Handler) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "ListBuckets", "", "")
}

// handleDeleteBucket handles DELETE /{bucket} — DeleteBucket.
func (h *Handler) handleDeleteBucket(w http.ResponseWriter, r *http.Request) {
	bucket := mux.Vars(r)["bucket"]
	if h.policyManager != nil {
		if policy := h.policyManager.GetPolicyForBucket(bucket); policy != nil {
			h.logger.WithFields(logrus.Fields{
				"bucket":    bucket,
				"policy_id": policy.ID,
			}).Warn("Deleting bucket with active policy reference")
		}
	}
	h.handlePassthrough(w, r, "DeleteBucket", bucket, "")
}

// handleGetBucketLocation handles GET /{bucket}?location — GetBucketLocation.
func (h *Handler) handleGetBucketLocation(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketLocation", mux.Vars(r)["bucket"], "")
}

// handleGetBucketVersioning handles GET /{bucket}?versioning — GetBucketVersioning.
func (h *Handler) handleGetBucketVersioning(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketVersioning", mux.Vars(r)["bucket"], "")
}

// handlePutBucketVersioning handles PUT /{bucket}?versioning — PutBucketVersioning.
func (h *Handler) handlePutBucketVersioning(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketVersioning", mux.Vars(r)["bucket"], "")
}

// handleListMultipartUploads handles GET /{bucket}?uploads — ListMultipartUploads.
func (h *Handler) handleListMultipartUploads(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "ListMultipartUploads", mux.Vars(r)["bucket"], "")
}

// handleGetBucketACL handles GET /{bucket}?acl — GetBucketACL.
func (h *Handler) handleGetBucketACL(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketACL", mux.Vars(r)["bucket"], "")
}

// handlePutBucketACL handles PUT /{bucket}?acl — PutBucketACL.
func (h *Handler) handlePutBucketACL(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketACL", mux.Vars(r)["bucket"], "")
}

// handleGetBucketPolicy handles GET /{bucket}?policy — GetBucketPolicy.
func (h *Handler) handleGetBucketPolicy(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketPolicy", mux.Vars(r)["bucket"], "")
}

// handlePutBucketPolicy handles PUT /{bucket}?policy — PutBucketPolicy.
func (h *Handler) handlePutBucketPolicy(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketPolicy", mux.Vars(r)["bucket"], "")
}

// handleDeleteBucketPolicy handles DELETE /{bucket}?policy — DeleteBucketPolicy.
func (h *Handler) handleDeleteBucketPolicy(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "DeleteBucketPolicy", mux.Vars(r)["bucket"], "")
}

// handleGetBucketCors handles GET /{bucket}?cors — GetBucketCors.
func (h *Handler) handleGetBucketCors(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketCors", mux.Vars(r)["bucket"], "")
}

// handlePutBucketCors handles PUT /{bucket}?cors — PutBucketCors.
func (h *Handler) handlePutBucketCors(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketCors", mux.Vars(r)["bucket"], "")
}

// handleDeleteBucketCors handles DELETE /{bucket}?cors — DeleteBucketCors.
func (h *Handler) handleDeleteBucketCors(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "DeleteBucketCors", mux.Vars(r)["bucket"], "")
}

// handleGetBucketLifecycle handles GET /{bucket}?lifecycle — GetBucketLifecycle.
func (h *Handler) handleGetBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketLifecycle", mux.Vars(r)["bucket"], "")
}

// handlePutBucketLifecycle handles PUT /{bucket}?lifecycle — PutBucketLifecycle.
func (h *Handler) handlePutBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketLifecycle", mux.Vars(r)["bucket"], "")
}

// handleDeleteBucketLifecycle handles DELETE /{bucket}?lifecycle — DeleteBucketLifecycle.
func (h *Handler) handleDeleteBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "DeleteBucketLifecycle", mux.Vars(r)["bucket"], "")
}

// handleGetBucketEncryption handles GET /{bucket}?encryption — GetBucketEncryption.
func (h *Handler) handleGetBucketEncryption(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketEncryption", mux.Vars(r)["bucket"], "")
}

// handlePutBucketEncryption handles PUT /{bucket}?encryption — PutBucketEncryption.
func (h *Handler) handlePutBucketEncryption(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketEncryption", mux.Vars(r)["bucket"], "")
}

// handleDeleteBucketEncryption handles DELETE /{bucket}?encryption — DeleteBucketEncryption.
func (h *Handler) handleDeleteBucketEncryption(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "DeleteBucketEncryption", mux.Vars(r)["bucket"], "")
}

// handleGetBucketNotification handles GET /{bucket}?notification — GetBucketNotification.
func (h *Handler) handleGetBucketNotification(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketNotification", mux.Vars(r)["bucket"], "")
}

// handlePutBucketNotification handles PUT /{bucket}?notification — PutBucketNotification.
func (h *Handler) handlePutBucketNotification(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketNotification", mux.Vars(r)["bucket"], "")
}

// handleGetBucketReplication handles GET /{bucket}?replication — GetBucketReplication.
func (h *Handler) handleGetBucketReplication(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketReplication", mux.Vars(r)["bucket"], "")
}

// handlePutBucketReplication handles PUT /{bucket}?replication — PutBucketReplication.
func (h *Handler) handlePutBucketReplication(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketReplication", mux.Vars(r)["bucket"], "")
}

// handleDeleteBucketReplication handles DELETE /{bucket}?replication — DeleteBucketReplication.
func (h *Handler) handleDeleteBucketReplication(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "DeleteBucketReplication", mux.Vars(r)["bucket"], "")
}

// handleGetBucketLogging handles GET /{bucket}?logging — GetBucketLogging.
func (h *Handler) handleGetBucketLogging(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketLogging", mux.Vars(r)["bucket"], "")
}

// handlePutBucketLogging handles PUT /{bucket}?logging — PutBucketLogging.
func (h *Handler) handlePutBucketLogging(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketLogging", mux.Vars(r)["bucket"], "")
}

// handleGetBucketRequestPayment handles GET /{bucket}?requestPayment — GetBucketRequestPayment.
func (h *Handler) handleGetBucketRequestPayment(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketRequestPayment", mux.Vars(r)["bucket"], "")
}

// handlePutBucketRequestPayment handles PUT /{bucket}?requestPayment — PutBucketRequestPayment.
func (h *Handler) handlePutBucketRequestPayment(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketRequestPayment", mux.Vars(r)["bucket"], "")
}

// handleGetBucketWebsite handles GET /{bucket}?website — GetBucketWebsite.
func (h *Handler) handleGetBucketWebsite(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketWebsite", mux.Vars(r)["bucket"], "")
}

// handlePutBucketWebsite handles PUT /{bucket}?website — PutBucketWebsite.
func (h *Handler) handlePutBucketWebsite(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketWebsite", mux.Vars(r)["bucket"], "")
}

// handleDeleteBucketWebsite handles DELETE /{bucket}?website — DeleteBucketWebsite.
func (h *Handler) handleDeleteBucketWebsite(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "DeleteBucketWebsite", mux.Vars(r)["bucket"], "")
}

// handleGetBucketInventory handles GET /{bucket}?inventory — GetBucketInventory.
func (h *Handler) handleGetBucketInventory(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketInventory", mux.Vars(r)["bucket"], "")
}

// handlePutBucketInventory handles PUT /{bucket}?inventory — PutBucketInventory.
func (h *Handler) handlePutBucketInventory(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketInventory", mux.Vars(r)["bucket"], "")
}

// handleDeleteBucketInventory handles DELETE /{bucket}?inventory — DeleteBucketInventory.
func (h *Handler) handleDeleteBucketInventory(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "DeleteBucketInventory", mux.Vars(r)["bucket"], "")
}

// handleGetBucketAnalytics handles GET /{bucket}?analytics — GetBucketAnalytics.
func (h *Handler) handleGetBucketAnalytics(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketAnalytics", mux.Vars(r)["bucket"], "")
}

// handlePutBucketIntelligentTiering handles PUT /{bucket}?intelligent-tiering — PutBucketIntelligentTiering.
func (h *Handler) handlePutBucketIntelligentTiering(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutBucketIntelligentTiering", mux.Vars(r)["bucket"], "")
}

// handleGetObjectTagging handles GET /{bucket}/{key}?tagging — GetObjectTagging.
func (h *Handler) handleGetObjectTagging(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetObjectTagging", mux.Vars(r)["bucket"], mux.Vars(r)["key"])
}

// handlePutObjectTagging handles PUT /{bucket}/{key}?tagging — PutObjectTagging.
func (h *Handler) handlePutObjectTagging(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutObjectTagging", mux.Vars(r)["bucket"], mux.Vars(r)["key"])
}

// handleDeleteObjectTagging handles DELETE /{bucket}/{key}?tagging — DeleteObjectTagging.
func (h *Handler) handleDeleteObjectTagging(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "DeleteObjectTagging", mux.Vars(r)["bucket"], mux.Vars(r)["key"])
}

// handleGetObjectACL handles GET /{bucket}/{key}?acl — GetObjectACL.
func (h *Handler) handleGetObjectACL(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetObjectACL", mux.Vars(r)["bucket"], mux.Vars(r)["key"])
}

// handlePutObjectACL handles PUT /{bucket}/{key}?acl — PutObjectACL.
func (h *Handler) handlePutObjectACL(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "PutObjectACL", mux.Vars(r)["bucket"], mux.Vars(r)["key"])
}

// handleRestoreObject handles POST /{bucket}/{key}?restore — RestoreObject.
func (h *Handler) handleRestoreObject(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "RestoreObject", mux.Vars(r)["bucket"], mux.Vars(r)["key"])
}

// handleCORSPreflight handles OPTIONS requests for S3 resources.
func (h *Handler) handleCORSPreflight(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "CORSPreflight", mux.Vars(r)["bucket"], mux.Vars(r)["key"])
}

// handleSelectObjectContent handles POST /{bucket}/{key}?select or ?select-type=2 — returns 501.
func (h *Handler) handleSelectObjectContent(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	s3Err := &S3Error{
		Code:       "NotImplemented",
		Message:    "SelectObjectContent is not implemented by the S3 Encryption Gateway. Server-side SQL evaluation on encrypted data is not feasible in a proxy model.",
		Resource:   r.URL.Path,
		HTTPStatus: http.StatusNotImplemented,
	}
	s3Err.WriteXML(w)
	h.metrics.RecordHTTPRequest(r.Context(), "POST", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
}
