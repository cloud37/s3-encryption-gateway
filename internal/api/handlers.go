package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/admin"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/sizecache"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// Handler handles HTTP requests for S3 operations.
type Handler struct {
	s3Client      s3.Client         // Legacy: kept for backward compatibility
	clientFactory *s3.ClientFactory // New: factory for per-request clients
	// clientAcquirer, when non-nil, overrides client resolution in
	// getS3Client. It is a test seam for observing that authorization
	// precedes backend client acquisition.
	clientAcquirer                 func(*http.Request) (s3.Client, error)
	encryptionEngine               crypto.EncryptionEngine
	logger                         *logrus.Logger
	metrics                        *metrics.Metrics
	keyManager                     crypto.KeyManager
	cache                          cache.Cache
	auditLogger                    audit.Logger
	config                         *config.Config
	allowBucketCreation            atomic.Bool
	allowUntrackedPlaintextUploads atomic.Bool
	policyManager                  *config.PolicyManager
	engineCache                    *ttlEngineCache // TTL cache for per-policy engines (V1.0-SEC-20)
	mpuStateStore                  mpu.StateStore  // nil when encrypted MPU is not configured
	sizeCache                      sizecache.SizeCache
	// Test seams for API metadata classification failures. Nil uses production
	// implementations; keeping these private avoids changing the public API.
	apiMetadataExpander    func(map[string]string) (map[string]string, error)
	encryptionEngineLoader func(string) (crypto.EncryptionEngine, error)
	// Optional test seam for observing destination encryption construction.
	destinationEncryptionConstructed func()
	destinationEncryptionReader      func(io.Reader, int64) (io.Reader, int64, error)
	spoolManager                     SpoolManager
	spoolLimits                      *SpoolLimitSource
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
	if config != nil {
		h.allowBucketCreation.Store(config.AllowBucketCreation)
		h.allowUntrackedPlaintextUploads.Store(config.MultipartState.AllowUntrackedPlaintextUploads)
	}
	h.spoolManager = DefaultSpoolManager()
	if config != nil && config.Server.MaxAggregateSpoolBytes > 0 {
		if m != nil {
			h.spoolManager = NewSpoolManager(config.Server.MaxAggregateSpoolBytes, config.Server.SpoolDirectory, m)
		} else {
			h.spoolManager = NewSpoolManager(config.Server.MaxAggregateSpoolBytes, config.Server.SpoolDirectory)
		}
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

// WithSpoolManager injects the process-wide manager shared with authentication.
// If omitted, the constructor's isolated default remains suitable for tests.
func (h *Handler) WithSpoolManager(manager SpoolManager) *Handler {
	if manager != nil {
		h.spoolManager = manager
	}
	return h
}

// WithSpoolLimitSource injects the live request-limit source shared with auth.
func (h *Handler) WithSpoolLimitSource(source *SpoolLimitSource) *Handler {
	if source != nil {
		h.spoolLimits = source
	}
	return h
}

// SetAllowBucketCreation updates the reload-safe management gate.
func (h *Handler) SetAllowBucketCreation(enabled bool) { h.allowBucketCreation.Store(enabled) }

// AllowBucketCreation reports the current live management gate.
func (h *Handler) AllowBucketCreation() bool { return h.allowBucketCreation.Load() }

// SetAllowUntrackedPlaintextUploads updates the reload-safe legacy MPU gate.
func (h *Handler) SetAllowUntrackedPlaintextUploads(enabled bool) {
	h.allowUntrackedPlaintextUploads.Store(enabled)
}

// AllowUntrackedPlaintextUploads reports the current live compatibility gate.
func (h *Handler) AllowUntrackedPlaintextUploads() bool {
	return h.allowUntrackedPlaintextUploads.Load()
}

// WithMPUStateStore attaches an encrypted multipart state store to the handler.
// When non-nil, buckets with EncryptMultipartUploads=true will use this store.
func (h *Handler) WithMPUStateStore(store mpu.StateStore) {
	h.mpuStateStore = store
}

// WithSizeCache sets the size cache used for ListObjects plaintext size resolution.
func (h *Handler) WithSizeCache(c sizecache.SizeCache) {
	h.sizeCache = c
}

// WithCache replaces the optional object response cache. It is primarily used
// by the conformance harness to exercise the production cache path.
func (h *Handler) WithCache(c cache.Cache) *Handler {
	h.cache = c
	return h
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
// subsequent UploadPart / Complete / Abort must use uploadState so
// that mid-upload policy flips do not affect in-flight uploads (ADR-0009
// §Security Considerations: "Policy snapshot captured at Create").
func (h *Handler) bucketEncryptsMPU(bucket string) bool {
	if h.policyManager == nil {
		return false
	}
	return h.policyManager.BucketEncryptsMultipart(bucket)
}

// uploadState is the single routing authority for an MPU. A configured store
// miss is not evidence of plaintext: it is a missing upload unless the
// explicit legacy migration switch is enabled.
func (h *Handler) uploadState(ctx context.Context, uploadID string) (*mpu.UploadState, error) {
	if h.mpuStateStore == nil {
		return nil, nil
	}
	state, err := h.mpuStateStore.Get(ctx, uploadID)
	if err == nil {
		return state, nil
	}
	if errors.Is(err, mpu.ErrUploadNotFound) {
		if h.allowUntrackedPlaintextUploads.Load() {
			if h.logger != nil {
				h.logger.WithField("uploadID", uploadID).Warn("using legacy untracked plaintext MPU compatibility path")
			}
			return nil, nil
		}
		return nil, mpu.ErrUploadNotFound
	}
	return nil, err
}

func (h *Handler) writeMissingMPUState(w http.ResponseWriter, r *http.Request, err error) bool {
	if err == nil {
		return false
	}
	start := time.Now()
	if errors.Is(err, mpu.ErrUploadNotFound) {
		h.writeObjectError(w, r, "MultipartUpload", &S3Error{Code: "NoSuchUpload", Message: "The specified multipart upload does not exist.", Resource: r.URL.Path, HTTPStatus: http.StatusNotFound}, start)
	} else {
		h.writeObjectError(w, r, "MultipartUpload", &S3Error{Code: "ServiceUnavailable", Message: "Multipart encryption state store unavailable; retry the request", Resource: r.URL.Path, HTTPStatus: http.StatusServiceUnavailable}, start)
	}
	return true
}

func validateMPURouteIdentity(state *mpu.UploadState, bucket, key string) error {
	if state == nil || state.Bucket != bucket || state.Key != key {
		return fmt.Errorf("multipart upload route does not match persisted upload identity")
	}
	return nil
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
	h.writeObjectError(w, r, "MultipartUpload", s3Err, start)
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
// Every route carries a Name() so tests can assert exact router/classifier
// parity; names have no effect on matching.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/health", h.handleHealth).Methods("GET").Name("Health")
	r.HandleFunc("/healthz", h.handleHealth).Methods("GET").Name("Health") // k8s-convention alias
	r.HandleFunc("/ready", h.handleReady).Methods("GET").Name("Ready")
	r.HandleFunc("/readyz", h.handleReady).Methods("GET").Name("Ready") // k8s-convention alias
	r.HandleFunc("/live", h.handleLive).Methods("GET").Name("Live")
	r.HandleFunc("/livez", h.handleLive).Methods("GET").Name("Live") // k8s-convention alias

	// S3-compatible health endpoint aliases. These are registered before the
	// generic S3 router so unauthenticated health probes cannot be interpreted
	// as bucket/object requests. AuthMiddleware permits only these exact paths.
	r.HandleFunc("/minio/health/live", h.handleLive).Methods("GET").Name("MinIOLive")
	r.HandleFunc("/minio/health/ready", h.handleReady).Methods("GET").Name("MinIOReady")
	r.HandleFunc("/health/live", h.handleLive).Methods("GET").Name("RustFSLive")
	r.HandleFunc("/health/ready", h.handleReady).Methods("GET").Name("RustFSReady")

	r.Handle("/", h.instrumentS3("ListBuckets", h.handleListBuckets)).Methods("GET").Name("ListBuckets")

	// S3 API routes
	s3Router := r.PathPrefix("/").Subrouter()
	s3Router.Use(h.s3InstrumentationMiddleware)

	// Multipart upload routes (must be registered first to ensure query parameter matching)
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleCreateMultipartUpload).Methods("POST").Queries("uploads", "").Name("CreateMultipartUpload")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleCompleteMultipartUpload).Methods("POST").Queries("uploadId", "{uploadId}").Name("CompleteMultipartUpload")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleAbortMultipartUpload).Methods("DELETE").Queries("uploadId", "{uploadId}").Name("AbortMultipartUpload")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleListParts).Methods("GET").Queries("uploadId", "{uploadId}").Name("ListParts")

	// Multipart-specific PUT route
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleUploadPart).Methods("PUT").Queries("partNumber", "{partNumber:[0-9]+}", "uploadId", "{uploadId}").Name("UploadPart")

	// Object Lock subresources (object-level) — must be registered BEFORE the
	// generic GET/PUT/{bucket}/{key:.+} routes so gorilla/mux matches the
	// query-parameter-scoped handlers first. V0.6-S3-2.
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObjectRetention).Methods("GET").Queries("retention", "").Name("GetObjectRetention")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObjectRetention).Methods("PUT").Queries("retention", "").Name("PutObjectRetention")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObjectLegalHold).Methods("GET").Queries("legal-hold", "").Name("GetObjectLegalHold")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObjectLegalHold).Methods("PUT").Queries("legal-hold", "").Name("PutObjectLegalHold")

	// Object tagging subresources
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObjectTagging).Methods("GET").Queries("tagging", "").Name("GetObjectTagging")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObjectTagging).Methods("PUT").Queries("tagging", "").Name("PutObjectTagging")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleDeleteObjectTagging).Methods("DELETE").Queries("tagging", "").Name("DeleteObjectTagging")

	// Object ACL subresources
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObjectACL).Methods("GET").Queries("acl", "").Name("GetObjectACL")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObjectACL).Methods("PUT").Queries("acl", "").Name("PutObjectACL")

	// RestoreObject
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleRestoreObject).Methods("POST").Queries("restore", "").Name("RestoreObject")

	// SelectObjectContent (501 NotImplemented)
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleSelectObjectContent).Methods("POST").Queries("select", "").Name("SelectObjectContent")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleSelectObjectContent).Methods("POST").Queries("select-type", "2").Name("SelectObjectContent")

	// Object Lock configuration (bucket-level) — must be registered BEFORE
	// the generic /{bucket} GET/PUT routes.
	s3Router.HandleFunc("/{bucket}", h.handleGetObjectLockConfiguration).Methods("GET").Queries("object-lock", "").Name("GetObjectLockConfiguration")
	s3Router.HandleFunc("/{bucket}", h.handlePutObjectLockConfiguration).Methods("PUT").Queries("object-lock", "").Name("PutObjectLockConfiguration")

	// CORS preflight
	s3Router.HandleFunc("/{bucket}", h.handleCORSPreflight).Methods("OPTIONS").Name("CORSPreflight")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleCORSPreflight).Methods("OPTIONS").Name("CORSPreflight")

	// Bucket lifecycle subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketLifecycle).Methods("GET").Queries("lifecycle", "").Name("GetBucketLifecycle")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketLifecycle).Methods("PUT").Queries("lifecycle", "").Name("PutBucketLifecycle")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketLifecycle).Methods("DELETE").Queries("lifecycle", "").Name("DeleteBucketLifecycle")

	// Bucket policy subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketPolicy).Methods("GET").Queries("policy", "").Name("GetBucketPolicy")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketPolicy).Methods("PUT").Queries("policy", "").Name("PutBucketPolicy")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketPolicy).Methods("DELETE").Queries("policy", "").Name("DeleteBucketPolicy")

	// Bucket CORS subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketCors).Methods("GET").Queries("cors", "").Name("GetBucketCors")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketCors).Methods("PUT").Queries("cors", "").Name("PutBucketCors")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketCors).Methods("DELETE").Queries("cors", "").Name("DeleteBucketCors")

	// Bucket versioning subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketVersioning).Methods("GET").Queries("versioning", "").Name("GetBucketVersioning")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketVersioning).Methods("PUT").Queries("versioning", "").Name("PutBucketVersioning")

	// Bucket encryption subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketEncryption).Methods("GET").Queries("encryption", "").Name("GetBucketEncryption")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketEncryption).Methods("PUT").Queries("encryption", "").Name("PutBucketEncryption")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketEncryption).Methods("DELETE").Queries("encryption", "").Name("DeleteBucketEncryption")

	// Bucket ACL subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketACL).Methods("GET").Queries("acl", "").Name("GetBucketACL")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketACL).Methods("PUT").Queries("acl", "").Name("PutBucketACL")

	// Bucket location
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketLocation).Methods("GET").Queries("location", "").Name("GetBucketLocation")

	// Bucket uploads listing (multipart)
	s3Router.HandleFunc("/{bucket}", h.handleListMultipartUploads).Methods("GET").Queries("uploads", "").Name("ListMultipartUploads")

	// Bucket notification subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketNotification).Methods("GET").Queries("notification", "").Name("GetBucketNotification")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketNotification).Methods("PUT").Queries("notification", "").Name("PutBucketNotification")

	// Bucket replication subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketReplication).Methods("GET").Queries("replication", "").Name("GetBucketReplication")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketReplication).Methods("PUT").Queries("replication", "").Name("PutBucketReplication")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketReplication).Methods("DELETE").Queries("replication", "").Name("DeleteBucketReplication")

	// Bucket logging subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketLogging).Methods("GET").Queries("logging", "").Name("GetBucketLogging")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketLogging).Methods("PUT").Queries("logging", "").Name("PutBucketLogging")

	// Bucket requestPayment subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketRequestPayment).Methods("GET").Queries("requestPayment", "").Name("GetBucketRequestPayment")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketRequestPayment).Methods("PUT").Queries("requestPayment", "").Name("PutBucketRequestPayment")

	// Bucket website subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketWebsite).Methods("GET").Queries("website", "").Name("GetBucketWebsite")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketWebsite).Methods("PUT").Queries("website", "").Name("PutBucketWebsite")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketWebsite).Methods("DELETE").Queries("website", "").Name("DeleteBucketWebsite")

	// Bucket inventory subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketInventory).Methods("GET").Queries("inventory", "").Name("GetBucketInventory")
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketInventory).Methods("PUT").Queries("inventory", "").Name("PutBucketInventory")
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucketInventory).Methods("DELETE").Queries("inventory", "").Name("DeleteBucketInventory")

	// Bucket analytics subresources
	s3Router.HandleFunc("/{bucket}", h.handleGetBucketAnalytics).Methods("GET").Queries("analytics", "").Name("GetBucketAnalytics")

	// Bucket intelligent-tiering
	s3Router.HandleFunc("/{bucket}", h.handlePutBucketIntelligentTiering).Methods("PUT").Queries("intelligent-tiering", "").Name("PutBucketIntelligentTiering")

	// Generic bucket routes. DELETE is intentionally placed AFTER all
	// query-specific bucket subresource routes so gorilla/mux gives the
	// subresource matchers higher priority.
	s3Router.HandleFunc("/{bucket}", h.handleDeleteBucket).Methods("DELETE").Name("DeleteBucket")

	// Generic S3 routes
	s3Router.HandleFunc("/{bucket}", h.handleListObjects).Methods("GET").Name("ListObjects")
	s3Router.HandleFunc("/{bucket}", h.handleHeadBucket).Methods("HEAD").Name("HeadBucket")
	s3Router.HandleFunc("/{bucket}", h.handleCreateBucket).Methods("PUT").Name("CreateBucket")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleGetObject).Methods("GET").Name("GetObject")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handlePutObject).Methods("PUT").Name("PutObject")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleDeleteObject).Methods("DELETE").Name("DeleteObject")
	s3Router.HandleFunc("/{bucket:[^/]+}/{key:.+}", h.handleHeadObject).Methods("HEAD").Name("HeadObject")

	// Batch operations
	s3Router.HandleFunc("/{bucket}", h.handleDeleteObjects).Methods("POST").Queries("delete", "").Name("DeleteObjects")
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
	h.writeObjectError(w, r, method, s3Err, start)
}

// classifyAuthError maps an error returned from getS3Client to a fixed
// client-facing S3Error. It is deliberately total: every input produces a
// response without consulting err.Error(). Pure function, no I/O — kept
// separate so it can be unit-tested.
//
// This function intentionally returns distinct S3
// error codes rather than collapsing all auth failures into a single opaque
// response. The distinct codes (SignatureDoesNotMatch, InvalidAccessKeyId,
// AccessDenied, RequestTimeTooSkewed, InvalidArgument) follow S3 semantics and
// are relied upon by AWS SDK clients for retry logic and diagnostics. The enumeration
// risk is mitigated by ensuring that err.Error() — which may contain computed
// HMAC signatures or other sensitive diagnostic detail — is NEVER included in
// the response body; only the fixed per-class message string is written to the
// wire. Regression coverage is provided by TestClassifyAuthError_Table and
// TestWriteS3ClientError_NoLeakRegression in auth_error_test.go.
func classifyAuthError(err error, resource string) *S3Error {
	switch {
	case errors.Is(err, ErrSpoolRequestLimit):
		return &S3Error{Code: "EntityTooLarge", Message: "The request exceeds the permitted payload size.", Resource: resource, HTTPStatus: http.StatusRequestEntityTooLarge}
	case errors.Is(err, ErrSpoolCapacity):
		return &S3Error{Code: "SlowDown", Message: "Please reduce your request rate.", Resource: resource, HTTPStatus: http.StatusServiceUnavailable}
	case errors.Is(err, ErrRequestTimeTooSkewed):
		return &S3Error{Code: "RequestTimeTooSkewed", Message: "The difference between the request time and the server's time is too large.", Resource: resource, HTTPStatus: http.StatusForbidden}
	case errors.Is(err, ErrRequestExpired):
		return &S3Error{Code: "AccessDenied", Message: "Request has expired.", Resource: resource, HTTPStatus: http.StatusForbidden}
	case errors.Is(err, ErrInvalidPresignedExpiry):
		return &S3Error{Code: "InvalidArgument", Message: "X-Amz-Expires must be a single integer between 1 and 604800 seconds.", Resource: resource, HTTPStatus: http.StatusBadRequest}
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

// getS3Client returns the configured backend S3 client.
// Authentication has already been validated by AuthMiddleware before this
// point; this function only needs to return the pre-configured client.
func (h *Handler) getS3Client(r *http.Request) (s3.Client, error) {
	if h.clientAcquirer != nil {
		return h.clientAcquirer(r)
	}
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
	if h.encryptionEngineLoader != nil {
		return h.encryptionEngineLoader(bucket)
	}
	if h.policyManager == nil {
		return h.encryptionEngine, nil
	}

	policy := h.policyManager.GetPolicyForBucket(bucket)
	if policy == nil {
		return h.encryptionEngine, nil
	}

	if policy.DisableEncryption {
		return crypto.PassthroughEngine{}, nil
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
		if capable, ok := h.mpuStateStore.(interface{ WriterCapabilityReady(context.Context) error }); ok {
			checks = append(checks, metrics.ReadyCheck{Name: "mpu_writer", Check: capable.WriterCapabilityReady})
		}
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
		h.writeObjectError(w, r, "GetObject", s3Err, start)
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
		h.writeObjectError(w, r, "GetObject", s3Err, start)
		return
	}

	// Check cache first if enabled and no range request
	if h.cache != nil && objectCacheRequestEligible(rangeHeader, versionID) {
		if cachedEntry, ok := h.cache.Get(ctx, bucket, key); ok {
			// Cached plaintext is only reusable after the current backend object
			// has passed v2 completeness preflight. Do not let stale cache state
			// bypass the integrity boundary.
			s3Client, clientErr := h.getS3Client(r)
			if clientErr != nil {
				h.writeChunkedCompletenessError(w, r, bucket, clientErr, start)
				return
			}
			cachePlan, planErr := h.planCachedObjectRead(ctx, s3Client, bucket, key)
			if planErr != nil {
				h.writeObjectDecryptError(w, r, "GET", bucket, key, planErr, start)
				return
			}
			meta := cachePlan.View.Raw
			// A cache entry is valid only when both its source and freshness token
			// were stored atomically with the complete plaintext body.
			if cachedEntry.BackendETag != "" && len(cachedEntry.Source) > 0 && meta["ETag"] != "" && cachedEntry.BackendETag == meta["ETag"] {
				var cachedSource objectResponseSource
				if err := json.Unmarshal(cachedEntry.Source, &cachedSource); err == nil && int64(len(cachedEntry.Data)) == cachedSource.PlainSize {
					cachedSource.BackendETag = cachedEntry.BackendETag
					readPlan := h.cachedObjectResponsePlan(cachePlan, cachedSource, cachedEntry.Data, r)
					readPlan.Started = start
					_, streamErr := h.serveObjectBody(w, r, readPlan)
					if streamErr != nil {
						h.logger.WithError(streamErr).Warn("Failed to write cached object response")
					}
					return
				}
			}
			_ = h.cache.Delete(ctx, bucket, key)
		}
	}

	// Fetch decisions are centralized in the object read planner.
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
		h.writeObjectError(w, r, "GetObject", s3Err, start)
		return
	}

	objectRead, planErr := h.prepareGetObjectRead(ctx, s3Client, bucket, key, versionID, rangeHeader, objectReadSupportsOptimizedDecrypt(engine), r)
	if planErr != nil {
		h.writeObjectDecryptError(w, r, "GET", bucket, key, planErr, start)
		return
	}
	h.servePlannedGetObject(w, r, s3Client, engine, versionID, objectRead, start)
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
		h.writeObjectError(w, r, "PutObject", s3Err, start)
		return
	}

	ctx := r.Context()

	// Check if this is a copy operation
	copySource := r.Header.Get("x-amz-copy-source")
	if copySource != "" {
		// V1.0-AUTH-2: parse and authorize the copy destination and source
		// before the handler can acquire a backend client. This mirrors the
		// AuthorizationMiddleware check as defense-in-depth so copy
		// authorization never depends on middleware ordering.
		if err := h.authorizeCopyOperation(r, bucket, copySource); err != nil {
			if errors.Is(err, ErrAccessDenied) {
				writeAuthorizationDenied(w, r, h.auditLogger, "bucket_scope")
			} else {
				s3Err := &S3Error{
					Code:       "InvalidArgument",
					Message:    "Invalid x-amz-copy-source header",
					Resource:   r.URL.Path,
					HTTPStatus: http.StatusBadRequest,
				}
				h.writeObjectError(w, r, "PutObject", s3Err, start)
			}
			return
		}
		s3Client, err := h.getS3Client(r)
		if err != nil {
			h.logger.WithError(err).Error("Failed to get S3 client")
			h.writeS3ClientError(w, r, err, "PUT", start)
			return
		}
		// Handle copy operation (pass s3Client)
		h.handleCopyObject(w, r, bucket, key, copySource, start, s3Client)
		return
	}

	// Get S3 client after authorization and copy classification.
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
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
		h.writeObjectError(w, r, "PutObject", s3Err, start)
		return
	}
	// Parse request metadata once so all standard fields and user keys flow
	// through the shared write model.
	writeMeta, writeMetaErr := parseWriteMetadata(r.Header)
	if writeMetaErr != nil {
		writeMetaErr.Resource = r.URL.Path
		h.writeObjectError(w, r, "PutObject", writeMetaErr, start)
		return
	}
	metadata := writeMeta.engineInput(0, false)
	// Extract canned ACL header (x-amz-acl) and fine-grained grant headers.
	// Forward verbatim to the backend; the gateway does not validate ACL values
	// because it is a transparent proxy and different backends support different
	// canned ACL strings (private, public-read, authenticated-read, etc.).
	cannedACL := r.Header.Get("x-amz-acl")
	grantFullControl := r.Header.Get("x-amz-grant-full-control")
	grantRead := r.Header.Get("x-amz-grant-read")
	grantReadACP := r.Header.Get("x-amz-grant-read-acp")
	grantWriteACP := r.Header.Get("x-amz-grant-write-acp")

	// Pass all six standard headers and normalized user metadata to the engine.
	// Content-Length is added separately for size derivation and removed by the
	// persistence plan before backend metadata is sent.
	// haveContentLength distinguishes a declared length from an absent one:
	// originalBytes is 0 for both "Content-Length: 0" and no header at all, but
	// only the latter is an unknown-length stream.
	var originalBytes int64
	var haveContentLength bool
	decodedLen := r.Header.Get("x-amz-decoded-content-length")
	if decodedLen != "" {
		metadata["Content-Length"] = decodedLen
		if v, err := strconv.ParseInt(decodedLen, 10, 64); err == nil && v >= 0 {
			originalBytes = v
			haveContentLength = true
		}
	} else if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
		metadata["Content-Length"] = contentLength
		if v, err := strconv.ParseInt(contentLength, 10, 64); err == nil && v >= 0 {
			originalBytes = v
			haveContentLength = true
		}
	}

	contentType := writeMeta.Standard.ContentType
	if contentType == "" {
		contentType = "application/octet-stream" // Default to match MinIO's behavior
	}
	standard := writeMeta.Standard
	if standard.ContentType == "" {
		standard.ContentType = contentType
	}
	standard.ApplyTo(metadata)
	var inputReader io.Reader = r.Body
	if mode, modeErr := classifyStreamingPayloadMode(r.Header.Get("x-amz-content-sha256")); modeErr != nil {
		writeStreamingPayloadError(w, r.URL.Path, modeErr)
		return
	} else if mode != streamingNone {
		spool, verifyErr := verifyAndSpoolAWSBody(r, streamingContext(r), h.spoolManager, h.verifiedSpoolLimit(r))
		if verifyErr != nil {
			writeStreamingPayloadError(w, r.URL.Path, verifyErr)
			return
		}
		defer spool.Close()
		inputReader = spool
		originalBytes, haveContentLength = spool.DecodedLength(), true
		metadata["Content-Length"] = strconv.FormatInt(originalBytes, 10)
	}

	// Verify and spool streaming bodies before touching backend or encryption state.
	s3Client, err = h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
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
		h.writeObjectError(w, r, "PutObject", s3Err, start)
		return
	}

	// Encrypt the object
	encryptStart := time.Now()
	encryptedReader, encMetadata, err := engine.Encrypt(r.Context(), crypto.ObjectContext{Bucket: bucket, Key: key}, inputReader, metadata)
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
		h.writeObjectError(w, r, "PutObject", s3Err, start)
		return
	}
	class, classErr := crypto.ClassifyObject(key, encMetadata)
	if classErr != nil {
		h.writeObjectError(w, r, "PutObject", decryptFailure(classErr, r.URL.Path), start)
		return
	}

	// Audit logging for successful encryption
	if h.auditLogger != nil {
		h.auditLogger.LogEncrypt(bucket, key, algorithm, keyVersion, true, nil, encryptDuration, nil)
	}
	if class.Format == crypto.FormatPlaintext {
		standard.ApplyTo(encMetadata)
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
	persist := buildPersistPlan(encMetadata, class, filterKeys)
	s3Metadata := persist.Metadata
	persist.Native.ApplyTo(s3Metadata)

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

	// Compute stored content length for backend PutObject.
	// For chunked encryption: plaintext + AEAD tag overhead per chunk.
	// For passthrough / bypass (disable_encryption): stored bytes = original bytes.
	// For legacy (non-chunked) encryption: the encrypted reader is a *bytes.Reader
	// which reports its own length; contentLengthPtr stays nil so the S3 client
	// derives it from the reader.
	// Keyed on haveContentLength, not originalBytes > 0: a declared zero is a
	// known length and must not be mistaken for an unknown-length stream.
	var contentLengthPtr *int64
	if haveContentLength && class.Format == crypto.FormatPlaintext {
		// Bypass / passthrough mode: plaintext is stored as-is.
		contentLengthPtr = &originalBytes
	} else if (class.Format == crypto.FormatChunkedV1 || class.Format == crypto.FormatChunkedV2) && haveContentLength {
		encLen, sizeErr := crypto.CiphertextSizeForPlaintext(encMetadata, originalBytes)
		if sizeErr == nil {
			contentLengthPtr = &encLen
		}
	}
	if seeker, ok := encryptedReader.(io.Seeker); ok {
		if current, seekErr := seeker.Seek(0, io.SeekCurrent); seekErr == nil {
			if end, endErr := seeker.Seek(0, io.SeekEnd); endErr == nil {
				if _, restoreErr := seeker.Seek(current, io.SeekStart); restoreErr == nil && end >= current {
					length := end - current
					contentLengthPtr = &length
				}
			}
		}
	}

	// Extract lock headers
	lockInput, s3Err := extractObjectLockInput(r)
	if s3Err != nil {
		h.writeObjectError(w, r, "PutObject", s3Err, start)
		return
	}

	// When the plaintext size is unknown (e.g. chunked transfer encoding from a
	// client with no Content-Length), wrap the encrypted reader to count
	// ciphertext bytes. After PutObject, back-calculate the plaintext size and
	// persist it via a metadata-only copy-to-self. This ensures HeadObject returns
	// the correct Content-Length so clients can issue correct range requests
	// without the gateway needing to fetch and decrypt the full object on every
	// range GET. A declared length needs none of this, zero included.
	var ciphertextCounter *countingReader
	if !haveContentLength && encMetadata[crypto.MetaChunkedFormat] == "true" {
		ciphertextCounter = newCountingReader(encryptedReader)
		encryptedReader = ciphertextCounter
	}

	// The SDK rewinds the body to retry, so a non-seekable reader makes every
	// retryable failure fatal ("failed to rewind transport stream for retry") and
	// leaves ADR 0010's retry policy inert on this path. Buffer into the bounded
	// wrapper handleUploadPart uses; see docs/plans/V0.6-PERF-1-plan.md §4.4.
	//
	// Gated on a known length that fits. NewSeekableBody has to drain maxBuf+1
	// bytes before it can report ErrPartTooLarge, and a partially drained source
	// cannot go back to streaming — so without a length up front, buffering is a
	// one-way bet on a body that may not fit. Checking the length first makes the
	// oversize branch unreachable instead of recoverable, which is why there is no
	// 413 here as there is in handleUploadPart: reaching it would mean our own
	// ciphertext length estimate was wrong, i.e. a server fault, not a too-large
	// request. Unknown-length bodies keep streaming and stay single-attempt.
	if maxBuf := effectiveMaxPartBuffer(h.config); contentLengthPtr != nil && *contentLengthPtr <= maxBuf {
		if _, seekable := encryptedReader.(io.Seeker); !seekable {
			sb, sbErr := s3.NewSeekableBody(encryptedReader, maxBuf)
			if sbErr != nil {
				h.logger.WithError(sbErr).WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    key,
				}).Error("Failed to buffer encrypted object for upload")
				s3Err := &S3Error{
					Code:       "InternalError",
					Message:    "Failed to prepare object for upload",
					Resource:   r.URL.Path,
					HTTPStatus: http.StatusInternalServerError,
				}
				h.writeObjectError(w, r, "PutObject", s3Err, start)
				return
			}
			// sb.Len is the exact ciphertext size, so prefer it over the value derived
			// from plaintext size and per-chunk tag overhead.
			encryptedReader = sb
			encLen := sb.Len
			contentLengthPtr = &encLen
		}
	}

	// Upload encrypted object with filtered metadata (streaming)
	etag, err := s3Client.PutObject(ctx, bucket, key, encryptedReader, s3Metadata, contentLengthPtr, tagging, lockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		h.writeObjectError(w, r, "PutObject", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":        bucket,
			"key":           key,
			"metadata_keys": metadataKeys,
		}).Error("Failed to put object")
		return
	}

	// After a successful streaming PUT where the plaintext size was unknown,
	// back-calculate the plaintext size from ciphertext length and update the
	// stored object's metadata. Chunked AES-GCM overhead: 16 bytes per chunk.
	// ciphertext = plaintext + ceil(plaintext/chunkSize)*16
	// This metadata-only update uses a server-side copy-to-self (zero data
	// movement on Ceph) so subsequent HEAD/range-GET calls return the correct
	// Content-Length, enabling the range-optimization path.
	if ciphertextCounter != nil && ciphertextCounter.n > 0 {
		ct := ciphertextCounter.n
		plainSize, _, sizeErr := crypto.PlaintextSizeForCiphertext(encMetadata, ct)
		if sizeErr != nil || plainSize <= 0 {
			return
		}
		if plainSize > 0 {
			updatedMetaInput := make(map[string]string, len(encMetadata)+1)
			for k, v := range encMetadata {
				updatedMetaInput[k] = v
			}
			updatedMetaInput[crypto.MetaOriginalSize] = fmt.Sprintf("%d", plainSize)
			backfillPlan := buildPersistPlan(updatedMetaInput, class, filterKeys)
			updatedMeta := backfillPlan.Metadata
			backfillPlan.Native.ApplyTo(updatedMeta)
			if _, _, copyErr := s3Client.CopyObject(ctx, bucket, key, bucket, key, nil, updatedMeta, nil); copyErr != nil {
				h.logger.WithError(copyErr).WithFields(logrus.Fields{
					"bucket":     bucket,
					"key":        key,
					"plain_size": plainSize,
				}).Warn("handlePutObject: failed to update MetaOriginalSize after streaming PUT; range optimisation unavailable for this object")
			} else {
				h.logger.WithFields(logrus.Fields{
					"bucket":     bucket,
					"key":        key,
					"plain_size": plainSize,
				}).Debug("handlePutObject: updated MetaOriginalSize after streaming PUT")
			}
		}
	}

	if n, err := strconv.ParseInt(encMetadata[crypto.MetaOriginalSize], 10, 64); err == nil {
		h.recordPlaintextSize(r.Context(), bucket, key, plaintextSize{Size: n, Exact: true, Source: "original-size"})
	}

	if etag != "" {
		writeObjectHeaders(w, http.Header{"Etag": []string{etag}})
	}
	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation(r.Context(), "PutObject", bucket, time.Since(start))
}

// quoteETag serializes an opaque stored ETag as an HTTP entity-tag. Older
// encrypted objects may already contain quotes, so preserve that wire form.
func quoteETag(etag string) string {
	if etag == "" || (strings.HasPrefix(etag, "\"") && strings.HasSuffix(etag, "\"")) {
		return etag
	}
	return "\"" + etag + "\""
}

// cleanupMPUManifest removes the companion manifest only when the primary
// object is known to be an encrypted MPU object. Resolving the manifest's
// version first is required because an unversioned DELETE creates a marker on
// versioned buckets instead of removing the existing manifest version.
func (h *Handler) cleanupMPUManifest(ctx context.Context, client s3.Client, view *objectView) {
	if view == nil || (view.Class.Format != crypto.FormatMPUV1 && view.Class.Format != crypto.FormatMPUV2) {
		return
	}

	bucket := view.Bucket
	manifestKey := view.Class.ManifestKey
	manifestMetadata, err := client.HeadObject(ctx, bucket, manifestKey, nil)
	if err != nil {
		if !isS3NotFoundError(err) {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    manifestKey,
			}).Warn("Failed to inspect MPU manifest before cleanup")
		}
		return
	}

	var versionID *string
	if v := manifestMetadata["x-amz-version-id"]; v != "" {
		versionID = &v
	}
	if err := client.DeleteObject(ctx, bucket, manifestKey, versionID); err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    manifestKey,
		}).Warn("Failed to clean up MPU manifest companion object")
		return
	}

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
		"key":    manifestKey,
	}).Debug("Cleaned up MPU manifest companion object")
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
		h.writeObjectError(w, r, "DeleteObject", s3Err, start)
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

	// Read metadata before deleting the primary object. This adds one backend
	// request for ordinary deletes but avoids probing/deleting a manifest key
	// that cannot belong to a non-MPU object.
	var primaryView *objectView
	if metadata, headErr := s3Client.HeadObject(ctx, bucket, key, versionID); headErr == nil {
		primaryView, _ = h.loadObjectView(bucket, key, versionID, metadata)
	} else if !isS3NotFoundError(headErr) {
		h.logger.WithError(headErr).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Debug("Unable to inspect object metadata before delete")
	}

	err = s3Client.DeleteObject(ctx, bucket, key, versionID)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		h.writeObjectError(w, r, "DeleteObject", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to delete object")
		if h.auditLogger != nil {
			h.auditLogger.LogAccess("delete", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), false, err, time.Since(start))
		}
		return
	}

	// Invalidate cache for deleted object
	if h.cache != nil {
		h.cache.Delete(ctx, bucket, key)
	}

	// Clean up an MPU manifest only when the primary object identified itself as
	// encrypted MPU. The cleanup is best-effort and never changes the response.
	h.cleanupMPUManifest(ctx, s3Client, primaryView)

	// Evict from size cache.
	if h.sizeCache != nil {
		if cacheErr := h.sizeCache.Delete(ctx, bucket, key); cacheErr != nil {
			h.logger.WithError(cacheErr).Warn("handleDeleteObject: failed to evict size cache")
		}
	}

	// Audit logging
	if h.auditLogger != nil {
		h.auditLogger.LogAccess("delete", bucket, key, getClientIP(r), r.UserAgent(), getRequestID(r), true, nil, time.Since(start))
	}

	w.WriteHeader(http.StatusNoContent)
	h.metrics.RecordS3Operation(r.Context(), "DeleteObject", bucket, time.Since(start))
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
		h.writeObjectError(w, r, "HeadObject", s3Err, start)
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
		h.writeObjectError(w, r, "HeadObject", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to head object")
		return
	}
	rawMetadata := metadata
	view, viewErr := h.loadObjectView(bucket, key, versionID, rawMetadata)
	if viewErr != nil {
		h.writeObjectError(w, r, "HEAD", decryptFailure(viewErr, r.URL.Path), start)
		return
	}
	metadata = view.Expanded
	resolved, resolveErr := h.resolvePlaintextSize(ctx, s3Client, view)
	if resolveErr != nil {
		if h.writeObjectBackendError(w, r, "HeadObject", resolveErr, start) {
			return
		}
		if view.Class.Format != crypto.FormatMPUV1 && view.Class.Format != crypto.FormatMPUV2 {
			h.writeObjectError(w, r, "HEAD", decryptFailure(resolveErr, r.URL.Path), start)
			return
		}
		// Documented MPU-manifest exception: HEAD remains fail-soft and reports
		// the backend ciphertext length while GET and copy remain fail-closed.
		h.logger.WithError(resolveErr).WithFields(logrus.Fields{"bucket": bucket, "key": key}).Warn("HeadObject: failed to read MPU manifest for size translation; returning ciphertext size")
	} else if resolved.Exact {
		metadata["Content-Length"] = strconv.FormatInt(resolved.Size, 10)
	}
	if originalETag := metadata[crypto.MetaOriginalETag]; originalETag != "" {
		metadata["ETag"] = quoteETag(originalETag)
	}
	filteredMetadata := crypto.PlaintextMetadataView(metadata, -1, "")
	plainSize := int64(-1)
	if resolved.Exact && resolveErr == nil {
		plainSize = resolved.Size
	} else if !view.Class.Encrypted {
		if value, parseErr := strconv.ParseInt(rawMetadata["Content-Length"], 10, 64); parseErr == nil {
			plainSize = value
		}
	} else if view.Class.Format == crypto.FormatMPUV1 || view.Class.Format == crypto.FormatMPUV2 {
		// Documented fail-soft HEAD behavior for a missing MPU manifest.
		if value, parseErr := strconv.ParseInt(rawMetadata["Content-Length"], 10, 64); parseErr == nil {
			plainSize = value
		}
	}
	versionValue := ""
	if versionID != nil {
		versionValue = *versionID
	}
	projected, projectErr := projectObjectHeaders(objectResponseSource{Class: view.Class, Meta: metadata, Decrypted: filteredMetadata, PlainSize: plainSize, BackendETag: rawMetadata["ETag"]}, responseShape{Method: http.MethodHead, VersionID: versionValue})
	if projectErr != nil {
		h.writeObjectError(w, r, "HEAD", decryptFailure(projectErr, r.URL.Path), start)
		return
	}
	writeObjectHeaders(w, projected)

	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation(r.Context(), "HeadObject", bucket, time.Since(start))
}

// handleListObjects handles list objects requests.
func (h *Handler) handleListObjects(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		h.writeObjectError(w, r, "ListObjects", s3Err, start)
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
		h.writeObjectError(w, r, "ListObjects", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"prefix": prefix,
		}).Error("Failed to list objects")
		return
	}

	// MPU manifests are gateway-owned implementation details. Exposing them
	// through ListObjects makes mirror/sync clients treat them as user data and
	// delete them when the source does not contain the companion objects.
	listResult.Objects = filterMPUManifestObjects(listResult.Objects)
	for listResult.IsTruncated && len(listResult.Objects) < int(maxKeys) && listResult.NextContinuationToken != "" {
		nextOpts := opts
		nextOpts.ContinuationToken = listResult.NextContinuationToken
		nextOpts.StartAfter = ""
		nextPage, pageErr := s3Client.ListObjects(ctx, bucket, prefix, nextOpts)
		if pageErr != nil {
			break
		}
		listResult.Objects = append(listResult.Objects, filterMPUManifestObjects(nextPage.Objects)...)
		if len(listResult.Objects) >= int(maxKeys) {
			listResult.Objects = listResult.Objects[:int(maxKeys)]
			listResult.IsTruncated = true
			listResult.NextContinuationToken = nextPage.NextContinuationToken
			break
		}
		listResult.CommonPrefixes = append(listResult.CommonPrefixes, nextPage.CommonPrefixes...)
		listResult.NextContinuationToken = nextPage.NextContinuationToken
		listResult.IsTruncated = nextPage.IsTruncated
	}

	// Bypass buckets already store plaintext bytes, so backend sizes are
	// authoritative and no size-cache lookup or fallback HEAD is needed.
	// Skipping the entire translation pipeline also avoids unnecessary Valkey
	// traffic for buckets matched by disable_encryption policies.
	if h.policyManager != nil && h.policyManager.BucketDisablesEncryption(bucket) {
		nextMarker := ""
		if listResult.IsTruncated && len(listResult.Objects) > 0 {
			nextMarker = listResult.Objects[len(listResult.Objects)-1].Key
		}
		xmlResponse := generateListObjectsXML(bucket, prefix, delimiter, listResult.Objects, listResult.CommonPrefixes, listResult.NextContinuationToken, nextMarker, listResult.IsTruncated, int(maxKeys))
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(xmlResponse))
		h.metrics.RecordS3Operation(r.Context(), "ListObjects", bucket, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, http.StatusOK, time.Since(start), int64(len(xmlResponse)))
		return
	}

	// NOTE: ListObjects returns backend (ciphertext) sizes and ETags for
	// completed single-PUT encrypted objects. Per-object HEAD translation is
	// NOT done for the general case because it causes an N-fold latency
	// explosion (one HEAD per listed object).
	//
	// However, Docker Distribution's S3 storage driver calls ListObjects with
	// max-keys=1 (statList) to determine the byte size of a blob upload object
	// — both while the upload is in progress AND after CompleteMultipartUpload
	// (when statHead/HeadObject returns an AWS error). The returned <Size> is
	// compared against the in-memory plaintext byte counter (w.size), so any
	// ciphertext inflation causes "blob invalid length".
	//
	// Active encrypted uploads use their state-store plaintext sizes. Completed
	// objects are classified and resolved only when the configured bounded HEAD
	// fallback is enabled.
	//
	// We apply plaintext-size translation in two phases:
	//   Phase 1 – In-progress uploads: Valkey state store holds per-part
	//             PlainLen values; sum them up. This covers the PATCH path.
	//   Phase 2 – Completed uploads: Valkey state is deleted on Complete.
	//             Read TotalPlainSize from the companion .mpu-manifest object
	//             (written before CompleteMultipartUpload and durable in S3).
	//             This covers the PUT (validateBlob) path.
	// Both phases are fail-soft: on any error the original backend size is kept.
	activeMPUKeys := map[string]struct{}{}
	if h.mpuStateStore != nil && len(listResult.Objects) > 0 {
		// Phase 1: in-progress uploads via Valkey.
		if plainSizeByKey, lookupErr := h.listActiveMPUPlainSizes(ctx, bucket); lookupErr == nil {
			for objectKey := range plainSizeByKey {
				activeMPUKeys[objectKey] = struct{}{}
			}
			for i := range listResult.Objects {
				if ps, ok := plainSizeByKey[listResult.Objects[i].Key]; ok {
					listResult.Objects[i].Size = ps
				}
			}
		}

		// Completed uploads are resolved by lookupListObjectPlaintextSize below,
		// which classifies each object and delegates size and manifest policy to
		// the shared resolver. Avoid a second manifest-only policy here.
	}

	// Small stat-style pages preserve their established plaintext-size behavior.
	// Larger/general pages rely on exact write-time size cache entries or the
	// configured fallback HEAD batch to avoid unconditional N+1 backend calls.
	if len(listResult.Objects) > 0 && maxKeys <= 10 && (h.config == nil || h.config.ListSizeTranslate.FallbackHeadEnabled) {
		for i := range listResult.Objects {
			obj := &listResult.Objects[i]
			if _, isActiveMPU := activeMPUKeys[obj.Key]; isActiveMPU {
				continue
			}
			if ps, ok, translateErr := h.lookupListObjectPlaintextSize(ctx, bucket, obj.Key, obj.Size, s3Client); translateErr == nil && ok {
				obj.Size = ps
			} else if translateErr != nil && h.logger != nil {
				h.logger.WithError(translateErr).WithFields(logrus.Fields{"bucket": bucket, "key": obj.Key}).Warn("ListObjects: unable to resolve plaintext size; preserving backend size")
			}
		}
	}

	// Phase 3: size-cache resolution for general listings.
	// The size cache is populated only through recordPlaintextSize from an exact
	// resolver result or a plaintext backend length. Accept these write-time
	// values without per-object HEADs on general listing pages.
	if h.sizeCache != nil && h.config != nil && h.config.ListSizeTranslate.Enabled && len(listResult.Objects) > 0 {
		missKeys := make([]string, len(listResult.Objects))
		for i := range listResult.Objects {
			missKeys[i] = listResult.Objects[i].Key
		}

		cached, cacheErr := h.sizeCache.GetBatch(ctx, bucket, missKeys)
		if cacheErr != nil {
			h.logger.WithError(cacheErr).Warn("handleListObjects: size cache GetBatch failed; returning ciphertext sizes")
		} else {
			stillMissIdxs := make([]int, 0, len(listResult.Objects))
			stillMissKeys := make([]string, 0, len(listResult.Objects))
			for i := range listResult.Objects {
				if _, ok := activeMPUKeys[missKeys[i]]; ok {
					continue
				}
				if ps, ok := cached[missKeys[i]]; ok {
					listResult.Objects[i].Size = ps
					h.metrics.RecordListSizeCacheHit(ctx, bucket)
				} else {
					stillMissIdxs = append(stillMissIdxs, i)
					stillMissKeys = append(stillMissKeys, missKeys[i])
					h.metrics.RecordListSizeCacheMiss(ctx, bucket)
				}
			}

			// Fallback HEAD batch for unresolved misses (opt-in).
			if h.config.ListSizeTranslate.FallbackHeadEnabled && len(stillMissIdxs) > 0 {
				h.resolveListSizesByHead(ctx, bucket, listResult.Objects, stillMissIdxs, stillMissKeys, s3Client)
			}
		}
	}

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

// filterMPUManifestObjects removes gateway-owned MPU manifest objects from
// client-facing listings. The backend still stores them for internal reads.
func filterMPUManifestObjects(objects []s3.ObjectInfo) []s3.ObjectInfo {
	filtered := objects[:0]
	for _, object := range objects {
		if !strings.HasSuffix(object.Key, crypto.MPUManifestSuffix) {
			filtered = append(filtered, object)
		}
	}
	return filtered
}

// lookupListObjectPlaintextSize returns the plaintext size for list results
// when the backend object is known to be encrypted and its reported size is
// ciphertext. It is intentionally used only on small stat-style listings to
// avoid per-object HEAD amplification on large enumerations.
func (h *Handler) lookupListObjectPlaintextSize(ctx context.Context, bucket, key string, ciphertextSize int64, s3Client s3.Client) (int64, bool, error) {
	if ciphertextSize < 0 {
		return 0, false, nil
	}

	metadata, err := s3Client.HeadObject(ctx, bucket, key, nil)
	if err != nil {
		return 0, false, err
	}

	view, viewErr := h.loadObjectView(bucket, key, nil, metadata)
	if viewErr != nil {
		return 0, false, viewErr
	}
	size, sizeErr := h.resolvePlaintextSize(ctx, s3Client, view)
	if sizeErr != nil {
		if view.Class.Format == crypto.FormatMPUV1 || view.Class.Format == crypto.FormatMPUV2 {
			// Documented MPU-manifest fail-soft exception for HEAD and ListObjects.
			h.logger.WithError(sizeErr).WithFields(logrus.Fields{"bucket": bucket, "key": key}).Warn("ListObjects: failed to read MPU manifest for size translation; returning ciphertext size")
			return ciphertextSize, false, nil
		}
		return 0, false, sizeErr
	}
	if size.Exact && size.Size >= 0 {
		return size.Size, true, nil
	}

	return 0, false, nil
}

// clampEncryptedRangeEnd limits an optimised ciphertext range to the actual
// stored object length. The range calculator works with nominal full chunks,
// but the final encrypted chunk may be shorter than chunkSize+AEADTagSize.
// Requesting the nominal end from strict S3-compatible backends can produce a
// 416 response or a short read, typically exactly one 16-byte AEAD tag short.
func clampEncryptedRangeEnd(start, end int64, contentLength string) (int64, error) {
	if start < 0 || end < start {
		return 0, fmt.Errorf("invalid encrypted range %d-%d", start, end)
	}
	if contentLength == "" {
		return end, nil
	}
	ciphertextSize, err := strconv.ParseInt(contentLength, 10, 64)
	if err != nil || ciphertextSize <= 0 {
		return 0, fmt.Errorf("invalid ciphertext content length %q", contentLength)
	}
	if start >= ciphertextSize {
		return 0, fmt.Errorf("encrypted range starts beyond object size: %d >= %d", start, ciphertextSize)
	}
	if end >= ciphertextSize {
		end = ciphertextSize - 1
	}
	return end, nil
}

// handleHeadBucket handles HEAD bucket requests.

// resolveListSizesByHead issues bounded concurrent HeadObject calls for the
// given object indices, substitutes plaintext sizes into the response, and
// populates the size cache.
//
// Design: FallbackHeadTimeout governs how long we block the HTTP response
// waiting for HEAD results. Goroutines that do not complete within that
// deadline are NOT cancelled — they continue running in the background and
// write their resolved sizes to Valkey after the response is sent. This
// ensures a single listing pass fully warms the cache for all objects,
// regardless of how many there are relative to the deadline.
//
// The background goroutines use a detached context (not tied to the request)
// so they survive after the HTTP response is written and the request ctx is
// cancelled. They are bounded by FallbackHeadConcurrency and a generous
// background deadline (5 minutes) to prevent unbounded resource use.
func (h *Handler) resolveListSizesByHead(
	ctx context.Context,
	bucket string,
	objects []s3.ObjectInfo,
	idxs []int,
	keys []string,
	s3Client s3.Client,
) {
	cfg := h.config.ListSizeTranslate

	// responseCtx bounds how long we wait before returning the HTTP response.
	// Goroutines that miss this deadline still run to completion in background.
	responseCtx, responseCancel := context.WithTimeout(ctx, cfg.FallbackHeadTimeout)
	defer responseCancel()

	// bgCtx is detached from the request so background goroutines can write
	// to Valkey after the HTTP response is sent and ctx is cancelled.
	// A 5-minute hard cap prevents unbounded background work.
	bgCtx, bgCancel := context.WithTimeout(context.Background(), 5*time.Minute)

	sem := make(chan struct{}, cfg.FallbackHeadConcurrency)

	// resolved carries results that arrived before the response deadline.
	// It is buffered to the full length so goroutines never block on send.
	resolved := make(chan struct {
		idx int
		sz  int64
	}, len(idxs))

	var wg sync.WaitGroup
	for i, idx := range idxs {
		wg.Add(1)
		go func(i, idx int, key string, ciphertextSz int64) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Use bgCtx for the HEAD so the call survives after the HTTP response
			// is written and ctx is cancelled. This is the key property that allows
			// background goroutines to complete their HEAD+cache work even after the
			// response deadline has fired.
			ps, ok, err := h.lookupListObjectPlaintextSize(bgCtx, bucket, key, ciphertextSz, s3Client)

			var sizeToCache int64
			switch {
			case err != nil:
				// Network error or context cancelled — skip caching; retry next listing.
				h.metrics.RecordListSizeFallbackHead(ctx, bucket, "error")
				return
			case !ok:
				// HEAD succeeded but no encryption metadata — plaintext or unrecognised
				// format. The ciphertext size is the correct answer; cache it to avoid
				// HEADing this object on every future listing.
				h.metrics.RecordListSizeFallbackHead(ctx, bucket, "hit")
				sizeToCache = ciphertextSz
				ps = ciphertextSz
			default:
				h.metrics.RecordListSizeFallbackHead(ctx, bucket, "hit")
				sizeToCache = ps
			}

			// Write to cache immediately using bgCtx so the entry is persisted
			// regardless of whether responseCtx has already expired.
			h.recordPlaintextSize(bgCtx, bucket, key, plaintextSize{Size: sizeToCache, Exact: sizeToCache >= 0, Source: "original-size"})

			// Send to resolved only if the response deadline hasn't fired yet.
			// Non-blocking: if responseCtx is already done, drop — the response
			// has been sent and substituting the size is no longer possible.
			select {
			case <-responseCtx.Done():
				// Response already sent; size substitution not possible, cache write
				// already done above.
			default:
				resolved <- struct {
					idx int
					sz  int64
				}{idx: idx, sz: ps}
			}
		}(i, idx, keys[i], objects[idx].Size)
	}

	// Close bgCtx when all goroutines finish so its resources are released.
	go func() {
		wg.Wait()
		bgCancel()
		close(resolved)
	}()

	// Drain resolved channel until the response deadline fires or all
	// goroutines have reported back.
	for {
		select {
		case r, ok := <-resolved:
			if !ok {
				// All goroutines finished within the deadline.
				return
			}
			if r.sz > 0 {
				objects[r.idx].Size = r.sz
			}
		case <-responseCtx.Done():
			// Deadline reached — return the response with whatever resolved so far.
			// Background goroutines continue running and writing to cache.
			return
		}
	}
}

func (h *Handler) handleHeadBucket(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		h.writeObjectError(w, r, "HeadBucket", s3Err, start)
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
		h.writeObjectErrorForBucket(w, r, "HeadBucket", bucket, s3Err, start)
		// Log err here: TranslateError no longer echoes err into the response
		// body, so this is the only place the underlying diagnostic is
		// recorded for this code path.
		h.logger.WithError(err).WithField("bucket", bucket).Error("Failed to head bucket")
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
		h.writeObjectError(w, r, "CreateBucket", s3Err, start)
		return
	}

	h.logger.WithFields(logrus.Fields{
		"bucket": bucket,
	}).Debug("Handling bucket creation request")
	if !h.allowBucketCreation.Load() {
		s3Err := &S3Error{Code: "NotImplemented", Message: "Bucket creation is not supported.", Resource: r.URL.Path, HTTPStatus: http.StatusNotImplemented}
		h.writeObjectError(w, r, "CreateBucket", s3Err, start)
		h.auditManagement(r, "CreateBucket", bucket, false, s3Err)
		return
	}
	credential, authorized := CredentialFromContext(r)
	if !authorized || !credential.AllowsBucket(bucket) || !credential.HasBucketPermission(config.BucketPermissionCreate) || (h.config != nil && h.config.ProxiedBucket != "" && h.config.ProxiedBucket != bucket) {
		s3Err := &S3Error{Code: "AccessDenied", Message: "Access Denied", Resource: r.URL.Path, HTTPStatus: http.StatusForbidden}
		h.writeObjectError(w, r, "CreateBucket", s3Err, start)
		h.auditManagement(r, "CreateBucket", bucket, false, s3Err)
		return
	}
	if err := ValidateBucketName(bucket); err != nil {
		s3Err := &S3Error{Code: "InvalidBucketName", Message: err.Error(), Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		h.writeObjectError(w, r, "CreateBucket", s3Err, start)
		h.auditManagement(r, "CreateBucket", bucket, false, s3Err)
		return
	}
	h.handlePassthroughWithBodyLimit(w, r, "CreateBucket", bucket, "", 64<<10)
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
		h.writeObjectError(w, r, "CreateMultipartUpload", s3Err, start)
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
		h.writeObjectError(w, r, "CreateMultipartUpload", s3Err, start)
		return
	}

	// Fail closed if policy requires encrypted MPU but infra is missing.
	if h.mpuGuardMisconfig(w, r, bucket, "POST", start) {
		return
	}

	ctx := r.Context()
	writeMeta, writeMetaErr := parseWriteMetadata(r.Header)
	if writeMetaErr != nil {
		writeMetaErr.Resource = r.URL.Path
		h.writeObjectError(w, r, "CreateMultipartUpload", writeMetaErr, start)
		return
	}
	metadata := writeMeta.engineInput(0, false)
	if metadata["Content-Type"] == "" {
		metadata["Content-Type"] = "application/octet-stream"
	}

	// Get S3 client (may use client credentials if enabled)
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "POST", start)
		return
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
		var bindingID [16]byte
		if _, err := rand.Read(bindingID[:]); err != nil {
			s3Err := &S3Error{Code: "InternalError", Message: "Failed to generate multipart upload binding", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}
			h.writeObjectError(w, r, "CreateMultipartUpload", s3Err, start)
			return
		}
		setEncryptedMPUMarker(metadata, "v2")
		metadata[crypto.MetaObjectBindingID] = base64.RawURLEncoding.EncodeToString(bindingID[:])
		metadata[crypto.MetaFallbackMode] = "mpu"
		metadata[crypto.MetaFallbackPointer] = key + crypto.MPUManifestSuffix
	}
	var filterKeys []string
	if h.config != nil {
		filterKeys = h.config.Backend.FilterMetadataKeys
	}
	// Multipart payload encryption happens per-part. The initiation metadata's
	// standard fields are native S3 object headers and remain outside part
	// ciphertext, so plan the metadata as a passthrough header set.
	persist := buildPersistPlan(metadata, crypto.ObjectClass{}, filterKeys)
	persist.Native.ApplyTo(persist.Metadata)
	metadata = persist.Metadata

	uploadID, err := s3Client.CreateMultipartUpload(ctx, bucket, key, metadata, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		h.writeObjectError(w, r, "CreateMultipartUpload", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to create multipart upload")
		return
	}

	// When EncryptMultipartUploads is enabled for this bucket, generate a
	// per-upload DEK and persist state to Valkey before returning to the client.
	if h.mpuStateStore != nil {
		opStart := time.Now()
		var storeErr error
		if h.bucketEncryptsMPU(bucket) {
			binding, bindErr := base64.RawURLEncoding.DecodeString(metadata[crypto.MetaObjectBindingID])
			var bindingID [16]byte
			if bindErr != nil || len(binding) != 16 {
				storeErr = fmt.Errorf("invalid MPU binding metadata")
			} else {
				copy(bindingID[:], binding)
				storeErr = h.initMPUEncryptionState(ctx, uploadID, bucket, key, bindingID)
			}
		} else {
			storeErr = h.mpuStateStore.Create(ctx, &mpu.UploadState{
				UploadID: uploadID, Bucket: bucket, Key: key,
				PolicySnapshot: mpu.PolicySnapshot{EncryptMultipartUploads: false},
				CreatedAt:      time.Now().UTC(), StateVersion: mpu.CurrentStateVersion,
				Phase: mpu.UploadPhaseOpen, Revision: 1,
			})
		}
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
			h.writeObjectError(w, r, "CreateMultipartUpload", s3Err, start)
			return
		}

		h.metrics.RecordMPUEncrypted("success")
		if h.auditLogger != nil {
			_ = h.auditLogger.Log(&audit.AuditEvent{
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
	_ = xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation(r.Context(), "CreateMultipartUpload", bucket, time.Since(start))
}

// initMPUEncryptionState generates a DEK + IV prefix and persists UploadState
// to Valkey. Called only when BucketEncryptsMultipart(bucket)==true.
func (h *Handler) initMPUEncryptionState(ctx context.Context, uploadID, bucket, key string, bindingID [16]byte) error {
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
	if bindingID == [16]byte{} {
		return fmt.Errorf("invalid zero MPU binding ID")
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
		BindingID:      base64.RawURLEncoding.EncodeToString(bindingID[:]),
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
		StateVersion:   mpu.CurrentStateVersion,
		Phase:          mpu.UploadPhaseOpen,
		Revision:       1,
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

		// minio-go removes the quotes from UploadPart ETags before sending
		// CompleteMultipartUpload. Accept both wire forms, then retain the
		// canonical quoted form for the backend request.
		canonicalETag, ok := normalizeETag(part.ETag)
		if !ok {
			return &S3Error{
				Code:       "InvalidArgument",
				Message:    fmt.Sprintf("Invalid ETag format for part %d: %s", part.PartNumber, part.ETag),
				HTTPStatus: http.StatusBadRequest,
			}
		}
		part.ETag = canonicalETag
		req.Parts[i].ETag = canonicalETag

		// Check if parts are in ascending order (AWS requires this)
		if i > 0 && part.PartNumber < lastPartNumber {
			return &S3Error{
				Code:       "InvalidPartOrder",
				Message:    "The list of parts is not in ascending order",
				HTTPStatus: http.StatusBadRequest,
			}
		}
		lastPartNumber = part.PartNumber
	}

	return nil
}

// normalizeETag accepts either the quoted HTTP form or the unquoted value
// emitted by clients such as minio-go, and returns the canonical quoted form.
func normalizeETag(etag string) (string, bool) {
	if len(etag) >= 2 && strings.HasPrefix(etag, "\"") && strings.HasSuffix(etag, "\"") {
		if isValidETag(etag) {
			return etag, true
		}
		return "", false
	}
	if len(etag) == 0 || strings.Contains(etag, "\"") {
		return "", false
	}
	quoted := "\"" + etag + "\""
	if !isValidETag(quoted) {
		return "", false
	}
	return quoted, true
}

// isValidETag validates the canonical quoted ETag form and its contents.
func isValidETag(etag string) bool {
	if len(etag) < 2 || !strings.HasPrefix(etag, "\"") || !strings.HasSuffix(etag, "\"") {
		return false
	}

	// Basic validation: should contain only hex digits, dashes, and quotes
	inner := etag[1 : len(etag)-1]
	for _, r := range inner {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') && r != '-' {
			return false
		}
	}

	return len(inner) > 0
}

type encryptedMPUPartReservation struct {
	store       mpu.StateStore
	claim       mpu.PartClaim
	reservation mpu.Reservation
	plainBody   *s3.SeekableBody
	plainLen    int64
	reserved    bool
}

// reserveEncryptedMPUPart authenticates and reserves plaintext before any
// destination encryption or backend mutation. Keeping this boundary separate
// makes the nonce-safety ordering explicit without changing the HTTP handler's
// transport and backend responsibilities.
func (h *Handler) reserveEncryptedMPUPart(ctx context.Context, bucket, uploadID string, partNumber int32, inputReader io.Reader, state *mpu.UploadState) (encryptedMPUPartReservation, *S3Error) {
	plainBody, err := s3.NewSeekableBody(inputReader, effectiveMaxPartBuffer(h.config))
	if err != nil {
		code, status, msg := "InternalError", http.StatusInternalServerError, "Failed to read multipart upload part"
		if _, ok := err.(*s3.ErrPartTooLarge); ok {
			code, status, msg = "EntityTooLarge", http.StatusRequestEntityTooLarge, err.Error()
		}
		return encryptedMPUPartReservation{}, &S3Error{Code: code, Message: msg, HTTPStatus: status}
	}
	store := h.mpuStateStore
	if store == nil {
		return encryptedMPUPartReservation{plainBody: plainBody, plainLen: plainBody.Len}, nil
	}
	dek, err := h.unwrapMPUDEK(ctx, state, bucket, uploadID)
	if err != nil {
		return encryptedMPUPartReservation{}, &S3Error{Code: "InternalError", Message: "Failed to prepare multipart upload part", HTTPStatus: http.StatusInternalServerError}
	}
	claimBytes, err := mpu.ComputePartClaim(dek, partNumber, plainBody.Len, plainBody)
	zeroBytes(dek)
	if err != nil {
		return encryptedMPUPartReservation{}, &S3Error{Code: "InternalError", Message: "Failed to claim multipart upload part", HTTPStatus: http.StatusInternalServerError}
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return encryptedMPUPartReservation{}, &S3Error{Code: "InternalError", Message: "Failed to reserve multipart upload part", HTTPStatus: http.StatusInternalServerError}
	}
	claim := mpu.PartClaim{PartNumber: partNumber, Claim: base64.RawURLEncoding.EncodeToString(claimBytes[:]), PlainLen: plainBody.Len, Token: base64.RawURLEncoding.EncodeToString(tokenBytes)}
	reservation, err := store.ReservePart(ctx, uploadID, claim)
	if err != nil {
		code, status, msg := "ServiceUnavailable", http.StatusServiceUnavailable, "Multipart encryption state store unavailable; retry the part upload"
		switch {
		case errors.Is(err, mpu.ErrPartContentMismatch):
			code, status, msg = "OperationAborted", http.StatusConflict, "Encrypted multipart part content is immutable; abort this upload and create a new upload."
		case errors.Is(err, mpu.ErrPartInProgress):
			code, status, msg = "OperationAborted", http.StatusConflict, "A conflicting operation is in progress; retry the identical part request."
		case errors.Is(err, mpu.ErrInvalidStateVersion):
			code, status, msg = "OperationAborted", http.StatusConflict, "This encrypted multipart upload predates nonce-safety state; abort it and create a new upload."
		case errors.Is(err, mpu.ErrInvalidPhase):
			code, status, msg = "OperationAborted", http.StatusConflict, "Multipart upload lifecycle transition is in progress."
		}
		claimResult := "mismatch"
		if errors.Is(err, mpu.ErrPartInProgress) {
			claimResult = "lease_active"
		}
		if errors.Is(err, mpu.ErrInvalidStateVersion) {
			claimResult = "legacy_rejected"
		}
		h.metrics.RecordMPUPartClaim(claimResult)
		return encryptedMPUPartReservation{}, &S3Error{Code: code, Message: msg, HTTPStatus: status}
	}
	if reservation.AlreadyDone {
		h.metrics.RecordMPUPartClaim("identical")
		return encryptedMPUPartReservation{store: store, reservation: reservation, plainBody: plainBody, plainLen: plainBody.Len}, nil
	}
	if reservation.Reacquired {
		h.metrics.RecordMPUPartClaim("lease_reacquired")
	}
	h.metrics.RecordMPUPartClaim("reserved")
	if _, err := plainBody.Seek(0, io.SeekStart); err != nil {
		return encryptedMPUPartReservation{}, &S3Error{Code: "InternalError", Message: "Failed to prepare multipart upload part", HTTPStatus: http.StatusInternalServerError}
	}
	return encryptedMPUPartReservation{store: store, claim: claim, reservation: reservation, plainBody: plainBody, plainLen: plainBody.Len, reserved: true}, nil
}

// beginEncryptedMPUComplete atomically validates the exact client selection
// before a manifest is written or the backend Complete operation is issued.
func (h *Handler) beginEncryptedMPUComplete(ctx context.Context, uploadID string, req *CompleteMultipartUpload) (*mpu.UploadState, error) {
	selected := make([]mpu.SelectedPart, len(req.Parts))
	for i, part := range req.Parts {
		selected[i] = mpu.SelectedPart{PartNumber: part.PartNumber, ETag: part.ETag}
	}
	state, _, err := h.mpuStateStore.BeginComplete(ctx, uploadID, selected)
	return state, err
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
		h.writeObjectError(w, r, "UploadPart", s3Err, start)
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
		h.writeObjectError(w, r, "UploadPart", s3Err, start)
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
		h.writeObjectError(w, r, "UploadPart", s3Err, start)
		return
	}

	ctx := r.Context()

	var inputReader io.Reader = r.Body
	mode, modeErr := classifyStreamingPayloadMode(r.Header.Get("x-amz-content-sha256"))
	if modeErr != nil {
		writeStreamingPayloadError(w, r.URL.Path, modeErr)
		return
	}
	if mode != streamingNone {
		spool, verifyErr := verifyAndSpoolAWSBody(r, streamingContext(r), h.spoolManager, h.verifiedSpoolLimit(r))
		if verifyErr != nil {
			writeStreamingPayloadError(w, r.URL.Path, verifyErr)
			return
		}
		defer spool.Close()
		inputReader = spool
		// All downstream length calculations use verified bytes.
		r.Header.Set("Content-Length", strconv.FormatInt(spool.DecodedLength(), 10))
	}

	// Verify and spool streaming bodies before backend, cache, or MPU state work.
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	// Default: no encryption layer added here (plaintext parts per ADR 0002, or
	// encrypted per-upload DEK below when the upload has a Valkey state record).
	var encryptedReader io.Reader
	var contentLengthPtr *int64
	// encMPUState is non-nil only for encrypted MPU parts; used after UploadPart
	// to record the PartRecord without a second Valkey round-trip.
	var encMPUState *mpu.UploadState
	var encMPUPlainLen int64
	var encMPUEncryptDuration time.Duration
	var encMPUClaimStore mpu.StateStore
	var encMPUClaim mpu.PartClaim
	var encMPUReservation mpu.Reservation
	var encMPUReserved bool
	preUploadReservationOwned := false
	defer func() {
		if preUploadReservationOwned && encMPUClaimStore != nil {
			// Pre-upload failures have a deterministic outcome. Cleanup errors
			// must not replace the original HTTP error.
			_ = encMPUClaimStore.ReleasePart(ctx, uploadID, encMPUClaim.PartNumber, encMPUReservation.Token)
		}
	}()

	if uploadState, stateErr := h.uploadState(ctx, uploadID); stateErr != nil {
		if h.writeMissingMPUState(w, r, stateErr) {
			return
		}
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
		if h.auditLogger != nil {
			_ = h.auditLogger.Log(&audit.AuditEvent{
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
		h.writeObjectError(w, r, "UploadPart", s3Err, start)
		return
	} else if uploadState != nil && uploadState.PolicySnapshot.EncryptMultipartUploads {
		if identityErr := validateMPURouteIdentity(uploadState, bucket, key); identityErr != nil {
			h.writeObjectError(w, r, "UploadPart", (&S3Error{Code: "NoSuchUpload", Message: identityErr.Error(), Resource: r.URL.Path, HTTPStatus: http.StatusNotFound}), start)
			return
		}
		// Encrypted multipart path — decision based on PolicySnapshot stored at
		// CreateMultipartUpload, not live policy (ADR-0009 §Security Considerations).
		// reserveEncryptedMPUPart buffers the plaintext and derives its exact
		// length before encryption, including AWS chunked requests.
		var plainLen int64

		// Claim the exact plaintext before constructing the encryptor or touching
		// the destination backend. Version-2 stores make replacement immutable.
		reserved, reserveErr := h.reserveEncryptedMPUPart(ctx, bucket, uploadID, int32(partNumber), inputReader, uploadState)
		if reserveErr != nil {
			reserveErr.Resource = r.URL.Path
			h.writeObjectError(w, r, "UploadPart", reserveErr, start)
			return
		}
		if reserved.reservation.AlreadyDone {
			writeObjectHeaders(w, http.Header{"Etag": []string{reserved.reservation.CommittedETag}})
			w.WriteHeader(http.StatusOK)
			return
		}
		encMPUClaimStore, encMPUClaim, encMPUReservation = reserved.store, reserved.claim, reserved.reservation
		encMPUReserved = reserved.reserved
		preUploadReservationOwned = reserved.reserved
		inputReader = reserved.plainBody
		plainLen = reserved.plainLen

		// Pass the pre-fetched state to avoid a second Valkey round-trip inside encryptMPUPart.
		encryptStart := time.Now()
		var encReader io.Reader
		var encLen int64
		if h.destinationEncryptionReader != nil {
			encReader, encLen, err = h.destinationEncryptionReader(inputReader, plainLen)
		} else {
			encReader, encLen, err = h.encryptMPUPartWithState(ctx, bucket, key, uploadID, int32(partNumber), inputReader, plainLen, uploadState)
		}
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
			h.writeObjectError(w, r, "UploadPart", s3Err, start)
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
			h.writeObjectError(w, r, "UploadPart", s3Err, start)
			return
		}
		encryptedReader = sb
		contentLengthPtr = &encLen
		// Hoist state into outer scope so CommitPart can use it without a
		// second Valkey round-trip after UploadPart succeeds.
		encMPUState = uploadState
		encMPUPlainLen = plainLen
		lease := 2 * time.Minute
		if h.config != nil && h.config.MultipartState.ReservationLease > 0 {
			lease = h.config.MultipartState.ReservationLease
		}
		if encMPUEncryptDuration >= lease/4 {
			if renewErr := encMPUClaimStore.RenewPart(ctx, uploadID, encMPUClaim.PartNumber, encMPUReservation.Token); renewErr != nil {
				h.writeObjectError(w, r, "UploadPart", (&S3Error{Code: "ServiceUnavailable", Message: "Multipart encryption state store unavailable; retry the part upload", Resource: r.URL.Path, HTTPStatus: http.StatusServiceUnavailable}), start)
				return
			}
			h.metrics.RecordMPUPartClaim("lease_renewed")
		}
	} else {
		// Plaintext multipart path (ADR 0002): buffer to make body seekable for
		// the AWS SDK's retry behaviour.
		// V0.6-PERF-1 Phase D: use pooled seekable wrapper instead of io.ReadAll.
		maxBuf := effectiveMaxPartBuffer(h.config)
		sb, sbErr := s3.NewSeekableBody(inputReader, maxBuf)
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
			h.writeObjectError(w, r, "UploadPart", s3Err, start)
			return
		}
		encryptedReader = sb
		partSize := sb.Len
		contentLengthPtr = &partSize
	}

	etag, err := s3Client.UploadPart(ctx, bucket, key, uploadID, int32(partNumber), encryptedReader, contentLengthPtr)
	// UploadPart has started, so its result is uncertain. Preserve the exact
	// reservation for reconciliation instead of allowing nonce reuse.
	preUploadReservationOwned = false
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		h.writeObjectError(w, r, "UploadPart", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":     bucket,
			"key":        key,
			"uploadID":   uploadID,
			"partNumber": partNumber,
		}).Error("Failed to upload part")
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
		chunkCount64, countErr := crypto.ChunkedDataChunkCount(encMPUPlainLen, crypto.DefaultChunkSize)
		if countErr != nil || chunkCount64 > uint64(^uint32(0)>>1) {
			h.writeObjectError(w, r, "UploadPart", (&S3Error{Code: "InternalError", Message: "Invalid encrypted multipart part size", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}), start)
			return
		}
		chunkCount := int32(chunkCount64)
		if encMPUClaimStore != nil && encMPUReserved {
			encMPUClaim.ETag, encMPUClaim.EncLen, encMPUClaim.ChunkCount = etag, *contentLengthPtr, chunkCount
			if commitErr := encMPUClaimStore.CommitPart(ctx, uploadID, encMPUClaim); commitErr != nil {
				// Do not release a reservation after an uncertain commit. Releasing
				// could permit a changed plaintext to reuse the deterministic nonce
				// schedule; the upload must be aborted if ownership is ambiguous.
				h.writeObjectError(w, r, "UploadPart", (&S3Error{Code: "ServiceUnavailable", Message: "Multipart encryption state store unavailable; retry the part upload", Resource: r.URL.Path, HTTPStatus: http.StatusServiceUnavailable}), start)
				return
			}
			h.metrics.RecordMPUPart("success")
			h.metrics.RecordEncryptionOperation(r.Context(), "encrypt", encMPUEncryptDuration, encMPUPlainLen)
			if h.auditLogger != nil {
				_ = h.auditLogger.Log(&audit.AuditEvent{
					EventType: audit.EventTypeMPUPart,
					Timestamp: time.Now().UTC(),
					Bucket:    bucket,
					Key:       key,
					Success:   true,
					Metadata:  map[string]interface{}{"upload_id": uploadID},
				})
			}
		}
	}

	writeObjectHeaders(w, http.Header{"Etag": []string{etag}})
	w.WriteHeader(http.StatusOK)
	h.metrics.RecordS3Operation(r.Context(), "UploadPart", bucket, time.Since(start))
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
		h.writeObjectError(w, r, "CompleteMultipartUpload", s3Err, start)
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
		h.writeObjectError(w, r, "CompleteMultipartUpload", s3Err, start)
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
		h.writeObjectError(w, r, "CompleteMultipartUpload", s3Err, start)
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
		h.writeObjectError(w, r, "CompleteMultipartUpload", s3Err, start)
		return
	}

	// For encrypted MPU: consult the PolicySnapshot stored at Create time so
	// a policy flip mid-upload cannot cause the manifest to be skipped or
	// written for an upload that was never encrypted (ADR-0009).
	completeState, completeStateErr := h.uploadState(ctx, uploadID)
	if completeStateErr != nil {
		if h.writeMissingMPUState(w, r, completeStateErr) {
			return
		}
		h.logger.WithError(completeStateErr).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("mpu.state.unavailable: cannot determine encryption state at Complete; failing closed")
		if h.auditLogger != nil {
			_ = h.auditLogger.Log(&audit.AuditEvent{
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
		h.writeObjectError(w, r, "CompleteMultipartUpload", s3Err, start)
		return
	}
	completeIsEnc := completeState != nil && completeState.PolicySnapshot.EncryptMultipartUploads
	if completeIsEnc {
		if identityErr := validateMPURouteIdentity(completeState, bucket, key); identityErr != nil {
			h.writeObjectError(w, r, "CompleteMultipartUpload", (&S3Error{Code: "NoSuchUpload", Message: identityErr.Error(), Resource: r.URL.Path, HTTPStatus: http.StatusNotFound}), start)
			return
		}
		if claimStore := h.mpuStateStore; claimStore != nil {
			var beginErr error
			completeState, beginErr = h.beginEncryptedMPUComplete(ctx, uploadID, completeReq)
			if beginErr != nil {
				code, status := "InvalidPart", http.StatusBadRequest
				if errors.Is(beginErr, mpu.ErrInvalidPhase) || errors.Is(beginErr, mpu.ErrInvalidStateVersion) || errors.Is(beginErr, mpu.ErrRevisionConflict) {
					code, status = "OperationAborted", http.StatusConflict
				}
				h.writeObjectError(w, r, "CompleteMultipartUpload", (&S3Error{Code: code, Message: "The selected parts do not match committed encrypted MPU state", Resource: r.URL.Path, HTTPStatus: status}), start)
				return
			}
		}
		if manifestErr := h.writeMPUManifestObject(ctx, uploadID, bucket, key, s3Client, completeState); manifestErr != nil {
			if claimStore := h.mpuStateStore; claimStore != nil && completeState != nil {
				_ = claimStore.Reopen(ctx, uploadID, completeState.Revision)
			}
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
			h.writeObjectError(w, r, "CompleteMultipartUpload", s3Err, start)
			return
		}

		if h.auditLogger != nil {
			_ = h.auditLogger.Log(&audit.AuditEvent{
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
		if completeIsEnc {
			if claimStore := h.mpuStateStore; claimStore != nil && completeState != nil {
				_ = claimStore.Reopen(ctx, uploadID, completeState.Revision)
			}
		}
		s3Err := TranslateError(err, bucket, key)
		h.writeObjectError(w, r, "CompleteMultipartUpload", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to complete multipart upload")
		return
	}

	// Clean up Valkey state after successful completion.
	if completeIsEnc {
		if claimStore := h.mpuStateStore; claimStore != nil && completeState != nil {
			if finalizeErr := claimStore.FinalizeComplete(ctx, uploadID, completeState.Revision); finalizeErr != nil {
				code, status := "ServiceUnavailable", http.StatusServiceUnavailable
				if errors.Is(finalizeErr, mpu.ErrRevisionConflict) {
					code, status = "OperationAborted", http.StatusConflict
				}
				h.writeObjectError(w, r, "CompleteMultipartUpload", (&S3Error{Code: code, Message: "Multipart upload lifecycle finalization failed.", Resource: r.URL.Path, HTTPStatus: status}), start)
				return
			}
		}
		if delErr := h.mpuStateStore.Delete(ctx, uploadID); delErr != nil {
			h.logger.WithError(delErr).WithField("uploadID", uploadID).
				Warn("Failed to delete MPU state after completion")
		}
	} else if completeState != nil && h.mpuStateStore != nil {
		if delErr := h.mpuStateStore.Delete(ctx, uploadID); delErr != nil {
			h.logger.WithError(delErr).WithField("uploadID", uploadID).Warn("mpu.complete: failed to delete plaintext routing state")
		}
	}

	// Populate the size cache after a successful complete so subsequent
	// ListObjects can resolve the plaintext size without a HEAD request.
	if completeState != nil {
		var totalPlain int64
		for _, p := range completeState.Parts {
			totalPlain += p.PlainLen
		}
		h.recordPlaintextSize(ctx, bucket, key, plaintextSize{Size: totalPlain, Exact: totalPlain >= 0, Source: "mpu-manifest"})
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
	_ = xml.NewEncoder(w).Encode(result)

	h.metrics.RecordS3Operation(r.Context(), "CompleteMultipartUpload", bucket, time.Since(start))
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
		h.writeObjectError(w, r, "AbortMultipartUpload", s3Err, start)
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
		h.writeObjectError(w, r, "AbortMultipartUpload", s3Err, start)
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
	var abortStore mpu.StateStore
	var abortRevision uint64
	var abortState *mpu.UploadState
	if store := h.mpuStateStore; store != nil {
		state, stateErr := h.uploadState(ctx, uploadID)
		if stateErr != nil {
			if h.writeMissingMPUState(w, r, stateErr) {
				return
			}
		}
		abortState = state
		if state != nil && state.PolicySnapshot.EncryptMultipartUploads {
			abortStore = store
			abortRevision, err = store.BeginAbort(ctx, uploadID)
			if err != nil {
				if errors.Is(err, mpu.ErrRevisionConflict) || errors.Is(err, mpu.ErrInvalidPhase) || errors.Is(err, mpu.ErrInvalidStateVersion) {
					h.writeObjectError(w, r, "AbortMultipartUpload", (&S3Error{Code: "OperationAborted", Message: "Multipart upload lifecycle transition is in progress.", Resource: r.URL.Path, HTTPStatus: http.StatusConflict}), start)
					return
				}
				h.writeObjectError(w, r, "AbortMultipartUpload", (&S3Error{Code: "OperationAborted", Message: "Multipart upload lifecycle transition is in progress.", Resource: r.URL.Path, HTTPStatus: http.StatusConflict}), start)
				return
			}
		}
	}

	err = s3Client.AbortMultipartUpload(ctx, bucket, key, uploadID)
	if err != nil {
		if abortStore != nil {
			if reopenErr := abortStore.Reopen(ctx, uploadID, abortRevision); reopenErr != nil && !errors.Is(reopenErr, mpu.ErrUploadNotFound) {
				// Reopen is revision-guarded. A conflict means another lifecycle
				// operation won; retain the original backend error for the client.
				h.logger.WithError(reopenErr).WithFields(logrus.Fields{
					"bucket":   bucket,
					"key":      key,
					"uploadID": uploadID,
				}).Warn("mpu.abort: failed to reopen state after backend abort failure")
			}
		}
		s3Err := TranslateError(err, bucket, key)
		h.writeObjectError(w, r, "AbortMultipartUpload", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to abort multipart upload")
		return
	}
	if abortStore != nil {
		if finalizeErr := abortStore.FinalizeAbort(ctx, uploadID, abortRevision); finalizeErr != nil && !errors.Is(finalizeErr, mpu.ErrUploadNotFound) {
			h.logger.WithError(finalizeErr).Warn("mpu.abort: failed to finalize state transition")
			code, status := "ServiceUnavailable", http.StatusServiceUnavailable
			if errors.Is(finalizeErr, mpu.ErrRevisionConflict) {
				code, status = "OperationAborted", http.StatusConflict
			}
			h.writeObjectError(w, r, "AbortMultipartUpload", (&S3Error{Code: code, Message: "Multipart upload lifecycle finalization failed.", Resource: r.URL.Path, HTTPStatus: status}), start)
			return
		}
		if delErr := abortStore.Delete(ctx, uploadID); delErr != nil {
			h.logger.WithError(delErr).Warn("mpu.abort.orphan: failed to delete MPU state after finalized abort")
		}
		if h.auditLogger != nil {
			_ = h.auditLogger.Log(&audit.AuditEvent{
				EventType: audit.EventTypeMPUAbort,
				Timestamp: time.Now().UTC(),
				Bucket:    bucket,
				Key:       key,
				Success:   true,
				Metadata:  map[string]interface{}{"upload_id": uploadID},
			})
		}
	} else if abortState != nil {
		if delErr := h.mpuStateStore.Delete(ctx, uploadID); delErr != nil {
			h.logger.WithError(delErr).WithField("uploadID", uploadID).Warn("mpu.abort: failed to delete plaintext routing state")
		}
	}

	w.WriteHeader(http.StatusNoContent)
	h.metrics.RecordS3Operation(r.Context(), "AbortMultipartUpload", bucket, time.Since(start))
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
	return h.encryptMPUPartWithState(ctx, bucket, state.Key, uploadID, partNumber, body, plainLen, state)
}

// encryptMPUPartWithState encrypts one MPU part using a pre-fetched UploadState,
// avoiding a redundant Valkey Get when the caller already holds the state.
func (h *Handler) encryptMPUPartWithState(ctx context.Context, bucket, key, uploadID string, partNumber int32, body io.Reader, plainLen int64, state *mpu.UploadState) (io.Reader, int64, error) {
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
	if h.destinationEncryptionConstructed != nil {
		h.destinationEncryptionConstructed()
	}
	var bindingID [16]byte
	decoded, hasBinding, bindErr := state.BindingIDBytes()
	if bindErr != nil {
		return nil, 0, fmt.Errorf("encryptMPUPart: invalid binding ID: %w", bindErr)
	}
	if !hasBinding {
		return nil, 0, fmt.Errorf("encryptMPUPart: legacy MPU state cannot encrypt a new part (upload=%s key=%s binding=%q)", state.UploadID, state.Key, state.BindingID)
	}
	bindingID = decoded
	encReader, encLen, err := crypto.NewMPUPartEncryptReader(ctx, crypto.ObjectContext{Bucket: bucket, Key: key}, bindingID, body, dek, uploadIDHash, ivPrefix, partNumber, state.ChunkSize, plainLen, state.Algorithm)
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
	readPlan, err := h.planObjectRead(ctx, s3Client, bucket, key, versionID, headMeta, &rangeHeader)
	if err != nil {
		h.writeObjectDecryptError(w, r, "GetObject", bucket, key, err, start)
		return
	}
	h.serveMPURangedGetPlanned(w, r, bucket, key, versionID, readPlan, s3Client, start)
}

func (h *Handler) serveMPURangedGetPlanned(
	w http.ResponseWriter,
	r *http.Request,
	bucket, key string,
	versionID *string,
	readPlan objectReadPlan,
	s3Client s3.Client,
	start time.Time,
) {
	ctx := r.Context()
	var err error
	loaded := readPlan.MPUManifest
	if !readPlan.validMPURange() {
		h.writeObjectError(w, r, "GET", decryptFailure(fmt.Errorf("object is not an MPU"), r.URL.Path), start)
		return
	}
	manifest := loaded.Manifest

	if h.serveUnsatisfiedObjectRange(w, r, readPlan, start) {
		return
	}
	pStart, pEnd := readPlan.RangeStart, readPlan.RangeEnd

	rangeResult := *readPlan.MPURange

	// ── 4. Fetch only the needed ciphertext bytes ────────────────────────────
	objReader, _, err := s3Client.GetObject(ctx, bucket, key, versionID, readPlan.BackendRange)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		h.writeObjectError(w, r, "GetObject", s3Err, start)
		return
	}
	defer objReader.Close()

	// ── 5. Unwrap DEK ────────────────────────────────────────────────────────
	dek, err := h.unwrapMPUDEKFromManifest(ctx, manifest, bucket, key)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: unwrap DEK")
		h.writeObjectDecryptError(w, r, "GetObject", bucket, key, err, start)
		return
	}
	defer zeroBytes(dek)

	ivPrefix, err := hexToIVPrefix(manifest.IVPrefix)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: decode iv prefix")
		h.writeObjectDecryptError(w, r, "GetObject", bucket, key, err, start)
		return
	}
	uploadIDHash, err := decodeBase64ToFixed32(manifest.UploadIDHash)
	if err != nil {
		h.logger.WithError(err).Error("serveMPURangedGet: decode upload id hash")
		h.writeObjectDecryptError(w, r, "GetObject", bucket, key, err, start)
		return
	}

	// ── 6. Decrypt affected chunks through the shared body owner ──────────────
	// The reader authenticates one chunk at a time and retains at most that
	// chunk's plaintext. serveObjectBody performs the first-output read-ahead
	// before committing 206, then owns the entire stream and its accounting.
	var plaintextOffset int64
	for i := 0; i < rangeResult.PartStartIdx; i++ {
		plaintextOffset += manifest.Parts[i].PlainLen
	}
	plaintextOffset += int64(rangeResult.ChunkStart) * int64(manifest.ChunkSize)
	firstPart := manifest.Parts[rangeResult.PartStartIdx]
	firstChunkPlainLen := int64(manifest.ChunkSize)
	if rangeResult.ChunkStart == firstPart.ChunkCount-1 {
		firstChunkPlainLen = firstPart.PlainLen - int64(rangeResult.ChunkStart)*int64(manifest.ChunkSize)
	}
	firstChunkEnd := plaintextOffset + firstChunkPlainLen - 1
	firstWriteStart := max(pStart, plaintextOffset)
	firstWriteEnd := pEnd
	if firstWriteEnd > firstChunkEnd {
		firstWriteEnd = firstChunkEnd
	}
	preflightLimit := firstWriteEnd - firstWriteStart + 1

	body := &mpuPlaintextRangeReader{
		ciphertext:  objReader,
		manifest:    manifest,
		rangeResult: rangeResult,
		rangeStart:  pStart,
		rangeEnd:    pEnd,
		plainOffset: plaintextOffset,
		partIndex:   rangeResult.PartStartIdx,
		chunkIndex:  rangeResult.ChunkStart,
		object:      crypto.ObjectContext{Bucket: bucket, Key: key},
		dek:         dek,
		uploadHash:  uploadIDHash,
		ivPrefix:    ivPrefix,
		decrypt:     readPlan.MPUDecrypt,
	}
	readPlan = readPlan.withExecutionResponse(r, readPlan.Source.Decrypted, readPlan.Size.Size, readPlan.Source.BackendETag, body)
	readPlan.PreflightBody = true
	readPlan.PreflightLimit = preflightLimit
	readPlan.Started = start
	readPlan.OperationStarted = start
	if _, err := h.serveObjectBody(w, r, readPlan); err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{"bucket": bucket, "key": key}).Error("serveMPURangedGet: failed to stream plaintext range")
	}
}

// writeMPUManifestObject builds the MultipartManifest from Valkey state and
// writes it as a companion object at <key>.mpu-manifest. The final object's
// metadata carries x-amz-meta-encrypted-mpu=true and the pointer set at
// CreateMultipartUpload time.
func (h *Handler) writeMPUManifestObject(ctx context.Context, uploadID, bucket, key string, s3Client s3.Client, snapshot *mpu.UploadState) error {
	opStart := time.Now()
	state := snapshot
	var err error
	if state == nil {
		state, err = h.mpuStateStore.Get(ctx, uploadID)
		if err != nil {
			h.metrics.RecordMPUStateStoreOp("Get", "error", time.Since(opStart))
			return fmt.Errorf("writeMPUManifest: get state: %w", err)
		}
		h.metrics.RecordMPUStateStoreOp("Get", "success", time.Since(opStart))
	}

	// Sort parts by part number for determinism.
	sortedParts := sortedPartRecords(state.Parts)
	mpuParts := make([]crypto.MPUPartRecord, len(sortedParts))
	var totalPlain int64
	for i, p := range sortedParts {
		if p.PlainLen < 0 || p.PlainLen > math.MaxInt64-totalPlain {
			return fmt.Errorf("writeMPUManifest: invalid or overflowing plaintext total")
		}
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
		Version:         2,
		ParentBucket:    bucket,
		ParentKey:       key,
		CompanionBucket: bucket,
		CompanionKey:    key + crypto.MPUManifestSuffix,
		BindingID:       state.BindingID,
		Algorithm:       state.Algorithm,
		ChunkSize:       state.ChunkSize,
		IVPrefix:        state.IVPrefixHex,
		UploadIDHash:    state.UploadIDHash,
		WrappedDEK:      state.WrappedDEK,
		KMSKeyID:        state.KMSKeyID,
		KMSProvider:     state.KMSProvider,
		KMSKeyVersion:   state.KMSKeyVersion,
		Parts:           mpuParts,
		TotalPlainSize:  totalPlain,
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
	var bindingID [16]byte
	b, bindErr := base64.RawURLEncoding.DecodeString(state.BindingID)
	if bindErr != nil || len(b) != 16 {
		return fmt.Errorf("writeMPUManifest: invalid binding ID")
	}
	copy(bindingID[:], b)
	encBytes, encMeta, err := crypto.EncryptMPUManifest(ctx, engine, crypto.ObjectContext{Bucket: bucket, Key: key + crypto.MPUManifestSuffix}, bindingID, manifestJSON)
	encryptDuration := time.Since(encryptStart)
	if err != nil {
		return fmt.Errorf("writeMPUManifest: encrypt manifest: %w", err)
	}
	h.metrics.RecordEncryptionOperation(ctx, "encrypt", encryptDuration, manifestPlainLen)

	// Buffer the encrypted output so we can set Content-Length precisely.
	companionKey := key + crypto.MPUManifestSuffix
	encLen := int64(len(encBytes))
	_, err = s3Client.PutObject(ctx, bucket, companionKey, bytes.NewReader(encBytes), encMeta, &encLen, "", nil, "", "", "", "", "")
	return err
}

// unwrapMPUDEK unwraps the DEK stored in UploadState using the KeyManager.
// Returns an error if the KeyManager is absent — encrypted MPU state must
// never be readable without KMS cooperation (fail-closed).
func (h *Handler) unwrapMPUDEK(ctx context.Context, state *mpu.UploadState, bucket, uploadID string) ([]byte, error) {
	if err := state.ValidateEncryptedCryptoMaterial(); err != nil {
		return nil, err
	}
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
	var loaded *loadedMPUManifest
	var loadErr error
	if view, viewErr := h.loadObjectView(bucket, key, nil, metadata); viewErr != nil {
		loadErr = viewErr
	} else {
		loaded, loadErr = h.loadMPUManifest(ctx, s3Client, bucket, key, view.Class)
	}
	if loadErr != nil {
		return nil, loadErr
	}
	return h.decryptMPUObjectWithManifest(ctx, bucket, key, reader, loaded)
}

func (h *Handler) decryptMPUObjectWithManifest(ctx context.Context, bucket, key string, reader io.ReadCloser, loaded *loadedMPUManifest) (io.Reader, error) {
	if loaded == nil || loaded.Manifest == nil {
		return nil, ErrMissingMPUManifest
	}
	{
		manifest := loaded.Manifest
		dek, err := h.unwrapMPUDEKFromManifest(ctx, manifest, bucket, key)
		if err != nil {
			return nil, fmt.Errorf("decryptMPUObject: unwrap DEK: %w", err)
		}
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
		var inner io.Reader
		if loaded.IsV2 {
			inner, err = crypto.NewMPUDecryptReader(crypto.ObjectContext{Bucket: bucket, Key: key}, loaded.BindingID, reader, manifest, dek, uploadIDHash, ivPrefix, manifest.Algorithm)
		} else {
			inner, err = crypto.NewMPUDecryptReaderV1(crypto.ObjectContext{Bucket: bucket, Key: key}, reader, manifest, dek, uploadIDHash, ivPrefix, manifest.Algorithm)
		}
		if err != nil {
			zeroBytes(dek)
			return nil, fmt.Errorf("decryptMPUObject: create decrypt reader: %w", err)
		}
		return &mpuDecryptCloser{Reader: inner, dek: dek}, nil
	}

}

// listActiveMPUPlainSizes returns a map of S3 object key → total plaintext
// bytes uploaded so far for all in-progress encrypted multipart uploads in
// the given bucket. It is used by handleListObjects to substitute correct
// plaintext sizes for in-progress MPU data objects when S3/Ceph would
// otherwise report ciphertext (inflated) sizes.
//
// The returned map is empty when there are no active encrypted MPU uploads.
// Errors are returned to the caller, which treats them as non-fatal.
// listActiveMPUPlainSizes returns a map of S3 object key → total plaintext
// bytes uploaded so far for all in-progress encrypted multipart uploads in
// the given bucket. It is used by handleListObjects to substitute correct
// plaintext sizes for in-progress MPU data objects when S3/Ceph would
// otherwise report ciphertext (inflated) sizes.
//
// The returned map is empty when there are no active encrypted MPU uploads.
// Errors are returned to the caller, which treats them as non-fatal.
func (h *Handler) listActiveMPUPlainSizes(ctx context.Context, bucket string) (map[string]int64, error) {
	if h.mpuStateStore == nil {
		return nil, nil
	}
	// List() returns UploadState records without part details (parts are stored
	// in separate hash fields). We call Get() for each matching state to
	// reconstruct the full PartRecord list including PlainLen values.
	states, err := h.mpuStateStore.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listActiveMPUPlainSizes: list: %w", err)
	}
	if len(states) == 0 {
		return nil, nil
	}
	result := make(map[string]int64, len(states))
	for _, summary := range states {
		if summary.Bucket != bucket {
			continue
		}
		// Fetch full state to get per-part PlainLen values.
		full, getErr := h.mpuStateStore.Get(ctx, summary.UploadID)
		if getErr != nil || full == nil || len(full.Parts) == 0 {
			continue
		}
		var total int64
		for _, p := range full.Parts {
			total += p.PlainLen
		}
		result[full.Key] = total
	}
	return result, nil
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
		h.writeObjectError(w, r, "ListParts", s3Err, start)
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
		h.writeObjectError(w, r, "ListParts", s3Err, start)
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
		h.writeObjectError(w, r, "ListParts", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket":   bucket,
			"key":      key,
			"uploadID": uploadID,
		}).Error("Failed to list parts")
		return
	}

	// For encrypted MPU uploads, Ceph stores encrypted part sizes but clients
	// like Docker Distribution track plaintext offsets. We have the per-upload
	// plaintext sizes in Valkey; substitute them so the client sees consistent
	// sizes.
	var plainLenByPart map[int32]int64
	if h.mpuStateStore != nil {
		if uploadState, err := h.mpuStateStore.Get(ctx, uploadID); err == nil && uploadState != nil && len(uploadState.Parts) > 0 {
			plainLenByPart = make(map[int32]int64, len(uploadState.Parts))
			for _, pr := range uploadState.Parts {
				plainLenByPart[pr.PartNumber] = pr.PlainLen
			}
		}
	}

	// Generate XML response. The response must include IsTruncated (always,
	// even when false). Some S3-compatible consumers (e.g. Docker Distribution's
	// S3 driver) dereference IsTruncated without nil checks, so omitting it
	// causes a nil-pointer panic on the client side.
	type PartElement struct {
		PartNumber   int32  `xml:"PartNumber"`
		ETag         string `xml:"ETag"`
		Size         int64  `xml:"Size"`
		LastModified string `xml:"LastModified"`
	}

	type ListPartsResult struct {
		XMLName              xml.Name      `xml:"ListPartsResult"`
		Bucket               string        `xml:"Bucket"`
		Key                  string        `xml:"Key"`
		UploadId             string        `xml:"UploadId"`
		PartNumberMarker     int32         `xml:"PartNumberMarker"`
		NextPartNumberMarker int32         `xml:"NextPartNumberMarker,omitempty"`
		MaxParts             int32         `xml:"MaxParts"`
		IsTruncated          bool          `xml:"IsTruncated"`
		Parts                []PartElement `xml:"Part"`
	}

	result := ListPartsResult{
		Bucket:           bucket,
		Key:              key,
		UploadId:         uploadID,
		PartNumberMarker: 0,
		MaxParts:         1000,
		IsTruncated:      false,
		Parts:            make([]PartElement, len(parts)),
	}

	for i, p := range parts {
		result.Parts[i].PartNumber = p.PartNumber
		result.Parts[i].ETag = p.ETag
		if plainLen, ok := plainLenByPart[p.PartNumber]; ok && plainLen > 0 {
			result.Parts[i].Size = plainLen
		} else {
			result.Parts[i].Size = p.Size
		}
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
	if directive := strings.TrimSpace(r.Header.Get("x-amz-metadata-directive")); directive != "" && !strings.EqualFold(directive, "COPY") && !strings.EqualFold(directive, "REPLACE") {
		s3Err := &S3Error{Code: "InvalidArgument", Message: "Unknown metadata directive.", Resource: r.URL.Path, HTTPStatus: http.StatusBadRequest}
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		return
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("x-amz-metadata-directive")), "REPLACE") {
		if _, metadataErr := parseWriteMetadata(r.Header); metadataErr != nil {
			metadataErr.Resource = r.URL.Path
			h.writeObjectError(w, r, "CopyObject", metadataErr, start)
			return
		}
	}
	// Parse copy source: format is "bucket/key" or "bucket/key?versionId=xxx"
	srcBucket, srcKey, srcVersionID, err := ParseCopySource(copySource)
	if err != nil {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Invalid x-amz-copy-source header",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
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
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		return
	}

	// Validate the source terminal before opening it for decryption. This keeps
	// a truncated v2 source from reaching destination encryption or PutObject.
	sourceHead, headErr := s3Client.HeadObject(ctx, srcBucket, srcKey, srcVersionID)
	if headErr != nil {
		s3Err := TranslateError(headErr, srcBucket, srcKey)
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		return
	}
	sourceView, sourceViewErr := h.loadObjectView(srcBucket, srcKey, srcVersionID, sourceHead)
	if sourceViewErr != nil {
		h.writeObjectError(w, r, "CopyObject", decryptFailure(sourceViewErr, r.URL.Path), start)
		return
	}
	sourceSize, sourceSizeErr := h.resolvePlaintextSize(ctx, s3Client, sourceView)
	if h.writeObjectBackendError(w, r, "CopyObject", sourceSizeErr, start) {
		return
	}
	if sourceSizeErr != nil && (sourceView.Class.Format == crypto.FormatMPUV1 || sourceView.Class.Format == crypto.FormatMPUV2) {
		h.writeObjectError(w, r, "CopyObject", decryptFailure(sourceSizeErr, r.URL.Path), start)
		return
	}
	if sourceSizeErr != nil {
		h.writeObjectError(w, r, "CopyObject", decryptFailure(sourceSizeErr, r.URL.Path), start)
		return
	}
	if sourceView.Class.Format == crypto.FormatChunkedV1 || sourceView.Class.Format == crypto.FormatChunkedV2 {
		if _, preflightErr := h.preflightChunkedCompleteness(ctx, s3Client, srcBucket, srcKey, srcVersionID, sourceHead); preflightErr != nil {
			if h.writeObjectBackendError(w, r, "CopyObject", preflightErr, start) {
				return
			}
			h.writeObjectError(w, r, "CopyObject", decryptFailure(preflightErr, r.URL.Path), start)
			return
		}
	}

	// Get source object (decrypt if encrypted)
	srcReader, srcMetadata, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		s3Err := TranslateError(err, srcBucket, srcKey)
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"srcBucket": srcBucket,
			"srcKey":    srcKey,
			"dstBucket": dstBucket,
			"dstKey":    dstKey,
		}).Error("Failed to get source object for copy")
		return
	}
	defer srcReader.Close()

	// Get source encryption engine
	srcEngine, err := h.getEncryptionEngine(srcBucket)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get source encryption engine")
		s3Err := &S3Error{Code: "InternalError", Message: "Failed to load encryption configuration", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		return
	}

	// V0.6-PERF-1 Phase C: enforce legacy-source cap on handleCopyObject
	// (mirror of the guard added in V0.6-S3-1 for uploadPartCopyLegacy).
	// Legacy AEAD cannot be range-decrypted, so the engine buffers the whole
	// source internally inside Decrypt. Cap the allocation before we start.
	if sourceView.Class.Format == crypto.FormatBufferedLegacy || sourceView.Class.Format == crypto.FormatBufferedV2 || sourceView.Class.Format == crypto.FormatBufferedFallback {
		legacyCap := effectiveCopySourceCap(h.config)
		srcSizeHint := sourceSize.Size
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
			h.writeObjectError(w, r, "CopyObject", s3Err, start)
			return
		}
	}

	// Decrypt source if encrypted.
	// Decrypt source object. MPU-encrypted objects (MetaMPUEncrypted=true) carry
	// their DEK and part manifest in a companion .mpu-manifest object and must be
	// decrypted via decryptMPUObject. Standard single-PUT encrypted objects are
	// handled by the engine's Decrypt method.
	var decryptedReader io.Reader
	// sourceMetadata contains the client-visible metadata recovered from the
	// plaintext object. Encrypted backends expose only the ciphertext headers,
	// so the decrypt result is authoritative for standard object metadata.
	sourceMetadata := make(map[string]string, len(srcMetadata))
	for key, value := range srcMetadata {
		sourceMetadata[key] = value
	}
	var decryptedSourceMetadata map[string]string
	if sourceView, viewErr := h.loadObjectView(srcBucket, srcKey, srcVersionID, srcMetadata); viewErr == nil && (sourceView.Class.Format == crypto.FormatMPUV1 || sourceView.Class.Format == crypto.FormatMPUV2) {
		decryptedReader, err = h.decryptMPUObject(ctx, srcBucket, srcKey, srcMetadata, srcReader, s3Client)
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"srcBucket": srcBucket,
				"srcKey":    srcKey,
			}).Error("Failed to decrypt MPU source object for copy")
			s3Err := &S3Error{
				Code:       "InternalError",
				Message:    "Failed to decrypt multipart-encrypted source object",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
			h.writeObjectError(w, r, "CopyObject", s3Err, start)
			return
		}
		decryptedSourceMetadata = crypto.PlaintextMetadataView(sourceView.Expanded, -1, "")
	} else {
		// V0.6-PERF-1 Phase C: pass srcReader directly to Decrypt — the engine
		// already handles buffering for legacy AEAD and streams for chunked.
		// The intermediate decryptedData []byte allocation is eliminated here.
		var decryptedMetadata map[string]string
		decryptedReader, decryptedMetadata, err = srcEngine.Decrypt(r.Context(), crypto.ObjectContext{Bucket: srcBucket, Key: srcKey}, srcReader, srcMetadata)
		if err != nil {
			h.logger.WithError(err).Error("Failed to decrypt source object for copy")
			s3Err := &S3Error{
				Code:       "InternalError",
				Message:    "Failed to decrypt source object",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusInternalServerError,
			}
			h.writeObjectError(w, r, "CopyObject", s3Err, start)
			return
		}
		decryptedSourceMetadata = decryptedMetadata
		for _, key := range objectmeta.Names {
			if value := decryptedMetadata[key]; value != "" {
				sourceMetadata[key] = value
			}
		}
		for key, value := range decryptedMetadata {
			if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") && !crypto.IsGatewayReservedKey(key) {
				sourceMetadata[key] = value
			}
		}
	}

	resolvedWrite, writeErr := resolveCopyWriteMetadata(r.Header, objectResponseSource{Meta: sourceMetadata, Decrypted: decryptedSourceMetadata, BackendETag: sourceMetadata["ETag"]})
	if writeErr != nil {
		writeErr.Resource = r.URL.Path
		h.writeObjectError(w, r, "CopyObject", writeErr, start)
		return
	}
	dstMetadata := resolvedWrite.engineInput(0, false)

	// Get destination encryption engine
	dstEngine, err := h.getEncryptionEngine(dstBucket)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get destination encryption engine")
		s3Err := &S3Error{Code: "InternalError", Message: "Failed to load encryption configuration", Resource: r.URL.Path, HTTPStatus: http.StatusInternalServerError}
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		return
	}

	// V0.6-PERF-1 Phase C: pass decryptedReader directly to Encrypt, eliminating
	// the intermediate decryptedData []byte allocation. The engine handles its
	// own buffering as needed for legacy vs chunked mode.
	encryptedReader, encMetadata, err := dstEngine.Encrypt(r.Context(), crypto.ObjectContext{Bucket: dstBucket, Key: dstKey}, decryptedReader, dstMetadata)
	if err != nil {
		h.logger.WithError(err).Error("Failed to encrypt destination object")
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Failed to encrypt destination object",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
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
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		return
	}

	// Filter out standard HTTP headers from metadata before sending to S3
	var filterKeys []string
	if h.config != nil {
		filterKeys = h.config.Backend.FilterMetadataKeys
	}
	dstClass, classErr := crypto.ClassifyObject(dstKey, encMetadata)
	if classErr != nil {
		h.writeObjectError(w, r, "CopyObject", decryptFailure(classErr, r.URL.Path), start)
		return
	}
	persist := buildPersistPlan(encMetadata, dstClass, filterKeys)
	s3Metadata := persist.Metadata
	persist.Native.ApplyTo(s3Metadata)

	lockInput, s3Err := extractObjectLockInput(r)
	if s3Err != nil {
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		return
	}

	// Upload encrypted copy with filtered metadata and known content length
	encLen := int64(len(encryptedData))
	_, err = s3Client.PutObject(ctx, dstBucket, dstKey, bytes.NewReader(encryptedData), s3Metadata, &encLen, tagging, lockInput, "", "", "", "", "")
	if err != nil {
		s3Err := TranslateError(err, dstBucket, dstKey)
		h.writeObjectError(w, r, "CopyObject", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"srcBucket": srcBucket,
			"srcKey":    srcKey,
			"dstBucket": dstBucket,
			"dstKey":    dstKey,
		}).Error("Failed to put copied object")
		return
	}

	// Fetch ETag via HEAD to return accurate ETag
	headMeta, _ := s3Client.HeadObject(ctx, dstBucket, dstKey, nil)
	etag := headMeta["ETag"]

	// Populate the size cache for the destination object so subsequent
	// ListObjects can resolve the plaintext size without a HEAD request.
	if sourceSizeErr == nil && sourceSize.Exact {
		h.recordPlaintextSize(ctx, dstBucket, dstKey, plaintextSize{Size: sourceSize.Size, Exact: true, Source: "copy-source"})
	}

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
}

// preflightChunkedCompleteness authenticates the fixed v2 terminal record
// without consuming the object body used by the subsequent operation. v1 is
// deliberately accepted with an inferred size and no backend suffix request.
func (h *Handler) preflightChunkedTerminal(ctx context.Context, s3Client s3.Client, bucket, key string, versionID *string, metadata map[string]string) (crypto.ChunkedObjectInfo, error) {
	// API handlers classify the stable compact aliases, but the raw metadata
	// must reach the engine so it can decrypt protected metadata itself.
	expandedMetadata, err := h.expandMetadataForAPI(bucket, metadata)
	if err != nil {
		return crypto.ChunkedObjectInfo{}, err
	}
	version, err := crypto.ChunkedFormatVersion(expandedMetadata)
	if err != nil {
		// Older chunked objects may not have a persisted manifest. Preserve
		// their established v1 read behavior; v2 always carries a manifest.
		if expandedMetadata[crypto.MetaManifest] == "" {
			version = crypto.ChunkedFormatV1
		} else {
			return crypto.ChunkedObjectInfo{}, err
		}
	}
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		return crypto.ChunkedObjectInfo{}, err
	}
	// A bypass bucket must reach the passthrough Decrypt path so encrypted
	// objects retain the established 409 configuration-mismatch response.
	// Trailer authentication is only meaningful for an active encryption
	// engine; invoking the passthrough method would incorrectly turn that
	// compatibility error into a generic integrity failure.
	if _, bypass := engine.(crypto.PassthroughEngine); bypass {
		return crypto.ChunkedObjectInfo{}, nil
	}
	if version == crypto.ChunkedFormatV1 {
		if expandedMetadata["Content-Length"] == "" {
			return crypto.ChunkedObjectInfo{Version: version}, nil
		}
		ciphertextSize, parseErr := strconv.ParseInt(expandedMetadata["Content-Length"], 10, 64)
		if parseErr != nil || ciphertextSize < 0 {
			return crypto.ChunkedObjectInfo{}, fmt.Errorf("%w: invalid ciphertext size", crypto.ErrChunkedObjectIncomplete)
		}
		plain, count, sizeErr := crypto.PlaintextSizeForCiphertext(expandedMetadata, ciphertextSize)
		if sizeErr != nil {
			return crypto.ChunkedObjectInfo{}, sizeErr
		}
		if plain < 0 {
			return crypto.ChunkedObjectInfo{}, fmt.Errorf("%w: negative plaintext size", crypto.ErrChunkedObjectIncomplete)
		}
		return crypto.ChunkedObjectInfo{Version: version, ChunkCount: count, PlaintextSize: uint64(plain)}, nil // #nosec G115 -- negative sizes are rejected above
	}
	// The caller's HeadObject metadata is authoritative. Do not issue a second
	// HEAD here: preflight must be exactly one 32-byte suffix GET and all reads
	// must retain the caller-selected version.
	ciphertextSize, err := strconv.ParseInt(expandedMetadata["Content-Length"], 10, 64)
	if err != nil || ciphertextSize < 0 {
		return crypto.ChunkedObjectInfo{}, fmt.Errorf("%w: invalid ciphertext size", crypto.ErrChunkedObjectIncomplete)
	}
	if ciphertextSize < crypto.ChunkedTerminalSize {
		return crypto.ChunkedObjectInfo{}, fmt.Errorf("%w: short ciphertext", crypto.ErrChunkedObjectIncomplete)
	}
	first := ciphertextSize - crypto.ChunkedTerminalSize
	rangeHeader := fmt.Sprintf("bytes=%d-%d", first, ciphertextSize-1)
	trailer, _, err := s3Client.GetObject(ctx, bucket, key, versionID, &rangeHeader)
	if err != nil {
		return crypto.ChunkedObjectInfo{}, backendObjectError(bucket, key, err)
	}
	defer trailer.Close()
	return engine.AuthenticateChunkedTrailer(ctx, crypto.ObjectContext{Bucket: bucket, Key: key}, trailer, metadata, ciphertextSize)
}

func (h *Handler) expandMetadataForAPI(bucket string, metadata map[string]string) (map[string]string, error) {
	expand := crypto.ExpandMetadataForAPI
	if h.apiMetadataExpander != nil {
		expand = h.apiMetadataExpander
	}
	expanded, err := expand(metadata)
	if err != nil {
		return nil, err
	}
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		return nil, err
	}
	if expander, ok := engine.(interface {
		APIExpandedMetadata(map[string]string) (map[string]string, error)
	}); ok {
		return expander.APIExpandedMetadata(metadata)
	}
	return expanded, nil
}

// preflightChunkedCompleteness applies shared expanded-metadata format policy
// and authenticates the v2 terminal where required, while preserving v1 reads.
func (h *Handler) preflightChunkedCompleteness(ctx context.Context, s3Client s3.Client, bucket, key string, versionID *string, metadata map[string]string) (crypto.ChunkedObjectInfo, error) {
	expandedMetadata, err := h.expandMetadataForAPI(bucket, metadata)
	if err != nil {
		return crypto.ChunkedObjectInfo{}, err
	}
	// Fallback-v2 objects carry chunk metadata inside the authenticated body
	// prefix, while the visible chunked marker is only a format discriminator.
	// Their full-body decrypt path authenticates the terminal and chunks.
	if expandedMetadata[crypto.MetaFallbackVersion] == "2" || expandedMetadata[crypto.MetaFallbackMode] == "true" {
		return crypto.ChunkedObjectInfo{Version: crypto.ChunkedFormatV2}, nil
	}
	manifest, present := expandedMetadata[crypto.MetaManifest]
	if !present {
		if expandedMetadata[crypto.MetaObjectFormatVersion] == "chunked-v2" {
			reader, raw, getErr := s3Client.GetObject(ctx, bucket, key, versionID, nil)
			if getErr != nil {
				return crypto.ChunkedObjectInfo{}, backendObjectError(bucket, key, getErr)
			}
			defer reader.Close()
			engine, engineErr := h.getEncryptionEngine(bucket)
			if engineErr != nil {
				return crypto.ChunkedObjectInfo{}, engineErr
			}
			decrypted, _, decErr := engine.Decrypt(ctx, crypto.ObjectContext{Bucket: bucket, Key: key}, reader, raw)
			if decErr != nil {
				return crypto.ChunkedObjectInfo{}, decErr
			}
			if _, readErr := io.Copy(io.Discard, decrypted); readErr != nil {
				return crypto.ChunkedObjectInfo{}, readErr
			}
			return crypto.ChunkedObjectInfo{Version: crypto.ChunkedFormatV2}, nil
		}
		return crypto.ChunkedObjectInfo{Version: crypto.ChunkedFormatV1}, nil
	}
	if manifest == "" {
		return crypto.ChunkedObjectInfo{}, fmt.Errorf("chunked manifest is present but empty")
	}
	version, err := crypto.ChunkedFormatVersion(expandedMetadata)
	if err != nil {
		return crypto.ChunkedObjectInfo{}, fmt.Errorf("invalid chunked manifest: %w", err)
	}
	if version == crypto.ChunkedFormatV1 {
		return crypto.ChunkedObjectInfo{Version: version}, nil
	}
	return h.preflightChunkedTerminal(ctx, s3Client, bucket, key, versionID, metadata)
}

func (h *Handler) writeChunkedCompletenessError(w http.ResponseWriter, r *http.Request, bucket string, err error, start time.Time) {
	h.logger.WithError(err).WithField("bucket", bucket).Error("Chunked object completeness check failed")
	h.writeObjectIntegrityError(w, r, "GetObject", bucket, mux.Vars(r)["key"], err, start)
}

// handleDeleteObjects handles batch delete requests.
func (h *Handler) handleDeleteObjects(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]

	if bucket == "" {
		s3Err := ErrInvalidBucketName
		s3Err.Resource = r.URL.Path
		h.writeObjectError(w, r, "DeleteObjects", s3Err, start)
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
		h.writeObjectError(w, r, "DeleteObjects", s3Err, start)
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

	// Inspect primary metadata concurrently before the batch delete. A bounded
	// worker pool keeps large DeleteObjects requests from creating an unbounded
	// burst of backend HEAD requests.
	primaryViews := make(map[string]*objectView, len(identifiers))
	var headWG sync.WaitGroup
	var headMu sync.Mutex
	sem := make(chan struct{}, 8)
	for _, obj := range identifiers {
		headWG.Add(1)
		go func() {
			defer headWG.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var versionID *string
			if obj.VersionID != "" {
				versionID = &obj.VersionID
			}
			metadata, headErr := s3Client.HeadObject(ctx, bucket, obj.Key, versionID)
			if headErr == nil {
				headMu.Lock()
				view, _ := h.loadObjectView(bucket, obj.Key, versionID, metadata)
				primaryViews[obj.Key] = view
				headMu.Unlock()
			} else if !isS3NotFoundError(headErr) {
				h.logger.WithError(headErr).WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    obj.Key,
				}).Debug("Unable to inspect object metadata before batch delete")
			}
		}()
	}
	headWG.Wait()

	deleted, errors, err := s3Client.DeleteObjects(ctx, bucket, identifiers)
	if err != nil {
		s3Err := TranslateError(err, bucket, "")
		h.writeObjectError(w, r, "DeleteObjects", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
		}).Error("Failed to delete objects")
		return
	}

	// Invalidate cache for deleted objects
	if h.cache != nil {
		for _, del := range deleted {
			h.cache.Delete(ctx, bucket, del.Key)
		}
	}

	// Clean up manifests only for successfully deleted objects that were
	// identified as encrypted MPUs before the primary batch delete.
	for _, del := range deleted {
		h.cleanupMPUManifest(ctx, s3Client, primaryViews[del.Key])
	}

	// Evict deleted keys from size cache.
	if h.sizeCache != nil && len(deleted) > 0 {
		keys := make([]string, len(deleted))
		for i, del := range deleted {
			keys[i] = del.Key
		}
		if cacheErr := h.sizeCache.DeleteBatch(ctx, bucket, keys); cacheErr != nil {
			h.logger.WithError(cacheErr).Warn("handleDeleteObjects: failed to evict size cache")
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
}

// ParseCopySource extracts bucket, key, and version ID from an x-amz-copy-source header.
// Format: "bucket/key" or "bucket/key?versionId=xxx" or "/bucket/key" or "/bucket/key?versionId=xxx"
// Decode the path and optional opaque version exactly once, preserving literal
// plus signs and key slashes. Split the raw version suffix before decoding so
// an encoded ?versionId= inside the key cannot become a version selector.
func ParseCopySource(copySource string) (bucket, key string, versionID *string, err error) {
	path, rawVersion, hasVersion := strings.Cut(copySource, "?versionId=")
	decodedPath, decodeErr := url.PathUnescape(path)
	if decodeErr != nil {
		return "", "", nil, fmt.Errorf("invalid copy source path: %w", decodeErr)
	}
	// Only the optional header-prefix slash is structural. Every slash after
	// the bucket separator is part of the S3 key, including leading // or ../.
	bucket, key, found := strings.Cut(strings.TrimPrefix(decodedPath, "/"), "/")
	if !found || bucket == "" || key == "" {
		return "", "", nil, fmt.Errorf("invalid copy source format")
	}
	if hasVersion && rawVersion != "" {
		version, decodeErr := url.PathUnescape(rawVersion)
		if decodeErr != nil {
			return "", "", nil, fmt.Errorf("invalid copy source version: %w", decodeErr)
		}
		versionID = &version
	}
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

func effectiveVerifiedSpoolLimit(cfg *config.Config, r *http.Request) int64 {
	global := int64(5 << 30)
	part := effectiveMaxPartBuffer(cfg)
	if cfg != nil && cfg.Server.MaxVerifiedSpoolBytes > 0 {
		global = cfg.Server.MaxVerifiedSpoolBytes
	}
	return spoolLimitForRequest(r, global, part)
}

func (h *Handler) verifiedSpoolLimit(r *http.Request) int64 {
	if h.spoolLimits != nil {
		limits := h.spoolLimits.Limits()
		return spoolLimitForRequest(r, limits.Global, limits.Part)
	}
	return effectiveVerifiedSpoolLimit(h.config, r)
}

// handleListBuckets handles GET / — ListBuckets.
func (h *Handler) handleListBuckets(w http.ResponseWriter, r *http.Request) {
	credential, ok := CredentialFromContext(r)
	if !ok {
		writeAuthorizationDenied(w, r, h.auditLogger, "unknown_operation")
		return
	}
	if credential.Policy.Permissions != config.ObjectPermissionReadOnly && credential.Policy.Permissions != config.ObjectPermissionReadWrite {
		writeAuthorizationDenied(w, r, h.auditLogger, "read_only")
		return
	}
	resp, err := h.forwardToBackend(r)
	if err != nil {
		scheme, host := backendEndpointIdentity(h.config)
		h.logger.WithError(sanitizeBackendForwardError(err)).WithFields(logrus.Fields{
			"operation": "ListBuckets", "backend_scheme": scheme, "backend_host": host,
		}).Error("Failed to forward ListBuckets request to backend")
		(&S3Error{Code: "BadGateway", Message: "The upstream S3 backend returned an error.", Resource: r.URL.Path, HTTPStatus: http.StatusBadGateway}).WriteXML(w)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		if _, err := copyProxyResponse(w, resp); err != nil {
			h.logger.WithError(err).Warn("Failed to copy proxy response for ListBuckets")
		}
		return
	}
	const maxListBucketsResponse = 8 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBucketsResponse+1))
	if err != nil || len(body) > maxListBucketsResponse {
		(&S3Error{Code: "BadGateway", Message: "The upstream S3 backend returned an invalid response.", Resource: r.URL.Path, HTTPStatus: http.StatusBadGateway}).WriteXML(w)
		return
	}
	type bucket struct {
		Name         string `xml:"Name"`
		CreationDate string `xml:"CreationDate"`
	}
	type listResult struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		XMLNS   string   `xml:"xmlns,attr,omitempty"`
		Owner   struct {
			ID          string `xml:"ID"`
			DisplayName string `xml:"DisplayName"`
		} `xml:"Owner"`
		Buckets struct {
			Items []bucket `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	var result listResult
	if err := xml.Unmarshal(body, &result); err != nil || result.XMLName.Local != "ListAllMyBucketsResult" {
		(&S3Error{Code: "BadGateway", Message: "The upstream S3 backend returned an invalid response.", Resource: r.URL.Path, HTTPStatus: http.StatusBadGateway}).WriteXML(w)
		return
	}
	result.XMLNS = result.XMLName.Space
	filtered := result.Buckets.Items[:0]
	for _, bucket := range result.Buckets.Items {
		if credential.AllowsBucket(bucket.Name) && (h.config == nil || h.config.ProxiedBucket == "" || bucket.Name == h.config.ProxiedBucket) {
			filtered = append(filtered, bucket)
		}
	}
	result.Buckets.Items = filtered
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	if err := xml.NewEncoder(w).Encode(result); err != nil {
		return
	}
}

// backendEndpointIdentity returns only safe endpoint fields for diagnostics.
func backendEndpointIdentity(cfg *config.Config) (scheme, host string) {
	if cfg == nil {
		return "", ""
	}
	u, err := s3.ResolveEndpoint(cfg.Backend.Endpoint, cfg.Backend.UseSSL)
	if err != nil {
		return "", ""
	}
	return u.Scheme, u.Host
}

// sanitizeBackendForwardError removes URL credentials and query material from
// transport errors before they reach structured logs.
func sanitizeBackendForwardError(err error) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	for start := strings.IndexByte(message, '"'); start >= 0; {
		rest := message[start+1:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			break
		}
		end += start + 1
		if u, parseErr := url.Parse(message[start+1 : end]); parseErr == nil && u.Host != "" {
			u.User = nil
			u.RawQuery = ""
			message = message[:start+1] + u.String() + message[end:]
			start = strings.IndexByte(message[start+1+len(u.String()):], '"')
			if start >= 0 {
				start += 1 + len(u.String())
			}
			continue
		}
		start = strings.IndexByte(message[end+1:], '"')
		if start >= 0 {
			start += end + 1
		}
	}
	return errors.New(message)
}

// handleDeleteBucket handles DELETE /{bucket} — DeleteBucket.
func (h *Handler) handleDeleteBucket(w http.ResponseWriter, r *http.Request) {
	bucket := mux.Vars(r)["bucket"]
	credential, authorized := CredentialFromContext(r)
	if !authorized || !credential.AllowsBucket(bucket) || !credential.HasBucketPermission(config.BucketPermissionDelete) || (h.config != nil && h.config.ProxiedBucket != "" && h.config.ProxiedBucket != bucket) {
		s3Err := &S3Error{Code: "AccessDenied", Message: "Access Denied", Resource: r.URL.Path, HTTPStatus: http.StatusForbidden}
		s3Err.WriteXML(w)
		h.auditManagement(r, "DeleteBucket", bucket, false, s3Err)
		return
	}
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

func (h *Handler) auditManagement(r *http.Request, operation, bucket string, success bool, err error) {
	if h.auditLogger == nil {
		return
	}
	h.auditLogger.LogAccessWithMetadata(operation, bucket, "", getClientIP(r), r.UserAgent(), getRequestID(r), success, err, 0, map[string]interface{}{"credential_label": CredentialLabelFromContext(r), "result": map[bool]string{true: "allowed", false: "denied"}[success]})
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
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketVersioning", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
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
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketACL", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketPolicy handles GET /{bucket}?policy — GetBucketPolicy.
func (h *Handler) handleGetBucketPolicy(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketPolicy", mux.Vars(r)["bucket"], "")
}

// handlePutBucketPolicy handles PUT /{bucket}?policy — PutBucketPolicy.
func (h *Handler) handlePutBucketPolicy(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketPolicy", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleDeleteBucketPolicy handles DELETE /{bucket}?policy — DeleteBucketPolicy.
func (h *Handler) handleDeleteBucketPolicy(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "DeleteBucketPolicy", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketCors handles GET /{bucket}?cors — GetBucketCors.
func (h *Handler) handleGetBucketCors(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketCors", mux.Vars(r)["bucket"], "")
}

// handlePutBucketCors handles PUT /{bucket}?cors — PutBucketCors.
func (h *Handler) handlePutBucketCors(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketCors", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleDeleteBucketCors handles DELETE /{bucket}?cors — DeleteBucketCors.
func (h *Handler) handleDeleteBucketCors(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "DeleteBucketCors", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketLifecycle handles GET /{bucket}?lifecycle — GetBucketLifecycle.
func (h *Handler) handleGetBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketLifecycle", mux.Vars(r)["bucket"], "")
}

// handlePutBucketLifecycle handles PUT /{bucket}?lifecycle — PutBucketLifecycle.
func (h *Handler) handlePutBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketLifecycle", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleDeleteBucketLifecycle handles DELETE /{bucket}?lifecycle — DeleteBucketLifecycle.
func (h *Handler) handleDeleteBucketLifecycle(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "DeleteBucketLifecycle", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketEncryption handles GET /{bucket}?encryption — GetBucketEncryption.
func (h *Handler) handleGetBucketEncryption(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketEncryption", mux.Vars(r)["bucket"], "")
}

// handlePutBucketEncryption handles PUT /{bucket}?encryption — PutBucketEncryption.
func (h *Handler) handlePutBucketEncryption(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketEncryption", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleDeleteBucketEncryption handles DELETE /{bucket}?encryption — DeleteBucketEncryption.
func (h *Handler) handleDeleteBucketEncryption(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "DeleteBucketEncryption", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketNotification handles GET /{bucket}?notification — GetBucketNotification.
func (h *Handler) handleGetBucketNotification(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketNotification", mux.Vars(r)["bucket"], "")
}

// handlePutBucketNotification handles PUT /{bucket}?notification — PutBucketNotification.
func (h *Handler) handlePutBucketNotification(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketNotification", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketReplication handles GET /{bucket}?replication — GetBucketReplication.
func (h *Handler) handleGetBucketReplication(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketReplication", mux.Vars(r)["bucket"], "")
}

// handlePutBucketReplication handles PUT /{bucket}?replication — PutBucketReplication.
func (h *Handler) handlePutBucketReplication(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketReplication", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleDeleteBucketReplication handles DELETE /{bucket}?replication — DeleteBucketReplication.
func (h *Handler) handleDeleteBucketReplication(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "DeleteBucketReplication", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketLogging handles GET /{bucket}?logging — GetBucketLogging.
func (h *Handler) handleGetBucketLogging(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketLogging", mux.Vars(r)["bucket"], "")
}

// handlePutBucketLogging handles PUT /{bucket}?logging — PutBucketLogging.
func (h *Handler) handlePutBucketLogging(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketLogging", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketRequestPayment handles GET /{bucket}?requestPayment — GetBucketRequestPayment.
func (h *Handler) handleGetBucketRequestPayment(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketRequestPayment", mux.Vars(r)["bucket"], "")
}

// handlePutBucketRequestPayment handles PUT /{bucket}?requestPayment — PutBucketRequestPayment.
func (h *Handler) handlePutBucketRequestPayment(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketRequestPayment", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketWebsite handles GET /{bucket}?website — GetBucketWebsite.
func (h *Handler) handleGetBucketWebsite(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketWebsite", mux.Vars(r)["bucket"], "")
}

// handlePutBucketWebsite handles PUT /{bucket}?website — PutBucketWebsite.
func (h *Handler) handlePutBucketWebsite(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketWebsite", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleDeleteBucketWebsite handles DELETE /{bucket}?website — DeleteBucketWebsite.
func (h *Handler) handleDeleteBucketWebsite(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "DeleteBucketWebsite", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketInventory handles GET /{bucket}?inventory — GetBucketInventory.
func (h *Handler) handleGetBucketInventory(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketInventory", mux.Vars(r)["bucket"], "")
}

// handlePutBucketInventory handles PUT /{bucket}?inventory — PutBucketInventory.
func (h *Handler) handlePutBucketInventory(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketInventory", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleDeleteBucketInventory handles DELETE /{bucket}?inventory — DeleteBucketInventory.
func (h *Handler) handleDeleteBucketInventory(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "DeleteBucketInventory", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
}

// handleGetBucketAnalytics handles GET /{bucket}?analytics — GetBucketAnalytics.
func (h *Handler) handleGetBucketAnalytics(w http.ResponseWriter, r *http.Request) {
	h.handlePassthrough(w, r, "GetBucketAnalytics", mux.Vars(r)["bucket"], "")
}

// handlePutBucketIntelligentTiering handles PUT /{bucket}?intelligent-tiering — PutBucketIntelligentTiering.
func (h *Handler) handlePutBucketIntelligentTiering(w http.ResponseWriter, r *http.Request) {
	h.handlePassthroughWithBodyLimit(w, r, "PutBucketIntelligentTiering", mux.Vars(r)["bucket"], "", maxBucketConfigurationBody)
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
