package metrics

import (
	"context"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/trace"
)

var (
	// defaultRegistry is the default Prometheus registry
	defaultRegistry = prometheus.DefaultRegisterer
	defaultGatherer = prometheus.DefaultGatherer
)

// Config holds metrics configuration.
type Config struct {
	EnableBucketLabel bool
}

// Metrics holds all application metrics.
type Metrics struct {
	config                            Config
	gatherer                          prometheus.Gatherer
	httpRequestsTotal                 *prometheus.CounterVec
	httpRequestDuration               *prometheus.HistogramVec
	httpRequestBytes                  *prometheus.CounterVec
	s3OperationsTotal                 *prometheus.CounterVec
	s3OperationDuration               *prometheus.HistogramVec
	s3OperationErrors                 *prometheus.CounterVec
	encryptionOperations              *prometheus.CounterVec
	encryptionDuration                *prometheus.HistogramVec
	encryptionErrors                  *prometheus.CounterVec
	encryptionBytes                   *prometheus.CounterVec
	rotatedReads                      *prometheus.CounterVec
	bufferPoolHits                    *prometheus.CounterVec
	bufferPoolMisses                  *prometheus.CounterVec
	activeConnections                 prometheus.Gauge
	goroutines                        prometheus.Gauge
	memoryAllocBytes                  prometheus.Gauge
	memorySysBytes                    prometheus.Gauge
	hardwareAccelerationEnabled       *prometheus.GaugeVec
	fipsMode                          prometheus.Gauge
	uploadPartCopyTotal               *prometheus.CounterVec
	uploadPartCopyBytes               *prometheus.CounterVec
	uploadPartCopyDuration            *prometheus.HistogramVec
	uploadPartCopyLegacyFallbackTotal prometheus.Counter
	// Admin and rotation metrics
	kmsActiveKeyVersion      *prometheus.GaugeVec
	kmsRotationOpsTotal      *prometheus.CounterVec
	kmsRotationDuration      *prometheus.HistogramVec
	kmsRotationInFlightWraps prometheus.Gauge
	gatewayAdminAPIEnabled   prometheus.Gauge

	// V0.6-S3-2 — objects skipped by the key-rotation worker because
	// they are Object-Lock-protected at the backend. See ADR 0008.
	gatewayRotationSkippedLocked *prometheus.CounterVec

	// V0.6-SEC-3 — encrypted multipart upload metrics (ADR 0009).
	mpuEncryptedTotal    *prometheus.CounterVec
	mpuPartsTotal        *prometheus.CounterVec
	mpuStateStoreOps     *prometheus.CounterVec
	mpuStateStoreLatency *prometheus.HistogramVec
	mpuValkeyUp          prometheus.Gauge
	mpuValkeyInsecure    prometheus.Gauge
	mpuManifestBytes     prometheus.Histogram
	mpuManifestStorage   *prometheus.CounterVec

	// V0.6-OBS-1 — admin pprof profiling metrics.
	// s3GatewayAdminPprofRequestsTotal counts pprof fetches per endpoint and
	// outcome. Labels: endpoint, outcome. Bounded cardinality: 11 × 4 = 44.
	s3GatewayAdminPprofRequestsTotal *prometheus.CounterVec
	// gatewayAdminProfilingEnabled is 1 when pprof routes are mounted.
	gatewayAdminProfilingEnabled prometheus.Gauge

	// V1.0-CRYPTO-2 — MPU state at-rest encryption metrics.
	// gateway_mpu_state_encrypted_writes_total counts every successful
	// encrypted write of a Valkey state blob. Labelled by op=create|get|list.
	mpuStateEncryptedWrites *prometheus.CounterVec
	// gateway_mpu_state_legacy_reads_total counts every fallback read of an
	// unencrypted (legacy plaintext) Valkey state blob.
	mpuStateLegacyReads prometheus.Counter

	// V0.6-PERF-2 — S3 backend retry metrics (ADR 0010).
	// s3BackendRetriesTotal counts retry attempts per operation and classifier
	// reason. Labels: operation, reason, mode.
	s3BackendRetriesTotal *prometheus.CounterVec
	// s3BackendAttemptsPerRequest is a histogram of total attempts made per
	// logical backend request (≥ 1). Labels: operation.
	s3BackendAttemptsPerRequest *prometheus.HistogramVec
	// s3BackendRetryGiveUpsTotal counts operations that exhausted MaxAttempts.
	// Labels: operation, final_reason.
	s3BackendRetryGiveUpsTotal *prometheus.CounterVec
	// s3BackendRetryBackoffSeconds is a histogram of backoff delays actually
	// slept.
	s3BackendRetryBackoffSeconds prometheus.Histogram

	// V1.0-OBS-1 — observability phase A new metrics.

	// kmsHealthy reports the result of the last KMS health check per provider.
	// Value: 1 = healthy, 0 = unhealthy/unavailable.
	// Labels: provider ∈ {cosmian, aws, vault, memory, self_contained}
	kmsHealthy *prometheus.GaugeVec

	// V1.0-KMS-1 — KMS production readiness metrics.

	// kmsDEKCacheHits counts successful DEK unwrap cache hits.
	// Labels: provider
	kmsDEKCacheHits *prometheus.CounterVec

	// kmsDEKCacheMisses counts DEK unwrap cache misses (went to KMS).
	// Labels: provider
	kmsDEKCacheMisses *prometheus.CounterVec

	// kmsCircuitBreakerState reports the current circuit-breaker state.
	// Value: 0 = closed (normal), 1 = open (failing fast), 2 = half-open (probe).
	// Labels: provider
	kmsCircuitBreakerState *prometheus.GaugeVec

	// kmsRetryAttemptsTotal counts total retry attempts by WrapKey/UnwrapKey.
	// Labels: provider, operation ∈ {wrap, unwrap}, outcome ∈ {success, failure}
	kmsRetryAttemptsTotal *prometheus.CounterVec

	// metadataEncryptionEnabled reports whether encrypted-object-metadata
	// (V1.0-CRYPTO-3) is active. Value: 1 = active, 0 = inactive.
	metadataEncryptionEnabled prometheus.Gauge

	// tlsCertExpirySeconds reports seconds until TLS certificate expiry
	// for the gateway's own serving certificate. Value: 0 when TLS is disabled.
	// Labels: role ∈ {data_plane, admin, metrics}
	tlsCertExpirySeconds *prometheus.GaugeVec

	// keyRotationObjectsTotal counts objects processed by the rotation worker.
	// Labels: result ∈ {reencrypted, skipped_locked, skipped_plaintext, error}
	keyRotationObjectsTotal *prometheus.CounterVec

	// kdfAlgorithmActive reports the active KDF algorithm as a label.
	// Value: always 1.0. Labels: algorithm ∈ {pbkdf2-sha256, argon2id}
	kdfAlgorithmActive *prometheus.GaugeVec

	// adminAPIRequestsTotal counts all requests to the admin listener.
	// Labels: method, path (sanitised), status_code
	adminAPIRequestsTotal *prometheus.CounterVec

	// adminAPIRequestDuration is a histogram of admin API request durations.
	// Labels: method, path
	adminAPIRequestDuration *prometheus.HistogramVec

	// mpuActiveUploads reports the current count of in-flight multipart
	// uploads tracked in Valkey.
	mpuActiveUploads prometheus.Gauge

	// encryptedObjectBytes is a histogram of plaintext object sizes seen
	// by the encryption engine at Encrypt() time.
	encryptedObjectBytes prometheus.Histogram
}

// NewMetrics creates a new metrics instance with default configuration.
func NewMetrics() *Metrics {
	return NewMetricsWithConfig(Config{EnableBucketLabel: true})
}

// NewMetricsWithConfig creates a new metrics instance with the provided configuration.
func NewMetricsWithConfig(cfg Config) *Metrics {
	return newMetricsWithRegistry(defaultRegistry, cfg)
}

// NewMetricsWithRegistry creates a new metrics instance with a custom registry.
// This is useful for testing to avoid metric registration conflicts.
func NewMetricsWithRegistry(reg prometheus.Registerer) *Metrics {
	return newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
}

// newMetricsWithRegistry creates a new metrics instance with a custom registry (for testing).
func newMetricsWithRegistry(reg prometheus.Registerer, cfg Config) *Metrics {
	factory := promauto.With(reg)
	gatherer := defaultGatherer
	if g, ok := reg.(prometheus.Gatherer); ok {
		gatherer = g
	}
	return &Metrics{
		config:   cfg,
		gatherer: gatherer,
		httpRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total number of HTTP requests",
			},
			[]string{"method", "path", "status"},
		),
		httpRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path", "status"},
		),
		httpRequestBytes: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_request_bytes_total",
				Help: "Total bytes transferred in HTTP requests",
			},
			[]string{"method", "path"},
		),
		s3OperationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_operations_total",
				Help: "Total number of S3 operations",
			},
			[]string{"operation", "bucket"},
		),
		s3OperationDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "s3_operation_duration_seconds",
				Help:    "S3 operation duration in seconds",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"operation", "bucket"},
		),
		s3OperationErrors: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_operation_errors_total",
				Help: "Total number of S3 operation errors",
			},
			[]string{"operation", "bucket", "error_type"},
		),
		encryptionOperations: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "encryption_operations_total",
				Help: "Total number of encryption/decryption operations",
			},
			[]string{"operation"}, // "encrypt" or "decrypt"
		),
		encryptionDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "encryption_duration_seconds",
				Help:    "Encryption/decryption operation duration in seconds",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0},
			},
			[]string{"operation"},
		),
		encryptionErrors: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "encryption_errors_total",
				Help: "Total number of encryption/decryption errors",
			},
			[]string{"operation", "error_type"},
		),
		encryptionBytes: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "encryption_bytes_total",
				Help: "Total bytes encrypted/decrypted",
			},
			[]string{"operation"},
		),
		rotatedReads: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kms_rotated_reads_total",
				Help: "Total number of decryption operations using rotated (non-active) key versions",
			},
			[]string{"key_version", "active_version"},
		),
		bufferPoolHits: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "buffer_pool_hits_total",
				Help: "Total number of buffer pool hits",
			},
			[]string{"size_class"},
		),
		bufferPoolMisses: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "buffer_pool_misses_total",
				Help: "Total number of buffer pool misses",
			},
			[]string{"size_class"},
		),
		activeConnections: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "active_connections",
				Help: "Number of active HTTP connections",
			},
		),
		goroutines: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "goroutines_total",
				Help: "Number of goroutines",
			},
		),
		memoryAllocBytes: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "memory_alloc_bytes",
				Help: "Number of bytes allocated and not yet freed",
			},
		),
		memorySysBytes: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "memory_sys_bytes",
				Help: "Total bytes of memory obtained from OS",
			},
		),
		hardwareAccelerationEnabled: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "hardware_acceleration_enabled",
				Help: "Hardware acceleration status (1=enabled, 0=disabled)",
			},
			[]string{"type"},
		),
		fipsMode: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_fips_mode",
				Help: "FIPS 140-3 mode status (1=enabled, 0=disabled)",
			},
		),
		uploadPartCopyTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_upload_part_copy_total",
				Help: "Total number of UploadPartCopy operations, labelled by source encryption mode and result",
			},
			[]string{"source_mode", "result"}, // source_mode ∈ {chunked,legacy,plaintext}; result ∈ {ok,error}
		),
		uploadPartCopyBytes: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_upload_part_copy_bytes_total",
				Help: "Total plaintext bytes copied via UploadPartCopy, labelled by source encryption mode",
			},
			[]string{"source_mode"},
		),
		uploadPartCopyDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_upload_part_copy_duration_seconds",
				Help:    "UploadPartCopy operation duration in seconds, labelled by source encryption mode",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"source_mode"},
		),
		uploadPartCopyLegacyFallbackTotal: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "gateway_upload_part_copy_legacy_fallback_total",
				Help: "Total number of UploadPartCopy operations that used the legacy (full-object-buffer) fallback path",
			},
		),
		kmsActiveKeyVersion: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "kms_active_key_version",
				Help: "Currently active KMS key version per provider",
			},
			[]string{"provider"},
		),
		kmsRotationOpsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "kms_rotation_operations_total",
				Help: "Total number of key rotation operations by step and result",
			},
			[]string{"step", "result"},
		),
		kmsRotationDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "kms_rotation_duration_seconds",
				Help:    "Duration of key rotation operations by step",
				Buckets: []float64{0.001, 0.01, 0.05, 0.1, 0.5, 1, 5, 10, 30},
			},
			[]string{"step"},
		),
		kmsRotationInFlightWraps: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "kms_rotation_in_flight_wraps",
				Help: "Number of in-flight WrapKey operations during rotation drain",
			},
		),
		gatewayAdminAPIEnabled: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_admin_api_enabled",
				Help: "Whether the admin API listener is enabled (1=enabled, 0=disabled)",
			},
		),
		gatewayRotationSkippedLocked: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_rotation_skipped_locked_total",
				Help: "Objects skipped during key rotation because they are Object-Lock-protected at the backend (labelled by mode: COMPLIANCE, GOVERNANCE, LEGAL_HOLD).",
			},
			[]string{"mode"},
		),

		// V0.6-SEC-3 MPU metrics.
		mpuEncryptedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_encrypted_total",
				Help: "Total encrypted multipart uploads completed (result=success|error).",
			},
			[]string{"result"},
		),
		mpuPartsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_parts_total",
				Help: "Total encrypted multipart parts uploaded (result=success|error).",
			},
			[]string{"result"},
		),
		mpuStateStoreOps: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_state_store_ops_total",
				Help: "Total Valkey state store operations (op=create|append|get|delete|healthcheck; result=success|error).",
			},
			[]string{"op", "result"},
		),
		mpuStateStoreLatency: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_mpu_state_store_latency_seconds",
				Help:    "Latency of Valkey state store operations in seconds.",
				Buckets: []float64{0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5},
			},
			[]string{"op"},
		),
		mpuValkeyUp: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_mpu_valkey_up",
				Help: "1 if the last Valkey health check succeeded, 0 otherwise.",
			},
		),
		mpuValkeyInsecure: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_mpu_valkey_insecure",
				Help: "1 if the gateway was started with insecure_allow_plaintext=true for Valkey.",
			},
		),
		mpuManifestBytes: factory.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "gateway_mpu_manifest_bytes",
				Help:    "Size of serialised MPU manifests in bytes.",
				Buckets: []float64{256, 512, 1024, 1800, 4096, 16384},
			},
		),
		mpuManifestStorage: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_manifest_storage_total",
				Help: "MPU manifests by storage location (location=inline|fallback).",
			},
			[]string{"location"},
		),

		// V1.0-CRYPTO-2 — MPU state at-rest encryption metrics.
		mpuStateEncryptedWrites: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_mpu_state_encrypted_writes_total",
				Help: "Total successful encrypted writes of Valkey MPU state blobs (op=create|get|list).",
			},
			[]string{"op"},
		),
		mpuStateLegacyReads: factory.NewCounter(
			prometheus.CounterOpts{
				Name: "gateway_mpu_state_legacy_reads_total",
				Help: "Total fallback reads of unencrypted (legacy plaintext) Valkey MPU state blobs.",
			},
		),

		// V0.6-PERF-2 — backend retry metrics (ADR 0010).
		s3BackendRetriesTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_backend_retries_total",
				Help: "Total S3 backend retry attempts, labelled by operation, classifier reason, and retry mode.",
			},
			[]string{"operation", "reason", "mode"},
		),
		s3BackendAttemptsPerRequest: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "s3_backend_attempts_per_request",
				Help:    "Total attempts (including first) made per logical S3 backend request.",
				Buckets: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			},
			[]string{"operation"},
		),
		s3BackendRetryGiveUpsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_backend_retry_give_ups_total",
				Help: "S3 backend operations that exhausted MaxAttempts, labelled by operation and final classifier reason.",
			},
			[]string{"operation", "final_reason"},
		),
		s3BackendRetryBackoffSeconds: factory.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "s3_backend_retry_backoff_seconds",
				Help:    "Backoff delays actually slept before a retry attempt, in seconds.",
				Buckets: []float64{0.001, 0.01, 0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20},
			},
		),

		// V0.6-OBS-1 — admin pprof metrics.
		s3GatewayAdminPprofRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3_gateway_admin_pprof_requests_total",
				Help: "Total pprof profile fetches via the admin API, labelled by endpoint and outcome.",
			},
			[]string{"endpoint", "outcome"}, // endpoint ∈ 11 paths; outcome ∈ {ok,busy,bad_request,error}
		),
		gatewayAdminProfilingEnabled: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_admin_profiling_enabled",
				Help: "Whether pprof profiling routes are mounted on the admin listener (1=enabled, 0=disabled).",
			},
		),

		// V1.0-OBS-1 — observability phase A new metrics.
		kmsHealthy: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gateway_kms_healthy",
				Help: "KMS health status per provider (1=healthy, 0=unhealthy/unavailable).",
			},
			[]string{"provider"},
		),

		// V1.0-KMS-1 — KMS production readiness metrics.
		kmsDEKCacheHits: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_kms_dek_cache_hits_total",
				Help: "Total number of DEK unwrap cache hits, labelled by provider.",
			},
			[]string{"provider"},
		),
		kmsDEKCacheMisses: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_kms_dek_cache_misses_total",
				Help: "Total number of DEK unwrap cache misses (went to KMS), labelled by provider.",
			},
			[]string{"provider"},
		),
		kmsCircuitBreakerState: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gateway_kms_circuit_breaker_state",
				Help: "Current circuit-breaker state (0=closed, 1=open, 2=half-open), labelled by provider.",
			},
			[]string{"provider"},
		),
		kmsRetryAttemptsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_kms_retry_attempts_total",
				Help: "Total KMS retry attempts, labelled by provider, operation (wrap/unwrap), and outcome (success/failure).",
			},
			[]string{"provider", "operation", "outcome"},
		),

		metadataEncryptionEnabled: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_metadata_encryption_enabled",
				Help: "Whether encrypted-object-metadata (V1.0-CRYPTO-3) is active (1=active, 0=inactive).",
			},
		),
		tlsCertExpirySeconds: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gateway_tls_cert_expiry_seconds",
				Help: "Seconds until TLS certificate expiry per role (0 when TLS is disabled).",
			},
			[]string{"role"},
		),
		keyRotationObjectsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_key_rotation_objects_total",
				Help: "Objects processed by the key rotation worker, labelled by result.",
			},
			[]string{"result"},
		),
		kdfAlgorithmActive: factory.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "gateway_kdf_algorithm_active",
				Help: "Active KDF algorithm (value always 1.0, label indicates algorithm).",
			},
			[]string{"algorithm"},
		),
		adminAPIRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: "gateway_admin_api_requests_total",
				Help: "Total admin API requests by method, sanitised path, and status code.",
			},
			[]string{"method", "path", "status_code"},
		),
		adminAPIRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "gateway_admin_api_request_duration_seconds",
				Help:    "Admin API request duration in seconds by method and path.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "path"},
		),
		mpuActiveUploads: factory.NewGauge(
			prometheus.GaugeOpts{
				Name: "gateway_mpu_active_uploads",
				Help: "Current number of in-flight multipart uploads tracked in Valkey.",
			},
		),
		encryptedObjectBytes: factory.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "gateway_encrypted_object_bytes",
				Help:    "Plaintext object size distribution at Encrypt() time.",
				Buckets: []float64{1 << 10, 16 << 10, 256 << 10, 1 << 20, 16 << 20, 64 << 20, 256 << 20, 1 << 30},
			},
		),
	}
}

// SetHardwareAccelerationStatus sets the hardware acceleration status metric.
func (m *Metrics) SetHardwareAccelerationStatus(accelType string, enabled bool) {
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.hardwareAccelerationEnabled.WithLabelValues(accelType).Set(val)
}

// SetFIPSMode sets the FIPS 140-3 mode status metric.
func (m *Metrics) SetFIPSMode(enabled bool) {
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.fipsMode.Set(val)
}

// GetHardwareAccelerationEnabledMetric returns the hardware acceleration enabled metric (for testing).
func (m *Metrics) GetHardwareAccelerationEnabledMetric() *prometheus.GaugeVec {
	return m.hardwareAccelerationEnabled
}

// SetActiveKeyVersion sets the active KMS key version gauge.
func (m *Metrics) SetActiveKeyVersion(provider string, version int) {
	m.kmsActiveKeyVersion.WithLabelValues(provider).Set(float64(version))
}

// RecordRotationOperation records a rotation operation counter and duration.
func (m *Metrics) RecordRotationOperation(step, result string, duration time.Duration) {
	m.kmsRotationOpsTotal.WithLabelValues(step, result).Inc()
	m.kmsRotationDuration.WithLabelValues(step).Observe(duration.Seconds())
}

// SetRotationInFlightWraps sets the in-flight wraps gauge.
func (m *Metrics) SetRotationInFlightWraps(count int64) {
	m.kmsRotationInFlightWraps.Set(float64(count))
}

// RecordPprofRequest increments the bounded-cardinality pprof request counter.
// endpoint is the short endpoint label (e.g. "heap", "profile"); outcome is one
// of "ok", "busy", "bad_request", "error".
// V0.6-OBS-1 — implements ProfilingMetrics interface for internal/admin/profiling.go.
func (m *Metrics) RecordPprofRequest(endpoint, outcome string) {
	if m == nil || m.s3GatewayAdminPprofRequestsTotal == nil {
		return
	}
	m.s3GatewayAdminPprofRequestsTotal.WithLabelValues(endpoint, outcome).Inc()
}

// SetAdminProfilingEnabled sets the gateway_admin_profiling_enabled gauge.
// V0.6-OBS-1.
func (m *Metrics) SetAdminProfilingEnabled(enabled bool) {
	if m == nil || m.gatewayAdminProfilingEnabled == nil {
		return
	}
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.gatewayAdminProfilingEnabled.Set(val)
}

// SetAdminAPIEnabled sets the admin API enabled gauge.
func (m *Metrics) SetAdminAPIEnabled(enabled bool) {
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.gatewayAdminAPIEnabled.Set(val)
}

// RecordRotationSkippedLocked records that a key-rotation attempt
// skipped an object because it is Object-Lock-protected at the backend.
// mode should be one of "COMPLIANCE", "GOVERNANCE", or "LEGAL_HOLD".
// V0.6-S3-2 — see ADR 0008.
func (m *Metrics) RecordRotationSkippedLocked(mode string) {
	if m == nil || m.gatewayRotationSkippedLocked == nil {
		return
	}
	m.gatewayRotationSkippedLocked.WithLabelValues(mode).Inc()
}

// GetRotatedReadsMetric returns the rotated reads metric (for testing).
func (m *Metrics) GetRotatedReadsMetric() *prometheus.CounterVec {
	return m.rotatedReads
}

// RecordHTTPRequest records an HTTP request metric.
func (m *Metrics) RecordHTTPRequest(ctx context.Context, method, path string, status int, duration time.Duration, bytes int64) {
	label := sanitizePathLabel(path)
	labels := prometheus.Labels{"method": method, "path": label, "status": http.StatusText(status)}

	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.httpRequestsTotal.With(labels).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.httpRequestsTotal.With(labels).Inc()
		}

		if observer, ok := m.httpRequestDuration.With(labels).(prometheus.ExemplarObserver); ok {
			observer.ObserveWithExemplar(duration.Seconds(), exemplar)
		} else {
			m.httpRequestDuration.With(labels).Observe(duration.Seconds())
		}
	} else {
		m.httpRequestsTotal.With(labels).Inc()
		m.httpRequestDuration.With(labels).Observe(duration.Seconds())
	}

	// No exemplars for byte counters usually
	m.httpRequestBytes.WithLabelValues(method, label).Add(float64(bytes))
}

// sanitizePathLabel reduces high-cardinality paths to stable labels.
// Examples:
// "/metrics" => "/metrics"
// "/bucket/key/long/path" => "/bucket/*"
func sanitizePathLabel(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	// Trim query if any (defensive; callers typically pass Path only)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	// Split into segments
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segs) <= 1 {
		return "/" + segs[0]
	}
	return "/" + segs[0] + "/*"
}

// RecordS3Operation records an S3 operation metric.
func (m *Metrics) RecordS3Operation(ctx context.Context, operation, bucket string, duration time.Duration) {
	bucketLabel := bucket
	if !m.config.EnableBucketLabel {
		bucketLabel = "*"
	}

	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.s3OperationsTotal.WithLabelValues(operation, bucketLabel).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.s3OperationsTotal.WithLabelValues(operation, bucketLabel).Inc()
		}

		if observer, ok := m.s3OperationDuration.WithLabelValues(operation, bucketLabel).(prometheus.ExemplarObserver); ok {
			observer.ObserveWithExemplar(duration.Seconds(), exemplar)
		} else {
			m.s3OperationDuration.WithLabelValues(operation, bucketLabel).Observe(duration.Seconds())
		}
	} else {
		m.s3OperationsTotal.WithLabelValues(operation, bucketLabel).Inc()
		m.s3OperationDuration.WithLabelValues(operation, bucketLabel).Observe(duration.Seconds())
	}
}

// RecordS3Error records an S3 operation error.
func (m *Metrics) RecordS3Error(ctx context.Context, operation, bucket, errorType string) {
	bucketLabel := bucket
	if !m.config.EnableBucketLabel {
		bucketLabel = "*"
	}

	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.s3OperationErrors.WithLabelValues(operation, bucketLabel, errorType).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.s3OperationErrors.WithLabelValues(operation, bucketLabel, errorType).Inc()
		}
	} else {
		m.s3OperationErrors.WithLabelValues(operation, bucketLabel, errorType).Inc()
	}
}

// RecordEncryptionOperation records an encryption operation metric.
func (m *Metrics) RecordEncryptionOperation(ctx context.Context, operation string, duration time.Duration, bytes int64) {
	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.encryptionOperations.WithLabelValues(operation).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.encryptionOperations.WithLabelValues(operation).Inc()
		}

		if observer, ok := m.encryptionDuration.WithLabelValues(operation).(prometheus.ExemplarObserver); ok {
			observer.ObserveWithExemplar(duration.Seconds(), exemplar)
		} else {
			m.encryptionDuration.WithLabelValues(operation).Observe(duration.Seconds())
		}
	} else {
		m.encryptionOperations.WithLabelValues(operation).Inc()
		m.encryptionDuration.WithLabelValues(operation).Observe(duration.Seconds())
	}

	m.encryptionBytes.WithLabelValues(operation).Add(float64(bytes))
}

// RecordEncryptionError records an encryption operation error.
func (m *Metrics) RecordEncryptionError(ctx context.Context, operation, errorType string) {
	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.encryptionErrors.WithLabelValues(operation, errorType).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.encryptionErrors.WithLabelValues(operation, errorType).Inc()
		}
	} else {
		m.encryptionErrors.WithLabelValues(operation, errorType).Inc()
	}
}

// RecordRotatedRead records a decryption operation using a rotated (non-active) key version.
func (m *Metrics) RecordRotatedRead(ctx context.Context, keyVersion, activeVersion int) {
	if exemplar := getExemplar(ctx); exemplar != nil {
		if adder, ok := m.rotatedReads.WithLabelValues(strconv.Itoa(keyVersion), strconv.Itoa(activeVersion)).(prometheus.ExemplarAdder); ok {
			adder.AddWithExemplar(1, exemplar)
		} else {
			m.rotatedReads.WithLabelValues(strconv.Itoa(keyVersion), strconv.Itoa(activeVersion)).Inc()
		}
	} else {
		m.rotatedReads.WithLabelValues(
			strconv.Itoa(keyVersion),
			strconv.Itoa(activeVersion),
		).Inc()
	}
}

// RecordBufferPoolHit records a buffer pool hit.
func (m *Metrics) RecordBufferPoolHit(sizeClass string) {
	m.bufferPoolHits.WithLabelValues(sizeClass).Inc()
}

// RecordBufferPoolMiss records a buffer pool miss.
func (m *Metrics) RecordBufferPoolMiss(sizeClass string) {
	m.bufferPoolMisses.WithLabelValues(sizeClass).Inc()
}

// UpdateSystemMetrics updates system-level metrics (goroutines, memory).
func (m *Metrics) UpdateSystemMetrics() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	m.goroutines.Set(float64(runtime.NumGoroutine()))
	m.memoryAllocBytes.Set(float64(memStats.Alloc))
	m.memorySysBytes.Set(float64(memStats.Sys))
}

// IncrementActiveConnections increments the active connections counter.
func (m *Metrics) IncrementActiveConnections() {
	m.activeConnections.Inc()
}

// DecrementActiveConnections decrements the active connections counter.
func (m *Metrics) DecrementActiveConnections() {
	m.activeConnections.Dec()
}

// RecordUploadPartCopy records an UploadPartCopy operation.
// sourceMode MUST be one of "chunked", "legacy", "plaintext" (to keep label
// cardinality bounded). result MUST be "ok" or "error". bytesCopied is the
// number of plaintext bytes transferred into the destination part (0 on
// error). A single call emits to the total, bytes, and duration metrics; if
// sourceMode == "legacy" the legacy_fallback counter is also incremented.
func (m *Metrics) RecordUploadPartCopy(sourceMode, result string, bytesCopied int64, duration time.Duration) {
	m.uploadPartCopyTotal.WithLabelValues(sourceMode, result).Inc()
	m.uploadPartCopyDuration.WithLabelValues(sourceMode).Observe(duration.Seconds())
	if bytesCopied > 0 {
		m.uploadPartCopyBytes.WithLabelValues(sourceMode).Add(float64(bytesCopied))
	}
	if sourceMode == "legacy" {
		m.uploadPartCopyLegacyFallbackTotal.Inc()
	}
}

// StartSystemMetricsCollector starts a goroutine that periodically updates system metrics.
func (m *Metrics) StartSystemMetricsCollector() {
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for range ticker.C {
			m.UpdateSystemMetrics()
		}
	}()
}

// Handler returns the HTTP handler for metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	if m != nil && m.gatherer != nil {
		return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
	}
	return promhttp.Handler()
}

// RecordMPUEncrypted increments the gateway_mpu_encrypted_total counter.
func (m *Metrics) RecordMPUEncrypted(result string) {
	if m == nil || m.mpuEncryptedTotal == nil {
		return
	}
	m.mpuEncryptedTotal.WithLabelValues(result).Inc()
}

// RecordMPUPart increments the gateway_mpu_parts_total counter.
func (m *Metrics) RecordMPUPart(result string) {
	if m == nil || m.mpuPartsTotal == nil {
		return
	}
	m.mpuPartsTotal.WithLabelValues(result).Inc()
}

// RecordMPUStateStoreOp records a Valkey state store operation.
func (m *Metrics) RecordMPUStateStoreOp(op, result string, duration time.Duration) {
	if m == nil {
		return
	}
	if m.mpuStateStoreOps != nil {
		m.mpuStateStoreOps.WithLabelValues(op, result).Inc()
	}
	if m.mpuStateStoreLatency != nil {
		m.mpuStateStoreLatency.WithLabelValues(op).Observe(duration.Seconds())
	}
}

// SetMPUValkeyUp sets the gateway_mpu_valkey_up gauge.
func (m *Metrics) SetMPUValkeyUp(up bool) {
	if m == nil || m.mpuValkeyUp == nil {
		return
	}
	if up {
		m.mpuValkeyUp.Set(1)
	} else {
		m.mpuValkeyUp.Set(0)
	}
}

// SetMPUValkeyInsecure sets the gateway_mpu_valkey_insecure gauge.
func (m *Metrics) SetMPUValkeyInsecure(insecure bool) {
	if m == nil || m.mpuValkeyInsecure == nil {
		return
	}
	if insecure {
		m.mpuValkeyInsecure.Set(1)
	} else {
		m.mpuValkeyInsecure.Set(0)
	}
}

// ObserveMPUManifestBytes records manifest serialised size.
func (m *Metrics) ObserveMPUManifestBytes(n int) {
	if m == nil || m.mpuManifestBytes == nil {
		return
	}
	m.mpuManifestBytes.Observe(float64(n))
}

// RecordMPUManifestStorage increments the manifest storage location counter.
func (m *Metrics) RecordMPUManifestStorage(location string) {
	if m == nil || m.mpuManifestStorage == nil {
		return
	}
	m.mpuManifestStorage.WithLabelValues(location).Inc()
}

// ---- V0.6-PERF-2 backend retry metric helpers --------------------------------

// RecordBackendRetry increments the retry counter for a single retry attempt.
// op is the SDK operation name; reason is from the closed set in retry.go.
// mode is the retry mode string ("standard", "adaptive", "off").
func (m *Metrics) RecordBackendRetry(op, reason string) {
	if m == nil || m.s3BackendRetriesTotal == nil {
		return
	}
	m.s3BackendRetriesTotal.WithLabelValues(op, reason, "standard").Inc()
}

// RecordBackendRetryWithMode is like RecordBackendRetry but accepts an
// explicit mode label.  Used when the mode is known at the call site.
func (m *Metrics) RecordBackendRetryWithMode(op, reason, mode string) {
	if m == nil || m.s3BackendRetriesTotal == nil {
		return
	}
	m.s3BackendRetriesTotal.WithLabelValues(op, reason, mode).Inc()
}

// RecordBackendAttemptsPerRequest records the total number of attempts made
// for a single logical S3 request (including the original; ≥ 1).
func (m *Metrics) RecordBackendAttemptsPerRequest(op string, attempts int) {
	if m == nil || m.s3BackendAttemptsPerRequest == nil {
		return
	}
	m.s3BackendAttemptsPerRequest.WithLabelValues(op).Observe(float64(attempts))
}

// RecordBackendRetryGiveUp increments the give-up counter when MaxAttempts
// has been exhausted.
func (m *Metrics) RecordBackendRetryGiveUp(op, finalReason string) {
	if m == nil || m.s3BackendRetryGiveUpsTotal == nil {
		return
	}
	m.s3BackendRetryGiveUpsTotal.WithLabelValues(op, finalReason).Inc()
}

// RecordBackendRetryBackoff observes the actual backoff delay slept (in seconds).
func (m *Metrics) RecordBackendRetryBackoff(delay time.Duration) {
	if m == nil || m.s3BackendRetryBackoffSeconds == nil {
		return
	}
	if delay > 0 {
		m.s3BackendRetryBackoffSeconds.Observe(delay.Seconds())
	}
}

// ---- V1.0-CRYPTO-2 MPU state encryption metric helpers ----------------------

// IncMPUStateEncryptedWrites increments gateway_mpu_state_encrypted_writes_total
// for the given operation label (e.g. "create", "get", "list").
func (m *Metrics) IncMPUStateEncryptedWrites(op string) {
	if m == nil || m.mpuStateEncryptedWrites == nil {
		return
	}
	m.mpuStateEncryptedWrites.WithLabelValues(op).Inc()
}

// IncMPUStateLegacyReads increments gateway_mpu_state_legacy_reads_total.
// Call this whenever the state store falls back to reading an unencrypted
// (legacy plaintext) Valkey blob.
func (m *Metrics) IncMPUStateLegacyReads() {
	if m == nil || m.mpuStateLegacyReads == nil {
		return
	}
	m.mpuStateLegacyReads.Inc()
}

// ---- V1.0-OBS-1 new metric helpers ------------------------------------------

// SetKMSHealthy sets the KMS health status gauge for the given provider.
// healthy=true sets 1, healthy=false sets 0.
func (m *Metrics) SetKMSHealthy(provider string, healthy bool) {
	if m == nil || m.kmsHealthy == nil {
		return
	}
	val := 0.0
	if healthy {
		val = 1.0
	}
	m.kmsHealthy.WithLabelValues(provider).Set(val)
}

// ---- V1.0-KMS-1 metric helpers --------------------------------------------

// RecordKMSDEKCacheHit increments the DEK cache hit counter for the provider.
func (m *Metrics) RecordKMSDEKCacheHit(provider string) {
	if m == nil || m.kmsDEKCacheHits == nil {
		return
	}
	m.kmsDEKCacheHits.WithLabelValues(provider).Inc()
}

// RecordKMSDEKCacheMiss increments the DEK cache miss counter for the provider.
func (m *Metrics) RecordKMSDEKCacheMiss(provider string) {
	if m == nil || m.kmsDEKCacheMisses == nil {
		return
	}
	m.kmsDEKCacheMisses.WithLabelValues(provider).Inc()
}

// SetKMSCircuitBreakerState sets the circuit-breaker state gauge for the provider.
// State: 0 = closed, 1 = open, 2 = half-open.
func (m *Metrics) SetKMSCircuitBreakerState(provider string, state int) {
	if m == nil || m.kmsCircuitBreakerState == nil {
		return
	}
	m.kmsCircuitBreakerState.WithLabelValues(provider).Set(float64(state))
}

// RecordKMSRetryAttempt increments the KMS retry attempt counter.
// operation ∈ {"wrap", "unwrap"}, outcome ∈ {"success", "failure"}.
func (m *Metrics) RecordKMSRetryAttempt(provider, operation, outcome string) {
	if m == nil || m.kmsRetryAttemptsTotal == nil {
		return
	}
	m.kmsRetryAttemptsTotal.WithLabelValues(provider, operation, outcome).Inc()
}

// SetMetadataEncryptionEnabled sets the metadata encryption enabled gauge.
func (m *Metrics) SetMetadataEncryptionEnabled(enabled bool) {
	if m == nil || m.metadataEncryptionEnabled == nil {
		return
	}
	val := 0.0
	if enabled {
		val = 1.0
	}
	m.metadataEncryptionEnabled.Set(val)
}

// SetTLSCertExpiry sets the TLS certificate expiry gauge for the given role.
// If the certificate is not loaded or TLS is disabled, call with a zero time.
func (m *Metrics) SetTLSCertExpiry(role string, expiresAt time.Time) {
	if m == nil || m.tlsCertExpirySeconds == nil {
		return
	}
	var seconds float64
	if !expiresAt.IsZero() {
		seconds = time.Until(expiresAt).Seconds()
		if seconds < 0 {
			seconds = 0
		}
	}
	m.tlsCertExpirySeconds.WithLabelValues(role).Set(seconds)
}

// RecordKeyRotationObject increments the key rotation objects counter.
// result is one of "reencrypted", "skipped_locked", "skipped_plaintext", "error".
func (m *Metrics) RecordKeyRotationObject(result string) {
	if m == nil || m.keyRotationObjectsTotal == nil {
		return
	}
	m.keyRotationObjectsTotal.WithLabelValues(result).Inc()
}

// SetKDFAlgorithmActive sets the active KDF algorithm gauge.
// The value is always 1.0; the label identifies which algorithm is in use.
func (m *Metrics) SetKDFAlgorithmActive(algorithm string) {
	if m == nil || m.kdfAlgorithmActive == nil {
		return
	}
	m.kdfAlgorithmActive.WithLabelValues(algorithm).Set(1.0)
}

// RecordAdminAPIRequest records an admin API request counter + duration.
// path is sanitised before use as a label to bound cardinality.
func (m *Metrics) RecordAdminAPIRequest(method, path string, status int, duration time.Duration) {
	if m == nil || m.adminAPIRequestsTotal == nil {
		return
	}
	label := sanitizePathLabel(path)
	m.adminAPIRequestsTotal.WithLabelValues(method, label, http.StatusText(status)).Inc()
	if m.adminAPIRequestDuration != nil {
		m.adminAPIRequestDuration.WithLabelValues(method, label).Observe(duration.Seconds())
	}
}

// SetMPUActiveUploads sets the current count of in-flight multipart uploads.
func (m *Metrics) SetMPUActiveUploads(count int64) {
	if m == nil || m.mpuActiveUploads == nil {
		return
	}
	m.mpuActiveUploads.Set(float64(count))
}

// ObserveEncryptedObjectBytes observes the plaintext size of an encrypted object.
func (m *Metrics) ObserveEncryptedObjectBytes(n int64) {
	if m == nil || m.encryptedObjectBytes == nil {
		return
	}
	m.encryptedObjectBytes.Observe(float64(n))
}

// IncMPUActiveUploads atomically increments the active MPU upload gauge by 1.
func (m *Metrics) IncMPUActiveUploads() {
	if m == nil || m.mpuActiveUploads == nil {
		return
	}
	m.mpuActiveUploads.Inc()
}

// DecMPUActiveUploads atomically decrements the active MPU upload gauge by 1.
func (m *Metrics) DecMPUActiveUploads() {
	if m == nil || m.mpuActiveUploads == nil {
		return
	}
	m.mpuActiveUploads.Dec()
}

// getExemplar extracts trace ID from context and returns prometheus Labels for exemplar.
func getExemplar(ctx context.Context) prometheus.Labels {
	if ctx == nil {
		return nil
	}
	spanContext := trace.SpanFromContext(ctx).SpanContext()
	if spanContext.IsValid() {
		return prometheus.Labels{"trace_id": spanContext.TraceID().String()}
	}
	return nil
}
