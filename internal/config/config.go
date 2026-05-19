package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Config holds the complete application configuration.
type Config struct {
	ListenAddr     string               `yaml:"listen_addr" env:"LISTEN_ADDR"`
	LogLevel       string               `yaml:"log_level" env:"LOG_LEVEL"`
	ProxiedBucket  string               `yaml:"proxied_bucket" env:"PROXIED_BUCKET"` // If set, only this bucket will be accessible
	Backend        BackendConfig        `yaml:"backend"`
	Encryption     EncryptionConfig     `yaml:"encryption"`
	Compression    CompressionConfig    `yaml:"compression"`
	Cache          CacheConfig          `yaml:"cache"`
	Audit          AuditConfig          `yaml:"audit"`
	TLS            TLSConfig            `yaml:"tls"`
	Server         ServerConfig         `yaml:"server"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit"`
	Tracing        TracingConfig        `yaml:"tracing"`
	Metrics        MetricsConfig        `yaml:"metrics"`
	Logging        LoggingConfig        `yaml:"logging"`
	Admin          AdminConfig          `yaml:"admin"`
	Auth           AuthConfig           `yaml:"auth"`
	PolicyFiles    []string             `yaml:"policies" env:"POLICIES"`
	MultipartState MultipartStateConfig `yaml:"multipart_state"`
}

// ResolvedCredentials returns a copy of the auth credentials with SecretKeyEnv
// values resolved from the environment.  The returned slice is safe to mutate
// (it does not alias the underlying config).
func (c *Config) ResolvedCredentials() []GatewayCredential {
	resolved := make([]GatewayCredential, len(c.Auth.Credentials))
	for i, cred := range c.Auth.Credentials {
		resolved[i] = cred
		if cred.SecretKeyEnv != "" {
			if v := os.Getenv(cred.SecretKeyEnv); v != "" {
				resolved[i].SecretKey = v
			}
		}
	}
	return resolved
}

// BackendConfig holds S3 backend configuration.
type BackendConfig struct {
	Endpoint     string `yaml:"endpoint" env:"BACKEND_ENDPOINT"`
	Region       string `yaml:"region" env:"BACKEND_REGION"`
	AccessKey    string `yaml:"access_key" env:"BACKEND_ACCESS_KEY"`
	SecretKey    string `yaml:"secret_key" env:"BACKEND_SECRET_KEY"`
	Provider     string `yaml:"provider" env:"BACKEND_PROVIDER"` // aws, wasabi, hetzner, minio, digitalocean, backblaze, cloudflare, linode, scaleway, oracle, idrive
	UseSSL       bool   `yaml:"use_ssl" env:"BACKEND_USE_SSL"`
	UsePathStyle bool   `yaml:"use_path_style" env:"BACKEND_USE_PATH_STYLE"`
	// Compatibility options for backends with metadata restrictions
	FilterMetadataKeys []string `yaml:"filter_metadata_keys" env:"BACKEND_FILTER_METADATA_KEYS"` // Comma-separated list of metadata keys to filter out
	// Retry governs the S3 backend retry policy (V0.6-PERF-2).
	// All fields are optional; zero values fall back to the DefaultBackendRetry* constants.
	Retry BackendRetryConfig `yaml:"retry"`
}

// BackendRetryConfig governs retries emitted by the S3 backend client.
// All fields optional; zero values fall back to safe defaults (see
// DefaultBackendRetry* constants). See docs/adr/0010-backend-retry-policy.md.
//
// V0.6-PERF-2 — Phase B.
type BackendRetryConfig struct {
	// Mode selects the retryer implementation.
	//   "standard" (default) — exponential backoff with jitter
	//   "adaptive"           — token bucket + adaptive rate limit
	//   "off"                — no retries (single attempt only)
	Mode string `yaml:"mode" env:"BACKEND_RETRY_MODE"`

	// MaxAttempts is the total number of attempts (including the first).
	// Must be >= 1. Default: 3.
	MaxAttempts int `yaml:"max_attempts" env:"BACKEND_RETRY_MAX_ATTEMPTS"`

	// InitialBackoff is the base delay before the first retry.
	// Default: 100 ms.
	InitialBackoff time.Duration `yaml:"initial_backoff" env:"BACKEND_RETRY_INITIAL_BACKOFF"`

	// MaxBackoff caps the per-attempt delay. Default: 20 s (matches SDK default).
	MaxBackoff time.Duration `yaml:"max_backoff" env:"BACKEND_RETRY_MAX_BACKOFF"`

	// Jitter selects the jitter algorithm.
	//   "full"         (default) — uniform [0, computed]
	//   "decorrelated"           — AWS Architecture Blog algorithm; best under high contention
	//   "equal"                  — half computed + uniform half
	//   "none"                   — no jitter (debug only; unsafe under contention)
	Jitter string `yaml:"jitter" env:"BACKEND_RETRY_JITTER"`

	// PerOperation overrides MaxAttempts per S3 API verb.  Keys are canonical
	// SDK operation names: "PutObject", "GetObject", "HeadObject", "UploadPart",
	// "CompleteMultipartUpload", "CopyObject", "UploadPartCopy", "DeleteObject",
	// "DeleteObjects", "ListObjectsV2", "ListParts", etc.
	// A value of 1 disables retries for that operation.
	// CompleteMultipartUpload defaults to 1 (non-idempotent post-commit).
	PerOperation map[string]int `yaml:"per_operation"`

	// SafeCopyObject enables retrying CopyObject. Some applications require
	// If-Match/If-None-Match contracts that break across a retried copy;
	// disable here to opt out. Default: true (nil → true).
	SafeCopyObject *bool `yaml:"safe_copy_object" env:"BACKEND_RETRY_SAFE_COPY_OBJECT"`
}

// Default values for BackendRetryConfig.
const (
	DefaultBackendRetryMode           = "standard"
	DefaultBackendRetryMaxAttempts    = 3
	DefaultBackendRetryInitialBackoff = 100 * time.Millisecond
	DefaultBackendRetryMaxBackoff     = 20 * time.Second
	DefaultBackendRetryJitter         = "full"
)

// knownOperationNames is the closed set of S3 operation names that may appear
// in BackendRetryConfig.PerOperation.  Unknown keys are rejected at validation
// time to surface typos promptly.
var knownOperationNames = map[string]bool{
	"PutObject":                true,
	"GetObject":                true,
	"HeadObject":               true,
	"UploadPart":               true,
	"CompleteMultipartUpload":  true,
	"CreateMultipartUpload":    true,
	"AbortMultipartUpload":     true,
	"ListParts":                true,
	"CopyObject":               true,
	"UploadPartCopy":           true,
	"DeleteObject":             true,
	"DeleteObjects":            true,
	"ListObjectsV2":            true,
	"ListObjects":              true,
	"PutObjectRetention":       true,
	"GetObjectRetention":       true,
	"PutObjectLegalHold":       true,
	"GetObjectLegalHold":       true,
	"PutObjectLockConfiguration": true,
	"GetObjectLockConfiguration": true,
}

// Normalize fills zero-value fields with their documented defaults.
// It is idempotent and safe to call multiple times.
func (r *BackendRetryConfig) Normalize() {
	if r.Mode == "" {
		r.Mode = DefaultBackendRetryMode
	}
	if r.MaxAttempts <= 0 {
		r.MaxAttempts = DefaultBackendRetryMaxAttempts
	}
	if r.InitialBackoff <= 0 {
		r.InitialBackoff = DefaultBackendRetryInitialBackoff
	}
	if r.MaxBackoff <= 0 {
		r.MaxBackoff = DefaultBackendRetryMaxBackoff
	}
	if r.Jitter == "" {
		r.Jitter = DefaultBackendRetryJitter
	}
	if r.SafeCopyObject == nil {
		t := true
		r.SafeCopyObject = &t
	}
}

// Validate checks the config for invalid values and returns a descriptive
// error if any field is out of range.  Normalize must be called first.
func (r *BackendRetryConfig) Validate() error {
	switch r.Mode {
	case "standard", "adaptive", "off":
	default:
		return fmt.Errorf("backend.retry.mode must be \"standard\", \"adaptive\", or \"off\" (got %q)", r.Mode)
	}
	if r.MaxAttempts < 1 {
		return fmt.Errorf("backend.retry.max_attempts must be >= 1 (got %d)", r.MaxAttempts)
	}
	if r.MaxAttempts > 10 {
		return fmt.Errorf("backend.retry.max_attempts must be <= 10 to prevent runaway retries (got %d)", r.MaxAttempts)
	}
	if r.InitialBackoff < time.Millisecond {
		return fmt.Errorf("backend.retry.initial_backoff must be >= 1ms (got %s)", r.InitialBackoff)
	}
	if r.MaxBackoff < r.InitialBackoff {
		return fmt.Errorf("backend.retry.max_backoff (%s) must be >= initial_backoff (%s)", r.MaxBackoff, r.InitialBackoff)
	}
	if r.MaxBackoff > 5*time.Minute {
		return fmt.Errorf("backend.retry.max_backoff must be <= 5m (got %s)", r.MaxBackoff)
	}
	switch r.Jitter {
	case "full", "decorrelated", "equal", "none":
	default:
		return fmt.Errorf("backend.retry.jitter must be \"full\", \"decorrelated\", \"equal\", or \"none\" (got %q)", r.Jitter)
	}
	for op, attempts := range r.PerOperation {
		if !knownOperationNames[op] {
			return fmt.Errorf("backend.retry.per_operation: unknown operation %q (check spelling; known ops: PutObject, GetObject, HeadObject, UploadPart, CompleteMultipartUpload, CopyObject, ...)", op)
		}
		if attempts < 1 {
			return fmt.Errorf("backend.retry.per_operation[%q] must be >= 1 (got %d)", op, attempts)
		}
		if attempts > 10 {
			return fmt.Errorf("backend.retry.per_operation[%q] must be <= 10 (got %d)", op, attempts)
		}
	}
	return nil
}

// EncryptionConfig holds encryption-related configuration.

// KDFConfig is the top-level key-derivation configuration block.
type KDFConfig struct {
    PBKDF2 PBKDF2Config `yaml:"pbkdf2"`
}

// PBKDF2Config holds parameters specific to PBKDF2-SHA256 key derivation.
type PBKDF2Config struct {
    Iterations int `yaml:"iterations" env:"ENCRYPTION_KDF_PBKDF2_ITERATIONS"`
}

type EncryptionConfig struct {
	Password            string           `yaml:"password" env:"ENCRYPTION_PASSWORD"`
	KeyFile             string           `yaml:"key_file" env:"ENCRYPTION_KEY_FILE"`
	PreferredAlgorithm  string           `yaml:"preferred_algorithm" env:"ENCRYPTION_PREFERRED_ALGORITHM"`
	SupportedAlgorithms []string         `yaml:"supported_algorithms" env:"ENCRYPTION_SUPPORTED_ALGORITHMS"`
	KeyManager          KeyManagerConfig `yaml:"key_manager"`
	ChunkedMode         bool             `yaml:"chunked_mode" env:"ENCRYPTION_CHUNKED_MODE"` // Enable chunked/streaming encryption
	ChunkSize           int              `yaml:"chunk_size" env:"ENCRYPTION_CHUNK_SIZE"`     // Size of each encryption chunk in bytes
	Hardware            HardwareConfig   `yaml:"hardware"`
	KDF                 KDFConfig        `yaml:"kdf"`
}

// HardwareConfig holds hardware acceleration configuration.
type HardwareConfig struct {
	// EnableAESNI enables AES-NI hardware acceleration on x86_64 architectures.
	// Default: true
	EnableAESNI bool `yaml:"enable_aesni" env:"HARDWARE_ENABLE_AESNI"`

	// EnableARMv8AES enables ARMv8 AES hardware acceleration on ARM64 architectures.
	// Default: true
	EnableARMv8AES bool `yaml:"enable_armv8_aes" env:"HARDWARE_ENABLE_ARMV8_AES"`
}

// KeyManagerConfig holds key manager (KMS) configuration.
//
// Currently supported providers:
//   - "cosmian" or "kmip": Cosmian KMIP (fully implemented in v0.5)
//   - "memory": In-process AES key-wrap — suitable for single-node deployments,
//     tests, and local development without an external KMS (v0.6)
//   - "hsm": PKCS#11 Hardware Security Module (skeleton in v0.6; functional in v1.0;
//     requires -tags hsm build flag — see docs/adr/0004-hsm-adapter-contract.md)
//   - "self_contained": Self-contained AES-256-GCM or RSA-OAEP KEK wrapping;
//     no external KMS required (v1.0, see V1.0-KMS-4)
//
// Planned providers (v1.0):
//   - "aws" or "aws-kms": AWS KMS (see V1.0-KMS-2)
//   - "vault" or "vault-transit": HashiCorp Vault Transit (see V1.0-KMS-3)
//
// See docs/KMS_COMPATIBILITY.md for implementation status and adapter options.
type KeyManagerConfig struct {
	Enabled        bool                 `yaml:"enabled" env:"KEY_MANAGER_ENABLED"`
	Provider       string               `yaml:"provider" env:"KEY_MANAGER_PROVIDER"`
	DualReadWindow int                  `yaml:"dual_read_window" env:"KEY_MANAGER_DUAL_READ_WINDOW"`
	RotationPolicy RotationPolicyConfig `yaml:"rotation_policy"`
	Cosmian        CosmianConfig        `yaml:"cosmian"`
	Memory         MemoryKMConfig       `yaml:"memory"`
	SelfContained  SelfContainedKMConfig `yaml:"self_contained"`
	// AWS        AWSKMSConfig  `yaml:"aws"`
	// Vault      VaultConfig   `yaml:"vault"`
}

// MemoryKMConfig captures settings for the in-memory key manager adapter.
//
// The master key is loaded from the configured source once at startup and is
// never written to disk by the gateway. Supported secret reference formats for
// MasterKeySource:
//
//   - "env:VAR"   — read from environment variable VAR
//   - "file:PATH" — read from file at PATH (hex-encoded or raw bytes)
//   - ""          — auto-generate a random key (suitable for tests only;
//     keys are NOT persisted and all wrapped DEKs are lost on restart)
type MemoryKMConfig struct {
	// MasterKeySource is a secret reference or empty string (auto-generate).
	MasterKeySource string `yaml:"master_key_source" env:"MEMORY_KM_MASTER_KEY_SOURCE"`
}

// SelfContainedKMConfig captures settings for the self-contained KEK adapter.
type SelfContainedKMConfig struct {
	// Type selects the wrapping algorithm: "aes" or "rsa".
	Type string `yaml:"type" env:"SELF_CONTAINED_TYPE"`

	// AES holds settings for AES-256-GCM KEK wrapping.
	AES SelfContainedAESConfig `yaml:"aes"`

	// RSA holds settings for RSA-OAEP KEK wrapping.
	RSA SelfContainedRSAConfig `yaml:"rsa"`
}

// SelfContainedAESConfig holds AES-256-GCM KEK settings.
type SelfContainedAESConfig struct {
	// Keys is the list of versioned KEK entries.
	Keys []SelfContainedAESKeyEntry `yaml:"keys"`
	// ActiveVersion selects the wrapping version (default: highest).
	ActiveVersion int `yaml:"active_version" env:"SELF_CONTAINED_AES_ACTIVE_VERSION"`
}

// SelfContainedAESKeyEntry is a single versioned AES KEK reference.
type SelfContainedAESKeyEntry struct {
	Version   int    `yaml:"version"`
	KeySource string `yaml:"key_source"` // "env:VAR", "base64:...", "file:PATH"
}

// SelfContainedRSAConfig holds RSA-OAEP KEK settings.
type SelfContainedRSAConfig struct {
	PrivateKeySource string `yaml:"private_key_source" env:"SELF_CONTAINED_RSA_PRIVATE_KEY_SOURCE"`
	KeyVersion       int    `yaml:"key_version" env:"SELF_CONTAINED_RSA_KEY_VERSION"`
}

// RotationPolicyConfig holds key rotation policy configuration.
type RotationPolicyConfig struct {
	// Enabled enables automatic rotation policy tracking and audit events.
	// Note: Actual rotation must be performed manually by updating the key configuration.
	Enabled bool `yaml:"enabled" env:"KEY_MANAGER_ROTATION_POLICY_ENABLED"`
	// GraceWindow is the duration after rotation during which both old and new keys are accepted.
	// This should match or exceed DualReadWindow in practice.
	// Default: 0 (disabled, use DualReadWindow instead)
	GraceWindow time.Duration `yaml:"grace_window" env:"KEY_MANAGER_ROTATION_GRACE_WINDOW"`
}

// CosmianConfig captures settings for the Cosmian KMIP integration.
type CosmianConfig struct {
	Endpoint           string                `yaml:"endpoint" env:"COSMIAN_KMS_ENDPOINT"`
	Timeout            time.Duration         `yaml:"timeout" env:"COSMIAN_KMS_TIMEOUT"`
	Keys               []CosmianKeyReference `yaml:"keys"`
	ClientCert         string                `yaml:"client_cert" env:"COSMIAN_KMS_CLIENT_CERT"`
	ClientKey          string                `yaml:"client_key" env:"COSMIAN_KMS_CLIENT_KEY"`
	CACert             string                `yaml:"ca_cert" env:"COSMIAN_KMS_CA_CERT"`
	InsecureSkipVerify bool                  `yaml:"insecure_skip_verify" env:"COSMIAN_KMS_INSECURE_SKIP_VERIFY"`
}

// CosmianKeyReference maps wrapping key identifiers to metadata versions.
type CosmianKeyReference struct {
	ID      string `yaml:"id"`
	Version int    `yaml:"version"`
}

// CompressionConfig holds compression settings.
type CompressionConfig struct {
	Enabled      bool     `yaml:"enabled" env:"COMPRESSION_ENABLED"`
	MinSize      int64    `yaml:"min_size" env:"COMPRESSION_MIN_SIZE"`
	ContentTypes []string `yaml:"content_types" env:"COMPRESSION_CONTENT_TYPES"`
	Algorithm    string   `yaml:"algorithm" env:"COMPRESSION_ALGORITHM"`
	Level        int      `yaml:"level" env:"COMPRESSION_LEVEL"`
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled" env:"TLS_ENABLED"`
	CertFile string `yaml:"cert_file" env:"TLS_CERT_FILE"`
	KeyFile  string `yaml:"key_file" env:"TLS_KEY_FILE"`
}

// ServerConfig holds HTTP server configuration.
type ServerConfig struct {
	ReadTimeout       time.Duration `yaml:"read_timeout" env:"SERVER_READ_TIMEOUT"`
	WriteTimeout      time.Duration `yaml:"write_timeout" env:"SERVER_WRITE_TIMEOUT"`
	IdleTimeout       time.Duration `yaml:"idle_timeout" env:"SERVER_IDLE_TIMEOUT"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout" env:"SERVER_READ_HEADER_TIMEOUT"`
	MaxHeaderBytes    int           `yaml:"max_header_bytes" env:"SERVER_MAX_HEADER_BYTES"`
	// TrustedProxies is a list of CIDR ranges that are trusted to provide X-Forwarded-For headers.
	// If empty (default), X-Forwarded-For headers are ignored and RemoteAddr is used (fail-safe).
	// Example: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
	TrustedProxies []string `yaml:"trusted_proxies" env:"SERVER_TRUSTED_PROXIES"`
	// DisableMultipartUploads disables multipart upload operations to ensure all data is encrypted
	DisableMultipartUploads bool `yaml:"disable_multipart_uploads" env:"SERVER_DISABLE_MULTIPART_UPLOADS"`
	// MaxLegacyCopySourceBytes caps the object size the legacy (non-chunked)
	// UploadPartCopy fallback path is willing to buffer in memory. Legacy
	// single-AEAD objects cannot be range-decrypted, so copying from one
	// requires reading the entire source into memory. The default is a
	// conservative 256 MiB (opt-out safety posture): operators who need a
	// higher limit MUST explicitly raise this and size pod memory for
	// max_concurrent_copies × cap. Exceeded requests return 400
	// InvalidRequest with a message pointing operators at the chunked
	// encryption migration path. A value ≤ 0 is treated as the default.
	MaxLegacyCopySourceBytes int64 `yaml:"max_legacy_copy_source_bytes" env:"SERVER_MAX_LEGACY_COPY_SOURCE_BYTES"`
	// MaxPartBuffer caps the amount of memory the gateway will allocate when
	// buffering a single UploadPart body to satisfy the AWS SDK V2 seekable-body
	// contract (SigV4 payload hashing over plaintext-HTTP backends). Parts whose
	// body exceeds this limit are rejected with HTTP 413 before any backend write
	// occurs. Default: 64 MiB. Operators uploading parts larger than 64 MiB
	// should raise this value and size pod memory accordingly.
	// V0.6-PERF-1 — Phase D.
	MaxPartBuffer int64 `yaml:"max_part_buffer" env:"SERVER_MAX_PART_BUFFER"`
	// ForceHTTPS unconditionally sends the HSTS header regardless of whether
	// the request arrived over TLS. This is required when the gateway runs
	// behind a TLS-terminating reverse proxy (nginx, ALB, Traefik, etc.)
	// where r.TLS is always nil on the Go side.
	ForceHTTPS bool `yaml:"force_https" env:"SERVER_FORCE_HTTPS"`
}

// DefaultMaxLegacyCopySourceBytes is the default cap for the legacy
// UploadPartCopy fallback path (256 MiB). See ServerConfig.MaxLegacyCopySourceBytes.
const DefaultMaxLegacyCopySourceBytes int64 = 256 * 1024 * 1024

// DefaultMaxPartBuffer is the default cap for the UploadPart seekable-body
// wrapper (64 MiB). See ServerConfig.MaxPartBuffer.
const DefaultMaxPartBuffer int64 = 64 * 1024 * 1024

// RateLimitConfig holds rate limiting configuration.
type RateLimitConfig struct {
	Enabled bool          `yaml:"enabled" env:"RATE_LIMIT_ENABLED"`
	Limit   int           `yaml:"limit" env:"RATE_LIMIT_REQUESTS"`
	Window  time.Duration `yaml:"window" env:"RATE_LIMIT_WINDOW"`
}

// CacheConfig holds cache configuration.
type CacheConfig struct {
	Enabled    bool          `yaml:"enabled" env:"CACHE_ENABLED"`
	MaxSize    int64         `yaml:"max_size" env:"CACHE_MAX_SIZE"`       // Max size in bytes
	MaxItems   int           `yaml:"max_items" env:"CACHE_MAX_ITEMS"`     // Max number of items
	DefaultTTL time.Duration `yaml:"default_ttl" env:"CACHE_DEFAULT_TTL"` // Default TTL
}

// AuditConfig holds audit logging configuration.
type AuditConfig struct {
	Enabled            bool       `yaml:"enabled" env:"AUDIT_ENABLED"`
	MaxEvents          int        `yaml:"max_events" env:"AUDIT_MAX_EVENTS"` // Max events to keep in memory
	Sink               SinkConfig `yaml:"sink"`
	RedactMetadataKeys []string   `yaml:"redact_metadata_keys" env:"AUDIT_REDACT_METADATA_KEYS"`
}

// SinkConfig holds audit sink configuration.
type SinkConfig struct {
	Type          string            `yaml:"type" env:"AUDIT_SINK_TYPE"` // stdout, file, http
	Endpoint      string            `yaml:"endpoint" env:"AUDIT_SINK_ENDPOINT"`
	FilePath      string            `yaml:"file_path" env:"AUDIT_SINK_FILE_PATH"`
	// FileMode sets the Unix permission bits for the audit log file.
	// Default 0 means use the secure default (0600). Operators may set e.g. 0640.
	// V1.0-SEC-26.
	FileMode      fs.FileMode       `yaml:"file_mode" env:"AUDIT_SINK_FILE_MODE"`
	Headers       map[string]string `yaml:"headers"` // Custom headers for HTTP sink
	BatchSize     int               `yaml:"batch_size" env:"AUDIT_SINK_BATCH_SIZE"`
	FlushInterval time.Duration     `yaml:"flush_interval" env:"AUDIT_SINK_FLUSH_INTERVAL"`
	RetryCount           int               `yaml:"retry_count" env:"AUDIT_SINK_RETRY_COUNT"`
	RetryBackoff         time.Duration     `yaml:"retry_backoff" env:"AUDIT_SINK_RETRY_BACKOFF"`
	// MaxConcurrentFlushes bounds the number of concurrent async flush
	// goroutines spawned by BatchSink.WriteEvent. V1.0-SEC-13.
	// Default: 4
	MaxConcurrentFlushes int `yaml:"max_concurrent_flushes" env:"AUDIT_SINK_MAX_CONCURRENT_FLUSHES"`
	// HTTP transport configuration for HTTP sink (V1.0-SEC-8)
	HTTP HTTPTransportConfig `yaml:"http"`
	// TLS configuration for HTTP sink (V1.0-SEC-H07)
	TLS SinkTLSConfig `yaml:"tls"`
}

// SinkTLSConfig holds TLS settings for the audit HTTP sink.
type SinkTLSConfig struct {
	CAFile             string `yaml:"ca_file" env:"AUDIT_SINK_TLS_CA_FILE"`
	CertFile           string `yaml:"cert_file" env:"AUDIT_SINK_TLS_CERT_FILE"`
	KeyFile            string `yaml:"key_file" env:"AUDIT_SINK_TLS_KEY_FILE"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" env:"AUDIT_SINK_TLS_INSECURE_SKIP_VERIFY"`
	MinVersion         string `yaml:"min_version" env:"AUDIT_SINK_TLS_MIN_VERSION"`
}

// HTTPTransportConfig holds HTTP client transport settings for the audit HTTP sink.
// These settings harden the HTTP client against slow endpoints and resource exhaustion.
// V1.0-SEC-8 — hardened HTTP transport for audit sink.
type HTTPTransportConfig struct {
	// Timeout is the total request timeout (including retries).
	// Default: 30s
	Timeout time.Duration `yaml:"timeout" env:"AUDIT_SINK_HTTP_TIMEOUT"`
	// MaxConnsPerHost limits connections per host to prevent resource exhaustion.
	// Default: 20
	MaxConnsPerHost int `yaml:"max_conns_per_host" env:"AUDIT_SINK_HTTP_MAX_CONNS_PER_HOST"`
	// MaxIdleConns is the maximum number of idle connections across all hosts.
	// Default: 100
	MaxIdleConns int `yaml:"max_idle_conns" env:"AUDIT_SINK_HTTP_MAX_IDLE_CONNS"`
	// MaxIdleConnsPerHost is the maximum idle connections per host.
	// Default: 10
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host" env:"AUDIT_SINK_HTTP_MAX_IDLE_CONNS_PER_HOST"`
	// IdleConnTimeout is the maximum time an idle connection remains open.
	// Default: 90s
	IdleConnTimeout time.Duration `yaml:"idle_conn_timeout" env:"AUDIT_SINK_HTTP_IDLE_CONN_TIMEOUT"`
	// TLSHandshakeTimeout is the maximum time to wait for TLS handshake.
	// Default: 10s
	TLSHandshakeTimeout time.Duration `yaml:"tls_handshake_timeout" env:"AUDIT_SINK_HTTP_TLS_HANDSHAKE_TIMEOUT"`
	// ResponseHeaderTimeout is the maximum time to wait for response headers.
	// Default: 10s
	ResponseHeaderTimeout time.Duration `yaml:"response_header_timeout" env:"AUDIT_SINK_HTTP_RESPONSE_HEADER_TIMEOUT"`
}

// TracingConfig holds OpenTelemetry tracing configuration.
type TracingConfig struct {
	Enabled         bool    `yaml:"enabled" env:"TRACING_ENABLED"`                   // Enable/disable tracing
	ServiceName     string  `yaml:"service_name" env:"TRACING_SERVICE_NAME"`         // Service name for traces
	ServiceVersion  string  `yaml:"service_version" env:"TRACING_SERVICE_VERSION"`   // Service version
	Exporter        string  `yaml:"exporter" env:"TRACING_EXPORTER"`                 // Exporter type: none, stdout, jaeger, otlp
	JaegerEndpoint  string  `yaml:"jaeger_endpoint" env:"TRACING_JAEGER_ENDPOINT"`   // Jaeger collector endpoint
	OtlpEndpoint    string  `yaml:"otlp_endpoint" env:"TRACING_OTLP_ENDPOINT"`       // OTLP gRPC endpoint
	SamplingRatio   float64 `yaml:"sampling_ratio" env:"TRACING_SAMPLING_RATIO"`     // Sampling ratio (0.0-1.0)
	RedactSensitive bool    `yaml:"redact_sensitive" env:"TRACING_REDACT_SENSITIVE"` // Redact sensitive data in spans
}

// MetricsConfig holds metrics configuration.
type MetricsConfig struct {
	EnableBucketLabel bool   `yaml:"enable_bucket_label" env:"METRICS_ENABLE_BUCKET_LABEL"`
	// Addr is the optional address for a dedicated unauthenticated metrics
	// listener (e.g. ":9090"). When set, /metrics is served on this port only
	// and is removed from both the S3 data-plane port and the admin port.
	// Restrict access via NetworkPolicy — this listener has no authentication.
	// When empty, /metrics falls back to the admin port (if admin is enabled)
	// or the S3 port (if admin is disabled).
	Addr string `yaml:"addr" env:"METRICS_ADDR"`
}

// LoggingConfig holds access logging configuration.
type LoggingConfig struct {
	AccessLogFormat string   `yaml:"access_log_format" env:"LOGGING_ACCESS_LOG_FORMAT"` // Access log format: default, json, clf
	RedactHeaders   []string `yaml:"redact_headers" env:"LOGGING_REDACT_HEADERS"`       // Headers to redact in access logs (comma-separated)
}

// GatewayCredential is a single access-key/secret-key pair managed by the gateway.
type GatewayCredential struct {
	// AccessKey is the S3 access key identifier presented by clients.
	AccessKey    string `yaml:"access_key"`
	// SecretKey is the inline plaintext secret (dev only; prefer SecretKeyEnv).
	SecretKey    string `yaml:"secret_key"`
	// SecretKeyEnv is the name of the environment variable that holds the
	// plaintext secret key.  Takes precedence over SecretKey.
	SecretKeyEnv string `yaml:"secret_key_env"`
	// Label is an optional human-readable name used in audit log entries.
	Label        string `yaml:"label"`
}

// AuthConfig holds authentication-related configuration for the S3 API.
type AuthConfig struct {
	// ClockSkewTolerance is the maximum acceptable difference between the
	// request timestamp (X-Amz-Date) and server time. Requests outside this
	// window are rejected to prevent replay attacks.
	// Default: 15 minutes (matching AWS SigV4 specification).
	ClockSkewTolerance time.Duration       `yaml:"clock_skew_tolerance" env:"AUTH_CLOCK_SKEW_TOLERANCE"`
	// Credentials holds the gateway-managed credential store.
	// Every inbound S3 request must present one of these access keys with a
	// valid signature.
	Credentials        []GatewayCredential `yaml:"credentials"`
}

// AdminConfig holds admin API configuration.
//
// The admin endpoint runs on a separate listener from the S3 data-plane,
// gated by bearer-token authentication with constant-time comparison.
// When enabled on a non-loopback address, TLS must be enabled.
type AdminConfig struct {
	Enabled        bool                 `yaml:"enabled" env:"ADMIN_ENABLED"`
	Address        string               `yaml:"address" env:"ADMIN_ADDRESS"`
	MaxHeaderBytes int                  `yaml:"max_header_bytes" env:"ADMIN_MAX_HEADER_BYTES"`
	TLS            AdminTLSConfig       `yaml:"tls"`
	Auth           AdminAuthConfig      `yaml:"auth"`
	RateLimit      AdminRateLimitConfig `yaml:"rate_limit"`
	Profiling      AdminProfilingConfig `yaml:"profiling"`
}

// AdminProfilingConfig controls the /admin/debug/pprof/* routes.
//
// Disabled by default. When enabled, requires AdminConfig.Enabled
// and (on non-loopback addresses) AdminTLSConfig.Enabled. The admin
// bearer token and rate limit apply; no new auth surface is added.
type AdminProfilingConfig struct {
	// Enabled mounts /admin/debug/pprof/* on the admin mux.
	Enabled bool `yaml:"enabled" env:"ADMIN_PROFILING_ENABLED"`

	// BlockRate is passed to runtime.SetBlockProfileRate at startup.
	// 0 (default) disables block profiling. Positive values sample
	// one event per N ns of blocking; 1 samples all (expensive).
	BlockRate int `yaml:"block_rate" env:"ADMIN_PROFILING_BLOCK_RATE"`

	// MutexFraction is passed to runtime.SetMutexProfileFraction.
	// 0 (default) disables mutex profiling. Positive values sample
	// 1/N contention events.
	MutexFraction int `yaml:"mutex_fraction" env:"ADMIN_PROFILING_MUTEX_FRACTION"`

	// MaxConcurrentProfiles bounds in-flight profile/trace requests.
	// Defaults to 2. A semaphore inside the profiling handler rejects
	// additional requests with 429 until one finishes.
	MaxConcurrentProfiles int `yaml:"max_concurrent_profiles" env:"ADMIN_PROFILING_MAX_CONCURRENT"`

	// MaxProfileSeconds caps the `seconds=` query parameter for
	// /profile and /trace. Defaults to 60. Values above cap are
	// rejected with 400.
	MaxProfileSeconds int `yaml:"max_profile_seconds" env:"ADMIN_PROFILING_MAX_SECONDS"`
}

// AdminTLSConfig holds TLS settings for the admin listener.
type AdminTLSConfig struct {
	Enabled  bool   `yaml:"enabled" env:"ADMIN_TLS_ENABLED"`
	CertFile string `yaml:"cert_file" env:"ADMIN_TLS_CERT_FILE"`
	KeyFile  string `yaml:"key_file" env:"ADMIN_TLS_KEY_FILE"`
}

// AdminAuthConfig holds authentication settings for the admin API.
type AdminAuthConfig struct {
	Type      string `yaml:"type" env:"ADMIN_AUTH_TYPE"`             // Only "bearer" in v0.6
	TokenFile string `yaml:"token_file" env:"ADMIN_AUTH_TOKEN_FILE"` // File path; 0600, never inline
	Token     string `yaml:"token" env:"ADMIN_AUTH_TOKEN"`           // Inline only with ADMIN_ALLOW_INLINE_TOKEN=1
}

// AdminRateLimitConfig holds rate-limiting settings for the admin API.
type AdminRateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute" env:"ADMIN_RATE_LIMIT_RPM"`
}

// MultipartStateConfig holds configuration for the multipart-upload encryption state store.
type MultipartStateConfig struct {
	Valkey ValkeyConfig `yaml:"valkey"`
}

// ValkeyConfig holds the connection settings for the Valkey state store.
type ValkeyConfig struct {
	Addr string `yaml:"addr" env:"VALKEY_ADDR"` // e.g. "valkey.internal:6379"
	// Username for Valkey 6.0+ ACL auth (optional).
	Username string `yaml:"username" env:"VALKEY_USERNAME"`
	// PasswordEnv is the name of the environment variable that holds the
	// plaintext password. Never the literal password.
	PasswordEnv string          `yaml:"password_env" env:"VALKEY_PASSWORD_ENV"`
	DB          int             `yaml:"db" env:"VALKEY_DB"`
	TLS         ValkeyTLSConfig `yaml:"tls"`
	// InsecureAllowPlaintext permits a non-TLS Valkey connection.
	//
	// WARNING: Enabling this in production exposes WrappedDEKs (and all
	// multipart-upload metadata) on the network in plaintext. The DEK itself
	// is already wrapped by the KeyManager, but the wrapped envelope, IV
	// prefixes, bucket names, object keys, and part metadata are all readable
	// by anyone on the wire. This flag is intended for development/testing
	// only and emits a startup warning + metric when true.
	InsecureAllowPlaintext bool          `yaml:"insecure_allow_plaintext" env:"VALKEY_INSECURE_ALLOW_PLAINTEXT"`
	TTLSeconds             int           `yaml:"ttl_seconds" env:"VALKEY_TTL_SECONDS"`
	DialTimeout            time.Duration `yaml:"dial_timeout" env:"VALKEY_DIAL_TIMEOUT"`
	ReadTimeout            time.Duration `yaml:"read_timeout" env:"VALKEY_READ_TIMEOUT"`
	WriteTimeout           time.Duration `yaml:"write_timeout" env:"VALKEY_WRITE_TIMEOUT"`
	PoolSize               int           `yaml:"pool_size" env:"VALKEY_POOL_SIZE"`
	MinIdleConns           int           `yaml:"min_idle_conns" env:"VALKEY_MIN_IDLE_CONNS"`
	// EncryptionPasswordEnv is the name of the environment variable holding the
	// dedicated password for at-rest encryption of multipart-upload state in
	// Valkey. If unset, falls back to the gateway's main encryption password
	// (encryption.password) with a distinct HKDF info string.
	// V1.0-CRYPTO-2.
	EncryptionPasswordEnv string `yaml:"encryption_password_env" env:"VALKEY_ENCRYPTION_PASSWORD_ENV"`
	// EncryptState enables at-rest encryption of the meta field in Valkey hash
	// entries. Defaults to true (nil → true). When true, EncyptionPasswordEnv
	// or the main encryption.password is used to derive an AES-256-GCM key.
	// V1.0-CRYPTO-2.
	EncryptState *bool `yaml:"encrypt_state" env:"VALKEY_ENCRYPT_STATE"`
}

// ValkeyTLSConfig holds TLS settings for the Valkey connection.
type ValkeyTLSConfig struct {
	Enabled            bool   `yaml:"enabled" env:"VALKEY_TLS_ENABLED"`
	CAFile             string `yaml:"ca_file" env:"VALKEY_TLS_CA_FILE"`
	CertFile           string `yaml:"cert_file" env:"VALKEY_TLS_CERT_FILE"`
	KeyFile            string `yaml:"key_file" env:"VALKEY_TLS_KEY_FILE"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" env:"VALKEY_TLS_INSECURE_SKIP_VERIFY"`
	// MinVersion is the minimum TLS version: "1.2" or "1.3" (default "1.3").
	MinVersion string `yaml:"min_version" env:"VALKEY_TLS_MIN_VERSION"`
}

const (
	// ValkeyDefaultTTLSeconds is the default state TTL (7 days).
	ValkeyDefaultTTLSeconds = 7 * 24 * 60 * 60
)

// LoadConfig loads configuration from a file and environment variables.
func LoadConfig(path string) (*Config, error) {
	config := &Config{
		ListenAddr: ":8080",
		LogLevel:   "info",
		Encryption: EncryptionConfig{
			KeyManager: KeyManagerConfig{
				Provider:       "cosmian",
				DualReadWindow: 1,
				RotationPolicy: RotationPolicyConfig{
					Enabled:     false,
					GraceWindow: 0, // Use DualReadWindow by default
				},
			},
			Hardware: HardwareConfig{
				EnableAESNI:    true,
				EnableARMv8AES: true,
			},
			KDF: KDFConfig{
				PBKDF2: PBKDF2Config{
					Iterations: 600000,
				},
			},
		},
		Backend: BackendConfig{
			Endpoint: "", // Leave empty for AWS default, or set for any S3-compatible endpoint
			Region:   "us-east-1",
			UseSSL:   true,
			Retry: BackendRetryConfig{
				Mode:           DefaultBackendRetryMode,
				MaxAttempts:    DefaultBackendRetryMaxAttempts,
				InitialBackoff: DefaultBackendRetryInitialBackoff,
				MaxBackoff:     DefaultBackendRetryMaxBackoff,
				Jitter:         DefaultBackendRetryJitter,
			},
		},
		Compression: CompressionConfig{
			Enabled:   false,
			MinSize:   1024,
			Algorithm: "gzip",
			Level:     6,
		},
		Server: ServerConfig{
			ReadTimeout:              0, // Disable; ReadHeaderTimeout (10s) guards against slow-loris; ReadTimeout would kill long response streams
			WriteTimeout:             0, // S3 object streaming can be unbounded; disable by default
			IdleTimeout:              60 * time.Second,
			ReadHeaderTimeout:        10 * time.Second,
			MaxHeaderBytes:           1 << 20, // 1MB
			DisableMultipartUploads:  false,   // Allow multipart uploads by default for compatibility
			MaxLegacyCopySourceBytes: DefaultMaxLegacyCopySourceBytes,
			MaxPartBuffer:            DefaultMaxPartBuffer,
		},
		RateLimit: RateLimitConfig{
			Enabled: false,
			Limit:   100,
			Window:  60 * time.Second,
		},
		Cache: CacheConfig{
			Enabled:    false,
			MaxSize:    100 * 1024 * 1024, // 100MB default
			MaxItems:   1000,
			DefaultTTL: 5 * time.Minute,
		},
		Audit: AuditConfig{
			Enabled:   false,
			MaxEvents: 10000,
		},
		Tracing: TracingConfig{
			Enabled:         false,
			ServiceName:     "s3-encryption-gateway",
			ServiceVersion:  "dev",
			Exporter:        "none",
			SamplingRatio:   1.0,
			RedactSensitive: true,
		},
		Metrics: MetricsConfig{
			EnableBucketLabel: true,
		},
		Logging: LoggingConfig{
			AccessLogFormat: "default",
			RedactHeaders:   []string{"authorization", "x-amz-security-token", "x-amz-signature", "x-amz-tagging", "x-encryption-key", "x-encryption-password"},
		},
		Auth: AuthConfig{
			ClockSkewTolerance: 5 * time.Minute,
		},
		Admin: AdminConfig{
			Enabled:        false,
			Address:        "127.0.0.1:8081",
			MaxHeaderBytes: 64 * 1024, // 64 KB — admin API has no need for large headers
			Auth: AdminAuthConfig{
				Type: "bearer",
			},
			RateLimit: AdminRateLimitConfig{
				RequestsPerMinute: 30,
			},
			Profiling: AdminProfilingConfig{
				Enabled:               false,
				BlockRate:             0,
				MutexFraction:         0,
				MaxConcurrentProfiles: 2,
				MaxProfileSeconds:     60,
			},
		},
		MultipartState: MultipartStateConfig{
			Valkey: ValkeyConfig{
				TTLSeconds:   ValkeyDefaultTTLSeconds,
				DialTimeout:  2 * time.Second,
				ReadTimeout:  1 * time.Second,
				WriteTimeout: 1 * time.Second,
				PoolSize:     16,
				MinIdleConns: 2,
				EncryptState: BoolPtr(true),
				TLS: ValkeyTLSConfig{
					Enabled:    true,
					MinVersion: "1.3",
				},
			},
		},
	}

	// Load from file if provided
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		if len(data) > 0 {
			dec := yaml.NewDecoder(bytes.NewReader(data))
			dec.KnownFields(true)
			if err := dec.Decode(config); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables
	loadFromEnv(config)

	// Set default hardware acceleration flags if not specified (default true)
	// This logic is now handled by initialization values above, but we check env vars here
	// if they were set to override default initialization.
	// Actually, loadFromEnv handles it.

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// isEnvSet checks if an environment variable is set
func isEnvSet(key string) bool {
	_, ok := os.LookupEnv(key)
	return ok
}

// loadFromEnv loads configuration values from environment variables.
func loadFromEnv(config *Config) {
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		config.ListenAddr = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		config.LogLevel = v
	}
	if v := os.Getenv("BACKEND_ENDPOINT"); v != "" {
		config.Backend.Endpoint = v
	}
	if v := os.Getenv("BACKEND_REGION"); v != "" {
		config.Backend.Region = v
	}
	if v := os.Getenv("BACKEND_ACCESS_KEY"); v != "" {
		config.Backend.AccessKey = v
	}
	if v := os.Getenv("BACKEND_SECRET_KEY"); v != "" {
		config.Backend.SecretKey = v
	}
	if v := os.Getenv("BACKEND_PROVIDER"); v != "" {
		config.Backend.Provider = v
	}
	if v := os.Getenv("BACKEND_USE_PATH_STYLE"); v != "" {
		config.Backend.UsePathStyle = v == "true" || v == "1"
	}
	if v := os.Getenv("BACKEND_FILTER_METADATA_KEYS"); v != "" {
		// Comma-separated list of metadata keys to filter out
		config.Backend.FilterMetadataKeys = strings.Split(v, ",")
		for i := range config.Backend.FilterMetadataKeys {
			config.Backend.FilterMetadataKeys[i] = strings.TrimSpace(config.Backend.FilterMetadataKeys[i])
		}
	}
	// V0.6-PERF-2 — backend retry config env vars.
	if v := os.Getenv("BACKEND_RETRY_MODE"); v != "" {
		config.Backend.Retry.Mode = v
	}
	if v := os.Getenv("BACKEND_RETRY_MAX_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			config.Backend.Retry.MaxAttempts = n
		}
	}
	if v := os.Getenv("BACKEND_RETRY_INITIAL_BACKOFF"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Backend.Retry.InitialBackoff = d
		}
	}
	if v := os.Getenv("BACKEND_RETRY_MAX_BACKOFF"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Backend.Retry.MaxBackoff = d
		}
	}
	if v := os.Getenv("BACKEND_RETRY_JITTER"); v != "" {
		config.Backend.Retry.Jitter = v
	}
	if v := os.Getenv("BACKEND_RETRY_SAFE_COPY_OBJECT"); v != "" {
		b := v == "true" || v == "1"
		config.Backend.Retry.SafeCopyObject = &b
	}
	if v := os.Getenv("ENCRYPTION_PASSWORD"); v != "" {
		config.Encryption.Password = v
	}
	if v := os.Getenv("ENCRYPTION_KEY_FILE"); v != "" {
		config.Encryption.KeyFile = v
	}
	if v := os.Getenv("ENCRYPTION_PREFERRED_ALGORITHM"); v != "" {
		config.Encryption.PreferredAlgorithm = v
	}
	if v := os.Getenv("ENCRYPTION_SUPPORTED_ALGORITHMS"); v != "" {
		// Comma-separated list of algorithms
		config.Encryption.SupportedAlgorithms = strings.Split(v, ",")
		for i := range config.Encryption.SupportedAlgorithms {
			config.Encryption.SupportedAlgorithms[i] = strings.TrimSpace(config.Encryption.SupportedAlgorithms[i])
		}
	}
	if v := os.Getenv("HARDWARE_ENABLE_AESNI"); v != "" {
		config.Encryption.Hardware.EnableAESNI = v == "true" || v == "1"
	}
	if v := os.Getenv("HARDWARE_ENABLE_ARMV8_AES"); v != "" {
		config.Encryption.Hardware.EnableARMv8AES = v == "true" || v == "1"
	}
	if v := os.Getenv("ENCRYPTION_KDF_PBKDF2_ITERATIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 100000 {
			config.Encryption.KDF.PBKDF2.Iterations = n
		}
	}
	if v := os.Getenv("KEY_MANAGER_ENABLED"); v != "" {
		config.Encryption.KeyManager.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("KEY_MANAGER_PROVIDER"); v != "" {
		config.Encryption.KeyManager.Provider = v
	}
	if v := os.Getenv("KEY_MANAGER_DUAL_READ_WINDOW"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			config.Encryption.KeyManager.DualReadWindow = n
		}
	}
	if v := os.Getenv("KEY_MANAGER_ROTATION_POLICY_ENABLED"); v != "" {
		config.Encryption.KeyManager.RotationPolicy.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("KEY_MANAGER_ROTATION_GRACE_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Encryption.KeyManager.RotationPolicy.GraceWindow = d
		}
	}
	if v := os.Getenv("COSMIAN_KMS_ENDPOINT"); v != "" {
		config.Encryption.KeyManager.Cosmian.Endpoint = v
	}
	if v := os.Getenv("COSMIAN_KMS_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Encryption.KeyManager.Cosmian.Timeout = d
		}
	}
	if v := os.Getenv("COSMIAN_KMS_CLIENT_CERT"); v != "" {
		config.Encryption.KeyManager.Cosmian.ClientCert = v
	}
	if v := os.Getenv("COSMIAN_KMS_CLIENT_KEY"); v != "" {
		config.Encryption.KeyManager.Cosmian.ClientKey = v
	}
	if v := os.Getenv("COSMIAN_KMS_CA_CERT"); v != "" {
		config.Encryption.KeyManager.Cosmian.CACert = v
	}
	if v := os.Getenv("COSMIAN_KMS_INSECURE_SKIP_VERIFY"); v != "" {
		config.Encryption.KeyManager.Cosmian.InsecureSkipVerify = v == "true" || v == "1"
	}
	if v := os.Getenv("COSMIAN_KMS_KEYS"); v != "" {
		config.Encryption.KeyManager.Cosmian.Keys = parseCosmianKeyRefs(v)
	}

	if v := os.Getenv("SELF_CONTAINED_TYPE"); v != "" {
		config.Encryption.KeyManager.SelfContained.Type = v
	}
	if v := os.Getenv("SELF_CONTAINED_AES_ACTIVE_VERSION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Encryption.KeyManager.SelfContained.AES.ActiveVersion = n
		}
	}
	if v := os.Getenv("SELF_CONTAINED_RSA_PRIVATE_KEY_SOURCE"); v != "" {
		config.Encryption.KeyManager.SelfContained.RSA.PrivateKeySource = v
	}
	if v := os.Getenv("SELF_CONTAINED_RSA_KEY_VERSION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Encryption.KeyManager.SelfContained.RSA.KeyVersion = n
		}
	}

	if v := os.Getenv("TLS_ENABLED"); v != "" {
		config.TLS.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("TLS_CERT_FILE"); v != "" {
		config.TLS.CertFile = v
	}
	if v := os.Getenv("TLS_KEY_FILE"); v != "" {
		config.TLS.KeyFile = v
	}
	// Server timeouts from environment
	if v := os.Getenv("SERVER_READ_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.ReadTimeout = d
		}
	}
	if v := os.Getenv("SERVER_WRITE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.WriteTimeout = d
		}
	}
	if v := os.Getenv("SERVER_IDLE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.IdleTimeout = d
		}
	}
	if v := os.Getenv("SERVER_READ_HEADER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Server.ReadHeaderTimeout = d
		}
	}
	if v := os.Getenv("SERVER_MAX_HEADER_BYTES"); v != "" {
		if maxBytes, err := strconv.Atoi(v); err == nil && maxBytes > 0 {
			config.Server.MaxHeaderBytes = maxBytes
		}
	}
	if v := os.Getenv("SERVER_FORCE_HTTPS"); v != "" {
		config.Server.ForceHTTPS = v == "true" || v == "1"
	}
	if v := os.Getenv("RATE_LIMIT_ENABLED"); v != "" {
		config.RateLimit.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("RATE_LIMIT_REQUESTS"); v != "" {
		if limit, err := strconv.Atoi(v); err == nil && limit > 0 {
			config.RateLimit.Limit = limit
		}
	}
	if v := os.Getenv("RATE_LIMIT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.RateLimit.Window = d
		}
	}
	// Cache configuration
	if v := os.Getenv("CACHE_ENABLED"); v != "" {
		config.Cache.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("CACHE_MAX_SIZE"); v != "" {
		if maxSize, err := strconv.ParseInt(v, 10, 64); err == nil && maxSize > 0 {
			config.Cache.MaxSize = maxSize
		}
	}
	if v := os.Getenv("CACHE_MAX_ITEMS"); v != "" {
		if maxItems, err := strconv.Atoi(v); err == nil && maxItems > 0 {
			config.Cache.MaxItems = maxItems
		}
	}
	if v := os.Getenv("CACHE_DEFAULT_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Cache.DefaultTTL = d
		}
	}
	// Audit configuration
	if v := os.Getenv("AUDIT_ENABLED"); v != "" {
		config.Audit.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("AUDIT_MAX_EVENTS"); v != "" {
		if maxEvents, err := strconv.Atoi(v); err == nil && maxEvents > 0 {
			config.Audit.MaxEvents = maxEvents
		}
	}
	// Audit Sink configuration
	if v := os.Getenv("AUDIT_SINK_TYPE"); v != "" {
		config.Audit.Sink.Type = v
	}
	if v := os.Getenv("AUDIT_SINK_ENDPOINT"); v != "" {
		config.Audit.Sink.Endpoint = v
	}
	if v := os.Getenv("AUDIT_SINK_FILE_PATH"); v != "" {
		config.Audit.Sink.FilePath = v
	}
	// V1.0-SEC-26 — parse octal file-mode for audit log (e.g. "0640")
	if v := os.Getenv("AUDIT_SINK_FILE_MODE"); v != "" {
		if n, err := strconv.ParseUint(v, 8, 32); err == nil {
			config.Audit.Sink.FileMode = fs.FileMode(n)
		}
	}
	if v := os.Getenv("AUDIT_SINK_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Audit.Sink.BatchSize = n
		}
	}
	if v := os.Getenv("AUDIT_SINK_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Audit.Sink.FlushInterval = d
		}
	}
	if v := os.Getenv("AUDIT_SINK_RETRY_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			config.Audit.Sink.RetryCount = n
		}
	}
	if v := os.Getenv("AUDIT_SINK_RETRY_BACKOFF"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Audit.Sink.RetryBackoff = d
		}
	}
	// V1.0-SEC-8 — HTTP transport configuration for audit sink
	if v := os.Getenv("AUDIT_SINK_HTTP_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Audit.Sink.HTTP.Timeout = d
		}
	}
	if v := os.Getenv("AUDIT_SINK_HTTP_MAX_CONNS_PER_HOST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Audit.Sink.HTTP.MaxConnsPerHost = n
		}
	}
	if v := os.Getenv("AUDIT_SINK_HTTP_MAX_IDLE_CONNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Audit.Sink.HTTP.MaxIdleConns = n
		}
	}
	if v := os.Getenv("AUDIT_SINK_HTTP_MAX_IDLE_CONNS_PER_HOST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Audit.Sink.HTTP.MaxIdleConnsPerHost = n
		}
	}
	if v := os.Getenv("AUDIT_SINK_HTTP_IDLE_CONN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Audit.Sink.HTTP.IdleConnTimeout = d
		}
	}
	if v := os.Getenv("AUDIT_SINK_HTTP_TLS_HANDSHAKE_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Audit.Sink.HTTP.TLSHandshakeTimeout = d
		}
	}
	if v := os.Getenv("AUDIT_SINK_HTTP_RESPONSE_HEADER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Audit.Sink.HTTP.ResponseHeaderTimeout = d
		}
	}
	// V1.0-SEC-H07 — TLS configuration for audit sink
	if v := os.Getenv("AUDIT_SINK_TLS_CA_FILE"); v != "" {
		config.Audit.Sink.TLS.CAFile = v
	}
	if v := os.Getenv("AUDIT_SINK_TLS_CERT_FILE"); v != "" {
		config.Audit.Sink.TLS.CertFile = v
	}
	if v := os.Getenv("AUDIT_SINK_TLS_KEY_FILE"); v != "" {
		config.Audit.Sink.TLS.KeyFile = v
	}
	if v := os.Getenv("AUDIT_SINK_TLS_INSECURE_SKIP_VERIFY"); v != "" {
		config.Audit.Sink.TLS.InsecureSkipVerify = v == "true" || v == "1"
	}
	if v := os.Getenv("AUDIT_SINK_TLS_MIN_VERSION"); v != "" {
		config.Audit.Sink.TLS.MinVersion = v
	}
	if v := os.Getenv("AUDIT_REDACT_METADATA_KEYS"); v != "" {
		config.Audit.RedactMetadataKeys = strings.Split(v, ",")
		for i := range config.Audit.RedactMetadataKeys {
			config.Audit.RedactMetadataKeys[i] = strings.TrimSpace(config.Audit.RedactMetadataKeys[i])
		}
	}
	// Proxied bucket configuration
	if v := os.Getenv("PROXIED_BUCKET"); v != "" {
		config.ProxiedBucket = v
	}
	// Tracing configuration
	if v := os.Getenv("TRACING_ENABLED"); v != "" {
		config.Tracing.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("TRACING_SERVICE_NAME"); v != "" {
		config.Tracing.ServiceName = v
	}
	if v := os.Getenv("TRACING_SERVICE_VERSION"); v != "" {
		config.Tracing.ServiceVersion = v
	}
	if v := os.Getenv("TRACING_EXPORTER"); v != "" {
		config.Tracing.Exporter = v
	}
	if v := os.Getenv("TRACING_JAEGER_ENDPOINT"); v != "" {
		config.Tracing.JaegerEndpoint = v
	}
	if v := os.Getenv("TRACING_OTLP_ENDPOINT"); v != "" {
		config.Tracing.OtlpEndpoint = v
	}
	if v := os.Getenv("TRACING_SAMPLING_RATIO"); v != "" {
		if ratio, err := strconv.ParseFloat(v, 64); err == nil && ratio >= 0.0 && ratio <= 1.0 {
			config.Tracing.SamplingRatio = ratio
		}
	}
	if v := os.Getenv("TRACING_REDACT_SENSITIVE"); v != "" {
		config.Tracing.RedactSensitive = v == "true" || v == "1"
	}
	// Metrics configuration
	if v := os.Getenv("METRICS_ENABLE_BUCKET_LABEL"); v != "" {
		config.Metrics.EnableBucketLabel = v == "true" || v == "1"
	}
	if v := os.Getenv("METRICS_ADDR"); v != "" {
		config.Metrics.Addr = v
	}
	// Logging configuration
	if v := os.Getenv("LOGGING_ACCESS_LOG_FORMAT"); v != "" {
		config.Logging.AccessLogFormat = v
	}
	if v := os.Getenv("LOGGING_REDACT_HEADERS"); v != "" {
		// Comma-separated list of headers to redact
		config.Logging.RedactHeaders = strings.Split(v, ",")
		for i := range config.Logging.RedactHeaders {
			config.Logging.RedactHeaders[i] = strings.TrimSpace(config.Logging.RedactHeaders[i])
		}
	}
	if v := os.Getenv("POLICIES"); v != "" {
		config.PolicyFiles = strings.Split(v, ",")
		for i := range config.PolicyFiles {
			config.PolicyFiles[i] = strings.TrimSpace(config.PolicyFiles[i])
		}
	}
	// Auth configuration
	if v := os.Getenv("AUTH_CLOCK_SKEW_TOLERANCE"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			config.Auth.ClockSkewTolerance = d
		}
	}
	// Resolve credential secrets from environment variables (V1.0-AUTH-1)
	for i := range config.Auth.Credentials {
		if config.Auth.Credentials[i].SecretKeyEnv != "" {
			if v := os.Getenv(config.Auth.Credentials[i].SecretKeyEnv); v != "" {
				config.Auth.Credentials[i].SecretKey = v
			}
		}
	}
	// Read indexed gateway credentials from Helm-injected env vars.
	// Helm sets GW_CRED_0_ACCESS_KEY, GW_CRED_0_SECRET_KEY, etc.
	for i := 0; ; i++ {
		ak := os.Getenv(fmt.Sprintf("GW_CRED_%d_ACCESS_KEY", i))
		sk := os.Getenv(fmt.Sprintf("GW_CRED_%d_SECRET_KEY", i))
		if ak == "" && sk == "" {
			break
		}
		found := false
		for j := range config.Auth.Credentials {
			if config.Auth.Credentials[j].AccessKey == ak {
				if sk != "" {
					config.Auth.Credentials[j].SecretKey = sk
				}
				found = true
				break
			}
		}
		if !found {
			config.Auth.Credentials = append(config.Auth.Credentials, GatewayCredential{
				AccessKey: ak,
				SecretKey: sk,
				Label:     fmt.Sprintf("helm-cred-%d", i),
			})
		}
	}
	// Load credentials from external file (AUTH_CREDENTIALS_FILE).
	if path := os.Getenv("AUTH_CREDENTIALS_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			slog.Error("failed to read AUTH_CREDENTIALS_FILE", "path", path, "error", err)
		} else {
			var fileCreds []GatewayCredential
			if err := yaml.Unmarshal(data, &fileCreds); err != nil {
				slog.Error("failed to parse AUTH_CREDENTIALS_FILE", "path", path, "error", err)
			} else {
				config.Auth.Credentials = append(config.Auth.Credentials, fileCreds...)
			}
		}
	}
	// Admin configuration
	if v := os.Getenv("ADMIN_ENABLED"); v != "" {
		config.Admin.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("ADMIN_ADDRESS"); v != "" {
		config.Admin.Address = v
	}
	if v := os.Getenv("ADMIN_TLS_ENABLED"); v != "" {
		config.Admin.TLS.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("ADMIN_TLS_CERT_FILE"); v != "" {
		config.Admin.TLS.CertFile = v
	}
	if v := os.Getenv("ADMIN_TLS_KEY_FILE"); v != "" {
		config.Admin.TLS.KeyFile = v
	}
	if v := os.Getenv("ADMIN_AUTH_TYPE"); v != "" {
		config.Admin.Auth.Type = v
	}
	if v := os.Getenv("ADMIN_AUTH_TOKEN_FILE"); v != "" {
		config.Admin.Auth.TokenFile = v
	}
	if v := os.Getenv("ADMIN_AUTH_TOKEN"); v != "" {
		config.Admin.Auth.Token = v
	}
	if v := os.Getenv("ADMIN_RATE_LIMIT_RPM"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.Admin.RateLimit.RequestsPerMinute = n
		}
	}
	// V0.6-OBS-1 — admin profiling env bindings.
	if v := os.Getenv("ADMIN_PROFILING_ENABLED"); v != "" {
		config.Admin.Profiling.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("ADMIN_PROFILING_BLOCK_RATE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			config.Admin.Profiling.BlockRate = n
		}
	}
	if v := os.Getenv("ADMIN_PROFILING_MUTEX_FRACTION"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			config.Admin.Profiling.MutexFraction = n
		}
	}
	if v := os.Getenv("ADMIN_PROFILING_MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			config.Admin.Profiling.MaxConcurrentProfiles = n
		}
	}
	if v := os.Getenv("ADMIN_PROFILING_MAX_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			config.Admin.Profiling.MaxProfileSeconds = n
		}
	}

	// Multipart-state / Valkey env bindings. Needed so the Helm chart can wire
	// the Valkey subchart's service name into the gateway without requiring a
	// ConfigMap-mounted config.yaml.
	if v := os.Getenv("VALKEY_ADDR"); v != "" {
		config.MultipartState.Valkey.Addr = v
	}
	if v := os.Getenv("VALKEY_USERNAME"); v != "" {
		config.MultipartState.Valkey.Username = v
	}
	if v := os.Getenv("VALKEY_PASSWORD_ENV"); v != "" {
		config.MultipartState.Valkey.PasswordEnv = v
	}
	if v := os.Getenv("VALKEY_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			config.MultipartState.Valkey.DB = n
		}
	}
	if v := os.Getenv("VALKEY_TLS_ENABLED"); v != "" {
		config.MultipartState.Valkey.TLS.Enabled = v == "true" || v == "1"
	}
	if v := os.Getenv("VALKEY_TLS_CA_FILE"); v != "" {
		config.MultipartState.Valkey.TLS.CAFile = v
	}
	if v := os.Getenv("VALKEY_TLS_CERT_FILE"); v != "" {
		config.MultipartState.Valkey.TLS.CertFile = v
	}
	if v := os.Getenv("VALKEY_TLS_KEY_FILE"); v != "" {
		config.MultipartState.Valkey.TLS.KeyFile = v
	}
	if v := os.Getenv("VALKEY_TLS_INSECURE_SKIP_VERIFY"); v != "" {
		config.MultipartState.Valkey.TLS.InsecureSkipVerify = v == "true" || v == "1"
	}
	if v := os.Getenv("VALKEY_INSECURE_ALLOW_PLAINTEXT"); v != "" {
		config.MultipartState.Valkey.InsecureAllowPlaintext = v == "true" || v == "1"
	}
	if v := os.Getenv("VALKEY_TTL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.MultipartState.Valkey.TTLSeconds = n
		}
	}
	if v := os.Getenv("VALKEY_POOL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			config.MultipartState.Valkey.PoolSize = n
		}
	}
	// V1.0-CRYPTO-2 — at-rest encryption for Valkey multipart state.
	if v := os.Getenv("VALKEY_ENCRYPTION_PASSWORD_ENV"); v != "" {
		config.MultipartState.Valkey.EncryptionPasswordEnv = v
	}
	if v := os.Getenv("VALKEY_ENCRYPT_STATE"); v != "" {
		b := v == "true" || v == "1"
		config.MultipartState.Valkey.EncryptState = &b
	}
}

func parseCosmianKeyRefs(value string) []CosmianKeyReference {
	parts := strings.Split(value, ",")
	refs := make([]CosmianKeyReference, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		ref := CosmianKeyReference{}
		if strings.Contains(part, ":") {
			pieces := strings.SplitN(part, ":", 2)
			ref.ID = strings.TrimSpace(pieces[0])
			if len(pieces) == 2 {
				if n, err := strconv.Atoi(strings.TrimSpace(pieces[1])); err == nil {
					ref.Version = n
				}
			}
		} else {
			ref.ID = part
		}
		refs = append(refs, ref)
	}
	return refs
}

// Validate validates the configuration and returns an error if invalid.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}

	// metrics.addr must be a distinct address from the S3 and admin ports.
	if c.Metrics.Addr != "" {
		if c.Metrics.Addr == c.ListenAddr {
			return fmt.Errorf("metrics.addr must differ from listen_addr")
		}
		if c.Admin.Enabled && c.Metrics.Addr == c.Admin.Address {
			return fmt.Errorf("metrics.addr must differ from admin.address")
		}
	}

	// Endpoint is optional - if empty, AWS SDK will use default AWS endpoints

	// Validate credential store (V1.0-AUTH-1)
	if len(c.Auth.Credentials) == 0 {
		return fmt.Errorf("auth.credentials must not be empty; at least one credential is required")
	}
	for i, cred := range c.Auth.Credentials {
		if cred.AccessKey == "" {
			return fmt.Errorf("auth.credentials[%d]: access_key is required", i)
		}
		if cred.SecretKey == "" && cred.SecretKeyEnv == "" {
			return fmt.Errorf("auth.credentials[%d]: either secret_key or secret_key_env is required", i)
		}
	}

	// Backend credentials are always required
	if c.Backend.AccessKey == "" {
		return fmt.Errorf("backend.access_key is required")
	}
	if c.Backend.SecretKey == "" {
		return fmt.Errorf("backend.secret_key is required")
	}

	if c.Encryption.Password == "" && c.Encryption.KeyFile == "" {
		return fmt.Errorf("either encryption.password or encryption.key_file is required")
	}

	if c.LogLevel != "" {
		validLevels := map[string]bool{
			"debug": true,
			"info":  true,
			"warn":  true,
			"error": true,
		}
		if !validLevels[c.LogLevel] {
			return fmt.Errorf("invalid log_level: %s (must be debug, info, warn, or error)", c.LogLevel)
		}
	}

	// Validate TLS configuration
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("tls.cert_file is required when TLS is enabled")
		}
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.key_file is required when TLS is enabled")
		}
	}

	// Validate encryption algorithms policy
	allowed := map[string]bool{
		"AES256-GCM":        true,
		"ChaCha20-Poly1305": true,
	}
	if alg := strings.TrimSpace(c.Encryption.PreferredAlgorithm); alg != "" {
		if !allowed[alg] {
			return fmt.Errorf("invalid encryption.preferred_algorithm: %s", alg)
		}
	}
	if len(c.Encryption.SupportedAlgorithms) > 0 {
		for _, alg := range c.Encryption.SupportedAlgorithms {
			if !allowed[strings.TrimSpace(alg)] {
				return fmt.Errorf("invalid entry in encryption.supported_algorithms: %s", alg)
			}
		}
	}

	if c.Encryption.KDF.PBKDF2.Iterations < 100000 {
		return fmt.Errorf("encryption.kdf.pbkdf2.iterations must be >= 100000 (got %d)", c.Encryption.KDF.PBKDF2.Iterations)
	}
	if c.Encryption.KDF.PBKDF2.Iterations < 600000 {
		slog.Warn("encryption.kdf.pbkdf2.iterations is below NIST SP 800-132 (2023) recommendation of 600,000",
			"iterations", c.Encryption.KDF.PBKDF2.Iterations)
	}

	if c.Encryption.KeyManager.Enabled {
		if c.Encryption.KeyManager.Provider == "" {
			return fmt.Errorf("encryption.key_manager.provider is required when key manager is enabled")
		}
		switch strings.ToLower(c.Encryption.KeyManager.Provider) {
		case "cosmian", "kmip":
			if c.Encryption.KeyManager.Cosmian.Endpoint == "" {
				return fmt.Errorf("encryption.key_manager.cosmian.endpoint is required")
			}
			if len(c.Encryption.KeyManager.Cosmian.Keys) == 0 {
				return fmt.Errorf("encryption.key_manager.cosmian.keys must include at least one entry")
			}
		case "memory":
			// No mandatory fields; master_key_source is optional (auto-generate if empty)
		case "hsm":
			// Validated at runtime by the HSM adapter; build-tag check not possible here
		case "self_contained":
			sc := c.Encryption.KeyManager.SelfContained
			if sc.Type == "" {
				return fmt.Errorf("encryption.key_manager.self_contained.type is required (must be \"aes\" or \"rsa\")")
			}
			switch sc.Type {
			case "aes":
				if len(sc.AES.Keys) == 0 {
					return fmt.Errorf("encryption.key_manager.self_contained.aes.keys must include at least one entry")
				}
				for i, k := range sc.AES.Keys {
					if k.KeySource == "" {
						return fmt.Errorf("encryption.key_manager.self_contained.aes.keys[%d].key_source is required", i)
					}
				}
			case "rsa":
				if sc.RSA.PrivateKeySource == "" {
					return fmt.Errorf("encryption.key_manager.self_contained.rsa.private_key_source is required")
				}
			default:
				return fmt.Errorf("encryption.key_manager.self_contained.type must be \"aes\" or \"rsa\" (got %q)", sc.Type)
			}
		default:
			return fmt.Errorf("unsupported key manager provider: %s (supported: cosmian, kmip, memory, hsm, self_contained)", c.Encryption.KeyManager.Provider)
		}
	}

	// Validate tracing configuration
	if c.Tracing.Enabled {
		if c.Tracing.ServiceName == "" {
			return fmt.Errorf("tracing.service_name is required when tracing is enabled")
		}
		validExporters := map[string]bool{
			"none":   true,
			"stdout": true,
			"jaeger": true,
			"otlp":   true,
		}
		if !validExporters[c.Tracing.Exporter] {
			return fmt.Errorf("invalid tracing.exporter: %s (must be none, stdout, jaeger, or otlp)", c.Tracing.Exporter)
		}
		if c.Tracing.SamplingRatio < 0.0 || c.Tracing.SamplingRatio > 1.0 {
			return fmt.Errorf("tracing.sampling_ratio must be between 0.0 and 1.0")
		}
		if c.Tracing.Exporter == "jaeger" && c.Tracing.JaegerEndpoint == "" {
			return fmt.Errorf("tracing.jaeger_endpoint is required when exporter is jaeger")
		}
		if c.Tracing.Exporter == "otlp" && c.Tracing.OtlpEndpoint == "" {
			return fmt.Errorf("tracing.otlp_endpoint is required when exporter is otlp")
		}
	}

	// Validate logging configuration
	if c.Logging.AccessLogFormat != "" {
		validFormats := map[string]bool{
			"default": true,
			"json":    true,
			"clf":     true,
		}
		if !validFormats[c.Logging.AccessLogFormat] {
			return fmt.Errorf("invalid logging.access_log_format: %s (must be default, json, or clf)", c.Logging.AccessLogFormat)
		}
	}

	// Validate audit configuration
	if c.Audit.Enabled {
		switch c.Audit.Sink.Type {
		case "", "stdout":
			// Valid, no extra config needed
		case "file":
			if c.Audit.Sink.FilePath == "" {
				return fmt.Errorf("audit.sink.file_path is required when sink type is file")
			}
		case "http":
			if c.Audit.Sink.Endpoint == "" {
				return fmt.Errorf("audit.sink.endpoint is required when sink type is http")
			}
		default:
			return fmt.Errorf("invalid audit.sink.type: %s (must be stdout, file, or http)", c.Audit.Sink.Type)
		}
	}

	// Validate multipart state / Valkey TLS min_version when Valkey is configured.
	if c.MultipartState.Valkey.Addr != "" {
		switch c.MultipartState.Valkey.TLS.MinVersion {
		case "", "1.2", "1.3":
			// valid
		default:
			return fmt.Errorf("invalid multipart_state.valkey.tls.min_version: %q (must be 1.2 or 1.3)", c.MultipartState.Valkey.TLS.MinVersion)
		}

		// V1.0-CRYPTO-2 — validate Valkey at-rest encryption config.
		encryptState := c.MultipartState.Valkey.EncryptState == nil || *c.MultipartState.Valkey.EncryptState
		if !encryptState {
			slog.Warn("multipart_state.valkey.encrypt_state is false — at-rest encryption is disabled for Valkey multipart state (deprecated, will be removed in v2.0)")
		} else if c.MultipartState.Valkey.EncryptionPasswordEnv != "" {
			if v := os.Getenv(c.MultipartState.Valkey.EncryptionPasswordEnv); v == "" {
				return fmt.Errorf("multipart_state.valkey.encryption_password_env is set to %q but the environment variable is empty or unset", c.MultipartState.Valkey.EncryptionPasswordEnv)
			}
		} else if c.Encryption.Password == "" {
			slog.Warn("multipart_state.valkey.encryption_password_env is not set and encryption.password is empty — at-rest encryption will fail at runtime if enabled")
		}
	}

	// Validate backend retry configuration (V0.6-PERF-2).
	// Normalize first so that empty-string defaults are resolved before validation.
	c.Backend.Retry.Normalize()
	if err := c.Backend.Retry.Validate(); err != nil {
		return err
	}

	// Validate admin configuration
	if c.Admin.Enabled {
		if c.Admin.Address == "" {
			return fmt.Errorf("admin.address is required when admin is enabled")
		}

		// Ensure admin address differs from data-plane address
		if c.Admin.Address == c.ListenAddr {
			return fmt.Errorf("admin.address must differ from listen_addr")
		}

		// Non-loopback address requires TLS
		if !isLoopbackAddress(c.Admin.Address) && !c.Admin.TLS.Enabled {
			return fmt.Errorf("admin.tls.enabled must be true when admin.address is not loopback (got %s)", c.Admin.Address)
		}

		// TLS cert/key validation
		if c.Admin.TLS.Enabled {
			if c.Admin.TLS.CertFile == "" {
				return fmt.Errorf("admin.tls.cert_file is required when admin TLS is enabled")
			}
			if c.Admin.TLS.KeyFile == "" {
				return fmt.Errorf("admin.tls.key_file is required when admin TLS is enabled")
			}
		}

		// Auth type must be "bearer"
		if c.Admin.Auth.Type != "" && c.Admin.Auth.Type != "bearer" {
			return fmt.Errorf("admin.auth.type must be \"bearer\" (got %q)", c.Admin.Auth.Type)
		}

		// Exactly one of token_file / token must be set
		hasTokenFile := c.Admin.Auth.TokenFile != ""
		hasInlineToken := c.Admin.Auth.Token != ""
		if !hasTokenFile && !hasInlineToken {
			return fmt.Errorf("one of admin.auth.token_file or admin.auth.token is required when admin is enabled")
		}
		if hasTokenFile && hasInlineToken {
			return fmt.Errorf("only one of admin.auth.token_file or admin.auth.token may be set, not both")
		}

		// Inline token requires ADMIN_ALLOW_INLINE_TOKEN=1
		if hasInlineToken && os.Getenv("ADMIN_ALLOW_INLINE_TOKEN") != "1" {
			return fmt.Errorf("admin.auth.token (inline) requires ADMIN_ALLOW_INLINE_TOKEN=1 environment variable")
		}

		// Validate token minimum length (32 bytes decoded)
		if hasTokenFile {
			// Check file permissions — use Lstat to avoid following symlinks (TOCTOU).
			info, err := os.Lstat(c.Admin.Auth.TokenFile)
			if err != nil {
				return fmt.Errorf("admin.auth.token_file: %w", err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("admin.auth.token_file must not be a symbolic link")
			}
			mode := info.Mode().Perm()
			if mode&0077 != 0 {
				return fmt.Errorf("admin.auth.token_file %s is too permissive (mode %04o); must be 0600 or stricter", c.Admin.Auth.TokenFile, mode)
			}
			// Read and validate token length
			tokenBytes, err := os.ReadFile(c.Admin.Auth.TokenFile)
			if err != nil {
				return fmt.Errorf("admin.auth.token_file: failed to read: %w", err)
			}
			if err := validateAdminTokenLength(strings.TrimSpace(string(tokenBytes))); err != nil {
				return fmt.Errorf("admin.auth.token_file: %w", err)
			}
		}
		if hasInlineToken {
			if err := validateAdminTokenLength(c.Admin.Auth.Token); err != nil {
				return fmt.Errorf("admin.auth.token: %w", err)
			}
		}

		// Validate rate limit
		if c.Admin.RateLimit.RequestsPerMinute <= 0 {
			return fmt.Errorf("admin.rate_limit.requests_per_minute must be positive")
		}
	}

	// V0.6-OBS-1 — profiling validation.
	if c.Admin.Profiling.Enabled {
		if !c.Admin.Enabled {
			return fmt.Errorf("admin.profiling requires admin.enabled")
		}
		if !isLoopbackAddress(c.Admin.Address) && !c.Admin.TLS.Enabled {
			return fmt.Errorf("admin.profiling on non-loopback requires admin.tls.enabled")
		}
		if c.Admin.Profiling.BlockRate < 0 {
			return fmt.Errorf("admin.profiling.block_rate must be >= 0")
		}
		if c.Admin.Profiling.MutexFraction < 0 {
			return fmt.Errorf("admin.profiling.mutex_fraction must be >= 0")
		}
		if c.Admin.Profiling.MaxProfileSeconds < 1 || c.Admin.Profiling.MaxProfileSeconds > 600 {
			return fmt.Errorf("admin.profiling.max_profile_seconds must be between 1 and 600")
		}
	}

	return nil
}

// isLoopbackAddress checks if the given address string refers to a loopback interface.
func isLoopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateAdminTokenLength validates that the token is at least 32 bytes when
// decoded from hex or base64, or 32 characters if it is a raw string.
func validateAdminTokenLength(token string) error {
	if token == "" {
		return fmt.Errorf("token is empty")
	}
	// Try hex decode
	if decoded, err := hex.DecodeString(token); err == nil {
		if len(decoded) < 32 {
			return fmt.Errorf("token too short: decoded hex is %d bytes, minimum 32", len(decoded))
		}
		return nil
	}
	// Try base64 decode
	if decoded, err := base64.StdEncoding.DecodeString(token); err == nil {
		if len(decoded) < 32 {
			return fmt.Errorf("token too short: decoded base64 is %d bytes, minimum 32", len(decoded))
		}
		return nil
	}
	// Raw string: require at least 32 characters
	if len(token) < 32 {
		return fmt.Errorf("token too short: %d characters, minimum 32", len(token))
	}
	return nil
}

// boolPtr returns a pointer to the given bool value.
func BoolPtr(v bool) *bool {
	return &v
}

// ConfigReloader handles hot-reloading of non-crypto configuration settings.
type ConfigReloader struct {
	currentConfig *Config
	configPath    string
	logger        *logrus.Logger
	watcher       *fsnotify.Watcher
	signalChan    chan os.Signal
	stopChan      chan struct{}
	mu            sync.RWMutex
	onReload      func(*Config, *Config) error // callback for applying config changes
}

// NewConfigReloader creates a new configuration reloader that watches for file changes
// and SIGHUP signals to reload non-crypto configuration settings.
func NewConfigReloader(configPath string, initialConfig *Config, logger *logrus.Logger) (*ConfigReloader, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	if configPath != "" {
		if err := watcher.Add(configPath); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("failed to watch config file: %w", err)
		}
	}

	reloader := &ConfigReloader{
		currentConfig: initialConfig,
		configPath:    configPath,
		logger:        logger,
		watcher:       watcher,
		signalChan:    make(chan os.Signal, 1),
		stopChan:      make(chan struct{}),
	}

	// Register for SIGHUP signal
	signal.Notify(reloader.signalChan, syscall.SIGHUP)

	return reloader, nil
}

// SetOnReloadCallback sets the callback function that will be called when configuration
// is reloaded. The callback receives the old and new configs.
func (r *ConfigReloader) SetOnReloadCallback(callback func(old, new *Config) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onReload = callback
}

// Start begins watching for configuration changes. This method blocks until Stop() is called.
func (r *ConfigReloader) Start() {
	r.logger.Info("Configuration hot-reload enabled")

	for {
		select {
		case <-r.stopChan:
			r.logger.Info("Configuration reloader stopping")
			return

		case event, ok := <-r.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) && event.Name == r.configPath {
				r.logger.Info("Configuration file changed, reloading...")
				r.reloadConfig()

			} else if event.Has(fsnotify.Remove) && event.Name == r.configPath {
				r.logger.Warn("Configuration file removed, stopping file watch")
				r.watcher.Remove(r.configPath)
			}

		case err, ok := <-r.watcher.Errors:
			if !ok {
				return
			}
			r.logger.WithError(err).Error("Configuration file watch error")

		case sig := <-r.signalChan:
			if sig == syscall.SIGHUP {
				r.logger.Info("Received SIGHUP, reloading configuration...")
				r.reloadConfig()
			}
		}
	}
}

// Stop stops the configuration reloader.
func (r *ConfigReloader) Stop() {
	close(r.stopChan)
	r.watcher.Close()
	signal.Stop(r.signalChan)
}

// reloadConfig attempts to reload the configuration from disk.
func (r *ConfigReloader) reloadConfig() {
	newConfig, err := LoadConfig(r.configPath)
	if err != nil {
		r.logger.WithError(err).Error("Failed to reload configuration")
		return
	}

	r.mu.RLock()
	oldConfig := *r.currentConfig // Make a copy of the old config
	r.mu.RUnlock()

	// Validate that only safe fields have changed
	if err := r.validateReloadSafety(&oldConfig, newConfig); err != nil {
		r.logger.WithError(err).Error("Configuration reload rejected: unsafe changes detected")
		return
	}

	// Apply the changes via callback
	if r.onReload != nil {
		if err := r.onReload(&oldConfig, newConfig); err != nil {
			r.logger.WithError(err).Error("Failed to apply configuration changes")
			return
		}
	}

	// Update current config
	r.mu.Lock()
	r.currentConfig = newConfig
	r.mu.Unlock()

	r.logger.Info("Configuration reloaded successfully")
}

// validateReloadSafety ensures that only non-crypto settings have changed.
func (r *ConfigReloader) validateReloadSafety(old, new *Config) error {
	// Crypto settings that MUST NOT change during hot reload
	if old.Encryption.Password != new.Encryption.Password {
		return fmt.Errorf("encryption.password cannot be changed during hot reload")
	}
	if old.Encryption.KeyFile != new.Encryption.KeyFile {
		return fmt.Errorf("encryption.key_file cannot be changed during hot reload")
	}
	if old.Encryption.KeyManager.Enabled != new.Encryption.KeyManager.Enabled {
		return fmt.Errorf("encryption.key_manager.enabled cannot be changed during hot reload")
	}
	if old.Encryption.PreferredAlgorithm != new.Encryption.PreferredAlgorithm {
		return fmt.Errorf("encryption.preferred_algorithm cannot be changed during hot reload")
	}
	if len(old.Encryption.SupportedAlgorithms) != len(new.Encryption.SupportedAlgorithms) {
		return fmt.Errorf("encryption.supported_algorithms cannot be changed during hot reload")
	}
	for i, alg := range old.Encryption.SupportedAlgorithms {
		if i >= len(new.Encryption.SupportedAlgorithms) || alg != new.Encryption.SupportedAlgorithms[i] {
			return fmt.Errorf("encryption.supported_algorithms cannot be changed during hot reload")
		}
	}
	if old.Encryption.ChunkedMode != new.Encryption.ChunkedMode {
		return fmt.Errorf("encryption.chunked_mode cannot be changed during hot reload")
	}
	if old.Encryption.ChunkSize != new.Encryption.ChunkSize {
		return fmt.Errorf("encryption.chunk_size cannot be changed during hot reload")
	}
	if old.Encryption.Hardware.EnableAESNI != new.Encryption.Hardware.EnableAESNI {
		return fmt.Errorf("encryption.hardware.enable_aesni cannot be changed during hot reload")
	}
	if old.Encryption.Hardware.EnableARMv8AES != new.Encryption.Hardware.EnableARMv8AES {
		return fmt.Errorf("encryption.hardware.enable_armv8_aes cannot be changed during hot reload")
	}

	// Compression settings - changing these could affect existing encrypted data
	if old.Compression.Enabled != new.Compression.Enabled {
		return fmt.Errorf("compression.enabled cannot be changed during hot reload")
	}
	if old.Compression.Algorithm != new.Compression.Algorithm {
		return fmt.Errorf("compression.algorithm cannot be changed during hot reload")
	}
	if old.Compression.Level != new.Compression.Level {
		return fmt.Errorf("compression.level cannot be changed during hot reload")
	}

	// Backend settings that affect encryption/decryption compatibility
	if old.Backend.Provider != new.Backend.Provider {
		return fmt.Errorf("backend.provider cannot be changed during hot reload")
	}

	// Admin settings — listener is only started/stopped at process start
	if old.Admin.Enabled != new.Admin.Enabled {
		return fmt.Errorf("admin.enabled cannot be changed during hot reload")
	}
	if old.Admin.Address != new.Admin.Address {
		return fmt.Errorf("admin.address cannot be changed during hot reload")
	}
	if old.Admin.TLS.Enabled != new.Admin.TLS.Enabled {
		return fmt.Errorf("admin.tls.enabled cannot be changed during hot reload")
	}
	if old.Admin.TLS.CertFile != new.Admin.TLS.CertFile {
		return fmt.Errorf("admin.tls.cert_file cannot be changed during hot reload")
	}
	if old.Admin.TLS.KeyFile != new.Admin.TLS.KeyFile {
		return fmt.Errorf("admin.tls.key_file cannot be changed during hot reload")
	}

	return nil
}

// GetCurrentConfig returns a copy of the current configuration.
func (r *ConfigReloader) GetCurrentConfig() *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	// Return a copy to prevent external modification
	configCopy := *r.currentConfig
	return &configCopy
}
