package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/kenchrcum/s3-encryption-gateway/internal/admin"
	"github.com/kenchrcum/s3-encryption-gateway/internal/api"
	"github.com/kenchrcum/s3-encryption-gateway/internal/audit"
	"github.com/kenchrcum/s3-encryption-gateway/internal/cache"
	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
	"github.com/kenchrcum/s3-encryption-gateway/internal/debug"
	"github.com/kenchrcum/s3-encryption-gateway/internal/metrics"
	"github.com/kenchrcum/s3-encryption-gateway/internal/middleware"
	mpupkg "github.com/kenchrcum/s3-encryption-gateway/internal/mpu"
	"github.com/kenchrcum/s3-encryption-gateway/internal/s3"
	"github.com/kenchrcum/s3-encryption-gateway/internal/util"
	"github.com/sirupsen/logrus"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

var (
	version = "dev"
	commit  = "unknown"
)

// ConfigChangeApplier holds references to components that can be updated during hot reload
type ConfigChangeApplier struct {
	logger         *logrus.Logger
	tracerProvider *sdktrace.TracerProvider
	RateLimiter    *middleware.RateLimiter
	cache          cache.Cache
	auditLogger    audit.Logger
	config         *config.Config
	policyManager  *config.PolicyManager
}

// NewConfigChangeApplier creates a new applier for configuration changes
func NewConfigChangeApplier(logger *logrus.Logger, tracerProvider *sdktrace.TracerProvider, rateLimiter *middleware.RateLimiter, cache cache.Cache, auditLogger audit.Logger, initialConfig *config.Config, policyManager *config.PolicyManager) *ConfigChangeApplier {
	return &ConfigChangeApplier{
		logger:         logger,
		tracerProvider: tracerProvider,
		RateLimiter:    rateLimiter,
		cache:          cache,
		auditLogger:    auditLogger,
		config:         initialConfig,
		policyManager:  policyManager,
	}
}

// stringSlicesEqual compares two string slices element-by-element.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ApplyConfigChanges applies non-crypto configuration changes to running components
func (a *ConfigChangeApplier) ApplyConfigChanges(oldConfig, newConfig *config.Config) error {
	changes := []string{}

	// Update log level
	if oldConfig.LogLevel != newConfig.LogLevel {
		level, err := logrus.ParseLevel(newConfig.LogLevel)
		if err != nil {
			a.logger.WithError(err).Warn("Invalid log level in reloaded config, keeping current level")
		} else {
			a.logger.SetLevel(level)
			debug.InitFromLogLevel(newConfig.LogLevel)
			changes = append(changes, fmt.Sprintf("log_level: %s -> %s", oldConfig.LogLevel, newConfig.LogLevel))
		}
	}

	// Update rate limiting
	if oldConfig.RateLimit.Enabled != newConfig.RateLimit.Enabled ||
		oldConfig.RateLimit.Limit != newConfig.RateLimit.Limit ||
		oldConfig.RateLimit.Window != newConfig.RateLimit.Window {

		if a.RateLimiter != nil {
			a.RateLimiter.Stop()
		}

		if newConfig.RateLimit.Enabled {
			a.RateLimiter = middleware.NewRateLimiter(
				newConfig.RateLimit.Limit,
				newConfig.RateLimit.Window,
				a.logger,
			)
			changes = append(changes, fmt.Sprintf("rate_limit: enabled=%v, limit=%d, window=%v",
				newConfig.RateLimit.Enabled, newConfig.RateLimit.Limit, newConfig.RateLimit.Window))
		} else {
			a.RateLimiter = nil
			changes = append(changes, "rate_limit: disabled")
		}
	}

	// Update cache settings
	if oldConfig.Cache.Enabled != newConfig.Cache.Enabled ||
		oldConfig.Cache.MaxSize != newConfig.Cache.MaxSize ||
		oldConfig.Cache.MaxItems != newConfig.Cache.MaxItems ||
		oldConfig.Cache.DefaultTTL != newConfig.Cache.DefaultTTL {

		// Note: Cache reconfiguration is complex and may not be safe for existing entries
		// For now, we'll log the change but not apply it
		a.logger.WithFields(logrus.Fields{
			"old_enabled":   oldConfig.Cache.Enabled,
			"new_enabled":   newConfig.Cache.Enabled,
			"old_max_size":  oldConfig.Cache.MaxSize,
			"new_max_size":  newConfig.Cache.MaxSize,
			"old_max_items": oldConfig.Cache.MaxItems,
			"new_max_items": newConfig.Cache.MaxItems,
			"old_ttl":       oldConfig.Cache.DefaultTTL,
			"new_ttl":       newConfig.Cache.DefaultTTL,
		}).Warn("Cache configuration changed - restart required for changes to take effect")

		changes = append(changes, "cache: configuration changed (restart required)")
	}

	// Update audit settings
	if oldConfig.Audit.Enabled != newConfig.Audit.Enabled ||
		oldConfig.Audit.MaxEvents != newConfig.Audit.MaxEvents {

		// Note: Changing audit settings during runtime is complex
		// For now, we'll log the change but not apply it
		a.logger.WithFields(logrus.Fields{
			"old_enabled":    oldConfig.Audit.Enabled,
			"new_enabled":    newConfig.Audit.Enabled,
			"old_max_events": oldConfig.Audit.MaxEvents,
			"new_max_events": newConfig.Audit.MaxEvents,
		}).Warn("Audit configuration changed - restart required for changes to take effect")

		changes = append(changes, "audit: configuration changed (restart required)")
	}

	// Update tracing settings
	if oldConfig.Tracing.Enabled != newConfig.Tracing.Enabled ||
		oldConfig.Tracing.ServiceName != newConfig.Tracing.ServiceName ||
		oldConfig.Tracing.ServiceVersion != newConfig.Tracing.ServiceVersion ||
		oldConfig.Tracing.Exporter != newConfig.Tracing.Exporter ||
		oldConfig.Tracing.JaegerEndpoint != newConfig.Tracing.JaegerEndpoint ||
		oldConfig.Tracing.OtlpEndpoint != newConfig.Tracing.OtlpEndpoint ||
		oldConfig.Tracing.SamplingRatio != newConfig.Tracing.SamplingRatio ||
		oldConfig.Tracing.RedactSensitive != newConfig.Tracing.RedactSensitive {

		// Tracing reconfiguration is complex and may require restarting the tracer provider
		a.logger.WithFields(logrus.Fields{
			"old_enabled": oldConfig.Tracing.Enabled,
			"new_enabled": newConfig.Tracing.Enabled,
		}).Warn("Tracing configuration changed - restart required for changes to take effect")

		changes = append(changes, "tracing: configuration changed (restart required)")
	}

	// Update proxied bucket
	if oldConfig.ProxiedBucket != newConfig.ProxiedBucket {
		a.logger.WithFields(logrus.Fields{
			"old_bucket": oldConfig.ProxiedBucket,
			"new_bucket": newConfig.ProxiedBucket,
		}).Warn("Proxied bucket changed - restart required for changes to take effect")

		changes = append(changes, fmt.Sprintf("proxied_bucket: %s -> %s (restart required)", oldConfig.ProxiedBucket, newConfig.ProxiedBucket))
	}

	// Update server timeouts (these require server restart, but we can log the change)
	if oldConfig.Server.ReadTimeout != newConfig.Server.ReadTimeout ||
		oldConfig.Server.WriteTimeout != newConfig.Server.WriteTimeout ||
		oldConfig.Server.IdleTimeout != newConfig.Server.IdleTimeout ||
		oldConfig.Server.ReadHeaderTimeout != newConfig.Server.ReadHeaderTimeout ||
		oldConfig.Server.MaxHeaderBytes != newConfig.Server.MaxHeaderBytes ||
		oldConfig.Server.DisableMultipartUploads != newConfig.Server.DisableMultipartUploads {

		a.logger.WithFields(logrus.Fields{
			"read_timeout":  newConfig.Server.ReadTimeout,
			"write_timeout": newConfig.Server.WriteTimeout,
			"idle_timeout":  newConfig.Server.IdleTimeout,
		}).Warn("Server configuration changed - restart required for changes to take effect")

		changes = append(changes, "server: timeouts/configuration changed (restart required)")
	}

	// Update logging configuration
	if oldConfig.Logging.AccessLogFormat != newConfig.Logging.AccessLogFormat ||
		len(oldConfig.Logging.RedactHeaders) != len(newConfig.Logging.RedactHeaders) {

		// Check if redact headers changed
		headersChanged := len(oldConfig.Logging.RedactHeaders) != len(newConfig.Logging.RedactHeaders)
		if !headersChanged {
			for i, header := range oldConfig.Logging.RedactHeaders {
				if i >= len(newConfig.Logging.RedactHeaders) || header != newConfig.Logging.RedactHeaders[i] {
					headersChanged = true
					break
				}
			}
		}

		if oldConfig.Logging.AccessLogFormat != newConfig.Logging.AccessLogFormat || headersChanged {
			a.logger.WithFields(logrus.Fields{
				"old_format": oldConfig.Logging.AccessLogFormat,
				"new_format": newConfig.Logging.AccessLogFormat,
			}).Warn("Logging configuration changed - restart required for changes to take effect")

			changes = append(changes, "logging: configuration changed (restart required)")
		}
	}

	// Update policy files
	if !stringSlicesEqual(oldConfig.PolicyFiles, newConfig.PolicyFiles) {
		if len(newConfig.PolicyFiles) > 0 {
			if a.policyManager == nil {
				a.policyManager = config.NewPolicyManager()
			}
			if err := a.policyManager.LoadPolicies(newConfig.PolicyFiles); err != nil {
				a.logger.WithError(err).Warn("Failed to reload policy files during config change")
				changes = append(changes, "policy_files: reload failed")
			} else {
				changes = append(changes, fmt.Sprintf("policy_files: reloaded (%d files)", len(newConfig.PolicyFiles)))
			}
		} else {
			a.policyManager = nil
			changes = append(changes, "policy_files: cleared")
		}
	}

	// Update the config reference
	a.config = newConfig

	// Log all changes
	if len(changes) > 0 {
		a.logger.WithField("changes", changes).Info("Configuration reloaded with changes")
	} else {
		a.logger.Info("Configuration reloaded (no changes detected)")
	}

	return nil
}

// InitTracing initializes OpenTelemetry tracing based on configuration
func InitTracing(cfg config.TracingConfig, logger *logrus.Logger) (*sdktrace.TracerProvider, error) {
	// Create resource with service information
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create exporter based on configuration
	var exporter sdktrace.SpanExporter
	switch cfg.Exporter {
	case "none":
		return sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.NeverSample()),
		), nil
	case "stdout":
		exporter, err = stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("failed to create stdout exporter: %w", err)
		}
	case "jaeger":
		exporter, err = jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(cfg.JaegerEndpoint)))
		if err != nil {
			return nil, fmt.Errorf("failed to create jaeger exporter: %w", err)
		}
	case "otlp":
		exporter, err = otlptracegrpc.New(context.Background(),
			otlptracegrpc.WithEndpoint(cfg.OtlpEndpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported exporter: %s", cfg.Exporter)
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if cfg.SamplingRatio >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SamplingRatio <= 0.0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SamplingRatio)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampler),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(sdktrace.NewBatchSpanProcessor(exporter)),
	)

	// Set as global tracer provider
	otel.SetTracerProvider(tp)

	return tp, nil
}

// zeroBytes overwrites a byte slice with zeros for secure memory cleanup.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func main() {
	// Initialize logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)

	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		logger.WithError(err).Fatal("Failed to load configuration")
	}

	// If the config file doesn't exist on disk, disable hot-reload.
	// This is normal when running with env-var-only configuration (e.g. Helm).
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) { // #nosec G703 — operator-configured file path
		logger.WithField("config_file", configPath).Info("Config file not found — hot-reload disabled")
		configPath = ""
	}

	// Set log level from config
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.WithError(err).Warn("Invalid log level, using info")
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Initialize debug logging based on log level
	debug.InitFromLogLevel(cfg.LogLevel)

	logger.WithFields(logrus.Fields{
		"version": version,
		"commit":  commit,
	}).Info("Starting S3 Encryption Gateway")

	// Assert FIPS profile if binary was built with -tags=fips
	if err := crypto.AssertFIPS(); err != nil {
		logger.WithError(err).Fatal("FIPS profile assertion failed")
	}

	// Initialize tracing if enabled
	var tracerProvider *sdktrace.TracerProvider
	if cfg.Tracing.Enabled {
		var err error
		tracerProvider, err = InitTracing(cfg.Tracing, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize tracing")
		}
		defer func() {
			if err := tracerProvider.Shutdown(context.Background()); err != nil {
				logger.WithError(err).Error("Failed to shutdown tracer provider")
			}
		}()
		logger.WithFields(logrus.Fields{
			"exporter":       cfg.Tracing.Exporter,
			"service_name":   cfg.Tracing.ServiceName,
			"sampling_ratio": cfg.Tracing.SamplingRatio,
		}).Info("Tracing initialized")
	}

	// Initialize metrics
	metricsConfig := metrics.Config{
		EnableBucketLabel: cfg.Metrics.EnableBucketLabel,
	}
	m := metrics.NewMetricsWithConfig(metricsConfig)
	metrics.SetVersion(version)
	m.SetFIPSMode(crypto.FIPSEnabled())
	logger.WithFields(logrus.Fields{
		"fips": crypto.FIPSEnabled(),
	}).Info("crypto profile")

	// Start system metrics collector
	m.StartSystemMetricsCollector()

	// Log any advisory warnings from the retry configuration.
	for _, w := range s3.ValidationWarnings(cfg.Backend.Retry) {
		logger.Warn("backend retry config: " + w)
	}

	// Initialize S3 client.
	// V0.6-PERF-2: always use ClientFactory so the retry policy is applied.
	factory := s3.NewClientFactory(&cfg.Backend, s3.WithMetrics(m))
	s3Client, err := factory.GetClient()
	if err != nil {
		logger.WithError(err).Fatal("Failed to create S3 client")
	}
	logger.WithFields(logrus.Fields{
		"retry_mode":      cfg.Backend.Retry.Mode,
		"max_attempts":    cfg.Backend.Retry.MaxAttempts,
		"initial_backoff": cfg.Backend.Retry.InitialBackoff,
	}).Info("S3 backend client initialized with configured credentials and retry policy")

	// Load encryption password (required for both single password and KMS modes)
	var encryptionPassword []byte
	var keyManager crypto.KeyManager

	if cfg.Encryption.Password != "" {
		encryptionPassword = []byte(cfg.Encryption.Password)
	} else if cfg.Encryption.KeyFile != "" {
		keyData, err := os.ReadFile(cfg.Encryption.KeyFile)
		if err != nil {
			logger.WithError(err).Fatal("Failed to read encryption key file")
		}
		encryptionPassword = make([]byte, len(keyData))
		copy(encryptionPassword, keyData)
		zeroBytes(keyData)
	}

	if len(encryptionPassword) == 0 {
		logger.Fatal("Encryption password is required (set ENCRYPTION_PASSWORD or encryption.password)")
	}

	activePassword := make([]byte, len(encryptionPassword))
	copy(activePassword, encryptionPassword)
	zeroBytes(encryptionPassword)
	if cfg.Encryption.KeyManager.Enabled {
		keyManager, err = api.BuildKeyManager(&cfg.Encryption.KeyManager, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize key manager")
		}
		defer func() {
			if err := keyManager.Close(context.Background()); err != nil {
				logger.WithError(err).Warn("Failed to close key manager cleanly")
			}
		}()
		logger.WithFields(logrus.Fields{
			"provider": strings.ToLower(cfg.Encryption.KeyManager.Provider),
		}).Info("External key manager initialized")
	} else {
		// Password-only mode: construct a PasswordKeyManager so that encrypted
		// multipart uploads (EncryptMultipartUploads=true) can wrap per-upload
		// DEKs with PBKDF2+AES-256-GCM instead of storing them in plaintext.
		// This provides equivalent confidentiality to single-PUT chunked encryption.
		pkm, pkmErr := crypto.NewPasswordKeyManager(activePassword, cfg.Encryption.KDF.PBKDF2.Iterations)
		if pkmErr != nil {
			logger.WithError(pkmErr).Fatal("Failed to initialize password key manager")
		}
		keyManager = pkm
		logger.Info("Using single password mode (no key rotation); PasswordKeyManager active for MPU DEK wrapping")
	}

	// Initialize compression engine if enabled
	var compressionEngine crypto.CompressionEngine
	if cfg.Compression.Enabled {
		compressionEngine = crypto.NewCompressionEngine(
			cfg.Compression.Enabled,
			cfg.Compression.MinSize,
			cfg.Compression.ContentTypes,
			cfg.Compression.Algorithm,
			cfg.Compression.Level,
		)
		logger.WithFields(logrus.Fields{
			"enabled":   cfg.Compression.Enabled,
			"algorithm": cfg.Compression.Algorithm,
			"min_size":  cfg.Compression.MinSize,
		}).Info("Compression enabled")
	}

	// Log hardware acceleration info
	hwInfo := crypto.GetHardwareAccelerationInfo(&cfg.Encryption.Hardware)
	logger.WithFields(logrus.Fields{
		"aes_hardware_support": hwInfo["aes_hardware_support"],
		"architecture":         hwInfo["architecture"],
		"active":               hwInfo["hardware_acceleration_active"],
	}).Info("Hardware acceleration status")

	// Set hardware acceleration metric
	if active, ok := hwInfo["hardware_acceleration_active"].(bool); ok {
		accelType := "unknown"
		if strings.Contains(hwInfo["architecture"].(string), "amd64") || strings.Contains(hwInfo["architecture"].(string), "386") {
			accelType = "aes-ni"
		} else if strings.Contains(hwInfo["architecture"].(string), "arm") {
			accelType = "armv8-aes"
		}
		m.SetHardwareAccelerationStatus(accelType, active)
	}

	// Initialize encryption engine with compression, algorithm support, chunked mode, and key resolver (if KMS mode)
	var encryptionEngine crypto.EncryptionEngine

	// Default to chunked mode enabled unless explicitly disabled
	chunkedMode := cfg.Encryption.ChunkedMode
	if !cfg.Encryption.ChunkedMode && cfg.Encryption.ChunkSize == 0 {
		// If neither is set, default to enabled for new installations
		chunkedMode = true
	}

	// NEW-01: Emit a prominent startup warning when legacy (non-chunked) mode is
	// active. In this mode Encrypt and Decrypt each call io.ReadAll on the
	// entire object body, so a single large upload allocates roughly the object
	// size as heap. This is a remote memory-exhaustion risk for large objects.
	// Chunked mode streams data in fixed-size chunks and is the recommended
	// default for all production deployments.
	if !chunkedMode {
		logger.Warn("SECURITY WARNING: chunked_mode is disabled. " +
			"Encrypt and Decrypt buffer entire objects in heap memory (io.ReadAll). " +
			"A large upload or download will allocate the full object size on the heap, " +
			"enabling a trivial remote memory-exhaustion DoS. " +
			"Enable encryption.chunked_mode: true in your configuration for production workloads.")
	}

	chunkSize := cfg.Encryption.ChunkSize
	if chunkSize == 0 {
		chunkSize = crypto.DefaultChunkSize
	}

	// Build engine options
	engineOpts := []crypto.Option{
		crypto.WithPreferredAlgorithm(cfg.Encryption.PreferredAlgorithm),
		crypto.WithSupportedAlgorithms(cfg.Encryption.SupportedAlgorithms),
		crypto.WithChunking(chunkedMode),
		crypto.WithChunkSize(chunkSize),
		crypto.WithProvider("default"),
		crypto.WithPBKDF2Iterations(cfg.Encryption.KDF.PBKDF2.Iterations),
		crypto.WithKDFAlgorithm(cfg.Encryption.KDF.Algorithm),
	}
	if cfg.Encryption.KDF.Algorithm == "argon2id" {
		engineOpts = append(engineOpts,
			crypto.WithArgon2idParams(
				cfg.Encryption.KDF.Argon2id.Time,
				cfg.Encryption.KDF.Argon2id.Memory,
				cfg.Encryption.KDF.Argon2id.Threads,
			),
		)
	}

	encryptionEngine, err = crypto.NewEngineWithOpts(
		activePassword,
		compressionEngine,
		engineOpts...,
	)
	// Zero the upstream password copy now that the engine owns its own defensive copy.
	zeroBytes(activePassword)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create encryption engine")
	}
	if keyManager != nil {
		crypto.SetKeyManager(encryptionEngine, keyManager)
	}

	// V1.0-CRYPTO-3: load metadata encryption key.
	var metadataKey []byte
	switch {
	case cfg.Encryption.MetadataEncryptionKeyFile != "" && cfg.Encryption.MetadataEncryptionKey != "":
		logger.Fatal("Only one of metadata_encryption_key_file or metadata_encryption_key may be set")

	case cfg.Encryption.MetadataEncryptionKeyFile != "":
		data, err := os.ReadFile(cfg.Encryption.MetadataEncryptionKeyFile)
		if err != nil {
			logger.WithError(err).Fatal("Failed to read metadata encryption key file")
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil {
			logger.WithError(err).Fatal("Metadata encryption key file is not valid base64")
		}
		if len(key) != 32 {
			logger.Fatalf("Metadata encryption key must be exactly 32 bytes (got %d)", len(key))
		}
		metadataKey = key

	case cfg.Encryption.MetadataEncryptionKey != "":
		if len(cfg.Encryption.MetadataEncryptionKey) < 128 {
			logger.Fatal("metadata_encryption_key must be at least 128 characters")
		}
		hash := sha256.Sum256([]byte(cfg.Encryption.MetadataEncryptionKey))
		metadataKey = hash[:]
	}

	if metadataKey != nil {
		if keyManager != nil {
			envelope, err := keyManager.WrapKey(context.Background(), metadataKey, nil)
			if err != nil {
				logger.WithError(err).Fatal("Failed to wrap metadata key with KMS")
			}
			crypto.SetWrappedMetadataKey(encryptionEngine, envelope)
		} else {
			crypto.SetMetadataKey(encryptionEngine, metadataKey)
		}
		zeroBytes(metadataKey)
		logger.Info("Metadata encryption key configured")
	} else {
		logger.Info("Metadata encryption not configured — encryption parameters will be stored as plaintext headers")
	}

	logger.WithFields(logrus.Fields{
		"preferred_algorithm":       cfg.Encryption.PreferredAlgorithm,
		"supported_algorithms":      cfg.Encryption.SupportedAlgorithms,
		"chunked_mode":              chunkedMode,
		"chunk_size":                chunkSize,
		"kdf_algorithm":             cfg.Encryption.KDF.Algorithm,
		"kdf_pbkdf2_iterations":     cfg.Encryption.KDF.PBKDF2.Iterations,
		"kdf_argon2id_time":         cfg.Encryption.KDF.Argon2id.Time,
		"kdf_argon2id_memory":       cfg.Encryption.KDF.Argon2id.Memory,
		"kdf_argon2id_threads":      cfg.Encryption.KDF.Argon2id.Threads,
	}).Info("Encryption configuration")

	// Initialize cache if enabled (Phase 5 feature)
	var objectCache cache.Cache
	if cfg.Cache.Enabled {
		objectCache = cache.NewMemoryCache(
			cfg.Cache.MaxSize,
			cfg.Cache.MaxItems,
			cfg.Cache.DefaultTTL,
		)
		logger.WithFields(logrus.Fields{
			"max_size":    cfg.Cache.MaxSize,
			"max_items":   cfg.Cache.MaxItems,
			"default_ttl": cfg.Cache.DefaultTTL,
		}).Info("Cache enabled")
	}

	// Initialize audit logger if enabled (Phase 5 feature)
	var auditLogger audit.Logger
	if cfg.Audit.Enabled {
		var err error
		auditLogger, err = audit.NewLoggerFromConfig(cfg.Audit)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize audit logger")
		}
		logger.WithFields(logrus.Fields{
			"max_events": cfg.Audit.MaxEvents,
			"sink_type":  cfg.Audit.Sink.Type,
		}).Info("Audit logging enabled")
	}

	// Initialize policy manager if policy files are configured
	var policyManager *config.PolicyManager
	if len(cfg.PolicyFiles) > 0 {
		policyManager = config.NewPolicyManager()
		if err := policyManager.LoadPolicies(cfg.PolicyFiles); err != nil {
			logger.WithError(err).Fatal("Failed to load policy files")
		}
		logger.WithField("count", len(cfg.PolicyFiles)).Info("Policy files loaded")
	}

	// Fail-closed startup check: if any bucket policy enables EncryptMultipartUploads
	// but the Valkey addr is not configured, refuse to start rather than silently
	// falling back to plaintext multipart uploads (Phase C DoD requirement).
	if policyManager.AnyPolicyRequiresMPUEncryption() && cfg.MultipartState.Valkey.Addr == "" {
		logger.Fatal("One or more bucket policies require EncryptMultipartUploads=true " +
			"but multipart_state.valkey.addr is not configured. " +
			"Configure Valkey or remove EncryptMultipartUploads from all policies.")
	}

	// Create gateway credential store from resolved credentials.
	// V1.0-AUTH-1: every request must present valid gateway-managed credentials.
	resolvedCreds := cfg.ResolvedCredentials()
	credStore, err := api.NewStaticCredentialStore(resolvedCreds)
	if err != nil {
		logger.WithError(err).Fatal("Failed to create credential store")
	}
	// Zero plaintext secrets from the transient slice; the store holds its own copy.
	for i := range resolvedCreds {
		resolvedCreds[i].SecretKey = strings.Repeat("\x00", len(resolvedCreds[i].SecretKey))
	}
	resolvedCreds = nil
	logger.WithField("count", len(cfg.Auth.Credentials)).Info("Gateway credential store initialized")

	// Initialize API handler with Phase 5 features
	handler := api.NewHandlerWithFeatures(s3Client, encryptionEngine, logger, m, keyManager, objectCache, auditLogger, cfg, policyManager)

	// Initialise Valkey state store for encrypted multipart uploads when any
	// bucket policy enables EncryptMultipartUploads. Fail-closed: if Valkey is
	// unreachable at startup and encrypted MPU is required, refuse to start.
	var mpuStore mpupkg.StateStore
	if cfg.MultipartState.Valkey.Addr != "" {
		var err error
		mpuStore, err = mpupkg.NewValkeyStateStore(context.Background(), cfg.MultipartState.Valkey, cfg.Encryption.Password)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialise MPU Valkey state store")
		}
		handler.WithMPUStateStore(mpuStore)
		m.SetMPUValkeyInsecure(!cfg.MultipartState.Valkey.TLS.Enabled)
		logger.WithField("addr", cfg.MultipartState.Valkey.Addr).Info("MPU Valkey state store initialised")
	}

	// Initialize configuration hot-reload (only if config file is specified)
	var configReloader *config.ConfigReloader
	var configApplier *ConfigChangeApplier

	if configPath != "" { // Enable hot-reload for any non-empty config path
		// Create config change applier
		var rateLimiterPtr *middleware.RateLimiter
		if cfg.RateLimit.Enabled {
			rateLimiterPtr = middleware.NewRateLimiter(
				cfg.RateLimit.Limit,
				cfg.RateLimit.Window,
				logger,
			)
			defer rateLimiterPtr.Stop()
		}

		configApplier = NewConfigChangeApplier(logger, tracerProvider, rateLimiterPtr, objectCache, auditLogger, cfg, policyManager)

		// Create and start config reloader
		var err error
		configReloader, err = config.NewConfigReloader(configPath, cfg, logger)
		if err != nil {
			logger.WithError(err).Fatal("Failed to initialize config reloader")
		}

		// Set the reload callback
		configReloader.SetOnReloadCallback(configApplier.ApplyConfigChanges)

		// Start config reloader in background
		go configReloader.Start()

		logger.WithField("config_file", configPath).Info("Configuration hot-reload enabled")
	}

	// Setup router
	router := mux.NewRouter()

	// Register health check endpoint
	router.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}).Methods("GET", "HEAD")

	// Register API routes
	handler.RegisterRoutes(router)

	// Initialize IP extractor with trusted proxies (V1.0-SEC-6, V1.0-SEC-16).
	// This ensures client IP extraction honors trusted proxy configuration
	// and prevents X-Forwarded-For header spoofing in tracing, rate limiting,
	// and audit logging.
	ipExtractor, err := util.NewIPExtractor(cfg.Server.TrustedProxies)
	if err != nil {
		logger.WithError(err).Fatal("Invalid trusted proxies configuration")
	}
	api.SetIPExtractor(ipExtractor)
	middleware.SetIPExtractor(ipExtractor)

	// Apply middleware
	// RecoveryMiddleware is intentionally applied LAST so it wraps all other
	// layers. If it were innermost, panics in outer middleware (logging,
	// security headers, tracing, bucket validation, rate limiting) would
	// bypass recovery and crash the server goroutine.
	httpHandler := middleware.LoggingMiddleware(logger, &cfg.Logging)(router)
	httpHandler = middleware.SecurityHeadersMiddleware(cfg.Server.ForceHTTPS)(httpHandler)

	// Apply tracing middleware if tracing is enabled
	if cfg.Tracing.Enabled {
		httpHandler = middleware.TracingMiddleware(cfg.Tracing.RedactSensitive, ipExtractor)(httpHandler)
	}

	// Apply bucket validation middleware if proxied bucket is configured
	if cfg.ProxiedBucket != "" {
		httpHandler = middleware.BucketValidationMiddleware(cfg.ProxiedBucket, logger)(httpHandler)
		logger.WithField("proxied_bucket", cfg.ProxiedBucket).Info("Single bucket proxy mode enabled")
	}

	// Add rate limiting if enabled
	if cfg.RateLimit.Enabled {
		// Use the rate limiter from config applier if hot-reload is enabled
		var rateLimiter *middleware.RateLimiter
		if configApplier != nil && configApplier.RateLimiter != nil {
			rateLimiter = configApplier.RateLimiter
		} else {
			rateLimiter = middleware.NewRateLimiter(
				cfg.RateLimit.Limit,
				cfg.RateLimit.Window,
				logger,
			)
			defer rateLimiter.Stop()
		}
		httpHandler = middleware.RateLimitMiddleware(rateLimiter)(httpHandler)
		logger.WithFields(logrus.Fields{
			"limit":  cfg.RateLimit.Limit,
			"window": cfg.RateLimit.Window,
		}).Info("Rate limiting enabled")
	}

	// V1.0-AUTH-1: AuthMiddleware gatekeeps every request before it reaches
	// business logic. It runs inside RecoveryMiddleware so panics during auth
	// validation are caught, but it must be outermost among functional
	// middleware so unauthenticated requests are rejected early.
	httpHandler = api.AuthMiddleware(credStore, cfg.Auth.ClockSkewTolerance, logger)(httpHandler)

	// RecoveryMiddleware wraps the ENTIRE chain so panics in any layer are caught.
	httpHandler = middleware.RecoveryMiddleware(logger)(httpHandler)

	// Create HTTP server
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpHandler,
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		IdleTimeout:       cfg.Server.IdleTimeout,
		ReadHeaderTimeout: cfg.Server.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.Server.MaxHeaderBytes,
	}

	// Start server in goroutine
	go func() {
		var err error
		if cfg.TLS.Enabled {
			logger.WithFields(logrus.Fields{
				"addr":      cfg.ListenAddr,
				"cert_file": cfg.TLS.CertFile,
				"key_file":  cfg.TLS.KeyFile,
			}).Info("Starting HTTPS server")
			err = server.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			logger.WithField("addr", cfg.ListenAddr).Info("Starting HTTP server")
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Fatal("Failed to start server")
		}
	}()

	// Start admin server if enabled
	var adminServer *admin.Server
	if cfg.Admin.Enabled {
		adminServer = admin.NewServer(cfg.Admin, logger)

		// Register rotation handler on admin mux
		rotationHandler := api.NewAdminRotationHandler(encryptionEngine, logger, m, auditLogger)
		rotationHandler.RegisterRoutes(adminServer.Mux())

		// Register MPU admin endpoints
		var abortFn admin.MPUAbortFunc
		if s3Client != nil {
			abortFn = s3Client.AbortMultipartUpload
		}
		admin.RegisterMPUAdminRoutes(adminServer.Mux(), mpuStore, abortFn, logger)

		// V0.6-OBS-1 — register pprof routes when profiling is enabled.
		if cfg.Admin.Profiling.Enabled {
			admin.ApplyRuntimeProfilingRates(cfg.Admin.Profiling, logger)
			admin.RegisterPprofRoutes(
				adminServer.Mux(),
				cfg.Admin.Profiling,
				m,
				auditLogger,
				logger,
			)
			m.SetAdminProfilingEnabled(true)
			logger.WithFields(logrus.Fields{
				"block_rate":     cfg.Admin.Profiling.BlockRate,
				"mutex_fraction": cfg.Admin.Profiling.MutexFraction,
				"max_seconds":    cfg.Admin.Profiling.MaxProfileSeconds,
				"max_concurrent": cfg.Admin.Profiling.MaxConcurrentProfiles,
			}).Warn("admin_profiling_enabled") // WARN — this surface widens blast radius
		}

		// Register metrics on admin mux only when no dedicated metrics addr is
		// configured (fallback: authenticated admin port).
		if cfg.Metrics.Addr == "" {
			adminServer.Mux().Handle("/metrics", m.Handler())
		}

		// Set admin API enabled metric
		m.SetAdminAPIEnabled(true)

		go func() {
			if err := adminServer.Start(context.Background()); err != nil {
				logger.WithError(err).Error("Admin server failed")
			}
		}()
	}

	// Start dedicated metrics listener when metrics.addr is configured.
	// This is the recommended approach for Kubernetes: serve /metrics on a
	// separate unauthenticated port and restrict access via NetworkPolicy.
	// When metrics.addr is empty and admin is disabled, fall back to the S3
	// data-plane router (legacy behaviour, no TLS / auth on metrics).
	if cfg.Metrics.Addr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", m.Handler())
		metricsServer := &http.Server{
			Addr:              cfg.Metrics.Addr,
			Handler:           metricsMux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			logger.WithField("addr", cfg.Metrics.Addr).Info("metrics listener started")
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Error("metrics listener failed")
			}
		}()
	} else if !cfg.Admin.Enabled {
		// No dedicated metrics addr, no admin server — serve on S3 port (legacy).
		router.Handle("/metrics", m.Handler()).Methods("GET")
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down server...")

	// Close the API handler, zeroising any cached per-policy engine passwords.
	if handler != nil {
		handler.Close()
		logger.Info("API handler closed")
	}

	// Stop admin server if running
	if adminServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := adminServer.Shutdown(shutdownCtx); err != nil {
			logger.WithError(err).Error("Admin server forced to shutdown")
		}
		shutdownCancel()
		logger.Info("Admin server stopped")
	}

	// Stop config reloader if enabled
	if configReloader != nil {
		configReloader.Stop()
		logger.Info("Configuration reloader stopped")
	}

	// Stop audit logger
	if auditLogger != nil {
		if err := auditLogger.Close(); err != nil {
			logger.WithError(err).Error("Failed to close audit logger")
		}
		logger.Info("Audit logger stopped")
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.WithError(err).Error("Server forced to shutdown")
	} else {
		logger.Info("Server stopped gracefully")
	}
}
