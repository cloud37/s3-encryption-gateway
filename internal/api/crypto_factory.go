package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

func init() {
	// Register the "cosmian" / "kmip" adapter here — not in the crypto package —
	// so that the KMIP client dependency is only pulled in when the api package
	// is compiled, keeping internal/crypto tests dependency-light.
	crypto.Register("cosmian", cosmianFactory)
	crypto.Register("kmip", cosmianFactory) // alias
}

// cosmianFactory is the adapter Factory for the Cosmian KMIP provider.
//
// It expects cfg["__opts"] to hold a pre-built crypto.CosmianKMIPOptions
// struct. In practice BuildKeyManager builds this struct from the typed
// configuration and passes it to crypto.Open via this factory. Third-party
// callers of crypto.Open("cosmian", …) must likewise supply a constructed
// options struct under the "__opts" key.
func cosmianFactory(_ context.Context, cfg map[string]any) (crypto.KeyManager, error) {
	opts, ok := cfg["__opts"].(crypto.CosmianKMIPOptions)
	if !ok {
		return nil, fmt.Errorf("cosmian factory: missing __opts (crypto.CosmianKMIPOptions) in configuration map")
	}
	return crypto.NewCosmianKMIPManager(opts)
}

// BuildKeyManager builds a KeyManager from configuration.
//
// For providers "cosmian" and "kmip" it builds the typed options struct and
// calls the registered factory; for "memory" and "hsm" it delegates directly
// to the registry via [crypto.Open].
//
// If enabled in cfg, the returned KeyManager is wrapped with decorator layers
// (innermost to outermost):
//  1. RetryingKeyManager — exponential-backoff retry on transient errors
//  2. CircuitBreakerKeyManager — fail-fast on consecutive failures
//  3. CachingKeyManager — LRU cache for DEK unwrap results
func BuildKeyManager(cfg *config.KeyManagerConfig, logger *logrus.Logger) (crypto.KeyManager, error) {
	km, err := buildBaseKeyManager(cfg, logger)
	if err != nil {
		return nil, err
	}

	// Layer 1: retry wrapper (innermost — retries before circuit-breaker sees result)
	if cfg.Retry.Enabled {
		km = crypto.NewRetryingKeyManager(km, toKMSRetryCfg(cfg.Retry))
	}

	// Layer 2: circuit-breaker (wraps retry so consecutive failures trip the breaker)
	if cfg.CircuitBreaker.Enabled {
		km = crypto.NewCircuitBreakerKeyManager(km, toKMSCircuitBreakerCfg(cfg.CircuitBreaker))
	}

	// Layer 3: DEK cache (outermost — catches cache hits before circuit-breaker and retry)
	if cfg.DEKCache.Enabled {
		km, err = crypto.NewCachingKeyManager(km, toDEKCacheCfg(cfg.DEKCache))
		if err != nil {
			return nil, fmt.Errorf("failed to create DEK cache: %w", err)
		}
	}

	return km, nil
}

// buildBaseKeyManager constructs the raw (undecorated) KeyManager from the
// provider-specific configuration. This is the same logic that was originally
// in BuildKeyManager before the decorator stack was added.
func buildBaseKeyManager(cfg *config.KeyManagerConfig, logger *logrus.Logger) (crypto.KeyManager, error) {
	_ = logger // reserved for future structured logging
	provider := strings.ToLower(cfg.Provider)
	if provider == "" {
		provider = "cosmian"
	}

	switch provider {
	case "cosmian", "kmip":
		opts, err := buildCosmianOptions(cfg)
		if err != nil {
			return nil, err
		}
		return crypto.Open(context.Background(), provider, map[string]any{"__opts": opts})
	case "memory":
		memoryCfg := map[string]any{}
		if src := cfg.Memory.MasterKeySource; src != "" {
			memoryCfg["master_key_source"] = src
		}
		return crypto.Open(context.Background(), "memory", memoryCfg)
	case "hsm":
		return crypto.Open(context.Background(), "hsm", map[string]any{})
	case "self_contained":
		return buildSelfContainedKeyManager(cfg)
	default:
		// Attempt generic registry lookup for third-party adapters.
		km, err := crypto.Open(context.Background(), provider, map[string]any{})
		if err != nil {
			return nil, fmt.Errorf("unsupported key manager provider %q: %w", provider, err)
		}
		return km, nil
	}
}

// --- KMS decorator config conversion helpers ---------------------------------

// toKMSRetryCfg converts config.KMSRetryConfig to crypto.RetryConfig.
func toKMSRetryCfg(cfg config.KMSRetryConfig) crypto.RetryConfig {
	return crypto.RetryConfig{
		InitialInterval: cfg.InitialInterval,
		MaxInterval:     cfg.MaxInterval,
		MaxElapsedTime:  cfg.MaxElapsedTime,
		Multiplier:      cfg.Multiplier,
	}
}

// toKMSCircuitBreakerCfg converts config.KMSCircuitBreakerConfig to crypto.CircuitBreakerConfig.
func toKMSCircuitBreakerCfg(cfg config.KMSCircuitBreakerConfig) crypto.CircuitBreakerConfig {
	return crypto.CircuitBreakerConfig{
		ConsecutiveFailures: cfg.ConsecutiveFailures,
		OpenTimeout:         cfg.OpenTimeout,
		SuccessThreshold:    cfg.SuccessThreshold,
	}
}

// toDEKCacheCfg converts config.DEKCacheConfig to crypto.DEKCacheConfig.
func toDEKCacheCfg(cfg config.DEKCacheConfig) crypto.DEKCacheConfig {
	return crypto.DEKCacheConfig{
		Enabled:         cfg.Enabled,
		TTL:             cfg.TTL,
		MaxEntries:      cfg.MaxEntries,
		CleanupInterval: cfg.CleanupInterval,
	}
}

// buildCosmianOptions constructs a crypto.CosmianKMIPOptions struct from the
// typed configuration. It performs the same validation as the previous
// newCosmianKeyManager helper.
// buildSelfContainedKeyManager constructs the cfg map expected by the
// selfContainedFactory from the typed [config.KeyManagerConfig.SelfContained]
// fields and calls [crypto.Open].
func buildSelfContainedKeyManager(kmCfg *config.KeyManagerConfig) (crypto.KeyManager, error) {
	sc := kmCfg.SelfContained
	scCfg := map[string]any{
		"type": sc.Type,
	}

	switch strings.ToLower(sc.Type) {
	case "aes":
		keys := make([]any, 0, len(sc.AES.Keys))
		for _, k := range sc.AES.Keys {
			keys = append(keys, map[string]any{
				"version":    k.Version,
				"key_source": k.KeySource,
			})
		}
		scCfg["keys"] = keys
		if sc.AES.ActiveVersion != 0 {
			scCfg["active_version"] = sc.AES.ActiveVersion
		}
	case "rsa":
		scCfg["private_key_source"] = sc.RSA.PrivateKeySource
		scCfg["key_version"] = sc.RSA.KeyVersion
	}

	return crypto.Open(context.Background(), "self_contained", scCfg)
}

func buildCosmianOptions(kmCfg *config.KeyManagerConfig) (crypto.CosmianKMIPOptions, error) {
	if kmCfg.Cosmian.Endpoint == "" {
		return crypto.CosmianKMIPOptions{}, fmt.Errorf("cosmian.key_manager.endpoint is required")
	}
	if len(kmCfg.Cosmian.Keys) == 0 {
		return crypto.CosmianKMIPOptions{}, fmt.Errorf("cosmian.key_manager.keys must include at least one wrapping key reference")
	}

	tlsCfg, err := buildCosmianTLSConfig(kmCfg.Cosmian)
	if err != nil {
		return crypto.CosmianKMIPOptions{}, err
	}

	keyRefs := make([]crypto.KMIPKeyReference, 0, len(kmCfg.Cosmian.Keys))
	for i, key := range kmCfg.Cosmian.Keys {
		if key.ID == "" {
			return crypto.CosmianKMIPOptions{}, fmt.Errorf("cosmian.key_manager.keys[%d].id is required", i)
		}
		version := key.Version
		if version == 0 {
			version = i + 1
		}
		keyRefs = append(keyRefs, crypto.KMIPKeyReference{ID: key.ID, Version: version})
	}

	return crypto.CosmianKMIPOptions{
		Endpoint:       kmCfg.Cosmian.Endpoint,
		Keys:           keyRefs,
		TLSConfig:      tlsCfg,
		Timeout:        kmCfg.Cosmian.Timeout,
		Provider:       "cosmian-kmip",
		DualReadWindow: kmCfg.DualReadWindow,
	}, nil
}

func buildCosmianTLSConfig(cfg config.CosmianConfig) (*tls.Config, error) {
	if cfg.InsecureSkipVerify {
		if cfg.CACert == "" {
			return nil, fmt.Errorf("cosmian.key_manager.insecure_skip_verify is ENABLED but no ca_cert is configured — " +
				"this disables TLS certificate verification for KMS connections without pinning a trusted CA, " +
				"allowing MITM attacks. Either provide a ca_cert or remove insecure_skip_verify")
		}
		logrus.WithFields(logrus.Fields{
			"component": "crypto_factory",
			"setting":   "COSMIAN_KMS_INSECURE_SKIP_VERIFY",
		}).Error("InsecureSkipVerify is ENABLED with a custom CA certificate: TLS certificate verification is disabled for KMS connections. This should only be used in development.")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// #nosec G402 — operator opt-in with startup warning
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	if cfg.CACert != "" {
		caData, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read Cosmian CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse Cosmian CA certificate")
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load Cosmian client certificate: %w", err)
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}

	return tlsCfg, nil
}
