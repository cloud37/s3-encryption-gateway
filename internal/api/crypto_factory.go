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

	// OpenBao / HashiCorp Vault Transit (V1.0-KMS-3). One adapter, four names:
	// the Transit API is identical across OpenBao and Vault servers.
	crypto.Register("openbao", openbaoFactory)
	crypto.Register("openbao-transit", openbaoFactory)
	crypto.Register("vault", openbaoFactory)
	crypto.Register("vault-transit", openbaoFactory)
}

// openbaoFactory is the adapter Factory for the OpenBao/Vault Transit provider.
// Like cosmianFactory it expects cfg["__opts"] to hold a pre-built
// crypto.OpenBaoTransitOptions assembled by BuildKeyManager.
func openbaoFactory(_ context.Context, cfg map[string]any) (crypto.KeyManager, error) {
	opts, ok := cfg["__opts"].(crypto.OpenBaoTransitOptions)
	if !ok {
		return nil, fmt.Errorf("openbao factory: missing __opts (crypto.OpenBaoTransitOptions) in configuration map")
	}
	return crypto.NewOpenBaoTransitManager(opts)
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
	case "openbao", "openbao-transit", "vault", "vault-transit":
		opts, err := buildOpenBaoOptions(cfg, provider)
		if err != nil {
			return nil, err
		}
		return crypto.Open(context.Background(), "openbao", map[string]any{"__opts": opts})
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

// buildOpenBaoOptions constructs crypto.OpenBaoTransitOptions from the typed
// configuration, resolving env:/file: secret references for the token /
// secret_id so the long-lived config struct never holds the resolved secret.
func buildOpenBaoOptions(kmCfg *config.KeyManagerConfig, providerName string) (crypto.OpenBaoTransitOptions, error) {
	ob := kmCfg.OpenBao
	if ob.Address == "" {
		return crypto.OpenBaoTransitOptions{}, fmt.Errorf("openbao.key_manager.address is required")
	}
	if ob.KeyName == "" {
		return crypto.OpenBaoTransitOptions{}, fmt.Errorf("openbao.key_manager.key_name is required")
	}

	// Reflect the operator's chosen provider family in Provider() (and thus in
	// object metadata / telemetry) rather than always reporting a single
	// canonical string.
	provider := "openbao-transit"
	if strings.HasPrefix(strings.ToLower(providerName), "vault") {
		provider = "vault-transit"
	}

	tlsCfg, err := buildOpenBaoTLSConfig(ob.TLS)
	if err != nil {
		return crypto.OpenBaoTransitOptions{}, err
	}

	auth := crypto.OpenBaoAuthConfig{
		Method:  ob.Auth.Method,
		Mount:   ob.Auth.Mount,
		RoleID:  ob.Auth.RoleID,
		Role:    ob.Auth.Role,
		JWTPath: ob.Auth.JWTPath,
	}
	if ob.Auth.TokenSource != "" {
		tok, err := resolveOpenBaoSecret(ob.Auth.TokenSource)
		if err != nil {
			return crypto.OpenBaoTransitOptions{}, err
		}
		auth.Token = tok
	} else {
		auth.Token = ob.Auth.Token
	}
	if ob.Auth.SecretIDSource != "" {
		sid, err := resolveOpenBaoSecret(ob.Auth.SecretIDSource)
		if err != nil {
			return crypto.OpenBaoTransitOptions{}, err
		}
		auth.SecretID = sid
	} else {
		auth.SecretID = ob.Auth.SecretID
	}

	return crypto.OpenBaoTransitOptions{
		Address:     ob.Address,
		TransitPath: ob.TransitPath,
		KeyName:     ob.KeyName,
		Namespace:   ob.Namespace,
		Provider:    provider,
		Timeout:     ob.Timeout,
		TLSConfig:   tlsCfg,
		Auth:        auth,
	}, nil
}

// buildOpenBaoTLSConfig builds a *tls.Config for the OpenBao client (TLS 1.2
// floor, restricted suites). For plain-HTTP (dev) addresses the returned config
// is simply unused by the transport.
//
// TLS verification semantics are honest about what Go actually does:
//
//   - ca_cert set, insecure_skip_verify=false → standard verification against
//     the pinned CA (chain + hostname). The normal production setup.
//   - ca_cert set, insecure_skip_verify=true  → REAL pinning that skips only the
//     hostname check: Go's default verification is disabled (so RootCAs alone
//     would pin nothing — the bug this avoids), and a VerifyConnection callback
//     verifies the peer chains to the pinned CA. Use for IP/SAN-mismatch cases.
//   - no ca_cert, insecure_skip_verify=true   → genuinely no verification
//     (dev only); logged loudly.
//   - no ca_cert, insecure_skip_verify=false  → system root CAs.
func buildOpenBaoTLSConfig(cfg config.OpenBaoTLSConfig) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	var pinnedPool *x509.CertPool
	if cfg.CACert != "" {
		caData, err := os.ReadFile(cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("failed to read OpenBao CA certificate: %w", err)
		}
		pinnedPool = x509.NewCertPool()
		if !pinnedPool.AppendCertsFromPEM(caData) {
			return nil, fmt.Errorf("failed to parse OpenBao CA certificate")
		}
		tlsCfg.RootCAs = pinnedPool
	}

	switch {
	case cfg.InsecureSkipVerify && pinnedPool != nil:
		// Skip Go's default verification (which includes the hostname check) but
		// still verify the chain to the pinned CA via VerifyConnection — RootCAs
		// alone would pin nothing once InsecureSkipVerify is true.
		// #nosec G402 — verification is performed manually below.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
		tlsCfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("openbao: server presented no certificates")
			}
			opts := x509.VerifyOptions{Roots: pinnedPool, Intermediates: x509.NewCertPool()}
			for _, intermediate := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(intermediate)
			}
			if _, err := cs.PeerCertificates[0].Verify(opts); err != nil {
				return fmt.Errorf("openbao: server certificate not trusted by pinned ca_cert: %w", err)
			}
			return nil
		}
		logrus.WithFields(logrus.Fields{
			"component": "crypto_factory",
			"setting":   "OPENBAO_SKIP_VERIFY",
		}).Warn("OpenBao TLS: hostname verification disabled; peer is verified against the pinned ca_cert only.")

	case cfg.InsecureSkipVerify:
		// No CA pinned and verification disabled: genuinely insecure, dev only.
		// #nosec G402 — operator opt-in with a loud startup warning.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec
		logrus.WithFields(logrus.Fields{
			"component": "crypto_factory",
			"setting":   "OPENBAO_SKIP_VERIFY",
		}).Error("OpenBao TLS certificate verification is DISABLED and no ca_cert is pinned — this allows MITM attacks. Use only in development.")
	}

	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load OpenBao client certificate: %w", err)
		}
		tlsCfg.Certificates = append(tlsCfg.Certificates, cert)
	}

	return tlsCfg, nil
}

// resolveOpenBaoSecret resolves an "env:VAR" or "file:PATH" reference (or a
// literal value) into the secret string.
func resolveOpenBaoSecret(ref string) (string, error) {
	switch {
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		v := os.Getenv(name)
		if v == "" {
			return "", fmt.Errorf("openbao: environment variable %q is empty or unset", name)
		}
		return v, nil
	case strings.HasPrefix(ref, "file:"):
		path := strings.TrimPrefix(ref, "file:")
		data, err := os.ReadFile(path) //nolint:gosec // operator-configured path
		if err != nil {
			return "", fmt.Errorf("openbao: read secret file %q: %w", path, err)
		}
		return strings.TrimSpace(string(data)), nil
	default:
		return strings.TrimSpace(ref), nil
	}
}
