// Package harness provides a unified gateway launcher for conformance tests.
// One Gateway is started per test via StartGateway; all configuration is
// supplied via functional Option values so tests compose only what they need.
package harness

import (
	"net/http"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
)

// options accumulates gateway configuration requested by Option functions.
type options struct {
	encryptionPassword  string
	policyManager       *config.PolicyManager
	keyManager          crypto.KeyManager
	mpuStore            mpu.StateStore
	auditLogger         audit.Logger
	encryptedMPU        bool
	valkeyAddr          string
	// encryptedMPUBucket is a glob pattern for which encrypted MPU is enabled.
	// When set the harness auto-creates a PolicyManager with
	// EncryptMultipartUploads=true for that pattern (unless policyManager is
	// already set by the caller).
	encryptedMPUBucket  string
	headObjectOverride  func(bucket, key string) *int64
	logLevel            string
	extraConfig         func(*config.Config)
	// pbkdf2Iterations overrides the default PBKDF2 iteration count (600k).
	// Values below the minimum (100k) are ignored and the default is used.
	pbkdf2Iterations    int
	// chunkedMode enables chunked/streaming encryption for the gateway engine.
	chunkedMode         bool
	// kdfAlgorithm overrides the KDF algorithm for new objects.
	// Empty string uses the default ("pbkdf2-sha256").
	kdfAlgorithm        string
	// argon2idParams overrides the argon2id KDF parameters.
	argon2idParams      config.Argon2idConfig
	// backendTransport, when non-nil, replaces the HTTP transport used by the
	// gateway's S3 backend client.  Use this in chaos / retry tests to inject
	// faults at the gateway→backend layer without an external proxy.
	// See WithBackendTransport and FaultyRoundTripper.
	backendTransport    http.RoundTripper
	// authCredentials holds credentials configured via WithAuth.
	authCredentials []config.GatewayCredential

	// adminEnabled, when true, starts an admin listener alongside the gateway.
	// The bearer token is adminToken (plain inline — test-only). The admin
	// listener binds to a random loopback port; its address is accessible via
	// Gateway.AdminURL.
	adminEnabled bool
	adminToken   string
	// adminProfiling enables /admin/debug/pprof/* when adminEnabled is also true.
	adminProfiling bool

	// metadataEncryptionKey is the 32-byte AES key for encrypting metadata
	// blobs (V1.0-CRYPTO-3). When set, the gateway engine will encrypt
	// encryption/compression metadata values in S3 object headers.
	metadataEncryptionKey []byte
}

// Option is a functional option for StartGateway.
type Option func(*options)

// WithEncryptionPassword sets the gateway's encryption password.
// Defaults to "test-encryption-password-123456" if not set.
func WithEncryptionPassword(pw string) Option {
	return func(o *options) { o.encryptionPassword = pw }
}

// WithPolicyManager wires a per-bucket policy manager into the gateway.
func WithPolicyManager(pm *config.PolicyManager) Option {
	return func(o *options) { o.policyManager = pm }
}

// WithKeyManager wires a KeyManager (for MPU DEK wrap/unwrap) into the gateway.
func WithKeyManager(km crypto.KeyManager) Option {
	return func(o *options) { o.keyManager = km }
}

// WithMPUStateStore wires a Valkey/miniredis state store into the gateway
// for encrypted multipart uploads.
func WithMPUStateStore(store mpu.StateStore) Option {
	return func(o *options) { o.mpuStore = store }
}

// WithAuditLogger wires an audit logger into the gateway.
func WithAuditLogger(al audit.Logger) Option {
	return func(o *options) { o.auditLogger = al }
}

// WithEncryptedMPU enables the encrypted-multipart-upload feature.
// Requires WithMPUStateStore or WithValkeyAddr to also be set so the
// gateway has a Valkey/miniredis state store.
func WithEncryptedMPU(enabled bool) Option {
	return func(o *options) { o.encryptedMPU = enabled }
}

// WithValkeyAddr sets the Valkey/Redis address (host:port) for the MPU state
// store. The harness constructs a ValkeyStateStore from this address.
// Mutually exclusive with WithMPUStateStore; the latter takes precedence.
func WithValkeyAddr(addr string) Option {
	return func(o *options) { o.valkeyAddr = addr }
}

// WithEncryptedMPUForBucket enables the encrypted multipart upload feature for
// the given bucket glob pattern. The harness creates a PolicyManager with
// EncryptMultipartUploads=true and a password-derived KeyManager (unless the
// caller already supplied WithKeyManager). Also requires WithValkeyAddr or
// WithMPUStateStore so the gateway has a state store.
func WithEncryptedMPUForBucket(bucketGlob string) Option {
	return func(o *options) { o.encryptedMPUBucket = bucketGlob }
}

// WithHeadObjectOverride wires a hook that overrides Content-Length returned
// by HeadObject for specific (bucket, key) pairs. Use this to simulate
// objects larger than 5 GiB without uploading real data.
// fn must return nil to leave Content-Length unmodified.
func WithHeadObjectOverride(fn func(bucket, key string) *int64) Option {
	return func(o *options) { o.headObjectOverride = fn }
}

// WithLogLevel sets the gateway logger level (default "error" in tests).
func WithLogLevel(level string) Option {
	return func(o *options) { o.logLevel = level }
}

// WithConfigMutator supplies a function that can make arbitrary mutations to
// the config.Config struct after all other options have been applied. Use
// sparingly; prefer typed options for discoverable configuration.
func WithConfigMutator(fn func(*config.Config)) Option {
	return func(o *options) { o.extraConfig = fn }
}

// WithBackendTransport replaces the HTTP transport used by the gateway's S3
// backend client.  When set, every backend request the gateway makes passes
// through rt before hitting the real (or fake) backend.
//
// Primary use: fault injection in retry / chaos conformance tests.  For
// example, wrap a real provider's transport with FaultyRoundTripper to inject
// transient errors at a controlled rate while still using a real MinIO backend
// for correctness assertions.
//
// Production code must never call this; it is for tests only.
func WithBackendTransport(rt http.RoundTripper) Option {
	return func(o *options) { o.backendTransport = rt }
}

// WithPBKDF2Iterations sets the PBKDF2 iteration count for the gateway's
// encryption engine and config.
func WithPBKDF2Iterations(n int) Option {
	return func(o *options) { o.pbkdf2Iterations = n }
}

// WithChunking enables or disables chunked/streaming encryption mode for the
// gateway's encryption engine.
func WithChunking(enabled bool) Option {
	return func(o *options) { o.chunkedMode = enabled }
}

// WithKDFAlgorithm sets the KDF algorithm for the gateway's encryption engine.
// Valid values: "pbkdf2-sha256" (default) or "argon2id" (non-FIPS only).
func WithKDFAlgorithm(alg string) Option {
	return func(o *options) { o.kdfAlgorithm = alg }
}

// WithArgon2idParams sets the argon2id KDF parameters for the gateway's
// encryption engine. These are only used when WithKDFAlgorithm is "argon2id".
func WithArgon2idParams(time, memory uint32, threads uint8) Option {
	return func(o *options) {
		o.argon2idParams = config.Argon2idConfig{
			Time:    time,
			Memory:  memory,
			Threads: threads,
		}
	}
}

// WithAuth enables gateway authentication with the given credentials.
// When at least one credential is provided, AuthMiddleware is wired into
// the gateway and every inbound S3 request must present a valid AWS
// Signature (V4 or V2) using one of the configured access keys.
func WithAuth(creds ...config.GatewayCredential) Option {
	return func(o *options) {
		o.authCredentials = append(o.authCredentials, creds...)
	}
}

// WithMetadataEncryptionKey sets the 32-byte AES key used for encrypting
// metadata blobs in S3 object headers (V1.0-CRYPTO-3). The caller should
// zero the slice after calling this; the harness makes its own copy.
func WithMetadataEncryptionKey(key []byte) Option {
	return func(o *options) {
		o.metadataEncryptionKey = make([]byte, len(key))
		copy(o.metadataEncryptionKey, key)
	}
}

// WithAdminServer starts an admin listener alongside the gateway. The listener
// binds to a random loopback port; its URL is exposed via Gateway.AdminURL.
// token is the bearer token used for authentication (inline — test-only).
// When profilingEnabled is true, the 11 pprof endpoints are also mounted.
func WithAdminServer(token string, profilingEnabled bool) Option {
	return func(o *options) {
		o.adminEnabled = true
		o.adminToken = token
		o.adminProfiling = profilingEnabled
	}
}
