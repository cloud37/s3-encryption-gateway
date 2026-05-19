package crypto

// Option is a functional option for configuring an engine at construction time.
// This pattern replaces the out-of-band SetKeyManager mutators
// for new callers (see [NewEngineWithOpts]).
type Option func(*engine)

// WithKeyManager sets the KeyManager that will be used for envelope encryption.
// The provided KeyManager must not be nil. If nil is passed, the option is a no-op.
//
// Using this option is the preferred alternative to the deprecated [SetKeyManager].
func WithKeyManager(km KeyManager) Option {
	return func(e *engine) {
		if km != nil {
			e.kmsManager = km
		}
	}
}

// WithPBKDF2Iterations sets the PBKDF2 iteration count for the engine.
func WithPBKDF2Iterations(n int) Option {
	return func(e *engine) {
		if n >= MinPBKDF2Iterations {
			e.pbkdf2Iterations = n
		}
	}
}

// WithKDFAlgorithm sets the KDF algorithm for new object encryption.
// Valid values: "pbkdf2-sha256" (default) or "argon2id" (non-FIPS only).
// An empty string is a no-op.
func WithKDFAlgorithm(alg string) Option {
	return func(e *engine) {
		if alg != "" {
			e.kdfAlgorithm = KDFAlgorithm(alg)
		}
	}
}

// WithArgon2idParams sets the argon2id key derivation parameters.
// These are only used when the KDF algorithm is set to "argon2id".
// If time, memory, and threads are all zero, the option is a no-op
// (keeps engine defaults: t=2, m=19456, p=1).
func WithArgon2idParams(time, memory uint32, threads uint8) Option {
	return func(e *engine) {
		if time > 0 && memory > 0 && threads > 0 {
			e.argon2idParams = Argon2idConfig{
				Time:    time,
				Memory:  memory,
				Threads: threads,
			}
		}
	}
}

// WithPreferredAlgorithm sets the preferred encryption algorithm for new objects.
func WithPreferredAlgorithm(alg string) Option {
	return func(e *engine) {
		if alg != "" {
			e.preferredAlgorithm = alg
		}
	}
}

// WithSupportedAlgorithms sets the list of supported encryption algorithms.
func WithSupportedAlgorithms(algs []string) Option {
	return func(e *engine) {
		if len(algs) > 0 {
			e.supportedAlgorithms = algs
		}
	}
}

// WithChunking enables or disables chunked/streaming encryption mode.
func WithChunking(enabled bool) Option {
	return func(e *engine) {
		e.chunkedMode = enabled
	}
}

// WithChunkSize sets the size of each encryption chunk.
func WithChunkSize(size int) Option {
	return func(e *engine) {
		if size > 0 {
			e.chunkSize = size
		}
	}
}

// WithProvider sets the provider profile used for metadata compaction.
func WithProvider(provider string) Option {
	return func(e *engine) {
		if provider != "" {
			e.providerProfile = GetProviderProfile(provider)
			e.compactor = NewMetadataCompactor(e.providerProfile)
		}
	}
}

// NewEngineWithOpts creates a new encryption engine with full options and zero or
// more functional Option values. This is the preferred constructor for new callers.
//
// Example:
//
//	eng, err := crypto.NewEngineWithOpts(password, nil,
//	    crypto.WithKeyManager(myKeyManager),
//	)
func NewEngineWithOpts(password []byte, compressionEngine CompressionEngine, opts ...Option) (EncryptionEngine, error) {
	eng, err := NewEngineWithChunkingAndProvider(password, compressionEngine, "", nil, false, DefaultChunkSize, "default", DefaultPBKDF2Iterations)
	if err != nil {
		return nil, err
	}
	e := eng.(*engine)
	for _, o := range opts {
		o(e)
	}
	return e, nil
}
