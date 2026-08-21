//go:build !fips

package crypto

// WithPasswordKMPBKDF2 sets PBKDF2-SHA256 as the KDF with the given
// iteration count. This is the default; call it explicitly only to
// override a previously-set Argon2id option.
// The iteration count is clamped to [MinPBKDF2Iterations, MaxPBKDF2Iterations].
func WithPasswordKMPBKDF2(iterations int) PasswordKMOption {
	return func(m *passwordKeyManager) {
		if iterations < MinPBKDF2Iterations || iterations > MaxPBKDF2Iterations {
			m.fipsErr = invalidKDF(KDFAlgPBKDF2SHA256, "iterations", uint64(max(iterations, 0)), "outside hard bounds")
			return
		}
		m.kdfAlgorithm = KDFAlgPBKDF2SHA256
		m.pbkdf2Iterations = iterations
		m.argon2idTime = 0
		m.argon2idMemory = 0
		m.argon2idThreads = 0
	}
}

func WithPasswordKMKDFLimits(limits KDFLimits) PasswordKMOption {
	return func(m *passwordKeyManager) { m.kdfLimits = limits }
}

// WithPasswordKMArgon2id sets Argon2id as the KDF with the given
// parameters (time, memory KiB, threads).
// Returns an option that records an error when parameters are invalid;
// the error is surfaced by NewPasswordKeyManager at construction time.
func WithPasswordKMArgon2id(time, memory uint32, threads uint8) PasswordKMOption {
	return func(m *passwordKeyManager) {
		if err := ValidateKDFParams(KDFParams{Algorithm: KDFAlgArgon2id, Time: time, Memory: memory, Threads: threads}, DefaultKDFLimits()); err != nil {
			m.fipsErr = err
			return
		}
		m.kdfAlgorithm = KDFAlgArgon2id
		m.argon2idTime = time
		m.argon2idMemory = memory
		m.argon2idThreads = threads
	}
}
