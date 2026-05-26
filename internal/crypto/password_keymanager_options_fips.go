//go:build fips

package crypto

// WithPasswordKMArgon2id is a no-op stub in FIPS builds.  It records
// ErrAlgorithmNotApproved so that NewPasswordKeyManager returns an error
// at construction time.
func WithPasswordKMArgon2id(time, memory uint32, threads uint8) PasswordKMOption {
	return func(m *passwordKeyManager) {
		m.fipsErr = ErrAlgorithmNotApproved
	}
}

// WithPasswordKMPBKDF2 sets PBKDF2-SHA256 as the KDF with the given
// iteration count. This is the only allowed option in FIPS builds.
func WithPasswordKMPBKDF2(iterations int) PasswordKMOption {
	return func(m *passwordKeyManager) {
		if iterations < MinPBKDF2Iterations {
			iterations = DefaultPBKDF2Iterations
		}
		if iterations > MaxPBKDF2Iterations {
			iterations = MaxPBKDF2Iterations
		}
		m.kdfAlgorithm = KDFAlgPBKDF2SHA256
		m.pbkdf2Iterations = iterations
		m.argon2idTime = 0
		m.argon2idMemory = 0
		m.argon2idThreads = 0
	}
}
