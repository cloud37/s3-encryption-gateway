//go:build !fips

package crypto

import (
	"fmt"
)

// WithPasswordKMPBKDF2 sets PBKDF2-SHA256 as the KDF with the given
// iteration count. This is the default; call it explicitly only to
// override a previously-set Argon2id option.
// The iteration count is clamped to [MinPBKDF2Iterations, MaxPBKDF2Iterations].
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

// WithPasswordKMArgon2id sets Argon2id as the KDF with the given
// parameters (time, memory KiB, threads).
// Returns an option that records an error when parameters are invalid;
// the error is surfaced by NewPasswordKeyManager at construction time.
func WithPasswordKMArgon2id(time, memory uint32, threads uint8) PasswordKMOption {
	return func(m *passwordKeyManager) {
		if time < 1 {
			m.fipsErr = fmt.Errorf("password_keymanager: argon2id time must be >= 1, got %d", time)
			return
		}
		if memory == 0 {
			m.fipsErr = fmt.Errorf("password_keymanager: argon2id memory must be > 0")
			return
		}
		if threads < 1 {
			m.fipsErr = fmt.Errorf("password_keymanager: argon2id threads must be >= 1, got %d", threads)
			return
		}
		m.kdfAlgorithm = KDFAlgArgon2id
		m.argon2idTime = time
		m.argon2idMemory = memory
		m.argon2idThreads = threads
	}
}
