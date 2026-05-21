package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// passwordKMProvider is the Provider() string for password-derived key wrapping.
const passwordKMProvider = "password"

// passwordKeyManager implements KeyManager using PBKDF2 + AES-256-GCM to wrap
// and unwrap Data Encryption Keys. It requires no external infrastructure and
// uses the same primitives as the existing single-PUT chunked encryption path.
//
// Wrapped-key format (stored in KeyEnvelope.Ciphertext):
//
//	salt(32) || nonce(12) || sealed(dek + tag)(48)  — total 92 bytes
//
// Without the gateway password the DEK cannot be recovered, so Valkey and
// backend companion objects are opaque to any party that doesn't hold the
// password. This is equivalent security to the existing object encryption.
type passwordKeyManager struct {
	password         []byte
	pbkdf2Iterations int
	closed           bool
}

// NewPasswordKeyManager creates a KeyManager that wraps DEKs using
// PBKDF2-SHA256 + AES-256-GCM. This is the fallback
// for deployments that do not configure an external KMS; it provides the
// same confidentiality guarantee as the existing single-PUT encryption.
//
// The password must be the gateway's configured encryption password — the same
// value used for all other object encryption in the deployment.
func NewPasswordKeyManager(password []byte, pbkdf2Iterations int) (KeyManager, error) {
	if len(password) < 12 {
		return nil, fmt.Errorf("password_keymanager: password must be at least 12 characters")
	}
	if pbkdf2Iterations < MinPBKDF2Iterations {
		pbkdf2Iterations = DefaultPBKDF2Iterations
	}
	// Defensive copy so the caller can zero their slice after construction.
	pw := make([]byte, len(password))
	copy(pw, password)
	return &passwordKeyManager{password: pw, pbkdf2Iterations: pbkdf2Iterations}, nil
}

func (m *passwordKeyManager) Provider() string { return passwordKMProvider }

// WrapKey encrypts plaintext with a PBKDF2-derived wrapping key.
func (m *passwordKeyManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	if m.closed {
		return nil, ErrProviderUnavailable
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("password_keymanager: plaintext DEK must not be empty")
	}

	// Random salt — ensures a unique wrapping key per DEK even with the same password.
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("password_keymanager: generate salt: %w", err)
	}

	// Derive wrapping key using the configured PBKDF2 parameters.
	wk, err := pbkdf2.Key(sha256.New, string(m.password), salt, m.pbkdf2Iterations, aesKeySize)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: derive wrapping key: %w", err)
	}
	defer zeroBytes(wk)

	block, err := aes.NewCipher(wk)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("password_keymanager: create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("password_keymanager: generate nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// New format: [4-byte BE iterations][salt][nonce][sealed]
	payload := make([]byte, 0, 4+len(salt)+len(nonce)+len(sealed))
	iterBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(iterBuf, uint32(m.pbkdf2Iterations)) // #nosec G115 — PBKDF2 iterations fit in uint32 (max ~10^7)
	payload = append(payload, iterBuf...)
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	return &KeyEnvelope{
		Provider:   passwordKMProvider,
		KeyVersion: 1,
		Ciphertext: payload,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// UnwrapKey decrypts an envelope produced by WrapKey.
func (m *passwordKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	if m.closed {
		return nil, ErrProviderUnavailable
	}
	if envelope == nil || len(envelope.Ciphertext) == 0 {
		return nil, ErrInvalidEnvelope
	}
	if envelope.Provider != passwordKMProvider {
		return nil, fmt.Errorf("password_keymanager: envelope provider mismatch (got %q, want %q)", envelope.Provider, passwordKMProvider)
	}

	payload := envelope.Ciphertext
	// Minimum old format: salt(32) + nonce(12) + tag(16) = 60 bytes (with zero-length DEK).
	// Minimum new format: 4-byte iterations + old format = 64 bytes.
	const minPayload = saltSize + nonceSize + tagSize
	if len(payload) < minPayload {
		return nil, fmt.Errorf("%w: payload too short (%d bytes)", ErrInvalidEnvelope, len(payload))
	}

	// Determine format.
	//
	// New format: [4-byte BE iterations][salt(32)][nonce(12)][sealed(...)]
	// Old format: [salt(32)][nonce(12)][sealed(...)]
	//
	// Because both formats have the same overall length for a given DEK size,
	// we cannot distinguish by length alone.  We use the 4-byte prefix as a
	// discriminant, but we must NOT blindly run PBKDF2 with that value:
	// old-format envelopes have random salt bytes in those positions, which
	// can decode to a uint32 >= MinPBKDF2Iterations (~99.8 % of the time) or
	// even to billions, which would hang the process.
	//
	// Safe strategy:
	//   1. If the prefix is in the realistic range [MinPBKDF2Iterations,
	//      MaxPBKDF2Iterations], try new format first (fast if correct).
	//   2. Otherwise skip the new-format attempt and try old format.
	//   3. If the first attempt fails, try the other format.
	//   4. Only return an error when BOTH attempts have failed.
	var newFormatErr error
	if len(payload) >= minPayload+4 {
		candidateIter := int(binary.BigEndian.Uint32(payload[:4]))
		if candidateIter >= MinPBKDF2Iterations && candidateIter <= MaxPBKDF2Iterations {
			saltNew := payload[4 : 4+saltSize]
			nonceNew := payload[4+saltSize : 4+saltSize+nonceSize]
			sealedNew := payload[4+saltSize+nonceSize:]
			plaintext, err := m.tryUnwrap(saltNew, nonceNew, sealedNew, candidateIter)
			if err == nil {
				return plaintext, nil
			}
			newFormatErr = err // remember for final error message
		}
	}

	// Try old format (no iteration prefix; always LegacyPBKDF2Iterations).
	salt := payload[:saltSize]
	nonce := payload[saltSize : saltSize+nonceSize]
	sealed := payload[saltSize+nonceSize:]

	plaintext, err := m.tryUnwrap(salt, nonce, sealed, LegacyPBKDF2Iterations)
	if err == nil {
		return plaintext, nil
	}

	// Both formats failed.  Prefer the new-format error when we actually
	// attempted it (the envelope likely is new format but ciphertext was
	// tampered or the password is wrong).
	if newFormatErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrapFailed, newFormatErr)
	}
	return nil, fmt.Errorf("%w: %v", ErrUnwrapFailed, err)
}

// tryUnwrap derives a wrapping key and attempts AES-GCM Open.  It returns the
// plaintext on success or a non-nil error on any failure (derive, cipher
// creation, or authentication).  The caller is responsible for trying a
// different format/iteration count on failure.
func (m *passwordKeyManager) tryUnwrap(salt, nonce, sealed []byte, iterations int) ([]byte, error) {
	wk, err := pbkdf2.Key(sha256.New, string(m.password), salt, iterations, aesKeySize)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(wk)

	block, err := aes.NewCipher(wk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, nonce, sealed, nil)
}

func (m *passwordKeyManager) ActiveKeyVersion(_ context.Context) (int, error) {
	if m.closed {
		return 0, ErrProviderUnavailable
	}
	return 1, nil
}

func (m *passwordKeyManager) HealthCheck(_ context.Context) error {
	if m.closed {
		return ErrProviderUnavailable
	}
	return nil
}

func (m *passwordKeyManager) Close(_ context.Context) error {
	if !m.closed {
		m.closed = true
		// Zero the password in memory.
		zeroBytes(m.password)
		m.password = nil
	}
	return nil
}

// IsPasswordKeyManager reports whether km is a passwordKeyManager. Used in
// tests and startup validation.
func IsPasswordKeyManager(km KeyManager) bool {
	if km == nil {
		return false
	}
	_, ok := km.(*passwordKeyManager)
	return ok
}

