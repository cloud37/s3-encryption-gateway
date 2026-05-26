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

// v2 envelope format constants.
//
// Version 2 format (all new wraps, regardless of algorithm):
//
//	[4-byte version marker: 0x00 0x00 0x00 0x01]
//	    [1-byte algorithm: 0x00=PBKDF2, 0x01=Argon2id]
//	        [algorithm-specific params]
//	            [salt (32 bytes)]
//	                [nonce (12 bytes)]
//	                    [sealed DEK + tag (variable)]
//
// The 4-byte version marker provides a robust discriminant against both
// v1 PBKDF2 format (iterations >= 100k) and old format (random salt).
const envelopeVersionMarker = 1

const (
	envelopeAlgPBKDF2   byte = 0x00
	envelopeAlgArgon2id byte = 0x01
)

// PasswordKMOption is a functional option for configuring a passwordKeyManager.
type PasswordKMOption func(*passwordKeyManager)

// passwordKeyManager implements KeyManager using PBKDF2-SHA256 or
// Argon2id + AES-256-GCM to wrap and unwrap Data Encryption Keys.
// It requires no external infrastructure and uses the same primitives
// as the existing single-PUT chunked encryption path.
//
// Wrapped-key format (v2, stored in KeyEnvelope.Ciphertext):
//
//	[4-byte version marker 1][1-byte alg][params][salt 32][nonce 12][sealed]
//
// Older formats (v1 PBKDF2 and legacy no-prefix) are still decrypted
// transparently for backward compatibility.
//
// Without the gateway password the DEK cannot be recovered, so Valkey and
// backend companion objects are opaque to any party that doesn't hold the
// password. This is equivalent security to the existing object encryption.
type passwordKeyManager struct {
	password         []byte
	pbkdf2Iterations int
	kdfAlgorithm     KDFAlgorithm
	argon2idTime     uint32
	argon2idMemory   uint32
	argon2idThreads  uint8
	fipsErr          error
	closed           bool
}

func (m *passwordKeyManager) kdfAlgByte() byte {
	switch m.kdfAlgorithm {
	case KDFAlgArgon2id:
		return envelopeAlgArgon2id
	default:
		return envelopeAlgPBKDF2
	}
}

func (m *passwordKeyManager) kdfParamsBytes() []byte {
	switch m.kdfAlgorithm {
	case KDFAlgArgon2id:
		buf := make([]byte, 9)
		binary.BigEndian.PutUint32(buf[0:4], m.argon2idTime)
		binary.BigEndian.PutUint32(buf[4:8], m.argon2idMemory)
		buf[8] = m.argon2idThreads
		return buf
	default:
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(m.pbkdf2Iterations)) // #nosec G115
		return buf
	}
}

func (m *passwordKeyManager) deriveWrappingKey(salt []byte) ([]byte, error) {
	switch m.kdfAlgorithm {
	case KDFAlgArgon2id:
		return deriveKeyArgon2id(m.password, salt, KDFParams{
			Algorithm: KDFAlgArgon2id,
			Time:      m.argon2idTime,
			Memory:    m.argon2idMemory,
			Threads:   m.argon2idThreads,
		})
	default:
		key, err := pbkdf2.Key(sha256.New, string(m.password), salt, m.pbkdf2Iterations, aesKeySize)
		if err != nil {
			return nil, fmt.Errorf("password_keymanager: derive wrapping key: %w", err)
		}
		return key, nil
	}
}

func (m *passwordKeyManager) deriveUnwrapKey(salt []byte, alg KDFAlgorithm, pbkdf2Iter int, argon2idTime, argon2idMem uint32, argon2idThr uint8) ([]byte, error) {
	switch alg {
	case KDFAlgArgon2id:
		return deriveKeyArgon2id(m.password, salt, KDFParams{
			Algorithm: KDFAlgArgon2id,
			Time:      argon2idTime,
			Memory:    argon2idMem,
			Threads:   argon2idThr,
		})
	default:
		key, err := pbkdf2.Key(sha256.New, string(m.password), salt, pbkdf2Iter, aesKeySize)
		if err != nil {
			return nil, fmt.Errorf("password_keymanager: derive unwrap key: %w", err)
		}
		return key, nil
	}
}

// NewPasswordKeyManager creates a KeyManager that wraps DEKs using
// PBKDF2-SHA256 + AES-256-GCM by default. Use WithPasswordKMArgon2id()
// to select Argon2id as the KDF.
//
// The password must be the gateway's configured encryption password — the same
// value used for all other object encryption in the deployment.
func NewPasswordKeyManager(password []byte, opts ...PasswordKMOption) (KeyManager, error) {
	if len(password) < 12 {
		return nil, fmt.Errorf("password_keymanager: password must be at least 12 characters")
	}

	pw := make([]byte, len(password))
	copy(pw, password)

	m := &passwordKeyManager{
		password:         pw,
		pbkdf2Iterations: DefaultPBKDF2Iterations,
		kdfAlgorithm:     KDFAlgPBKDF2SHA256,
		argon2idTime:     2,
		argon2idMemory:   19456,
		argon2idThreads:  1,
	}

	for _, opt := range opts {
		opt(m)
	}

	if m.fipsErr != nil {
		zeroBytes(pw)
		m.password = nil
		return nil, m.fipsErr
	}

	return m, nil
}

func (m *passwordKeyManager) Provider() string { return passwordKMProvider }

// WrapKey encrypts plaintext with a password-derived wrapping key.
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

	// Derive wrapping key using the configured KDF.
	wk, err := m.deriveWrappingKey(salt)
	if err != nil {
		return nil, err
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

	// v2 format: [4-byte BE marker(1)][1-byte alg][params][salt][nonce][sealed]
	params := m.kdfParamsBytes()
	payload := make([]byte, 0, 4+1+len(params)+len(salt)+len(nonce)+len(sealed))
	marker := make([]byte, 4)
	binary.BigEndian.PutUint32(marker, envelopeVersionMarker)
	payload = append(payload, marker...)
	payload = append(payload, m.kdfAlgByte())
	payload = append(payload, params...)
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
//
// Three formats are detected transparently:
//  1. v2 format (marker=1): [4B marker][1B alg][params][salt][nonce][sealed]
//  2. v1 PBKDF2 format:     [4B BE iterations][salt][nonce][sealed]
//  3. Legacy format:        [salt][nonce][sealed] (100k PBKDF2)
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

	// Minimum: salt(32) + nonce(12) + tag(16) = 60 bytes (legacy format).
	const minPayload = saltSize + nonceSize + tagSize
	if len(payload) < minPayload {
		return nil, fmt.Errorf("%w: payload too short (%d bytes)", ErrInvalidEnvelope, len(payload))
	}

	var v2Err error
	var v1Err error

	// --- v2 format detection (marker == 1) ---
	const minV2Payload = saltSize + nonceSize + tagSize + 5 // marker(4) + alg(1)
	if len(payload) >= minV2Payload {
		marker := binary.BigEndian.Uint32(payload[:4])
		if marker == envelopeVersionMarker {
			plaintext, err := m.tryUnwrapV2(payload)
			if err == nil {
				return plaintext, nil
			}
			v2Err = err
		}
	}

	// --- v1 PBKDF2 format detection (legacy new format) ---
	// New format: [4-byte BE iterations][salt(32)][nonce(12)][sealed(...)]
	// Old format: [salt(32)][nonce(12)][sealed(...)]
	//
	// We use the 4-byte prefix as a discriminant, but restrict the value
	// to [MinPBKDF2Iterations, MaxPBKDF2Iterations] so random salt bytes
	// from old-format envelopes don't trigger billion-iteration PBKDF2 calls.
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
			v1Err = err
		}
	}

	// --- Legacy format (no prefix; always LegacyPBKDF2Iterations) ---
	salt := payload[:saltSize]
	nonce := payload[saltSize : saltSize+nonceSize]
	sealed := payload[saltSize+nonceSize:]

	plaintext, err := m.tryUnwrap(salt, nonce, sealed, LegacyPBKDF2Iterations)
	if err == nil {
		return plaintext, nil
	}

	// Report the most specific error we have.
	if v2Err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrapFailed, v2Err)
	}
	if v1Err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnwrapFailed, v1Err)
	}
	return nil, fmt.Errorf("%w: %v", ErrUnwrapFailed, err)
}

// tryUnwrapV2 parses a v2-format payload and attempts AES-GCM Open.
func (m *passwordKeyManager) tryUnwrapV2(payload []byte) ([]byte, error) {
	algByte := payload[4]
	var alg KDFAlgorithm
	var pbkdf2Iter int
	var arTime, arMem uint32
	var arThr uint8
	var paramsEnd int

	switch algByte {
	case envelopeAlgPBKDF2:
		alg = KDFAlgPBKDF2SHA256
		if len(payload) < 5+4+saltSize+nonceSize+tagSize {
			return nil, fmt.Errorf("password_keymanager: v2 PBKDF2 payload too short")
		}
		pbkdf2Iter = int(binary.BigEndian.Uint32(payload[5:9]))
		paramsEnd = 9

	case envelopeAlgArgon2id:
		alg = KDFAlgArgon2id
		if len(payload) < 5+9+saltSize+nonceSize+tagSize {
			return nil, fmt.Errorf("password_keymanager: v2 Argon2id payload too short")
		}
		arTime = binary.BigEndian.Uint32(payload[5:9])
		arMem = binary.BigEndian.Uint32(payload[9:13])
		arThr = payload[13]
		paramsEnd = 14

	default:
		return nil, fmt.Errorf("password_keymanager: unknown v2 algorithm byte 0x%02x", algByte)
	}

	salt := payload[paramsEnd : paramsEnd+saltSize]
	nonce := payload[paramsEnd+saltSize : paramsEnd+saltSize+nonceSize]
	sealed := payload[paramsEnd+saltSize+nonceSize:]

	wk, err := m.deriveUnwrapKey(salt, alg, pbkdf2Iter, arTime, arMem, arThr)
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

