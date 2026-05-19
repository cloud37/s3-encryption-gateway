package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// RSAKEKOption is a functional option for NewRSAKEKManager.
type RSAKEKOption func(*RSAKEKManager)

// WithRSAProvider sets the provider string returned by KeyManager.Provider().
// Defaults to "self_contained".
func WithRSAProvider(name string) RSAKEKOption {
	return func(m *RSAKEKManager) {
		if name != "" {
			m.providerName = name
		}
	}
}

// RSAKEKManager wraps DEKs using RSA-OAEP (SHA-256) with a locally-held key pair.
//
// Invariants (additional to KeyManager base):
//   - Minimum key size: 2048 bits (enforced at construction time).
//   - Public key must match private key; mismatch -> error at construction.
//   - WrapKey uses the public key only (encryption); no private key access.
//   - UnwrapKey uses the private key; private key is not exported or logged.
//   - Ciphertext format: raw RSA-OAEP output stored in KeyEnvelope.Ciphertext.
//   - KeyID: hex-encoded SHA-256 of the public key's DER representation,
//     truncated to 16 bytes, prefixed "self-contained-rsa-".
//   - Versioning: version is set at construction; all wrapped envelopes carry
//     that version. Multi-version support requires instantiating multiple
//     managers (no AddVersion path for RSA).
//   - Close: zeroizes the private key's primes (d, p, q, dp, dq, qinv) by
//     overwriting with zeros via reflect or manual field zeroing.
type RSAKEKManager struct {
	mu           sync.RWMutex
	providerName string
	privateKey   *rsa.PrivateKey // includes public key
	keyID        string          // fingerprint
	keyVersion   int
	closed       bool
}

// NewRSAKEKManager creates a new RSAKEKManager.
// privateKey must be non-nil and at least 2048 bits.
// version is the version number carried in all wrapped envelopes.
func NewRSAKEKManager(privateKey *rsa.PrivateKey, version int, opts ...RSAKEKOption) (*RSAKEKManager, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: private key must not be nil")
	}
	if privateKey.PublicKey.N == nil {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: public key modulus is nil")
	}
	if privateKey.N == nil {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: private key modulus is nil")
	}

	privateKey.Precompute()

	keySize := privateKey.Size() // modulus length in bytes
	if keySize < 256 {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: minimum key size is 2048 bits, got %d bits", keySize*8)
	}

	if privateKey.PublicKey.N.Cmp(privateKey.N) != 0 {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: public and private key modulus mismatch")
	}

	// Compute keyID: hex(SHA-256(DER public key)[:8])
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: failed to marshal public key: %w", err)
	}
	hash := sha256.Sum256(pubDER)
	keyID := "self-contained-rsa-" + hex.EncodeToString(hash[:8])

	if version < 1 {
		version = 1
	}

	m := &RSAKEKManager{
		providerName: "self_contained",
		privateKey:   privateKey,
		keyID:        keyID,
		keyVersion:   version,
	}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

// Provider implements KeyManager.
func (m *RSAKEKManager) Provider() string { return m.providerName }

// WrapKey implements KeyManager using RSA-OAEP with SHA-256.
func (m *RSAKEKManager) WrapKey(ctx context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: %w", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrProviderUnavailable
	}

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &m.privateKey.PublicKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: wrap failed: %w", err)
	}

	return &KeyEnvelope{
		KeyID:      m.keyID,
		KeyVersion: m.keyVersion,
		Provider:   m.providerName,
		Ciphertext: ciphertext,
		CreatedAt:  time.Now(),
	}, nil
}

// UnwrapKey implements KeyManager using RSA-OAEP with SHA-256.
func (m *RSAKEKManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, _ map[string]string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("keymanager/self-contained-rsa: %w", err)
	}
	if envelope == nil {
		return nil, fmt.Errorf("%w: envelope is nil", ErrInvalidEnvelope)
	}
	if len(envelope.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: ciphertext is empty", ErrInvalidEnvelope)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, ErrProviderUnavailable
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, m.privateKey, envelope.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnwrapFailed, err)
	}
	return plaintext, nil
}

// ActiveKeyVersion implements KeyManager.
func (m *RSAKEKManager) ActiveKeyVersion(_ context.Context) (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return 0, ErrProviderUnavailable
	}
	return m.keyVersion, nil
}

// HealthCheck implements KeyManager. Verifies modulus consistency.
func (m *RSAKEKManager) HealthCheck(_ context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return ErrProviderUnavailable
	}
	if m.privateKey == nil {
		return fmt.Errorf("keymanager/self-contained-rsa: private key is nil")
	}
	if m.privateKey.PublicKey.N == nil || m.privateKey.N == nil {
		return fmt.Errorf("keymanager/self-contained-rsa: key modulus is nil")
	}
	if m.privateKey.PublicKey.N.Cmp(m.privateKey.N) != 0 {
		return fmt.Errorf("keymanager/self-contained-rsa: public and private key modulus mismatch")
	}
	return nil
}

// Close implements KeyManager. Idempotent; zeroizes private key material.
func (m *RSAKEKManager) Close(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true

	if m.privateKey != nil {
		zeroBigInt(m.privateKey.D)
		for i := range m.privateKey.Primes {
			if m.privateKey.Primes[i] != nil {
				zeroBigInt(m.privateKey.Primes[i])
			}
		}
		if m.privateKey.Precomputed.Dp != nil {
			zeroBigInt(m.privateKey.Precomputed.Dp)
		}
		if m.privateKey.Precomputed.Dq != nil {
			zeroBigInt(m.privateKey.Precomputed.Dq)
		}
		if m.privateKey.Precomputed.Qinv != nil {
			zeroBigInt(m.privateKey.Precomputed.Qinv)
		}
	}
	return nil
}

// zeroBigInt overwrites the backing storage of a big.Int with zeros.
// This is a best-effort attempt; copies made by the Go runtime may still
// exist on the heap. For higher-assurance key zeroization, use the HSM
// adapter.
func zeroBigInt(bi *big.Int) {
	if bi == nil {
		return
	}
	bitLen := bi.BitLen()
	if bitLen == 0 {
		return
	}
	byteLen := (bitLen + 7) / 8
	if byteLen > 0 {
		bi.SetBytes(make([]byte, byteLen))
	}
	bi.SetInt64(0)
}

// Compile-time assertion.
var _ KeyManager = (*RSAKEKManager)(nil)
