package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

const (
	// AlgorithmAES256GCM is the default AES-256-GCM algorithm.
	AlgorithmAES256GCM = "AES256-GCM"
	// AlgorithmChaCha20Poly1305 is the ChaCha20-Poly1305 algorithm.
	AlgorithmChaCha20Poly1305 = "ChaCha20-Poly1305"

	// ChaCha20 key and nonce sizes
	chacha20KeySize   = 32 // 256 bits
	chacha20NonceSize = 12 // 96 bits for XChaCha20-Poly1305, but standard ChaCha20-Poly1305 uses 12 bytes
)

var (
	// ErrAlgorithmNotApproved is returned when an algorithm is not FIPS-approved in this build.
	ErrAlgorithmNotApproved = errors.New("crypto: algorithm not FIPS-approved in this build")
)

// AlgorithmEntry describes an encryption algorithm and its properties.
type AlgorithmEntry struct {
	// Name is the algorithm identifier.
	Name string
	// FIPSApproved indicates if the algorithm is FIPS 140-3 approved.
	FIPSApproved bool
}

// AlgorithmConfig holds configuration for encryption algorithms.
type AlgorithmConfig struct {
	// PreferredAlgorithm is the algorithm to use for new encryptions.
	PreferredAlgorithm string

	// SupportedAlgorithms is a list of algorithms that can be used for decryption.
	SupportedAlgorithms []string
}

// AEADCipher is an interface that wraps cipher.AEAD with algorithm name.
type AEADCipher interface {
	cipher.AEAD
	Algorithm() string
}

// aesGCMCipher wraps cipher.AEAD with algorithm name.
type aesGCMCipher struct {
	cipher.AEAD
}

func (c *aesGCMCipher) Algorithm() string {
	return AlgorithmAES256GCM
}

// chacha20Poly1305Cipher wraps cipher.AEAD with algorithm name.
type chacha20Poly1305Cipher struct {
	cipher.AEAD
}

func (c *chacha20Poly1305Cipher) Algorithm() string {
	return AlgorithmChaCha20Poly1305
}

// createAESGCMCipher creates an AES-GCM cipher.
func createAESGCMCipher(key []byte) (AEADCipher, error) {
	if len(key) != aesKeySize {
		return nil, fmt.Errorf("invalid key size for AES-256: expected %d bytes, got %d", aesKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return &aesGCMCipher{AEAD: gcm}, nil
}

// AEADOverheadForAlgorithm returns the ciphertext tag overhead for a
// supported algorithm without requiring a key. It is used only for legacy
// metadata-only size estimation; unsupported algorithms fail closed.
func AEADOverheadForAlgorithm(algorithm string) (int, error) {
	switch algorithm {
	case AlgorithmAES256GCM, AlgorithmChaCha20Poly1305:
		return tagSize, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// getNonceSize returns the nonce size for the given algorithm.
func getNonceSize(algorithm string) (int, error) {
	switch algorithm {
	case AlgorithmAES256GCM:
		return nonceSize, nil
	case AlgorithmChaCha20Poly1305:
		return chacha20NonceSize, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}

// isAlgorithmSupported checks if an algorithm is supported.
func isAlgorithmSupported(algorithm string, supported []string) bool {
	if len(supported) == 0 {
		// If no supported list, allow all known algorithms
		return algorithm == AlgorithmAES256GCM || algorithm == AlgorithmChaCha20Poly1305
	}

	for _, alg := range supported {
		if alg == algorithm {
			return true
		}
	}
	return false
}
