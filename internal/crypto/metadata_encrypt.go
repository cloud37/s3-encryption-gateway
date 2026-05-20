package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
)

// encryptMetadata encrypts the encryption/compression metadata subset into a
// single AES-256-GCM sealed blob. Only keys matching IsEncryptionMetadata or
// IsCompressionMetadata are included in the encrypted payload. The returned
// string is a base64-encoded blob containing nonce || ciphertext || tag.
//
// Callers must remove the individual encryption/compression keys from the
// metadata map after calling this function and store the returned blob under
// MetaEncryptedMetadata.
func (e *engine) encryptMetadata(encMeta map[string]string) (string, error) {
	if e.metadataKey == nil {
		return "", fmt.Errorf("metadata key not configured")
	}

	// Extract encryption and compression metadata subset.
	subset := make(map[string]string)
	for k, v := range encMeta {
		if IsEncryptionMetadata(k) || IsCompressionMetadata(k) {
			subset[k] = v
		}
	}

	// Serialize to JSON.
	plaintext, err := json.Marshal(subset)
	if err != nil {
		return "", fmt.Errorf("marshal metadata: %w", err)
	}

	// Create AES-256-GCM cipher.
	block, err := aes.NewCipher(e.metadataKey)
	if err != nil {
		return "", fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("gcm: %w", err)
	}

	// Generate random nonce.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}

	// Seal: nonce || ciphertext || tag.
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return encodeBase64(ciphertext), nil
}

// decryptMetadata decrypts an encrypted metadata blob produced by
// encryptMetadata. It expects a base64-encoded blob containing
// nonce || ciphertext || tag. The returned map contains the individual
// encryption/compression metadata keys.
func (e *engine) decryptMetadata(blob string) (map[string]string, error) {
	if e.metadataKey == nil {
		return nil, fmt.Errorf("metadata key not configured")
	}

	// Base64-decode the blob.
	ciphertext, err := decodeBase64(blob)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	// Create AES-256-GCM cipher.
	block, err := aes.NewCipher(e.metadataKey)
	if err != nil {
		return nil, fmt.Errorf("aes new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}

	// Split nonce and ciphertext.
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Open (decrypt and authenticate).
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}

	// Unmarshal JSON.
	var result map[string]string
	if err := json.Unmarshal(plaintext, &result); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return result, nil
}
