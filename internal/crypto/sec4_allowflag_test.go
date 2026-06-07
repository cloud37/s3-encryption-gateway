package crypto

import (
	"bytes"
	"context"
	"crypto/cipher"
	"io"
	"testing"
)

// TestDecrypt_UnmarkedNoAAD_FlagOff_FailsClosed verifies that when
// allowUnmarkedNoAAD is false (the default), a legacy no-AAD object
// WITHOUT the MetaLegacyNoAAD marker fails to decrypt — preserving the
// SEC-4 invariant.
func TestDecrypt_UnmarkedNoAAD_FlagOff_FailsClosed(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-sec4-closed-1234567"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	// Default: allowUnmarkedNoAAD is false.

	testNoAADWithoutFlagFails(t, eng)
}

// TestDecrypt_UnmarkedNoAAD_FlagOn_Recovers verifies that when
// allowUnmarkedNoAAD is true, a legacy no-AAD object WITHOUT the
// MetaLegacyNoAAD marker can be decrypted.
func TestDecrypt_UnmarkedNoAAD_FlagOn_Recovers(t *testing.T) {
	eng, err := NewEngineWithOpts(
		[]byte("test-password-sec4-recover-1234567"),
		WithAllowUnmarkedNoAADFallback(true),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	testNoAADWithoutFlagSucceeds(t, eng)
}

// TestEncryptionConfig_AllowUnmarkedNoAAD_DefaultsFalse verifies the default
// value of allowUnmarkedNoAAD on a fresh engine.
func TestEncryptionConfig_AllowUnmarkedNoAAD_DefaultsFalse(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-default-test"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)
	if e.allowUnmarkedNoAAD {
		t.Error("expected allowUnmarkedNoAAD to default to false")
	}
}

// testNoAADWithoutFlagFails creates a no-AAD ciphertext without the legacy
// marker and asserts that decryption fails.
func testNoAADWithoutFlagFails(t *testing.T, eng EncryptionEngine) {
	t.Helper()
	data := []byte("legacy payload without flag for closed test")

	// Encrypt normally (with AAD).
	encryptedReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(data), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	// Decrypt to recover plaintext and extract crypto params.
	decReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	plaintext, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	e := eng.(*engine)
	salt, err := decodeBase64(encMeta[MetaKeySalt])
	if err != nil {
		t.Fatalf("decodeBase64(salt) error: %v", err)
	}
	iv, err := decodeBase64(encMeta[MetaIV])
	if err != nil {
		t.Fatalf("decodeBase64(iv) error: %v", err)
	}
	algorithm := encMeta[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	key, err := e.deriveKey(salt)
	if err != nil {
		t.Fatalf("deriveKey() error: %v", err)
	}
	defer zeroBytes(key)

	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		t.Fatalf("createAEADCipher() error: %v", err)
	}
	gcm := aeadCipher.(cipher.AEAD)

	// Re-encrypt without AAD.
	noAADCiphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Ensure the legacy flag is NOT set.
	delete(encMeta, MetaLegacyNoAAD)

	_, _, err = eng.Decrypt(context.Background(), bytes.NewReader(noAADCiphertext), encMeta)
	if err == nil {
		t.Fatalf("Decrypt() expected error for unmarked no-AAD object with flag off, got nil")
	}
}

// testNoAADWithoutFlagSucceeds creates a no-AAD ciphertext without the legacy
// marker and asserts that decryption succeeds when allowUnmarkedNoAAD is true.
func testNoAADWithoutFlagSucceeds(t *testing.T, eng EncryptionEngine) {
	t.Helper()
	data := []byte("legacy payload without flag for recovery test")

	encryptedReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(data), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	decReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	plaintext, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	e := eng.(*engine)
	salt, err := decodeBase64(encMeta[MetaKeySalt])
	if err != nil {
		t.Fatalf("decodeBase64(salt) error: %v", err)
	}
	iv, err := decodeBase64(encMeta[MetaIV])
	if err != nil {
		t.Fatalf("decodeBase64(iv) error: %v", err)
	}
	algorithm := encMeta[MetaAlgorithm]
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}

	key, err := e.deriveKey(salt)
	if err != nil {
		t.Fatalf("deriveKey() error: %v", err)
	}
	defer zeroBytes(key)

	aeadCipher, err := createAEADCipher(algorithm, key)
	if err != nil {
		t.Fatalf("createAEADCipher() error: %v", err)
	}
	gcm := aeadCipher.(cipher.AEAD)

	noAADCiphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Ensure the legacy flag is NOT set.
	delete(encMeta, MetaLegacyNoAAD)

	decReader, _, err = eng.Decrypt(context.Background(), bytes.NewReader(noAADCiphertext), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() expected success for unmarked no-AAD object with flag on, got: %v", err)
	}
	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt() plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}
