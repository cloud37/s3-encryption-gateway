package crypto

import (
	"bytes"
	"context"
	"crypto/cipher"
	"io"
	"testing"
)

// TestEncrypt_DoesNotSetLegacyNoAADFlag verifies that newly encrypted objects
// never carry the MetaLegacyNoAAD marker.
func TestEncrypt_DoesNotSetLegacyNoAADFlag(t *testing.T) {
	eng, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	data := []byte("hello world")
	_, encMeta, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(data), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	if encMeta[MetaLegacyNoAAD] != "" {
		t.Errorf("Encrypt() must not set %s, got %q", MetaLegacyNoAAD, encMeta[MetaLegacyNoAAD])
	}
}

// TestAADFallback_NewObjectTamperedFails confirms that when an attacker
// tampers with metadata (changing AAD-bound fields), decryption fails because
// the no-AAD blind fallback is disabled for objects without MetaLegacyNoAAD.
func TestAADFallback_NewObjectTamperedFails(t *testing.T) {
	eng, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	data := []byte("sensitive payload")
	encryptedReader, encMeta, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(data), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	// Tamper with the v2 binding identifier so the object AAD does not match.
	if encMeta[MetaObjectBindingID][0] == 'A' {
		encMeta[MetaObjectBindingID] = "B" + encMeta[MetaObjectBindingID][1:]
	} else {
		encMeta[MetaObjectBindingID] = "A" + encMeta[MetaObjectBindingID][1:]
	}

	_, _, err = eng.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(encryptedData), encMeta)
	if err == nil {
		t.Fatalf("Decrypt() expected error for tampered metadata without legacy flag, got nil")
	}
}

// TestAADFallback_LegacyObjectWithFlagSucceeds confirms that a legacy object
// (encrypted without AAD) can still be decrypted when MetaLegacyNoAAD is "true".
func TestAADFallback_LegacyObjectWithFlagSucceeds(t *testing.T) {
	eng, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	data := []byte("legacy payload")
	encryptedReader, encMeta, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(data), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	// Recover plaintext by decrypting the AAD-encrypted data so we can
	// re-encrypt it without AAD using the same key material.
	decReader, _, err := eng.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(encryptedData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	plaintext, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	// Extract parameters and re-encrypt without AAD.
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

	// Mark as legacy and attempt decryption.
	encMeta[MetaLegacyNoAAD] = "true"
	delete(encMeta, MetaObjectFormatVersion)
	delete(encMeta, MetaObjectBindingID)

	decReader, _, err = eng.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(noAADCiphertext), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() error for legacy object with flag: %v", err)
	}
	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypt() plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
}

// TestAADFallback_LegacyObjectWithoutFlagFails confirms that a legacy object
// encrypted without AAD fails to decrypt when MetaLegacyNoAAD is absent.
func TestAADFallback_LegacyObjectWithoutFlagFails(t *testing.T) {
	eng, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	data := []byte("legacy payload without flag")
	encryptedReader, encMeta, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(data), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}

	decReader, _, err := eng.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(encryptedData), encMeta)
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

	_, _, err = eng.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(noAADCiphertext), encMeta)
	if err == nil {
		t.Fatalf("Decrypt() expected error for legacy object without flag, got nil")
	}
}
