package crypto

import (
	"bytes"
	"context"
	"crypto/cipher"
	"io"
	"testing"
)

// TestBuildAAD_InjectionResistance verifies that two distinct metadata
// combinations that would produce identical AAD in the legacy pipe-delimited
// format produce different AAD in the new length-prefixed format (V1.0-SEC-H01).
func TestBuildAAD_InjectionResistance(t *testing.T) {
	salt := []byte("testsalt12345678")
	nonce := []byte("testnonce1234")

	// These two metadata maps would collide in the old format:
	// Old: alg:aes-256-gcm|salt:dGVzdHNhbHQxMjM0NTY3OA==|iv:dGVzdG5vbmNlMTIzNA==|ct:text/plain|osz:999
	// vs  alg:aes-256-gcm|salt:dGVzdHNhbHQxMjM0NTY3OA==|iv:dGVzdG5vbmNlMTIzNA==|ct:text/plain|osz:999
	// Wait, that's the same. Let me construct a real collision:
	// Map A: Content-Type="text/plain",  OriginalSize=""
	// Map B: Content-Type="",             OriginalSize=""
	// No, the old format skips empty fields.
	//
	// Real collision:
	// Map A: Content-Type="text/plain",  OriginalSize=""
	// Map B: Content-Type="",             OriginalSize="text/plain"
	// Old format for A: ...|ct:text_plain
	// Old format for B: ...|osz:text_plain
	// These are different. Need a better example.
	//
	// The actual vulnerability: Content-Type="text/plain|osz:999" with OriginalSize=""
	// vs Content-Type="text/plain" with OriginalSize="999"
	// Old A: alg:aes-256-gcm|salt:...|iv:...|ct:text/plain|osz:999
	// Old B: alg:aes-256-gcm|salt:...|iv:...|ct:text/plain|osz:999
	// These are IDENTICAL!

	metaA := map[string]string{
		"Content-Type":   "text/plain|osz:999",
		MetaOriginalSize: "",
	}
	metaB := map[string]string{
		"Content-Type":   "text/plain",
		MetaOriginalSize: "999",
	}

	aadNewA := buildAAD(AlgorithmAES256GCM, salt, nonce, metaA)
	aadNewB := buildAAD(AlgorithmAES256GCM, salt, nonce, metaB)

	if bytes.Equal(aadNewA, aadNewB) {
		t.Errorf("buildAAD produced identical AAD for different metadata combinations")
	}

	// Also verify the legacy format WOULD collide
	aadLegacyA := buildAADLegacy(AlgorithmAES256GCM, salt, nonce, metaA)
	aadLegacyB := buildAADLegacy(AlgorithmAES256GCM, salt, nonce, metaB)

	if !bytes.Equal(aadLegacyA, aadLegacyB) {
		t.Errorf("buildAADLegacy should have collided for this test case, but didn't")
	}
}

// TestBuildAAD_CanonicalOrder verifies that metadata key ordering does not
// affect the AAD output (fields are always in fixed canonical order).
func TestBuildAAD_CanonicalOrder(t *testing.T) {
	salt := []byte("salt123456789012")
	nonce := []byte("nonce123456789")

	meta := map[string]string{
		MetaOriginalSize: "1024",
		"Content-Type":   "application/json",
		MetaKeyVersion:   "v1",
	}

	aad1 := buildAAD(AlgorithmAES256GCM, salt, nonce, meta)

	// Rebuild with the same values; should be identical
	aad2 := buildAAD(AlgorithmAES256GCM, salt, nonce, meta)

	if !bytes.Equal(aad1, aad2) {
		t.Errorf("buildAAD is not deterministic for identical inputs")
	}
}

// TestDecrypt_BackwardCompatibility_LegacyAAD verifies that objects encrypted
// with the legacy pipe-delimited AAD format can still be decrypted after the
// V1.0-SEC-H01 fix.
func TestDecrypt_BackwardCompatibility_LegacyAAD(t *testing.T) {
	eng, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("NewEngine() error: %v", err)
	}

	data := []byte("backward compatibility payload")
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

	// Decrypt through the normal path (should use new AAD format)
	decReader, _, err := eng.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(encryptedData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Errorf("Decrypt() plaintext mismatch: got %q, want %q", decrypted, data)
	}

	// Now simulate an "old object" encrypted with legacy AAD format:
	// Extract key material and re-encrypt with legacy AAD.
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

	// Build legacy AAD and re-encrypt plaintext with it
	legacyAADMeta := map[string]string{
		"Content-Type":   encMeta["Content-Type"],
		MetaOriginalSize: encMeta[MetaOriginalSize],
		MetaKeyVersion:   encMeta[MetaKeyVersion],
	}
	legacyAAD := buildAADLegacy(algorithm, salt, iv, legacyAADMeta)
	legacyCiphertext := gcm.Seal(nil, iv, data, legacyAAD)
	delete(encMeta, MetaObjectFormatVersion)
	delete(encMeta, MetaObjectBindingID)

	// Attempt decryption — engine should fall back to legacy AAD format
	decReader2, _, err := eng.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(legacyCiphertext), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() error for legacy-AAD object: %v", err)
	}
	decrypted2, err := io.ReadAll(decReader2)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if !bytes.Equal(decrypted2, data) {
		t.Errorf("Decrypt() plaintext mismatch for legacy-AAD object: got %q, want %q", decrypted2, data)
	}
}

// TestBuildAAD_DifferentMetaProducesDifferentAAD verifies that changing any
// AAD-bound metadata field produces a different AAD.
func TestBuildAAD_DifferentMetaProducesDifferentAAD(t *testing.T) {
	salt := []byte("salt123456789012")
	nonce := []byte("nonce123456789")
	baseMeta := map[string]string{
		MetaKeyVersion:   "v1",
		"Content-Type":   "text/plain",
		MetaOriginalSize: "1024",
	}

	baseAAD := buildAAD(AlgorithmAES256GCM, salt, nonce, baseMeta)

	tests := []struct {
		name string
		meta map[string]string
	}{
		{
			name: "different key version",
			meta: map[string]string{MetaKeyVersion: "v2", "Content-Type": "text/plain", MetaOriginalSize: "1024"},
		},
		{
			name: "different content type",
			meta: map[string]string{MetaKeyVersion: "v1", "Content-Type": "application/json", MetaOriginalSize: "1024"},
		},
		{
			name: "different original size",
			meta: map[string]string{MetaKeyVersion: "v1", "Content-Type": "text/plain", MetaOriginalSize: "2048"},
		},
		{
			name: "empty key version",
			meta: map[string]string{MetaKeyVersion: "", "Content-Type": "text/plain", MetaOriginalSize: "1024"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aad := buildAAD(AlgorithmAES256GCM, salt, nonce, tt.meta)
			if bytes.Equal(aad, baseAAD) {
				t.Errorf("buildAAD produced identical AAD for different metadata")
			}
		})
	}
}

// TestBuildAAD_EmptyFieldsIncluded verifies that empty fields are explicitly
// included (length=0) rather than skipped, preventing field-boundary shifts.
func TestBuildAAD_EmptyFieldsIncluded(t *testing.T) {
	salt := []byte("salt123456789012")
	nonce := []byte("nonce123456789")

	metaWithEmpty := map[string]string{
		MetaKeyVersion:   "",
		"Content-Type":   "text/plain",
		MetaOriginalSize: "1024",
	}
	metaWithValue := map[string]string{
		MetaKeyVersion:   "v1",
		"Content-Type":   "text/plain",
		MetaOriginalSize: "1024",
	}

	aadEmpty := buildAAD(AlgorithmAES256GCM, salt, nonce, metaWithEmpty)
	aadValue := buildAAD(AlgorithmAES256GCM, salt, nonce, metaWithValue)

	if bytes.Equal(aadEmpty, aadValue) {
		t.Errorf("buildAAD should differentiate empty vs non-empty key version")
	}
}
