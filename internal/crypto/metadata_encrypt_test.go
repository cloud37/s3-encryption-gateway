package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestEncryptDecryptMetadata_RoundTrip(t *testing.T) {
	engine := newTestEngine(t)

	// Build a representative encMetadata map.
	encMeta := map[string]string{
		MetaEncrypted:     "true",
		MetaAlgorithm:     "AES256-GCM",
		MetaKeySalt:       "abc123+def456=",
		MetaIV:            "nonce12345678",
		MetaOriginalSize:  "4096",
		MetaOriginalETag:  `"abc123def456"`,
		MetaKDFParams:     "pbkdf2-sha256:600000",
		"Content-Type":    "application/octet-stream",
		"x-amz-meta-foo":  "user-visible-header", // should remain outside blob
	}

	blob, err := engine.encryptMetadata(encMeta)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}
	if blob == "" {
		t.Fatal("encryptMetadata returned empty blob")
	}

	// Decrypt the blob.
	decrypted, err := engine.decryptMetadata(blob)
	if err != nil {
		t.Fatalf("decryptMetadata failed: %v", err)
	}

	// Verify encryption/compression keys are present.
	if decrypted[MetaEncrypted] != "true" {
		t.Errorf("MetaEncrypted = %q, want %q", decrypted[MetaEncrypted], "true")
	}
	if decrypted[MetaAlgorithm] != "AES256-GCM" {
		t.Errorf("MetaAlgorithm = %q, want %q", decrypted[MetaAlgorithm], "AES256-GCM")
	}
	if decrypted[MetaKeySalt] != "abc123+def456=" {
		t.Errorf("MetaKeySalt = %q, want %q", decrypted[MetaKeySalt], "abc123+def456=")
	}
	if decrypted[MetaIV] != "nonce12345678" {
		t.Errorf("MetaIV = %q, want %q", decrypted[MetaIV], "nonce12345678")
	}
	if decrypted[MetaOriginalSize] != "4096" {
		t.Errorf("MetaOriginalSize = %q, want %q", decrypted[MetaOriginalSize], "4096")
	}
	if decrypted[MetaOriginalETag] != `"abc123def456"` {
		t.Errorf("MetaOriginalETag = %q, want %q", decrypted[MetaOriginalETag], `"abc123def456"`)
	}
	if decrypted[MetaKDFParams] != "pbkdf2-sha256:600000" {
		t.Errorf("MetaKDFParams = %q, want %q", decrypted[MetaKDFParams], "pbkdf2-sha256:600000")
	}

	// User-visible headers should NOT be in the encrypted subset.
	if _, ok := decrypted["x-amz-meta-foo"]; ok {
		t.Error("user-visible header found in encrypted metadata blob")
	}
	if _, ok := decrypted["Content-Type"]; ok {
		t.Error("Content-Type found in encrypted metadata blob (not encryption/compression metadata)")
	}
}

func TestEncryptDecryptMetadata_WrongKey(t *testing.T) {
	engine := newTestEngine(t)
	otherEngine := newTestEngineWithKey(t, "different-key-for-testing-purposes-only!")

	encMeta := map[string]string{
		MetaEncrypted:    "true",
		MetaAlgorithm:    "AES256-GCM",
		MetaKeySalt:      "somesaltvaluehere",
		MetaOriginalSize: "1024",
	}

	blob, err := engine.encryptMetadata(encMeta)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	// Decrypt with wrong key should fail.
	_, err = otherEngine.decryptMetadata(blob)
	if err == nil {
		t.Fatal("decryptMetadata with wrong key should have failed (GCM auth error)")
	}
}

func TestEncryptDecryptMetadata_TamperedCiphertext(t *testing.T) {
	engine := newTestEngine(t)

	encMeta := map[string]string{
		MetaEncrypted: "true",
		MetaAlgorithm: "AES256-GCM",
		MetaKeySalt:   "somesaltvaluehere",
	}

	blob, err := engine.encryptMetadata(encMeta)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	// Tamper with the base64 blob (flip a character).
	tampered := flipBase64Char(blob)

	_, err = engine.decryptMetadata(tampered)
	if err == nil {
		t.Fatal("decryptMetadata with tampered blob should have failed (GCM auth error)")
	}
}

func TestEncryptDecryptMetadata_EmptySubset(t *testing.T) {
	engine := newTestEngine(t)

	// Metadata with no encryption/compression keys should still produce a
	// valid blob containing an empty JSON object.
	encMeta := map[string]string{
		"x-amz-meta-user-key": "user-value",
	}

	blob, err := engine.encryptMetadata(encMeta)
	if err != nil {
		t.Fatalf("encryptMetadata failed: %v", err)
	}

	decrypted, err := engine.decryptMetadata(blob)
	if err != nil {
		t.Fatalf("decryptMetadata failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("expected empty decrypted map, got %v", decrypted)
	}
}

func TestEncryptMetadata_NilKey(t *testing.T) {
	engine := &engine{
		metadataKey: nil,
	}

	_, err := engine.encryptMetadata(map[string]string{MetaEncrypted: "true"})
	if err == nil {
		t.Fatal("encryptMetadata with nil key should fail")
	}
}

func TestDecryptMetadata_NilKey(t *testing.T) {
	engine := &engine{
		metadataKey: nil,
	}

	_, err := engine.decryptMetadata("dGVzdA==")
	if err == nil {
		t.Fatal("decryptMetadata with nil key should fail")
	}
}

func TestEncryptDecryptMetadata_MultipleRuns(t *testing.T) {
	engine := newTestEngine(t)

	// Each invocation should produce a unique ciphertext (random nonce).
	encMeta := map[string]string{
		MetaEncrypted: "true",
		MetaAlgorithm: "AES256-GCM",
		MetaKeySalt:   "somesaltvaluehere",
	}

	blob1, err := engine.encryptMetadata(encMeta)
	if err != nil {
		t.Fatalf("first encryptMetadata failed: %v", err)
	}
	blob2, err := engine.encryptMetadata(encMeta)
	if err != nil {
		t.Fatalf("second encryptMetadata failed: %v", err)
	}

	if blob1 == blob2 {
		t.Error("encryptMetadata should produce different outputs each time (random nonce)")
	}

	// Both should decrypt correctly.
	for i, blob := range []string{blob1, blob2} {
		dec, err := engine.decryptMetadata(blob)
		if err != nil {
			t.Fatalf("decryptMetadata blob[%d] failed: %v", i, err)
		}
		if dec[MetaEncrypted] != "true" {
			t.Errorf("blob[%d]: MetaEncrypted = %q", i, dec[MetaEncrypted])
		}
	}
}

// --- helpers ---

// newTestEngine creates an engine with a random 32-byte metadata key.
func newTestEngine(t *testing.T) *engine {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return &engine{
		metadataKey: key,
	}
}

// newTestEngineWithKey creates an engine with a metadata key derived from the
// given passphrase (SHA-256).
func newTestEngineWithKey(t *testing.T, passphrase string) *engine {
	t.Helper()
	h := sha256.Sum256([]byte(passphrase))
	return &engine{
		metadataKey: h[:],
	}
}

// flipBase64Char flips the last character of a base64 string to simulate
// tampering. This always corrupts the decoded bytes.
func flipBase64Char(s string) string {
	if len(s) == 0 {
		return s
	}
	b := []byte(s)
	// Toggle a bit in the last character.
	b[len(b)-1] ^= 0x01
	return string(b)
}
