package audit

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func TestInspect_ModernObject_ReportsAES256GCM(t *testing.T) {
	mock := newMockAuditClient()
	meta := map[string]string{
		crypto.MetaEncrypted:     "true",
		crypto.MetaAlgorithm:     crypto.AlgorithmAES256GCM,
		crypto.MetaKDFParams:     "pbkdf2-sha256:600000",
		crypto.MetaKeyVersion:    "1",
		crypto.MetaChunkedFormat: "true",
		crypto.MetaIVDerivation:  "hkdf-sha256",
		crypto.MetaKeySalt:       "a1b2c3d4e5f60718293a4b5c6d7e8f90",
		crypto.MetaIV:            "0102030405060708090a0b0c",
	}
	mock.addObject("b/k", []byte("ciphertext-data-here"), meta)

	report, err := Inspect(context.Background(), mock, "b", "k")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !report.Encrypted {
		t.Error("expected Encrypted=true")
	}
	if report.Algorithm != crypto.AlgorithmAES256GCM {
		t.Errorf("Algorithm = %q, want %q", report.Algorithm, crypto.AlgorithmAES256GCM)
	}
	if report.Class != "modern" {
		t.Errorf("Class = %q, want modern", report.Class)
	}
	if report.AADScheme != "v2-aad" {
		t.Errorf("AADScheme = %q, want v2-aad", report.AADScheme)
	}
	if report.KeyVersion != "1" {
		t.Errorf("KeyVersion = %q, want 1", report.KeyVersion)
	}
	if !report.Chunked {
		t.Error("expected Chunked=true")
	}
	if report.SaltHex == "" {
		t.Error("expected non-empty SaltHex")
	}
	if report.IVHex == "" {
		t.Error("expected non-empty IVHex")
	}
}

func TestInspect_NoAADObject_ReportsV1NoAAD(t *testing.T) {
	mock := newMockAuditClient()
	meta := map[string]string{
		crypto.MetaEncrypted:   "true",
		crypto.MetaAlgorithm:   crypto.AlgorithmAES256GCM,
		crypto.MetaLegacyNoAAD: "true",
	}
	mock.addObject("b/k", []byte("ciphertext"), meta)

	report, err := Inspect(context.Background(), mock, "b", "k")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if !report.Encrypted {
		t.Error("expected Encrypted=true")
	}
	if report.AADScheme != "v1-no-aad" {
		t.Errorf("AADScheme = %q, want v1-no-aad", report.AADScheme)
	}
	if report.Class != "class_b_no_aad" {
		t.Errorf("Class = %q, want class_b_no_aad", report.Class)
	}
}

func TestInspect_Plaintext_ReportsEncryptedFalse(t *testing.T) {
	mock := newMockAuditClient()
	mock.addObject("b/k", []byte("plaintext data"), map[string]string{
		"Content-Type": "text/plain",
	})

	report, err := Inspect(context.Background(), mock, "b", "k")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.Encrypted {
		t.Error("expected Encrypted=false for plaintext")
	}
	if report.Class != "plaintext" {
		t.Errorf("Class = %q, want plaintext", report.Class)
	}
}

func TestInspect_KMSWrapped_ReportsProviderKeyVersion(t *testing.T) {
	mock := newMockAuditClient()
	meta := map[string]string{
		crypto.MetaEncrypted:        "true",
		crypto.MetaAlgorithm:        crypto.AlgorithmAES256GCM,
		crypto.MetaKMSProvider:      "cosmian",
		crypto.MetaKMSKeyID:         "wrapping-key-1",
		crypto.MetaKeyVersion:       "2",
		crypto.MetaWrappedKeyCiphertext: "abcdef1234567890",
		crypto.MetaKDFParams:        "pbkdf2-sha256:600000",
	}
	mock.addObject("b/k", []byte("ciphertext"), meta)

	report, err := Inspect(context.Background(), mock, "b", "k")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.KMSProvider != "cosmian" {
		t.Errorf("KMSProvider = %q, want cosmian", report.KMSProvider)
	}
	if report.KMSKeyID != "wrapping-key-1" {
		t.Errorf("KMSKeyID = %q, want wrapping-key-1", report.KMSKeyID)
	}
	if report.KeyVersion != "2" {
		t.Errorf("KeyVersion = %q, want 2", report.KeyVersion)
	}
}

func TestInspect_MalformedSalt_OmitsFieldNotFatal(t *testing.T) {
	mock := newMockAuditClient()
	meta := map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKeySalt:   "not-valid-hex!!",
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	}
	mock.addObject("b/k", []byte("ciphertext"), meta)

	report, err := Inspect(context.Background(), mock, "b", "k")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.SaltHex != "" {
		t.Errorf("SaltHex should be omitted for malformed input, got %q", report.SaltHex)
	}
	if !report.Encrypted {
		t.Error("expected Encrypted=true despite malformed salt")
	}
}

func TestInspect_NonExistentObject_ReturnsError(t *testing.T) {
	mock := newMockAuditClient()
	_, err := Inspect(context.Background(), mock, "b", "nonexistent")
	if err == nil {
		t.Fatal("expected error for non-existent object")
	}
}

func TestInspect_CiphertextFingerprint_Included(t *testing.T) {
	mock := newMockAuditClient()
	meta := map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	}
	ciphertext := make([]byte, 100)
	for i := range ciphertext {
		ciphertext[i] = byte(i)
	}
	mock.addObject("b/k", ciphertext, meta)

	report, err := Inspect(context.Background(), mock, "b", "k")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	decoded, err := hex.DecodeString(report.CiphertextHeadHex)
	if err != nil {
		t.Fatalf("failed to decode CiphertextHeadHex: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("expected non-empty ciphertext fingerprint")
	}
	// Should be at most 32 bytes
	if len(decoded) > 32 {
		t.Errorf("ciphertext head too long: %d bytes", len(decoded))
	}
}
