package audit

import (
	"context"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func TestVerifyKey_MatchingVersion_ReturnsMatch(t *testing.T) {
	mock := newMockAuditClient()
	meta := map[string]string{
		crypto.MetaEncrypted:   "true",
		crypto.MetaAlgorithm:   crypto.AlgorithmAES256GCM,
		crypto.MetaKeyVersion:  "2",
		crypto.MetaKDFParams:   "pbkdf2-sha256:600000",
	}
	mock.addObject("b/k", []byte("ciphertext"), meta)

	wantVer := 2
	report, err := VerifyKey(context.Background(), mock, "b", "k", &wantVer)
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}

	if !report.Match {
		t.Error("expected Match=true for matching version")
	}
	if report.Recorded != "2" {
		t.Errorf("Recorded = %q, want 2", report.Recorded)
	}
	if report.Want != "2" {
		t.Errorf("Want = %q, want 2", report.Want)
	}
}

func TestVerifyKey_MismatchVersion_ReturnsMismatch(t *testing.T) {
	mock := newMockAuditClient()
	meta := map[string]string{
		crypto.MetaEncrypted:   "true",
		crypto.MetaAlgorithm:   crypto.AlgorithmAES256GCM,
		crypto.MetaKeyVersion:  "1",
		crypto.MetaKDFParams:   "pbkdf2-sha256:600000",
	}
	mock.addObject("b/k", []byte("ciphertext"), meta)

	wantVer := 2
	report, err := VerifyKey(context.Background(), mock, "b", "k", &wantVer)
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}

	if report.Match {
		t.Error("expected Match=false for mismatching version")
	}
	if report.Recorded != "1" {
		t.Errorf("Recorded = %q, want 1", report.Recorded)
	}
	if report.Want != "2" {
		t.Errorf("Want = %q, want 2", report.Want)
	}
}

func TestVerifyKey_NoUnwrapPath_ReturnsMetadataOnly(t *testing.T) {
	mock := newMockAuditClient()
	meta := map[string]string{
		crypto.MetaEncrypted:   "true",
		crypto.MetaAlgorithm:   crypto.AlgorithmAES256GCM,
		crypto.MetaKeyVersion:  "3",
		crypto.MetaKDFParams:   "pbkdf2-sha256:600000",
	}
	mock.addObject("b/k", []byte("ciphertext"), meta)

	// No desired version — just check metadata
	report, err := VerifyKey(context.Background(), mock, "b", "k", nil)
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}

	if !report.Match {
		t.Error("expected Match=true when no version is specified")
	}
	if report.Recorded != "3" {
		t.Errorf("Recorded = %q, want 3", report.Recorded)
	}
	if report.Verified != "metadata-only" {
		t.Errorf("Verified = %q, want metadata-only", report.Verified)
	}
}

func TestVerifyKey_NonExistentObject_ReturnsError(t *testing.T) {
	mock := newMockAuditClient()
	_, err := VerifyKey(context.Background(), mock, "b", "nonexistent", nil)
	if err == nil {
		t.Fatal("expected error for non-existent object")
	}
}
