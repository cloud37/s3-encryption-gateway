package migrate

import (
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func TestClassify_Plaintext(t *testing.T) {
	meta := map[string]string{
		"Content-Type": "text/plain",
	}
	if got := ClassifyObject(meta); got != ClassPlaintext {
		t.Errorf("ClassifyObject(plaintext) = %v, want ClassPlaintext", ClassToString(got))
	}
}

func TestClassify_Modern_Chunked(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted:     "true",
		crypto.MetaChunkedFormat: "true",
		crypto.MetaIVDerivation:  "hkdf-sha256",
		crypto.MetaKDFParams:     "pbkdf2-sha256:600000",
	}
	if got := ClassifyObject(meta); got != ClassModern {
		t.Errorf("ClassifyObject(modern chunked) = %v, want ClassModern", ClassToString(got))
	}
}

func TestClassify_Modern_NonChunked(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	}
	if got := ClassifyObject(meta); got != ClassModern {
		t.Errorf("ClassifyObject(modern non-chunked) = %v, want ClassModern", ClassToString(got))
	}
}

func TestClassify_ClassA_XOR(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted:     "true",
		crypto.MetaChunkedFormat: "true",
		// IVDerivation absent → XOR legacy
	}
	if got := ClassifyObject(meta); got != ClassA_XOR {
		t.Errorf("ClassifyObject(class A) = %v, want ClassA_XOR", ClassToString(got))
	}
}

func TestClassify_ClassB_NoAAD(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted:    "true",
		crypto.MetaLegacyNoAAD:  "true",
		crypto.MetaAlgorithm:    crypto.AlgorithmAES256GCM,
		// non-chunked (no MetaChunkedFormat)
	}
	if got := ClassifyObject(meta); got != ClassB_NoAAD {
		t.Errorf("ClassifyObject(class B) = %v, want ClassB_NoAAD", ClassToString(got))
	}
}

func TestClassify_ClassC_FallbackXOR(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted:      "true",
		crypto.MetaFallbackMode:   "true",
		// fallback-version absent → "1" (legacy)
		// iv-deriv absent → XOR
	}
	if got := ClassifyObject(meta); got != ClassC_Fallback_XOR {
		t.Errorf("ClassifyObject(class C XOR) = %v, want ClassC_Fallback_XOR", ClassToString(got))
	}
}

func TestClassify_ClassC_FallbackHKDF(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted:       "true",
		crypto.MetaFallbackMode:    "true",
		crypto.MetaFallbackVersion: "1",
		crypto.MetaIVDerivation:    "hkdf-sha256",
	}
	if got := ClassifyObject(meta); got != ClassC_Fallback_HKDF {
		t.Errorf("ClassifyObject(class C HKDF) = %v, want ClassC_Fallback_HKDF", ClassToString(got))
	}
}

func TestClassify_FallbackV2_IsModern(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted:       "true",
		crypto.MetaFallbackMode:    "true",
		crypto.MetaFallbackVersion: "2",
		crypto.MetaIVDerivation:    "hkdf-sha256",
		crypto.MetaKDFParams:       "pbkdf2-sha256:600000",
	}
	if got := ClassifyObject(meta); got != ClassModern {
		t.Errorf("ClassifyObject(fallback v2) = %v, want ClassModern", ClassToString(got))
	}
}

func TestClassify_CompactEncryptedKey(t *testing.T) {
	meta := map[string]string{
		"x-amz-meta-e":           "true",
		crypto.MetaChunkedFormat: "true",
		crypto.MetaIVDerivation:  "hkdf-sha256",
		crypto.MetaKDFParams:     "pbkdf2-sha256:600000",
	}
	if got := ClassifyObject(meta); got != ClassModern {
		t.Errorf("ClassifyObject(compact key) = %v, want ClassModern", ClassToString(got))
	}
}

func TestClassify_NilMetadata(t *testing.T) {
	if got := ClassifyObject(nil); got != ClassPlaintext {
		t.Errorf("ClassifyObject(nil) = %v, want ClassPlaintext", ClassToString(got))
	}
}

func TestClassify_EncryptedFlagFalse(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted: "false",
	}
	if got := ClassifyObject(meta); got != ClassPlaintext {
		t.Errorf("ClassifyObject(encrypted=false) = %v, want ClassPlaintext", ClassToString(got))
	}
}

func TestNeedsMigration(t *testing.T) {
	tests := []struct {
		class ObjectClass
		want  bool
	}{
		{ClassModern, false},
		{ClassPlaintext, false},
		{ClassUnknown, false},
		{ClassA_XOR, true},
		{ClassB_NoAAD, true},
		{ClassC_Fallback_XOR, true},
		{ClassC_Fallback_HKDF, true},
		{ClassD_LegacyKDF, true},
	}
	for _, tt := range tests {
		t.Run(ClassToString(tt.class), func(t *testing.T) {
			if got := NeedsMigration(tt.class); got != tt.want {
				t.Errorf("NeedsMigration(%s) = %v, want %v", ClassToString(tt.class), got, tt.want)
			}
		})
	}
}

func TestClassify_ClassD_LegacyKDF(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		// MetaKDFParams absent → legacy KDF
	}
	if got := ClassifyObject(meta); got != ClassD_LegacyKDF {
		t.Errorf("ClassifyObject(class D) = %v, want ClassD_LegacyKDF", ClassToString(got))
	}
}

func TestClassify_ClassD_LegacyKDF_Chunked(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted:     "true",
		crypto.MetaChunkedFormat: "true",
		crypto.MetaIVDerivation:  "hkdf-sha256",
		// MetaKDFParams absent → legacy KDF
	}
	if got := ClassifyObject(meta); got != ClassD_LegacyKDF {
		t.Errorf("ClassifyObject(class D chunked) = %v, want ClassD_LegacyKDF", ClassToString(got))
	}
}

func TestClassify_ClassModern_WithExplicitLowerKDFParams(t *testing.T) {
	// An object with an explicit "pbkdf2-sha256:100000" KDF params value is
	// ClassModern — the presence of any KDF params means the encryption
	// algorithm is known and recorded. Migrating based on iteration count
	// is handled by SourceIterations in the Migrator, not by class.
	meta := map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKDFParams: "pbkdf2-sha256:100000",
	}
	if got := ClassifyObject(meta); got != ClassModern {
		t.Errorf("ClassifyObject(explicit 100k KDF params) = %v, want ClassModern", ClassToString(got))
	}
}

func TestClassify_ClassModern_WithDefaultKDFParams(t *testing.T) {
	// An object with the current default iteration count is ClassModern.
	meta := map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	}
	if got := ClassifyObject(meta); got != ClassModern {
		t.Errorf("ClassifyObject(600k KDF params) = %v, want ClassModern", ClassToString(got))
	}
}

func TestClassToString_ClassD(t *testing.T) {
	if got := ClassToString(ClassD_LegacyKDF); got != "class_d_legacy_kdf" {
		t.Errorf("ClassToString(ClassD_LegacyKDF) = %q, want class_d_legacy_kdf", got)
	}
}

func TestFilterKDF_AllowsClassD(t *testing.T) {
	if !FilterKDF.IsAllowed(ClassD_LegacyKDF) {
		t.Error("FilterKDF should allow ClassD_LegacyKDF")
	}
}

func TestFilterKDF_SkipsModern(t *testing.T) {
	if FilterKDF.IsAllowed(ClassModern) {
		t.Error("FilterKDF should not allow ClassModern")
	}
}

func TestFilterKDF_SkipsClassA(t *testing.T) {
	if FilterKDF.IsAllowed(ClassA_XOR) {
		t.Error("FilterKDF should not allow ClassA_XOR")
	}
}

func TestFilterAll_AllowsClassD(t *testing.T) {
	if !FilterAll.IsAllowed(ClassD_LegacyKDF) {
		t.Error("FilterAll should allow ClassD_LegacyKDF")
	}
}

func TestClassifyObject_ClassD_NeedsMigration(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		// NO crypto.MetaKDFParams
	}
	if got := ClassifyObject(meta); got != ClassD_LegacyKDF {
		t.Errorf("ClassifyObject(class D) = %v, want ClassD_LegacyKDF", ClassToString(got))
	}
	if got := NeedsMigration(ClassD_LegacyKDF); got != true {
		t.Errorf("NeedsMigration(ClassD_LegacyKDF) = %v, want true", got)
	}
}

func TestClassifyObject_Modern_WithKDFParams(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted: "true",
		crypto.MetaKDFParams: "pbkdf2-sha256:600000",
	}
	if got := ClassifyObject(meta); got != ClassModern {
		t.Errorf("ClassifyObject(modern with KDF params) = %v, want ClassModern", ClassToString(got))
	}
	if got := NeedsMigration(ClassModern); got != false {
		t.Errorf("NeedsMigration(ClassModern) = %v, want false", got)
	}
}
