package crypto

import (
	"reflect"
	"strings"
	"testing"
)

func TestIsEncryptionMetadata_UnchangedSet(t *testing.T) {
	legacyCanonical := []string{
		"x-amz-meta-encrypted", "x-amz-meta-encryption-algorithm", "x-amz-meta-encryption-key-salt",
		"x-amz-meta-encryption-iv", "x-amz-meta-encryption-auth-tag", "x-amz-meta-encryption-original-size",
		"x-amz-meta-encryption-original-etag", "x-amz-meta-encryption-content-type", "x-amz-meta-encryption-cache-control",
		"x-amz-meta-encryption-content-disposition", "x-amz-meta-encryption-chunked", "x-amz-meta-encryption-chunk-size",
		"x-amz-meta-encryption-chunk-count", "x-amz-meta-encryption-manifest", "x-amz-meta-encryption-key-version",
		"x-amz-meta-encryption-wrapped-key", "x-amz-meta-encryption-kms-id", "x-amz-meta-encryption-kms-provider",
		"x-amz-meta-encryption-kdf-params", "x-amz-meta-encryption-fallback", "x-amz-meta-encryption-fallback-ptr",
		"x-amz-meta-encryption-fallback-version", "x-amz-meta-enc-iv-deriv", "x-amz-meta-enc-legacy-no-aad",
		"x-amz-meta-encryption-format-version", "x-amz-meta-encryption-binding-id", "x-amz-meta-encryption-mpu-manifest-version",
	}
	var got []string
	for _, key := range legacyCanonical {
		if IsEncryptionMetadata(key) && key != MetaEncrypted {
			got = append(got, key)
		}
	}
	wantPredicate := append([]string(nil), legacyCanonical[1:]...)
	if !reflect.DeepEqual(got, wantPredicate) {
		t.Fatalf("registry predicate keys=%v", got)
	}
	if IsEncryptionMetadata(MetaEncrypted) || !IsEncryptionMetadata("x-amz-meta-original-content-length") || len(legacyCanonical) != 27 {
		t.Fatal("frozen legacy predicate set changed")
	}
	// Snapshot the historical predicate rather than relying on registry values
	// as the expected side of the assertion.
	legacySet := map[string]bool{}
	for _, key := range legacyCanonical {
		legacySet[key] = key != MetaEncrypted
	}
	legacySet["x-amz-meta-original-content-length"] = true
	for _, spec := range MetaKeys() {
		if spec.Canonical == "" {
			continue
		}
		if got, want := IsEncryptionMetadata(spec.Canonical), legacySet[spec.Canonical]; got != want {
			t.Errorf("IsEncryptionMetadata(%q)=%t want %t", spec.Canonical, got, want)
		}
	}
}

func TestCompactExpand_GoldenUnchanged(t *testing.T) {
	original := map[string]string{
		MetaEncrypted: "true", MetaAlgorithm: "AES256-GCM", MetaKeySalt: "salt", MetaIV: "iv",
		MetaAuthTag: "tag", MetaOriginalSize: "17", MetaOriginalETag: "etag",
		MetaContentType: "text/plain", MetaCacheControl: "no-cache", MetaContentDisposition: "attachment",
		MetaChunkedFormat: "true", MetaChunkSize: "65536", MetaChunkCount: "1", MetaManifest: "manifest",
		MetaKeyVersion: "2", MetaWrappedKeyCiphertext: "wrapped", MetaKMSKeyID: "kms-id",
		MetaKMSProvider: "provider", MetaKDFParams: "kdf", MetaFallbackMode: "v1",
		MetaFallbackPointer: "key.mpu-manifest", MetaFallbackVersion: "1", MetaIVDerivation: "derived",
		MetaLegacyNoAAD: "true", MetaObjectFormatVersion: "buffered-v2", MetaObjectBindingID: "binding",
		MetaMPUManifestVersion: "2", MetaMPUEncrypted: "true", MetaEncryptedMetadata: "blob",
	}
	wantCompact := map[string]string{
		MetaEncrypted: "true", MetaEncryptedMetadata: "blob", MetaMPUEncrypted: "true",
		"x-amz-meta-e": "true", "x-amz-meta-a": "AES256-GCM", "x-amz-meta-s": "salt", "x-amz-meta-i": "iv",
		"x-amz-meta-os": "17", "x-amz-meta-oe": "etag", "x-amz-meta-ct": "text/plain", "x-amz-meta-ccache": "no-cache",
		"x-amz-meta-cdisp": "attachment", "x-amz-meta-c": "true", "x-amz-meta-cs": "65536", "x-amz-meta-cc": "1",
		"x-amz-meta-m": "manifest", "x-amz-meta-kv": "2", "x-amz-meta-wk": "wrapped", "x-amz-meta-kid": "kms-id",
		"x-amz-meta-kp": "provider", "x-amz-meta-kdf": "kdf", "x-amz-meta-fb": "v1", "x-amz-meta-fbv": "1",
		"x-amz-meta-fmt": "buffered-v2", "x-amz-meta-bid": "binding", "x-amz-meta-em": "blob",
	}
	compactor := NewMetadataCompactor(ProviderAWS)
	compact, err := compactor.CompactMetadata(original)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(compact, wantCompact) {
		t.Fatalf("compacted snapshot differs: %#v", compact)
	}
	expanded, err := compactor.ExpandMetadata(compact)
	if err != nil {
		t.Fatal(err)
	}
	wantExpanded := map[string]string{
		MetaEncrypted: "true", MetaEncryptedMetadata: "blob", MetaMPUEncrypted: "true", MetaAlgorithm: "AES256-GCM", MetaKeySalt: "salt", MetaIV: "iv", MetaOriginalSize: "17", MetaOriginalETag: "etag",
		MetaContentType: "text/plain", MetaCacheControl: "no-cache", MetaContentDisposition: "attachment", MetaChunkedFormat: "true",
		MetaChunkSize: "65536", MetaChunkCount: "1", MetaManifest: "manifest", MetaKeyVersion: "2", MetaWrappedKeyCiphertext: "wrapped",
		MetaKMSKeyID: "kms-id", MetaKMSProvider: "provider", MetaKDFParams: "kdf", MetaFallbackMode: "v1", MetaFallbackVersion: "1",
		MetaObjectFormatVersion: "buffered-v2", MetaObjectBindingID: "binding",
	}
	if !reflect.DeepEqual(expanded, wantExpanded) {
		t.Fatalf("expanded snapshot differs: %#v", expanded)
	}
}

func TestMetaKeyRegistry_PredicatesAndSnapshotsCoverEveryKey(t *testing.T) {
	compactor := NewMetadataCompactor(ProviderAWS)
	for _, spec := range MetaKeys() {
		if spec.Canonical == "" {
			continue
		}
		for _, key := range append([]string{spec.Canonical, spec.Compact}, spec.Legacy...) {
			if key == "" {
				continue
			}
			wantPredicate := spec.LegacyEncryptionPredicate && key != MetaEncrypted
			if got := IsEncryptionMetadata(key); got != wantPredicate {
				t.Errorf("legacy encryption predicate for %q=%t want %t", key, got, wantPredicate)
			}
			if !IsGatewayReservedKey(key) {
				t.Errorf("registry form %q is not reserved", key)
			}
		}
		if spec.Compact == "" {
			continue
		}
		original := map[string]string{spec.Canonical: "snapshot-value"}
		compacted, err := compactor.CompactMetadata(original)
		if err != nil {
			t.Fatalf("compact %q: %v", spec.Canonical, err)
		}
		if got := compacted[spec.Compact]; got != "snapshot-value" {
			t.Errorf("compact snapshot %q=%q", spec.Compact, got)
		}
		expanded, err := compactor.ExpandMetadata(map[string]string{spec.Compact: "snapshot-value"})
		if err != nil {
			t.Fatalf("expand %q: %v", spec.Compact, err)
		}
		if got := expanded[spec.Canonical]; got != "snapshot-value" {
			t.Errorf("expanded snapshot %q=%q", spec.Canonical, got)
		}
	}
}

func TestMetaKeys_UniqueNames(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range MetaKeys() {
		for _, name := range append([]string{spec.Canonical, spec.Compact}, spec.Legacy...) {
			if name == "" {
				continue
			}
			if seen[name] {
				t.Fatalf("duplicate metadata name %q", name)
			}
			seen[name] = true
		}
	}
}

func TestMetaKeys_EmptyLookupAndCleanupPredicate(t *testing.T) {
	if _, ok := LookupMetaKey(""); !ok || !IsEncryptionMetadata("") {
		t.Fatal("empty-key compatibility behavior unexpectedly changed")
	}
	if !IsGatewayReservedKey("") {
		t.Fatal("empty-key compatibility behavior unexpectedly changed")
	}
	if isEncryptionCleanupMetadata("x-amz-meta-unregistered") {
		t.Fatal("unregistered key classified for cleanup")
	}
	if !isEncryptionCleanupMetadata(MetaEncrypted) || isEncryptionPayloadMetadata(MetaEncrypted) {
		t.Fatal("clear marker cleanup/payload distinction changed")
	}
}

func TestMetaKeys_CopyReturnsIndependentRegistrySlice(t *testing.T) {
	first := MetaKeys()
	first[0].Canonical = "mutated"
	if MetaKeys()[0].Canonical == "mutated" {
		t.Fatal("caller mutated the registry slice")
	}
}

func TestMetaKeys_LookupAndAliasCaseFold(t *testing.T) {
	for _, spec := range MetaKeys() {
		for _, name := range append([]string{spec.Canonical, spec.Compact}, spec.Legacy...) {
			if name == "" {
				continue
			}
			if got, ok := LookupMetaKey(strings.ToUpper(name)); !ok || !strings.EqualFold(got.Canonical, spec.Canonical) {
				t.Errorf("lookup %q = %#v, %t", name, got, ok)
			}
		}
	}
}

func TestIsGatewayReservedKey_AllForms(t *testing.T) {
	for _, spec := range MetaKeys() {
		for _, name := range append([]string{spec.Canonical, spec.Compact}, spec.Legacy...) {
			if name != "" && !IsGatewayReservedKey(name) {
				t.Errorf("%q is not reserved", name)
			}
		}
	}
	if !IsGatewayReservedKey("X-Amz-Meta-Original-Content-Length") {
		t.Error("original content length must be reserved")
	}
}

func TestHasCompactAlias_DetectsEveryAlias(t *testing.T) {
	if HasCompactAlias(nil) {
		t.Fatal("nil map has a compact alias")
	}
	for _, spec := range MetaKeys() {
		if spec.Compact != "" && !HasCompactAlias(map[string]string{spec.Compact: "value"}) {
			t.Errorf("alias %q not detected", spec.Compact)
		}
	}
}
