package crypto

import (
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
)

type MetaKeyClass uint8

const (
	MetaClassControl MetaKeyClass = iota + 1
	MetaClassProtectedStandard
	MetaClassStructural
)

type MetaKeySpec struct {
	Canonical, Compact        string
	Legacy                    []string
	Class                     MetaKeyClass
	Header                    string
	LegacyEncryptionPredicate bool
}

var metaKeyRegistry = []MetaKeySpec{
	{MetaEncrypted, "x-amz-meta-e", nil, MetaClassControl, "", true}, {MetaAlgorithm, "x-amz-meta-a", nil, MetaClassControl, "", true},
	{MetaKeySalt, "x-amz-meta-s", nil, MetaClassControl, "", true}, {MetaIV, "x-amz-meta-i", nil, MetaClassControl, "", true},
	{MetaAuthTag, "", nil, MetaClassControl, "", true}, {MetaOriginalSize, "x-amz-meta-os", nil, MetaClassControl, "", true},
	{MetaOriginalETag, "x-amz-meta-oe", nil, MetaClassControl, "", true}, {MetaContentType, "x-amz-meta-ct", []string{"encryption-content-type"}, MetaClassProtectedStandard, "Content-Type", true},
	{MetaCacheControl, "x-amz-meta-ccache", []string{"encryption-cache-control"}, MetaClassProtectedStandard, "Cache-Control", true}, {MetaContentDisposition, "x-amz-meta-cdisp", []string{"encryption-content-disposition"}, MetaClassProtectedStandard, "Content-Disposition", true},
	{MetaContentEncoding, "x-amz-meta-cenc", nil, MetaClassProtectedStandard, "Content-Encoding", false}, {MetaContentLanguage, "x-amz-meta-clang", nil, MetaClassProtectedStandard, "Content-Language", false}, {MetaExpires, "x-amz-meta-cexp", nil, MetaClassProtectedStandard, "Expires", false},
	{MetaChunkedFormat, "x-amz-meta-c", nil, MetaClassControl, "", true}, {MetaChunkSize, "x-amz-meta-cs", nil, MetaClassControl, "", true}, {MetaChunkCount, "x-amz-meta-cc", nil, MetaClassControl, "", true}, {MetaManifest, "x-amz-meta-m", nil, MetaClassControl, "", true},
	{MetaKeyVersion, "x-amz-meta-kv", nil, MetaClassControl, "", true}, {MetaWrappedKeyCiphertext, "x-amz-meta-wk", nil, MetaClassControl, "", true}, {MetaKMSKeyID, "x-amz-meta-kid", nil, MetaClassControl, "", true}, {MetaKMSProvider, "x-amz-meta-kp", nil, MetaClassControl, "", true}, {MetaKDFParams, "x-amz-meta-kdf", nil, MetaClassControl, "", true},
	{MetaFallbackMode, "x-amz-meta-fb", nil, MetaClassStructural, "", true}, {MetaFallbackPointer, "", nil, MetaClassStructural, "", true}, {MetaFallbackVersion, "x-amz-meta-fbv", nil, MetaClassStructural, "", true}, {MetaIVDerivation, "", nil, MetaClassControl, "", true}, {MetaLegacyNoAAD, "", nil, MetaClassControl, "", true}, {MetaObjectFormatVersion, "x-amz-meta-fmt", nil, MetaClassStructural, "", true},
	{MetaObjectBindingID, "x-amz-meta-bid", nil, MetaClassStructural, "", true}, {MetaMPUManifestVersion, "", nil, MetaClassStructural, "", true},
	{MetaMPUEncrypted, "", nil, MetaClassStructural, "", false}, {MetaEncryptedMetadata, "x-amz-meta-em", nil, MetaClassStructural, "", false},
}

func init() {
	seen := map[string]bool{}
	for _, s := range metaKeyRegistry {
		for _, n := range append([]string{s.Canonical, s.Compact}, s.Legacy...) {
			if n != "" {
				k := strings.ToLower(n)
				if seen[k] {
					panic("duplicate metadata key " + n)
				}
				seen[k] = true
			}
		}
	}
}
func MetaKeys() []MetaKeySpec { return append([]MetaKeySpec(nil), metaKeyRegistry...) }
func LookupMetaKey(key string) (MetaKeySpec, bool) {
	k := strings.ToLower(key)
	for _, s := range metaKeyRegistry {
		if strings.ToLower(s.Canonical) == k || strings.ToLower(s.Compact) == k {
			return s, true
		}
		for _, l := range s.Legacy {
			if strings.ToLower(l) == k {
				return s, true
			}
		}
	}
	return MetaKeySpec{}, false
}
func IsEncryptionMetadata(key string) bool {
	if strings.EqualFold(key, "x-amz-meta-original-content-length") {
		return true
	}
	s, ok := LookupMetaKey(key)
	return ok && s.LegacyEncryptionPredicate && !strings.EqualFold(key, MetaEncrypted)
}

// isEncryptionPayloadMetadata excludes the cleartext encryption marker. The
// public classifier intentionally recognizes that marker, while encryption
// payload sealing/decrypted-view cleanup must retain it outside the payload.
func isEncryptionPayloadMetadata(key string) bool {
	return IsEncryptionMetadata(key) && !strings.EqualFold(key, MetaEncrypted)
}

func isEncryptionCleanupMetadata(key string) bool {
	return IsEncryptionMetadata(key) || strings.EqualFold(key, MetaEncrypted)
}
func IsGatewayReservedKey(key string) bool {
	if strings.EqualFold(key, "x-amz-meta-original-content-length") {
		return true
	}
	_, ok := LookupMetaKey(key)
	return ok
}
func ProtectedStandardKeys() []MetaKeySpec {
	out := []MetaKeySpec{}
	for _, n := range objectmeta.Names {
		for _, s := range metaKeyRegistry {
			if s.Class == MetaClassProtectedStandard && s.Header == n {
				out = append(out, s)
			}
		}
	}
	return out
}
func CompactAliases() map[string]string {
	out := map[string]string{}
	for _, s := range metaKeyRegistry {
		if s.Compact != "" {
			out[s.Canonical] = s.Compact
		}
	}
	return out
}
func HasCompactAlias(meta map[string]string) bool {
	for _, s := range metaKeyRegistry {
		if s.Compact != "" {
			for k := range meta {
				if strings.EqualFold(k, s.Compact) {
					return true
				}
			}
		}
	}
	return false
}
