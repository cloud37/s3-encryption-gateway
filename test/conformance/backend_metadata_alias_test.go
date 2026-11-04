//go:build conformance

package conformance

import (
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// AWS SDK Metadata strips x-amz-meta-; reconstruct it before expanding aliases.
func expandSDKUserMetadata(metadata map[string]string) (map[string]string, error) {
	full := make(map[string]string, len(metadata))
	for key, value := range metadata {
		full["x-amz-meta-"+strings.ToLower(key)] = value
	}
	return crypto.ExpandMetadataForAPI(full)
}

func sdkBackendEncryptedMarker(metadata map[string]string) bool {
	expanded, err := expandSDKUserMetadata(metadata)
	return err == nil && expanded[crypto.MetaEncrypted] == "true"
}

func TestGH353SDKBackendEncryptedMarker(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata map[string]string
		want     bool
	}{
		{"canonical", map[string]string{"encrypted": "true"}, true},
		{"compact", map[string]string{"e": "true"}, true},
		{"missing", map[string]string{"unrelated": "true"}, false},
		{"wrong-canonical", map[string]string{"encrypted": "false"}, false},
		{"wrong-compact", map[string]string{"e": "false"}, false},
		{"canonical-wrong-wins", map[string]string{"encrypted": "false", "e": "true"}, false},
		{"canonical-true-wins", map[string]string{"encrypted": "true", "e": "false"}, true},
		{"empty-canonical-wins", map[string]string{"encrypted": "", "e": "true"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if sdkBackendEncryptedMarker(tc.metadata) != tc.want {
				t.Fatal("encrypted marker classification mismatch")
			}
		})
	}
}

func TestGH353BackendMetadataAliasExpansion(t *testing.T) {
	for _, metadata := range []map[string]string{
		{"ct": "application/json", "kdf": "pbkdf2-sha256:600000"},
		{"encryption-content-type": "application/json", "encryption-kdf-params": "pbkdf2-sha256:600000"},
	} {
		expanded, err := expandSDKUserMetadata(metadata)
		if err != nil || expanded[crypto.MetaContentType] != "application/json" || expanded[crypto.MetaKDFParams] != "pbkdf2-sha256:600000" {
			t.Fatal("backend metadata alias expansion lost asserted values")
		}
	}
}
