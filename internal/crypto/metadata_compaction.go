package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// MetadataCompactor handles compaction of encryption metadata
type MetadataCompactor struct {
	profile *ProviderProfile
}

// ExpandMetadataForAPI expands the compact aliases that may be returned by a
// backend before an API handler classifies an encrypted object. API callers do
// not own an engine/profile, but the aliases are protocol-stable.
func ExpandMetadataForAPI(metadata map[string]string) (map[string]string, error) {
	if !HasCompactAlias(metadata) {
		return metadata, nil
	}
	// API classification must understand aliases emitted by provider profiles;
	// use the canonical short-key profile rather than the non-compacting default.
	return NewMetadataCompactor(ProviderAWS).ExpandMetadata(metadata)
}

// NewMetadataCompactor creates a new compactor for the given provider
func NewMetadataCompactor(profile *ProviderProfile) *MetadataCompactor {
	return &MetadataCompactor{profile: profile}
}

// CompactMetadata compacts metadata according to the provider's strategy
func (c *MetadataCompactor) CompactMetadata(metadata map[string]string) (map[string]string, error) {
	if !c.profile.ShouldCompact(metadata) {
		return metadata, nil
	}

	compacted := make(map[string]string)

	// Copy non-encryption metadata as-is
	for key, value := range metadata {
		if !IsEncryptionMetadata(key) && !strings.EqualFold(key, MetaEncrypted) {
			compacted[key] = value
		}
	}
	// The clear encryption marker is intentionally not part of the metadata
	// blob, but it must survive provider compaction so API reads classify the
	// payload as encrypted before decrypting that blob.
	if marker, ok := metadataValue(metadata, MetaEncrypted); ok {
		compacted[MetaEncrypted] = marker
	}

	// Compact encryption metadata
	encMeta, err := c.compactEncryptionMetadata(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to compact encryption metadata: %w", err)
	}

	// Merge compacted metadata
	for key, value := range encMeta {
		compacted[key] = value
	}

	return compacted, nil
}

// ExpandMetadata expands compacted metadata back to full form
func (c *MetadataCompactor) ExpandMetadata(metadata map[string]string) (map[string]string, error) {
	expanded := make(map[string]string)

	// Copy non-compacted metadata as-is
	for key, value := range metadata {
		if !c.isCompactedKey(key) {
			expanded[key] = value
		}
	}
	if marker, ok := metadataValue(metadata, MetaEncrypted); ok {
		expanded[MetaEncrypted] = marker
	}

	// Expand compacted encryption metadata
	encMeta, err := c.expandEncryptionMetadata(metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to expand encryption metadata: %w", err)
	}

	// Merge expanded metadata
	for key, value := range encMeta {
		expanded[key] = value
	}

	return expanded, nil
}

// compactEncryptionMetadata compacts encryption-related metadata
func (c *MetadataCompactor) compactEncryptionMetadata(metadata map[string]string) (map[string]string, error) {
	compacted := make(map[string]string)

	// Use short key aliases for base64url strategy
	if c.profile.CompactionStrategy == "base64url" {
		// Compact every registry entry with an alias, including structural
		// entries such as the encrypted metadata blob.  The frozen
		// LegacyEncryptionPredicate controls the historical public predicate;
		// it must not decide which gateway-owned fields are serialized.
		for _, spec := range MetaKeys() {
			if spec.Compact == "" {
				continue
			}
			v, ok := metadataValue(metadata, spec.Canonical)
			if !ok {
				// Compaction is intentionally idempotent. API tests and some
				// adapters may hand us metadata that is already in its compact
				// spelling.
				v, ok = metadataValue(metadata, spec.Compact)
			}
			if ok && v != "" {
				compacted[spec.Compact] = v
			}
		}

	} else {
		// No compaction - copy as-is
		for key, value := range metadata {
			if IsEncryptionMetadata(key) {
				compacted[key] = value
			}
		}
	}

	return compacted, nil
}

// expandEncryptionMetadata expands compacted encryption metadata back to full keys
func (c *MetadataCompactor) expandEncryptionMetadata(metadata map[string]string) (map[string]string, error) {
	expanded := make(map[string]string)

	if c.profile.CompactionStrategy == "base64url" {
		for _, spec := range MetaKeys() {
			if spec.Compact == "" {
				continue
			}
			if v, ok := metadataValue(metadata, spec.Compact); ok && v != "" {
				expanded[spec.Canonical] = v
			}
		}
	} else {
		// No expansion needed - copy encryption metadata as-is
		for key, value := range metadata {
			if IsEncryptionMetadata(key) {
				expanded[key] = value
			}
		}
	}

	return expanded, nil
}

func metadataValue(metadata map[string]string, name string) (string, bool) {
	for key, value := range metadata {
		if strings.EqualFold(key, name) {
			return value, true
		}
	}
	return "", false
}

// isCompactedKey returns true if the key is a compacted short key
func (c *MetadataCompactor) isCompactedKey(key string) bool {
	if c.profile.CompactionStrategy != "base64url" {
		return false
	}

	for _, spec := range MetaKeys() {
		if spec.Compact != "" && strings.EqualFold(key, spec.Compact) {
			return true
		}
	}
	return false
}

// EstimateMetadataSize estimates the size of metadata in bytes
func EstimateMetadataSize(metadata map[string]string) int {
	total := 0
	for key, value := range metadata {
		// HTTP header format: "Key: Value\r\n"
		total += len(key) + 2 + len(value) + 2
	}
	return total
}

// encodeBase64URL encodes data using base64url encoding (URL-safe base64)
func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// decodeBase64URL decodes data using base64url encoding
func decodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// CompactNumericValue compacts numeric values using shorter representations
func CompactNumericValue(value string) string {
	// For now, just return as-is. Could implement variable-length encoding later
	return value
}

// ExpandNumericValue expands compacted numeric values
func ExpandNumericValue(value string) (string, error) {
	// Parse to ensure it's valid, then return
	if _, err := strconv.ParseInt(value, 10, 64); err != nil {
		return "", fmt.Errorf("invalid numeric value: %s", value)
	}
	return value, nil
}
