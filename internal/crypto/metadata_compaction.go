package crypto

import (
	"encoding/base64"
	"fmt"
	"strconv"
)

// MetadataCompactor handles compaction of encryption metadata
type MetadataCompactor struct {
	profile *ProviderProfile
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
		if !IsEncryptionMetadata(key) {
			compacted[key] = value
		}
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
		// Core encryption metadata with short keys
		if v := metadata[MetaEncrypted]; v != "" {
			compacted["x-amz-meta-e"] = v // encrypted
		}
		if v := metadata[MetaAlgorithm]; v != "" {
			compacted["x-amz-meta-a"] = v // algorithm
		}
		if v := metadata[MetaKeySalt]; v != "" {
			compacted["x-amz-meta-s"] = v // salt
		}
		if v := metadata[MetaIV]; v != "" {
			compacted["x-amz-meta-i"] = v // iv
		}
		if v := metadata[MetaOriginalSize]; v != "" {
			compacted["x-amz-meta-os"] = v // original size
		}
		if v := metadata[MetaOriginalETag]; v != "" {
			compacted["x-amz-meta-oe"] = v // original etag
		}
		if v := metadata[MetaContentType]; v != "" {
			compacted["x-amz-meta-ct"] = v // content type
		}

		// Chunked encryption metadata
		if v := metadata[MetaChunkedFormat]; v != "" {
			compacted["x-amz-meta-c"] = v // chunked
		}
		if v := metadata[MetaChunkSize]; v != "" {
			compacted["x-amz-meta-cs"] = v // chunk size
		}
		if v := metadata[MetaChunkCount]; v != "" {
			compacted["x-amz-meta-cc"] = v // chunk count
		}
		if v := metadata[MetaManifest]; v != "" {
			compacted["x-amz-meta-m"] = v // manifest
		}
		if v := metadata[MetaKeyVersion]; v != "" {
			compacted["x-amz-meta-kv"] = v // key version
		}
		if v := metadata[MetaWrappedKeyCiphertext]; v != "" {
			compacted["x-amz-meta-wk"] = v // wrapped key
		}
		if v := metadata[MetaKMSKeyID]; v != "" {
			compacted["x-amz-meta-kid"] = v // kms key id
		}
		if v := metadata[MetaKMSProvider]; v != "" {
			compacted["x-amz-meta-kp"] = v // kms provider
		}
		if v := metadata[MetaKDFParams]; v != "" {
			compacted["x-amz-meta-kdf"] = v // kdf params
		}

		// V1.0-CRYPTO-3: encrypted metadata blob
		if v := metadata[MetaEncryptedMetadata]; v != "" {
			compacted[MetaEncryptedMetadataCompact] = v // encrypted metadata blob
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
		// Expand short keys back to full keys
		if v := metadata["x-amz-meta-e"]; v != "" {
			expanded[MetaEncrypted] = v
		}
		if v := metadata["x-amz-meta-a"]; v != "" {
			expanded[MetaAlgorithm] = v
		}
		if v := metadata["x-amz-meta-s"]; v != "" {
			expanded[MetaKeySalt] = v
		}
		if v := metadata["x-amz-meta-i"]; v != "" {
			expanded[MetaIV] = v
		}
		if v := metadata["x-amz-meta-os"]; v != "" {
			expanded[MetaOriginalSize] = v
		}
		if v := metadata["x-amz-meta-oe"]; v != "" {
			expanded[MetaOriginalETag] = v
		}
		if v := metadata["x-amz-meta-ct"]; v != "" {
			expanded[MetaContentType] = v
		}
		if v := metadata["x-amz-meta-c"]; v != "" {
			expanded[MetaChunkedFormat] = v
		}
		if v := metadata["x-amz-meta-cs"]; v != "" {
			expanded[MetaChunkSize] = v
		}
		if v := metadata["x-amz-meta-cc"]; v != "" {
			expanded[MetaChunkCount] = v
		}
		if v := metadata["x-amz-meta-m"]; v != "" {
			expanded[MetaManifest] = v
		}
		if v := metadata["x-amz-meta-kv"]; v != "" {
			expanded[MetaKeyVersion] = v
		}
		if v := metadata["x-amz-meta-wk"]; v != "" {
			expanded[MetaWrappedKeyCiphertext] = v
		}
		if v := metadata["x-amz-meta-kid"]; v != "" {
			expanded[MetaKMSKeyID] = v
		}
		if v := metadata["x-amz-meta-kp"]; v != "" {
			expanded[MetaKMSProvider] = v
		}
		if v := metadata["x-amz-meta-kdf"]; v != "" {
			expanded[MetaKDFParams] = v
		}
		// V1.0-CRYPTO-3: encrypted metadata blob expansion
		if v := metadata[MetaEncryptedMetadataCompact]; v != "" {
			expanded[MetaEncryptedMetadata] = v
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

// isCompactedKey returns true if the key is a compacted short key
func (c *MetadataCompactor) isCompactedKey(key string) bool {
	if c.profile.CompactionStrategy != "base64url" {
		return false
	}

	compactedKeys := []string{
		"x-amz-meta-e", "x-amz-meta-a", "x-amz-meta-s", "x-amz-meta-i",
		"x-amz-meta-os", "x-amz-meta-oe", "x-amz-meta-c", "x-amz-meta-cs",
		"x-amz-meta-cc", "x-amz-meta-m", "x-amz-meta-kv", "x-amz-meta-wk",
		"x-amz-meta-kid", "x-amz-meta-kp", "x-amz-meta-kdf",
		MetaEncryptedMetadataCompact,
	}

	for _, ck := range compactedKeys {
		if key == ck {
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
