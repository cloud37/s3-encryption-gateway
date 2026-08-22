package crypto

import (
	"fmt"
	"strings"
)

// ProviderProfile defines metadata limits and compaction strategies for S3 providers
type ProviderProfile struct {
	Name                string
	UserMetadataLimit   int    // bytes, 0 = unlimited
	SystemMetadataLimit int    // bytes, 0 = unlimited
	TotalHeaderLimit    int    // bytes, 0 = unlimited
	SupportsLongKeys    bool   // whether provider supports long header names
	CompactionStrategy  string // "none", "short-keys", "base64url"
}

// Known provider profiles based on research and documentation
var (
	ProviderAWS = &ProviderProfile{
		Name:                "aws",
		UserMetadataLimit:   2048, // 2KB for user-defined metadata
		SystemMetadataLimit: 0,    // AWS doesn't have separate system limit
		TotalHeaderLimit:    8192, // 8KB total PUT request header limit
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	ProviderMinIO = &ProviderProfile{
		Name:                "minio",
		UserMetadataLimit:   2048, // Follows AWS limits
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    8192,
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	ProviderWasabi = &ProviderProfile{
		Name:                "wasabi",
		UserMetadataLimit:   2048, // Similar to AWS
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    8192,
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	ProviderHetzner = &ProviderProfile{
		Name:                "hetzner",
		UserMetadataLimit:   2048, // Uses MinIO underneath
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    8192,
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	ProviderBackblaze = &ProviderProfile{
		Name:                "backblaze",
		UserMetadataLimit:   2048, // S3-compatible, similar to AWS
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    8192,
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	// Default profile for unknown providers - no compaction by default for backward compatibility
	ProviderDefault = &ProviderProfile{
		Name:                "default",
		UserMetadataLimit:   2048, // Conservative default
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    8192,
		SupportsLongKeys:    true,
		CompactionStrategy:  "none",
	}
)

// GetProviderProfile returns the profile for the given provider name
func GetProviderProfile(provider string) *ProviderProfile {
	switch strings.ToLower(provider) {
	case "aws", "amazon", "s3":
		return ProviderAWS
	case "minio", "min.io":
		return ProviderMinIO
	case "wasabi":
		return ProviderWasabi
	case "hetzner":
		return ProviderHetzner
	case "backblaze", "b2":
		return ProviderBackblaze
	default:
		return ProviderDefault
	}
}

// ValidateMetadataSize checks if the metadata fits within provider limits
func (p *ProviderProfile) ValidateMetadataSize(metadata map[string]string) error {
	totalSize := 0

	for key, value := range metadata {
		// Calculate size: key + ": " + value + "\r\n"
		entrySize := len(key) + 2 + len(value) + 2
		totalSize += entrySize
	}

	if p.TotalHeaderLimit > 0 && totalSize > p.TotalHeaderLimit {
		return fmt.Errorf("metadata size %d bytes exceeds provider %s total header limit of %d bytes",
			totalSize, p.Name, p.TotalHeaderLimit)
	}

	// Calculate user metadata size (x-amz-meta-* keys)
	userMetaSize := 0
	for key, value := range metadata {
		if strings.HasPrefix(key, "x-amz-meta-") {
			userMetaSize += len(key) + 2 + len(value) + 2
		}
	}

	if p.UserMetadataLimit > 0 && userMetaSize > p.UserMetadataLimit {
		return fmt.Errorf("user metadata size %d bytes exceeds provider %s user metadata limit of %d bytes",
			userMetaSize, p.Name, p.UserMetadataLimit)
	}

	return nil
}

// ShouldCompact returns true if metadata should be compacted for this provider
func (p *ProviderProfile) ShouldCompact(metadata map[string]string) bool {
	return p.CompactionStrategy != "none"
}
