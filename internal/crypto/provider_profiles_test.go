package crypto

import (
	"testing"
)

func TestGetProviderProfile(t *testing.T) {
	tests := []struct {
		provider string
		expected *ProviderProfile
	}{
		{"aws", ProviderAWS},
		{"AWS", ProviderAWS},
		{"amazon", ProviderAWS},
		{"s3", ProviderAWS},
		{"minio", ProviderMinIO},
		{"MinIO", ProviderMinIO},
		{"min.io", ProviderMinIO},
		{"wasabi", ProviderWasabi},
		{"Wasabi", ProviderWasabi},
		{"hetzner", ProviderHetzner},
		{"Hetzner", ProviderHetzner},
		{"unknown", ProviderDefault},
		{"", ProviderDefault},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			profile := GetProviderProfile(tt.provider)
			if profile.Name != tt.expected.Name {
				t.Errorf("GetProviderProfile(%q) = %q, want %q", tt.provider, profile.Name, tt.expected.Name)
			}
			if profile.UserMetadataLimit != tt.expected.UserMetadataLimit {
				t.Errorf("GetProviderProfile(%q) UserMetadataLimit = %d, want %d", tt.provider, profile.UserMetadataLimit, tt.expected.UserMetadataLimit)
			}
		})
	}
}

func TestProviderProfile_ValidateMetadataSize(t *testing.T) {
	profile := &ProviderProfile{
		Name:                "test",
		UserMetadataLimit:   100,
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    200,
	}

	tests := []struct {
		name        string
		metadata    map[string]string
		expectError bool
	}{
		{
			name: "within limits",
			metadata: map[string]string{
				"x-amz-meta-key1": "value1",
				"x-amz-meta-key2": "value2",
			},
			expectError: false,
		},
		{
			name: "exceeds user metadata limit",
			metadata: map[string]string{
				"x-amz-meta-very-long-key-name-that-exceeds-limits": "very-long-value-that-exceeds-the-metadata-limits-for-this-test-case",
			},
			expectError: true,
		},
		{
			name: "exceeds total header limit",
			metadata: map[string]string{
				"content-type":    "application/json",
				"x-amz-meta-key1": "value1",
				"x-amz-meta-key2": "value2",
				"x-amz-meta-key3": "value3",
				"x-amz-meta-key4": "value4",
				"x-amz-meta-key5": "value5",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := profile.ValidateMetadataSize(tt.metadata)
			if tt.expectError && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestProviderProfile_ShouldCompact(t *testing.T) {
	tests := []struct {
		profile       *ProviderProfile
		metadata      map[string]string
		expectCompact bool
	}{
		{
			profile: &ProviderProfile{
				CompactionStrategy: "base64url",
			},
			metadata:      map[string]string{"key": "value"},
			expectCompact: true,
		},
		{
			profile: &ProviderProfile{
				CompactionStrategy: "none",
			},
			metadata:      map[string]string{"key": "value"},
			expectCompact: false,
		},
		{
			profile: &ProviderProfile{
				CompactionStrategy: "",
			},
			metadata:      map[string]string{"key": "value"},
			expectCompact: true, // Empty string is not "none", so should compact
		},
	}

	for _, tt := range tests {
		t.Run(tt.profile.CompactionStrategy, func(t *testing.T) {
			result := tt.profile.ShouldCompact(tt.metadata)
			if result != tt.expectCompact {
				t.Errorf("ShouldCompact() = %v, want %v", result, tt.expectCompact)
			}
		})
	}
}
