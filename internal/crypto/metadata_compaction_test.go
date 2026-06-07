package crypto

import (
	"reflect"
	"testing"
)

func TestMetadataCompactor_CompactMetadata(t *testing.T) {
	profile := &ProviderProfile{
		Name:              "test",
		CompactionStrategy: "base64url",
	}

	compactor := NewMetadataCompactor(profile)

	originalMetadata := map[string]string{
		"Content-Type":                   "application/json",
		"x-amz-meta-user-key":            "user-value",
		MetaEncrypted:                   "true",
		MetaAlgorithm:                   "AES256-GCM",
		MetaKeySalt:                     "dGVzdC1zYWx0", // base64 "test-salt"
		MetaIV:                          "dGVzdC1pdg==", // base64 "test-iv"
		MetaOriginalSize:                "1024",
		MetaOriginalETag:                "abcd1234",
		MetaChunkedFormat:               "true",
		MetaChunkSize:                   "65536",
		MetaManifest:                    "dGVzdC1tYW5pZmVzdA==", // base64 "test-manifest"
	}

	compacted, err := compactor.CompactMetadata(originalMetadata)
	if err != nil {
		t.Fatalf("CompactMetadata failed: %v", err)
	}

	// Check that compacted metadata contains short keys
	expectedCompacted := map[string]string{
		"Content-Type":                   "application/json",
		"x-amz-meta-user-key":            "user-value",
		"x-amz-meta-e":                   "true",           // encrypted
		"x-amz-meta-a":                   "AES256-GCM",     // algorithm
		"x-amz-meta-s":                   "dGVzdC1zYWx0",   // salt
		"x-amz-meta-i":                   "dGVzdC1pdg==",   // iv
		"x-amz-meta-os":                  "1024",           // original size
		"x-amz-meta-oe":                  "abcd1234",       // original etag
		"x-amz-meta-c":                   "true",           // chunked
		"x-amz-meta-cs":                  "65536",          // chunk size
		"x-amz-meta-m":                   "dGVzdC1tYW5pZmVzdA==", // manifest
	}

	if !reflect.DeepEqual(compacted, expectedCompacted) {
		t.Errorf("CompactMetadata() = %v, want %v", compacted, expectedCompacted)
	}
}

func TestMetadataCompactor_ExpandMetadata(t *testing.T) {
	profile := &ProviderProfile{
		Name:              "test",
		CompactionStrategy: "base64url",
	}

	compactor := NewMetadataCompactor(profile)

	compactedMetadata := map[string]string{
		"Content-Type":                   "application/json",
		"x-amz-meta-user-key":            "user-value",
		"x-amz-meta-e":                   "true",           // encrypted
		"x-amz-meta-a":                   "AES256-GCM",     // algorithm
		"x-amz-meta-s":                   "dGVzdC1zYWx0",   // salt
		"x-amz-meta-i":                   "dGVzdC1pdg==",   // iv
		"x-amz-meta-os":                  "1024",           // original size
		"x-amz-meta-oe":                  "abcd1234",       // original etag
		"x-amz-meta-c":                   "true",           // chunked
		"x-amz-meta-cs":                  "65536",          // chunk size
		"x-amz-meta-m":                   "dGVzdC1tYW5pZmVzdA==", // manifest
	}

	expanded, err := compactor.ExpandMetadata(compactedMetadata)
	if err != nil {
		t.Fatalf("ExpandMetadata failed: %v", err)
	}

	// Check that expanded metadata contains full keys
	expectedExpanded := map[string]string{
		"Content-Type":                   "application/json",
		"x-amz-meta-user-key":            "user-value",
		MetaEncrypted:                   "true",
		MetaAlgorithm:                   "AES256-GCM",
		MetaKeySalt:                     "dGVzdC1zYWx0",
		MetaIV:                          "dGVzdC1pdg==",
		MetaOriginalSize:                "1024",
		MetaOriginalETag:                "abcd1234",
		MetaChunkedFormat:               "true",
		MetaChunkSize:                   "65536",
		MetaManifest:                    "dGVzdC1tYW5pZmVzdA==",
	}

	if !reflect.DeepEqual(expanded, expectedExpanded) {
		t.Errorf("ExpandMetadata() = %v, want %v", expanded, expectedExpanded)
	}
}

func TestMetadataCompactor_RoundTrip(t *testing.T) {
	profile := &ProviderProfile{
		Name:              "test",
		CompactionStrategy: "base64url",
	}

	compactor := NewMetadataCompactor(profile)

	originalMetadata := map[string]string{
		"Content-Type":                   "application/json",
		"x-amz-meta-user-key":            "user-value",
		MetaEncrypted:                   "true",
		MetaAlgorithm:                   "AES256-GCM",
		MetaKeySalt:                     "dGVzdC1zYWx0",
		MetaIV:                          "dGVzdC1pdg==",
		MetaOriginalSize:                "1024",
		MetaOriginalETag:                "abcd1234",
		MetaChunkedFormat:               "true",
		MetaChunkSize:                   "65536",
		MetaManifest:                    "dGVzdC1tYW5pZmVzdA==",
	}

	// Compact then expand
	compacted, err := compactor.CompactMetadata(originalMetadata)
	if err != nil {
		t.Fatalf("CompactMetadata failed: %v", err)
	}

	expanded, err := compactor.ExpandMetadata(compacted)
	if err != nil {
		t.Fatalf("ExpandMetadata failed: %v", err)
	}

	// Should be identical to original
	if !reflect.DeepEqual(expanded, originalMetadata) {
		t.Errorf("Round-trip failed: got %v, want %v", expanded, originalMetadata)
	}
}

func TestMetadataCompactor_NoCompaction(t *testing.T) {
	profile := &ProviderProfile{
		Name:              "test",
		CompactionStrategy: "none",
	}

	compactor := NewMetadataCompactor(profile)

	originalMetadata := map[string]string{
		"Content-Type":                   "application/json",
		MetaEncrypted:                   "true",
		MetaAlgorithm:                   "AES256-GCM",
	}

	compacted, err := compactor.CompactMetadata(originalMetadata)
	if err != nil {
		t.Fatalf("CompactMetadata failed: %v", err)
	}

	// Should be identical for no compaction
	if !reflect.DeepEqual(compacted, originalMetadata) {
		t.Errorf("No-compaction failed: got %v, want %v", compacted, originalMetadata)
	}

	expanded, err := compactor.ExpandMetadata(compacted)
	if err != nil {
		t.Fatalf("ExpandMetadata failed: %v", err)
	}

	// Should still be identical
	if !reflect.DeepEqual(expanded, originalMetadata) {
		t.Errorf("No-compaction expand failed: got %v, want %v", expanded, originalMetadata)
	}
}

func TestEstimateMetadataSize(t *testing.T) {
	metadata := map[string]string{
		"key1": "value1", // "key1: value1\r\n" = 14 bytes
		"key2": "value2", // "key2: value2\r\n" = 14 bytes
	}

	size := EstimateMetadataSize(metadata)
	expected := 14 + 14 // 28 bytes
	if size != expected {
		t.Errorf("EstimateMetadataSize() = %d, want %d", size, expected)
	}
}

func TestEncodeDecodeBase64URL(t *testing.T) {
	original := []byte("test data with special chars: !@#$%^&*()")

	encoded := encodeBase64URL(original)
	decoded, err := decodeBase64URL(encoded)
	if err != nil {
		t.Fatalf("decodeBase64URL failed: %v", err)
	}

	if !reflect.DeepEqual(decoded, original) {
		t.Errorf("Base64URL round-trip failed: got %v, want %v", decoded, original)
	}
}

// TestCompactNumericValue verifies the no-op compaction function.
func TestCompactNumericValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1024", "1024"},
		{"65536", "65536"},
		{"0", "0"},
		{"", ""},
	}

	for _, tc := range tests {
		got := CompactNumericValue(tc.input)
		if got != tc.want {
			t.Errorf("CompactNumericValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestExpandNumericValue verifies valid numeric strings are expanded correctly.
func TestExpandNumericValue(t *testing.T) {
	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"1024", "1024", false},
		{"65536", "65536", false},
		{"0", "0", false},
		{"-1", "-1", false},
		{"not-a-number", "", true},
		{"1.5", "", true},
	}

	for _, tc := range tests {
		got, err := ExpandNumericValue(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("ExpandNumericValue(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ExpandNumericValue(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
