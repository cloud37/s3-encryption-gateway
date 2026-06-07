package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestEngine_MetadataFallback(t *testing.T) {
	// Create a provider profile with very small limits to force fallback
	profile := &ProviderProfile{
		Name:                "test-small-limits",
		UserMetadataLimit:   50, // Very small limit to force fallback
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    100, // Very small limit
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	encEngine, err := NewEngineWithProvider([]byte("test-password-123456789"), "", nil, "default")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Type assert to concrete engine type to access internal fields
	concreteEngine, ok := encEngine.(*engine)
	if !ok {
		t.Fatalf("Failed to type assert to concrete engine")
	}

	// Override the provider profile to use small limits
	concreteEngine.providerProfile = profile
	concreteEngine.compactor = NewMetadataCompactor(profile)

	// Create metadata that will exceed limits even when compacted
	largeMetadata := map[string]string{
		"Content-Type": "application/json",
		"x-amz-meta-very-long-user-metadata-key-that-exceeds-limits": "very-long-user-metadata-value-that-will-cause-header-overflow",
		"x-amz-meta-another-key":                                     "another-value",
		"x-amz-meta-third-key":                                       "third-value",
	}

	// Test data
	testData := []byte("Hello, World! This is test data for fallback mode.")

	// Encrypt - should use fallback mode
	reader := bytes.NewReader(testData)
	encryptedReader, encMetadata, err := encEngine.Encrypt(context.Background(), reader, largeMetadata)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Verify fallback mode was used
	if encMetadata[MetaFallbackMode] != "true" {
		t.Errorf("Expected fallback mode, but MetaFallbackMode != 'true'")
	}

	// Verify minimal metadata in headers
	if encMetadata[MetaEncrypted] != "true" {
		t.Errorf("Expected encrypted flag in headers")
	}
	if encMetadata[MetaAlgorithm] == "" {
		t.Errorf("Expected algorithm in headers")
	}
	if encMetadata[MetaKeySalt] == "" {
		t.Errorf("Expected key salt in headers")
	}

	// Read encrypted data
	encryptedData, err := ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Verify encrypted data is different
	if bytes.Equal(encryptedData, testData) {
		t.Errorf("Encrypted data should be different from plaintext")
	}

	// Decrypt
	decryptReader, decMetadata, err := encEngine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	// Read decrypted data
	decryptedData, err := ReadAll(decryptReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	// Verify data integrity
	if !bytes.Equal(decryptedData, testData) {
		t.Errorf("Decrypted data doesn't match original: got %q, want %q", decryptedData, testData)
	}

	// Verify metadata restoration
	if decMetadata["Content-Type"] != "application/json" {
		t.Errorf("Content-Type not restored: got %q", decMetadata["Content-Type"])
	}
	if decMetadata["x-amz-meta-very-long-user-metadata-key-that-exceeds-limits"] != "very-long-user-metadata-value-that-will-cause-header-overflow" {
		t.Errorf("User metadata not restored")
	}
}

func TestEngine_FallbackDetection(t *testing.T) {
	tests := []struct {
		name           string
		totalLimit     int
		metadata       map[string]string
		expectFallback bool
	}{
		{
			name:       "within limits",
			totalLimit: 1000,
			metadata: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectFallback: false,
		},
		{
			name:       "exceeds limits",
			totalLimit: 10,
			metadata: map[string]string{
				"x-amz-meta-very-long-key": "very-long-value",
			},
			expectFallback: true,
		},
		{
			name:       "unlimited provider",
			totalLimit: 0, // unlimited
			metadata: map[string]string{
				"x-amz-meta-very-long-key": "very-long-value",
			},
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &ProviderProfile{
				Name:                "test",
				UserMetadataLimit:   tt.totalLimit,
				SystemMetadataLimit: 0,
				TotalHeaderLimit:    tt.totalLimit,
				SupportsLongKeys:    true,
				CompactionStrategy:  "base64url",
			}

			encEngine, err := NewEngineWithProvider([]byte("test-password-123"), "", nil, "default")
			if err != nil {
				t.Fatalf("Failed to create engine: %v", err)
			}

			concreteEngine, ok := encEngine.(*engine)
			if !ok {
				t.Fatalf("Failed to type assert to concrete engine")
			}
			concreteEngine.providerProfile = profile
			concreteEngine.compactor = NewMetadataCompactor(profile)

			result := concreteEngine.needsMetadataFallback(tt.metadata)
			if result != tt.expectFallback {
				t.Errorf("needsMetadataFallback() = %v, want %v", result, tt.expectFallback)
			}
		})
	}
}

func TestEngine_IsFallbackMode(t *testing.T) {
	encEngine, err := NewEngine([]byte("test-password-123"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	concreteEngine, ok := encEngine.(*engine)
	if !ok {
		t.Fatalf("Failed to type assert to concrete engine")
	}

	tests := []struct {
		metadata       map[string]string
		expectFallback bool
	}{
		{
			metadata:       map[string]string{MetaFallbackMode: "true"},
			expectFallback: true,
		},
		{
			metadata:       map[string]string{MetaFallbackMode: "false"},
			expectFallback: false,
		},
		{
			metadata:       map[string]string{},
			expectFallback: false,
		},
		{
			metadata:       nil,
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		result := concreteEngine.isFallbackMode(tt.metadata)
		if result != tt.expectFallback {
			t.Errorf("isFallbackMode() = %v, want %v for metadata %v", result, tt.expectFallback, tt.metadata)
		}
	}
}

func TestMetadataJSONEncoding(t *testing.T) {
	original := map[string]string{
		"key1":            "value1",
		"key2":            "value2",
		"x-amz-meta-user": "data",
	}

	// Encode
	jsonData, err := encodeMetadataToJSON(original)
	if err != nil {
		t.Fatalf("encodeMetadataToJSON failed: %v", err)
	}

	// Decode
	decoded, err := decodeMetadataFromJSON(jsonData)
	if err != nil {
		t.Fatalf("decodeMetadataFromJSON failed: %v", err)
	}

	// Compare
	if len(decoded) != len(original) {
		t.Errorf("Length mismatch: got %d, want %d", len(decoded), len(original))
	}

	for k, v := range original {
		if decoded[k] != v {
			t.Errorf("Value mismatch for key %q: got %q, want %q", k, decoded[k], v)
		}
	}
}



// ReadAll is a helper to read all data from a reader (avoids import issues)
func ReadAll(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}
