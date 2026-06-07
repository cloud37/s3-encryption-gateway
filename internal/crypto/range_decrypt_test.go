package crypto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
)

func TestRangeDecryptReader_Basic(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), "", nil, true, 16*1024) // 16KB chunks
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create test data that spans multiple chunks
	originalData := make([]byte, 50*1024) // 50KB
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	// Encrypt
	reader := bytes.NewReader(originalData)
	encryptedReader, metadata, err := engine.Encrypt(context.Background(), reader, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Update metadata with correct chunk count (manifest is encoded before encryption completes)
	expectedChunkCount := (len(originalData) + 16*1024 - 1) / (16 * 1024)
	metadata[MetaChunkCount] = fmt.Sprintf("%d", expectedChunkCount)
	// Update manifest in metadata
	manifest, _ := loadManifestFromMetadata(metadata)
	if manifest != nil {
		manifest.ChunkCount = expectedChunkCount
		manifestEncoded, err := encodeManifest(manifest)
		if err == nil {
			metadata[MetaManifest] = manifestEncoded
		}
	}

	// Test range decryption: bytes 10KB to 20KB
	plaintextStart := int64(10 * 1024)
	plaintextEnd := int64(20 * 1024)
	expectedRangeSize := plaintextEnd - plaintextStart + 1

	encryptedReader2 := bytes.NewReader(encryptedData)
	rangeReader, _, err := engine.(interface {
		DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
	}).DecryptRange(context.Background(), encryptedReader2, metadata, plaintextStart, plaintextEnd)

	if err != nil {
		t.Fatalf("Failed to decrypt range: %v", err)
	}

	decryptedRange, err := io.ReadAll(rangeReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted range: %v", err)
	}

	// Verify size
	if int64(len(decryptedRange)) != expectedRangeSize {
		t.Errorf("Range size = %d, expected %d", len(decryptedRange), expectedRangeSize)
	}

	// Verify content matches original
	expectedData := originalData[plaintextStart : plaintextEnd+1]
	if !bytes.Equal(decryptedRange, expectedData) {
		// Find first mismatch
		for i := 0; i < len(decryptedRange) && i < len(expectedData); i++ {
			if decryptedRange[i] != expectedData[i] {
				t.Errorf("Mismatch at offset %d: got %d, expected %d", i, decryptedRange[i], expectedData[i])
				break
			}
		}
		t.Error("Decrypted range does not match original")
	}
}

func TestRangeDecryptReader_EdgeCases(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	originalData := make([]byte, 32*1024) // Exactly 2 chunks
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	reader := bytes.NewReader(originalData)
	encryptedReader, metadata, err := engine.Encrypt(context.Background(), reader, nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Update metadata with correct chunk count
	expectedChunkCount := (len(originalData) + 16*1024 - 1) / (16 * 1024)
	metadata[MetaChunkCount] = fmt.Sprintf("%d", expectedChunkCount)
	manifest, _ := loadManifestFromMetadata(metadata)
	if manifest != nil {
		manifest.ChunkCount = expectedChunkCount
		manifestEncoded, _ := encodeManifest(manifest)
		metadata[MetaManifest] = manifestEncoded
	}

	testCases := []struct {
		name         string
		start        int64
		end          int64
		expectedSize int64
	}{
		{
			name:         "start of first chunk",
			start:        0,
			end:          1000,
			expectedSize: 1001,
		},
		{
			name:         "end of last chunk",
			start:        31 * 1024,
			end:          32*1024 - 1,
			expectedSize: 1024,
		},
		{
			name:         "across chunk boundary",
			start:        16*1024 - 100,
			end:          16*1024 + 100,
			expectedSize: 201,
		},
		{
			name:         "entire first chunk",
			start:        0,
			end:          16*1024 - 1,
			expectedSize: 16 * 1024,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encryptedReader3 := bytes.NewReader(encryptedData)
			rangeReader, _, err := engine.(interface {
				DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
			}).DecryptRange(context.Background(), encryptedReader3, metadata, tc.start, tc.end)

			if err != nil {
				t.Fatalf("Failed to decrypt range: %v", err)
			}

			decryptedRange, err := io.ReadAll(rangeReader)
			if err != nil {
				t.Fatalf("Failed to read decrypted range: %v", err)
			}

			if int64(len(decryptedRange)) != tc.expectedSize {
				t.Errorf("Range size = %d, expected %d", len(decryptedRange), tc.expectedSize)
			}

			// Verify content matches original
			if tc.end < int64(len(originalData)) {
				expectedData := originalData[tc.start : tc.end+1]
				if !bytes.Equal(decryptedRange, expectedData) {
					t.Error("Decrypted range does not match original")
				}
			}
		})
	}
}
