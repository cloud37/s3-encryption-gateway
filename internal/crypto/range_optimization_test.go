package crypto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
)

func TestCalculateChunkRangeFromPlaintext(t *testing.T) {
	tests := []struct {
		name                string
		plaintextStart      int64
		plaintextEnd        int64
		chunkSize           int
		totalChunks         int
		expectedStartChunk  int
		expectedEndChunk    int
		expectedStartOffset int
		expectedEndOffset   int
	}{
		{
			name:                "single chunk",
			plaintextStart:      100,
			plaintextEnd:        200,
			chunkSize:           1024,
			totalChunks:         10,
			expectedStartChunk:  0,
			expectedEndChunk:    0,
			expectedStartOffset: 100,
			expectedEndOffset:   200,
		},
		{
			name:                "span multiple chunks",
			plaintextStart:      1024,
			plaintextEnd:        3072,
			chunkSize:           1024,
			totalChunks:         10,
			expectedStartChunk:  1, // chunk 1 (bytes 1024-2047)
			expectedEndChunk:    3, // chunk 3 (bytes 3072-4095) - 3072 is start of chunk 3
			expectedStartOffset: 0,
			expectedEndOffset:   0,
		},
		{
			name:                "exact chunk boundary",
			plaintextStart:      2048,
			plaintextEnd:        4095,
			chunkSize:           1024,
			totalChunks:         10,
			expectedStartChunk:  2,
			expectedEndChunk:    3,
			expectedStartOffset: 0,
			expectedEndOffset:   1023,
		},
		{
			name:                "start at chunk boundary, end in middle",
			plaintextStart:      2048,
			plaintextEnd:        2500,
			chunkSize:           1024,
			totalChunks:         10,
			expectedStartChunk:  2,
			expectedEndChunk:    2,
			expectedStartOffset: 0,
			expectedEndOffset:   452,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startChunk, endChunk, startOffset, endOffset := calculateChunkRangeFromPlaintext(
				tt.plaintextStart,
				tt.plaintextEnd,
				tt.chunkSize,
				tt.totalChunks,
			)

			if startChunk != tt.expectedStartChunk {
				t.Errorf("startChunk = %d, expected %d", startChunk, tt.expectedStartChunk)
			}
			if endChunk != tt.expectedEndChunk {
				t.Errorf("endChunk = %d, expected %d", endChunk, tt.expectedEndChunk)
			}
			if startOffset != tt.expectedStartOffset {
				t.Errorf("startOffset = %d, expected %d", startOffset, tt.expectedStartOffset)
			}
			if endOffset != tt.expectedEndOffset {
				t.Errorf("endOffset = %d, expected %d", endOffset, tt.expectedEndOffset)
			}
		})
	}
}

func TestCalculateEncryptedByteRange(t *testing.T) {
	tests := []struct {
		name                   string
		startChunk             int
		endChunk               int
		chunkSize              int
		expectedEncryptedStart int64
		expectedEncryptedEnd   int64
		expectError            bool
	}{
		{
			name:                   "single chunk",
			startChunk:             0,
			endChunk:               0,
			chunkSize:              65536, // 64KB
			expectedEncryptedStart: 0,
			expectedEncryptedEnd:   65551, // 65536 + 16 - 1
			expectError:            false,
		},
		{
			name:                   "two chunks",
			startChunk:             0,
			endChunk:               1,
			chunkSize:              65536,
			expectedEncryptedStart: 0,
			expectedEncryptedEnd:   131103, // 2 * (65536 + 16) - 1
			expectError:            false,
		},
		{
			name:                   "multiple chunks",
			startChunk:             2,
			endChunk:               5,
			chunkSize:              65536,
			expectedEncryptedStart: 131104, // 2 * (65536 + 16)
			expectedEncryptedEnd:   393311, // (5+1) * (65536 + 16) - 1 = 6 * 65552 - 1
			expectError:            false,
		},
		{
			name:        "endChunk negative",
			startChunk:  0,
			endChunk:    -1,
			chunkSize:   65536,
			expectError: true,
		},
		{
			name:        "startChunk negative",
			startChunk:  -1,
			endChunk:    0,
			chunkSize:   65536,
			expectError: true,
		},
		{
			name:        "chunkSize near MaxInt32",
			startChunk:  0,
			endChunk:    1,
			chunkSize:   int(^uint(0) >> 1), // math.MaxInt
			expectError: true,
		},
		{
			name:        "endChunk near MaxInt32",
			startChunk:  0,
			endChunk:    int(^uint(0) >> 1), // math.MaxInt
			chunkSize:   65536,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encryptedStart, encryptedEnd, err := calculateEncryptedByteRange(
				tt.startChunk,
				tt.endChunk,
				tt.chunkSize,
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if encryptedStart != tt.expectedEncryptedStart {
				t.Errorf("encryptedStart = %d, expected %d", encryptedStart, tt.expectedEncryptedStart)
			}
			if encryptedEnd != tt.expectedEncryptedEnd {
				t.Errorf("encryptedEnd = %d, expected %d", encryptedEnd, tt.expectedEncryptedEnd)
			}
		})
	}
}

// TestCalculateEncryptedByteRangeOverflow specifically tests overflow conditions
// for V1.0-SEC-5: Integer Overflow in Encrypted Range Calculation
func TestCalculateEncryptedByteRangeOverflow(t *testing.T) {
	// Test that endChunk < 0 returns error (missing guard case)
	t.Run("endChunk negative", func(t *testing.T) {
		_, _, err := calculateEncryptedByteRange(0, -1, 65536)
		if err == nil {
			t.Error("expected error for negative endChunk, got nil")
		}
	})

	// Test that startChunk < 0 returns error
	t.Run("startChunk negative", func(t *testing.T) {
		_, _, err := calculateEncryptedByteRange(-1, 0, 65536)
		if err == nil {
			t.Error("expected error for negative startChunk, got nil")
		}
	})

	// Test endChunk > MaxInt32-1 returns error
	t.Run("endChunk exceeds safe limit", func(t *testing.T) {
		_, _, err := calculateEncryptedByteRange(0, int(^uint(0)>>1), 65536)
		if err == nil {
			t.Error("expected error for endChunk exceeding safe limit, got nil")
		}
	})

	// Test chunkSize > MaxInt32-tagSize returns error
	t.Run("chunkSize exceeds safe limit", func(t *testing.T) {
		_, _, err := calculateEncryptedByteRange(0, 1, int(^uint(0)>>1))
		if err == nil {
			t.Error("expected error for chunkSize exceeding safe limit, got nil")
		}
	})

	// Test that invalid range (end < start) returns error
	t.Run("endChunk less than startChunk", func(t *testing.T) {
		_, _, err := calculateEncryptedByteRange(5, 3, 65536)
		if err == nil {
			t.Error("expected error for endChunk < startChunk, got nil")
		}
	})

	// Test normal values still work correctly (regression test)
	t.Run("normal values produce correct results", func(t *testing.T) {
		start, end, err := calculateEncryptedByteRange(2, 5, 65536)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// 2 * (65536 + 16) = 131104
		if start != 131104 {
			t.Errorf("encryptedStart = %d, expected 131104", start)
		}
		// (5+1) * (65536 + 16) - 1 = 393311
		if end != 393311 {
			t.Errorf("encryptedEnd = %d, expected 393311", end)
		}
	})
}

func TestParseHTTPRangeHeader(t *testing.T) {
	tests := []struct {
		name          string
		rangeHeader   string
		totalSize     int64
		expectedStart int64
		expectedEnd   int64
		expectedErr   bool
	}{
		{
			name:          "valid range",
			rangeHeader:   "bytes=100-200",
			totalSize:     1000,
			expectedStart: 100,
			expectedEnd:   200,
			expectedErr:   false,
		},
		{
			name:          "open-ended range",
			rangeHeader:   "bytes=100-",
			totalSize:     1000,
			expectedStart: 100,
			expectedEnd:   999,
			expectedErr:   false,
		},
		{
			name:          "suffix range",
			rangeHeader:   "bytes=-100",
			totalSize:     1000,
			expectedStart: 900,
			expectedEnd:   999,
			expectedErr:   false,
		},
		{
			name:        "invalid format",
			rangeHeader: "invalid",
			totalSize:   1000,
			expectedErr: true,
		},
		{
			name:        "invalid range (out of bounds)",
			rangeHeader: "bytes=5000-6000",
			totalSize:   1000,
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := ParseHTTPRangeHeader(tt.rangeHeader, tt.totalSize)

			if tt.expectedErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if start != tt.expectedStart {
				t.Errorf("start = %d, expected %d", start, tt.expectedStart)
			}
			if end != tt.expectedEnd {
				t.Errorf("end = %d, expected %d", end, tt.expectedEnd)
			}
		})
	}
}

func TestGetPlaintextSizeFromMetadata(t *testing.T) {
	tests := []struct {
		name         string
		metadata     map[string]string
		expectedSize int64
		expectedErr  bool
	}{
		{
			name: "chunked format",
			metadata: map[string]string{
				MetaChunkCount: "10",
				MetaChunkSize:  "65536",
			},
			expectedSize: 655360, // 10 * 65536
			expectedErr:  false,
		},
		{
			name: "legacy format",
			metadata: map[string]string{
				MetaOriginalSize: "123456",
			},
			expectedSize: 123456,
			expectedErr:  false,
		},
		{
			name: "no size info",
			metadata: map[string]string{
				MetaEncrypted: "true",
			},
			expectedErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			size, err := GetPlaintextSizeFromMetadata(tt.metadata)

			if tt.expectedErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if size != tt.expectedSize {
				t.Errorf("size = %d, expected %d", size, tt.expectedSize)
			}
		})
	}
}

func TestCalculateEncryptedRangeForPlaintextRange(t *testing.T) {
	metadata := map[string]string{
		MetaManifest: encodeBase64([]byte(`{"v":1,"cs":65536,"cc":10,"iv":"dGVzdC1iYXNlLWl2"}`)),
	}

	// Create a proper manifest for the test
	manifest := &ChunkManifest{
		Version:    1,
		ChunkSize:  65536,
		ChunkCount: 10,
		BaseIV:     "dGVzdC1iYXNlLWl2",
	}
	manifestEncoded, _ := encodeManifest(manifest)
	metadata[MetaManifest] = manifestEncoded

	encryptedStart, encryptedEnd, err := CalculateEncryptedRangeForPlaintextRange(metadata, 65536, 131071)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should span chunks 1-1 (bytes 65536-131071 are in chunk 1)
	// Encrypted: chunk 1 = bytes (1 * (65536+16)) to ((1+1) * (65536+16) - 1)
	// = 65552 to 131103
	expectedStart := int64(65552) // chunk 1 start: 1 * 65552
	expectedEnd := int64(131103)  // chunk 1 end: 2 * 65552 - 1

	if encryptedStart != expectedStart {
		t.Errorf("encryptedStart = %d, expected %d", encryptedStart, expectedStart)
	}
	if encryptedEnd != expectedEnd {
		t.Errorf("encryptedEnd = %d, expected %d", encryptedEnd, expectedEnd)
	}
}

// TestRangeDecryptionEdgeCases covers all edge cases for range-optimized decryption
func TestRangeDecryptionEdgeCases(t *testing.T) {
	// Create test engine
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), "", nil, true, 16*1024) // 16KB chunks
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create test data that spans exactly 3 chunks (48KB total)
	originalData := make([]byte, 48*1024) // 48KB = 3 * 16KB chunks
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	// Encrypt the data
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
	expectedChunkCount := (len(originalData) + 16*1024 - 1) / (16 * 1024) // Should be 3
	metadata[MetaChunkCount] = fmt.Sprintf("%d", expectedChunkCount)
	manifest, _ := loadManifestFromMetadata(metadata)
	if manifest != nil {
		manifest.ChunkCount = expectedChunkCount
		manifestEncoded, err := encodeManifest(manifest)
		if err == nil {
			metadata[MetaManifest] = manifestEncoded
		}
	}

	// Define comprehensive test cases
	testCases := []struct {
		name           string
		plaintextStart int64
		plaintextEnd   int64
		expectedSize   int64
		expectError    bool
		description    string
	}{
		// First-byte ranges
		{
			name:           "first-byte-only",
			plaintextStart: 0,
			plaintextEnd:   0,
			expectedSize:   1,
			expectError:    false,
			description:    "single first byte of object",
		},
		{
			name:           "first-few-bytes",
			plaintextStart: 0,
			plaintextEnd:   99,
			expectedSize:   100,
			expectError:    false,
			description:    "first 100 bytes",
		},

		// Last-byte ranges
		{
			name:           "last-byte-only",
			plaintextStart: int64(len(originalData)) - 1,
			plaintextEnd:   int64(len(originalData)) - 1,
			expectedSize:   1,
			expectError:    false,
			description:    "single last byte of object",
		},
		{
			name:           "last-few-bytes",
			plaintextStart: int64(len(originalData)) - 100,
			plaintextEnd:   int64(len(originalData)) - 1,
			expectedSize:   100,
			expectError:    false,
			description:    "last 100 bytes",
		},

		// Suffix ranges (HTTP Range spec)
		{
			name:           "suffix-1-byte",
			plaintextStart: int64(len(originalData)) - 1,
			plaintextEnd:   int64(len(originalData)) - 1,
			expectedSize:   1,
			expectError:    false,
			description:    "suffix range equivalent to last 1 byte",
		},
		{
			name:           "suffix-100-bytes",
			plaintextStart: int64(len(originalData)) - 100,
			plaintextEnd:   int64(len(originalData)) - 1,
			expectedSize:   100,
			expectError:    false,
			description:    "suffix range equivalent to last 100 bytes",
		},

		// Cross-chunk boundary ranges
		{
			name:           "exact-chunk-boundary",
			plaintextStart: 16*1024 - 10, // 10 bytes before chunk 1 ends
			plaintextEnd:   16*1024 + 10, // 10 bytes into chunk 1
			expectedSize:   21,
			expectError:    false,
			description:    "range spanning exact chunk boundary",
		},
		{
			name:           "cross-multiple-chunks",
			plaintextStart: 16*1024 - 100,                              // within chunk 0
			plaintextEnd:   32*1024 + 100,                              // within chunk 2
			expectedSize:   int64(32*1024 + 100 - (16*1024 - 100) + 1), // 16585 bytes
			expectError:    false,
			description:    "range spanning chunks 0, 1, and 2",
		},
		{
			name:           "start-at-chunk-boundary",
			plaintextStart: 16 * 1024,            // exact start of chunk 1
			plaintextEnd:   16*1024 + 4*1024 - 1, // end of 4KB range
			expectedSize:   4 * 1024,
			expectError:    false,
			description:    "range starting exactly at chunk boundary",
		},
		{
			name:           "end-at-chunk-boundary",
			plaintextStart: 14 * 1024,
			plaintextEnd:   16*1024 - 1, // exact end of chunk 0
			expectedSize:   2 * 1024,
			expectError:    false,
			description:    "range ending exactly at chunk boundary",
		},

		// Empty ranges
		{
			name:           "empty-range-invalid",
			plaintextStart: 1000,
			plaintextEnd:   999,
			expectedSize:   0,
			expectError:    true,
			description:    "invalid range where start > end",
		},

		// Out-of-bounds clamping
		{
			name:           "out-of-bounds-start-negative",
			plaintextStart: -100,
			plaintextEnd:   1000,
			expectedSize:   0,
			expectError:    true,
			description:    "negative start should be clamped or rejected",
		},
		{
			name:           "out-of-bounds-end-too-large",
			plaintextStart: int64(len(originalData)) - 100,
			plaintextEnd:   int64(len(originalData)) + 1000, // beyond end
			expectedSize:   0,
			expectError:    true,
			description:    "end beyond object size should be clamped or rejected",
		},
		{
			name:           "entire-object",
			plaintextStart: 0,
			plaintextEnd:   int64(len(originalData)) - 1,
			expectedSize:   int64(len(originalData)),
			expectError:    false,
			description:    "full object range",
		},
		{
			name:           "middle-chunk-only",
			plaintextStart: 16 * 1024,   // start of chunk 1
			plaintextEnd:   32*1024 - 1, // end of chunk 1
			expectedSize:   16 * 1024,
			expectError:    false,
			description:    "exactly one middle chunk",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encryptedReader2 := bytes.NewReader(encryptedData)

			// Use the engine's DecryptRange method
			rangeReader, _, err := engine.(interface {
				DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
			}).DecryptRange(context.Background(), encryptedReader2, metadata, tc.plaintextStart, tc.plaintextEnd)

			if tc.expectError {
				if err == nil {
					t.Errorf("expected error for %s but got none", tc.description)
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to decrypt range: %v", err)
			}

			decryptedRange, err := io.ReadAll(rangeReader)
			if err != nil {
				t.Fatalf("failed to read decrypted range for %s: %v", tc.description, err)
			}

			// Verify size
			if int64(len(decryptedRange)) != tc.expectedSize {
				t.Errorf("%s: range size = %d, expected %d", tc.description, len(decryptedRange), tc.expectedSize)
			}

			// Verify content matches original (if valid range)
			if !tc.expectError && tc.expectedSize > 0 {
				expectedData := originalData[tc.plaintextStart : tc.plaintextStart+tc.expectedSize]
				if !bytes.Equal(decryptedRange, expectedData) {
					t.Errorf("%s: decrypted range does not match original data", tc.description)
					// Show first mismatch
					for i := 0; i < len(decryptedRange) && i < len(expectedData); i++ {
						if decryptedRange[i] != expectedData[i] {
							t.Errorf("first mismatch at offset %d: got %d, expected %d", i, decryptedRange[i], expectedData[i])
							break
						}
					}
				}
			}
		})
	}
}

// TestRangeDecryptionContentRangeMapping tests Content-Range header mapping
func TestRangeDecryptionContentRangeMapping(t *testing.T) {
	// Test the mapping between plaintext ranges and encrypted object sizes
	chunkSize := 16 * 1024
	totalChunks := 3
	totalPlaintextSize := int64(totalChunks * chunkSize)

	testCases := []struct {
		name                string
		plaintextStart      int64
		plaintextEnd        int64
		expectedStartChunk  int
		expectedEndChunk    int
		expectedStartOffset int
		expectedEndOffset   int
	}{
		{
			name:                "first-chunk-partial",
			plaintextStart:      1000,
			plaintextEnd:        2000,
			expectedStartChunk:  0,
			expectedEndChunk:    0,
			expectedStartOffset: 1000,
			expectedEndOffset:   2000,
		},
		{
			name:                "cross-chunk",
			plaintextStart:      int64(chunkSize - 100),
			plaintextEnd:        int64(chunkSize + 100),
			expectedStartChunk:  0,
			expectedEndChunk:    1,
			expectedStartOffset: chunkSize - 100,
			expectedEndOffset:   100,
		},
		{
			name:                "last-chunk-partial",
			plaintextStart:      totalPlaintextSize - 1000,
			plaintextEnd:        totalPlaintextSize - 1,
			expectedStartChunk:  2,
			expectedEndChunk:    2,
			expectedStartOffset: chunkSize - 1000,
			expectedEndOffset:   chunkSize - 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			startChunk, endChunk, startOffset, endOffset := calculateChunkRangeFromPlaintext(
				tc.plaintextStart,
				tc.plaintextEnd,
				chunkSize,
				totalChunks,
			)

			if startChunk != tc.expectedStartChunk {
				t.Errorf("startChunk = %d, expected %d", startChunk, tc.expectedStartChunk)
			}
			if endChunk != tc.expectedEndChunk {
				t.Errorf("endChunk = %d, expected %d", endChunk, tc.expectedEndChunk)
			}
			if startOffset != tc.expectedStartOffset {
				t.Errorf("startOffset = %d, expected %d", startOffset, tc.expectedStartOffset)
			}
			if endOffset != tc.expectedEndOffset {
				t.Errorf("endOffset = %d, expected %d", endOffset, tc.expectedEndOffset)
			}

			// Test encrypted range calculation
			encryptedStart, encryptedEnd, err := calculateEncryptedByteRange(startChunk, endChunk, chunkSize)
			if err != nil {
				t.Fatalf("calculateEncryptedByteRange failed: %v", err)
			}

			// Verify encrypted range covers the necessary chunks
			encryptedChunkSize := int64(chunkSize + tagSize)
			expectedEncryptedStart := int64(startChunk) * encryptedChunkSize
			expectedEncryptedEnd := int64(endChunk+1)*encryptedChunkSize - 1

			if encryptedStart != expectedEncryptedStart {
				t.Errorf("encryptedStart = %d, expected %d", encryptedStart, expectedEncryptedStart)
			}
			if encryptedEnd != expectedEncryptedEnd {
				t.Errorf("encryptedEnd = %d, expected %d", encryptedEnd, expectedEncryptedEnd)
			}
		})
	}
}

// TestRangeDecryptionAuthenticationVerification tests that authentication tags are properly verified
func TestRangeDecryptionAuthenticationVerification(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create test data
	originalData := make([]byte, 32*1024) // 2 chunks
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	// Encrypt the data
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
	metadata[MetaChunkSize] = fmt.Sprintf("%d", 16*1024)
	// Update manifest in metadata
	manifest, _ := loadManifestFromMetadata(metadata)
	if manifest != nil {
		manifest.ChunkCount = expectedChunkCount
		manifestEncoded, err := encodeManifest(manifest)
		if err == nil {
			metadata[MetaManifest] = manifestEncoded
		}
	}

	// Test successful range decryption (should verify auth tags correctly)
	plaintextStart := int64(1000)
	plaintextEnd := int64(2000)
	expectedSize := plaintextEnd - plaintextStart + 1

	rangeReader, _, err := engine.(interface {
		DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
	}).DecryptRange(context.Background(), bytes.NewReader(encryptedData), metadata, plaintextStart, plaintextEnd)

	if err != nil {
		t.Fatalf("Failed to create range reader: %v", err)
	}

	decryptedRange, err := io.ReadAll(rangeReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted range: %v", err)
	}

	if int64(len(decryptedRange)) != expectedSize {
		t.Errorf("Range size = %d, expected %d", len(decryptedRange), expectedSize)
	}

	// Verify content matches original
	expectedData := originalData[plaintextStart : plaintextStart+expectedSize]
	if !bytes.Equal(decryptedRange, expectedData) {
		t.Error("Decrypted range does not match original data")
	}

	// Test with corrupted encrypted data (should fail authentication)
	t.Run("corrupted-data-detection", func(t *testing.T) {
		corruptedData := make([]byte, len(encryptedData))
		copy(corruptedData, encryptedData)

		// Corrupt a byte in the middle of a chunk (not in auth tag)
		// Find a good spot to corrupt - avoid the auth tag at the end
		chunkSize := 16*1024 + tagSize    // 16KB + 16 bytes tag
		corruptOffset := chunkSize/2 + 10 // Middle of first chunk, avoid tag
		if corruptOffset < len(corruptedData) {
			corruptedData[corruptOffset] ^= 0xFF // Flip all bits
		}

		// Try to decrypt range - should fail due to auth tag verification
		rangeReader, _, err := engine.(interface {
			DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
		}).DecryptRange(context.Background(), bytes.NewReader(corruptedData), metadata, plaintextStart, plaintextEnd)

		if err != nil {
			// Should fail during range reader creation or reading
			return
		}

		// If no error during creation, try to read
		_, err = io.ReadAll(rangeReader)
		if err == nil {
			t.Error("Expected authentication verification to fail for corrupted data")
		}
	})
}

// TestRangeDecryptionChunkAlignment tests that only required chunks are processed
func TestRangeDecryptionChunkAlignment(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create test data spanning exactly 4 chunks (64KB total)
	originalData := make([]byte, 64*1024)
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	// Encrypt the data
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
	metadata[MetaChunkSize] = fmt.Sprintf("%d", 16*1024)
	// Update manifest in metadata
	manifest, _ := loadManifestFromMetadata(metadata)
	if manifest != nil {
		manifest.ChunkCount = expectedChunkCount
		manifestEncoded, err := encodeManifest(manifest)
		if err == nil {
			metadata[MetaManifest] = manifestEncoded
		}
	}

	// Test range that only needs chunks 1 and 2 (middle chunks)
	plaintextStart := int64(16*1024 + 1000) // Start in chunk 1
	plaintextEnd := int64(48*1024 - 1000)   // End in chunk 2
	expectedSize := plaintextEnd - plaintextStart + 1

	rangeReader, _, err := engine.(interface {
		DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
	}).DecryptRange(context.Background(), bytes.NewReader(encryptedData), metadata, plaintextStart, plaintextEnd)

	if err != nil {
		t.Fatalf("Failed to create range reader: %v", err)
	}

	decryptedRange, err := io.ReadAll(rangeReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted range: %v", err)
	}

	if int64(len(decryptedRange)) != expectedSize {
		t.Errorf("Range size = %d, expected %d", len(decryptedRange), expectedSize)
	}

	// Verify content matches original
	expectedData := originalData[plaintextStart : plaintextStart+expectedSize]
	if !bytes.Equal(decryptedRange, expectedData) {
		t.Error("Decrypted range does not match original data")
	}
}
