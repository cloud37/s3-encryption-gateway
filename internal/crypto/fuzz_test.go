package crypto

import (
	"encoding/json"
	"testing"
)

// FuzzMetadataCompaction fuzzes the metadata compaction and expansion logic.
func FuzzMetadataCompaction(f *testing.F) {
	// Seed corpus
	seed1, _ := json.Marshal(map[string]string{"key": "value"})
	f.Add(seed1, "base64url")
	seed2, _ := json.Marshal(map[string]string{MetaEncrypted: "true", MetaAlgorithm: "AES256-GCM"})
	f.Add(seed2, "base64url")

	f.Fuzz(func(t *testing.T, data []byte, strategy string) {
		// Only support valid strategies
		if strategy != "base64url" && strategy != "none" {
			return
		}

		var metadata map[string]string
		if err := json.Unmarshal(data, &metadata); err != nil {
			return // invalid input
		}

		// Skip if empty
		if len(metadata) == 0 {
			return
		}

		profile := &ProviderProfile{
			Name:               "fuzz",
			CompactionStrategy: strategy,
			TotalHeaderLimit:   8192,
		}

		compactor := NewMetadataCompactor(profile)

		// Compact
		compacted, err := compactor.CompactMetadata(metadata)
		if err != nil {
			// Compaction errors are acceptable (e.g., if data invalid)
			return
		}

		// Expand
		expanded, err := compactor.ExpandMetadata(compacted)
		if err != nil {
			t.Errorf("failed to expand compacted metadata: %v", err)
		}

		// Verify round-trip for encryption metadata
		for k, v := range metadata {
			if IsEncryptionMetadata(k) {
				if gotV, ok := expanded[k]; !ok || gotV != v {
					// Special case: some keys might be normalized or dropped if empty
					if v == "" {
						continue 
					}
					t.Errorf("metadata mismatch for key %s: got %q, want %q", k, gotV, v)
				}
			}
		}
	})
}

// FuzzRangeCalculation fuzzes the chunk range calculation logic.
func FuzzRangeCalculation(f *testing.F) {
	f.Add(int64(0), int64(100), 1024, 10)
	f.Add(int64(1000), int64(2000), 1024, 10)
	f.Add(int64(5000), int64(6000), 1024, 5) // Out of bounds end

	f.Fuzz(func(t *testing.T, start, end int64, chunkSize, totalChunks int) {
		// Basic validation of inputs to match function expectations
		// The internal function expects non-negative ranges. 
		// DecryptRange validates this before calling.
		if chunkSize <= 0 || totalChunks <= 0 || start < 0 || end < 0 {
			return
		}

		// Call the function
		startChunk, endChunk, startOffset, endOffset := calculateChunkRangeFromPlaintext(start, end, chunkSize, totalChunks)

		// Invariants check
		
		// 1. Chunks should be within valid range [0, totalChunks-1]
		if startChunk < 0 || startChunk >= totalChunks {
			t.Errorf("startChunk %d out of bounds [0, %d)", startChunk, totalChunks)
		}
		if endChunk < 0 || endChunk >= totalChunks {
			t.Errorf("endChunk %d out of bounds [0, %d)", endChunk, totalChunks)
		}

		// 2. endChunk should be >= startChunk
		if endChunk < startChunk {
			t.Errorf("endChunk %d < startChunk %d", endChunk, startChunk)
		}

		// 3. Offsets should be within [0, chunkSize)
		if startOffset < 0 || startOffset >= chunkSize {
			t.Errorf("startOffset %d out of bounds [0, %d)", startOffset, chunkSize)
		}
		// End offset logic: int(plaintextEnd % int64(chunkSize))
		if endOffset < 0 || endOffset >= chunkSize {
			t.Errorf("endOffset %d out of bounds [0, %d)", endOffset, chunkSize)
		}
		
		// 4. Calculate encrypted range should not panic
		encStart, encEnd, err := calculateEncryptedByteRange(startChunk, endChunk, chunkSize)
		if err != nil {
			// Error is acceptable for invalid inputs (e.g., overflow conditions)
			return
		}
		if encStart < 0 {
			t.Errorf("encryptedStart negative: %d", encStart)
		}
		if encEnd < encStart {
			t.Errorf("encryptedEnd %d < encryptedStart %d", encEnd, encStart)
		}
	})
}

// FuzzParseHTTPRangeHeader fuzzes the HTTP Range header parser.
func FuzzParseHTTPRangeHeader(f *testing.F) {
	f.Add("bytes=0-100", int64(1000))
	f.Add("bytes=-100", int64(1000))
	f.Add("bytes=100-", int64(1000))
	f.Add("bytes=0-0", int64(1))

	f.Fuzz(func(t *testing.T, rangeHeader string, totalSize int64) {
		start, end, err := ParseHTTPRangeHeader(rangeHeader, totalSize)

		if err == nil {
			// If no error, range must be valid
			if totalSize > 0 {
				if start < 0 || start >= totalSize {
					t.Errorf("start %d out of bounds [0, %d)", start, totalSize)
				}
				if end < start || end >= totalSize {
					t.Errorf("end %d out of bounds [%d, %d)", end, start, totalSize)
				}
			} else {
				// If totalSize <= 0 (unknown), we can't validate upper bounds strictly,
				// but start should be >= 0
				if start < 0 {
					t.Errorf("start negative: %d", start)
				}
				if end < start {
					t.Errorf("end %d < start %d", end, start)
				}
			}
		}
	})
}

// FuzzMetadataParsing fuzzes metadata parsing functions.
func FuzzMetadataParsing(f *testing.F) {
	seed1, _ := json.Marshal(map[string]string{
		MetaChunkCount: "10",
		MetaChunkSize:  "1024",
	})
	f.Add(seed1)

	f.Fuzz(func(t *testing.T, data []byte) {
		var metadata map[string]string
		if err := json.Unmarshal(data, &metadata); err != nil {
			return
		}

		// Fuzz GetPlaintextSizeFromMetadata
		_, _ = GetPlaintextSizeFromMetadata(metadata)

		// Fuzz loadManifestFromMetadata via CalculateEncryptedRangeForPlaintextRange
		_, _, _ = CalculateEncryptedRangeForPlaintextRange(metadata, 0, 100)
	})
}
