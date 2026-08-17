package crypto

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// calculateChunkRangeFromPlaintext calculates which chunks contain a given plaintext byte range.
// Returns: startChunk, endChunk (inclusive), startOffsetInStartChunk, endOffsetInEndChunk
func validateChunkedVersion(version uint8) error {
	if version != ChunkedFormatV1 && version != ChunkedFormatV2 {
		return ErrUnsupportedChunkedVersion
	}
	return nil
}

func validateChunkSize(chunkSize int) error {
	if chunkSize > math.MaxInt-tagSize {
		return fmt.Errorf("invalid chunk size: %d", chunkSize)
	}
	if chunkSize <= 0 {
		return fmt.Errorf("invalid chunk size: %d", chunkSize)
	}
	return nil
}

// ChunkedDataChunkCount returns the number of authenticated data records.
func ChunkedDataChunkCount(plaintextSize int64, chunkSize int) (uint64, error) {
	if plaintextSize < 0 {
		return 0, fmt.Errorf("negative plaintext size")
	}
	if err := validateChunkSize(chunkSize); err != nil {
		return 0, err
	}
	if plaintextSize == 0 {
		return 0, nil
	}
	return uint64((plaintextSize-1)/int64(chunkSize) + 1), nil
}

// ChunkedCiphertextSize returns the canonical ciphertext size for a chunked object.
func ChunkedCiphertextSize(plaintextSize int64, chunkSize int, version uint8) (int64, error) {
	if err := validateChunkedVersion(version); err != nil {
		return 0, err
	}
	count, err := ChunkedDataChunkCount(plaintextSize, chunkSize)
	if err != nil {
		return 0, err
	}
	overhead := count * uint64(tagSize)
	if version == ChunkedFormatV2 {
		overhead += ChunkedTerminalSize
	}
	if overhead > uint64(math.MaxInt64) || uint64(plaintextSize) > uint64(math.MaxInt64)-overhead {
		return 0, fmt.Errorf("chunked ciphertext size overflow")
	}
	return plaintextSize + int64(overhead), nil
}

// ChunkedPlaintextSize reverses the canonical size equation and returns count too.
func ChunkedPlaintextSize(ciphertextSize int64, chunkSize int, version uint8) (int64, uint64, error) {
	if err := validateChunkedVersion(version); err != nil {
		return 0, 0, err
	}
	if ciphertextSize < 0 {
		return 0, 0, fmt.Errorf("negative ciphertext size")
	}
	overhead := int64(0)
	if version == ChunkedFormatV2 {
		overhead = ChunkedTerminalSize
	}
	if ciphertextSize < overhead {
		return 0, 0, fmt.Errorf("ciphertext shorter than terminal")
	}
	dataSize := ciphertextSize - overhead
	if dataSize == 0 {
		return 0, 0, nil
	}
	if err := validateChunkSize(chunkSize); err != nil {
		return 0, 0, err
	}
	if version == ChunkedFormatV2 && dataSize < int64(tagSize) {
		return 0, 0, fmt.Errorf("non-canonical chunked ciphertext size")
	}
	unit := uint64(chunkSize + tagSize)
	candidate := uint64(dataSize) / unit
	if candidate == 0 {
		candidate = 1
	}
	for _, count := range []uint64{candidate, candidate + 1} {
		if count > uint64(math.MaxInt64/tagSize) {
			continue
		}
		plain := dataSize - int64(count*tagSize)
		if plain < 0 {
			continue
		}
		actual, err := ChunkedDataChunkCount(plain, chunkSize)
		if err == nil && actual == count {
			return plain, count, nil
		}
	}
	return 0, 0, fmt.Errorf("non-canonical chunked ciphertext size")
}

// ChunkedEncryptedDataRange returns a terminal-exclusive inclusive byte range.
func ChunkedEncryptedDataRange(startChunk, endChunk uint64, chunkSize int, version uint8) (int64, int64, error) {
	if err := validateChunkedVersion(version); err != nil {
		return 0, 0, err
	}
	if err := validateChunkSize(chunkSize); err != nil {
		return 0, 0, err
	}
	if endChunk < startChunk {
		return 0, 0, fmt.Errorf("invalid chunk range")
	}
	unit := uint64(chunkSize) + tagSize
	if startChunk > uint64(math.MaxInt64)/unit || endChunk+1 > uint64(math.MaxInt64)/unit {
		return 0, 0, fmt.Errorf("encrypted range overflow")
	}
	start := startChunk * unit
	end := (endChunk+1)*unit - 1
	if end > uint64(math.MaxInt64) {
		return 0, 0, fmt.Errorf("encrypted range overflow")
	}
	return int64(start), int64(end), nil
}

func calculateChunkRangeFromPlaintext(plaintextStart, plaintextEnd int64, chunkSize int, totalChunks int) (startChunk, endChunk int, startOffset, endOffset int) {
	if chunkSize <= 0 || totalChunks <= 0 {
		return 0, 0, 0, 0
	}

	startChunk = int(plaintextStart / int64(chunkSize))
	endChunk = int(plaintextEnd / int64(chunkSize))

	// Clamp to valid range
	if startChunk >= totalChunks {
		startChunk = totalChunks - 1
	}
	if endChunk >= totalChunks {
		endChunk = totalChunks - 1
	}

	startOffset = int(plaintextStart % int64(chunkSize))
	endOffset = int(plaintextEnd % int64(chunkSize))

	return startChunk, endChunk, startOffset, endOffset
}

// calculateEncryptedByteRange calculates the byte range in encrypted data for given chunk indices.
// Each encrypted chunk = chunkSize + tagSize (16 bytes for GCM)
func calculateEncryptedByteRange(startChunk, endChunk int, chunkSize int) (encryptedStart, encryptedEnd int64, err error) {
	// Input validation guards
	if chunkSize <= 0 || startChunk < 0 || endChunk < 0 || endChunk < startChunk {
		return 0, 0, fmt.Errorf("invalid range parameters: chunkSize=%d, startChunk=%d, endChunk=%d", chunkSize, startChunk, endChunk)
	}

	// Pre-cast overflow detection: ensure intermediate int arithmetic won't overflow
	// before promotion to int64. These checks protect against integer overflow on
	// 32-bit platforms or when inputs are near math.MaxInt32.
	if endChunk > math.MaxInt32-1 {
		return 0, 0, fmt.Errorf("endChunk exceeds safe limit")
	}
	if chunkSize > math.MaxInt32-tagSize {
		return 0, 0, fmt.Errorf("chunkSize exceeds safe limit")
	}

	encryptedChunkSize := int64(chunkSize + tagSize)
	encryptedStart = int64(startChunk) * encryptedChunkSize
	encryptedEnd = int64(endChunk+1)*encryptedChunkSize - 1

	// Post-calculation sanity check: detect any overflow that may have occurred
	if encryptedEnd < encryptedStart {
		return 0, 0, fmt.Errorf("range calculation overflow")
	}

	return encryptedStart, encryptedEnd, nil
}

// CalculateEncryptedRangeForPlaintextRange calculates the encrypted byte range needed to satisfy a plaintext range request.
// This is used to optimize range requests by fetching only necessary encrypted chunks from S3.
func CalculateEncryptedRangeForPlaintextRange(metadata map[string]string, plaintextStart, plaintextEnd int64) (encryptedStart, encryptedEnd int64, err error) {
	// Load manifest
	manifest, err := loadManifestFromMetadata(metadata)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to load manifest: %w", err)
	}
	version, err := ChunkedFormatVersion(metadata)
	if err != nil {
		return 0, 0, err
	}

	// Backfill ChunkCount when the encrypt path left it at 0 (see engine.go
	// DecryptRange for rationale). Without this backfill, the range is
	// collapsed to 0-0 which triggers the fallback-to-full-decrypt path in
	// handleGetObject — defeating the point of range optimisation.
	if manifest.ChunkCount == 0 && manifest.ChunkSize > 0 {
		if plaintextSize, err2 := GetPlaintextSizeFromMetadata(metadata); err2 == nil && plaintextSize > 0 {
			manifest.ChunkCount = int((plaintextSize + int64(manifest.ChunkSize) - 1) / int64(manifest.ChunkSize))
		}
	}
	if manifest.ChunkCount <= 0 || manifest.ChunkSize <= 0 {
		return 0, 0, fmt.Errorf("invalid chunked manifest")
	}

	// Calculate which chunks we need
	startChunk, endChunk, _, _ := calculateChunkRangeFromPlaintext(
		plaintextStart,
		plaintextEnd,
		manifest.ChunkSize,
		manifest.ChunkCount,
	)

	// Calculate encrypted byte range for those chunks
	encryptedStart, encryptedEnd, err = ChunkedEncryptedDataRange(uint64(startChunk), uint64(endChunk), manifest.ChunkSize, version)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to calculate encrypted byte range: %w", err)
	}

	return encryptedStart, encryptedEnd, nil
}

// ParseHTTPRangeHeader parses an HTTP Range header and returns the plaintext byte range.
// Returns: start, end (inclusive), totalSize (if known), error
func ParseHTTPRangeHeader(rangeHeader string, totalSizeHint int64) (start, end int64, err error) {
	if len(rangeHeader) < 6 || rangeHeader[:6] != "bytes=" {
		return 0, 0, fmt.Errorf("invalid range header format")
	}

	rangeSpec := rangeHeader[6:]
	if len(rangeSpec) == 0 {
		return 0, 0, fmt.Errorf("invalid range format")
	}

	if rangeSpec[0] == '-' {
		// Suffix range: "-suffix" means last N bytes
		if totalSizeHint <= 0 {
			return 0, 0, fmt.Errorf("suffix range requires known total size")
		}
		suffix, err := strconv.ParseInt(rangeSpec[1:], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid suffix range: %w", err)
		}
		start = totalSizeHint - suffix
		if start < 0 {
			start = 0
		}
		end = totalSizeHint - 1
	} else {
		// Range: "start-end" or "start-"
		parts := strings.Split(rangeSpec, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Errorf("invalid range format")
		}

		var err error
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid start: %w", err)
		}

		if parts[1] == "" {
			if totalSizeHint <= 0 {
				return 0, 0, fmt.Errorf("open-ended range requires known total size")
			}
			end = totalSizeHint - 1
		} else {
			end, err = strconv.ParseInt(parts[1], 10, 64)
			if err != nil {
				return 0, 0, fmt.Errorf("invalid end: %w", err)
			}
		}
	}

	// Basic consistency check independent of total size
	if start < 0 {
		return 0, 0, fmt.Errorf("invalid range: start must be non-negative")
	}
	if end < start {
		return 0, 0, fmt.Errorf("invalid range: end must be >= start")
	}

	// Validate range against total size if known
	if totalSizeHint > 0 {
		if start >= totalSizeHint || end >= totalSizeHint {
			return 0, 0, fmt.Errorf("range not satisfiable: %d-%d (size: %d)", start, end, totalSizeHint)
		}
	}

	return start, end, nil
}

// GetPlaintextSizeFromMetadata extracts the approximate plaintext size from chunked metadata.
func GetPlaintextSizeFromMetadata(metadata map[string]string) (int64, error) {
	if original, ok := metadata[MetaOriginalSize]; ok {
		if size, parseErr := strconv.ParseInt(original, 10, 64); parseErr == nil && size >= 0 {
			return size, nil
		}
	}
	if version, err := ChunkedFormatVersion(metadata); err == nil {
		if ciphertext, ok := metadata["Content-Length"]; ok {
			if size, parseErr := strconv.ParseInt(ciphertext, 10, 64); parseErr == nil {
				plain, _, sizeErr := ChunkedPlaintextSize(size, mustChunkSize(metadata), version)
				if sizeErr == nil {
					return plain, nil
				}
			}
		}
		// Legacy callers often provide the original size but no canonical
		// backend length. It is still the best available range hint.
		if original, ok := metadata[MetaOriginalSize]; ok {
			if size, parseErr := strconv.ParseInt(original, 10, 64); parseErr == nil {
				return size, nil
			}
		}
	}
	chunkCountStr, ok1 := metadata[MetaChunkCount]
	chunkSizeStr, ok2 := metadata[MetaChunkSize]

	if !ok1 || !ok2 {
		// Try legacy format
		if sizeStr, ok := metadata[MetaOriginalSize]; ok {
			size, err := strconv.ParseInt(sizeStr, 10, 64)
			if err == nil {
				return size, nil
			}
		}
		return 0, fmt.Errorf("size information not found in metadata")
	}

	chunkCount, err1 := strconv.Atoi(chunkCountStr)
	chunkSize, err2 := strconv.Atoi(chunkSizeStr)

	if err1 != nil || err2 != nil {
		return 0, fmt.Errorf("invalid chunk count or size in metadata")
	}

	// Approximate: (chunkCount - 1) * chunkSize + chunkSize
	// Last chunk might be smaller, so this is an approximation
	size := int64((chunkCount-1)*chunkSize + chunkSize)
	return size, nil
}

func mustChunkSize(metadata map[string]string) int {
	size, _ := strconv.Atoi(metadata[MetaChunkSize])
	return size
}
