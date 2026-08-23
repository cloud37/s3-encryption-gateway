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
	count := (plaintextSize-1)/int64(chunkSize) + 1
	if count < 0 {
		return 0, fmt.Errorf("chunk count overflow")
	}
	return uint64(count), nil
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
	if count > (uint64(math.MaxInt64)-uint64(ChunkedTerminalSize))/uint64(tagSize) {
		return 0, fmt.Errorf("chunked ciphertext size overflow")
	}
	overhead := count * uint64(tagSize)
	if version == ChunkedFormatV2 {
		if overhead > uint64(math.MaxInt64)-uint64(ChunkedTerminalSize) {
			return 0, fmt.Errorf("chunked ciphertext size overflow")
		}
		overhead += ChunkedTerminalSize
	}
	if overhead > uint64(math.MaxInt64) || plaintextSize > math.MaxInt64-int64(overhead) {
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
	unit := int64(chunkSize) + tagSize
	candidate := uint64(dataSize / unit) // #nosec G115 -- dataSize is non-negative
	if candidate == 0 {
		candidate = 1
	}
	for _, count := range []uint64{candidate, candidate + 1} {
		if count > uint64(math.MaxInt64/tagSize) {
			continue
		}
		plain := dataSize - int64(count*uint64(tagSize))
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
	unit := uint64(chunkSize) + uint64(tagSize) // #nosec G115 -- validateChunkSize requires a positive chunk size
	if endChunk == math.MaxUint64 || startChunk > uint64(math.MaxInt64)/unit || endChunk >= uint64(math.MaxInt64)/unit {
		return 0, 0, fmt.Errorf("encrypted range overflow")
	}
	start := startChunk * unit
	end := (endChunk+1)*unit - 1
	if end > uint64(math.MaxInt64) {
		return 0, 0, fmt.Errorf("encrypted range overflow")
	}
	return int64(start), int64(end), nil // #nosec G115 -- values are bounded by MaxInt64 above
}

// calculateEncryptedByteRange is retained for internal legacy callers. New
// code must use ChunkedEncryptedDataRange with an explicit format version.
func calculateEncryptedByteRange(startChunk, endChunk int, chunkSize int) (int64, int64, error) {
	if startChunk < 0 || endChunk < 0 {
		return 0, 0, fmt.Errorf("invalid chunk range")
	}
	return ChunkedEncryptedDataRange(uint64(startChunk), uint64(endChunk), chunkSize, ChunkedFormatV1)
}

// ChunkedEncryptedDataRangeForPlaintextSize returns a canonical data-only
// range, clipping the final record to its actual ciphertext length. This is
// required for v2 ranges ending in a short final plaintext chunk: the terminal
// record is never part of the returned range.
func ChunkedEncryptedDataRangeForPlaintextSize(startChunk, endChunk uint64, plaintextSize int64, chunkSize int, version uint8) (int64, int64, error) {
	count, err := ChunkedDataChunkCount(plaintextSize, chunkSize)
	if err != nil {
		return 0, 0, err
	}
	if count == 0 || startChunk > endChunk || endChunk >= count {
		return 0, 0, fmt.Errorf("invalid chunk range")
	}
	start, end, err := ChunkedEncryptedDataRange(startChunk, endChunk, chunkSize, version)
	if err != nil {
		return 0, 0, err
	}
	canonical, err := ChunkedCiphertextSize(plaintextSize, chunkSize, version)
	if err != nil {
		return 0, 0, err
	}
	dataEnd := canonical
	if version == ChunkedFormatV2 {
		dataEnd -= ChunkedTerminalSize
	}
	if end >= dataEnd {
		end = dataEnd - 1
	}
	return start, end, nil
}

func calculateChunkRangeFromPlaintext(plaintextStart, plaintextEnd int64, chunkSize int, totalChunks uint64) (startChunk, endChunk uint64, startOffset, endOffset int) {
	if chunkSize <= 0 || totalChunks <= 0 {
		return 0, 0, 0, 0
	}

	if plaintextStart < 0 || plaintextEnd < 0 {
		return 0, 0, 0, 0
	}
	startChunk = uint64(plaintextStart / int64(chunkSize)) // #nosec G115 -- negative offsets were rejected above
	endChunk = uint64(plaintextEnd / int64(chunkSize))     // #nosec G115 -- negative offsets were rejected above

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
			count, countErr := ChunkedDataChunkCount(plaintextSize, manifest.ChunkSize)
			if countErr == nil {
				manifest.ChunkCount = count
			}
		}
	}
	if manifest.ChunkCount == 0 || manifest.ChunkSize <= 0 {
		return 0, 0, fmt.Errorf("invalid chunked manifest")
	}

	// Calculate which chunks we need
	startChunk, endChunk, _, _ := calculateChunkRangeFromPlaintext(
		plaintextStart,
		plaintextEnd,
		manifest.ChunkSize,
		manifest.ChunkCount,
	)

	// Calculate a canonical encrypted data range. The helper clips a short
	// final record before the v2 terminal, so range GETs never fetch terminal
	// bytes as part of a data record.
	plaintextSize, sizeErr := GetPlaintextSizeFromMetadata(metadata)
	if sizeErr != nil {
		if manifest.ChunkCount == 0 || manifest.ChunkSize <= 0 || manifest.ChunkCount > uint64(math.MaxInt64)/uint64(manifest.ChunkSize) {
			return 0, 0, fmt.Errorf("failed to determine plaintext size: %w", sizeErr)
		}
		// Legacy manifests expose only a conservative upper bound. The caller
		// clamps this range to backend Content-Length before issuing the request.
		plaintextSize = int64(manifest.ChunkCount) * int64(manifest.ChunkSize) // #nosec G115 -- ChunkCount was bounded by MaxInt64 above
	}
	encryptedStart, encryptedEnd, err = ChunkedEncryptedDataRangeForPlaintextSize(startChunk, endChunk, plaintextSize, manifest.ChunkSize, version)
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
	// A present manifest is authoritative. When the backend supplies a stored
	// content length, the format equation is exact and must win over v1's legacy
	// original-size hint.
	if _, present := metadata[MetaManifest]; present {
		version, err := ChunkedFormatVersion(metadata)
		if err != nil {
			return 0, err
		}
		if ciphertext, ok := metadata["Content-Length"]; ok {
			size, parseErr := strconv.ParseInt(ciphertext, 10, 64)
			if parseErr != nil {
				return 0, fmt.Errorf("invalid ciphertext size")
			}
			manifest, manifestErr := loadManifestFromMetadata(metadata)
			if manifestErr != nil {
				return 0, manifestErr
			}
			plain, _, sizeErr := ChunkedPlaintextSize(size, manifest.ChunkSize, version)
			if sizeErr != nil {
				return 0, sizeErr
			}
			return plain, nil
		}
	}
	if original, ok := metadata[MetaOriginalSize]; ok {
		if size, parseErr := strconv.ParseInt(original, 10, 64); parseErr == nil && size >= 0 {
			return size, nil
		}
	}
	// Legacy metadata without a backend length can only provide an upper bound.
	// Preserve that compatibility hint with checked uint64 arithmetic; all
	// exact v1/v2 wire calculations use ChunkedPlaintextSize above.
	if countText, countOK := metadata[MetaChunkCount]; countOK {
		if sizeText, sizeOK := metadata[MetaChunkSize]; sizeOK {
			count, countErr := strconv.ParseUint(countText, 10, 64)
			chunkSize, sizeErr := strconv.ParseUint(sizeText, 10, 64)
			if countErr == nil && sizeErr == nil && count > 0 && chunkSize > 0 && count <= uint64(math.MaxInt64)/chunkSize {
				size := count * chunkSize
				return int64(size), nil // #nosec G115 -- size was bounded by MaxInt64 above
			}
		}
	}
	return 0, fmt.Errorf("exact plaintext size not available in metadata")
}
