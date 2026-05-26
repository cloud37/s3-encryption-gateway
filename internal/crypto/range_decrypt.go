package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
)

// rangeDecryptReader decrypts only the chunks needed for a specific plaintext range.
// This optimizes range requests by skipping unnecessary chunks during decryption.
type rangeDecryptReader struct {
	source            io.Reader
	aead              cipher.AEAD
	manifest          *ChunkManifest
	baseIV            []byte
	chunkSize         int
	plaintextStart    int64
	plaintextEnd      int64
	startChunk        int
	endChunk           int
	startOffsetInChunk int
	endOffsetInChunk   int
	buffer             []byte
	currentChunk       []byte
	currentChunkIndex  int  // Absolute chunk index for IV derivation
	sourceChunkIndex   int  // Relative index in the source stream (0, 1, 2, ...)
	bytesReturned      int64
	bufferPool         *BufferPool
	closed             bool
	err                error
	isOptimized        bool // Whether source contains only needed chunks
}

// newRangeDecryptReader creates a decryption reader that only decrypts chunks needed for a range.
// If isOptimizedSource is true, the caller has already positioned the source at the first
// encrypted chunk; otherwise the reader is expected to start at chunk 0 and will be
// seeked forward by discarding startChunk*encryptedChunkSize bytes.
func newRangeDecryptReader(
	source io.Reader,
	aead cipher.AEAD,
	manifest *ChunkManifest,
	baseIV []byte,
	plaintextStart, plaintextEnd int64,
	bufferPool *BufferPool,
	isOptimizedSource bool,
) (*rangeDecryptReader, error) {
	// Calculate which chunks we need
	startChunk, endChunk, startOffset, endOffset := calculateChunkRangeFromPlaintext(
		plaintextStart,
		plaintextEnd,
		manifest.ChunkSize,
		manifest.ChunkCount,
	)

	// Validate range
	if startChunk < 0 || endChunk >= manifest.ChunkCount || startChunk > endChunk {
		return nil, fmt.Errorf("invalid chunk range: %d-%d (total chunks: %d)", startChunk, endChunk, manifest.ChunkCount)
	}

	// For non-optimized sources the reader starts at chunk 0; skip forward to
	// the first chunk we actually need.  When the caller has already applied a
	// backend byte-range (isOptimizedSource == true) the reader is already
	// positioned at startChunk and skipping would read past the start of the
	// partial stream.
	if !isOptimizedSource && startChunk > 0 {
		encryptedChunkSize := manifest.ChunkSize + tagSize
		skipBytes := int64(startChunk) * int64(encryptedChunkSize)
		skipped, err := io.CopyN(io.Discard, source, skipBytes)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("failed to skip to start chunk: %w", err)
		}
		if skipped < skipBytes {
			return nil, fmt.Errorf("unexpected EOF while skipping to chunk %d", startChunk)
		}
	}

	encryptedChunkSize := manifest.ChunkSize + tagSize

	return &rangeDecryptReader{
		source:             source,
		aead:               aead,
		manifest:           manifest,
		baseIV:             baseIV,
		chunkSize:          manifest.ChunkSize,
		plaintextStart:     plaintextStart,
		plaintextEnd:       plaintextEnd,
		startChunk:         startChunk,
		endChunk:           endChunk,
		startOffsetInChunk: startOffset,
		endOffsetInChunk:   endOffset,
		buffer:             make([]byte, encryptedChunkSize),
		currentChunk:       nil,
		currentChunkIndex:  startChunk, // Start from startChunk
		sourceChunkIndex:   0,
		bytesReturned:      0,
		bufferPool:         bufferPool,
		closed:             false,
		err:                nil,
		isOptimized:        isOptimizedSource,
	}, nil
}

// deriveChunkIV derives an IV for a specific chunk.
// If the manifest was written with the HKDF flag, HKDF derivation is used.
// Otherwise, the legacy XOR path is used for backward compatibility.
func (r *rangeDecryptReader) deriveChunkIV(chunkIndex int) []byte {
	if r.manifest.IVDerivation == "hkdf-sha256" {
		return deriveChunkIVHKDF(r.baseIV, chunkIndex)
	}
	// Deprecated: used for objects without MetaIVDerivation flag. Remove no earlier than v3.0.
	iv := make([]byte, len(r.baseIV))
	copy(iv, r.baseIV)

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, uint32(chunkIndex)) // #nosec G115 — chunkIndex bounded by object size / chunk size

	for i := 0; i < 4 && i < len(iv); i++ {
		iv[len(iv)-1-i] ^= indexBytes[3-i]
	}

	return iv
}

// Read implements io.Reader for range-aware chunked decryption.
func (r *rangeDecryptReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.EOF
	}
	if r.err != nil {
		return 0, r.err
	}

	totalRead := 0
	maxBytes := r.plaintextEnd - r.plaintextStart + 1

	for len(p) > totalRead && r.bytesReturned < maxBytes {
		// If we have decrypted data, return it
		if len(r.currentChunk) > 0 {
			remaining := maxBytes - r.bytesReturned
			toCopy := int64(len(r.currentChunk))
			if toCopy > remaining {
				toCopy = remaining
			}
			if int64(len(p)-totalRead) < toCopy {
				toCopy = int64(len(p) - totalRead)
			}

			n := copy(p[totalRead:], r.currentChunk[:toCopy])
			r.currentChunk = r.currentChunk[n:]
			totalRead += n
			r.bytesReturned += int64(n)

			if r.bytesReturned >= maxBytes {
				r.closed = true
				return totalRead, io.EOF
			}
			continue
		}

		// Check if we've processed all needed chunks
		if r.currentChunkIndex > r.endChunk {
			r.closed = true
			if totalRead > 0 {
				return totalRead, nil
			}
			return 0, io.EOF
		}

		// Read and decrypt next chunk
		encryptedChunkSize := r.chunkSize + tagSize

		// For last chunk in the source, it might be smaller
		var expectedSize int
		if r.currentChunkIndex == r.manifest.ChunkCount-1 {
			// Last chunk might be partial - read what we can
			expectedSize = encryptedChunkSize
		} else {
			expectedSize = encryptedChunkSize
		}

		n, err := io.ReadFull(r.source, r.buffer[:expectedSize])
		if err == io.EOF {
			if n == 0 {
				r.closed = true
				if totalRead > 0 {
					return totalRead, nil
				}
				return 0, io.EOF
			}
			// Partial read at end - try to decrypt
		} else if err != nil && err != io.ErrUnexpectedEOF {
			r.err = err
			return totalRead, err
		}

		// Decrypt the chunk
		chunkIV := r.deriveChunkIV(r.currentChunkIndex)
		plaintext, err := r.aead.Open(nil, chunkIV, r.buffer[:n], nil)
		if err != nil {
			r.err = fmt.Errorf("failed to decrypt chunk %d: %w", r.currentChunkIndex, err)
			return totalRead, r.err
		}

		// Extract the relevant portion of this chunk
		chunkData := plaintext
		if r.currentChunkIndex == r.startChunk {
			// First chunk: skip bytes before startOffset
			if r.startOffsetInChunk >= len(chunkData) {
				// Start offset is beyond this chunk, something's wrong
				r.err = fmt.Errorf("start offset %d exceeds chunk size %d", r.startOffsetInChunk, len(chunkData))
				return totalRead, r.err
			}
			chunkData = chunkData[r.startOffsetInChunk:]
		}
		if r.currentChunkIndex == r.endChunk {
			// Last chunk: only take bytes up to endOffset (inclusive)
			if r.endOffsetInChunk < len(chunkData) {
				chunkData = chunkData[:r.endOffsetInChunk+1]
			}
		}

		r.currentChunk = append(r.currentChunk, chunkData...)

		// Move to next chunk
		r.currentChunkIndex++
		r.sourceChunkIndex++
	}

	return totalRead, nil
}

// Close finalizes the decryption.
func (r *rangeDecryptReader) Close() error {
	r.closed = true
	return nil
}
