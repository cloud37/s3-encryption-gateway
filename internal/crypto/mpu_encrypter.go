package crypto

import (
	"bytes"
	"context"
	"crypto/cipher"
	"fmt"
	"io"
	"sync"
)

const mpuAEADTagSize = 16 // AES-GCM and ChaCha20-Poly1305 authentication tag size

// mpuEncryptReader is a streaming io.Reader that encrypts an MPU part one AEAD
// chunk at a time. It never buffers more than one plaintext chunk
// (chunkSize bytes) plus one ciphertext chunk (chunkSize+tagSize bytes) at
// a time, regardless of part size.
//
// V0.6-PERF-1 Phase G: replaces the io.ReadAll+bytes.Buffer implementation in
// NewMPUPartEncryptReader. IVs are derived deterministically from
// (DEK, uploadIDHash, ivPrefix, partNumber, chunkIndex), so ciphertext output
// is byte-identical across retries for the same source — the SDK retry
// contract is preserved.
type mpuEncryptReader struct {
	src      io.Reader
	gcm      cipher.AEAD
	dek      []byte
	hash     [32]byte
	prefix   [12]byte
	part     uint32
	csz      int // chunk size (plaintext)

	// per-chunk state
	plainBuf []byte // pooled, cap=csz
	cipherBuf []byte // current chunk ciphertext output
	cipherOff int    // read position within cipherBuf
	chunkIdx  uint32

	// flow control
	srcDone bool // source exhausted
	eof     bool // all ciphertext consumed
	err     error
}

// plainChunkPool reuses per-chunk plaintext buffers to reduce GC pressure.
// The pool is keyed by DefaultChunkSize; callers using a different chunkSize
// allocate independently (uncommon in production).
var plainChunkPool = sync.Pool{New: func() any { return make([]byte, DefaultChunkSize) }}

// NewMPUPartEncryptReader creates a streaming encrypter for a single multipart
// upload part. It uses DeriveMultipartIV for each chunk so that IVs are
// deterministic across retries but unique across (upload, part, chunk) tuples.
//
// Returns the ciphertext reader and the exact byte length of the ciphertext.
// plainLen must be ≥ 0; when 0 (empty part) the reader immediately returns
// io.EOF. All callers in the gateway provide Content-Length via the
// x-amz-decoded-content-length or Content-Length header.
//
// V0.6-PERF-1 Phase G: fully streaming — peak heap per call is
// O(chunkSize + chunkSize+tagSize) regardless of part size.
func NewMPUPartEncryptReader(
	ctx context.Context,
	body io.Reader,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	partNumber int32,
	chunkSize int,
	plainLen int64,
	algorithm string,
) (io.Reader, int64, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	aead, err := createMPUAEADCipher(algorithm, dek)
	if err != nil {
		return nil, 0, err
	}
	tagSize := aead.Overhead()

	// Compute exact output length upfront so callers can set ContentLength.
	// Formula: every full chunk → chunkSize + tagSize bytes; if plainLen is
	// not an exact multiple of chunkSize, the final partial chunk adds
	// (rem + tagSize) bytes; empty part → 0.
	//
	// When plainLen == N * chunkSize exactly, there are N full chunks and no
	// trailing partial chunk — fullChunks × (chunkSize + tagSize) is the total.
	var encLen int64
	if plainLen > 0 {
		fullChunks := plainLen / int64(chunkSize)
		rem := plainLen % int64(chunkSize)
		encLen = fullChunks * int64(chunkSize+tagSize)
		if rem > 0 {
			// Trailing partial chunk.
			encLen += rem + int64(tagSize)
		}
	}

	// Get a pooled plaintext buffer when chunkSize matches the pool size.
	var plainBuf []byte
	if chunkSize == DefaultChunkSize {
		plainBuf = plainChunkPool.Get().([]byte)[:chunkSize]
	} else {
		plainBuf = make([]byte, chunkSize)
	}

	// Copy the DEK so that the caller's defer zeroBytes(dek) does not corrupt
	// IVs derived on subsequent Read calls (DeriveMultipartIV uses dek).
	// The copy is zeroed when the streaming reader is fully consumed or abandoned
	// via returnPlainBuf (which also zeros dekCopy — see Read/returnPlainBuf).
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)

	return &mpuEncryptReader{
		src:    body,
		gcm:    aead,
		dek:    dekCopy,
		hash:   uploadIDHash,
		prefix: ivPrefix,
		part:   uint32(partNumber), // #nosec G115 — S3 part number ≤ 10000, fits uint32
		csz:    chunkSize,

		plainBuf: plainBuf,
		srcDone:  plainLen == 0,
		eof:      plainLen == 0,
	}, encLen, nil
}

// Read implements io.Reader. It encrypts one AEAD chunk per source read,
// serving ciphertext bytes on demand.
func (r *mpuEncryptReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.eof {
		r.returnPlainBuf()
		return 0, io.EOF
	}

	total := 0
	for len(p) > 0 {
		// Serve from the current chunk's ciphertext buffer if available.
		if r.cipherOff < len(r.cipherBuf) {
			n := copy(p, r.cipherBuf[r.cipherOff:])
			r.cipherOff += n
			total += n
			p = p[n:]
			continue
		}

		// Need a new chunk.
		if r.srcDone {
			r.eof = true
			r.returnPlainBuf()
			if total > 0 {
				return total, nil
			}
			return 0, io.EOF
		}

		// Read one chunk from the source (may be short if near EOF).
		n, readErr := io.ReadFull(r.src, r.plainBuf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			r.err = fmt.Errorf("mpu_encrypter: read source: %w", readErr)
			r.returnPlainBuf()
			return total, r.err
		}
		if readErr == io.ErrUnexpectedEOF || readErr == io.EOF {
			// Short or empty read — this is the final (possibly partial) chunk.
			r.srcDone = true
			if n == 0 {
				// Source was already at EOF; no more chunks.
				r.eof = true
				r.returnPlainBuf()
				if total > 0 {
					return total, nil
				}
				return 0, io.EOF
			}
		}

		iv := DeriveMultipartIV(r.dek, r.hash, r.prefix, r.part, r.chunkIdx)
		r.cipherBuf = r.gcm.Seal(r.cipherBuf[:0], iv[:], r.plainBuf[:n], nil)
		r.cipherOff = 0
		r.chunkIdx++
	}
	return total, nil
}

// returnPlainBuf returns the pooled plaintext buffer and zeros the DEK copy.
// Called when the reader reaches EOF or an error — safe to call multiple times.
func (r *mpuEncryptReader) returnPlainBuf() {
	if r.plainBuf != nil && r.csz == DefaultChunkSize {
		for i := range r.plainBuf {
			r.plainBuf[i] = 0
		}
		plainChunkPool.Put(r.plainBuf)
		r.plainBuf = nil
	}
	// Zero the DEK copy we own so key material doesn't linger in heap.
	for i := range r.dek {
		r.dek[i] = 0
	}
}

// newMPUPartEncryptReader is the unexported alias used from within the api package via the exported function.
// Both names delegate to the same implementation.
func newMPUPartEncryptReader(
	ctx context.Context,
	body io.Reader,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	partNumber int32,
	chunkSize int,
	plainLen int64,
	algorithm string,
) (io.Reader, int64, error) {
	return NewMPUPartEncryptReader(ctx, body, dek, uploadIDHash, ivPrefix, partNumber, chunkSize, plainLen, algorithm)
}

// mpuDecryptReader is a streaming io.Reader that decrypts an MPU-encrypted
// S3 object one AEAD chunk at a time. It never buffers more than one chunk
// (at most ChunkSize+tagSize bytes) of ciphertext in memory, regardless of
// object size.
//
// Ownership of the underlying source reader is retained by the caller — the
// caller is responsible for closing it after the mpuDecryptReader is exhausted
// or abandoned.
type mpuDecryptReader struct {
	src          io.Reader
	manifest     *MultipartManifest
	dek          []byte
	uploadIDHash [32]byte
	ivPrefix     [12]byte
	gcm          cipher.AEAD

	// read state
	partIdx  int
	chunkIdx int32

	// plaintext chunk buffer; nil when empty
	buf    []byte
	bufOff int

	done bool
	err  error

	// reusable ciphertext read buffer (capacity = ChunkSize + tagSize)
	encBuf []byte
}

// encBufPool reuses per-chunk ciphertext buffers to reduce GC pressure.
// Capacity is ChunkSize + tagSize (DefaultChunkSize + 16 = 65552 bytes).
var encBufPool = sync.Pool{New: func() any { return make([]byte, DefaultChunkSize+mpuAEADTagSize) }}

// NewMPUDecryptReader returns a streaming io.Reader that decrypts the
// ciphertext produced by NewMPUPartEncryptReader for each part in order.
// Memory overhead is O(ChunkSize) — one chunk at a time — regardless of
// object size.
//
// The caller retains ownership of src and must close it after the reader
// is fully consumed.
func NewMPUDecryptReader(
	src io.Reader,
	manifest *MultipartManifest,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	algorithm string,
) (io.Reader, error) {
	if len(manifest.Parts) == 0 {
		return bytes.NewReader(nil), nil
	}
	aead, err := createMPUAEADCipher(algorithm, dek)
	if err != nil {
		return nil, err
	}
	// Copy the DEK so that the reader has sole ownership and can safely
	// zeroize it in returnEncBuf() without affecting the caller's slice.
	dekCopy := make([]byte, len(dek))
	copy(dekCopy, dek)

	return &mpuDecryptReader{
		src:          src,
		manifest:     manifest,
		dek:          dekCopy,
		uploadIDHash: uploadIDHash,
		ivPrefix:     ivPrefix,
		gcm:          aead,
		encBuf:       encBufPool.Get().([]byte),
	}, nil
}

// Read implements io.Reader. It decrypts one AEAD chunk per call to the
// underlying source, serving bytes from the chunk buffer until it's empty,
// then advancing to the next chunk.
func (r *mpuDecryptReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	for len(p) > 0 {
		// Serve from the plaintext buffer if available.
		if r.buf != nil && r.bufOff < len(r.buf) {
			n := copy(p, r.buf[r.bufOff:])
			r.bufOff += n
			if r.bufOff == len(r.buf) {
				r.buf = nil
				r.bufOff = 0
			}
			return n, nil
		}

		// Buffer exhausted — advance to next chunk.
		if r.done {
			r.returnEncBuf()
			return 0, io.EOF
		}
		if r.partIdx >= len(r.manifest.Parts) {
			r.done = true
			r.returnEncBuf()
			return 0, io.EOF
		}

		part := r.manifest.Parts[r.partIdx]
		if err := r.decryptNextChunk(part); err != nil {
			r.err = err
			r.returnEncBuf()
			return 0, err
		}
	}
	return len(p) - len(p), nil // unreachable but satisfies compiler
}

// decryptNextChunk reads the next encrypted chunk from src, authenticates it,
// and stores the plaintext in r.buf.
func (r *mpuDecryptReader) decryptNextChunk(part MPUPartRecord) error {
	isLastChunk := r.chunkIdx == part.ChunkCount-1

	var encSize int
	if isLastChunk {
		// Last chunk may be shorter than ChunkSize.
		lastPlainSize := part.PlainLen - int64(part.ChunkCount-1)*int64(r.manifest.ChunkSize)
		encSize = int(lastPlainSize) + mpuAEADTagSize
	} else {
		encSize = r.manifest.ChunkSize + mpuAEADTagSize
	}

	encChunk := r.encBuf[:encSize]
	if _, err := io.ReadFull(r.src, encChunk); err != nil {
		return fmt.Errorf("mpu_decrypt: part %d chunk %d: read: %w", part.PartNumber, r.chunkIdx, err)
	}

	iv := DeriveMultipartIV(r.dek, r.uploadIDHash, r.ivPrefix, uint32(part.PartNumber), uint32(r.chunkIdx)) // #nosec G115 — partNumber ≤ 10000, chunkIdx bounded by part size
	plain, err := r.gcm.Open(nil, iv[:], encChunk, nil)
	if err != nil {
		return fmt.Errorf("mpu_decrypt: part %d chunk %d auth failure: %w", part.PartNumber, r.chunkIdx, err)
	}

	r.buf = plain
	r.bufOff = 0

	// Advance position.
	r.chunkIdx++
	if r.chunkIdx >= part.ChunkCount {
		r.partIdx++
		r.chunkIdx = 0
	}
	if r.partIdx >= len(r.manifest.Parts) {
		r.done = true
	}
	return nil
}

func (r *mpuDecryptReader) returnEncBuf() {
	if r.encBuf != nil {
		encBufPool.Put(r.encBuf)
		r.encBuf = nil
	}
	// Zero DEK to prevent key material lingering in heap after the reader is done.
	for i := range r.dek {
		r.dek[i] = 0
	}
}

// DecryptMPUPartRange decrypts a consecutive run of chunks from a single MPU part.
// ciphertext must start at the first byte of chunk startChunkIdx — i.e. the caller
// must have requested the backend bytes starting from EncOffsetForPartChunk(part, startChunkIdx).
// All bytes in ciphertext are consumed (one or more chunks); authentication failure on
// any chunk returns an error with the chunk index, satisfying the tamper-detection requirement.
func DecryptMPUPartRange(
	ciphertext []byte,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	partNumber int32,
	chunkSize int,
	startChunkIdx int32,
	algorithm string,
) ([]byte, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	aead, err := createMPUAEADCipher(algorithm, dek)
	if err != nil {
		return nil, err
	}

	encChunkSize := chunkSize + aead.Overhead()
	var (
		out        []byte
		offset     int
		chunkIndex = uint32(startChunkIdx) // #nosec G115 — startChunkIdx ≤ total chunks (\u003c 2^32)
	)

	for offset < len(ciphertext) {
		end := offset + encChunkSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		encChunk := ciphertext[offset:end]
		iv := DeriveMultipartIV(dek, uploadIDHash, ivPrefix, uint32(partNumber), chunkIndex) // #nosec G115 — partNumber ≤ 10000, chunkIndex already uint32
		plain, err := aead.Open(nil, iv[:], encChunk, nil)
		if err != nil {
			return nil, fmt.Errorf("mpu_encrypter: chunk %d auth failure in part %d: %w", chunkIndex, partNumber, err)
		}
		out = append(out, plain...)
		offset = end
		chunkIndex++
	}
	return out, nil
}

// DecryptMPUPart decrypts a single MPU part. It reconstructs per-chunk IVs
// using DeriveMultipartIV and decrypts each chunk independently.
// Returns the plaintext bytes or an error if any chunk fails authentication.
func DecryptMPUPart(
	ciphertext []byte,
	dek []byte,
	uploadIDHash [32]byte,
	ivPrefix [12]byte,
	partNumber int32,
	chunkSize int,
	algorithm string,
) ([]byte, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}

	aead, err := createMPUAEADCipher(algorithm, dek)
	if err != nil {
		return nil, err
	}

	encChunkSize := chunkSize + aead.Overhead()
	var (
		out        []byte
		chunkIndex uint32
		offset     int
	)

	for offset < len(ciphertext) {
		end := offset + encChunkSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}
		encChunk := ciphertext[offset:end]
		iv := DeriveMultipartIV(dek, uploadIDHash, ivPrefix, uint32(partNumber), chunkIndex) // #nosec G115 — partNumber ≤ 10000, chunkIndex already uint32
		plain, err := aead.Open(nil, iv[:], encChunk, nil)
		if err != nil {
			return nil, fmt.Errorf("mpu_encrypter: chunk %d auth failure in part %d: %w", chunkIndex, partNumber, err)
		}
		out = append(out, plain...)
		offset = end
		chunkIndex++
	}
	return out, nil
}

// createMPUAEADCipher creates an AEAD cipher for the given MPU algorithm string.
// It normalises the legacy bare-string alias "AES256GCM" (no hyphen) to the
// canonical constant AlgorithmAES256GCM so that objects created before
// V1.0-SEC-25 continue to decrypt.  An empty algorithm defaults to AES-256-GCM.
func createMPUAEADCipher(algorithm string, key []byte) (cipher.AEAD, error) {
	if algorithm == "" {
		algorithm = AlgorithmAES256GCM
	}
	if algorithm == "AES256GCM" {
		algorithm = AlgorithmAES256GCM
	}
	c, err := createAEADCipher(algorithm, key)
	if err != nil {
		return nil, fmt.Errorf("mpu_encrypter: create AEAD for algorithm %s: %w", algorithm, err)
	}
	return c, nil
}
