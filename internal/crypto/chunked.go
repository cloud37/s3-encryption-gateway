package crypto

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const (
	// Default chunk size for segmented encryption (64KB)
	// This balances memory usage with encryption overhead
	DefaultChunkSize = 64 * 1024

	// Minimum chunk size to ensure reasonable performance
	MinChunkSize = 16 * 1024 // 16KB

	// Maximum chunk size to prevent excessive memory usage
	MaxChunkSize = 1024 * 1024 // 1MB

	// Metadata key for chunked encryption format
	MetaChunkedFormat = "x-amz-meta-encryption-chunked"
	MetaChunkSize     = "x-amz-meta-encryption-chunk-size"
	MetaChunkCount    = "x-amz-meta-encryption-chunk-count"
	MetaManifest      = "x-amz-meta-encryption-manifest"
	MetaIVDerivation  = "x-amz-meta-enc-iv-deriv"
)

// ChunkManifest represents the encryption manifest for chunked objects.
// It stores the IV for each chunk, allowing decryption without reading
// the entire object first.
type ChunkManifest struct {
	Version      int      `json:"v"` // Format version (currently 1)
	ChunkSize    int      `json:"cs"` // Size of each chunk in bytes
	ChunkCount   int      `json:"cc"` // Number of chunks
	BaseIV       string   `json:"iv"` // Base64-encoded base IV (for IV derivation)
	IVs          []string `json:"ivs,omitempty"` // Optional: explicit IVs per chunk (if baseIV not used)
	IVDerivation string   `json:"ivd,omitempty"` // IV derivation method: "hkdf-sha256" or "" (legacy XOR)
}

// chunkedEncryptReader implements streaming encryption in chunks.
// Each chunk is encrypted independently with its own IV, allowing
// true streaming without buffering the entire object.
type chunkedEncryptReader struct {
	source       io.Reader
	aead         cipher.AEAD
	baseIV       []byte
	chunkSize    int
	buffer       []byte
	currentChunk []byte
	chunkIndex   int
	manifest     *ChunkManifest
	bufferPool   *BufferPool
	closed       bool
	err          error
	ctx          context.Context // Context for cancellation

	// Parallel processing
	parallel   bool
	pending    chan *cryptoJob // Channel of jobs in order
	workerPool chan struct{}   // Semaphore for concurrency control
	startOnce  sync.Once       // Ensure pipeline starts only once (on first Read)
	
	// Buffer management for recycling
	recycleBuf []byte
}

type cryptoJob struct {
	index  int
	input  []byte
	output []byte
	err    error
	done   chan struct{}
}

// newChunkedEncryptReader creates a new chunked encryption reader.
// It generates a base IV and derives per-chunk IVs deterministically.
func newChunkedEncryptReader(source io.Reader, aead cipher.AEAD, baseIV []byte, chunkSize int, bufferPool *BufferPool) (*chunkedEncryptReader, *ChunkManifest) {
	return newChunkedEncryptReaderWithContext(context.Background(), source, aead, baseIV, chunkSize, bufferPool)
}

// newChunkedEncryptReaderWithContext creates a new chunked encryption reader with context support.
// It generates a base IV and derives per-chunk IVs deterministically.
func newChunkedEncryptReaderWithContext(ctx context.Context, source io.Reader, aead cipher.AEAD, baseIV []byte, chunkSize int, bufferPool *BufferPool) (*chunkedEncryptReader, *ChunkManifest) {
	if chunkSize < MinChunkSize {
		chunkSize = MinChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}

	manifest := &ChunkManifest{
		Version:      1,
		ChunkSize:    chunkSize,
		BaseIV:       encodeBase64(baseIV),
		IVDerivation: "hkdf-sha256",
	}

	return &chunkedEncryptReader{
		source:       source,
		aead:         aead,
		baseIV:       baseIV,
		chunkSize:    chunkSize,
		buffer:       make([]byte, chunkSize),
		currentChunk: nil,
		chunkIndex:   0,
		manifest:     manifest,
		bufferPool:   bufferPool,
		ctx:          ctx,
		parallel:     true,
	}, manifest
}

// deriveChunkIVHKDF derives a per-chunk IV using HKDF-Expand(SHA-256).
// This is the recommended derivation method for all objects created from v1.0 onward.
func deriveChunkIVHKDF(baseIV []byte, chunkIndex int) []byte {
	info := make([]byte, 8+4)
	copy(info, "chunk-iv")
	binary.BigEndian.PutUint32(info[8:], uint32(chunkIndex)) // #nosec G115 — chunkIndex is bounded by object size / chunk size
	r := hkdf.Expand(sha256.New, baseIV, info)
	iv := make([]byte, len(baseIV))
	io.ReadFull(r, iv)
	return iv
}

func (r *chunkedEncryptReader) deriveChunkIV(chunkIndex int) []byte {
	return deriveChunkIVHKDF(r.baseIV, chunkIndex)
}

// Read implements io.Reader for chunked encryption.
// It reads from source, encrypts in chunks, and returns encrypted data.
func (r *chunkedEncryptReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.EOF
	}
	if r.err != nil {
		return 0, r.err
	}

	// Ensure pipeline is started
	r.startOnce.Do(r.startPipeline)

	// Check for context cancellation
	select {
	case <-r.ctx.Done():
		r.err = r.ctx.Err()
		return 0, r.err
	default:
	}

	totalRead := 0

	for len(p) > totalRead {
		// Check for context cancellation in the loop
		select {
		case <-r.ctx.Done():
			r.err = r.ctx.Err()
			if totalRead > 0 {
				return totalRead, nil // Return what we have so far
			}
			return 0, r.err
		default:
		}

		// If we have encrypted data in currentChunk, return it
		if len(r.currentChunk) > 0 {
			n := copy(p[totalRead:], r.currentChunk)
			r.currentChunk = r.currentChunk[n:]
			totalRead += n
			
			// If current chunk is fully consumed, recycle buffer
			if len(r.currentChunk) == 0 && r.recycleBuf != nil {
				if r.bufferPool != nil {
					r.bufferPool.Put(r.recycleBuf)
				}
				r.recycleBuf = nil
			}
			continue
		}

		// Get next job from pipeline
		job, ok := <-r.pending
		if !ok {
			// Pipeline closed (EOF from source)
			if totalRead > 0 {
				return totalRead, nil
			}
			r.closed = true
			return 0, io.EOF
		}

		// Wait for job to complete
		select {
		case <-job.done:
		case <-r.ctx.Done():
			r.err = r.ctx.Err()
			return totalRead, r.err
		}

		// Check job error
		if job.err != nil {
			r.err = job.err
			return totalRead, r.err
		}

		// Process successful job
		r.currentChunk = job.output
		r.manifest.ChunkCount++
		
		// Keep reference to original buffer for recycling
		// We only recycle if it came from pool (which we assume for now if pool exists)
		if r.bufferPool != nil {
			r.recycleBuf = job.output
		}
	}

	return totalRead, nil
}

func (r *chunkedEncryptReader) startPipeline() {
	concurrency := runtime.NumCPU()
	if concurrency < 2 {
		concurrency = 2
	}
	// Create buffered channel to hold pending jobs in order
	// Buffer size allows reading ahead while workers process
	r.pending = make(chan *cryptoJob, concurrency*2)
	r.workerPool = make(chan struct{}, concurrency)

	go r.feeder()
}

func (r *chunkedEncryptReader) feeder() {
	defer close(r.pending)

	chunkIdx := 0

	for {
		// Check context
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		// Allocate buffer
		var buf []byte
		if r.bufferPool != nil {
			buf = r.bufferPool.Get(r.chunkSize)
		} else {
			buf = make([]byte, r.chunkSize)
		}

		// Read chunk
		n, err := io.ReadFull(r.source, buf)
		
		// Handle read result
		if n > 0 {
			job := &cryptoJob{
				index: chunkIdx,
				input: buf[:n], // Slice to actual size
				done:  make(chan struct{}),
			}
			chunkIdx++

			// Send to pending queue (blocks if full, providing backpressure)
			select {
			case r.pending <- job:
			case <-r.ctx.Done():
				return
			}

			// Acquire worker (blocks if max concurrency reached)
			select {
			case r.workerPool <- struct{}{}:
			case <-r.ctx.Done():
				return
			}

			// Dispatch worker
			go func(j *cryptoJob, buffer []byte) {
				defer func() { <-r.workerPool }()
				defer close(j.done)

				// Reuse bufferPool for output to avoid allocation in Seal
				var outBuf []byte
				if r.bufferPool != nil {
					// We need chunk size + tag size
					// Seal appends, so we need capacity but length 0
					reqSize := len(j.input) + tagSize
					outBuf = r.bufferPool.Get(reqSize)
					outBuf = outBuf[:0]
				}
				
				j.output = r.encryptChunkParallel(j.index, j.input, outBuf)
				
				if r.bufferPool != nil {
					r.bufferPool.Put(buffer)
				}
			}(job, buf)
		}

		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				// Report error via a job
				job := &cryptoJob{
					err:  err,
					done: make(chan struct{}),
				}
				close(job.done)
				select {
				case r.pending <- job:
				case <-r.ctx.Done():
				}
			}
			return
		}
	}
}

// encryptChunkParallel encrypts a single chunk of plaintext.
// It is safe for concurrent use.
func (r *chunkedEncryptReader) encryptChunkParallel(index int, plaintext, outBuf []byte) []byte {
	if len(plaintext) == 0 {
		return nil
	}

	// Derive IV for this chunk
	chunkIV := r.deriveChunkIV(index)

	// Encrypt the chunk
	// Seal appends to dst. Use outBuf if provided.
	return r.aead.Seal(outBuf, chunkIV, plaintext, nil)
}

// Close finalizes the encryption and returns the manifest.
func (r *chunkedEncryptReader) Close() error {
	r.closed = true
	return nil
}


// chunkedDecryptReader implements streaming decryption from chunked format.
type chunkedDecryptReader struct {
	source       io.Reader
	aead         cipher.AEAD
	manifest     *ChunkManifest
	baseIV       []byte
	chunkSize    int
	buffer       []byte
	currentChunk []byte
	chunkIndex   int
	bufferPool   *BufferPool
	closed       bool
	err          error
	ctx          context.Context // Context for cancellation

	// Parallel processing
	parallel   bool
	pending    chan *cryptoJob
	workerPool chan struct{}
	startOnce  sync.Once
	
	// Buffer management for recycling
	recycleBuf []byte
}

// newChunkedDecryptReader creates a new chunked decryption reader.
func newChunkedDecryptReader(source io.Reader, aead cipher.AEAD, manifest *ChunkManifest, bufferPool *BufferPool) (*chunkedDecryptReader, error) {
	return newChunkedDecryptReaderWithContext(context.Background(), source, aead, manifest, bufferPool)
}

// newChunkedDecryptReaderWithContext creates a new chunked decryption reader with context support.
func newChunkedDecryptReaderWithContext(ctx context.Context, source io.Reader, aead cipher.AEAD, manifest *ChunkManifest, bufferPool *BufferPool) (*chunkedDecryptReader, error) {
	baseIV, err := decodeBase64(manifest.BaseIV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base IV: %w", err)
	}

	return &chunkedDecryptReader{
		source:       source,
		aead:         aead,
		manifest:     manifest,
		baseIV:       baseIV,
		chunkSize:    manifest.ChunkSize,
		buffer:       make([]byte, manifest.ChunkSize+tagSize), // Account for auth tag
		currentChunk: nil,
		chunkIndex:   0,
		bufferPool:   bufferPool,
		ctx:          ctx,
		parallel:     true,
	}, nil
}

// deriveChunkIV derives an IV for a specific chunk.
// If the manifest was written with the HKDF flag, HKDF derivation is used.
// Otherwise, the legacy XOR path is used for backward compatibility.
func (r *chunkedDecryptReader) deriveChunkIV(chunkIndex int) []byte {
	if r.manifest.IVDerivation == "hkdf-sha256" {
		return deriveChunkIVHKDF(r.baseIV, chunkIndex)
	}
	// Deprecated: used for objects without MetaIVDerivation flag. Remove no earlier than v3.0.
	iv := make([]byte, len(r.baseIV))
	copy(iv, r.baseIV)

	indexBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(indexBytes, uint32(chunkIndex)) // #nosec G115 — chunkIndex is bounded by object size / chunk size

	for i := 0; i < 4 && i < len(iv); i++ {
		iv[len(iv)-1-i] ^= indexBytes[3-i]
	}

	return iv
}

// Read implements io.Reader for chunked decryption.
func (r *chunkedDecryptReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, io.EOF
	}
	if r.err != nil {
		return 0, r.err
	}

	r.startOnce.Do(r.startPipeline)

	// Check for context cancellation
	select {
	case <-r.ctx.Done():
		r.err = r.ctx.Err()
		return 0, r.err
	default:
	}

	totalRead := 0

	for len(p) > totalRead {
		// Check for context cancellation in the loop
		select {
		case <-r.ctx.Done():
			r.err = r.ctx.Err()
			if totalRead > 0 {
				return totalRead, nil // Return what we have so far
			}
			return 0, r.err
		default:
		}

		// If we have decrypted data, return it
		if len(r.currentChunk) > 0 {
			n := copy(p[totalRead:], r.currentChunk)
			r.currentChunk = r.currentChunk[n:]
			totalRead += n
			
			// Recycle buffer if fully consumed
			if len(r.currentChunk) == 0 && r.recycleBuf != nil {
				if r.bufferPool != nil {
					r.bufferPool.Put(r.recycleBuf)
				}
				r.recycleBuf = nil
			}
			continue
		}

		// Get next job from pipeline
		job, ok := <-r.pending
		if !ok {
			// Pipeline closed (EOF from source)
			if totalRead > 0 {
				return totalRead, nil
			}
			r.closed = true
			return 0, io.EOF
		}

		// Wait for job to complete
		select {
		case <-job.done:
		case <-r.ctx.Done():
			r.err = r.ctx.Err()
			return totalRead, r.err
		}

		// Check job error
		if job.err != nil {
			r.err = job.err
			return totalRead, r.err
		}

		// Process successful job
		r.currentChunk = job.output

		// Store reference for recycling
		if r.bufferPool != nil {
			r.recycleBuf = job.output
		}
	}

	return totalRead, nil
}

func (r *chunkedDecryptReader) startPipeline() {
	concurrency := runtime.NumCPU()
	if concurrency < 2 {
		concurrency = 2
	}
	r.pending = make(chan *cryptoJob, concurrency*2)
	r.workerPool = make(chan struct{}, concurrency)
	go r.feeder()
}

func (r *chunkedDecryptReader) feeder() {
	defer close(r.pending)
	chunkIdx := 0

	for {
		select {
		case <-r.ctx.Done():
			return
		default:
		}

		// Allocate buffer for encrypted chunk
		// Needs to be chunkSize + tagSize
		expectedSize := r.chunkSize + tagSize
		var buf []byte
		if r.bufferPool != nil {
			buf = r.bufferPool.Get(expectedSize)
		} else {
			buf = make([]byte, expectedSize)
		}

		// Read encrypted chunk
		n, err := io.ReadFull(r.source, buf)

		if n > 0 {
			job := &cryptoJob{
				index: chunkIdx,
				input: buf[:n],
				done:  make(chan struct{}),
			}
			chunkIdx++

			select {
			case r.pending <- job:
			case <-r.ctx.Done():
				return
			}

			select {
			case r.workerPool <- struct{}{}:
			case <-r.ctx.Done():
				return
			}

			go func(j *cryptoJob, buffer []byte) {
				defer func() { <-r.workerPool }()
				defer close(j.done)

				// Reuse buffer for output? 
				// Decryption: Open(dst, nonce, ciphertext, additionalData)
				// If we use buffer pool for output, we avoid allocation
				var outBuf []byte
				if r.bufferPool != nil {
					// Decrypted size is input size - tag size
					reqSize := len(j.input) - tagSize
					if reqSize > 0 {
						outBuf = r.bufferPool.Get(reqSize)
						outBuf = outBuf[:0]
					}
				}

				var parallelErr error
				j.output, parallelErr = r.decryptChunkParallel(j.index, j.input, outBuf)
				if parallelErr != nil {
					j.err = fmt.Errorf("failed to decrypt chunk %d: %w", j.index, parallelErr)
				}

				if r.bufferPool != nil {
					r.bufferPool.Put(buffer)
				}
			}(job, buf)
		}

		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				job := &cryptoJob{
					err:  err,
					done: make(chan struct{}),
				}
				close(job.done)
				select {
				case r.pending <- job:
				case <-r.ctx.Done():
				}
			}
			return
		}
	}
}

// decryptChunkParallel decrypts a single chunk of ciphertext.
func (r *chunkedDecryptReader) decryptChunkParallel(index int, ciphertext, outBuf []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, nil
	}

	chunkIV := r.deriveChunkIV(index)
	return r.aead.Open(outBuf, chunkIV, ciphertext, nil)
}

// Close finalizes the decryption.
func (r *chunkedDecryptReader) Close() error {
	r.closed = true
	return nil
}

// encodeManifest encodes a chunk manifest to JSON for storage in metadata.
func encodeManifest(manifest *ChunkManifest) (string, error) {
	data, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("failed to encode manifest: %w", err)
	}
	return encodeBase64(data), nil
}

// decodeManifest decodes a chunk manifest from metadata.
func decodeManifest(encoded string) (*ChunkManifest, error) {
	data, err := decodeBase64(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	var manifest ChunkManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return &manifest, nil
}

// IsChunkedFormat checks if metadata indicates chunked encryption format.
// This is exported for use by handlers to optimize range requests.
func IsChunkedFormat(metadata map[string]string) bool {
	if metadata == nil {
		return false
	}
	return metadata[MetaChunkedFormat] == "true"
}

// isChunkedFormat is the internal version (kept for backward compatibility).
func isChunkedFormat(metadata map[string]string) bool {
	return IsChunkedFormat(metadata)
}

// loadManifestFromMetadata loads chunk manifest from object metadata.
func loadManifestFromMetadata(metadata map[string]string) (*ChunkManifest, error) {
	manifestEncoded, ok := metadata[MetaManifest]
	if !ok {
		return nil, fmt.Errorf("manifest not found in metadata")
	}

	return decodeManifest(manifestEncoded)
}
