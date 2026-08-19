package crypto

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	ChunkedFormatV1          uint8 = 1
	ChunkedFormatV2          uint8 = 2
	ChunkedTerminalSize            = 32
	chunkedTerminalPlainSize       = 16

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
// ErrUnsupportedChunkedVersion indicates a manifest version that this build cannot read.
var ErrUnsupportedChunkedVersion = errors.New("unsupported chunked format version")

// ErrChunkedObjectIncomplete indicates that authenticated object completeness could not be proven.
var ErrChunkedObjectIncomplete = errors.New("chunked object completeness check failed")

// ChunkedObjectInfo describes authenticated or inferred chunked object state.
type ChunkedObjectInfo struct {
	Version       uint8
	ChunkCount    uint64
	PlaintextSize uint64
	Authenticated bool
}

type ChunkManifest struct {
	Version      int      `json:"v"`             // Format version (currently 1)
	ChunkSize    int      `json:"cs"`            // Size of each chunk in bytes
	ChunkCount   uint64   `json:"cc"`            // Number of chunks
	BaseIV       string   `json:"iv"`            // Base64-encoded base IV (for IV derivation)
	IVs          []string `json:"ivs,omitempty"` // Optional: explicit IVs per chunk (if baseIV not used)
	IVDerivation string   `json:"ivd,omitempty"` // IV derivation method: "hkdf-sha256" or "" (legacy XOR)
}

// chunkedEncryptReader implements streaming encryption in chunks.
type chunkedEncryptReader struct {
	source       io.Reader
	aead         cipher.AEAD
	baseIV       []byte
	chunkSize    int
	manifest     *ChunkManifest
	bufferPool   *BufferPool
	ctx          context.Context
	version      uint8
	terminalAEAD cipher.AEAD
	index        uint64
	plainSize    uint64
	pending      []byte
	done         bool
	err          error
}

// newChunkedEncryptReader creates a legacy-compatible v1 reader.
func newChunkedEncryptReader(source io.Reader, aead cipher.AEAD, baseIV []byte, chunkSize int, bufferPool *BufferPool) (*chunkedEncryptReader, *ChunkManifest) {
	return newChunkedEncryptReaderV1(context.Background(), source, aead, baseIV, chunkSize, bufferPool)
}

func newChunkedEncryptReaderV1(ctx context.Context, source io.Reader, aead cipher.AEAD, baseIV []byte, chunkSize int, bufferPool *BufferPool) (*chunkedEncryptReader, *ChunkManifest) {
	return newChunkedEncryptReaderForVersion(ctx, source, aead, baseIV, chunkSize, bufferPool, ChunkedFormatV1, nil)
}

func newChunkedEncryptReaderV2(ctx context.Context, source io.Reader, aead cipher.AEAD, baseIV []byte, chunkSize int, bufferPool *BufferPool, version uint8, terminalAEAD cipher.AEAD) (*chunkedEncryptReader, *ChunkManifest, error) {
	if version != ChunkedFormatV2 {
		return nil, nil, fmt.Errorf("unsupported v2 chunked writer version: %d", version)
	}
	if terminalAEAD == nil {
		return nil, nil, fmt.Errorf("v2 chunked writer requires terminal AEAD")
	}
	reader, manifest := newChunkedEncryptReaderForVersion(ctx, source, aead, baseIV, chunkSize, bufferPool, version, terminalAEAD)
	return reader, manifest, nil
}

// newChunkedEncryptReaderWithContext is the plan-specified versioned entry
// point. The typed constructors remain the implementation-specific helpers.
func newChunkedEncryptReaderWithContext(ctx context.Context, source io.Reader, aead cipher.AEAD, terminalAEAD cipher.AEAD, baseIV []byte, chunkSize int, version uint8, bufferPool *BufferPool) (*chunkedEncryptReader, *ChunkManifest, error) {
	if version == ChunkedFormatV2 {
		if aead == nil {
			return nil, nil, fmt.Errorf("v2 chunked writer requires data AEAD")
		}
		return newChunkedEncryptReaderV2(ctx, source, aead, baseIV, chunkSize, bufferPool, version, terminalAEAD)
	}
	if version != ChunkedFormatV1 {
		return nil, nil, fmt.Errorf("unsupported chunked format version: %d", version)
	}
	reader, manifest := newChunkedEncryptReaderForVersion(ctx, source, aead, baseIV, chunkSize, bufferPool, version, nil)
	return reader, manifest, nil
}

func newChunkedEncryptReaderForVersion(ctx context.Context, source io.Reader, aead cipher.AEAD, baseIV []byte, chunkSize int, bufferPool *BufferPool, version uint8, terminalAEAD cipher.AEAD) (*chunkedEncryptReader, *ChunkManifest) {
	if chunkSize < MinChunkSize {
		chunkSize = MinChunkSize
	}
	if chunkSize > MaxChunkSize {
		chunkSize = MaxChunkSize
	}
	manifest := &ChunkManifest{Version: int(version), ChunkSize: chunkSize, BaseIV: encodeBase64(baseIV), IVDerivation: "hkdf-sha256"}
	return &chunkedEncryptReader{source: source, aead: aead, terminalAEAD: terminalAEAD, baseIV: baseIV, chunkSize: chunkSize, manifest: manifest, bufferPool: bufferPool, ctx: ctx, version: version}, manifest
}

// deriveChunkIVHKDF preserves the v1 wire format for legacy reads.
func deriveChunkIVHKDF(baseIV []byte, chunkIndex int) []byte {
	iv, _ := deriveChunkIVHKDFIndex(baseIV, uint64(chunkIndex))
	return iv
}

func deriveChunkIVHKDFIndex(baseIV []byte, chunkIndex uint64) ([]byte, error) {
	if chunkIndex > uint64(^uint32(0)) {
		return nil, fmt.Errorf("chunk index %d exceeds v1 wire limit", chunkIndex)
	}
	info := make([]byte, 12)
	copy(info, "chunk-iv")
	binary.BigEndian.PutUint32(info[8:], uint32(chunkIndex))
	r := hkdf.Expand(sha256.New, baseIV, info)
	iv := make([]byte, len(baseIV))
	if _, err := io.ReadFull(r, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func deriveLegacyChunkIVIndex(baseIV []byte, chunkIndex uint64) ([]byte, error) {
	if chunkIndex > uint64(^uint32(0)) {
		return nil, fmt.Errorf("chunk index %d exceeds v1 wire limit", chunkIndex)
	}
	iv := append([]byte(nil), baseIV...)
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], uint32(chunkIndex))
	for i := 0; i < 4 && i < len(iv); i++ {
		iv[len(iv)-1-i] ^= index[3-i]
	}
	return iv, nil
}

func (r *chunkedEncryptReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.done && len(r.pending) == 0 {
		return 0, io.EOF
	}
	written := 0
	for written < len(p) {
		if len(r.pending) > 0 {
			n := copy(p[written:], r.pending)
			r.pending = r.pending[n:]
			written += n
			continue
		}
		if r.done {
			break
		}
		select {
		case <-r.ctx.Done():
			r.err = r.ctx.Err()
			return written, r.err
		default:
		}
		buf := make([]byte, r.chunkSize)
		n, err := io.ReadFull(r.source, buf)
		if n > 0 {
			pt := buf[:n]
			var nonce []byte
			var aad []byte
			if r.version == ChunkedFormatV2 {
				nonce, r.err = deriveChunkNonceHKDF(r.baseIV, r.version, r.index)
				aad = buildChunkAAD(r.version, r.index)
			} else {
				nonce, r.err = deriveChunkIVHKDFIndex(r.baseIV, r.index)
				aad = nil
			}
			if r.err != nil {
				return written, r.err
			}
			r.pending = r.aead.Seal(nil, nonce, pt, aad)
			if uint64(n) > ^uint64(0)-r.plainSize {
				r.err = fmt.Errorf("plaintext size overflow")
				return written, r.err
			}
			r.plainSize += uint64(n)
			if r.index == ^uint64(0) {
				r.err = fmt.Errorf("chunk count overflow")
				return written, r.err
			}
			r.index++
			r.manifest.ChunkCount = r.index
			continue
		}
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			r.err = err
			return written, err
		}
		r.done = true
		if r.version == ChunkedFormatV2 {
			if r.terminalAEAD == nil {
				r.err = fmt.Errorf("terminal AEAD is not configured")
				return written, r.err
			}
			var nonce []byte
			nonce, r.err = deriveTerminalNonceHKDF(r.baseIV, r.version)
			if r.err == nil {
				terminal := encodeChunkedTerminal(r.index, r.plainSize)
				r.pending = r.terminalAEAD.Seal(nil, nonce, terminal[:], buildTerminalAAD(r.version))
			}
			if r.err != nil {
				return written, r.err
			}
		}
	}
	if written > 0 {
		return written, nil
	}
	if r.done {
		return 0, io.EOF
	}
	return 0, nil
}

func (r *chunkedEncryptReader) Close() error { r.done = true; return nil }

// chunkedDecryptReader verifies v1 data records and v2's authenticated terminal.
type chunkedDecryptReader struct {
	source       io.Reader
	aead         cipher.AEAD
	terminalAEAD cipher.AEAD
	manifest     *ChunkManifest
	baseIV       []byte
	chunkSize    int
	bufferPool   *BufferPool
	ctx          context.Context
	version      uint8
	index        uint64
	plainSize    uint64
	pending      []byte
	lookbehind   []byte
	done         bool
	err          error
}

func newChunkedDecryptReader(source io.Reader, aead cipher.AEAD, manifest *ChunkManifest, bufferPool *BufferPool) (*chunkedDecryptReader, error) {
	return newChunkedDecryptReaderV1(context.Background(), source, aead, manifest, bufferPool)
}

func newChunkedDecryptReaderV1(ctx context.Context, source io.Reader, aead cipher.AEAD, manifest *ChunkManifest, bufferPool *BufferPool) (*chunkedDecryptReader, error) {
	return newChunkedDecryptReaderForVersion(ctx, source, aead, manifest, bufferPool, nil)
}

func newChunkedDecryptReaderV2(ctx context.Context, source io.Reader, aead cipher.AEAD, manifest *ChunkManifest, bufferPool *BufferPool, terminalAEAD cipher.AEAD) (*chunkedDecryptReader, error) {
	if manifest == nil || uint8(manifest.Version) != ChunkedFormatV2 {
		return nil, fmt.Errorf("v2 chunked reader requires version 2 manifest")
	}
	if terminalAEAD == nil {
		return nil, fmt.Errorf("v2 chunked reader requires terminal AEAD")
	}
	return newChunkedDecryptReaderForVersion(ctx, source, aead, manifest, bufferPool, terminalAEAD)
}

// newChunkedDecryptReaderWithContext is the plan-specified versioned entry
// point for callers that already selected the terminal AEAD when needed.
func newChunkedDecryptReaderWithContext(ctx context.Context, source io.Reader, dataAEAD cipher.AEAD, terminalAEAD cipher.AEAD, manifest *ChunkManifest, bufferPool *BufferPool) (*chunkedDecryptReader, error) {
	if manifest != nil && manifest.Version == int(ChunkedFormatV2) {
		return newChunkedDecryptReaderV2(ctx, source, dataAEAD, manifest, bufferPool, terminalAEAD)
	}
	return newChunkedDecryptReaderV1(ctx, source, dataAEAD, manifest, bufferPool)
}

func newChunkedDecryptReaderForVersion(ctx context.Context, source io.Reader, aead cipher.AEAD, manifest *ChunkManifest, bufferPool *BufferPool, terminalAEAD cipher.AEAD) (*chunkedDecryptReader, error) {
	if manifest == nil {
		return nil, fmt.Errorf("missing chunk manifest")
	}
	if err := validateChunkedVersion(uint8(manifest.Version)); err != nil {
		return nil, err
	}
	baseIV, err := decodeBase64(manifest.BaseIV)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base IV: %w", err)
	}
	if uint8(manifest.Version) == ChunkedFormatV2 && terminalAEAD == nil {
		return nil, fmt.Errorf("v2 chunked reader requires terminal AEAD")
	}
	return &chunkedDecryptReader{source: source, aead: aead, terminalAEAD: terminalAEAD, manifest: manifest, baseIV: baseIV, chunkSize: manifest.ChunkSize, bufferPool: bufferPool, ctx: ctx, version: uint8(manifest.Version)}, nil
}

func (r *chunkedDecryptReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		if len(r.pending) > 0 {
			n := copy(p[written:], r.pending)
			r.pending = r.pending[n:]
			written += n
			continue
		}
		if r.done {
			break
		}
		select {
		case <-r.ctx.Done():
			r.err = r.ctx.Err()
			return written, r.err
		default:
		}

		buf := make([]byte, r.chunkSize+tagSize)
		n, err := io.ReadFull(r.source, buf)
		if r.version == ChunkedFormatV2 {
			if n > 0 {
				r.lookbehind = append(r.lookbehind, buf[:n]...)
			}
			for len(r.lookbehind) > ChunkedTerminalSize+r.chunkSize+tagSize {
				if err := r.decryptData(r.lookbehind[:r.chunkSize+tagSize]); err != nil {
					r.err = fmt.Errorf("%w: invalid data record: %v", ErrChunkedObjectIncomplete, err)
					return written, r.err
				}
				r.lookbehind = r.lookbehind[r.chunkSize+tagSize:]
			}
			if err == nil {
				continue
			}
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				r.err = err
				return written, err
			}
			if len(r.lookbehind) < ChunkedTerminalSize {
				r.err = fmt.Errorf("%w: missing or short terminal", ErrChunkedObjectIncomplete)
				return written, r.err
			}
			bodyLen := len(r.lookbehind) - ChunkedTerminalSize
			if bodyLen > 0 {
				if err := r.decryptData(r.lookbehind[:bodyLen]); err != nil {
					r.err = fmt.Errorf("%w: invalid data record: %v", ErrChunkedObjectIncomplete, err)
					return written, r.err
				}
			}
			if err := r.verifyTerminal(r.lookbehind[bodyLen:]); err != nil {
				r.err = err
				return written, err
			}
			r.lookbehind = nil
			r.done = true
			continue
		}
		if n > 0 {
			if err := r.decryptData(buf[:n]); err != nil {
				r.err = err
				return written, err
			}
			continue
		}
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			r.err = err
			return written, err
		}
		r.done = true
	}
	if written > 0 {
		return written, nil
	}
	return 0, io.EOF
}

func (r *chunkedDecryptReader) verifyTerminal(terminal []byte) error {
	if len(terminal) != ChunkedTerminalSize || r.terminalAEAD == nil {
		return fmt.Errorf("%w: missing or short terminal", ErrChunkedObjectIncomplete)
	}
	nonce, err := deriveTerminalNonceHKDF(r.baseIV, r.version)
	if err != nil {
		return err
	}
	plain, err := r.terminalAEAD.Open(nil, nonce, terminal, buildTerminalAAD(r.version))
	if err != nil {
		return fmt.Errorf("%w: terminal authentication failed: %v", ErrChunkedObjectIncomplete, err)
	}
	count, size, err := decodeChunkedTerminal(plain)
	if err != nil {
		return err
	}
	if count != r.index || size != r.plainSize {
		return fmt.Errorf("%w: terminal mismatch", ErrChunkedObjectIncomplete)
	}
	return nil
}

func (r *chunkedDecryptReader) decryptData(ciphertext []byte) error {
	var nonce []byte
	var aad []byte
	var err error
	if r.version == ChunkedFormatV2 {
		nonce, err = deriveChunkNonceHKDF(r.baseIV, r.version, r.index)
		aad = buildChunkAAD(r.version, r.index)
	} else {
		if r.manifest.IVDerivation == "hkdf-sha256" {
			nonce, err = deriveChunkIVHKDFIndex(r.baseIV, r.index)
		} else {
			nonce, err = deriveLegacyChunkIVIndex(r.baseIV, r.index)
		}
	}
	if err != nil {
		return err
	}
	pt, err := r.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return fmt.Errorf("failed to decrypt chunk %d: %w", r.index, err)
	}
	r.pending = append(r.pending, pt...)
	r.index++
	if uint64(len(pt)) > ^uint64(0)-r.plainSize {
		return fmt.Errorf("plaintext size overflow")
	}
	r.plainSize += uint64(len(pt))
	return nil
}
func (r *chunkedDecryptReader) Close() error { r.done = true; return nil }

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

// ChunkedFormatVersion returns the supported version from the encoded manifest.
func ChunkedFormatVersion(metadata map[string]string) (uint8, error) {
	manifest, err := loadManifestFromMetadata(metadata)
	if err != nil {
		return 0, err
	}
	switch manifest.Version {
	case int(ChunkedFormatV1), int(ChunkedFormatV2):
		return uint8(manifest.Version), nil
	default:
		return 0, ErrUnsupportedChunkedVersion
	}
}

func deriveChunkNonceHKDF(baseIV []byte, version uint8, chunkIndex uint64) ([]byte, error) {
	if version != ChunkedFormatV2 {
		return nil, ErrUnsupportedChunkedVersion
	}
	info := make([]byte, len("chunked-v2/data-nonce")+1+8)
	copy(info, "chunked-v2/data-nonce")
	info[len("chunked-v2/data-nonce")] = 0
	binary.BigEndian.PutUint64(info[len(info)-8:], chunkIndex)
	return readHKDFNonce(baseIV, info)
}

func deriveTerminalNonceHKDF(baseIV []byte, version uint8) ([]byte, error) {
	if version != ChunkedFormatV2 {
		return nil, ErrUnsupportedChunkedVersion
	}
	return readHKDFNonce(baseIV, []byte("chunked-v2/terminal-nonce\x00"))
}

func readHKDFNonce(baseIV, info []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(hkdf.New(sha256.New, baseIV, nil, info), nonce); err != nil {
		return nil, fmt.Errorf("derive chunk nonce: %w", err)
	}
	return nonce, nil
}

func buildChunkAAD(version uint8, chunkIndex uint64) []byte {
	if version != ChunkedFormatV2 {
		return nil
	}
	aad := make([]byte, len("chunked-v2/data")+1+8)
	copy(aad, "chunked-v2/data")
	aad[len("chunked-v2/data")] = 0
	binary.BigEndian.PutUint64(aad[len(aad)-8:], chunkIndex)
	return aad
}

func buildTerminalAAD(version uint8) []byte {
	if version != ChunkedFormatV2 {
		return nil
	}
	return []byte("chunked-v2/terminal\x00")
}

func encodeChunkedTerminal(chunkCount, plaintextSize uint64) [chunkedTerminalPlainSize]byte {
	var encoded [chunkedTerminalPlainSize]byte
	binary.BigEndian.PutUint64(encoded[:8], chunkCount)
	binary.BigEndian.PutUint64(encoded[8:], plaintextSize)
	return encoded
}

func decodeChunkedTerminal(plaintext []byte) (uint64, uint64, error) {
	if len(plaintext) != chunkedTerminalPlainSize {
		return 0, 0, fmt.Errorf("%w: invalid terminal length", ErrChunkedObjectIncomplete)
	}
	return binary.BigEndian.Uint64(plaintext[:8]), binary.BigEndian.Uint64(plaintext[8:]), nil
}
