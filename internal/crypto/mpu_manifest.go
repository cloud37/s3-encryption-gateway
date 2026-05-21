package crypto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	// mpuManifestVersion is the current version of the MultipartManifest JSON format.
	mpuManifestVersion = 1

	// mpuInlineLimit is the maximum byte size for an inline manifest in S3 metadata.
	// AWS limits x-amz-meta-* headers to 2 KiB total; we use 1.8 KiB to leave ~200 B
	// headroom for other metadata keys.
	mpuInlineLimit = 1800
)

// MPUPartRecord records per-part encryption metadata needed to decrypt an
// uploaded part and to reconstruct plaintext byte offsets during range GETs.
type MPUPartRecord struct {
	// PartNumber is the S3 part number (1-indexed, 1–10000).
	PartNumber int32 `json:"pn"`
	// ETag is the backend ETag returned by UploadPart.
	ETag string `json:"etag"`
	// PlainLen is the number of plaintext bytes in this part.
	PlainLen int64 `json:"plain_len"`
	// EncLen is the number of backend bytes for this part
	// (PlainLen + chunkCount * tagSize).
	EncLen int64 `json:"enc_len"`
	// ChunkCount is the number of AEAD chunks in this part.
	ChunkCount int32 `json:"chunks"`
}

// MultipartManifest stores the encryption parameters needed to decrypt a
// completed multipart upload. It is serialised as JSON and stored either
// inline in x-amz-meta-encryption-mpu or as a fallback companion object.
type MultipartManifest struct {
	// Version is the manifest format version; currently always 1.
	Version int `json:"v"`
	// Algorithm is the AEAD algorithm (e.g. "AES256GCM").
	Algorithm string `json:"alg"`
	// ChunkSize is the plaintext chunk size used for every part (bytes).
	ChunkSize int `json:"cs"`
	// IVPrefix is the base64url-encoded 12-byte random prefix used for IV
	// derivation. Combined with part+chunk indices via HKDF to produce each
	// chunk's GCM nonce.
	IVPrefix string `json:"iv_prefix"`
	// UploadIDHash is the base64url-encoded sha256(uploadID), used as the HKDF
	// salt during IV derivation.
	UploadIDHash string `json:"uid_hash"`
	// WrappedDEK is the base64url-encoded KMS-wrapped Data Encryption Key.
	WrappedDEK string `json:"wrapped_dek"`
	// KMSKeyID identifies the wrapping key in the KMS.
	KMSKeyID string `json:"kms_key_id,omitempty"`
	// KMSProvider identifies the KMS provider (e.g. "cosmian-kmip", "aws-kms").
	KMSProvider string `json:"kms_provider,omitempty"`
	// KMSKeyVersion is the wrapping key version at the time of DEK wrap.
	KMSKeyVersion int `json:"kms_key_ver,omitempty"`
	// Parts lists each uploaded part in ascending PartNumber order.
	Parts []MPUPartRecord `json:"parts"`
	// OriginalETag is the ETag of the plaintext content (MD5 of plaintext data,
	// or ETag-of-ETags computed by the gateway).
	OriginalETag string `json:"orig_etag,omitempty"`
	// TotalPlainSize is the sum of all parts' PlainLen values.
	TotalPlainSize int64 `json:"total_plain"`
}

// Marshal serialises the manifest to JSON.
func (m *MultipartManifest) Marshal() ([]byte, error) {
	return json.Marshal(m)
}

// MarshalBase64 serialises the manifest to base64url-encoded JSON (for metadata values).
func (m *MultipartManifest) MarshalBase64() (string, error) {
	b, err := m.Marshal()
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// FitsInline reports whether the JSON representation of the manifest fits
// within limit bytes (suitable for inline S3 metadata storage).
func (m *MultipartManifest) FitsInline(limit int) bool {
	b, err := m.Marshal()
	if err != nil {
		return false
	}
	return len(b) <= limit
}

// FitsInlineDefault reports whether the manifest fits within the standard 1.8 KiB limit.
func (m *MultipartManifest) FitsInlineDefault() bool {
	return m.FitsInline(mpuInlineLimit)
}

// UnmarshalMultipartManifest deserialises a MultipartManifest from JSON bytes.
func UnmarshalMultipartManifest(data []byte) (*MultipartManifest, error) {
	var m MultipartManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("mpu_manifest: unmarshal: %w", err)
	}
	if m.Version != mpuManifestVersion {
		return nil, fmt.Errorf("mpu_manifest: unsupported version %d (want %d)", m.Version, mpuManifestVersion)
	}
	return &m, nil
}

// UnmarshalMultipartManifestBase64 deserialises from a base64url-encoded string.
func UnmarshalMultipartManifestBase64(s string) (*MultipartManifest, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("mpu_manifest: base64 decode: %w", err)
	}
	return UnmarshalMultipartManifest(b)
}

// PlainOffsetToPartChunk translates a plaintext byte offset into the part
// number, chunk index within that part, and intra-chunk byte offset.
// Returns an error if offset is out of range.
func (m *MultipartManifest) PlainOffsetToPartChunk(offset int64) (partIdx int, chunkIdx int32, intraChunk int64, err error) {
	if offset < 0 || offset >= m.TotalPlainSize {
		return 0, 0, 0, fmt.Errorf("mpu_manifest: offset %d out of range [0, %d)", offset, m.TotalPlainSize)
	}
	var cumPlain int64
	for i, part := range m.Parts {
		if offset < cumPlain+part.PlainLen {
			relOffset := offset - cumPlain
			ci := int32(relOffset / int64(m.ChunkSize)) // #nosec G115 — relOffset ≤ part.PlainLen ≤ maxPartSize (5 GiB), ChunkSize ≥ 64 KiB, quotient fits int32
			ic := relOffset % int64(m.ChunkSize)
			return i, ci, ic, nil
		}
		cumPlain += part.PlainLen
	}
	return 0, 0, 0, fmt.Errorf("mpu_manifest: offset %d beyond total plain size %d", offset, m.TotalPlainSize)
}

// EncOffsetForPartChunk returns the backend byte offset of the first byte of
// the given chunk within the given part (part index is 0-based).
// The backend offset is absolute (from the start of the concatenated parts).
func (m *MultipartManifest) EncOffsetForPartChunk(partIdx int, chunkIdx int32) (int64, error) {
	if partIdx < 0 || partIdx >= len(m.Parts) {
		return 0, fmt.Errorf("mpu_manifest: part index %d out of range", partIdx)
	}
	var base int64
	for i := 0; i < partIdx; i++ {
		base += m.Parts[i].EncLen
	}
	// Each chunk occupies (ChunkSize + tagSize) backend bytes.
	const tagSize = 16
	chunkEncSize := int64(m.ChunkSize) + tagSize
	base += int64(chunkIdx) * chunkEncSize
	return base, nil
}

// MPURangeResult describes the backend byte range and chunk boundaries needed
// to satisfy a plaintext range request on an encrypted multipart object.
type MPURangeResult struct {
	// EncStart and EncEnd are the inclusive backend byte offsets to request.
	EncStart int64
	EncEnd   int64

	// PartStartIdx / ChunkStart identify the first affected chunk in manifest.Parts.
	// The fetched ciphertext starts at the first byte of this chunk.
	PartStartIdx int
	ChunkStart   int32

	// PartEndIdx / ChunkEnd identify the last affected chunk.
	PartEndIdx int
	ChunkEnd   int32
}

// EncRangeForPlaintextRange translates a plaintext byte range [pStart, pEnd]
// into the backend byte range that must be fetched so that every ciphertext
// chunk touched by the range can be fully authenticated and decrypted.
//
// Chunk boundaries are respected: if pStart falls mid-chunk, the whole chunk
// is included from EncStart so the AES-GCM tag can be verified. EncEnd is
// calculated precisely (the last byte of the last affected chunk) so no bytes
// from the next part are fetched.
func (m *MultipartManifest) EncRangeForPlaintextRange(pStart, pEnd int64) (MPURangeResult, error) {
	if pStart < 0 || pStart > pEnd || pEnd >= m.TotalPlainSize {
		return MPURangeResult{}, fmt.Errorf("mpu_manifest: range [%d,%d] out of [0,%d)", pStart, pEnd, m.TotalPlainSize)
	}

	const tagSize = int64(16)
	encChunkSize := int64(m.ChunkSize) + tagSize

	// Locate pStart.
	partStartIdx, chunkStart, _, err := m.PlainOffsetToPartChunk(pStart)
	if err != nil {
		return MPURangeResult{}, err
	}

	// Locate pEnd.
	partEndIdx, chunkEnd, _, err := m.PlainOffsetToPartChunk(pEnd)
	if err != nil {
		return MPURangeResult{}, err
	}

	// Accumulate backend offsets of the start of each affected part.
	var partStartOff, partEndOff int64
	for i := 0; i < partStartIdx; i++ {
		partStartOff += m.Parts[i].EncLen
	}
	for i := 0; i < partEndIdx; i++ {
		partEndOff += m.Parts[i].EncLen
	}

	encStart := partStartOff + int64(chunkStart)*encChunkSize

	// encEnd must point to the last byte of chunkEnd within partEndIdx.
	// Use EncLen of that part to handle the last (potentially short) chunk precisely.
	var encEnd int64
	if int(chunkEnd) == int(m.Parts[partEndIdx].ChunkCount)-1 {
		// Last chunk of the part — use EncLen which already accounts for the short tail.
		encEnd = partEndOff + m.Parts[partEndIdx].EncLen - 1
	} else {
		encEnd = partEndOff + int64(chunkEnd+1)*encChunkSize - 1
	}

	return MPURangeResult{
		EncStart:     encStart,
		EncEnd:       encEnd,
		PartStartIdx: partStartIdx,
		ChunkStart:   chunkStart,
		PartEndIdx:   partEndIdx,
		ChunkEnd:     chunkEnd,
	}, nil
}
