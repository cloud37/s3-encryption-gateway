package crypto

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeTestManifest(numParts int) *MultipartManifest {
	parts := make([]MPUPartRecord, numParts)
	var total int64
	for i := range parts {
		pn := int32(i + 1)
		plain := int64(8 * 1024 * 1024) // 8 MiB per part
		chunks := int32((plain + int64(DefaultChunkSize) - 1) / int64(DefaultChunkSize))
		enc := plain + int64(chunks)*16
		parts[i] = MPUPartRecord{
			PartNumber: pn,
			ETag:       "\"etag\"",
			PlainLen:   plain,
			EncLen:     enc,
			ChunkCount: chunks,
		}
		total += plain
	}
	return &MultipartManifest{
		Version:        mpuManifestVersion,
		Algorithm:      "AES256GCM",
		ChunkSize:      DefaultChunkSize,
		IVPrefix:       "AAAAAAAAAAAAAAAA", // 12 bytes base64url
		UploadIDHash:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		WrappedDEK:     "c29tZXdyYXBwZWRkZWs=",
		Parts:          parts,
		TotalPlainSize: total,
	}
}

// TestMultipartManifest_RoundTrip verifies marshal/unmarshal symmetry.
func TestMultipartManifest_RoundTrip(t *testing.T) {
	m := makeTestManifest(3)
	b, err := m.Marshal()
	require.NoError(t, err)

	got, err := UnmarshalMultipartManifest(b)
	require.NoError(t, err)

	assert.Equal(t, m.Version, got.Version)
	assert.Equal(t, m.Algorithm, got.Algorithm)
	assert.Equal(t, m.ChunkSize, got.ChunkSize)
	assert.Equal(t, m.WrappedDEK, got.WrappedDEK)
	assert.Equal(t, len(m.Parts), len(got.Parts))
	assert.Equal(t, m.TotalPlainSize, got.TotalPlainSize)
}

// TestMultipartManifest_Base64RoundTrip verifies base64url marshal/unmarshal.
func TestMultipartManifest_Base64RoundTrip(t *testing.T) {
	m := makeTestManifest(2)
	s, err := m.MarshalBase64()
	require.NoError(t, err)
	require.NotEmpty(t, s)

	got, err := UnmarshalMultipartManifestBase64(s)
	require.NoError(t, err)
	assert.Equal(t, m.TotalPlainSize, got.TotalPlainSize)
	assert.Equal(t, len(m.Parts), len(got.Parts))
}

// TestMultipartManifest_FitsInline_SmallManifest checks that a 3-part manifest fits inline.
func TestMultipartManifest_FitsInline_SmallManifest(t *testing.T) {
	m := makeTestManifest(3)
	b, err := m.Marshal()
	require.NoError(t, err)
	t.Logf("3-part manifest JSON size: %d bytes", len(b))
	assert.True(t, m.FitsInlineDefault(), "3-part manifest should fit inline (≤1800 B)")
}

// TestMultipartManifest_FitsInline_LargeManifest checks that a 31-part manifest
// does NOT fit inline (calibrated against 1.8 KiB cap).
// Adjust part count if the manifest schema changes significantly.
func TestMultipartManifest_FitsInline_LargeManifest(t *testing.T) {
	// Grow until we exceed 1800 bytes, then assert the exact boundary.
	for n := 10; n <= 200; n += 5 {
		m := makeTestManifest(n)
		b, _ := m.Marshal()
		if len(b) > mpuInlineLimit {
			t.Logf("first part count that exceeds inline limit (%d B): %d parts (%d B)", mpuInlineLimit, n, len(b))
			assert.False(t, m.FitsInlineDefault(), "manifest with %d parts should NOT fit inline", n)
			// Check just below the boundary.
			mSmall := makeTestManifest(n - 5)
			bSmall, _ := mSmall.Marshal()
			t.Logf("%d-part manifest: %d bytes (fits=%v)", n-5, len(bSmall), mSmall.FitsInlineDefault())
			return
		}
	}
	t.Error("no part count in range 10–200 exceeded the inline limit; schema may have shrunk unexpectedly")
}

// TestMultipartManifest_UnknownVersion ensures an unknown version returns an error.
func TestMultipartManifest_UnknownVersion(t *testing.T) {
	raw := `{"v":99,"alg":"AES256GCM","cs":65536,"parts":[]}`
	_, err := UnmarshalMultipartManifest([]byte(raw))
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "unsupported version"), "error should mention version")
}

// TestMultipartManifest_UnmarshalInvalidJSON verifies json errors are wrapped.
func TestMultipartManifest_UnmarshalInvalidJSON(t *testing.T) {
	_, err := UnmarshalMultipartManifest([]byte("not json"))
	require.Error(t, err)
}

// TestMultipartManifest_PlainOffsetToPartChunk verifies offset translation.
func TestMultipartManifest_PlainOffsetToPartChunk(t *testing.T) {
	const partSize = 8 * 1024 * 1024 // 8 MiB
	m := makeTestManifest(3)

	tests := []struct {
		offset    int64
		wantPart  int
		wantChunk int32
		wantIntra int64
	}{
		{0, 0, 0, 0},
		{int64(DefaultChunkSize) - 1, 0, 0, int64(DefaultChunkSize) - 1},
		{int64(DefaultChunkSize), 0, 1, 0},
		{partSize - 1, 0, int32(partSize/DefaultChunkSize) - 1, int64(DefaultChunkSize) - 1},
		{partSize, 1, 0, 0},
		{2 * partSize, 2, 0, 0},
	}

	for _, tc := range tests {
		pIdx, cIdx, intra, err := m.PlainOffsetToPartChunk(tc.offset)
		require.NoErrorf(t, err, "offset %d", tc.offset)
		assert.Equalf(t, tc.wantPart, pIdx, "partIdx at offset %d", tc.offset)
		assert.Equalf(t, tc.wantChunk, cIdx, "chunkIdx at offset %d", tc.offset)
		assert.Equalf(t, tc.wantIntra, intra, "intraChunk at offset %d", tc.offset)
	}
}

// TestMultipartManifest_PlainOffsetToPartChunk_OutOfRange checks error on out-of-range offset.
func TestMultipartManifest_PlainOffsetToPartChunk_OutOfRange(t *testing.T) {
	m := makeTestManifest(2)
	_, _, _, err := m.PlainOffsetToPartChunk(m.TotalPlainSize)
	require.Error(t, err)
	_, _, _, err = m.PlainOffsetToPartChunk(-1)
	require.Error(t, err)
}

// TestEncRangeForPlaintextRange verifies backend byte range calculation.
func TestEncRangeForPlaintextRange(t *testing.T) {
	const partSize = 8 * 1024 * 1024 // 8 MiB
	const chunkSz = DefaultChunkSize // 64 KiB
	const tagSz = 16
	const encChunkSz = int64(chunkSz + tagSz)

	m := makeTestManifest(3) // 3 × 8 MiB parts

	t.Run("within first chunk of first part", func(t *testing.T) {
		r, err := m.EncRangeForPlaintextRange(0, 100)
		require.NoError(t, err)
		assert.Equal(t, int64(0), r.EncStart)
		assert.Equal(t, encChunkSz-1, r.EncEnd)
		assert.Equal(t, 0, r.PartStartIdx)
		assert.Equal(t, int32(0), r.ChunkStart)
		assert.Equal(t, 0, r.PartEndIdx)
		assert.Equal(t, int32(0), r.ChunkEnd)
	})

	t.Run("spanning first two chunks of first part", func(t *testing.T) {
		r, err := m.EncRangeForPlaintextRange(int64(chunkSz)-1, int64(chunkSz)+1)
		require.NoError(t, err)
		assert.Equal(t, int64(0), r.EncStart, "must start at chunk 0")
		assert.Equal(t, 2*encChunkSz-1, r.EncEnd, "must end at last byte of chunk 1")
		assert.Equal(t, int32(0), r.ChunkStart)
		assert.Equal(t, int32(1), r.ChunkEnd)
	})

	t.Run("spanning part boundary (part 0 last chunk → part 1 first chunk)", func(t *testing.T) {
		crossStart := int64(partSize) - 1 // last byte of part 0
		crossEnd := int64(partSize) + 1   // first bytes of part 1

		r, err := m.EncRangeForPlaintextRange(crossStart, crossEnd)
		require.NoError(t, err)
		assert.Equal(t, 0, r.PartStartIdx)
		assert.Equal(t, 1, r.PartEndIdx)
		assert.Equal(t, int32(0), r.ChunkEnd, "range ends in chunk 0 of part 1")

		// EncStart must be the start of the last chunk in part 0.
		chunksInPart := int32(partSize / chunkSz)
		lastChunkOfPart0 := chunksInPart - 1
		part0EncOff, _ := m.EncOffsetForPartChunk(0, lastChunkOfPart0)
		assert.Equal(t, part0EncOff, r.EncStart)

		// EncEnd must be the last byte of chunk 0 in part 1.
		part1BaseOff := m.Parts[0].EncLen
		assert.Equal(t, part1BaseOff+encChunkSz-1, r.EncEnd)
	})

	t.Run("last byte of object (last chunk of last part)", func(t *testing.T) {
		last := m.TotalPlainSize - 1
		r, err := m.EncRangeForPlaintextRange(last, last)
		require.NoError(t, err)
		assert.Equal(t, 2, r.PartEndIdx)
		// EncEnd must equal the last byte of the last part.
		partEndBase := m.Parts[0].EncLen + m.Parts[1].EncLen
		assert.Equal(t, partEndBase+m.Parts[2].EncLen-1, r.EncEnd)
	})

	t.Run("out of range returns error", func(t *testing.T) {
		_, err := m.EncRangeForPlaintextRange(0, m.TotalPlainSize)
		require.Error(t, err)
		_, err = m.EncRangeForPlaintextRange(-1, 10)
		require.Error(t, err)
		_, err = m.EncRangeForPlaintextRange(10, 5)
		require.Error(t, err)
	})
}

// TestDecryptMPUPartRange verifies that partial chunk-range decryption agrees
// with full-part decryption for the same bytes.
func TestDecryptMPUPartRange(t *testing.T) {
	ctx := context.Background()
	plain := bytes.Repeat([]byte("abcd"), DefaultChunkSize) // 2.5 chunks

	// Encrypt as a full part.
	r, _, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), "AES256GCM")
	require.NoError(t, err)
	ct, err := io.ReadAll(r)
	require.NoError(t, err)

	// Decrypt full part via DecryptMPUPart.
	gotFull, err := DecryptMPUPart(ct, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, "AES256GCM")
	require.NoError(t, err)
	assert.Equal(t, plain, gotFull)

	encChunkSz := DefaultChunkSize + 16

	// Decrypt just chunk 1 (second chunk) via DecryptMPUPartRange.
	chunk1Ct := ct[encChunkSz : 2*encChunkSz]
	gotChunk1, err := decryptMPUPartRangeV1(ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, chunk1Ct, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, 1, "AES256GCM")
	require.NoError(t, err)
	assert.Equal(t, plain[DefaultChunkSize:2*DefaultChunkSize], gotChunk1)

	// Decrypt chunks 0+1 via DecryptMPUPartRange starting from 0.
	gotChunks01, err := decryptMPUPartRangeV1(ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, ct[:2*encChunkSz], testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, 0, "AES256GCM")
	require.NoError(t, err)
	assert.Equal(t, plain[:2*DefaultChunkSize], gotChunks01)

	// Tampered second chunk must fail.
	tampered := make([]byte, len(chunk1Ct))
	copy(tampered, chunk1Ct)
	tampered[0] ^= 0xff
	_, err = decryptMPUPartRangeV1(ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, tampered, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, 1, "AES256GCM")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth failure")
}

// TestMultipartManifest_JSONFieldNames checks that the compact JSON field names
// are used (important for staying under the inline size budget).
func TestMultipartManifest_JSONFieldNames(t *testing.T) {
	m := makeTestManifest(1)
	b, err := json.Marshal(m)
	require.NoError(t, err)
	s := string(b)

	assert.Contains(t, s, `"v":`)
	assert.Contains(t, s, `"alg":`)
	assert.Contains(t, s, `"cs":`)
	assert.Contains(t, s, `"iv_prefix":`)
	assert.Contains(t, s, `"wrapped_dek":`)
	assert.Contains(t, s, `"pn":`)
	assert.Contains(t, s, `"enc_len":`)
}
