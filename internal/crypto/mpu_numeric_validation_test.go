package crypto

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMultipartManifestRejectsInvalidNumericLayout(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, tc := range []struct {
			name   string
			mutate func(*MultipartManifest)
		}{
			{"zero chunk size", func(m *MultipartManifest) { m.ChunkSize = 0 }},
			{"negative chunk size", func(m *MultipartManifest) { m.ChunkSize = -1 }},
			{"oversized chunk size", func(m *MultipartManifest) { m.ChunkSize = MaxChunkSize + 1 }},
			{"negative plaintext", func(m *MultipartManifest) { m.Parts[0].PlainLen = -1 }},
			{"negative ciphertext", func(m *MultipartManifest) { m.Parts[0].EncLen = -1 }},
			{"negative count", func(m *MultipartManifest) { m.Parts[0].ChunkCount = -1 }},
			{"wrong count", func(m *MultipartManifest) { m.Parts[0].ChunkCount++ }},
			{"wrong ciphertext length", func(m *MultipartManifest) { m.Parts[0].EncLen++ }},
			{"wrong total", func(m *MultipartManifest) { m.TotalPlainSize++ }},
			{"negative part", func(m *MultipartManifest) { m.Parts[0].PartNumber = -1 }},
			{"zero part", func(m *MultipartManifest) { m.Parts[0].PartNumber = 0 }},
			{"large part number", func(m *MultipartManifest) { m.Parts[0].PartNumber = 10001 }},
			{"duplicate part", func(m *MultipartManifest) { m.Parts[1].PartNumber = m.Parts[0].PartNumber }},
			{"overflowing index", func(m *MultipartManifest) {
				m.ChunkSize = 1
				m.Parts[0].PlainLen = 1<<32 + 1
				m.TotalPlainSize = 1<<32 + 1
			}},
		} {
			t.Run(tc.name+string(rune('0'+version)), func(t *testing.T) {
				m := makeTestManifest(2)
				m.Version = version
				tc.mutate(m)
				data, err := json.Marshal(m)
				require.NoError(t, err)
				_, err = UnmarshalMultipartManifest(data)
				require.Error(t, err, "malformed backend manifest must fail during parsing")
				_, _, _, err = m.PlainOffsetToPartChunk(0)
				require.Error(t, err, "programmatic manifest must also be validated")
				_, err = m.EncRangeForPlaintextRange(0, 0)
				require.Error(t, err)
				_, err = m.Marshal()
				require.Error(t, err, "invalid manifests must not be emitted by writers")
			})
		}
	}
}

func TestMultipartManifestRejectsCumulativeCiphertextOverflow(t *testing.T) {
	// Every part is independently valid. Their plaintext sum fits int64, but
	// the accumulated authentication overhead pushes the ciphertext sum over it.
	const count = int32(math.MaxInt32)
	plain := int64(count) * MaxChunkSize
	enc := plain + int64(count)*mpuAEADTagSize
	parts := make([]MPUPartRecord, 4096)
	for i := range parts {
		parts[i] = MPUPartRecord{PartNumber: int32(i + 1), PlainLen: plain, EncLen: enc, ChunkCount: count}
	}
	// Assert independent validity so this regression cannot pass via an earlier
	// count/length-consistency rejection.
	single := &MultipartManifest{Version: 1, ChunkSize: MaxChunkSize, TotalPlainSize: plain, Parts: parts[:1]}
	require.NoError(t, single.validateLayout())
	m := &MultipartManifest{Version: 1, ChunkSize: MaxChunkSize, TotalPlainSize: plain * int64(len(parts)), Parts: parts}
	require.Positive(t, m.TotalPlainSize)
	require.ErrorContains(t, m.validateLayout(), "overflowing part sizes")
	_, err := m.Marshal()
	require.ErrorContains(t, err, "overflowing part sizes")
}

func TestMPURejectsInvalidCoordinatesBeforeCiphertext(t *testing.T) {
	object := ObjectContext{Bucket: "bucket", Key: "key"}
	for _, tc := range []struct {
		name        string
		part, chunk int32
	}{
		{"negative part", -1, 0}, {"zero part", 0, 0}, {"too large part", 10001, 0}, {"negative chunk", 1, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecryptMPUPartRange(object, phaseCBinding(1), nil, testDEK, testUIDHash, testIVPrefix, tc.part, DefaultChunkSize, tc.chunk, AlgorithmAES256GCM)
			require.Error(t, err, "must not depend on ciphertext authentication to reject coordinates")
			_, err = DecryptMPUPartRangeV1(object, nil, testDEK, testUIDHash, testIVPrefix, tc.part, DefaultChunkSize, tc.chunk, AlgorithmAES256GCM)
			require.Error(t, err)
		})
	}
}

func TestMPUEncryptRejectsInvalidNumericInputs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		part   int32
		size   int
		length int64
	}{
		{"negative part", -1, DefaultChunkSize, 1}, {"zero part", 0, DefaultChunkSize, 1}, {"large part", 10001, DefaultChunkSize, 1},
		{"negative length", 1, DefaultChunkSize, -1}, {"ciphertext overflow", 1, DefaultChunkSize, math.MaxInt64},
		{"chunk count overflow", 1, 1, math.MaxInt32 + 1}, {"large chunk size", 1, MaxChunkSize + 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := NewMPUPartEncryptReader(t.Context(), ObjectContext{Bucket: "bucket", Key: "key"}, phaseCBinding(1), bytes.NewReader(nil), testDEK, testUIDHash, testIVPrefix, tc.part, tc.size, tc.length, AlgorithmAES256GCM)
			require.Error(t, err)
		})
	}
}

func TestMPUDecryptRejectsInvalidLayoutBeforeRead(t *testing.T) {
	m := makeTestManifest(1)
	m.Parts[0].ChunkCount = -1
	_, err := NewMPUDecryptReaderV1(ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(nil), m, testDEK, testUIDHash, testIVPrefix, AlgorithmAES256GCM)
	require.Error(t, err)
}

func TestMPUEncryptDeclaredLengthIsEnforced(t *testing.T) {
	for _, body := range []string{"a", "abc"} {
		r, _, err := NewMPUPartEncryptReaderV1(t.Context(), ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewBufferString(body), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, 2, AlgorithmAES256GCM)
		require.NoError(t, err)
		_, err = io.ReadAll(r)
		require.Error(t, err, "source size must match declared plaintext size")
	}
}

func TestMPUCounterLimitBeforeCipherUse(t *testing.T) {
	r, _, err := NewMPUPartEncryptReaderV1(t.Context(), ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewBufferString("a"), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, 1, AlgorithmAES256GCM)
	require.NoError(t, err)
	reader := r.(*mpuEncryptReader)
	reader.chunkIdx = math.MaxInt32
	_, err = io.ReadAll(reader)
	require.ErrorContains(t, err, "chunk index overflow")
	for _, keyByte := range reader.dek {
		require.Zero(t, keyByte, "counter failure must release the owned key")
	}
	_, err = DecryptMPUPartRangeV1(ObjectContext{Bucket: "bucket", Key: "key"}, []byte{1}, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, math.MaxInt32, AlgorithmAES256GCM)
	require.ErrorContains(t, err, "chunk index overflow")
}

func TestMultipartManifestAllowsValidEmptyParts(t *testing.T) {
	m := &MultipartManifest{Version: 1, ChunkSize: DefaultChunkSize, Parts: []MPUPartRecord{{PartNumber: 1}}}
	data, err := json.Marshal(m)
	require.NoError(t, err)
	parsed, err := UnmarshalMultipartManifest(data)
	require.NoError(t, err)
	r, err := NewMPUDecryptReaderV1(ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(nil), parsed, testDEK, testUIDHash, testIVPrefix, AlgorithmAES256GCM)
	require.NoError(t, err)
	plain, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, plain)
}
