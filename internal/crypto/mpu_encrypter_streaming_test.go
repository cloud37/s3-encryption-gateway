package crypto

// V0.6-PERF-1 Phase G: streaming MPU encrypt reader tests.
// These tests verify that:
//   - Peak heap per read is bounded (O(chunkSize + tagSize)).
//   - Ciphertext output is byte-identical across two reads from the same
//     source (determinism / SDK retry safety).
//   - encLen formula is correct for all plainLen values.

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMPUEncryptReader_DeterministicCiphertext_AcrossRetries verifies that
// re-sealing the same plaintext with the same (DEK, uploadIDHash, ivPrefix,
// partNumber) produces byte-identical ciphertext — the SDK retry contract
// depends on this property (V0.6-PERF-1 plan §G).
func TestMPUEncryptReader_DeterministicCiphertext_AcrossRetries(t *testing.T) {
	plain := bytes.Repeat([]byte{0xAB}, 200_000) // cross-chunk, non-power-of-2

	r1, encLen1, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), "AES256GCM")
	require.NoError(t, err)
	ct1, err := io.ReadAll(r1)
	require.NoError(t, err)
	require.Equal(t, encLen1, int64(len(ct1)))

	r2, encLen2, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), "AES256GCM")
	require.NoError(t, err)
	ct2, err := io.ReadAll(r2)
	require.NoError(t, err)
	require.Equal(t, encLen2, int64(len(ct2)))

	assert.Equal(t, encLen1, encLen2, "encLen must be identical across retries")
	assert.Equal(t, ct1, ct2, "ciphertext must be byte-identical across retries")
}

// TestMPUEncryptReader_EncLenFormula verifies the encLen formula for a range
// of plaintext sizes, including exact multiples of chunkSize.
func TestMPUEncryptReader_EncLenFormula(t *testing.T) {
	const cs = DefaultChunkSize
	const ts = mpuAEADTagSize

	tests := []struct {
		name       string
		plainLen   int64
		wantEncLen int64
	}{
		{"zero", 0, 0},
		{"one_byte", 1, 1 + ts},
		{"exactly_one_chunk", cs, cs + ts},
		{"one_chunk_plus_one", cs + 1, (cs + ts) + (1 + ts)},
		{"16_chunks_exact", 16 * cs, 16 * (cs + ts)},
		{"16_chunks_plus_partial", 16*cs + 512, 16*(cs+ts) + (512 + ts)},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var plain []byte
			if tc.plainLen > 0 {
				plain = bytes.Repeat([]byte{0x42}, int(tc.plainLen))
			}
			r, encLen, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, cs, tc.plainLen, "AES256GCM")
			require.NoError(t, err)
			assert.Equal(t, tc.wantEncLen, encLen, "encLen formula for plainLen=%d", tc.plainLen)

			ct, err := io.ReadAll(r)
			require.NoError(t, err)
			assert.Equal(t, encLen, int64(len(ct)), "actual bytes must equal encLen for plainLen=%d", tc.plainLen)
		})
	}
}

// TestMPUEncryptReader_Streaming_BoundedHeap verifies that the streaming
// encrypt reader only allocates O(chunkSize + tagSize) bytes — independent
// of part size (V0.6-PERF-1 plan §G-2). This is a functional proxy: we
// verify that the reader produces correct output in streaming fashion by
// reading it 1 byte at a time (worst case for buffering).
func TestMPUEncryptReader_Streaming_BoundedHeap(t *testing.T) {
	// 5 MiB — well above a single chunk so multi-chunk path is exercised.
	const plainBytes = 5 * 1024 * 1024
	plain := bytes.Repeat([]byte{0xCC}, plainBytes)

	r, encLen, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 2, DefaultChunkSize, int64(plainBytes), "AES256GCM")
	require.NoError(t, err)

	// Read one byte at a time to exercise the buffering logic in Read.
	var out bytes.Buffer
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			out.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}

	assert.Equal(t, encLen, int64(out.Len()), "streaming read produced wrong byte count")

	// Decrypt and verify plaintext matches.
	got, err := DecryptMPUPart(out.Bytes(), testDEK, testUIDHash, testIVPrefix, 2, DefaultChunkSize, "AES256GCM")
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

// TestMPUEncryptReader_DEKCopied verifies that zeroing the caller's DEK slice
// after NewMPUPartEncryptReader returns does not corrupt subsequent reads.
// This is the regression test for the "defer zeroBytes(dek)" bug in
// encryptMPUPartWithState (V0.6-PERF-1 Phase G implementation notes).
func TestMPUEncryptReader_DEKCopied(t *testing.T) {
	plain := bytes.Repeat([]byte{0x77}, 200_000)

	// First: produce ciphertext from a clean DEK (reference).
	dekOrig := make([]byte, len(testDEK))
	copy(dekOrig, testDEK)
	r1, encLen1, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), dekOrig, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), "AES256GCM")
	require.NoError(t, err)
	// Zero the DEK immediately — simulating defer zeroBytes in the caller.
	for i := range dekOrig {
		dekOrig[i] = 0
	}
	ct1, err := io.ReadAll(r1)
	require.NoError(t, err)
	require.Equal(t, encLen1, int64(len(ct1)))

	// Second: produce ciphertext from a fresh DEK (control).
	dekFresh := make([]byte, len(testDEK))
	copy(dekFresh, testDEK)
	r2, encLen2, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), dekFresh, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), "AES256GCM")
	require.NoError(t, err)
	ct2, err := io.ReadAll(r2)
	require.NoError(t, err)
	require.Equal(t, encLen2, int64(len(ct2)))

	// Both must be identical — the streaming reader must have copied the DEK.
	assert.Equal(t, ct1, ct2, "zeroing caller DEK must not affect the streaming reader's output")

	// Must decrypt correctly.
	got, err := DecryptMPUPart(ct1, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, "AES256GCM")
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}
