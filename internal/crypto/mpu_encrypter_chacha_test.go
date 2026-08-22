//go:build !fips

package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMPUEncryptDecrypt_ChaCha20Poly1305 verifies that the MPU path correctly
// uses ChaCha20-Poly1305 when the algorithm parameter is set.
func TestMPUEncryptDecrypt_ChaCha20Poly1305(t *testing.T) {
	ctx := context.Background()
	plain := bytes.Repeat([]byte("chacha20-test-"), 5000)

	r, encLen, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), AlgorithmChaCha20Poly1305)
	require.NoError(t, err)
	ct, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, encLen, int64(len(ct)))

	got, err := DecryptMPUPart(ct, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, AlgorithmChaCha20Poly1305)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

// TestMPUEncryptDecrypt_ChaCha20Poly1305_Streaming verifies the streaming
// decrypt reader dispatches to ChaCha20-Poly1305 correctly.
func TestMPUEncryptDecrypt_ChaCha20Poly1305_Streaming(t *testing.T) {
	ctx := context.Background()
	plain := bytes.Repeat([]byte{0xAB}, DefaultChunkSize*2+123)

	r, encLen, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), AlgorithmChaCha20Poly1305)
	require.NoError(t, err)
	ct, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, encLen, int64(len(ct)))

	manifest := &MultipartManifest{
		Version:      1,
		Algorithm:    AlgorithmChaCha20Poly1305,
		ChunkSize:    DefaultChunkSize,
		IVPrefix:     "aabbccddeeff112233445566",
		UploadIDHash: encodeBase64(testUIDHash[:]),
		WrappedDEK:   "test",
		Parts: []MPUPartRecord{{
			PartNumber: 1,
			PlainLen:   int64(len(plain)),
			EncLen:     encLen,
			ChunkCount: 3,
		}},
		TotalPlainSize: int64(len(plain)),
	}

	dr, err := newMPUDecryptReaderV1(ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(ct), manifest, testDEK, testUIDHash, testIVPrefix, AlgorithmChaCha20Poly1305)
	require.NoError(t, err)
	got, err := io.ReadAll(dr)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}
