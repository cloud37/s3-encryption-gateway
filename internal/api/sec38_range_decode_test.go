package api

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/stretchr/testify/require"
)

func sec38EncryptedRangeFixture(t *testing.T) ([]byte, *crypto.MultipartManifest, []byte, [32]byte, [32]byte, [12]byte) {
	t.Helper()
	dek := bytes.Repeat([]byte{0x31}, 32)
	var dek32 [32]byte
	copy(dek32[:], dek)
	var uidHash [32]byte
	for i := range uidHash {
		uidHash[i] = byte(i + 1)
	}
	var ivPrefix [12]byte
	for i := range ivPrefix {
		ivPrefix[i] = byte(0xa0 + i)
	}
	plain := bytes.Repeat([]byte("range-data"), crypto.DefaultChunkSize/len("range-data")+1)
	r, _, err := crypto.NewMPUPartEncryptReader(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{1}, bytes.NewReader(plain), dek, uidHash, ivPrefix, 1, crypto.DefaultChunkSize, int64(len(plain)), crypto.AlgorithmAES256GCM)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(r)
	require.NoError(t, err)
	manifest := &crypto.MultipartManifest{
		Version:        1,
		Algorithm:      crypto.AlgorithmAES256GCM,
		ChunkSize:      crypto.DefaultChunkSize,
		Parts:          []crypto.MPUPartRecord{{PartNumber: 1, PlainLen: int64(len(plain)), EncLen: int64(len(ciphertext)), ChunkCount: 2}},
		TotalPlainSize: int64(len(plain)),
	}
	return plain, manifest, ciphertext, dek32, uidHash, ivPrefix
}

func TestSEC38DecodeMPUPlaintextRange(t *testing.T) {
	plain, manifest, ciphertext, dek, uidHash, ivPrefix := sec38EncryptedRangeFixture(t)
	chunkCipherLen := crypto.DefaultChunkSize + 16

	t.Run("valid range across chunks", func(t *testing.T) {
		start := int64(crypto.DefaultChunkSize - 3)
		end := start + 4
		got, err := decodeMPUPlaintextRange(ciphertext, manifest, dek[:], uidHash, ivPrefix,
			crypto.MPURangeResult{PartStartIdx: 0, ChunkStart: 0, PartEndIdx: 0, ChunkEnd: 1}, start, end, crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{1})
		require.NoError(t, err)
		require.Equal(t, plain[start:end+1], got)
	})

	t.Run("short ciphertext fails authentication", func(t *testing.T) {
		_, err := decodeMPUPlaintextRange(ciphertext[:chunkCipherLen-1], manifest, dek[:], uidHash, ivPrefix,
			crypto.MPURangeResult{PartStartIdx: 0, ChunkStart: 0, PartEndIdx: 0, ChunkEnd: 0}, 0, 10, crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{1})
		require.Error(t, err)
	})

	t.Run("tampered ciphertext fails authentication", func(t *testing.T) {
		tampered := append([]byte(nil), ciphertext...)
		tampered[7] ^= 0xff
		_, err := decodeMPUPlaintextRange(tampered, manifest, dek[:], uidHash, ivPrefix,
			crypto.MPURangeResult{PartStartIdx: 0, ChunkStart: 0, PartEndIdx: 0, ChunkEnd: 0}, 0, 10, crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{1})
		require.ErrorContains(t, err, "auth failure")
	})

	t.Run("invalid manifest part index", func(t *testing.T) {
		_, err := decodeMPUPlaintextRange(ciphertext, manifest, dek[:], uidHash, ivPrefix,
			crypto.MPURangeResult{PartStartIdx: 1, ChunkStart: 0, PartEndIdx: 1, ChunkEnd: 0}, 0, 1, crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{1})
		require.ErrorContains(t, err, "part index")
	})

	t.Run("invalid plaintext slice", func(t *testing.T) {
		_, err := decodeMPUPlaintextRange(ciphertext, manifest, dek[:], uidHash, ivPrefix,
			crypto.MPURangeResult{PartStartIdx: 0, ChunkStart: 0, PartEndIdx: 0, ChunkEnd: 0}, -1, 1, crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{1})
		require.ErrorContains(t, err, "outside")
	})
}
