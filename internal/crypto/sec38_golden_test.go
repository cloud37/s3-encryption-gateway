package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMPU_SEC38_GoldenCompletedObjectCompatibility locks the v1 manifest
// contract and deterministic part framing used by completed objects.
func TestMPU_SEC38_GoldenCompletedObjectCompatibility(t *testing.T) {
	dek := bytes.Repeat([]byte{0x11}, 32)
	var uid [32]byte
	for i := range uid {
		uid[i] = byte(i)
	}
	var prefix [12]byte
	for i := range prefix {
		prefix[i] = byte(0xa0 + i)
	}
	plain := []byte("golden completed MPU")
	r, encLen, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), dek, uid, prefix, 1, DefaultChunkSize, int64(len(plain)), AlgorithmAES256GCM)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, int64(len(ciphertext)), encLen)
	require.Equal(t, len(plain)+16, len(ciphertext))
	require.Equal(t, "250bf3a4f576bf00b5c7a8ba73a5a984d501b2b8e2b574cc8a3a9b2312dedc1c95c1d9b4", hex.EncodeToString(ciphertext))
	manifest := &MultipartManifest{Version: 1, Algorithm: AlgorithmAES256GCM, ChunkSize: DefaultChunkSize, IVPrefix: base64.RawURLEncoding.EncodeToString(prefix[:]), UploadIDHash: base64.RawURLEncoding.EncodeToString(uid[:]), WrappedDEK: "golden-wrapped", Parts: []MPUPartRecord{{PartNumber: 1, ETag: `"golden"`, PlainLen: int64(len(plain)), EncLen: encLen, ChunkCount: 1}}, TotalPlainSize: int64(len(plain))}
	encoded, err := manifest.Marshal()
	require.NoError(t, err)
	require.Equal(t, `{"v":1,"alg":"AES256-GCM","cs":65536,"iv_prefix":"oKGio6Slpqeoqaqr","uid_hash":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8","wrapped_dek":"golden-wrapped","parts":[{"pn":1,"etag":"\"golden\"","plain_len":20,"enc_len":36,"chunks":1}],"total_plain":20}`, string(encoded))
	require.Contains(t, string(encoded), `"v":1`)
	decoded, err := UnmarshalMultipartManifest(encoded)
	require.NoError(t, err)
	require.Equal(t, manifest.Version, decoded.Version)
	require.Equal(t, manifest.Parts, decoded.Parts)
	iv := DeriveMultipartIV(dek, uid, prefix, 1, 0)
	require.NotEqual(t, [12]byte{}, iv)
	require.NotEmpty(t, ciphertext)
}
