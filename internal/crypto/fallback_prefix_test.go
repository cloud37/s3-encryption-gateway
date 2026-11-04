package crypto

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func fallbackFrame(t *testing.T, m map[string]string) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	out := make([]byte, 4, len(b)+4)
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

type cancelPrefixReader struct {
	data   []byte
	cancel context.CancelFunc
	calls  int
}

func (r *cancelPrefixReader) Read(p []byte) (int, error) {
	r.calls++
	n := copy(p, r.data)
	r.data = r.data[n:]
	r.cancel()
	return n, nil
}

func TestGH353FallbackPrefixBoundaryAndCancellation(t *testing.T) {
	var nilReader *bytes.Reader
	_, err := ReadFallbackV2Prefix(t.Context(), nilReader)
	require.Error(t, err)
	_, err = ReadFallbackV2Prefix(nil, bytes.NewReader(nil))
	require.Error(t, err)
	_, err = ReadFallbackV2Prefix(t.Context(), nil)
	require.Error(t, err)
	n := MaxFallbackPrefixBytes - 4
	jsonData := []byte(`{"k":"` + strings.Repeat("x", n-8) + `"}`)
	require.Len(t, jsonData, n)
	frame := make([]byte, 4, 4+len(jsonData)+4)
	binary.BigEndian.PutUint32(frame, uint32(n))
	frame = append(frame, jsonData...)
	frame = append(frame, []byte("tail")...)
	r := bytes.NewReader(frame)
	m, err := ReadFallbackV2Prefix(t.Context(), r)
	require.NoError(t, err)
	require.Len(t, m["k"], n-8)
	require.Equal(t, 4, r.Len())
	var over [4]byte
	binary.BigEndian.PutUint32(over[:], uint32(n+1))
	_, err = ReadFallbackV2Prefix(t.Context(), bytes.NewReader(over[:]))
	require.Error(t, err)
	_, err = ReadFallbackV2Prefix(t.Context(), bytes.NewReader([]byte{0, 0, 0, 0}))
	require.Error(t, err)
	ctx, cancel := context.WithCancel(t.Context())
	cr := &cancelPrefixReader{data: frame, cancel: cancel}
	_, err = ReadFallbackV2Prefix(ctx, cr)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, cr.calls)
}

func TestGH353FallbackLegacyControlAuthority(t *testing.T) {
	header := map[string]string{MetaManifest: "trusted", MetaObjectFormatVersion: "chunked-v2", MetaObjectBindingID: "binding", MetaWrappedKeyCiphertext: "wrapped", MetaKeyVersion: "4", MetaLegacyNoAAD: "false"}
	prefix := map[string]string{MetaManifest: "evil", MetaObjectFormatVersion: "evil", MetaObjectBindingID: "evil", MetaWrappedKeyCiphertext: "evil", MetaKeyVersion: "8", MetaLegacyNoAAD: "true", MetaKDFParams: "legacy"}
	merged := mergeLegacyFallbackControls(header, prefix)
	for k, v := range header {
		require.Equal(t, v, merged[k])
	}
	require.Equal(t, "legacy", merged[MetaKDFParams])
	delete(header, MetaLegacyNoAAD)
	merged = mergeLegacyFallbackControls(header, prefix)
	require.NotContains(t, merged, MetaLegacyNoAAD)
}

func TestGH353FallbackPrefixBounded(t *testing.T) {
	for _, data := range [][]byte{nil, {0, 0, 0, 2, '{'}, {0, 16, 0, 1}, {0, 0, 0, 4, 'n', 'u', 'l', 'l'}, {0, 0, 0, 1, '{'}} {
		_, err := ReadFallbackV2Prefix(t.Context(), bytes.NewReader(data))
		require.Error(t, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := ReadFallbackV2Prefix(ctx, bytes.NewReader(fallbackFrame(t, map[string]string{})))
	require.ErrorIs(t, err, context.Canceled)
	data := append(fallbackFrame(t, map[string]string{"x-amz-meta-test": "value"}), []byte("ciphertext")...)
	r := bytes.NewReader(data)
	meta, err := ReadFallbackV2Prefix(t.Context(), r)
	require.NoError(t, err)
	require.Equal(t, "value", meta["x-amz-meta-test"])
	rest, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, "ciphertext", string(rest))
}

func TestGH353FallbackPrefixHeaderAuthority(t *testing.T) {
	header := map[string]string{MetaEncryptedMetadata: "header-blob", MetaAlgorithm: "AES256-GCM", MetaContentType: "safe", "x-amz-meta-user": "header"}
	prefix := map[string]string{MetaEncryptedMetadata: "attacker", "X-Amz-Meta-A": "attacker", "content-type": "attacker", "X-Amz-Meta-User": "attacker", "x-amz-meta-extra": "yes", MetaKDFParams: "legacy"}
	got := MergeFallbackV2Metadata(header, prefix)
	require.Equal(t, "header-blob", got[MetaEncryptedMetadata])
	require.Equal(t, "AES256-GCM", got[MetaAlgorithm])
	require.Equal(t, "safe", got[MetaContentType])
	require.Equal(t, "header", got["x-amz-meta-user"])
	require.Equal(t, "yes", got["x-amz-meta-extra"])
	require.NotContains(t, got, MetaKDFParams)
	legacy := mergeLegacyFallbackControls(header, prefix)
	require.Equal(t, "legacy", legacy[MetaKDFParams])
	require.Equal(t, "safe", legacy[MetaContentType])
}

func TestGH353FallbackHeaderBlobAuthorityRoundTrip(t *testing.T) {
	e, _ := newChunkedFallbackEngine(t)
	t.Cleanup(func() { _ = e.Close() })
	key := bytes.Repeat([]byte{3}, 32)
	SetMetadataKey(e, key)
	t.Cleanup(func() { clear(key); clear(e.metadataKey) })
	obj := ObjectContext{Bucket: "bucket", Key: "key"}
	stream, header, err := e.Encrypt(t.Context(), obj, bytes.NewReader([]byte("body")), largeMetadataMap())
	require.NoError(t, err)
	data, err := io.ReadAll(stream)
	require.NoError(t, err)
	n := int(binary.BigEndian.Uint32(data[:4]))
	var prefix map[string]string
	require.NoError(t, json.Unmarshal(data[4:4+n], &prefix))
	prefix[MetaEncryptedMetadata] = "substituted"
	prefix[MetaContentType] = "malicious"
	modified := append(fallbackFrame(t, prefix), data[4+n:]...)
	reader, meta, err := e.Decrypt(t.Context(), obj, bytes.NewReader(modified), header)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "body", string(plain))
	require.Equal(t, "application/octet-stream", meta["Content-Type"])
	delete(prefix, MetaEncryptedMetadata)
	modified = append(fallbackFrame(t, prefix), data[4+n:]...)
	reader, meta, err = e.Decrypt(t.Context(), obj, bytes.NewReader(modified), header)
	require.NoError(t, err)
	plain, err = io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "body", string(plain))
	require.Equal(t, "application/octet-stream", meta["Content-Type"])
	// A blob found solely in the prefix is never accepted as header provenance.
	delete(header, MetaEncryptedMetadata)
	delete(header, MetaEncryptedMetadataCompact)
	delete(header, MetaContentType)
	delete(header, "x-amz-meta-ct")
	delete(header, "Content-Type")
	reader, meta, err = e.Decrypt(t.Context(), obj, bytes.NewReader(data), header)
	if err == nil {
		require.NotEqual(t, "application/octet-stream", meta["Content-Type"])
	}
}

func TestGH353FallbackLegacyPrefixControls(t *testing.T) {
	e, _ := newChunkedFallbackEngine(t)
	t.Cleanup(func() { _ = e.Close() })
	obj := ObjectContext{Bucket: "bucket", Key: "key"}
	stream, header, err := e.Encrypt(t.Context(), obj, bytes.NewReader([]byte("legacy")), largeMetadataMap())
	require.NoError(t, err)
	data, err := io.ReadAll(stream)
	require.NoError(t, err)
	delete(header, MetaKDFParams)
	delete(header, "x-amz-meta-kdf")
	reader, _, err := e.Decrypt(t.Context(), obj, bytes.NewReader(data), header)
	require.NoError(t, err)
	plain, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, "legacy", string(plain))
}

func TestGH353FallbackHeaderBlobPresenceIsNotAuthentication(t *testing.T) {
	e, _ := newChunkedFallbackEngine(t)
	t.Cleanup(func() { _ = e.Close() })
	obj := ObjectContext{Bucket: "bucket", Key: "key"}
	stream, header, err := e.Encrypt(t.Context(), obj, bytes.NewReader([]byte("legacy")), largeMetadataMap())
	require.NoError(t, err)
	data, err := io.ReadAll(stream)
	require.NoError(t, err)
	length := int(binary.BigEndian.Uint32(data[:4]))
	var prefix map[string]string
	require.NoError(t, json.Unmarshal(data[4:4+length], &prefix))
	prefix[MetaKDFParams] = "invalid-untrusted-kdf"
	data = append(fallbackFrame(t, prefix), data[4+length:]...)
	for _, blob := range []string{"", "not-a-valid-blob"} {
		h := make(map[string]string, len(header)+1)
		for k, v := range header {
			h[k] = v
		}
		h[MetaEncryptedMetadata] = blob
		reader, _, err := e.Decrypt(t.Context(), obj, bytes.NewReader(data), h)
		require.NoError(t, err, "untrusted prefix KDF must not be selected when header blob is present")
		plain, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.Equal(t, "legacy", string(plain))
	}
	SetMetadataKey(e, bytes.Repeat([]byte{7}, 32))
	t.Cleanup(func() { clear(e.metadataKey) })
	header[MetaEncryptedMetadata] = "invalid-blob"
	_, _, err = e.Decrypt(t.Context(), obj, bytes.NewReader(data), header)
	require.ErrorContains(t, err, "decrypt metadata")
}
