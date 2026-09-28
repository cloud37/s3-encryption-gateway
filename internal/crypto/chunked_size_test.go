package crypto

import (
	"testing"
)

func TestPlaintextSizeForCiphertext_V1V2(t *testing.T) {
	for _, version := range []uint8{ChunkedFormatV1, ChunkedFormatV2} {
		manifest, _ := encodeManifest(&ChunkManifest{Version: int(version), ChunkSize: DefaultChunkSize})
		meta := map[string]string{MetaChunkedFormat: "true", MetaManifest: manifest, MetaObjectFormatVersion: "chunked-v1"}
		if version == ChunkedFormatV2 {
			meta[MetaObjectFormatVersion] = "chunked-v2"
		}
		ct, err := CiphertextSizeForPlaintext(meta, 100)
		if err != nil {
			t.Fatal(err)
		}
		plain, _, err := PlaintextSizeForCiphertext(meta, ct)
		if err != nil || plain != 100 {
			t.Fatalf("v%d: %d %v", version, plain, err)
		}
	}
}

func TestChunkedSizeHelpers_InvalidAndLegacyMetadata(t *testing.T) {
	if _, err := CiphertextSizeForPlaintext(nil, -1); err == nil {
		t.Fatal("negative plaintext size accepted")
	}
	if _, _, err := PlaintextSizeForCiphertext(nil, -1); err == nil {
		t.Fatal("negative ciphertext size accepted")
	}
	if got, err := CiphertextSizeForPlaintext(nil, 100); err != nil || got <= 100 {
		t.Fatalf("legacy v1 size=%d err=%v", got, err)
	}
	bad := map[string]string{MetaManifest: "not-json"}
	if _, err := CiphertextSizeForPlaintext(bad, 100); err == nil {
		t.Fatal("malformed manifest accepted")
	}
	for _, meta := range []map[string]string{
		{MetaManifest: `{"v":3,"cs":65536}`},
		{MetaManifest: `{"v":1,"cs":0}`},
	} {
		if _, _, err := PlaintextSizeForCiphertext(meta, 100); err == nil {
			t.Fatalf("invalid version metadata accepted: %v", meta)
		}
	}
}
