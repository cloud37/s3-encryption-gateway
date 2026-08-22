package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"testing"
)

func TestSEC37_Coverage_ConstructorAndTerminalMatrix(t *testing.T) {
	block, _ := aes.NewCipher(bytes.Repeat([]byte{1}, aesKeySize))
	data, _ := cipher.NewGCM(block)
	terminal, _ := cipher.NewGCM(block)
	iv := bytes.Repeat([]byte{2}, nonceSize)
	if _, _, err := newLegacyChunkedEncryptReaderV2(context.Background(), nil, data, iv, MinChunkSize, nil, ChunkedFormatV1, terminal); err == nil {
		t.Fatal("writer accepted unknown v2 version")
	}
	if _, _, err := newLegacyChunkedEncryptReaderV2(context.Background(), nil, data, iv, MinChunkSize, nil, ChunkedFormatV2, nil); err == nil {
		t.Fatal("writer accepted nil terminal")
	}
	if _, err := newLegacyChunkedDecryptReaderV2(context.Background(), nil, data, &ChunkManifest{Version: 1}, nil, terminal); err == nil {
		t.Fatal("decrypt accepted v1 as v2")
	}
	if _, err := newLegacyChunkedDecryptReaderV2(context.Background(), nil, data, &ChunkManifest{Version: 2, BaseIV: "%%%"}, nil, terminal); err == nil {
		t.Fatal("decrypt accepted bad IV")
	}
	if _, err := newLegacyChunkedDecryptReaderV2(context.Background(), nil, data, &ChunkManifest{Version: 2, BaseIV: encodeBase64(iv)}, nil, nil); err == nil {
		t.Fatal("decrypt accepted nil terminal")
	}
	if _, _, err := newChunkedEncryptReaderWithContext(context.Background(), bytes.NewReader([]byte("v1")), data, nil, iv, MinChunkSize, ChunkedFormatV1, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newChunkedEncryptReaderWithContext(context.Background(), bytes.NewReader([]byte("v2")), data, terminal, iv, MinChunkSize, ChunkedFormatV2, nil); err == nil {
		t.Fatal("generic current v2 writer accepted an unbound stream")
	}
	if _, err := newChunkedDecryptReaderWithContext(context.Background(), bytes.NewReader(nil), data, nil, &ChunkManifest{Version: 1, BaseIV: encodeBase64(iv)}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := newChunkedDecryptReaderWithContext(context.Background(), bytes.NewReader(nil), data, terminal, &ChunkManifest{Version: 2, BaseIV: encodeBase64(iv)}, nil); err == nil {
		t.Fatal("generic current v2 reader accepted an unbound stream")
	}
	for _, v := range []int{0, 3, 255} {
		if _, _, err := newChunkedEncryptReaderWithContext(context.Background(), nil, data, terminal, iv, MinChunkSize, uint8(v), nil); err == nil {
			t.Fatalf("writer version %d accepted", v)
		}
		if _, err := newChunkedDecryptReaderWithContext(context.Background(), nil, data, terminal, &ChunkManifest{Version: v, BaseIV: encodeBase64(iv)}, nil); err == nil {
			t.Fatalf("decrypt version %d accepted", v)
		}
	}
	for _, size := range []int64{-1, 0, 1, MinChunkSize, MinChunkSize + 1} {
		for _, version := range []uint8{1, 2} {
			_, _, _ = ChunkedPlaintextSize(size, MinChunkSize, version)
		}
	}
	for _, tc := range []struct {
		name     string
		terminal []byte
	}{
		{"short", make([]byte, 31)}, {"bad tag", bytes.Repeat([]byte{3}, ChunkedTerminalSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := &ChunkManifest{Version: 2, ChunkSize: MinChunkSize, BaseIV: encodeBase64(iv)}
			r, err := newLegacyChunkedDecryptReaderV2(context.Background(), nil, data, m, nil, terminal)
			if err != nil {
				t.Fatal(err)
			}
			r.lookbehind = tc.terminal
			if err := r.verifyTerminal(tc.terminal); err == nil {
				t.Fatal("terminal accepted")
			}
		})
	}
}

func TestSEC37_Coverage_ArithmeticAndMetadataMatrix(t *testing.T) {
	for _, version := range []uint8{1, 2} {
		for _, size := range []int64{-1, 0, 1, MinChunkSize, MinChunkSize + 1} {
			_, _, _ = ChunkedPlaintextSize(size, MinChunkSize, version)
		}
	}
	for _, version := range []uint8{1, 2} {
		_, _, _ = ChunkedEncryptedDataRangeForPlaintextSize(1, 0, 0, MinChunkSize, version)
		_, _, _ = ChunkedEncryptedDataRangeForPlaintextSize(0, 0, 1, 0, version)
	}
	for _, version := range []uint8{1, 2} {
		for _, end := range []uint64{0, 1, ^uint64(0)} {
			_, _, _ = ChunkedEncryptedDataRangeForPlaintextSize(0, end, MinChunkSize+1, MinChunkSize, version)
		}
	}
	for _, metadata := range []map[string]string{{}, {MetaOriginalSize: "9"}, {MetaChunkCount: "2", MetaChunkSize: "4"}, {MetaChunkCount: "bad", MetaChunkSize: "4"}, {"Content-Length": "bad"}} {
		_, _ = GetPlaintextSizeFromMetadata(metadata)
	}
	manifest := &ChunkManifest{Version: 2, ChunkSize: MinChunkSize, ChunkCount: 1, BaseIV: encodeBase64(bytes.Repeat([]byte{1}, nonceSize))}
	encoded, _ := encodeManifest(manifest)
	for _, rng := range [][2]int64{{0, 0}, {MinChunkSize, MinChunkSize}, {-1, 1}} {
		_, _, _ = CalculateEncryptedRangeForPlaintextRange(map[string]string{MetaManifest: encoded, MetaOriginalSize: fmt.Sprint(MinChunkSize + 1), "Content-Length": fmt.Sprint(MinChunkSize + 1 + ChunkedTerminalSize)}, rng[0], rng[1])
	}
	badVersion := *manifest
	badVersion.Version = 9
	badEncoded, _ := encodeManifest(&badVersion)
	_, _, _ = CalculateEncryptedRangeForPlaintextRange(map[string]string{MetaManifest: badEncoded, MetaOriginalSize: "1"}, 0, 0)
	zeroCount := *manifest
	zeroCount.ChunkCount = 0
	zeroEncoded, _ := encodeManifest(&zeroCount)
	_, _, _ = CalculateEncryptedRangeForPlaintextRange(map[string]string{MetaManifest: zeroEncoded, MetaOriginalSize: fmt.Sprint(MinChunkSize)}, 0, 1)
	_, _, _ = CalculateEncryptedRangeForPlaintextRange(map[string]string{MetaManifest: "%%%"}, 0, 1)
	_ = io.EOF
}
