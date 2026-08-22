package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"math"
	"testing"
)

func makeSEC37V2Object(t *testing.T, plaintext []byte) ([]byte, *ChunkManifest, cipher.AEAD, cipher.AEAD) {
	t.Helper()
	key := bytes.Repeat([]byte{0x31}, aesKeySize)
	baseIV := bytes.Repeat([]byte{0x52}, nonceSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	dataAEAD, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	terminalAEAD, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	reader, manifest, err := newLegacyChunkedEncryptReaderV2(context.Background(), bytes.NewReader(plaintext), dataAEAD, baseIV, MinChunkSize, nil, ChunkedFormatV2, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext, manifest, dataAEAD, terminalAEAD
}

func TestSEC37PhaseB_V2CompletenessFailures(t *testing.T) {
	plaintext := []byte("authenticated chunk")
	ciphertext, manifest, dataAEAD, terminalAEAD := makeSEC37V2Object(t, plaintext)
	baseCases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated terminal", func(b []byte) []byte { return b[:len(b)-1] }},
		{"tampered terminal", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }},
		{"extra bytes", func(b []byte) []byte { return append(b, 0) }},
	}
	for _, tc := range baseCases {
		t.Run(tc.name, func(t *testing.T) {
			reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(tc.mutate(append([]byte(nil), ciphertext...))), dataAEAD, manifest, nil, terminalAEAD)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
				t.Fatalf("error = %v, want completeness failure", err)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		count uint64
		size  uint64
	}{
		{"count mismatch", 2, uint64(len(plaintext))},
		{"size mismatch", 1, uint64(len(plaintext) + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			baseIV, err := decodeBase64(manifest.BaseIV)
			if err != nil {
				t.Fatal(err)
			}
			nonce, err := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
			if err != nil {
				t.Fatal(err)
			}
			terminal := encodeChunkedTerminal(tc.count, tc.size)
			replacement := terminalAEAD.Seal(nil, nonce, terminal[:], buildTerminalAAD(ChunkedFormatV2))
			mutated := append([]byte(nil), ciphertext[:len(ciphertext)-ChunkedTerminalSize]...)
			mutated = append(mutated, replacement...)
			reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(mutated), dataAEAD, manifest, nil, terminalAEAD)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
				t.Fatalf("error = %v, want completeness failure", err)
			}
		})
	}

	emptyCiphertext, emptyManifest, emptyDataAEAD, emptyTerminalAEAD := makeSEC37V2Object(t, nil)
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(emptyCiphertext), emptyDataAEAD, emptyManifest, nil, emptyTerminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	if err != nil || len(decoded) != 0 {
		t.Fatalf("empty round trip = %q, %v", decoded, err)
	}
}

func TestSEC37PhaseB_UnknownVersionRejected(t *testing.T) {
	manifest := &ChunkManifest{Version: 3, ChunkSize: MinChunkSize, BaseIV: encodeBase64(bytes.Repeat([]byte{1}, nonceSize))}
	if _, err := newChunkedDecryptReader(bytes.NewReader(nil), nil, manifest, nil); !errors.Is(err, ErrUnsupportedChunkedVersion) {
		t.Fatalf("error = %v, want unsupported version", err)
	}
}

func TestSEC37PhaseA_TerminalCodec(t *testing.T) {
	encoded := encodeChunkedTerminal(7, 65537)
	count, size, err := decodeChunkedTerminal(encoded[:])
	if err != nil || count != 7 || size != 65537 {
		t.Fatalf("decoded terminal = (%d, %d, %v)", count, size, err)
	}
	if _, _, err := decodeChunkedTerminal(make([]byte, 15)); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("short terminal error = %v", err)
	}
}

func TestSEC37PhaseA_NonceAndAADDomains(t *testing.T) {
	baseIV := bytes.Repeat([]byte{0x42}, nonceSize)
	dataNonce, err := deriveChunkNonceHKDF(baseIV, ChunkedFormatV2, 0)
	if err != nil {
		t.Fatal(err)
	}
	terminalNonce, err := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dataNonce, terminalNonce) {
		t.Fatal("data and terminal nonce domains collided")
	}
	if bytes.Equal(buildChunkAAD(ChunkedFormatV2, 0), buildTerminalAAD(ChunkedFormatV2)) {
		t.Fatal("data and terminal AAD domains collided")
	}
	if _, err := deriveChunkNonceHKDF(baseIV, ChunkedFormatV1, 0); !errors.Is(err, ErrUnsupportedChunkedVersion) {
		t.Fatalf("v1 nonce derivation error = %v", err)
	}
}

func TestSEC37PhaseA_SizeEquations(t *testing.T) {
	for _, version := range []uint8{ChunkedFormatV1, ChunkedFormatV2} {
		for _, plaintextSize := range []int64{0, 1, 65536, 65537} {
			ciphertextSize, err := ChunkedCiphertextSize(plaintextSize, 65536, version)
			if err != nil {
				t.Fatal(err)
			}
			decodedSize, count, err := ChunkedPlaintextSize(ciphertextSize, 65536, version)
			if err != nil || decodedSize != plaintextSize {
				t.Fatalf("v%d size round trip: %d -> %d, %d, %v", version, plaintextSize, ciphertextSize, decodedSize, err)
			}
			expectedCount, _ := ChunkedDataChunkCount(plaintextSize, 65536)
			if count != expectedCount {
				t.Fatalf("v%d count = %d, want %d", version, count, expectedCount)
			}
		}
	}
}

func TestSEC37PhaseA_ArithmeticRejectsInvalidInput(t *testing.T) {
	if _, err := ChunkedCiphertextSize(-1, 65536, ChunkedFormatV2); err == nil {
		t.Fatal("negative plaintext accepted")
	}
	if _, err := ChunkedCiphertextSize(1, 65536, 3); !errors.Is(err, ErrUnsupportedChunkedVersion) {
		t.Fatalf("unknown version error = %v", err)
	}
	if _, _, err := ChunkedPlaintextSize(33, 65536, ChunkedFormatV2); err == nil {
		t.Fatal("non-canonical ciphertext accepted")
	}
	if _, err := ChunkedCiphertextSize(math.MaxInt64, 1, ChunkedFormatV2); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestSEC37PhaseA_DataRangeExcludesTerminal(t *testing.T) {
	start, end, err := ChunkedEncryptedDataRange(2, 3, 65536, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	if start != 131104 || end != 262207 {
		t.Fatalf("range = %d-%d", start, end)
	}
	ciphertextSize, _ := ChunkedCiphertextSize(4*65536, 65536, ChunkedFormatV2)
	if end >= ciphertextSize-ChunkedTerminalSize {
		t.Fatalf("range includes terminal: end=%d ciphertext=%d", end, ciphertextSize)
	}
}
