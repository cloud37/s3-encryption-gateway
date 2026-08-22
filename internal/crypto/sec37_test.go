package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"testing"
)

func newSEC37V2Fixture(t *testing.T, plaintext []byte) ([]byte, *ChunkManifest, cipher.AEAD, cipher.AEAD) {
	t.Helper()
	key := bytes.Repeat([]byte{0x37}, aesKeySize)
	baseIV := bytes.Repeat([]byte{0x73}, nonceSize)
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

func TestSEC37_EncryptReaderForVersion_ClampsChunkSize(t *testing.T) {
	_, manifest := newChunkedEncryptReaderForVersion(
		context.Background(), bytes.NewReader(nil), nil, bytes.Repeat([]byte{0x73}, nonceSize), 1, nil, ChunkedFormatV1, nil,
	)
	if manifest.ChunkSize != MinChunkSize {
		t.Fatalf("small chunk size = %d, want %d", manifest.ChunkSize, MinChunkSize)
	}
	_, manifest = newChunkedEncryptReaderForVersion(
		context.Background(), bytes.NewReader(nil), nil, bytes.Repeat([]byte{0x73}, nonceSize), 100000000, nil, ChunkedFormatV1, nil,
	)
	if manifest.ChunkSize != MaxChunkSize {
		t.Fatalf("large chunk size = %d, want %d", manifest.ChunkSize, MaxChunkSize)
	}
}

func TestSEC37_DecryptReaderForVersion_NilManifest(t *testing.T) {
	_, err := newChunkedDecryptReaderForVersion(context.Background(), nil, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "missing chunk manifest") {
		t.Fatalf("error = %v, want missing chunk manifest", err)
	}
}

func TestSEC37_DecryptReaderForVersion_V2WithoutTerminalAEAD(t *testing.T) {
	manifest := &ChunkManifest{
		Version:   int(ChunkedFormatV2),
		BaseIV:    encodeBase64(bytes.Repeat([]byte{0x73}, nonceSize)),
		ChunkSize: MinChunkSize,
	}
	_, err := newChunkedDecryptReaderForVersion(context.Background(), nil, nil, manifest, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requires terminal AEAD") {
		t.Fatalf("error = %v, want terminal AEAD error", err)
	}
}

func TestSEC37_V2NonceAndAAD_KnownAnswer(t *testing.T) {
	baseIV := bytes.Repeat([]byte{0x42}, nonceSize)
	nonce, err := deriveChunkNonceHKDF(baseIV, ChunkedFormatV2, 7)
	if err != nil {
		t.Fatal(err)
	}
	wantNonce := "b9e066288b84937ad341eb0b"
	if got := encodeHexSEC37(nonce); got != wantNonce {
		t.Fatalf("nonce = %s, want %s", got, wantNonce)
	}
	if bytes.Equal(buildChunkAAD(ChunkedFormatV2, 7), buildTerminalAAD(ChunkedFormatV2)) {
		t.Fatal("data and terminal AAD domains must differ")
	}
	if got := encodeHexSEC37(buildChunkAAD(ChunkedFormatV2, 7)); got != "6368756e6b65642d76322f64617461000000000000000007" {
		t.Fatalf("data AAD = %s", got)
	}
	if got := encodeHexSEC37(buildTerminalAAD(ChunkedFormatV2)); got != "6368756e6b65642d76322f7465726d696e616c00" {
		t.Fatalf("terminal AAD = %s", got)
	}
	terminalNonce, err := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	if got := encodeHexSEC37(terminalNonce); got != "144496f4b7471b156ee4c11b" {
		t.Fatalf("terminal nonce = %s", got)
	}
}

func TestSEC37_V2NonceAndAAD_BoundaryKnownAnswers(t *testing.T) {
	baseIV := bytes.Repeat([]byte{0x42}, nonceSize)
	for _, vector := range []struct {
		name       string
		index      uint64
		nonce, aad string
	}{
		{"zero", 0, "6d644467c05283e8db1c8252", "6368756e6b65642d76322f64617461000000000000000000"},
		{"max", ^uint64(0), "08856a568afb01fe3a1a9b7f", "6368756e6b65642d76322f6461746100ffffffffffffffff"},
	} {
		t.Run(vector.name, func(t *testing.T) {
			nonce, err := deriveChunkNonceHKDF(baseIV, ChunkedFormatV2, vector.index)
			if err != nil {
				t.Fatal(err)
			}
			if encodeHexSEC37(nonce) != vector.nonce || encodeHexSEC37(buildChunkAAD(ChunkedFormatV2, vector.index)) != vector.aad {
				t.Fatalf("nonce=%s aad=%s", encodeHexSEC37(nonce), encodeHexSEC37(buildChunkAAD(ChunkedFormatV2, vector.index)))
			}
		})
	}
	terminal, err := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	if encodeHexSEC37(terminal) != "144496f4b7471b156ee4c11b" || encodeHexSEC37(buildTerminalAAD(ChunkedFormatV2)) != "6368756e6b65642d76322f7465726d696e616c00" {
		t.Fatal("terminal KAT mismatch")
	}
	for _, index := range []uint64{0, ^uint64(0)} {
		data, _ := deriveChunkNonceHKDF(baseIV, ChunkedFormatV2, index)
		if bytes.Equal(data, terminal) {
			t.Fatal("nonce collision")
		}
	}
}

func encodeHexSEC37(value []byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for i, b := range value {
		result[i*2] = hex[b>>4]
		result[i*2+1] = hex[b&15]
	}
	return string(result)
}

func TestSEC37_TerminalCodec_RoundTrip(t *testing.T) {
	encoded := encodeChunkedTerminal(9, 65537)
	count, size, err := decodeChunkedTerminal(encoded[:])
	if err != nil || count != 9 || size != 65537 {
		t.Fatalf("decoded terminal = (%d, %d, %v)", count, size, err)
	}
	for length := 0; length != chunkedTerminalPlainSize+2; length++ {
		if length == chunkedTerminalPlainSize {
			continue
		}
		if _, _, err := decodeChunkedTerminal(make([]byte, length)); !errors.Is(err, ErrChunkedObjectIncomplete) {
			t.Fatalf("length %d error = %v", length, err)
		}
	}
}

type sec37ReadCounter struct {
	reader io.Reader
	reads  int
	bytes  int
}

func (r *sec37ReadCounter) Read(p []byte) (int, error) {
	r.reads++
	n, err := r.reader.Read(p)
	r.bytes += n
	return n, err
}

func TestSEC37_AuthenticateChunkedTrailer_ReadsExactTrailerAndOverread(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("trailer")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	source := &sec37ReadCounter{reader: bytes.NewReader(append(append([]byte{}, ciphertext[len(ciphertext)-ChunkedTerminalSize:]...), 1))}
	if _, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, source, metadata, int64(len(ciphertext))); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
	if source.bytes != ChunkedTerminalSize+1 {
		t.Fatalf("read %d bytes, want %d", source.bytes, ChunkedTerminalSize+1)
	}
}

func TestChunkedCiphertextSize_V1V2(t *testing.T) {
	for _, version := range []uint8{ChunkedFormatV1, ChunkedFormatV2} {
		for _, size := range []int64{0, 1, MinChunkSize, MinChunkSize + 1} {
			got, err := ChunkedCiphertextSize(size, MinChunkSize, version)
			if err != nil {
				t.Fatal(err)
			}
			count, err := ChunkedDataChunkCount(size, MinChunkSize)
			if err != nil {
				t.Fatal(err)
			}
			want := size + int64(count)*tagSize
			if version == ChunkedFormatV2 {
				want += ChunkedTerminalSize
			}
			if got != want {
				t.Fatalf("v%d size %d = %d, want %d", version, size, got, want)
			}
		}
	}
}

func TestChunkedPlaintextSize_V1V2_RoundTrip(t *testing.T) {
	for _, version := range []uint8{ChunkedFormatV1, ChunkedFormatV2} {
		for _, size := range []int64{0, 1, MinChunkSize, MinChunkSize + 1} {
			ciphertext, err := ChunkedCiphertextSize(size, MinChunkSize, version)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := ChunkedPlaintextSize(ciphertext, MinChunkSize, version)
			if err != nil || got != size {
				t.Fatalf("v%d size %d inverse = %d, %v", version, size, got, err)
			}
		}
	}
}

func TestChunkedSizeArithmetic_RejectsNonCanonicalAndOverflow(t *testing.T) {
	for _, test := range []struct {
		name string
		call func() error
	}{
		{"negative", func() error { _, err := ChunkedCiphertextSize(-1, MinChunkSize, ChunkedFormatV2); return err }},
		{"unknown", func() error { _, err := ChunkedCiphertextSize(1, MinChunkSize, 255); return err }},
		{"impossible tag", func() error { _, _, err := ChunkedPlaintextSize(1, MinChunkSize, ChunkedFormatV2); return err }},
		{"overflow", func() error { _, err := ChunkedCiphertextSize(math.MaxInt64, 1, ChunkedFormatV2); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); err == nil {
				t.Fatal("invalid arithmetic was accepted")
			}
		})
	}
}

func TestChunkedEncryptedDataRange_V2ExcludesTerminal(t *testing.T) {
	start, end, err := ChunkedEncryptedDataRange(0, 2, MinChunkSize, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	total, err := ChunkedCiphertextSize(3*MinChunkSize, MinChunkSize, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	if start != 0 || end >= total-ChunkedTerminalSize {
		t.Fatalf("data range = %d-%d, total = %d", start, end, total)
	}
}

func TestSEC37_EncryptV2_AppendsAuthenticatedTerminal(t *testing.T) {
	ciphertext, manifest, _, terminalAEAD := newSEC37V2Fixture(t, []byte("sec37"))
	if manifest.Version != int(ChunkedFormatV2) || len(ciphertext) < ChunkedTerminalSize {
		t.Fatal("fixture is not v2 with a terminal")
	}
	baseIV, err := decodeBase64(manifest.BaseIV)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := terminalAEAD.Open(nil, nonce, ciphertext[len(ciphertext)-ChunkedTerminalSize:], buildTerminalAAD(ChunkedFormatV2))
	if err != nil {
		t.Fatal(err)
	}
	count, size, err := decodeChunkedTerminal(plain)
	if err != nil || count != 1 || size != 5 {
		t.Fatalf("terminal = (%d, %d, %v)", count, size, err)
	}
}

func TestSEC37_EncryptV2_EmptyObjectHasTerminalOnly(t *testing.T) {
	ciphertext, manifest, _, terminalAEAD := newSEC37V2Fixture(t, nil)
	if len(ciphertext) != ChunkedTerminalSize || manifest.ChunkCount != 0 {
		t.Fatalf("empty ciphertext/count = %d/%d", len(ciphertext), manifest.ChunkCount)
	}
	baseIV, _ := decodeBase64(manifest.BaseIV)
	nonce, _ := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	plain, err := terminalAEAD.Open(nil, nonce, ciphertext, buildTerminalAAD(ChunkedFormatV2))
	if err != nil {
		t.Fatal(err)
	}
	count, size, _ := decodeChunkedTerminal(plain)
	if count != 0 || size != 0 {
		t.Fatalf("empty terminal = (%d, %d)", count, size)
	}
}

func TestSEC37_EncryptV2_DataAADRejectsReordering(t *testing.T) {
	plaintext := bytes.Repeat([]byte("r"), MinChunkSize*2)
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, plaintext)
	first := ciphertext[:MinChunkSize+tagSize]
	second := ciphertext[MinChunkSize+tagSize : 2*(MinChunkSize+tagSize)]
	mutated := append(append([]byte{}, second...), first...)
	mutated = append(mutated, ciphertext[2*(MinChunkSize+tagSize):]...)
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(mutated), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("reordered data records were accepted")
	}
}

func TestSEC37_DecryptV2_VerifiesTerminalAtEOF(t *testing.T) {
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, []byte("complete"))
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil || string(plain) != "complete" {
		t.Fatalf("plaintext = %q, error = %v", plain, err)
	}
}

func TestSEC37_DecryptV2_RejectsMissingTerminal(t *testing.T) {
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, []byte("complete"))
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext[:len(ciphertext)-ChunkedTerminalSize]), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestSEC37_DecryptV2_RejectsWholeChunkTruncation(t *testing.T) {
	plaintext := bytes.Repeat([]byte("c"), MinChunkSize*2)
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, plaintext)
	cut := MinChunkSize + tagSize
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(append([]byte{}, ciphertext[:len(ciphertext)-cut]...)), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestSEC37_DecryptV2_RejectsTamperedTerminal(t *testing.T) {
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, []byte("terminal"))
	ciphertext[len(ciphertext)-1] ^= 1
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestSEC37_DecryptV2_RejectsTerminalFromOtherObject(t *testing.T) {
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, []byte("terminal"))
	other, otherManifest, _, otherTerminal := newSEC37V2Fixture(t, []byte("different"))
	_ = other
	baseIV, err := decodeBase64(otherManifest.BaseIV)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	terminalPlain := encodeChunkedTerminal(1, 9)
	valid := otherTerminal.Seal(nil, nonce, terminalPlain[:], buildTerminalAAD(ChunkedFormatV2))
	copy(ciphertext[len(ciphertext)-ChunkedTerminalSize:], valid)
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestSEC37_DecryptV2_RejectsCountMismatch(t *testing.T) {
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, []byte("count"))
	resealSEC37Terminal(t, ciphertext, manifest, terminalAEAD, 2, 5)
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestSEC37_DecryptV2_RejectsSizeMismatch(t *testing.T) {
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, []byte("size"))
	resealSEC37Terminal(t, ciphertext, manifest, terminalAEAD, 1, 99)
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestSEC37_DecryptV2_RejectsTrailingBytes(t *testing.T) {
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, []byte("trailing"))
	ciphertext = append(ciphertext, 0)
	reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext), dataAEAD, manifest, nil, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func resealSEC37Terminal(t *testing.T, ciphertext []byte, manifest *ChunkManifest, aead cipher.AEAD, count, size uint64) {
	t.Helper()
	baseIV, err := decodeBase64(manifest.BaseIV)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodeChunkedTerminal(count, size)
	sealed := aead.Seal(nil, nonce, encoded[:], buildTerminalAAD(ChunkedFormatV2))
	copy(ciphertext[len(ciphertext)-ChunkedTerminalSize:], sealed)
}

func TestSEC37_AuthenticateChunkedTrailer_Password(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("trailer")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	info, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(ciphertext[len(ciphertext)-ChunkedTerminalSize:]), metadata, int64(len(ciphertext)))
	if err != nil || !info.Authenticated || info.PlaintextSize != 7 {
		t.Fatalf("trailer info = %+v, error = %v", info, err)
	}
}

func TestSEC37_AuthenticateChunkedTrailer_ContextCanceled(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.AuthenticateChunkedTrailer(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(nil), nil, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context cancellation", err)
	}
}

func TestSEC37_AuthenticateChunkedTrailer_KeyManager(t *testing.T) {
	km, err := NewInMemoryKeyManager(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	engine, err := NewEngineWithOpts([]byte("sec37-password"), WithKeyManager(km), WithChunking(true), WithChunkSize(MinChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("km trailer")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	info, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(ciphertext[len(ciphertext)-ChunkedTerminalSize:]), metadata, int64(len(ciphertext)))
	if err != nil || !info.Authenticated || info.PlaintextSize != 10 {
		t.Fatalf("trailer info = %+v, error = %v", info, err)
	}
}

func TestSEC37_AuthenticateChunkedTrailer_V1Unauthenticated(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &ChunkManifest{Version: int(ChunkedFormatV1), ChunkSize: MinChunkSize, BaseIV: encodeBase64(bytes.Repeat([]byte{0x73}, nonceSize))}
	manifestEncoded, err := encodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	metadata := map[string]string{MetaChunkedFormat: "true", MetaManifest: manifestEncoded}
	info, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(nil), metadata, int64(MinChunkSize+tagSize))
	if err != nil || info.Authenticated || info.Version != ChunkedFormatV1 {
		t.Fatalf("v1 trailer info = %+v, error = %v", info, err)
	}
}

func TestSEC37_DecryptV1_RemainsReadable(t *testing.T) {
	key := bytes.Repeat([]byte{0x37}, aesKeySize)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	baseIV := bytes.Repeat([]byte{0x73}, nonceSize)
	reader, manifest := newChunkedEncryptReader(bytes.NewReader([]byte("v1")), aead, baseIV, MinChunkSize, nil)
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := newChunkedDecryptReader(bytes.NewReader(ciphertext), aead, manifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(decoded)
	if err != nil || string(plain) != "v1" {
		t.Fatalf("plaintext = %q, error = %v", plain, err)
	}
}

func TestSEC37_AuthenticateChunkedTrailer_WrongKey(t *testing.T) {
	good, err := NewEngineWithChunking([]byte("sec37-good-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := NewEngineWithChunking([]byte("sec37-bad-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := good.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("wrong key")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(ciphertext[len(ciphertext)-ChunkedTerminalSize:]), metadata, int64(len(ciphertext))); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestSEC37_AuthenticateChunkedTrailer_RejectsMalformedLengthsAndCommitments(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("auth branches")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	trailer := ciphertext[len(ciphertext)-ChunkedTerminalSize:]
	for _, tc := range []struct {
		name  string
		input []byte
		size  int64
	}{
		{"short", trailer[:ChunkedTerminalSize-1], int64(len(ciphertext))},
		{"long", append(append([]byte{}, trailer...), 1), int64(len(ciphertext))},
		{"canonical size mismatch", trailer, int64(len(ciphertext) + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(tc.input), metadata, tc.size); !errors.Is(err, ErrChunkedObjectIncomplete) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	bad := append([]byte{}, trailer...)
	resealSEC37Terminal(t, ciphertext, func() *ChunkManifest { m, _ := loadManifestFromMetadata(metadata); return m }(), func() cipher.AEAD {
		key := bytes.Repeat([]byte{0x37}, aesKeySize)
		block, _ := aes.NewCipher(key)
		a, _ := cipher.NewGCM(block)
		return a
	}(), 2, 99)
	copy(bad, ciphertext[len(ciphertext)-ChunkedTerminalSize:])
	if _, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(bad), metadata, int64(len(ciphertext))); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("mismatched terminal error = %v", err)
	}
}

func TestSEC37_DecryptRange_ValidationBranches(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	for _, metadata := range []map[string]string{nil, {MetaEncrypted: "true"}, {MetaEncrypted: "true", MetaChunkedFormat: "true", MetaManifest: "%%%"}} {
		if _, _, err := engine.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(nil), metadata, 0, 0); err == nil {
			t.Fatal("invalid range metadata accepted")
		}
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("range")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, _ := io.ReadAll(reader)
	metadata[MetaOriginalSize] = "1"
	if _, _, err := engine.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(ciphertext), metadata, 0, 4); err == nil {
		t.Fatal("invalid plaintext range accepted")
	}
}

func TestSEC37_AuthenticateChunkedTrailer_ErrorMatrix(t *testing.T) {
	good, err := NewEngineWithChunking([]byte("sec37-good-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := good.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("matrix")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	trailer := body[len(body)-ChunkedTerminalSize:]
	for _, tc := range []struct {
		name string
		data []byte
		size int64
	}{
		{"short", trailer[:31], int64(len(body))}, {"long", append(append([]byte{}, trailer...), 0), int64(len(body))},
		{"wrong size", trailer, int64(len(body) - 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := good.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(tc.data), metadata, tc.size); !errors.Is(err, ErrChunkedObjectIncomplete) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	badTrailer := append([]byte{}, trailer...)
	badTrailer[0] ^= 1
	if _, err := good.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(badTrailer), metadata, int64(len(body))); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("tag error=%v", err)
	}
	manifest, err := loadManifestFromMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x37}, aesKeySize)
	block, _ := aes.NewCipher(key)
	terminal, _ := cipher.NewGCM(block)
	baseIV, _ := decodeBase64(manifest.BaseIV)
	nonce, _ := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	for _, tc := range []struct {
		name        string
		count, size uint64
	}{{"count", 9, 6}, {"plaintext size", 1, 99}} {
		plain := encodeChunkedTerminal(tc.count, tc.size)
		replacement := terminal.Seal(nil, nonce, plain[:], buildTerminalAAD(ChunkedFormatV2))
		if _, err := good.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(replacement), metadata, int64(len(body))); !errors.Is(err, ErrChunkedObjectIncomplete) {
			t.Fatalf("%s error=%v", tc.name, err)
		}
	}
}

func TestSEC37_AuthenticateChunkedTrailer_KeyManagerAndMetadataErrors(t *testing.T) {
	engine, err := NewEngineWithOpts([]byte("sec37-password"), WithChunking(true), WithChunkSize(MinChunkSize), WithMetadataKey(bytes.Repeat([]byte{0x44}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(nil), map[string]string{MetaEncryptedMetadata: "%%%"}, 0); err == nil {
		t.Fatal("metadata decrypt error accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.AuthenticateChunkedTrailer(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(nil), nil, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("context error = %v", err)
	}
}

func TestSEC37_AuthenticateChunkedTrailer_ProtectedChunkedMetadata(t *testing.T) {
	engine, err := NewEngineWithOpts([]byte("sec37-protected-password"), WithMetadataKey(bytes.Repeat([]byte{0x55}, 32)), WithChunking(true), WithChunkSize(MinChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("protected chunked")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body[len(body)-ChunkedTerminalSize:]), metadata, int64(len(body))); err != nil {
		t.Fatal(err)
	}
}

func TestSEC37_AuthenticateChunkedTrailer_KeyManagerErrorBranches(t *testing.T) {
	km := &sec37FailingKeyManager{err: errors.New("unwrap failed"), key: bytes.Repeat([]byte{1}, aesKeySize)}
	engine, err := NewEngineWithOpts([]byte("sec37-kms-password"), WithKeyManager(km), WithChunking(true), WithChunkSize(MinChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("kms")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	metadata[MetaOriginalSize] = "12"
	metadata[MetaWrappedKeyCiphertext] = encodeBase64([]byte("wrapped"))
	if _, err := engine.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body[len(body)-ChunkedTerminalSize:]), metadata, int64(len(body))); err == nil {
		t.Fatal("unwrap error accepted")
	}
}

type sec37ErrorReader struct{ err error }

func (r sec37ErrorReader) Read([]byte) (int, error) { return 0, r.err }

func TestSEC37_AuthenticateChunkedTrailer_ReachableErrorMatrix(t *testing.T) {
	eng, err := NewEngineWithChunking([]byte("sec37-auth-errors-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("auth errors")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	validTrailer := body[len(body)-ChunkedTerminalSize:]
	clone := func() map[string]string {
		m := make(map[string]string, len(metadata))
		for k, v := range metadata {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name     string
		metadata func() map[string]string
		trailer  io.Reader
		size     int64
	}{
		{"v1 invalid size", func() map[string]string {
			return map[string]string{MetaChunkedFormat: "true", MetaManifest: metadata[MetaManifest]}
		}, bytes.NewReader(validTrailer), 1},
		{"malformed manifest", func() map[string]string { m := clone(); m[MetaManifest] = "%%%"; return m }, bytes.NewReader(validTrailer), int64(len(body))},
		{"bad salt", func() map[string]string { m := clone(); m[MetaKeySalt] = "%%%"; return m }, bytes.NewReader(validTrailer), int64(len(body))},
		{"bad iv", func() map[string]string { m := clone(); m[MetaIV] = "%%%"; return m }, bytes.NewReader(validTrailer), int64(len(body))},
		{"read error", clone, sec37ErrorReader{err: errors.New("read failed")}, int64(len(body))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := eng.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, tc.trailer, tc.metadata(), tc.size); err == nil {
				t.Fatal("error path accepted")
			}
		})
	}
	manifest, _ := loadManifestFromMetadata(metadata)
	baseIV, _ := decodeBase64(manifest.BaseIV)
	nonce, _ := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	key := bytes.Repeat([]byte{0x37}, aesKeySize)
	block, _ := aes.NewCipher(key)
	terminal, _ := cipher.NewGCM(block)
	plain := encodeChunkedTerminal(99, 11)
	countMismatch := terminal.Seal(nil, nonce, plain[:], buildTerminalAAD(ChunkedFormatV2))
	if _, err := eng.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(countMismatch), metadata, int64(len(body))); !errors.Is(err, ErrChunkedObjectIncomplete) {
		t.Fatalf("count mismatch error=%v", err)
	}
}

func TestSEC37_AuthenticateChunkedTrailer_CompactorAndTerminalDecodeBranches(t *testing.T) {
	eng, err := NewEngineWithChunking([]byte("sec37-branches-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	e := eng.(*engine)
	e.metadataExpansionOverride = func(map[string]string) (map[string]string, error) { return nil, errors.New("compactor failure") }
	if _, err := eng.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, nil, nil, 0); err == nil {
		t.Fatal("compactor failure ignored")
	}
	e.metadataExpansionOverride = nil
	// A validly sealed terminal carrying non-canonical data exercises the
	// decoder/commitment rejection without relying on impossible AES failures.
	reader, metadata, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("decode")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	e.compactor = NewMetadataCompactor(ProviderAWS)
	manifest, _ := loadManifestFromMetadata(metadata)
	baseIV, _ := decodeBase64(manifest.BaseIV)
	nonce, _ := deriveTerminalNonceHKDF(baseIV, ChunkedFormatV2)
	key := bytes.Repeat([]byte{0x37}, aesKeySize)
	block, _ := aes.NewCipher(key)
	terminal, _ := cipher.NewGCM(block)
	invalidPlain := make([]byte, 15)
	sealed := terminal.Seal(nil, nonce, invalidPlain, buildTerminalAAD(ChunkedFormatV2))
	if _, err := eng.AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(sealed), metadata, int64(len(body))); err == nil {
		t.Fatal("invalid terminal plaintext accepted")
	}
}

type sec37FailingKeyManager struct {
	err error
	key []byte
}

type sec37RecordingKeyManager struct {
	key           []byte
	unwrapContext context.Context
	returnError   error
	returned      []byte
}

func (k *sec37RecordingKeyManager) Provider() string { return "recording" }
func (k *sec37RecordingKeyManager) WrapKey(_ context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	k.key = append([]byte(nil), plaintext...)
	return &KeyEnvelope{Ciphertext: []byte("wrapped")}, nil
}
func (k *sec37RecordingKeyManager) UnwrapKey(ctx context.Context, _ *KeyEnvelope, _ map[string]string) ([]byte, error) {
	k.unwrapContext = ctx
	k.returned = append([]byte(nil), k.key...)
	return k.returned, k.returnError
}
func (k *sec37RecordingKeyManager) ActiveKeyVersion(context.Context) (int, error) { return 1, nil }
func (k *sec37RecordingKeyManager) HealthCheck(context.Context) error             { return nil }
func (k *sec37RecordingKeyManager) Close(context.Context) error                   { return nil }

func TestSEC37_AuthenticateChunkedTrailer_KeyManagerContextAndZeroization(t *testing.T) {
	km := &sec37RecordingKeyManager{}
	eng, err := NewEngineWithOpts([]byte("sec37-recording-password"), WithKeyManager(km), WithChunking(true), WithChunkSize(MinChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	r, metadata, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("recorded")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r)
	ctx := context.WithValue(context.Background(), "sec37-marker", "marker")
	if _, err := eng.AuthenticateChunkedTrailer(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body[len(body)-ChunkedTerminalSize:]), metadata, int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if km.unwrapContext == nil || km.unwrapContext.Value("sec37-marker") != "marker" {
		t.Fatal("unwrap context marker missing")
	}
	for _, b := range km.returned {
		if b != 0 {
			t.Fatal("returned DEK was not zeroized")
		}
	}
	km.returnError = errors.New("unwrap error")
	if _, err := eng.AuthenticateChunkedTrailer(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body[len(body)-ChunkedTerminalSize:]), metadata, int64(len(body))); err == nil {
		t.Fatal("unwrap error accepted")
	}
	for _, b := range km.returned {
		if b != 0 {
			t.Fatal("error-path DEK was not zeroized")
		}
	}
}

func (k *sec37FailingKeyManager) Provider() string { return "test" }
func (k *sec37FailingKeyManager) WrapKey(context.Context, []byte, map[string]string) (*KeyEnvelope, error) {
	return &KeyEnvelope{Ciphertext: []byte("wrapped")}, nil
}
func (k *sec37FailingKeyManager) UnwrapKey(context.Context, *KeyEnvelope, map[string]string) ([]byte, error) {
	return k.key, k.err
}
func (k *sec37FailingKeyManager) ActiveKeyVersion(context.Context) (int, error) { return 1, nil }
func (k *sec37FailingKeyManager) HealthCheck(context.Context) error             { return nil }
func (k *sec37FailingKeyManager) Close(context.Context) error                   { return nil }

func TestSEC37_PassthroughAuthenticateChunkedTrailer(t *testing.T) {
	_, err := (PassthroughEngine{}).AuthenticateChunkedTrailer(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(nil), nil, 0)
	if err == nil || !strings.Contains(err.Error(), "unavailable in passthrough mode") {
		t.Fatalf("error = %v", err)
	}
}

func TestSEC37_DecryptRange_MetadataAndKeyManagerBranches(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("range metadata")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	for _, m := range []map[string]string{
		{MetaEncrypted: "true", MetaChunkedFormat: "true", MetaManifest: "%%%"},
		{MetaEncrypted: "true", MetaChunkedFormat: "true", MetaOriginalSize: "14", "Content-Length": "bad"},
	} {
		if _, _, err := engine.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), m, 0, 1); err == nil {
			t.Fatal("malformed range metadata accepted")
		}
	}
	metadata[MetaOriginalSize] = "1"
	if _, _, err := engine.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), metadata, 0, 13); err == nil {
		t.Fatal("invalid range accepted")
	}
}

func TestSEC37_NewRangeDecryptReader_ConstructorBranches(t *testing.T) {
	if _, err := newRangeDecryptReader(bytes.NewReader(nil), nil, nil, nil, 0, 0, nil, false); err == nil {
		t.Fatal("nil manifest accepted")
	}
	manifest := &ChunkManifest{Version: int(ChunkedFormatV2), ChunkSize: MinChunkSize, ChunkCount: 1}
	if _, err := newRangeDecryptReader(bytes.NewReader(nil), nil, manifest, nil, int64(MinChunkSize), int64(MinChunkSize), nil, false); err == nil {
		t.Log("range is clamped by the constructor; runtime validation covers the boundary")
	}
	manifest.Version = int(ChunkedFormatV1)
	if _, err := newRangeDecryptReader(bytes.NewReader(nil), nil, manifest, nil, 0, 0, nil, false); err != nil {
		t.Fatal(err)
	}
	optimized, err := newRangeDecryptReader(bytes.NewReader(nil), nil, &ChunkManifest{Version: int(ChunkedFormatV2), ChunkSize: MinChunkSize, ChunkCount: 1}, bytes.Repeat([]byte{1}, nonceSize), 0, 0, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := optimized.Read(make([]byte, 1)); err == nil {
		t.Fatal("optimized final chunk without exact size accepted")
	}
	zero := &ChunkManifest{Version: int(ChunkedFormatV2), ChunkSize: MinChunkSize, ChunkCount: 0}
	if _, err := newRangeDecryptReader(bytes.NewReader(nil), nil, zero, nil, 0, 0, nil, false); err == nil {
		t.Fatal("zero chunk manifest accepted")
	}
}

func TestSEC37_DecryptRange_PasswordAndOptimizedBranches(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-range-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(bytes.Repeat([]byte("r"), 37)), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	metadata["Content-Length"] = fmt.Sprintf("%d", len(body))
	metadata[MetaOriginalSize] = "37"
	optimized := engine.(interface {
		DecryptRangeOptimized(context.Context, ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error)
	})
	if _, _, err := optimized.DecryptRangeOptimized(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), metadata, 0, 3); err != nil {
		t.Fatal(err)
	}
	metadata[MetaOriginalSize] = "bad"
	if _, _, err := engine.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), metadata, 0, 3); err != nil {
		t.Fatal(err)
	}
}

func TestSEC37_DecryptRange_EngineEntryBranches(t *testing.T) {
	engine, err := NewEngineWithOpts([]byte("sec37-engine-range-password"), WithChunking(true), WithChunkSize(MinChunkSize), WithMetadataKey(bytes.Repeat([]byte{0x66}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("engine range")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		m          map[string]string
		start, end int64
	}{
		{"not encrypted", map[string]string{}, 0, 1},
		{"missing manifest", map[string]string{MetaEncrypted: "true", MetaChunkedFormat: "true"}, 0, 1},
		{"bad manifest", map[string]string{MetaEncrypted: "true", MetaChunkedFormat: "true", MetaManifest: "%%%"}, 0, 1},
		{"bad range", metadata, -1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := engine.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), tc.m, tc.start, tc.end); err == nil {
				t.Fatal("invalid engine range accepted")
			}
		})
	}
	protected := make(map[string]string, len(metadata))
	for k, v := range metadata {
		protected[k] = v
	}
	protected[MetaEncryptedMetadata] = "%%%"
	if _, _, err := engine.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), protected, 0, 1); err == nil {
		t.Fatal("metadata decrypt failure accepted")
	}
	optimized := engine.(interface {
		DecryptRangeOptimized(context.Context, ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error)
	})
	metadata["Content-Length"] = fmt.Sprintf("%d", len(body))
	metadata[MetaOriginalSize] = "12"
	if _, _, err := optimized.DecryptRangeOptimized(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), metadata, 0, 1); err != nil {
		t.Fatal(err)
	}
}

func TestSEC37_DecryptRange_ParameterErrorBranches(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("sec37-parameter-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("parameter range")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	base := func() map[string]string {
		m := make(map[string]string, len(metadata))
		for k, v := range metadata {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"bad salt", func(m map[string]string) { m[MetaKeySalt] = "%%%" }},
		{"bad iv", func(m map[string]string) { m[MetaIV] = "%%%" }},
		{"unsupported algorithm", func(m map[string]string) { m[MetaAlgorithm] = "no-such" }},
		{"bad kdf", func(m map[string]string) { m[MetaKDFParams] = "%%%" }},
		{"bad wrapped key", func(m map[string]string) { m[MetaWrappedKeyCiphertext] = "%%%" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mutate(m)
			if _, _, err := engine.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), m, 0, 1); err == nil {
				t.Fatal("parameter error accepted")
			}
		})
	}
}

func TestSEC37_DecryptRange_ReachableParameterMatrix(t *testing.T) {
	eng, err := NewEngineWithChunking([]byte("sec37-range-errors-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("range errors")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	metadata[MetaOriginalSize] = "12"
	clone := func() map[string]string {
		m := make(map[string]string, len(metadata))
		for k, v := range metadata {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"bad salt", func(m map[string]string) { m[MetaKeySalt] = "%%%" }},
		{"bad iv", func(m map[string]string) { m[MetaIV] = "%%%" }},
		{"bad algorithm", func(m map[string]string) { m[MetaAlgorithm] = "unsupported" }},
		{"bad kdf", func(m map[string]string) { m[MetaKDFParams] = "%%%" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := clone()
			tc.mutate(m)
			if _, _, err := eng.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), m, 0, 1); err == nil {
				t.Fatal("parameter error accepted")
			}
		})
	}
	// Every response-header restoration branch is exercised by a valid engine call.
	metadata[MetaContentType] = "application/test"
	metadata[MetaCacheControl] = "max-age=1"
	metadata[MetaContentDisposition] = "inline"
	if _, out, err := eng.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), metadata, 0, 1); err != nil {
		t.Fatal(err)
	} else if out["Content-Type"] == "" || out["Cache-Control"] == "" || out["Content-Disposition"] == "" {
		t.Fatal("restored response headers missing")
	}
}

func TestSEC37_DecryptRange_CompactorAndProtectedMetadataErrors(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("sec37-compactor-password"), WithChunking(true), WithChunkSize(MinChunkSize), WithMetadataKey(bytes.Repeat([]byte{0x77}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	e := eng.(*engine)
	e.metadataExpansionOverride = func(map[string]string) (map[string]string, error) { return nil, errors.New("compactor failure") }
	if _, _, err := eng.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, nil, map[string]string{MetaEncrypted: "true"}, 0, 1); err == nil {
		t.Fatal("compactor error ignored")
	}
	e.metadataExpansionOverride = nil
	reader, metadata, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("protected range")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	metadata[MetaEncryptedMetadata] = "%%%"
	if _, _, err := eng.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), metadata, 0, 1); err == nil {
		t.Fatal("protected metadata error ignored")
	}
}

func TestSEC37_DecryptRange_ResponseMetadataAndFallback(t *testing.T) {
	eng, err := NewEngineWithChunking([]byte("sec37-response-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := eng.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("response metadata")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(reader)
	metadata[MetaContentType] = "application/test"
	metadata[MetaCacheControl] = "max-age=1"
	metadata[MetaContentDisposition] = "inline"
	metadata[MetaOriginalSize] = "17"
	delete(metadata, "Content-Length")
	r, out, err := eng.DecryptRange(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(body), metadata, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	_ = r
	for key, want := range map[string]string{"Content-Type": "application/test", "Cache-Control": "max-age=1", "Content-Disposition": "inline", "Content-Length": "4"} {
		if out[key] != want {
			t.Fatalf("%s=%q", key, out[key])
		}
	}
}

func TestSEC37_UnknownVersion_FailsClosed(t *testing.T) {
	for _, version := range []int{0, 3, 255} {
		block, _ := aes.NewCipher(bytes.Repeat([]byte{1}, aesKeySize))
		dataAEAD, _ := cipher.NewGCM(block)
		terminal, _ := cipher.NewGCM(block)
		if _, _, err := newChunkedEncryptReaderWithContext(context.Background(), bytes.NewReader(nil), dataAEAD, terminal, bytes.Repeat([]byte{1}, nonceSize), MinChunkSize, uint8(version), nil); err == nil {
			t.Fatalf("writer v%d accepted", version)
		}
		manifest := &ChunkManifest{Version: version, ChunkSize: MinChunkSize, BaseIV: encodeBase64(bytes.Repeat([]byte{1}, nonceSize))}
		if _, err := newChunkedDecryptReader(bytes.NewReader(nil), nil, manifest, nil); !errors.Is(err, ErrUnsupportedChunkedVersion) {
			t.Fatalf("decrypt v%d error = %v", version, err)
		}
		if _, err := newRangeDecryptReader(bytes.NewReader(nil), nil, manifest, nil, 0, 0, nil, false); !errors.Is(err, ErrUnsupportedChunkedVersion) {
			t.Fatalf("range v%d error = %v", version, err)
		}
	}
}

// TestSEC37_LegacyV2EncryptWrapperTerminalUsesSuppliedAEAD verifies the
// supplied terminal AEAD on the legacy, unbound V2 writer.
func TestSEC37_LegacyV2EncryptWrapperTerminalUsesSuppliedAEAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, aesKeySize)
	block, _ := aes.NewCipher(key)
	data, _ := cipher.NewGCM(block)
	terminal, _ := cipher.NewGCM(block)
	reader, manifest, err := newLegacyChunkedEncryptReaderV2(context.Background(), bytes.NewReader([]byte("wrapper")), data, bytes.Repeat([]byte{0x22}, nonceSize), MinChunkSize, nil, ChunkedFormatV2, terminal)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	iv := bytes.Repeat([]byte{0x22}, nonceSize)
	nonce, _ := deriveTerminalNonceHKDF(iv, ChunkedFormatV2)
	if _, err := terminal.Open(nil, nonce, body[len(body)-ChunkedTerminalSize:], buildTerminalAAD(ChunkedFormatV2)); err != nil {
		t.Fatal(err)
	}
	zeroBlock, _ := aes.NewCipher(make([]byte, aesKeySize))
	zero, _ := cipher.NewGCM(zeroBlock)
	if _, err := zero.Open(nil, nonce, body[len(body)-ChunkedTerminalSize:], buildTerminalAAD(ChunkedFormatV2)); err == nil {
		t.Fatal("zero-key terminal authenticated")
	}
	if manifest.Version != int(ChunkedFormatV2) {
		t.Fatal("wrapper manifest version")
	}
}

func TestSEC37_DecryptRangeV2_FirstMiddleFinal(t *testing.T) {
	plaintext := bytes.Repeat([]byte("r"), MinChunkSize*3)
	ciphertext, manifest, dataAEAD, _ := newSEC37V2Fixture(t, plaintext)
	for _, test := range []struct {
		name       string
		start, end int64
	}{
		{"first", 0, 2},
		{"middle", MinChunkSize + 2, MinChunkSize + 5},
		{"final", int64(len(plaintext) - 1), int64(len(plaintext) - 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			reader, err := newRangeDecryptReader(bytes.NewReader(ciphertext), dataAEAD, manifest, bytes.Repeat([]byte{0x73}, nonceSize), test.start, test.end, nil, false)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(got, plaintext[test.start:test.end+1]) {
				t.Fatalf("range = %d bytes, error = %v", len(got), err)
			}
		})
	}
}

func TestSEC37_DecryptRangeV2_OptimizedShortFinalReadsFullRecord(t *testing.T) {
	plaintext := bytes.Repeat([]byte("s"), 37)
	ciphertext, manifest, dataAEAD, _ := newSEC37V2Fixture(t, plaintext)
	dataRecord := ciphertext[:len(plaintext)+tagSize]
	reader, err := newRangeDecryptReader(bytes.NewReader(dataRecord), dataAEAD, manifest,
		bytes.Repeat([]byte{0x73}, nonceSize), 0, 11, nil, true, int64(len(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, plaintext[:12]) {
		t.Fatalf("optimized short-final range = %d bytes, error = %v", len(got), err)
	}
}

func TestSEC37_OptimizedRangeUsesExactContentLengthOverStaleOriginalSize(t *testing.T) {
	plaintext := bytes.Repeat([]byte("z"), 37)
	ciphertext, manifest, _, _ := newSEC37V2Fixture(t, plaintext)
	manifestEncoded, err := encodeManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	metadata := map[string]string{
		MetaChunkedFormat: "true", MetaManifest: manifestEncoded,
		MetaChunkSize:    fmt.Sprintf("%d", MinChunkSize),
		MetaOriginalSize: "9999", "Content-Length": fmt.Sprintf("%d", len(ciphertext)),
	}
	got, err := GetPlaintextSizeFromMetadata(metadata)
	if err != nil || got != int64(len(plaintext)) {
		t.Fatalf("exact size = %d, error = %v", got, err)
	}
}

func TestSEC37_DecryptRangeV2_WrongAADFails(t *testing.T) {
	plaintext := bytes.Repeat([]byte("a"), MinChunkSize*2)
	ciphertext, manifest, dataAEAD, _ := newSEC37V2Fixture(t, plaintext)
	recordSize := MinChunkSize + tagSize
	// Keep valid ciphertext but associate record zero with absolute index one.
	reader, err := newRangeDecryptReader(bytes.NewReader(ciphertext[:recordSize]), dataAEAD, manifest,
		bytes.Repeat([]byte{0x73}, nonceSize), int64(MinChunkSize), int64(MinChunkSize+2), nil, true, int64(len(plaintext)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("wrong AAD/index association succeeded")
	}
}

func TestSEC37_DecryptRangeV2_WrongIndexFails(t *testing.T) {
	// The named WrongAAD test covers the incorrect absolute-index association;
	// retain this test as a distinct constructor validation regression.
	manifest := &ChunkManifest{Version: 3, ChunkSize: MinChunkSize, ChunkCount: 1}
	if _, err := newRangeDecryptReader(bytes.NewReader(nil), nil, manifest, nil, 0, 0, nil, false); !errors.Is(err, ErrUnsupportedChunkedVersion) {
		t.Fatalf("unsupported range version error = %v", err)
	}
}

func TestSEC37_DecryptRangeV1_Compatible(t *testing.T) {
	plaintext := bytes.Repeat([]byte("v"), MinChunkSize*2)
	key := bytes.Repeat([]byte{0x37}, aesKeySize)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	baseIV := bytes.Repeat([]byte{0x73}, nonceSize)
	reader, manifest := newChunkedEncryptReader(bytes.NewReader(plaintext), aead, baseIV, MinChunkSize, nil)
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := newRangeDecryptReader(bytes.NewReader(ciphertext), aead, manifest, baseIV, int64(MinChunkSize+1), int64(MinChunkSize+3), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(decoded)
	if err != nil || !bytes.Equal(got, plaintext[MinChunkSize+1:MinChunkSize+4]) {
		t.Fatalf("range = %q, error = %v", got, err)
	}
}

func FuzzSEC37_ChunkedSizeRoundTrip(f *testing.F) {
	for _, size := range []int64{0, 1, MinChunkSize, MinChunkSize + 1, 1 << 20} {
		f.Add(size)
	}
	f.Fuzz(func(t *testing.T, size int64) {
		if size < 0 || size > 64<<20 {
			return
		}
		for _, version := range []uint8{ChunkedFormatV1, ChunkedFormatV2} {
			ciphertext, err := ChunkedCiphertextSize(size, MinChunkSize, version)
			if err != nil {
				return
			}
			got, _, err := ChunkedPlaintextSize(ciphertext, MinChunkSize, version)
			if err != nil || got != size {
				t.Fatalf("v%d size round trip: %d -> %d -> %d, %v", version, size, ciphertext, got, err)
			}
		}
	})
}

func FuzzSEC37_DecodeTerminal(f *testing.F) {
	seed := encodeChunkedTerminal(7, 65537)
	f.Add(seed[:])
	f.Add([]byte{})
	f.Add(make([]byte, chunkedTerminalPlainSize-1))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		if len(encoded) > ChunkedTerminalSize {
			encoded = encoded[:ChunkedTerminalSize]
		}
		count, size, err := decodeChunkedTerminal(encoded)
		if len(encoded) != chunkedTerminalPlainSize {
			if !errors.Is(err, ErrChunkedObjectIncomplete) {
				t.Fatalf("length %d returned (%d, %d, %v)", len(encoded), count, size, err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		if encodeChunkedTerminal(count, size) != [chunkedTerminalPlainSize]byte(encoded) {
			t.Fatal("decoded terminal did not round-trip")
		}
	})
}

func FuzzSEC37_DecryptV2Mutations(f *testing.F) {
	f.Add([]byte("sec37 fuzz"), uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, plaintext []byte, mutation, offset uint8) {
		if len(plaintext) > 128<<10 {
			plaintext = plaintext[:128<<10]
		}
		ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, plaintext)
		if len(ciphertext) > 0 {
			ciphertext[int(offset)%len(ciphertext)] ^= mutation
		}
		reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext), dataAEAD, manifest, nil, terminalAEAD)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		if err == nil && !bytes.Equal(got, plaintext) {
			t.Fatal("successful decrypt returned altered plaintext")
		}
	})
}

func TestSEC37_ConcurrentV2RoundTrips(t *testing.T) {
	plaintext := bytes.Repeat([]byte("concurrent-sec37"), 8192)
	ciphertext, manifest, dataAEAD, terminalAEAD := newSEC37V2Fixture(t, plaintext)
	const workers = 8
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reader, err := newLegacyChunkedDecryptReaderV2(context.Background(), bytes.NewReader(ciphertext), dataAEAD, manifest, nil, terminalAEAD)
			if err != nil {
				errs <- err
				return
			}
			got, err := io.ReadAll(reader)
			if err == nil && !bytes.Equal(got, plaintext) {
				err = errors.New("concurrent plaintext mismatch")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}
