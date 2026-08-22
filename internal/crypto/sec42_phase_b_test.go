package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
)

func phaseBFixture(t *testing.T, plain []byte) ([]byte, ObjectContext, []byte, *ChunkManifest, cipher.AEAD, cipher.AEAD) {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, aesKeySize)
	var err error
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(key)
	iv := bytes.Repeat([]byte{0x24}, nonceSize)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "phase-b", Key: "object"}
	binding := bytes.Repeat([]byte{0x91}, 16)
	r, manifest, err := newChunkedEncryptReaderV2Bound(context.Background(), bytes.NewReader(plain), data, iv, MinChunkSize, nil, terminal, object, binding)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext, object, binding, manifest, data, terminal
}

func TestChunkedV2_DataBindsBucketKeyAndIndex(t *testing.T) {
	ct, object, binding, manifest, data, _ := phaseBFixture(t, []byte("data"))
	nonce, _ := deriveChunkNonceHKDF(bytes.Repeat([]byte{0x24}, nonceSize), ChunkedFormatV2, 0)
	if _, err := data.Open(nil, nonce, ct[:len(ct)-ChunkedTerminalSize], func() []byte { a, _ := buildObjectAAD(aadChunkedV2Data, object, binding, 1); return a }()); err == nil {
		t.Fatal("wrong absolute index authenticated")
	}
	wrong, err := newChunkedDecryptReaderV2Bound(context.Background(), bytes.NewReader(ct), data, manifest, nil, data, ObjectContext{Bucket: "wrong", Key: object.Key}, binding)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(wrong)
	if err == nil || len(got) != 0 {
		t.Fatalf("wrong context returned %d plaintext bytes, error=%v", len(got), err)
	}
}

func TestChunkedV2_TrailerBindsIdentityAndTotals(t *testing.T) {
	ct, object, binding, manifest, data, terminal := phaseBFixture(t, []byte("trailer"))
	r, err := newChunkedDecryptReaderV2Bound(context.Background(), bytes.NewReader(ct), data, manifest, nil, terminal, object, binding)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(r); err != nil || string(got) != "trailer" {
		t.Fatalf("read = %q, %v", got, err)
	}
	bad, err := buildObjectAAD(aadChunkedV2Trailer, object, binding, uint64(manifest.ChunkCount+1), uint64(len("trailer")))
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := deriveTerminalNonceHKDF(bytes.Repeat([]byte{0x24}, nonceSize), ChunkedFormatV2)
	if _, err := terminal.Open(nil, nonce, ct[len(ct)-ChunkedTerminalSize:], bad); err == nil {
		t.Fatal("wrong trailer totals authenticated")
	}
}

func TestChunkedV2_CrossDomainReplayFails(t *testing.T) {
	ct, object, binding, _, _, terminal := phaseBFixture(t, []byte("domain"))
	nonce, _ := deriveChunkNonceHKDF(bytes.Repeat([]byte{0x24}, nonceSize), ChunkedFormatV2, 0)
	trailerAAD, _ := buildObjectAAD(aadChunkedV2Trailer, object, binding, 1, uint64(len("domain")))
	if _, err := terminal.Open(nil, nonce, ct[:len(ct)-ChunkedTerminalSize], trailerAAD); err == nil {
		t.Fatal("data record replayed across AAD domains")
	}
}

func TestChunkedV2_TagFailureDoesNotFallbackToV1(t *testing.T) {
	e, err := NewEngineWithChunking([]byte("phase-b-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "phase-b", Key: "fallback"}
	r, metadata, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("fallback")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if metadata[MetaObjectFormatVersion] != "chunked-v2" {
		t.Fatalf("marker=%q", metadata[MetaObjectFormatVersion])
	}
	ct[0] ^= 1
	reader, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(ct), metadata)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err == nil || len(got) != 0 {
		t.Fatalf("declared v2 returned %d plaintext bytes, error=%v", len(got), err)
	}
}

func TestChunkedV2_DeclaredMarkerDoesNotDispatchToLegacyFormats(t *testing.T) {
	e, err := NewEngineWithChunking([]byte("phase-b-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "phase-b", Key: "declared-format"}
	r, metadata, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("declared-format")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	// A current marker must never select the buffered legacy decoder.
	bufferedMetadata := make(map[string]string, len(metadata))
	for k, v := range metadata {
		bufferedMetadata[k] = v
	}
	delete(bufferedMetadata, MetaChunkedFormat)
	delete(bufferedMetadata, MetaManifest)
	if _, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(ciphertext), bufferedMetadata); err == nil {
		t.Fatal("declared chunked-v2 dispatched to buffered legacy decoder")
	}

	// A current marker must also agree with the manifest version before keys
	// are derived or unwrapped.
	legacyManifestMetadata := make(map[string]string, len(metadata))
	for k, v := range metadata {
		legacyManifestMetadata[k] = v
	}
	manifest, err := loadManifestFromMetadata(legacyManifestMetadata)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Version = int(ChunkedFormatV1)
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	legacyManifestMetadata[MetaManifest] = encodeBase64(manifestJSON)
	if _, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(ciphertext), legacyManifestMetadata); err == nil {
		t.Fatal("declared chunked-v2 dispatched to a v1 manifest")
	}
	legacyManifestMetadata["Content-Length"] = strconv.Itoa(len(ciphertext))
	if _, _, err := e.DecryptRange(context.Background(), object, bytes.NewReader(ciphertext), legacyManifestMetadata, 0, 1); err == nil {
		t.Fatal("declared chunked-v2 range dispatched to a v1 manifest")
	}
}

func TestChunkedV2_UnmarkedLegacyDualReadNormalAndRange(t *testing.T) {
	e, err := NewEngineWithChunking([]byte("legacy-v2-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "legacy-v2", Key: "object"}
	salt := bytes.Repeat([]byte{1}, saltSize)
	key, err := e.(*engine).deriveKey(salt)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(key)
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
	r, manifest, err := newLegacyChunkedEncryptReaderV2(context.Background(), bytes.NewReader([]byte("legacy v2 compatibility")), dataAEAD, bytes.Repeat([]byte{0x24}, nonceSize), MinChunkSize, nil, ChunkedFormatV2, terminalAEAD)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	metadata := map[string]string{MetaEncrypted: "true", MetaChunkedFormat: "true", MetaManifest: encodeBase64(manifestJSON), MetaAlgorithm: AlgorithmAES256GCM, MetaKeySalt: encodeBase64(salt), MetaIV: encodeBase64(bytes.Repeat([]byte{0x24}, nonceSize)), MetaKDFParams: FormatKDFParams(e.(*engine).defaultKDFParams()), MetaOriginalSize: "23"}
	plain, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(ciphertext), metadata)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(plain)
	if err != nil || string(got) != "legacy v2 compatibility" {
		t.Fatalf("normal read = %q, %v", got, err)
	}
	metadata["Content-Length"] = strconv.Itoa(len(ciphertext))
	plain, _, err = e.DecryptRange(context.Background(), object, bytes.NewReader(ciphertext), metadata, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(plain)
	if err != nil || string(got) != "legacy" {
		t.Fatalf("range read = %q, %v", got, err)
	}
}

func TestAuthenticateChunkedTrailer_V2RequiresDeclaredMarker(t *testing.T) {
	e, err := NewEngineWithChunking([]byte("trailer-marker-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "b", Key: "k"}
	r, metadata, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("trailer")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	delete(metadata, MetaObjectFormatVersion)
	delete(metadata, MetaKeySalt)
	if _, err := e.AuthenticateChunkedTrailer(context.Background(), object, bytes.NewReader(ct[len(ct)-ChunkedTerminalSize:]), metadata, int64(len(ct))); err == nil || !strings.Contains(err.Error(), "requires declared chunked-v2 marker") {
		t.Fatal("unmarked v2 trailer authenticated")
	}
}

func TestChunkedV2_ReadRejectsTruncatedAndTamperedTerminal(t *testing.T) {
	ct, object, binding, manifest, data, terminal := phaseBFixture(t, []byte("terminal-check"))
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated terminal", func(in []byte) []byte { return in[:len(in)-1] }},
		{"tampered terminal", func(in []byte) []byte { out := append([]byte(nil), in...); out[len(out)-1] ^= 1; return out }},
		{"tampered data", func(in []byte) []byte { out := append([]byte(nil), in...); out[0] ^= 1; return out }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := newChunkedDecryptReaderV2Bound(context.Background(), bytes.NewReader(tc.mutate(ct)), data, manifest, nil, terminal, object, binding)
			if err != nil {
				t.Fatal(err)
			}
			if got, err := io.ReadAll(r); err == nil || len(got) >= len("terminal-check") {
				t.Fatalf("tampered stream accepted: %q, %v", got, err)
			}
		})
	}
}

func TestChunkedV2_BoundReaderValidatesContextAndBinding(t *testing.T) {
	ct, object, binding, manifest, data, terminal := phaseBFixture(t, []byte("bound"))
	for _, tc := range []struct {
		name    string
		object  ObjectContext
		binding []byte
	}{
		{"invalid object", ObjectContext{}, binding},
		{"short binding", object, binding[:15]},
		{"long binding", object, append(binding, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newChunkedDecryptReaderV2Bound(context.Background(), bytes.NewReader(ct), data, manifest, nil, terminal, tc.object, tc.binding); err == nil {
				t.Fatal("invalid bound reader accepted")
			}
		})
	}
}

func TestChunkedV2_BoundConstructorsAndTerminalRejectInvalidInputs(t *testing.T) {
	ct, object, binding, manifest, data, terminal := phaseBFixture(t, []byte("terminal-auth"))
	for _, tc := range []struct {
		name    string
		object  ObjectContext
		binding []byte
	}{
		{"encrypt invalid object", ObjectContext{}, binding},
		{"encrypt short binding", object, binding[:15]},
		{"decrypt invalid object", ObjectContext{}, binding},
		{"decrypt short binding", object, binding[:15]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name[:7] == "encrypt" {
				if _, _, err := newChunkedEncryptReaderV2Bound(context.Background(), bytes.NewReader([]byte("x")), data, bytes.Repeat([]byte{1}, nonceSize), MinChunkSize, nil, terminal, tc.object, tc.binding); err == nil {
					t.Fatal("invalid bound encrypt input accepted")
				}
				return
			}
			if _, err := newChunkedDecryptReaderV2Bound(context.Background(), bytes.NewReader(ct), data, manifest, nil, terminal, tc.object, tc.binding); err == nil {
				t.Fatal("invalid bound decrypt input accepted")
			}
		})
	}
	terminalTampered := append([]byte(nil), ct...)
	terminalTampered[len(terminalTampered)-1] ^= 1
	r, err := newChunkedDecryptReaderV2Bound(context.Background(), bytes.NewReader(terminalTampered), data, manifest, nil, terminal, object, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err == nil {
		t.Fatal("tampered terminal accepted")
	}
}

func TestBoundOptimizedRangeRejectsFinalSizeAndAADErrors(t *testing.T) {
	block, err := aes.NewCipher(bytes.Repeat([]byte{1}, aesKeySize))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &ChunkManifest{Version: int(ChunkedFormatV2), ChunkSize: 4, ChunkCount: 1}
	for _, tc := range []struct {
		name   string
		reader *rangeDecryptReader
	}{
		{"missing exact plaintext size", &rangeDecryptReader{source: bytes.NewReader(nil), aead: aead, manifest: manifest, chunkSize: 4, plaintextStart: 0, plaintextEnd: 0, endChunk: 0, currentChunkIndex: 0, buffer: make([]byte, 20), boundV2: true, plaintextSize: -1}},
		{"invalid bound object", &rangeDecryptReader{source: bytes.NewReader(make([]byte, 20)), aead: aead, manifest: manifest, chunkSize: 4, plaintextStart: 0, plaintextEnd: 0, endChunk: 0, currentChunkIndex: 0, buffer: make([]byte, 20), boundV2: true, plaintextSize: 4, object: ObjectContext{}}},
		{"final offset overflow", &rangeDecryptReader{source: bytes.NewReader(nil), aead: aead, manifest: &ChunkManifest{Version: int(ChunkedFormatV2), ChunkSize: 1, ChunkCount: math.MaxUint64}, chunkSize: 1, plaintextStart: 0, plaintextEnd: 0, endChunk: math.MaxUint64 - 1, currentChunkIndex: math.MaxUint64 - 1, buffer: make([]byte, 17), boundV2: true, plaintextSize: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.reader.Read(make([]byte, 1)); err == nil {
				t.Fatal("invalid optimized range accepted")
			}
		})
	}
}

func TestChunkedV1_DualRead(t *testing.T) {
	key := bytes.Repeat([]byte{0x51}, aesKeySize)
	iv := bytes.Repeat([]byte{0x11}, nonceSize)
	b, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(b)
	r, manifest := newChunkedEncryptReaderV1(context.Background(), bytes.NewReader([]byte("legacy")), aead, iv, MinChunkSize, nil)
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := newChunkedDecryptReaderV1(context.Background(), bytes.NewReader(ct), aead, manifest, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(dec)
	if err != nil || string(got) != "legacy" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDecryptRangeV2_FirstMiddleLastChunk(t *testing.T) {
	plain := bytes.Repeat([]byte("x"), MinChunkSize*2+7)
	e, err := NewEngineWithChunking([]byte("range-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "phase-b", Key: "range"}
	r, meta, err := e.Encrypt(context.Background(), object, bytes.NewReader(plain), map[string]string{"Content-Length": strconv.Itoa(len(plain))})
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := io.ReadAll(r)
	meta["Content-Length"] = strconv.Itoa(len(ct))
	for _, tc := range []struct{ start, end int64 }{{0, 3}, {int64(MinChunkSize), int64(MinChunkSize + 3)}, {int64(2 * MinChunkSize), int64(2*MinChunkSize + 6)}} {
		rr, _, err := e.DecryptRange(context.Background(), object, bytes.NewReader(ct), meta, tc.start, tc.end)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rr)
		if err != nil || !bytes.Equal(got, plain[tc.start:tc.end+1]) {
			t.Fatalf("range %d-%d: %v", tc.start, tc.end, err)
		}
	}
}

func TestDecryptRangeV2_CrossChunkAndSuffix(t *testing.T) {
	plain := bytes.Repeat([]byte("q"), MinChunkSize*2+9)
	e, err := NewEngineWithChunking([]byte("suffix-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "phase-b", Key: "suffix"}
	r, metadata, err := e.Encrypt(context.Background(), object, bytes.NewReader(plain), map[string]string{"Content-Length": strconv.Itoa(len(plain))})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	metadata["Content-Length"] = strconv.Itoa(len(ct))
	for _, tc := range []struct{ start, end int64 }{{int64(MinChunkSize - 2), int64(MinChunkSize + 2)}, {int64(len(plain) - 5), int64(len(plain) - 1)}} {
		reader, _, err := e.DecryptRange(context.Background(), object, bytes.NewReader(ct), metadata, tc.start, tc.end)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		if err != nil || !bytes.Equal(got, plain[tc.start:tc.end+1]) {
			t.Fatalf("range %d-%d got %d bytes, error=%v", tc.start, tc.end, len(got), err)
		}
	}
}

func TestDecryptRangeV2_WrongObjectContextFails(t *testing.T) {
	e, err := NewEngineWithChunking([]byte("wrong-context"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "phase-b", Key: "range"}
	plain := bytes.Repeat([]byte("z"), MinChunkSize+4)
	r, meta, err := e.Encrypt(context.Background(), object, bytes.NewReader(plain), map[string]string{"Content-Length": strconv.Itoa(len(plain))})
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := io.ReadAll(r)
	rr, _, err := e.DecryptRange(context.Background(), ObjectContext{Bucket: "phase-b", Key: "wrong"}, bytes.NewReader(ct), meta, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(rr); err == nil {
		t.Fatal("wrong context decrypted range")
	}
}

func TestDecryptRangeOptimizedV2_ValidAndRejectedSources(t *testing.T) {
	plain := bytes.Repeat([]byte("z"), MinChunkSize+17)
	e, err := NewEngineWithChunking([]byte("optimized-range-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "optimized", Key: "object"}
	r, metadata, err := e.Encrypt(context.Background(), object, bytes.NewReader(plain), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	metadata["Content-Length"] = strconv.Itoa(len(ciphertext))
	optimized, ok := e.(interface {
		DecryptRangeOptimized(context.Context, ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error)
	})
	if !ok {
		t.Fatal("engine lacks optimized range contract")
	}
	reader, _, err := optimized.DecryptRangeOptimized(context.Background(), object, bytes.NewReader(ciphertext), metadata, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, plain[:17]) {
		t.Fatalf("optimized range=%d err=%v", len(got), err)
	}
	for _, tc := range []struct {
		name     string
		object   ObjectContext
		metadata map[string]string
		body     []byte
	}{
		{"invalid object", ObjectContext{}, metadata, ciphertext},
		{"truncated source", object, metadata, ciphertext[:20]},
		{"tampered source", object, metadata, func() []byte { b := append([]byte(nil), ciphertext...); b[0] ^= 1; return b }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, _, err := optimized.DecryptRangeOptimized(context.Background(), tc.object, bytes.NewReader(tc.body), tc.metadata, 0, 16)
			if err == nil {
				_, err = io.ReadAll(reader)
			}
			if err == nil {
				t.Fatal("invalid optimized range accepted")
			}
		})
	}
}

func TestRangeDecryptV1IVContractSeparatesIndicesAndRejectsOverflow(t *testing.T) {
	r := &rangeDecryptReader{manifest: &ChunkManifest{Version: int(ChunkedFormatV1), IVDerivation: "legacy"}, baseIV: bytes.Repeat([]byte{0x55}, nonceSize)}
	first, err := r.deriveChunkIV(0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.deriveChunkIV(1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("distinct v1 chunk indices reused IV")
	}
	if _, err := r.deriveChunkIV(uint64(^uint32(0)) + 1); err == nil {
		t.Fatal("v1 chunk index overflow accepted")
	}
	r.manifest = &ChunkManifest{Version: int(ChunkedFormatV1), IVDerivation: "hkdf-sha256"}
	if _, err := r.deriveChunkIV(1); err != nil {
		t.Fatal(err)
	}
}
