package crypto

// V0.6-PERF-1 Phase A: benchmarks for NewMPUPartEncryptReader streaming path.
// Run with: go test -bench=BenchmarkMPUEncryptReader -benchmem -benchtime=10s

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// BenchmarkMPUEncryptReader_5MiB benchmarks a 5 MiB part (common minimum S3 part size).
func BenchmarkMPUEncryptReader_5MiB(b *testing.B) {
	benchmarkMPUEncryptReader(b, 5*1024*1024)
}

// BenchmarkMPUEncryptReader_100MiB benchmarks a 100 MiB part.
func BenchmarkMPUEncryptReader_100MiB(b *testing.B) {
	benchmarkMPUEncryptReader(b, 100*1024*1024)
}

func benchmarkMPUEncryptReader(b *testing.B, plainLen int) {
	b.Helper()
	plain := bytes.Repeat([]byte{0xAB}, plainLen)
	b.SetBytes(int64(plainLen))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, _, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(plainLen), "AES256GCM")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			b.Fatal(err)
		}
	}
}

// V0.6-QA-1 Phase B: symmetric decrypt benchmark.
//
// BenchmarkMPUDecryptReader_100MiB mirrors the encrypt-side
// BenchmarkMPUEncryptReader_100MiB. Fixture: build a 100 MiB single-part
// ciphertext once outside the timed loop; inside, reconstruct a
// NewMPUDecryptReader and stream it to io.Discard. b.SetBytes reports MB/s
// normalised to the plaintext size so benchstat comparisons are
// unit-consistent with the encrypt side.
func BenchmarkMPUDecryptReader_100MiB(b *testing.B) {
	const plainLen = 100 * 1024 * 1024
	plain := bytes.Repeat([]byte{0xAB}, plainLen)

	// 1) Build the ciphertext + manifest once (outside the timed loop).
	enc, encLen, err := newMPUPartEncryptReaderV1(
		context.Background(),
		ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{},
		bytes.NewReader(plain),
		testDEK, testUIDHash, testIVPrefix,
		1, DefaultChunkSize, int64(plainLen), "AES256GCM",
	)
	if err != nil {
		b.Fatal(err)
	}
	ct, err := io.ReadAll(enc)
	if err != nil {
		b.Fatal(err)
	}
	if int64(len(ct)) != encLen {
		b.Fatalf("ciphertext length mismatch: got %d want %d", len(ct), encLen)
	}

	chunks := int32((int64(plainLen) + int64(DefaultChunkSize) - 1) / int64(DefaultChunkSize))
	manifest := &MultipartManifest{
		Version:      1,
		Algorithm:    "AES256GCM",
		ChunkSize:    DefaultChunkSize,
		IVPrefix:     "aabbccddeeff112233445566",
		UploadIDHash: encodeBase64(testUIDHash[:]),
		WrappedDEK:   "bench",
		Parts: []MPUPartRecord{{
			PartNumber: 1,
			PlainLen:   int64(plainLen),
			EncLen:     encLen,
			ChunkCount: chunks,
		}},
		TotalPlainSize: int64(plainLen),
	}

	b.SetBytes(int64(plainLen))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r, err := newMPUDecryptReaderV1(ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(ct), manifest, testDEK, testUIDHash, testIVPrefix, "AES256GCM")
		if err != nil {
			b.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, r); err != nil {
			b.Fatal(err)
		}
	}
}
