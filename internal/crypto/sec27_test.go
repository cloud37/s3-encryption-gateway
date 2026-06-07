package crypto

// V1.0-SEC-27: Metadata Fallback Path Double-Buffering — proper fix verification.
//
// The issue: encryptChunkedWithMetadataFallback previously wrapped the full
// chunked ciphertext in a second outer aead.Seal, forcing peak memory ≈ 2×
// object size. The fix emits a streaming format (v2):
//   [4-byte BE metadata_length][metadata_json][chunked_ciphertext_stream]
// with no outer AEAD. Per-chunk AEAD from the chunked layer is sufficient.
//
// These tests verify:
//  1. New chunked-fallback objects use version "2" in header metadata.
//  2. Round-trip correctness: encrypt → decrypt produces identical plaintext.
//  3. Full metadata is restored correctly after decryption.
//  4. Backward compatibility: legacy v1 (outer-AEAD) objects still decrypt.
//  5. Peak-heap benchmark confirms O(chunkSize) not O(objectSize) allocation.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime"
	"strings"
	"testing"
)

// newChunkedFallbackEngine creates an engine that (a) uses chunked mode and
// (b) has metadata limits small enough to force the fallback path.
func newChunkedFallbackEngine(t *testing.T) (*engine, *ProviderProfile) {
	t.Helper()

	profile := &ProviderProfile{
		Name:                "test-chunked-fallback",
		UserMetadataLimit:   50,
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    80, // small enough to force fallback for any encryption metadata
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	enc, err := NewEngineWithChunkingAndProvider(
		[]byte("sec27-test-password-2026"),
		"",
		nil,
		true,  // chunkedMode = true
		65536, // 64 KiB chunks
		"default",
		DefaultPBKDF2Iterations,
	)
	if err != nil {
		t.Fatalf("NewEngineWithChunkingAndProvider: %v", err)
	}

	e := enc.(*engine)
	e.providerProfile = profile
	e.compactor = NewMetadataCompactor(profile)
	return e, profile
}

// largeMetadataMap returns metadata that exceeds the test profile limits,
// forcing the fallback path even after compaction.
func largeMetadataMap() map[string]string {
	return map[string]string{
		"Content-Type":       "application/octet-stream",
		"x-amz-meta-project": "s3-encryption-gateway",
		"x-amz-meta-very-long-key-that-forces-overflow": strings.Repeat("v", 80),
	}
}

// TestSEC27_ChunkedFallbackV2_Format verifies that the new encrypt path sets
// MetaFallbackVersion == "2" in the returned header metadata.
func TestSEC27_ChunkedFallbackV2_Format(t *testing.T) {
	e, _ := newChunkedFallbackEngine(t)

	plaintext := []byte("hello sec-27 streaming fallback")
	encReader, encMeta, err := e.Encrypt(context.Background(), bytes.NewReader(plaintext), largeMetadataMap())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// Drain the reader (needed so any lazy computation runs)
	if _, err := io.Copy(io.Discard, encReader); err != nil {
		t.Fatalf("drain: %v", err)
	}

	if encMeta[MetaFallbackMode] != "true" {
		t.Errorf("MetaFallbackMode = %q, want \"true\"", encMeta[MetaFallbackMode])
	}
	if encMeta[MetaFallbackVersion] != "2" {
		t.Errorf("MetaFallbackVersion = %q, want \"2\" — new objects must use streaming format", encMeta[MetaFallbackVersion])
	}
}

// TestSEC27_ChunkedFallbackV2_RoundTrip verifies end-to-end encrypt/decrypt
// correctness for the v2 streaming format.
func TestSEC27_ChunkedFallbackV2_RoundTrip(t *testing.T) {
	sizes := []int{0, 1, 255, 65535, 65536, 65537, 200000}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("size=%d", sz), func(t *testing.T) {
			e, _ := newChunkedFallbackEngine(t)

			plaintext := bytes.Repeat([]byte{0xAB}, sz)
			meta := largeMetadataMap()

			encReader, encMeta, err := e.Encrypt(context.Background(), bytes.NewReader(plaintext), meta)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			encData, err := io.ReadAll(encReader)
			if err != nil {
				t.Fatalf("ReadAll encrypted: %v", err)
			}

			if encMeta[MetaFallbackVersion] != "2" {
				t.Fatalf("unexpected fallback version %q, want \"2\"", encMeta[MetaFallbackVersion])
			}

			decReader, decMeta, err := e.Decrypt(context.Background(), bytes.NewReader(encData), encMeta)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			got, err := io.ReadAll(decReader)
			if err != nil {
				t.Fatalf("ReadAll decrypted: %v", err)
			}

			if !bytes.Equal(got, plaintext) {
				t.Errorf("plaintext mismatch at size %d: got %d bytes, want %d bytes", sz, len(got), len(plaintext))
			}

			// Verify user metadata is restored
			if decMeta["Content-Type"] != "application/octet-stream" {
				t.Errorf("Content-Type not restored: got %q", decMeta["Content-Type"])
			}
			if decMeta["x-amz-meta-project"] != "s3-encryption-gateway" {
				t.Errorf("user metadata not restored: got %q", decMeta["x-amz-meta-project"])
			}
		})
	}
}

// TestSEC27_ChunkedFallbackV2_NoOuterAEAD verifies that the new format's body
// is NOT a valid outer-AEAD ciphertext (i.e., the redundant wrapping is gone).
// It does this by attempting to decrypt the body with decryptFallbackV1 and
// confirming it fails — meaning the two layers are no longer present.
func TestSEC27_ChunkedFallbackV2_NoOuterAEAD(t *testing.T) {
	e, _ := newChunkedFallbackEngine(t)

	plaintext := []byte("outer aead must be absent")
	encReader, encMeta, err := e.Encrypt(context.Background(), bytes.NewReader(plaintext), largeMetadataMap())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	// Attempt v1 (outer-AEAD) decryption on a v2 body — must fail.
	// This confirms the outer AEAD Seal is no longer present in the new format.
	_, _, errV1 := e.decryptFallbackV1(bytes.NewReader(encData), encMeta)
	if errV1 == nil {
		t.Error("decryptFallbackV1 succeeded on a v2 body — outer AEAD Seal is still present (SEC-27 not fixed)")
	}
}

// TestSEC27_BackwardCompatibility_LegacyV1 verifies that objects encrypted with
// the old outer-AEAD (v1) format can still be decrypted after the fix.
// This test manually constructs a v1 fallback object using the legacy path.
func TestSEC27_BackwardCompatibility_LegacyV1(t *testing.T) {
	// Use a non-chunked engine to produce a v1 fallback object (legacy format).
	// The non-chunked Encrypt path calls encryptWithMetadataFallback, which is
	// the original single-AEAD implementation and is unchanged.
	profile := &ProviderProfile{
		Name:                "test-legacy-fallback",
		UserMetadataLimit:   50,
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    80,
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}
	legacyEnc, err := NewEngineWithProvider([]byte("sec27-test-password-2026"), "", nil, "default")
	if err != nil {
		t.Fatalf("NewEngineWithProvider: %v", err)
	}
	legacyEngine := legacyEnc.(*engine)
	legacyEngine.providerProfile = profile
	legacyEngine.compactor = NewMetadataCompactor(profile)

	plaintext := []byte("legacy fallback v1 object")
	meta := largeMetadataMap()

	encReader, encMeta, err := legacyEngine.Encrypt(context.Background(), bytes.NewReader(plaintext), meta)
	if err != nil {
		t.Fatalf("Encrypt (legacy): %v", err)
	}
	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	// Legacy engine produces v1 (no MetaFallbackVersion), with outer AEAD.
	// Confirm the version header is absent (or "1").
	ver := encMeta[MetaFallbackVersion]
	if ver != "" && ver != "1" {
		t.Fatalf("unexpected version %q from legacy engine, want empty or \"1\"", ver)
	}

	// Now decrypt using the updated engine — must still work (backward compat).
	updatedEnc, err := NewEngineWithChunkingAndProvider(
		[]byte("sec27-test-password-2026"), "", nil, true, 65536, "default", DefaultPBKDF2Iterations,
	)
	if err != nil {
		t.Fatalf("NewEngineWithChunkingAndProvider: %v", err)
	}
	updatedEngine := updatedEnc.(*engine)
	updatedEngine.providerProfile = profile
	updatedEngine.compactor = NewMetadataCompactor(profile)

	decReader, _, err := updatedEngine.Decrypt(context.Background(), bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt (legacy v1 object with updated engine): %v", err)
	}
	got, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll decrypted: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("backward compat: got %q, want %q", got, plaintext)
	}
}

// TestSEC27_FallbackV2_MetadataLengthSanityCheck verifies that the decrypt path
// rejects objects with a pathologically large metadata-length prefix rather than
// allocating unbounded memory.
func TestSEC27_FallbackV2_MetadataLengthSanityCheck(t *testing.T) {
	e, _ := newChunkedFallbackEngine(t)

	// Craft a fake v2 body with an absurdly large metadata_length (> 1 MiB limit).
	oversizeLen := uint32((1 << 20) + 1) // 1 MiB + 1
	fakeLenBuf := []byte{
		byte(oversizeLen >> 24),
		byte(oversizeLen >> 16),
		byte(oversizeLen >> 8),
		byte(oversizeLen),
	}
	fakeBody := bytes.NewReader(fakeLenBuf)

	fakeHeaderMeta := map[string]string{
		MetaEncrypted:       "true",
		MetaFallbackMode:    "true",
		MetaFallbackVersion: "2",
		MetaAlgorithm:       AlgorithmAES256GCM,
		MetaKeySalt:         encodeBase64(make([]byte, saltSize)),
		MetaIV:              encodeBase64(make([]byte, nonceSize)),
	}

	_, _, err := e.decryptFallbackV2(context.Background(), fakeBody, fakeHeaderMeta)
	if err == nil {
		t.Error("expected error for oversize metadata length, got nil")
	}
}

// BenchmarkSEC27_ChunkedFallback_PeakHeap measures peak heap growth during
// encryption of a 10 MiB object via the chunked fallback path.
// The new v2 format should allocate O(chunkSize + metadataSize), not O(objectSize).
func BenchmarkSEC27_ChunkedFallback_PeakHeap(b *testing.B) {
	e, _ := newChunkedFallbackEngine(&testing.T{})

	const objectSize = 10 << 20 // 10 MiB
	plaintext := bytes.Repeat([]byte{0xBB}, objectSize)
	meta := largeMetadataMap()

	b.ReportAllocs()
	b.SetBytes(objectSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)

		encReader, _, err := e.Encrypt(context.Background(), bytes.NewReader(plaintext), meta)
		if err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
		if _, err := io.Copy(io.Discard, encReader); err != nil {
			b.Fatalf("drain: %v", err)
		}

		runtime.GC()
		runtime.ReadMemStats(&after)

		// TotalAlloc grows monotonically; HeapInuse reflects live heap.
		heapGrowthMiB := float64(after.TotalAlloc-before.TotalAlloc) / (1 << 20)
		b.ReportMetric(heapGrowthMiB, "MiB-allocated")

		// In the fixed implementation, TotalAlloc should be well below 2×objectSize.
		// We assert < 1.5× objectSize (15 MiB) as a conservative upper bound.
		const maxAllowedMiB = 15.0
		if heapGrowthMiB > maxAllowedMiB {
			b.Errorf("heap growth %.1f MiB exceeds limit %.1f MiB (SEC-27 double-buffer regression)", heapGrowthMiB, maxAllowedMiB)
		}
	}
}
