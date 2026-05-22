//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// TestEncryptWithMetadataEncryption_Enabled verifies that when a metadata
// key is configured, the engine encrypts the encryption/compression metadata
// into a single sealed blob and restores it on decrypt.
func TestEncryptWithMetadataEncryption_Enabled(t *testing.T) {
	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	engine, err := crypto.NewEngineWithOpts(
		[]byte("test-password-at-least-12-chars"),
		nil,
		crypto.WithMetadataKey(metaKey),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}

	data := []byte("Hello, encrypted metadata world!")
	ctx := context.Background()

	encReader, encMeta, err := engine.Encrypt(ctx, bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll(encrypted): %v", err)
	}

	// Verify the encrypted metadata blob exists and individual keys are hidden.
	blob, hasBlob := encMeta[crypto.MetaEncryptedMetadata]
	if !hasBlob || blob == "" {
		t.Fatal("expected MetaEncryptedMetadata in output metadata")
	}

	// MetaEncrypted (x-amz-meta-encrypted) MUST remain outside the blob
	// so that IsEncrypted works even without the metadata key (§2.6).
	if encMeta[crypto.MetaEncrypted] != "true" {
		t.Errorf("MetaEncrypted should be 'true' in output, got %q", encMeta[crypto.MetaEncrypted])
	}

	// Individual encryption/compression keys should NOT be visible in output.
	if _, ok := encMeta[crypto.MetaAlgorithm]; ok {
		t.Error("MetaAlgorithm should not be visible in output metadata (should be in blob)")
	}
	if _, ok := encMeta[crypto.MetaKeySalt]; ok {
		t.Error("MetaKeySalt should not be visible in output metadata (should be in blob)")
	}

	// Decrypt and verify.
	decReader, decMeta, err := engine.Decrypt(ctx, bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	decData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll(decrypted): %v", err)
	}

	if !bytes.Equal(decData, data) {
		t.Fatalf("round-trip data mismatch: got %q, want %q", decData, data)
	}

	// The decrypt output strips encryption/compression metadata keys by design.
	// Verify that non-encryption metadata is still present.
	if decMeta["Content-Length"] == "" {
		t.Error("Content-Length should be present after decrypt")
	}
}

// TestEncryptWithMetadataEncryption_Disabled verifies that without a metadata
// key, the engine produces the traditional individual metadata keys (no blob).
func TestEncryptWithMetadataEncryption_Disabled(t *testing.T) {
	engine, err := crypto.NewEngine([]byte("test-password-at-least-12-chars"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	data := []byte("Hello, plain metadata world!")
	ctx := context.Background()

	encReader, encMeta, err := engine.Encrypt(ctx, bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll(encrypted): %v", err)
	}

	// No encrypted metadata blob should exist.
	if _, ok := encMeta[crypto.MetaEncryptedMetadata]; ok {
		t.Error("MetaEncryptedMetadata should NOT be present when metadata key is not configured")
	}

	// Individual keys should be present.
	if encMeta[crypto.MetaAlgorithm] == "" {
		t.Error("MetaAlgorithm should be present when metadata encryption is disabled")
	}
	if encMeta[crypto.MetaKeySalt] == "" {
		t.Error("MetaKeySalt should be present when metadata encryption is disabled")
	}

	// Verify decrypt still works.
	decReader, _, err := engine.Decrypt(ctx, bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	decData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll(decrypted): %v", err)
	}

	if !bytes.Equal(decData, data) {
		t.Fatalf("round-trip data mismatch: got %q, want %q", decData, data)
	}
}

// TestDecryptWithMetadataEncryption_BackwardCompat verifies that objects
// encrypted without metadata encryption can still be decrypted when a
// metadata key is configured (backward compatibility).
func TestDecryptWithMetadataEncryption_BackwardCompat(t *testing.T) {
	// Encrypt without metadata key.
	engineNoMeta, err := crypto.NewEngine([]byte("test-password-at-least-12-chars"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	data := []byte("Backward compatible data")
	ctx := context.Background()

	encReader, encMeta, err := engineNoMeta.Encrypt(ctx, bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt (no meta key): %v", err)
	}

	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll(encrypted): %v", err)
	}

	// Decrypt with metadata key configured.
	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	engineWithMeta, err := crypto.NewEngineWithOpts(
		[]byte("test-password-at-least-12-chars"),
		nil,
		crypto.WithMetadataKey(metaKey),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}

	decReader, _, err := engineWithMeta.Decrypt(ctx, bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Backward-compatible Decrypt: %v", err)
	}

	decData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll(decrypted): %v", err)
	}

	if !bytes.Equal(decData, data) {
		t.Fatalf("backward-compat data mismatch: got %q, want %q", decData, data)
	}
}

// TestEncryptWithMetadataEncryption_Compaction verifies that metadata
// encryption works correctly with compaction enabled.
func TestEncryptWithMetadataEncryption_Compaction(t *testing.T) {
	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	engine, err := crypto.NewEngineWithOpts(
		[]byte("test-password-at-least-12-chars"),
		nil,
		crypto.WithMetadataKey(metaKey),
		crypto.WithProvider("minio"),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}

	data := []byte("Compaction test data")
	ctx := context.Background()

	encReader, encMeta, err := engine.Encrypt(ctx, bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll(encrypted): %v", err)
	}

	// Verify the encrypted metadata blob is present (even with compaction,
	// encryption replaces individual keys with a single blob).
	blob := encMeta[crypto.MetaEncryptedMetadata]
	if blob == "" {
		// Check compacted form too.
		blob = encMeta[crypto.MetaEncryptedMetadataCompact]
	}
	if blob == "" {
		t.Fatal("MetaEncryptedMetadata or its compacted form should be present")
	}

	// Decrypt and verify round-trip.
	decReader, _, err := engine.Decrypt(ctx, bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	decData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll(decrypted): %v", err)
	}

	if !bytes.Equal(decData, data) {
		t.Fatalf("round-trip data mismatch: got %q, want %q", decData, data)
	}
}

// TestEncryptWithMetadataEncryption_FallbackV1 verifies that metadata
// encryption works correctly with the V1 (buffered) metadata fallback path.
func TestEncryptWithMetadataEncryption_FallbackV1(t *testing.T) {
	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Use a provider with a tiny header limit to force fallback.
	engine, err := crypto.NewEngineWithOpts(
		[]byte("test-password-at-least-12-chars"),
		nil,
		crypto.WithMetadataKey(metaKey),
		crypto.WithProvider("default"), // default has no compaction, small limit
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}

	data := []byte("Fallback V1 test data")
	ctx := context.Background()

	// Add large metadata to force fallback detection.
	userMeta := map[string]string{
		"x-amz-meta-large-payload": string(bytes.Repeat([]byte("X"), 8192)),
	}

	encReader, encMeta, err := engine.Encrypt(ctx, bytes.NewReader(data), userMeta)
	if err != nil {
		t.Fatalf("Encrypt (with large metadata, fallback): %v", err)
	}

	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll(encrypted): %v", err)
	}

	// Decrypt and verify.
	decReader, _, err := engine.Decrypt(ctx, bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt (fallback path): %v", err)
	}

	decData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll(decrypted): %v", err)
	}

	if !bytes.Equal(decData, data) {
		t.Fatalf("fallback round-trip data mismatch: got %q, want %q", decData, data)
	}
}

// TestEncryptWithMetadataEncryption_FallbackV2 verifies that metadata
// encryption works correctly with the V2 (chunked streaming) metadata
// fallback path.
func TestEncryptWithMetadataEncryption_FallbackV2(t *testing.T) {
	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Enable chunked mode and use default provider to trigger V2 fallback
	// with large metadata.
	engine, err := crypto.NewEngineWithOpts(
		[]byte("test-password-at-least-12-chars"),
		nil,
		crypto.WithMetadataKey(metaKey),
		crypto.WithChunking(true),
		crypto.WithProvider("default"),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}

	data := bytes.Repeat([]byte("F2"), 1024) // 2KB of data for chunked mode
	ctx := context.Background()

	// Add large metadata to force fallback in chunked mode.
	userMeta := map[string]string{
		"x-amz-meta-large-payload": string(bytes.Repeat([]byte("X"), 8192)),
	}

	encReader, encMeta, err := engine.Encrypt(ctx, bytes.NewReader(data), userMeta)
	if err != nil {
		t.Fatalf("Encrypt (chunked + large metadata): %v", err)
	}

	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll(encrypted): %v", err)
	}

	// Decrypt and verify.
	decReader, _, err := engine.Decrypt(ctx, bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt (V2 fallback path): %v", err)
	}

	decData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll(decrypted): %v", err)
	}

	if !bytes.Equal(decData, data) {
		t.Fatalf("V2 fallback round-trip data mismatch: got %d bytes, want %d bytes", len(decData), len(data))
	}
}

// TestIsEncrypted_WithCompactedEncryptedMetadata verifies that IsEncrypted
// correctly identifies objects with compacted encrypted metadata markers.
func TestIsEncrypted_WithCompactedEncryptedMetadata(t *testing.T) {
	metaKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	engine, err := crypto.NewEngineWithOpts(
		[]byte("test-password-at-least-12-chars"),
		nil,
		crypto.WithMetadataKey(metaKey),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}

	// Test 1: Standard MetaEncryptedMetadata with MetaEncrypted=true
	meta1 := map[string]string{
		crypto.MetaEncrypted:          "true",
		crypto.MetaEncryptedMetadata:  "some-blob-value",
	}
	if !engine.IsEncrypted(meta1) {
		t.Error("IsEncrypted should return true for metadata with MetaEncrypted=true and MetaEncryptedMetadata")
	}

	// Test 2: Compacted form with MetaEncrypted=true and compacted metadata blob
	meta2 := map[string]string{
		"x-amz-meta-e":               "true",
		crypto.MetaEncryptedMetadataCompact: "some-blob-value",
	}
	if !engine.IsEncrypted(meta2) {
		t.Error("IsEncrypted should return true for compacted metadata with MetaEncrypted=true")
	}

	// Test 3: Compacted form, MetaEncrypted=true, no blob key (should still be encrypted)
	meta3 := map[string]string{
		"x-amz-meta-e": "true",
	}
	if !engine.IsEncrypted(meta3) {
		t.Error("IsEncrypted should return true when compacted MetaEncrypted is true")
	}

	// Test 4: Not encrypted
	meta4 := map[string]string{
		"x-amz-meta-foo": "bar",
	}
	if engine.IsEncrypted(meta4) {
		t.Error("IsEncrypted should return false for plain metadata")
	}

	// Test 5: Nil metadata
	if engine.IsEncrypted(nil) {
		t.Error("IsEncrypted should return false for nil metadata")
	}

	// Test 6: MetaEncryptedMetadata present but MetaEncrypted is false
	meta6 := map[string]string{
		crypto.MetaEncrypted:          "false",
		crypto.MetaEncryptedMetadata:  "some-blob",
	}
	if engine.IsEncrypted(meta6) {
		t.Error("IsEncrypted should return false when MetaEncrypted is false")
	}

	// Test 7: Only MetaEncryptedMetadataCompact (should check through compacted marker)
	meta7 := map[string]string{
		crypto.MetaEncryptedMetadataCompact: "some-blob",
		"x-amz-meta-e": "true",
	}
	if !engine.IsEncrypted(meta7) {
		t.Error("IsEncrypted should return true with compacted blob and compacted encrypted marker")
	}
}
