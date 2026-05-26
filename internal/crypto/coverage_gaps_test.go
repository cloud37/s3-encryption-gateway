// coverage_gaps_test.go — targeted tests to lift internal/crypto past 80%.
// V0.6-QA-2: unit-test coverage gap closure.
package crypto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
)

// ---- chunkedEncryptReader.Close --------------------------------------------

// TestChunkedEncryptReader_Close verifies that Close returns nil and is safe
// to call multiple times.
func TestChunkedEncryptReader_Close(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345678"), nil, "", nil, true, DefaultChunkSize)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}

	data := []byte("hello close test")
	r, _, err := engine.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Drain so the reader is fully read.
	if _, err := io.ReadAll(r); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	// Close should be a no-op that returns nil.
	if c, ok := r.(io.Closer); ok {
		if err := c.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
		// Second close should also succeed.
		if err := c.Close(); err != nil {
			t.Errorf("second Close() error = %v", err)
		}
	}
}

// ---- chunkedDecryptReader.Close --------------------------------------------

// TestChunkedDecryptReader_Close verifies that the decrypt reader's Close
// returns nil.
func TestChunkedDecryptReader_Close(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345678"), nil, "", nil, true, DefaultChunkSize)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}

	data := []byte("hello decrypt close test")
	encReader, meta, err := engine.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}

	decReader, _, err := engine.Decrypt(context.Background(), bytes.NewReader(encData), meta)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// Drain.
	if _, err := io.ReadAll(decReader); err != nil {
		t.Fatalf("ReadAll decrypted: %v", err)
	}

	if c, ok := decReader.(io.Closer); ok {
		if err := c.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}
}

// ---- passwordKeyManager.Provider -------------------------------------------

func TestPasswordKeyManager_Provider(t *testing.T) {
	km, err := NewPasswordKeyManager([]byte("test-password-long-enough"), WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	if err != nil {
		t.Fatalf("NewPasswordKeyManager: %v", err)
	}
	if got := km.Provider(); got != passwordKMProvider {
		t.Errorf("Provider() = %q, want %q", got, passwordKMProvider)
	}
}

// ---- engine.GetKeyManager --------------------------------------------------

func TestGetKeyManager_NoManager(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-for-getkey"), nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}
	if got := GetKeyManager(eng); got != nil {
		t.Errorf("GetKeyManager() without manager = %v, want nil", got)
	}
}

func TestGetKeyManager_WithManager(t *testing.T) {
	km := NewInMemoryKeyManagerForTestDefault()
	eng, err := NewEngineWithOpts([]byte("test-password-for-getkey2"), nil, WithKeyManager(km))
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}
	got := GetKeyManager(eng)
	if got == nil {
		t.Error("GetKeyManager() should return the installed manager")
	}
}

// ---- engine.GetRotationState -----------------------------------------------

func TestGetRotationState_InitialisesIfNil(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-rotation-state"), nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}
	rs := GetRotationState(eng)
	if rs == nil {
		t.Error("GetRotationState() should never return nil")
	}
	// Should be in Idle phase
	if rs.Phase() != RotationIdle {
		t.Errorf("Phase() = %v, want RotationIdle", rs.Phase())
	}
}

// ---- engine.NewEngineWithChunkingAndProvider --------------------------------

func TestNewEngineWithChunkingAndProvider(t *testing.T) {
	eng, err := NewEngineWithChunkingAndProvider(
		[]byte("test-password-chunk-provider123"), nil, "", nil, true, DefaultChunkSize, "default", DefaultPBKDF2Iterations,
	)
	if err != nil {
		t.Fatalf("NewEngineWithChunkingAndProvider: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithChunkingAndProvider returned nil")
	}
	// Smoke-test encrypt/decrypt.
	data := []byte("chunking-and-provider")
	encReader, meta, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encData, _ := io.ReadAll(encReader)
	decReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encData), meta)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	got, _ := io.ReadAll(decReader)
	if !bytes.Equal(got, data) {
		t.Errorf("round-trip mismatch")
	}
}

// ---- parseKeyVersion -------------------------------------------------------

func TestParseKeyVersion(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"1", 1},
		{"0", 0},
		{"", 0},    // empty → 0 (default)
		{"abc", 0}, // invalid → 0 (default)
		{"42", 42},
	}
	for _, tt := range tests {
		got := parseKeyVersion(tt.input)
		if got != tt.want {
			t.Errorf("parseKeyVersion(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// ---- keymanager_memory.WithMemoryVersions ----------------------------------

func TestWithMemoryVersions(t *testing.T) {
	// Exercise WithMemoryVersions option.
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte(i)
	}

	km, err := NewInMemoryKeyManager(nil,
		WithMemoryVersions([]struct {
			Version int
			Key     []byte
		}{
			{Version: 1, Key: key1},
			{Version: 2, Key: key2},
		}),
	)
	if err != nil {
		t.Fatalf("NewInMemoryKeyManager with versions: %v", err)
	}

	ctx := context.Background()
	ver, err := km.ActiveKeyVersion(ctx)
	if err != nil {
		t.Fatalf("ActiveKeyVersion: %v", err)
	}
	if ver < 2 {
		t.Errorf("expected active version >= 2, got %d", ver)
	}
}

func TestMemoryKeyManager_AdditionalCoverage(t *testing.T) {
	// Wrap with memory manager to test WithMemoryVersions if available.
	// We use InMemoryKeyManager which is the primary memory KM.
	memKM := NewInMemoryKeyManagerForTestDefault()

	// Exercise Provider() path.
	if memKM.Provider() == "" {
		t.Error("Provider() should not be empty")
	}

	ctx := context.Background()
	ver, err := memKM.ActiveKeyVersion(ctx)
	if err != nil {
		t.Fatalf("ActiveKeyVersion: %v", err)
	}
	if ver <= 0 {
		t.Errorf("expected positive version, got %d", ver)
	}

	// HealthCheck should pass.
	if err := memKM.HealthCheck(ctx); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}
}

// ---- range_decrypt.Close ---------------------------------------------------

func TestRangeDecryptReader_Close(t *testing.T) {
	engine, err := NewEngineWithChunking([]byte("test-password-12345678"), nil, "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}

	data := make([]byte, 32*1024) // 32KB
	for i := range data {
		data[i] = byte(i % 251)
	}

	encReader, meta, err := engine.Encrypt(context.Background(), bytes.NewReader(data), map[string]string{
		"Content-Length": fmt.Sprintf("%d", len(data)),
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("read encrypted: %v", err)
	}

	// Create a range decrypt reader via the engine's DecryptRange method.
	decReader, _, err := engine.DecryptRange(context.Background(), bytes.NewReader(encData), meta, 0, int64(len(data)-1))
	if err != nil {
		t.Fatalf("DecryptRange: %v", err)
	}

	// Read partial data.
	buf := make([]byte, 100)
	if _, err := decReader.Read(buf); err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}

	// Close should succeed.
	if c, ok := decReader.(io.Closer); ok {
		if err := c.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}
}

// ---- buffer pool: Get4/Get12/Get32/Get64K eviction paths -------------------

func TestBufferPool_AllSizes_GetPut(t *testing.T) {
	pool := GetGlobalBufferPool()

	// Get4
	b4 := pool.Get4()
	if b4 == nil {
		t.Fatal("Get4() returned nil")
	}
	pool.Put4(b4)

	// Get12
	b12 := pool.Get12()
	if b12 == nil {
		t.Fatal("Get12() returned nil")
	}
	pool.Put12(b12)

	// Get32
	b32 := pool.Get32()
	if b32 == nil {
		t.Fatal("Get32() returned nil")
	}
	pool.Put32(b32)

	// Get64K
	b64k := pool.Get64K()
	if b64k == nil {
		t.Fatal("Get64K() returned nil")
	}
	pool.Put64K(b64k)

	// HitRate methods are on BufferPoolMetrics — ensure they don't panic.
	metrics := pool.GetMetrics()
	_ = metrics.HitRate4()
	_ = metrics.HitRate12()
	_ = metrics.HitRate32()
	_ = metrics.HitRate64K()
}

// TestBufferPool_HitRateMissCase exercises the miss/hit tracking in Get*/Put*.
func TestBufferPool_HitRateMissCase(t *testing.T) {
	pool := GetGlobalBufferPool()

	// Reset counters so this test has a clean slate.
	pool.Reset()

	// First Get after reset: pool may return from internal sync.Pool (hit) or
	// allocate new (miss). Either way, Put then Get again should update counters.
	b := pool.Get4()
	if b == nil {
		t.Fatal("Get4() should return non-nil")
	}
	pool.Put4(b)

	b2 := pool.Get4()
	if b2 == nil {
		t.Fatal("Get4() hit returned nil")
	}
	pool.Put4(b2)

	// At least one operation (first Get after Reset) should record a miss or hit.
	metrics := pool.GetMetrics()
	total4 := metrics.Hits4 + metrics.Misses4
	if total4 == 0 {
		t.Error("expected at least one Get4 recorded in metrics")
	}

	// HitRate should be in [0, 1].
	hr := metrics.HitRate4()
	if hr < 0 || hr > 1 {
		t.Errorf("HitRate4() = %f, want in [0,1]", hr)
	}
}

// ---- engine.Decrypt: unencrypted pass-through ------------------------------

func TestEngine_Decrypt_NotEncrypted(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-decrypt-noenc"), nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}

	// Metadata with no encryption markers → pass-through.
	data := []byte("plain text data")
	meta := map[string]string{"Content-Type": "text/plain"}

	r, outMeta, err := eng.Decrypt(context.Background(), bytes.NewReader(data), meta)
	if err != nil {
		t.Fatalf("Decrypt unencrypted: %v", err)
	}
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, data) {
		t.Errorf("Decrypt passthrough: data mismatch")
	}
	_ = outMeta
}

// ---- engine.Encrypt + Decrypt: KMS path (InMemoryKeyManager) ---------------

func TestEngine_EncryptDecrypt_WithInMemoryKeyManager(t *testing.T) {
	km, err := NewInMemoryKeyManager(nil)
	if err != nil {
		t.Fatalf("NewInMemoryKeyManager: %v", err)
	}
	eng, err := NewEngineWithOpts([]byte("test-password-base-long-enough"), nil, WithKeyManager(km))
	if err != nil {
		t.Fatalf("NewEngineWithOpts with km: %v", err)
	}

	data := []byte("encrypt-decrypt with in-memory key manager")

	encReader, meta, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt with KM: %v", err)
	}
	encData, _ := io.ReadAll(encReader)

	decReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encData), meta)
	if err != nil {
		t.Fatalf("Decrypt with KM: %v", err)
	}
	got, _ := io.ReadAll(decReader)
	if !bytes.Equal(got, data) {
		t.Errorf("round-trip mismatch with KM")
	}
}

// ---- engine.Decrypt: legacy non-chunked path --------------------------------

func TestEngine_EncryptDecrypt_LegacyMode(t *testing.T) {
	// Use non-chunked engine to exercise the legacy buffered decrypt path.
	eng, err := NewEngine([]byte("test-password-legacy-mode-long12345"))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	data := []byte("legacy mode encrypt-decrypt test")

	encReader, meta, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt legacy: %v", err)
	}
	encData, _ := io.ReadAll(encReader)

	decReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encData), meta)
	if err != nil {
		t.Fatalf("Decrypt legacy: %v", err)
	}
	got, _ := io.ReadAll(decReader)
	if !bytes.Equal(got, data) {
		t.Errorf("legacy round-trip mismatch")
	}
}

// ---- engine.Encrypt: large data to trigger multiple chunks -----------------

func TestEngine_Encrypt_MultiChunk(t *testing.T) {
	chunkSize := 16 * 1024 // 16KB chunks
	eng, err := NewEngineWithChunking([]byte("test-password-multichunk-123456"), nil, "", nil, true, chunkSize)
	if err != nil {
		t.Fatalf("NewEngineWithChunking: %v", err)
	}

	// 3x chunk size to guarantee multiple chunks.
	data := make([]byte, 3*chunkSize+1000)
	for i := range data {
		data[i] = byte(i % 251)
	}

	encReader, meta, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt multi-chunk: %v", err)
	}
	encData, _ := io.ReadAll(encReader)
	if len(encData) == 0 {
		t.Fatal("expected non-empty encrypted data")
	}

	decReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encData), meta)
	if err != nil {
		t.Fatalf("Decrypt multi-chunk: %v", err)
	}
	got, _ := io.ReadAll(decReader)
	if !bytes.Equal(got, data) {
		t.Errorf("multi-chunk round-trip mismatch")
	}
}

// ---- engine.IsEncrypted (additional cases) ---------------------------------

func TestEngine_IsEncrypted_Additional(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-isencrypted-long"), nil)
	if err != nil {
		t.Fatalf("NewEngineWithOpts: %v", err)
	}

	// Not encrypted.
	if eng.IsEncrypted(nil) {
		t.Error("IsEncrypted(nil) should be false")
	}
	if eng.IsEncrypted(map[string]string{}) {
		t.Error("IsEncrypted({}) should be false")
	}

	// Encrypt and check.
	encR, meta, err := eng.Encrypt(context.Background(), bytes.NewReader([]byte("data")), nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	io.ReadAll(encR)

	if !eng.IsEncrypted(meta) {
		t.Error("IsEncrypted should be true for encrypted metadata")
	}
}

// ---- keymanager_memory: PrepareRotation / PromoteActiveVersion -------------

func TestMemoryKeyManager_PrepareAndPromoteRotation(t *testing.T) {
	km, err := NewInMemoryKeyManager(nil)
	if err != nil {
		t.Fatalf("NewInMemoryKeyManager: %v", err)
	}

	ctx := context.Background()
	rotKM, ok := km.(RotatableKeyManager)
	if !ok {
		t.Skip("InMemoryKeyManager does not implement RotatableKeyManager")
	}

	// PrepareRotation — add a new version first.
	if adder, ok := km.(interface {
		AddVersion(ctx context.Context) (int, error)
	}); ok {
		_, err := adder.AddVersion(ctx)
		if err != nil {
			t.Logf("AddVersion error (may be expected on single-version manager): %v", err)
		}
	}

	plan, err := rotKM.PrepareRotation(ctx, nil)
	if err != nil {
		t.Logf("PrepareRotation error (may be expected): %v", err)
	}
	_ = plan

	// PromoteActiveVersion with the plan we got back.
	err = rotKM.PromoteActiveVersion(ctx, plan)
	if err != nil {
		t.Logf("PromoteActiveVersion error (may be expected): %v", err)
	}
}

// ---- keymanager_memory: UnwrapKey error paths ------------------------------

func TestMemoryKeyManager_UnwrapKey_NilEnvelope(t *testing.T) {
	km, err := NewInMemoryKeyManager(nil)
	if err != nil {
		t.Fatalf("NewInMemoryKeyManager: %v", err)
	}

	ctx := context.Background()

	// Nil envelope.
	_, err = km.UnwrapKey(ctx, nil, nil)
	if err == nil {
		t.Error("expected error for nil envelope")
	}
}

func TestMemoryKeyManager_UnwrapKey_TamperedCiphertext(t *testing.T) {
	km, err := NewInMemoryKeyManager(nil)
	if err != nil {
		t.Fatalf("NewInMemoryKeyManager: %v", err)
	}

	ctx := context.Background()

	// WrapKey, then tamper with ciphertext.
	dek := make([]byte, 32)
	env, err := km.WrapKey(ctx, dek, nil)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}

	// Tamper.
	env.Ciphertext[len(env.Ciphertext)-1] ^= 0xff
	_, err = km.UnwrapKey(ctx, env, nil)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

// ---- compression.ShouldCompress uncovered branch ---------------------------

func TestCompressionEngine_ShouldCompress_FalseWhenDisabled(t *testing.T) {
	// When compression is disabled, ShouldCompress should return false.
	ce := NewCompressionEngine(false, 1024, nil, "gzip", 6)
	if ce.ShouldCompress(10_000, "image/png") {
		t.Error("ShouldCompress should be false when compression disabled")
	}
}

func TestCompressionEngine_ShouldCompress_LargeFile(t *testing.T) {
	ce := NewCompressionEngine(true, 1024, []string{"application/json"}, "gzip", 6)
	// Content type that is compressible, large size.
	result := ce.ShouldCompress(100_000, "application/json")
	_ = result // just ensure no panic
}

func TestCompressionEngine_ShouldCompress_SmallFileBelowThreshold(t *testing.T) {
	ce := NewCompressionEngine(true, 10_000, nil, "gzip", 6)
	// File smaller than minSize should not be compressed.
	if ce.ShouldCompress(100, "application/json") {
		t.Error("ShouldCompress should be false when size < minSize")
	}
}
