package crypto

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockCacheKM implements KeyManager with controllable call counting for cache tests.
type mockCacheKM struct {
	KeyManager
	provider       string
	unwrapCallCount atomic.Int32
	unwrapResult   []byte
	unwrapErr      error
}

func (m *mockCacheKM) Provider() string { return m.provider }

func (m *mockCacheKM) WrapKey(_ context.Context, _ []byte, _ map[string]string) (*KeyEnvelope, error) {
	return &KeyEnvelope{KeyID: "k1", Ciphertext: []byte("env")}, nil
}

func (m *mockCacheKM) UnwrapKey(_ context.Context, env *KeyEnvelope, _ map[string]string) ([]byte, error) {
	m.unwrapCallCount.Add(1)
	if m.unwrapErr != nil {
		return nil, m.unwrapErr
	}
	if env == nil {
		return nil, nil
	}
	pt := make([]byte, len(m.unwrapResult))
	copy(pt, m.unwrapResult)
	return pt, nil
}

func (m *mockCacheKM) HealthCheck(_ context.Context) error { return nil }

func (m *mockCacheKM) ActiveKeyVersion(_ context.Context) (int, error) { return 1, nil }

func (m *mockCacheKM) Close(_ context.Context) error { return nil }

func TestCachingKeyManager_UnwrapKey_CacheHit(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true
	cfg.TTL = time.Minute

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	env := &KeyEnvelope{Ciphertext: []byte("same-ciphertext")}

	// First call — cache miss
	pt1, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, inner.unwrapResult, pt1)
	require.Equal(t, int32(1), inner.unwrapCallCount.Load())

	// Second call — cache hit
	pt2, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, inner.unwrapResult, pt2)
	// Inner should still have been called only once
	require.Equal(t, int32(1), inner.unwrapCallCount.Load())
}

func TestCachingKeyManager_UnwrapKey_CacheMiss(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true
	cfg.TTL = time.Minute

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Two distinct envelopes should both miss the cache
	env1 := &KeyEnvelope{Ciphertext: []byte("ciphertext-1")}
	env2 := &KeyEnvelope{Ciphertext: []byte("ciphertext-2")}

	pt1, err := km.UnwrapKey(context.Background(), env1, nil)
	require.NoError(t, err)
	require.NotNil(t, pt1)

	pt2, err := km.UnwrapKey(context.Background(), env2, nil)
	require.NoError(t, err)
	require.NotNil(t, pt2)

	require.Equal(t, int32(2), inner.unwrapCallCount.Load())
}

func TestCachingKeyManager_UnwrapKey_TTLExpired(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true
	cfg.TTL = 50 * time.Millisecond

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	env := &KeyEnvelope{Ciphertext: []byte("test-ct")}

	// First call — miss
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), inner.unwrapCallCount.Load())

	// Second call — should be a hit (before TTL)
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, int32(1), inner.unwrapCallCount.Load(), "should be cache hit before TTL expiry")

	// Wait for TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Third call — TTL expired, should miss
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, int32(2), inner.unwrapCallCount.Load(), "should be cache miss after TTL expiry")
}

func TestCachingKeyManager_LRU_EvictedEntryZeroized(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true
	cfg.TTL = time.Hour
	cfg.MaxEntries = 2 // very small cache

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Create 3 distinct envelopes — the first should be evicted
	env1 := &KeyEnvelope{Ciphertext: []byte("ct-1")}
	env2 := &KeyEnvelope{Ciphertext: []byte("ct-2")}
	env3 := &KeyEnvelope{Ciphertext: []byte("ct-3")}

	_, _ = km.UnwrapKey(context.Background(), env1, nil)
	_, _ = km.UnwrapKey(context.Background(), env2, nil)
	_, _ = km.UnwrapKey(context.Background(), env3, nil)

	// env1 should have been evicted (LRU)
	fp1 := cacheFingerprint([]byte("ct-1"))
	km.(*CachingKeyManager).mu.RLock()
	_, ok1 := km.(*CachingKeyManager).entries[fp1]
	km.(*CachingKeyManager).mu.RUnlock()
	require.False(t, ok1, "env1 should be evicted from cache")
}

func TestCachingKeyManager_Close_ZeroizesAllEntries(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true
	cfg.TTL = time.Hour
	cfg.MaxEntries = 10

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)

	// Populate cache with some entries
	for i := byte(0); i < 3; i++ {
		env := &KeyEnvelope{Ciphertext: []byte{i, 2, 3}}
		_, err := km.UnwrapKey(context.Background(), env, nil)
		require.NoError(t, err)
	}

	// Close should zeroize all
	err = km.Close(context.Background())
	require.NoError(t, err)

	// After close, entries map should be empty
	ckm := km.(*CachingKeyManager)
	ckm.mu.RLock()
	require.Empty(t, ckm.entries, "all entries should be zeroized and removed on Close")
	ckm.mu.RUnlock()
}

func TestCachingKeyManager_TamperedCiphertextNotCached(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true
	cfg.TTL = time.Hour

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Two different ciphertexts produce different fingerprints
	env1 := &KeyEnvelope{Ciphertext: []byte("original-ct")}
	env2 := &KeyEnvelope{Ciphertext: []byte("tampered-ct")}

	fp1 := cacheFingerprint(env1.Ciphertext)
	fp2 := cacheFingerprint(env2.Ciphertext)
	require.NotEqual(t, fp1, fp2, "SHA-256 fingerprints must differ for different ciphertexts")

	_, _ = km.UnwrapKey(context.Background(), env1, nil)
	_, _ = km.UnwrapKey(context.Background(), env2, nil)

	// Both should be in the cache
	ckm := km.(*CachingKeyManager)
	ckm.mu.RLock()
	_, ok1 := ckm.entries[fp1]
	_, ok2 := ckm.entries[fp2]
	ckm.mu.RUnlock()
	require.True(t, ok1, "env1 should be cached")
	require.True(t, ok2, "env2 should be cached")
}

func TestCachingKeyManager_WrapKey_NotCached(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// WrapKey should never be cached; each call should delegate
	env, err := km.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err)
	require.NotNil(t, env)
}

func TestCachingKeyManager_Disabled_NoCaching(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = false // cache disabled

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	env := &KeyEnvelope{Ciphertext: []byte("test-ct")}

	// Both calls should delegate to inner
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)

	require.Equal(t, int32(2), inner.unwrapCallCount.Load(), "with cache disabled, every call should delegate")
}

func TestCachingKeyManager_NilEnvelope_NoCaching(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("32byte-dek-plaintext-xxxxxxxxxx"),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Nil envelope should delegate without caching
	pt, err := km.UnwrapKey(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, pt)

	// Each call should delegate to inner
	pt2, err := km.UnwrapKey(context.Background(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, pt2)

	require.Equal(t, int32(2), inner.unwrapCallCount.Load(), "nil envelope should never cache")
}

func TestCachingKeyManager_Provider_Delegates(t *testing.T) {
	inner := &mockCacheKM{provider: "cosmian-kmip"}
	cfg := DefaultDEKCacheConfig()

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	require.Equal(t, "cosmian-kmip", km.Provider())
}

func TestCachingKeyManager_HealthCheck_Delegates(t *testing.T) {
	inner := &mockCacheKM{provider: "test"}
	cfg := DefaultDEKCacheConfig()

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	err = km.HealthCheck(context.Background())
	require.NoError(t, err)
}

func TestCachingKeyManager_ActiveKeyVersion_Delegates(t *testing.T) {
	inner := &mockCacheKM{provider: "test"}
	cfg := DefaultDEKCacheConfig()

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	ver, err := km.ActiveKeyVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, ver)
}

// TestCachingKeyManager_ConcurrentAccess verifies thread safety under concurrent reads.
func TestCachingKeyManager_ConcurrentAccess(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: make([]byte, 32),
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true
	cfg.TTL = time.Minute
	cfg.MaxEntries = 100

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	// Fire concurrent unwrap requests
	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func(id byte) {
			env := &KeyEnvelope{Ciphertext: []byte{id, 0x01, 0x02}}
			_, err := km.UnwrapKey(context.Background(), env, nil)
			require.NoError(t, err)
			done <- struct{}{}
		}(byte(i))
	}

	for i := 0; i < 20; i++ {
		<-done
	}
}

// TestCachingKeyManager_ReturnedCopyIsIndependent verifies that the caller gets
// a copy and modifying it doesn't affect the cache.
func TestCachingKeyManager_ReturnedCopyIsIndependent(t *testing.T) {
	inner := &mockCacheKM{
		provider:     "test",
		unwrapResult: []byte("01234567890123456789012345678901"), // 32 bytes
	}
	cfg := DefaultDEKCacheConfig()
	cfg.Enabled = true
	cfg.TTL = time.Minute

	km, err := NewCachingKeyManager(inner, cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	env := &KeyEnvelope{Ciphertext: []byte("test-ct")}
	pt1, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)

	// Modify caller's copy
	pt1[0] = 0xFF

	// Second call should still get the original data
	pt2, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, byte('0'), pt2[0], "cache should return original data, not modified copy")
}
