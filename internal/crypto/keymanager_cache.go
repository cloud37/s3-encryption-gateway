package crypto

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

// cacheEntry holds a cached DEK plaintext and its expiry time.
type cacheEntry struct {
	plaintext []byte
	expiresAt time.Time
}

// DEKCacheConfig holds configuration for the CachingKeyManager.
type DEKCacheConfig struct {
	// Enabled enables the DEK unwrap cache. Default: false.
	Enabled bool
	// TTL is the duration a cached DEK unwrap result is valid. Default: 60 s.
	TTL time.Duration
	// MaxEntries is the maximum number of cached entries (LRU eviction). Default: 1000.
	MaxEntries int
	// CleanupInterval is how often the background cleanup ticker runs.
	// Default: TTL/2, minimum 5 s.
	CleanupInterval time.Duration
}

// DefaultDEKCacheConfig returns a DEKCacheConfig with production defaults.
func DefaultDEKCacheConfig() DEKCacheConfig {
	return DEKCacheConfig{
		Enabled:    false,
		TTL:        60 * time.Second,
		MaxEntries: 1000,
	}
}

// CachingKeyManager wraps a KeyManager and caches UnwrapKey results in a
// fixed-size LRU (Least-Recently-Used) map.
//
// Invariants:
//   - Thread-safe: all cache operations are guarded by a sync.RWMutex.
//   - Cache key: SHA-256 of envelope.Ciphertext (32-byte fingerprint, never
//     stores plaintext key material as the map key).
//   - Cache value: plaintext DEK bytes + expiry time.Time.
//   - On Get hit: a copy of the cached DEK is returned; the caller owns the copy
//     and is responsible for zeroization.
//   - On eviction (TTL expiry or capacity): the cached DEK bytes are zeroized.
//   - Close: all cached DEK bytes are zeroized before the cache is cleared.
//   - WrapKey is never cached.
//   - Expired entries are lazily evicted on access or via a background cleanup
//     ticker (cleanupInterval default: TTL/2).
type CachingKeyManager struct {
	inner KeyManager
	cfg   DEKCacheConfig

	mu            sync.RWMutex
	entries       map[[32]byte]*cacheEntry // fingerprint → entry
	lruOrder      [][32]byte               // insertion-ordered for LRU eviction
	stopCleanup   chan struct{}
	cleanupDone   chan struct{}
}

// cacheFingerprint computes the SHA-256 fingerprint of ciphertext.
func cacheFingerprint(ciphertext []byte) [32]byte {
	return sha256.Sum256(ciphertext)
}

// Compile-time assertion that CachingKeyManager implements KeyManager.
var _ KeyManager = (*CachingKeyManager)(nil)

// NewCachingKeyManager creates a new CachingKeyManager wrapping the given KeyManager.
// Returns an error if configuration is invalid.
// KMS cache metrics are recorded via the callbacks registered by
// SetKMSDEKCacheHitObserver and SetKMSDEKCacheMissObserver.
func NewCachingKeyManager(inner KeyManager, cfg DEKCacheConfig) (KeyManager, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultDEKCacheConfig().TTL
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultDEKCacheConfig().MaxEntries
	}
	cleanupInterval := cfg.CleanupInterval
	if cleanupInterval <= 0 {
		cleanupInterval = cfg.TTL / 2
		if cleanupInterval < 5*time.Second {
			cleanupInterval = 5 * time.Second
		}
	}

	km := &CachingKeyManager{
		inner:        inner,
		cfg:          cfg,
		entries:      make(map[[32]byte]*cacheEntry),
		lruOrder:     make([][32]byte, 0, cfg.MaxEntries),
		stopCleanup:  make(chan struct{}),
		cleanupDone:  make(chan struct{}),
	}

	if cfg.Enabled {
		go km.cleanupLoop(cleanupInterval)
	} else {
		close(km.cleanupDone) // no cleanup needed
	}

	return km, nil
}

// cleanupLoop periodically removes expired entries.
func (c *CachingKeyManager) cleanupLoop(interval time.Duration) {
	defer close(c.cleanupDone)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.evictExpired()
		case <-c.stopCleanup:
			return
		}
	}
}

// evictExpired removes all entries where the TTL has expired.
func (c *CachingKeyManager) evictExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	var newOrder [][32]byte
	for _, fp := range c.lruOrder {
		entry, ok := c.entries[fp]
		if !ok {
			continue
		}
		if now.After(entry.expiresAt) {
			zeroBytes(entry.plaintext)
			delete(c.entries, fp)
		} else {
			newOrder = append(newOrder, fp)
		}
	}
	c.lruOrder = newOrder
}

// Provider returns the inner KeyManager's provider identifier.
func (c *CachingKeyManager) Provider() string {
	return c.inner.Provider()
}

// WrapKey delegates to the inner KeyManager; never cached.
func (c *CachingKeyManager) WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error) {
	return c.inner.WrapKey(ctx, plaintext, metadata)
}

// UnwrapKey checks the cache first, then delegates to the inner KeyManager on miss.
func (c *CachingKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error) {
	if !c.cfg.Enabled || envelope == nil {
		return c.inner.UnwrapKey(ctx, envelope, metadata)
	}

	fp := cacheFingerprint(envelope.Ciphertext)

	// Check cache (read lock)
	c.mu.RLock()
	entry, ok := c.entries[fp]
	if ok && !time.Now().After(entry.expiresAt) {
		// Cache hit: return a COPY of the cached plaintext
		hit := make([]byte, len(entry.plaintext))
		copy(hit, entry.plaintext)
		c.mu.RUnlock()
		if recordKMSDEKCacheHitFn != nil {
			recordKMSDEKCacheHitFn(c.inner.Provider())
		}
		return hit, nil
	}
	c.mu.RUnlock()

	// Cache miss: call inner
	pt, err := c.inner.UnwrapKey(ctx, envelope, metadata)
	if err != nil {
		return nil, err
	}

	// Store in cache (write lock)
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check if another goroutine already cached this
	if existing, ok := c.entries[fp]; ok {
		// Entry already exists (race) — use existing, zeroize our copy
		// Actually, we just got a fresh pt from inner, we should store it.
		// But zeroize the existing one if it's different.
		if !time.Now().After(existing.expiresAt) {
			zeroBytes(pt)
			hit := make([]byte, len(existing.plaintext))
			copy(hit, existing.plaintext)
			if recordKMSDEKCacheHitFn != nil {
				recordKMSDEKCacheHitFn(c.inner.Provider())
			}
			return hit, nil
		}
		// Existing entry is expired — remove it
		zeroBytes(existing.plaintext)
		delete(c.entries, fp)
	}

	// Store new entry
	ptCopy := make([]byte, len(pt))
	copy(ptCopy, pt)
	c.entries[fp] = &cacheEntry{
		plaintext: ptCopy,
		expiresAt: time.Now().Add(c.cfg.TTL),
	}
	c.lruOrder = append(c.lruOrder, fp)

	// LRU eviction if over capacity
	if len(c.entries) > c.cfg.MaxEntries {
		c.evictLRU()
	}

	if recordKMSDEKCacheMissFn != nil {
		recordKMSDEKCacheMissFn(c.inner.Provider())
	}

	return pt, nil
}

// evictLRU removes the oldest entry from the cache.
func (c *CachingKeyManager) evictLRU() {
	for len(c.entries) > c.cfg.MaxEntries && len(c.lruOrder) > 0 {
		fp := c.lruOrder[0]
		c.lruOrder = c.lruOrder[1:]
		if entry, ok := c.entries[fp]; ok {
			zeroBytes(entry.plaintext)
			delete(c.entries, fp)
		}
	}
}

// HealthCheck delegates to the inner KeyManager.
func (c *CachingKeyManager) HealthCheck(ctx context.Context) error {
	return c.inner.HealthCheck(ctx)
}

// ActiveKeyVersion delegates to the inner KeyManager.
func (c *CachingKeyManager) ActiveKeyVersion(ctx context.Context) (int, error) {
	return c.inner.ActiveKeyVersion(ctx)
}

// Close stops the cleanup goroutine, zeroizes all cached plaintexts,
// and delegates to the inner KeyManager.
func (c *CachingKeyManager) Close(ctx context.Context) error {
	close(c.stopCleanup)
	<-c.cleanupDone

	c.mu.Lock()
	defer c.mu.Unlock()

	for fp, entry := range c.entries {
		zeroBytes(entry.plaintext)
		delete(c.entries, fp)
	}
	c.lruOrder = nil

	return c.inner.Close(ctx)
}

