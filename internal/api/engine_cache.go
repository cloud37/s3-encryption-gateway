package api

import (
	"sync"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
)

// closeEngine calls Close() on an EncryptionEngine if it implements the
// io.Closer interface.  This is used when evicting engines from the policy
// cache so that password bytes are zeroised.
func closeEngine(e crypto.EncryptionEngine) {
	if c, ok := e.(interface{ Close() error }); ok {
		_ = c.Close()
	}
}

// engineCacheEntry wraps a per-policy engine with an expiration timestamp.
type engineCacheEntry struct {
	engine    crypto.EncryptionEngine
	expiresAt time.Time
}

// ttlEngineCache is a TTL-based cache for per-policy encryption engines.
// It guarantees that Close() is called on every evicted engine so that
// password bytes are zeroised (V1.0-SEC-20).
type ttlEngineCache struct {
	mu       sync.RWMutex
	entries  map[string]*engineCacheEntry
	ttl      time.Duration
	interval time.Duration
	ticker   *time.Ticker
	stop     chan struct{}
	done     chan struct{}
	started  bool
}

// newTTLEngineCache creates a TTL engine cache.  ttl controls how long an
// engine remains valid; interval controls how often the background sweeper
// runs to evict expired entries.
func newTTLEngineCache(ttl, interval time.Duration) *ttlEngineCache {
	return &ttlEngineCache{
		ttl:      ttl,
		interval: interval,
	}
}

// start begins the background sweep goroutine.  The caller must hold c.mu.
// It is safe to call multiple times; only the first call has any effect.
func (c *ttlEngineCache) start() {
	if c.started {
		return
	}
	c.started = true
	c.entries = make(map[string]*engineCacheEntry)
	c.ticker = time.NewTicker(c.interval)
	c.stop = make(chan struct{})
	c.done = make(chan struct{})
	go c.sweepLoop()
}

// sweepLoop periodically calls sweep() until Stop() is invoked.
func (c *ttlEngineCache) sweepLoop() {
	defer close(c.done)
	for {
		select {
		case <-c.ticker.C:
			c.sweep()
		case <-c.stop:
			return
		}
	}
}

// sweep iterates the cache and closes + deletes any expired entries.
func (c *ttlEngineCache) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		return
	}
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			closeEngine(entry.engine)
			delete(c.entries, key)
		}
	}
}

// Get returns a cached engine if it exists and has not expired.
// If the entry has expired it is removed from the cache and Close() is
// called on the engine before returning (false, nil).
func (c *ttlEngineCache) Get(key string) (crypto.EncryptionEngine, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	if !ok {
		c.mu.RUnlock()
		return nil, false
	}
	if time.Now().Before(entry.expiresAt) {
		c.mu.RUnlock()
		return entry.engine, true
	}
	c.mu.RUnlock()

	// Expired — acquire write lock to delete and close.
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok && time.Now().After(entry.expiresAt) {
		closeEngine(entry.engine)
		delete(c.entries, key)
	}
	return nil, false
}

// GetOrStore atomically stores engine if no unexpired entry exists for key,
// or returns the existing unexpired entry.  If an existing entry is found the
// supplied engine is safely closed (it was never returned to a caller).
func (c *ttlEngineCache) GetOrStore(key string, engine crypto.EncryptionEngine) crypto.EncryptionEngine {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.started {
		c.start()
	}
	if old, ok := c.entries[key]; ok && time.Now().Before(old.expiresAt) {
		closeEngine(engine)
		return old.engine
	}
	c.entries[key] = &engineCacheEntry{
		engine:    engine,
		expiresAt: time.Now().Add(c.ttl),
	}
	return engine
}

// Stop halts the background sweeper and calls Close() on every remaining
// cached engine.  It is safe to call on an unstarted cache (no-op).
func (c *ttlEngineCache) Stop() {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return
	}
	c.ticker.Stop()
	close(c.stop)
	c.mu.Unlock()

	<-c.done

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, entry := range c.entries {
		closeEngine(entry.engine)
	}
	c.entries = make(map[string]*engineCacheEntry)
}
