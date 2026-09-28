package cache

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CacheEntry represents a cached item.
type CacheEntry struct {
	Data        []byte
	Metadata    map[string]string
	BackendETag string
	Source      []byte
	ExpiresAt   time.Time
}

// IsExpired checks if the cache entry has expired.
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// Cache is an interface for caching objects.
type Cache interface {
	// Get retrieves a cached object.
	Get(ctx context.Context, bucket, key string) (*CacheEntry, bool)

	// Set stores an object in the cache.
	Set(ctx context.Context, bucket, key string, data []byte, metadata map[string]string, ttl time.Duration) error

	// Delete removes an object from the cache.
	Delete(ctx context.Context, bucket, key string) error

	// Clear clears all cached objects.
	Clear(ctx context.Context) error

	// Stats returns cache statistics.
	Stats() CacheStats
}

// EntryWriter is an optional cache capability for atomically storing the body
// together with freshness and response-source metadata. Cache implementations
// that do not implement it remain usable for legacy cache callers.
type EntryWriter interface {
	SetEntry(ctx context.Context, bucket, key string, entry *CacheEntry, ttl time.Duration) error
}

// CacheStats holds cache statistics.
type CacheStats struct {
	Size      int64
	Items     int
	Hits      int64
	Misses    int64
	Evictions int64
}

// memoryCache is an in-memory implementation of Cache.
type memoryCache struct {
	mu       sync.RWMutex
	entries  map[string]*CacheEntry
	maxSize  int64
	maxItems int
	stats    CacheStats
	ttl      time.Duration
}

// NewMemoryCache creates a new in-memory cache.
func NewMemoryCache(maxSize int64, maxItems int, defaultTTL time.Duration) Cache {
	return &memoryCache{
		entries:  make(map[string]*CacheEntry),
		maxSize:  maxSize,
		maxItems: maxItems,
		ttl:      defaultTTL,
	}
}

// cacheKey generates a cache key from bucket and object key.
func cacheKey(bucket, key string) string {
	return fmt.Sprintf("%s:%s", bucket, key)
}

// Get retrieves a cached object.
func (c *memoryCache) Get(ctx context.Context, bucket, key string) (*CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyStr := cacheKey(bucket, key)
	entry, ok := c.entries[keyStr]
	if !ok {
		c.stats.Misses++
		return nil, false
	}

	if entry.IsExpired() {
		c.stats.Misses++
		return nil, false
	}

	c.stats.Hits++
	return entry, true
}

// Set stores an object in the cache.
func (c *memoryCache) Set(ctx context.Context, bucket, key string, data []byte, metadata map[string]string, ttl time.Duration) error {
	return c.SetEntry(ctx, bucket, key, &CacheEntry{Data: data, Metadata: metadata}, ttl)
}

// SetEntry stores a complete cache entry atomically.
func (c *memoryCache) SetEntry(ctx context.Context, bucket, key string, value *CacheEntry, ttl time.Duration) error {
	if value == nil {
		return fmt.Errorf("cache entry is nil")
	}
	if ttl == 0 {
		ttl = c.ttl
	}

	entry := &CacheEntry{
		Data:        append([]byte(nil), value.Data...),
		Metadata:    cloneMetadata(value.Metadata),
		BackendETag: value.BackendETag,
		Source:      append([]byte(nil), value.Source...),
		ExpiresAt:   time.Now().Add(ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Check size limits
	entrySize := int64(len(entry.Data))
	currentSize := c.getCurrentSizeLocked()

	// Evict expired entries first
	c.evictExpiredLocked()

	// Check if we need to evict to make room
	if currentSize+entrySize > c.maxSize || len(c.entries) >= c.maxItems {
		if !c.evictForSpaceLocked(entrySize) {
			return fmt.Errorf("cache full and unable to evict")
		}
	}

	keyStr := cacheKey(bucket, key)
	c.entries[keyStr] = entry

	return nil
}

func cloneMetadata(metadata map[string]string) map[string]string {
	if metadata == nil {
		return nil
	}
	cloned := make(map[string]string, len(metadata))
	for key, value := range metadata {
		cloned[key] = value
	}
	return cloned
}

// Delete removes an object from the cache.
func (c *memoryCache) Delete(ctx context.Context, bucket, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	keyStr := cacheKey(bucket, key)
	delete(c.entries, keyStr)

	return nil
}

// Clear clears all cached objects.
func (c *memoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[string]*CacheEntry)
	c.stats = CacheStats{}

	return nil
}

// Stats returns cache statistics.
func (c *memoryCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := c.stats
	stats.Size = c.getCurrentSizeLocked()
	stats.Items = len(c.entries)

	return stats
}

// getCurrentSizeLocked calculates the current cache size (must be called with lock held).
func (c *memoryCache) getCurrentSizeLocked() int64 {
	var size int64
	for _, entry := range c.entries {
		if !entry.IsExpired() {
			size += int64(len(entry.Data))
		}
	}
	return size
}

// evictExpiredLocked removes expired entries (must be called with lock held).
func (c *memoryCache) evictExpiredLocked() {
	for key, entry := range c.entries {
		if entry.IsExpired() {
			delete(c.entries, key)
			c.stats.Evictions++
		}
	}
}

// evictForSpaceLocked evicts entries to make room (must be called with lock held).
func (c *memoryCache) evictForSpaceLocked(neededSpace int64) bool {
	// Simple LRU-style eviction: remove oldest entries first
	// In production, you might want a more sophisticated eviction policy

	// First, try to remove expired entries
	c.evictExpiredLocked()

	currentSize := c.getCurrentSizeLocked()
	if currentSize+neededSpace <= c.maxSize && len(c.entries) < c.maxItems {
		return true
	}

	// Remove oldest entries (simplified - in production use proper LRU)
	// For now, just remove enough entries
	targetSize := c.maxSize - neededSpace
	for key, entry := range c.entries {
		if currentSize <= targetSize && len(c.entries) < c.maxItems {
			break
		}
		delete(c.entries, key)
		c.stats.Evictions++
		currentSize -= int64(len(entry.Data))
	}

	return true
}
