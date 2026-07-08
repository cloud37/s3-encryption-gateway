// Package sizecache provides a write-through index mapping (bucket, key) to
// plaintext size, used by handleListObjects to resolve encrypted object sizes
// without issuing per-object HeadObject calls to the backend.
package sizecache

import (
	"context"
	"errors"
)

// ErrCacheUnavailable is returned when the cache backend is unreachable.
var ErrCacheUnavailable = errors.New("sizecache: cache unavailable")

// SizeCache is a write-through index mapping (bucket, key) → plaintextSize.
// It is used by handleListObjects to resolve encrypted object sizes without
// issuing per-object HeadObject calls to the backend.
//
// Invariants:
//   - All methods are safe for concurrent use.
//   - Context cancellation must be respected; implementations must not block
//     past ctx.Done().
//   - Set and Delete are best-effort: callers MUST NOT treat an error as fatal.
//     The index is advisory; stale or absent entries fall back to ciphertext sizes.
//   - GetBatch returns a map keyed on the requested keys. Missing keys are
//     absent from the map (not present with zero value).
//   - plaintextSize values MUST be > 0; implementations may reject ≤ 0 sizes.
type SizeCache interface {
	// Set records bucket/key → plaintextSize. Overwrites any existing entry.
	Set(ctx context.Context, bucket, key string, plaintextSize int64) error

	// SetBatch records multiple entries atomically where possible.
	// Partial failure is permitted; the error describes the first failure.
	SetBatch(ctx context.Context, bucket string, sizes map[string]int64) error

	// GetBatch returns the plaintext sizes for all requested keys that exist
	// in the cache. Keys not found are absent from the returned map.
	GetBatch(ctx context.Context, bucket string, keys []string) (map[string]int64, error)

	// Delete removes the entry for bucket/key. Safe to call for absent keys.
	Delete(ctx context.Context, bucket, key string) error

	// DeleteBatch removes entries for multiple keys in the same bucket.
	DeleteBatch(ctx context.Context, bucket string, keys []string) error

	// Close releases resources. Idempotent.
	Close() error
}

// NoopSizeCache implements SizeCache with no storage. All writes are no-ops;
// all reads return empty results. Used when Valkey is not configured.
type NoopSizeCache struct{}

func (n *NoopSizeCache) Set(_ context.Context, _, _ string, _ int64) error {
	return nil
}

func (n *NoopSizeCache) SetBatch(_ context.Context, _ string, _ map[string]int64) error {
	return nil
}

func (n *NoopSizeCache) GetBatch(_ context.Context, _ string, _ []string) (map[string]int64, error) {
	return nil, nil
}

func (n *NoopSizeCache) Delete(_ context.Context, _, _ string) error {
	return nil
}

func (n *NoopSizeCache) DeleteBatch(_ context.Context, _ string, _ []string) error {
	return nil
}

func (n *NoopSizeCache) Close() error {
	return nil
}
