package crypto

import (
	"testing"
	"time"
)

// TestCachingKeyManager_Conformance runs the full ConformanceSuite on a
// CachingKeyManager wrapping an in-memory adapter.
func TestCachingKeyManager_Conformance(t *testing.T) {
	ConformanceSuite(t, func(t *testing.T) KeyManager {
		t.Helper()
		inner, err := NewInMemoryKeyManager(nil)
		if err != nil {
			t.Fatalf("NewInMemoryKeyManager: %v", err)
		}
		cfg := DEKCacheConfig{
			Enabled: true,
			TTL:     time.Minute,
		}
		km, err := NewCachingKeyManager(inner, cfg)
		if err != nil {
			t.Fatalf("NewCachingKeyManager: %v", err)
		}
		return km
	})
}
