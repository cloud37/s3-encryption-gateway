package crypto

import (
	"testing"
	"time"
)

// TestRetryingKeyManager_Conformance runs the full ConformanceSuite on a
// RetryingKeyManager wrapping an in-memory adapter.
func TestRetryingKeyManager_Conformance(t *testing.T) {
	ConformanceSuite(t, func(t *testing.T) KeyManager {
		t.Helper()
		inner, err := NewInMemoryKeyManager(nil)
		if err != nil {
			t.Fatalf("NewInMemoryKeyManager: %v", err)
		}
		cfg := DefaultRetryConfig()
		cfg.InitialInterval = time.Millisecond
		cfg.MaxInterval = 5 * time.Millisecond
		cfg.MaxElapsedTime = time.Second
		return NewRetryingKeyManager(inner, cfg)
	})
}
