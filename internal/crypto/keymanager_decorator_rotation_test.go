package crypto

import (
	"context"
	"crypto/rand"
	"testing"
	"time"
)

func newRotatableAESBase(t *testing.T) KeyManager {
	t.Helper()
	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	if _, err := rand.Read(k1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(k2); err != nil {
		t.Fatal(err)
	}
	km, err := NewAESKEKManager(map[int][]byte{1: k1, 2: k2}, 1)
	if err != nil {
		t.Fatalf("NewAESKEKManager: %v", err)
	}
	return km
}

// nonRotatableKM is a minimal KeyManager that intentionally does NOT implement
// RotatableKeyManager, used to verify the decorators do not fabricate
// rotatability.
type nonRotatableKM struct{}

func (nonRotatableKM) Provider() string { return "test-nonrotatable" }
func (nonRotatableKM) WrapKey(_ context.Context, pt []byte, _ map[string]string) (*KeyEnvelope, error) {
	return &KeyEnvelope{Ciphertext: append([]byte(nil), pt...)}, nil
}
func (nonRotatableKM) UnwrapKey(_ context.Context, e *KeyEnvelope, _ map[string]string) ([]byte, error) {
	return append([]byte(nil), e.Ciphertext...), nil
}
func (nonRotatableKM) ActiveKeyVersion(context.Context) (int, error) { return 1, nil }
func (nonRotatableKM) HealthCheck(context.Context) error             { return nil }
func (nonRotatableKM) Close(context.Context) error                   { return nil }

func testRetryCfg() RetryConfig {
	return RetryConfig{InitialInterval: time.Millisecond, MaxInterval: 10 * time.Millisecond, MaxElapsedTime: 100 * time.Millisecond, Multiplier: 2.0}
}
func testCBCfg() CircuitBreakerConfig {
	return CircuitBreakerConfig{ConsecutiveFailures: 5, OpenTimeout: time.Second, SuccessThreshold: 2}
}
func testCacheCfg() DEKCacheConfig {
	return DEKCacheConfig{Enabled: true, TTL: time.Minute, MaxEntries: 100}
}

// TestDecorators_PreserveRotatable is the regression test for the bug where the
// KMS decorators dropped RotatableKeyManager, making the admin rotation API
// return "rotation not supported" whenever a decorator was enabled.
func TestDecorators_PreserveRotatable(t *testing.T) {
	ctx := context.Background()
	wraps := map[string]func(*testing.T, KeyManager) KeyManager{
		"retry": func(t *testing.T, km KeyManager) KeyManager {
			return NewRetryingKeyManager(km, testRetryCfg())
		},
		"circuitbreaker": func(t *testing.T, km KeyManager) KeyManager {
			return NewCircuitBreakerKeyManager(km, testCBCfg())
		},
		"cache": func(t *testing.T, km KeyManager) KeyManager {
			c, err := NewCachingKeyManager(km, testCacheCfg())
			if err != nil {
				t.Fatal(err)
			}
			return c
		},
		"fallback": func(t *testing.T, km KeyManager) KeyManager {
			return NewFallbackKeyManager(km, nonRotatableKM{})
		},
		// Matches the BuildKeyManager order: cache(circuitbreaker(retry(base))).
		"fullstack": func(t *testing.T, km KeyManager) KeyManager {
			km = NewRetryingKeyManager(km, testRetryCfg())
			km = NewCircuitBreakerKeyManager(km, testCBCfg())
			c, err := NewCachingKeyManager(km, testCacheCfg())
			if err != nil {
				t.Fatal(err)
			}
			return c
		},
		// Matches cmd/server/main.go when a password is configured alongside a
		// KMS: fallback(cache(circuitbreaker(retry(base)))).
		"fullstack_with_fallback": func(t *testing.T, km KeyManager) KeyManager {
			km = NewRetryingKeyManager(km, testRetryCfg())
			km = NewCircuitBreakerKeyManager(km, testCBCfg())
			c, err := NewCachingKeyManager(km, testCacheCfg())
			if err != nil {
				t.Fatal(err)
			}
			return NewFallbackKeyManager(c, nonRotatableKM{})
		},
	}

	for name, wrap := range wraps {
		t.Run(name, func(t *testing.T) {
			km := wrap(t, newRotatableAESBase(t))
			t.Cleanup(func() { _ = km.Close(ctx) })

			rkm, ok := km.(RotatableKeyManager)
			if !ok {
				t.Fatalf("%s decorator dropped RotatableKeyManager", name)
			}
			plan, err := rkm.PrepareRotation(ctx, nil)
			if err != nil {
				t.Fatalf("PrepareRotation through %s: %v", name, err)
			}
			if plan.TargetVersion == plan.CurrentVersion {
				t.Fatalf("PrepareRotation returned no-op plan {%d,%d}", plan.CurrentVersion, plan.TargetVersion)
			}
			if err := rkm.PromoteActiveVersion(ctx, plan); err != nil {
				t.Fatalf("PromoteActiveVersion through %s: %v", name, err)
			}
			got, err := km.ActiveKeyVersion(ctx)
			if err != nil {
				t.Fatalf("ActiveKeyVersion through %s: %v", name, err)
			}
			if got != plan.TargetVersion {
				t.Fatalf("active version after promote through %s = %d, want %d", name, got, plan.TargetVersion)
			}
		})
	}
}

func TestDecorators_NonRotatableStaysNonRotatable(t *testing.T) {
	ctx := context.Background()
	base := nonRotatableKM{}

	cache, err := NewCachingKeyManager(base, testCacheCfg())
	if err != nil {
		t.Fatal(err)
	}
	wraps := map[string]KeyManager{
		"retry":          NewRetryingKeyManager(base, testRetryCfg()),
		"circuitbreaker": NewCircuitBreakerKeyManager(base, testCBCfg()),
		"cache":          cache,
		"fallback":       NewFallbackKeyManager(base, nonRotatableKM{}),
	}
	for name, km := range wraps {
		t.Cleanup(func() { _ = km.Close(ctx) })
		if _, ok := km.(RotatableKeyManager); ok {
			t.Errorf("%s decorator fabricated RotatableKeyManager for a non-rotatable base", name)
		}
	}
}
