package api

import (
	"context"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

// TestBuildKeyManager_RotationSurvivesDecoratorStack is the integration
// regression test for the admin rotation API: handleRotate* type-asserts the
// KeyManager returned by BuildKeyManager to crypto.RotatableKeyManager. With
// the retry / circuit-breaker / DEK-cache decorators enabled, that assertion
// must still succeed for a rotatable provider (here: memory), otherwise the
// admin API reports "rotation not supported".
func TestBuildKeyManager_RotationSurvivesDecoratorStack(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "memory",
		Retry: config.KMSRetryConfig{
			Enabled:         true,
			InitialInterval: time.Millisecond,
			MaxInterval:     10 * time.Millisecond,
			MaxElapsedTime:  100 * time.Millisecond,
			Multiplier:      2.0,
		},
		CircuitBreaker: config.KMSCircuitBreakerConfig{
			Enabled:             true,
			ConsecutiveFailures: 5,
			OpenTimeout:         time.Second,
			SuccessThreshold:    2,
		},
		DEKCache: config.DEKCacheConfig{
			Enabled:    true,
			TTL:        time.Minute,
			MaxEntries: 100,
		},
	}

	km, err := BuildKeyManager(cfg, logrus.New())
	if err != nil {
		t.Fatalf("BuildKeyManager: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	if _, ok := km.(crypto.RotatableKeyManager); !ok {
		t.Fatalf("decorated KeyManager (%T) does not implement RotatableKeyManager — admin rotation API would report 'not supported'", km)
	}
}

// TestBuildKeyManager_NonRotatableProvider_NotRotatable ensures the assertion
// still correctly reports unsupported rotation for a non-rotatable provider
// even with decorators enabled (hsm stub does not implement rotation).
func TestBuildKeyManager_NonRotatableProvider_NotRotatable(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "hsm",
		Retry:    config.KMSRetryConfig{Enabled: true, InitialInterval: time.Millisecond, MaxInterval: 10 * time.Millisecond, MaxElapsedTime: 100 * time.Millisecond, Multiplier: 2.0},
	}
	km, err := BuildKeyManager(cfg, logrus.New())
	if err != nil {
		t.Skipf("hsm provider unavailable in this build: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	if _, ok := km.(crypto.RotatableKeyManager); ok {
		t.Error("non-rotatable provider must not be reported as rotatable through decorators")
	}
}
