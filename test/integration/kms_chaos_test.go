//go:build integration

package integration

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// mockChaosKM implements KeyManager with controllable failure modes for chaos testing.
type mockChaosKM struct {
	crypto.KeyManager
	provider        string
	shouldTimeout   atomic.Bool
	shouldFailAll   atomic.Bool
	unwrapCallCount atomic.Int32
	mu              sync.Mutex
	healthResult    error
}

func (m *mockChaosKM) Provider() string { return m.provider }

func (m *mockChaosKM) WrapKey(ctx context.Context, _ []byte, _ map[string]string) (*crypto.KeyEnvelope, error) {
	if m.shouldTimeout.Load() {
		// Simulate a timeout by blocking until ctx is cancelled
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if m.shouldFailAll.Load() {
		return nil, errors.New("kms: simulated outage")
	}
	return &crypto.KeyEnvelope{KeyID: "k1", Ciphertext: []byte("env")}, nil
}

func (m *mockChaosKM) UnwrapKey(ctx context.Context, _ *crypto.KeyEnvelope, _ map[string]string) ([]byte, error) {
	m.unwrapCallCount.Add(1)
	if m.shouldTimeout.Load() {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if m.shouldFailAll.Load() {
		return nil, errors.New("kms: simulated outage")
	}
	return []byte("32byte-dek-plaintext-for-chaos-tests"), nil
}

func (m *mockChaosKM) HealthCheck(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.healthResult
}

func (m *mockChaosKM) ActiveKeyVersion(_ context.Context) (int, error) { return 1, nil }

func (m *mockChaosKM) Close(_ context.Context) error { return nil }

// TestKMSChaos_TimeoutRetry verifies that a retrying key manager properly
// handles timeouts and retries.
func TestKMSChaos_TimeoutRetry(t *testing.T) {
	inner := &mockChaosKM{provider: "chaos"}
	inner.shouldTimeout.Store(true)

	cfg := crypto.RetryConfig{
		InitialInterval: time.Millisecond,
		MaxInterval:     5 * time.Millisecond,
		MaxElapsedTime:  100 * time.Millisecond,
		Multiplier:      2.0,
	}
	km := crypto.NewRetryingKeyManager(inner, cfg)

	// With timeouts simulated, the retry should exhaust and return an error
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := km.WrapKey(ctx, []byte("pt"), nil)
	require.Error(t, err, "expected error from exhausted retries due to timeouts")
}

// TestKMSChaos_CircuitBreakerTrips verifies that the circuit breaker trips
// open after a configured number of failures.
func TestKMSChaos_CircuitBreakerTrips(t *testing.T) {
	inner := &mockChaosKM{provider: "chaos"}
	inner.shouldFailAll.Store(true)

	cbCfg := crypto.CircuitBreakerConfig{
		ConsecutiveFailures: 3,
		OpenTimeout:         time.Hour, // stay open
		SuccessThreshold:    2,
	}
	cb := crypto.NewCircuitBreakerKeyManager(inner, cbCfg)

	// First 3 failures should trip the breaker
	for i := 0; i < 3; i++ {
		_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
		require.Error(t, err, "attempt %d should fail", i+1)
	}

	// 4th call should return ErrProviderUnavailable without calling inner
	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, crypto.ErrProviderUnavailable)
}

// TestKMSChaos_CircuitBreakerRecovery verifies automatic circuit-breaker
// recovery after a simulated KMS outage.
func TestKMSChaos_CircuitBreakerRecovery(t *testing.T) {
	inner := &mockChaosKM{provider: "chaos"}

	cbCfg := crypto.CircuitBreakerConfig{
		ConsecutiveFailures: 3,
		OpenTimeout:         50 * time.Millisecond,
		SuccessThreshold:    2,
	}
	cb := crypto.NewCircuitBreakerKeyManager(inner, cbCfg)

	// Simulate outage: fail first 3 calls
	inner.shouldFailAll.Store(true)
	for i := 0; i < 3; i++ {
		_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
		require.Error(t, err)
	}

	// Verify open state
	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, crypto.ErrProviderUnavailable)

	// Recover KMS
	inner.shouldFailAll.Store(false)

	// Wait for OpenTimeout to elapse
	time.Sleep(60 * time.Millisecond)

	// Half-Open probe should succeed
	env, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err, "probe should succeed after recovery")
	require.NotNil(t, env)

	// Second success should close the breaker
	env, err = cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err)
	require.NotNil(t, env)
}

// TestKMSChaos_DEKCacheUnderLoad verifies that the DEK cache maintains
// a high hit rate under concurrent load when accessing the same keys repeatedly.
func TestKMSChaos_DEKCacheUnderLoad(t *testing.T) {
	inner := &mockChaosKM{provider: "chaos"}

	cacheCfg := crypto.DEKCacheConfig{
		Enabled:    true,
		TTL:        time.Minute,
		MaxEntries: 100,
	}
	km, err := crypto.NewCachingKeyManager(inner, cacheCfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	const (
		numGoroutines = 50
		numOpsEach    = 10
	)

	// Each goroutine repeatedly accesses the same envelope to build cache hits
	env := &crypto.KeyEnvelope{Ciphertext: []byte("chaos-test-key")}

	var wg sync.WaitGroup
	for g := 0; g < numGoroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < numOpsEach; i++ {
				pt, err := km.UnwrapKey(context.Background(), env, nil)
				if err != nil {
					t.Errorf("UnwrapKey error: %v", err)
					return
				}
				if len(pt) == 0 {
					t.Error("UnwrapKey returned empty plaintext")
					return
				}
			}
		}()
	}
	wg.Wait()

	// With 50 goroutines × 10 ops each = 500 total calls, and the inner
	// adapter being called at most once (first miss), the hit rate should
	// be > 99%.
	calls := inner.unwrapCallCount.Load()
	totalOps := int32(numGoroutines * numOpsEach)
	hitRate := float64(totalOps-calls) / float64(totalOps) * 100
	t.Logf("Cache hit rate: %.1f%% (%d hits, %d misses)", hitRate, totalOps-calls, calls)
	require.Greater(t, hitRate, float64(90), "cache hit rate must exceed 90%% under concurrent load")
}
