package crypto

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockCbKM implements KeyManager with controllable failure for circuit breaker tests.
type mockCbKM struct {
	provider       string
	wrapCount      atomic.Int32
	unwrapCount    atomic.Int32
	healthCount    atomic.Int32
	failWrapsUntil int32 // fail the first N WrapKey calls
	unwrapErr      error
	wrapErr        error
}

func (m *mockCbKM) Provider() string { return m.provider }

func (m *mockCbKM) WrapKey(_ context.Context, _ []byte, _ map[string]string) (*KeyEnvelope, error) {
	call := m.wrapCount.Add(1) - 1
	if call < m.failWrapsUntil {
		return nil, m.wrapErr
	}
	return &KeyEnvelope{KeyID: "k1", Ciphertext: []byte("env")}, nil
}

func (m *mockCbKM) UnwrapKey(_ context.Context, _ *KeyEnvelope, _ map[string]string) ([]byte, error) {
	call := m.unwrapCount.Add(1) - 1
	if call < m.failWrapsUntil {
		return nil, m.wrapErr
	}
	return []byte("plaintext"), nil
}

func (m *mockCbKM) HealthCheck(_ context.Context) error {
	m.healthCount.Add(1)
	return nil
}

func (m *mockCbKM) ActiveKeyVersion(_ context.Context) (int, error) {
	return 1, nil
}

func (m *mockCbKM) Close(_ context.Context) error { return nil }

func TestCircuitBreaker_InitialState_Closed(t *testing.T) {
	inner := &mockCbKM{provider: "test"}
	cb := NewCircuitBreakerKeyManager(inner, DefaultCircuitBreakerConfig())

	// Initial state should be closed; first request should go through
	env, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err)
	require.NotNil(t, env)
}

func TestCircuitBreaker_ConsecutiveFailures_TripsOpen(t *testing.T) {
	inner := &mockCbKM{
		provider:       "test",
		failWrapsUntil: 100,
		wrapErr:        errors.New("kms error"),
	}
	cfg := DefaultCircuitBreakerConfig()
	cfg.ConsecutiveFailures = 3

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	// First 3 failures should trip the breaker
	for i := 0; i < 3; i++ {
		_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
		require.Error(t, err, "attempt %d should fail", i+1)
	}

	// 4th call should return ErrProviderUnavailable without calling inner
	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestCircuitBreaker_Open_FailsFastWithoutCallingInner(t *testing.T) {
	inner := &mockCbKM{
		provider:       "test",
		failWrapsUntil: 100,
		wrapErr:        errors.New("kms error"),
	}
	cfg := DefaultCircuitBreakerConfig()
	cfg.ConsecutiveFailures = 2

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	// Trip the breaker
	_, _ = cb.WrapKey(context.Background(), []byte("pt"), nil)
	_, _ = cb.WrapKey(context.Background(), []byte("pt"), nil)

	// Reset wrap counter
	inner.wrapCount.Store(0)

	// Now open — should fail fast without calling inner
	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable)
	require.Equal(t, int32(0), inner.wrapCount.Load(), "inner should not be called when circuit is open")
}

func TestCircuitBreaker_HalfOpen_SuccessCloses(t *testing.T) {
	inner := &mockCbKM{
		provider:       "test",
		failWrapsUntil: 3, // fail first 3 calls, succeed after
		wrapErr:        errors.New("kms error"),
	}
	cfg := DefaultCircuitBreakerConfig()
	cfg.ConsecutiveFailures = 3
	cfg.OpenTimeout = 10 * time.Millisecond
	cfg.SuccessThreshold = 2

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	// Trip the breaker
	for i := 0; i < 3; i++ {
		_, _ = cb.WrapKey(context.Background(), []byte("pt"), nil)
	}

	// Should be Open now
	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable)

	// Wait for OpenTimeout to pass
	time.Sleep(15 * time.Millisecond)

	// First probe (Half-Open transition occurs here)
	env, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err, "probe should succeed")
	require.NotNil(t, env)

	// Second success should close the breaker
	env, err = cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err)
	require.NotNil(t, env)
}

func TestCircuitBreaker_HalfOpen_FailureReopens(t *testing.T) {
	inner := &mockCbKM{
		provider:       "test",
		failWrapsUntil: 4, // fail first 4 calls
		wrapErr:        errors.New("kms error"),
	}
	cfg := DefaultCircuitBreakerConfig()
	cfg.ConsecutiveFailures = 3
	cfg.OpenTimeout = 10 * time.Millisecond
	cfg.SuccessThreshold = 2

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	// Trip the breaker (3 failures)
	for i := 0; i < 3; i++ {
		_, _ = cb.WrapKey(context.Background(), []byte("pt"), nil)
	}

	// Wait for OpenTimeout
	time.Sleep(15 * time.Millisecond)

	// Half-Open probe — still fails (failUntil=4, this is call 4 or idx 3)
	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.Error(t, err, "probe should fail")
	// Should NOT be ErrProviderUnavailable (that's only for fast-fail)
	// Actually, after failure in half-open, it re-opens
	// but the error IS from the inner KMS, not from the circuit breaker

	// The next call should be Open again
	_, err = cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestCircuitBreaker_SuccessResetsFailureCounter(t *testing.T) {
	inner := &mockCbKM{
		provider:       "test",
		failWrapsUntil: 100,
		wrapErr:        errors.New("kms error"),
	}
	cfg := DefaultCircuitBreakerConfig()
	cfg.ConsecutiveFailures = 5

	cbTyped := NewCircuitBreakerKeyManager(inner, cfg).(*CircuitBreakerKeyManager)

	// 2 failures (counter = 2)
	_, _ = cbTyped.WrapKey(context.Background(), []byte("pt"), nil)
	_, _ = cbTyped.WrapKey(context.Background(), []byte("pt"), nil)

	// They both fail — check state is still closed
	cbTyped.mu.Lock()
	require.Equal(t, cbStateClosed, cbTyped.state, "should still be closed after 2 failures (threshold=5)")
	require.Equal(t, 2, cbTyped.failures)
	cbTyped.mu.Unlock()

	// Reset the inner mock so it starts succeeding
	inner.failWrapsUntil = 0

	// Success should reset failure counter
	env, err := cbTyped.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err)
	require.NotNil(t, env)

	// Verify counter was reset
	cbTyped.mu.Lock()
	require.Equal(t, 0, cbTyped.failures, "failures should be reset after success")
	cbTyped.mu.Unlock()
}

func TestCircuitBreaker_HealthCheck_AlwaysDelegates(t *testing.T) {
	inner := &mockCbKM{
		provider:       "test",
		failWrapsUntil: 100,
		wrapErr:        errors.New("kms error"),
	}
	cfg := DefaultCircuitBreakerConfig()
	cfg.ConsecutiveFailures = 2

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	// Trip the breaker
	_, _ = cb.WrapKey(context.Background(), []byte("pt"), nil)
	_, _ = cb.WrapKey(context.Background(), []byte("pt"), nil)

	// Even though circuit is open, HealthCheck should still work
	err := cb.HealthCheck(context.Background())
	require.NoError(t, err)
	require.Equal(t, int32(1), inner.healthCount.Load(), "HealthCheck should always delegate")
}

func TestCircuitBreaker_ActiveKeyVersion_AlwaysDelegates(t *testing.T) {
	inner := &mockCbKM{
		provider:       "test",
		failWrapsUntil: 100,
		wrapErr:        errors.New("kms error"),
	}
	cfg := DefaultCircuitBreakerConfig()
	cfg.ConsecutiveFailures = 2

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	// Trip the breaker
	_, _ = cb.WrapKey(context.Background(), []byte("pt"), nil)
	_, _ = cb.WrapKey(context.Background(), []byte("pt"), nil)

	// ActiveKeyVersion should still work even when circuit is open
	version, err := cb.ActiveKeyVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, version)
}

func TestCircuitBreaker_Close_SetsOpenState(t *testing.T) {
	inner := &mockCbKM{provider: "test"}
	cfg := DefaultCircuitBreakerConfig()
	cfg.OpenTimeout = time.Hour // long timeout so it stays open

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	require.NoError(t, cb.Close(context.Background()))

	// After Close, all operations should return ErrProviderUnavailable
	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestCircuitBreaker_Close_Idempotent(t *testing.T) {
	inner := &mockCbKM{provider: "test"}
	cfg := DefaultCircuitBreakerConfig()

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	// First Close should succeed
	require.NoError(t, cb.Close(context.Background()))

	// Second Close should also succeed (idempotent)
	require.NoError(t, cb.Close(context.Background()))

	// Operations still fail with ErrProviderUnavailable
	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestCircuitBreaker_Close_NoRecoveryAfterClose(t *testing.T) {
	inner := &mockCbKM{
		provider:       "test",
		failWrapsUntil: 100,
		wrapErr:        errors.New("kms error"),
	}
	cfg := DefaultCircuitBreakerConfig()
	cfg.ConsecutiveFailures = 2
	cfg.OpenTimeout = 10 * time.Millisecond // short timeout

	cb := NewCircuitBreakerKeyManager(inner, cfg)

	// Close the breaker permanently
	require.NoError(t, cb.Close(context.Background()))

	// Even after OpenTimeout elapses, it should NOT transition to Half-Open
	time.Sleep(20 * time.Millisecond)

	_, err := cb.WrapKey(context.Background(), []byte("pt"), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable, "breaker must not recover after Close")
}
