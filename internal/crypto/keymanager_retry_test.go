package crypto

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
)

// mockRetryKM implements KeyManager with controllable failure for retry tests.
type mockRetryKM struct {
	KeyManager
	provider        string
	wrapAttempts    atomic.Int32
	unwrapAttempts  atomic.Int32
	healthAttempts  atomic.Int32
	failWrapsUntil int32  // fail the first N WrapKey calls
	failUnwrapsUntil int32 // fail the first N UnwrapKey calls
	wrapErr         error
	unwrapErr       error
	wrapResult      *KeyEnvelope
	unwrapResult    []byte
}

func (m *mockRetryKM) Provider() string { return m.provider }

func (m *mockRetryKM) WrapKey(_ context.Context, plaintext []byte, _ map[string]string) (*KeyEnvelope, error) {
	attempt := m.wrapAttempts.Add(1) - 1
	if attempt < m.failWrapsUntil {
		return nil, m.wrapErr
	}
	return m.wrapResult, nil
}

func (m *mockRetryKM) UnwrapKey(_ context.Context, _ *KeyEnvelope, _ map[string]string) ([]byte, error) {
	attempt := m.unwrapAttempts.Add(1) - 1
	if attempt < m.failUnwrapsUntil {
		return nil, m.unwrapErr
	}
	return m.unwrapResult, nil
}

func (m *mockRetryKM) HealthCheck(_ context.Context) error {
	m.healthAttempts.Add(1)
	return nil
}

func (m *mockRetryKM) Close(_ context.Context) error { return nil }

func TestRetryingKeyManager_WrapUnwrap_NoError(t *testing.T) {
	inner := &mockRetryKM{
		provider:     "test",
		wrapResult:   &KeyEnvelope{KeyID: "k1", Ciphertext: []byte("env")},
		unwrapResult: []byte("plaintext"),
	}
	cfg := DefaultRetryConfig()
	cfg.InitialInterval = time.Millisecond
	cfg.MaxElapsedTime = time.Second

	km := NewRetryingKeyManager(inner, cfg, nil)

	// WrapKey — should succeed on first attempt
	env, err := km.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err)
	require.Equal(t, "k1", env.KeyID)
	require.Equal(t, int32(1), inner.wrapAttempts.Load())

	// UnwrapKey — should succeed on first attempt
	pt, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, "plaintext", string(pt))
	require.Equal(t, int32(1), inner.unwrapAttempts.Load())
}

func TestRetryingKeyManager_WrapKey_TransientErrorRetries(t *testing.T) {
	inner := &mockRetryKM{
		provider:       "test",
		failWrapsUntil: 2, // fail first 2 calls, succeed on 3rd
		wrapErr:        errors.New("transient: connection reset"),
		wrapResult:     &KeyEnvelope{KeyID: "k1", Ciphertext: []byte("env")},
	}
	cfg := DefaultRetryConfig()
	cfg.InitialInterval = time.Millisecond
	cfg.MaxInterval = 10 * time.Millisecond
	cfg.MaxElapsedTime = time.Second

	km := NewRetryingKeyManager(inner, cfg, nil)

	env, err := km.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err)
	require.Equal(t, "k1", env.KeyID)
	require.Equal(t, int32(3), inner.wrapAttempts.Load(), "expected 3 attempts (2 failures + 1 success)")
}

func TestRetryingKeyManager_UnwrapKey_PermanentError_NotRetried(t *testing.T) {
	inner := &mockRetryKM{
		provider:        "test",
		failUnwrapsUntil: 100, // always fails
		unwrapErr:       ErrUnwrapFailed,
	}
	cfg := DefaultRetryConfig()
	cfg.InitialInterval = time.Millisecond
	cfg.MaxInterval = 10 * time.Millisecond
	cfg.MaxElapsedTime = time.Second

	km := NewRetryingKeyManager(inner, cfg, nil)

	_, err := km.UnwrapKey(context.Background(), &KeyEnvelope{Ciphertext: []byte("ct")}, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrUnwrapFailed)
	// Should have been called exactly once (no retry for permanent errors)
	require.Equal(t, int32(1), inner.unwrapAttempts.Load())
}

func TestRetryingKeyManager_WrapKey_ContextCancelled_StopsRetry(t *testing.T) {
	inner := &mockRetryKM{
		provider:       "test",
		failWrapsUntil: 100, // always fails
		wrapErr:        errors.New("transient: timeout"),
	}
	cfg := DefaultRetryConfig()
	cfg.InitialInterval = 10 * time.Millisecond
	cfg.MaxInterval = 10 * time.Millisecond
	cfg.MaxElapsedTime = 0 // retry indefinitely

	km := NewRetryingKeyManager(inner, cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := km.WrapKey(ctx, []byte("pt"), nil)
	require.Error(t, err)
	// Should stop early due to ctx cancellation, not exhaust max elapsed time
	require.True(t, errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled),
		"expected context error, got: %v", err)
}

func TestRetryingKeyManager_WrapKey_ExhaustedRetries(t *testing.T) {
	inner := &mockRetryKM{
		provider:       "test",
		failWrapsUntil: 100, // always fails
		wrapErr:        errors.New("transient: timeout"),
	}
	cfg := DefaultRetryConfig()
	cfg.InitialInterval = time.Millisecond
	cfg.MaxInterval = 2 * time.Millisecond
	cfg.MaxElapsedTime = 5 * time.Millisecond // very short window — ~3-5 attempts before exhausted

	km := NewRetryingKeyManager(inner, cfg, nil)

	_, err := km.WrapKey(context.Background(), []byte("pt"), nil)
	require.Error(t, err, "expected error from exhausted retries")
	// With very short MaxElapsedTime, the inner should have been called at
	// least once but should NOT have succeeded (failWrapsUntil = 100).
	attempts := inner.wrapAttempts.Load()
	require.GreaterOrEqual(t, attempts, int32(1), "expected at least 1 attempt")
	require.Less(t, attempts, int32(100), "should not have reached success threshold")
}

func TestRetryingKeyManager_HealthCheck_NoRetry(t *testing.T) {
	inner := &mockRetryKM{
		provider: "test",
	}
	cfg := DefaultRetryConfig()
	km := NewRetryingKeyManager(inner, cfg, nil)

	err := km.HealthCheck(context.Background())
	require.NoError(t, err)
	// HealthCheck should be called exactly once with no retry logic
	require.Equal(t, int32(1), inner.healthAttempts.Load())
}

func TestRetryingKeyManager_Provider_Delegates(t *testing.T) {
	inner := &mockRetryKM{provider: "cosmian-kmip"}
	km := NewRetryingKeyManager(inner, DefaultRetryConfig(), nil)
	require.Equal(t, "cosmian-kmip", km.Provider())
}

func TestRetryingKeyManager_AllPermanentErrors_NotRetried(t *testing.T) {
	permanentErrs := []error{
		ErrUnwrapFailed,
		ErrInvalidEnvelope,
		ErrKeyNotFound,
		ErrProviderUnavailable,
	}

	for _, permErr := range permanentErrs {
		t.Run(permErr.Error(), func(t *testing.T) {
			inner := &mockRetryKM{
				provider:        "test",
				failUnwrapsUntil: 100,
				unwrapErr:       permErr,
			}
			cfg := DefaultRetryConfig()
			cfg.InitialInterval = time.Millisecond
			cfg.MaxElapsedTime = time.Second

			km := NewRetryingKeyManager(inner, cfg, nil)
			_, err := km.UnwrapKey(context.Background(), &KeyEnvelope{Ciphertext: []byte("ct")}, nil)
			require.Error(t, err)
			require.ErrorIs(t, err, permErr)
			// Must be called exactly once
			require.Equal(t, int32(1), inner.unwrapAttempts.Load())
		})
	}
}

// TestRetryingKeyManager_MetricsRecords verifies that retry metrics are recorded.
func TestRetryingKeyManager_MetricsRecords(t *testing.T) {
	m := testMetrics(t)
	inner := &mockRetryKM{
		provider:       "test",
		failWrapsUntil: 2,
		wrapErr:        errors.New("transient error"),
		wrapResult:     &KeyEnvelope{KeyID: "k1"},
	}
	cfg := DefaultRetryConfig()
	cfg.InitialInterval = time.Millisecond
	cfg.MaxInterval = 5 * time.Millisecond
	cfg.MaxElapsedTime = time.Second

	km := NewRetryingKeyManager(inner, cfg, m)
	_, err := km.WrapKey(context.Background(), []byte("pt"), nil)
	require.NoError(t, err)

	// We just verify it didn't panic; metric value checking is in metrics tests
}

// testMetrics creates a Metrics with a fresh registry for testing.
func testMetrics(t *testing.T) *metrics.Metrics {
	t.Helper()
	return metrics.NewMetricsWithRegistry(prometheus.NewRegistry())
}
