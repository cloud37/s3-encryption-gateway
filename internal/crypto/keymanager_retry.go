package crypto

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
)

// RetryConfig holds exponential-backoff parameters for KMS retries.
type RetryConfig struct {
	// InitialInterval is the wait before the first retry. Default: 100 ms.
	InitialInterval time.Duration
	// MaxInterval caps the per-attempt delay. Default: 5 s.
	MaxInterval time.Duration
	// MaxElapsedTime caps the total retry window. Default: 30 s.
	// Set to 0 to retry indefinitely (ctx cancellation is the only stop).
	MaxElapsedTime time.Duration
	// Multiplier is the backoff multiplier between attempts. Default: 2.0.
	Multiplier float64
}

// DefaultRetryConfig returns a RetryConfig with production defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		InitialInterval: 100 * time.Millisecond,
		MaxInterval:     5 * time.Second,
		MaxElapsedTime:  30 * time.Second,
		Multiplier:      2.0,
	}
}

// RetryingKeyManager wraps a KeyManager and retries transient errors using
// exponential backoff with full jitter.
//
// Invariants:
//   - Thread-safe: delegates to the inner KeyManager; no internal state mutation.
//   - Only WrapKey and UnwrapKey are retried; HealthCheck is not.
//   - Permanent errors (ErrUnwrapFailed, ErrInvalidEnvelope, ErrKeyNotFound,
//     ErrProviderUnavailable) are never retried; the first error is returned
//     immediately.
//   - ctx cancellation terminates the retry loop immediately (backoff.Retry
//     checks ctx.Done on each iteration).
//   - MaxElapsedTime caps the total time across all attempts; 0 means no cap.
//   - If all retries are exhausted, the last error is returned wrapped with
//     fmt.Errorf("keymanager/retry: max elapsed time exceeded: %w", lastErr).
type RetryingKeyManager struct {
	inner   KeyManager
	cfg     RetryConfig
	metrics *metrics.Metrics
}

// Compile-time assertion that RetryingKeyManager implements KeyManager.
var _ KeyManager = (*RetryingKeyManager)(nil)

// NewRetryingKeyManager wraps inner with exponential-backoff retry on
// transient KMS errors. Only WrapKey and UnwrapKey are retried.
// Provide a nil metrics to disable metric recording.
func NewRetryingKeyManager(inner KeyManager, cfg RetryConfig, m *metrics.Metrics) KeyManager {
	return &RetryingKeyManager{
		inner:   inner,
		cfg:     cfg,
		metrics: m,
	}
}

// isPermanentKMSError returns true for errors that should never be retried.
func isPermanentKMSError(err error) bool {
	return errors.Is(err, ErrUnwrapFailed) ||
		errors.Is(err, ErrInvalidEnvelope) ||
		errors.Is(err, ErrKeyNotFound) ||
		errors.Is(err, ErrProviderUnavailable)
}

// newBackOff constructs a backoff.ExponentialBackOff from the config and wraps
// it with ctx cancellation support.
func (r *RetryingKeyManager) newBackOff(ctx context.Context) backoff.BackOff {
	b := &backoff.ExponentialBackOff{
		InitialInterval:     r.cfg.InitialInterval,
		MaxInterval:         r.cfg.MaxInterval,
		MaxElapsedTime:      r.cfg.MaxElapsedTime,
		Multiplier:          r.cfg.Multiplier,
		Clock:               backoff.SystemClock,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Stop:                backoff.Stop,
	}
	b.Reset()
	return backoff.WithContext(b, ctx)
}

// Provider returns the inner KeyManager's provider identifier.
func (r *RetryingKeyManager) Provider() string {
	return r.inner.Provider()
}

// WrapKey retries transient errors during key wrapping using exponential backoff.
func (r *RetryingKeyManager) WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error) {
	var result *KeyEnvelope
	op := func() error {
		env, err := r.inner.WrapKey(ctx, plaintext, metadata)
		if err != nil {
			if isPermanentKMSError(err) {
				return backoff.Permanent(err)
			}
			if r.metrics != nil {
				r.metrics.RecordKMSRetryAttempt(r.inner.Provider(), "wrap", "failure")
			}
			return err
		}
		result = env
		if r.metrics != nil {
			r.metrics.RecordKMSRetryAttempt(r.inner.Provider(), "wrap", "success")
		}
		return nil
	}
	bo := r.newBackOff(ctx)
	if err := backoff.Retry(op, bo); err != nil {
		return nil, fmt.Errorf("keymanager/retry: %w", err)
	}
	return result, nil
}

// UnwrapKey retries transient errors during key unwrapping using exponential backoff.
func (r *RetryingKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error) {
	var result []byte
	op := func() error {
		pt, err := r.inner.UnwrapKey(ctx, envelope, metadata)
		if err != nil {
			if isPermanentKMSError(err) {
				return backoff.Permanent(err)
			}
			if r.metrics != nil {
				r.metrics.RecordKMSRetryAttempt(r.inner.Provider(), "unwrap", "failure")
			}
			return err
		}
		result = pt
		if r.metrics != nil {
			r.metrics.RecordKMSRetryAttempt(r.inner.Provider(), "unwrap", "success")
		}
		return nil
	}
	bo := r.newBackOff(ctx)
	if err := backoff.Retry(op, bo); err != nil {
		return nil, fmt.Errorf("keymanager/retry: %w", err)
	}
	return result, nil
}

// HealthCheck delegates directly to the inner KeyManager without retry.
func (r *RetryingKeyManager) HealthCheck(ctx context.Context) error {
	return r.inner.HealthCheck(ctx)
}

// ActiveKeyVersion delegates directly to the inner KeyManager.
func (r *RetryingKeyManager) ActiveKeyVersion(ctx context.Context) (int, error) {
	return r.inner.ActiveKeyVersion(ctx)
}

// Close delegates to the inner KeyManager.
func (r *RetryingKeyManager) Close(ctx context.Context) error {
	return r.inner.Close(ctx)
}
