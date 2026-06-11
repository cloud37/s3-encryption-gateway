package crypto

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v5"
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
	inner KeyManager
	cfg   RetryConfig
}

// Compile-time assertion that RetryingKeyManager implements KeyManager.
var _ KeyManager = (*RetryingKeyManager)(nil)

// NewRetryingKeyManager wraps inner with exponential-backoff retry on
// transient KMS errors. Only WrapKey and UnwrapKey are retried.
// KMS retry metrics are recorded via the callback registered by
// SetKMSRetryAttemptObserver.
func NewRetryingKeyManager(inner KeyManager, cfg RetryConfig) KeyManager {
	return &RetryingKeyManager{
		inner: inner,
		cfg:   cfg,
	}
}

// isPermanentKMSError returns true for errors that should never be retried.
func isPermanentKMSError(err error) bool {
	return errors.Is(err, ErrUnwrapFailed) ||
		errors.Is(err, ErrInvalidEnvelope) ||
		errors.Is(err, ErrKeyNotFound) ||
		errors.Is(err, ErrProviderUnavailable)
}

// newBackOff constructs a backoff.ExponentialBackOff from the config.
func (r *RetryingKeyManager) newBackOff() backoff.BackOff {
	b := &backoff.ExponentialBackOff{
		InitialInterval:     r.cfg.InitialInterval,
		MaxInterval:         r.cfg.MaxInterval,
		Multiplier:          r.cfg.Multiplier,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
	}
	b.Reset()
	return b
}

// Provider returns the inner KeyManager's provider identifier.
func (r *RetryingKeyManager) Provider() string {
	return r.inner.Provider()
}

// WrapKey retries transient errors during key wrapping using exponential backoff.
func (r *RetryingKeyManager) WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error) {
	var result *KeyEnvelope
	op := func() (*KeyEnvelope, error) {
		env, err := r.inner.WrapKey(ctx, plaintext, metadata)
		if err != nil {
			if isPermanentKMSError(err) {
				return nil, backoff.Permanent(err)
			}
			if fn := getRecordKMSRetryAttemptFn(); fn != nil {
				fn(r.inner.Provider(), "wrap", "failure")
			}
			return nil, err
		}
		if fn := getRecordKMSRetryAttemptFn(); fn != nil {
			fn(r.inner.Provider(), "wrap", "success")
		}
		return env, nil
	}
	bo := r.newBackOff()
	opts := []backoff.RetryOption{backoff.WithBackOff(bo)}
	if r.cfg.MaxElapsedTime > 0 {
		opts = append(opts, backoff.WithMaxElapsedTime(r.cfg.MaxElapsedTime))
	}
	var err error
	result, err = backoff.Retry(ctx, op, opts...)
	if err != nil {
		return nil, fmt.Errorf("keymanager/retry: %w", err)
	}
	return result, nil
}

// UnwrapKey retries transient errors during key unwrapping using exponential backoff.
func (r *RetryingKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error) {
	var result []byte
	op := func() ([]byte, error) {
		pt, err := r.inner.UnwrapKey(ctx, envelope, metadata)
		if err != nil {
			if isPermanentKMSError(err) {
				return nil, backoff.Permanent(err)
			}
			if fn := getRecordKMSRetryAttemptFn(); fn != nil {
				fn(r.inner.Provider(), "unwrap", "failure")
			}
			return nil, err
		}
		if fn := getRecordKMSRetryAttemptFn(); fn != nil {
			fn(r.inner.Provider(), "unwrap", "success")
		}
		return pt, nil
	}
	bo := r.newBackOff()
	opts := []backoff.RetryOption{backoff.WithBackOff(bo)}
	if r.cfg.MaxElapsedTime > 0 {
		opts = append(opts, backoff.WithMaxElapsedTime(r.cfg.MaxElapsedTime))
	}
	var err error
	result, err = backoff.Retry(ctx, op, opts...)
	if err != nil {
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
