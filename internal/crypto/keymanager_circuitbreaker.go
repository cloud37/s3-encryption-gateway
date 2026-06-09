package crypto

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// cbState represents the circuit-breaker state.
type cbState int

const (
	cbStateClosed   cbState = 0 // normal operation
	cbStateOpen     cbState = 1 // failing fast
	cbStateHalfOpen cbState = 2 // probe mode
)

// CircuitBreakerConfig holds circuit-breaker configuration.
type CircuitBreakerConfig struct {
	// ConsecutiveFailures trips the breaker after N consecutive failures.
	// Default: 5.
	ConsecutiveFailures int
	// OpenTimeout is how long the breaker stays open before probing.
	// Default: 30 s.
	OpenTimeout time.Duration
	// SuccessThreshold closes the breaker after N consecutive probe successes.
	// Default: 2.
	SuccessThreshold int
}

// DefaultCircuitBreakerConfig returns a CircuitBreakerConfig with production defaults.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		ConsecutiveFailures: 5,
		OpenTimeout:         30 * time.Second,
		SuccessThreshold:    2,
	}
}

// CircuitBreakerKeyManager wraps a KeyManager with a three-state circuit breaker.
//
// Invariants:
//   - Thread-safe: all state transitions are guarded by a sync.Mutex.
//   - States: Closed (normal), Open (failing fast), Half-Open (probe).
//   - WrapKey and UnwrapKey are circuit-guarded; HealthCheck and ActiveKeyVersion
//     bypass the circuit so the health-check goroutine always reaches the KMS.
//   - When Open, WrapKey/UnwrapKey return ErrProviderUnavailable immediately,
//     without calling the inner KeyManager.
//   - After OpenTimeout elapses, one probe attempt is allowed (Half-Open).
//     On success → Closed; on failure → Open with reset timer.
//   - Failure threshold: ConsecutiveFailures consecutive errors trip the breaker.
//   - SuccessThreshold: consecutive successes in Half-Open to close the breaker.
//   - After Close, all operations permanently return ErrProviderUnavailable
//     (breaker cannot recover to Half-Open after Close). Idempotent.
type CircuitBreakerKeyManager struct {
	inner KeyManager
	cfg   CircuitBreakerConfig

	mu        sync.Mutex
	state     cbState
	failures  int
	successes int
	openedAt  time.Time
	closed    bool // permanent shutdown; overrides all state transitions
}

// Compile-time assertion that CircuitBreakerKeyManager implements KeyManager.
var _ KeyManager = (*CircuitBreakerKeyManager)(nil)

// NewCircuitBreakerKeyManager wraps inner with a circuit breaker.
// Circuit-breaker state metrics are recorded via the callback registered
// by SetKMSCircuitBreakerStateObserver.
func NewCircuitBreakerKeyManager(inner KeyManager, cfg CircuitBreakerConfig) KeyManager {
	return &CircuitBreakerKeyManager{
		inner: inner,
		cfg:   cfg,
		state: cbStateClosed,
	}
}

// Provider returns the inner KeyManager's provider identifier.
func (cb *CircuitBreakerKeyManager) Provider() string {
	return cb.inner.Provider()
}

// WrapKey attempts to wrap a DEK, subject to circuit-breaker state.
func (cb *CircuitBreakerKeyManager) WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error) {
	if err := cb.allowRequest(); err != nil {
		return nil, err
	}
	env, err := cb.inner.WrapKey(ctx, plaintext, metadata)
	cb.recordResult(err)
	return env, err
}

// UnwrapKey attempts to unwrap a DEK, subject to circuit-breaker state.
func (cb *CircuitBreakerKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error) {
	if err := cb.allowRequest(); err != nil {
		return nil, err
	}
	pt, err := cb.inner.UnwrapKey(ctx, envelope, metadata)
	cb.recordResult(err)
	return pt, err
}

// HealthCheck bypasses the circuit breaker and always delegates to the inner KeyManager.
func (cb *CircuitBreakerKeyManager) HealthCheck(ctx context.Context) error {
	return cb.inner.HealthCheck(ctx)
}

// ActiveKeyVersion bypasses the circuit breaker.
func (cb *CircuitBreakerKeyManager) ActiveKeyVersion(ctx context.Context) (int, error) {
	return cb.inner.ActiveKeyVersion(ctx)
}

// Close delegates to the inner KeyManager and permanently closes the circuit.
// Subsequent WrapKey/UnwrapKey calls return ErrProviderUnavailable regardless
// of state transitions. Idempotent.
func (cb *CircuitBreakerKeyManager) Close(ctx context.Context) error {
	cb.mu.Lock()
	if cb.closed {
		cb.mu.Unlock()
		return nil
	}
	cb.closed = true
	cb.state = cbStateOpen
	cb.openedAt = time.Now()
	cb.mu.Unlock()
	cb.updateMetrics()
	return cb.inner.Close(ctx)
}

// allowRequest checks whether the circuit breaker allows a request to proceed.
func (cb *CircuitBreakerKeyManager) allowRequest() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.closed {
		return fmt.Errorf("keymanager/circuitbreaker: %w", ErrProviderUnavailable)
	}

	switch cb.state {
	case cbStateClosed:
		return nil
	case cbStateOpen:
		if time.Since(cb.openedAt) >= cb.cfg.OpenTimeout {
			cb.state = cbStateHalfOpen
			cb.successes = 0
			cb.updateMetricsLocked()
			return nil
		}
		return fmt.Errorf("keymanager/circuitbreaker: %w", ErrProviderUnavailable)
	case cbStateHalfOpen:
		return nil
	default:
		return fmt.Errorf("keymanager/circuitbreaker: unknown state: %d", cb.state)
	}
}

// recordResult records the outcome of a KMS operation and updates state.
func (cb *CircuitBreakerKeyManager) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err == nil {
		switch cb.state {
		case cbStateClosed:
			cb.failures = 0
		case cbStateHalfOpen:
			cb.successes++
			if cb.successes >= cb.cfg.SuccessThreshold {
				cb.state = cbStateClosed
				cb.failures = 0
				cb.successes = 0
			}
		}
	} else {
		switch cb.state {
		case cbStateClosed:
			cb.failures++
			if cb.failures >= cb.cfg.ConsecutiveFailures {
				cb.state = cbStateOpen
				cb.openedAt = time.Now()
				cb.failures = 0
			}
		case cbStateHalfOpen:
			cb.state = cbStateOpen
			cb.openedAt = time.Now()
			cb.successes = 0
		}
	}
	cb.updateMetricsLocked()
}

// updateMetrics sends the current state to Prometheus.
func (cb *CircuitBreakerKeyManager) updateMetrics() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.updateMetricsLocked()
}

// updateMetricsLocked must be called with cb.mu held.
func (cb *CircuitBreakerKeyManager) updateMetricsLocked() {
	if fn := getSetKMSCircuitBreakerStateFn(); fn != nil {
		fn(cb.inner.Provider(), int(cb.state))
	}
}
