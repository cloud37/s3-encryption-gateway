package crypto

import "context"

// Rotatable forwarding for the KMS decorators and the password fallback.
//
// RetryingKeyManager, CircuitBreakerKeyManager, CachingKeyManager and
// fallbackKeyManager wrap a KeyManager but otherwise expose only the KeyManager
// method set. When the wrapped/primary adapter ALSO implements
// RotatableKeyManager (OpenBao, Cosmian, self-contained AES, memory), the
// constructor returns one of the rotatable* variants below, so a
// `km.(RotatableKeyManager)` assertion through the full wrapping chain still
// succeeds and reaches the base adapter.
//
// Without this, the admin rotation API (internal/api/admin_rotation.go) — which
// type-asserts the (possibly wrapped) KeyManager set on the engine — would
// report "rotation not supported" whenever any KMS decorator (retry, circuit
// breaker, DEK cache) or the password fallback (cmd/server/main.go, enabled
// when a password is configured alongside a KMS) is active, for every rotatable
// adapter.
//
// The variants are constructed ONLY when inner is rotatable, so the embedded
// `inner.(RotatableKeyManager)` assertions are always safe. This preserves the
// contract that `km.(RotatableKeyManager)` is true iff the underlying adapter
// is rotatable: wrapping a non-rotatable adapter still yields a plain
// KeyManager.
//
// Rotation is a control-plane operation (admin-triggered, infrequent), so it
// bypasses the retry/circuit-breaker/cache hot-path logic and delegates
// straight to the inner adapter. Note that PromoteActiveVersion does not
// invalidate the DEK cache: rotation does not re-wrap existing objects, so
// previously-cached unwrap results remain valid (old ciphertexts still decrypt
// to the same DEK), and new objects produce new ciphertexts that simply miss
// the cache.

type rotatableRetryingKeyManager struct{ *RetryingKeyManager }

func (m *rotatableRetryingKeyManager) PrepareRotation(ctx context.Context, target *int) (RotationPlan, error) {
	return m.inner.(RotatableKeyManager).PrepareRotation(ctx, target)
}

func (m *rotatableRetryingKeyManager) PromoteActiveVersion(ctx context.Context, plan RotationPlan) error {
	return m.inner.(RotatableKeyManager).PromoteActiveVersion(ctx, plan)
}

type rotatableCircuitBreakerKeyManager struct{ *CircuitBreakerKeyManager }

func (m *rotatableCircuitBreakerKeyManager) PrepareRotation(ctx context.Context, target *int) (RotationPlan, error) {
	return m.inner.(RotatableKeyManager).PrepareRotation(ctx, target)
}

func (m *rotatableCircuitBreakerKeyManager) PromoteActiveVersion(ctx context.Context, plan RotationPlan) error {
	return m.inner.(RotatableKeyManager).PromoteActiveVersion(ctx, plan)
}

type rotatableCachingKeyManager struct{ *CachingKeyManager }

func (m *rotatableCachingKeyManager) PrepareRotation(ctx context.Context, target *int) (RotationPlan, error) {
	return m.inner.(RotatableKeyManager).PrepareRotation(ctx, target)
}

func (m *rotatableCachingKeyManager) PromoteActiveVersion(ctx context.Context, plan RotationPlan) error {
	return m.inner.(RotatableKeyManager).PromoteActiveVersion(ctx, plan)
}

// rotatableFallbackKeyManager forwards rotation to the PRIMARY key manager.
// The password fallback is never rotatable; rotation always concerns the
// primary KMS, which is exactly what WrapKey/ActiveKeyVersion already delegate
// to.
type rotatableFallbackKeyManager struct{ *fallbackKeyManager }

func (m *rotatableFallbackKeyManager) PrepareRotation(ctx context.Context, target *int) (RotationPlan, error) {
	return m.primary.(RotatableKeyManager).PrepareRotation(ctx, target)
}

func (m *rotatableFallbackKeyManager) PromoteActiveVersion(ctx context.Context, plan RotationPlan) error {
	return m.primary.(RotatableKeyManager).PromoteActiveVersion(ctx, plan)
}

// Compile-time assertions.
var (
	_ RotatableKeyManager = (*rotatableRetryingKeyManager)(nil)
	_ RotatableKeyManager = (*rotatableCircuitBreakerKeyManager)(nil)
	_ RotatableKeyManager = (*rotatableCachingKeyManager)(nil)
	_ RotatableKeyManager = (*rotatableFallbackKeyManager)(nil)
)
