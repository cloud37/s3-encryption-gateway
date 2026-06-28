package crypto

import (
	"context"
	"errors"
	"fmt"
)

// NewFallbackKeyManager wraps primary with a password-based fallback that is
// consulted only when primary.UnwrapKey returns ErrUnwrapFailed for an
// envelope whose Provider field equals "password".
//
// This supports backwards compatibility: objects encrypted before the
// self-contained or KMIP key manager was introduced stored their DEK wrapped
// by the passwordKeyManager (provider="password"). After upgrading to a KMS
// provider, ranged or streaming reads of those old MPU objects would fail
// because the new primary KM cannot unwrap a password-wrapped DEK.
//
// WrapKey always uses the primary KM so no new objects are created with the
// legacy password wrapping.
//
// Close closes both the primary and the fallback. If primary.Close returns an
// error the fallback is still closed and the primary error is returned.
func NewFallbackKeyManager(primary KeyManager, fallback KeyManager) KeyManager {
	f := &fallbackKeyManager{primary: primary, fallback: fallback}
	// Preserve rotatability of the primary KMS through the fallback wrapper (see
	// keymanager_decorator_rotation.go) so the admin rotation API still works for
	// KMS + password-fallback deployments.
	if _, ok := primary.(RotatableKeyManager); ok {
		return &rotatableFallbackKeyManager{f}
	}
	return f
}

type fallbackKeyManager struct {
	primary  KeyManager
	fallback KeyManager
}

// Provider returns the primary provider identifier.
func (f *fallbackKeyManager) Provider() string {
	return f.primary.Provider()
}

// WrapKey always delegates to the primary key manager so new objects are
// always wrapped with the current provider.
func (f *fallbackKeyManager) WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*KeyEnvelope, error) {
	return f.primary.WrapKey(ctx, plaintext, metadata)
}

// UnwrapKey attempts primary first. If primary returns ErrUnwrapFailed and the
// envelope's provider is "password", the fallback passwordKeyManager is tried.
func (f *fallbackKeyManager) UnwrapKey(ctx context.Context, envelope *KeyEnvelope, metadata map[string]string) ([]byte, error) {
	plaintext, err := f.primary.UnwrapKey(ctx, envelope, metadata)
	if err == nil {
		return plaintext, nil
	}

	// Only fall back when the envelope was produced by the password key manager
	// AND the primary rejected it structurally. Different primaries reject a
	// non-native (password) envelope with different sentinels: KMIP/Cosmian
	// tries to decrypt and returns ErrUnwrapFailed, while the OpenBao adapter
	// rejects it up-front with ErrInvalidEnvelope because the ciphertext lacks
	// the "vault:v" prefix. Both must route to the password fallback.
	if (errors.Is(err, ErrUnwrapFailed) || errors.Is(err, ErrInvalidEnvelope)) &&
		envelope != nil && envelope.Provider == passwordKMProvider {
		plaintext2, fallbackErr := f.fallback.UnwrapKey(ctx, envelope, metadata)
		if fallbackErr == nil {
			return plaintext2, nil
		}
		// Both failed — return a combined error that surfaces both failures.
		return nil, fmt.Errorf("%w: primary: %v; password-fallback: %v", ErrUnwrapFailed, err, fallbackErr)
	}

	return nil, err
}

// ActiveKeyVersion delegates to the primary key manager.
func (f *fallbackKeyManager) ActiveKeyVersion(ctx context.Context) (int, error) {
	return f.primary.ActiveKeyVersion(ctx)
}

// HealthCheck delegates to the primary key manager.
// The fallback is a local in-memory operation and needs no health check.
func (f *fallbackKeyManager) HealthCheck(ctx context.Context) error {
	return f.primary.HealthCheck(ctx)
}

// Close closes both key managers. The primary error takes precedence.
func (f *fallbackKeyManager) Close(ctx context.Context) error {
	primaryErr := f.primary.Close(ctx)
	fallbackErr := f.fallback.Close(ctx)
	if primaryErr != nil {
		return primaryErr
	}
	return fallbackErr
}
