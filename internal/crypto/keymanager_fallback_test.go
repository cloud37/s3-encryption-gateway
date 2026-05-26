package crypto_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

const fallbackTestPassword = "fallback-test-password-long-enough"

func makeFallbackKMs(t *testing.T) (primary crypto.KeyManager, password crypto.KeyManager) {
	t.Helper()
	// Use an in-memory (AES-KW) manager as the primary.
	primary, err := crypto.NewPasswordKeyManager([]byte("primary-test-password-long-enough"), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)
	password, err = crypto.NewPasswordKeyManager([]byte(fallbackTestPassword), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)
	return primary, password
}

// TestFallbackKeyManager_WrapUnwrap_Primary verifies that a DEK wrapped by the
// primary is correctly unwrapped through the FallbackKeyManager.
func TestFallbackKeyManager_WrapUnwrap_Primary(t *testing.T) {
	primary, fallback := makeFallbackKMs(t)
	fm := crypto.NewFallbackKeyManager(primary, fallback)

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	env, err := fm.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)
	require.NotNil(t, env)
	assert.Equal(t, "password", env.Provider) // primary is a passwordKM here

	got, err := fm.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

// TestFallbackKeyManager_UnwrapFallback_OldPasswordEnvelope verifies that when
// the primary KM cannot unwrap a "password"-provider envelope (ErrUnwrapFailed),
// the fallback password KM is used successfully.
func TestFallbackKeyManager_UnwrapFallback_OldPasswordEnvelope(t *testing.T) {
	// Simulate the real scenario: primary is a self-contained AES KM that
	// cannot unwrap a DEK wrapped by the old password KM.
	// We use two separate password KMs with different passwords to reproduce
	// the "wrong key" scenario.
	legacyPKM, err := crypto.NewPasswordKeyManager([]byte(fallbackTestPassword), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)
	newPrimary, err := crypto.NewPasswordKeyManager([]byte("new-primary-password-long-enough"), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)

	// Wrap the DEK with the *legacy* password KM (simulates old object).
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i + 1)
	}
	env, err := legacyPKM.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)
	assert.Equal(t, "password", env.Provider)

	// Build FallbackKeyManager: newPrimary cannot decrypt it, legacyPKM can.
	fm := crypto.NewFallbackKeyManager(newPrimary, legacyPKM)

	got, err := fm.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err, "FallbackKeyManager must succeed via the password fallback")
	assert.Equal(t, dek, got)
}

// TestFallbackKeyManager_NoFallbackForNonPasswordProvider verifies that when
// the primary returns ErrUnwrapFailed for an envelope with a non-"password"
// provider, the fallback is NOT tried and the primary error is returned as-is.
func TestFallbackKeyManager_NoFallbackForNonPasswordProvider(t *testing.T) {
	// Use two KMs with the same password so primary fails with ErrUnwrapFailed
	// (wrong ciphertext), not a provider-mismatch, for a "password" envelope
	// that was wrapped by a third KM.  Then use a non-"password" provider field.
	primary, err := crypto.NewPasswordKeyManager([]byte("primary-test-password-long-enough"), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)
	fallback, err := crypto.NewPasswordKeyManager([]byte(fallbackTestPassword), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)
	fm := crypto.NewFallbackKeyManager(primary, fallback)

	// Build a garbage envelope with provider != "password".
	// The primary (passwordKM) will return a provider-mismatch error (not
	// ErrUnwrapFailed), so the FallbackKeyManager must NOT invoke the fallback.
	env := &crypto.KeyEnvelope{
		Provider:   "self_contained",
		KeyVersion: 1,
		Ciphertext: make([]byte, 60), // valid length, but wrong provider
	}

	_, err = fm.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
	// fallback must NOT have been tried.
	assert.NotContains(t, err.Error(), "password-fallback", "fallback must not be invoked for non-password provider")
}

// TestFallbackKeyManager_BothFail verifies combined error message when both
// primary and fallback fail for a "password" provider envelope.
func TestFallbackKeyManager_BothFail(t *testing.T) {
	// Both KMs use different passwords — neither can unwrap the other's envelope.
	km1, err := crypto.NewPasswordKeyManager([]byte("password-one-long-enough-here"), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)
	km2, err := crypto.NewPasswordKeyManager([]byte("password-two-long-enough-here"), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)
	km3, err := crypto.NewPasswordKeyManager([]byte("password-thr-long-enough-here"), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)

	// Wrap with km3 — neither km1 nor km2 can unwrap it.
	dek := make([]byte, 32)
	env, err := km3.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	fm := crypto.NewFallbackKeyManager(km1, km2)
	_, err = fm.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, crypto.ErrUnwrapFailed))
	assert.Contains(t, err.Error(), "password-fallback")
}

// TestFallbackKeyManager_WrapAlwaysPrimary verifies that WrapKey always
// delegates to the primary (not the fallback), so new objects are never
// written with the legacy password wrapping.
func TestFallbackKeyManager_WrapAlwaysPrimary(t *testing.T) {
	primary, err := crypto.NewPasswordKeyManager([]byte("primary-test-password-long-enough"), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)
	fallback, err := crypto.NewPasswordKeyManager([]byte(fallbackTestPassword), crypto.DefaultPBKDF2Iterations)
	require.NoError(t, err)

	fm := crypto.NewFallbackKeyManager(primary, fallback)

	dek := make([]byte, 32)
	env, err := fm.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	// Must be unwrappable by primary directly (not via fallback).
	got, err := primary.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)

	// Must NOT be unwrappable by the fallback KM (different password).
	_, err = fallback.UnwrapKey(context.Background(), env, nil)
	assert.Error(t, err, "fallback KM with different password must not unwrap primary-wrapped DEK")
}

// TestFallbackKeyManager_Provider returns the primary provider string.
func TestFallbackKeyManager_Provider(t *testing.T) {
	primary, fallback := makeFallbackKMs(t)
	fm := crypto.NewFallbackKeyManager(primary, fallback)
	assert.Equal(t, primary.Provider(), fm.Provider())
}

// TestFallbackKeyManager_Close closes both managers.
func TestFallbackKeyManager_Close(t *testing.T) {
	primary, fallback := makeFallbackKMs(t)
	fm := crypto.NewFallbackKeyManager(primary, fallback)
	err := fm.Close(context.Background())
	require.NoError(t, err)
	// After close, WrapKey must return ErrProviderUnavailable on both.
	_, err = fm.WrapKey(context.Background(), make([]byte, 32), nil)
	assert.ErrorIs(t, err, crypto.ErrProviderUnavailable)
}
