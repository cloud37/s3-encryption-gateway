package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func generateTestRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	return key
}

func newTestRSAKEKManager(t *testing.T, bits int) *RSAKEKManager {
	t.Helper()
	key := generateTestRSAKey(t, bits)
	km, err := NewRSAKEKManager(key, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	return km
}

func TestRSAKEKManager_WrapUnwrap_RoundTrip(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)

	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)

	env, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)
	require.Contains(t, env.KeyID, "self-contained-rsa-")
	require.Equal(t, 1, env.KeyVersion)
	require.Equal(t, "self_contained", env.Provider)
	require.NotEmpty(t, env.Ciphertext)

	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, dek, got)
}

func TestRSAKEKManager_New_KeyTooSmall(t *testing.T) {
	key := generateTestRSAKey(t, 1024)
	_, err := NewRSAKEKManager(key, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "minimum")
}

func TestRSAKEKManager_New_NilKey(t *testing.T) {
	_, err := NewRSAKEKManager(nil, 1)
	require.Error(t, err)
}

func TestRSAKEKManager_Close_ZeroizesPrivateKey(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)
	err := km.Close(context.Background())
	require.NoError(t, err)

	_, err = km.WrapKey(context.Background(), make([]byte, 32), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestRSAKEKManager_Close_Idempotent(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)
	require.NoError(t, km.Close(context.Background()))
	require.NoError(t, km.Close(context.Background()))
}

func TestRSAKEKManager_NilEnvelope(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)
	_, err := km.UnwrapKey(context.Background(), nil, nil)
	require.ErrorIs(t, err, ErrInvalidEnvelope)
}

func TestRSAKEKManager_EmptyCiphertext(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)
	env := &KeyEnvelope{
		KeyID:    "test",
		Provider: "self_contained",
	}
	_, err := km.UnwrapKey(context.Background(), env, nil)
	require.ErrorIs(t, err, ErrInvalidEnvelope)
}

func TestRSAKEKManager_ProviderOption(t *testing.T) {
	key := generateTestRSAKey(t, 2048)
	km, err := NewRSAKEKManager(key, 1, WithRSAProvider("custom-rsa"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	require.Equal(t, "custom-rsa", km.Provider())
}

func TestRSAKEKManager_KeyVersion(t *testing.T) {
	key := generateTestRSAKey(t, 2048)
	km, err := NewRSAKEKManager(key, 5)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	av, err := km.ActiveKeyVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, 5, av)
}

func TestRSAKEKManager_HealthCheck_OK(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)
	err := km.HealthCheck(context.Background())
	require.NoError(t, err)
}

func TestRSAKEKManager_HealthCheck_AfterClose(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)
	require.NoError(t, km.Close(context.Background()))
	err := km.HealthCheck(context.Background())
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestRSAKEKManager_WrapKey_InvalidKeySize(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)
	// RSA-OAEP can only encrypt data up to key size - 2*hashSize - 2
	// For 2048-bit RSA with SHA-256: max = 256 - 2*32 - 2 = 190
	largeDEK := make([]byte, 200)
	_, err := km.WrapKey(context.Background(), largeDEK, nil)
	require.Error(t, err)
}

func TestRSAKEKManager_ContextCancellation(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := km.WrapKey(ctx, make([]byte, 32), nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled) || err.Error() != "")
}

func TestRSAKEKManager_UnwrapKey_TamperedCiphertext(t *testing.T) {
	km := newTestRSAKEKManager(t, 2048)

	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)

	env, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	env.Ciphertext[0] ^= 0xff
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrUnwrapFailed))
}

func FuzzRSAKEKManager_UnwrapKey(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.Fatal(err)
	}
	km, err := NewRSAKEKManager(key, 1)
	if err != nil {
		f.Fatal(err)
	}
	defer km.Close(context.Background())

	f.Add([]byte{})
	f.Add(make([]byte, 512))
	// Note: we intentionally do NOT add env.Ciphertext as a seed corpus entry.
	// It is a valid ciphertext for this key and would succeed unwrapping,
	// which would incorrectly fail the fuzz target (which expects errors).

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		env := &KeyEnvelope{
			KeyID:      "fuzz-rsa",
			KeyVersion: 1,
			Provider:   "self_contained",
			Ciphertext: ciphertext,
		}
		result, err := km.UnwrapKey(context.Background(), env, nil)
		if err == nil {
			t.Fatalf("expected error for fuzzed ciphertext, got plaintext of length %d", len(result))
		}
		if !errors.Is(err, ErrInvalidEnvelope) && !errors.Is(err, ErrUnwrapFailed) {
			t.Fatalf("unexpected error type: %v", err)
		}
	})
}

func TestRSAKEKManager_PEMRoundTrip(t *testing.T) {
	key := generateTestRSAKey(t, 2048)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "test.pem")
	err := os.WriteFile(pemPath, pemData, 0600)
	require.NoError(t, err)

	pk, err := resolveSelfContainedRSAKey("file:" + pemPath)
	require.NoError(t, err)
	require.NotNil(t, pk)
	require.Equal(t, key.N, pk.N)
}

func TestRSAKEKManager_KeyID_Stable(t *testing.T) {
	key := generateTestRSAKey(t, 2048)
	km1, err := NewRSAKEKManager(key, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km1.Close(context.Background()) })

	km2, err := NewRSAKEKManager(key, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km2.Close(context.Background()) })

	require.Equal(t, km1.keyID, km2.keyID, "keyID must be deterministic for the same key")
}
