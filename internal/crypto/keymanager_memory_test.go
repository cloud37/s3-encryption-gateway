package crypto

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInMemoryKeyManager_Conformance(t *testing.T) {
	ConformanceSuite(t, func(t *testing.T) KeyManager {
		t.Helper()
		km, err := NewInMemoryKeyManager(nil)
		require.NoError(t, err)
		return km
	})
}

// TestInMemoryKeyManager_RotationConformance runs the shared rotation
// contract tests against the in-memory adapter. The addVersion callback
// stages a fresh 32-byte key at the requested version via AddVersion.
func TestInMemoryKeyManager_RotationConformance(t *testing.T) {
	ConformanceSuite_Rotation(t,
		func(t *testing.T) KeyManager {
			t.Helper()
			km, err := NewInMemoryKeyManager(nil)
			require.NoError(t, err)
			return km
		},
		func(t *testing.T, km KeyManager, version int) error {
			t.Helper()
			material := make([]byte, 32)
			for i := range material {
				material[i] = byte(version*37 + i + 1) // deterministic non-zero material
			}
			return AddVersionForTest(km, version, material)
		},
	)
}

func TestInMemoryKeyManager_SpecificKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	km, err := NewInMemoryKeyManager(key)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	plaintext := []byte("test-dek-32bytes-xxxxxxxxxxxxxxx")
	env, err := km.WrapKey(context.Background(), plaintext, nil)
	require.NoError(t, err)
	require.Equal(t, "memory-v1", env.KeyID)
	require.Equal(t, 1, env.KeyVersion)
	require.Equal(t, "memory", env.Provider)

	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, string(plaintext), string(got))
}

func TestInMemoryKeyManager_InvalidKeySize(t *testing.T) {
	_, err := NewInMemoryKeyManager(make([]byte, 10))
	require.Error(t, err)
}

func TestInMemoryKeyManager_NilEnvelope(t *testing.T) {
	km, err := NewInMemoryKeyManager(nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	_, err = km.UnwrapKey(context.Background(), nil, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrInvalidEnvelope))
}

func TestInMemoryKeyManager_EmptyCiphertext(t *testing.T) {
	km, err := NewInMemoryKeyManager(nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	env := &KeyEnvelope{KeyID: "memory-v1", KeyVersion: 1, Provider: "memory"}
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrInvalidEnvelope))
}

func TestInMemoryKeyManager_ProviderOption(t *testing.T) {
	km, err := NewInMemoryKeyManager(nil, WithMemoryProvider("test-provider"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	require.Equal(t, "test-provider", km.Provider())
}

func BenchmarkEncryptWithMemoryKM(b *testing.B) {
	km, err := NewInMemoryKeyManager(nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = km.Close(context.Background()) })

	eng, err := NewEngineWithOpts([]byte("test-password-123456"), WithKeyManager(km))
	if err != nil {
		b.Fatal(err)
	}

	data := make([]byte, 64*1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
