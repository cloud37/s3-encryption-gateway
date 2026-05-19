package crypto

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newTestAESKEKManager(t *testing.T) *AESKEKManager {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	km, err := NewAESKEKManager(map[int][]byte{1: key}, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	return km
}

func TestAESKEKManager_WrapUnwrap_RoundTrip(t *testing.T) {
	km := newTestAESKEKManager(t)

	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)

	env, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)
	require.Equal(t, "self-contained-aes-v1", env.KeyID)
	require.Equal(t, 1, env.KeyVersion)
	require.Equal(t, "self_contained", env.Provider)
	require.GreaterOrEqual(t, len(env.Ciphertext), 12+16)

	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, dek, got)
}

func TestAESKEKManager_WrapUnwrap_WrongKEK(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, err := rand.Read(key1)
	require.NoError(t, err)
	_, err = rand.Read(key2)
	require.NoError(t, err)

	km1, err := NewAESKEKManager(map[int][]byte{1: key1}, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km1.Close(context.Background()) })

	km2, err := NewAESKEKManager(map[int][]byte{1: key2}, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km2.Close(context.Background()) })

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	env, err := km1.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	_, err = km2.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrUnwrapFailed))
}

func TestAESKEKManager_Close_Zeroizes(t *testing.T) {
	km := newTestAESKEKManager(t)
	err := km.Close(context.Background())
	require.NoError(t, err)

	_, err = km.WrapKey(context.Background(), make([]byte, 32), nil)
	require.ErrorIs(t, err, ErrProviderUnavailable)

	require.Empty(t, km.keys)
}

func TestAESKEKManager_Close_Idempotent(t *testing.T) {
	km := newTestAESKEKManager(t)
	require.NoError(t, km.Close(context.Background()))
	require.NoError(t, km.Close(context.Background()))
}

func TestAESKEKManager_UnwrapKey_VersionNotFound(t *testing.T) {
	km := newTestAESKEKManager(t)

	env := &KeyEnvelope{
		KeyID:      "self-contained-aes-v99",
		KeyVersion: 99,
		Provider:   "self_contained",
		Ciphertext: make([]byte, 28),
	}
	_, err := km.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrUnwrapFailed))
}

func TestAESKEKManager_UnwrapKey_TamperedCiphertext(t *testing.T) {
	km := newTestAESKEKManager(t)

	dek := make([]byte, 32)
	_, err := rand.Read(dek)
	require.NoError(t, err)

	env, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	env.Ciphertext[5] ^= 0xff
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrUnwrapFailed))
}

func TestAESKEKManager_NilEnvelope(t *testing.T) {
	km := newTestAESKEKManager(t)
	_, err := km.UnwrapKey(context.Background(), nil, nil)
	require.ErrorIs(t, err, ErrInvalidEnvelope)
}

func TestAESKEKManager_EmptyEnvelope(t *testing.T) {
	km := newTestAESKEKManager(t)
	_, err := km.UnwrapKey(context.Background(), &KeyEnvelope{Ciphertext: []byte{}}, nil)
	require.ErrorIs(t, err, ErrInvalidEnvelope)
}

func TestAESKEKManager_MultiVersion_DualRead(t *testing.T) {
	key1 := make([]byte, 32)
	_, err := rand.Read(key1)
	require.NoError(t, err)

	key2 := make([]byte, 32)
	_, err = rand.Read(key2)
	require.NoError(t, err)

	km, err := NewAESKEKManager(map[int][]byte{1: key1, 2: key2}, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	env1, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)
	require.Equal(t, 1, env1.KeyVersion)

	plan, err := km.PrepareRotation(context.Background(), nil)
	require.NoError(t, err)
	require.Equal(t, 2, plan.TargetVersion)

	err = km.PromoteActiveVersion(context.Background(), plan)
	require.NoError(t, err)

	av, err := km.ActiveKeyVersion(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, av)

	env2, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)
	require.Equal(t, 2, env2.KeyVersion)

	got1, err := km.UnwrapKey(context.Background(), env1, nil)
	require.NoError(t, err)
	require.Equal(t, dek, got1)

	got2, err := km.UnwrapKey(context.Background(), env2, nil)
	require.NoError(t, err)
	require.Equal(t, dek, got2)
}

func TestAESKEKManager_ProviderOption(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	km, err := NewAESKEKManager(map[int][]byte{1: key}, 1, WithAESProvider("custom-provider"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	require.Equal(t, "custom-provider", km.Provider())
}

func TestAESKEKManager_New_RejectsZeroKey(t *testing.T) {
	zeroKey := make([]byte, 32)
	_, err := NewAESKEKManager(map[int][]byte{1: zeroKey}, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "all zeros")
}

func TestAESKEKManager_New_RejectsWrongSize(t *testing.T) {
	_, err := NewAESKEKManager(map[int][]byte{1: make([]byte, 16)}, 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "must be 32 bytes")
}

func TestAESKEKManager_New_RejectsMissingActiveVersion(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	_, err = NewAESKEKManager(map[int][]byte{1: key}, 2)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestAESKEKManager_New_RejectsEmptyKeys(t *testing.T) {
	_, err := NewAESKEKManager(map[int][]byte{}, 0)
	require.Error(t, err)
}

func TestAESKEKManager_HealthCheck_FailAfterClose(t *testing.T) {
	km := newTestAESKEKManager(t)
	require.NoError(t, km.Close(context.Background()))
	err := km.HealthCheck(context.Background())
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestAESKEKManager_ActiveKeyVersion_FailAfterClose(t *testing.T) {
	km := newTestAESKEKManager(t)
	require.NoError(t, km.Close(context.Background()))
	_, err := km.ActiveKeyVersion(context.Background())
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestAESKEKManager_AddVersion_Duplicate(t *testing.T) {
	km := newTestAESKEKManager(t)
	mat := make([]byte, 32)
	_, err := rand.Read(mat)
	require.NoError(t, err)
	err = km.AddVersion(context.Background(), 1, mat)
	require.Error(t, err)
}

func TestAESKEKManager_AddVersion_AfterClose(t *testing.T) {
	km := newTestAESKEKManager(t)
	require.NoError(t, km.Close(context.Background()))
	mat := make([]byte, 32)
	for i := range mat {
		mat[i] = byte(i + 1)
	}
	err := km.AddVersion(context.Background(), 2, mat)
	require.ErrorIs(t, err, ErrProviderUnavailable)
}

func TestAESKEKManager_PrepareRotation_TargetAlreadyActive(t *testing.T) {
	km := newTestAESKEKManager(t)
	target := 1
	_, err := km.PrepareRotation(context.Background(), &target)
	require.Error(t, err)
}

func TestAESKEKManager_PrepareRotation_TargetNotFound(t *testing.T) {
	km := newTestAESKEKManager(t)
	target := 99
	_, err := km.PrepareRotation(context.Background(), &target)
	require.ErrorIs(t, err, ErrKeyNotFound)
}

func TestAESKEKManager_PromoteActiveVersion_Conflict(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	_, err := rand.Read(key1)
	require.NoError(t, err)
	_, err = rand.Read(key2)
	require.NoError(t, err)

	km, err := NewAESKEKManager(map[int][]byte{1: key1, 2: key2}, 1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	err = km.PromoteActiveVersion(context.Background(), RotationPlan{CurrentVersion: 1, TargetVersion: 2})
	require.NoError(t, err)

	err = km.PromoteActiveVersion(context.Background(), RotationPlan{CurrentVersion: 1, TargetVersion: 2})
	require.ErrorIs(t, err, ErrRotationConflict)
}

func TestAESKEKManager_NoKEKInLogs(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	keyB64 := base64Encode(key)

	var buf bytes.Buffer
	logrus.SetOutput(&buf)
	logrus.SetLevel(logrus.DebugLevel)

	km, err := NewAESKEKManager(map[int][]byte{1: key}, 1, WithAESProvider("test-aes"))
	require.NoError(t, err)

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	env, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)

	_, err = km.UnwrapKey(context.Background(), &KeyEnvelope{Ciphertext: make([]byte, 4)}, nil)
	require.Error(t, err)

	logOutput := buf.String()

	for _, chunk := range splitIntoChunks(keyB64, 8) {
		if strings.Contains(logOutput, chunk) {
			t.Errorf("log contains KEK substring %q", chunk)
		}
	}

	require.NoError(t, km.Close(context.Background()))
}

func TestAESKEKManager_ContextCancellation(t *testing.T) {
	km := newTestAESKEKManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := km.WrapKey(ctx, make([]byte, 32), nil)
	require.Error(t, err)
	require.True(t, errors.Is(err, context.Canceled) || strings.Contains(err.Error(), context.Canceled.Error()))
}

func FuzzAESKEKManager_UnwrapKey(f *testing.F) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		f.Fatal(err)
	}
	km, err := NewAESKEKManager(map[int][]byte{1: key}, 1)
	if err != nil {
		f.Fatal(err)
	}
	defer km.Close(context.Background())

	f.Add([]byte{})
	f.Add([]byte("short"))
	f.Add(make([]byte, 100))
	// Note: we intentionally do NOT add env.Ciphertext as a seed corpus entry.
	// It is a valid ciphertext for this key and would succeed unwrapping,
	// which would incorrectly fail the fuzz target (which expects errors).

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		env := &KeyEnvelope{
			KeyID:      "fuzz",
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

func base64Encode(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	out := make([]byte, 0, ((len(b)+2)/3)*4)
	for i := 0; i < len(b); i += 3 {
		val := uint(b[i]) << 16
		if i+1 < len(b) {
			val |= uint(b[i+1]) << 8
		}
		if i+2 < len(b) {
			val |= uint(b[i+2])
		}
		out = append(out, alphabet[(val>>18)&0x3F])
		out = append(out, alphabet[(val>>12)&0x3F])
		if i+1 < len(b) {
			out = append(out, alphabet[(val>>6)&0x3F])
		} else {
			out = append(out, '=')
		}
		if i+2 < len(b) {
			out = append(out, alphabet[val&0x3F])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}

func splitIntoChunks(s string, n int) []string {
	var chunks []string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		chunks = append(chunks, s[i:end])
	}
	return chunks
}

// AddVersionForTest wraps AESKEKManager.AddVersion for conformance tests.
func addAESVersion(t *testing.T, km KeyManager, version int) error {
	t.Helper()
	material := make([]byte, 32)
	for i := range material {
		material[i] = byte(version*37 + i + 1)
	}
	if aekm, ok := km.(*AESKEKManager); ok {
		return aekm.AddVersion(context.Background(), version, material)
	}
	return fmt.Errorf("not an AESKEKManager")
}

func newAESFactory(t *testing.T) func(t *testing.T) KeyManager {
	return func(t *testing.T) KeyManager {
		t.Helper()
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)
		km, err := NewAESKEKManager(map[int][]byte{1: key}, 1)
		require.NoError(t, err)
		return km
	}
}

// Ensure AddVersionForTest from the test helpers file works with AESKEKManager
var _ = os.DevNull
