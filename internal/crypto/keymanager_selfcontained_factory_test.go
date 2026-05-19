package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelfContainedFactory_AESType_EnvVar(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	t.Setenv("TEST_AES_KEK_V1", keyB64)

	cfg := map[string]any{
		"type": "aes",
		"keys": []any{
			map[string]any{
				"version":    float64(1),
				"key_source": "env:TEST_AES_KEK_V1",
			},
		},
	}

	km, err := selfContainedFactory(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "self_contained", km.Provider())
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	env, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, dek, got)
}

func TestSelfContainedFactory_RSAType_PEMFile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	tmpDir := t.TempDir()
	pemPath := filepath.Join(tmpDir, "kek.pem")
	err = os.WriteFile(pemPath, pemData, 0600)
	require.NoError(t, err)

	cfg := map[string]any{
		"type":                "rsa",
		"private_key_source":  "file:" + pemPath,
		"key_version":         1,
	}

	km, err := selfContainedFactory(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	env, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, dek, got)
}

func TestSelfContainedFactory_UnknownType_ReturnsError(t *testing.T) {
	cfg := map[string]any{
		"type": "bogus",
	}
	_, err := selfContainedFactory(context.Background(), cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown type")
}

func TestSelfContainedFactory_MissingType_ReturnsError(t *testing.T) {
	cfg := map[string]any{}
	_, err := selfContainedFactory(context.Background(), cfg)
	require.Error(t, err)
	require.Contains(t, err.Error(), "type")
}

func TestSelfContainedFactoryAES_Base64Key(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	cfg := map[string]any{
		"type": "aes",
		"keys": []any{
			map[string]any{
				"version":    1,
				"key_source": "base64:" + keyB64,
			},
		},
	}

	km, err := selfContainedFactory(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })

	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)

	env, err := km.WrapKey(context.Background(), dek, nil)
	require.NoError(t, err)

	got, err := km.UnwrapKey(context.Background(), env, nil)
	require.NoError(t, err)
	require.Equal(t, dek, got)
}

func TestSelfContainedFactory_AESMissingKeys(t *testing.T) {
	cfg := map[string]any{
		"type": "aes",
	}
	_, err := selfContainedFactory(context.Background(), cfg)
	require.Error(t, err)
}

func TestSelfContainedFactory_RSAMissingSource(t *testing.T) {
	cfg := map[string]any{
		"type": "rsa",
	}
	_, err := selfContainedFactory(context.Background(), cfg)
	require.Error(t, err)
}

func TestResolveAESKey_Env(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	t.Setenv("TEST_RESOLVE_AES_KEY", keyB64)

	got, err := resolveSelfContainedAESKey("env:TEST_RESOLVE_AES_KEY")
	require.NoError(t, err)
	require.Equal(t, key, got)
}

func TestResolveAESKey_Base64(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	got, err := resolveSelfContainedAESKey("base64:" + keyB64)
	require.NoError(t, err)
	require.Equal(t, key, got)
}

func TestResolveAESKey_File(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "aes.key")
	err = os.WriteFile(keyPath, []byte(keyB64), 0600)
	require.NoError(t, err)

	got, err := resolveSelfContainedAESKey("file:" + keyPath)
	require.NoError(t, err)
	require.Equal(t, key, got)
}

func TestResolveAESKey_InvalidBase64(t *testing.T) {
	t.Setenv("TEST_INVALID_B64", "not-valid-base64!!!")
	_, err := resolveSelfContainedAESKey("env:TEST_INVALID_B64")
	require.Error(t, err)
}

func TestResolveRSAKey_Env(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	t.Setenv("TEST_RSA_KEY", string(pemData))

	got, err := resolveSelfContainedRSAKey("env:TEST_RSA_KEY")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, key.N, got.N)
}

func TestSelfContainedFactory_WithProvider(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	keyB64 := base64.StdEncoding.EncodeToString(key)

	cfg := map[string]any{
		"type":     "aes",
		"provider": "custom-aes",
		"keys": []any{
			map[string]any{
				"version":    1,
				"key_source": "base64:" + keyB64,
			},
		},
	}

	km, err := selfContainedFactory(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = km.Close(context.Background()) })
	require.Equal(t, "custom-aes", km.Provider())
}
