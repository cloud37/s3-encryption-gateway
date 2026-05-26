//go:build !fips

package crypto

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordKM_Argon2id_WrapUnwrap_RoundTrip(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMArgon2id(2, 19456, 1))
	require.NoError(t, err)

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)
	assert.Equal(t, passwordKMProvider, env.Provider)
	assert.NotEmpty(t, env.Ciphertext)

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestPasswordKM_Argon2id_DifferentSaltPerWrap(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMArgon2id(2, 19456, 1))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()

	env1, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)
	env2, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	assert.NotEqual(t, env1.Ciphertext, env2.Ciphertext)
}

func TestPasswordKM_Argon2id_WrongPassword(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMArgon2id(2, 19456, 1))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	km2, err := NewPasswordKeyManager([]byte("totally-different-password!!"), WithPasswordKMArgon2id(2, 19456, 1))
	require.NoError(t, err)
	_, err = km2.UnwrapKey(ctx, env, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnwrapFailed)
}

func TestPasswordKM_Argon2id_TamperedCiphertext(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMArgon2id(2, 19456, 1))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	tampered := make([]byte, len(env.Ciphertext))
	copy(tampered, env.Ciphertext)
	tampered[len(tampered)-1] ^= 0xff
	env.Ciphertext = tampered

	_, err = km.UnwrapKey(ctx, env, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnwrapFailed)
}

func TestPasswordKM_Argon2id_BackwardCompat_PBKDF2(t *testing.T) {
	pbkdf2KM, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)

	arKM, err := NewPasswordKeyManager(testPassword, WithPasswordKMArgon2id(2, 19456, 1))
	require.NoError(t, err)

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	ctx := context.Background()
	env, err := pbkdf2KM.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	got, err := arKM.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestPasswordKM_PBKDF2_BackwardCompat_Argon2id(t *testing.T) {
	arKM, err := NewPasswordKeyManager(testPassword, WithPasswordKMArgon2id(2, 19456, 1))
	require.NoError(t, err)

	pbkdf2KM, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	ctx := context.Background()
	env, err := arKM.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	got, err := pbkdf2KM.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestPasswordKM_V2FormatHasMarker(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMArgon2id(2, 19456, 1))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	if len(env.Ciphertext) < 5 {
		t.Fatal("ciphertext too short")
	}

	marker := binary.BigEndian.Uint32(env.Ciphertext[:4])
	if marker != uint32(envelopeVersionMarker) {
		t.Errorf("v2 marker = %d, want %d", marker, envelopeVersionMarker)
	}

	algByte := env.Ciphertext[4]
	if algByte != envelopeAlgArgon2id {
		t.Errorf("v2 algorithm byte = %d, want %d (Argon2id)", algByte, envelopeAlgArgon2id)
	}
}

func TestPasswordKM_V2Format_ParsesCorrectly(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMArgon2id(3, 25000, 4))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}
