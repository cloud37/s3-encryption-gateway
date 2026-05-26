package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testPassword = []byte("a-sufficiently-long-test-password")

func TestPasswordKeyManager_WrapUnwrap_RoundTrip(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
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
	assert.Equal(t, 1, env.KeyVersion)

	// Ciphertext must not contain the plaintext DEK.
	for i := 0; i+len(dek) <= len(env.Ciphertext); i++ {
		assert.NotEqual(t, dek, env.Ciphertext[i:i+len(dek)], "ciphertext must not embed plaintext DEK at offset %d", i)
	}

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

// TestPasswordKeyManager_DifferentSaltPerWrap verifies two wraps of the same
// DEK produce different ciphertexts (random salt per wrap).
func TestPasswordKeyManager_DifferentSaltPerWrap(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()

	env1, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)
	env2, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	assert.NotEqual(t, env1.Ciphertext, env2.Ciphertext, "two wraps must produce distinct ciphertexts")
}

// TestPasswordKeyManager_WrongPassword verifies that a different password
// cannot unwrap the envelope.
func TestPasswordKeyManager_WrongPassword(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	km2, err := NewPasswordKeyManager([]byte("totally-different-password!!"), WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)
	_, err = km2.UnwrapKey(ctx, env, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnwrapFailed)
}

// TestPasswordKeyManager_TamperedCiphertext verifies authentication failure
// when the ciphertext is modified.
func TestPasswordKeyManager_TamperedCiphertext(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
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

// TestPasswordKeyManager_ProviderMismatch verifies rejection of foreign envelopes.
func TestPasswordKeyManager_ProviderMismatch(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)

	env := &KeyEnvelope{Provider: "cosmian-kmip", Ciphertext: []byte{1, 2, 3}}
	_, err = km.UnwrapKey(context.Background(), env, nil)
	require.Error(t, err)
}

// TestPasswordKeyManager_InvalidEnvelope verifies ErrInvalidEnvelope on nil/empty.
func TestPasswordKeyManager_InvalidEnvelope(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)
	ctx := context.Background()

	_, err = km.UnwrapKey(ctx, nil, nil)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)

	_, err = km.UnwrapKey(ctx, &KeyEnvelope{Provider: passwordKMProvider}, nil)
	assert.ErrorIs(t, err, ErrInvalidEnvelope)
}

// TestPasswordKeyManager_ShortPassword verifies rejection of short passwords.
func TestPasswordKeyManager_ShortPassword(t *testing.T) {
	_, err := NewPasswordKeyManager([]byte("short"), WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.Error(t, err)
}

// TestPasswordKeyManager_HealthCheck verifies HealthCheck passes while open.
func TestPasswordKeyManager_HealthCheck(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)
	assert.NoError(t, km.HealthCheck(context.Background()))

	km.Close(context.Background())
	assert.ErrorIs(t, km.HealthCheck(context.Background()), ErrProviderUnavailable)
}

// TestPasswordKeyManager_ClosedRejectsAllOps verifies the closed state.
func TestPasswordKeyManager_ClosedRejectsAllOps(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)
	km.Close(context.Background())

	ctx := context.Background()
	_, err = km.WrapKey(ctx, make([]byte, 32), nil)
	assert.ErrorIs(t, err, ErrProviderUnavailable)

	_, err = km.ActiveKeyVersion(ctx)
	assert.ErrorIs(t, err, ErrProviderUnavailable)
}

// TestIsPasswordKeyManager confirms the type predicate.
func TestIsPasswordKeyManager(t *testing.T) {
	km, _ := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	assert.True(t, IsPasswordKeyManager(km))
	assert.False(t, IsPasswordKeyManager(nil))
}


func TestPasswordKM_WrapUnwrap_100k(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(100000))
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
	assert.Equal(t, 1, env.KeyVersion)

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestPasswordKM_WrapUnwrap_600k(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(600000))
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
	assert.Equal(t, 1, env.KeyVersion)

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestPasswordKM_BackwardCompat_OldEnvelope(t *testing.T) {
	// Old format envelope: salt(32) || nonce(12) || sealed(dek + tag)(48) = 92 bytes total
	// Construct one that was wrapped with 100k iterations.
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(100000))
	require.NoError(t, err)

	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(i)
	}

	ctx := context.Background()

	// Create a manual old-format envelope using 100k iterations.
	// Use a RANDOM salt so the first 4 bytes have a ~99.998% chance of
	// decoding to a uint32 >= MinPBKDF2Iterations.  A heuristic-based
	// format detector would misclassify this as new format, so this
	// verifies the robust try-and-fallback implementation.
	salt := make([]byte, saltSize)
	_, err = io.ReadFull(rand.Reader, salt)
	require.NoError(t, err)

	wk, err := pbkdf2.Key(sha256.New, string(testPassword), salt, LegacyPBKDF2Iterations, aesKeySize)
	require.NoError(t, err)

	block, err := aes.NewCipher(wk)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	require.NoError(t, err)

	sealed := gcm.Seal(nil, nonce, dek, nil)

	// Old format: no prefix, just salt || nonce || sealed
	oldFormatCiphertext := make([]byte, 0, len(salt)+len(nonce)+len(sealed))
	oldFormatCiphertext = append(oldFormatCiphertext, salt...)
	oldFormatCiphertext = append(oldFormatCiphertext, nonce...)
	oldFormatCiphertext = append(oldFormatCiphertext, sealed...)

	env := &KeyEnvelope{
		Provider:   passwordKMProvider,
		Ciphertext: oldFormatCiphertext,
	}

	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err)
	assert.Equal(t, dek, got)
}

func TestPasswordKM_NewEnvelopeFormat_HasPrefix(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	if len(env.Ciphertext) < 4 {
		t.Fatal("ciphertext too short for prefix")
	}

	prefix := binary.BigEndian.Uint32(env.Ciphertext[:4])
	if prefix != uint32(envelopeVersionMarker) {
		t.Errorf("prefix %d is not the v2 envelope version marker %d", prefix, envelopeVersionMarker)
	}

	// Verify algorithm byte is present (PBKDF2 = 0x00)
	if len(env.Ciphertext) < 5 {
		t.Fatal("ciphertext too short for algorithm byte")
	}
	algByte := env.Ciphertext[4]
	if algByte != envelopeAlgPBKDF2 {
		t.Errorf("algorithm byte = %d, want %d (PBKDF2)", algByte, envelopeAlgPBKDF2)
	}
}

func TestPasswordKM_WrongIterations_Fails(t *testing.T) {
	km600k, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(600000))
	require.NoError(t, err)

	dek := make([]byte, 32)
	ctx := context.Background()
	env, err := km600k.WrapKey(ctx, dek, nil)
	require.NoError(t, err)

	// Change the marker to a large integer so v2 detection fails and v1
	// detection tries with a wrong iteration count.
	if len(env.Ciphertext) < 4 {
		t.Fatal("ciphertext too short for prefix")
	}
	corrupted := make([]byte, len(env.Ciphertext))
	copy(corrupted, env.Ciphertext)
	binary.BigEndian.PutUint32(corrupted[:4], 100000)

	env.Ciphertext = corrupted

	_, err = km600k.UnwrapKey(ctx, env, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnwrapFailed)
}


