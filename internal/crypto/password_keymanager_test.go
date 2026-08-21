package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPasswordKeyManager_WriteCostExceedsDecryptLimit(t *testing.T) {
	limits := DefaultKDFLimits()
	limits.PBKDF2MaxIterations = 100000
	_, err := NewPasswordKeyManager([]byte("password-manager-write-limit"), WithPasswordKMKDFLimits(limits), WithPasswordKMPBKDF2(100001))
	var cost *ErrKDFCostTooHigh
	if !errors.As(err, &cost) {
		t.Fatalf("expected typed cost error, got %v", err)
	}
}

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

func sec39V2Payload(alg byte, params []byte) []byte {
	p := make([]byte, 4+1+len(params)+saltSize+nonceSize+tagSize)
	binary.BigEndian.PutUint32(p[:4], envelopeVersionMarker)
	p[4] = alg
	copy(p[5:], params)
	return p
}

func TestPasswordKM_UnwrapKey_V2ValidationFailsClosed(t *testing.T) {
	limits := DefaultKDFLimits()
	limits.PBKDF2MaxIterations = 100000
	limits.Argon2idMaxMemory = 1
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMKDFLimits(limits), WithPasswordKMPBKDF2(100000))
	require.NoError(t, err)
	for _, tc := range []struct {
		name      string
		data      []byte
		kind      string
		algorithm KDFAlgorithm
		parameter string
		requested uint64
		maximum   uint64
		value     uint64
	}{
		{"pbkdf2-cost", func() []byte {
			p := make([]byte, 4)
			binary.BigEndian.PutUint32(p, 100001)
			return sec39V2Payload(envelopeAlgPBKDF2, p)
		}(), "cost", KDFAlgPBKDF2SHA256, "iterations", 100001, 100000, 0},
		{"pbkdf2-invalid", func() []byte {
			p := make([]byte, 4)
			binary.BigEndian.PutUint32(p, 1)
			return sec39V2Payload(envelopeAlgPBKDF2, p)
		}(), "invalid", KDFAlgPBKDF2SHA256, "iterations", 0, 0, 1},
		{"argon-cost", func() []byte {
			p := make([]byte, 9)
			binary.BigEndian.PutUint32(p[0:4], 1)
			binary.BigEndian.PutUint32(p[4:8], 2)
			p[8] = 1
			return sec39V2Payload(envelopeAlgArgon2id, p)
		}(), "cost", KDFAlgArgon2id, "memory", 2, 1, 0},
		{"argon-invalid", func() []byte {
			p := make([]byte, 9)
			binary.BigEndian.PutUint32(p[0:4], 0)
			binary.BigEndian.PutUint32(p[4:8], 1)
			p[8] = 1
			return sec39V2Payload(envelopeAlgArgon2id, p)
		}(), "invalid", KDFAlgArgon2id, "time", 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := km.UnwrapKey(context.Background(), &KeyEnvelope{Provider: passwordKMProvider, Ciphertext: tc.data}, nil)
			switch tc.kind {
			case "cost":
				var cost *ErrKDFCostTooHigh
				if !errors.As(err, &cost) {
					t.Fatalf("expected ErrKDFCostTooHigh through UnwrapKey, got %v", err)
				}
				if cost.Algorithm != tc.algorithm || cost.Parameter != tc.parameter || cost.Requested != tc.requested || cost.Maximum != tc.maximum {
					t.Fatalf("unexpected PBKDF2 cost details: %+v", cost)
				}
			case "invalid":
				var invalid *ErrInvalidKDFParams
				if !errors.As(err, &invalid) {
					t.Fatalf("expected ErrInvalidKDFParams through UnwrapKey, got %v", err)
				}
				if invalid.Algorithm != tc.algorithm || invalid.Parameter != tc.parameter || invalid.Value != tc.value {
					t.Fatalf("unexpected invalid details: %+v", invalid)
				}
			}
		})
	}
}

func TestPasswordKM_UnwrapKey_V2MarkerDoesNotFallback(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)
	payload := sec39V2Payload(envelopeAlgPBKDF2, []byte{0, 1, 0, 0})
	_, err = km.UnwrapKey(context.Background(), &KeyEnvelope{Provider: passwordKMProvider, Ciphertext: payload}, nil)
	var invalid *ErrInvalidKDFParams
	if !errors.As(err, &invalid) {
		t.Fatalf("recognized v2 marker fell through or lost typed error: %v", err)
	}
}

func TestPasswordKM_UnwrapKey_UnknownV2AlgorithmFailsClosed(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)
	payload := sec39V2Payload(0xff, nil)
	_, err = km.UnwrapKey(context.Background(), &KeyEnvelope{Provider: passwordKMProvider, Ciphertext: payload}, nil)
	var invalid *ErrInvalidKDFParams
	if !errors.As(err, &invalid) {
		t.Fatalf("unknown v2 algorithm did not return ErrInvalidKDFParams: %v", err)
	}
	if invalid.Parameter != "algorithm" || invalid.Value != 0xff {
		t.Fatalf("unexpected unknown-algorithm details: %+v", invalid)
	}
}

func TestPasswordKM_UnwrapKey_TruncatedV2DoesNotFallback(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword)
	require.NoError(t, err)

	for _, size := range []int{saltSize + nonceSize + tagSize, saltSize + nonceSize + tagSize + 4} {
		t.Run(fmt.Sprintf("%d-bytes", size), func(t *testing.T) {
			payload := make([]byte, size)
			binary.BigEndian.PutUint32(payload[:4], envelopeVersionMarker)
			payload[4] = envelopeAlgPBKDF2
			_, err := km.UnwrapKey(context.Background(), &KeyEnvelope{Provider: passwordKMProvider, Ciphertext: payload}, nil)
			var invalid *ErrInvalidKDFParams
			if !errors.As(err, &invalid) {
				t.Fatalf("truncated v2 envelope fell through or lost typed error: %v", err)
			}
			if invalid.Algorithm != KDFAlgPBKDF2SHA256 || invalid.Parameter != "format" {
				t.Fatalf("unexpected truncated-v2 details: %+v", invalid)
			}
		})
	}
}

func TestPasswordKM_UnwrapKey_V1AndLegacyCompatibility(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(100000))
	require.NoError(t, err)
	dek := []byte("01234567890123456789012345678901")
	for _, tc := range []struct {
		name       string
		iterations int
		prefix     bool
	}{
		{name: "v1-maximum", iterations: MaxPBKDF2Iterations, prefix: true},
		{name: "legacy", iterations: LegacyPBKDF2Iterations, prefix: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := sec39PBKDF2Envelope(t, testPassword, dek, tc.iterations, tc.prefix)
			got, err := km.UnwrapKey(context.Background(), env, nil)
			require.NoError(t, err)
			assert.Equal(t, dek, got)
		})
	}
}

func sec39PBKDF2Envelope(t *testing.T, password, plaintext []byte, iterations int, v1 bool) *KeyEnvelope {
	t.Helper()
	salt := bytes.Repeat([]byte{0x31}, saltSize)
	nonce := bytes.Repeat([]byte{0x42}, nonceSize)
	wk, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, aesKeySize)
	require.NoError(t, err)
	block, err := aes.NewCipher(wk)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	payload := make([]byte, 0, 4+len(salt)+len(nonce)+len(sealed))
	if v1 {
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, uint32(iterations))
		payload = append(payload, prefix...)
	}
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)
	return &KeyEnvelope{Provider: passwordKMProvider, Ciphertext: payload}
}

func TestPasswordKM_TryUnwrap_SuccessAndAuthenticationFailure(t *testing.T) {
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(100000))
	require.NoError(t, err)
	salt := bytes.Repeat([]byte{7}, saltSize)
	nonce := bytes.Repeat([]byte{8}, nonceSize)
	wk, err := pbkdf2.Key(sha256.New, string(testPassword), salt, 100000, aesKeySize)
	require.NoError(t, err)
	block, err := aes.NewCipher(wk)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	sealed := gcm.Seal(nil, nonce, []byte("dek"), nil)
	got, err := km.(*passwordKeyManager).tryUnwrap(salt, nonce, sealed, 100000)
	require.NoError(t, err)
	assert.Equal(t, []byte("dek"), got)
	sealed[0] ^= 1
	_, err = km.(*passwordKeyManager).tryUnwrap(salt, nonce, sealed, 100000)
	require.Error(t, err)
}

func TestOpenPasswordKMGCM_InvalidKey(t *testing.T) {
	_, err := openPasswordKMGCM([]byte("short"), make([]byte, nonceSize), make([]byte, tagSize))
	if err == nil {
		t.Fatal("expected invalid AES key error")
	}
}

func TestPasswordKM_UnwrapKey_V1AboveConfiguredLimit(t *testing.T) {
	limits := DefaultKDFLimits()
	limits.PBKDF2MaxIterations = 100000
	km, err := NewPasswordKeyManager(testPassword, WithPasswordKMPBKDF2(100000), WithPasswordKMKDFLimits(limits))
	require.NoError(t, err)
	payload := make([]byte, 4+saltSize+nonceSize+tagSize)
	binary.BigEndian.PutUint32(payload[:4], 100001)
	_, err = km.UnwrapKey(context.Background(), &KeyEnvelope{Provider: passwordKMProvider, Ciphertext: payload}, nil)
	var cost *ErrKDFCostTooHigh
	if !errors.As(err, &cost) {
		t.Fatalf("expected v1 operational limit error through dispatch, got %v", err)
	}
}
