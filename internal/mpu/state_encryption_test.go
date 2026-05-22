package mpu

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newEncryptedTestStore returns a ValkeyStateStore with encryption enabled and
// backed by a fresh miniredis instance. password is used to derive the AEAD key.
func newEncryptedTestStore(t *testing.T, password string) (*ValkeyStateStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)
	s := &ValkeyStateStore{
		client:       client,
		ttl:          7 * 24 * time.Hour,
		stateKey:     deriveStateAEADKey(password),
		encryptState: true,
		metrics:      m,
	}
	return s, mr
}

// TestStateStore_EncryptDecrypt_RoundTrip encrypts a state blob and decrypts it,
// verifying that the original JSON is recovered exactly.
func TestStateStore_EncryptDecrypt_RoundTrip(t *testing.T) {
	s, _ := newEncryptedTestStore(t, "test-password-roundtrip")

	original := sampleState("upload-enc-roundtrip")
	plaintext, err := json.Marshal(original)
	require.NoError(t, err)

	ciphertext, err := s.EncryptState(plaintext)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// Verify the version byte is set.
	assert.Equal(t, stateEncryptionVersionV1, ciphertext[0], "version byte should be 0x01")

	// Decrypt and compare.
	recovered, err := s.DecryptState(ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered, "decrypted plaintext should match original")

	// Unmarshal and compare struct fields.
	var got UploadState
	require.NoError(t, json.Unmarshal(recovered, &got))
	assert.Equal(t, original.UploadID, got.UploadID)
	assert.Equal(t, original.Bucket, got.Bucket)
	assert.Equal(t, original.Key, got.Key)
	assert.Equal(t, original.WrappedDEK, got.WrappedDEK)
	assert.Equal(t, original.IVPrefixHex, got.IVPrefixHex)
}

// TestStateStore_Encrypt_NonceUnique verifies that encrypting the same plaintext
// twice produces different ciphertexts (fresh nonce per call).
func TestStateStore_Encrypt_NonceUnique(t *testing.T) {
	s, _ := newEncryptedTestStore(t, "test-password-nonce")

	plaintext := []byte(`{"upload_id":"nonce-test","bucket":"b","key":"k"}`)

	ct1, err := s.EncryptState(plaintext)
	require.NoError(t, err)

	ct2, err := s.EncryptState(plaintext)
	require.NoError(t, err)

	// Nonces occupy bytes [1:13]; verify they differ.
	nonce1 := ct1[stateEncryptionVersionLen : stateEncryptionVersionLen+stateEncryptionNonceLen]
	nonce2 := ct2[stateEncryptionVersionLen : stateEncryptionVersionLen+stateEncryptionNonceLen]
	assert.False(t, bytes.Equal(nonce1, nonce2), "nonces must differ across separate encryptions")

	// The full ciphertexts must also differ.
	assert.False(t, bytes.Equal(ct1, ct2), "ciphertexts must differ when nonces differ")

	// Both must decrypt correctly.
	dec1, err := s.DecryptState(ct1)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec1)

	dec2, err := s.DecryptState(ct2)
	require.NoError(t, err)
	assert.Equal(t, plaintext, dec2)
}

// TestStateStore_Decrypt_TamperedCiphertext verifies that flipping a byte in the
// ciphertext body causes DecryptState to return ErrStateDecryptFailed.
func TestStateStore_Decrypt_TamperedCiphertext(t *testing.T) {
	s, _ := newEncryptedTestStore(t, "test-password-tamper")

	plaintext := []byte(`{"upload_id":"tamper-test","bucket":"b","key":"k"}`)
	ct, err := s.EncryptState(plaintext)
	require.NoError(t, err)

	// Tamper with a byte in the ciphertext body (past version + nonce).
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tamperOffset := stateEncryptionVersionLen + stateEncryptionNonceLen + 2
	tampered[tamperOffset] ^= 0xFF

	_, err = s.DecryptState(tampered)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStateDecryptFailed, "tampered ciphertext should return ErrStateDecryptFailed")
}

// TestStateStore_Get_LegacyPlaintextFallback puts a raw JSON blob (no version
// prefix) directly into miniredis, then calls Get with encryption enabled and
// verifies the state is decoded successfully via the legacy fallback path.
func TestStateStore_Get_LegacyPlaintextFallback(t *testing.T) {
	s, mr := newEncryptedTestStore(t, "test-password-legacy")
	ctx := context.Background()

	// Build the legacy (plaintext) state.
	legacy := sampleState("upload-legacy-plaintext")
	rawJSON, err := json.Marshal(legacy)
	require.NoError(t, err)

	// Write the raw JSON directly into miniredis, bypassing the encrypted path.
	key := uploadKey(legacy.UploadID)
	mr.HSet(key, fieldMeta, string(rawJSON))

	// Get should succeed via legacy fallback.
	got, err := s.Get(ctx, legacy.UploadID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, legacy.UploadID, got.UploadID)
	assert.Equal(t, legacy.Bucket, got.Bucket)
	assert.Equal(t, legacy.Key, got.Key)
}

// TestDeriveStateAEADKey_DifferentPasswords verifies that two different
// passwords produce different derived keys.
func TestDeriveStateAEADKey_DifferentPasswords(t *testing.T) {
	key1 := deriveStateAEADKey("password-alpha")
	key2 := deriveStateAEADKey("password-beta")

	require.Len(t, key1, 32, "derived key should be 32 bytes")
	require.Len(t, key2, 32, "derived key should be 32 bytes")
	assert.False(t, bytes.Equal(key1, key2), "different passwords must produce different keys")
}

// TestDeriveStateAEADKey_Deterministic verifies that the same password always
// produces the same key (HKDF-Extract is deterministic for fixed salt+input).
func TestDeriveStateAEADKey_Deterministic(t *testing.T) {
	key1 := deriveStateAEADKey("deterministic-password")
	key2 := deriveStateAEADKey("deterministic-password")
	assert.True(t, bytes.Equal(key1, key2), "same password must produce identical keys")
}

// TestValkeyConfig_Validate_MissingEnvVar creates a store with EncryptState=true
// and EncryptionPasswordEnv pointing to an unset env var, then verifies that
// NewValkeyStateStore returns an error.
func TestValkeyConfig_Validate_MissingEnvVar(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()

	// Ensure the env var does NOT exist.
	t.Setenv("VALKEY_ENC_TEST_MISSING_VAR", "")

	trueVal := true
	cfg := config.ValkeyConfig{
		Addr:                   mr.Addr(),
		EncryptState:           &trueVal,
		EncryptionPasswordEnv:  "VALKEY_ENC_TEST_MISSING_VAR",
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             60,
		DialTimeout:            2 * time.Second,
		ReadTimeout:            1 * time.Second,
		WriteTimeout:           1 * time.Second,
		PoolSize:               2,
	}
	_, err := NewValkeyStateStore(ctx, cfg, "" /* no fallback password */)
	require.Error(t, err, "should fail when encryption password env var is empty")
	assert.ErrorIs(t, err, ErrStateUnavailable)
}

// TestStateStore_Close_ZeroizesKey creates a store, calls Close(), then
// verifies that the stateKey has been zeroed and set to nil.
func TestStateStore_Close_ZeroizesKey(t *testing.T) {
	s, _ := newEncryptedTestStore(t, "test-password-close")

	require.NotNil(t, s.stateKey, "stateKey should be non-nil before Close")
	require.NoError(t, s.Close())

	// After Close, stateKey should be nil (zeroized in Close()).
	assert.Nil(t, s.stateKey, "stateKey should be nil after Close (zeroized)")
}

// TestStateStore_CreateGetList_WithEncryption exercises the full
// Create → Get → List cycle with encryption enabled. It also verifies that
// no plaintext bucket/key names appear in the raw Valkey hash value.
func TestStateStore_CreateGetList_WithEncryption(t *testing.T) {
	s, mr := newEncryptedTestStore(t, "test-password-full")
	ctx := context.Background()

	state1 := sampleState("upload-enc-full-1")
	state1.Bucket = "secret-bucket"
	state1.Key = "very/secret/key.bin"

	state2 := sampleState("upload-enc-full-2")
	state2.Bucket = "another-bucket"

	// Create both uploads.
	require.NoError(t, s.Create(ctx, state1))
	require.NoError(t, s.Create(ctx, state2))

	// --- Verify raw Valkey values contain no plaintext secrets ---
	key1 := uploadKey(state1.UploadID)
	rawMeta1 := mr.HGet(key1, fieldMeta)
	assert.NotContains(t, rawMeta1, "secret-bucket", "bucket name must not appear in raw Valkey value")
	assert.NotContains(t, rawMeta1, "very/secret/key.bin", "object key must not appear in raw Valkey value")

	// --- Get ---
	got, err := s.Get(ctx, state1.UploadID)
	require.NoError(t, err)
	assert.Equal(t, state1.UploadID, got.UploadID)
	assert.Equal(t, state1.Bucket, got.Bucket)
	assert.Equal(t, state1.Key, got.Key)
	assert.Equal(t, state1.WrappedDEK, got.WrappedDEK)

	// --- List ---
	states, err := s.List(ctx)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(states), 2)

	found := make(map[string]bool)
	for _, st := range states {
		found[st.UploadID] = true
	}
	assert.True(t, found[state1.UploadID], "state1 should appear in list")
	assert.True(t, found[state2.UploadID], "state2 should appear in list")

	// --- AppendPart ---
	require.NoError(t, s.AppendPart(ctx, state1.UploadID, PartRecord{
		PartNumber: 1,
		ETag:       `"etag1"`,
		PlainLen:   1024,
		EncLen:     1040,
		ChunkCount: 1,
	}))

	got2, err := s.Get(ctx, state1.UploadID)
	require.NoError(t, err)
	assert.Len(t, got2.Parts, 1)

	// --- Delete ---
	require.NoError(t, s.Delete(ctx, state1.UploadID))
	_, err = s.Get(ctx, state1.UploadID)
	assert.ErrorIs(t, err, ErrUploadNotFound)
}

// TestStateStore_DecryptState_TooShort verifies that ciphertexts shorter than
// the minimum (1 + 12 + 16 = 29 bytes) are rejected with ErrStateDecryptFailed.
func TestStateStore_DecryptState_TooShort(t *testing.T) {
	s, _ := newEncryptedTestStore(t, "test-password-tooshort")

	cases := []struct {
		name string
		ct   []byte
	}{
		{"empty", []byte{}},
		{"one byte", []byte{stateEncryptionVersionV1}},
		{"28 bytes", make([]byte, 28)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.DecryptState(tc.ct)
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrStateDecryptFailed)
		})
	}
}

// TestStateStore_DecryptState_UnknownVersion verifies that a ciphertext with an
// unknown version byte returns ErrStateDecryptFailed.
func TestStateStore_DecryptState_UnknownVersion(t *testing.T) {
	s, _ := newEncryptedTestStore(t, "test-password-version")

	// Minimum-length ciphertext with version byte 0x02 (unknown).
	ct := make([]byte, stateEncryptionVersionLen+stateEncryptionNonceLen+stateEncryptionTagLen)
	ct[0] = 0x02

	_, err := s.DecryptState(ct)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStateDecryptFailed)
}

// FuzzStateEncryption is a fuzz test that feeds random bytes to DecryptState and
// verifies it never panics (only returns errors on invalid inputs), and that
// DecryptState(EncryptState(p)) == p for valid inputs.
func FuzzStateEncryption(f *testing.F) {
	// Add seed corpus.
	f.Add([]byte(`{"upload_id":"fuzz","bucket":"b","key":"k"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte("short"))
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0x00})

	s := &ValkeyStateStore{
		stateKey:     deriveStateAEADKey("fuzz-password"),
		encryptState: true,
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// DecryptState on arbitrary bytes must never panic.
		_, _ = s.DecryptState(data)

		// For non-empty inputs, EncryptState must succeed and round-trip.
		if len(data) > 0 {
			ct, err := s.EncryptState(data)
			if err != nil {
				return
			}
			recovered, err := s.DecryptState(ct)
			if err != nil {
				t.Errorf("DecryptState(EncryptState(data)) failed: %v", err)
				return
			}
			if !bytes.Equal(data, recovered) {
				t.Errorf("round-trip mismatch: got %q, want %q", recovered, data)
			}
		}
	})
}
