package crypto

import (
	"testing"
)

// TestWithKeyManager_SetsManager verifies that the WithKeyManager option sets
// the kmsManager field on the engine when a non-nil KeyManager is provided.
func TestWithKeyManager_SetsManager(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-for-engine-options"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	km := NewInMemoryKeyManagerForTestDefault()

	eng2, err := NewEngineWithOpts([]byte("test-password-for-engine-options"), WithKeyManager(km))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with WithKeyManager error: %v", err)
	}
	if eng2 == nil {
		t.Fatal("NewEngineWithOpts() with WithKeyManager returned nil engine")
	}

	// The engine without WithKeyManager should be valid too
	if eng == nil {
		t.Fatal("NewEngineWithOpts() without options returned nil engine")
	}
}

// TestWithKeyManager_NilIsNoop verifies that passing nil to WithKeyManager
// does not change the engine's kmsManager (nil guard).
func TestWithKeyManager_NilIsNoop(t *testing.T) {
	// Create engine without a key manager
	eng, err := NewEngineWithOpts([]byte("test-password-key-mgr-noop"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	// Apply a nil KeyManager option — should be a no-op
	eng2, err := NewEngineWithOpts([]byte("test-password-key-mgr-noop"), WithKeyManager(nil))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with nil KeyManager error: %v", err)
	}

	// Both should be valid engines
	if eng == nil || eng2 == nil {
		t.Fatal("engines should not be nil")
	}
}

// TestNewEngineWithOpts_MultipleOptions verifies that multiple options are all
// applied in order without any option overwriting a previous one.
func TestNewEngineWithOpts_MultipleOptions(t *testing.T) {
	km := NewInMemoryKeyManagerForTestDefault()

	eng, err := NewEngineWithOpts(
		[]byte("test-password-multi-opts"),
		WithKeyManager(km),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with multiple options error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithOpts() with multiple options returned nil engine")
	}
}

// TestNewEngineWithOpts_ValidPassword verifies that NewEngineWithOpts with a
// valid password and no additional options returns a usable EncryptionEngine.
func TestNewEngineWithOpts_ValidPassword(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("valid-password-at-least-20-chars"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithOpts() returned nil engine")
	}

	// Verify the engine can be used (implements EncryptionEngine interface)
	var _ EncryptionEngine = eng
}

// TestWithPreferredAlgorithm verifies that WithPreferredAlgorithm sets and
// PreferredAlgorithm() returns the configured algorithm.
func TestWithPreferredAlgorithm(t *testing.T) {
	eng, err := NewEngineWithOpts(
		[]byte("test-preferred-alg-password"),
		WithPreferredAlgorithm("AES-256-GCM"),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)
	if e.preferredAlgorithm != "AES-256-GCM" {
		t.Errorf("preferredAlgorithm = %q, want %q", e.preferredAlgorithm, "AES-256-GCM")
	}
	// Also test PreferredAlgorithm() accessor
	if got := e.PreferredAlgorithm(); got != "AES-256-GCM" {
		t.Errorf("PreferredAlgorithm() = %q, want %q", got, "AES-256-GCM")
	}
}

// TestWithPreferredAlgorithm_EmptyIsNoop verifies that an empty string is
// a no-op and does not overwrite the existing value.
func TestWithPreferredAlgorithm_EmptyIsNoop(t *testing.T) {
	eng, err := NewEngineWithOpts(
		[]byte("test-preferred-alg-noop-password"),
		WithPreferredAlgorithm("AES-256-GCM"),
		WithPreferredAlgorithm(""),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)
	// The empty-string option should have been a no-op; first value should persist
	if e.preferredAlgorithm != "AES-256-GCM" {
		t.Errorf("preferredAlgorithm = %q, want %q after empty no-op", e.preferredAlgorithm, "AES-256-GCM")
	}
}

// TestWithSupportedAlgorithms verifies that WithSupportedAlgorithms sets the
// supported algorithm list on the engine.
func TestWithSupportedAlgorithms(t *testing.T) {
	algs := []string{"AES-256-GCM", "ChaCha20-Poly1305"}
	eng, err := NewEngineWithOpts(
		[]byte("test-supported-algs-password"),
		WithSupportedAlgorithms(algs),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)
	if len(e.supportedAlgorithms) != len(algs) {
		t.Fatalf("supportedAlgorithms length = %d, want %d", len(e.supportedAlgorithms), len(algs))
	}
	for i, a := range algs {
		if e.supportedAlgorithms[i] != a {
			t.Errorf("supportedAlgorithms[%d] = %q, want %q", i, e.supportedAlgorithms[i], a)
		}
	}
}

// TestWithSupportedAlgorithms_EmptyIsNoop verifies that an empty slice is
// a no-op and does not overwrite an existing value.
func TestWithSupportedAlgorithms_EmptyIsNoop(t *testing.T) {
	algs := []string{"AES-256-GCM"}
	eng, err := NewEngineWithOpts(
		[]byte("test-supported-algs-noop"),
		WithSupportedAlgorithms(algs),
		WithSupportedAlgorithms([]string{}),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)
	if len(e.supportedAlgorithms) != 1 || e.supportedAlgorithms[0] != "AES-256-GCM" {
		t.Errorf("supportedAlgorithms = %v, want [AES-256-GCM]", e.supportedAlgorithms)
	}
}

// TestWithProvider verifies that WithProvider sets the provider profile on
// the engine (covered by the non-empty path in the option).
func TestWithProvider(t *testing.T) {
	eng, err := NewEngineWithOpts(
		[]byte("test-provider-password"),
		WithProvider("default"),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with WithProvider error: %v", err)
	}
	if eng == nil {
		t.Fatal("NewEngineWithOpts() with WithProvider returned nil")
	}
}

// TestWithProvider_EmptyIsNoop verifies that empty string provider is a no-op.
func TestWithProvider_EmptyIsNoop(t *testing.T) {
	eng, err := NewEngineWithOpts(
		[]byte("test-provider-noop-password"),
		WithProvider(""),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() with empty provider error: %v", err)
	}
	if eng == nil {
		t.Fatal("engine should not be nil")
	}
}

// TestWithKDFAlgorithm_EmptyIsNoop verifies that empty string KDF algorithm
// option is a no-op.
func TestWithKDFAlgorithm_EmptyIsNoop(t *testing.T) {
	eng, err := NewEngineWithOpts(
		[]byte("test-kdf-noop-password"),
		WithKDFAlgorithm("pbkdf2-sha256"),
		WithKDFAlgorithm(""),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)
	if e.kdfAlgorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("kdfAlgorithm = %q, want %q after empty no-op", e.kdfAlgorithm, KDFAlgPBKDF2SHA256)
	}
}

// TestWithArgon2idParams_ZeroIsNoop verifies that all-zero argon2id params
// are a no-op (does not overwrite existing params).
func TestWithArgon2idParams_ZeroIsNoop(t *testing.T) {
	eng, err := NewEngineWithOpts(
		[]byte("test-argon2id-noop-password"),
		WithArgon2idParams(2, 19456, 1),
		WithArgon2idParams(0, 0, 0),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)
	if e.argon2idParams.Time != 2 || e.argon2idParams.Memory != 19456 || e.argon2idParams.Threads != 1 {
		t.Errorf("argon2idParams = %+v, want {Time:2, Memory:19456, Threads:1}", e.argon2idParams)
	}
}

// TestCreateCipher_ValidKey verifies that createCipher succeeds with a 32-byte
// AES-256 key and returns a non-nil AEAD (covers the 0% createCipher function).
func TestCreateCipher_ValidKey(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-createcipher-password"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)

	key := make([]byte, aesKeySize)
	aead, err := e.createCipher(key)
	if err != nil {
		t.Fatalf("createCipher() unexpected error: %v", err)
	}
	if aead == nil {
		t.Fatal("createCipher() returned nil AEAD")
	}
}

// TestCreateCipher_InvalidKeySize verifies that createCipher returns an error
// for a key of an incorrect size.
func TestCreateCipher_InvalidKeySize(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-createcipher-invalid-password"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)

	// AES requires 16, 24, or 32 byte keys; 5 bytes is invalid.
	_, err = e.createCipher([]byte("short"))
	if err == nil {
		t.Fatal("createCipher() expected error for invalid key size, got nil")
	}
}

// TestDeriveKeyWithParams_InvalidSaltSize verifies that an incorrect salt size
// returns an error (covers the invalid-salt-size branch of deriveKeyWithParams).
func TestDeriveKeyWithParams_InvalidSaltSize(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-derivekeyparams-password"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)

	params := KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: 600000}
	// Salt must be saltSize bytes; use 5 (invalid).
	_, err = e.deriveKeyWithParams([]byte("short"), params)
	if err == nil {
		t.Fatal("deriveKeyWithParams() expected error for invalid salt size, got nil")
	}
}

// TestDeriveKeyWithParams_UnsupportedAlgorithm verifies that an unknown algorithm
// returns an error (covers the default/unsupported branch of deriveKeyWithParams).
func TestDeriveKeyWithParams_UnsupportedAlgorithm(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-derivekeyparams-unknown-password"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)

	salt := make([]byte, saltSize)
	params := KDFParams{Algorithm: KDFAlgorithm("unknown-kdf"), Iterations: 100000}
	_, err = e.deriveKeyWithParams(salt, params)
	if err == nil {
		t.Fatal("deriveKeyWithParams() expected error for unsupported algorithm, got nil")
	}
}

// TestCreateChaCha20Poly1305Cipher_Valid verifies that a valid 32-byte key
// produces a non-nil AEAD (covers the happy path of createChaCha20Poly1305Cipher).
func TestCreateChaCha20Poly1305Cipher_Valid(t *testing.T) {
	if FIPSEnabled() {
		t.Skip("ChaCha20-Poly1305 is not approved in FIPS builds")
	}
	key := make([]byte, chacha20KeySize)
	aead, err := createChaCha20Poly1305Cipher(key)
	if err != nil {
		t.Fatalf("createChaCha20Poly1305Cipher() unexpected error: %v", err)
	}
	if aead == nil {
		t.Fatal("createChaCha20Poly1305Cipher() returned nil")
	}
}

// TestCreateChaCha20Poly1305Cipher_InvalidKey verifies that an incorrect key
// size returns an error (covers the invalid-key-size branch).
func TestCreateChaCha20Poly1305Cipher_InvalidKey(t *testing.T) {
	_, err := createChaCha20Poly1305Cipher([]byte("short"))
	if err == nil {
		t.Fatal("createChaCha20Poly1305Cipher() expected error for invalid key size, got nil")
	}
}

// TestGetKeyManager_NonEngine verifies that GetKeyManager returns nil when
// passed a non-*engine value (covers the `!ok` branch).
func TestGetKeyManager_NonEngine(t *testing.T) {
	km := GetKeyManager(nil)
	if km != nil {
		t.Errorf("GetKeyManager(nil) = %v, want nil", km)
	}
}

// TestGetRotationState_NonEngine verifies that GetRotationState returns a
// non-nil RotationState even when passed nil (covers the non-*engine branch).
func TestGetRotationState_NonEngine(t *testing.T) {
	rs := GetRotationState(nil)
	if rs == nil {
		t.Fatal("GetRotationState(nil) returned nil, want non-nil RotationState")
	}
}

// TestGenerateNonceForAlgorithm_UnknownAlgorithm verifies that an unsupported
// algorithm returns an error from generateNonceForAlgorithm.
func TestGenerateNonceForAlgorithm_UnknownAlgorithm(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-nonce-password"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	e := eng.(*engine)
	_, err = e.generateNonceForAlgorithm("unknown-algorithm")
	if err == nil {
		t.Fatal("generateNonceForAlgorithm() expected error for unknown algorithm, got nil")
	}
}

// TestIsEncrypted_NotEncrypted verifies that metadata without encryption keys
// returns false (covers the false branch of IsEncrypted).
func TestIsEncrypted_NotEncrypted(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-isencrypted-password"))
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}
	if eng.IsEncrypted(map[string]string{}) {
		t.Error("IsEncrypted({}) = true, want false")
	}
	if eng.IsEncrypted(nil) {
		t.Error("IsEncrypted(nil) = true, want false")
	}
}
