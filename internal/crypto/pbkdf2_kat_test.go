package crypto

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestPBKDF2KAT verifies that the stdlib crypto/pbkdf2 produces byte-identical
// output to a pre-recorded known-answer test vector. This regression test guards
// against accidental algorithm drift as the stdlib package evolves.
//
// Test vector: PBKDF2-HMAC-SHA256 with the parameters used in gateway key derivation:
// - password: "testpassword"
// - salt: 32 bytes of 0x01
// - iterations: 100000 (compile-time constant pbkdf2Iterations)
// - keyLen: 32 bytes (compile-time constant aesKeySize)
func TestPBKDF2KAT(t *testing.T) {
	const (
		password   = "testpassword"
		iterations = 100000
		keyLen     = 32 // aesKeySize
	)

	// Pre-computed salt: 32 bytes of 0x01
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = 0x01
	}

	// Expected output (pre-recorded from crypto/pbkdf2 with the above parameters)
	// Generated using:
	// salt := make([]byte, 32); for i := range salt { salt[i] = 0x01 }
	// key, _ := pbkdf2.Key(sha256.New, "testpassword", salt, 100000, 32)
	// hex.EncodeToString(key)
	expectedHex := "555408728bbbb92a70c5759b5a514f85a58a2f5067561607831cc759f99b9d07"

	// Derive key using stdlib pbkdf2
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("pbkdf2.Key() failed: %v", err)
	}

	// Verify output matches known-answer test
	actualHex := hex.EncodeToString(key)
	if actualHex != expectedHex {
		t.Errorf("PBKDF2 output mismatch\nexpected: %s\nactual:   %s", expectedHex, actualHex)
	}
}

// TestPBKDF2StringPassword verifies that pbkdf2.Key accepts string passwords
// directly (unlike the x/crypto variant which required []byte conversion).
// This documents the API difference and ensures our call sites use it correctly.
func TestPBKDF2StringPassword(t *testing.T) {
	const (
		password   = "mypassword"
		iterations = 100000
		keyLen     = 32
	)

	salt := []byte("a 32-byte salt for testing only!.")[:32] // 32 bytes
	if len(salt) != 32 {
		t.Fatalf("salt length must be 32, got %d", len(salt))
	}

	// Verify we can pass string password directly
	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("pbkdf2.Key() with string password failed: %v", err)
	}

	if len(key) != keyLen {
		t.Errorf("key length mismatch: expected %d, got %d", keyLen, len(key))
	}
}

// TestPBKDF2KAT_600k verifies PBKDF2-HMAC-SHA256 with 600000 iterations.
func TestPBKDF2KAT_600k(t *testing.T) {
	const (
		password   = "testpassword"
		iterations = 600000
		keyLen     = 32
	)

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = 0x01
	}

	expectedHex := "6172973d78018899fcecd7ba5c454a977f87cd72ea1ce124dfa6cef6fa819108"

	key, err := pbkdf2.Key(sha256.New, password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("pbkdf2.Key() failed: %v", err)
	}

	actualHex := hex.EncodeToString(key)
	if actualHex != expectedHex {
		t.Errorf("PBKDF2 output mismatch\nexpected: %s\nactual:   %s", expectedHex, actualHex)
	}
}
