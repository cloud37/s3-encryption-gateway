package crypto

import (
	"fmt"
	"testing"
)

func TestFormatKDFParams_PBKDF2(t *testing.T) {
	p := KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: 100000}
	got := FormatKDFParams(p)
	want := "pbkdf2-sha256:100000"
	if got != want {
		t.Errorf("FormatKDFParams() = %q, want %q", got, want)
	}
}

func TestFormatKDFParams_600k(t *testing.T) {
	p := KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: 600000}
	got := FormatKDFParams(p)
	want := "pbkdf2-sha256:600000"
	if got != want {
		t.Errorf("FormatKDFParams() = %q, want %q", got, want)
	}
}

func TestParseKDFParams_Empty(t *testing.T) {
	p, err := ParseKDFParams("")
	if err != nil {
		t.Fatalf("ParseKDFParams(\"\") unexpected error: %v", err)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
	if p.Iterations != 100000 {
		t.Errorf("Iterations = %d, want %d", p.Iterations, 100000)
	}
}

func TestParseKDFParams_100k(t *testing.T) {
	raw := "pbkdf2-sha256:100000"
	p, err := ParseKDFParams(raw)
	if err != nil {
		t.Fatalf("ParseKDFParams(%q) unexpected error: %v", raw, err)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
	if p.Iterations != 100000 {
		t.Errorf("Iterations = %d, want %d", p.Iterations, 100000)
	}
	// Round-trip
	got := FormatKDFParams(p)
	if got != raw {
		t.Errorf("round-trip: FormatKDFParams() = %q, want %q", got, raw)
	}
}

func TestParseKDFParams_600k(t *testing.T) {
	raw := "pbkdf2-sha256:600000"
	p, err := ParseKDFParams(raw)
	if err != nil {
		t.Fatalf("ParseKDFParams(%q) unexpected error: %v", raw, err)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
	if p.Iterations != 600000 {
		t.Errorf("Iterations = %d, want %d", p.Iterations, 600000)
	}
	got := FormatKDFParams(p)
	if got != raw {
		t.Errorf("round-trip: FormatKDFParams() = %q, want %q", got, raw)
	}
}

func TestParseKDFParams_ArbitraryValue(t *testing.T) {
	raw := "pbkdf2-sha256:750000"
	p, err := ParseKDFParams(raw)
	if err != nil {
		t.Fatalf("ParseKDFParams(%q) unexpected error: %v", raw, err)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
	if p.Iterations != 750000 {
		t.Errorf("Iterations = %d, want %d", p.Iterations, 750000)
	}
	got := FormatKDFParams(p)
	if got != raw {
		t.Errorf("round-trip: FormatKDFParams() = %q, want %q", got, raw)
	}
}

func TestParseKDFParams_Invalid_NoColon(t *testing.T) {
	_, err := ParseKDFParams("pbkdf2-sha256")
	if err == nil {
		t.Fatal("expected error for missing colon")
	}
}

func TestParseKDFParams_Invalid_NegativeIter(t *testing.T) {
	_, err := ParseKDFParams("pbkdf2-sha256:-1")
	if err == nil {
		t.Fatal("expected error for negative iterations")
	}
}

func TestParseKDFParams_Invalid_ZeroIter(t *testing.T) {
	_, err := ParseKDFParams("pbkdf2-sha256:0")
	if err == nil {
		t.Fatal("expected error for zero iterations")
	}
}

func TestParseKDFParams_Invalid_UnknownAlg(t *testing.T) {
	_, err := ParseKDFParams("sha3:100000")
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
}

func TestParseKDFParams_Argon2id_WellFormed(t *testing.T) {
	raw := "argon2id:2:19456:1"
	p, err := ParseKDFParams(raw)
	if err != nil {
		t.Fatalf("ParseKDFParams(%q) unexpected error: %v", raw, err)
	}
	if p.Algorithm != KDFAlgArgon2id {
		t.Errorf("Algorithm = %q, want %q", p.Algorithm, KDFAlgArgon2id)
	}
	if p.Time != 2 {
		t.Errorf("Time = %d, want %d", p.Time, 2)
	}
	if p.Memory != 19456 {
		t.Errorf("Memory = %d, want %d", p.Memory, 19456)
	}
	if p.Threads != 1 {
		t.Errorf("Threads = %d, want %d", p.Threads, 1)
	}
}

func TestParseKDFParams_Argon2id_MissingFields(t *testing.T) {
	_, err := ParseKDFParams("argon2id:2")
	if err == nil {
		t.Fatal("expected error for missing fields")
	}
}

func TestParseKDFParams_Argon2id_ZeroMemory(t *testing.T) {
	_, err := ParseKDFParams("argon2id:2:0:1")
	if err == nil {
		t.Fatal("expected error for zero memory")
	}
}

func TestRoundTrip_PBKDF2_Various(t *testing.T) {
	tests := []int{100000, 200000, 600000, 1200000}
	for _, iterations := range tests {
		t.Run(fmt.Sprintf("%d", iterations), func(t *testing.T) {
			p := KDFParams{Algorithm: KDFAlgPBKDF2SHA256, Iterations: iterations}
			raw := FormatKDFParams(p)
			got, err := ParseKDFParams(raw)
			if err != nil {
				t.Fatalf("ParseKDFParams(%q) error: %v", raw, err)
			}
			if got != p {
				t.Errorf("round-trip mismatch: got %+v, want %+v", got, p)
			}
		})
	}
}

func TestArgon2id_KAT(t *testing.T) {
	// Known-answer test for argon2id derivation.
	// Computed with: argon2.IDKey([]byte("test-password"), []byte("test-salt"), 2, 19456, 1, 32)
	// Verified offline against the reference implementation.
	password := []byte("test-password")
	salt := []byte("test-salt")
	params := KDFParams{Algorithm: KDFAlgArgon2id, Time: 2, Memory: 19456, Threads: 1}

	key, err := deriveKeyArgon2id(password, salt, params)
	if err != nil {
		t.Fatalf("deriveKeyArgon2id() unexpected error: %v", err)
	}
	if len(key) != aesKeySize {
		t.Fatalf("key length = %d, want %d", len(key), aesKeySize)
	}
	// Verify the key matches the expected output.
	// Computed with argon2.IDKey([]byte("test-password"), []byte("test-salt"), 2, 19456, 1, 32).
	want := []byte{
		0xb6, 0xa9, 0x2d, 0xb8, 0x01, 0x68, 0x92, 0xbe,
		0x1a, 0xd0, 0xf3, 0x56, 0x2f, 0xc9, 0x6e, 0x9f,
		0xc1, 0xae, 0x30, 0x35, 0x5e, 0x59, 0x5f, 0xa7,
		0xdf, 0xca, 0x3d, 0x95, 0x55, 0x5d, 0x27, 0xe3,
	}
	for i := range key {
		if key[i] != want[i] {
			t.Fatalf("key[%d] = 0x%02x, want 0x%02x", i, key[i], want[i])
		}
	}
}

func TestArgon2id_RoundTrip(t *testing.T) {
	password := []byte("test-password-2")
	salt := []byte("test-salt-2")
	params := KDFParams{Algorithm: KDFAlgArgon2id, Time: 2, Memory: 19456, Threads: 1}

	key1, err := deriveKeyArgon2id(password, salt, params)
	if err != nil {
		t.Fatalf("first deriveKeyArgon2id() unexpected error: %v", err)
	}

	key2, err := deriveKeyArgon2id(password, salt, params)
	if err != nil {
		t.Fatalf("second deriveKeyArgon2id() unexpected error: %v", err)
	}

	if len(key1) != aesKeySize {
		t.Fatalf("key1 length = %d, want %d", len(key1), aesKeySize)
	}
	if len(key2) != aesKeySize {
		t.Fatalf("key2 length = %d, want %d", len(key2), aesKeySize)
	}
	for i := range key1 {
		if key1[i] != key2[i] {
			t.Fatalf("determinism mismatch at index %d: 0x%02x vs 0x%02x", i, key1[i], key2[i])
		}
	}
}

func TestArgon2id_InvalidMemory(t *testing.T) {
	password := []byte("password")
	salt := []byte("salt")
	params := KDFParams{Algorithm: KDFAlgArgon2id, Time: 2, Memory: 0, Threads: 1}

	_, err := deriveKeyArgon2id(password, salt, params)
	if err == nil {
		t.Fatal("expected error for zero memory")
	}
}

func TestFormatKDFParams_UnknownAlgorithm(t *testing.T) {
	p := KDFParams{Algorithm: KDFAlgorithm("unknown-alg"), Iterations: 100000}
	got := FormatKDFParams(p)
	if got != "" {
		t.Errorf("FormatKDFParams() for unknown algorithm = %q, want %q", got, "")
	}
}

func TestParseKDFParams_PBKDF2_TooManyParts(t *testing.T) {
	_, err := ParseKDFParams("pbkdf2-sha256:100000:extra")
	if err == nil {
		t.Fatal("expected error for pbkdf2-sha256 with too many parts")
	}
}

func TestParseKDFParams_PBKDF2_InvalidIterNonNumeric(t *testing.T) {
	_, err := ParseKDFParams("pbkdf2-sha256:notanumber")
	if err == nil {
		t.Fatal("expected error for non-numeric PBKDF2 iteration count")
	}
}

func TestParseKDFParams_Argon2id_InvalidTime(t *testing.T) {
	_, err := ParseKDFParams("argon2id:notanumber:19456:1")
	if err == nil {
		t.Fatal("expected error for non-numeric argon2id time")
	}
}

func TestParseKDFParams_Argon2id_InvalidMemory(t *testing.T) {
	_, err := ParseKDFParams("argon2id:2:notanumber:1")
	if err == nil {
		t.Fatal("expected error for non-numeric argon2id memory")
	}
}

func TestParseKDFParams_Argon2id_InvalidThreads(t *testing.T) {
	_, err := ParseKDFParams("argon2id:2:19456:notanumber")
	if err == nil {
		t.Fatal("expected error for non-numeric argon2id threads")
	}
}

func TestDefaultKDFParams_LowIterations(t *testing.T) {
	// When pbkdf2Iterations is below the minimum, should reset to DefaultPBKDF2Iterations.
	p := DefaultKDFParams(1000)
	if p.Iterations != DefaultPBKDF2Iterations {
		t.Errorf("DefaultKDFParams(1000).Iterations = %d, want %d", p.Iterations, DefaultPBKDF2Iterations)
	}
	if p.Algorithm != KDFAlgPBKDF2SHA256 {
		t.Errorf("DefaultKDFParams(1000).Algorithm = %q, want %q", p.Algorithm, KDFAlgPBKDF2SHA256)
	}
}

func TestDefaultKDFParams_SufficientIterations(t *testing.T) {
	p := DefaultKDFParams(600000)
	if p.Iterations != 600000 {
		t.Errorf("DefaultKDFParams(600000).Iterations = %d, want 600000", p.Iterations)
	}
}

func TestArgon2id_MismatchedPasswordLength(t *testing.T) {
	// Verify derivation works with various password lengths (no minimum/maximum).
	params := KDFParams{Algorithm: KDFAlgArgon2id, Time: 2, Memory: 19456, Threads: 1}
	salt := []byte("fixed-salt")

	tests := [][]byte{
		[]byte("a"),
		[]byte("a-long-password-that-exceeds-thirty-two-bytes-in-length"),
		[]byte(""),
	}
	for _, pw := range tests {
		key, err := deriveKeyArgon2id(pw, salt, params)
		if err != nil {
			t.Fatalf("deriveKeyArgon2id(password=%q) unexpected error: %v", string(pw), err)
		}
		if len(key) != aesKeySize {
			t.Fatalf("key length = %d, want %d for password=%q", len(key), aesKeySize, string(pw))
		}
	}
}
