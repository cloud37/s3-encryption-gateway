//go:build fips

package config

import (
	"strings"
	"testing"
)

// TestConfig_Validate_Argon2id_FIPS_Rejected verifies that a FIPS build
// rejects argon2id at config-validation time (before the engine is even
// constructed).  This complements TestArgon2id_Rejected_InFIPSBuild in the
// crypto package, which tests the low-level KDF gate.
func TestConfig_Validate_Argon2id_FIPS_Rejected(t *testing.T) {
	cfg := &Config{}
	cfg.ListenAddr = ":8080"
	cfg.Auth.Credentials = []GatewayCredential{{AccessKey: "ak", SecretKey: "sk"}}
	cfg.Backend.AccessKey = "bk"
	cfg.Backend.SecretKey = "bs"
	cfg.Encryption.Password = "test-password"
	cfg.Encryption.KDF.Algorithm = "argon2id"
	cfg.Encryption.KDF.Argon2id = Argon2idConfig{Time: 2, Memory: 19456, Threads: 1}
	cfg.Encryption.KDF.PBKDF2 = PBKDF2Config{Iterations: 600000}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error in FIPS build when algorithm is argon2id, got nil")
	}
	if !strings.Contains(err.Error(), "fips") && !strings.Contains(err.Error(), "FIPS") && !strings.Contains(err.Error(), "not approved") {
		t.Errorf("error message should mention FIPS or approval status; got: %v", err)
	}
}

// TestConfig_Validate_PBKDF2_FIPS_Allowed verifies that pbkdf2-sha256 is
// still accepted in a FIPS build (the approved alternative).
func TestConfig_Validate_PBKDF2_FIPS_Allowed(t *testing.T) {
	cfg := &Config{}
	cfg.ListenAddr = ":8080"
	cfg.Auth.Credentials = []GatewayCredential{{AccessKey: "ak", SecretKey: "sk"}}
	cfg.Backend.AccessKey = "bk"
	cfg.Backend.SecretKey = "bs"
	cfg.Encryption.Password = "test-password"
	cfg.Encryption.KDF.Algorithm = "pbkdf2-sha256"
	cfg.Encryption.KDF.PBKDF2 = PBKDF2Config{Iterations: 600000}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() unexpected error for pbkdf2-sha256 in FIPS build: %v", err)
	}
}
