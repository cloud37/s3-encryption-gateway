//go:build fips

package crypto

import (
	"errors"
	"testing"
)

func TestPasswordKM_PBKDF2DecryptLimits_FIPS(t *testing.T) {
	limits := DefaultKDFLimits()
	limits.PBKDF2MaxIterations = 100000
	_, err := NewPasswordKeyManager([]byte("fips-password-manager"), WithPasswordKMKDFLimits(limits), WithPasswordKMPBKDF2(100001))
	var cost *ErrKDFCostTooHigh
	if !errors.As(err, &cost) {
		t.Fatalf("expected PBKDF2 cost error, got %v", err)
	}
	if _, err := NewPasswordKeyManager([]byte("fips-password-manager"), WithPasswordKMArgon2id(1, 1, 1)); !errors.Is(err, ErrAlgorithmNotApproved) {
		t.Fatalf("expected FIPS Argon2 rejection, got %v", err)
	}
}
