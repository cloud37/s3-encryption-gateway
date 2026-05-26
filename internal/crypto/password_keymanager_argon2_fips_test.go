//go:build fips

package crypto

import (
	"errors"
	"testing"
)

func TestPasswordKM_Argon2id_FIPSRejected(t *testing.T) {
	_, err := NewPasswordKeyManager(
		[]byte("test-password-long-enough"),
		WithPasswordKMArgon2id(2, 19456, 1),
	)
	if err == nil {
		t.Fatal("expected error from NewPasswordKeyManager with Argon2id in FIPS build")
	}
	if !errors.Is(err, ErrAlgorithmNotApproved) {
		t.Errorf("expected ErrAlgorithmNotApproved, got %v", err)
	}
}
