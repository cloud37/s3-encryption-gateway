package harness

import (
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func TestNewOptions_DefaultAndOverrideKDFLimits(t *testing.T) {
	o := newOptions()
	if o.kdfDecryptLimits != crypto.DefaultKDFLimits() {
		t.Fatalf("default limits = %+v, want %+v", o.kdfDecryptLimits, crypto.DefaultKDFLimits())
	}
	o.kdfDecryptLimits = crypto.KDFLimits{PBKDF2MaxIterations: 100000, Argon2idMaxTime: 1, Argon2idMaxMemory: 1, Argon2idMaxThreads: 1}
	if o.kdfDecryptLimits.PBKDF2MaxIterations != 100000 || o.kdfDecryptLimits.Argon2idMaxMemory != 1 {
		t.Fatalf("explicit override was not retained: %+v", o.kdfDecryptLimits)
	}
}
