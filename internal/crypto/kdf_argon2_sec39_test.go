//go:build !fips

package crypto

import (
	"errors"
	"testing"
)

func TestDeriveKeyArgon2id_RejectsBeforeWork(t *testing.T) {
	for _, tc := range []struct {
		p         KDFParams
		parameter string
		want      uint64
		max       uint64
		invalid   bool
	}{{KDFParams{Algorithm: KDFAlgArgon2id, Time: 0, Memory: 1, Threads: 1}, "time", 0, 0, true}, {KDFParams{Algorithm: KDFAlgArgon2id, Time: 1, Memory: 0, Threads: 1}, "memory", 0, 0, true}, {KDFParams{Algorithm: KDFAlgArgon2id, Time: 1, Memory: 1, Threads: 0}, "threads", 0, 0, true}, {KDFParams{Algorithm: KDFAlgArgon2id, Time: 1, Memory: MaxArgon2idMemory, Threads: 1}, "memory", uint64(MaxArgon2idMemory), 65536, false}} {
		_, err := deriveKeyArgon2id([]byte("pw"), make([]byte, saltSize), tc.p)
		var invalid *ErrInvalidKDFParams
		if tc.invalid {
			if !errors.As(err, &invalid) || invalid.Algorithm != KDFAlgArgon2id || invalid.Parameter != tc.parameter {
				t.Fatalf("unexpected invalid error: %+v", err)
			}
		} else {
			var cost *ErrKDFCostTooHigh
			if !errors.As(err, &cost) || cost.Algorithm != KDFAlgArgon2id || cost.Parameter != tc.parameter || cost.Requested != tc.want || cost.Maximum != tc.max {
				t.Fatalf("expected cost error: %v", err)
			}
		}
	}
	limits := DefaultKDFLimits()
	limits.Argon2idMaxTime = 1
	limits.Argon2idMaxThreads = 1
	for _, p := range []KDFParams{{Algorithm: KDFAlgArgon2id, Time: 2, Memory: 1, Threads: 1}, {Algorithm: KDFAlgArgon2id, Time: 1, Memory: 1, Threads: 2}} {
		var cost *ErrKDFCostTooHigh
		if err := ValidateKDFParams(p, limits); !errors.As(err, &cost) || cost.Algorithm != KDFAlgArgon2id {
			t.Fatalf("expected selected-limit error: %v", err)
		}
	}
}
