//go:build !fips

package crypto

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// ErrArgon2NotEnabled is returned when argon2id is parsed from metadata but
// the gateway was not compiled with argon2id support enabled.
// Note: kdf_argon2_default.go provides the real implementation; this sentinel
// is retained for backward compatibility with tests.
var ErrArgon2NotEnabled = errors.New("argon2id KDF is not enabled in this build")

func deriveKeyArgon2id(password, salt []byte, params KDFParams) ([]byte, error) {
	if params.Memory == 0 {
		return nil, fmt.Errorf("argon2id: memory must be > 0")
	}
	key := argon2.IDKey(password, salt, params.Time, params.Memory, params.Threads, aesKeySize)
	return key, nil
}
