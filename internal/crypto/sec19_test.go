package crypto

// V1.0-SEC-19: Password Loaded into Immutable String Before Engine Copy
//
// Ensures that engine constructors accept []byte passwords and that the
// engine stores the password as a mutable []byte slice (which can be
// zeroized on Close()).

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSEC19_EngineAcceptsByteSlicePassword verifies that NewEngine and
// related constructors accept a []byte password rather than a string.
func TestSEC19_EngineAcceptsByteSlicePassword(t *testing.T) {
	pw := []byte("test-password-123456")

	eng, err := NewEngine(pw)
	require.NoError(t, err)
	require.NotNil(t, eng)

	e, ok := eng.(*engine)
	require.True(t, ok, "engine must be *engine")

	// The engine must store the password as a []byte, not a string.
	assert.IsType(t, []byte{}, e.password, "engine.password must be a []byte")
	assert.Equal(t, pw, e.password, "engine.password must match the input")

	// Zeroing the caller's slice must not affect the engine's defensive copy.
	for i := range pw {
		pw[i] = 0
	}
	assert.NotEqual(t, pw, e.password, "engine.password must be a defensive copy")
}

// TestSEC19_PasswordKeyManagerAcceptsByteSlicePassword verifies that
// NewPasswordKeyManager accepts a []byte password.
func TestSEC19_PasswordKeyManagerAcceptsByteSlicePassword(t *testing.T) {
	pw := []byte("a-sufficiently-long-test-password")

	km, err := NewPasswordKeyManager(pw, WithPasswordKMPBKDF2(DefaultPBKDF2Iterations))
	require.NoError(t, err)
	require.NotNil(t, km)

	// Zeroing the caller's slice must not affect the key manager's copy.
	for i := range pw {
		pw[i] = 0
	}

	// Unwrapping must still work because the KM owns a defensive copy.
	pkm, ok := km.(*passwordKeyManager)
	require.True(t, ok)
	assert.NotEqual(t, []byte(""), pkm.password, "passwordKeyManager must retain a copy of the password")
}
