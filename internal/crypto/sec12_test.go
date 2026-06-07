package crypto

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shortKeyManager is a mock KeyManager that always returns a 16-byte key,
// which is catastrophically short for AES-256.  This verifies that the
// engine rejects wrong-sized keys instead of padding them.
type shortKeyManager struct{}

func (s *shortKeyManager) Provider() string { return "short" }
func (s *shortKeyManager) WrapKey(ctx context.Context, dek []byte, meta map[string]string) (*KeyEnvelope, error) {
	return &KeyEnvelope{
		KeyID:      "test-key",
		KeyVersion: 1,
		Provider:   "short",
		Ciphertext: []byte("short-ciphertext"),
	}, nil
}
func (s *shortKeyManager) UnwrapKey(ctx context.Context, env *KeyEnvelope, meta map[string]string) ([]byte, error) {
	return make([]byte, 16), nil // intentionally too short
}
func (s *shortKeyManager) HealthCheck(ctx context.Context) error             { return nil }
func (s *shortKeyManager) ActiveKeyVersion(ctx context.Context) (int, error) { return 1, nil }
func (s *shortKeyManager) Close(ctx context.Context) error                   { return nil }

// TestSEC12_Encrypt_KMSShortKey rejects a 16-byte key from generateDataKey.
func TestSEC12_Encrypt_KMSShortKey(t *testing.T) {
	oldGen := generateDataKey
	generateDataKey = func(size int) ([]byte, error) {
		return make([]byte, 16), nil
	}
	defer func() { generateDataKey = oldGen }()

	eng, err := NewEngineWithOpts([]byte("test-password-123456"), WithKeyManager(&shortKeyManager{}))
	require.NoError(t, err)

	_, _, err = eng.Encrypt(context.Background(), strings.NewReader("hello world"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generateDataKey returned unexpected key size")
}

// TestSEC12_Decrypt_KMSShortKey rejects a 16-byte key from the KMS.
func TestSEC12_Decrypt_KMSShortKey(t *testing.T) {
	// Encrypt with a correct KMS first so we have valid metadata.
	goodKM := NewInMemoryKeyManagerForTestDefault()
	goodEng, err := NewEngineWithOpts([]byte("test-password-123456"), WithKeyManager(goodKM))
	require.NoError(t, err)

	reader, meta, err := goodEng.Encrypt(context.Background(), strings.NewReader("hello world"), nil)
	require.NoError(t, err)

	// Decrypt with a short-key KMS.
	badEng, err := NewEngineWithOpts([]byte("test-password-123456"), WithKeyManager(&shortKeyManager{}))
	require.NoError(t, err)

	_, _, err = badEng.Decrypt(context.Background(), reader, meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KMS returned key of size 16, expected 32")
}

// TestSEC12_EncryptChunked_KMSShortKey rejects a 16-byte key in chunked mode.
func TestSEC12_EncryptChunked_KMSShortKey(t *testing.T) {
	oldGen := generateDataKey
	generateDataKey = func(size int) ([]byte, error) {
		return make([]byte, 16), nil
	}
	defer func() { generateDataKey = oldGen }()

	eng, err := NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, DefaultChunkSize)
	require.NoError(t, err)
	e := eng.(*engine)
	e.kmsManager = &shortKeyManager{}

	_, _, err = e.encryptChunked(context.Background(), strings.NewReader("hello world"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "generateDataKey returned unexpected key size")
}

// TestSEC12_DecryptChunked_KMSShortKey rejects a 16-byte key in chunked mode.
func TestSEC12_DecryptChunked_KMSShortKey(t *testing.T) {
	// Encrypt with a correct KMS in chunked mode.
	goodKM := NewInMemoryKeyManagerForTestDefault()
	goodEng, err := NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, DefaultChunkSize)
	require.NoError(t, err)
	goodEng.(*engine).kmsManager = goodKM

	reader, meta, err := goodEng.Encrypt(context.Background(), strings.NewReader("hello world, this is chunked data for testing"), nil)
	require.NoError(t, err)

	// Decrypt with a short-key KMS.
	badEng, err := NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, DefaultChunkSize)
	require.NoError(t, err)
	badEng.(*engine).kmsManager = &shortKeyManager{}

	_, _, err = badEng.Decrypt(context.Background(), reader, meta)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KMS returned key of size 16, expected 32")
}

// TestSEC12_DecryptRange_KMSShortKey rejects a 16-byte key in range decryption.
func TestSEC12_DecryptRange_KMSShortKey(t *testing.T) {
	// Encrypt with a correct KMS in chunked mode.
	goodKM := NewInMemoryKeyManagerForTestDefault()
	goodEng, err := NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, DefaultChunkSize)
	require.NoError(t, err)
	goodEng.(*engine).kmsManager = goodKM

	data := []byte("hello world, this is chunked range data for testing sec12")
	reader, meta, err := goodEng.Encrypt(context.Background(), bytes.NewReader(data), map[string]string{
		"Content-Length": fmt.Sprintf("%d", len(data)),
	})
	require.NoError(t, err)

	encryptedData, err := io.ReadAll(reader)
	require.NoError(t, err)

	// Decrypt range with a short-key KMS.
	badEng, err := NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, DefaultChunkSize)
	require.NoError(t, err)
	badEng.(*engine).kmsManager = &shortKeyManager{}

	_, _, err = badEng.(interface {
		DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, plaintextStart, plaintextEnd int64) (io.Reader, map[string]string, error)
	}).DecryptRange(context.Background(), bytes.NewReader(encryptedData), meta, 0, int64(len(data)-1))

	require.Error(t, err)
	assert.Contains(t, err.Error(), "KMS returned key of size 16, expected 32")
}

// TestSEC12_KMSHappyPath_32ByteKey verifies that a correct 32-byte KMS key works.
func TestSEC12_KMSHappyPath_32ByteKey(t *testing.T) {
	km := NewInMemoryKeyManagerForTestDefault()
	eng, err := NewEngineWithOpts([]byte("test-password-123456"), WithKeyManager(km))
	require.NoError(t, err)

	plaintext := "hello, V1.0-SEC-12 world!"
	reader, meta, err := eng.Encrypt(context.Background(), strings.NewReader(plaintext), nil)
	require.NoError(t, err)

	decReader, _, err := eng.Decrypt(context.Background(), reader, meta)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}

// TestSEC12_DeriveKey_Always32Bytes asserts that PBKDF2 returns exactly 32 bytes.
func TestSEC12_DeriveKey_Always32Bytes(t *testing.T) {
	eng, err := NewEngine([]byte("test-password-123456"))
	require.NoError(t, err)

	salt, err := eng.(*engine).generateSalt()
	require.NoError(t, err)

	key, err := eng.(*engine).deriveKey(salt)
	require.NoError(t, err)
	assert.Equal(t, aesKeySize, len(key), "PBKDF2 must always return exactly 32 bytes")
}

// TestSEC12_PasswordOnly_NoPaddingPathReaches confirms password-only encrypt/decrypt
// round-trips successfully and never touches the former padding code.
func TestSEC12_PasswordOnly_NoPaddingPathReaches(t *testing.T) {
	eng, err := NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, DefaultChunkSize)
	require.NoError(t, err)

	plaintext := strings.Repeat("A", 1024*1024) // 1 MB object
	reader, meta, err := eng.Encrypt(context.Background(), strings.NewReader(plaintext), nil)
	require.NoError(t, err)

	decReader, _, err := eng.Decrypt(context.Background(), reader, meta)
	require.NoError(t, err)

	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(decrypted))
}
