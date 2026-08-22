package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testDEK      = fixedDEK
	testIVPrefix = fixedIVPrefix
	testUIDHash  = UploadIDHash(fixedUploadID)
)

// TestMPUEncryptDecrypt_RoundTrip verifies full encrypt → decrypt round-trip.
func TestMPUEncryptDecrypt_RoundTrip(t *testing.T) {
	plaintext := bytes.Repeat([]byte("hello world!"), 1000)
	ctx := context.Background()

	reader, encLen, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plaintext), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plaintext)), "AES256GCM")
	require.NoError(t, err)
	assert.Greater(t, encLen, int64(len(plaintext)), "ciphertext must be larger than plaintext")

	ciphertext, err := io.ReadAll(reader)
	require.NoError(t, err)
	assert.Equal(t, encLen, int64(len(ciphertext)), "reported encLen must match actual ciphertext length")

	got, err := DecryptMPUPart(ciphertext, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, "AES256GCM")
	require.NoError(t, err)
	assert.Equal(t, plaintext, got)
}

// TestMPUEncryptDecrypt_MultiPart verifies that different part numbers produce
// independent ciphertexts that each decrypt correctly.
func TestMPUEncryptDecrypt_MultiPart(t *testing.T) {
	ctx := context.Background()
	const numParts = 5
	plain := bytes.Repeat([]byte("abcde"), 5000) // 25 000 bytes per part

	ciphertexts := make([][]byte, numParts)
	for p := 1; p <= numParts; p++ {
		r, encLen, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, int32(p), DefaultChunkSize, int64(len(plain)), "AES256GCM")
		require.NoErrorf(t, err, "part %d", p)
		ct, err := io.ReadAll(r)
		require.NoError(t, err)
		assert.Equal(t, encLen, int64(len(ct)))
		ciphertexts[p-1] = ct
	}

	// All ciphertexts must be distinct (IV differs by part number).
	for i := 0; i < numParts-1; i++ {
		assert.NotEqual(t, ciphertexts[i], ciphertexts[i+1], "parts %d and %d must produce different ciphertexts", i+1, i+2)
	}

	// Each must decrypt correctly.
	for p := 1; p <= numParts; p++ {
		got, err := DecryptMPUPart(ciphertexts[p-1], testDEK, testUIDHash, testIVPrefix, int32(p), DefaultChunkSize, "AES256GCM")
		require.NoErrorf(t, err, "part %d", p)
		assert.Equal(t, plain, got)
	}
}

// TestMPUEncryptDecrypt_TamperDetection verifies that flipping one byte in the
// ciphertext causes authentication failure (GET tamper test).
func TestMPUEncryptDecrypt_TamperDetection(t *testing.T) {
	ctx := context.Background()
	plain := bytes.Repeat([]byte("secret"), 1000)

	r, _, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), "AES256GCM")
	require.NoError(t, err)
	ct, err := io.ReadAll(r)
	require.NoError(t, err)

	// Flip byte 42.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[42] ^= 0xff

	_, err = DecryptMPUPart(tampered, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, "AES256GCM")
	require.Error(t, err, "tampered ciphertext must be rejected")
	assert.Contains(t, err.Error(), "auth failure")
}

// TestNewMPUDecryptReader_Streaming verifies that the streaming reader produces
// the same plaintext as the buffered DecryptMPUPart, and that it processes
// multi-part objects chunk by chunk without requiring the full ciphertext
// to be buffered at once.
func TestNewMPUDecryptReader_Streaming(t *testing.T) {
	ctx := context.Background()
	const numParts = 3
	const plainPerPart = DefaultChunkSize*2 + 1 // 2 full chunks + 1 partial

	var fullCiphertext []byte
	var fullPlain []byte

	// Build a multi-part manifest and encrypt each part.
	parts := make([]MPUPartRecord, numParts)
	var totalPlain int64
	for p := 1; p <= numParts; p++ {
		plain := bytes.Repeat([]byte{byte(p)}, plainPerPart)
		fullPlain = append(fullPlain, plain...)

		r, encLen, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, int32(p), DefaultChunkSize, int64(len(plain)), "AES256GCM")
		require.NoError(t, err)
		ct, err := io.ReadAll(r)
		require.NoError(t, err)
		fullCiphertext = append(fullCiphertext, ct...)

		chunks := int32((int64(plainPerPart) + int64(DefaultChunkSize) - 1) / int64(DefaultChunkSize))
		parts[p-1] = MPUPartRecord{
			PartNumber: int32(p),
			PlainLen:   int64(plainPerPart),
			EncLen:     encLen,
			ChunkCount: chunks,
		}
		totalPlain += int64(plainPerPart)
	}

	h := UploadIDHash(fixedUploadID)
	manifest := &MultipartManifest{
		Version:        1,
		Algorithm:      "AES256GCM",
		ChunkSize:      DefaultChunkSize,
		IVPrefix:       "aabbccddeeff112233445566",
		UploadIDHash:   encodeBase64(h[:]),
		WrappedDEK:     "test",
		Parts:          parts,
		TotalPlainSize: totalPlain,
	}

	// Use the streaming reader.
	r, err := newMPUDecryptReaderV1(ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(fullCiphertext), manifest, testDEK, testUIDHash, testIVPrefix, "AES256GCM")
	require.NoError(t, err)

	// Read in small increments to verify streaming behaviour (no full buffer).
	var got []byte
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
	}

	assert.Equal(t, fullPlain, got, "streaming decrypt must equal buffered decrypt")
}

// TestNewMPUDecryptReader_TamperDetected verifies authentication failure propagates.
func TestNewMPUDecryptReader_TamperDetected(t *testing.T) {
	ctx := context.Background()
	plain := bytes.Repeat([]byte("x"), DefaultChunkSize+1) // 2 chunks

	r, _, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), "AES256GCM")
	require.NoError(t, err)
	ct, err := io.ReadAll(r)
	require.NoError(t, err)

	// Flip byte in second chunk ciphertext.
	ct[DefaultChunkSize+16+5] ^= 0xff

	manifest := &MultipartManifest{
		Version:   1,
		ChunkSize: DefaultChunkSize,
		Parts: []MPUPartRecord{{
			PartNumber: 1,
			PlainLen:   int64(len(plain)),
			EncLen:     int64(len(ct)),
			ChunkCount: 2,
		}},
		TotalPlainSize: int64(len(plain)),
	}

	dr, err := newMPUDecryptReaderV1(ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(ct), manifest, testDEK, testUIDHash, testIVPrefix, "AES256GCM")
	require.NoError(t, err)

	_, err = io.ReadAll(dr)
	require.Error(t, err, "tampered ciphertext must produce an error")
	assert.Contains(t, err.Error(), "auth failure")
}

// TestMPUEncryptDecrypt_EmptyPart checks that an empty part encrypts and decrypts correctly.
func TestMPUEncryptDecrypt_EmptyPart(t *testing.T) {
	ctx := context.Background()

	r, encLen, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(nil), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, 0, "AES256GCM")
	require.NoError(t, err)
	ct, err := io.ReadAll(r)
	require.NoError(t, err)
	assert.Equal(t, encLen, int64(len(ct)))
	assert.Equal(t, int64(0), encLen, "empty part should produce zero ciphertext bytes")

	got, err := DecryptMPUPart(ct, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, "AES256GCM")
	require.NoError(t, err)
	assert.Equal(t, []byte(nil), got)
}

// TestMPUEncryptDecrypt_LegacyAES256GCMString verifies backward compatibility
// with manifests that use the bare string "AES256GCM" (no hyphen).
func TestMPUEncryptDecrypt_LegacyAES256GCMString(t *testing.T) {
	ctx := context.Background()
	plain := bytes.Repeat([]byte("legacy-compat-"), 1000)

	r, encLen, err := newMPUPartEncryptReaderV1(ctx, ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(plain), testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, int64(len(plain)), "AES256GCM")
	require.NoError(t, err)
	ct, err := io.ReadAll(r)
	require.NoError(t, err)

	got, err := DecryptMPUPart(ct, testDEK, testUIDHash, testIVPrefix, 1, DefaultChunkSize, "AES256GCM")
	require.NoError(t, err)
	assert.Equal(t, plain, got)

	// Streaming path must also accept the legacy string.
	manifest := &MultipartManifest{
		Version:      1,
		Algorithm:    "AES256GCM",
		ChunkSize:    DefaultChunkSize,
		IVPrefix:     "aabbccddeeff112233445566",
		UploadIDHash: encodeBase64(testUIDHash[:]),
		WrappedDEK:   "test",
		Parts: []MPUPartRecord{{
			PartNumber: 1,
			PlainLen:   int64(len(plain)),
			EncLen:     encLen,
			ChunkCount: 1,
		}},
		TotalPlainSize: int64(len(plain)),
	}

	dr, err := newMPUDecryptReaderV1(ObjectContext{Bucket: "test-bucket", Key: "test-key"}, [16]byte{}, bytes.NewReader(ct), manifest, testDEK, testUIDHash, testIVPrefix, "AES256GCM")
	require.NoError(t, err)
	gotStream, err := io.ReadAll(dr)
	require.NoError(t, err)
	assert.Equal(t, plain, gotStream)
}
