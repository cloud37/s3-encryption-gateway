//go:build conformance

package conformance

import (
	"bytes"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// kdfTestPassword matches the default harness password so that objects written
// directly to the backend can be read back via the gateway.
var kdfTestPassword = []byte("test-encryption-password-123456")

// newEngine100k creates an engine using the legacy 100k PBKDF2 iteration count.
func newEngine100k(t *testing.T) crypto.EncryptionEngine {
	t.Helper()
	eng, err := crypto.NewEngineWithOpts(kdfTestPassword, nil, crypto.WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("newEngine100k: %v", err)
	}
	return eng
}

// newEngine100kChunked creates a chunked engine using the legacy 100k
// PBKDF2 iteration count.
func newEngine100kChunked(t *testing.T) crypto.EncryptionEngine {
	t.Helper()
	eng, err := crypto.NewEngineWithOpts(kdfTestPassword, nil, crypto.WithChunking(true), crypto.WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("newEngine100kChunked: %v", err)
	}
	return eng
}

// testKDF_Default600k_RoundTrip verifies that the default gateway (600k)
// encrypts and decrypts a 128 KiB object correctly.
func testKDF_Default600k_RoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	data := bytes.Repeat([]byte("d"), 128*1024)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(data))
	}
}

// testKDF_LegacyRead_100k writes an object directly to the backend with a
// 100k engine and no MetaKDFParams (ClassD), then reads it back through a
// default 600k gateway. The gateway must fall back to LegacyPBKDF2Iterations.
func testKDF_LegacyRead_100k(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine100k(t)
	key := uniqueKey(t)
	plaintext := []byte("legacy-read-100k-plaintext")

	putEncryptedObject(t, client, eng, inst.Bucket, key, plaintext, func(meta map[string]string) {
		delete(meta, crypto.MetaKDFParams)
	})

	gw := harness.StartGateway(t, inst)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("legacy read mismatch: got %q, want %q", got, plaintext)
	}
}

// testKDF_CrossIteration_100k_to_600k writes an object via a 100k gateway
// (metadata records 100k) and then reads it via a default 600k gateway.
// Decryption must be driven by the metadata, not the engine default.
func testKDF_CrossIteration_100k_to_600k(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw100k := harness.StartGateway(t, inst, harness.WithPBKDF2Iterations(100000))

	plaintext := []byte("cross-iteration-plaintext")
	key := uniqueKey(t)
	put(t, gw100k, inst.Bucket, key, plaintext)

	gw600k := harness.StartGateway(t, inst)
	got := get(t, gw600k, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("cross-iteration read mismatch: got %q, want %q", got, plaintext)
	}
}

// testKDF_MetadataPresent verifies that a PUT via the default gateway stores
// the expected KDF parameters metadata on the backend object.
func testKDF_MetadataPresent(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, []byte("metadata-present"))

	client := newS3Client(t, inst)
	meta := headMeta(t, client, inst.Bucket, key)
	if meta[crypto.MetaKDFParams] != "pbkdf2-sha256:600000" {
		t.Errorf("MetaKDFParams = %q, want %q", meta[crypto.MetaKDFParams], "pbkdf2-sha256:600000")
	}
}

// testKDF_Chunked_600k_RoundTrip verifies a chunked PUT/GET round-trip with
// the default 600k iteration count.
func testKDF_Chunked_600k_RoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst, harness.WithChunking(true))

	data := bytes.Repeat([]byte("c"), 512*1024)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("chunked round-trip mismatch: got %d bytes, want %d bytes", len(got), len(data))
	}
}

// testKDF_Chunked_LegacyRead writes a chunked object directly to the backend
// using a 100k engine with no MetaKDFParams, then reads it via a chunked 600k
// gateway. The gateway must fall back to legacy 100k iterations.
func testKDF_Chunked_LegacyRead(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngine100kChunked(t)
	key := uniqueKey(t)
	plaintext := bytes.Repeat([]byte("legacy-chunked"), 128*1024)

	putEncryptedObject(t, client, eng, inst.Bucket, key, plaintext, func(meta map[string]string) {
		delete(meta, crypto.MetaKDFParams)
	})

	gw := harness.StartGateway(t, inst, harness.WithChunking(true))
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("chunked legacy read mismatch")
	}
}


// newEngineArgon2id creates an engine using argon2id KDF with the test
// password and default argon2id parameters.
func newEngineArgon2id(t *testing.T) crypto.EncryptionEngine {
	t.Helper()
	eng, err := crypto.NewEngineWithOpts(kdfTestPassword, nil,
		crypto.WithKDFAlgorithm("argon2id"),
		crypto.WithArgon2idParams(2, 19456, 1),
	)
	if err != nil {
		t.Fatalf("newEngineArgon2id: %v", err)
	}
	return eng
}

// testKDF_Argon2id_RoundTrip verifies that a gateway configured with argon2id
// KDF can PUT and GET a 128 KiB object correctly.
func testKDF_Argon2id_RoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithKDFAlgorithm("argon2id"),
		harness.WithArgon2idParams(2, 19456, 1),
	)

	data := bytes.Repeat([]byte("a"), 128*1024)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("argon2id round-trip mismatch: got %d bytes, want %d bytes", len(got), len(data))
	}
}

// testKDF_Argon2id_LegacyRead writes an object directly to the backend using
// an argon2id engine, then reads it back through a default PBKDF2 gateway.
// Decryption must be driven by the metadata, not the engine default.
func testKDF_Argon2id_LegacyRead(t *testing.T, inst provider.Instance) {
	t.Helper()
	client := newS3Client(t, inst)
	eng := newEngineArgon2id(t)
	key := uniqueKey(t)
	plaintext := []byte("argon2id-legacy-read-plaintext")

	putEncryptedObject(t, client, eng, inst.Bucket, key, plaintext, nil)

	gw := harness.StartGateway(t, inst)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("argon2id legacy read mismatch: got %q, want %q", got, plaintext)
	}
}

// testKDF_Argon2id_Chunked_RoundTrip verifies that a chunked gateway
// configured with argon2id KDF can PUT and GET a 512 KiB object correctly.
func testKDF_Argon2id_Chunked_RoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithChunking(true),
		harness.WithKDFAlgorithm("argon2id"),
		harness.WithArgon2idParams(2, 19456, 1),
	)

	data := bytes.Repeat([]byte("c"), 512*1024)
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, data)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, data) {
		t.Errorf("argon2id chunked round-trip mismatch: got %d bytes, want %d bytes", len(got), len(data))
	}
}
