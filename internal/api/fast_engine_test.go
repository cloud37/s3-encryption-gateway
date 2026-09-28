package api

import "github.com/cloud37/s3-encryption-gateway/internal/crypto"

// newAPIUnitEngine uses a supported PBKDF2 cost for handler tests. These tests
// cover S3 behavior rather than the default KDF work factor; crypto's tests
// exercise the production default and KDF bounds independently.
func newAPIUnitEngine(password []byte) (crypto.EncryptionEngine, error) {
	return crypto.NewEngineWithOpts(password, crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
}

func newAPIUnitChunkedEngine(password []byte, preferred string, supported []string, chunked bool, chunkSize int) (crypto.EncryptionEngine, error) {
	return crypto.NewEngineWithChunkingAndProvider(password, preferred, supported, chunked, chunkSize, "default", crypto.MinPBKDF2Iterations)
}
