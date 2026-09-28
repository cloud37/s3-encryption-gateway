package crypto

// newUnitEngine keeps object-format tests at the supported PBKDF2 minimum;
// tests of the default and explicit KDF work factors use production constructors.
func newUnitEngine(password []byte) (EncryptionEngine, error) {
	return NewEngineWithOpts(password, WithPBKDF2Iterations(MinPBKDF2Iterations))
}

func newUnitChunkedEngine(password []byte, preferred string, supported []string, chunked bool, chunkSize int) (EncryptionEngine, error) {
	return NewEngineWithChunkingAndProvider(password, preferred, supported, chunked, chunkSize, "default", MinPBKDF2Iterations)
}
