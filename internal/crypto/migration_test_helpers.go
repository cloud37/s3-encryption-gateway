package crypto

// NewTestEngineWithFallbackProfile creates an encryption engine configured with
// an extremely small metadata limit (100 bytes total).  This forces the
// metadata-fallback path for almost any object, making it possible for
// out-of-package conformance tests to generate legacy fallback-v1 objects
// without bloating S3 headers.
//
// It is intentionally exported so that the tier-2 migration conformance suite
// (test/migration) can construct ClassC objects end-to-end against real S3
// backends such as MinIO.
func NewTestEngineWithFallbackProfile(password []byte, chunkedMode bool) (EncryptionEngine, error) {
	eng, err := NewEngineWithChunkingAndProvider(password, "", nil, chunkedMode, DefaultChunkSize, "default", DefaultPBKDF2Iterations)
	if err != nil {
		return nil, err
	}
	e := eng.(*engine)
	profile := &ProviderProfile{
		Name:                "test-fallback",
		UserMetadataLimit:   50,
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    100,
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}
	e.providerProfile = profile
	e.compactor = NewMetadataCompactor(profile)
	return e, nil
}
