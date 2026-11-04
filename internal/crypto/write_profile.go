package crypto

// EncryptionWriteProfile describes the plaintext memory behavior of an engine.
// It is immutable after construction and contains no request or key material.
type EncryptionWriteProfile struct {
	StreamsPlaintext bool
}

// EncryptionWriteProfiler is an optional capability. Callers that do not see
// this interface must conservatively treat the engine as buffered.
type EncryptionWriteProfiler interface {
	WriteProfile() EncryptionWriteProfile
}

var _ EncryptionWriteProfiler = (*engine)(nil)
var _ EncryptionWriteProfiler = PassthroughEngine{}

func (e *engine) WriteProfile() EncryptionWriteProfile {
	return EncryptionWriteProfile{StreamsPlaintext: e != nil && e.chunkedMode}
}

func (PassthroughEngine) WriteProfile() EncryptionWriteProfile {
	return EncryptionWriteProfile{StreamsPlaintext: true}
}
