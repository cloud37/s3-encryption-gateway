package crypto

import "fmt"

func CiphertextSizeForPlaintext(meta map[string]string, plain int64) (int64, error) {
	version, err := chunkedVersionForMetadata(meta)
	if err != nil {
		return 0, err
	}
	return ChunkedCiphertextSize(plain, parseChunkSize(meta), version)
}
func PlaintextSizeForCiphertext(meta map[string]string, ciphertext int64) (int64, uint64, error) {
	version, err := chunkedVersionForMetadata(meta)
	if err != nil {
		return 0, 0, err
	}
	if ciphertext < 0 {
		return 0, 0, fmt.Errorf("ciphertext size must not be negative")
	}
	return ChunkedPlaintextSize(ciphertext, parseChunkSize(meta), version)
}

func chunkedVersionForMetadata(meta map[string]string) (uint8, error) {
	if meta[MetaManifest] == "" {
		return ChunkedFormatV1, nil
	}
	return ChunkedFormatVersion(meta)
}
