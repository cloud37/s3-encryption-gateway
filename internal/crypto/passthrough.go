package crypto

import (
	"context"
	"errors"
	"io"
)

var ErrEncryptedObjectInBypassBucket = errors.New(
	"object was stored encrypted; bucket now has disable_encryption — " +
		"use the migration tool to re-store as plaintext")

var _ EncryptionEngine = PassthroughEngine{}

type PassthroughEngine struct{}

func (PassthroughEngine) Encrypt(_ context.Context, r io.Reader, meta map[string]string) (io.Reader, map[string]string, error) {
	return r, meta, nil
}

func (PassthroughEngine) Decrypt(_ context.Context, r io.Reader, meta map[string]string) (io.Reader, map[string]string, error) {
	if IsEncryptedMetadata(meta) {
		return nil, nil, ErrEncryptedObjectInBypassBucket
	}
	return r, meta, nil
}

func (PassthroughEngine) DecryptRange(_ context.Context, r io.Reader, meta map[string]string, _, _ int64) (io.Reader, map[string]string, error) {
	if IsEncryptedMetadata(meta) {
		return nil, nil, ErrEncryptedObjectInBypassBucket
	}
	return r, meta, nil
}

func (PassthroughEngine) IsEncrypted(_ map[string]string) bool { return false }
func (PassthroughEngine) PreferredAlgorithm() string           { return "none" }
