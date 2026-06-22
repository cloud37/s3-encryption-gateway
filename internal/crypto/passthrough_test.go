package crypto

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestPassthroughEngine_SatisfiesInterface(t *testing.T) {
	var _ EncryptionEngine = PassthroughEngine{}
}

func TestPassthroughEngine_Encrypt_IsIdentity(t *testing.T) {
	eng := PassthroughEngine{}
	ctx := context.Background()
	input := "hello world"
	meta := map[string]string{"foo": "bar"}

	reader, outMeta, err := eng.Encrypt(ctx, strings.NewReader(input), meta)
	if err != nil {
		t.Fatalf("Encrypt returned error: %v", err)
	}
	data, _ := io.ReadAll(reader)
	if string(data) != input {
		t.Fatalf("Encrypt modified data: got %q, want %q", string(data), input)
	}
	if outMeta["x-amz-meta-encrypted"] == "true" {
		t.Fatal("Encrypt should not set encryption metadata on passthrough")
	}
	if outMeta["foo"] != "bar" {
		t.Fatal("Encrypt should preserve user metadata")
	}
}

func TestPassthroughEngine_Decrypt_PlaintextObject(t *testing.T) {
	eng := PassthroughEngine{}
	ctx := context.Background()
	input := "plaintext data"
	meta := map[string]string{"foo": "bar"}

	reader, outMeta, err := eng.Decrypt(ctx, strings.NewReader(input), meta)
	if err != nil {
		t.Fatalf("Decrypt returned error: %v", err)
	}
	data, _ := io.ReadAll(reader)
	if string(data) != input {
		t.Fatalf("Decrypt modified data: got %q, want %q", string(data), input)
	}
	if outMeta["foo"] != "bar" {
		t.Fatal("Decrypt should preserve user metadata")
	}
}

func TestPassthroughEngine_Decrypt_EncryptedObject_ReturnsError(t *testing.T) {
	eng := PassthroughEngine{}
	ctx := context.Background()
	meta := map[string]string{MetaEncrypted: "true"}

	_, _, err := eng.Decrypt(ctx, strings.NewReader("data"), meta)
	if !errors.Is(err, ErrEncryptedObjectInBypassBucket) {
		t.Fatalf("Decrypt on encrypted metadata: got %v, want %v", err, ErrEncryptedObjectInBypassBucket)
	}
}

func TestPassthroughEngine_Decrypt_CompactedKey_ReturnsError(t *testing.T) {
	eng := PassthroughEngine{}
	ctx := context.Background()
	meta := map[string]string{"x-amz-meta-e": "true"}

	_, _, err := eng.Decrypt(ctx, strings.NewReader("data"), meta)
	if !errors.Is(err, ErrEncryptedObjectInBypassBucket) {
		t.Fatalf("Decrypt on compacted encrypted key: got %v, want %v", err, ErrEncryptedObjectInBypassBucket)
	}
}

func TestPassthroughEngine_DecryptRange_PlaintextObject(t *testing.T) {
	eng := PassthroughEngine{}
	ctx := context.Background()
	input := "plaintext data"
	meta := map[string]string{"foo": "bar"}

	reader, outMeta, err := eng.DecryptRange(ctx, strings.NewReader(input), meta, 0, 5)
	if err != nil {
		t.Fatalf("DecryptRange returned error: %v", err)
	}
	data, _ := io.ReadAll(reader)
	if string(data) != input {
		t.Fatalf("DecryptRange modified data: got %q, want %q", string(data), input)
	}
	if outMeta["foo"] != "bar" {
		t.Fatal("DecryptRange should preserve user metadata")
	}
}

func TestPassthroughEngine_DecryptRange_EncryptedObject_ReturnsError(t *testing.T) {
	eng := PassthroughEngine{}
	ctx := context.Background()
	meta := map[string]string{MetaEncrypted: "true"}

	_, _, err := eng.DecryptRange(ctx, strings.NewReader("data"), meta, 0, 3)
	if !errors.Is(err, ErrEncryptedObjectInBypassBucket) {
		t.Fatalf("DecryptRange on encrypted metadata: got %v, want %v", err, ErrEncryptedObjectInBypassBucket)
	}
}

func TestPassthroughEngine_IsEncrypted_AlwaysFalse(t *testing.T) {
	eng := PassthroughEngine{}
	if eng.IsEncrypted(map[string]string{MetaEncrypted: "true"}) {
		t.Fatal("IsEncrypted should return false for passthrough engine")
	}
	if eng.IsEncrypted(nil) {
		t.Fatal("IsEncrypted should return false for nil metadata")
	}
	if eng.IsEncrypted(map[string]string{}) {
		t.Fatal("IsEncrypted should return false for empty metadata")
	}
}

func TestPassthroughEngine_PreferredAlgorithm(t *testing.T) {
	eng := PassthroughEngine{}
	if alg := eng.PreferredAlgorithm(); alg != "none" {
		t.Fatalf("PreferredAlgorithm: got %q, want %q", alg, "none")
	}
}

func TestIsEncryptedMetadata_Nil(t *testing.T) {
	if IsEncryptedMetadata(nil) {
		t.Fatal("IsEncryptedMetadata(nil) should return false")
	}
}

func TestIsEncryptedMetadata_Empty(t *testing.T) {
	if IsEncryptedMetadata(map[string]string{}) {
		t.Fatal("IsEncryptedMetadata(empty) should return false")
	}
}

func TestIsEncryptedMetadata_FullKey(t *testing.T) {
	if !IsEncryptedMetadata(map[string]string{MetaEncrypted: "true"}) {
		t.Fatal("IsEncryptedMetadata should return true for full key")
	}
}

func TestIsEncryptedMetadata_CompactedKey(t *testing.T) {
	if !IsEncryptedMetadata(map[string]string{"x-amz-meta-e": "true"}) {
		t.Fatal("IsEncryptedMetadata should return true for compacted key")
	}
}

func TestIsEncryptedMetadata_FalseValue(t *testing.T) {
	if IsEncryptedMetadata(map[string]string{MetaEncrypted: "false"}) {
		t.Fatal("IsEncryptedMetadata should return false for false value")
	}
}
