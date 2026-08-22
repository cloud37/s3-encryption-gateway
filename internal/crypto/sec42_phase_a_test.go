package crypto

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/base64"
	"io"
	"strings"
	"testing"
)

func TestBuildObjectAAD_LengthPrefixesPreventAmbiguity(t *testing.T) {
	id := bytes.Repeat([]byte{1}, 16)
	a, err := buildObjectAAD(aadBufferedV2, ObjectContext{Bucket: "a", Key: "bc"}, id)
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildObjectAAD(aadBufferedV2, ObjectContext{Bucket: "ab", Key: "c"}, id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("distinct bucket/key tuples produced identical AAD")
	}
}

func TestBuildObjectAAD_KeyBytesAreExact(t *testing.T) {
	id := bytes.Repeat([]byte{2}, 16)
	keys := []string{"a/b", "a//b", "a%2Fb", "a b", "a\x00b", "e\u0301", "\u00e9"}
	seen := make(map[string]bool)
	for _, key := range keys {
		a, err := buildObjectAAD(aadBufferedV2, ObjectContext{Bucket: "bucket", Key: key}, id)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(a)] {
			t.Fatalf("AAD collision for key %q", key)
		}
		seen[string(a)] = true
	}
}

func TestObjectContextValidate_RejectsEmptyOrOversizeIdentity(t *testing.T) {
	for _, object := range []ObjectContext{{}, {Bucket: "", Key: "k"}, {Bucket: "b", Key: ""}, {Bucket: strings.Repeat("b", 64), Key: "k"}, {Bucket: "b", Key: strings.Repeat("k", 1025)}} {
		if err := object.Validate(); err == nil {
			t.Fatalf("expected invalid context: %+v", object)
		}
	}
}

func TestBufferedV2_BindsBucketAndKey(t *testing.T) {
	eng, err := NewEngine([]byte("test-password-long-enough"))
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "bucket", Key: "key"}
	ciphertext, metadata, err := eng.Encrypt(context.Background(), object, strings.NewReader("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if metadata[MetaObjectFormatVersion] != "buffered-v2" {
		t.Fatalf("format marker = %q", metadata[MetaObjectFormatVersion])
	}
	for _, wrong := range []ObjectContext{{Bucket: "other-bucket", Key: object.Key}, {Bucket: object.Bucket, Key: "other"}} {
		if _, _, err = eng.Decrypt(context.Background(), wrong, bytes.NewReader(body), metadata); err == nil {
			t.Fatalf("wrong object context decrypted ciphertext: %+v", wrong)
		}
	}
	plain, _, err := eng.Decrypt(context.Background(), object, bytes.NewReader(body), metadata)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(plain)
	if err != nil || string(got) != "secret" {
		t.Fatalf("plaintext = %q, err = %v", got, err)
	}
	if _, err = base64.RawURLEncoding.DecodeString(metadata[MetaObjectBindingID]); err != nil {
		t.Fatal(err)
	}
}

func TestBufferedV2_TamperedTagDoesNotFallback(t *testing.T) {
	engine, err := NewEngine([]byte("test-password-long-enough"))
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "bucket", Key: "key"}
	ciphertext, metadata, err := engine.Encrypt(context.Background(), object, strings.NewReader("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(ciphertext)
	body[len(body)-1] ^= 1
	if _, _, err = engine.Decrypt(context.Background(), object, bytes.NewReader(body), metadata); err == nil {
		t.Fatal("tampered buffered-v2 tag was accepted")
	}
}

func TestBufferedV2_RejectsChunkedMetadataBeforeDecrypt(t *testing.T) {
	good, err := NewEngineWithChunking([]byte("good-password-long-enough"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "b", Key: "k"}
	r, meta, err := good.Encrypt(context.Background(), object, bytes.NewReader([]byte("chunked metadata")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	meta[MetaObjectFormatVersion] = "buffered-v2"
	wrong, err := NewEngine([]byte("wrong-password-long-enough"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []func() error{
		func() error {
			_, _, err := wrong.Decrypt(context.Background(), object, bytes.NewReader(ciphertext), meta)
			return err
		},
		func() error {
			_, _, err := wrong.DecryptRange(context.Background(), object, bytes.NewReader(ciphertext), meta, 0, 5)
			return err
		},
	} {
		if err := test(); err == nil || (!strings.Contains(err.Error(), "buffered-v2 format marker cannot use chunked metadata") && !strings.Contains(err.Error(), "buffered-v2 format marker cannot use range chunked metadata")) {
			t.Fatalf("contradictory marker did not fail before crypto work: %v", err)
		}
	}
}

func TestParseObjectBindingID_RequiresCanonicalRawURL(t *testing.T) {
	canonical := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16))
	if got, err := parseObjectBindingID(canonical); err != nil || !bytes.Equal(got, bytes.Repeat([]byte{7}, 16)) {
		t.Fatalf("canonical ID rejected: %v", err)
	}
	mutated := canonical[:len(canonical)-1] + "B"
	for _, value := range []string{canonical + "=", base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)), mutated} {
		if _, err := parseObjectBindingID(value); err == nil {
			t.Fatalf("noncanonical binding %q accepted", value)
		}
	}
}

func TestBufferedLegacy_DualRead(t *testing.T) {
	eng, err := NewEngine([]byte("test-password-long-enough"))
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "bucket", Key: "key"}
	e := eng.(*engine)
	salt := bytes.Repeat([]byte{3}, saltSize)
	iv := bytes.Repeat([]byte{4}, nonceSize)
	key, err := e.deriveKey(salt)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(key)
	aead, err := createAEADCipher(AlgorithmAES256GCM, key)
	if err != nil {
		t.Fatal(err)
	}
	aadMeta := map[string]string{MetaOriginalSize: "6", "Content-Type": ""}
	legacyAAD := buildAAD(AlgorithmAES256GCM, salt, iv, aadMeta)
	body := aead.(cipher.AEAD).Seal(nil, iv, []byte("legacy"), legacyAAD)
	metadata := map[string]string{MetaEncrypted: "true", MetaAlgorithm: AlgorithmAES256GCM, MetaKeySalt: encodeBase64(salt), MetaIV: encodeBase64(iv), MetaOriginalSize: "6", MetaKDFParams: FormatKDFParams(e.defaultKDFParams())}
	plain, _, err := eng.Decrypt(context.Background(), object, bytes.NewReader(body), metadata)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(plain)
	if err != nil || string(got) != "legacy" {
		t.Fatalf("plaintext = %q, err = %v", got, err)
	}
}

func FuzzBuildObjectAAD(f *testing.F) {
	f.Add("bucket", "key", "s3eg/buffered/v2", bytes.Repeat([]byte{1}, 16))
	f.Add("a/b", "a%2Fb", "s3eg/mpu/v2/chunk", bytes.Repeat([]byte{2}, 16))
	f.Add("a\x00b", "e\u0301", "s3eg/chunked/v2/data", bytes.Repeat([]byte{3}, 16))
	f.Add("bucket", "key", "s3eg/buffered/v2", []byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, bucket, key, domain string, binding []byte) {
		if len(domain) == 0 {
			return
		}
		object := ObjectContext{Bucket: bucket, Key: key}
		if object.Validate() != nil {
			return
		}
		_, err := buildObjectAAD(aadDomain(domain), object, binding)
		if len(binding) != 16 {
			if err == nil {
				t.Fatalf("malformed binding length %d accepted", len(binding))
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		id2 := append([]byte(nil), binding...)
		id2[0] ^= 1
		a, err := buildObjectAAD(aadDomain(domain), object, binding)
		if err != nil {
			t.Fatal(err)
		}
		b, err := buildObjectAAD(aadDomain(domain), object, id2)
		if err != nil || bytes.Equal(a, b) {
			t.Fatal("distinct valid bindings collided")
		}
		other := ObjectContext{Bucket: bucket + "x", Key: key}
		if other.Validate() == nil {
			b, err = buildObjectAAD(aadDomain(domain), other, binding)
			if err != nil || bytes.Equal(a, b) {
				t.Fatal("distinct valid identities collided")
			}
		}
	})
}

func TestBuildObjectAAD_RejectsMalformedBindingSizes(t *testing.T) {
	object := ObjectContext{Bucket: "b", Key: "k"}
	for _, id := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, 15), bytes.Repeat([]byte{1}, 17)} {
		if _, err := buildObjectAAD(aadBufferedV2, object, id); err == nil {
			t.Fatalf("binding length %d accepted", len(id))
		}
	}
}
