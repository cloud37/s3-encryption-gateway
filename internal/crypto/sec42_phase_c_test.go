package crypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"testing"
)

func phaseCBinding(n byte) [16]byte {
	var b [16]byte
	for i := range b {
		b[i] = n + byte(i)
	}
	return b
}

func TestMultipartManifestV2_ValidatesCompanionRelationship(t *testing.T) {
	b := phaseCBinding(1)
	m := &MultipartManifest{Version: 2, ParentBucket: "b", ParentKey: "k", CompanionBucket: "b", CompanionKey: "k.mpu-manifest", BindingID: base64.RawURLEncoding.EncodeToString(b[:])}
	if err := m.ValidateFor(ObjectContext{Bucket: "b", Key: "k"}, ObjectContext{Bucket: "b", Key: "k.mpu-manifest"}, b); err != nil {
		t.Fatal(err)
	}
}

func TestMultipartManifestV2_RejectsSwappedCompanion(t *testing.T) {
	b := phaseCBinding(2)
	m := &MultipartManifest{Version: 2, ParentBucket: "b", ParentKey: "k", CompanionBucket: "b", CompanionKey: "other.mpu-manifest", BindingID: base64.RawURLEncoding.EncodeToString(b[:])}
	if err := m.ValidateFor(ObjectContext{Bucket: "b", Key: "k"}, ObjectContext{Bucket: "b", Key: "k.mpu-manifest"}, b); err == nil {
		t.Fatal("swapped companion accepted")
	}
}

func TestMultipartManifestV2_MalformedBindingNeverFallsBack(t *testing.T) {
	m := &MultipartManifest{Version: 2, BindingID: "not-base64"}
	if err := m.ValidateFor(ObjectContext{Bucket: "b", Key: "k"}, ObjectContext{Bucket: "b", Key: "k.mpu-manifest"}, phaseCBinding(3)); err == nil {
		t.Fatal("malformed binding accepted")
	}
	if _, _, err := NewMPUPartEncryptReader(context.Background(), ObjectContext{Bucket: "b", Key: "k"}, [16]byte{}, bytes.NewReader([]byte("x")), bytes.Repeat([]byte{1}, 32), [32]byte{}, [12]byte{}, 1, 4, 1, AlgorithmAES256GCM); err == nil {
		t.Fatal("zero binding accepted")
	}
}

func TestMultipartManifestV1_DualRead(t *testing.T) {
	m := &MultipartManifest{Version: 1, ChunkSize: 4, Parts: []MPUPartRecord{{PartNumber: 1, PlainLen: 3, EncLen: 19, ChunkCount: 1}}}
	if _, err := UnmarshalMultipartManifest(mustMarshal(t, m)); err != nil {
		t.Fatal(err)
	}
	plain := []byte("abc")
	r, _, err := newMPUPartEncryptReaderV1(context.Background(), ObjectContext{Bucket: "b", Key: "k"}, [16]byte{}, bytes.NewReader(plain), bytes.Repeat([]byte{1}, 32), [32]byte{}, [12]byte{}, 1, 4, 3, AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := io.ReadAll(r)
	got, err := decryptMPUPartRangeV1(ObjectContext{Bucket: "b", Key: "k"}, [16]byte{}, ct, bytes.Repeat([]byte{1}, 32), [32]byte{}, [12]byte{}, 1, 4, 0, AlgorithmAES256GCM)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("v1 dual read failed: %v", err)
	}
}

func TestMPUV2_ChunkBindsObjectPartAndChunk(t *testing.T) {
	b := phaseCBinding(4)
	obj := ObjectContext{Bucket: "b", Key: "k"}
	dek := bytes.Repeat([]byte{2}, 32)
	p := bytes.Repeat([]byte("x"), 8)
	r, _, err := NewMPUPartEncryptReader(context.Background(), obj, b, bytes.NewReader(p), dek, [32]byte{}, [12]byte{}, 2, 4, int64(len(p)), AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := io.ReadAll(r)
	if _, err = DecryptMPUPartRange(ObjectContext{Bucket: "other", Key: "k"}, b, ct, dek, [32]byte{}, [12]byte{}, 2, 4, 0, AlgorithmAES256GCM); err == nil {
		t.Fatal("wrong object accepted")
	}
	if _, err = DecryptMPUPartRange(obj, b, ct, dek, [32]byte{}, [12]byte{}, 3, 4, 0, AlgorithmAES256GCM); err == nil {
		t.Fatal("wrong part accepted")
	}
}

func TestMPUV2_RetryIsDeterministicWithinBinding(t *testing.T) {
	b := phaseCBinding(5)
	obj := ObjectContext{Bucket: "b", Key: "k"}
	dek := bytes.Repeat([]byte{3}, 32)
	p := []byte("retry")
	enc := func() []byte {
		r, _, _ := NewMPUPartEncryptReader(context.Background(), obj, b, bytes.NewReader(p), dek, [32]byte{}, [12]byte{}, 1, 8, int64(len(p)), AlgorithmAES256GCM)
		c, _ := io.ReadAll(r)
		return c
	}
	if !bytes.Equal(enc(), enc()) {
		t.Fatal("retry ciphertext changed")
	}
}

func TestMPUV2_PartBoundaryPrimitive(t *testing.T) {
	b := phaseCBinding(8)
	obj := ObjectContext{Bucket: "b", Key: "k"}
	dek := bytes.Repeat([]byte{4}, 32)
	r, _, err := NewMPUPartEncryptReader(context.Background(), obj, b, bytes.NewReader([]byte("abcd")), dek, [32]byte{}, [12]byte{}, 1, 4, 4, AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := io.ReadAll(r)
	got, err := DecryptMPUPartRange(obj, b, ct, dek, [32]byte{}, [12]byte{}, 1, 4, 0, AlgorithmAES256GCM)
	if err != nil || !bytes.Equal(got, []byte("abcd")) {
		t.Fatalf("part decrypt: %v", err)
	}
}

func TestMPUV2_RejectsWrongChunkIndexCoordinate(t *testing.T) {
	b := phaseCBinding(9)
	obj := ObjectContext{Bucket: "b", Key: "k"}
	dek := bytes.Repeat([]byte{5}, 32)
	r, _, err := NewMPUPartEncryptReader(context.Background(), obj, b, bytes.NewReader([]byte("abcdefgh")), dek, [32]byte{}, [12]byte{}, 1, 4, 8, AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ct, _ := io.ReadAll(r)
	if _, err = DecryptMPUPartRange(obj, b, ct[:4+mpuAEADTagSize], dek, [32]byte{}, [12]byte{}, 1, 4, 1, AlgorithmAES256GCM); err == nil {
		t.Fatal("wrong chunk coordinate accepted")
	}
}

func TestMultipartManifestV2_AuthenticatedRelationshipMismatch(t *testing.T) {
	eng, err := NewEngine([]byte("manifest-relationship-password"))
	if err != nil {
		t.Fatal(err)
	}
	binding := phaseCBinding(10)
	manifest := &MultipartManifest{Version: 2, ParentBucket: "b", ParentKey: "different-parent", CompanionBucket: "b", CompanionKey: "parent.mpu-manifest", BindingID: base64.RawURLEncoding.EncodeToString(binding[:])}
	payload, err := manifest.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	companion := ObjectContext{Bucket: "b", Key: "parent.mpu-manifest"}
	r, meta, err := eng.Encrypt(context.Background(), companion, bytes.NewReader(payload), nil)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	plainReader, _, err := eng.Decrypt(context.Background(), companion, bytes.NewReader(ct), meta)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(plainReader)
	if err != nil {
		t.Fatal(err)
	}
	authentic, err := UnmarshalMultipartManifest(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := authentic.ValidateFor(ObjectContext{Bucket: "b", Key: "parent"}, companion, binding); err == nil {
		t.Fatal("authenticated companion with mismatched relationship accepted")
	}
	valid := *authentic
	valid.ParentKey = "parent"
	if err := valid.ValidateFor(ObjectContext{Bucket: "b", Key: "parent"}, companion, binding); err != nil {
		t.Fatalf("valid relationship rejected: %v", err)
	}
}

func TestMPUManifestV2_EncryptDecryptAndReject(t *testing.T) {
	eng, err := NewEngine([]byte("manifest-v2-coverage-password"))
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "b", Key: "k.mpu-manifest"}
	binding := phaseCBinding(11)
	plain := []byte(`{"v":2,"parent_bucket":"b","parent_key":"k"}`)
	e := eng.(*engine)
	ct, meta, err := e.EncryptMPUManifest(context.Background(), object, binding, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.DecryptMPUManifest(context.Background(), object, binding, ct, meta)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("manifest round trip: %v", err)
	}
	for _, wrong := range []struct {
		object  ObjectContext
		binding [16]byte
		meta    map[string]string
	}{
		{ObjectContext{Bucket: "other", Key: object.Key}, binding, meta},
		{object, phaseCBinding(12), meta},
		{object, binding, map[string]string{}},
	} {
		if _, err := e.DecryptMPUManifest(context.Background(), wrong.object, wrong.binding, ct, wrong.meta); err == nil {
			t.Fatal("invalid manifest context accepted")
		}
	}
	corrupt := append([]byte(nil), ct...)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := e.DecryptMPUManifest(context.Background(), object, binding, corrupt, meta); err == nil {
		t.Fatal("corrupt manifest accepted")
	}
}

func TestMPUV2_DecryptReaderRoundTripAndErrors(t *testing.T) {
	object := ObjectContext{Bucket: "b", Key: "k"}
	binding := phaseCBinding(13)
	dek := bytes.Repeat([]byte{6}, 32)
	text := bytes.Repeat([]byte("m"), 9)
	r, encLen, err := NewMPUPartEncryptReader(context.Background(), object, binding, bytes.NewReader(text), dek, [32]byte{}, [12]byte{}, 1, 4, int64(len(text)), AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &MultipartManifest{Version: 2, ChunkSize: 4, Parts: []MPUPartRecord{{PartNumber: 1, PlainLen: int64(len(text)), EncLen: encLen, ChunkCount: 3}}, TotalPlainSize: int64(len(text))}
	dec, err := NewMPUDecryptReader(object, binding, bytes.NewReader(ct), manifest, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(dec)
	if err != nil || !bytes.Equal(got, text) {
		t.Fatalf("reader round trip: %q, %v", got, err)
	}
	wrong, err := NewMPUDecryptReader(ObjectContext{Bucket: "wrong", Key: object.Key}, binding, bytes.NewReader(ct), manifest, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM)
	if err == nil {
		_, err = io.ReadAll(wrong)
	}
	if err == nil {
		t.Fatal("wrong reader context accepted")
	}
	if _, err := NewMPUDecryptReader(object, [16]byte{}, bytes.NewReader(ct), manifest, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM); err == nil {
		t.Fatal("zero reader binding accepted")
	}
}

func TestMPUManifestV2_ValidateForRejectsEveryIdentityComponent(t *testing.T) {
	binding := phaseCBinding(14)
	m := &MultipartManifest{Version: 2, ParentBucket: "b", ParentKey: "k", CompanionBucket: "b", CompanionKey: "k.mpu-manifest", BindingID: base64.RawURLEncoding.EncodeToString(binding[:])}
	parent := ObjectContext{Bucket: "b", Key: "k"}
	companion := ObjectContext{Bucket: "b", Key: "k.mpu-manifest"}
	for _, tc := range []struct {
		name              string
		parent, companion ObjectContext
		binding           [16]byte
	}{
		{"parent bucket", ObjectContext{Bucket: "other", Key: "k"}, companion, binding},
		{"parent key", ObjectContext{Bucket: "b", Key: "other"}, companion, binding},
		{"companion bucket", parent, ObjectContext{Bucket: "other", Key: companion.Key}, binding},
		{"companion key", parent, ObjectContext{Bucket: "b", Key: "other"}, binding},
		{"binding", parent, companion, phaseCBinding(15)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := m.ValidateFor(tc.parent, tc.companion, tc.binding); err == nil {
				t.Fatal("relationship mismatch accepted")
			}
		})
	}
	for _, bad := range []ObjectContext{{}, {Bucket: "b"}} {
		if err := m.ValidateFor(bad, companion, binding); err == nil {
			t.Fatal("invalid parent accepted")
		}
	}
}

func TestMPUV2_RangeRejectsMalformedCiphertextAndCoordinates(t *testing.T) {
	object := ObjectContext{Bucket: "b", Key: "k"}
	binding := phaseCBinding(16)
	dek := bytes.Repeat([]byte{8}, 32)
	for _, tc := range []struct {
		name        string
		ciphertext  []byte
		part, chunk int32
	}{
		{"short", []byte("short"), 1, 0},
		{"wrong part", bytes.Repeat([]byte{1}, 20), 0, 0},
		{"negative chunk", bytes.Repeat([]byte{1}, 20), 1, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecryptMPUPartRange(object, binding, tc.ciphertext, dek, [32]byte{}, [12]byte{}, tc.part, 4, tc.chunk, AlgorithmAES256GCM); err == nil {
				t.Fatal("malformed range accepted")
			}
		})
	}
}

func TestMPUV2_PublicRangeContractMatrix(t *testing.T) {
	object := ObjectContext{Bucket: "range-contract", Key: "object"}
	binding := phaseCBinding(19)
	dek := bytes.Repeat([]byte{3}, 32)
	plain := []byte("0123456789abcdef")
	r, _, err := NewMPUPartEncryptReader(context.Background(), object, binding, bytes.NewReader(plain), dek, [32]byte{}, [12]byte{}, 1, 4, int64(len(plain)), AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	chunk := 4 + mpuAEADTagSize
	for _, tc := range []struct {
		name             string
		object           ObjectContext
		binding          [16]byte
		ciphertext       []byte
		part, chunkIndex int32
		want             []byte
	}{
		{"first chunk", object, binding, ciphertext[:chunk], 1, 0, plain[:4]},
		{"middle chunks", object, binding, ciphertext[chunk : 3*chunk], 1, 1, plain[4:12]},
		{"final chunk", object, binding, ciphertext[3*chunk:], 1, 3, plain[12:]},
		{"wrong object", ObjectContext{Bucket: "other", Key: object.Key}, binding, ciphertext[:chunk], 1, 0, nil},
		{"wrong binding", object, phaseCBinding(20), ciphertext[:chunk], 1, 0, nil},
		{"wrong part", object, binding, ciphertext[:chunk], 2, 0, nil},
		{"trailing partial record", object, binding, append(append([]byte(nil), ciphertext[:chunk]...), 1, 2), 1, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecryptMPUPartRange(tc.object, tc.binding, tc.ciphertext, dek, [32]byte{}, [12]byte{}, tc.part, 4, tc.chunkIndex, AlgorithmAES256GCM)
			if tc.want == nil {
				if err == nil {
					t.Fatal("invalid range accepted")
				}
				return
			}
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("range=%q err=%v", got, err)
			}
		})
	}
}

func TestMPUV2_RangeValidationRejectsContextBindingAndAlgorithm(t *testing.T) {
	object := ObjectContext{Bucket: "range-validation", Key: "object"}
	valid := phaseCBinding(21)
	data := []byte("not-a-record")
	for _, tc := range []struct {
		name      string
		object    ObjectContext
		binding   [16]byte
		algorithm string
	}{
		{"invalid object", ObjectContext{}, valid, AlgorithmAES256GCM},
		{"zero binding", object, [16]byte{}, AlgorithmAES256GCM},
		{"unsupported algorithm", object, valid, "AES128GCM"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecryptMPUPartRange(tc.object, tc.binding, data, bytes.Repeat([]byte{4}, 32), [32]byte{}, [12]byte{}, 1, 4, 0, tc.algorithm); err == nil {
				t.Fatal("invalid range contract accepted")
			}
		})
	}
}

func TestMPUV1_ExplicitReaderAndRangeCompatibility(t *testing.T) {
	object := ObjectContext{Bucket: "b", Key: "k"}
	dek := bytes.Repeat([]byte{9}, 32)
	plain := []byte("legacy-mpu")
	r, encLen, err := NewMPUPartEncryptReaderV1(context.Background(), object, bytes.NewReader(plain), dek, [32]byte{}, [12]byte{}, 1, DefaultChunkSize, int64(len(plain)), AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &MultipartManifest{Version: 1, ChunkSize: DefaultChunkSize, Parts: []MPUPartRecord{{PartNumber: 1, PlainLen: int64(len(plain)), EncLen: encLen, ChunkCount: 1}}, TotalPlainSize: int64(len(plain))}
	reader, err := NewMPUDecryptReaderV1(object, bytes.NewReader(ct), manifest, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("legacy reader: %v", err)
	}
	if _, err := DecryptMPUPartRangeV1(object, ct, dek, [32]byte{}, [12]byte{}, 1, DefaultChunkSize, 0, AlgorithmAES256GCM); err != nil {
		t.Fatal(err)
	}
}

func TestMPUManifestV2_RejectsMalformedMetadataAndCiphertext(t *testing.T) {
	e := mustEngine(t, "manifest-malformed-password")
	object := ObjectContext{Bucket: "b", Key: "manifest"}
	binding := phaseCBinding(17)
	ct, meta, err := e.EncryptMPUManifest(context.Background(), object, binding, []byte("manifest"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]string){
		func(m map[string]string) { delete(m, MetaObjectFormatVersion) },
		func(m map[string]string) { m[MetaObjectBindingID] = "bad" },
		func(m map[string]string) { m[MetaKeySalt] = "bad" },
		func(m map[string]string) { m[MetaIV] = "bad" },
		func(m map[string]string) { m[MetaKDFParams] = "bad" },
		func(m map[string]string) { m[MetaAlgorithm] = "bad" },
	} {
		copyMeta := map[string]string{}
		for k, v := range meta {
			copyMeta[k] = v
		}
		mutate(copyMeta)
		if _, err := e.DecryptMPUManifest(context.Background(), object, binding, ct, copyMeta); err == nil {
			t.Fatal("malformed manifest metadata accepted")
		}
	}
}

func TestMPUManifestV2_RejectsSecurityMetadataMatrix(t *testing.T) {
	e := mustEngine(t, "manifest-security-matrix")
	object := ObjectContext{Bucket: "matrix", Key: "manifest"}
	binding := phaseCBinding(31)
	ct, meta, err := e.EncryptMPUManifest(context.Background(), object, binding, []byte("manifest"))
	if err != nil {
		t.Fatal(err)
	}
	copyMeta := func() map[string]string {
		m := make(map[string]string, len(meta))
		for k, v := range meta {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		name    string
		object  ObjectContext
		binding [16]byte
		mutate  func(map[string]string)
	}{
		{"invalid decrypt object", ObjectContext{}, binding, func(map[string]string) {}},
		{"zero decrypt binding", object, [16]byte{}, func(map[string]string) {}},
		{"wrong marker", object, binding, func(m map[string]string) { m[MetaObjectFormatVersion] = "object" }},
		{"wrong companion marker", object, binding, func(m map[string]string) { m[MetaMPUManifestVersion] = "1" }},
		{"wrong length binding", object, binding, func(m map[string]string) { m[MetaObjectBindingID] = encodeBase64([]byte{1, 2, 3}) }},
		{"different binding metadata", object, binding, func(m map[string]string) { b := phaseCBinding(32); m[MetaObjectBindingID] = encodeBase64(b[:]) }},
		{"short salt", object, binding, func(m map[string]string) { m[MetaKeySalt] = encodeBase64([]byte{1}) }},
		{"malformed nonce", object, binding, func(m map[string]string) { m[MetaIV] = "not-base64" }},
		{"invalid kdf", object, binding, func(m map[string]string) { m[MetaKDFParams] = "not-kdf" }},
		{"unsupported algorithm", object, binding, func(m map[string]string) { m[MetaAlgorithm] = "AES128GCM" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := copyMeta()
			tc.mutate(m)
			if _, err := e.DecryptMPUManifest(context.Background(), tc.object, tc.binding, ct, m); err == nil {
				t.Fatal("invalid manifest security input accepted")
			}
		})
	}
	for _, tc := range []struct {
		name    string
		object  ObjectContext
		binding [16]byte
	}{
		{"invalid encrypt object", ObjectContext{}, binding},
		{"zero encrypt binding", object, [16]byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := e.EncryptMPUManifest(context.Background(), tc.object, tc.binding, []byte("manifest")); err == nil {
				t.Fatal("invalid manifest encryption input accepted")
			}
		})
	}
}

func TestBoundMPUConstructorsRejectInvalidContextAndAuthentication(t *testing.T) {
	object := ObjectContext{Bucket: "constructors", Key: "object"}
	binding := phaseCBinding(33)
	dek := bytes.Repeat([]byte{7}, 32)
	args := func(obj ObjectContext, b [16]byte) (io.Reader, int64, error) {
		return NewMPUPartEncryptReader(context.Background(), obj, b, bytes.NewReader([]byte("data")), dek, [32]byte{}, [12]byte{}, 1, 4, 4, AlgorithmAES256GCM)
	}
	if _, _, err := args(ObjectContext{}, binding); err == nil {
		t.Fatal("invalid encryption object accepted")
	}
	if _, _, err := args(object, [16]byte{}); err == nil {
		t.Fatal("zero encryption binding accepted")
	}
	r, encLen, err := args(object, binding)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &MultipartManifest{Version: 2, ChunkSize: 4, Parts: []MPUPartRecord{{PartNumber: 1, PlainLen: 4, EncLen: encLen, ChunkCount: 1}}}
	if _, err := NewMPUDecryptReader(ObjectContext{}, binding, bytes.NewReader(ct), manifest, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM); err == nil {
		t.Fatal("invalid decrypt object accepted")
	}
	if _, err := NewMPUDecryptReader(object, [16]byte{}, bytes.NewReader(ct), manifest, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM); err == nil {
		t.Fatal("zero decrypt binding accepted")
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 1
	reader, err := NewMPUDecryptReader(object, binding, bytes.NewReader(bad), manifest, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil {
		t.Fatal("tampered MPU chunk accepted")
	}
}

func TestMPUDecryptDispatchAndRangeBoundaries(t *testing.T) {
	object := ObjectContext{Bucket: "dispatch", Key: "object"}
	dek := bytes.Repeat([]byte{7}, 32)

	if _, err := NewMPUDecryptReader(object, [16]byte{}, bytes.NewReader(nil), nil, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM); err == nil {
		t.Fatal("nil manifest accepted")
	}
	if _, err := NewMPUDecryptReader(object, phaseCBinding(18), bytes.NewReader(nil), &MultipartManifest{Version: 3}, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM); err == nil {
		t.Fatal("unsupported manifest version accepted")
	}
	if _, err := NewMPUDecryptReader(object, phaseCBinding(18), bytes.NewReader(nil), &MultipartManifest{Version: 2, Parts: []MPUPartRecord{{PartNumber: 1, PlainLen: 1, EncLen: 17, ChunkCount: 1}}, ChunkSize: 1}, dek, [32]byte{}, [12]byte{}, "unsupported"); err == nil {
		t.Fatal("unsupported algorithm accepted")
	}

	v1 := &MultipartManifest{Version: 1}
	r, err := NewMPUDecryptReader(object, [16]byte{}, bytes.NewReader(nil), v1, dek, [32]byte{}, [12]byte{}, AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(r); err != nil || len(got) != 0 {
		t.Fatalf("empty v1 reader: %d, %v", len(got), err)
	}

	if _, err := DecryptMPUPartRange(object, phaseCBinding(18), []byte("bad"), dek, [32]byte{}, [12]byte{}, 1, 0, 0, AlgorithmAES256GCM); err == nil {
		t.Fatal("truncated default-size range accepted")
	}

	plain := []byte("abcdefgh")
	r, _, err = NewMPUPartEncryptReader(context.Background(), object, phaseCBinding(18), bytes.NewReader(plain), dek, [32]byte{}, [12]byte{}, 1, 4, int64(len(plain)), AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	chunkCiphertext := ciphertext[20:]
	got, err := DecryptMPUPartRange(object, phaseCBinding(18), chunkCiphertext, dek, [32]byte{}, [12]byte{}, 1, 4, 1, AlgorithmAES256GCM)
	if err != nil || !bytes.Equal(got, plain[4:]) {
		t.Fatalf("valid range: %q, %v", got, err)
	}
}

func TestMultipartManifestValidateV1AndUnsupported(t *testing.T) {
	parent := ObjectContext{Bucket: "b", Key: "k"}
	companion := ObjectContext{Bucket: "b", Key: "k.mpu-manifest"}
	if err := (&MultipartManifest{Version: 1}).ValidateFor(parent, companion, [16]byte{}); err != nil {
		t.Fatalf("v1 relationship validation: %v", err)
	}
	if err := (&MultipartManifest{Version: 3}).ValidateFor(parent, companion, [16]byte{}); err == nil {
		t.Fatal("unsupported manifest version accepted")
	}
}

func mustEngine(t *testing.T, password string) *engine {
	t.Helper()
	e, err := NewEngine([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	return e.(*engine)
}

func TestObjectBinding_ConcurrentContextsDoNotCrossContaminate(t *testing.T) {
	eng, err := NewEngine([]byte("concurrent-object-binding-password"))
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		object ObjectContext
		body   []byte
		meta   map[string]string
	}
	objects := []ObjectContext{{Bucket: "b1", Key: "k1"}, {Bucket: "b2", Key: "k2"}}
	results := make(chan result, len(objects))
	errs := make(chan error, len(objects))
	for _, object := range objects {
		go func(object ObjectContext) {
			r, meta, e := eng.Encrypt(context.Background(), object, bytes.NewReader([]byte(object.Key)), nil)
			if e != nil {
				errs <- e
				return
			}
			body, e := io.ReadAll(r)
			if e != nil {
				errs <- e
				return
			}
			results <- result{object, body, meta}
		}(object)
	}
	for i := 0; i < len(objects); i++ {
		var got result
		select {
		case err := <-errs:
			t.Fatal(err)
		case got = <-results:
		}
		r, _, e := eng.Decrypt(context.Background(), got.object, bytes.NewReader(got.body), got.meta)
		if e != nil {
			t.Fatal(e)
		}
		plain, e := io.ReadAll(r)
		if e != nil || string(plain) != got.object.Key {
			t.Fatalf("isolated decrypt: %q, %v", plain, e)
		}
		for _, other := range objects {
			if other == got.object {
				continue
			}
			wrong, _, e := eng.Decrypt(context.Background(), other, bytes.NewReader(got.body), got.meta)
			if e == nil {
				_, e = io.ReadAll(wrong)
			}
			if e == nil {
				t.Fatalf("cross-context decrypt succeeded: %+v as %+v", got.object, other)
			}
		}
	}
}

func mustMarshal(t *testing.T, m *MultipartManifest) []byte {
	t.Helper()
	b, err := m.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
