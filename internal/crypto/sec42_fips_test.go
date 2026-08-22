//go:build fips

package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestObjectBinding_FIPS_BufferedChunkedAndMPU(t *testing.T) {
	eng, err := NewEngineWithChunking([]byte("fips-object-binding-password"), "", nil, true, MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	object := ObjectContext{Bucket: "fips-bucket", Key: "fips-key"}
	input := bytes.NewReader(bytes.Repeat([]byte("f"), MinChunkSize+3))
	r, meta, err := eng.Encrypt(context.Background(), object, input, nil)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	dec, _, err := eng.Decrypt(context.Background(), object, bytes.NewReader(ct), meta)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.ReadAll(dec); err != nil {
		t.Fatal(err)
	}
	wrongReader, _, err := eng.Decrypt(context.Background(), ObjectContext{Bucket: "wrong", Key: object.Key}, bytes.NewReader(ct), meta)
	if err == nil {
		if _, err = io.ReadAll(wrongReader); err == nil {
			t.Fatal("wrong FIPS context accepted")
		}
	}
	var binding [16]byte
	for i := range binding {
		binding[i] = byte(i + 1)
	}
	dek := bytes.Repeat([]byte{7}, 32)
	part, _, err := NewMPUPartEncryptReader(context.Background(), object, binding, bytes.NewReader([]byte("fips-mpu")), dek, [32]byte{}, [12]byte{}, 1, 64, 8, AlgorithmAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	partCT, err := io.ReadAll(part)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DecryptMPUPartRange(object, binding, partCT, dek, [32]byte{}, [12]byte{}, 1, 64, 0, AlgorithmAES256GCM)
	if err != nil || string(plain) != "fips-mpu" {
		t.Fatalf("FIPS MPU decrypt: %q, %v", plain, err)
	}
	wrongPlain, err := DecryptMPUPartRange(ObjectContext{Bucket: "wrong", Key: object.Key}, binding, partCT, dek, [32]byte{}, [12]byte{}, 1, 64, 0, AlgorithmAES256GCM)
	if err == nil {
		t.Fatalf("wrong FIPS MPU context accepted: %q", wrongPlain)
	}
}
