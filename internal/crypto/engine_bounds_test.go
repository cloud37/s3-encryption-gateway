package crypto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestCheckedLengthPrefix_Uint32Bounds(t *testing.T) {
	for _, length := range []uint64{0, 1, math.MaxUint32 - 1, math.MaxUint32, math.MaxUint32 + 1, math.MaxUint64} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			// Only a numeric length is passed: no huge slice or unsafe header is needed.
			prefix, err := checkedLengthPrefix(length)
			if length > math.MaxUint32 {
				if err == nil || prefix != [4]byte{} {
					t.Fatalf("oversized length encoded: prefix=%x err=%v", prefix, err)
				}
				return
			}
			if err != nil || uint64(binary.BigEndian.Uint32(prefix[:])) != length {
				t.Fatalf("length=%d prefix=%x err=%v", length, prefix, err)
			}
		})
	}
}

func TestCheckedMetadataEnd_WideBounds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		declared  uint32
		available uint64
		wantEnd   uint64
		wantError bool
	}{
		{"missing prefix", 0, 3, 0, true},
		{"empty metadata", 0, 4, 4, false},
		{"exact metadata", 2, 6, 6, false},
		{"truncated metadata", 3, 6, 0, true},
		{"high bit in tiny body", 1 << 31, 6, 0, true},
		{"uint32 max in tiny body", math.MaxUint32, 6, 0, true},
		// The old uint32(available-4) comparison wrapped to zero and
		// rejected this valid small metadata prefix in a >4 GiB body.
		{"body crosses uint32", 2, uint64(math.MaxUint32) + 5, 6, false},
		{"body crosses uint32 with remainder", 3, uint64(math.MaxUint32) + 6, 7, false},
		{"largest declared prefix", math.MaxUint32, uint64(math.MaxUint32) + 4, uint64(math.MaxUint32) + 4, false},
		{"largest prefix truncated", math.MaxUint32, uint64(math.MaxUint32) + 3, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			end, err := checkedMetadataEnd(tc.declared, tc.available)
			if (err != nil) != tc.wantError || end != tc.wantEnd {
				t.Fatalf("end=%d err=%v; want end=%d error=%v", end, err, tc.wantEnd, tc.wantError)
			}
		})
	}
}

func TestWriteLengthPrefixed_WireBytes(t *testing.T) {
	var buf bytes.Buffer
	for _, data := range [][]byte{nil, []byte{'a', 0, 'b'}} {
		if err := writeLengthPrefixed(&buf, data); err != nil {
			t.Fatal(err)
		}
	}
	want := []byte{0, 0, 0, 0, 0, 0, 0, 3, 'a', 0, 'b'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("wire bytes=%x want=%x", buf.Bytes(), want)
	}
}

func TestBuildAAD_WireBytes(t *testing.T) {
	aad, err := buildAAD("alg", []byte{0, 255}, []byte{1}, map[string]string{
		MetaKeyVersion: "v1", "Content-Type": "", MetaOriginalSize: "7",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Fixed algorithm/salt/nonce/version/content-type/size order, including
	// zero-length fields; this is the existing legacy length-prefixed format.
	want := []byte{
		0, 0, 0, 3, 'a', 'l', 'g',
		0, 0, 0, 2, 0, 255,
		0, 0, 0, 1, 1,
		0, 0, 0, 2, 'v', '1',
		0, 0, 0, 0,
		0, 0, 0, 1, '7',
	}
	if !bytes.Equal(aad, want) {
		t.Fatalf("AAD bytes=%x want=%x", aad, want)
	}
}

func TestDecryptFallbackBound_RejectsOversizedPrefix(t *testing.T) {
	// Use real AES key wrapping rather than any password KDF. Each fixture
	// authenticates a four-byte plaintext; validation must reject before slicing.
	ctx := context.Background()
	object := ObjectContext{Bucket: "bucket", Key: "key"}
	bindingID := bytes.Repeat([]byte{3}, 16)
	key := bytes.Repeat([]byte{4}, aesKeySize)
	defer zeroBytes(key)
	km, err := NewInMemoryKeyManager(bytes.Repeat([]byte{5}, aesKeySize))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := km.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	envelope, err := km.WrapKey(ctx, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	metadata := map[string]string{
		MetaObjectBindingID:      base64.RawURLEncoding.EncodeToString(bindingID),
		MetaKeySalt:              encodeBase64(bytes.Repeat([]byte{6}, saltSize)),
		MetaIV:                   encodeBase64(bytes.Repeat([]byte{7}, nonceSize)),
		MetaAlgorithm:            AlgorithmAES256GCM,
		MetaKMSKeyID:             envelope.KeyID,
		MetaKMSProvider:          envelope.Provider,
		MetaKeyVersion:           fmt.Sprint(envelope.KeyVersion),
		MetaWrappedKeyCiphertext: encodeBase64(envelope.Ciphertext),
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := buildObjectAAD(aadBufferedV2, object, bindingID)
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{kmsManager: km}
	for i, length := range []uint32{1, math.MaxInt32, 1 << 31, math.MaxUint32} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			var plaintext [4]byte
			binary.BigEndian.PutUint32(plaintext[:], length)
			iv := make([]byte, nonceSize)
			binary.BigEndian.PutUint64(iv[nonceSize-8:], uint64(i+1))
			metadata[MetaIV] = encodeBase64(iv)
			body := aead.Seal(nil, iv, plaintext[:], aad)
			reader, restored, err := e.decryptFallbackBound(ctx, object, bytes.NewReader(body), metadata)
			if err == nil || !strings.Contains(err.Error(), "invalid metadata length") || reader != nil || restored != nil {
				t.Fatalf("reader=%v metadata=%v err=%v", reader, restored, err)
			}
		})
	}
}
