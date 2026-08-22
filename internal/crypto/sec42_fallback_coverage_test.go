package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// TestSEC42_FallbackCoverage exercises every current fallback write/dispatch,
// seal/open, metadata restoration, and relocation branch in one artifact.
func TestSEC42_FallbackCoverage(t *testing.T) {
	e0, err := NewEngineWithProvider([]byte("coverage-password-123"), "", nil, "default")
	if err != nil {
		t.Fatal(err)
	}
	e := e0.(*engine)
	p := &ProviderProfile{Name: "coverage-overflow", UserMetadataLimit: 40, TotalHeaderLimit: 500, SupportsLongKeys: true, CompactionStrategy: "base64url"}
	e.providerProfile, e.compactor = p, NewMetadataCompactor(p)
	object := ObjectContext{Bucket: "coverage", Key: "source"}
	r, metadata, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("coverage")), map[string]string{"Content-Type": "text/plain", "x-amz-meta-large": string(bytes.Repeat([]byte("z"), 100))})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if r, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(body), metadata); err != nil {
		t.Fatal(err)
	} else if _, err = io.ReadAll(r); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.Decrypt(context.Background(), ObjectContext{Bucket: "coverage", Key: "moved"}, bytes.NewReader(body), metadata); err == nil {
		t.Fatal("relocated fallback accepted")
	}
	if len(body) == 0 {
		t.Fatal("empty fallback body")
	}
	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-1] ^= 1
	if _, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(tampered), metadata); err == nil {
		t.Fatal("tampered fallback accepted")
	}
}

func TestSEC42_FallbackWriterValidationAndOverflow(t *testing.T) {
	e0, err := NewEngine([]byte("fallback-validation-password"))
	if err != nil {
		t.Fatal(err)
	}
	e := e0.(*engine)
	object := ObjectContext{Bucket: "coverage", Key: "writer"}
	key := bytes.Repeat([]byte{1}, aesKeySize)
	nonce := bytes.Repeat([]byte{2}, 12)
	binding := bytes.Repeat([]byte{3}, 16)
	for name, dataKey := range map[string][]byte{
		"bad binding": bytes.Repeat([]byte{1}, 15),
		"bad key":     bytes.Repeat([]byte{1}, aesKeySize-1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := e.encryptWithMetadataFallback(context.Background(), object, []byte("body"), nil, "", 4, "", nil, nonce, dataKey, nil, binding); err == nil {
				t.Fatal("invalid writer input was accepted")
			}
		})
	}
	if _, _, err := e.encryptWithMetadataFallback(context.Background(), object, []byte("body"), nil, "", 4, "", nil, nonce, key, nil, bytes.Repeat([]byte{4}, 15)); err == nil {
		t.Fatal("invalid binding was accepted")
	}
	e.providerProfile = &ProviderProfile{Name: "overflow", TotalHeaderLimit: 1, SupportsLongKeys: true, CompactionStrategy: "base64url"}
	e.compactor = NewMetadataCompactor(e.providerProfile)
	if _, _, err := e.encryptWithMetadataFallback(context.Background(), object, []byte("body"), map[string]string{"x-amz-meta-large": "value"}, "", 4, "", []byte("salt"), nonce, key, nil, binding); err == nil {
		t.Fatal("required-header overflow was accepted")
	}
	e.providerProfile.TotalHeaderLimit = 10000
	e.compactor = NewMetadataCompactor(e.providerProfile)
	e.preferredAlgorithm = AlgorithmAES256GCM
	if _, _, err := e.encryptWithMetadataFallback(context.Background(), object, []byte("body"), nil, "", 4, "", []byte("salt"), nonce, key, nil, binding); err != nil {
		t.Fatal(err)
	}
	e.preferredAlgorithm = AlgorithmAES256GCM
	if _, _, err := e.encryptWithMetadataFallback(context.Background(), object, []byte("body"), map[string]string{
		MetaContentType:        "text/plain",
		MetaCacheControl:       "no-cache",
		MetaContentDisposition: "inline",
	}, "", 4, "etag", []byte("salt"), nonce, key, &KeyEnvelope{
		KeyVersion: 1, Ciphertext: []byte("wrapped"), KeyID: "key-id", Provider: "provider",
	}, binding); err != nil {
		t.Fatal(err)
	}
	e.preferredAlgorithm = "unsupported"
	if _, _, err := e.encryptWithMetadataFallback(context.Background(), object, []byte("body"), nil, "", 4, "", []byte("salt"), nonce, key, nil, binding); err == nil {
		t.Fatal("unsupported writer algorithm accepted")
	}
	e.preferredAlgorithm = AlgorithmAES256GCM
	e.compactor = NewMetadataCompactor(&ProviderProfile{Name: "no-compaction", TotalHeaderLimit: 1000, CompactionStrategy: "none"})
	if _, _, err := e.encryptWithMetadataFallback(context.Background(), object, []byte("body"), nil, "", 4, "", []byte("salt"), nonce, key, nil, binding); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.encryptWithMetadataFallback(context.Background(), ObjectContext{}, []byte("body"), nil, "", 4, "", []byte("salt"), nonce, key, nil, binding); err == nil {
		t.Fatal("invalid writer identity accepted")
	}
}

func TestSEC42_BoundFallbackValidationBranches(t *testing.T) {
	e0, err := NewEngine([]byte("fallback-validation-password"))
	if err != nil {
		t.Fatal(err)
	}
	e := e0.(*engine)
	e.providerProfile = &ProviderProfile{Name: "bound", UserMetadataLimit: 40, TotalHeaderLimit: 1000, SupportsLongKeys: true, CompactionStrategy: "base64url"}
	e.compactor = NewMetadataCompactor(e.providerProfile)
	object := ObjectContext{Bucket: "coverage", Key: "bound"}
	r, metadata, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("body")), map[string]string{"x-amz-meta-large": string(bytes.Repeat([]byte("x"), 100))})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	base := make(map[string]string, len(metadata))
	expanded, err := e.compactor.ExpandMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range expanded {
		base[k] = v
	}
	for name, mutate := range map[string]func(map[string]string){
		"binding":   func(m map[string]string) { m[MetaObjectBindingID] = "bad" },
		"salt":      func(m map[string]string) { m[MetaKeySalt] = "bad" },
		"iv":        func(m map[string]string) { m[MetaIV] = "bad" },
		"kdf":       func(m map[string]string) { m[MetaKDFParams] = "bad" },
		"algorithm": func(m map[string]string) { m[MetaAlgorithm] = "unsupported" },
		"format":    func(m map[string]string) { m[MetaObjectFormatVersion] = "wrong" },
	} {
		t.Run(name, func(t *testing.T) {
			m := make(map[string]string, len(base))
			for k, v := range base {
				m[k] = v
			}
			mutate(m)
			if r, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(body), m); err == nil {
				plaintext, _ := io.ReadAll(r)
				t.Fatalf("invalid fallback returned plaintext: %q", plaintext)
			}
		})
	}
	// Exercise the opener directly with full metadata so each validation branch
	// is tested independently of header compaction.
	for name, mutate := range map[string]func(map[string]string){
		"binding direct": func(m map[string]string) { m[MetaObjectBindingID] = "bad" },
		"salt direct":    func(m map[string]string) { m[MetaKeySalt] = "bad" },
		"iv direct":      func(m map[string]string) { m[MetaIV] = "bad" },
		"kdf direct":     func(m map[string]string) { m[MetaKDFParams] = "bad" },
		"algorithm direct": func(m map[string]string) {
			m[MetaAlgorithm] = "unsupported"
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := make(map[string]string, len(expanded))
			for k, v := range expanded {
				m[k] = v
			}
			mutate(m)
			if r, _, err := e.decryptFallbackBound(context.Background(), object, bytes.NewReader(body), m); err == nil {
				plaintext, _ := io.ReadAll(r)
				t.Fatalf("invalid direct fallback returned plaintext: %q", plaintext)
			}
		})
	}
	for name, body := range map[string][]byte{"empty": nil, "truncated": body[:len(body)-1]} {
		t.Run(name, func(t *testing.T) {
			if r, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(body), base); err == nil {
				plaintext, _ := io.ReadAll(r)
				t.Fatalf("malformed fallback returned plaintext: %q", plaintext)
			}
		})
	}
	// A valid tag around malformed fallback plaintext reaches the body framing
	// and metadata-length checks after authentication succeeds.
	plainSalt, err := decodeBase64(expanded[MetaKeySalt])
	if err != nil {
		t.Fatal(err)
	}
	plainIV, err := decodeBase64(expanded[MetaIV])
	if err != nil {
		t.Fatal(err)
	}
	bindingID, err := parseObjectBindingID(expanded[MetaObjectBindingID])
	if err != nil {
		t.Fatal(err)
	}
	plainKey, err := e.deriveKeyWithParams(plainSalt, e.defaultKDFParams())
	if err != nil {
		t.Fatal(err)
	}
	plainAEAD, err := createAEADCipher(expanded[MetaAlgorithm], plainKey)
	zeroBytes(plainKey)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := buildObjectAAD(aadBufferedV2, object, bindingID)
	if err != nil {
		t.Fatal(err)
	}
	malformedBody := plainAEAD.Seal(nil, plainIV, []byte{0, 0, 0}, aad)
	if _, _, err := e.decryptFallbackBound(context.Background(), object, bytes.NewReader(malformedBody), expanded); err == nil {
		t.Fatal("malformed authenticated body accepted")
	}
	badLengthBody := plainAEAD.Seal(nil, plainIV, []byte{0xff, 0xff, 0xff, 0xff}, aad)
	if _, _, err := e.decryptFallbackBound(context.Background(), object, bytes.NewReader(badLengthBody), expanded); err == nil {
		t.Fatal("invalid authenticated metadata length accepted")
	}
	badJSONBody := plainAEAD.Seal(nil, plainIV, []byte{0, 0, 0, 4, '{', 'b', 'a', 'd'}, aad)
	if _, _, err := e.decryptFallbackBound(context.Background(), object, bytes.NewReader(badJSONBody), expanded); err == nil {
		t.Fatal("invalid authenticated metadata JSON accepted")
	}
	shortBody := plainAEAD.Seal(nil, plainIV, []byte{0, 0, 0, 4, '{', '}', 'x', 'x'}, aad)
	if _, _, err := e.decryptFallbackBound(context.Background(), object, bytes.NewReader(shortBody), expanded); err == nil {
		t.Fatal("authenticated short metadata accepted")
	}
	richReader, richMetadata, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("rich body")), map[string]string{
		MetaContentType: "text/plain", MetaCacheControl: "no-cache", MetaContentDisposition: "inline",
	})
	if err != nil {
		t.Fatal(err)
	}
	richBody, err := io.ReadAll(richReader)
	if err != nil {
		t.Fatal(err)
	}
	richReader, restored, err := e.Decrypt(context.Background(), object, bytes.NewReader(richBody), richMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, readErr := io.ReadAll(richReader); readErr != nil || string(plaintext) != "rich body" || restored["Cache-Control"] != "no-cache" || restored["Content-Disposition"] != "inline" {
		t.Fatalf("rich fallback restoration plaintext=%q metadata=%v err=%v", plaintext, restored, readErr)
	}
	manager, err := NewInMemoryKeyManager(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	SetKeyManager(e, manager)
	e.providerProfile.TotalHeaderLimit = 1000
	e.compactor = NewMetadataCompactor(e.providerProfile)
	r, kmsMetadata, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("kms body")), map[string]string{"x-amz-meta-large": string(bytes.Repeat([]byte("q"), 100))})
	if err != nil {
		t.Fatal(err)
	}
	kmsBody, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if r, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(kmsBody), kmsMetadata); err != nil {
		t.Fatal(err)
	} else if plaintext, readErr := io.ReadAll(r); readErr != nil || string(plaintext) != "kms body" {
		t.Fatalf("KMS plaintext=%q err=%v", plaintext, readErr)
	}
	badKMS := make(map[string]string, len(kmsMetadata))
	for k, v := range kmsMetadata {
		badKMS[k] = v
	}
	badKMS["x-amz-meta-wk"] = "bad"
	if _, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(kmsBody), badKMS); err == nil {
		t.Fatal("invalid KMS envelope accepted")
	}
	for name, mutate := range map[string]func(map[string]string){
		"missing KMS fields":   func(m map[string]string) { delete(m, MetaKMSKeyID) },
		"bad wrapped encoding": func(m map[string]string) { m[MetaWrappedKeyCiphertext] = "%%%" },
	} {
		t.Run(name, func(t *testing.T) {
			m := make(map[string]string, len(kmsMetadata))
			for k, v := range kmsMetadata {
				m[k] = v
			}
			mutate(m)
			if _, _, err := e.decryptFallbackBound(context.Background(), object, bytes.NewReader(kmsBody), m); err == nil {
				t.Fatal("invalid KMS metadata accepted")
			}
		})
	}
}

func TestSEC42_FallbackDispatchAndLegacyFailures(t *testing.T) {
	e0, err := NewEngine([]byte("fallback-validation-password"))
	if err != nil {
		t.Fatal(err)
	}
	e := e0.(*engine)
	object := ObjectContext{Bucket: "coverage", Key: "dispatch"}
	for version := range map[string]bool{"4": true, "3": true} {
		m := map[string]string{MetaEncrypted: "true", MetaFallbackMode: "true", MetaFallbackVersion: version}
		if version == "3" {
			m[MetaObjectFormatVersion] = "wrong"
		}
		if _, _, err := e.Decrypt(context.Background(), object, bytes.NewReader([]byte("not plaintext")), m); err == nil {
			t.Fatalf("version %s dispatch accepted", version)
		}
	}
	if _, _, err := e.decryptWithMetadataFallback(context.Background(), object, bytes.NewReader(nil), map[string]string{
		MetaFallbackVersion: "3", MetaObjectFormatVersion: "wrong",
	}); err == nil {
		t.Fatal("invalid direct v3 dispatch accepted")
	}
	legacy := map[string]string{MetaEncrypted: "true", MetaFallbackMode: "true", MetaAlgorithm: AlgorithmAES256GCM, MetaKeySalt: "bad", MetaIV: "bad"}
	if _, _, err := e.Decrypt(context.Background(), object, bytes.NewReader([]byte("legacy")), legacy); err == nil {
		t.Fatal("malformed legacy fallback accepted")
	}
	legacy[MetaKeySalt] = encodeBase64(bytes.Repeat([]byte{1}, 16))
	legacy[MetaIV] = encodeBase64(bytes.Repeat([]byte{2}, 12))
	for name, change := range map[string]func(map[string]string){
		"unsupported algorithm": func(m map[string]string) { m[MetaAlgorithm] = "unsupported" },
		"bad kdf":               func(m map[string]string) { m[MetaKDFParams] = "bad" },
	} {
		t.Run(name, func(t *testing.T) {
			m := make(map[string]string, len(legacy))
			for k, v := range legacy {
				m[k] = v
			}
			change(m)
			if _, _, err := e.Decrypt(context.Background(), object, bytes.NewReader([]byte("legacy")), m); err == nil {
				t.Fatal("invalid legacy fallback accepted")
			}
		})
	}
}
