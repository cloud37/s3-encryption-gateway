package crypto

import (
	"bytes"
	"context"
	"crypto/cipher"
	"io"
	"testing"
)

func TestEngine_MetadataFallback(t *testing.T) {
	// Create a provider profile with very small limits to force fallback
	profile := &ProviderProfile{
		Name:                "test-small-limits",
		UserMetadataLimit:   50, // Very small limit to force fallback
		SystemMetadataLimit: 0,
		TotalHeaderLimit:    500, // Small enough to require fallback, large enough for required headers
		SupportsLongKeys:    true,
		CompactionStrategy:  "base64url",
	}

	encEngine, err := NewEngineWithProvider([]byte("test-password-123456789"), "", nil, "default")
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Type assert to concrete engine type to access internal fields
	concreteEngine, ok := encEngine.(*engine)
	if !ok {
		t.Fatalf("Failed to type assert to concrete engine")
	}

	// Override the provider profile to use small limits
	concreteEngine.providerProfile = profile
	concreteEngine.compactor = NewMetadataCompactor(profile)

	// Create metadata that will exceed limits even when compacted
	largeMetadata := map[string]string{
		"Content-Type": "application/json",
		"x-amz-meta-very-long-user-metadata-key-that-exceeds-limits": "very-long-user-metadata-value-that-will-cause-header-overflow",
		"x-amz-meta-another-key":                                     "another-value",
		"x-amz-meta-third-key":                                       "third-value",
	}

	// Test data
	testData := []byte("Hello, World! This is test data for fallback mode.")

	// Encrypt - should use fallback mode
	reader := bytes.NewReader(testData)
	encryptedReader, encMetadata, err := encEngine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, largeMetadata)
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}

	// Verify fallback mode was used
	expanded, err := concreteEngine.compactor.ExpandMetadata(encMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if expanded[MetaFallbackMode] != "true" {
		t.Errorf("Expected fallback mode, but MetaFallbackMode != 'true'")
	}
	if expanded[MetaFallbackVersion] != "3" || expanded[MetaObjectFormatVersion] != "buffered-fallback-v2" {
		t.Fatalf("new buffered fallback is not declared bound format: version=%q format=%q", expanded[MetaFallbackVersion], expanded[MetaObjectFormatVersion])
	}

	// Verify minimal metadata in headers
	if expanded[MetaEncrypted] != "true" {
		t.Errorf("Expected encrypted flag in headers")
	}
	if expanded[MetaAlgorithm] == "" {
		t.Errorf("Expected algorithm in headers")
	}
	if expanded[MetaKeySalt] == "" {
		t.Errorf("Expected key salt in headers")
	}
	if _, ok := encMetadata["x-amz-meta-very-long-user-metadata-key-that-exceeds-limits"]; ok {
		t.Errorf("overflowing user metadata must not remain in fallback headers")
	}
	if _, ok := encMetadata["x-amz-meta-another-key"]; ok {
		t.Errorf("arbitrary user metadata must not remain in fallback headers")
	}

	// Read encrypted data
	encryptedData, err := ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Verify encrypted data is different
	if bytes.Equal(encryptedData, testData) {
		t.Errorf("Encrypted data should be different from plaintext")
	}

	// Decrypt
	decryptReader, decMetadata, err := encEngine.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}

	// Read decrypted data
	decryptedData, err := ReadAll(decryptReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	// Verify data integrity
	if !bytes.Equal(decryptedData, testData) {
		t.Errorf("Decrypted data doesn't match original: got %q, want %q", decryptedData, testData)
	}

	// Verify metadata restoration
	if decMetadata["Content-Type"] != "application/json" {
		t.Errorf("Content-Type not restored: got %q", decMetadata["Content-Type"])
	}
	if decMetadata["x-amz-meta-very-long-user-metadata-key-that-exceeds-limits"] != "very-long-user-metadata-value-that-will-cause-header-overflow" {
		t.Errorf("User metadata not restored")
	}
}

type recordingFallbackKeyManager struct {
	delegate       KeyManager
	wraps, unwraps int
}

func (m *recordingFallbackKeyManager) Provider() string { return m.delegate.Provider() }
func (m *recordingFallbackKeyManager) WrapKey(ctx context.Context, dek []byte, meta map[string]string) (*KeyEnvelope, error) {
	m.wraps++
	return m.delegate.WrapKey(ctx, dek, meta)
}
func (m *recordingFallbackKeyManager) UnwrapKey(ctx context.Context, env *KeyEnvelope, meta map[string]string) ([]byte, error) {
	m.unwraps++
	return m.delegate.UnwrapKey(ctx, env, meta)
}
func (m *recordingFallbackKeyManager) ActiveKeyVersion(ctx context.Context) (int, error) {
	return m.delegate.ActiveKeyVersion(ctx)
}
func (m *recordingFallbackKeyManager) HealthCheck(ctx context.Context) error {
	return m.delegate.HealthCheck(ctx)
}
func (m *recordingFallbackKeyManager) Close(ctx context.Context) error { return m.delegate.Close(ctx) }

func TestBufferedFallback_RecordingKeyManagerAndMissingEnvelope(t *testing.T) {
	base, err := NewInMemoryKeyManager(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	km := &recordingFallbackKeyManager{delegate: base}
	enc, err := NewEngine([]byte("fallback-kms-password-123"))
	if err != nil {
		t.Fatal(err)
	}
	SetKeyManager(enc, km)
	e := enc.(*engine)
	p := &ProviderProfile{Name: "kms-compact", UserMetadataLimit: 40, TotalHeaderLimit: 1000, SupportsLongKeys: true, CompactionStrategy: "base64url"}
	e.providerProfile, e.compactor = p, NewMetadataCompactor(p)
	obj := ObjectContext{Bucket: "bucket", Key: "key"}
	r, meta, err := e.Encrypt(context.Background(), obj, bytes.NewReader([]byte("kms body")), map[string]string{"x-amz-meta-overflow": string(bytes.Repeat([]byte("q"), 150))})
	if err != nil {
		t.Fatal(err)
	}
	if km.wraps != 1 {
		t.Fatalf("WrapKey calls=%d", km.wraps)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = e.Decrypt(context.Background(), obj, bytes.NewReader(body), meta); err != nil {
		t.Fatal(err)
	}
	if km.unwraps != 1 {
		t.Fatalf("UnwrapKey calls=%d", km.unwraps)
	}
	missing := make(map[string]string, len(meta))
	for k, v := range meta {
		missing[k] = v
	}
	delete(missing, "x-amz-meta-wk")
	if r, _, err = e.Decrypt(context.Background(), obj, bytes.NewReader(body), missing); err == nil {
		if got, _ := io.ReadAll(r); len(got) > 0 {
			t.Fatalf("plaintext returned: %q", got)
		}
	} else if km.unwraps != 1 {
		t.Fatalf("missing envelope unexpectedly called unwrap: %d", km.unwraps)
	}
}

func TestBufferedFallback_LegacyV1Compatibility(t *testing.T) {
	e0, err := NewEngine([]byte("legacy-fallback-password-123"))
	if err != nil {
		t.Fatal(err)
	}
	e := e0.(*engine)
	salt, err := e.generateSalt()
	if err != nil {
		t.Fatal(err)
	}
	iv, err := e.generateNonce()
	if err != nil {
		t.Fatal(err)
	}
	key, err := e.deriveKey(salt)
	if err != nil {
		t.Fatal(err)
	}
	defer zeroBytes(key)
	aead, err := createAEADCipher(AlgorithmAES256GCM, key)
	if err != nil {
		t.Fatal(err)
	}
	gcm := aead.(cipher.AEAD)
	full := map[string]string{MetaEncrypted: "true", MetaOriginalSize: "9", MetaOriginalETag: "legacy-etag", MetaContentType: "text/plain", "x-amz-meta-user": "restored"}
	encoded, err := encodeMetadataToJSON(full)
	if err != nil {
		t.Fatal(err)
	}
	pt := append([]byte{0, 0, 0, byte(len(encoded))}, encoded...)
	pt = append(pt, []byte("legacy-v1")...)
	aad := buildAAD(AlgorithmAES256GCM, salt, iv, map[string]string{"Content-Type": "text/plain", MetaOriginalSize: "9"})
	body := gcm.Seal(nil, iv, pt, aad)
	meta := map[string]string{MetaEncrypted: "true", MetaFallbackMode: "true", MetaAlgorithm: AlgorithmAES256GCM, MetaKeySalt: encodeBase64(salt), MetaIV: encodeBase64(iv), MetaKDFParams: FormatKDFParams(e.defaultKDFParams()), MetaOriginalSize: "9", MetaContentType: "text/plain"}
	r, restored, err := e.Decrypt(context.Background(), ObjectContext{Bucket: "legacy", Key: "object"}, bytes.NewReader(body), meta)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "legacy-v1" {
		t.Fatalf("got %q: %v", got, err)
	}
	if restored["x-amz-meta-user"] != "restored" {
		t.Fatal("legacy user metadata not restored")
	}
}

func TestBufferedFallback_BindsRelocationAndFailsClosed(t *testing.T) {
	encEngine, err := NewEngineWithProvider([]byte("test-password-123456789"), "", nil, "default")
	if err != nil {
		t.Fatal(err)
	}
	e := encEngine.(*engine)
	profile := &ProviderProfile{Name: "overflow", UserMetadataLimit: 50, TotalHeaderLimit: 500, SupportsLongKeys: true, CompactionStrategy: "base64url"}
	e.providerProfile, e.compactor = profile, NewMetadataCompactor(profile)
	object := ObjectContext{Bucket: "source-bucket", Key: "source-key"}
	meta := map[string]string{"x-amz-meta-overflow": string(bytes.Repeat([]byte("x"), 200))}
	r, storedMeta, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("secret")), meta)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if r, _, err := e.Decrypt(context.Background(), object, bytes.NewReader(body), storedMeta); err != nil {
		t.Fatalf("source decrypt failed: %v", err)
	} else if got, err := io.ReadAll(r); err != nil || string(got) != "secret" {
		t.Fatalf("source plaintext=%q err=%v", got, err)
	}
	wrong := ObjectContext{Bucket: object.Bucket, Key: "destination-key"}
	if r, _, err := e.Decrypt(context.Background(), wrong, bytes.NewReader(body), storedMeta); err == nil {
		got, readErr := io.ReadAll(r)
		t.Fatalf("relocated fallback decrypted: %q, err=%v", got, readErr)
	}
	wrongBucket := ObjectContext{Bucket: "destination-bucket", Key: object.Key}
	if _, _, err := e.Decrypt(context.Background(), wrongBucket, bytes.NewReader(body), storedMeta); err == nil {
		t.Fatal("relocated fallback accepted under wrong bucket")
	}
	wrongPassword, err := NewEngine([]byte("wrong-password-123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if r, _, err := wrongPassword.Decrypt(context.Background(), object, bytes.NewReader(body), storedMeta); err == nil {
		got, _ := io.ReadAll(r)
		t.Fatalf("wrong password decrypted fallback: %q", got)
	}
}

func TestBufferedFallback_DeclaredBoundFormatDoesNotFallbackToV1(t *testing.T) {
	encEngine, err := NewEngine([]byte("test-password-123456789"))
	if err != nil {
		t.Fatal(err)
	}
	e := encEngine.(*engine)
	meta := map[string]string{
		MetaEncrypted: "true", MetaFallbackMode: "true", MetaFallbackVersion: "3",
		MetaObjectFormatVersion: "buffered-fallback-v2", MetaObjectBindingID: "bad",
	}
	if _, _, err := e.Decrypt(context.Background(), ObjectContext{Bucket: "b", Key: "k"}, bytes.NewReader([]byte("legacy-looking")), meta); err == nil {
		t.Fatal("malformed declared bound fallback entered legacy recovery")
	}
}

func TestBufferedFallback_KeyManagerRoundTrip(t *testing.T) {
	manager, err := NewInMemoryKeyManager(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := NewEngine([]byte("test-password-123456789"))
	if err != nil {
		t.Fatal(err)
	}
	SetKeyManager(decrypted, manager)
	e := decrypted.(*engine)
	p := &ProviderProfile{Name: "kms-overflow", UserMetadataLimit: 40, TotalHeaderLimit: 1000, SupportsLongKeys: true, CompactionStrategy: "base64url"}
	e.providerProfile, e.compactor = p, NewMetadataCompactor(p)
	object := ObjectContext{Bucket: "kms-bucket", Key: "kms-key"}
	r, metadata, err := e.Encrypt(context.Background(), object, bytes.NewReader([]byte("kms secret")), map[string]string{"x-amz-meta-large": string(bytes.Repeat([]byte("x"), 100))})
	if err != nil {
		t.Fatal(err)
	}
	if metadata["x-amz-meta-wk"] == "" || metadata["x-amz-meta-kid"] == "" || metadata["x-amz-meta-kp"] == "" {
		t.Fatalf("missing envelope metadata: %#v", metadata)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err = e.Decrypt(context.Background(), object, bytes.NewReader(body), metadata)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "kms secret" {
		t.Fatalf("got %q: %v", got, err)
	}
}

func TestEngine_FallbackDetection(t *testing.T) {
	tests := []struct {
		name           string
		totalLimit     int
		metadata       map[string]string
		expectFallback bool
	}{
		{
			name:       "within limits",
			totalLimit: 1000,
			metadata: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expectFallback: false,
		},
		{
			name:       "exceeds limits",
			totalLimit: 10,
			metadata: map[string]string{
				"x-amz-meta-very-long-key": "very-long-value",
			},
			expectFallback: true,
		},
		{
			name:       "unlimited provider",
			totalLimit: 0, // unlimited
			metadata: map[string]string{
				"x-amz-meta-very-long-key": "very-long-value",
			},
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := &ProviderProfile{
				Name:                "test",
				UserMetadataLimit:   tt.totalLimit,
				SystemMetadataLimit: 0,
				TotalHeaderLimit:    tt.totalLimit,
				SupportsLongKeys:    true,
				CompactionStrategy:  "base64url",
			}

			encEngine, err := NewEngineWithProvider([]byte("test-password-123"), "", nil, "default")
			if err != nil {
				t.Fatalf("Failed to create engine: %v", err)
			}

			concreteEngine, ok := encEngine.(*engine)
			if !ok {
				t.Fatalf("Failed to type assert to concrete engine")
			}
			concreteEngine.providerProfile = profile
			concreteEngine.compactor = NewMetadataCompactor(profile)

			result := concreteEngine.needsMetadataFallback(tt.metadata)
			if result != tt.expectFallback {
				t.Errorf("needsMetadataFallback() = %v, want %v", result, tt.expectFallback)
			}
		})
	}
}

func TestEngine_IsFallbackMode(t *testing.T) {
	encEngine, err := NewEngine([]byte("test-password-123"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	concreteEngine, ok := encEngine.(*engine)
	if !ok {
		t.Fatalf("Failed to type assert to concrete engine")
	}

	tests := []struct {
		metadata       map[string]string
		expectFallback bool
	}{
		{
			metadata:       map[string]string{MetaFallbackMode: "true"},
			expectFallback: true,
		},
		{
			metadata:       map[string]string{MetaFallbackMode: "false"},
			expectFallback: false,
		},
		{
			metadata:       map[string]string{},
			expectFallback: false,
		},
		{
			metadata:       nil,
			expectFallback: false,
		},
	}

	for _, tt := range tests {
		result := concreteEngine.isFallbackMode(tt.metadata)
		if result != tt.expectFallback {
			t.Errorf("isFallbackMode() = %v, want %v for metadata %v", result, tt.expectFallback, tt.metadata)
		}
	}
}

func TestMetadataJSONEncoding(t *testing.T) {
	original := map[string]string{
		"key1":            "value1",
		"key2":            "value2",
		"x-amz-meta-user": "data",
	}

	// Encode
	jsonData, err := encodeMetadataToJSON(original)
	if err != nil {
		t.Fatalf("encodeMetadataToJSON failed: %v", err)
	}

	// Decode
	decoded, err := decodeMetadataFromJSON(jsonData)
	if err != nil {
		t.Fatalf("decodeMetadataFromJSON failed: %v", err)
	}

	// Compare
	if len(decoded) != len(original) {
		t.Errorf("Length mismatch: got %d, want %d", len(decoded), len(original))
	}

	for k, v := range original {
		if decoded[k] != v {
			t.Errorf("Value mismatch for key %q: got %q, want %q", k, decoded[k], v)
		}
	}
}

// ReadAll is a helper to read all data from a reader (avoids import issues)
func ReadAll(r io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}
