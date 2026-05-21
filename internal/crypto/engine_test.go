package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func TestNewEngine(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: []byte("test-password-123456"),
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: []byte(""),
			wantErr:  true,
		},
		{
			name:     "short password",
			password: []byte("short"),
			wantErr:  true,
		},
		{
			name:     "minimum length password",
			password: []byte("123456789012"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewEngine(tt.password)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewEngine() expected error, got nil")
				}
				if engine != nil {
					t.Errorf("NewEngine() expected nil engine on error, got %v", engine)
				}
				return
			}

			if err != nil {
				t.Errorf("NewEngine() unexpected error: %v", err)
				return
			}

			if engine == nil {
				t.Errorf("NewEngine() expected engine, got nil")
			}
		})
	}
}

func TestEngine_EncryptDecrypt(t *testing.T) {
	engine, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "small data",
			data: []byte("Hello, World!"),
		},
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "medium data",
			data: make([]byte, 1024),
		},
		{
			name: "large data",
			data: make([]byte, 64*1024),
		},
		{
			name: "binary data",
			data: []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			reader := bytes.NewReader(tt.data)
			metadata := make(map[string]string)
			metadata["Content-Type"] = "text/plain"

			encryptedReader, encMetadata, err := engine.Encrypt(context.Background(), reader, metadata)
			if err != nil {
				t.Fatalf("Encrypt() error: %v", err)
			}

			// Verify encryption metadata
			if encMetadata[MetaEncrypted] != "true" {
				t.Errorf("Encrypt() metadata missing encrypted flag")
			}
			if encMetadata[MetaAlgorithm] != AlgorithmAES256GCM {
				t.Errorf("Encrypt() metadata wrong algorithm: got %s, want %s", encMetadata[MetaAlgorithm], AlgorithmAES256GCM)
			}
			if encMetadata[MetaKeySalt] == "" {
				t.Errorf("Encrypt() metadata missing salt")
			}
			if encMetadata[MetaIV] == "" {
				t.Errorf("Encrypt() metadata missing IV")
			}

			// Read encrypted data
			encryptedData, err := io.ReadAll(encryptedReader)
			if err != nil {
				t.Fatalf("Failed to read encrypted data: %v", err)
			}

			// Encrypted data should be different and longer (due to authentication tag)
			if bytes.Equal(encryptedData, tt.data) {
				t.Errorf("Encrypt() encrypted data should differ from plaintext")
			}
			if len(encryptedData) <= len(tt.data) {
				t.Errorf("Encrypt() encrypted data should be longer (has auth tag), got %d, want > %d", len(encryptedData), len(tt.data))
			}

			// Decrypt
			decryptedReader, decMetadata, err := engine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
			if err != nil {
				t.Fatalf("Decrypt() error: %v", err)
			}

			// Verify decryption metadata (encryption markers should be removed)
			if decMetadata[MetaEncrypted] != "" {
				t.Errorf("Decrypt() should remove encryption metadata, got %s", decMetadata[MetaEncrypted])
			}
			if decMetadata["Content-Type"] != "text/plain" {
				t.Errorf("Decrypt() should preserve original metadata, got Content-Type=%s", decMetadata["Content-Type"])
			}

			// Read decrypted data
			decryptedData, err := io.ReadAll(decryptedReader)
			if err != nil {
				t.Fatalf("Failed to read decrypted data: %v", err)
			}

			// Verify round-trip
			if !bytes.Equal(decryptedData, tt.data) {
				t.Errorf("Decrypt() decrypted data mismatch\nGot:  %x\nWant: %x", decryptedData, tt.data)
			}
		})
	}
}

func TestEngine_IsEncrypted(t *testing.T) {
	engine, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	tests := []struct {
		name     string
		metadata map[string]string
		want     bool
	}{
		{
			name: "encrypted object",
			metadata: map[string]string{
				MetaEncrypted: "true",
			},
			want: true,
		},
		{
			name: "not encrypted",
			metadata: map[string]string{
				"Content-Type": "text/plain",
			},
			want: false,
		},
		{
			name:     "nil metadata",
			metadata: nil,
			want:     false,
		},
		{
			name:     "empty metadata",
			metadata: map[string]string{},
			want:     false,
		},
		{
			name: "encrypted flag false",
			metadata: map[string]string{
				MetaEncrypted: "false",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := engine.IsEncrypted(tt.metadata)
			if got != tt.want {
				t.Errorf("IsEncrypted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEngine_DecryptUnencrypted(t *testing.T) {
	engine, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Try to decrypt unencrypted data
	data := []byte("plaintext data")
	metadata := map[string]string{
		"Content-Type": "text/plain",
	}

	decryptedReader, decMetadata, err := engine.Decrypt(context.Background(), bytes.NewReader(data), metadata)
	if err != nil {
		t.Fatalf("Decrypt() should not error on unencrypted data: %v", err)
	}

	// Should return data as-is
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}

	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() unencrypted data should be unchanged, got %x, want %x", decryptedData, data)
	}

	if decMetadata["Content-Type"] != "text/plain" {
		t.Errorf("Decrypt() should preserve metadata for unencrypted data")
	}
}

func TestEngine_WrongPassword(t *testing.T) {
	// Encrypt with one password
	engine1, err := NewEngine([]byte("password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := []byte("secret data")
	reader := bytes.NewReader(data)
	encryptedReader, encMetadata, err := engine1.Encrypt(context.Background(), reader, nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Try to decrypt with wrong password
	engine2, err := NewEngine([]byte("wrong-password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	_, _, err = engine2.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err == nil {
		t.Errorf("Decrypt() with wrong password should fail")
	}
}

func TestEngine_DifferentSaltPerEncryption(t *testing.T) {
	engine, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := []byte("test data")

	// Encrypt twice
	encrypted1, metadata1, err := engine.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	encrypted2, metadata2, err := engine.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Salts should be different
	if metadata1[MetaKeySalt] == metadata2[MetaKeySalt] {
		t.Errorf("Encrypt() should generate different salt each time")
	}

	// IVs should be different
	if metadata1[MetaIV] == metadata2[MetaIV] {
		t.Errorf("Encrypt() should generate different IV each time")
	}

	// Encrypted data should be different (even with same plaintext)
	encData1, _ := io.ReadAll(encrypted1)
	encData2, _ := io.ReadAll(encrypted2)
	if bytes.Equal(encData1, encData2) {
		t.Errorf("Encrypt() should produce different ciphertext each time")
	}

	// But both should decrypt to same plaintext
	dec1, _, _ := engine.Decrypt(context.Background(), bytes.NewReader(encData1), metadata1)
	dec2, _, _ := engine.Decrypt(context.Background(), bytes.NewReader(encData2), metadata2)
	decData1, _ := io.ReadAll(dec1)
	decData2, _ := io.ReadAll(dec2)

	if !bytes.Equal(decData1, data) {
		t.Errorf("Decrypt() failed for first encryption")
	}
	if !bytes.Equal(decData2, data) {
		t.Errorf("Decrypt() failed for second encryption")
	}
}

func TestEngine_OriginalETagPreservation(t *testing.T) {
	engine, err := NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := []byte("test data for ETag preservation")
	reader := bytes.NewReader(data)

	// Compute expected ETag for the test (uses the same algorithm as the
	// engine – MD5 in default builds, SHA-256 in FIPS builds).
	expectedETag := computeETag(data)

	// Encrypt with ETag provided in metadata
	metadata := map[string]string{
		"ETag": expectedETag,
	}
	encryptedReader, encMetadata, err := engine.Encrypt(context.Background(), reader, metadata)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Verify original ETag is stored
	originalETag, ok := encMetadata[MetaOriginalETag]
	if !ok {
		t.Errorf("Encrypt() should store original ETag in metadata")
	}
	if originalETag == "" {
		t.Errorf("Encrypt() original ETag should not be empty")
	}

	// Verify ETag is a valid hex string (MD5 = 32 chars, SHA-256 = 64 chars).
	if len(originalETag) != 32 && len(originalETag) != 64 {
		t.Errorf("Encrypt() original ETag has unexpected length, got %d", len(originalETag))
	}

	// Decrypt and verify ETag is restored
	encryptedData, _ := io.ReadAll(encryptedReader)
	decryptedReader, decMetadata, err := engine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	// Verify ETag is restored in decrypted metadata
	restoredETag, ok := decMetadata["ETag"]
	if !ok {
		t.Errorf("Decrypt() should restore original ETag")
	}
	if restoredETag != originalETag {
		t.Errorf("Decrypt() restored ETag mismatch: got %s, want %s", restoredETag, originalETag)
	}

	// Verify the ETag matches the provided ETag
	if originalETag != expectedETag {
		t.Errorf("Encrypt() ETag mismatch: got %s, want %s", originalETag, expectedETag)
	}

	// Verify decrypted data matches original
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}


func TestEncryptDecrypt_DefaultIterations(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for default iterations")
	encryptedReader, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestEncryptDecrypt_ExplicitIterations_100k(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for 100k iterations")
	encryptedReader, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestEncryptDecrypt_ExplicitIterations_600k(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(600000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for 600k iterations")
	encryptedReader, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestDecrypt_LegacyAbsentKDFParams(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for legacy fallback")
	encryptedReader, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	// Strip KDF params to simulate legacy object
	delete(encMetadata, MetaKDFParams)
	decryptedReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestDecrypt_CrossIteration_100k_to_600k(t *testing.T) {
	eng100k, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	eng600k, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(600000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for cross iteration")
	encryptedReader, encMetadata, err := eng100k.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng600k.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestDecrypt_CrossIteration_600k_to_100k(t *testing.T) {
	eng100k, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	eng600k, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(600000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for cross iteration")
	encryptedReader, encMetadata, err := eng600k.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng100k.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestEncrypt_WritesKDFParamsMetadata(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data")
	_, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if encMetadata[MetaKDFParams] != "pbkdf2-sha256:600000" {
		t.Errorf("MetaKDFParams = %q, want %q", encMetadata[MetaKDFParams], "pbkdf2-sha256:600000")
	}
}

func TestEncrypt_WritesKDFParamsMetadata_CustomIter(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(750000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data")
	_, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if encMetadata[MetaKDFParams] != "pbkdf2-sha256:750000" {
		t.Errorf("MetaKDFParams = %q, want %q", encMetadata[MetaKDFParams], "pbkdf2-sha256:750000")
	}
}

func TestChunked_EncryptDecrypt_KDFParams(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithChunking(true))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for chunked kdf params")
	encryptedReader, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if encMetadata[MetaChunkedFormat] != "true" {
		t.Error("Expected chunked format marker")
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestDecrypt_AbsentMetadata_FallbackIs100k(t *testing.T) {
	eng100k, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	eng600k, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithPBKDF2Iterations(600000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for absent metadata fallback")
	encryptedReader, encMetadata, err := eng100k.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	// Strip KDF params to simulate legacy object
	delete(encMetadata, MetaKDFParams)
	decryptedReader, _, err := eng600k.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestChunked_CrossIteration(t *testing.T) {
	eng100k, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithChunking(true), WithChunkSize(DefaultChunkSize), WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	eng600k, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithChunking(true), WithChunkSize(DefaultChunkSize), WithPBKDF2Iterations(600000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for chunked cross iteration")
	encryptedReader, encMetadata, err := eng100k.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if encMetadata[MetaChunkedFormat] != "true" {
		t.Error("Expected chunked format marker")
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng600k.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestChunked_LegacyAbsentKDFParams(t *testing.T) {
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil, WithChunking(true), WithPBKDF2Iterations(100000))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	data := []byte("test data for chunked legacy fallback")
	encryptedReader, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	// Strip KDF params to simulate legacy object
	delete(encMetadata, MetaKDFParams)
	decryptedReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch")
	}
}

func TestEncryptDecrypt_Argon2id(t *testing.T) {
	if FIPSEnabled() {
		t.Skip("argon2id is not approved in FIPS builds")
	}
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil,
		WithKDFAlgorithm("argon2id"),
		WithArgon2idParams(2, 19456, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := []byte("hello argon2id encryption")
	encryptedReader, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch: got %q, want %q", decryptedData, data)
	}
}

func TestEncryptDecrypt_Argon2id_LegacyPBKDF2Read(t *testing.T) {
	// Encrypt with PBKDF2 (default), decrypt with argon2id-configured engine.
	pbkdf2Engine, err := NewEngineWithOpts([]byte("test-password-12345"), nil)
	if err != nil {
		t.Fatalf("Failed to create PBKDF2 engine: %v", err)
	}

	data := []byte("legacy pbkdf2 object read by argon2id engine")
	encryptedReader, encMetadata, err := pbkdf2Engine.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Decrypt with argon2id-configured engine (reads algorithm from metadata).
	argon2idEngine, err := NewEngineWithOpts([]byte("test-password-12345"), nil,
		WithKDFAlgorithm("argon2id"),
		WithArgon2idParams(2, 19456, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create argon2id engine: %v", err)
	}
	decryptedReader, _, err := argon2idEngine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch: got %q, want %q", decryptedData, data)
	}
}

func TestEncryptDecrypt_PBKDF2_LegacyArgon2idRead(t *testing.T) {
	if FIPSEnabled() {
		t.Skip("argon2id is not approved in FIPS builds")
	}
	// Encrypt with argon2id, decrypt with PBKDF2-configured engine (reads algorithm from metadata).
	argon2idEngine, err := NewEngineWithOpts([]byte("test-password-12345"), nil,
		WithKDFAlgorithm("argon2id"),
		WithArgon2idParams(2, 19456, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create argon2id engine: %v", err)
	}

	data := []byte("argon2id object read by pbkdf2 engine")
	encryptedReader, encMetadata, err := argon2idEngine.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Decrypt with PBKDF2 engine (reads argon2id from metadata).
	pbkdf2Engine, err := NewEngineWithOpts([]byte("test-password-12345"), nil)
	if err != nil {
		t.Fatalf("Failed to create PBKDF2 engine: %v", err)
	}
	decryptedReader, _, err := pbkdf2Engine.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch: got %q, want %q", decryptedData, data)
	}
}

func TestEncrypt_WritesArgon2idMetadata(t *testing.T) {
	if FIPSEnabled() {
		t.Skip("argon2id is not approved in FIPS builds")
	}
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil,
		WithKDFAlgorithm("argon2id"),
		WithArgon2idParams(3, 32768, 2),
	)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := []byte("test data for argon2id metadata")
	_, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	want := "argon2id:3:32768:2"
	if encMetadata[MetaKDFParams] != want {
		t.Errorf("MetaKDFParams = %q, want %q", encMetadata[MetaKDFParams], want)
	}
}

func TestEncryptDecrypt_Argon2id_Chunked(t *testing.T) {
	if FIPSEnabled() {
		t.Skip("argon2id is not approved in FIPS builds")
	}
	eng, err := NewEngineWithOpts([]byte("test-password-12345"), nil,
		WithChunking(true),
		WithKDFAlgorithm("argon2id"),
		WithArgon2idParams(2, 19456, 1),
	)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	data := []byte("chunked argon2id encryption test data")
	encryptedReader, encMetadata, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if encMetadata[MetaChunkedFormat] != "true" {
		t.Error("Expected chunked format marker")
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	decryptedReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encryptedData), encMetadata)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decryptedData, err := io.ReadAll(decryptedReader)
	if err != nil {
		t.Fatalf("Failed to read decrypted data: %v", err)
	}
	if !bytes.Equal(decryptedData, data) {
		t.Errorf("Decrypt() data mismatch: got %q, want %q", decryptedData, data)
	}
}

// TestEncryptDecrypt_ChaCha20Poly1305 verifies that the ChaCha20-Poly1305
// algorithm path through encryptChunkedWithMetadataFallback is covered.
// Using WithPreferredAlgorithm("ChaCha20-Poly1305") selects the non-AES
// keySize branch.
func TestEncryptDecrypt_ChaCha20Poly1305(t *testing.T) {
	if FIPSEnabled() {
		t.Skip("ChaCha20-Poly1305 is not approved in FIPS builds")
	}
	eng, err := NewEngineWithOpts(
		[]byte("test-password-chacha20poly1305"),
		nil,
		WithPreferredAlgorithm(AlgorithmChaCha20Poly1305),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	data := []byte("chacha20-poly1305 test payload for coverage")
	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("io.ReadAll(encrypted): %v", err)
	}

	decReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("io.ReadAll(decrypted): %v", err)
	}
	if !bytes.Equal(decData, data) {
		t.Errorf("round-trip mismatch: got %q, want %q", decData, data)
	}
}

// TestEncryptDecrypt_ChaCha20Poly1305_NonChunked verifies ChaCha20-Poly1305 in
// non-chunked mode (standard Encrypt path).
func TestEncryptDecrypt_ChaCha20Poly1305_NonChunked(t *testing.T) {
	if FIPSEnabled() {
		t.Skip("ChaCha20-Poly1305 is not approved in FIPS builds")
	}
	eng, err := NewEngineWithOpts(
		[]byte("test-password-chacha20-nonchunked"),
		nil,
		WithPreferredAlgorithm(AlgorithmChaCha20Poly1305),
		WithChunking(false),
	)
	if err != nil {
		t.Fatalf("NewEngineWithOpts() error: %v", err)
	}

	data := []byte("non-chunked chacha20 test payload")
	encReader, encMeta, err := eng.Encrypt(context.Background(), bytes.NewReader(data), nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("io.ReadAll(encrypted): %v", err)
	}

	decReader, _, err := eng.Decrypt(context.Background(), bytes.NewReader(encData), encMeta)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	decData, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("io.ReadAll(decrypted): %v", err)
	}
	if !bytes.Equal(decData, data) {
		t.Errorf("non-chunked round-trip mismatch: got %q, want %q", decData, data)
	}
}
