package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

func BenchmarkChunkedEncrypt_Parallel(b *testing.B) {
	chunkSize := 64 * 1024 // 64KB
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), "", nil, true, chunkSize)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	// 10MB data
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		encrypted, _, err := engine.Encrypt(context.Background(), reader, nil)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		_, err = io.Copy(io.Discard, encrypted)
		if err != nil {
			b.Fatalf("Failed to read encrypted data: %v", err)
		}
	}
}

func BenchmarkChunkedDecrypt_Parallel(b *testing.B) {
	chunkSize := 64 * 1024 // 64KB
	engine, err := NewEngineWithChunking([]byte("test-password-12345"), "", nil, true, chunkSize)
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	// 10MB data
	size := 10 * 1024 * 1024
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}

	reader := bytes.NewReader(data)
	encrypted, metadata, err := engine.Encrypt(context.Background(), reader, nil)
	if err != nil {
		b.Fatalf("Failed to encrypt: %v", err)
	}

	encryptedData, err := io.ReadAll(encrypted)
	if err != nil {
		b.Fatalf("Failed to read encrypted data: %v", err)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encryptedData)
		decrypted, _, err := engine.Decrypt(context.Background(), reader, metadata)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}

		_, err = io.Copy(io.Discard, decrypted)
		if err != nil {
			b.Fatalf("Failed to read decrypted data: %v", err)
		}
	}
}
