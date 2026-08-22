package crypto

import (
	"bytes"
	"context"
	"io"
	"testing"
)

// BenchmarkEngine_Encrypt_Small benchmarks small encryption operations.
// Buffer pooling is enabled to reduce memory allocations in crypto operations.
func BenchmarkEngine_Encrypt_Small(b *testing.B) {
	engine, err := NewEngine([]byte("test-password-12345"))
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	data := make([]byte, 1024) // 1KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		encrypted, _, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, nil)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		// Consume the encrypted data
		_, err = io.Copy(io.Discard, encrypted)
		if err != nil {
			b.Fatalf("Failed to read encrypted data: %v", err)
		}
	}
}

func BenchmarkEngine_Encrypt_Medium(b *testing.B) {
	engine, err := NewEngine([]byte("test-password-12345"))
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	data := make([]byte, 1024*1024) // 1MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		encrypted, _, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, nil)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		_, err = io.Copy(io.Discard, encrypted)
		if err != nil {
			b.Fatalf("Failed to read encrypted data: %v", err)
		}
	}
}

func BenchmarkEngine_Encrypt_Large(b *testing.B) {
	engine, err := NewEngine([]byte("test-password-12345"))
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	data := make([]byte, 10*1024*1024) // 10MB
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reader := bytes.NewReader(data)
			encrypted, _, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, nil)
			if err != nil {
				b.Fatalf("Encryption failed: %v", err)
			}

			_, err = io.Copy(io.Discard, encrypted)
			if err != nil {
				b.Fatalf("Failed to read encrypted data: %v", err)
			}
		}
	})
}

func BenchmarkEngine_Decrypt_Small(b *testing.B) {
	engine, err := NewEngine([]byte("test-password-12345"))
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	// Prepare encrypted data
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	reader := bytes.NewReader(data)
	encrypted, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, nil)
	if err != nil {
		b.Fatalf("Failed to encrypt test data: %v", err)
	}

	encryptedData, err := io.ReadAll(encrypted)
	if err != nil {
		b.Fatalf("Failed to read encrypted data: %v", err)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encryptedData)
		decrypted, _, err := engine.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, metadata)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}

		_, err = io.Copy(io.Discard, decrypted)
		if err != nil {
			b.Fatalf("Failed to read decrypted data: %v", err)
		}
	}
}

func BenchmarkEngine_Decrypt_Medium(b *testing.B) {
	engine, err := NewEngine([]byte("test-password-12345"))
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	// Prepare encrypted data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	reader := bytes.NewReader(data)
	encrypted, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, nil)
	if err != nil {
		b.Fatalf("Failed to encrypt test data: %v", err)
	}

	encryptedData, err := io.ReadAll(encrypted)
	if err != nil {
		b.Fatalf("Failed to read encrypted data: %v", err)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(encryptedData)
		decrypted, _, err := engine.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, metadata)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}

		_, err = io.Copy(io.Discard, decrypted)
		if err != nil {
			b.Fatalf("Failed to read decrypted data: %v", err)
		}
	}
}

func BenchmarkEngine_EncryptDecrypt_RoundTrip(b *testing.B) {
	engine, err := NewEngine([]byte("test-password-12345"))
	if err != nil {
		b.Fatalf("Failed to create engine: %v", err)
	}

	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Encrypt
		reader := bytes.NewReader(data)
		encrypted, metadata, err := engine.Encrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, nil)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}

		encryptedData, err := io.ReadAll(encrypted)
		if err != nil {
			b.Fatalf("Failed to read encrypted data: %v", err)
		}

		// Decrypt
		reader = bytes.NewReader(encryptedData)
		decrypted, _, err := engine.Decrypt(context.Background(), ObjectContext{Bucket: "test-bucket", Key: "test-key"}, reader, metadata)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}

		decryptedData, err := io.ReadAll(decrypted)
		if err != nil {
			b.Fatalf("Failed to read decrypted data: %v", err)
		}

		// Verify
		if !bytes.Equal(data, decryptedData) {
			b.Fatal("Decrypted data does not match original")
		}
	}
}
