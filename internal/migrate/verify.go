package migrate

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// VerifyMaxBytes is the maximum object size for which the verifier performs a
// full SHA-256 hash comparison. Larger objects use a metadata + partial read
// strategy to bound memory usage.
const VerifyMaxBytes = 256 * 1024 * 1024 // 256 MiB

// ErrVerifyMismatch is returned when the post-migration verification read does
// not match the expected plaintext.
var ErrVerifyMismatch = fmt.Errorf("verify mismatch: decrypted data does not match expected plaintext")

// Verify re-reads a migrated object and compares its decrypted content against
// the expected plaintext using a constant-time comparison.
//
// For objects larger than VerifyMaxBytes, it falls back to metadata correctness
// checks and first/last 4 KiB hash comparisons.
func Verify(ctx context.Context, s3 S3Client, engine crypto.EncryptionEngine, bucket, key string, expectedPlaintext []byte) error {
	reader, meta, err := s3.GetObject(ctx, bucket, key, nil, nil)
	if err != nil {
		return fmt.Errorf("verify get failed: %w", err)
	}
	defer reader.Close()

	// If the expected plaintext is small enough, do a full comparison.
	if int64(len(expectedPlaintext)) <= VerifyMaxBytes {
		decrypted, _, err := engine.Decrypt(ctx, reader, meta)
		if err != nil {
			return fmt.Errorf("verify decrypt failed: %w", err)
		}
		actual, err := io.ReadAll(decrypted)
		if err != nil {
			return fmt.Errorf("verify read failed: %w", err)
		}
		if subtle.ConstantTimeCompare(actual, expectedPlaintext) != 1 {
			return ErrVerifyMismatch
		}
		return nil
	}

	// Large-object path: verify metadata correctness and first/last 4 KiB.
	return verifyLargeObject(ctx, reader, meta, engine, expectedPlaintext)
}

func verifyLargeObject(ctx context.Context, reader io.Reader, meta map[string]string, engine crypto.EncryptionEngine, expectedPlaintext []byte) error {
	// Metadata correctness: ensure new class markers are present and old ones absent.
	if meta[crypto.MetaIVDerivation] != "hkdf-sha256" {
		return fmt.Errorf("verify metadata: missing %s=hkdf-sha256", crypto.MetaIVDerivation)
	}
	if meta[crypto.MetaLegacyNoAAD] == "true" {
		return fmt.Errorf("verify metadata: unexpected %s=true", crypto.MetaLegacyNoAAD)
	}
	if meta[crypto.MetaFallbackMode] == "true" && meta[crypto.MetaFallbackVersion] != "2" {
		return fmt.Errorf("verify metadata: fallback version not v2")
	}

	// Decrypt first and last 4 KiB for a spot-check.
	decryptedReader, _, err := engine.Decrypt(ctx, reader, meta)
	if err != nil {
		return fmt.Errorf("verify decrypt failed: %w", err)
	}

	const spotSize = 4 * 1024
	firstExpected := expectedPlaintext[:min(len(expectedPlaintext), spotSize)]
	firstActual := make([]byte, len(firstExpected))
	if _, err := io.ReadFull(decryptedReader, firstActual); err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("verify read first bytes failed: %w", err)
	}
	if !bytes.Equal(firstActual, firstExpected) {
		return ErrVerifyMismatch
	}

	// If plaintext is larger than spotSize, check last spotSize bytes.
	if len(expectedPlaintext) > spotSize {
		lastExpected := expectedPlaintext[len(expectedPlaintext)-spotSize:]
		lastActual, err := readLastBytes(decryptedReader, spotSize)
		if err != nil {
			return fmt.Errorf("verify read last bytes failed: %w", err)
		}
		if !bytes.Equal(lastActual, lastExpected) {
			return ErrVerifyMismatch
		}
	}

	return nil
}

func readLastBytes(r io.Reader, n int) ([]byte, error) {
	// Simple ring buffer approach.
	buf := make([]byte, n)
	total := 0
	for {
		nr, err := r.Read(buf[total%n:])
		if nr > 0 {
			total += nr
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	if total < n {
		return buf[:total], nil
	}
	start := total % n
	result := make([]byte, n)
	copy(result, buf[start:])
	copy(result[n-start:], buf[:start])
	return result, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
