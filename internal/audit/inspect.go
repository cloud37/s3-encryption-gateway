package audit

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

// Inspect retrieves and decodes the encryption envelope for a single object.
// It issues a HeadObject for metadata and a bounded ranged GetObject (first 64 bytes)
// for the ciphertext fingerprint. It never reads the full body.
func Inspect(ctx context.Context, client AuditClient, bucket, key string) (*EnvelopeReport, error) {
	meta, err := client.HeadObject(ctx, bucket, key, nil)
	if err != nil {
		return nil, fmt.Errorf("inspect: %s/%s: %w", bucket, key, err)
	}

	report := &EnvelopeReport{
		Bucket:            bucket,
		Key:               key,
		EncryptionHeaders: make(map[string]string),
	}

	// Collect all encryption headers
	for k, v := range meta {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "x-amz-meta-enc") || strings.Contains(lower, "x-amz-meta-e") {
			report.EncryptionHeaders[k] = v
		}
	}

	// Check encrypted flag
	isEncrypted := meta[crypto.MetaEncrypted] == "true" || meta["x-amz-meta-e"] == "true"
	report.Encrypted = isEncrypted

	if !isEncrypted {
		report.Class = ClassToString(ClassPlaintext)
		report.AADScheme = "none"
		return report, nil
	}

	// Classify
	class := ClassifyObject(meta)
	report.Class = ClassToString(class)

	// AAD scheme
	if meta[crypto.MetaLegacyNoAAD] == "true" {
		report.AADScheme = "v1-no-aad"
	} else {
		report.AADScheme = "v2-aad"
	}

	// Algorithm
	if v := meta[crypto.MetaAlgorithm]; v != "" {
		report.Algorithm = v
	}

	// KMS fields
	if v := meta[crypto.MetaKMSProvider]; v != "" {
		report.KMSProvider = v
	}
	if v := meta[crypto.MetaKMSKeyID]; v != "" {
		report.KMSKeyID = v
	}
	if v := meta[crypto.MetaKeyVersion]; v != "" {
		report.KeyVersion = v
	}

	// KDF Params
	if v := meta[crypto.MetaKDFParams]; v != "" {
		report.KDFParams = v
	}

	// Format flags
	if meta[crypto.MetaChunkedFormat] == "true" {
		report.Chunked = true
	}
	if meta[crypto.MetaFallbackMode] == "true" {
		report.Fallback = true
	}

	// Decode salt (hex)
	if v := meta[crypto.MetaKeySalt]; v != "" {
		decoded, err := hex.DecodeString(v)
		if err == nil {
			report.SaltHex = hex.EncodeToString(decoded)
		}
	}

	// Decode IV (hex)
	if v := meta[crypto.MetaIV]; v != "" {
		decoded, err := hex.DecodeString(v)
		if err == nil {
			report.IVHex = hex.EncodeToString(decoded)
		}
	}

	// Ciphertext fingerprint: bounded ranged GET (first 64 bytes)
	rangeHeader := "bytes=0-63"
	body, _, err := client.GetObject(ctx, bucket, key, nil, &rangeHeader)
	if err == nil {
		fingerprint := make([]byte, 32)
		n, readErr := io.ReadFull(body, fingerprint)
		body.Close()
		if readErr == nil || n > 0 {
			report.CiphertextHeadHex = hex.EncodeToString(fingerprint[:n])
		}
	}
	// Non-fatal: if the ranged GET fails, we omit the fingerprint

	return report, nil
}

// bytes.Equal is used in tests; this is an internal helper to compare
// ciphertext heads without importing testing.
func ciphertextHeadEquals(report *EnvelopeReport, expected []byte) bool {
	got, err := hex.DecodeString(report.CiphertextHeadHex)
	if err != nil {
		return false
	}
	return bytes.Equal(got, expected)
}
