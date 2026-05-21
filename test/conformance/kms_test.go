//go:build conformance

package conformance

import (
	"bytes"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// testKMSIntegration verifies the end-to-end KMS envelope encryption path:
//
//  1. Start a Cosmian KMS container and create a wrapping key.
//  2. Build a CosmianKMIPManager that uses the JSON/HTTP transport (no TLS
//     needed for a local test container).
//  3. Start the in-process gateway wired with that KeyManager.
//  4. PUT an object through the gateway → DEK is wrapped by the KMS.
//  5. GET the same object back → DEK is unwrapped by the KMS, plaintext must
//     match the original.
//
// The test is gated on CapKMSIntegration so it only runs on providers whose
// network topology allows the in-process gateway to reach the KMS container
// (i.e. all local Testcontainer providers).
func testKMSIntegration(t *testing.T, inst provider.Instance) {
	t.Helper()

	ctx := t.Context()

	// Start the Cosmian KMS container and obtain a wrapping key ID.
	kmsInst := provider.StartCosmianKMS(ctx, t)

	// Build a CosmianKMIPManager using the JSON/HTTP transport.
	// The endpoint has an "http://" scheme so NewCosmianKMIPManager routes to
	// the JSON manager automatically.
	km, err := crypto.NewCosmianKMIPManager(crypto.CosmianKMIPOptions{
		Endpoint: kmsInst.Endpoint,
		Keys: []crypto.KMIPKeyReference{
			{ID: kmsInst.KeyID, Version: 1},
		},
		// Generous timeout for a cold container.
		Timeout: 0, // uses default (5 s)
	})
	if err != nil {
		t.Fatalf("NewCosmianKMIPManager: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(ctx) })

	// Verify the KMS is healthy before wiring it into the gateway.
	if err := km.HealthCheck(ctx); err != nil {
		t.Fatalf("KMS HealthCheck: %v", err)
	}

	// Wire the KMS into the in-process gateway.
	gw := harness.StartGateway(t, inst,
		harness.WithKeyManager(km),
	)

	plaintext := bytes.Repeat([]byte("kms-envelope-encryption-test"), 128)
	key := uniqueKey(t)

	// PUT — the gateway wraps the DEK with the KMS.
	put(t, gw, inst.Bucket, key, plaintext)

	// GET — the gateway unwraps the DEK via the KMS and decrypts the object.
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("KMS round-trip: content mismatch (got %d bytes, want %d bytes)",
			len(got), len(plaintext))
	}
}
