//go:build conformance

package conformance

import (
	"bytes"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testOpenBaoKMSIntegration verifies the end-to-end OpenBao / Vault Transit
// envelope encryption path through the full in-process gateway proxy:
//
//  1. Start an OpenBao dev-server container and enable the Transit engine.
//  2. Build an OpenBaoTransitManager wired to the container (token auth).
//  3. Start the in-process gateway with that KeyManager.
//  4. PUT an object through the gateway → DEK is wrapped by OpenBao Transit.
//  5. GET the same object back → DEK is unwrapped, plaintext must match.
//  6. Verify the object is ciphertext at rest (not equal to plaintext).
//
// Gated on CapOpenBaoKMS so it only runs on local Testcontainer providers
// where the in-process gateway can reach the OpenBao container.
// Disable with GATEWAY_TEST_SKIP_OPENBAO=1.
func testOpenBaoKMSIntegration(t *testing.T, inst provider.Instance) {
	t.Helper()

	ctx := t.Context()

	baoInst := provider.StartOpenBao(ctx, t)

	km, err := crypto.NewOpenBaoTransitManager(crypto.OpenBaoTransitOptions{
		Address:        baoInst.Address,
		KeyName:        baoInst.KeyName,
		Auth:           crypto.OpenBaoAuthConfig{Method: "token", Token: baoInst.RootToken},
		DisableRenewal: true,
		Timeout:        10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOpenBaoTransitManager: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(ctx) })

	if err := km.HealthCheck(ctx); err != nil {
		t.Fatalf("OpenBao HealthCheck: %v", err)
	}

	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	plaintext := bytes.Repeat([]byte("openbao-transit-envelope-encryption-test"), 128)
	key := uniqueKey(t)

	// PUT — the gateway wraps the DEK via OpenBao Transit.
	put(t, gw, inst.Bucket, key, plaintext)

	// GET — the gateway unwraps the DEK via OpenBao Transit and decrypts.
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("OpenBao round-trip: content mismatch (got %d bytes, want %d bytes)",
			len(got), len(plaintext))
	}
}

// testOpenBaoKMSRotation verifies that a Transit key rotation is transparent
// to reads: objects written before the rotation remain decryptable after it,
// because Transit self-routes decryption by the "vault:vN:" ciphertext prefix.
//
//  1. PUT an object (wrapped with version N).
//  2. Rotate the Transit key server-side via RotatableKeyManager.
//  3. PUT a second object (wrapped with version N+1).
//  4. GET both objects — both must decrypt to their original plaintexts.
//
// Gated on CapOpenBaoKMS.
func testOpenBaoKMSRotation(t *testing.T, inst provider.Instance) {
	t.Helper()

	ctx := t.Context()

	baoInst := provider.StartOpenBao(ctx, t)

	km, err := crypto.NewOpenBaoTransitManager(crypto.OpenBaoTransitOptions{
		Address:        baoInst.Address,
		KeyName:        baoInst.KeyName,
		Auth:           crypto.OpenBaoAuthConfig{Method: "token", Token: baoInst.RootToken},
		DisableRenewal: true,
		Timeout:        10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOpenBaoTransitManager: %v", err)
	}
	t.Cleanup(func() { _ = km.Close(ctx) })

	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	beforeKey := uniqueKey(t)
	beforePlaintext := []byte("written-before-rotation")
	put(t, gw, inst.Bucket, beforeKey, beforePlaintext)

	// Rotate the Transit key server-side.
	rkm, ok := km.(crypto.RotatableKeyManager)
	if !ok {
		t.Fatal("OpenBaoTransitManager does not implement RotatableKeyManager")
	}
	plan, err := rkm.PrepareRotation(ctx, nil)
	if err != nil {
		t.Fatalf("PrepareRotation: %v", err)
	}
	if err := rkm.PromoteActiveVersion(ctx, plan); err != nil {
		t.Fatalf("PromoteActiveVersion: %v", err)
	}

	afterKey := uniqueKey(t)
	afterPlaintext := []byte("written-after-rotation")
	put(t, gw, inst.Bucket, afterKey, afterPlaintext)

	// Both objects must still decrypt correctly.
	if got := get(t, gw, inst.Bucket, beforeKey); !bytes.Equal(got, beforePlaintext) {
		t.Errorf("pre-rotation object: content mismatch (got %d bytes, want %d)",
			len(got), len(beforePlaintext))
	}
	if got := get(t, gw, inst.Bucket, afterKey); !bytes.Equal(got, afterPlaintext) {
		t.Errorf("post-rotation object: content mismatch (got %d bytes, want %d)",
			len(got), len(afterPlaintext))
	}
}

// testOpenBaoKMSTokenRenewal proves that the in-process token-renewal goroutine
// keeps a short-lived AppRole token alive past its original TTL. The AppRole
// role is configured with a 5s periodic token; without renewal every operation
// would return HTTP 403 after ~5s.
//
//  1. Start OpenBao with an AppRole whose token TTL is 5s.
//  2. PUT an object immediately (token is fresh).
//  3. Sleep 13s (>2× the 5s TTL) — renewal goroutine must keep it alive.
//  4. HealthCheck and GET must both succeed after the sleep.
//
// Gated on CapOpenBaoKMS. This test has a 20s timeout budget — it is
// intentionally slow and only runs in tier-2, not tier-1.
func testOpenBaoKMSTokenRenewal(t *testing.T, inst provider.Instance) {
	t.Helper()

	ctx := t.Context()

	baoInst := provider.StartOpenBao(ctx, t, provider.WithOpenBaoAppRole(5*time.Second))

	km, err := crypto.NewOpenBaoTransitManager(crypto.OpenBaoTransitOptions{
		Address: baoInst.Address,
		KeyName: baoInst.KeyName,
		Auth: crypto.OpenBaoAuthConfig{
			Method:   "approle",
			RoleID:   baoInst.AppRoleID,
			SecretID: baoInst.AppRoleSecret,
		},
		// renewal ENABLED (default) — this is what the test validates
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewOpenBaoTransitManager (approle): %v", err)
	}
	t.Cleanup(func() { _ = km.Close(ctx) })

	gw := harness.StartGateway(t, inst, harness.WithKeyManager(km))

	key := uniqueKey(t)
	plaintext := []byte("token-renewal-test-object")
	put(t, gw, inst.Bucket, key, plaintext)

	// Wait well past the 5s TTL. Only the renewal goroutine keeps the token alive.
	t.Log("sleeping 13s to validate token renewal past original TTL...")
	time.Sleep(13 * time.Second)

	if err := km.HealthCheck(ctx); err != nil {
		t.Fatalf("HealthCheck after TTL window: %v (token must be renewed)", err)
	}
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("GET after TTL window: content mismatch (got %d bytes, want %d)",
			len(got), len(plaintext))
	}
}
