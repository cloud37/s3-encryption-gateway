//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testSelfContained_AES_EncryptedMPU_RoundTrip verifies that an encrypted
// multipart upload assembled with an AES KEK can be read back correctly:
//
//  1. Start a Valkey container + gateway with AES KEK and EncryptedMPU policy.
//  2. Upload 3 parts (2× 5 MiB + small tail).
//  3. CompleteMultipartUpload.
//  4. GET the assembled object — gateway unwraps the DEK with AES-256-GCM KEK
//     and decrypts all parts.
//  5. Assert byte-perfect round-trip.
func testSelfContained_AES_EncryptedMPU_RoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	vk := provider.StartValkey(ctx, t)
	km := makeAESKEKManager(t)

	gw := harness.StartGateway(t, inst,
		harness.WithKeyManager(km),
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	part1 := bytes.Repeat([]byte("M"), 5*1024*1024)
	part2 := bytes.Repeat([]byte("N"), 5*1024*1024)
	part3 := []byte("aes-mpu-tail")

	etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1)
	etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part2)
	etag3 := uploadPart(t, gw, inst.Bucket, key, uploadID, 3, part3)
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1}, {2, etag2}, {3, etag3},
	})

	want := append(append(append([]byte(nil), part1...), part2...), part3...)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Errorf("AES MPU round-trip: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// testSelfContained_AES_EncryptedMPU_RangedGet verifies that byte-range reads
// on an object assembled via encrypted MPU with an AES KEK work correctly.
//
// The object is 2 parts × 5 MiB. We perform ranged GETs that cross part
// boundaries and compare against the known plaintext.
func testSelfContained_AES_EncryptedMPU_RangedGet(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	vk := provider.StartValkey(ctx, t)
	km := makeAESKEKManager(t)

	gw := harness.StartGateway(t, inst,
		harness.WithKeyManager(km),
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	// Two parts with distinct fill patterns so we can identify cross-boundary reads.
	const partSize = 5 * 1024 * 1024
	part1 := bytes.Repeat([]byte{0xAA}, partSize)
	part2 := bytes.Repeat([]byte{0xBB}, partSize)

	etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1)
	etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part2)
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1}, {2, etag2},
	})

	want := append(append([]byte(nil), part1...), part2...)

	// Sub-test: a range entirely within part 1.
	rangeTests := []struct {
		name       string
		start, end int64
	}{
		{"within-part1", 0, 1023},
		{"end-of-part1", int64(partSize - 512), int64(partSize - 1)},
		{"cross-boundary", int64(partSize - 256), int64(partSize + 255)},
		{"within-part2", int64(partSize), int64(partSize + 4095)},
		{"tail-of-part2", int64(2*partSize - 512), int64(2*partSize - 1)},
	}

	for _, rt := range rangeTests {
		rt := rt
		t.Run(rt.name, func(t *testing.T) {
			got := getRange(t, gw, inst.Bucket, key, rt.start, rt.end)
			wantSlice := want[rt.start : rt.end+1]
			if !bytes.Equal(got, wantSlice) {
				t.Errorf("range [%d-%d]: got %d bytes, want %d bytes (mismatch)",
					rt.start, rt.end, len(got), len(wantSlice))
			}
		})
	}
}

// testSelfContained_AES_EncryptedMPU_AtRest verifies that objects assembled via
// encrypted MPU with an AES KEK are stored as ciphertext on the backend:
//
//  1. Upload 2 parts containing a distinctive plaintext marker.
//  2. CompleteMultipartUpload.
//  3. Bypass-read the assembled object directly from the backend.
//  4. Assert the raw bytes do NOT contain the plaintext marker.
//  5. Gateway GET must still recover the full plaintext.
func testSelfContained_AES_EncryptedMPU_AtRest(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	vk := provider.StartValkey(ctx, t)
	km := makeAESKEKManager(t)

	gw := harness.StartGateway(t, inst,
		harness.WithKeyManager(km),
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	const marker = "AES_ENCRYPTED_MPU_PLAINTEXT"
	markerBytes := []byte(marker)
	part1 := bytes.Repeat(markerBytes, (5*1024*1024)/len(markerBytes)+1)[:5*1024*1024]
	part2 := append([]byte("TAIL_"), markerBytes...)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1)
	etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part2)
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1}, {2, etag2},
	})

	// Bypass-read from backend.
	rawClient := newBypassS3Client(t, inst)
	out, err := rawClient.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("bypass GetObject: %v", err)
	}
	defer out.Body.Close()
	rawBytes, err := io.ReadAll(out.Body)
	if err != nil {
		t.Fatalf("bypass ReadAll: %v", err)
	}
	if bytes.Contains(rawBytes, markerBytes) {
		t.Error("AES MPU at-rest: backend contains plaintext marker — object was NOT encrypted")
	}

	// Gateway must still recover the full plaintext.
	want := append(append([]byte(nil), part1...), part2...)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Errorf("AES MPU at-rest gateway round-trip: got %d bytes, want %d bytes",
			len(got), len(want))
	}
}

// testSelfContained_AES_Rotation_EncryptedMPU verifies that objects uploaded via
// encrypted MPU with key-version 1 remain readable after a rotation to version 2
// (dual-read window — old ciphertext is still decryptable when the new manager
// retains the old key).
func testSelfContained_AES_Rotation_EncryptedMPU(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	kekV1 := bytes.Repeat([]byte{0xC1}, 32)
	kekV2 := bytes.Repeat([]byte{0xC2}, 32)

	// Gateway 1: version 1 only.
	kmV1, err := crypto.NewAESKEKManager(map[int][]byte{1: kekV1}, 1)
	if err != nil {
		t.Fatalf("NewAESKEKManager v1: %v", err)
	}
	t.Cleanup(func() { _ = kmV1.Close(context.Background()) })

	vk := provider.StartValkey(ctx, t)

	gw1 := harness.StartGateway(t, inst,
		harness.WithKeyManager(kmV1),
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw1, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw1, inst.Bucket, key, uploadID) })

	part1 := bytes.Repeat([]byte("R"), 5*1024*1024)
	part2 := []byte("rotation-mpu-tail")

	etag1 := uploadPart(t, gw1, inst.Bucket, key, uploadID, 1, part1)
	etag2 := uploadPart(t, gw1, inst.Bucket, key, uploadID, 2, part2)
	completeMultipartUpload(t, gw1, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1}, {2, etag2},
	})

	// Gateway 2: version 2 active, version 1 retained.
	kmV2, err := crypto.NewAESKEKManager(map[int][]byte{1: kekV1, 2: kekV2}, 2)
	if err != nil {
		t.Fatalf("NewAESKEKManager v2: %v", err)
	}
	t.Cleanup(func() { _ = kmV2.Close(context.Background()) })

	gw2 := harness.StartGateway(t, inst,
		harness.WithKeyManager(kmV2),
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	want := append(append([]byte(nil), part1...), part2...)
	got := get(t, gw2, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Errorf("AES MPU rotation dual-read: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// testFallbackKeyManager_EncryptedMPU_LegacyUpgrade verifies the upgrade
// scenario: an object uploaded with the password-only key manager is still
// readable after upgrading to an AES KEK primary, using a FallbackKeyManager
// that retains the old password-based DEK unwrap capability.
//
// This is the conformance-level end-to-end test for the FallbackKeyManager fix
// introduced in commit 6c091f9 (fix(crypto): add FallbackKeyManager for legacy
// password-wrapped MPU DEKs).
func testFallbackKeyManager_EncryptedMPU_LegacyUpgrade(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	// The password used by the legacy (pre-upgrade) gateway.
	const legacyPassword = "legacy-gateway-password-long-enough"

	vk := provider.StartValkey(ctx, t)

	// Step 1: Upload with the old password-only gateway (no AES KEK).
	gwLegacy := harness.StartGateway(t, inst,
		harness.WithEncryptionPassword(legacyPassword),
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gwLegacy, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gwLegacy, inst.Bucket, key, uploadID) })

	part1 := bytes.Repeat([]byte("L"), 5*1024*1024)
	part2 := []byte("fallback-upgrade-tail")

	etag1 := uploadPart(t, gwLegacy, inst.Bucket, key, uploadID, 1, part1)
	etag2 := uploadPart(t, gwLegacy, inst.Bucket, key, uploadID, 2, part2)
	completeMultipartUpload(t, gwLegacy, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1}, {2, etag2},
	})

	// Step 2: "Upgrade" to a new gateway with AES KEK primary + password fallback.
	newKM := makeAESKEKManager(t)
	legacyKM, err := crypto.NewPasswordKeyManager([]byte(legacyPassword), crypto.DefaultPBKDF2Iterations)
	if err != nil {
		t.Fatalf("NewPasswordKeyManager (legacy): %v", err)
	}
	t.Cleanup(func() { _ = legacyKM.Close(ctx) })

	fallbackKM := crypto.NewFallbackKeyManager(newKM, legacyKM)

	gwNew := harness.StartGateway(t, inst,
		harness.WithKeyManager(fallbackKM),
		harness.WithEncryptionPassword(legacyPassword),
		harness.WithValkeyAddr(vk.Addr),
		harness.WithEncryptedMPUForBucket(inst.Bucket),
	)

	// The new gateway must be able to read back the legacy object.
	want := append(append([]byte(nil), part1...), part2...)
	got := get(t, gwNew, inst.Bucket, key)
	if !bytes.Equal(got, want) {
		t.Errorf("FallbackKeyManager MPU upgrade: got %d bytes, want %d bytes", len(got), len(want))
	}
}
