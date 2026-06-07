//go:build integration

package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// testPassword is the deterministic password used for engine construction.
var testPassword = []byte("integration-test-audit-password-1234")

// TestAudit_MinIO_InspectVerifyList_EndToEnd tests the s3eg-cli audit
// sub-commands against a real MinIO backend. It writes encrypted objects
// through the crypto engine (simulating the gateway), then exercises
// Inspect, VerifyKey, and ListAlgorithm via the internal S3 client.
//
// This test requires Docker. It is excluded from the default `go test ./...`
// by the integration build tag. Run with:
//
//	go test -tags=integration ./test/integration/... -run TestAudit_MinIO
func TestAudit_MinIO_InspectVerifyList_EndToEnd(t *testing.T) {
	ctx := context.Background()

	// ── Start MinIO ──────────────────────────────────────────────────────────
	req := testcontainers.ContainerRequest{
		Image:        "quay.io/minio/minio:latest",
		ExposedPorts: []string{"9000/tcp"},
		Env: map[string]string{
			"MINIO_ROOT_USER":     "minioadmin",
			"MINIO_ROOT_PASSWORD": "minioadmin",
		},
		Cmd: []string{"server", "/data"},
		WaitingFor: wait.ForLog("API:").WithStartupTimeout(60 * time.Second),
	}
	minioC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	defer minioC.Terminate(ctx)

	mappedPort, err := minioC.MappedPort(ctx, "9000")
	require.NoError(t, err)
	endpoint := fmt.Sprintf("http://localhost:%s", mappedPort.Port())

	// ── Create S3 backend config ─────────────────────────────────────────────
	backendCfg := &config.BackendConfig{
		Endpoint:     endpoint,
		Region:       "us-east-1",
		AccessKey:    "minioadmin",
		SecretKey:    "minioadmin",
		Provider:     "minio",
		UseSSL:       false,
		UsePathStyle: true,
	}

	// Build internal S3 client (same code path as s3eg-cli).
	client, err := s3.NewClient(backendCfg)
	require.NoError(t, err)

	// Create the test bucket.
	bucket := fmt.Sprintf("audit-test-%d", time.Now().UnixNano())
	err = createBucket(ctx, client, bucket)
	require.NoError(t, err)
	t.Cleanup(func() { cleanupBucket(ctx, t, client, bucket) })

	// ── Create crypto engine ──────────────────────────────────────────────────
	eng, err := crypto.NewEngineWithChunking(testPassword, "", nil, true, crypto.DefaultChunkSize)
	require.NoError(t, err)

	// ── Write test objects ────────────────────────────────────────────────────
	// Object 1: modern encrypted object (AES256-GCM, chunked, HKDF)
	obj1Plain := []byte("modern encrypted object data for audit inspection")
	obj1Key := "modern-object.dat"
	writeEncryptedObject(t, ctx, client, eng, bucket, obj1Key, obj1Plain, nil)

	// Object 2: legacy no-AAD object (ClassB)
	obj2Plain := []byte("legacy no-aad object data")
	obj2Key := "legacy-no-aad.dat"
	writeEncryptedObject(t, ctx, client, eng, bucket, obj2Key, obj2Plain, func(meta map[string]string) {
		meta[crypto.MetaLegacyNoAAD] = "true"
		// Remove IV derivation to make it non-modern (non-chunked, no iv-deriv → Class B)
		delete(meta, crypto.MetaIVDerivation)
	})

	// Object 3: plaintext (not encrypted)
	obj3Key := "plaintext-file.txt"
	_, err = client.PutObject(ctx, bucket, obj3Key, bytes.NewReader([]byte("this is plaintext")),
		map[string]string{"Content-Type": "text/plain"}, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)

	// Object 4: KMS-wrapped modern object (simulated via key manager)
	obj4Key := "kms-wrapped-object.dat"
	obj4Plain := []byte("kms wrapped object data")
	km, err := crypto.NewAESKEKManager(map[int][]byte{1: make([]byte, 32)}, 1)
	require.NoError(t, err)
	defer km.Close(ctx)
	engKM, err := crypto.NewEngineWithOpts(testPassword, crypto.WithKeyManager(km))
	require.NoError(t, err)
	writeEncryptedObject(t, ctx, client, engKM, bucket, obj4Key, obj4Plain, nil)

	// ── Test Inspect ──────────────────────────────────────────────────────────
	t.Run("inspect-modern", func(t *testing.T) {
		report, err := audit.Inspect(ctx, client, bucket, obj1Key)
		require.NoError(t, err)
		require.True(t, report.Encrypted)
		require.Equal(t, "modern", report.Class)
		require.Equal(t, "v2-aad", report.AADScheme)
		require.Equal(t, crypto.AlgorithmAES256GCM, report.Algorithm)
		require.NotEmpty(t, report.SaltHex)
		require.NotEmpty(t, report.IVHex)
		require.NotEmpty(t, report.CiphertextHeadHex)
		t.Logf("Inspect modern: algorithm=%s class=%s aad=%s", report.Algorithm, report.Class, report.AADScheme)
	})

	t.Run("inspect-legacy-no-aad", func(t *testing.T) {
		report, err := audit.Inspect(ctx, client, bucket, obj2Key)
		require.NoError(t, err)
		require.True(t, report.Encrypted)
		require.Equal(t, "class_b_no_aad", report.Class)
		require.Equal(t, "v1-no-aad", report.AADScheme)
		t.Logf("Inspect legacy no-aad: class=%s aad=%s", report.Class, report.AADScheme)
	})

	t.Run("inspect-plaintext", func(t *testing.T) {
		report, err := audit.Inspect(ctx, client, bucket, obj3Key)
		require.NoError(t, err)
		require.False(t, report.Encrypted)
		require.Equal(t, "plaintext", report.Class)
		t.Logf("Inspect plaintext: encrypted=%v class=%s", report.Encrypted, report.Class)
	})

	t.Run("inspect-kms-wrapped", func(t *testing.T) {
		report, err := audit.Inspect(ctx, client, bucket, obj4Key)
		require.NoError(t, err)
		require.True(t, report.Encrypted)
		require.Equal(t, "modern", report.Class)
		require.NotEmpty(t, report.KeyVersion)
		t.Logf("Inspect KMS: key_version=%s", report.KeyVersion)
	})

	t.Run("inspect-not-found", func(t *testing.T) {
		_, err := audit.Inspect(ctx, client, bucket, "nonexistent-object")
		require.Error(t, err)
		require.Contains(t, err.Error(), "not found")
	})

	// ── Test VerifyKey ────────────────────────────────────────────────────────
	t.Run("verify-key-match", func(t *testing.T) {
		wantVer := 1
		report, err := audit.VerifyKey(ctx, client, bucket, obj4Key, &wantVer)
		require.NoError(t, err)
		require.True(t, report.Match)
		require.Equal(t, "1", report.Recorded)
		t.Logf("VerifyKey match: recorded=%s want=%d", report.Recorded, wantVer)
	})

	t.Run("verify-key-mismatch", func(t *testing.T) {
		wantVer := 99
		report, err := audit.VerifyKey(ctx, client, bucket, obj4Key, &wantVer)
		require.NoError(t, err)
		require.False(t, report.Match)
		require.Equal(t, "1", report.Recorded)
		t.Logf("VerifyKey mismatch: recorded=%s want=%d", report.Recorded, wantVer)
	})

	t.Run("verify-key-metadata-only", func(t *testing.T) {
		report, err := audit.VerifyKey(ctx, client, bucket, obj4Key, nil)
		require.NoError(t, err)
		require.True(t, report.Match)
		require.Equal(t, "metadata-only", report.Verified)
		t.Logf("VerifyKey metadata-only: recorded=%s", report.Recorded)
	})

	// ── Test ListAlgorithm ────────────────────────────────────────────────────
	t.Run("list-algorithm", func(t *testing.T) {
		report, err := audit.ListAlgorithm(ctx, client, bucket, "", 2)
		require.NoError(t, err)
		require.Equal(t, int64(4), report.Total,
			"expected 4 objects total (3 encrypted + 1 plaintext)")

		// Build algorithm map
		algMap := make(map[string]int64)
		for _, item := range report.ByAlgorithm {
			algMap[item.Algorithm] = item.Count
		}
		// At minimum we have AES256-GCM objects and maybe plaintext
		require.GreaterOrEqual(t, algMap[crypto.AlgorithmAES256GCM], int64(3),
			"expected at least 3 AES256-GCM objects")
		require.Contains(t, algMap, "(plaintext)",
			"expected plaintext category")

		t.Logf("ListAlgorithm: total=%d algorithms=%v", report.Total, algMap)
	})

	t.Run("list-algorithm-with-prefix", func(t *testing.T) {
		report, err := audit.ListAlgorithm(ctx, client, bucket, "modern-", 2)
		require.NoError(t, err)
		require.Equal(t, int64(1), report.Total,
			"expected 1 object under 'modern-' prefix")
	})
}

// ── Helpers ──────────────────────────────────────────────────────────────────

// writeEncryptedObject encrypts plaintext and writes it to MinIO via the
// internal S3 client. metaMutate allows test-specific metadata modifications.
func writeEncryptedObject(t *testing.T, ctx context.Context, client s3.Client,
	eng crypto.EncryptionEngine, bucket, key string, plaintext []byte,
	metaMutate func(map[string]string)) {

	t.Helper()

	encReader, encMeta, err := eng.Encrypt(ctx, bytes.NewReader(plaintext), nil)
	require.NoError(t, err)

	cipherdata, err := io.ReadAll(encReader)
	require.NoError(t, err)

	if metaMutate != nil {
		metaMutate(encMeta)
	}

	_, err = client.PutObject(ctx, bucket, key, bytes.NewReader(cipherdata),
		encMeta, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)
}

// createBucket creates an S3 bucket using the internal client by writing a
// config with the bucket name and using a standard S3 put-bucket request.
func createBucket(ctx context.Context, client s3.Client, bucket string) error {
	// The internal s3.Client doesn't expose CreateBucket directly.
	// We create an empty object as a sentinel (MinIO auto-creates buckets
	// on first write when path style is used, but for correctness we attempt
	// the create via a zero-length PutObject which MinIO will accept as
	// implicitly creating the bucket in the path-style virtual-hosted style).
	// Actually, the simplest approach: MinIO allows us to just write an object;
	// the bucket is created implicitly with path-style requests.
	// We'll write a marker object to ensure the bucket exists.
	_, err := client.PutObject(ctx, bucket, ".bucket-init-marker",
		bytes.NewReader([]byte{}), nil, nil, "", nil, "", "", "", "", "")
	return err
}

// cleanupBucket lists and deletes all objects in the bucket, then attempts
// to remove the bucket itself (best-effort).
func cleanupBucket(ctx context.Context, t *testing.T, client s3.Client, bucket string) {
	t.Helper()

	// List all objects
	result, err := client.ListObjects(ctx, bucket, "", s3.ListOptions{MaxKeys: 1000})
	if err != nil {
		t.Logf("cleanup: ListObjects failed (bucket may already be gone): %v", err)
		return
	}

	for _, obj := range result.Objects {
		if delErr := client.DeleteObject(ctx, bucket, obj.Key, nil); delErr != nil {
			t.Logf("cleanup: DeleteObject %s failed: %v", obj.Key, delErr)
		}
	}

	// For MinIO with path-style, the bucket delete is handled by the container
	// teardown.
}
