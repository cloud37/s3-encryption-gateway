//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	bao "github.com/openbao/openbao/api/v2"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	openBaoImage   = "quay.io/openbao/openbao:2.5.5"
	openBaoRoot    = "root"
	openBaoKeyName = "s3gw-dek"
)

// TestOpenBaoTransit_Container_EndToEnd spins up REAL OpenBao + MinIO containers
// (via Docker or Podman — set DOCKER_HOST to the podman socket and
// TESTCONTAINERS_RYUK_DISABLED=true for rootless podman) and exercises the
// adapter against them with no external dependencies. It covers:
//   - token auth: full S3 PUT/GET round-trip through the engine + server-side rotation,
//   - approle auth with a SHORT token TTL: proves the in-process renewal
//     goroutine keeps the token alive past its original TTL against a real
//     server (the one path the httptest mock cannot fully validate).
func TestOpenBaoTransit_Container_EndToEnd(t *testing.T) {
	testcontainers.SkipIfProviderIsNotHealthy(t)
	ctx := context.Background()

	// --- OpenBao dev server container ---
	baoC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        openBaoImage,
			ExposedPorts: []string{"8200/tcp"},
			Env:          map[string]string{"BAO_DEV_ROOT_TOKEN_ID": openBaoRoot},
			Cmd:          []string{"server", "-dev", "-dev-listen-address=0.0.0.0:8200"},
			WaitingFor: wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").
				WithStatusCodeMatcher(func(s int) bool { return s == 200 || s == 429 }).
				WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err, "start OpenBao container")
	t.Cleanup(func() { _ = baoC.Terminate(ctx) })

	baoHost, err := baoC.Host(ctx)
	require.NoError(t, err)
	baoPort, err := baoC.MappedPort(ctx, "8200")
	require.NoError(t, err)
	baoAddr := fmt.Sprintf("http://%s:%s", baoHost, baoPort.Port())

	// --- configure OpenBao with the root token: transit + approle ---
	roleID, secretID := setupOpenBao(t, ctx, baoAddr)

	// --- MinIO backend container ---
	minioC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "quay.io/minio/minio:latest",
			ExposedPorts: []string{"9000/tcp"},
			Env:          map[string]string{"MINIO_ROOT_USER": "minioadmin", "MINIO_ROOT_PASSWORD": "minioadmin"},
			Cmd:          []string{"server", "/data"},
			WaitingFor:   wait.ForLog("API:").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err, "start MinIO container")
	t.Cleanup(func() { _ = minioC.Terminate(ctx) })

	minioPort, err := minioC.MappedPort(ctx, "9000")
	require.NoError(t, err)
	minioHost, err := minioC.Host(ctx)
	require.NoError(t, err)
	s3Endpoint := fmt.Sprintf("http://%s:%s", minioHost, minioPort.Port())

	t.Run("TokenAuth_S3_RoundTrip_And_Rotate", func(t *testing.T) {
		km, err := crypto.NewOpenBaoTransitManager(crypto.OpenBaoTransitOptions{
			Address: baoAddr,
			KeyName: openBaoKeyName,
			Auth:    crypto.OpenBaoAuthConfig{Method: "token", Token: openBaoRoot},
			Timeout: 10 * time.Second,
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = km.Close(ctx) })
		require.NoError(t, km.HealthCheck(ctx))

		eng, err := crypto.NewEngineWithOpts([]byte("openbao-container-password-aaa111"), crypto.WithKeyManager(km))
		require.NoError(t, err)

		s3Client := newMinioClient(t, ctx, s3Endpoint)
		bucket := "openbao-ct-" + fmt.Sprintf("%d", time.Now().UnixNano())
		_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)})
		require.NoError(t, err)

		plaintext := []byte("OpenBao container E2E — wrap me, store me, rotate me.")
		key := "obj.dat"

		// PUT (encrypt -> OpenBao wraps DEK)
		encReader, meta, err := eng.Encrypt(ctx, bytes.NewReader(plaintext), map[string]string{"Content-Type": "application/octet-stream"})
		require.NoError(t, err)
		encData, err := io.ReadAll(encReader)
		require.NoError(t, err)
		require.NotEqual(t, plaintext, encData)
		_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: aws.String(bucket), Key: aws.String(key),
			Body: bytes.NewReader(encData), Metadata: meta,
		})
		require.NoError(t, err)

		// GET + decrypt (OpenBao unwraps DEK)
		out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		require.NoError(t, err)
		atRest, err := io.ReadAll(out.Body)
		require.NoError(t, err)
		_ = out.Body.Close()
		dec, _, err := eng.Decrypt(ctx, bytes.NewReader(atRest), out.Metadata)
		require.NoError(t, err)
		decData, err := io.ReadAll(dec)
		require.NoError(t, err)
		require.Equal(t, plaintext, decData)

		// Rotate server-side; old object still decrypts
		rkm := km.(crypto.RotatableKeyManager)
		plan, err := rkm.PrepareRotation(ctx, nil)
		require.NoError(t, err)
		require.NoError(t, rkm.PromoteActiveVersion(ctx, plan))
		newVer, err := km.ActiveKeyVersion(ctx)
		require.NoError(t, err)
		require.Equal(t, plan.TargetVersion, newVer)

		out2, err := s3Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
		require.NoError(t, err)
		atRest2, err := io.ReadAll(out2.Body)
		require.NoError(t, err)
		_ = out2.Body.Close()
		dec2, _, err := eng.Decrypt(ctx, bytes.NewReader(atRest2), out2.Metadata)
		require.NoError(t, err)
		decData2, err := io.ReadAll(dec2)
		require.NoError(t, err)
		require.Equal(t, plaintext, decData2, "pre-rotation object still decryptable")
		t.Logf("token-auth round-trip + rotate OK (version -> %d)", newVer)
	})

	t.Run("AppRole_TokenRenewal_SurvivesTTLExpiry", func(t *testing.T) {
		// The approle role issues a PERIODIC token with a 5s TTL. Without renewal
		// the token dies at ~5s; the adapter's renewal goroutine must keep it
		// alive so wrap/unwrap still work well past the original TTL.
		km, err := crypto.NewOpenBaoTransitManager(crypto.OpenBaoTransitOptions{
			Address: baoAddr,
			KeyName: openBaoKeyName,
			Auth: crypto.OpenBaoAuthConfig{
				Method:   "approle",
				RoleID:   roleID,
				SecretID: secretID,
			},
			Timeout: 10 * time.Second,
			// renewal ENABLED (default)
		})
		require.NoError(t, err)
		t.Cleanup(func() { _ = km.Close(ctx) })

		// Immediately works.
		dek := make([]byte, 32)
		_, _ = rand.Read(dek)
		env, err := km.WrapKey(ctx, dek, nil)
		require.NoError(t, err, "initial wrap")

		// Wait well past the 5s token TTL — only continuous renewal keeps it alive.
		t.Log("waiting 13s (>2x the 5s token TTL) to prove renewal...")
		time.Sleep(13 * time.Second)

		require.NoError(t, km.HealthCheck(ctx), "health check after TTL window (token must be renewed)")
		got, err := km.UnwrapKey(ctx, env, nil)
		require.NoError(t, err, "unwrap after TTL window — token survived via renewal")
		require.Equal(t, dek, got)

		env2, err := km.WrapKey(ctx, dek, nil)
		require.NoError(t, err, "wrap after TTL window — token survived via renewal")
		require.True(t, len(env2.Ciphertext) > 0)
		t.Log("approle token renewal verified against real OpenBao")
	})
}

// setupOpenBao configures transit + approle on a fresh dev server using the root
// token, returning the approle role_id and a fresh secret_id.
func setupOpenBao(t *testing.T, ctx context.Context, addr string) (roleID, secretID string) {
	t.Helper()
	cfg := bao.DefaultConfig()
	cfg.Address = addr
	admin, err := bao.NewClient(cfg)
	require.NoError(t, err)
	admin.SetToken(openBaoRoot)
	l := admin.Logical()

	_, err = l.WriteWithContext(ctx, "sys/mounts/transit", map[string]any{"type": "transit"})
	require.NoError(t, err, "enable transit")
	_, err = l.WriteWithContext(ctx, "transit/keys/"+openBaoKeyName, map[string]any{"type": "aes256-gcm96"})
	require.NoError(t, err, "create transit key")

	_, err = l.WriteWithContext(ctx, "sys/auth/approle", map[string]any{"type": "approle"})
	require.NoError(t, err, "enable approle")

	policy := fmt.Sprintf(`
path "transit/encrypt/%[1]s" { capabilities = ["update"] }
path "transit/decrypt/%[1]s" { capabilities = ["update"] }
path "transit/keys/%[1]s"    { capabilities = ["read"] }
path "transit/keys/%[1]s/rotate" { capabilities = ["update"] }
`, openBaoKeyName)
	_, err = l.WriteWithContext(ctx, "sys/policies/acl/s3gw", map[string]any{"policy": policy})
	require.NoError(t, err, "write policy")

	// Periodic token with a short TTL: renewable indefinitely, but dies in ~5s
	// without renewal — the renewal test depends on this.
	_, err = l.WriteWithContext(ctx, "auth/approle/role/s3gw", map[string]any{
		"token_policies": "s3gw",
		"token_ttl":      "5s",
		"period":         "5s",
	})
	require.NoError(t, err, "create approle role")

	rid, err := l.ReadWithContext(ctx, "auth/approle/role/s3gw/role-id")
	require.NoError(t, err)
	roleID, _ = rid.Data["role_id"].(string)
	require.NotEmpty(t, roleID)

	sid, err := l.WriteWithContext(ctx, "auth/approle/role/s3gw/secret-id", nil)
	require.NoError(t, err)
	secretID, _ = sid.Data["secret_id"].(string)
	require.NotEmpty(t, secretID)
	return roleID, secretID
}

func newMinioClient(t *testing.T, ctx context.Context, endpoint string) *s3.Client {
	t.Helper()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("minioadmin", "minioadmin", "")),
	)
	require.NoError(t, err)
	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})
}
