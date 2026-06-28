//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/stretchr/testify/require"
)

// TestOpenBaoTransit_S3_EndToEnd exercises the OpenBao Transit KeyManager
// against a REAL OpenBao server and a REAL S3-compatible backend, through the
// real crypto Engine. It proves:
//   - WrapKey/UnwrapKey work against live transit/encrypt + transit/decrypt,
//   - an object stored via the engine is ciphertext at rest (encrypted),
//   - the round-trip recovers the exact plaintext,
//   - server-side rotation (transit rotate) advances the version while older
//     objects remain decryptable (Transit self-routes by the vault:vN: prefix).
//
// Required environment (test skips if unset):
//
//	OPENBAO_ADDR        e.g. http://127.0.0.1:8200
//	OPENBAO_TOKEN       a token able to use the transit key
//	OPENBAO_KEY_NAME    transit key name (default "s3gw-dek")
//	S3_ENDPOINT         e.g. https://hel1.your-objectstorage.com
//	S3_BUCKET           an existing writable bucket
//	S3_ACCESS_KEY / S3_SECRET_KEY   backend credentials
//	S3_REGION           optional (default "hel1")
func TestOpenBaoTransit_S3_EndToEnd(t *testing.T) {
	addr := os.Getenv("OPENBAO_ADDR")
	token := os.Getenv("OPENBAO_TOKEN")
	endpoint := os.Getenv("S3_ENDPOINT")
	bucket := os.Getenv("S3_BUCKET")
	accessKey := os.Getenv("S3_ACCESS_KEY")
	secretKey := os.Getenv("S3_SECRET_KEY")
	if addr == "" || token == "" || endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
		t.Skip("set OPENBAO_ADDR, OPENBAO_TOKEN, S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY, S3_SECRET_KEY to run")
	}
	keyName := os.Getenv("OPENBAO_KEY_NAME")
	if keyName == "" {
		keyName = "s3gw-dek"
	}
	region := os.Getenv("S3_REGION")
	if region == "" {
		region = "hel1"
	}

	ctx := context.Background()

	// --- OpenBao Transit KeyManager (the component under test) ---
	km, err := crypto.NewOpenBaoTransitManager(crypto.OpenBaoTransitOptions{
		Address: addr,
		KeyName: keyName,
		Auth:    crypto.OpenBaoAuthConfig{Method: "token", Token: token},
		Timeout: 10 * time.Second,
	})
	require.NoError(t, err, "construct OpenBao Transit manager")
	t.Cleanup(func() { _ = km.Close(ctx) })

	require.NoError(t, km.HealthCheck(ctx), "health check (token + reachability)")

	// Direct adapter sanity round-trip.
	dek := make([]byte, 32)
	_, err = rand.Read(dek)
	require.NoError(t, err)
	env, err := km.WrapKey(ctx, dek, nil)
	require.NoError(t, err, "WrapKey via transit/encrypt")
	require.True(t, strings.HasPrefix(string(env.Ciphertext), "vault:v"), "wrapped DEK is a Transit ciphertext")
	require.Equal(t, "vault-transit:transit/"+keyName, env.KeyID)
	got, err := km.UnwrapKey(ctx, env, nil)
	require.NoError(t, err, "UnwrapKey via transit/decrypt")
	require.Equal(t, dek, got, "DEK round-trip")
	t.Logf("adapter round-trip OK: KeyID=%s version=%d ciphertext=%s…", env.KeyID, env.KeyVersion, string(env.Ciphertext)[:24])

	// --- Engine wired with the OpenBao KeyManager ---
	eng, err := crypto.NewEngineWithOpts([]byte("openbao-integration-password-xyz123"), crypto.WithKeyManager(km))
	require.NoError(t, err)

	// --- S3 client to the real backend ---
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
	)
	require.NoError(t, err)
	s3Client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(endpoint)
		o.UsePathStyle = true
	})

	prefix := fmt.Sprintf("openbao-e2e-%d/", time.Now().UnixNano())
	objectKey := prefix + "object.dat"
	plaintext := []byte("OpenBao Transit end-to-end: the quick brown fox encrypts the lazy DEK.")

	// PUT (encrypt via engine -> OpenBao wraps the DEK).
	encReader, metadata, err := eng.Encrypt(ctx, bytes.NewReader(plaintext), map[string]string{
		"Content-Type": "application/octet-stream",
	})
	require.NoError(t, err)
	encData, err := io.ReadAll(encReader)
	require.NoError(t, err)
	require.NotEqual(t, plaintext, encData, "stored object must be ciphertext, not plaintext")

	s3Meta := map[string]string{}
	for k, v := range metadata {
		s3Meta[k] = v
	}
	_, err = s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(objectKey),
		Body:     bytes.NewReader(encData),
		Metadata: s3Meta,
	})
	require.NoError(t, err, "PUT encrypted object to backend")
	t.Cleanup(func() {
		_, _ = s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(objectKey)})
	})

	// GET + decrypt (engine -> OpenBao unwraps the DEK).
	out, err := s3Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(objectKey)})
	require.NoError(t, err, "GET object")
	atRest, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	_ = out.Body.Close()
	require.NotEqual(t, plaintext, atRest, "object at rest in the backend must be encrypted")

	getMeta := map[string]string{}
	for k, v := range out.Metadata {
		getMeta[k] = v
	}
	decReader, _, err := eng.Decrypt(ctx, bytes.NewReader(atRest), getMeta)
	require.NoError(t, err)
	decData, err := io.ReadAll(decReader)
	require.NoError(t, err)
	require.Equal(t, plaintext, decData, "decrypted plaintext must match original")
	t.Logf("S3 round-trip OK via %s (bucket %s): %d bytes plaintext, %d bytes at rest", endpoint, bucket, len(plaintext), len(atRest))

	// --- Rotation: rotate the Transit key server-side; old object still reads ---
	rkm, ok := km.(crypto.RotatableKeyManager)
	require.True(t, ok, "adapter implements RotatableKeyManager")
	plan, err := rkm.PrepareRotation(ctx, nil)
	require.NoError(t, err)
	require.Equal(t, plan.CurrentVersion+1, plan.TargetVersion)
	require.NoError(t, rkm.PromoteActiveVersion(ctx, plan), "server-side rotate")

	newVer, err := km.ActiveKeyVersion(ctx)
	require.NoError(t, err)
	require.Equal(t, plan.TargetVersion, newVer, "active version advanced after rotate")

	// Old object (wrapped with the previous version) must still decrypt.
	out2, err := s3Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(objectKey)})
	require.NoError(t, err)
	atRest2, err := io.ReadAll(out2.Body)
	require.NoError(t, err)
	_ = out2.Body.Close()
	getMeta2 := map[string]string{}
	for k, v := range out2.Metadata {
		getMeta2[k] = v
	}
	decReader2, _, err := eng.Decrypt(ctx, bytes.NewReader(atRest2), getMeta2)
	require.NoError(t, err)
	decData2, err := io.ReadAll(decReader2)
	require.NoError(t, err)
	require.Equal(t, plaintext, decData2, "pre-rotation object still decryptable after rotate")
	t.Logf("post-rotation OK: version %d->%d, old object still decrypts", plan.CurrentVersion, newVer)
}
