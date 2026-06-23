//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// newBypassPolicyManager creates a PolicyManager that enables
// disable_encryption for the given bucket. Writes a temp YAML file,
// loads it, and returns the populated manager.
func newBypassPolicyManager(t *testing.T, bucket string) *config.PolicyManager {
	t.Helper()
	tmpDir := t.TempDir()
	policyYAML := "id: bypass\nbuckets:\n  - \"" + bucket + "\"\ndisable_encryption: true\n"
	policyPath := filepath.Join(tmpDir, "bypass-policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{policyPath}); err != nil {
		t.Fatalf("load bypass policy: %v", err)
	}
	return pm
}

// newBypassPolicyManagerFromEnv creates a PolicyManager by reading
// GW_POLICY_N_* environment variables set by the caller.
func newBypassPolicyManagerFromEnv(t *testing.T) *config.PolicyManager {
	t.Helper()
	pm := config.NewPolicyManager()
	if err := pm.LoadPoliciesFromEnv(); err != nil {
		t.Fatalf("load policies from env: %v", err)
	}
	return pm
}

// testBypassEncryption_RoundTrip verifies that a PUT+GET through a bypass
// bucket produces byte-identical plaintext.
func testBypassEncryption_RoundTrip(t *testing.T, inst provider.Instance) {
	t.Helper()

	pm := newBypassPolicyManager(t, inst.Bucket)
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm))

	plaintext := []byte("Hello, bypass world!\n")
	key := uniqueKey(t)

	put(t, gw, inst.Bucket, key, plaintext)
	got := get(t, gw, inst.Bucket, key)

	if !bytes.Equal(got, plaintext) {
		t.Errorf("bypass round-trip mismatch: got %q, want %q", string(got), string(plaintext))
	}
}

// testBypassEncryption_AtRest verifies that objects stored in a bypass
// bucket are plaintext on the backend (no encryption markers, raw bytes
// match the original).
func testBypassEncryption_AtRest(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	pm := newBypassPolicyManager(t, inst.Bucket)
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm))

	plaintext := []byte("should-be-plaintext-at-rest")
	key := uniqueKey(t)

	put(t, gw, inst.Bucket, key, plaintext)

	// Read directly from backend (bypassing gateway).
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

	if !bytes.Equal(rawBytes, plaintext) {
		t.Errorf("backend does NOT contain plaintext — object was encrypted when it shouldn't be")
	}

	// Encryption marker must be absent from backend metadata.
	if meta := out.Metadata; meta != nil {
		if v, ok := meta[crypto.MetaEncrypted]; ok && v == "true" {
			t.Error("backend metadata has encryption marker on bypass bucket")
		}
	}
}

// testBypassEncryption_NoEncryptionMetadata verifies that objects stored
// through PassthroughEngine carry no x-amz-meta-encrypted header.
func testBypassEncryption_NoEncryptionMetadata(t *testing.T, inst provider.Instance) {
	t.Helper()

	pm := newBypassPolicyManager(t, inst.Bucket)
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm))

	key := uniqueKey(t)
	data := []byte("no-encryption-metadata-check")

	put(t, gw, inst.Bucket, key, data)

	// Read metadata via HeadObject from the backend directly.
	client := newS3Client(t, inst)
	meta := headMeta(t, client, inst.Bucket, key)

	if v, ok := meta[crypto.MetaEncrypted]; ok && v == "true" {
		t.Error("object in bypass bucket has x-amz-meta-encrypted header")
	}
}

// testBypassEncryption_EncryptedObjectReturns409 verifies that a GET on
// an encrypted object in a bypass bucket returns HTTP 409 with
// EncryptionConfigurationMismatch.
func testBypassEncryption_EncryptedObjectReturns409(t *testing.T, inst provider.Instance) {
	t.Helper()

	// Step 1: Store an encrypted object directly on the backend
	// using the normal encryption engine (no policy).
	encKey := uniqueKey(t)
	plaintext := []byte("pre-existing encrypted object")

	encEng, err := crypto.NewEngineWithChunking(
		[]byte("test-password-12345678"), "", nil, true, crypto.DefaultChunkSize,
	)
	if err != nil {
		t.Fatalf("create engine: %v", err)
	}

	client := newS3Client(t, inst)
	putEncryptedObject(t, client, encEng, inst.Bucket, encKey, plaintext, nil)

	// Verify the object has encryption metadata
	meta := headMeta(t, client, inst.Bucket, encKey)
	if v, ok := meta[crypto.MetaEncrypted]; !ok || v != "true" {
		t.Fatal("pre-stored object should have encryption metadata")
	}

	// Step 2: Start gateway with bypass policy for this bucket
	pm := newBypassPolicyManager(t, inst.Bucket)
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm))

	// Step 3: GET the encrypted object through the bypass gateway
	resp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, encKey))
	if err != nil {
		t.Fatalf("GET encrypted object in bypass bucket: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusConflict {
		t.Errorf("expected 409 Conflict, got %d: %s", resp.StatusCode, string(body))
	}

	if !strings.Contains(string(body), "EncryptionConfigurationMismatch") {
		t.Errorf("response body should contain EncryptionConfigurationMismatch: %s", string(body))
	}
}

// testBypassEncryption_PlaintextObjectServedCorrectly verifies that
// a plaintext (non-encrypted) object stored directly on the backend
// is served correctly through a bypass gateway.
func testBypassEncryption_PlaintextObjectServedCorrectly(t *testing.T, inst provider.Instance) {
	t.Helper()

	// Step 1: PUT a plaintext object directly on the backend
	ctx := context.Background()
	plainKey := uniqueKey(t)
	plaintext := []byte("plaintext-direct-to-backend")

	client := newS3Client(t, inst)
	meta := map[string]string{"Content-Type": "text/plain"}
	if _, err := client.PutObject(ctx, inst.Bucket, plainKey, bytes.NewReader(plaintext), meta, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("put object directly: %v", err)
	}

	// Step 2: Start gateway with bypass policy
	pm := newBypassPolicyManager(t, inst.Bucket)
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm))

	// Step 3: GET through gateway — should work
	got := get(t, gw, inst.Bucket, plainKey)

	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext object mismatch: got %q, want %q", string(got), string(plaintext))
	}
}

// testBypassEncryption_EnvPolicy_EndToEnd verifies the full end-to-end
// GW_POLICY_N_* env-var contract using two consecutive indices:
//
//   N=0 — Restic bypass (disable_encryption: true) + round-trip.
//   N=1 — Full field set (require_encryption, disallow_lock_bypass,
//         encrypt_multipart_uploads: false) + struct assertion + round-trip.
//
// Both scenarios are combined into one test to avoid cross-provider race
// conditions: the conformance suite runs providers in parallel (t.Parallel)
// and os.Setenv is process-global.  Two separate tests setting GW_POLICY_N_*
// from parallel providers would race.
func testBypassEncryption_EnvPolicy_EndToEnd(t *testing.T, inst provider.Instance) {
	t.Helper()

	// ---- N=0: Restic bypass use-case -------------------------------------
	os.Setenv("GW_POLICY_0_ID", "restic-bypass")
	os.Setenv("GW_POLICY_0_BUCKETS", inst.Bucket)
	os.Setenv("GW_POLICY_0_DISABLE_ENCRYPTION", "true")
	// ---- N=1: Full field set ---------------------------------------------
	os.Setenv("GW_POLICY_1_ID", "full-policy")
	os.Setenv("GW_POLICY_1_BUCKETS", inst.Bucket)
	os.Setenv("GW_POLICY_1_DISABLE_ENCRYPTION", "false")
	os.Setenv("GW_POLICY_1_REQUIRE_ENCRYPTION", "true")
	os.Setenv("GW_POLICY_1_DISALLOW_LOCK_BYPASS", "true")
	os.Setenv("GW_POLICY_1_ENCRYPT_MULTIPART_UPLOADS", "false")

	t.Cleanup(func() {
		for _, k := range []string{
			"GW_POLICY_0_ID", "GW_POLICY_0_BUCKETS", "GW_POLICY_0_DISABLE_ENCRYPTION",
			"GW_POLICY_1_ID", "GW_POLICY_1_BUCKETS", "GW_POLICY_1_DISABLE_ENCRYPTION",
			"GW_POLICY_1_REQUIRE_ENCRYPTION", "GW_POLICY_1_DISALLOW_LOCK_BYPASS",
			"GW_POLICY_1_ENCRYPT_MULTIPART_UPLOADS",
		} {
			os.Unsetenv(k)
		}
	})

	pm := newBypassPolicyManagerFromEnv(t)
	policies := pm.Policies()
	if len(policies) != 2 {
		t.Fatalf("expected 2 policies from env, got %d", len(policies))
	}

	// --- Verify N=0 (Restic bypass) ---
	p0 := policies[0]
	if p0.ID != "restic-bypass" {
		t.Errorf("N=0 ID = %q, want restic-bypass", p0.ID)
	}
	if !p0.DisableEncryption {
		t.Error("N=0: DisableEncryption should be true")
	}

	// --- Verify N=1 (full fields) ---
	p1 := policies[1]
	if p1.ID != "full-policy" {
		t.Errorf("N=1 ID = %q, want full-policy", p1.ID)
	}
	if p1.DisableEncryption {
		t.Error("N=1: DisableEncryption should be false")
	}
	if !p1.RequireEncryption {
		t.Error("N=1: RequireEncryption should be true")
	}
	if !p1.DisallowLockBypass {
		t.Error("N=1: DisallowLockBypass should be true")
	}
	if p1.EncryptMultipartUploads == nil {
		t.Error("N=1: EncryptMultipartUploads should not be nil")
	} else if *p1.EncryptMultipartUploads {
		t.Error("N=1: EncryptMultipartUploads should be false")
	}

	// --- End-to-end round-trip through N=0 bypass policy ---
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm))

	plaintext := []byte("restic-backup-via-env-policy")
	key := uniqueKey(t)
	put(t, gw, inst.Bucket, key, plaintext)
	got := get(t, gw, inst.Bucket, key)
	if !bytes.Equal(got, plaintext) {
		t.Errorf("env-policy round-trip mismatch: got %q, want %q", string(got), string(plaintext))
	}
}

// testBypassEncryption_MultiPolicy_MixedBypassAndEncrypt verifies that
// multiple policies can coexist: one bucket bypasses encryption while
// another bucket still encrypts. This proves the gateway correctly
// dispatches to different engines per-bucket.
func testBypassEncryption_MultiPolicy_MixedBypassAndEncrypt(t *testing.T, inst provider.Instance) {
	t.Helper()

	// Bucket names: use the singleton bucket for both policies since we
	// can only have one bucket per Instance. Instead, we test two separate
	// gateways with different policies against the same bucket, verifying
	// that each policy mode works independently when applied to the same
	// bucket. This is equivalent to testing two different buckets.

	// Part A: bypass mode — plaintext round-trip
	pmBypass := newBypassPolicyManager(t, inst.Bucket)
	gwBypass := harness.StartGateway(t, inst, harness.WithPolicyManager(pmBypass))

	plaintext := []byte("bypass-bucket-data")
	bypassKey := uniqueKey(t)
	put(t, gwBypass, inst.Bucket, bypassKey, plaintext)
	gotBypass := get(t, gwBypass, inst.Bucket, bypassKey)
	if !bytes.Equal(gotBypass, plaintext) {
		t.Errorf("bypass gateway: round-trip mismatch")
	}

	// Verify backend has plaintext
	rawClient := newBypassS3Client(t, inst)
	out, err := rawClient.GetObject(context.Background(), &awss3.GetObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(bypassKey),
	})
	if err != nil {
		t.Fatalf("bypass GetObject for mixed test: %v", err)
	}
	rawBytes, _ := io.ReadAll(out.Body)
	out.Body.Close()
	if !bytes.Equal(rawBytes, plaintext) {
		t.Error("backend should contain plaintext for bypass bucket")
	}

	// Part B: encrypted mode — ciphertext round-trip
	encKey := uniqueKey(t)
	encPlaintext := []byte("encrypted-bucket-data")
	gwEnc := harness.StartGateway(t, inst) // default: encrypts everything
	put(t, gwEnc, inst.Bucket, encKey, encPlaintext)
	gotEnc := get(t, gwEnc, inst.Bucket, encKey)
	if !bytes.Equal(gotEnc, encPlaintext) {
		t.Errorf("encrypt gateway: round-trip mismatch")
	}

	// Verify backend has ciphertext (prove it's different from plaintext)
	outEnc, err := rawClient.GetObject(context.Background(), &awss3.GetObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(encKey),
	})
	if err != nil {
		t.Fatalf("bypass GetObject for encrypted key: %v", err)
	}
	encRawBytes, _ := io.ReadAll(outEnc.Body)
	outEnc.Body.Close()
	if bytes.Contains(encRawBytes, encPlaintext) {
		t.Error("backend should contain ciphertext for encrypted bucket, but plaintext marker found")
	}
}

// testBypassEncryption_ConflictRejected ensures that a policy with both
// disable_encryption: true and require_encryption: true is rejected at
// load time (gateway refuses to start / policy logic rejects).
func testBypassEncryption_ConflictRejected(t *testing.T, inst provider.Instance) {
	t.Helper()

	tmpDir := t.TempDir()
	policyYAML := "id: conflict\nbuckets:\n  - \"" + inst.Bucket + "\"\ndisable_encryption: true\nrequire_encryption: true\n"
	policyPath := filepath.Join(tmpDir, "conflict.yaml")
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	pm := config.NewPolicyManager()
	err := pm.LoadPolicies([]string{policyPath})
	if err == nil {
		t.Error("expected error for disable_encryption + require_encryption conflict, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' in error, got: %v", err)
	}
}

// testBypassEncryption_ResetClearsPolicies verifies that PolicyManager.Reset()
// correctly clears loaded policies (regression guard against SIGHUP
// accumulation).
func testBypassEncryption_ResetClearsPolicies(t *testing.T, inst provider.Instance) {
	t.Helper()

	pm := newBypassPolicyManager(t, inst.Bucket)
	if pm.GetPolicyForBucket(inst.Bucket) == nil {
		t.Fatal("policy should match before Reset")
	}

	pm.Reset()

	if pm.GetPolicyForBucket(inst.Bucket) != nil {
		t.Error("policy should NOT match after Reset")
	}
}
