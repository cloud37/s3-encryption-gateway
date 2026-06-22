package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPolicyLoadingAndMatching(t *testing.T) {
	// Create temporary policy file
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy1.yaml")
	policyContent := `
id: "tenant-a"
buckets: 
  - "tenant-a-*"
  - "shared-bucket"
encryption:
  password: "tenant-a-password-123456"
  preferred_algorithm: "ChaCha20-Poly1305"
  chunked_mode: false
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	// Initialize PolicyManager
	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	require.NoError(t, err)

	// Test matching
	tests := []struct {
		bucket      string
		shouldMatch bool
		policyID    string
	}{
		{"tenant-a-data", true, "tenant-a"},
		{"tenant-a-logs", true, "tenant-a"},
		{"shared-bucket", true, "tenant-a"},
		{"other-bucket", false, ""},
		{"tenant-b-data", false, ""},
	}

	for _, tt := range tests {
		policy := pm.GetPolicyForBucket(tt.bucket)
		if tt.shouldMatch {
			require.NotNil(t, policy, "Expected policy match for bucket %s", tt.bucket)
			assert.Equal(t, tt.policyID, policy.ID)
		} else {
			assert.Nil(t, policy, "Expected no policy match for bucket %s", tt.bucket)
		}
	}
}

// TestBucketRequiresEncryption verifies BucketRequiresEncryption returns
// the correct boolean for matching and non-matching buckets.
func TestBucketRequiresEncryption(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "require-enc.yaml")
	policyContent := `
id: "require-enc-policy"
buckets:
  - "encrypted-*"
require_encryption: true
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	require.NoError(t, err)

	tests := []struct {
		bucket string
		want   bool
	}{
		{"encrypted-bucket", true},
		{"other-bucket", false},
		{"encrypted-files", true},
	}

	for _, tt := range tests {
		got := pm.BucketRequiresEncryption(tt.bucket)
		assert.Equal(t, tt.want, got, "BucketRequiresEncryption(%q)", tt.bucket)
	}

	// nil manager should return false (not panic)
	var nilPM *PolicyManager
	assert.False(t, nilPM.BucketRequiresEncryption("any-bucket"))
}

// TestBucketEncryptsMultipart verifies BucketEncryptsMultipart returns the
// correct boolean for matching and non-matching buckets.
// Default is true: buckets with no matching policy or a policy that omits the
// field are encrypted; only an explicit false opts a bucket out.
func TestBucketEncryptsMultipart(t *testing.T) {
	tmpDir := t.TempDir()

	// Policy with explicit true for specific buckets, explicit false for others.
	policyFile := filepath.Join(tmpDir, "mpu-enc.yaml")
	policyContent := `
id: "mpu-enc-policy"
buckets:
  - "mpu-bucket"
  - "multi-*"
encrypt_multipart_uploads: true
`
	policyFileOff := filepath.Join(tmpDir, "mpu-off.yaml")
	policyContentOff := `
id: "mpu-off-policy"
buckets:
  - "plain-bucket"
encrypt_multipart_uploads: false
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)
	err = os.WriteFile(policyFileOff, []byte(policyContentOff), 0644)
	require.NoError(t, err)

	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	require.NoError(t, err)

	tests := []struct {
		bucket string
		want   bool
	}{
		{"mpu-bucket", true},          // explicit true
		{"multi-upload", true},        // explicit true via glob
		{"plain-bucket", false},       // explicit false
		{"other-bucket", true},        // no matching policy → default true
	}

	for _, tt := range tests {
		got := pm.BucketEncryptsMultipart(tt.bucket)
		assert.Equal(t, tt.want, got, "BucketEncryptsMultipart(%q)", tt.bucket)
	}

	// nil manager should return true (safe default)
	var nilPM *PolicyManager
	assert.True(t, nilPM.BucketEncryptsMultipart("any-bucket"))
}

// TestAnyPolicyRequiresMPUEncryption verifies the boolean aggregate.
// Returns true when at least one policy has encrypt_multipart_uploads omitted
// (default true) or set explicitly to true.
// Returns false only when every loaded policy explicitly sets it to false,
// or when no policies are loaded.
func TestAnyPolicyRequiresMPUEncryption(t *testing.T) {
	tmpDir := t.TempDir()

	// No policies loaded → false (Valkey not required if there are no policies at all).
	pm0 := NewPolicyManager()
	assert.False(t, pm0.AnyPolicyRequiresMPUEncryption(), "expected false with no policies loaded")

	// Policy with field omitted → default true → AnyPolicyRequiresMPUEncryption = true.
	policyFile := filepath.Join(tmpDir, "default.yaml")
	policyContent := `
id: "plain-policy"
buckets:
  - "plain-bucket"
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{policyFile})
	require.NoError(t, err)
	assert.True(t, pm.AnyPolicyRequiresMPUEncryption(), "expected true when policy omits field (default true)")

	// Policy with explicit false → false.
	policyFileOff := filepath.Join(tmpDir, "off.yaml")
	policyContentOff := `
id: "off-policy"
buckets:
  - "other-bucket"
encrypt_multipart_uploads: false
`
	err = os.WriteFile(policyFileOff, []byte(policyContentOff), 0644)
	require.NoError(t, err)

	pmOff := NewPolicyManager()
	err = pmOff.LoadPolicies([]string{policyFileOff})
	require.NoError(t, err)
	assert.False(t, pmOff.AnyPolicyRequiresMPUEncryption(), "expected false when all policies explicitly set false")

	// Mix: one explicit false + one explicit true → true.
	policyFileOn := filepath.Join(tmpDir, "on.yaml")
	policyContentOn := `
id: "on-policy"
buckets:
  - "mpu-bucket"
encrypt_multipart_uploads: true
`
	err = os.WriteFile(policyFileOn, []byte(policyContentOn), 0644)
	require.NoError(t, err)

	pmMix := NewPolicyManager()
	err = pmMix.LoadPolicies([]string{policyFileOff, policyFileOn})
	require.NoError(t, err)
	assert.True(t, pmMix.AnyPolicyRequiresMPUEncryption(), "expected true when at least one policy enables MPU encryption")

	// nil manager should return false
	var nilPM *PolicyManager
	assert.False(t, nilPM.AnyPolicyRequiresMPUEncryption())
}

// TestBucketDisallowsLockBypass verifies BucketDisallowsLockBypass.
func TestBucketDisallowsLockBypass(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "lock.yaml")
	policyContent := `
id: "lock-policy"
buckets:
  - "locked-bucket"
disallow_lock_bypass: true
`
	err := os.WriteFile(policyFile, []byte(policyContent), 0644)
	require.NoError(t, err)

	pm := NewPolicyManager()
	err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	require.NoError(t, err)

	assert.True(t, pm.BucketDisallowsLockBypass("locked-bucket"))
	assert.False(t, pm.BucketDisallowsLockBypass("other-bucket"))
}

// TestPolicyManager_NilSafe verifies methods on a nil PolicyManager that have
// explicit nil guards do not panic. GetPolicyForBucket is not nil-safe by
// design (it acquires a lock), so it is excluded from this test.
// BucketEncryptsMultipart returns true on a nil manager (safe default: encrypt).
func TestPolicyManager_NilSafe(t *testing.T) {
	var pm *PolicyManager
	assert.False(t, pm.BucketRequiresEncryption("any-bucket"))
	assert.True(t, pm.BucketEncryptsMultipart("any-bucket")) // default-on: nil manager = encrypt
	assert.False(t, pm.AnyPolicyRequiresMPUEncryption())
}

// TestLoadPolicies_MissingRequiredFields verifies that policies with missing
// required fields (ID, buckets) are rejected.
func TestLoadPolicies_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name: "missing ID",
			content: `
buckets:
  - "test-bucket"
`,
		},
		{
			name: "missing buckets",
			content: `
id: "test-policy"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			policyFile := filepath.Join(tmpDir, "bad-policy.yaml")
			err := os.WriteFile(policyFile, []byte(tt.content), 0644)
			require.NoError(t, err)

			pm := NewPolicyManager()
			err = pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
			assert.Error(t, err, "expected error for policy with missing required field")
		})
	}
}

func TestPolicyApplication(t *testing.T) {
	// Base config
	baseConfig := &Config{
		Encryption: EncryptionConfig{
			Password:           "base-password",
			PreferredAlgorithm: "AES256-GCM",
			ChunkedMode:        true,
			ChunkSize:          65536,
		},
	}

	// Policy
	policy := &PolicyConfig{
		ID: "test-policy",
		Encryption: &EncryptionConfig{
			Password:           "policy-password",
			PreferredAlgorithm: "ChaCha20-Poly1305",
			// ChunkedMode and ChunkSize not set, should retain zero values if struct default?
			// The Unmarshal will leave them as zero values (false, 0).
			// But ApplyToConfig logic manually merges specific fields for Encryption.
		},
	}

	// Apply policy
	newConfig := policy.ApplyToConfig(baseConfig)

	// Verify base config not modified
	assert.Equal(t, "base-password", baseConfig.Encryption.Password)
	// Verify new config has overrides
	assert.Equal(t, "policy-password", newConfig.Encryption.Password)
	assert.Equal(t, "ChaCha20-Poly1305", newConfig.Encryption.PreferredAlgorithm)
	
	assert.Equal(t, true, newConfig.Encryption.ChunkedMode)
	assert.Equal(t, 65536, newConfig.Encryption.ChunkSize)
}

// TestBucketDisablesEncryption_Match verifies that a policy with
// DisableEncryption: true causes BucketDisablesEncryption to return true.
func TestBucketDisablesEncryption_Match(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "bypass.yaml")
	content := `
id: "bypass-policy"
buckets:
  - "bypass-*"
disable_encryption: true
`
	require.NoError(t, os.WriteFile(policyFile, []byte(content), 0644))

	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")}))

	assert.True(t, pm.BucketDisablesEncryption("bypass-bucket"))
	assert.False(t, pm.BucketDisablesEncryption("other-bucket"))
}

func TestBucketDisablesEncryption_NoMatchReturnsDefault(t *testing.T) {
	pm := NewPolicyManager()
	assert.False(t, pm.BucketDisablesEncryption("any-bucket"))

	var nilPM *PolicyManager
	assert.False(t, nilPM.BucketDisablesEncryption("any-bucket"))
}

func TestBucketEncryptsMultipart_DisableEncryptionImpliesFalse(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "bypass.yaml")
	content := `
id: "bypass-policy"
buckets:
  - "bypass-*"
disable_encryption: true
`
	require.NoError(t, os.WriteFile(policyFile, []byte(content), 0644))

	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")}))

	assert.False(t, pm.BucketEncryptsMultipart("bypass-bucket"),
		"BucketEncryptsMultipart should return false when DisableEncryption is true")
}

func TestPolicyLoad_DisableAndRequireConflict(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "conflict.yaml")
	content := `
id: "conflict-policy"
buckets:
  - "test-bucket"
disable_encryption: true
require_encryption: true
`
	require.NoError(t, os.WriteFile(policyFile, []byte(content), 0644))

	pm := NewPolicyManager()
	err := pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestPolicyManager_Reset(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	content := `
id: "test-policy"
buckets:
  - "test-bucket"
`
	require.NoError(t, os.WriteFile(policyFile, []byte(content), 0644))

	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")}))
	assert.NotNil(t, pm.GetPolicyForBucket("test-bucket"))

	pm.Reset()
	assert.Nil(t, pm.GetPolicyForBucket("test-bucket"),
		"GetPolicyForBucket should return nil after Reset")
}

// setenv is a helper that restores the original env var on test cleanup.
func setenv(t *testing.T, key, value string) {
	old := os.Getenv(key)
	os.Setenv(key, value)
	t.Cleanup(func() { os.Setenv(key, old) })
}

func TestLoadPoliciesFromEnv_ResticUseCase(t *testing.T) {
	setenv(t, "GW_POLICY_0_ID", "restic-bypass")
	setenv(t, "GW_POLICY_0_BUCKETS", "restic-*")
	setenv(t, "GW_POLICY_0_DISABLE_ENCRYPTION", "true")
	t.Cleanup(func() {
		os.Unsetenv("GW_POLICY_0_ID")
		os.Unsetenv("GW_POLICY_0_BUCKETS")
		os.Unsetenv("GW_POLICY_0_DISABLE_ENCRYPTION")
	})

	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPoliciesFromEnv())

	policy := pm.GetPolicyForBucket("restic-data")
	require.NotNil(t, policy)
	assert.Equal(t, "restic-bypass", policy.ID)
	assert.True(t, policy.DisableEncryption)
}

func TestLoadPoliciesFromEnv_AllFields(t *testing.T) {
	setenv(t, "GW_POLICY_0_ID", "full-policy")
	setenv(t, "GW_POLICY_0_BUCKETS", "bucket-a,bucket-b")
	setenv(t, "GW_POLICY_0_DISABLE_ENCRYPTION", "false")
	setenv(t, "GW_POLICY_0_REQUIRE_ENCRYPTION", "true")
	setenv(t, "GW_POLICY_0_DISALLOW_LOCK_BYPASS", "true")
	setenv(t, "GW_POLICY_0_ENCRYPT_MULTIPART_UPLOADS", "false")
	setenv(t, "GW_POLICY_0_ENCRYPTION_PASSWORD", "test-password-123456")
	setenv(t, "GW_POLICY_0_ENCRYPTION_ALGORITHM", "ChaCha20-Poly1305")
	setenv(t, "GW_POLICY_0_RATE_LIMIT_ENABLED", "true")
	setenv(t, "GW_POLICY_0_RATE_LIMIT_REQUESTS", "50")
	setenv(t, "GW_POLICY_0_RATE_LIMIT_WINDOW", "30s")
	t.Cleanup(func() {
		for _, k := range []string{
			"GW_POLICY_0_ID", "GW_POLICY_0_BUCKETS",
			"GW_POLICY_0_DISABLE_ENCRYPTION", "GW_POLICY_0_REQUIRE_ENCRYPTION",
			"GW_POLICY_0_DISALLOW_LOCK_BYPASS", "GW_POLICY_0_ENCRYPT_MULTIPART_UPLOADS",
			"GW_POLICY_0_ENCRYPTION_PASSWORD", "GW_POLICY_0_ENCRYPTION_ALGORITHM",
			"GW_POLICY_0_RATE_LIMIT_ENABLED", "GW_POLICY_0_RATE_LIMIT_REQUESTS",
			"GW_POLICY_0_RATE_LIMIT_WINDOW",
		} {
			os.Unsetenv(k)
		}
	})

	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPoliciesFromEnv())
	policies := pm.Policies()
	require.Len(t, policies, 1)

	p := policies[0]
	assert.Equal(t, "full-policy", p.ID)
	assert.Equal(t, []string{"bucket-a", "bucket-b"}, p.Buckets)
	assert.False(t, p.DisableEncryption)
	assert.True(t, p.RequireEncryption)
	assert.True(t, p.DisallowLockBypass)
	require.NotNil(t, p.EncryptMultipartUploads)
	assert.False(t, *p.EncryptMultipartUploads)
	require.NotNil(t, p.Encryption)
	assert.Equal(t, "test-password-123456", p.Encryption.Password)
	assert.Equal(t, "ChaCha20-Poly1305", p.Encryption.PreferredAlgorithm)
	require.NotNil(t, p.RateLimit)
	assert.True(t, p.RateLimit.Enabled)
	assert.Equal(t, 50, p.RateLimit.Limit)
	assert.Equal(t, 30*time.Second, p.RateLimit.Window)
}

func TestLoadPoliciesFromEnv_MissingBuckets_ReturnsError(t *testing.T) {
	setenv(t, "GW_POLICY_0_ID", "no-buckets")
	t.Cleanup(func() {
		os.Unsetenv("GW_POLICY_0_ID")
	})

	pm := NewPolicyManager()
	err := pm.LoadPoliciesFromEnv()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "BUCKETS must specify at least one pattern")
}

func TestLoadPoliciesFromEnv_Conflict_ReturnsError(t *testing.T) {
	setenv(t, "GW_POLICY_0_ID", "conflict")
	setenv(t, "GW_POLICY_0_BUCKETS", "test")
	setenv(t, "GW_POLICY_0_DISABLE_ENCRYPTION", "true")
	setenv(t, "GW_POLICY_0_REQUIRE_ENCRYPTION", "true")
	t.Cleanup(func() {
		os.Unsetenv("GW_POLICY_0_ID")
		os.Unsetenv("GW_POLICY_0_BUCKETS")
		os.Unsetenv("GW_POLICY_0_DISABLE_ENCRYPTION")
		os.Unsetenv("GW_POLICY_0_REQUIRE_ENCRYPTION")
	})

	pm := NewPolicyManager()
	err := pm.LoadPoliciesFromEnv()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestLoadPoliciesFromEnv_MultiplePolicies(t *testing.T) {
	setenv(t, "GW_POLICY_0_ID", "policy-zero")
	setenv(t, "GW_POLICY_0_BUCKETS", "bucket-0")
	setenv(t, "GW_POLICY_1_ID", "policy-one")
	setenv(t, "GW_POLICY_1_BUCKETS", "bucket-1")
	// GW_POLICY_2_ID is absent — iteration should stop at N=2.
	t.Cleanup(func() {
		os.Unsetenv("GW_POLICY_0_ID")
		os.Unsetenv("GW_POLICY_0_BUCKETS")
		os.Unsetenv("GW_POLICY_1_ID")
		os.Unsetenv("GW_POLICY_1_BUCKETS")
	})

	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPoliciesFromEnv())
	assert.Len(t, pm.Policies(), 2)
}

func TestLoadPoliciesFromEnv_MergesWithFilePolicies(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "file-policy.yaml")
	content := `
id: "file-policy"
buckets:
  - "file-bucket"
`
	require.NoError(t, os.WriteFile(policyFile, []byte(content), 0644))

	setenv(t, "GW_POLICY_0_ID", "env-policy")
	setenv(t, "GW_POLICY_0_BUCKETS", "env-bucket")
	t.Cleanup(func() {
		os.Unsetenv("GW_POLICY_0_ID")
		os.Unsetenv("GW_POLICY_0_BUCKETS")
	})

	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")}))
	require.NoError(t, pm.LoadPoliciesFromEnv())
	require.Len(t, pm.Policies(), 2)

	assert.NotNil(t, pm.GetPolicyForBucket("file-bucket"))
	assert.NotNil(t, pm.GetPolicyForBucket("env-bucket"))
}

func TestPoliciesAccessor(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "policy.yaml")
	content := `
id: "test-policy"
buckets:
  - "test-bucket"
`
	require.NoError(t, os.WriteFile(policyFile, []byte(content), 0644))

	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPolicies([]string{filepath.Join(tmpDir, "*.yaml")}))
	policies := pm.Policies()
	assert.Len(t, policies, 1)
	assert.Equal(t, "test-policy", policies[0].ID)
}

func TestSplitTrimmed(t *testing.T) {
	tests := []struct {
		input string
		sep   string
		want  []string
	}{
		{"a,b,c", ",", []string{"a", "b", "c"}},
		{"a, b, c", ",", []string{"a", "b", "c"}},
		{"  a  ,  b  ", ",", []string{"a", "b"}},
		{"single", ",", []string{"single"}},
		{"", ",", []string{""}},
	}
	for _, tt := range tests {
		got := splitTrimmed(tt.input, tt.sep)
		assert.Equal(t, tt.want, got, "splitTrimmed(%q, %q)", tt.input, tt.sep)
	}
}



