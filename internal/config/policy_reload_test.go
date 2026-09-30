package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeReloadPolicy(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(body), 0600))
	return path
}

func setReloadPolicyEnv(t *testing.T) {
	t.Helper()
	for _, field := range []string{"DISABLE_ENCRYPTION", "REQUIRE_ENCRYPTION", "DISALLOW_LOCK_BYPASS", "ENCRYPT_MULTIPART_UPLOADS", "ENCRYPTION_PASSWORD", "ENCRYPTION_ALGORITHM", "RATE_LIMIT_ENABLED", "RATE_LIMIT_REQUESTS", "RATE_LIMIT_WINDOW"} {
		t.Setenv("GW_POLICY_0_"+field, "")
	}
	t.Setenv("GW_POLICY_0_ID", "env-bypass")
	t.Setenv("GW_POLICY_0_BUCKETS", "backups")
	t.Setenv("GW_POLICY_0_DISABLE_ENCRYPTION", "true")
	t.Setenv("GW_POLICY_1_ID", "")
}

// Pause at the source boundary, not at a guessed scheduling delay. Every
// lookup must still see the complete old snapshot until publication.
func TestPolicyReload_ReadersKeepCompleteSnapshot(t *testing.T) {
	for _, withFiles := range []bool{false, true} {
		t.Run(fmt.Sprint(withFiles), func(t *testing.T) { testPolicyReloadSourceBoundary(t, withFiles) })
	}
}

func testPolicyReloadSourceBoundary(t *testing.T, withFiles bool) {
	t.Helper()
	setReloadPolicyEnv(t)
	file := writeReloadPolicy(t, t.TempDir(), "policy.yaml", "id: file-required\nbuckets: [protected]\nrequire_encryption: true\ndisallow_lock_bypass: true\n")
	var paths []string
	if withFiles {
		paths = []string{file}
	}
	pm := NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies(paths))
	before := pm.Policies()
	loadingEnv, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- pm.reloadPolicies(paths, func(candidate *PolicyManager) error {
			close(loadingEnv)
			<-release
			return candidate.LoadPoliciesFromEnv()
		})
	}()
	defer func() {
		close(release)
		require.NoError(t, <-done)
	}()
	select {
	case <-loadingEnv:
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not reach environment source")
	}
	assert.Equal(t, before, pm.Policies(), "readers must never see a file-only snapshot")
	assert.True(t, pm.BucketDisablesEncryption("backups"))
	assert.False(t, pm.BucketEncryptsMultipart("backups"))
	assert.Equal(t, withFiles, pm.BucketRequiresEncryption("protected"))
	assert.Equal(t, withFiles, pm.BucketDisallowsLockBypass("protected"))
}

func TestPolicyReload_ConcurrentLookups(t *testing.T) {
	setReloadPolicyEnv(t)
	file := writeReloadPolicy(t, t.TempDir(), "policy.yaml", "id: required\nbuckets: [protected]\nrequire_encryption: true\ndisallow_lock_bypass: true\n")
	pm := NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies([]string{file}))
	var wg sync.WaitGroup
	start := make(chan struct{})
	violations := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 200; i++ {
				if !pm.BucketDisablesEncryption("backups") || pm.BucketEncryptsMultipart("backups") || !pm.BucketRequiresEncryption("protected") || !pm.BucketDisallowsLockBypass("protected") || len(pm.Policies()) != 2 {
					violations <- "lookup observed incomplete policy set"
					return
				}
			}
		}()
	}
	close(start)
	for i := 0; i < 100; i++ {
		require.NoError(t, pm.ReloadPolicies([]string{file}))
	}
	wg.Wait()
	close(violations)
	for violation := range violations {
		t.Error(violation)
	}
}

func TestPolicyReload_FailurePreservesAllPolicies(t *testing.T) {
	for _, failure := range []string{"malformed-first", "malformed-after-valid", "invalid-glob", "unreadable", "missing-id", "missing-buckets", "conflict", "invalid-env"} {
		t.Run(failure, func(t *testing.T) {
			setReloadPolicyEnv(t)
			dir := t.TempDir()
			file := writeReloadPolicy(t, dir, "old.yaml", "id: required\nbuckets: [protected]\nrequire_encryption: true\ndisallow_lock_bypass: true\n")
			pm := NewPolicyManager()
			require.NoError(t, pm.ReloadPolicies([]string{file}))
			before := pm.Policies()
			valid := writeReloadPolicy(t, dir, "new.yaml", "id: new\nbuckets: [new-bucket]\n")
			bad := writeReloadPolicy(t, dir, "bad.yaml", "id: [malformed\n")
			paths := []string{bad}
			switch failure {
			case "malformed-after-valid":
				paths = []string{valid, bad}
			case "invalid-glob":
				paths = []string{"["}
			case "unreadable":
				paths = []string{dir} // Reading a directory fails even when run as root.
			case "missing-id", "missing-buckets", "conflict":
				bodies := map[string]string{"missing-id": "buckets: [new-bucket]\n", "missing-buckets": "id: invalid\n", "conflict": "id: invalid\nbuckets: [new-bucket]\ndisable_encryption: true\nrequire_encryption: true\n"}
				paths = []string{writeReloadPolicy(t, dir, "invalid.yaml", bodies[failure])}
			case "invalid-env":
				paths = []string{valid}
				t.Setenv("GW_POLICY_1_ID", "invalid")
				t.Setenv("GW_POLICY_1_BUCKETS", "")
			}
			require.Error(t, pm.ReloadPolicies(paths))
			assert.Equal(t, before, pm.Policies())
			assert.True(t, pm.BucketDisablesEncryption("backups"))
			assert.True(t, pm.BucketRequiresEncryption("protected"))
			assert.Nil(t, pm.GetPolicyForBucket("new-bucket"))
		})
	}
}

func TestPolicyReload_ReplacementOrderAndRemoval(t *testing.T) {
	setReloadPolicyEnv(t)
	dir := t.TempDir()
	a := writeReloadPolicy(t, dir, "a.yaml", "id: file-first\nbuckets: [backups]\nrequire_encryption: true\n")
	b := writeReloadPolicy(t, dir, "b.yaml", "id: file-second\nbuckets: [other]\n")
	pm := NewPolicyManager()
	for i := 0; i < 3; i++ {
		require.NoError(t, pm.ReloadPolicies([]string{filepath.Join(dir, "*.yaml")}))
		policies := pm.Policies()
		require.Len(t, policies, 3)
		assert.Equal(t, []string{"file-first", "file-second", "env-bypass"}, []string{policies[0].ID, policies[1].ID, policies[2].ID})
		assert.Equal(t, "file-first", pm.GetPolicyForBucket("backups").ID)
	}
	require.NoError(t, pm.ReloadPolicies([]string{b, a}))
	assert.Equal(t, "file-second", pm.Policies()[0].ID, "pattern order must be preserved")
	require.NoError(t, pm.ReloadPolicies(nil))
	require.Len(t, pm.Policies(), 1)
	assert.True(t, pm.BucketDisablesEncryption("backups"))
	t.Setenv("GW_POLICY_0_ID", "")
	require.NoError(t, pm.ReloadPolicies(nil))
	assert.Empty(t, pm.Policies(), "an intentionally empty candidate must replace the old set")
	assert.False(t, pm.BucketDisablesEncryption("backups"))
}

func TestPolicyLoad_FailurePreservesSnapshot(t *testing.T) {
	setReloadPolicyEnv(t)
	pm := NewPolicyManager()
	require.NoError(t, pm.LoadPoliciesFromEnv())
	before := pm.Policies()
	bad := writeReloadPolicy(t, t.TempDir(), "bad.yaml", "id: [invalid\n")
	require.Error(t, pm.LoadPolicies([]string{bad}))
	assert.Equal(t, before, pm.Policies())
	// A valid first environment entry must not be appended when a later entry fails.
	t.Setenv("GW_POLICY_1_ID", "invalid")
	t.Setenv("GW_POLICY_1_BUCKETS", "")
	require.Error(t, pm.LoadPoliciesFromEnv())
	assert.Equal(t, before, pm.Policies(), "failed env append changed the active set")
}
