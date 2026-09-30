package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigApplier_PolicyFailureBeforeLiveMutation(t *testing.T) {
	t.Setenv("GW_POLICY_0_ID", "")
	dir := t.TempDir()
	good, bad := filepath.Join(dir, "good.yaml"), filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(good, []byte("id: bypass\nbuckets: [backups]\ndisable_encryption: true\n"), 0600))
	require.NoError(t, os.WriteFile(bad, []byte("id: [invalid\n"), 0600))
	old := &config.Config{PolicyFiles: []string{good}, LogLevel: "info", Auth: config.AuthConfig{Credentials: []config.GatewayCredential{{AccessKey: "old", SecretKey: "secret"}}}}
	newCfg := *old
	newCfg.PolicyFiles, newCfg.LogLevel, newCfg.AllowBucketCreation = []string{bad}, "debug", true
	newCfg.Auth.Credentials = []config.GatewayCredential{{AccessKey: "new", SecretKey: "new-secret"}}
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies(old.PolicyFiles))
	store, err := api.NewStaticCredentialStore(old.Auth.Credentials)
	require.NoError(t, err)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	gate := api.NewHandler(nil, nil, logger, nil)
	a := NewConfigChangeApplier(logger, nil, nil, nil, nil, old, pm, store)
	a.SetManagementGate(gate)
	assert.Error(t, a.ApplyConfigChanges(old, &newCfg))
	assert.Same(t, old, a.config)
	assert.Same(t, pm, a.policyManager)
	assert.True(t, pm.BucketDisablesEncryption("backups"))
	assert.False(t, gate.AllowBucketCreation())
	assert.Equal(t, logrus.InfoLevel, logger.GetLevel())
	_, err = store.Lookup("old")
	assert.NoError(t, err)
	_, err = store.Lookup("new")
	assert.Error(t, err)
}

func TestConfigApplier_CredentialFailureKeepsPolicySnapshot(t *testing.T) {
	t.Setenv("GW_POLICY_0_ID", "")
	dir := t.TempDir()
	good, replacement := filepath.Join(dir, "good.yaml"), filepath.Join(dir, "replacement.yaml")
	require.NoError(t, os.WriteFile(good, []byte("id: bypass\nbuckets: [backups]\ndisable_encryption: true\n"), 0600))
	require.NoError(t, os.WriteFile(replacement, []byte("id: required\nbuckets: [backups]\nrequire_encryption: true\n"), 0600))
	old := &config.Config{PolicyFiles: []string{good}, Auth: config.AuthConfig{Credentials: []config.GatewayCredential{{AccessKey: "old", SecretKey: "secret"}}}}
	newCfg := *old
	newCfg.PolicyFiles = []string{replacement}
	newCfg.Auth.Credentials = []config.GatewayCredential{{AccessKey: "invalid"}}
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies(old.PolicyFiles))
	store, err := api.NewStaticCredentialStore(old.Auth.Credentials)
	require.NoError(t, err)
	a := NewConfigChangeApplier(logrus.New(), nil, nil, nil, nil, old, pm, store)
	require.Error(t, a.ApplyConfigChanges(old, &newCfg))
	assert.True(t, pm.BucketDisablesEncryption("backups"))
	assert.Same(t, old, a.config)
}

func TestConfigApplier_PolicySnapshotPublishedOnSharedManager(t *testing.T) {
	t.Setenv("GW_POLICY_0_ID", "env-bypass")
	t.Setenv("GW_POLICY_0_BUCKETS", "backups")
	t.Setenv("GW_POLICY_0_DISABLE_ENCRYPTION", "true")
	t.Setenv("GW_POLICY_0_REQUIRE_ENCRYPTION", "false")
	t.Setenv("GW_POLICY_1_ID", "")
	old := &config.Config{}
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies(nil))
	selected := pm.GetPolicyForBucket("backups")
	require.NotNil(t, selected)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	a := NewConfigChangeApplier(logger, nil, nil, nil, nil, old, pm, nil)
	for i := 0; i < 3; i++ {
		require.NoError(t, a.ApplyConfigChanges(old, old))
		assert.Same(t, pm, a.policyManager)
		require.Len(t, pm.Policies(), 1)
		assert.True(t, pm.BucketDisablesEncryption("backups"))
	}
	t.Setenv("GW_POLICY_0_DISABLE_ENCRYPTION", "false")
	require.NoError(t, a.ApplyConfigChanges(old, old))
	assert.False(t, pm.BucketDisablesEncryption("backups"))
	assert.True(t, selected.DisableEncryption, "a selected policy must not be mutated by publication")
}

// Exercise the actual credentials-file watcher and reload callback. Completion
// is signalled by the callback, not inferred from a scheduling sleep.
func TestConfigReloader_CredentialsFilePolicyFailurePreservesConfig(t *testing.T) {
	t.Setenv("GW_POLICY_0_ID", "")
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	credentialsPath := filepath.Join(dir, "credentials.yaml")
	configPath := filepath.Join(dir, "config.yaml")
	t.Setenv("AUTH_CREDENTIALS_FILE", credentialsPath)
	require.NoError(t, os.WriteFile(policyPath, []byte("id: bypass\nbuckets: [backups]\ndisable_encryption: true\n"), 0600))
	require.NoError(t, os.WriteFile(credentialsPath, []byte("- access_key: file-old\n  secret_key: file-secret\n"), 0600))
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "base", secretKey: "base-secret"})
	f, err := os.OpenFile(configPath, os.O_APPEND|os.O_WRONLY, 0600)
	require.NoError(t, err)
	_, err = f.WriteString("policies: [" + policyPath + "]\n")
	require.NoError(t, err)
	require.NoError(t, f.Close())
	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies(cfg.PolicyFiles))
	store, err := api.NewStaticCredentialStore(cfg.ResolvedCredentials())
	require.NoError(t, err)
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	a := NewConfigChangeApplier(logger, nil, nil, nil, nil, cfg, pm, store)
	r, err := config.NewConfigReloader(configPath, cfg, logger)
	require.NoError(t, err)
	results := make(chan error, 16)
	r.SetOnReloadCallback(func(old, newCfg *config.Config) error {
		err := a.ApplyConfigChanges(old, newCfg)
		results <- err
		return err
	})
	stopped := make(chan struct{})
	go func() { defer close(stopped); r.Start() }()
	t.Cleanup(func() { r.Stop(); <-stopped })
	// Policy files themselves are not watched; the credentials replacement
	// below triggers the reload of the now-invalid policy.
	require.NoError(t, os.WriteFile(policyPath, []byte("id: [invalid\n"), 0600))
	replacement := filepath.Join(dir, "next.yaml")
	require.NoError(t, os.WriteFile(replacement, []byte("- access_key: file-new\n  secret_key: new-secret\n"), 0600))
	require.NoError(t, os.Rename(replacement, credentialsPath))
	select {
	case err := <-results:
		assert.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("credentials-file reload callback was not invoked")
	}
	assert.True(t, pm.BucketDisablesEncryption("backups"))
	_, err = store.Lookup("file-old")
	assert.NoError(t, err)
	_, err = store.Lookup("file-new")
	assert.Error(t, err)
	assert.Equal(t, cfg.Auth.Credentials, r.GetCurrentConfig().Auth.Credentials)
}
