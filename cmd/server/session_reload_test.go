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

type gh353SpoolReconfigure struct {
	calls    int
	capacity int64
}

func (s *gh353SpoolReconfigure) ReconfigureCapacity(n int64) error {
	s.calls++
	s.capacity = n
	return nil
}

func gh353ReloadFixture(t *testing.T) (*ConfigChangeApplier, *config.Config, api.CredentialStore, *gh353SpoolReconfigure, *api.SpoolLimitSource) {
	t.Helper()
	t.Setenv("GW_POLICY_0_ID", "")
	path := filepath.Join(t.TempDir(), "old-policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte("id: old-bypass\nbuckets: [bucket]\ndisable_encryption: true\n"), 0600))
	deadline := time.Now().UTC().Add(time.Hour)
	old := &config.Config{LogLevel: "info", PolicyFiles: []string{path},
		Backend: config.BackendConfig{AccessKey: "backend", SecretKey: "backend-secret", SessionToken: "backend-token", Endpoint: "https://backend"},
		Auth:    config.AuthConfig{Credentials: []config.GatewayCredential{{AccessKey: "session", SecretKey: "secret", SessionToken: "old-token", ExpiresAt: &deadline}}},
		Server:  config.ServerConfig{MaxVerifiedSpoolBytes: 1024, MaxAggregateSpoolBytes: 2048}}
	store, err := api.NewStaticCredentialStore(old.ResolvedCredentials())
	require.NoError(t, err)
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies(old.PolicyFiles))
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	a := NewConfigChangeApplier(logger, nil, nil, nil, nil, old, pm, store)
	spool := &gh353SpoolReconfigure{capacity: 2048}
	a.SetSpoolManager(spool)
	limits := api.NewSpoolLimitSource(api.SpoolLimitsForConfig(old))
	a.SetSpoolLimitSource(limits)
	a.SetManagementGate(api.NewHandler(nil, nil, logger, nil))
	return a, old, store, spool, limits
}

func TestGH353SessionReload_RotationAndInvalidSnapshot(t *testing.T) {
	a, old, store, spool, limits := gh353ReloadFixture(t)
	inFlight, err := store.Lookup("session")
	require.NoError(t, err)
	next := *old
	deadline := time.Now().UTC().Add(time.Hour * 2)
	next.Auth.Credentials = []config.GatewayCredential{{AccessKey: "session", SecretKey: "rotated-secret", SessionToken: "rotated-token", ExpiresAt: &deadline}}
	require.NoError(t, a.ApplyConfigChanges(old, &next))
	current, err := store.Lookup("session")
	require.NoError(t, err)
	assert.Equal(t, "rotated-token", current.SessionToken)
	assert.Equal(t, "old-token", inFlight.SessionToken)
	assert.Equal(t, "secret", inFlight.SecretKey)
	assert.Equal(t, deadline, *current.ExpiresAt)
	assert.Same(t, &next, a.config)
	bad := next
	bad.Auth.Credentials = []config.GatewayCredential{{AccessKey: "session", SecretKey: "invalid-secret", SessionToken: "missing-deadline"}}
	bad.Server.MaxVerifiedSpoolBytes = 512
	bad.Server.MaxAggregateSpoolBytes = 4096
	bad.AllowBucketCreation = true
	before := limits.Limits()
	require.Error(t, a.ApplyConfigChanges(&next, &bad))
	retained, err := store.Lookup("session")
	require.NoError(t, err)
	assert.Equal(t, current, retained)
	assert.Same(t, &next, a.config)
	assert.Equal(t, before, limits.Limits())
	assert.Zero(t, spool.calls)
	assert.False(t, a.managementGate.(*api.Handler).AllowBucketCreation())
	assert.True(t, a.policyManager.BucketDisablesEncryption("bucket"))
	// A missing specified env must not retain a previous resolved token.
	t.Setenv("GH353_EMPTY_RELOAD_TOKEN", "")
	bad.Auth.Credentials = []config.GatewayCredential{{AccessKey: "session", SecretKey: "secret", SessionTokenEnv: "GH353_EMPTY_RELOAD_TOKEN", ExpiresAt: &deadline}}
	require.Error(t, a.ApplyConfigChanges(&next, &bad))
	retained, err = store.Lookup("session")
	require.NoError(t, err)
	assert.Equal(t, current, retained)
	// Invalid already-expired entries are not the same as valid expired entries:
	// the latter can be published for operator recovery and reject at runtime.
	expired := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	bad = next
	bad.Auth.Credentials = []config.GatewayCredential{{AccessKey: "session", SecretKey: "secret", SessionToken: "expired-token", ExpiresAt: &expired}}
	require.NoError(t, a.ApplyConfigChanges(&next, &bad))
	retained, err = store.Lookup("session")
	require.NoError(t, err)
	assert.Equal(t, expired, *retained.ExpiresAt)
}

func TestGH353SessionReload_RestartChangeHasNoSideEffects(t *testing.T) {
	changes := map[string]func(*config.Config){
		"access":          func(c *config.Config) { c.Backend.AccessKey = "other" },
		"secret":          func(c *config.Config) { c.Backend.SecretKey = "other" },
		"token":           func(c *config.Config) { c.Backend.SessionToken = "other" },
		"endpoint":        func(c *config.Config) { c.Backend.Endpoint = "http://other" },
		"region":          func(c *config.Config) { c.Backend.Region = "other" },
		"provider":        func(c *config.Config) { c.Backend.Provider = "other" },
		"type":            func(c *config.Config) { c.Backend.Type = config.BackendTypeAzure },
		"azure":           func(c *config.Config) { c.Backend.Azure.AccountName = "other" },
		"ssl":             func(c *config.Config) { c.Backend.UseSSL = true },
		"path_style":      func(c *config.Config) { c.Backend.UsePathStyle = true },
		"ca":              func(c *config.Config) { c.Backend.TLS.CAFile = "other" },
		"insecure":        func(c *config.Config) { c.Backend.TLS.InsecureSkipVerify = true },
		"trusted_proxies": func(c *config.Config) { c.Server.TrustedProxies = []string{"127.0.0.1/32"} },
		"ingress_tls":     func(c *config.Config) { c.TLS.Enabled = true },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			a, old, store, spool, limits := gh353ReloadFixture(t)
			initial, err := store.Lookup("session")
			require.NoError(t, err)
			next := *old
			change(&next)
			deadline := time.Now().UTC().Add(time.Hour)
			next.Auth.Credentials = []config.GatewayCredential{{AccessKey: "new", SecretKey: "new-secret", SessionToken: "new-token", ExpiresAt: &deadline}}
			next.Server.MaxAggregateSpoolBytes = 4096
			next.Server.MaxVerifiedSpoolBytes = 512
			next.AllowBucketCreation = true
			next.LogLevel = "debug"
			path := filepath.Join(t.TempDir(), "new-policy.yaml")
			require.NoError(t, os.WriteFile(path, []byte("id: replacement\nbuckets: [bucket]\nrequire_encryption: true\n"), 0600))
			next.PolicyFiles = []string{path}
			before := limits.Limits()
			err = a.ApplyConfigChanges(old, &next)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "backend-secret")
			assert.NotContains(t, err.Error(), "backend-token")
			assert.Zero(t, spool.calls)
			assert.Equal(t, int64(2048), spool.capacity)
			assert.Equal(t, before, limits.Limits())
			assert.False(t, a.managementGate.(*api.Handler).AllowBucketCreation())
			assert.True(t, a.policyManager.BucketDisablesEncryption("bucket"))
			assert.Equal(t, logrus.InfoLevel, a.logger.GetLevel())
			assert.Same(t, old, a.config)
			retained, err := store.Lookup("session")
			require.NoError(t, err)
			assert.Equal(t, initial, retained)
			_, err = store.Lookup("new")
			assert.ErrorIs(t, err, api.ErrUnknownAccessKey)
			// The restart guard must run even before attempting to read policy files.
			next.PolicyFiles = []string{"/does-not-exist-gh353"}
			err = a.ApplyConfigChanges(old, &next)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "policy")
		})
	}
}
