package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestGH353SessionConfig_SourcesAndPrecedence(t *testing.T) {
	t.Setenv("GH353_SECRET", "environment-secret")
	t.Setenv("GH353_TOKEN", "environment-token")
	t.Setenv("GW_CRED_0_ACCESS_KEY", "")
	t.Setenv("GW_CRED_0_SECRET_KEY", "")
	var cred GatewayCredential
	require.NoError(t, yaml.Unmarshal([]byte("access_key: yaml\nsecret_key: inline-secret\nsecret_key_env: GH353_SECRET\nsession_token_env: GH353_TOKEN\nexpires_at: '2026-12-01T12:00:00Z'\n"), &cred))
	cfg := &Config{Auth: AuthConfig{Credentials: []GatewayCredential{cred}}}
	require.NoError(t, ValidateGatewayCredentials(cfg.Auth.Credentials, false))
	resolved := cfg.ResolvedCredentials()
	assert.Equal(t, "environment-secret", resolved[0].SecretKey)
	assert.Equal(t, "environment-token", resolved[0].SessionToken)
	assert.Empty(t, resolved[0].SessionTokenEnv)
	assert.Empty(t, cred.SessionToken)

	path := filepath.Join(t.TempDir(), "credentials.yaml")
	require.NoError(t, os.WriteFile(path, []byte("- access_key: file\n  secret_key: file-secret\n  session_token_env: GH353_TOKEN\n  expires_at: '2026-12-01T12:00:00Z'\n"), 0600))
	t.Setenv("AUTH_CREDENTIALS_FILE", path)
	require.NoError(t, loadCredentialFile(cfg))
	require.Len(t, cfg.Auth.Credentials, 2)
	assert.Equal(t, "environment-token", cfg.ResolvedCredentials()[1].SessionToken)

	t.Setenv("GW_CRED_0_ACCESS_KEY", "yaml")
	t.Setenv("GW_CRED_0_SECRET_KEY", "indexed-secret")
	t.Setenv("GW_CRED_0_SESSION_TOKEN", "indexed-token")
	t.Setenv("GW_CRED_0_EXPIRES_AT", "2027-01-01T00:00:00.000000001Z")
	t.Setenv("GW_CRED_1_ACCESS_KEY", "indexed-new")
	t.Setenv("GW_CRED_1_SECRET_KEY", "new-secret")
	t.Setenv("GW_CRED_1_SESSION_TOKEN", "new-token")
	t.Setenv("GW_CRED_1_EXPIRES_AT", "2027-02-01T00:00:00Z")
	t.Setenv("GW_CRED_2_ACCESS_KEY", "")
	t.Setenv("GW_CRED_2_SECRET_KEY", "")
	t.Setenv("BACKEND_SESSION_TOKEN", "backend-only")
	require.NoError(t, loadFromEnv(cfg))
	require.Len(t, cfg.Auth.Credentials, 3)
	assert.Equal(t, "indexed-token", cfg.ResolvedCredentials()[0].SessionToken)
	assert.Equal(t, "new-token", cfg.ResolvedCredentials()[2].SessionToken)
	assert.Equal(t, "backend-only", cfg.Backend.SessionToken)
	// LookupEnv permits explicit removal; expiration must be removed with it.
	t.Setenv("GW_CRED_0_SESSION_TOKEN", "")
	t.Setenv("GW_CRED_0_EXPIRES_AT", "")
	t.Setenv("BACKEND_SESSION_TOKEN", "")
	require.NoError(t, loadFromEnv(cfg))
	assert.Empty(t, cfg.Auth.Credentials[0].SessionToken)
	assert.Nil(t, cfg.Auth.Credentials[0].ExpiresAt)
	assert.Empty(t, cfg.Backend.SessionToken)
	t.Setenv("GW_CRED_0_EXPIRES_AT", "not-a-time-secret")
	err := loadFromEnv(cfg)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not-a-time-secret")
	t.Run("complete_yaml_file_env_load", func(t *testing.T) {
		t.Setenv("GW_CRED_0_ACCESS_KEY", "")
		t.Setenv("GW_CRED_0_SECRET_KEY", "")
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte("listen_addr: ':8080'\nbackend:\n  access_key: backend\n  secret_key: backend-secret\n  session_token: backend-inline\nencryption:\n  password: encryption-password\nauth:\n  credentials:\n    - access_key: yaml\n      secret_key_env: GH353_SECRET\n      session_token_env: GH353_TOKEN\n      expires_at: '2026-12-01T12:00:00Z'\n"), 0600))
		t.Setenv("BACKEND_SESSION_TOKEN", "backend-env")
		loaded, err := LoadConfig(path)
		require.NoError(t, err)
		require.Len(t, loaded.Auth.Credentials, 2)
		assert.Equal(t, "yaml", loaded.Auth.Credentials[0].AccessKey)
		assert.Equal(t, "file", loaded.Auth.Credentials[1].AccessKey)
		assert.Equal(t, "environment-token", loaded.ResolvedCredentials()[1].SessionToken)
		assert.Equal(t, "backend-env", loaded.Backend.SessionToken)
		t.Setenv("GH353_TOKEN", "")
		_, err = LoadConfig(path)
		require.Error(t, err, "missing token env must reject the entire loaded configuration")
	})
}

func TestGH353SessionConfig_PairingExpiryAndClone(t *testing.T) {
	expired := time.Date(2000, 1, 1, 0, 0, 0, 1, time.UTC)
	nonGMT := expired.In(time.FixedZone("other", 3600))
	zero := time.Time{}
	t.Setenv("GH353_MISSING_TOKEN", "")
	t.Setenv("GH353_GOOD_TOKEN", "env-token")
	tests := []struct {
		name, token, env string
		deadline         *time.Time
		valid            bool
	}{
		{"static", "", "", nil, true},
		{"expired_valid", "token", "", &expired, true},
		{"maximum_token", strings.Repeat("x", 16*1024), "", &expired, true},
		{"env", "", "GH353_GOOD_TOKEN", &expired, true},
		{"missing_env", "", "GH353_MISSING_TOKEN", &expired, false},
		{"no_inline_fallback", "inline", "GH353_MISSING_TOKEN", &expired, false},
		{"both_sources", "inline", "GH353_GOOD_TOKEN", &expired, false},
		{"static_deadline", "", "", &expired, false},
		{"session_no_deadline", "token", "", nil, false},
		{"zero_deadline", "token", "", &zero, false},
		{"non_gmt", "token", "", &nonGMT, false},
		{"oversize", strings.Repeat("x", 16*1024+1), "", &expired, false},
		{"nul", "secret\x00value", "", &expired, false},
		{"cr", "secret\rvalue", "", &expired, false},
		{"lf", "secret\nvalue", "", &expired, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateGatewayCredentials([]GatewayCredential{{AccessKey: "key", SecretKey: "secret", SessionToken: tc.token, SessionTokenEnv: tc.env, ExpiresAt: tc.deadline}}, true)
			assert.Equal(t, tc.valid, err == nil)
			if err != nil && tc.token != "" {
				assert.NotContains(t, err.Error(), tc.token)
			}
		})
	}
	for _, value := range []string{"bad", "2026-12-01", "2026-12-01T12:00:00+01:00", "2026-12-01T12:00:00+00:00", "2026-12-01T12:00:00,001Z", "0001-01-01T00:00:00Z", ""} {
		var c GatewayCredential
		assert.Error(t, yaml.Unmarshal([]byte("expires_at: '"+value+"'\n"), &c), value)
	}
	var c GatewayCredential
	assert.Error(t, yaml.Unmarshal([]byte("unknown_field: true\n"), &c))
	cfg := &Config{Auth: AuthConfig{Credentials: []GatewayCredential{{AccessKey: "key", SecretKey: "secret", SessionToken: "token", ExpiresAt: &expired}}}}
	copy := cfg.ResolvedCredentials()
	*copy[0].ExpiresAt = expired.Add(time.Hour)
	assert.Equal(t, expired, *cfg.Auth.Credentials[0].ExpiresAt)
}

func TestGH353SessionConfig_RestartOnlyTransport(t *testing.T) {
	old := &Config{Backend: BackendConfig{AccessKey: "key", SecretKey: "secret", SessionToken: "backend-token"}}
	changes := map[string]func(*Config){
		"access":      func(c *Config) { c.Backend.AccessKey = "changed" },
		"secret":      func(c *Config) { c.Backend.SecretKey = "changed" },
		"token":       func(c *Config) { c.Backend.SessionToken = "changed" },
		"endpoint":    func(c *Config) { c.Backend.Endpoint = "https://other" },
		"region":      func(c *Config) { c.Backend.Region = "other" },
		"provider":    func(c *Config) { c.Backend.Provider = "other" },
		"type":        func(c *Config) { c.Backend.Type = BackendTypeAzure },
		"azure":       func(c *Config) { c.Backend.Azure.AccountName = "other" },
		"ssl":         func(c *Config) { c.Backend.UseSSL = true },
		"path_style":  func(c *Config) { c.Backend.UsePathStyle = true },
		"ca":          func(c *Config) { c.Backend.TLS.CAFile = "other" },
		"insecure":    func(c *Config) { c.Backend.TLS.InsecureSkipVerify = true },
		"trust":       func(c *Config) { c.Server.TrustedProxies = []string{"127.0.0.1/32"} },
		"ingress_tls": func(c *Config) { c.TLS.Enabled = true },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			next := *old
			change(&next)
			err := (&ConfigReloader{}).validateReloadSafety(old, &next)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), "backend-token")
		})
	}
	next := *old
	next.Auth.Credentials = []GatewayCredential{{AccessKey: "rotated", SessionToken: "gateway-token"}}
	require.NoError(t, (&ConfigReloader{}).validateReloadSafety(old, &next))
	assert.Error(t, ValidateConstructionTimeReload(nil, &next))
	t.Run("watcher_path_before_callback", func(t *testing.T) {
		t.Setenv("AUTH_CREDENTIALS_FILE", "")
		t.Setenv("GW_CRED_0_ACCESS_KEY", "")
		t.Setenv("GW_CRED_0_SECRET_KEY", "")
		path := filepath.Join(t.TempDir(), "config.yaml")
		base := "listen_addr: ':8080'\nbackend:\n  access_key: backend\n  secret_key: backend-secret\nencryption:\n  password: encryption-password\nauth:\n  credentials:\n    - access_key: session\n      secret_key: secret\n      session_token: token\n      expires_at: '2026-12-01T12:00:00Z'\n"
		require.NoError(t, os.WriteFile(path, []byte(base), 0600))
		cfg, err := LoadConfig(path)
		require.NoError(t, err)
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		r, err := NewConfigReloader(path, cfg, logger)
		require.NoError(t, err)
		t.Cleanup(r.Stop)
		calls := 0
		r.SetOnReloadCallback(func(old, next *Config) error { calls++; return nil })
		require.NoError(t, os.WriteFile(path, []byte(strings.Replace(base, "token\n", "rotated\n", 1)), 0600))
		r.reloadConfig()
		assert.Equal(t, 1, calls)
		assert.Equal(t, "rotated", r.GetCurrentConfig().Auth.Credentials[0].SessionToken)
		require.NoError(t, os.WriteFile(path, []byte(strings.Replace(base, "backend-secret", "changed-secret", 1)), 0600))
		r.reloadConfig()
		assert.Equal(t, 1, calls)
		assert.Equal(t, "rotated", r.GetCurrentConfig().Auth.Credentials[0].SessionToken)
		require.NoError(t, os.WriteFile(path, []byte(strings.Replace(base, "expires_at: '2026-12-01T12:00:00Z'", "expires_at: 'invalid'", 1)), 0600))
		r.reloadConfig()
		assert.Equal(t, 1, calls)
		assert.Equal(t, "rotated", r.GetCurrentConfig().Auth.Credentials[0].SessionToken)
	})
}
