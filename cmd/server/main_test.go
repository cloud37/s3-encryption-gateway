package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func TestInitTracing_Stdout(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:        true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		Exporter:       "stdout",
		SamplingRatio:  1.0,
	}

	tp, err := InitTracing(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()

	// Verify tracer provider was set globally
	tracer := otel.Tracer("test")
	require.NotNil(t, tracer)
}

func TestInitTracing_InvalidExporter(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:     true,
		ServiceName: "test-service",
		Exporter:    "invalid",
	}

	tp, err := InitTracing(cfg, logger)
	assert.Error(t, err)
	assert.Nil(t, tp)
	assert.Contains(t, err.Error(), "unsupported exporter")
}

func TestInitTracing_JaegerMissingEndpoint(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:        true,
		ServiceName:    "test-service",
		Exporter:       "jaeger",
		JaegerEndpoint: "", // Empty endpoint
	}

	tp, err := InitTracing(cfg, logger)
	// Jaeger exporter may succeed with empty endpoint, but should still return a valid provider
	require.NotNil(t, tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()
	require.NoError(t, err)
}

func TestInitTracing_OtlpMissingEndpoint(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:      true,
		ServiceName:  "test-service",
		Exporter:     "otlp",
		OtlpEndpoint: "", // Empty endpoint
	}

	tp, err := InitTracing(cfg, logger)
	// OTLP exporter may succeed with empty endpoint, but should still return a valid provider
	require.NotNil(t, tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()
	require.NoError(t, err)
}

func TestInitTracing_InvalidSamplingRatio(t *testing.T) {
	logger := logrus.New()
	cfg := config.TracingConfig{
		Enabled:       true,
		ServiceName:   "test-service",
		Exporter:      "stdout",
		SamplingRatio: 2.0, // Invalid: > 1.0
	}

	tp, err := InitTracing(cfg, logger)
	require.NoError(t, err) // initTracing doesn't validate sampling ratio
	require.NotNil(t, tp)
	defer func() {
		_ = tp.Shutdown(context.Background())
	}()
}

func TestInitTracing_Disabled(t *testing.T) {
	// When tracing is disabled, initTracing should not be called
	// This test just verifies the config struct works when disabled
	cfg := config.TracingConfig{
		Enabled: false,
		// Other fields can be empty when disabled
	}

	// Just verify the struct is valid (no validation method on TracingConfig directly)
	assert.False(t, cfg.Enabled)
	assert.Equal(t, "", cfg.ServiceName)
}

func TestStringSlicesEqual(t *testing.T) {
	assert.True(t, stringSlicesEqual(nil, nil))
	assert.True(t, stringSlicesEqual([]string{}, []string{}))
	assert.True(t, stringSlicesEqual([]string{"a", "b"}, []string{"a", "b"}))
	assert.False(t, stringSlicesEqual([]string{"a"}, []string{"a", "b"}))
	assert.False(t, stringSlicesEqual([]string{"a", "b"}, []string{"a", "c"}))
	assert.False(t, stringSlicesEqual([]string{"a"}, nil))
}

func TestApplyConfigChanges_PolicyFiles(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	// Create temporary policy files
	tmpDir := t.TempDir()
	policyFile1 := tmpDir + "/policy1.yaml"
	policyFile2 := tmpDir + "/policy2.yaml"

	require.NoError(t, os.WriteFile(policyFile1, []byte(`
id: test-policy-1
buckets:
  - "test-*"
`), 0600))
	require.NoError(t, os.WriteFile(policyFile2, []byte(`
id: test-policy-2
buckets:
  - "other-*"
`), 0600))

	oldCfg := &config.Config{
		ListenAddr:  ":8080",
		PolicyFiles: []string{policyFile1},
	}
	newCfg := &config.Config{
		ListenAddr:  ":8080",
		PolicyFiles: []string{policyFile1, policyFile2},
	}

	pm := config.NewPolicyManager()
	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, pm, nil)

	err := applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)
	assert.NotNil(t, applier.policyManager)
}

func TestApplyConfigChanges_CredentialAdditionBecomesActive(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
			},
		},
	}
	newCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
				{AccessKey: "key2", SecretKey: "secret2"},
			},
		},
	}

	store, err := api.NewStaticCredentialStore(oldCfg.Auth.Credentials)
	require.NoError(t, err)

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, store)
	err = applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)

	cred, err := store.Lookup("key2")
	require.NoError(t, err)
	assert.Equal(t, "key2", cred.AccessKey)
	assert.Equal(t, "secret2", cred.SecretKey)
}

func TestApplyConfigChanges_CredentialRemovalBecomesInactive(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
				{AccessKey: "key2", SecretKey: "secret2"},
			},
		},
	}
	newCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
			},
		},
	}

	store, err := api.NewStaticCredentialStore(oldCfg.Auth.Credentials)
	require.NoError(t, err)

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, store)
	err = applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)

	_, err = store.Lookup("key2")
	assert.ErrorIs(t, err, api.ErrUnknownAccessKey)
}

func TestApplyConfigChanges_InvalidCredentialReloadRetainsOldCredentials(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
			},
		},
	}
	// Duplicate access key makes the config invalid for Replace.
	newCfg := &config.Config{
		Auth: config.AuthConfig{
			Credentials: []config.GatewayCredential{
				{AccessKey: "key1", SecretKey: "secret1"},
				{AccessKey: "key1", SecretKey: "secret2"},
			},
		},
	}

	store, err := api.NewStaticCredentialStore(oldCfg.Auth.Credentials)
	require.NoError(t, err)

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, store)
	err = applier.ApplyConfigChanges(oldCfg, newCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replace credential store")

	// Old credential should still be available after failed reload.
	cred, err := store.Lookup("key1")
	require.NoError(t, err)
	assert.Equal(t, "key1", cred.AccessKey)
	assert.Equal(t, "secret1", cred.SecretKey)
}

func TestApplyConfigChanges_RateLimitReconfiguration(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		RateLimit: config.RateLimitConfig{
			Enabled: false,
		},
	}
	newCfg := &config.Config{
		RateLimit: config.RateLimitConfig{
			Enabled: true,
			Limit:   100,
			Window:  time.Minute,
		},
	}

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, nil)
	err := applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)
	assert.NotNil(t, applier.RateLimiter)

	// Toggle off
	newCfg2 := &config.Config{
		RateLimit: config.RateLimitConfig{
			Enabled: false,
		},
	}
	err = applier.ApplyConfigChanges(newCfg, newCfg2)
	require.NoError(t, err)
	assert.Nil(t, applier.RateLimiter)
}

func TestApplyConfigChanges_LogLevelChange(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		LogLevel: "info",
	}
	newCfg := &config.Config{
		LogLevel: "debug",
	}

	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, nil)
	err := applier.ApplyConfigChanges(oldCfg, newCfg)
	require.NoError(t, err)
	assert.Equal(t, logrus.DebugLevel, logger.Level)
}

// TestApplyConfigChanges_UnrelatedSectionsAreHandled exercises the
// restart-required branches (cache, audit, tracing, proxied bucket, server
// timeouts, logging) plus the invalid-log-level warning path so hot reloads
// involving credentials never mis-handle the surrounding configuration.
func TestApplyConfigChanges_UnrelatedSectionsAreHandled(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	oldCfg := &config.Config{
		LogLevel:      "info",
		Cache:         config.CacheConfig{Enabled: false},
		Audit:         config.AuditConfig{Enabled: false},
		Tracing:       config.TracingConfig{Enabled: false},
		ProxiedBucket: "old-bucket",
		Server:        config.ServerConfig{ReadTimeout: time.Second},
		Logging:       config.LoggingConfig{AccessLogFormat: "text"},
		Auth: config.AuthConfig{Credentials: []config.GatewayCredential{
			{AccessKey: "key", SecretKey: "secret"},
		}},
	}
	newCfg := &config.Config{
		LogLevel:      "not-a-valid-level",
		Cache:         config.CacheConfig{Enabled: true, MaxSize: 1024, MaxItems: 100, DefaultTTL: time.Minute},
		Audit:         config.AuditConfig{Enabled: true, MaxEvents: 10},
		Tracing:       config.TracingConfig{Enabled: true, ServiceName: "svc"},
		ProxiedBucket: "new-bucket",
		Server:        config.ServerConfig{ReadTimeout: 2 * time.Second},
		Logging:       config.LoggingConfig{AccessLogFormat: "json"},
		Auth: config.AuthConfig{Credentials: []config.GatewayCredential{
			{AccessKey: "key", SecretKey: "secret"},
		}},
	}

	store, err := api.NewStaticCredentialStore(oldCfg.Auth.Credentials)
	require.NoError(t, err)
	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, oldCfg, nil, store)
	require.NoError(t, applier.ApplyConfigChanges(oldCfg, newCfg))

	// The credential store must still serve the credential after the reload.
	cred, err := store.Lookup("key")
	require.NoError(t, err)
	assert.Equal(t, "secret", cred.SecretKey)
}

// --- End-to-end hot-reload coverage: real file events / SIGHUP trigger
// LoadConfig, the reload callback drives ConfigChangeApplier, and the live
// credential store reflects the complete new snapshot. ---

// reloadCredential describes one auth credential entry in a test config file.
type reloadCredential struct {
	accessKey string
	secretKey string
	buckets   string // YAML fragment; empty omits the field
}

func writeReloadConfig(t *testing.T, path string, creds ...reloadCredential) {
	t.Helper()
	var credsYAML strings.Builder
	for _, c := range creds {
		fmt.Fprintf(&credsYAML, "    - access_key: %q\n      secret_key: %q\n", c.accessKey, c.secretKey)
		if c.buckets != "" {
			fmt.Fprintf(&credsYAML, "      buckets: %s\n", c.buckets)
		}
	}
	yaml := fmt.Sprintf(`log_level: info
listen_addr: ":8080"
backend:
  access_key: "backend-key"
  secret_key: "backend-secret"
encryption:
  password: "enc-password"
auth:
  credentials:
%s`, credsYAML.String())
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// newReloadHarness wires a real ConfigReloader to a real ConfigChangeApplier
// and a live credential store, mirroring the production wiring in run().
func newReloadHarness(t *testing.T, configPath string, cfg *config.Config) (*api.StaticCredentialStore, *config.ConfigReloader) {
	t.Helper()
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	store, err := api.NewStaticCredentialStore(cfg.Auth.Credentials)
	require.NoError(t, err)
	applier := NewConfigChangeApplier(logger, nil, nil, nil, nil, cfg, nil, store)
	reloader, err := config.NewConfigReloader(configPath, cfg, logger)
	require.NoError(t, err)
	reloader.SetOnReloadCallback(applier.ApplyConfigChanges)
	go reloader.Start()
	t.Cleanup(reloader.Stop)
	return store, reloader
}

func waitForCondition(t *testing.T, timeout time.Duration, description string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestConfigReloader_CredentialAdditionBecomesActive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond) // allow the directory watcher to start
	writeReloadConfig(t, configPath,
		reloadCredential{accessKey: "key1", secretKey: "secret1"},
		reloadCredential{accessKey: "key2", secretKey: "secret2", buckets: `["tenant-a", "shared-*"]`})

	waitForCondition(t, 5*time.Second, "key2 becoming active", func() bool {
		cred, err := store.Lookup("key2")
		return err == nil && cred.SecretKey == "secret2" &&
			cred.AllowsBucket("tenant-a") && cred.AllowsBucket("shared-x") && !cred.AllowsBucket("other")
	})
}

func TestConfigReloader_CredentialRemovalBecomesInactive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath,
		reloadCredential{accessKey: "key1", secretKey: "secret1"},
		reloadCredential{accessKey: "key2", secretKey: "secret2"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	waitForCondition(t, 5*time.Second, "key2 becoming inactive", func() bool {
		_, err := store.Lookup("key2")
		return errors.Is(err, api.ErrUnknownAccessKey)
	})
	if _, err := store.Lookup("key1"); err != nil {
		t.Fatalf("key1 must remain active: %v", err)
	}
}

func TestConfigReloader_EndToEnd_ScopeChangeBecomesActive(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1", buckets: `["tenant-a"]`})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1", buckets: `["tenant-b"]`})

	waitForCondition(t, 5*time.Second, "key1 scope change", func() bool {
		cred, err := store.Lookup("key1")
		return err == nil && cred.AllowsBucket("tenant-b") && !cred.AllowsBucket("tenant-a")
	})
}

func TestConfigReloader_InvalidCredentialReloadRetainsOldCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, reloader := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)
	// Duplicate access keys make the reloaded config invalid; the reload
	// must be rejected wholesale and the live store unchanged.
	var invalidYAML strings.Builder
	fmt.Fprintf(&invalidYAML, "    - access_key: %q\n      secret_key: %q\n", "key1", "secret-x")
	fmt.Fprintf(&invalidYAML, "    - access_key: %q\n      secret_key: %q\n", "key1", "secret-y")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})
	invalid := fmt.Sprintf(`log_level: info
listen_addr: ":8080"
backend:
  access_key: "backend-key"
  secret_key: "backend-secret"
encryption:
  password: "enc-password"
auth:
  credentials:
%s`, invalidYAML.String())
	require.NoError(t, os.WriteFile(configPath, []byte(invalid), 0o644))

	// Give the watcher time to observe and reject the invalid config, then
	// assert the old snapshot is untouched.
	time.Sleep(400 * time.Millisecond)
	cred, err := store.Lookup("key1")
	require.NoError(t, err)
	assert.Equal(t, "secret1", cred.SecretKey)
	if _, err := store.Lookup("key2"); !errors.Is(err, api.ErrUnknownAccessKey) {
		t.Fatalf("invalid reload must not publish partial state")
	}
	current := reloader.GetCurrentConfig()
	require.Len(t, current.Auth.Credentials, 1)
	assert.Equal(t, "key1", current.Auth.Credentials[0].AccessKey)
}

func TestConfigReloader_EndToEnd_CredentialsFileReload(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	credPath := filepath.Join(tmpDir, "credentials.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})
	require.NoError(t, os.WriteFile(credPath, []byte("- access_key: \"file-key\"\n  secret_key: \"file-secret-v1\"\n"), 0o644))
	t.Setenv("AUTH_CREDENTIALS_FILE", credPath)

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)

	// Atomic replacement via rename — the watcher must follow it.
	newCredPath := filepath.Join(tmpDir, "credentials-new.yaml")
	require.NoError(t, os.WriteFile(newCredPath, []byte("- access_key: \"file-key\"\n  secret_key: \"file-secret-v2\"\n  buckets: [\"file-bucket\"]\n"), 0o644))
	require.NoError(t, os.Rename(newCredPath, credPath))

	waitForCondition(t, 5*time.Second, "credentials-file rename reload", func() bool {
		cred, err := store.Lookup("file-key")
		return err == nil && cred.SecretKey == "file-secret-v2" && cred.AllowsBucket("file-bucket")
	})
}

func TestConfigReloader_EndToEnd_SIGHUPReloadsCredentials(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	writeReloadConfig(t, configPath, reloadCredential{accessKey: "key1", secretKey: "secret1"})

	cfg, err := config.LoadConfig(configPath)
	require.NoError(t, err)
	// Write the new state before starting the watcher. The test's only
	// triggering event is SIGHUP, not a file notification.
	writeReloadConfig(t, configPath,
		reloadCredential{accessKey: "key1", secretKey: "secret1"},
		reloadCredential{accessKey: "sighup-key", secretKey: "sighup-secret"})
	store, _ := newReloadHarness(t, configPath, cfg)

	time.Sleep(100 * time.Millisecond)
	// Exercise the signal path end-to-end (LoadConfig -> callback -> live store).
	process, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	require.NoError(t, process.Signal(syscall.SIGHUP))

	waitForCondition(t, 5*time.Second, "SIGHUP credential reload", func() bool {
		cred, err := store.Lookup("sighup-key")
		return err == nil && cred.SecretKey == "sighup-secret"
	})
	if _, err := store.Lookup("key1"); err != nil {
		t.Fatalf("key1 must remain active after SIGHUP reload: %v", err)
	}
}
