package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfigReloader(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise

	// Test with valid config and no file (SIGHUP only)
	cfg := &Config{LogLevel: "info"}
	reloader, err := NewConfigReloader("", cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, reloader)
	reloader.Stop()

	// Test with temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	err = os.WriteFile(configPath, []byte("log_level: info\n"), 0644)
	require.NoError(t, err)

	reloader, err = NewConfigReloader(configPath, cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, reloader)
	reloader.Stop()
}

func TestConfigReloader_FileWatching(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	// Write initial config
	initialYAML := `log_level: info
rate_limit:
  enabled: false
backend:
  access_key: test-key
  secret_key: test-secret
encryption:
  password: test-password
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	err := os.WriteFile(configPath, []byte(initialYAML), 0644)
	require.NoError(t, err)

	// Load initial config (this will set defaults)
	initialConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Create reloader
	reloader, err := NewConfigReloader(configPath, initialConfig, logger)
	require.NoError(t, err)
	defer reloader.Stop()

	// Set up callback tracking
	var callbackCalled int64
	var callbackMu sync.Mutex
	var firstCallbackOld, firstCallbackNew *Config
	reloader.SetOnReloadCallback(func(old, new *Config) error {
		callCount := atomic.AddInt64(&callbackCalled, 1)
		if callCount == 1 { // Capture first call
			callbackMu.Lock()
			firstCallbackOld = old
			firstCallbackNew = new
			callbackMu.Unlock()
		}
		return nil
	})

	// Start reloader in background
	go reloader.Start()

	// Wait a bit for watcher to start
	time.Sleep(100 * time.Millisecond)

	// Modify config file
	updatedYAML := `log_level: debug
rate_limit:
  enabled: true
  limit: 200
  window: 120s
backend:
  access_key: test-key
  secret_key: test-secret
encryption:
  password: test-password
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	err = os.WriteFile(configPath, []byte(updatedYAML), 0644)
	require.NoError(t, err)

	// Wait for reload
	time.Sleep(200 * time.Millisecond)

	// Check that callback was called at least once
	assert.True(t, atomic.LoadInt64(&callbackCalled) >= 1, "Callback should have been called at least once")
	callbackMu.Lock()
	localOld := firstCallbackOld
	localNew := firstCallbackNew
	callbackMu.Unlock()
	assert.NotNil(t, localOld)
	assert.NotNil(t, localNew)
	assert.Equal(t, "info", localOld.LogLevel)
	assert.Equal(t, "debug", localNew.LogLevel)
}

func TestConfigReloader_SIGHUP(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	// Write initial config with valid credentials so reload validation succeeds
	initialYAML := `log_level: info
rate_limit:
  enabled: false
backend:
  access_key: "backend-key"
  secret_key: "backend-secret"
encryption:
  password: "enc-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	err := os.WriteFile(configPath, []byte(initialYAML), 0644)
	require.NoError(t, err)

	// Load initial config from file so it exactly matches what SIGHUP reload produces
	initialConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	// Create reloader with the config path so SIGHUP can reload it
	reloader, err := NewConfigReloader(configPath, initialConfig, logger)
	require.NoError(t, err)
	defer reloader.Stop()

	// Set up callback tracking
	var callbackCalled int64
	reloader.SetOnReloadCallback(func(old, new *Config) error {
		atomic.AddInt64(&callbackCalled, 1)
		return nil
	})

	// Start reloader in background
	go reloader.Start()

	// Wait a bit for watcher to start
	time.Sleep(100 * time.Millisecond)

	// Send SIGHUP
	pid := os.Getpid()
	process, err := os.FindProcess(pid)
	require.NoError(t, err)
	err = process.Signal(syscall.SIGHUP)
	require.NoError(t, err)

	// Wait for signal handling
	time.Sleep(200 * time.Millisecond)

	// SIGHUP should trigger the callback at least once
	assert.True(t, atomic.LoadInt64(&callbackCalled) >= 1)
}

func TestValidateReloadSafety(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cfg := &Config{}
	reloader, err := NewConfigReloader("", cfg, logger)
	require.NoError(t, err)
	defer reloader.Stop()

	tests := []struct {
		name        string
		oldConfig   *Config
		newConfig   *Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "safe changes allowed",
			oldConfig: &Config{
				LogLevel:  "info",
				ListenAddr: ":8080",
			},
			newConfig: &Config{
				LogLevel:  "debug",
				ListenAddr: ":9090",
			},
			expectError: false,
		},
		{
			name: "crypto password change rejected",
			oldConfig: &Config{
				Encryption: EncryptionConfig{Password: "oldpass"},
			},
			newConfig: &Config{
				Encryption: EncryptionConfig{Password: "newpass"},
			},
			expectError: true,
			errorMsg:    "encryption.password cannot be changed during hot reload",
		},
		{
			name: "crypto key file change rejected",
			oldConfig: &Config{
				Encryption: EncryptionConfig{KeyFile: "/old/key"},
			},
			newConfig: &Config{
				Encryption: EncryptionConfig{KeyFile: "/new/key"},
			},
			expectError: true,
			errorMsg:    "encryption.key_file cannot be changed during hot reload",
		},
		{
			name: "crypto algorithm change rejected",
			oldConfig: &Config{
				Encryption: EncryptionConfig{PreferredAlgorithm: "AES256-GCM"},
			},
			newConfig: &Config{
				Encryption: EncryptionConfig{PreferredAlgorithm: "ChaCha20-Poly1305"},
			},
			expectError: true,
			errorMsg:    "encryption.preferred_algorithm cannot be changed during hot reload",
		},
		{
			name: "crypto supported algorithms change rejected",
			oldConfig: &Config{
				Encryption: EncryptionConfig{SupportedAlgorithms: []string{"AES256-GCM"}},
			},
			newConfig: &Config{
				Encryption: EncryptionConfig{SupportedAlgorithms: []string{"AES256-GCM", "ChaCha20-Poly1305"}},
			},
			expectError: true,
			errorMsg:    "encryption.supported_algorithms cannot be changed during hot reload",
		},
		{
			name: "crypto chunked mode change rejected",
			oldConfig: &Config{
				Encryption: EncryptionConfig{ChunkedMode: true},
			},
			newConfig: &Config{
				Encryption: EncryptionConfig{ChunkedMode: false},
			},
			expectError: true,
			errorMsg:    "encryption.chunked_mode cannot be changed during hot reload",
		},
		{
			name: "backend provider change rejected",
			oldConfig: &Config{
				Backend: BackendConfig{Provider: "aws"},
			},
			newConfig: &Config{
				Backend: BackendConfig{Provider: "minio"},
			},
			expectError: true,
			errorMsg:    "backend.provider cannot be changed during hot reload",
		},
		{
			name: "backend type change rejected",
			oldConfig: &Config{
				Backend: BackendConfig{Type: BackendTypeS3},
			},
			newConfig: &Config{
				Backend: BackendConfig{Type: BackendTypeGCS},
			},
			expectError: true,
			errorMsg:    "backend.type cannot be changed during hot reload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := reloader.validateReloadSafety(tt.oldConfig, tt.newConfig)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestConfigReloader_ReloadErrorPaths exercises the failure branches of
// reloadConfig synchronously: failed LoadConfig (malformed file), rejected
// unsafe changes, and callback errors. In every case the current config must
// remain the previous snapshot.
func TestConfigReloader_ReloadErrorPaths(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	initialYAML := `log_level: info
backend:
  access_key: "backend-key"
  secret_key: "backend-secret"
encryption:
  password: "enc-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	require.NoError(t, os.WriteFile(configPath, []byte(initialYAML), 0644))
	initialConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	reloader, err := NewConfigReloader(configPath, initialConfig, logger)
	require.NoError(t, err)
	defer reloader.Stop()

	t.Run("callback error keeps old config", func(t *testing.T) {
		reloader.SetOnReloadCallback(func(old, new *Config) error {
			return fmt.Errorf("apply failed")
		})
		require.NoError(t, os.WriteFile(configPath, []byte(strings.Replace(initialYAML, "log_level: info", "log_level: debug", 1)), 0644))
		reloader.reloadConfig()
		assert.Equal(t, "info", reloader.GetCurrentConfig().LogLevel)
	})

	t.Run("malformed file keeps old config", func(t *testing.T) {
		reloader.SetOnReloadCallback(func(old, new *Config) error { return nil })
		require.NoError(t, os.WriteFile(configPath, []byte(":\n  not: [valid"), 0644))
		reloader.reloadConfig()
		assert.Equal(t, "info", reloader.GetCurrentConfig().LogLevel)
	})

	t.Run("unsafe change keeps old config", func(t *testing.T) {
		reloader.SetOnReloadCallback(func(old, new *Config) error { return nil })
		unsafeYAML := strings.Replace(initialYAML, "enc-password", "changed-password", 1)
		require.NoError(t, os.WriteFile(configPath, []byte(unsafeYAML), 0644))
		reloader.reloadConfig()
		assert.Equal(t, "info", reloader.GetCurrentConfig().LogLevel)
	})

	t.Run("valid reload applies", func(t *testing.T) {
		reloader.SetOnReloadCallback(func(old, new *Config) error { return nil })
		require.NoError(t, os.WriteFile(configPath, []byte(strings.Replace(initialYAML, "log_level: info", "log_level: debug", 1)), 0644))
		reloader.reloadConfig()
		assert.Equal(t, "debug", reloader.GetCurrentConfig().LogLevel)
	})
}

func TestNewConfigReloader_WatchSetupFailures(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Watching a nonexistent directory must fail.
	missing := filepath.Join(t.TempDir(), "missing", "config.yaml")
	if _, err := NewConfigReloader(missing, &Config{}, logger); err == nil {
		t.Fatal("expected error watching nonexistent config directory")
	}

	// Watching a nonexistent credentials directory must fail.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("log_level: info\n"), 0644))
	t.Setenv("AUTH_CREDENTIALS_FILE", filepath.Join(tmpDir, "missing-creds", "creds.yaml"))
	if _, err := NewConfigReloader(configPath, &Config{}, logger); err == nil {
		t.Fatal("expected error watching nonexistent credentials directory")
	}
}

func TestGetCurrentConfig(t *testing.T) {	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	originalConfig := &Config{LogLevel: "info"}
	reloader, err := NewConfigReloader("", originalConfig, logger)
	require.NoError(t, err)
	defer reloader.Stop()

	// Get current config
	current := reloader.GetCurrentConfig()
	assert.Equal(t, "info", current.LogLevel)

	// Modify returned config (should not affect internal state)
	current.LogLevel = "debug"
	assert.Equal(t, "info", reloader.GetCurrentConfig().LogLevel)
}

func TestConfigReloader_CredentialFileReload(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	credPath := filepath.Join(tmpDir, "credentials.yaml")

	initialYAML := `log_level: info
listen_addr: ":8080"
backend:
  access_key: "backend-key"
  secret_key: "backend-secret"
encryption:
  password: "enc-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	require.NoError(t, os.WriteFile(configPath, []byte(initialYAML), 0644))

	initialCreds := `
- access_key: "cred-key"
  secret_key: "cred-secret"
`
	require.NoError(t, os.WriteFile(credPath, []byte(initialCreds), 0644))
	t.Setenv("AUTH_CREDENTIALS_FILE", credPath)

	initialConfig, err := LoadConfig(configPath)
	require.NoError(t, err)

	reloader, err := NewConfigReloader(configPath, initialConfig, logger)
	require.NoError(t, err)
	defer reloader.Stop()

	var callbackCalled int64
	var callbackMu sync.Mutex
	var callbackNew *Config
	reloader.SetOnReloadCallback(func(old, new *Config) error {
		atomic.AddInt64(&callbackCalled, 1)
		callbackMu.Lock()
		callbackNew = new
		callbackMu.Unlock()
		return nil
	})

	go reloader.Start()
	time.Sleep(100 * time.Millisecond)

	updatedCreds := `
- access_key: "cred-key-updated"
  secret_key: "cred-secret-updated"
`
	require.NoError(t, os.WriteFile(credPath, []byte(updatedCreds), 0644))
	time.Sleep(500 * time.Millisecond)

	assert.True(t, atomic.LoadInt64(&callbackCalled) >= 1, "Callback should have been called at least once")
	callbackMu.Lock()
	localNew := callbackNew
	callbackMu.Unlock()
	require.NotNil(t, localNew)
	foundUpdated := false
	for _, c := range localNew.Auth.Credentials {
		if c.AccessKey == "cred-key-updated" {
			foundUpdated = true
			break
		}
	}
	assert.True(t, foundUpdated, "updated credential should be present in reloaded config")
}
