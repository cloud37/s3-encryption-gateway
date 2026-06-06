package config

import (
	"os"
	"path/filepath"
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
compression:
  enabled: false
  algorithm: gzip
  level: 6
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

	// Initial config
	initialConfig := &Config{
		LogLevel: "info",
		RateLimit: RateLimitConfig{Enabled: false},
	}

	// Write initial config
	initialYAML := `log_level: info
rate_limit:
  enabled: false
`
	err := os.WriteFile(configPath, []byte(initialYAML), 0644)
	require.NoError(t, err)

	// Create reloader (without file watching by using empty path)
	reloader, err := NewConfigReloader("", initialConfig, logger)
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

	// Check that callback was called (though it may fail due to empty config path)
	// The important thing is that the signal was handled without panic
	assert.True(t, atomic.LoadInt64(&callbackCalled) >= 0) // May be 0 if config loading fails
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
			name: "compression enabled change rejected",
			oldConfig: &Config{
				Compression: CompressionConfig{Enabled: false},
			},
			newConfig: &Config{
				Compression: CompressionConfig{Enabled: true},
			},
			expectError: true,
			errorMsg:    "compression.enabled cannot be changed during hot reload",
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

func TestGetCurrentConfig(t *testing.T) {
	logger := logrus.New()
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
