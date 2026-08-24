package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRotationPolicyConfig_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password-123456"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	// Defaults should be set in LoadConfig
	cfg, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.False(t, cfg.Encryption.KeyManager.RotationPolicy.Enabled)
	assert.Equal(t, time.Duration(0), cfg.Encryption.KeyManager.RotationPolicy.GraceWindow)
}

func TestRotationPolicyConfig_FromEnv(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password-123456"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	// Set rotation policy environment variables
	os.Setenv("KEY_MANAGER_ROTATION_POLICY_ENABLED", "true")
	os.Setenv("KEY_MANAGER_ROTATION_GRACE_WINDOW", "168h")
	defer func() {
		os.Unsetenv("KEY_MANAGER_ROTATION_POLICY_ENABLED")
		os.Unsetenv("KEY_MANAGER_ROTATION_GRACE_WINDOW")
	}()

	config, err := LoadConfig(configPath)
	require.NoError(t, err)
	assert.True(t, config.Encryption.KeyManager.RotationPolicy.Enabled)
	assert.Equal(t, 168*time.Hour, config.Encryption.KeyManager.RotationPolicy.GraceWindow)
}

func TestRotationPolicyConfig_FromYAML(t *testing.T) {
	yamlContent := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password-123456"
  key_manager:
    enabled: true
    provider: "cosmian"
    dual_read_window: 2
    rotation_policy:
      enabled: true
      grace_window: 72h
    cosmian:
      endpoint: "https://localhost:9998/kmip/2_1"
      keys:
        - id: "key-1"
          version: 1
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`

	tmpFile := createTempConfigFile(t, yamlContent)
	defer os.Remove(tmpFile)

	config, err := LoadConfig(tmpFile)
	require.NoError(t, err)
	assert.True(t, config.Encryption.KeyManager.RotationPolicy.Enabled)
	assert.Equal(t, 72*time.Hour, config.Encryption.KeyManager.RotationPolicy.GraceWindow)
}

func TestRotationPolicyConfig_InvalidGraceWindow(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password-123456"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	os.Setenv("KEY_MANAGER_ROTATION_GRACE_WINDOW", "invalid")
	defer func() {
		os.Unsetenv("KEY_MANAGER_ROTATION_GRACE_WINDOW")
	}()

	config, err := LoadConfig(configPath)
	require.NoError(t, err)
	// Invalid duration should be ignored, default to 0
	assert.Equal(t, time.Duration(0), config.Encryption.KeyManager.RotationPolicy.GraceWindow)
}

func TestRotationPolicyConfig_EnvOverridesYAML(t *testing.T) {
	yamlContent := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password-123456"
  key_manager:
    rotation_policy:
      enabled: false
      grace_window: 24h
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`

	tmpFile := createTempConfigFile(t, yamlContent)
	defer os.Remove(tmpFile)

	os.Setenv("KEY_MANAGER_ROTATION_POLICY_ENABLED", "true")
	os.Setenv("KEY_MANAGER_ROTATION_GRACE_WINDOW", "168h")
	defer func() {
		os.Unsetenv("KEY_MANAGER_ROTATION_POLICY_ENABLED")
		os.Unsetenv("KEY_MANAGER_ROTATION_GRACE_WINDOW")
	}()

	config, err := LoadConfig(tmpFile)
	require.NoError(t, err)
	// Environment should override YAML
	assert.True(t, config.Encryption.KeyManager.RotationPolicy.Enabled)
	assert.Equal(t, 168*time.Hour, config.Encryption.KeyManager.RotationPolicy.GraceWindow)
}

// Helper function to create temporary config file
func createTempConfigFile(t *testing.T, content string) string {
	tmpFile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)

	_, err = tmpFile.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	return tmpFile.Name()
}
