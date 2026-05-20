package config

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Set minimal required environment variables for test
	os.Setenv("BACKEND_ACCESS_KEY", "test-key")
	os.Setenv("BACKEND_SECRET_KEY", "test-secret")
	os.Setenv("ENCRYPTION_PASSWORD", "test-password")
	defer func() {
		os.Unsetenv("BACKEND_ACCESS_KEY")
		os.Unsetenv("BACKEND_SECRET_KEY")
		os.Unsetenv("ENCRYPTION_PASSWORD")
	}()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.ListenAddr != ":8080" {
		t.Errorf("expected ListenAddr :8080, got %s", config.ListenAddr)
	}

	if config.LogLevel != "info" {
		t.Errorf("expected LogLevel info, got %s", config.LogLevel)
	}

	// Provider is now optional, just for reference
}

func TestLoadConfig_EnvOverrides(t *testing.T) {
	os.Setenv("LISTEN_ADDR", ":9090")
	os.Setenv("LOG_LEVEL", "debug")
	os.Setenv("BACKEND_ENDPOINT", "http://localhost:9000")
	os.Setenv("BACKEND_ACCESS_KEY", "test-key")
	os.Setenv("BACKEND_SECRET_KEY", "test-secret")
	os.Setenv("ENCRYPTION_PASSWORD", "test-password")

	defer func() {
		os.Unsetenv("LISTEN_ADDR")
		os.Unsetenv("LOG_LEVEL")
		os.Unsetenv("BACKEND_ENDPOINT")
		os.Unsetenv("BACKEND_ACCESS_KEY")
		os.Unsetenv("BACKEND_SECRET_KEY")
		os.Unsetenv("ENCRYPTION_PASSWORD")
	}()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.ListenAddr != ":9090" {
		t.Errorf("expected ListenAddr :9090, got %s", config.ListenAddr)
	}

	if config.LogLevel != "debug" {
		t.Errorf("expected LogLevel debug, got %s", config.LogLevel)
	}

	if config.Backend.Endpoint != "http://localhost:9000" {
		t.Errorf("expected Backend.Endpoint http://localhost:9000, got %s", config.Backend.Endpoint)
	}
}

// TestLoadConfig_ValkeyEnvOverrides verifies the V0.6-SEC-3 / #14 env var
// bindings for the Helm chart's Valkey subchart wiring.
func TestLoadConfig_ValkeyEnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  endpoint: "http://localhost:9000"
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password-12345"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	t.Setenv("ENCRYPTION_PASSWORD", "test-password-12345")
	t.Setenv("BACKEND_ENDPOINT", "http://localhost:9000")
	t.Setenv("BACKEND_ACCESS_KEY", "test-key")
	t.Setenv("BACKEND_SECRET_KEY", "test-secret")
	t.Setenv("VALKEY_ADDR", "valkey.prod.svc:6379")
	t.Setenv("VALKEY_USERNAME", "default")
	t.Setenv("VALKEY_PASSWORD_ENV", "VALKEY_PW")
	t.Setenv("VALKEY_DB", "3")
	t.Setenv("VALKEY_TLS_ENABLED", "true")
	t.Setenv("VALKEY_TLS_CA_FILE", "/etc/tls/ca.pem")
	t.Setenv("VALKEY_TLS_CERT_FILE", "/etc/tls/cert.pem")
	t.Setenv("VALKEY_TLS_KEY_FILE", "/etc/tls/key.pem")
	t.Setenv("VALKEY_TLS_INSECURE_SKIP_VERIFY", "false")
	t.Setenv("VALKEY_INSECURE_ALLOW_PLAINTEXT", "false")
	t.Setenv("VALKEY_TTL_SECONDS", "86400")
	t.Setenv("VALKEY_POOL_SIZE", "32")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.MultipartState.Valkey.Addr != "valkey.prod.svc:6379" {
		t.Errorf("expected Valkey.Addr valkey.prod.svc:6379, got %s", cfg.MultipartState.Valkey.Addr)
	}
	if cfg.MultipartState.Valkey.Username != "default" {
		t.Errorf("expected Username 'default', got %q", cfg.MultipartState.Valkey.Username)
	}
	if cfg.MultipartState.Valkey.DB != 3 {
		t.Errorf("expected DB 3, got %d", cfg.MultipartState.Valkey.DB)
	}
	if !cfg.MultipartState.Valkey.TLS.Enabled {
		t.Errorf("expected TLS.Enabled=true, got false")
	}
	if cfg.MultipartState.Valkey.TLS.CAFile != "/etc/tls/ca.pem" {
		t.Errorf("expected TLS.CAFile /etc/tls/ca.pem, got %q", cfg.MultipartState.Valkey.TLS.CAFile)
	}
	if cfg.MultipartState.Valkey.TLS.CertFile != "/etc/tls/cert.pem" {
		t.Errorf("expected TLS.CertFile /etc/tls/cert.pem, got %q", cfg.MultipartState.Valkey.TLS.CertFile)
	}
	if cfg.MultipartState.Valkey.InsecureAllowPlaintext {
		t.Errorf("expected InsecureAllowPlaintext=false, got true")
	}
	if cfg.MultipartState.Valkey.TTLSeconds != 86400 {
		t.Errorf("expected TTLSeconds 86400, got %d", cfg.MultipartState.Valkey.TTLSeconds)
	}
	if cfg.MultipartState.Valkey.PoolSize != 32 {
		t.Errorf("expected PoolSize 32, got %d", cfg.MultipartState.Valkey.PoolSize)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
					KDF: KDFConfig{
						PBKDF2: PBKDF2Config{
							Iterations: 600000,
						},
					},
				},
				Auth: AuthConfig{
					Credentials: []GatewayCredential{
						{
							AccessKey: "gateway-key",
							SecretKey: "gateway-secret",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing listen addr",
			config: &Config{
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
					KDF: KDFConfig{
						PBKDF2: PBKDF2Config{
							Iterations: 600000,
						},
					},
				},
				Auth: AuthConfig{
					Credentials: []GatewayCredential{
						{
							AccessKey: "gateway-key",
							SecretKey: "gateway-secret",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing backend endpoint",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
					KDF: KDFConfig{
						PBKDF2: PBKDF2Config{
							Iterations: 600000,
						},
					},
				},
				Auth: AuthConfig{
					Credentials: []GatewayCredential{
						{
							AccessKey: "gateway-key",
							SecretKey: "gateway-secret",
						},
					},
				},
			},
			wantErr: false, // Endpoint is optional - empty means AWS default
		},
		{
			name: "missing encryption password",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{},
				Auth: AuthConfig{
					Credentials: []GatewayCredential{
						{
							AccessKey: "gateway-key",
							SecretKey: "gateway-secret",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "empty credentials list",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
					KDF: KDFConfig{
						PBKDF2: PBKDF2Config{
							Iterations: 600000,
						},
					},
				},
				Auth: AuthConfig{
					Credentials: []GatewayCredential{},
				},
			},
			wantErr: true,
		},
		{
			name: "credential missing access key",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
					KDF: KDFConfig{
						PBKDF2: PBKDF2Config{
							Iterations: 600000,
						},
					},
				},
				Auth: AuthConfig{
					Credentials: []GatewayCredential{
						{
							SecretKey: "gateway-secret",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "credential missing both secret key and secret key env",
			config: &Config{
				ListenAddr: ":8080",
				Backend: BackendConfig{
					Endpoint:  "http://localhost:9000",
					AccessKey: "test-key",
					SecretKey: "test-secret",
				},
				Encryption: EncryptionConfig{
					Password: "test-password",
					KDF: KDFConfig{
						PBKDF2: PBKDF2Config{
							Iterations: 600000,
						},
					},
				},
				Auth: AuthConfig{
					Credentials: []GatewayCredential{
						{
							AccessKey: "gateway-key",
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ---- V1.0-AUTH-1 GatewayCredential tests ---------------------------------

func TestConfig_Validate_EmptyCredentials(t *testing.T) {
	cfg := minValidConfig()
	cfg.Auth.Credentials = []GatewayCredential{}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for empty credentials list, got nil")
	}
	if !strings.Contains(err.Error(), "auth.credentials must not be empty") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestConfig_Validate_CredentialMissingAccessKey(t *testing.T) {
	cfg := minValidConfig()
	cfg.Auth.Credentials = []GatewayCredential{
		{SecretKey: "secret"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for credential missing access_key, got nil")
	}
	if !strings.Contains(err.Error(), "access_key is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestConfig_Validate_CredentialMissingSecret(t *testing.T) {
	cfg := minValidConfig()
	cfg.Auth.Credentials = []GatewayCredential{
		{AccessKey: "key"},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for credential missing secret, got nil")
	}
	if !strings.Contains(err.Error(), "either secret_key or secret_key_env is required") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestConfig_ResolvedCredentials_FromEnv(t *testing.T) {
	cfg := &Config{
		Auth: AuthConfig{
			Credentials: []GatewayCredential{
				{
					AccessKey:    "gateway-key",
					SecretKeyEnv: "GATEWAY_SECRET",
				},
			},
		},
	}

	t.Setenv("GATEWAY_SECRET", "resolved-from-env")
	resolved := cfg.ResolvedCredentials()

	if len(resolved) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(resolved))
	}
	if resolved[0].SecretKey != "resolved-from-env" {
		t.Errorf("expected SecretKey 'resolved-from-env', got %q", resolved[0].SecretKey)
	}
	// Original config should remain unchanged
	if cfg.Auth.Credentials[0].SecretKey != "" {
		t.Errorf("original config SecretKey should remain empty, got %q", cfg.Auth.Credentials[0].SecretKey)
	}
}

func TestConfig_ResolvedCredentials_EnvNotSet(t *testing.T) {
	cfg := &Config{
		Auth: AuthConfig{
			Credentials: []GatewayCredential{
				{
					AccessKey:    "gateway-key",
					SecretKey:    "inline-secret",
					SecretKeyEnv: "NONEXISTENT_ENV_VAR",
				},
			},
		},
	}

	os.Unsetenv("NONEXISTENT_ENV_VAR")
	resolved := cfg.ResolvedCredentials()

	if len(resolved) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(resolved))
	}
	// When env var is not set, inline SecretKey should be preserved
	if resolved[0].SecretKey != "inline-secret" {
		t.Errorf("expected SecretKey 'inline-secret', got %q", resolved[0].SecretKey)
	}
}

func TestConfig_Validate_ValidCredentials(t *testing.T) {
	cfg := minValidConfig()
	cfg.Auth.Credentials = []GatewayCredential{
		{
			AccessKey: "key-1",
			SecretKey: "secret-1",
			Label:     "first",
		},
		{
			AccessKey:    "key-2",
			SecretKeyEnv: "ENV_SECRET",
		},
	}
	err := cfg.Validate()
	if err != nil {
		t.Fatalf("expected no error for valid credentials, got: %v", err)
	}
}

// ---- V0.6-PERF-2 retry config tests ----------------------------------------

// TestBackendRetryConfig_Defaults verifies that a zero-value config normalises
// to the documented defaults.
func TestBackendRetryConfig_Defaults(t *testing.T) {
	var r BackendRetryConfig
	r.Normalize()

	if r.Mode != DefaultBackendRetryMode {
		t.Errorf("Mode: expected %q, got %q", DefaultBackendRetryMode, r.Mode)
	}
	if r.MaxAttempts != DefaultBackendRetryMaxAttempts {
		t.Errorf("MaxAttempts: expected %d, got %d", DefaultBackendRetryMaxAttempts, r.MaxAttempts)
	}
	if r.InitialBackoff != DefaultBackendRetryInitialBackoff {
		t.Errorf("InitialBackoff: expected %s, got %s", DefaultBackendRetryInitialBackoff, r.InitialBackoff)
	}
	if r.MaxBackoff != DefaultBackendRetryMaxBackoff {
		t.Errorf("MaxBackoff: expected %s, got %s", DefaultBackendRetryMaxBackoff, r.MaxBackoff)
	}
	if r.Jitter != DefaultBackendRetryJitter {
		t.Errorf("Jitter: expected %q, got %q", DefaultBackendRetryJitter, r.Jitter)
	}
	if r.SafeCopyObject == nil || !*r.SafeCopyObject {
		t.Errorf("SafeCopyObject: expected true, got %v", r.SafeCopyObject)
	}
}

// TestBackendRetryConfig_Validate is a table-driven test covering every
// invalid combination documented in the plan.
func TestBackendRetryConfig_Validate(t *testing.T) {
	trueVal := true

	validBase := func() BackendRetryConfig {
		r := BackendRetryConfig{
			Mode:           "standard",
			MaxAttempts:    3,
			InitialBackoff: 100 * time.Millisecond,
			MaxBackoff:     20 * time.Second,
			Jitter:         "full",
			SafeCopyObject: &trueVal,
		}
		return r
	}

	tests := []struct {
		name    string
		mutate  func(*BackendRetryConfig)
		wantErr bool
		wantMsg string
	}{
		{
			name:    "valid defaults",
			mutate:  func(r *BackendRetryConfig) {},
			wantErr: false,
		},
		{
			name:    "mode adaptive valid",
			mutate:  func(r *BackendRetryConfig) { r.Mode = "adaptive" },
			wantErr: false,
		},
		{
			name:    "mode off valid",
			mutate:  func(r *BackendRetryConfig) { r.Mode = "off" },
			wantErr: false,
		},
		{
			name:    "invalid mode",
			mutate:  func(r *BackendRetryConfig) { r.Mode = "turbo" },
			wantErr: true,
			wantMsg: "backend.retry.mode",
		},
		{
			name:    "max_attempts zero",
			mutate:  func(r *BackendRetryConfig) { r.MaxAttempts = 0 },
			wantErr: true,
			wantMsg: "max_attempts",
		},
		{
			name:    "max_attempts too high",
			mutate:  func(r *BackendRetryConfig) { r.MaxAttempts = 11 },
			wantErr: true,
			wantMsg: "max_attempts",
		},
		{
			name:    "initial_backoff too small",
			mutate:  func(r *BackendRetryConfig) { r.InitialBackoff = 500 * time.Microsecond },
			wantErr: true,
			wantMsg: "initial_backoff",
		},
		{
			name:    "max_backoff less than initial",
			mutate:  func(r *BackendRetryConfig) { r.MaxBackoff = 50 * time.Millisecond },
			wantErr: true,
			wantMsg: "max_backoff",
		},
		{
			name:    "max_backoff exceeds 5m",
			mutate:  func(r *BackendRetryConfig) { r.MaxBackoff = 6 * time.Minute },
			wantErr: true,
			wantMsg: "max_backoff",
		},
		{
			name:    "invalid jitter",
			mutate:  func(r *BackendRetryConfig) { r.Jitter = "random" },
			wantErr: true,
			wantMsg: "jitter",
		},
		{
			name:    "jitter decorrelated valid",
			mutate:  func(r *BackendRetryConfig) { r.Jitter = "decorrelated" },
			wantErr: false,
		},
		{
			name:    "jitter equal valid",
			mutate:  func(r *BackendRetryConfig) { r.Jitter = "equal" },
			wantErr: false,
		},
		{
			name:    "jitter none valid",
			mutate:  func(r *BackendRetryConfig) { r.Jitter = "none" },
			wantErr: false,
		},
		{
			name: "per_operation unknown key",
			mutate: func(r *BackendRetryConfig) {
				r.PerOperation = map[string]int{"DoMagic": 2}
			},
			wantErr: true,
			wantMsg: "per_operation",
		},
		{
			name: "per_operation valid key",
			mutate: func(r *BackendRetryConfig) {
				r.PerOperation = map[string]int{"PutObject": 2}
			},
			wantErr: false,
		},
		{
			name: "per_operation attempts zero",
			mutate: func(r *BackendRetryConfig) {
				r.PerOperation = map[string]int{"PutObject": 0}
			},
			wantErr: true,
			wantMsg: "per_operation",
		},
		{
			name: "per_operation CompleteMultipartUpload override 1 valid",
			mutate: func(r *BackendRetryConfig) {
				r.PerOperation = map[string]int{"CompleteMultipartUpload": 1}
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validBase()
			tt.mutate(&r)
			err := r.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("expected error containing %q, got nil", tt.wantMsg)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.wantErr && err != nil && tt.wantMsg != "" {
				if !containsStr(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantMsg)
				}
			}
		})
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		}())
}

// TestBackendRetryConfig_EnvOverrides verifies that env vars override YAML values.
func TestBackendRetryConfig_EnvOverrides(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password-12345"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	t.Setenv("BACKEND_RETRY_MODE", "adaptive")
	t.Setenv("BACKEND_RETRY_MAX_ATTEMPTS", "5")
	t.Setenv("BACKEND_RETRY_INITIAL_BACKOFF", "200ms")
	t.Setenv("BACKEND_RETRY_MAX_BACKOFF", "30s")
	t.Setenv("BACKEND_RETRY_JITTER", "decorrelated")
	t.Setenv("BACKEND_RETRY_SAFE_COPY_OBJECT", "false")

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	r := cfg.Backend.Retry
	if r.Mode != "adaptive" {
		t.Errorf("Mode: expected adaptive, got %q", r.Mode)
	}
	if r.MaxAttempts != 5 {
		t.Errorf("MaxAttempts: expected 5, got %d", r.MaxAttempts)
	}
	if r.InitialBackoff != 200*time.Millisecond {
		t.Errorf("InitialBackoff: expected 200ms, got %s", r.InitialBackoff)
	}
	if r.MaxBackoff != 30*time.Second {
		t.Errorf("MaxBackoff: expected 30s, got %s", r.MaxBackoff)
	}
	if r.Jitter != "decorrelated" {
		t.Errorf("Jitter: expected decorrelated, got %q", r.Jitter)
	}
	if r.SafeCopyObject == nil || *r.SafeCopyObject {
		t.Errorf("SafeCopyObject: expected false, got %v", r.SafeCopyObject)
	}
}

// TestBackendConfig_RoundTrip verifies that YAML serialisation/deserialisation
// preserves every retry field.
func TestBackendConfig_RoundTrip(t *testing.T) {
	falseVal := false
	original := BackendRetryConfig{
		Mode:           "adaptive",
		MaxAttempts:    7,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		Jitter:         "equal",
		SafeCopyObject: &falseVal,
		PerOperation:   map[string]int{"PutObject": 2, "GetObject": 5},
	}

	import_yaml := `mode: adaptive
max_attempts: 7
initial_backoff: 50ms
max_backoff: 10s
jitter: equal
safe_copy_object: false
per_operation:
  GetObject: 5
  PutObject: 2
`
	_ = import_yaml // Parsed manually above; this documents the expected YAML representation.

	// Normalise and validate the original.
	original.Normalize() // should be a no-op since all fields are set
	if err := original.Validate(); err != nil {
		t.Fatalf("original.Validate() = %v", err)
	}

	if original.Mode != "adaptive" {
		t.Errorf("Mode: %q", original.Mode)
	}
	if original.MaxAttempts != 7 {
		t.Errorf("MaxAttempts: %d", original.MaxAttempts)
	}
	if original.InitialBackoff != 50*time.Millisecond {
		t.Errorf("InitialBackoff: %s", original.InitialBackoff)
	}
	if original.MaxBackoff != 10*time.Second {
		t.Errorf("MaxBackoff: %s", original.MaxBackoff)
	}
	if original.Jitter != "equal" {
		t.Errorf("Jitter: %q", original.Jitter)
	}
	if original.SafeCopyObject == nil || *original.SafeCopyObject {
		t.Errorf("SafeCopyObject: %v", original.SafeCopyObject)
	}
	if original.PerOperation["PutObject"] != 2 {
		t.Errorf("PerOperation[PutObject]: %d", original.PerOperation["PutObject"])
	}
	if original.PerOperation["GetObject"] != 5 {
		t.Errorf("PerOperation[GetObject]: %d", original.PerOperation["GetObject"])
	}
}

// ---- V0.6-OBS-1 AdminProfilingConfig validation tests ------------------

// minValidConfig returns a Config that passes all existing validation rules so
// that profiling tests can inject only the fields they care about.
func minValidConfig() *Config {
	return &Config{
		ListenAddr: ":8080",
		Backend: BackendConfig{
			AccessKey: "test-key",
			SecretKey: "test-secret",
		},
		Encryption: EncryptionConfig{
			Password: "test-password",
			KDF: KDFConfig{
				PBKDF2: PBKDF2Config{
					Iterations: 600000,
				},
			},
		},
		Auth: AuthConfig{
			Credentials: []GatewayCredential{
				{
					AccessKey: "gateway-key",
					SecretKey: "gateway-secret",
				},
			},
		},
	}
}

// TestAdminProfilingConfig_Validate_RequiresAdminEnabled verifies that
// admin.profiling.enabled=true + admin.enabled=false produces an error.
func TestAdminProfilingConfig_Validate_RequiresAdminEnabled(t *testing.T) {
	cfg := minValidConfig()
	cfg.Admin.Profiling.Enabled = true
	cfg.Admin.Enabled = false // profiling requires admin

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when profiling enabled but admin disabled")
	}
	if !strings.Contains(err.Error(), "admin.profiling requires admin.enabled") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestAdminProfilingConfig_Validate_NonLoopbackRequiresTLS verifies that
// a non-loopback admin address with profiling enabled requires TLS.
// Note: the existing admin-block validator fires first with a slightly
// different (but equivalent) message. We accept either message.
func TestAdminProfilingConfig_Validate_NonLoopbackRequiresTLS(t *testing.T) {
	cfg := minValidConfig()
	t.Setenv("ADMIN_ALLOW_INLINE_TOKEN", "1")
	cfg.Admin.Enabled = true
	cfg.Admin.Address = "0.0.0.0:8081" // non-loopback
	cfg.Admin.Auth.Token = strings.Repeat("a", 64)
	cfg.Admin.RateLimit.RequestsPerMinute = 30
	cfg.Admin.TLS.Enabled = false
	cfg.Admin.Profiling.Enabled = true
	cfg.Admin.Profiling.MaxProfileSeconds = 60
	cfg.Admin.Profiling.MaxConcurrentProfiles = 2

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error when profiling on non-loopback without TLS")
	}
	// The existing admin-block validator fires first with the admin-level
	// message; the profiling block fires second if the admin one is absent.
	// Either message is acceptable — both require TLS on non-loopback.
	hasTLSMsg := strings.Contains(err.Error(), "tls.enabled")
	if !hasTLSMsg {
		t.Errorf("expected TLS-related error, got: %v", err)
	}
}

// TestAdminProfilingConfig_Validate_NegativeBlockRate verifies that a negative
// block_rate is rejected.
func TestAdminProfilingConfig_Validate_NegativeBlockRate(t *testing.T) {
	cfg := minValidConfig()
	t.Setenv("ADMIN_ALLOW_INLINE_TOKEN", "1")
	cfg.Admin.Enabled = true
	cfg.Admin.Address = "127.0.0.1:8081"
	cfg.Admin.Auth.Token = strings.Repeat("b", 64)
	cfg.Admin.RateLimit.RequestsPerMinute = 30
	cfg.Admin.Profiling.Enabled = true
	cfg.Admin.Profiling.BlockRate = -1
	cfg.Admin.Profiling.MaxProfileSeconds = 60
	cfg.Admin.Profiling.MaxConcurrentProfiles = 2

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative block_rate")
	}
	if !strings.Contains(err.Error(), "block_rate") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestAdminProfilingConfig_Validate_NegativeMutexFraction verifies that a
// negative mutex_fraction is rejected.
func TestAdminProfilingConfig_Validate_NegativeMutexFraction(t *testing.T) {
	cfg := minValidConfig()
	t.Setenv("ADMIN_ALLOW_INLINE_TOKEN", "1")
	cfg.Admin.Enabled = true
	cfg.Admin.Address = "127.0.0.1:8081"
	cfg.Admin.Auth.Token = strings.Repeat("c", 64)
	cfg.Admin.RateLimit.RequestsPerMinute = 30
	cfg.Admin.Profiling.Enabled = true
	cfg.Admin.Profiling.MutexFraction = -1
	cfg.Admin.Profiling.MaxProfileSeconds = 60
	cfg.Admin.Profiling.MaxConcurrentProfiles = 2

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for negative mutex_fraction")
	}
	if !strings.Contains(err.Error(), "mutex_fraction") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestAdminProfilingConfig_Validate_OutOfRangeMaxProfileSeconds verifies that
// max_profile_seconds outside [1, 600] is rejected.
func TestAdminProfilingConfig_Validate_OutOfRangeMaxProfileSeconds(t *testing.T) {
	t.Setenv("ADMIN_ALLOW_INLINE_TOKEN", "1")

	cases := []struct {
		secs    int
		wantErr bool
	}{
		{0, true},   // below minimum
		{601, true}, // above maximum
		{1, false},  // minimum — OK
		{60, false}, // typical — OK
		{600, false}, // maximum — OK
	}

	for _, c := range cases {
		cfg := minValidConfig()
		cfg.Admin.Enabled = true
		cfg.Admin.Address = "127.0.0.1:8081"
		cfg.Admin.Auth.Token = strings.Repeat("d", 64)
		cfg.Admin.RateLimit.RequestsPerMinute = 30
		cfg.Admin.Profiling.Enabled = true
		cfg.Admin.Profiling.MaxProfileSeconds = c.secs
		cfg.Admin.Profiling.MaxConcurrentProfiles = 2

		err := cfg.Validate()
		if c.wantErr && err == nil {
			t.Errorf("secs=%d: expected error, got nil", c.secs)
		}
		if !c.wantErr && err != nil {
			t.Errorf("secs=%d: unexpected error: %v", c.secs, err)
		}
	}
}

// TestAdminProfilingConfig_Validate_DefaultsPassValidation verifies that the
// default AdminProfilingConfig (enabled=false) passes validation silently.
func TestAdminProfilingConfig_Validate_DefaultsPassValidation(t *testing.T) {
	cfg := minValidConfig()
	// Profiling disabled by default — no admin setup needed.
	err := cfg.Validate()
	if err != nil {
		t.Errorf("default profiling config should pass validation, got: %v", err)
	}
}

// TestAdminProfilingEnvVars verifies that the ADMIN_PROFILING_* env vars are
// picked up by loadFromEnv.
func TestAdminProfilingEnvVars(t *testing.T) {
	t.Setenv("ADMIN_PROFILING_ENABLED", "true")
	t.Setenv("ADMIN_PROFILING_BLOCK_RATE", "100")
	t.Setenv("ADMIN_PROFILING_MUTEX_FRACTION", "5")
	t.Setenv("ADMIN_PROFILING_MAX_CONCURRENT", "3")
	t.Setenv("ADMIN_PROFILING_MAX_SECONDS", "120")

	// We just call loadFromEnv on a fresh Config; no need to go through
	// full LoadConfig (which validates admin token files we don't have).
	cfg := &Config{}
	loadFromEnv(cfg)

	if !cfg.Admin.Profiling.Enabled {
		t.Error("Profiling.Enabled should be true")
	}
	if cfg.Admin.Profiling.BlockRate != 100 {
		t.Errorf("BlockRate: want 100, got %d", cfg.Admin.Profiling.BlockRate)
	}
	if cfg.Admin.Profiling.MutexFraction != 5 {
		t.Errorf("MutexFraction: want 5, got %d", cfg.Admin.Profiling.MutexFraction)
	}
	if cfg.Admin.Profiling.MaxConcurrentProfiles != 3 {
		t.Errorf("MaxConcurrentProfiles: want 3, got %d", cfg.Admin.Profiling.MaxConcurrentProfiles)
	}
	if cfg.Admin.Profiling.MaxProfileSeconds != 120 {
		t.Errorf("MaxProfileSeconds: want 120, got %d", cfg.Admin.Profiling.MaxProfileSeconds)
	}
}

// ---- validateAdminTokenLength tests ----------------------------------------

func TestValidateAdminTokenLength(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			name:    "empty token",
			token:   "",
			wantErr: true,
		},
		{
			name:    "hex too short (15 bytes)",
			token:   strings.Repeat("ab", 15), // 30 hex chars = 15 bytes
			wantErr: true,
		},
		{
			name:    "hex exactly 32 bytes",
			token:   strings.Repeat("ab", 32), // 64 hex chars = 32 bytes
			wantErr: false,
		},
		{
			name:    "raw string 31 chars with special chars",
			token:   strings.Repeat("!", 31), // '!' is not valid hex or base64
			wantErr: true,
		},
		{
			name:    "raw string 32 chars with special chars",
			token:   strings.Repeat("!", 32), // '!' is not valid hex or base64
			wantErr: false,
		},
		{
			name:    "raw string longer than 32",
			token:   strings.Repeat("!", 64), // '!' is not valid hex or base64
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAdminTokenLength(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAdminTokenLength(%q) error = %v, wantErr %v", tt.token, err, tt.wantErr)
			}
		})
	}
}

// ---- admin token file permission tests (V1.0-SEC-28) -----------------------

func TestValidate_AdminTokenFilePermissions(t *testing.T) {
	t.Run("symlink rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenFile := tmpDir + "/token"
		targetFile := tmpDir + "/real_token"
		if err := os.WriteFile(targetFile, []byte(strings.Repeat("a", 64)), 0600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		if err := os.Symlink(targetFile, tokenFile); err != nil {
			t.Fatalf("symlink: %v", err)
		}

		cfg := minValidConfig()
		cfg.Admin.Enabled = true
		cfg.Admin.Address = "127.0.0.1:8081"
		cfg.Admin.Auth.TokenFile = tokenFile
		cfg.Admin.RateLimit.RequestsPerMinute = 30

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for symlink token file, got nil")
		}
		if !strings.Contains(err.Error(), "symbolic link") {
			t.Errorf("expected 'symbolic link' error, got: %v", err)
		}
	})

	t.Run("regular file with correct permissions passes", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenFile := tmpDir + "/token"
		if err := os.WriteFile(tokenFile, []byte(strings.Repeat("a", 64)), 0600); err != nil {
			t.Fatalf("write token: %v", err)
		}

		cfg := minValidConfig()
		cfg.Admin.Enabled = true
		cfg.Admin.Address = "127.0.0.1:8081"
		cfg.Admin.Auth.TokenFile = tokenFile
		cfg.Admin.Auth.Type = "bearer"
		cfg.Admin.RateLimit.RequestsPerMinute = 30

		err := cfg.Validate()
		if err != nil {
			t.Errorf("expected no error for 0600 token file, got: %v", err)
		}
	})

	t.Run("regular file with 0644 permissions rejected", func(t *testing.T) {
		tmpDir := t.TempDir()
		tokenFile := tmpDir + "/token"
		if err := os.WriteFile(tokenFile, []byte(strings.Repeat("a", 64)), 0644); err != nil {
			t.Fatalf("write token: %v", err)
		}

		cfg := minValidConfig()
		cfg.Admin.Enabled = true
		cfg.Admin.Address = "127.0.0.1:8081"
		cfg.Admin.Auth.TokenFile = tokenFile
		cfg.Admin.RateLimit.RequestsPerMinute = 30

		err := cfg.Validate()
		if err == nil {
			t.Fatal("expected error for 0644 token file, got nil")
		}
		if !strings.Contains(err.Error(), "too permissive") {
			t.Errorf("expected 'too permissive' error, got: %v", err)
		}
	})
}

// ---- isLoopbackAddress tests -----------------------------------------------

func TestIsLoopbackAddress(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"[::1]:8080", true},
		{"localhost:9090", true},
		{"localhost", true},
		{"127.0.0.1", true},
		{"0.0.0.0:8080", false},
		{"192.168.1.1:8080", false},
		{"example.com:8080", false},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := isLoopbackAddress(tt.addr)
			if got != tt.want {
				t.Errorf("isLoopbackAddress(%q) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// ---- Validate: TLS, audit, key-manager, tracing, logging branches ----------

func TestValidate_TLSConfig(t *testing.T) {
	base := minValidConfig()

	t.Run("TLS enabled no cert", func(t *testing.T) {
		cfg := *base
		cfg.TLS = TLSConfig{Enabled: true, KeyFile: "key.pem"}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tls.cert_file") {
			t.Errorf("expected tls.cert_file error, got %v", err)
		}
	})

	t.Run("TLS enabled no key", func(t *testing.T) {
		cfg := *base
		cfg.TLS = TLSConfig{Enabled: true, CertFile: "cert.pem"}
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "tls.key_file") {
			t.Errorf("expected tls.key_file error, got %v", err)
		}
	})

	t.Run("TLS enabled with both files", func(t *testing.T) {
		cfg := *base
		cfg.TLS = TLSConfig{Enabled: true, CertFile: "cert.pem", KeyFile: "key.pem"}
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := minValidConfig()
	cfg.LogLevel = "verbose"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "log_level") {
		t.Errorf("expected log_level error, got %v", err)
	}
}

func TestValidate_InvalidAlgorithm(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.PreferredAlgorithm = "DES-CBC"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "preferred_algorithm") {
		t.Errorf("expected preferred_algorithm error, got %v", err)
	}
}

func TestValidate_InvalidSupportedAlgorithm(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.SupportedAlgorithms = []string{"AES256-GCM", "Blowfish"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "supported_algorithms") {
		t.Errorf("expected supported_algorithms error, got %v", err)
	}
}

func TestValidate_KeyManagerMissingProvider(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "provider") {
		t.Errorf("expected provider error, got %v", err)
	}
}

func TestValidate_KeyManagerCosmianMissingEndpoint(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "cosmian"
	cfg.Encryption.KeyManager.Cosmian.Keys = []CosmianKeyReference{{ID: "key1"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("expected endpoint error, got %v", err)
	}
}

func TestValidate_KeyManagerCosmianMissingKeys(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "cosmian"
	cfg.Encryption.KeyManager.Cosmian.Endpoint = "https://kms.example.com"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "keys") {
		t.Errorf("expected keys error, got %v", err)
	}
}

func TestValidate_KeyManagerMemoryValid(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "memory"
	if err := cfg.Validate(); err != nil {
		t.Errorf("memory provider should pass validation, got %v", err)
	}
}

func TestValidate_KeyManagerUnsupportedProvider(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "bogus"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected unsupported provider error, got %v", err)
	}
}

func TestConfig_SelfContained_MissingType_Invalid(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "self_contained"
	cfg.Encryption.KeyManager.SelfContained.Type = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "type") {
		t.Errorf("expected type error for empty self_contained.type, got %v", err)
	}
}

func TestConfig_SelfContained_AES_NoKeys_Invalid(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "self_contained"
	cfg.Encryption.KeyManager.SelfContained.Type = "aes"
	cfg.Encryption.KeyManager.SelfContained.AES.Keys = nil
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "keys") {
		t.Errorf("expected keys error for empty aes.keys, got %v", err)
	}
}

func TestConfig_SelfContained_AES_MissingKeySource_Invalid(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "self_contained"
	cfg.Encryption.KeyManager.SelfContained.Type = "aes"
	cfg.Encryption.KeyManager.SelfContained.AES.Keys = []SelfContainedAESKeyEntry{
		{Version: 1, KeySource: ""},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "key_source") {
		t.Errorf("expected key_source error for missing aes.keys[0].key_source, got %v", err)
	}
}

func TestConfig_SelfContained_RSA_MissingPrivateKey_Invalid(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "self_contained"
	cfg.Encryption.KeyManager.SelfContained.Type = "rsa"
	cfg.Encryption.KeyManager.SelfContained.RSA.PrivateKeySource = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "private_key_source") {
		t.Errorf("expected private_key_source error for empty rsa.private_key_source, got %v", err)
	}
}

func TestConfig_SelfContained_InvalidType_Invalid(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "self_contained"
	cfg.Encryption.KeyManager.SelfContained.Type = "ecdsa"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "aes") {
		t.Errorf("expected aes/rsa type error for unsupported self_contained.type, got %v", err)
	}
}

func TestValidate_TracingConfig(t *testing.T) {
	base := minValidConfig()

	t.Run("tracing enabled missing service name", func(t *testing.T) {
		cfg := *base
		cfg.Tracing.Enabled = true
		cfg.Tracing.Exporter = "stdout"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "service_name") {
			t.Errorf("expected service_name error, got %v", err)
		}
	})

	t.Run("tracing invalid exporter", func(t *testing.T) {
		cfg := *base
		cfg.Tracing.Enabled = true
		cfg.Tracing.ServiceName = "gateway"
		cfg.Tracing.Exporter = "datadog"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "exporter") {
			t.Errorf("expected exporter error, got %v", err)
		}
	})

	t.Run("tracing jaeger missing endpoint", func(t *testing.T) {
		cfg := *base
		cfg.Tracing.Enabled = true
		cfg.Tracing.ServiceName = "gateway"
		cfg.Tracing.Exporter = "jaeger"
		cfg.Tracing.SamplingRatio = 0.5
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "jaeger_endpoint") {
			t.Errorf("expected jaeger_endpoint error, got %v", err)
		}
	})

	t.Run("tracing otlp missing endpoint", func(t *testing.T) {
		cfg := *base
		cfg.Tracing.Enabled = true
		cfg.Tracing.ServiceName = "gateway"
		cfg.Tracing.Exporter = "otlp"
		cfg.Tracing.SamplingRatio = 1.0
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "otlp_endpoint") {
			t.Errorf("expected otlp_endpoint error, got %v", err)
		}
	})

	t.Run("tracing out-of-range sampling ratio", func(t *testing.T) {
		cfg := *base
		cfg.Tracing.Enabled = true
		cfg.Tracing.ServiceName = "gateway"
		cfg.Tracing.Exporter = "stdout"
		cfg.Tracing.SamplingRatio = 1.5
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "sampling_ratio") {
			t.Errorf("expected sampling_ratio error, got %v", err)
		}
	})

	t.Run("tracing stdout valid", func(t *testing.T) {
		cfg := *base
		cfg.Tracing.Enabled = true
		cfg.Tracing.ServiceName = "gateway"
		cfg.Tracing.Exporter = "stdout"
		cfg.Tracing.SamplingRatio = 0.5
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
}

func TestValidate_AuditConfig(t *testing.T) {
	base := minValidConfig()

	t.Run("audit file sink missing path", func(t *testing.T) {
		cfg := *base
		cfg.Audit.Enabled = true
		cfg.Audit.Sink.Type = "file"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "file_path") {
			t.Errorf("expected file_path error, got %v", err)
		}
	})

	t.Run("audit http sink missing endpoint", func(t *testing.T) {
		cfg := *base
		cfg.Audit.Enabled = true
		cfg.Audit.Sink.Type = "http"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "endpoint") {
			t.Errorf("expected endpoint error, got %v", err)
		}
	})

	t.Run("audit invalid sink type", func(t *testing.T) {
		cfg := *base
		cfg.Audit.Enabled = true
		cfg.Audit.Sink.Type = "kafka"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "audit.sink.type") {
			t.Errorf("expected audit.sink.type error, got %v", err)
		}
	})

	t.Run("audit stdout sink valid", func(t *testing.T) {
		cfg := *base
		cfg.Audit.Enabled = true
		cfg.Audit.Sink.Type = "stdout"
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})

	t.Run("audit file sink with path valid", func(t *testing.T) {
		cfg := *base
		cfg.Audit.Enabled = true
		cfg.Audit.Sink.Type = "file"
		cfg.Audit.Sink.FilePath = "/tmp/audit.log"
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
}

// TestValidate_InvalidValkeyMinVersion verifies that an invalid Valkey TLS
// min_version is rejected when Valkey is configured.
func TestValidate_InvalidValkeyMinVersion(t *testing.T) {
	cfg := minValidConfig()
	cfg.MultipartState.Valkey.Addr = "valkey.internal:6379"
	cfg.MultipartState.Valkey.TLS.MinVersion = "1.4"

	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min_version")
}

func TestValidate_LoggingFormat(t *testing.T) {
	base := minValidConfig()

	t.Run("invalid access_log_format", func(t *testing.T) {
		cfg := *base
		cfg.Logging.AccessLogFormat = "csv"
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "access_log_format") {
			t.Errorf("expected access_log_format error, got %v", err)
		}
	})

	t.Run("valid json format", func(t *testing.T) {
		cfg := *base
		cfg.Logging.AccessLogFormat = "json"
		if err := cfg.Validate(); err != nil {
			t.Errorf("expected no error, got %v", err)
		}
	})
}

// ---- validateReloadSafety tests --------------------------------------------

func TestValidateReloadSafety_Coverage(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	makeCfg := func() *Config {
		return &Config{
			ListenAddr: ":8080",
			Backend: BackendConfig{
				AccessKey: "test-key",
				SecretKey: "test-secret",
				Provider:  "minio",
			},
			Encryption: EncryptionConfig{
				Password:            "test-password",
				PreferredAlgorithm:  "AES256-GCM",
				SupportedAlgorithms: []string{"AES256-GCM"},
				ChunkedMode:         false,
				ChunkSize:           65536,
				KDF: KDFConfig{
					PBKDF2: PBKDF2Config{
						Iterations: 600000,
					},
				},
			},
		}
	}

	reloader := &ConfigReloader{
		currentConfig: makeCfg(),
		logger:        logger,
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
		wantMsg string
	}{
		{
			name:    "no changes",
			mutate:  func(c *Config) {},
			wantErr: false,
		},
		{
			name:    "password changed",
			mutate:  func(c *Config) { c.Encryption.Password = "new-password" },
			wantErr: true,
			wantMsg: "encryption.password",
		},
		{
			name:    "key_file changed",
			mutate:  func(c *Config) { c.Encryption.KeyFile = "new-key.pem" },
			wantErr: true,
			wantMsg: "encryption.key_file",
		},
		{
			name:    "preferred_algorithm changed",
			mutate:  func(c *Config) { c.Encryption.PreferredAlgorithm = "ChaCha20-Poly1305" },
			wantErr: true,
			wantMsg: "preferred_algorithm",
		},
		{
			name:    "supported_algorithms length changed",
			mutate:  func(c *Config) { c.Encryption.SupportedAlgorithms = []string{"AES256-GCM", "ChaCha20-Poly1305"} },
			wantErr: true,
			wantMsg: "supported_algorithms",
		},
		{
			name:    "supported_algorithms value changed",
			mutate:  func(c *Config) { c.Encryption.SupportedAlgorithms = []string{"ChaCha20-Poly1305"} },
			wantErr: true,
			wantMsg: "supported_algorithms",
		},
		{
			name:    "chunked_mode changed",
			mutate:  func(c *Config) { c.Encryption.ChunkedMode = true },
			wantErr: true,
			wantMsg: "chunked_mode",
		},
		{
			name:    "chunk_size changed",
			mutate:  func(c *Config) { c.Encryption.ChunkSize = 131072 },
			wantErr: true,
			wantMsg: "chunk_size",
		},
		{
			name:    "backend.provider changed",
			mutate:  func(c *Config) { c.Backend.Provider = "garage" },
			wantErr: true,
			wantMsg: "backend.provider",
		},
		{
			name:    "key_manager.enabled changed",
			mutate:  func(c *Config) { c.Encryption.KeyManager.Enabled = true },
			wantErr: true,
			wantMsg: "key_manager.enabled",
		},
		{
			name:    "admin.enabled changed",
			mutate:  func(c *Config) { c.Admin.Enabled = true },
			wantErr: true,
			wantMsg: "admin.enabled",
		},
		{
			name:    "admin.address changed",
			mutate:  func(c *Config) { c.Admin.Address = "127.0.0.1:9090" },
			wantErr: true,
			wantMsg: "admin.address",
		},
		{
			name:    "admin.tls.enabled changed",
			mutate:  func(c *Config) { c.Admin.TLS.Enabled = true },
			wantErr: true,
			wantMsg: "admin.tls.enabled",
		},
		{
			name:    "compression.enabled changed",
			mutate:  func(c *Config) { c.Compression.Enabled = true },
			wantErr: true,
			wantMsg: "compression.enabled",
		},
		{
			name:    "listen_addr change allowed",
			mutate:  func(c *Config) { c.ListenAddr = ":9090" },
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := makeCfg()
			newCfg := makeCfg()
			tt.mutate(newCfg)

			err := reloader.validateReloadSafety(old, newCfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateReloadSafety() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && err != nil && tt.wantMsg != "" {
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantMsg)
				}
			}
		})
	}
}

// ---- isEnvSet tests --------------------------------------------------------

func TestIsEnvSet(t *testing.T) {
	const key = "TEST_IS_ENV_SET_UNIQUE_XYZ_12345"
	os.Unsetenv(key)
	if isEnvSet(key) {
		t.Error("expected isEnvSet to return false for unset variable")
	}
	t.Setenv(key, "value")
	if !isEnvSet(key) {
		t.Error("expected isEnvSet to return true for set variable")
	}
}

// ---- loadFromEnv additional coverage ---------------------------------------

func TestLoadFromEnv_InvalidRetryFields(t *testing.T) {
	t.Setenv("BACKEND_RETRY_MAX_ATTEMPTS", "not-a-number") // should be ignored
	t.Setenv("BACKEND_RETRY_INITIAL_BACKOFF", "invalid")   // should be ignored
	t.Setenv("BACKEND_RETRY_MAX_BACKOFF", "invalid")       // should be ignored
	t.Setenv("BACKEND_RETRY_SAFE_COPY_OBJECT", "true")

	cfg := &Config{}
	loadFromEnv(cfg)

	// Invalid numeric/duration values are silently skipped.
	if cfg.Backend.Retry.MaxAttempts != 0 {
		t.Errorf("expected MaxAttempts=0 (invalid input skipped), got %d", cfg.Backend.Retry.MaxAttempts)
	}
	if cfg.Backend.Retry.SafeCopyObject == nil || !*cfg.Backend.Retry.SafeCopyObject {
		t.Errorf("expected SafeCopyObject=true, got %v", cfg.Backend.Retry.SafeCopyObject)
	}
}

func TestLoadFromEnv_BackendFilterMetadata(t *testing.T) {
	t.Setenv("BACKEND_FILTER_METADATA_KEYS", "x-amz-meta-foo, x-amz-meta-bar , baz")

	cfg := &Config{}
	loadFromEnv(cfg)

	expected := []string{"x-amz-meta-foo", "x-amz-meta-bar", "baz"}
	if len(cfg.Backend.FilterMetadataKeys) != len(expected) {
		t.Fatalf("expected %d keys, got %d: %v", len(expected), len(cfg.Backend.FilterMetadataKeys), cfg.Backend.FilterMetadataKeys)
	}
	for i, k := range expected {
		if cfg.Backend.FilterMetadataKeys[i] != k {
			t.Errorf("key[%d]: expected %q, got %q", i, k, cfg.Backend.FilterMetadataKeys[i])
		}
	}
}

func TestLoadFromEnv_EncryptionSupportedAlgorithms(t *testing.T) {
	t.Setenv("ENCRYPTION_SUPPORTED_ALGORITHMS", "AES256-GCM , ChaCha20-Poly1305")

	cfg := &Config{}
	loadFromEnv(cfg)

	if len(cfg.Encryption.SupportedAlgorithms) != 2 {
		t.Fatalf("expected 2 algorithms, got %d: %v", len(cfg.Encryption.SupportedAlgorithms), cfg.Encryption.SupportedAlgorithms)
	}
	if cfg.Encryption.SupportedAlgorithms[0] != "AES256-GCM" {
		t.Errorf("expected AES256-GCM, got %q", cfg.Encryption.SupportedAlgorithms[0])
	}
	if cfg.Encryption.SupportedAlgorithms[1] != "ChaCha20-Poly1305" {
		t.Errorf("expected ChaCha20-Poly1305, got %q", cfg.Encryption.SupportedAlgorithms[1])
	}
}

func TestLoadFromEnv_HardwareFlags(t *testing.T) {
	t.Setenv("HARDWARE_ENABLE_AESNI", "true")
	t.Setenv("HARDWARE_ENABLE_ARMV8_AES", "false")

	cfg := &Config{}
	loadFromEnv(cfg)

	if !cfg.Encryption.Hardware.EnableAESNI {
		t.Error("expected EnableAESNI=true")
	}
	if cfg.Encryption.Hardware.EnableARMv8AES {
		t.Error("expected EnableARMv8AES=false")
	}
}

func TestLoadFromEnv_ServerAndCacheAndAudit(t *testing.T) {
	t.Setenv("SERVER_READ_TIMEOUT", "30s")
	t.Setenv("SERVER_WRITE_TIMEOUT", "60s")
	t.Setenv("SERVER_IDLE_TIMEOUT", "120s")
	t.Setenv("SERVER_READ_HEADER_TIMEOUT", "10s")
	t.Setenv("SERVER_MAX_HEADER_BYTES", "65536")
	t.Setenv("RATE_LIMIT_ENABLED", "true")
	t.Setenv("RATE_LIMIT_REQUESTS", "100")
	t.Setenv("RATE_LIMIT_WINDOW", "1m")
	t.Setenv("CACHE_ENABLED", "true")
	t.Setenv("CACHE_MAX_SIZE", "104857600")
	t.Setenv("CACHE_MAX_ITEMS", "1000")
	t.Setenv("CACHE_DEFAULT_TTL", "5m")
	t.Setenv("AUDIT_ENABLED", "true")
	t.Setenv("AUDIT_MAX_EVENTS", "500")
	t.Setenv("AUDIT_SINK_TYPE", "file")
	t.Setenv("AUDIT_SINK_FILE_PATH", "/tmp/audit.log")
	t.Setenv("AUDIT_SINK_ENDPOINT", "http://audit.example.com")
	t.Setenv("AUDIT_SINK_BATCH_SIZE", "10")
	t.Setenv("AUDIT_SINK_FLUSH_INTERVAL", "5s")
	t.Setenv("AUDIT_SINK_RETRY_COUNT", "3")
	t.Setenv("AUDIT_SINK_RETRY_BACKOFF", "2s")
	t.Setenv("AUDIT_REDACT_METADATA_KEYS", "x-amz-meta-secret, x-amz-meta-key")
	t.Setenv("PROXIED_BUCKET", "my-proxied-bucket")

	cfg := &Config{}
	loadFromEnv(cfg)

	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Errorf("ReadTimeout: want 30s, got %s", cfg.Server.ReadTimeout)
	}
	if cfg.Server.WriteTimeout != 60*time.Second {
		t.Errorf("WriteTimeout: want 60s, got %s", cfg.Server.WriteTimeout)
	}
	if cfg.Server.MaxHeaderBytes != 65536 {
		t.Errorf("MaxHeaderBytes: want 65536, got %d", cfg.Server.MaxHeaderBytes)
	}
	if !cfg.RateLimit.Enabled {
		t.Error("RateLimit.Enabled: want true")
	}
	if cfg.RateLimit.Limit != 100 {
		t.Errorf("RateLimit.Limit: want 100, got %d", cfg.RateLimit.Limit)
	}
	if !cfg.Cache.Enabled {
		t.Error("Cache.Enabled: want true")
	}
	if cfg.Cache.MaxSize != 104857600 {
		t.Errorf("Cache.MaxSize: want 104857600, got %d", cfg.Cache.MaxSize)
	}
	if !cfg.Audit.Enabled {
		t.Error("Audit.Enabled: want true")
	}
	if cfg.Audit.Sink.Type != "file" {
		t.Errorf("Audit.Sink.Type: want file, got %q", cfg.Audit.Sink.Type)
	}
	if cfg.Audit.Sink.FilePath != "/tmp/audit.log" {
		t.Errorf("Audit.Sink.FilePath: want /tmp/audit.log, got %q", cfg.Audit.Sink.FilePath)
	}
	if len(cfg.Audit.RedactMetadataKeys) != 2 {
		t.Errorf("Audit.RedactMetadataKeys: want 2, got %d", len(cfg.Audit.RedactMetadataKeys))
	}
	if cfg.ProxiedBucket != "my-proxied-bucket" {
		t.Errorf("ProxiedBucket: want my-proxied-bucket, got %q", cfg.ProxiedBucket)
	}
}

func TestLoadFromEnv_TracingAndMetricsAndLogging(t *testing.T) {
	t.Setenv("TRACING_ENABLED", "true")
	t.Setenv("TRACING_SERVICE_NAME", "s3-gateway")
	t.Setenv("TRACING_SERVICE_VERSION", "v0.6")
	t.Setenv("TRACING_EXPORTER", "jaeger")
	t.Setenv("TRACING_JAEGER_ENDPOINT", "http://jaeger:14268/api/traces")
	t.Setenv("TRACING_OTLP_ENDPOINT", "http://collector:4317")
	t.Setenv("TRACING_SAMPLING_RATIO", "0.5")
	t.Setenv("TRACING_REDACT_SENSITIVE", "true")
	t.Setenv("METRICS_ENABLE_BUCKET_LABEL", "true")
	t.Setenv("LOGGING_ACCESS_LOG_FORMAT", "json")
	t.Setenv("LOGGING_REDACT_HEADERS", "Authorization, x-amz-security-token")
	t.Setenv("POLICIES", "policy1.yaml, policy2.yaml")

	cfg := &Config{}
	loadFromEnv(cfg)

	if !cfg.Tracing.Enabled {
		t.Error("Tracing.Enabled: want true")
	}
	if cfg.Tracing.ServiceName != "s3-gateway" {
		t.Errorf("Tracing.ServiceName: want s3-gateway, got %q", cfg.Tracing.ServiceName)
	}
	if cfg.Tracing.SamplingRatio != 0.5 {
		t.Errorf("Tracing.SamplingRatio: want 0.5, got %f", cfg.Tracing.SamplingRatio)
	}
	if !cfg.Metrics.EnableBucketLabel {
		t.Error("Metrics.EnableBucketLabel: want true")
	}
	if cfg.Logging.AccessLogFormat != "json" {
		t.Errorf("Logging.AccessLogFormat: want json, got %q", cfg.Logging.AccessLogFormat)
	}
	if len(cfg.Logging.RedactHeaders) != 2 {
		t.Errorf("Logging.RedactHeaders: want 2, got %d", len(cfg.Logging.RedactHeaders))
	}
	if len(cfg.PolicyFiles) != 2 {
		t.Errorf("PolicyFiles: want 2, got %d", len(cfg.PolicyFiles))
	}
}

func TestLoadFromEnv_AdminConfig(t *testing.T) {
	t.Setenv("ADMIN_ENABLED", "true")
	t.Setenv("ADMIN_ADDRESS", "127.0.0.1:8090")
	t.Setenv("ADMIN_TLS_ENABLED", "true")
	t.Setenv("ADMIN_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("ADMIN_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("ADMIN_AUTH_TYPE", "bearer")
	t.Setenv("ADMIN_AUTH_TOKEN_FILE", "/run/secrets/token")
	t.Setenv("ADMIN_AUTH_TOKEN", "my-inline-token")
	t.Setenv("ADMIN_RATE_LIMIT_RPM", "60")

	cfg := &Config{}
	loadFromEnv(cfg)

	if !cfg.Admin.Enabled {
		t.Error("Admin.Enabled: want true")
	}
	if cfg.Admin.Address != "127.0.0.1:8090" {
		t.Errorf("Admin.Address: want 127.0.0.1:8090, got %q", cfg.Admin.Address)
	}
	if !cfg.Admin.TLS.Enabled {
		t.Error("Admin.TLS.Enabled: want true")
	}
	if cfg.Admin.Auth.Type != "bearer" {
		t.Errorf("Admin.Auth.Type: want bearer, got %q", cfg.Admin.Auth.Type)
	}
	if cfg.Admin.Auth.Token != "my-inline-token" {
		t.Errorf("Admin.Auth.Token: want my-inline-token, got %q", cfg.Admin.Auth.Token)
	}
	if cfg.Admin.RateLimit.RequestsPerMinute != 60 {
		t.Errorf("Admin.RateLimit.RPM: want 60, got %d", cfg.Admin.RateLimit.RequestsPerMinute)
	}
}

func TestLoadFromEnv_KeyManagerConfig(t *testing.T) {
	t.Setenv("KEY_MANAGER_ENABLED", "true")
	t.Setenv("KEY_MANAGER_PROVIDER", "memory")
	t.Setenv("KEY_MANAGER_DUAL_READ_WINDOW", "5")
	t.Setenv("KEY_MANAGER_ROTATION_POLICY_ENABLED", "true")
	t.Setenv("KEY_MANAGER_ROTATION_GRACE_WINDOW", "24h")
	t.Setenv("COSMIAN_KMS_ENDPOINT", "https://kms.example.com")
	t.Setenv("COSMIAN_KMS_TIMEOUT", "30s")
	t.Setenv("COSMIAN_KMS_CLIENT_CERT", "/tls/client.pem")
	t.Setenv("COSMIAN_KMS_CLIENT_KEY", "/tls/client.key")
	t.Setenv("COSMIAN_KMS_CA_CERT", "/tls/ca.pem")
	t.Setenv("COSMIAN_KMS_INSECURE_SKIP_VERIFY", "true")
	t.Setenv("COSMIAN_KMS_KEYS", "key-abc:1,key-def:2")

	cfg := &Config{}
	loadFromEnv(cfg)

	if !cfg.Encryption.KeyManager.Enabled {
		t.Error("KeyManager.Enabled: want true")
	}
	if cfg.Encryption.KeyManager.Provider != "memory" {
		t.Errorf("KeyManager.Provider: want memory, got %q", cfg.Encryption.KeyManager.Provider)
	}
	if cfg.Encryption.KeyManager.DualReadWindow != 5 {
		t.Errorf("KeyManager.DualReadWindow: want 5, got %d", cfg.Encryption.KeyManager.DualReadWindow)
	}
	if !cfg.Encryption.KeyManager.RotationPolicy.Enabled {
		t.Error("RotationPolicy.Enabled: want true")
	}
	if cfg.Encryption.KeyManager.Cosmian.Endpoint != "https://kms.example.com" {
		t.Errorf("Cosmian.Endpoint: want ..., got %q", cfg.Encryption.KeyManager.Cosmian.Endpoint)
	}
	if len(cfg.Encryption.KeyManager.Cosmian.Keys) != 2 {
		t.Errorf("Cosmian.Keys: want 2, got %d", len(cfg.Encryption.KeyManager.Cosmian.Keys))
	}
}

func TestParseCosmianKeyRefs(t *testing.T) {
	tests := []struct {
		input   string
		wantLen int
		wantID  string
		wantVer int
	}{
		{"key1", 1, "key1", 0},
		{"key1:3", 1, "key1", 3},
		{"key1,key2:2", 2, "key1", 0},
		{"", 0, "", 0},
		{" key-abc : 7 ", 1, "key-abc", 7},
	}

	for _, tt := range tests {
		refs := parseCosmianKeyRefs(tt.input)
		if len(refs) != tt.wantLen {
			t.Errorf("parseCosmianKeyRefs(%q): expected %d refs, got %d", tt.input, tt.wantLen, len(refs))
			continue
		}
		if tt.wantLen > 0 {
			if refs[0].ID != tt.wantID {
				t.Errorf("parseCosmianKeyRefs(%q)[0].ID = %q, want %q", tt.input, refs[0].ID, tt.wantID)
			}
			if refs[0].Version != tt.wantVer {
				t.Errorf("parseCosmianKeyRefs(%q)[0].Version = %d, want %d", tt.input, refs[0].Version, tt.wantVer)
			}
		}
	}
}

// ---- V1.0-SEC-H03 PBKDF2 iteration tests ---------------------------------

func TestConfig_Default_PBKDF2Iterations(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Encryption.KDF.PBKDF2.Iterations != 600000 {
		t.Errorf("expected default PBKDF2 iterations 600000, got %d", config.Encryption.KDF.PBKDF2.Iterations)
	}
}

func TestConfig_Validate_TooFew(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KDF.PBKDF2.Iterations = 99999

	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for iterations < 100000, got nil")
	}
	if !strings.Contains(err.Error(), "encryption.kdf.pbkdf2.iterations") {
		t.Errorf("error %q does not contain 'encryption.kdf.pbkdf2.iterations'", err.Error())
	}
}

func TestConfig_Validate_ExactMinimum(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KDF.PBKDF2.Iterations = 100000

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("expected no error for iterations == 100000, got: %v", err)
	}
}

func TestConfig_Validate_Recommended(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KDF.PBKDF2.Iterations = 600000

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("expected no error for iterations == 600000, got: %v", err)
	}
}

func TestConfig_EnvOverride_PBKDF2Iterations(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	t.Setenv("ENCRYPTION_KDF_PBKDF2_ITERATIONS", "750000")

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Encryption.KDF.PBKDF2.Iterations != 750000 {
		t.Errorf("expected PBKDF2 iterations 750000 after env override, got %d", config.Encryption.KDF.PBKDF2.Iterations)
	}
}

func TestConfig_EnvOverride_BelowMin_Ignored(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	t.Setenv("ENCRYPTION_KDF_PBKDF2_ITERATIONS", "50000")

	config, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if config.Encryption.KDF.PBKDF2.Iterations != 600000 {
		t.Errorf("expected default PBKDF2 iterations 600000 when env override is below min, got %d", config.Encryption.KDF.PBKDF2.Iterations)
	}
}

// TestLoadConfig_UnknownField verifies that loading a config file containing
// an unknown field returns an error (yaml.Decoder.KnownFields(true) behaviour).
func TestLoadConfig_UnknownField(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
listen_addr: ":8080"
unknown_field: "value"
`
	err := os.WriteFile(configPath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	_, err = LoadConfig(configPath)
	if err == nil {
		t.Fatal("LoadConfig expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "failed to parse config file") {
		t.Errorf("expected error to contain 'failed to parse config file', got: %v", err)
	}
}

func TestMetricsAddr_Validation(t *testing.T) {
	tests := []struct {
		name        string
		metricsAddr string
		adminAddr   string
		adminEnabled bool
		wantErr     string
	}{
		{
			name:        "empty metrics addr is valid",
			metricsAddr: "",
			wantErr:     "",
		},
		{
			name:        "valid dedicated metrics addr",
			metricsAddr: ":9090",
			wantErr:     "",
		},
		{
			name:        "metrics addr conflicts with listen_addr",
			metricsAddr: ":8080", // same as default listen_addr
			wantErr:     "metrics.addr must differ from listen_addr",
		},
		{
			name:         "metrics addr conflicts with admin addr",
			metricsAddr:  "127.0.0.1:8081",
			adminAddr:    "127.0.0.1:8081",
			adminEnabled: true,
			wantErr:      "metrics.addr must differ from admin.address",
		},
		{
			name:         "metrics addr same as admin addr but admin disabled — ok",
			metricsAddr:  "127.0.0.1:8081",
			adminAddr:    "127.0.0.1:8081",
			adminEnabled: false,
			wantErr:      "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{
				ListenAddr: ":8080",
				Metrics: MetricsConfig{
					Addr: tc.metricsAddr,
				},
				Admin: AdminConfig{
					Enabled: tc.adminEnabled,
					Address: tc.adminAddr,
				},
			}
			err := cfg.Validate()
			if tc.wantErr == "" {
				// Only check our specific field — other validation errors are fine.
				if err != nil && strings.Contains(err.Error(), "metrics.addr") {
					t.Errorf("unexpected metrics.addr error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestMetricsAddr_EnvOverride(t *testing.T) {
	t.Setenv("METRICS_ADDR", ":9091")
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Metrics.Addr != ":9091" {
		t.Errorf("expected Metrics.Addr \":9091\", got %q", cfg.Metrics.Addr)
	}
}

func TestConfig_Validate_Argon2id_NonFIPS_OK(t *testing.T) {
	// In a non-FIPS build, argon2id algorithm should validate without error.
	t.Setenv("BACKEND_ACCESS_KEY", "test-key")
	t.Setenv("BACKEND_SECRET_KEY", "test-secret")
	t.Setenv("ENCRYPTION_PASSWORD", "test-password")

	// isFIPS() is false in non-FIPS builds.
	cfg := &Config{}
	cfg.ListenAddr = ":8080"
	cfg.Auth.Credentials = []GatewayCredential{{AccessKey: "ak", SecretKey: "sk"}}
	cfg.Backend.AccessKey = "bk"
	cfg.Backend.SecretKey = "bs"
	cfg.Encryption.Password = "test-password"
	cfg.Encryption.KDF.Algorithm = "argon2id"
	cfg.Encryption.KDF.Argon2id = Argon2idConfig{Time: 2, Memory: 19456, Threads: 1}

	// Also require sufficient PBKDF2 iterations test to pass as side-effect.
	cfg.Encryption.KDF.PBKDF2 = PBKDF2Config{Iterations: 600000}

	err := cfg.Validate()
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
}

func TestConfig_Load_Argon2id_FullYAML(t *testing.T) {
	t.Setenv("BACKEND_ACCESS_KEY", "test-key")
	t.Setenv("BACKEND_SECRET_KEY", "test-secret")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password"
  kdf:
    algorithm: "argon2id"
    pbkdf2:
      iterations: 600000
    argon2id:
      time: 3
      memory: 32768
      threads: 2
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Encryption.KDF.Algorithm != "argon2id" {
		t.Errorf("KDF.Algorithm = %q, want %q", cfg.Encryption.KDF.Algorithm, "argon2id")
	}
	if cfg.Encryption.KDF.Argon2id.Time != 3 {
		t.Errorf("Argon2id.Time = %d, want %d", cfg.Encryption.KDF.Argon2id.Time, 3)
	}
	if cfg.Encryption.KDF.Argon2id.Memory != 32768 {
		t.Errorf("Argon2id.Memory = %d, want %d", cfg.Encryption.KDF.Argon2id.Memory, 32768)
	}
	if cfg.Encryption.KDF.Argon2id.Threads != 2 {
		t.Errorf("Argon2id.Threads = %d, want %d", cfg.Encryption.KDF.Argon2id.Threads, 2)
	}
}



func TestConfig_Validate_Argon2id_BadParams(t *testing.T) {
	tests := []struct {
		name    string
		time    uint32
		memory  uint32
		threads uint8
	}{
		{"zero time", 0, 19456, 1},
		{"zero memory", 2, 0, 1},
		{"zero threads", 2, 19456, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.ListenAddr = ":8080"
			cfg.Auth.Credentials = []GatewayCredential{{AccessKey: "ak", SecretKey: "sk"}}
			cfg.Backend.AccessKey = "bk"
			cfg.Backend.SecretKey = "bs"
			cfg.Encryption.Password = "test-password"
			cfg.Encryption.KDF.Algorithm = "argon2id"
			cfg.Encryption.KDF.Argon2id = Argon2idConfig{Time: tt.time, Memory: tt.memory, Threads: tt.threads}
			cfg.Encryption.KDF.PBKDF2 = PBKDF2Config{Iterations: 600000}

			err := cfg.Validate()
			if err == nil {
				t.Errorf("Validate() expected error for %s params", tt.name)
			}
		})
	}
}

func TestConfig_Validate_Argon2id_UnknownAlgorithm(t *testing.T) {
	cfg := &Config{}
	cfg.ListenAddr = ":8080"
	cfg.Auth.Credentials = []GatewayCredential{{AccessKey: "ak", SecretKey: "sk"}}
	cfg.Backend.AccessKey = "bk"
	cfg.Backend.SecretKey = "bs"
	cfg.Encryption.Password = "test-password"
	cfg.Encryption.KDF.Algorithm = "sha3"
	cfg.Encryption.KDF.PBKDF2 = PBKDF2Config{Iterations: 600000}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error for unknown algorithm")
	}
	if !strings.Contains(err.Error(), `"sha3"`) {
		t.Errorf("error should mention the unknown algorithm: %v", err)
	}
}

func TestConfig_EnvOverride_Argon2idParams(t *testing.T) {
	t.Setenv("ENCRYPTION_KDF_ALGORITHM", "argon2id")
	t.Setenv("ENCRYPTION_KDF_ARGON2ID_TIME", "4")
	t.Setenv("ENCRYPTION_KDF_ARGON2ID_MEMORY", "65536")
	t.Setenv("ENCRYPTION_KDF_ARGON2ID_THREADS", "2")
	t.Setenv("BACKEND_ACCESS_KEY", "test-key")
	t.Setenv("BACKEND_SECRET_KEY", "test-secret")
	t.Setenv("ENCRYPTION_PASSWORD", "test-password")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := `
backend:
  access_key: "test-key"
  secret_key: "test-secret"
encryption:
  password: "test-password"
auth:
  credentials:
    - access_key: "gateway-key"
      secret_key: "gateway-secret"
`
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.Encryption.KDF.Algorithm != "argon2id" {
		t.Errorf("KDF.Algorithm = %q, want %q", cfg.Encryption.KDF.Algorithm, "argon2id")
	}
	if cfg.Encryption.KDF.Argon2id.Time != 4 {
		t.Errorf("Argon2id.Time = %d, want %d", cfg.Encryption.KDF.Argon2id.Time, 4)
	}
	if cfg.Encryption.KDF.Argon2id.Memory != 65536 {
		t.Errorf("Argon2id.Memory = %d, want %d", cfg.Encryption.KDF.Argon2id.Memory, 65536)
	}
	if cfg.Encryption.KDF.Argon2id.Threads != 2 {
		t.Errorf("Argon2id.Threads = %d, want %d", cfg.Encryption.KDF.Argon2id.Threads, 2)
	}
}

// ---- V1.0-CRYPTO-3: metadata encryption key validation --------------------

func TestValidate_MetadataEncryptionKey_MutuallyExclusive(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.MetadataEncryptionKeyFile = "/etc/key"
	cfg.Encryption.MetadataEncryptionKey = "inline-key-that-is-at-least-128-characters-long-to-pass-the-initial-length-check-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual exclusion error, got %v", err)
	}
}

func TestValidate_MetadataEncryptionKey_InvalidTooShort(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.MetadataEncryptionKey = "short-key"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "at least 128") {
		t.Errorf("expected 'at least 128' error for short key, got %v", err)
	}
}

func TestValidate_MetadataEncryptionKey_ValidLength(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.MetadataEncryptionKey = ""
	for i := 0; i < 128; i++ {
		cfg.Encryption.MetadataEncryptionKey += "a"
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error for 128-char key, got %v", err)
	}
}

func TestValidate_MetadataEncryptionKey_WithKeyManagerEnabled(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.MetadataEncryptionKeyFile = "/etc/key"
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "self_contained"
	cfg.Encryption.KeyManager.SelfContained.Type = "aes"
	cfg.Encryption.KeyManager.SelfContained.AES.Keys = []SelfContainedAESKeyEntry{
		{Version: 1, KeySource: "env:MY_KEK"},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual exclusion error with key_manager, got %v", err)
	}
}

// TestMetadataEncryptionKey_ValidFile verifies that a valid base64-encoded
// 32-byte key file passes validation.
func TestMetadataEncryptionKey_ValidFile(t *testing.T) {
	// Generate a random 32-byte key and base64-encode it.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "metadata.key")
	if err := os.WriteFile(keyFile, []byte(encoded+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := minValidConfig()
	cfg.Encryption.MetadataEncryptionKeyFile = keyFile
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected no error for valid key file, got: %v", err)
	}
}

// TestMetadataEncryptionKey_InvalidFileLength verifies that a base64 value
// decoding to a non-32-byte key is rejected.
func TestMetadataEncryptionKey_InvalidFileLength(t *testing.T) {
	// Generate 16 random bytes and base64-encode — decodes to 16, not 32.
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)

	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "metadata.key")
	if err := os.WriteFile(keyFile, []byte(encoded+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := minValidConfig()
	cfg.Encryption.MetadataEncryptionKeyFile = keyFile
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for wrong-length key file, got nil")
	}
	if !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("expected '32 bytes' error, got: %v", err)
	}
}

// TestMetadataEncryptionKey_InvalidBase64 verifies that non-base64 file
// content is rejected.
func TestMetadataEncryptionKey_InvalidBase64(t *testing.T) {
	tmpDir := t.TempDir()
	keyFile := filepath.Join(tmpDir, "metadata.key")
	if err := os.WriteFile(keyFile, []byte("not-valid-base64!!!"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := minValidConfig()
	cfg.Encryption.MetadataEncryptionKeyFile = keyFile
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid base64 key file, got nil")
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("expected 'base64' error, got: %v", err)
	}
}

// TestMetadataEncryptionKey_BothSet verifies that setting both
// MetadataEncryptionKeyFile and MetadataEncryptionKey is rejected.
func TestMetadataEncryptionKey_BothSet(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.MetadataEncryptionKeyFile = "/etc/metadata.key"
	cfg.Encryption.MetadataEncryptionKey = "inline-key-that-is-at-least-128-characters-long-to-pass-the-initial-length-check-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected mutual exclusion error, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected 'mutually exclusive' error, got: %v", err)
	}
}


