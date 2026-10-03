package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateCORSOriginPattern(t *testing.T) {
	for _, value := range []string{"*", "https://example.com", "https://example.com:8443", "http://*.example.com:8443", "https://*.example.com", "https://127.0.0.1", "https://[2001:db8::1]:8443"} {
		require.NoError(t, ValidateCORSOriginPattern(value), value)
	}
	for _, value := range []string{"", "null", "NULL", "https://example.com/path", "https://example.com?x", "ftp://example.com", "https://a*b*c.example", "https://example.com\r\nX: y", "https://host]", "https://ho\"st", "https://ho<st", "https://ho>st", "https://:8443", "https://host:", "https://host:0", "https://host:65536", "https://2001:db8::1", "https://[not-ip]", "https://[2001:db8::1]extra", "https://bad_host", "https://-bad.example", "https://bad-.example", "https://example..com"} {
		require.Error(t, ValidateCORSOriginPattern(value), value)
	}
}

func TestValidateCORSHeaderPattern(t *testing.T) {
	for _, value := range []string{"content-type", "x-amz-*", "*", "x-*-bad"} {
		require.NoError(t, ValidateCORSHeaderPattern(value), value)
	}
	for _, value := range []string{"", "bad header", "x-**", "x-name\r\n"} {
		require.Error(t, ValidateCORSHeaderPattern(value), value)
	}
}

func TestValidateCORSFieldName(t *testing.T) {
	for _, value := range []string{"ETag", "x-amz-id-2"} {
		require.NoError(t, ValidateCORSFieldName(value), value)
	}
	for _, value := range []string{"", "x-*", "bad header", "x\nname"} {
		require.Error(t, ValidateCORSFieldName(value), value)
	}
}

func TestLoadConfig_CORSModeAndFallback(t *testing.T) {
	t.Setenv("CORS_MODE", "gateway")
	t.Setenv("CORS_FALLBACK_ALLOWED_ORIGINS", `["https://yaml.example","https://env.example"]`)
	t.Setenv("CORS_FALLBACK_ALLOWED_METHODS", `["GET","PUT"]`)
	t.Setenv("CORS_FALLBACK_ALLOWED_HEADERS", `["content-type","x-amz-*"]`)
	t.Setenv("CORS_FALLBACK_EXPOSE_HEADERS", `["ETag"]`)
	t.Setenv("CORS_FALLBACK_MAX_AGE_SECONDS", "3600")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "true")
	t.Setenv("VALKEY_ADDR", "valkey:6379")
	t.Setenv("BACKEND_ACCESS_KEY", "test-key")
	t.Setenv("BACKEND_SECRET_KEY", "test-secret")
	t.Setenv("ENCRYPTION_PASSWORD", "test-password")
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := []byte("auth:\n  credentials:\n    - access_key: gateway\n      secret_key: gateway-secret\ncors:\n  mode: passthrough\n  fallback:\n    allowed_origins: [\"https://yaml.example\"]\n    allowed_methods: [GET]\n")
	require.NoError(t, os.WriteFile(path, data, 0600))
	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	require.Equal(t, "gateway", cfg.CORS.Mode)
	require.True(t, cfg.CORS.AllowCredentials)
	require.Equal(t, []string{"https://yaml.example", "https://env.example"}, cfg.CORS.Fallback.AllowedOrigins)
	require.Equal(t, []string{"GET", "PUT"}, cfg.CORS.Fallback.AllowedMethods)
	require.Equal(t, []string{"content-type", "x-amz-*"}, cfg.CORS.Fallback.AllowedHeaders)
	require.Equal(t, []string{"ETag"}, cfg.CORS.Fallback.ExposeHeaders)
	require.Equal(t, 3600, cfg.CORS.Fallback.MaxAgeSeconds)
}

func TestLoadConfig_CORSRejectsInvalidEnv(t *testing.T) {
	cases := []struct{ name, value string }{
		{"mode", "invalid"}, {"bool", "perhaps"}, {"array", `GET,PUT`}, {"age", "1.2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Start with a valid baseline so the named invalid environment
			// setting, not unrelated config validation, is the failure source.
			t.Setenv("CORS_MODE", "passthrough")
			t.Setenv("CORS_ALLOW_CREDENTIALS", "false")
			t.Setenv("CORS_FALLBACK_ALLOWED_ORIGINS", "[]")
			t.Setenv("CORS_FALLBACK_ALLOWED_METHODS", "[]")
			t.Setenv("CORS_FALLBACK_ALLOWED_HEADERS", "[]")
			t.Setenv("CORS_FALLBACK_EXPOSE_HEADERS", "[]")
			t.Setenv("CORS_FALLBACK_MAX_AGE_SECONDS", "0")
			name := map[string]string{"mode": "CORS_MODE", "bool": "CORS_ALLOW_CREDENTIALS", "array": "CORS_FALLBACK_ALLOWED_ORIGINS", "age": "CORS_FALLBACK_MAX_AGE_SECONDS"}[tc.name]
			t.Setenv(name, tc.value)
			_, err := LoadConfig("")
			require.Error(t, err)
			switch tc.name {
			case "mode":
				require.ErrorContains(t, err, "cors.mode")
			case "bool":
				require.ErrorContains(t, err, "CORS_ALLOW_CREDENTIALS")
			case "array":
				require.ErrorContains(t, err, "CORS_FALLBACK_ALLOWED_ORIGINS")
			case "age":
				require.ErrorContains(t, err, "CORS_FALLBACK_MAX_AGE_SECONDS")
			}
		})
	}
	for _, value := range []string{"+1", "-1", " 1", "1x"} {
		t.Setenv("CORS_MODE", "passthrough")
		t.Setenv("CORS_ALLOW_CREDENTIALS", "false")
		t.Setenv("CORS_FALLBACK_ALLOWED_ORIGINS", "[]")
		t.Setenv("CORS_FALLBACK_ALLOWED_METHODS", "[]")
		t.Setenv("CORS_FALLBACK_ALLOWED_HEADERS", "[]")
		t.Setenv("CORS_FALLBACK_EXPOSE_HEADERS", "[]")
		t.Setenv("CORS_FALLBACK_MAX_AGE_SECONDS", value)
		_, err := LoadConfig("")
		require.ErrorContains(t, err, "CORS_FALLBACK_MAX_AGE_SECONDS")
	}
	t.Setenv("CORS_MODE", "passthrough")
	t.Setenv("CORS_ALLOW_CREDENTIALS", "false")
	t.Setenv("CORS_FALLBACK_ALLOWED_ORIGINS", "[]")
	t.Setenv("CORS_FALLBACK_ALLOWED_METHODS", "[]")
	t.Setenv("CORS_FALLBACK_ALLOWED_HEADERS", "[]")
	t.Setenv("CORS_FALLBACK_EXPOSE_HEADERS", "[]")
	t.Setenv("CORS_FALLBACK_MAX_AGE_SECONDS", "0")
	t.Setenv("BACKEND_ACCESS_KEY", "test-key")
	t.Setenv("BACKEND_SECRET_KEY", "test-secret")
	t.Setenv("ENCRYPTION_PASSWORD", "test-password")
	t.Setenv("GW_CRED_0_ACCESS_KEY", "gateway")
	t.Setenv("GW_CRED_0_SECRET_KEY", "gateway-secret")
	_, err := LoadConfig("")
	require.NoError(t, err, "valid environment baseline must load")
}

func TestConfigValidate_CORSRequiresValkey(t *testing.T) {
	cfg := &Config{ListenAddr: ":8080", CORS: CORSConfig{Mode: "gateway"}}
	require.ErrorContains(t, cfg.Validate(), "requires multipart_state.valkey.addr")
}

func TestConfigValidate_CORSFallback(t *testing.T) {
	tests := []struct {
		name string
		cfg  CORSConfig
		bad  bool
	}{
		{"valid", CORSConfig{Mode: "gateway", Fallback: CORSFallbackConfig{AllowedOrigins: []string{"https://example.com"}, AllowedMethods: []string{"GET"}}}, false},
		{"partial", CORSConfig{Mode: "gateway", Fallback: CORSFallbackConfig{AllowedOrigins: []string{"https://example.com"}}}, true},
		{"bad-origin", CORSConfig{Mode: "gateway", Fallback: CORSFallbackConfig{AllowedOrigins: []string{"null"}, AllowedMethods: []string{"GET"}}}, true},
		{"malformed-authority", CORSConfig{Mode: "gateway", Fallback: CORSFallbackConfig{AllowedOrigins: []string{"https://host]"}, AllowedMethods: []string{"GET"}}}, true},
		{"empty-host", CORSConfig{Mode: "gateway", Fallback: CORSFallbackConfig{AllowedOrigins: []string{"https://:8443"}, AllowedMethods: []string{"GET"}}}, true},
		{"bad-method", CORSConfig{Mode: "gateway", Fallback: CORSFallbackConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"OPTIONS"}}}, true},
		{"passthrough-credentials", CORSConfig{AllowCredentials: true}, true},
		{"negative-age", CORSConfig{Mode: "gateway", Fallback: CORSFallbackConfig{MaxAgeSeconds: -1}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate(true)
			if tc.bad {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	for _, origin := range []string{"https://host]", "https://ho\"st", "https://ho<st", "https://ho>st", "https://:8443"} {
		t.Run("malformed-fallback-origin-"+origin, func(t *testing.T) {
			cfg := CORSConfig{Mode: "gateway", Fallback: CORSFallbackConfig{AllowedOrigins: []string{origin}, AllowedMethods: []string{"GET"}}}
			require.Error(t, cfg.Validate(true), origin)
		})
	}
}
