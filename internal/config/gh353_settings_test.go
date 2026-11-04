package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestGH353BackendSettingsConfigEnvAndReload(t *testing.T) {
	var c Config
	if err := yaml.Unmarshal([]byte("backend:\n  metadata_profile: compact\n  post_inline_tagging: unsupported\n"), &c); err != nil {
		t.Fatal(err)
	}
	if c.Backend.MetadataProfile != "compact" || c.Backend.PostInlineTagging != "unsupported" {
		t.Fatal("YAML settings missing")
	}
	t.Setenv("BACKEND_METADATA_PROFILE", "auto")
	t.Setenv("BACKEND_POST_INLINE_TAGGING", "supported")
	if err := loadFromEnv(&c); err != nil {
		t.Fatal(err)
	}
	if c.Backend.MetadataProfile != "auto" || c.Backend.PostInlineTagging != "supported" {
		t.Fatal("environment did not override YAML")
	}
	t.Setenv("BACKEND_METADATA_PROFILE", "")
	t.Setenv("BACKEND_POST_INLINE_TAGGING", "")
	if err := loadFromEnv(&c); err != nil {
		t.Fatal(err)
	}
	if c.Backend.MetadataProfile != "" || c.Backend.PostInlineTagging != "" {
		t.Fatal("empty environment failed to reset")
	}
	for _, backend := range []BackendConfig{{MetadataProfile: "invalid"}, {PostInlineTagging: "invalid"}, {MetadataProfile: "COMPACT"}, {PostInlineTagging: "SUPPORTED"}} {
		if backend.ValidatePostSettings() == nil || (&Config{Backend: backend}).Validate() == nil {
			t.Fatal("invalid setting accepted")
		}
		if ValidateConstructionTimeReload(&Config{}, &Config{Backend: backend}) == nil {
			t.Fatal("invalid reload accepted")
		}
	}
	r := &ConfigReloader{}
	for _, backend := range []BackendConfig{{MetadataProfile: "compact"}, {PostInlineTagging: "unsupported"}} {
		old, next := &Config{}, &Config{Backend: backend}
		if ValidateConstructionTimeReload(old, next) == nil || r.validateReloadSafety(old, next) == nil {
			t.Fatal("construction setting reload accepted")
		}
		if old.Backend.MetadataProfile != "" || old.Backend.PostInlineTagging != "" {
			t.Fatal("old config mutated")
		}
	}
}

func TestGH353BackendSettingsStrictYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("backend:\n  metadata_profile_typo: compact\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("unknown YAML setting accepted")
	}
}

func TestGH353BackendSettingsLoadConfig(t *testing.T) {
	t.Setenv("BACKEND_ACCESS_KEY", "fixture-key")
	t.Setenv("BACKEND_SECRET_KEY", "fixture-secret")
	t.Setenv("ENCRYPTION_PASSWORD", "fixture-password")
	path := filepath.Join(t.TempDir(), "config.yaml")
	data := "auth:\n  credentials:\n    - access_key: gateway\n      secret_key: gateway-secret\nbackend:\n  metadata_profile: compact\n  post_inline_tagging: unsupported\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	// Unset variables so the YAML values, rather than explicit empty resets, win.
	for _, name := range []string{"BACKEND_METADATA_PROFILE", "BACKEND_POST_INLINE_TAGGING"} {
		value, ok := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if ok {
				_ = os.Setenv(name, value)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
	cfg, err := LoadConfig(path)
	if err != nil || cfg.Backend.MetadataProfile != "compact" || cfg.Backend.PostInlineTagging != "unsupported" {
		t.Fatalf("YAML load failed: %v", err)
	}
	t.Setenv("BACKEND_METADATA_PROFILE", "")
	t.Setenv("BACKEND_POST_INLINE_TAGGING", "")
	cfg, err = LoadConfig(path)
	if err != nil || cfg.Backend.MetadataProfile != "" || cfg.Backend.PostInlineTagging != "" {
		t.Fatalf("empty reset failed: %v", err)
	}
	t.Setenv("BACKEND_METADATA_PROFILE", "bad")
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("invalid environment profile accepted")
	}
	t.Setenv("BACKEND_METADATA_PROFILE", "auto")
	t.Setenv("BACKEND_POST_INLINE_TAGGING", "bad")
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("invalid environment tagging accepted")
	}
}
