package harness

import (
	"bytes"
	"io"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func TestGH353HarnessConfiguredProviderProfile(t *testing.T) {
	for _, tc := range []struct {
		provider string
		compact  bool
	}{{"", false}, {"unknown", false}, {"minio", true}, {"min.io", true}, {"b2", true}} {
		cfg := &config.Config{Backend: config.BackendConfig{Provider: tc.provider}}
		engine, err := crypto.NewEngineWithOpts([]byte("provider-config-password"), backendProviderOption(cfg), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
		if err != nil {
			t.Fatal(err)
		}
		_, meta, err := engine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "b", Key: "k"}, bytes.NewReader([]byte("x")), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, compact := meta["x-amz-meta-a"]
		if compact != tc.compact {
			t.Fatalf("provider %q compact=%v", tc.provider, compact)
		}
		_ = engine.(io.Closer).Close()
	}
}

func TestGH353HarnessCompactOptionAndMutators(t *testing.T) {
	cfg := &config.Config{Backend: config.BackendConfig{Provider: "backblaze-b2", Endpoint: "https://example.invalid", AccessKey: "fixture"}}
	o := newOptions()
	WithConfigMutator(func(c *config.Config) { c.Backend.MetadataProfile = "compact" })(o)
	WithConfigMutator(func(c *config.Config) { c.Backend.PostInlineTagging = "unsupported" })(o)
	o.extraConfig(cfg)
	if cfg.Backend.Provider != "backblaze-b2" || cfg.Backend.Endpoint != "https://example.invalid" || cfg.Backend.AccessKey != "fixture" || cfg.Backend.MetadataProfile != "compact" || cfg.Backend.PostInlineTagging != "unsupported" {
		t.Fatal("fixture configuration lost identity or mutator")
	}
	engine, err := crypto.NewEngineWithOpts([]byte("provider-config-password"), backendProviderOption(cfg), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	if err != nil {
		t.Fatal(err)
	}
	_, meta, err := engine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "b", Key: "k"}, bytes.NewReader([]byte("x")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := meta["x-amz-meta-a"]; !ok {
		t.Fatal("compact setting not applied")
	}
	_ = engine.(io.Closer).Close()
	cfg.Backend.MetadataProfile = "invalid"
	if _, err := crypto.NewEngineWithOpts([]byte("provider-config-password"), backendProviderOption(cfg)); err == nil {
		t.Fatal("invalid profile accepted")
	}
}
