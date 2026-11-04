package main

import (
	"bytes"
	"io"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func TestGH353ConfiguredProviderProfile(t *testing.T) {
	for _, tc := range []struct {
		provider string
		compact  bool
	}{{"", false}, {"unknown", false}, {"minio", true}, {"AMAZON", true}, {"b2", true}} {
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

func TestGH353ServerCompactAndReloadSettings(t *testing.T) {
	cfg := &config.Config{Backend: config.BackendConfig{Provider: "backblaze-b2", MetadataProfile: "compact"}}
	engine, err := crypto.NewEngineWithOpts([]byte("provider-config-password"), backendProviderOption(cfg), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	if err != nil {
		t.Fatal(err)
	}
	_, meta, err := engine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "b", Key: "k"}, bytes.NewReader([]byte("x")), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := meta["x-amz-meta-a"]; !ok {
		t.Fatal("server did not apply compact profile")
	}
	_ = engine.(io.Closer).Close()
	for _, backend := range []config.BackendConfig{{MetadataProfile: "compact"}, {PostInlineTagging: "unsupported"}, {MetadataProfile: "invalid"}} {
		old, next := &config.Config{}, &config.Config{Backend: backend}
		applier := NewConfigChangeApplier(nil, nil, nil, nil, nil, old, nil, nil)
		if err := applier.ApplyConfigChanges(old, next); err == nil {
			t.Fatal("direct reload accepted construction setting")
		}
		if old.Backend.MetadataProfile != "" || old.Backend.PostInlineTagging != "" {
			t.Fatal("reload mutated old config")
		}
	}
}
