package api

import (
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

func TestBuildOpenBaoOptions_ProviderReflectsConfiguredName(t *testing.T) {
	cases := map[string]string{
		"openbao":         "openbao-transit",
		"openbao-transit": "openbao-transit",
		"vault":           "vault-transit",
		"vault-transit":   "vault-transit",
	}
	for providerName, wantProvider := range cases {
		cfg := &config.KeyManagerConfig{
			OpenBao: config.OpenBaoConfig{
				Address: "https://bao.internal:8200",
				KeyName: "s3gw-dek",
				Auth:    config.OpenBaoAuthConfig{Method: "token", Token: "x"},
			},
		}
		opts, err := buildOpenBaoOptions(cfg, providerName)
		if err != nil {
			t.Fatalf("buildOpenBaoOptions(%q): %v", providerName, err)
		}
		if opts.Provider != wantProvider {
			t.Errorf("provider %q -> Provider()=%q, want %q", providerName, opts.Provider, wantProvider)
		}
	}
}

func TestBuildOpenBaoOptions_ResolvesSecretSources(t *testing.T) {
	t.Setenv("TEST_BAO_TOKEN", "tok-from-env")
	t.Setenv("TEST_BAO_SID", "sid-from-env")
	cfg := &config.KeyManagerConfig{
		OpenBao: config.OpenBaoConfig{
			Address: "https://bao.internal:8200",
			KeyName: "s3gw-dek",
			Auth: config.OpenBaoAuthConfig{
				Method:         "approle",
				RoleID:         "rid",
				SecretIDSource: "env:TEST_BAO_SID",
				TokenSource:    "env:TEST_BAO_TOKEN",
			},
		},
	}
	opts, err := buildOpenBaoOptions(cfg, "openbao")
	if err != nil {
		t.Fatal(err)
	}
	if opts.Auth.SecretID != "sid-from-env" {
		t.Errorf("SecretID not resolved from env: got %q", opts.Auth.SecretID)
	}
	if opts.Auth.Token != "tok-from-env" {
		t.Errorf("Token not resolved from env: got %q", opts.Auth.Token)
	}
}
