package config

import (
	"strings"
	"testing"
)

func TestValidate_KeyManagerOpenBao_TokenValid(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "openbao"
	cfg.Encryption.KeyManager.OpenBao.Address = "https://bao.internal:8200"
	cfg.Encryption.KeyManager.OpenBao.KeyName = "s3gw-dek"
	cfg.Encryption.KeyManager.OpenBao.Auth.Method = "token"
	cfg.Encryption.KeyManager.OpenBao.Auth.TokenSource = "env:OPENBAO_TOKEN"
	if err := cfg.Validate(); err != nil {
		t.Errorf("token auth should pass validation, got %v", err)
	}
}

func TestValidate_KeyManagerOpenBao_MissingAddress(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "vault-transit" // alias still hits the same block
	cfg.Encryption.KeyManager.OpenBao.KeyName = "s3gw-dek"
	cfg.Encryption.KeyManager.OpenBao.Auth.Token = "x"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "address") {
		t.Errorf("expected address error, got %v", err)
	}
}

func TestValidate_KeyManagerOpenBao_MissingKeyName(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "openbao-transit"
	cfg.Encryption.KeyManager.OpenBao.Address = "https://bao.internal:8200"
	cfg.Encryption.KeyManager.OpenBao.Auth.Token = "x"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "key_name") {
		t.Errorf("expected key_name error, got %v", err)
	}
}

func TestValidate_KeyManagerOpenBao_TokenMissing(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "openbao"
	cfg.Encryption.KeyManager.OpenBao.Address = "https://bao.internal:8200"
	cfg.Encryption.KeyManager.OpenBao.KeyName = "s3gw-dek"
	cfg.Encryption.KeyManager.OpenBao.Auth.Method = "token"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "token") {
		t.Errorf("expected token error, got %v", err)
	}
}

func TestValidate_KeyManagerOpenBao_AppRoleMissingRoleID(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "openbao"
	cfg.Encryption.KeyManager.OpenBao.Address = "https://bao.internal:8200"
	cfg.Encryption.KeyManager.OpenBao.KeyName = "s3gw-dek"
	cfg.Encryption.KeyManager.OpenBao.Auth.Method = "approle"
	cfg.Encryption.KeyManager.OpenBao.Auth.SecretID = "sid"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "role_id") {
		t.Errorf("expected role_id error, got %v", err)
	}
}

func TestValidate_KeyManagerOpenBao_KubernetesMissingRole(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "openbao"
	cfg.Encryption.KeyManager.OpenBao.Address = "https://bao.internal:8200"
	cfg.Encryption.KeyManager.OpenBao.KeyName = "s3gw-dek"
	cfg.Encryption.KeyManager.OpenBao.Auth.Method = "kubernetes"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "role") {
		t.Errorf("expected role error, got %v", err)
	}
}

func TestValidate_KeyManagerOpenBao_UnknownAuthMethod(t *testing.T) {
	cfg := minValidConfig()
	cfg.Encryption.KeyManager.Enabled = true
	cfg.Encryption.KeyManager.Provider = "openbao"
	cfg.Encryption.KeyManager.OpenBao.Address = "https://bao.internal:8200"
	cfg.Encryption.KeyManager.OpenBao.KeyName = "s3gw-dek"
	cfg.Encryption.KeyManager.OpenBao.Auth.Method = "ldap"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "method") {
		t.Errorf("expected auth.method error, got %v", err)
	}
}

func TestLoadFromEnv_OpenBao(t *testing.T) {
	t.Setenv("OPENBAO_ADDR", "https://bao.env:8200")
	t.Setenv("OPENBAO_TRANSIT_KEY_NAME", "env-key")
	t.Setenv("OPENBAO_AUTH_METHOD", "approle")
	t.Setenv("OPENBAO_ROLE_ID", "rid-env")

	cfg := &Config{}
	loadFromEnv(cfg)

	ob := cfg.Encryption.KeyManager.OpenBao
	if ob.Address != "https://bao.env:8200" {
		t.Errorf("Address: got %q", ob.Address)
	}
	if ob.KeyName != "env-key" {
		t.Errorf("KeyName: got %q", ob.KeyName)
	}
	if ob.Auth.Method != "approle" {
		t.Errorf("Auth.Method: got %q", ob.Auth.Method)
	}
	if ob.Auth.RoleID != "rid-env" {
		t.Errorf("Auth.RoleID: got %q", ob.Auth.RoleID)
	}
}
