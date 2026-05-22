package api

import (
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

func TestStaticCredentialStore_Lookup_Known(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Label: "primary"},
	}
	store, err := NewStaticCredentialStore(creds)
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	secret, label, err := store.Lookup("AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("Lookup error = %v", err)
	}
	if secret != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
		t.Errorf("secret = %q, want %q", secret, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
	}
	if label != "primary" {
		t.Errorf("label = %q, want %q", label, "primary")
	}
}

func TestStaticCredentialStore_Lookup_Unknown(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "secret", Label: "primary"},
	}
	store, err := NewStaticCredentialStore(creds)
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	_, _, err = store.Lookup("UNKNOWNKEY")
	if err != ErrUnknownAccessKey {
		t.Fatalf("Lookup error = %v, want ErrUnknownAccessKey", err)
	}
}

func TestStaticCredentialStore_EmptyStore(t *testing.T) {
	_, err := NewStaticCredentialStore(nil)
	if err == nil {
		t.Fatal("expected error for empty credential list")
	}
	_, err = NewStaticCredentialStore([]config.GatewayCredential{})
	if err == nil {
		t.Fatal("expected error for empty credential list")
	}
}

func TestStaticCredentialStore_MissingAccessKey(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "", SecretKey: "secret"},
	}
	_, err := NewStaticCredentialStore(creds)
	if err == nil {
		t.Fatal("expected error for missing access key")
	}
}

func TestStaticCredentialStore_MissingSecretKey(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: ""},
	}
	_, err := NewStaticCredentialStore(creds)
	if err == nil {
		t.Fatal("expected error for missing secret key")
	}
}

func TestStaticCredentialStore_MultipleCredentials(t *testing.T) {
	creds := []config.GatewayCredential{
		{AccessKey: "key1", SecretKey: "secret1", Label: "first"},
		{AccessKey: "key2", SecretKey: "secret2", Label: "second"},
	}
	store, err := NewStaticCredentialStore(creds)
	if err != nil {
		t.Fatalf("NewStaticCredentialStore error = %v", err)
	}
	secret, label, err := store.Lookup("key2")
	if err != nil {
		t.Fatalf("Lookup error = %v", err)
	}
	if secret != "secret2" {
		t.Errorf("secret = %q, want %q", secret, "secret2")
	}
	if label != "second" {
		t.Errorf("label = %q, want %q", label, "second")
	}
}
