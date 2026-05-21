package api

import (
	"fmt"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
)

// CredentialStore is a read-only lookup of gateway-managed credentials.
// Implementations must be safe for concurrent use.
type CredentialStore interface {
	// Lookup returns the secret key for the given access key, or
	// ErrUnknownAccessKey if the key is not registered.
	Lookup(accessKey string) (secretKey string, label string, err error)
}

// StaticCredentialStore is an in-memory credential store loaded at startup.
type StaticCredentialStore struct {
	m map[string]credentialEntry
}

type credentialEntry struct {
	secretKey string
	label     string
}

// NewStaticCredentialStore creates a credential store from the provided credentials.
// It returns an error if the credential list is empty or if any entry is missing
// an access key or secret key.
func NewStaticCredentialStore(creds []config.GatewayCredential) (*StaticCredentialStore, error) {
	if len(creds) == 0 {
		return nil, fmt.Errorf("credential store requires at least one credential")
	}
	m := make(map[string]credentialEntry, len(creds))
	for _, c := range creds {
		if c.AccessKey == "" || c.SecretKey == "" {
			return nil, fmt.Errorf("credential entry is missing access key or secret key")
		}
		m[c.AccessKey] = credentialEntry{secretKey: c.SecretKey, label: c.Label}
	}
	return &StaticCredentialStore{m: m}, nil
}

// Lookup returns the secret key and label for the given access key.
func (s *StaticCredentialStore) Lookup(accessKey string) (string, string, error) {
	entry, ok := s.m[accessKey]
	if !ok {
		return "", "", ErrUnknownAccessKey
	}
	return entry.secretKey, entry.label, nil
}
