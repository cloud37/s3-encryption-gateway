package crypto

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

func init() {
	Register("self_contained", selfContainedFactory)
}

// selfContainedFactory builds a self-contained KeyManager from a configuration map.
// Recognised keys:
//   - "type" string: "aes" or "rsa" (required)
//   - "provider" string: override Provider() name
//   - "keys" []map[string]any: AES key entries (for type "aes")
//   - "active_version" int: wrapping version for AES (default: highest)
//   - "private_key_source" string: PEM source for RSA (for type "rsa")
//   - "key_version" int: version for RSA (default: 1)
func selfContainedFactory(_ context.Context, cfg map[string]any) (KeyManager, error) {
	typeVal, ok := cfg["type"].(string)
	if !ok || typeVal == "" {
		return nil, fmt.Errorf("keymanager/self-contained: \"type\" field is required (must be \"aes\" or \"rsa\")")
	}

	switch strings.ToLower(typeVal) {
	case "aes":
		return newAESKEKManagerFromConfig(cfg)
	case "rsa":
		return newRSAKEKManagerFromConfig(cfg)
	default:
		return nil, fmt.Errorf("keymanager/self-contained: unknown type %q (must be \"aes\" or \"rsa\")", typeVal)
	}
}

// newAESKEKManagerFromConfig builds an AESKEKManager from a configuration map.
func newAESKEKManagerFromConfig(cfg map[string]any) (KeyManager, error) {
	var opts []AESKEKOption
	if p, ok := cfg["provider"].(string); ok && p != "" {
		opts = append(opts, WithAESProvider(p))
	}

	keysRaw, ok := cfg["keys"].([]any)
	if !ok || len(keysRaw) == 0 {
		return nil, fmt.Errorf("keymanager/self-contained/aes: \"keys\" is required and must be a non-empty list")
	}

	keys := make(map[int][]byte)
	for i, raw := range keysRaw {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("keymanager/self-contained/aes: keys[%d] is not a map", i)
		}

		version, err := parseIntEntry(entry, "version")
		if err != nil {
			return nil, fmt.Errorf("keymanager/self-contained/aes: keys[%d].version: %w", i, err)
		}
		if version < 1 {
			return nil, fmt.Errorf("keymanager/self-contained/aes: keys[%d].version must be positive", i)
		}

		keySource, ok := entry["key_source"].(string)
		if !ok || keySource == "" {
			return nil, fmt.Errorf("keymanager/self-contained/aes: keys[%d].key_source is required", i)
		}

		material, err := resolveSelfContainedAESKey(keySource)
		if err != nil {
			return nil, fmt.Errorf("keymanager/self-contained/aes: keys[%d]: %w", i, err)
		}

		if _, exists := keys[version]; exists {
			return nil, fmt.Errorf("keymanager/self-contained/aes: duplicate version %d in keys", version)
		}
		keys[version] = material
	}

	activeVersion := 0
	if av, err := parseIntEntry(cfg, "active_version"); err == nil {
		activeVersion = av
	}
	if activeVersion < 1 {
		activeVersion = 0
		for v := range keys {
			if v > activeVersion {
				activeVersion = v
			}
		}
	}

	return NewAESKEKManager(keys, activeVersion, opts...)
}

// newRSAKEKManagerFromConfig builds an RSAKEKManager from a configuration map.
func newRSAKEKManagerFromConfig(cfg map[string]any) (KeyManager, error) {
	var opts []RSAKEKOption
	if p, ok := cfg["provider"].(string); ok && p != "" {
		opts = append(opts, WithRSAProvider(p))
	}

	privateKeySource, ok := cfg["private_key_source"].(string)
	if !ok || privateKeySource == "" {
		return nil, fmt.Errorf("keymanager/self-contained/rsa: \"private_key_source\" is required")
	}

	privateKey, err := resolveSelfContainedRSAKey(privateKeySource)
	if err != nil {
		return nil, fmt.Errorf("keymanager/self-contained/rsa: %w", err)
	}

	keyVersion := 1
	if kv, err := parseIntEntry(cfg, "key_version"); err == nil {
		keyVersion = kv
	}

	return NewRSAKEKManager(privateKey, keyVersion, opts...)
}

// resolveSelfContainedAESKey resolves an AES KEK source reference into raw bytes.
// Supported formats:
//   - "env:VAR"     — base64-decode the environment variable VAR
//   - "base64:DATA" — decode the literal base64 string
//   - "file:PATH"   — read file at PATH, base64-decode contents
//   - raw bytes     — treated as literal bytes (must be 32 bytes)
func resolveSelfContainedAESKey(src string) ([]byte, error) {
	switch {
	case strings.HasPrefix(src, "env:"):
		name := strings.TrimPrefix(src, "env:")
		val := os.Getenv(name)
		if val == "" {
			return nil, fmt.Errorf("environment variable %q is empty or unset", name)
		}
		return base64.StdEncoding.DecodeString(strings.TrimSpace(val))
	case strings.HasPrefix(src, "base64:"):
		data := strings.TrimPrefix(src, "base64:")
		return base64.StdEncoding.DecodeString(strings.TrimSpace(data))
	case strings.HasPrefix(src, "file:"):
		path := strings.TrimPrefix(src, "file:")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read key file %q: %w", path, err)
		}
		trimmed := strings.TrimSpace(string(data))
		if trimmed == "" {
			return nil, fmt.Errorf("key file %q is empty", path)
		}
		return base64.StdEncoding.DecodeString(trimmed)
	default:
		// Treat as raw bytes
		raw := []byte(src)
		if len(raw) != 32 {
			return nil, fmt.Errorf("invalid key material: must be 32 bytes (got %d bytes); use \"env:VAR\", \"base64:DATA\", or \"file:PATH\"", len(raw))
		}
		return raw, nil
	}
}

// resolveSelfContainedRSAKey resolves an RSA private key source reference.
// Supported formats:
//   - "env:VAR"     — PEM-encoded private key from environment variable VAR
//   - "file:PATH"   — PEM-encoded private key from file at PATH
//   - literal PEM   — treated as a PEM block directly
func resolveSelfContainedRSAKey(src string) (*rsa.PrivateKey, error) {
	var pemData string

	switch {
	case strings.HasPrefix(src, "env:"):
		name := strings.TrimPrefix(src, "env:")
		val := os.Getenv(name)
		if val == "" {
			return nil, fmt.Errorf("environment variable %q is empty or unset", name)
		}
		pemData = val
	case strings.HasPrefix(src, "file:"):
		path := strings.TrimPrefix(src, "file:")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key file %q: %w", path, err)
		}
		pemData = string(data)
	default:
		pemData = src
	}

	block, rest := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	if len(rest) > 0 && strings.TrimSpace(string(rest)) != "" {
		// Allow trailing whitespace
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PEM block is not an RSA private key (type: %T)", key)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q (expected \"RSA PRIVATE KEY\" or \"PRIVATE KEY\")", block.Type)
	}
}

// parseIntEntry extracts an integer value from a map that may contain
// either int or float64 (the latter when the map comes from YAML parsing).
func parseIntEntry(m map[string]any, key string) (int, error) {
	v, ok := m[key]
	if !ok {
		return 0, fmt.Errorf("missing key %q", key)
	}
	switch val := v.(type) {
	case float64:
		return int(val), nil
	case int:
		return val, nil
	default:
		return 0, fmt.Errorf("key %q must be a number", key)
	}
}
