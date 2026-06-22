package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryanuber/go-glob"
	"gopkg.in/yaml.v3"
)

// PolicyConfig holds the structure for a policy file
type PolicyConfig struct {
	ID          string             `yaml:"id"`
	Buckets     []string           `yaml:"buckets"` // Glob patterns for bucket names
	Encryption  *EncryptionConfig  `yaml:"encryption,omitempty"`
	RateLimit   *RateLimitConfig   `yaml:"rate_limit,omitempty"`
	// RequireEncryption, when true, mandates that every object stored in
	// matching buckets must be encrypted. It enables hard-refusal semantics
	// at policy-relevant points (e.g. UploadPartCopy from a plaintext source
	// into a bucket with this flag set). Default is false, preserving
	// backward compatibility; set explicitly per-bucket to enforce.
	RequireEncryption bool `yaml:"require_encryption,omitempty"`
	// DisableEncryption, when true, causes the gateway to store and serve
	// objects in matching buckets as plain bytes without AEAD encryption.
	// Mutually exclusive with RequireEncryption: true.
	// Also implies EncryptMultipartUploads = false.
	DisableEncryption bool `yaml:"disable_encryption,omitempty"`
	DisallowLockBypass bool `yaml:"disallow_lock_bypass,omitempty"`
	// EncryptMultipartUploads opts this bucket into the encrypted multipart
	// upload path (ADR 0009). When true a per-upload DEK is generated at
	// CreateMultipartUpload and state is persisted in Valkey.
	// Default is true (nil pointer = unset = enabled). Set explicitly to
	// false to opt a bucket out.
	EncryptMultipartUploads *bool `yaml:"encrypt_multipart_uploads,omitempty"`
}

// PolicyManager manages loading and matching policies
type PolicyManager struct {
	policies []*PolicyConfig
	mu       sync.RWMutex
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager() *PolicyManager {
	return &PolicyManager{
		policies: make([]*PolicyConfig, 0),
	}
}

// LoadPolicies loads policies from the specified file patterns
func (pm *PolicyManager) LoadPolicies(patterns []string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.policies = make([]*PolicyConfig, 0)

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("failed to glob pattern %s: %w", pattern, err)
		}

		for _, match := range matches {
			data, err := os.ReadFile(match)
			if err != nil {
				return fmt.Errorf("failed to read policy file %s: %w", match, err)
			}

			var policy PolicyConfig
			if err := yaml.Unmarshal(data, &policy); err != nil {
				return fmt.Errorf("failed to parse policy file %s: %w", match, err)
			}

			// Validate policy
			if policy.ID == "" {
				return fmt.Errorf("policy in file %s must have an ID", match)
			}
			if len(policy.Buckets) == 0 {
				return fmt.Errorf("policy %s must specify at least one bucket pattern", policy.ID)
			}

			if policy.DisableEncryption && policy.RequireEncryption {
				return fmt.Errorf("policy %q: disable_encryption and require_encryption are mutually exclusive", policy.ID)
			}

			pm.policies = append(pm.policies, &policy)
		}
	}

	return nil
}

// GetPolicyForBucket returns the first matching policy for the given bucket
func (pm *PolicyManager) GetPolicyForBucket(bucket string) *PolicyConfig {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, policy := range pm.policies {
		for _, pattern := range policy.Buckets {
			if glob.Glob(pattern, bucket) {
				return policy
			}
		}
	}
	return nil
}

// BucketRequiresEncryption reports whether the bucket's matching policy sets
// RequireEncryption. Returns false when no policy matches (backward compat —
// callers must opt in explicitly per-bucket).
func (pm *PolicyManager) BucketRequiresEncryption(bucket string) bool {
	if pm == nil {
		return false
	}
	policy := pm.GetPolicyForBucket(bucket)
	if policy == nil {
		return false
	}
	return policy.RequireEncryption
}

// BucketDisablesEncryption reports whether the bucket's matching policy sets
// DisableEncryption. Returns false when no policy matches.
func (pm *PolicyManager) BucketDisablesEncryption(bucket string) bool {
	if pm == nil {
		return false
	}
	policy := pm.GetPolicyForBucket(bucket)
	if policy == nil {
		return false
	}
	return policy.DisableEncryption
}

// ApplyToConfig applies policy overrides to a copy of the base configuration
func (p *PolicyConfig) ApplyToConfig(base *Config) *Config {
	// Create a shallow copy of the base config
	newConfig := *base

	// Deep copy specific sections if they are being modified to avoid side effects
	// For now, we replace whole sections if they exist in policy

	if p.Encryption != nil {
		// Start with base encryption config
		enc := base.Encryption
		// Override fields that are set in policy
		// Note: partial override is tricky with simple struct replacement.
		// For this implementation, we assume the policy provides a complete encryption config
		// OR we manually merge specific fields.

		// Let's do a manual merge for common fields to be safe and useful
		if p.Encryption.Password != "" {
			enc.Password = p.Encryption.Password
		}
		if p.Encryption.PreferredAlgorithm != "" {
			enc.PreferredAlgorithm = p.Encryption.PreferredAlgorithm
		}
		// If KeyManager is explicitly configured in policy (Enabled is true or Provider is set), override it
		if p.Encryption.KeyManager.Enabled || p.Encryption.KeyManager.Provider != "" {
			enc.KeyManager = p.Encryption.KeyManager
		}

		newConfig.Encryption = enc
	}

	if p.RateLimit != nil {
		newConfig.RateLimit = *p.RateLimit
	}

	return &newConfig
}

// BucketEncryptsMultipart reports whether the bucket's matching policy enables
// encrypted multipart uploads. The default is true: a nil pointer (field
// omitted in the policy file) or no matching policy both result in true.
// Set encrypt_multipart_uploads: false explicitly to opt a bucket out.
func (pm *PolicyManager) BucketEncryptsMultipart(bucket string) bool {
	if pm == nil {
		return true
	}
	policy := pm.GetPolicyForBucket(bucket)
	if policy == nil {
		return true
	}
	if policy.DisableEncryption {
		return false
	}
	if policy.EncryptMultipartUploads == nil {
		return true
	}
	return *policy.EncryptMultipartUploads
}

// AnyPolicyRequiresMPUEncryption reports whether at least one loaded policy
// effectively enables encrypted multipart uploads (i.e. EncryptMultipartUploads
// is nil/unset or explicitly true). Used at startup to enforce fail-closed
// behaviour when the Valkey state store is not configured.
// Returns false only when every loaded policy has an explicit false, or when
// no policies are loaded at all.
func (pm *PolicyManager) AnyPolicyRequiresMPUEncryption() bool {
	if pm == nil {
		return false
	}
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, p := range pm.policies {
		if p.EncryptMultipartUploads == nil || *p.EncryptMultipartUploads {
			return true
		}
	}
	return false
}

// BucketDisallowsLockBypass returns true if the bucket policy disallows lock bypass.
func (pm *PolicyManager) BucketDisallowsLockBypass(bucket string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	for _, policy := range pm.policies {
		for _, b := range policy.Buckets {
			if glob.Glob(b, bucket) && policy.DisallowLockBypass {
				return true
			}
		}
	}

	return false
}

// Policies returns a copy of all loaded policies.
func (pm *PolicyManager) Policies() []*PolicyConfig {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	result := make([]*PolicyConfig, len(pm.policies))
	copy(result, pm.policies)
	return result
}

// Reset clears all loaded policies. Must be called before a full config
// reload to prevent policy accumulation across SIGHUP cycles.
func (pm *PolicyManager) Reset() {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.policies = make([]*PolicyConfig, 0)
}

// splitTrimmed splits s by sep and trims whitespace from each element.
func splitTrimmed(s, sep string) []string {
	parts := strings.Split(s, sep)
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// LoadPoliciesFromEnv reads GW_POLICY_N_* indexed env vars and appends the
// resulting policies to pm.policies. Iteration stops at the first N where
// GW_POLICY_N_ID is absent. Validation is identical to LoadPolicies.
//
// Invariants:
//   - Thread-safe (acquires pm.mu.Lock).
//   - Appends to existing policies; call Reset() before a full reload.
//   - Returns the first validation error encountered.
func (pm *PolicyManager) LoadPoliciesFromEnv() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	for i := 0; ; i++ {
		id := os.Getenv(fmt.Sprintf("GW_POLICY_%d_ID", i))
		if id == "" {
			break
		}
		bucketsRaw := os.Getenv(fmt.Sprintf("GW_POLICY_%d_BUCKETS", i))
		if bucketsRaw == "" {
			return fmt.Errorf("GW_POLICY_%d_BUCKETS must specify at least one pattern", i)
		}
		buckets := splitTrimmed(bucketsRaw, ",")

		policy := &PolicyConfig{ID: id, Buckets: buckets}

		if v := os.Getenv(fmt.Sprintf("GW_POLICY_%d_DISABLE_ENCRYPTION", i)); v != "" {
			policy.DisableEncryption = v == "true" || v == "1"
		}
		if v := os.Getenv(fmt.Sprintf("GW_POLICY_%d_REQUIRE_ENCRYPTION", i)); v != "" {
			policy.RequireEncryption = v == "true" || v == "1"
		}
		if v := os.Getenv(fmt.Sprintf("GW_POLICY_%d_DISALLOW_LOCK_BYPASS", i)); v != "" {
			policy.DisallowLockBypass = v == "true" || v == "1"
		}
		if v := os.Getenv(fmt.Sprintf("GW_POLICY_%d_ENCRYPT_MULTIPART_UPLOADS", i)); v != "" {
			b := v == "true" || v == "1"
			policy.EncryptMultipartUploads = &b
		}

		encPwd := os.Getenv(fmt.Sprintf("GW_POLICY_%d_ENCRYPTION_PASSWORD", i))
		encAlg := os.Getenv(fmt.Sprintf("GW_POLICY_%d_ENCRYPTION_ALGORITHM", i))
		if encPwd != "" || encAlg != "" {
			enc := &EncryptionConfig{}
			enc.Password = encPwd
			enc.PreferredAlgorithm = encAlg
			policy.Encryption = enc
		}

		rlEnabled := os.Getenv(fmt.Sprintf("GW_POLICY_%d_RATE_LIMIT_ENABLED", i))
		rlReq := os.Getenv(fmt.Sprintf("GW_POLICY_%d_RATE_LIMIT_REQUESTS", i))
		rlWin := os.Getenv(fmt.Sprintf("GW_POLICY_%d_RATE_LIMIT_WINDOW", i))
		if rlEnabled != "" || rlReq != "" || rlWin != "" {
			rl := &RateLimitConfig{}
			rl.Enabled = rlEnabled == "true" || rlEnabled == "1"
			if n, err := strconv.Atoi(rlReq); err == nil && n > 0 {
				rl.Limit = n
			}
			if d, err := time.ParseDuration(rlWin); err == nil {
				rl.Window = d
			}
			policy.RateLimit = rl
		}

		if policy.DisableEncryption && policy.RequireEncryption {
			return fmt.Errorf("GW_POLICY_%d (%q): disable_encryption and require_encryption are mutually exclusive", i, id)
		}

		pm.policies = append(pm.policies, policy)
	}
	return nil
}
