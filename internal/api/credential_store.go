package api

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

// AuthorizationPolicy is the immutable bucket-level policy attached to a credential.
type AuthorizationPolicy struct {
	Buckets           []string
	Permissions       config.ObjectPermission
	BucketPermissions []config.BucketPermission
	matchers          []bucketMatcher
}

type bucketMatcher struct {
	exact  string
	prefix string
}

// Credential is the authenticated gateway principal.
type Credential struct {
	AccessKey string
	SecretKey string
	Label     string
	Policy    AuthorizationPolicy
}

// AllowsBucket reports whether the bucket is in scope. A nil scope is unrestricted;
// an empty scope is an intentional deny-all policy.
func (c Credential) AllowsBucket(bucket string) bool {
	if c.Policy.matchers != nil {
		for _, matcher := range c.Policy.matchers {
			if matcher.exact == bucket || (matcher.prefix != "" && strings.HasPrefix(bucket, matcher.prefix)) {
				return true
			}
		}
		return false
	}
	if c.Policy.Buckets == nil {
		return true
	}
	for _, pattern := range c.Policy.Buckets {
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(bucket, strings.TrimSuffix(pattern, "*")) {
				return true
			}
		} else if bucket == pattern {
			return true
		}
	}
	return false
}

func (c Credential) CanWrite() bool { return c.Policy.Permissions == config.ObjectPermissionReadWrite }

func (c Credential) HasBucketPermission(permission config.BucketPermission) bool {
	for _, grant := range c.Policy.BucketPermissions {
		if grant == permission {
			return true
		}
	}
	return false
}

// CredentialStore is a concurrent, atomically replaceable gateway credential store.
type CredentialStore interface {
	Lookup(accessKey string) (Credential, error)
	Replace(credentials []config.GatewayCredential) error
}

type credentialSnapshot struct{ credentials map[string]Credential }

// StaticCredentialStore retains its historical name while publishing immutable
// snapshots so authentication and authorization policy can be reloaded atomically.
type StaticCredentialStore struct {
	snapshot atomic.Pointer[credentialSnapshot]
}

func NewStaticCredentialStore(creds []config.GatewayCredential) (*StaticCredentialStore, error) {
	s := &StaticCredentialStore{}
	if err := s.Replace(creds); err != nil {
		return nil, err
	}
	return s, nil
}

func compileCredentialSnapshot(creds []config.GatewayCredential) (*credentialSnapshot, error) {
	if err := config.ValidateGatewayCredentials(creds, true); err != nil {
		return nil, err
	}
	m := make(map[string]Credential, len(creds))
	for _, source := range creds {
		if source.AccessKey == "" || source.SecretKey == "" {
			return nil, fmt.Errorf("credential entry is missing access key or secret key")
		}
		if _, exists := m[source.AccessKey]; exists {
			return nil, fmt.Errorf("duplicate credential access key %q", source.AccessKey)
		}
		buckets := cloneStringSlice(source.Buckets)
		grants := cloneBucketPermissionSlice(source.BucketPermissions)
		matchers := compileBucketMatchers(buckets)
		permission := config.ObjectPermissionReadWrite
		if source.Permissions != nil {
			permission = *source.Permissions
		}
		m[source.AccessKey] = Credential{AccessKey: source.AccessKey, SecretKey: source.SecretKey, Label: source.Label, Policy: AuthorizationPolicy{Buckets: buckets, Permissions: permission, BucketPermissions: grants, matchers: matchers}}
	}
	return &credentialSnapshot{credentials: m}, nil
}

// Replace validates and builds the complete next snapshot before publishing it.
func (s *StaticCredentialStore) Replace(creds []config.GatewayCredential) error {
	snapshot, err := compileCredentialSnapshot(creds)
	if err != nil {
		return err
	}
	s.snapshot.Store(snapshot)
	return nil
}

func (s *StaticCredentialStore) Lookup(accessKey string) (Credential, error) {
	snapshot := s.snapshot.Load()
	if snapshot == nil {
		return Credential{}, ErrUnknownAccessKey
	}
	credential, ok := snapshot.credentials[accessKey]
	if !ok {
		return Credential{}, ErrUnknownAccessKey
	}
	credential.Policy.Buckets = cloneStringSlice(credential.Policy.Buckets)
	credential.Policy.BucketPermissions = cloneBucketPermissionSlice(credential.Policy.BucketPermissions)
	credential.Policy.matchers = append([]bucketMatcher(nil), credential.Policy.matchers...)
	return credential, nil
}

func compileBucketMatchers(patterns []string) []bucketMatcher {
	if patterns == nil {
		return nil
	}
	matchers := make([]bucketMatcher, 0, len(patterns))
	for _, pattern := range patterns {
		if strings.HasSuffix(pattern, "*") {
			matchers = append(matchers, bucketMatcher{prefix: strings.TrimSuffix(pattern, "*")})
		} else {
			matchers = append(matchers, bucketMatcher{exact: pattern})
		}
	}
	return matchers
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func cloneBucketPermissionSlice(values []config.BucketPermission) []config.BucketPermission {
	if values == nil {
		return nil
	}
	return append([]config.BucketPermission{}, values...)
}
