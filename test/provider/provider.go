// Package provider defines the Provider interface and registry used by the
// conformance test suite. Each backend-under-test implements Provider; the
// suite iterates provider.All() so test authors never reference backend names
// directly inside test bodies.
package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

// Provider is the contract every S3-compatible backend-under-test satisfies.
// Implementations are registered via init() and discovered at test start time.
type Provider interface {
	// Name returns a stable identifier used in subtest names and skip messages.
	// Must not contain characters that break `go test -run`.
	Name() string

	// Start brings the backend up and returns a configured Instance.
	// The bucket named in Instance.Bucket is already created and empty.
	// t.Cleanup is registered internally; callers do not manage teardown.
	Start(ctx context.Context, t *testing.T) Instance

	// Capabilities declares which features this backend supports.
	// Tests consult this bitmap and call t.Skipf when the backend does not
	// support the feature being tested.
	Capabilities() Capabilities

	// CleanupPolicy declares whether the conformance suite should delete objects
	// it creates. Minimum-storage-duration backends (Wasabi) declare SkipDelete
	// to avoid billing churn; free-delete backends declare Delete.
	CleanupPolicy() CleanupPolicy

	// BackendConfig returns the config stanza the gateway-under-test should
	// load to talk to this backend instance.
	BackendConfig(inst Instance) config.BackendConfig
}

// Instance holds the live connection details for one backend started by
// Provider.Start. All fields are populated before Start returns.
type Instance struct {
	// GH353MetadataProfile opts a fixture into the real gateway configuration.
	GH353MetadataProfile string
	BackendTLS           *TLSFixture
	// ObjectSSE is present only after real SDK verification of the required
	// provider-side SSE modes over trusted backend HTTPS.
	ObjectSSE *SSEFixture
	// ObjectSSEError is a non-secret diagnostic retained when an optional local
	// static-KMS probe fails; mandatory conformance reports it as failure.
	ObjectSSEError string
	// MinIOObjectSSEAttempted marks that the mandatory isolated MinIO ObjectSSE
	// fixture probe is expected for this provider instance. It does not claim
	// that static-KMS or SSE verification passed.
	MinIOObjectSSEAttempted bool
	// Endpoint is the HTTP(S) endpoint, e.g. "http://127.0.0.1:9000".
	Endpoint string
	// Region is the S3 region, e.g. "us-east-1".
	Region string
	// AccessKey is the AWS-style access key.
	AccessKey string
	// SecretKey is the AWS-style secret key.
	SecretKey string
	// Bucket is the name of the pre-created, empty test bucket.
	Bucket string
	// Raw exposes provider-specific handles for edge-case tests
	// (e.g. MinIO admin client for at-rest inspection).
	// Most tests do NOT use this.
	Raw interface{}
	// ProviderName is the Name() of the provider that produced this instance.
	ProviderName string
}

// GH353PostInlineTagging reports provider-owned POST fixture policy.
func GH353PostInlineTagging(inst Instance) string {
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			p, ok := candidate.(interface{ GH353PostInlineTagging() string })
			if ok {
				return p.GH353PostInlineTagging()
			}
		}
	}
	return "supported"
}

// GH353UnsupportedTaggingProofProviders identifies required local proofs.
func GH353UnsupportedTaggingProofProviders() []Provider {
	var result []Provider
	for _, candidate := range registry {
		if policy, ok := candidate.(interface{ GH353PostInlineTagging() string }); ok && policy.GH353PostInlineTagging() == "unsupported" {
			result = append(result, candidate)
		}
	}
	return result
}

// GH353FeedbackProviders are deterministic fixture identities, independent of
// whether local containers are registered for the current process.
func GH353FeedbackProviders() []Provider {
	return []Provider{&minioProvider{}, &rustfsProvider{}, &garageProvider{}, &seaweedfsProvider{}}
}

func GH353FeedbackCompactingProvider() Provider   { return &minioProvider{} }
func GH353FeedbackConservativeProvider() Provider { return &rustfsProvider{} }

type TLSFixture struct {
	Endpoint  string
	CAFile    string
	Bucket    string
	AccessKey string
	SecretKey string
}

// SSEFixture describes a verified HTTPS backend with the disposable static KMS
// key name used by provider-side server-side-encryption tests.
type SSEFixture struct {
	Backend  TLSFixture
	KMSKeyID string
}

// ValidateMinIOObjectSSEFixture reports whether the mandatory local MinIO
// static-KMS fixture was attempted and completed real SDK verification.
func ValidateMinIOObjectSSEFixture(inst Instance) error {
	if inst.ObjectSSEError != "" {
		return fmt.Errorf("mandatory MinIO ObjectSSE fixture was not verified: %s", inst.ObjectSSEError)
	}
	if !inst.MinIOObjectSSEAttempted {
		return fmt.Errorf("mandatory static-KMS fixture probe was not attempted")
	}
	if inst.ObjectSSE == nil {
		return fmt.Errorf("mandatory MinIO ObjectSSE fixture was not published")
	}
	if inst.ObjectSSE.KMSKeyID != "gh353-test" || inst.ObjectSSE.Backend.Endpoint == "" || inst.ObjectSSE.Backend.CAFile == "" || inst.ObjectSSE.Backend.Bucket == "" || inst.ObjectSSE.Backend.AccessKey == "" || inst.ObjectSSE.Backend.SecretKey == "" {
		return fmt.Errorf("mandatory MinIO ObjectSSE fixture is missing trusted backend or KMS metadata")
	}
	return nil
}

// CleanupPolicy controls whether the conformance suite deletes objects after tests.
type CleanupPolicy uint8

const (
	// CleanupPolicyDelete instructs the suite to delete test objects on teardown.
	// Use this for local containers and providers where delete is free.
	CleanupPolicyDelete CleanupPolicy = iota
	// CleanupPolicySkipDelete leaves objects in place for the provider's own
	// lifecycle policy. Use this for Wasabi and other minimum-storage-duration
	// backends where delete-before-TTL incurs a charge.
	CleanupPolicySkipDelete
)

// registry holds all registered Provider implementations.
var registry []Provider

// Register adds p to the global registry. Call Register from an init() function
// in each provider implementation file.
func Register(p Provider) {
	registry = append(registry, p)
}

// All returns a snapshot of all registered providers. The returned slice is a
// copy; modifying it does not affect the registry.
func All() []Provider {
	return append([]Provider(nil), registry...)
}

// SupportsGH353Post is a provider-owned test applicability decision, not a
// claim that a provider has passed the GH-353 conformance suite.
func SupportsGH353Post(p Provider) bool {
	policy, ok := p.(interface{ GH353PostUnsupported() bool })
	return !ok || !policy.GH353PostUnsupported()
}

// GH353LiteralRejectionProviders selects independent mandatory native-negative
// proofs, not providers that support the entire GH-353 POST contract.
func GH353LiteralRejectionProviders() []Provider {
	var result []Provider
	for _, p := range LiteralPostRejectionProviders() {
		policy, ok := p.(interface{ RequiresGH353LiteralRejectionProof() bool })
		if ok && policy.RequiresGH353LiteralRejectionProof() {
			result = append(result, p)
		}
	}
	return result
}

// LiteralPostPositiveProofProviders returns providers with a mandatory
// positive proof, rather than treating unknown support as a capability skip.
func LiteralPostPositiveProofProviders() []Provider {
	var result []Provider
	for _, candidate := range registry {
		policy, ok := candidate.(interface{ RequiresLiteralPostPositiveProof() bool })
		if ok && policy.RequiresLiteralPostPositiveProof() {
			result = append(result, candidate)
		}
	}
	return result
}

// LiteralPostRejection is a provider-owned, exact observed wire contract.
type LiteralPostRejection struct {
	BackendStatus int
	BackendCode   string
	GatewayStatus int
	GatewayCode   string
}

func LiteralPostRejectionForInstance(inst Instance) (LiteralPostRejection, bool) {
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			policy, ok := candidate.(interface{ LiteralPostRejection() LiteralPostRejection })
			if ok {
				return policy.LiteralPostRejection(), true
			}
			break
		}
	}
	return LiteralPostRejection{}, false
}

// Missing fixture registration is a mandatory gate failure, not a skip.
func LiteralPostRejectionProviders() []Provider {
	var result []Provider
	for _, candidate := range registry {
		if _, ok := candidate.(interface{ LiteralPostRejection() LiteralPostRejection }); ok {
			result = append(result, candidate)
		}
	}
	return result
}

// CapabilitiesForInstance resolves the registered provider policy for an
// instance without making conformance tests depend on provider identities.
// ProviderName is the registry key only; behavior remains provider-owned.
func CapabilitiesForInstance(inst Instance) (Capabilities, bool) {
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			return candidate.Capabilities(), true
		}
	}
	return 0, false
}

// CleanupPolicyForInstance returns the provider-owned cleanup policy.
func CleanupPolicyForInstance(inst Instance) (CleanupPolicy, bool) {
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			return candidate.CleanupPolicy(), true
		}
	}
	return CleanupPolicySkipDelete, false
}

// RequiresObjectSSEFixture reports whether the registered provider requires a
// verified ObjectSSE fixture for conformance. This is fixture policy, not a
// capability bit: a missing mandatory fixture must fail instead of skip.
func RequiresObjectSSEFixture(inst Instance) bool {
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			required, ok := candidate.(interface{ RequiresObjectSSEFixture() bool })
			return ok && required.RequiresObjectSSEFixture()
		}
	}
	return false
}

// RequiresBackendCredentialIdentity reports whether conformance should assert
// that ordinary backend requests use the instance's configured access key.
func RequiresBackendCredentialIdentity(inst Instance) bool {
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			assertion, ok := candidate.(interface{ RequiresBackendCredentialIdentity() bool })
			return ok && assertion.RequiresBackendCredentialIdentity()
		}
	}
	return false
}

// IsDisposableLocalFixture reports local, isolated providers that own their
// disposable fixture lifecycle. External providers remain false even when
// their object cleanup policy permits deleting individual objects.
func IsDisposableLocalFixture(inst Instance) bool {
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			local, ok := candidate.(interface{ IsDisposableLocalFixture() bool })
			return ok && local.IsDisposableLocalFixture()
		}
	}
	return false
}

// ObjectSSEStorageClass returns the expected at-rest class for a disposable
// local static-KMS ObjectSSE fixture, or an empty string when no such policy
// applies.
func ObjectSSEStorageClass(inst Instance, fixture *SSEFixture) string {
	if fixture == nil {
		return ""
	}
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			policy, ok := candidate.(interface {
				ObjectSSEStorageClass(*SSEFixture) string
			})
			if ok {
				return policy.ObjectSSEStorageClass(fixture)
			}
			return ""
		}
	}
	return ""
}

// ObjectSSEKMSIdentityMatches applies the registered provider's KMS identity
// response policy. Providers default to exact identity equality; MinIO's
// ObjectInfo canonicalizes a non-ARN key ID by prefixing arn:aws:kms: (see
// https://github.com/minio/minio/blob/7aac2a2c5b7c882e68c1ce017d8256be2feea27f/cmd/encryption-v1.go#L79-L101
// and https://github.com/minio/minio/blob/7aac2a2c5b7c882e68c1ce017d8256be2feea27f/internal/crypto/metadata.go#L63-L64).
// The configured identity must be nonempty, and the only accepted alternate
// is that exact prefix plus the configured raw ID for the registered MinIO
// provider. Already-prefixed IDs are never stripped or prefixed a second time.
func ObjectSSEKMSIdentityMatches(inst Instance, configured, returned string) bool {
	if configured == "" || returned == "" {
		return false
	}
	for _, candidate := range registry {
		if candidate.Name() == inst.ProviderName {
			policy, ok := candidate.(interface {
				MatchesObjectSSEKMSIdentity(configured, returned string) bool
			})
			if ok {
				return policy.MatchesObjectSSEKMSIdentity(configured, returned)
			}
			break
		}
	}
	return configured == returned
}

// ShouldCreateDisposableVersionedBucket keeps providers with costly deletes
// from creating versioned conformance buckets that cannot be safely cleaned.
func ShouldCreateDisposableVersionedBucket(inst Instance) bool {
	policy, ok := CleanupPolicyForInstance(inst)
	return ok && policy != CleanupPolicySkipDelete
}
