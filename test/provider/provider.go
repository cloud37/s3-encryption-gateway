// Package provider defines the Provider interface and registry used by the
// conformance test suite. Each backend-under-test implements Provider; the
// suite iterates provider.All() so test authors never reference backend names
// directly inside test bodies.
package provider

import (
	"context"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
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
