package provider_test

import (
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// TestRegistry_NoDuplicateNames asserts that no two registered providers share
// a Name(). Duplicate names break `go test -run` subtest filtering.
func TestRegistry_NoDuplicateNames(t *testing.T) {
	seen := make(map[string]bool)
	for _, p := range provider.All() {
		name := p.Name()
		if seen[name] {
			t.Errorf("duplicate provider name: %q", name)
		}
		seen[name] = true
	}
}

// TestRegistry_NamesNotEmpty asserts that every registered provider has a
// non-empty Name().
func TestRegistry_NamesNotEmpty(t *testing.T) {
	for _, p := range provider.All() {
		if p.Name() == "" {
			t.Errorf("provider %T has an empty Name()", p)
		}
	}
}

// TestCapabilities_Stringer exercises the Capabilities.String() method to
// ensure it does not panic and produces a non-empty string for known bits.
func TestCapabilities_Stringer(t *testing.T) {
	cases := []struct {
		cap  provider.Capabilities
		want string
	}{
		{0, "none"},
		{provider.CapMultipartUpload, "MultipartUpload"},
		{provider.CapObjectLock | provider.CapVersioning, "ObjectLock|Versioning"},
	}
	for _, tc := range cases {
		got := tc.cap.String()
		if got != tc.want {
			t.Errorf("Capabilities(%d).String() = %q, want %q", tc.cap, got, tc.want)
		}
	}
}

// TestCleanupPolicy_Values asserts the two policy constants have distinct values.
func TestCleanupPolicy_Values(t *testing.T) {
	if provider.CleanupPolicyDelete == provider.CleanupPolicySkipDelete {
		t.Error("CleanupPolicyDelete and CleanupPolicySkipDelete must be distinct")
	}
}
