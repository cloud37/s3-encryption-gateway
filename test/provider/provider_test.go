package provider_test

import (
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/provider"
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

// TestCapabilities_NewBitsPresent asserts that the six V1.0-COMPAT-1
// capability bits (bits 20-25) are independently defined (non-zero, powers of
// two, distinct values) and their String() outputs match expected names.
func TestCapabilities_NewBitsPresent(t *testing.T) {
	bits := []struct {
		cap  provider.Capabilities
		name string
	}{
		{provider.CapSDKAWSGoV2, "SDKAWSGoV2"},
		{provider.CapSDKBoto3, "SDKBoto3"},
		{provider.CapCLIAWSCLI, "CLIAWSCLI"},
		{provider.CapCLIS5cmd, "CLIS5cmd"},
		{provider.CapCLIRclone, "CLIRclone"},
		{provider.CapSDKMinIOPy, "SDKMinIOPy"},
	}

	// Check 1: none is zero.
	for _, b := range bits {
		if b.cap == 0 {
			t.Errorf("%s is zero — not a valid capability bit", b.name)
		}
	}

	// Check 2: each is a power of two (single, independent bit).
	for _, b := range bits {
		if b.cap&(b.cap-1) != 0 {
			t.Errorf("%s = %d has multiple bits set — should be a single power-of-two",
				b.name, b.cap)
		}
	}

	// Check 3: all distinct (no aliasing).
	seen := make(map[provider.Capabilities]string)
	for _, b := range bits {
		if prev, ok := seen[b.cap]; ok {
			t.Errorf("value %d aliased by %s and %s", b.cap, prev, b.name)
		}
		seen[b.cap] = b.name
	}

	// Check 4: no alias with any pre-existing bit (bits 0-19).
	existing := []struct {
		cap  provider.Capabilities
		name string
	}{
		{provider.CapObjectLock, "ObjectLock"},
		{provider.CapObjectTagging, "ObjectTagging"},
		{provider.CapMultipartUpload, "MultipartUpload"},
		{provider.CapMultipartCopy, "MultipartCopy"},
		{provider.CapVersioning, "Versioning"},
		{provider.CapServerSideEncryption, "SSE"},
		{provider.CapPresignedURL, "PresignedURL"},
		{provider.CapConditionalWrites, "ConditionalWrites"},
		{provider.CapBatchDelete, "BatchDelete"},
		{provider.CapKMSIntegration, "KMSIntegration"},
		{provider.CapInlinePutTagging, "InlinePutTagging"},
		{provider.CapEncryptedMPU, "EncryptedMPU"},
		{provider.CapLoadTest, "LoadTest"},
		{provider.CapBucketPolicy, "BucketPolicy"},
		{provider.CapBucketLifecycle, "BucketLifecycle"},
		{provider.CapBucketCors, "BucketCors"},
		{provider.CapBucketACL, "BucketACL"},
		{provider.CapObjectACL, "ObjectACL"},
		{provider.CapBucketEncryption, "BucketEncryption"},
	}
	for _, newb := range bits {
		for _, old := range existing {
			if newb.cap == old.cap {
				t.Errorf("%s = %d aliases pre-existing bit %s",
					newb.name, newb.cap, old.name)
			}
		}
	}

	// Check 5: String() returns canonical names for individual bits.
	for _, b := range bits {
		if got := b.cap.String(); got != b.name {
			t.Errorf("%s.String() = %q, want %q", b.name, got, b.name)
		}
	}

	// Check 6: combined String() works for new bits.
	combined := bits[0].cap | bits[len(bits)-1].cap
	want := bits[0].name + "|" + bits[len(bits)-1].name
	if got := combined.String(); got != want {
		t.Errorf("combined(%d|%d).String() = %q, want %q",
			bits[0].cap, bits[len(bits)-1].cap, got, want)
	}
}

func TestCleanupPolicy_Values(t *testing.T) {
	if provider.CleanupPolicyDelete == provider.CleanupPolicySkipDelete {
		t.Error("CleanupPolicyDelete and CleanupPolicySkipDelete must be distinct")
	}
}
