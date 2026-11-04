//go:build conformance

package conformance

import (
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

type gh353ExcludedProvider struct{ externalFakeProvider }

func (gh353ExcludedProvider) GH353PostUnsupported() bool { return true }

func TestGH353PostCaseApplicability(t *testing.T) {
	excluded := gh353ExcludedProvider{externalFakeProvider("fixture")}
	supported := externalFakeProvider("fixture")
	for _, name := range []string{
		"PostObject_RoundTrip", "PostObject_RejectPreservesExisting", "PostObject_SessionAndExpiry",
		"PostObject_Responses", "PostObject_TaggingACLVersion", "PostObject_SSE", "PostObject_FutureFamily",
		"Compat_Boto3PresignedPost", "Compat_AWSJSPresignedPost", "Compat_BrowserPost",
	} {
		if !gh353PostCase(name) {
			t.Errorf("GH-353 case %s is not gated", name)
		}
		if gh353CaseApplicable(excluded, name) || !gh353CaseApplicable(supported, name) {
			t.Errorf("provider applicability incorrect for %s", name)
		}
	}
	for _, name := range []string{"PutGet", "Tagging_Passthrough", "Compat_Boto3", "Metadata_RoundTrip"} {
		if gh353PostCase(name) {
			t.Errorf("non-GH-353 case %s is gated", name)
		}
		if !gh353CaseApplicable(excluded, name) || !gh353CaseApplicable(supported, name) {
			t.Errorf("unrelated case excluded: %s", name)
		}
	}
}

var _ provider.Provider = gh353ExcludedProvider{}
