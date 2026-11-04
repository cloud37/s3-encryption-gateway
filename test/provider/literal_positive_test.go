package provider

import "testing"

func TestGH353LiteralPositiveProviderOwnership(t *testing.T) {
	if !(&garageProvider{}).RequiresLiteralPostPositiveProof() {
		t.Fatal("mandatory fixture policy missing")
	}
	selected := LiteralPostPositiveProofProviders()
	if len(selected) != 1 || selected[0].Name() != (&garageProvider{}).Name() {
		t.Fatal("mandatory positive provider registration missing or ambiguous")
	}
	if _, ok := any(&minioProvider{}).(interface{ RequiresLiteralPostPositiveProof() bool }); ok {
		t.Fatal("unverified provider acquired positive proof policy")
	}
}
