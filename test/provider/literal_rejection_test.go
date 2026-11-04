package provider

import "testing"

func TestGH353LiteralRejectionProviderPolicies(t *testing.T) {
	for _, tc := range []struct {
		p    Provider
		want LiteralPostRejection
	}{
		{&minioProvider{}, LiteralPostRejection{400, "XMinioInvalidResourceName", 500, "InternalError"}},
		{&rustfsProvider{}, LiteralPostRejection{400, "InvalidArgument", 400, "InvalidArgument"}},
		{&seaweedfsProvider{}, LiteralPostRejection{400, "InvalidRequest", 500, "InternalError"}},
	} {
		got, ok := LiteralPostRejectionForInstance(Instance{ProviderName: tc.p.Name()})
		if !ok || got != tc.want {
			t.Fatal("provider rejection policy mismatch")
		}
	}
	if _, ok := LiteralPostRejectionForInstance(Instance{ProviderName: (&garageProvider{}).Name()}); ok {
		t.Fatal("positive provider incorrectly restricted")
	}
	if _, ok := LiteralPostRejectionForInstance(Instance{ProviderName: "unregistered"}); ok || len(LiteralPostRejectionProviders()) != 3 {
		t.Fatal("rejection policy registry incomplete")
	}
}

func TestGH353PostApplicabilityIsProviderOwned(t *testing.T) {
	for _, p := range []Provider{&seaweedfsProvider{}, &rustfsProvider{}} {
		if SupportsGH353Post(p) {
			t.Fatal("unsupported provider selected for GH-353 POST")
		}
	}
	for _, p := range []Provider{&minioProvider{}, &garageProvider{}, &externalProvider{}} {
		if !SupportsGH353Post(p) {
			t.Fatal("unrelated provider unexpectedly excluded from GH-353 POST")
		}
	}
	want := map[string]bool{(&minioProvider{}).Name(): true, (&rustfsProvider{}).Name(): true}
	got := GH353LiteralRejectionProviders()
	if len(got) != len(want) {
		t.Fatal("mandatory native-negative pair missing or ambiguous")
	}
	for _, p := range got {
		if !want[p.Name()] {
			t.Fatal("unexpected or duplicate mandatory proof provider")
		}
		delete(want, p.Name())
	}
}
