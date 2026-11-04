//go:build conformance

package conformance

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

type externalFakeProvider string

func (p externalFakeProvider) Name() string { return string(p) }
func (externalFakeProvider) Start(context.Context, *testing.T) provider.Instance {
	panic("unexpected provider runtime")
}
func (externalFakeProvider) Capabilities() provider.Capabilities { return 0 }
func (externalFakeProvider) CleanupPolicy() provider.CleanupPolicy {
	return provider.CleanupPolicySkipDelete
}
func (externalFakeProvider) BackendConfig(provider.Instance) config.BackendConfig {
	return config.BackendConfig{}
}

func TestGH353ExternalPreflight(t *testing.T) {
	registry := []provider.Provider{externalFakeProvider("backblaze-b2"), externalFakeProvider("wasabi")}
	base := map[string]string{
		"B2_ACCESS_KEY_ID": "sensitive-fake", "B2_SECRET_ACCESS_KEY": "sensitive-fake", "B2_BUCKET_NAME": "fake",
		"WASABI_ACCESS_KEY_ID": "sensitive-fake", "WASABI_SECRET_ACCESS_KEY": "sensitive-fake", "WASABI_BUCKET_NAME": "fake",
	}
	get := func(k string) string { return base[k] }
	for _, selection := range []string{"backblaze-b2", "wasabi", "backblaze-b2,wasabi"} {
		got, err := provider.GH353ExternalPreflight(selection, get, registry)
		if err != nil || len(got) != len(strings.Split(selection, ",")) {
			t.Fatal("valid selection rejected")
		}
	}
	for _, selection := range []string{"", "backblaze-b2,", "backblaze-b2,backblaze-b2", "sensitive-fake", " wasabi"} {
		_, err := provider.GH353ExternalPreflight(selection, get, registry)
		if err == nil || strings.Contains(err.Error(), "sensitive-fake") {
			t.Fatal("invalid selection accepted or sensitive input disclosed")
		}
	}
	for _, key := range []string{"B2_ACCESS_KEY_ID", "B2_SECRET_ACCESS_KEY", "B2_BUCKET_NAME", "WASABI_ACCESS_KEY_ID", "WASABI_SECRET_ACCESS_KEY", "WASABI_BUCKET_NAME"} {
		old := base[key]
		base[key] = ""
		name := "backblaze-b2"
		if strings.HasPrefix(key, "WASABI_") {
			name = "wasabi"
		}
		_, err := provider.GH353ExternalPreflight(name, get, registry)
		base[key] = old
		if err == nil || !strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "sensitive-fake") {
			t.Fatalf("missing variable %s not safely rejected", key)
		}
	}
	base["GATEWAY_TEST_SKIP_EXTERNAL"] = "1"
	if _, err := provider.GH353ExternalPreflight("wasabi", get, registry); err == nil {
		t.Fatal("disabled external accepted")
	}
	delete(base, "GATEWAY_TEST_SKIP_EXTERNAL")
	base["GATEWAY_TEST_SKIP_VALKEY"] = "1"
	if _, err := provider.GH353ExternalPreflight("wasabi", get, registry); err == nil {
		t.Fatal("disabled browser fixture accepted")
	}
	delete(base, "GATEWAY_TEST_SKIP_VALKEY")
	if _, err := provider.GH353ExternalPreflight("wasabi", get, registry[:1]); err == nil {
		t.Fatal("missing registration accepted")
	}
	if _, err := provider.GH353ExternalPreflight("wasabi", get, append(registry, registry[1])); err == nil {
		t.Fatal("duplicate registration accepted")
	}
}

// The subprocess has no inherited credentials or provider configuration. It
// reaches only local preflight/mandatory-parent checks, never provider Start.
func TestGH353ExternalRunnerProcessGuards(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GATEWAY_TEST_SKIP_MINIO=1", "GATEWAY_TEST_SKIP_GARAGE=1", "GATEWAY_TEST_SKIP_RUSTFS=1", "GATEWAY_TEST_SKIP_SEAWEEDFS=1"}
	cases := []struct {
		name, run string
		env       []string
		want      string
	}{
		{"missing", "^TestConformanceGH353External$", []string{externalSelectionEnv + "=backblaze-b2"}, "B2_ACCESS_KEY_ID"},
		{"empty", "^TestConformanceGH353External$", []string{externalSelectionEnv + "="}, "invalid external provider selection"},
		{"partial", "^TestConformanceGH353External$", []string{externalSelectionEnv + "=backblaze-b2", "B2_ACCESS_KEY_ID=secret-canary"}, "B2_SECRET_ACCESS_KEY"},
		{"wasabi-missing", "^TestConformanceGH353External$", []string{externalSelectionEnv + "=wasabi"}, "WASABI_ACCESS_KEY_ID"},
		{"disabled", "^TestConformanceGH353External$", []string{externalSelectionEnv + "=wasabi", "GATEWAY_TEST_SKIP_EXTERNAL=1"}, "GATEWAY_TEST_SKIP_EXTERNAL"},
		{"unknown", "^TestConformanceGH353External$", []string{externalSelectionEnv + "=secret-canary"}, "invalid external provider selection"},
		{"duplicate", "^TestConformanceGH353External$", []string{externalSelectionEnv + "=backblaze-b2,backblaze-b2", "B2_ACCESS_KEY_ID=secret-canary", "B2_SECRET_ACCESS_KEY=secret-canary", "B2_BUCKET_NAME=fake"}, "duplicate"},
		{"filtered", "^TestGH353NoSuchTest$", []string{externalSelectionEnv + "=backblaze-b2", "B2_ACCESS_KEY_ID=secret-canary", "B2_SECRET_ACCESS_KEY=secret-canary", "B2_BUCKET_NAME=fake"}, "exact unfiltered"},
		{"local-positive-missing", "^TestConformanceLiteralPositiveProof$", nil, "mandatory literal positive fixture"},
		{"local-negative-missing", "^TestConformanceLiteralNativeRejection$", nil, "mandatory native rejection fixtures"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run="+tc.run, "-test.v")
			cmd.Env = append(append([]string{}, base...), tc.env...)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), tc.want) || strings.Contains(string(out), "secret-canary") {
				t.Fatalf("guard did not fail safely: %s", tc.name)
			}
		})
	}
}

func TestGH353RequiredCaseSkipFails(t *testing.T) {
	if os.Getenv("GH353_TEST_SKIP_CHILD") == "1" {
		requiredCase(t, "required", func(t *testing.T) { t.Skip("fixture unavailable") })
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestGH353RequiredCaseSkipFails$", "-test.v")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GH353_TEST_SKIP_CHILD=1", "GATEWAY_TEST_SKIP_EXTERNAL=1"}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "did not complete successfully") {
		t.Fatal("skipped mandatory case passed")
	}
}

func TestGH353MandatoryModeProcessGuards(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base := []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GATEWAY_TEST_SKIP_EXTERNAL=1"}
	for _, disabled := range []string{"GATEWAY_TEST_SKIP_MINIO=1", "GATEWAY_TEST_SKIP_RUSTFS=1"} {
		t.Run("native-one-missing-"+disabled, func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestConformanceLiteralNativeRejection$", "-test.v")
			cmd.Env = append(append([]string{}, base...), disabled)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "mandatory native rejection fixtures missing or ambiguous") {
				t.Fatal("missing mandatory native fixture passed")
			}
		})
	}
	t.Run("native-children-skipped", func(t *testing.T) {
		cmd := exec.Command(exe, "-test.run=^TestConformanceLiteralNativeRejection$", "-test.skip=^TestConformanceLiteralNativeRejection$/.", "-test.v")
		cmd.Env = base
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "mandatory native rejection scenario did not complete") {
			t.Fatal("skipped mandatory native children passed")
		}
	})
	for _, parent := range []string{"TestConformanceLiteralPositiveProof", "TestConformanceLiteralNativeRejection"} {
		t.Run(parent+"-filtered", func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^"+parent+"$/^not-selected$", "-test.v")
			cmd.Env = base
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "did not complete") {
				t.Fatal("filtered local mandatory proof passed")
			}
		})
	}
	t.Run("tagging-filtered", func(t *testing.T) {
		cmd := exec.Command(exe, "-test.run=^TestConformancePostUnsupportedTaggingProof$/^not-selected$", "-test.v")
		cmd.Env = base
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "did not complete") {
			t.Fatal("filtered mandatory tagging proof passed")
		}
	})
	t.Run("tagging-missing", func(t *testing.T) {
		cmd := exec.Command(exe, "-test.run=^TestConformancePostUnsupportedTaggingProof$", "-test.v")
		cmd.Env = append(append([]string{}, base...), "GATEWAY_TEST_SKIP_GARAGE=1")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "mandatory unsupported POST tagging fixture missing") {
			t.Fatal("missing mandatory tagging fixture passed")
		}
	})
	t.Run("runner-skipped", func(t *testing.T) {
		cmd := exec.Command(exe, "-test.run=^TestConformanceGH353External$", "-test.skip=^TestConformanceGH353External$", "-test.v")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), externalSelectionEnv + "=backblaze-b2", "B2_ACCESS_KEY_ID=fake", "B2_SECRET_ACCESS_KEY=fake", "B2_BUCKET_NAME=fake"}
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "required scenarios did not complete") {
			t.Fatal("skipped external runner passed")
		}
	})
	t.Run("runner-list-only", func(t *testing.T) {
		cmd := exec.Command(exe, "-test.run=^TestConformanceGH353External$", "-test.list=.")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), externalSelectionEnv + "=backblaze-b2", "B2_ACCESS_KEY_ID=fake", "B2_SECRET_ACCESS_KEY=fake", "B2_BUCKET_NAME=fake"}
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "cannot list") {
			t.Fatal("listing without execution passed")
		}
	})
	t.Run("skip-nested-required", func(t *testing.T) {
		cmd := exec.Command(exe, "-test.run=^TestConformanceGH353External$", "-test.skip=^TestConformanceGH353External$")
		cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), externalSelectionEnv + "=wasabi", "WASABI_ACCESS_KEY_ID=fake", "WASABI_SECRET_ACCESS_KEY=fake", "WASABI_BUCKET_NAME=fake"}
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "required scenarios did not complete") {
			t.Fatal("skipped provider runner passed")
		}
	})
	t.Run("full-mode-filtered", func(t *testing.T) {
		cmd := exec.Command(exe, "-test.run=^TestConformanceLiteralPositiveProof$")
		cmd.Env = append(append([]string{}, base...), "GATEWAY_TEST_CONFORMANCE_EXTERNAL_ONLY=1", "GATEWAY_TEST_SKIP_MINIO=1", "GATEWAY_TEST_SKIP_GARAGE=1", "GATEWAY_TEST_SKIP_RUSTFS=1", "GATEWAY_TEST_SKIP_SEAWEEDFS=1")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "does not accept filtered") {
			t.Fatal("filtered full external mode passed")
		}
	})
}

func TestGH353ExternalModeExcludesLocalProofs(t *testing.T) {
	t.Setenv("GATEWAY_TEST_CONFORMANCE_EXTERNAL_ONLY", "1")
	for _, tc := range []struct {
		name string
		fn   func(*testing.T)
	}{{"positive", TestConformanceLiteralPositiveProof}, {"negative", TestConformanceLiteralNativeRejection}, {"tagging", TestConformancePostUnsupportedTaggingProof}} {
		completed := false
		if !t.Run(tc.name, func(t *testing.T) { tc.fn(t); completed = true }) || completed {
			t.Fatal("local proof was not explicitly skipped in external mode")
		}
	}
}

func TestGH353ExternalCleanupSkipsUnregistered(t *testing.T) {
	// A wrong-policy implementation would try to connect to this deliberately
	// invalid endpoint; no network operation is authorized for unknown owners.
	cleanupPostObject(t, provider.Instance{ProviderName: "not-registered", Endpoint: "://invalid"}, "owned")
}

func TestGH353ExternalFixtureProfileIdentity(t *testing.T) {
	inst := provider.Instance{ProviderName: "fixture-provider", Endpoint: "https://fixture.invalid", Region: "fixture-region", Bucket: "fixture-bucket", AccessKey: "fixture-access", SecretKey: "fixture-secret"}
	got := gh353ExternalFixture(inst)
	if got.GH353MetadataProfile != "compact" || got.ProviderName != inst.ProviderName || got.Endpoint != inst.Endpoint || got.Region != inst.Region || got.Bucket != inst.Bucket || got.AccessKey != inst.AccessKey || got.SecretKey != inst.SecretKey {
		t.Fatal("fixture changed backend identity")
	}
}

func TestGH353GarageTaggingFixturePolicy(t *testing.T) {
	providers := provider.GH353UnsupportedTaggingProofProviders()
	if len(providers) != 1 || providers[0].Capabilities()&provider.CapInlinePutTagging == 0 || provider.GH353PostInlineTagging(provider.Instance{ProviderName: providers[0].Name()}) != "unsupported" {
		t.Fatal("mandatory provider-owned tagging policy unavailable")
	}
}
