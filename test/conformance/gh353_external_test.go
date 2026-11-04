//go:build conformance

package conformance

import (
	"context"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

const externalSelectionEnv = "GATEWAY_TEST_GH353_EXTERNAL"

var externalCompleted bool
var fullExternalCompleted bool

func externalOnlyMode() bool {
	return os.Getenv("GATEWAY_TEST_CONFORMANCE_EXTERNAL_ONLY") == "1"
}

func TestMain(m *testing.M) {
	flag.Parse()
	selection, selected := os.LookupEnv(externalSelectionEnv)
	if externalOnlyMode() {
		for _, name := range []string{"GATEWAY_TEST_SKIP_MINIO", "GATEWAY_TEST_SKIP_GARAGE", "GATEWAY_TEST_SKIP_RUSTFS", "GATEWAY_TEST_SKIP_SEAWEEDFS"} {
			if os.Getenv(name) == "" {
				fmt.Fprintln(os.Stderr, "external-only mode requires", name)
				os.Exit(1)
			}
		}
	}
	if value := os.Getenv("GATEWAY_TEST_CONFORMANCE_EXTERNAL_ONLY"); value != "" && value != "1" {
		fmt.Fprintln(os.Stderr, "invalid external-only mode")
		os.Exit(1)
	}
	if externalOnlyMode() && flag.Lookup("test.run").Value.String() != "" {
		fmt.Fprintln(os.Stderr, "full external mode does not accept filtered tests")
		os.Exit(1)
	}
	if selected {
		if externalOnlyMode() {
			fmt.Fprintln(os.Stderr, "focused and full external modes cannot be combined")
			os.Exit(1)
		}
		if _, err := provider.GH353ExternalPreflight(selection, os.Getenv, provider.All()); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if flag.Lookup("test.run").Value.String() != "^TestConformanceGH353External$" {
			fmt.Fprintln(os.Stderr, "external GH-353 mode requires the exact unfiltered runner selection")
			os.Exit(1)
		}
	}
	if f := flag.Lookup("test.list"); (selected || externalOnlyMode()) && f != nil && f.Value.String() != "" {
		fmt.Fprintln(os.Stderr, "external mode cannot list without running scenarios")
		os.Exit(1)
	}
	code := m.Run()
	if selected && !externalCompleted {
		fmt.Fprintln(os.Stderr, "external GH-353 required scenarios did not complete")
		code = 1
	}
	if externalOnlyMode() && !fullExternalCompleted {
		fmt.Fprintln(os.Stderr, "full external conformance did not complete")
		code = 1
	}
	os.Exit(code)
}

// requiredCase fails if Go's filter or SkipNow prevents the body completing.
func requiredCase(t *testing.T, name string, fn func(*testing.T)) {
	t.Helper()
	completed := false
	ok := t.Run(name, func(t *testing.T) {
		fn(t)
		completed = true
	})
	if !ok || !completed {
		t.Errorf("required scenario %s did not complete successfully", name)
	}
}

func runPostCase(t *testing.T, name string, fn func(*testing.T)) {
	if _, selected := os.LookupEnv(externalSelectionEnv); selected {
		requiredCase(t, name, fn)
		return
	}
	t.Run(name, fn)
}

func gh353ExternalFixture(inst provider.Instance) provider.Instance {
	inst.GH353MetadataProfile = "compact"
	return inst
}

func TestConformanceGH353External(t *testing.T) {
	selection, selected := os.LookupEnv(externalSelectionEnv)
	if !selected {
		t.Skip("explicit external GH-353 selection not requested")
	}
	if os.Getenv("GATEWAY_TEST_CONFORMANCE_EXTERNAL_ONLY") != "" {
		t.Fatal("focused external mode conflicts with full external mode")
	}
	providers, err := provider.GH353ExternalPreflight(selection, os.Getenv, provider.All())
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range providers {
		p := p
		requiredCase(t, p.Name(), func(t *testing.T) {
			inst := p.Start(provider.WithOwnedKeyCleanup(context.Background()), t)
			if inst.ProviderName != p.Name() || inst.Endpoint == "" || inst.Region == "" || inst.Bucket == "" || inst.AccessKey == "" || inst.SecretKey == "" {
				t.Fatal("requested external provider fixture is incomplete")
			}
			if policy, known := provider.CleanupPolicyForInstance(inst); !known || policy != p.CleanupPolicy() {
				t.Fatal("requested external provider cleanup policy is unavailable")
			}
			inst = gh353ExternalFixture(inst)
			for _, tc := range []struct {
				name string
				fn   func(*testing.T, provider.Instance)
			}{
				{"RoundTrip", testPostObjectRoundTrip},
				{"RejectPreservesExisting", testPostObjectRejectPreservesExisting},
				{"SessionAndExpiry", testPostObjectSessionAndExpiry},
				{"Responses", testPostObjectResponses},
				{"Literal201Inventory", testLiteralPositive201},
				{"Boto3Static", func(t *testing.T, i provider.Instance) { testCompatPresignedPostSDK(t, i, "boto3", false) }},
				{"Boto3Session", func(t *testing.T, i provider.Instance) { testCompatPresignedPostSDK(t, i, "boto3", true) }},
				{"AWSJSStatic", func(t *testing.T, i provider.Instance) { testCompatPresignedPostSDK(t, i, "aws-js", false) }},
				{"AWSJSSession", func(t *testing.T, i provider.Instance) { testCompatPresignedPostSDK(t, i, "aws-js", true) }},
				{"BrowserStatic", func(t *testing.T, i provider.Instance) { testCompatBrowserPostMode(t, i, false) }},
				{"BrowserSession", func(t *testing.T, i provider.Instance) { testCompatBrowserPostMode(t, i, true) }},
			} {
				tc := tc
				requiredCase(t, tc.name, func(t *testing.T) { tc.fn(t, inst) })
			}
			// External focused feedback never creates buckets. Exercise tagging and
			// ACL where advertised, without the separately bucket-owning version test.
			t.Run("OptionalTaggingACL", func(t *testing.T) { testPostObjectTaggingACLVersion(t, inst) })
		})
	}
	if !t.Failed() {
		externalCompleted = true
	}
}
