package ci

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHelmWorkflow_OCIPublishIsReleaseOnly(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "helm.yml"))
	if err != nil {
		t.Fatal(err)
	}

	var workflow yaml.Node
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("helm workflow is not valid YAML: %v", err)
	}
	root := workflow.Content[0]
	jobs := mappingValue(root, "jobs")
	if jobs == nil {
		t.Fatal("workflow has no jobs")
	}
	release := mappingValue(jobs, "release")
	if release == nil {
		t.Fatal("workflow has no release job")
	}
	if got := scalarValue(mappingValue(release, "if")); got != "github.event_name == 'push' && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/master')" {
		t.Fatalf("release job is not push-only: %q", got)
	}

	permissions := mappingValue(release, "permissions")
	if scalarValue(mappingValue(permissions, "packages")) != "write" || scalarValue(mappingValue(permissions, "id-token")) != "write" {
		t.Fatal("release job must grant packages: write and id-token: write")
	}
	for _, job := range mappingKeys(jobs) {
		if job == "release" {
			continue
		}
		permissions := mappingValue(mappingValue(jobs, job), "permissions")
		if mappingValue(permissions, "packages") != nil || mappingValue(permissions, "id-token") != nil {
			t.Fatalf("non-release job %q grants publishing permissions", job)
		}
	}

	steps := sequenceValue(mappingValue(release, "steps"))
	wantOCI := []string{"helm registry login", "helm push", "cosign sign"}
	for _, marker := range wantOCI {
		found := false
		for _, step := range steps {
			run := scalarValue(mappingValue(step, "run"))
			if strings.Contains(run, marker) {
				found = true
				if scalarValue(mappingValue(step, "if")) != "steps.version_check.outputs.already_released == 'false'" {
					t.Fatalf("OCI step containing %q is not release-gated", marker)
				}
			}
		}
		if !found {
			t.Fatalf("release job is missing OCI step containing %q", marker)
		}
	}

	for _, job := range mappingKeys(jobs) {
		if job == "release" {
			continue
		}
		for _, step := range sequenceValue(mappingValue(mappingValue(jobs, job), "steps")) {
			run := scalarValue(mappingValue(step, "run"))
			if strings.Contains(run, "helm registry login") || strings.Contains(run, "helm push") || strings.Contains(run, "cosign sign") {
				t.Fatalf("non-release job %q contains an OCI publishing step", job)
			}
		}
	}
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func scalarValue(node *yaml.Node) string {
	if node == nil || node.Kind != yaml.ScalarNode {
		return ""
	}
	return node.Value
}

func sequenceValue(node *yaml.Node) []*yaml.Node {
	if node == nil || node.Kind != yaml.SequenceNode {
		return nil
	}
	return node.Content
}

func mappingKeys(node *yaml.Node) []string {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	keys := make([]string, 0, len(node.Content)/2)
	for i := 0; i+1 < len(node.Content); i += 2 {
		keys = append(keys, node.Content[i].Value)
	}
	return keys
}
