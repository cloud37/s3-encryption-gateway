package ci

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func parseSuppressionComment(line string) (string, string, error) {
	directive := regexp.MustCompile(`^//\s*(?:#nosec|gosec:disable)\s+((?:G\d{3}\s*)+)--\s*(.+)$`)
	match := directive.FindStringSubmatch(line)
	if match == nil || strings.TrimSpace(match[2]) == "" || strings.Count(line, "#nosec")+strings.Count(line, "gosec:disable") != 1 {
		return "", "", fmt.Errorf("requires one directive, rule IDs and a nonempty -- reason")
	}
	rule := regexp.MustCompile(`G\d{3}`)
	ids := rule.FindAllString(match[1], -1)
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return "", "", fmt.Errorf("duplicate rule %s", id)
		}
		seen[id] = true
	}
	return strings.Join(ids, ", "), strings.TrimSpace(match[2]), nil
}

func TestSuppressionCommentRejectsMalformedDirectives(t *testing.T) {
	for _, line := range []string{
		"// #nosec G115 --   ",
		"// #nosec -- missing rule; #nosec G115 -- valid reason",
		"// #nosec G115 G115 -- duplicated rule",
		"// #nosec G115 -- reason; #nosec G402 -- second directive",
		"// #nosec G115",
	} {
		if _, _, err := parseSuppressionComment(line); err == nil {
			t.Errorf("accepted malformed directive %q", line)
		}
	}
	for _, line := range []string{"// #nosec G115 -- bounded value", "//gosec:disable G115 G402 -- explicit reviewed scope"} {
		if _, _, err := parseSuppressionComment(line); err != nil {
			t.Fatal(err)
		}
	}
}

// Check every source file, independent of build tags and scanner severity.
// This prevents a stale inventory or broad annotations from silently returning.
func TestGosecSuppressionInventory(t *testing.T) {
	root := filepath.Join("..", "..")
	var rows []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, data, parser.ParseComments)
		if err != nil {
			return err
		}
		for _, group := range file.Comments {
			for _, comment := range group.List {
				line := comment.Text
				index := fset.Position(comment.Pos()).Line - 1
				if strings.Contains(line, "nolint:") && strings.Contains(line, "gosec") {
					t.Errorf("%s:%d uses a broad linter suppression", rel, index+1)
				}
				if !strings.Contains(line, "#nosec") && !strings.Contains(line, "gosec:disable") {
					continue
				}
				if !strings.HasPrefix(line, "//") || strings.Contains(line, "\n") {
					t.Errorf("%s:%d requires a single-line suppression comment", rel, index+1)
					continue
				}
				rules, explanation, err := parseSuppressionComment(line)
				if err != nil {
					t.Errorf("%s:%d: %v", rel, index+1, err)
					continue
				}
				scope := "Production"
				if strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(filepath.ToSlash(rel), "test/") {
					scope = "Test fixture"
				}
				reason := strings.ReplaceAll(strings.ReplaceAll(explanation, "|", `\|`), "`", "'")
				rows = append(rows, fmt.Sprintf("| `%s:%d` | %s | %s | %s |", filepath.ToSlash(rel), index+1, rules, scope, reason))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "docs", "security", "gosec-suppressions.md"))
	if err != nil {
		t.Fatal(err)
	}
	start := "<!-- BEGIN GENERATED GOSEC SUPPRESSIONS -->"
	end := "<!-- END GENERATED GOSEC SUPPRESSIONS -->"
	if strings.Count(string(data), start) != 1 || strings.Count(string(data), end) != 1 {
		t.Fatal("documentation must contain exactly one generated inventory section")
	}
	_, tail, ok := strings.Cut(string(data), start)
	if !ok {
		t.Fatal("missing inventory start marker")
	}
	actual, _, ok := strings.Cut(tail, end)
	if !ok {
		t.Fatal("missing inventory end marker")
	}
	expected := "\n| Source location | Rules | Scope | Verified justification / precondition |\n|---|---|---|---|\n" + strings.Join(rows, "\n") + "\n"
	if actual != expected {
		t.Fatal("suppression inventory is stale or incomplete; review source then run python3 scripts/gosec-suppressions.py --write")
	}
}
