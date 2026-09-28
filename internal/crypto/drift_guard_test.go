package crypto

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDriftGuard_CryptoMetaLiterals(t *testing.T) {
	aliases := map[string]bool{}
	for _, alias := range CompactAliases() {
		aliases[alias] = true
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "metakeys.go" {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		var allowed [][2]token.Pos
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				values, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				containsMetaName := false
				for _, ident := range values.Names {
					if strings.HasPrefix(ident.Name, "Meta") {
						containsMetaName = true
						break
					}
				}
				if containsMetaName {
					allowed = append(allowed, [2]token.Pos{values.Pos(), values.End()})
				}
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			lower := strings.ToLower(value)
			inAllowedConst := false
			for _, span := range allowed {
				if literal.Pos() >= span[0] && literal.End() <= span[1] {
					inAllowedConst = true
					break
				}
			}
			registeredAlias := strings.HasPrefix(lower, "x-amz-meta-") && aliases[lower]
			if !inAllowedConst && (strings.HasPrefix(lower, "x-amz-meta-enc") || strings.HasPrefix(lower, "x-amz-meta-encrypt") || registeredAlias) {
				t.Errorf("%s:%d declares gateway metadata literal %q outside registry/constants", path, fset.Position(literal.Pos()).Line, value)
			}
			return true
		})
	}
}

func TestDriftGuard_CryptoMPUMarkerComparisonsOwnedByClassifier(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				binary, ok := node.(*ast.BinaryExpr)
				if !ok || (binary.Op != token.EQL && binary.Op != token.NEQ) {
					return true
				}
				for _, side := range []ast.Expr{binary.X, binary.Y} {
					index, ok := side.(*ast.IndexExpr)
					if !ok {
						continue
					}
					selector, ok := index.Index.(*ast.SelectorExpr)
					if ok && selector.Sel.Name == "MetaMPUEncrypted" && (name != "object_format.go" || function.Name.Name != "ClassifyObject") {
						t.Errorf("%s:%d compares MetaMPUEncrypted outside ClassifyObject", path, fset.Position(binary.Pos()).Line)
					}
				}
				return true
			})
		}
	}
}
