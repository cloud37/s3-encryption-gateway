package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func productionGoFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		files = append(files, filepath.Join(".", entry.Name()))
	}
	return files
}

func TestProductionDriftGuards(t *testing.T) {
	for _, path := range productionGoFiles(t) {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(src)
		for _, forbidden := range []string{"readMPUManifestTotalPlainSize", "forwardSignatureV4Request", "func isEncryptionMetadata", "func filterS3Metadata", "func decryptedSizeForMPU"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s contains forbidden production duplicate %q", path, forbidden)
			}
		}
		if strings.Contains(text, "sizeCache.Set(") && !strings.Contains(filepath.Base(path), "size_record.go") {
			t.Errorf("%s writes plaintext size cache outside recordPlaintextSize", path)
		}
		if _, err := parser.ParseFile(token.NewFileSet(), path, src, 0); err != nil {
			t.Errorf("%s does not parse: %v", path, err)
		}
	}
}

func TestGH353DriftGuard_SharedWriteAndSecretOwnership(t *testing.T) {
	files := make(map[string]*ast.File)
	for _, path := range productionGoFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files[filepath.Base(path)] = file
	}
	function := func(file string, name string) *ast.FuncDecl {
		if files[file] == nil {
			return nil
		}
		for _, declaration := range files[file].Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok && fn.Name.Name == name {
				return fn
			}
		}
		return nil
	}
	put, post := function("handlers.go", "handlePutObject"), function("post_object.go", "handlePostObject")
	if put == nil || post == nil {
		t.Fatal("ordinary PUT or POST handler is missing")
	}
	countCalls := func(node ast.Node, name string) int {
		count := 0
		ast.Inspect(node, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				switch function := call.Fun.(type) {
				case *ast.Ident:
					if function.Name == name {
						count++
					}
				case *ast.SelectorExpr:
					if function.Sel.Name == name {
						count++
					}
				}
			}
			return true
		})
		return count
	}
	if countCalls(put.Body, "putObjectData") != 1 || countCalls(post.Body, "putObjectData") != 1 {
		t.Fatalf("ordinary PUT and POST must each call shared putObjectData exactly once (PUT=%d POST=%d)", countCalls(put.Body, "putObjectData"), countCalls(post.Body, "putObjectData"))
	}
	postSuccess := function("post_response.go", "writePostSuccess")
	postProjector := function("object_response.go", "projectPostResponseHeaders")
	writeProjector := function("object_response.go", "projectObjectWriteHeaders")
	if countCalls(post.Body, "writePostSuccess") != 1 || postSuccess == nil || postProjector == nil || writeProjector == nil {
		t.Fatal("POST response headers/version projection must flow through the closed response owners")
	}
	if !postResponseOwnershipIntact(postSuccess, postProjector, writeProjector, countCalls) {
		t.Fatal("POST response owner chain must be writePostSuccess -> projectPostResponseHeaders -> projectObjectWriteHeaders")
	}
	if countCalls(put.Body, "writeObjectHeaders") != 1 || countCalls(put.Body, "projectObjectWriteHeaders") != 1 || countCalls(postSuccess.Body, "writeObjectHeaders") == 0 {
		t.Fatal("ordinary PUT and POST response paths must use the closed object-header writer")
	}
	for name, file := range map[string]*ast.File{"handlers.go": files["handlers.go"], "post_object.go": files["post_object.go"], "object_put.go": files["object_put.go"]} {
		if writes := rawCustomerKeyPersistenceWrites(file); writes != 0 {
			t.Errorf("%s contains %d raw customer-key persistence writes", name, writes)
		}
	}
	if hasDirectResponseWriteBypass(put.Body) || hasDirectResponseWriteBypass(post.Body) {
		t.Fatal("production PUT or POST handler contains a direct response-header/customer-key ownership bypass")
	}

	for _, fixture := range []string{
		`package fixture
func bad(h http.ResponseWriter) { headers := h.Header(); alias := headers; alias.Set("x-amz-version-id", "v") }`,
		`package fixture
func bad(metadata map[string]string, key []byte) { metadata["x-amz-server-side-encryption-customer-key"] = string(key) }`,
		`package fixture
func bad(h http.ResponseWriter) { headers := h.Header(); headers["ETag"] = []string{"x"} }`,
	} {
		parsed, err := parser.ParseFile(token.NewFileSet(), "fixture.go", fixture, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !driftGuardFixtureRejectsSharedOwnershipBypass(parsed) {
			t.Errorf("drift guard missed synthetic ownership bypass: %s", fixture)
		}
	}
	for _, fixture := range []struct {
		name, source string
	}{
		{"good pipeline", `package fixture
func writePostSuccess(h http.ResponseWriter) { headers := projectPostResponseHeaders(); writeObjectHeaders(h, headers) }
func projectPostResponseHeaders() http.Header { return projectObjectWriteHeaders() }
func projectObjectWriteHeaders() http.Header { return nil }
func writeObjectHeaders(http.ResponseWriter, http.Header) {}`},
		{"missing common writer", `package fixture
func writePostSuccess(h http.ResponseWriter) { h.Header().Set("ETag", "unsafe") }
func projectPostResponseHeaders() http.Header { return nil }
func projectObjectWriteHeaders() http.Header { return nil }
func writeObjectHeaders(http.ResponseWriter, http.Header) {}`},
		{"missing shared projection", `package fixture
func writePostSuccess(h http.ResponseWriter) { writeObjectHeaders(h, http.Header{}) }
func projectPostResponseHeaders() http.Header { return nil }
func projectObjectWriteHeaders() http.Header { return nil }
func writeObjectHeaders(http.ResponseWriter, http.Header) {}`},
	} {
		parsed, err := parser.ParseFile(token.NewFileSet(), fixture.name+".go", fixture.source, 0)
		if err != nil {
			t.Fatal(err)
		}
		functions := make(map[string]*ast.FuncDecl)
		for _, declaration := range parsed.Decls {
			if fn, ok := declaration.(*ast.FuncDecl); ok {
				functions[fn.Name.Name] = fn
			}
		}
		got := postResponseOwnershipIntact(functions["writePostSuccess"], functions["projectPostResponseHeaders"], functions["projectObjectWriteHeaders"], countASTCalls) && !driftGuardFixtureRejectsSharedOwnershipBypass(parsed)
		if got != (fixture.name == "good pipeline") {
			t.Errorf("same production guard for %s = %t", fixture.name, got)
		}
	}
}

func hasDirectResponseWriteBypass(node ast.Node) bool {
	bad := false
	ast.Inspect(node, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if callMethod(call, "Set") && len(call.Args) > 0 {
			if key, known := headerWriteKey(call.Args[0]); known && (strings.EqualFold(key, "ETag") || strings.EqualFold(key, "x-amz-version-id") || strings.EqualFold(key, "x-amz-server-side-encryption-customer-key")) {
				bad = true
			}
		}
		return true
	})
	return bad
}

func countASTCalls(node ast.Node, name string) int {
	count := 0
	ast.Inspect(node, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			switch function := call.Fun.(type) {
			case *ast.Ident:
				if function.Name == name {
					count++
				}
			case *ast.SelectorExpr:
				if function.Sel.Name == name {
					count++
				}
			}
		}
		return true
	})
	return count
}

func postResponseOwnershipIntact(success, postProjector, writeProjector *ast.FuncDecl, countCalls func(ast.Node, string) int) bool {
	return success != nil && postProjector != nil && writeProjector != nil &&
		countCalls(success.Body, "projectPostResponseHeaders") > 0 &&
		countCalls(success.Body, "writeObjectHeaders") > 0 &&
		countCalls(postProjector.Body, "projectObjectWriteHeaders") > 0
}

func driftGuardFixtureRejectsSharedOwnershipBypass(file *ast.File) bool {
	aliases := responseHeaderAliases(file)
	bad := false
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if index, ok := lhs.(*ast.IndexExpr); ok {
					key, known := headerWriteKey(index.Index)
					if isResponseHeaderMapIndex(index, aliases) && (!known || key == "ETag" || key == "x-amz-version-id") {
						bad = true
					}
					if known && strings.EqualFold(key, "x-amz-server-side-encryption-customer-key") {
						bad = true
					}
				}
			}
		case *ast.CallExpr:
			if callMethod(n, "Set") && len(n.Args) > 0 {
				key, known := headerWriteKey(n.Args[0])
				if isResponseHeaderReceiverOrAlias(callReceiver(n), aliases) && (!known || key == "ETag" || key == "x-amz-version-id") {
					bad = true
				}
				if known && strings.EqualFold(key, "x-amz-server-side-encryption-customer-key") {
					bad = true
				}
			}
		}
		return true
	})
	return bad
}

func callMethod(call *ast.CallExpr, name string) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == name
}

func callReceiver(call *ast.CallExpr) ast.Expr {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	return selector.X
}

func rawCustomerKeyPersistenceWrites(file *ast.File) int {
	if file == nil {
		return 0
	}
	writes := 0
	ast.Inspect(file, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok {
			for _, target := range assignment.Lhs {
				if index, ok := target.(*ast.IndexExpr); ok {
					if key, known := headerWriteKey(index.Index); known && strings.EqualFold(key, "x-amz-server-side-encryption-customer-key") {
						writes++
					}
				}
			}
		}
		if call, ok := node.(*ast.CallExpr); ok && callMethod(call, "Set") && len(call.Args) > 0 {
			if key, known := headerWriteKey(call.Args[0]); known && strings.EqualFold(key, "x-amz-server-side-encryption-customer-key") {
				writes++
			}
		}
		return true
	})
	return writes
}

func TestDriftGuard_OwnershipFixtureDetectsS3ErrorAndRequestMetric(t *testing.T) {
	source := `package fixture
type Metrics struct{}
func (*Metrics) RecordS3Error() {}
func (*Metrics) RecordHTTPRequest() {}
func bad(m *Metrics) {
	if false && m.RecordS3Error() {}
	m.RecordHTTPRequest()
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := map[string]*ast.FuncDecl{}
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	var records, requests int
	ast.Inspect(functions["bad"].Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isSelectorCall(call, "RecordS3Error") {
			records++
		}
		if isSelectorCall(call, "RecordHTTPRequest") {
			requests++
		}
		return true
	})
	if records != 1 || requests != 1 {
		t.Fatalf("AST fixture counts RecordS3Error=%d RecordHTTPRequest=%d", records, requests)
	}
}

func TestDriftGuard_ProductionObjectErrorsHaveSingleOwner(t *testing.T) {
	objectHandlers := map[string]bool{
		"handleGetObject": true, "handlePutObject": true, "handleDeleteObject": true, "handleHeadObject": true,
		"handleCopyObject": true, "handleDeleteObjects": true, "handleCreateMultipartUpload": true,
		"handleUploadPart": true, "handleCompleteMultipartUpload": true, "handleAbortMultipartUpload": true,
		"handleUploadPartCopy": true, "serveMPURangedGet": true, "serveMPURangedGetPlanned": true,
		"handleListParts": true, "writeS3ClientError": true, "writeMissingMPUState": true, "writeChunkedCompletenessError": true,
		"handlePostObject": true,
	}
	for _, path := range productionGoFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || !objectHandlers[function.Name.Name] || filepath.Base(path) == "object_errors.go" || filepath.Base(path) == "auth_middleware.go" {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if selector.Sel.Name == "WriteXML" {
					t.Errorf("%s.%s writes object error inline; use writeObjectError", filepath.Base(path), function.Name.Name)
				}
				if selector.Sel.Name == "RecordHTTPRequest" && !isAllowedFinalSuccessMetric(function, call) || selector.Sel.Name == "RecordS3Error" {
					t.Errorf("%s.%s records error metrics inline; use writeObjectError", filepath.Base(path), function.Name.Name)
				}
				decryptMetric := selector.Sel.Name == "RecordEncryptionError" && len(call.Args) > 1 && stringLiteral(call.Args[0]) == "decrypt"
				if decryptMetric || selector.Sel.Name == "LogDecrypt" || selector.Sel.Name == "recordObjectIntegrityFailure" || selector.Sel.Name == "recordObjectStreamFailure" {
					t.Errorf("%s.%s records integrity/decrypt accounting inline; use shared object accounting owner", filepath.Base(path), function.Name.Name)
				}
				return true
			})
		}
	}
}

func TestDriftGuard_ObjectErrorOwnershipFixtureDetectsUnreachableMetrics(t *testing.T) {
	source := `package fixture
func bad(metrics *Metrics) {
	if false && metrics.RecordS3Error(ctx, op, bucket, code) {}
	metrics.RecordHTTPRequest(ctx, method, path, status, elapsed, bytes)
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var s3Errors, httpRequests int
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if isSelectorCall(call, "RecordS3Error") {
			s3Errors++
		}
		if isSelectorCall(call, "RecordHTTPRequest") {
			httpRequests++
		}
		return true
	})
	if s3Errors != 1 || httpRequests != 1 {
		t.Fatalf("guard AST calls s3=%d http=%d", s3Errors, httpRequests)
	}
}

func stringLiteral(expr ast.Expr) string {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return ""
	}
	value, _ := strconv.Unquote(lit.Value)
	return value
}

func TestDriftGuard_APIResponseHeaderWriters(t *testing.T) {
	expectedCORSHeaders := map[string]struct{}{
		"Access-Control-Allow-Origin":      {},
		"Access-Control-Allow-Methods":     {},
		"Access-Control-Allow-Headers":     {},
		"Access-Control-Expose-Headers":    {},
		"Access-Control-Max-Age":           {},
		"Access-Control-Allow-Credentials": {},
	}
	// Keep this independent expected set exact: positive membership checks alone
	// would not detect an extra production registry entry.
	if len(corsOwnedResponseHeaderNames) != len(expectedCORSHeaders) {
		t.Fatalf("CORS response-header registry has %d entries, want exactly %d", len(corsOwnedResponseHeaderNames), len(expectedCORSHeaders))
	}
	registeredCORSHeaders := make(map[string]struct{}, len(corsOwnedResponseHeaderNames))
	for _, name := range corsOwnedResponseHeaderNames {
		registeredCORSHeaders[name] = struct{}{}
	}
	if len(registeredCORSHeaders) != len(expectedCORSHeaders) {
		t.Fatalf("CORS response-header registry contains duplicate entries: %v", corsOwnedResponseHeaderNames)
	}
	for name := range expectedCORSHeaders {
		if _, ok := registeredCORSHeaders[name]; !ok {
			t.Errorf("CORS response-header registry is missing %q", name)
		}
	}
	for name := range registeredCORSHeaders {
		if _, ok := expectedCORSHeaders[name]; !ok {
			t.Errorf("CORS response-header registry contains unexpected name %q", name)
		}
	}
	for name := range expectedCORSHeaders {
		if !isOwnedCORSResponseHeader(name) {
			t.Errorf("expected gateway CORS response header %q to be registered", name)
		}
	}
	for _, name := range []string{"Access-Control-Allow-Private-Network", "Content-Type", "ETag", "X-Arbitrary"} {
		if isOwnedCORSResponseHeader(name) {
			t.Errorf("arbitrary/non-CORS response header %q unexpectedly has CORS owner permission", name)
		}
	}
	for _, path := range productionGoFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(path) == "utils.go" || filepath.Base(path) == "auth_middleware.go" {
			continue
		}
		aliases := responseHeaderAliases(file)
		ast.Inspect(file, func(node ast.Node) bool {
			if assignment, ok := node.(*ast.AssignStmt); ok {
				for _, lhs := range assignment.Lhs {
					if index, ok := lhs.(*ast.IndexExpr); ok && isResponseHeaderMapIndex(index, aliases) {
						key, ok := headerWriteKey(index.Index)
						if filepath.Base(path) == "cors_response_headers.go" && corsOwnerMapWriteIsInvalid(path, index, aliases) {
							t.Errorf("%s writes an unregistered or dynamic gateway CORS response header", path)
						} else if filepath.Base(path) != "cors_response_headers.go" && filepath.Base(path) != "object_response.go" && (!ok || key == "Content-Length" || key == "Content-Range" || key == "ETag" || key == "x-amz-version-id") {
							t.Errorf("%s assigns owned or dynamic object response header outside object_response.go", path)
						}
					}
				}
			}
			if inc, ok := node.(*ast.IncDecStmt); ok {
				if index, ok := inc.X.(*ast.IndexExpr); ok && isResponseHeaderMapIndex(index, aliases) {
					t.Errorf("%s mutates response headers through an increment/decrement", path)
				}
			}
			if unary, ok := node.(*ast.UnaryExpr); ok && unary.Op == token.AND {
				if index, ok := unary.X.(*ast.IndexExpr); ok && isResponseHeaderMapIndex(index, aliases) && filepath.Base(path) != "object_response.go" {
					t.Errorf("%s takes a mutable response header map entry address", path)
				}
			}
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name != "Set" && selector.Sel.Name != "Del" && selector.Sel.Name != "Add" {
				return true
			}
			if !isResponseHeaderReceiverOrAlias(selector.X, aliases) {
				return true
			}
			value, ok := headerWriteKey(call.Args[0])
			if !ok {
				if filepath.Base(path) != "object_response.go" {
					t.Errorf("%s writes a dynamic response header name outside object_response.go", path)
				}
				return true
			}
			if filepath.Base(path) == "cors_response_headers.go" {
				if !isOwnedCORSResponseHeader(value) {
					t.Errorf("%s writes unregistered gateway CORS response header %q", filepath.Base(path), value)
				}
				return true
			}
			switch value {
			case "Content-Length", "Content-Range", "ETag", "x-amz-version-id":
				if filepath.Base(path) != "object_response.go" {
					t.Errorf("%s writes object response header %q outside object_response.go", path, value)
				}
			}
			return true
		})
	}
}

func TestDriftGuard_CORSOwnerRejectsUnregisteredMapWrites(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		invalid bool
	}{
		{name: "arbitrary literal", key: `"X-Arbitrary"`, invalid: true},
		{name: "private network literal", key: `"Access-Control-Allow-Private-Network"`, invalid: true},
		{name: "dynamic key", key: "name", invalid: true},
		{name: "allow origin", key: `"Access-Control-Allow-Origin"`},
		{name: "allow methods", key: `"Access-Control-Allow-Methods"`},
		{name: "allow headers", key: `"Access-Control-Allow-Headers"`},
		{name: "expose headers", key: `"Access-Control-Expose-Headers"`},
		{name: "max age", key: `"Access-Control-Max-Age"`},
		{name: "allow credentials", key: `"Access-Control-Allow-Credentials"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := `package api
import "net/http"
func owner(headers http.Header, name string) {
	headers[` + test.key + `] = []string{"value"}
}`
			file, err := parser.ParseFile(token.NewFileSet(), "cors_response_headers.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			aliases := responseHeaderAliases(file)
			var invalidWrites int
			ast.Inspect(file, func(node ast.Node) bool {
				assignment, ok := node.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assignment.Lhs {
					index, ok := lhs.(*ast.IndexExpr)
					if ok && isResponseHeaderMapIndex(index, aliases) && corsOwnerMapWriteIsInvalid("cors_response_headers.go", index, aliases) {
						invalidWrites++
					}
				}
				return true
			})
			if got := invalidWrites != 0; got != test.invalid {
				t.Fatalf("owner map write invalid=%t, want %t", got, test.invalid)
			}
		})
	}
}

func corsOwnerMapWriteIsInvalid(path string, index *ast.IndexExpr, aliases map[string]bool) bool {
	if filepath.Base(path) != "cors_response_headers.go" || !isResponseHeaderMapIndex(index, aliases) {
		return false
	}
	key, known := headerWriteKey(index.Index)
	return !known || !isOwnedCORSResponseHeader(key)
}

func TestDriftGuard_IntentionalHeaderOwnershipViolationDetected(t *testing.T) {
	source := `package fixture
import "net/http"
func bad(w http.ResponseWriter, responseHeaders http.Header, key string) {
	w.Header().Set(key, "dynamic")
	responseHeaders["ETag"] = []string{"bad"}
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	aliases := responseHeaderAliases(file)
	var dynamicSet, ownedMapWrite int
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && len(call.Args) > 0 {
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Set" && isResponseHeaderReceiverOrAlias(selector.X, aliases) {
				if _, ok := headerWriteKey(call.Args[0]); !ok {
					dynamicSet++
				}
			}
		}
		if assignment, ok := node.(*ast.AssignStmt); ok {
			for _, lhs := range assignment.Lhs {
				if index, ok := lhs.(*ast.IndexExpr); ok && isResponseHeaderMapIndex(index, aliases) {
					if key, ok := headerWriteKey(index.Index); ok && key == "ETag" {
						ownedMapWrite++
					}
				}
			}
		}
		return true
	})
	if dynamicSet != 1 || ownedMapWrite != 1 {
		t.Fatalf("dynamic=%d owned map writes=%d", dynamicSet, ownedMapWrite)
	}
}

func TestDriftGuard_HeaderAliasFixturesIncludeTypedMapsAndChainedAssignments(t *testing.T) {
	source := `package fixture
import "net/http"
type responseHeaderMap map[string][]string
func bad() {
	var responseHeaders responseHeaderMap
	first := responseHeaders
	second := first
	second[dynamicHeaderName] = []string{"value"}
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = responseHeaderAliases(file)
	aliases := responseHeaderAliases(file)
	if !aliases["responseHeaders"] || !aliases["first"] || !aliases["second"] {
		t.Fatalf("typed alias chain not detected: %v", aliases)
	}
}

func TestDriftGuard_LocalRequestMetadataIsNotResponseHeaders(t *testing.T) {
	source := `package fixture
import "net/http"
func good(r *http.Request, key string) {
	metadataHeader := make(http.Header)
	metadataHeader.Set(key, "request metadata only")
	metadataHeader["ETag"] = []string{"request metadata only"}
	r.Header().Set(key, "request header")
	r.Header()[key] = []string{"request header"}
}`
	file, err := parser.ParseFile(token.NewFileSet(), "post_object.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	aliases := responseHeaderAliases(file)
	if aliases["metadataHeader"] || driftGuardFixtureRejectsSharedOwnershipBypass(file) {
		t.Fatal("local metadata assembly was classified as a ResponseWriter header write")
	}
}

func TestDriftGuard_ArbitraryResponseWriterHeaderOriginsRemainOwned(t *testing.T) {
	for _, fixture := range []struct {
		name, source string
	}{
		{"renamed writer dynamic Set", `package fixture
import "net/http"
	func bad(writer http.ResponseWriter, key string) { writer.Header().Set(key, "unsafe") }`},
		{"header map-index after chained writer aliases", `package fixture
import "net/http"
func bad(writer http.ResponseWriter, key string) {
	writerAlias := writer
	first := writerAlias.Header()
	second := first
	third := second
	third[key] = []string{"unsafe"}
}`},
		{"dynamic Set after chained header aliases", `package fixture
import "net/http"
func bad(writer http.ResponseWriter, key string) {
	writerAlias := writer
	first := writerAlias.Header()
	second := first
	second.Set(key, "unsafe")
}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "post_object.go", fixture.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !driftGuardFixtureRejectsSharedOwnershipBypass(file) {
				t.Fatal("intentional ResponseWriter header violation was not detected")
			}
		})
	}
}

func isResponseHeaderReceiver(expr ast.Expr) bool {
	if call, ok := expr.(*ast.CallExpr); ok {
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Header" {
			return true
		}
	}
	if selector, ok := expr.(*ast.SelectorExpr); ok {
		name := strings.ToLower(selector.Sel.Name)
		if strings.Contains(name, "responseheader") || strings.Contains(name, "writerheader") {
			return true
		}
		if selector.Sel.Name == "Header" && headerReceiverIsResponse(selector.X) {
			return true
		}
	}
	return false
}

func headerReceiverIsResponse(expr ast.Expr) bool {
	// Request metadata is reconstructed as make(http.Header), while the paths
	// covered here obtain response headers from a ResponseWriter or a response
	// object's Header method. Keep arbitrary receiver names supported without
	// treating local Header maps as response-writer aliases.
	if call, ok := expr.(*ast.CallExpr); ok {
		selector, ok := call.Fun.(*ast.SelectorExpr)
		return ok && selector.Sel.Name == "Response"
	}
	return true
}

func isResponseHeaderReceiverOrAlias(expr ast.Expr, aliases map[string]bool) bool {
	if isRequestHeaderField(expr, aliases) {
		return false
	}
	if isResponseHeaderReceiver(expr) {
		return true
	}
	if id, ok := expr.(*ast.Ident); ok {
		return aliases[id.Name]
	}
	return false
}

const requestHeaderVariablePrefix = "\x00request-header-variable:"

func isRequestHeaderField(expr ast.Expr, aliases map[string]bool) bool {
	var receiver ast.Expr
	switch header := expr.(type) {
	case *ast.CallExpr:
		selector, ok := header.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Header" {
			return false
		}
		receiver = selector.X
	case *ast.SelectorExpr:
		if header.Sel.Name != "Header" {
			return false
		}
		receiver = header.X
	default:
		return false
	}
	request, ok := receiver.(*ast.Ident)
	return ok && aliases[requestHeaderVariablePrefix+request.Name]
}

func headerWriteKey(expr ast.Expr) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		return strings.Trim(value.Value, "\"` "), true
	case *ast.Ident:
		return value.Name, value.Name == "ContentLength" || value.Name == "ContentRange" || value.Name == "ETag" || value.Name == "VersionID"
	case *ast.SelectorExpr:
		return value.Sel.Name, value.Sel.Name == "HeaderContentLength" || value.Sel.Name == "HeaderContentRange" || value.Sel.Name == "HeaderETag" || value.Sel.Name == "HeaderVersionID"
	default:
		return "", false
	}
}

func TestDriftGuard_APIInlineMPUMarkersAndSuffix(t *testing.T) {
	for _, path := range productionGoFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.IndexExpr:
				if selector, ok := n.Index.(*ast.SelectorExpr); ok && selector.Sel.Name == "MetaMPUEncrypted" && filepath.Base(path) != "object_view.go" {
					t.Errorf("%s indexes MetaMPUEncrypted outside object_view.go", path)
				}
			case *ast.BasicLit:
				if n.Kind == token.STRING && strings.Trim(n.Value, "\"` ") == ".mpu-manifest" && filepath.Base(path) != "object_format.go" {
					t.Errorf("%s contains inline MPU manifest suffix", path)
				}
			case *ast.BinaryExpr:
				for _, side := range []ast.Expr{n.X, n.Y} {
					index, ok := side.(*ast.IndexExpr)
					if !ok {
						continue
					}
					selector, ok := index.Index.(*ast.SelectorExpr)
					if ok && selector.Sel.Name == "MetaMPUEncrypted" && filepath.Base(path) != "object_view.go" {
						t.Errorf("%s compares MetaMPUEncrypted outside object_view.go", path)
					}
				}
			}
			return true
		})
	}
}

func TestDriftGuard_GetPlannerOwnerOwnsClassificationAndPreflight(t *testing.T) {
	var getHandler *ast.FuncDecl
	for _, path := range productionGoFiles(t) {
		if filepath.Base(path) != "handlers.go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Name.Name == "handleGetObject" {
				getHandler = function
			}
		}
	}
	if getHandler == nil {
		t.Fatal("handleGetObject not found")
	}
	var plannerCalls, classifiers, sizeResolvers, completenessPreflights, directProjectors, localBranching, localSources int
	ast.Inspect(getHandler.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		switch selector.Sel.Name {
		case "planGetObjectRead", "completeGetObjectRead", "planObjectRead", "planFullObjectRead", "prepareGetObjectRead":
			plannerCalls++
		case "loadObjectView":
			classifiers++
		case "resolvePlaintextSize":
			sizeResolvers++
		case "preflightChunkedCompleteness":
			completenessPreflights++
		case "projectObjectHeaders":
			directProjectors++
		}
		return true
	})
	ast.Inspect(getHandler.Body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.SwitchStmt:
			if objectReadSwitch(n.Tag) {
				localBranching++
			}
		}
		if call, ok := node.(*ast.CallExpr); ok && (isSelectorCall(call, "planGetObjectRead") || isSelectorCall(call, "completeGetObjectRead")) {
			plannerCalls++
		}
		if literal, ok := node.(*ast.CompositeLit); ok {
			if selector, ok := literal.Type.(*ast.Ident); ok && selector.Name == "objectResponseSource" {
				localSources++
			}
		}
		return true
	})
	if plannerCalls == 0 || classifiers != 0 || sizeResolvers != 0 || completenessPreflights != 0 || directProjectors != 0 || localBranching != 0 || localSources != 0 {
		t.Fatalf("GET ownership calls planner=%d classify=%d size=%d completeness=%d projection=%d local-branches=%d source-assembly=%d", plannerCalls, classifiers, sizeResolvers, completenessPreflights, directProjectors, localBranching, localSources)
	}
	if violations := objectReadOwnerViolations(getHandler); len(violations) != 0 {
		t.Fatalf("GET handler contains mode selection or response-source assembly: %v", violations)
	}
}

func objectReadOwnerViolations(function *ast.FuncDecl) []string {
	if function == nil || function.Body == nil {
		return []string{"missing GET handler body"}
	}
	var violations []string
	modeFields := map[string]bool{"Mode": true, "BackendRange": true, "MPURange": true, "MPURangeError": true, "MPUDecrypt": true}
	checkDecision := func(expr ast.Expr) {
		if expressionReferences(expr, modeFields) {
			violations = append(violations, "read-mode decision outside planner")
		}
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.IfStmt:
			checkDecision(n.Cond)
		case *ast.SwitchStmt:
			if n.Tag != nil {
				checkDecision(n.Tag)
			}
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if selector, ok := lhs.(*ast.SelectorExpr); ok && modeFields[selector.Sel.Name] {
					violations = append(violations, "read-mode assignment outside planner")
				}
			}
		case *ast.IncDecStmt:
			if selector, ok := n.X.(*ast.SelectorExpr); ok && modeFields[selector.Sel.Name] {
				violations = append(violations, "read-mode assignment outside planner")
			}
		case *ast.CompositeLit:
			if typ, ok := n.Type.(*ast.Ident); ok && typ.Name == "objectResponseSource" {
				violations = append(violations, "object response source assembled outside planner")
			}
		case *ast.CallExpr:
			if isSelectorCall(n, "objectResponsePlan") || isSelectorCall(n, "projectObjectHeaders") {
				violations = append(violations, "object response source projected outside planner")
			}
			if isSelectorCall(n, "parseObjectRange") || isSelectorCall(n, "EncRangeForPlaintextRange") || isSelectorCall(n, "CalculateEncryptedRangeForPlaintextRange") {
				violations = append(violations, "object plaintext/ciphertext range assembled outside planner")
			}
		}
		return true
	})
	return violations
}

func plannedReadExecutorsViolations(function *ast.FuncDecl) []string {
	violations := objectReadOwnerViolations(function)
	if function == nil || function.Body == nil {
		return violations
	}
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		case *ast.Ident:
			name = fun.Name
		}
		switch name {
		case "DecryptMPUPartRange", "DecryptMPUPartRangeV1":
			violations = append(violations, "MPU decrypt mode selected outside planner")
		case "PlaintextMetadataView":
			violations = append(violations, "MPU response source assembled outside planner")
		}
		return true
	})
	return violations
}

func TestDriftGuard_PlannedExecutorsHaveSingleReadOwner(t *testing.T) {
	owners := map[string]bool{"servePlannedGetObject": false, "serveMPURangedGetPlanned": false}
	for _, path := range productionGoFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, tracked := owners[function.Name.Name]; !tracked {
				continue
			}
			owners[function.Name.Name] = true
			if violations := plannedReadExecutorsViolations(function); len(violations) != 0 {
				t.Errorf("%s.%s duplicates object-read policy: %v", filepath.Base(path), function.Name.Name, violations)
			}
			forbiddenResponseAssembly := map[string]bool{"projectObjectHeaders": true, "objectResponsePlan": true, "makeObjectResponsePlan": true, "projectPlannedObjectResponse": true, "plannedMPURangeResponse": true, "completeObjectReadResponse": true}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := ""
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				case *ast.Ident:
					name = fun.Name
				}
				if forbiddenResponseAssembly[name] {
					t.Errorf("%s.%s reconstructs a response plan through %s", filepath.Base(path), function.Name.Name, name)
				}
				return true
			})
			forbiddenResponseFields := map[string]bool{"ResponseStatus": true, "ResponseRange": true, "Status": true, "Source": true, "Body": true, "MPURangeError": true}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				assignment, ok := node.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range assignment.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if ok && forbiddenResponseFields[sel.Sel.Name] {
						t.Errorf("%s.%s reconstructs response policy through assignment to %s", filepath.Base(path), function.Name.Name, sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	for name, found := range owners {
		if !found {
			t.Errorf("production executor %s was not found", name)
		}
	}
}

func TestDriftGuard_PlannedExecutorsRejectResponseAssemblyViolations(t *testing.T) {
	source := `package fixture
func servePlannedGetObject() { _, _ = h.objectResponsePlan(source, shape, 200, body, "b", "k") }
func serveMPURangedGetPlanned() { _, _ = h.projectObjectHeaders(source, shape) }`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		var found bool
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if ok && (isSelectorCall(call, "objectResponsePlan") || isSelectorCall(call, "projectObjectHeaders")) {
				found = true
			}
			return true
		})
		if !found {
			t.Errorf("intentional response assembly in %s was not detected", function.Name.Name)
		}
	}
}

func TestDriftGuard_PlannedExecutorsRejectResponsePolicyReads(t *testing.T) {
	source := `package fixture
func servePlannedGetObject() { if objectRead.ResponseStatus == 206 { _ = objectRead.ResponseRange } }
func serveMPURangedGetPlanned() { objectRead.Source = source; objectRead.Body = body }`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function := declaration.(*ast.FuncDecl)
		found := false
		ast.Inspect(function.Body, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if ok && map[string]bool{"ResponseStatus": true, "ResponseRange": true}[selector.Sel.Name] {
				found = true
			}
			return true
		})
		if function.Name.Name == "servePlannedGetObject" && !found {
			t.Errorf("intentional response policy read in %s was not detected", function.Name.Name)
		}
	}
}

func TestDriftGuard_PlannedExecutorsRejectIntentionalModeAndSourceViolations(t *testing.T) {
	source := `package fixture
func servePlannedGetObject() {
	objectRead.Mode = objectReadFull
	source := objectResponseSource{Class: objectRead.Class}
	_ = source
	_, _, _ = parseObjectRange("bytes=1-2", 5)
}

func serveMPURangedGetPlanned() {
	if objectRead.BackendRange != nil {
	}
	 rangeResult, _ := manifest.EncRangeForPlaintextRange(0, 1)
 _ = rangeResult
 _, _ = crypto.DecryptMPUPartRangeV1(nil, nil, nil, [8]byte{}, 1, 1, 0, "")
 source := crypto.PlaintextMetadataView(nil, -1, "")
 _ = source
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(function.Name.Name, "serve") {
			continue
		}
		violations := plannedReadExecutorsViolations(function)
		if len(violations) < 2 {
			t.Errorf("intentional executor violations in %s were not detected: %v", function.Name.Name, violations)
		}
	}
}

func TestDriftGuard_GetPlannerRejectsIntentionalModeAndSourceViolations(t *testing.T) {
	source := `package fixture
func handleGetObject() {
 if objectRead.Mode == objectReadFull {
  source := objectResponseSource{Class: objectRead.Class}
  _ = source
 }
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fixture *ast.FuncDecl
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "handleGetObject" {
			fixture = function
		}
	}
	if violations := objectReadOwnerViolations(fixture); len(violations) < 2 {
		t.Fatalf("intentional read-owner violations were not detected: %v", violations)
	}
}

func objectReadSwitch(expr ast.Expr) bool {
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	base, ok := selector.X.(*ast.Ident)
	return ok && base.Name == "objectRead" && selector.Sel.Name == "Class"
}

func objectReadModeComparison(expr *ast.BinaryExpr) bool {
	for _, side := range []ast.Expr{expr.X, expr.Y} {
		selector, ok := side.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		base, ok := selector.X.(*ast.Ident)
		if ok && base.Name == "objectRead" && selector.Sel.Name == "Mode" {
			return true
		}
	}
	return false
}

func expressionReferences(expr ast.Expr, names map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		if id, ok := node.(*ast.Ident); ok && names[id.Name] {
			found = true
		}
		if selector, ok := node.(*ast.SelectorExpr); ok && names[selector.Sel.Name] {
			found = true
		}
		return true
	})
	return found
}

func TestDriftGuardIntentionalViolationsAreDetected(t *testing.T) {
	source := `package fixture
func bad(w http.ResponseWriter, h http.Header, headers http.Header, metadata map[string]string, m map[string]string, x map[string]string) {
 w.Header().Set(headerName, "x")
 h.Set("Content-Length", "1")
 headers[headerName] = []string{"1"}
 metadata[crypto.MetaMPUEncrypted] = "v2"
 m[crypto.MetaMPUEncrypted] != "true"
 x[key] = "1"
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var dynamicHeaderWrite, dynamicHeaderMap, mpuIndex int
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			if selector, ok := n.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Set" && isResponseHeaderReceiver(selector.X) {
				if _, ok := n.Args[0].(*ast.Ident); ok {
					dynamicHeaderWrite++
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if index, ok := lhs.(*ast.IndexExpr); ok && isResponseHeaderMapIndex(index, map[string]bool{"headers": true}) {
					if _, ok := index.Index.(*ast.Ident); ok {
						dynamicHeaderMap++
					}
				}
			}
		case *ast.IndexExpr:
			if selector, ok := n.Index.(*ast.SelectorExpr); ok && selector.Sel.Name == "MetaMPUEncrypted" {
				mpuIndex++
			}
		}
		return true
	})
	if dynamicHeaderWrite != 1 || dynamicHeaderMap != 1 || mpuIndex != 2 {
		t.Fatalf("intentional AST violations not recognized: call=%d map=%d marker/index=%d", dynamicHeaderWrite, dynamicHeaderMap, mpuIndex)
	}
}

func TestDriftGuard_APIHeaderProjectionOwnership(t *testing.T) {
	owned := map[string]bool{"Content-Length": true, "Content-Range": true, "ETag": true, "x-amz-version-id": true}
	for _, path := range productionGoFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Base(path) == "utils.go" || filepath.Base(path) == "auth_middleware.go" {
			continue
		}
		base := filepath.Base(path)
		aliases := responseHeaderAliases(file)
		if base == "object_response.go" {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (selector.Sel.Name != "Set" && selector.Sel.Name != "Del" && selector.Sel.Name != "Add") || len(call.Args) == 0 {
				return true
			}
			if !isResponseHeaderReceiverOrAlias(selector.X, aliases) {
				return true
			}
			key, ok := headerWriteKey(call.Args[0])
			if !ok {
				if filepath.Base(path) != "object_response.go" {
					t.Errorf("%s writes a dynamic header name outside object_response.go", base)
				}
				return true
			}
			if owned[key] {
				t.Errorf("%s directly projects owned object header %q", base, key)
			}
			return true
		})
	}
}

func TestDriftGuard_ErrorMetricGuardDetectsWrappedAndDeadBranchCalls(t *testing.T) {
	source := `package fixture
func bad(h *Handler, w http.ResponseWriter, r *http.Request) {
	if false && h.metrics.RecordS3Error(r.Context(), "GetObject", "b", "InternalError") {}
	(&S3Error{}).WriteXML(w)
	h.metrics.RecordHTTPRequest(r.Context(), "GET", r.URL.Path, 500, time.Second, 0)
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var recordS3Error, writeXML, requestMetric int
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case isSelectorCall(call, "RecordS3Error"):
			recordS3Error++
		case isSelectorCall(call, "WriteXML"):
			writeXML++
		case isSelectorCall(call, "RecordHTTPRequest"):
			requestMetric++
		}
		return true
	})
	if recordS3Error != 1 || writeXML != 1 || requestMetric != 1 {
		t.Fatalf("AST guard missed metrics/errors: s3=%d xml=%d http=%d", recordS3Error, writeXML, requestMetric)
	}
}

func TestDriftGuard_ObjectMetadataGuardCatchesAliasedSetDelAndMapWrites(t *testing.T) {
	source := `package fixture
import "net/http"
func bad(w http.ResponseWriter) {
	var responseHeaderMap http.Header
	alias := responseHeaderMap
	alias.Set(dynamicHeaderName, "x")
	alias.Del("ETag")
	alias["Content-Length"] = []string{"5"}
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	aliases := responseHeaderAliases(file)
	var dynamic, ownedMap int
	ast.Inspect(file, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok && len(call.Args) > 0 {
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && (selector.Sel.Name == "Set" || selector.Sel.Name == "Del") && isResponseHeaderReceiverOrAlias(selector.X, aliases) {
				if key, known := headerWriteKey(call.Args[0]); !known || key == "ETag" {
					if !known {
						dynamic++
					} else {
						ownedMap++
					}
				}
			}
		}
		if assignment, ok := node.(*ast.AssignStmt); ok {
			for _, lhs := range assignment.Lhs {
				if index, ok := lhs.(*ast.IndexExpr); ok && isResponseHeaderMapIndex(index, aliases) {
					if key, known := headerWriteKey(index.Index); known && key == "Content-Length" {
						ownedMap++
					}
				}
			}
		}
		return true
	})
	if dynamic != 1 || ownedMap != 2 {
		t.Fatalf("dynamic writes=%d owned writes=%d aliases=%v", dynamic, ownedMap, aliases)
	}
}

func TestDriftGuard_ResponseHeaderAliasesDetectMapAndChainedAliases(t *testing.T) {
	source := `package fixture
import "net/http"
func bad(w http.ResponseWriter) {
	var responseHeaders http.Header
	alias := responseHeaders
	alias[headerName] = []string{"bad"}
	alias.Set(dynamicName, "bad")
	_ = w
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	aliases := responseHeaderAliases(file)
	if !aliases["responseHeaders"] || !aliases["alias"] {
		t.Fatalf("response header aliases not followed: %v", aliases)
	}
	var mapWrites, dynamicWrites int
	ast.Inspect(file, func(node ast.Node) bool {
		if assignment, ok := node.(*ast.AssignStmt); ok {
			for _, lhs := range assignment.Lhs {
				if index, ok := lhs.(*ast.IndexExpr); ok && isResponseHeaderMapIndex(index, aliases) {
					mapWrites++
				}
			}
		}
		if call, ok := node.(*ast.CallExpr); ok && len(call.Args) > 0 {
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Set" && isResponseHeaderReceiverOrAlias(selector.X, aliases) {
				if _, known := headerWriteKey(call.Args[0]); !known {
					dynamicWrites++
				}
			}
		}
		return true
	})
	if mapWrites != 1 || dynamicWrites != 1 {
		t.Fatalf("header violations found map=%d dynamic=%d", mapWrites, dynamicWrites)
	}
}

func TestDriftGuard_ObjectMetricPairsDetectUnreachableRecordS3Error(t *testing.T) {
	source := `package fixture
func bad() {
	if false && metrics.RecordS3Error(ctx, op, bucket, code) {}
}`
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var records int
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if ok && isSelectorCall(call, "RecordS3Error") {
			records++
		}
		return true
	})
	if records != 1 {
		t.Fatalf("RecordS3Error AST condition missed unreachable call: %d", records)
	}
}

func TestDriftGuard_APIErrorMetricPairs(t *testing.T) {
	allowed := map[string]map[string]bool{"object_errors.go": {"writeObjectErrorForBucket": true, "writeObjectResponseMetric": true}, "object_stream.go": {"streamObjectBody": true}, "handlers.go": {"writeS3ClientError": true}}
	objectHandlers := map[string]bool{
		"handleGetObject": true, "handlePutObject": true, "handleDeleteObject": true, "handleHeadObject": true,
		"handleCopyObject": true, "handleDeleteObjects": true, "handleCreateMultipartUpload": true,
		"handleUploadPart": true, "handleCompleteMultipartUpload": true, "handleAbortMultipartUpload": true,
		"serveMPURangedGetPlanned":      true,
		"handleUploadPartCopy":          true,
		"writeMissingMPUState":          true,
		"writeChunkedCompletenessError": true,
		"handleListParts":               true,
		"decryptMPUObject":              true,
	}
	for _, path := range productionGoFiles(t) {
		base := filepath.Base(path)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		functionAllowlist := allowed[base]
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || !objectHandlers[function.Name.Name] {
				continue
			}
			if functionAllowlist[function.Name.Name] {
				continue
			}
			if filepath.Base(path) == "object_errors.go" && (function.Name.Name == "writeObjectDecryptError" || function.Name.Name == "recordObjectDecryptSuccess" || function.Name.Name == "recordObjectIntegrityFailure" || function.Name.Name == "recordObjectDecryptFailure") {
				continue
			}
			if filepath.Base(path) == "handlers.go" && function.Name.Name == "decryptMPUObject" {
				continue
			}
			forbiddenErrorMetricPairs := 0
			inlineMetrics := 0
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isSelectorCall(call, "RecordS3Error") || isSelectorCall(call, "RecordHTTPRequest") && !isAllowedFinalSuccessMetric(function, call) {
					inlineMetrics++
				}
				if isSelectorCall(call, "WriteXML") {
					forbiddenErrorMetricPairs++
				}
				return true
			})
			if forbiddenErrorMetricPairs != 0 {
				t.Errorf("%s.%s has %d inline S3 error/metric pairs; use writeObjectError", base, function.Name.Name, forbiddenErrorMetricPairs)
			}
			if inlineMetrics != 0 {
				t.Errorf("%s.%s has %d inline non-success request metrics; use writeObjectError", base, function.Name.Name, inlineMetrics)
			}
		}
	}
}

// Only the ListParts XML handler retains an inline success request metric; it
// is its final statement after the successful response body has been written.
// Error and stream metrics are always owned by object_errors.go/object_stream.go.
func isAllowedFinalSuccessMetric(function *ast.FuncDecl, call *ast.CallExpr) bool {
	if function.Name.Name != "handleListParts" || !isSuccessfulHTTPRequestMetric(call) {
		return false
	}
	statements := function.Body.List
	if len(statements) == 0 {
		return false
	}
	last, ok := statements[len(statements)-1].(*ast.ExprStmt)
	return ok && last.X == call
}

func TestDriftGuard_MPURangedGetUsesSharedErrorAndStreamOwners(t *testing.T) {
	var target *ast.FuncDecl
	for _, path := range productionGoFiles(t) {
		if filepath.Base(path) != "handlers.go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if ok && function.Name.Name == "serveMPURangedGetPlanned" {
				target = function
				break
			}
		}
	}
	if target == nil {
		t.Fatal("serveMPURangedGet not found")
	}
	sharedOwners := map[string]int{}
	var serveObjectBodyCalls, directStreamCalls, directResponseWrites int
	forbiddenInline := map[string]bool{
		"WriteXML": true, "RecordHTTPRequest": true, "RecordS3Error": true,
		"RecordEncryptionError": true, "recordObjectIntegrityFailure": true,
	}
	ast.Inspect(target.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		case *ast.Ident:
			name = fun.Name
		}
		if forbiddenInline[name] {
			t.Errorf("serveMPURangedGet calls %s inline; use the shared object error/stream owner", name)
		}
		if name == "serveObjectBody" {
			serveObjectBodyCalls++
		}
		if name == "streamObjectBody" {
			directStreamCalls++
		}
		if name == "Write" || name == "WriteString" || name == "WriteHeader" || name == "Header" || name == "Set" || name == "Del" || name == "writeObjectHeaders" || name == "startObjectBody" {
			directResponseWrites++
		}
		switch name {
		case "writeObjectError", "writeObjectIntegrityError", "serveObjectBody":
			sharedOwners[name]++
		}
		return true
	})
	for _, owner := range []string{"writeObjectError", "serveObjectBody"} {
		if sharedOwners[owner] == 0 {
			t.Errorf("serveMPURangedGet does not use shared owner %s", owner)
		}
	}
	if serveObjectBodyCalls != 1 {
		t.Errorf("serveMPURangedGet calls serveObjectBody %d times, want exactly once for the whole body", serveObjectBodyCalls)
	}
	if directStreamCalls != 0 || directResponseWrites != 0 {
		t.Errorf("serveMPURangedGet bypasses the shared body owner: streamObjectBody=%d direct response writes=%d", directStreamCalls, directResponseWrites)
	}
}

func isSuccessfulHTTPRequestMetric(call *ast.CallExpr) bool {
	if len(call.Args) < 4 {
		return false
	}
	status, ok := call.Args[3].(*ast.SelectorExpr)
	if !ok {
		return false
	}
	base, ok := status.X.(*ast.Ident)
	if !ok || base.Name != "http" {
		return false
	}
	switch status.Sel.Name {
	case "StatusOK", "StatusCreated", "StatusAccepted", "StatusNoContent", "StatusPartialContent", "StatusNotModified":
		return true
	default:
		return strings.HasPrefix(status.Sel.Name, "Status") && metricsStatusIsSuccess(status.Sel.Name)
	}
}

func metricsStatusIsSuccess(name string) bool {
	return name == "StatusPermanentRedirect" || name == "StatusTemporaryRedirect"
}

func isSelectorCall(expression ast.Expr, name string) bool {
	call, ok := expression.(*ast.CallExpr)
	if !ok {
		return false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	return ok && selector.Sel.Name == name
}

func responseHeaderAliases(file *ast.File) map[string]bool {
	aliases := map[string]bool{}
	mapTypes := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		function, ok := node.(*ast.FuncDecl)
		if !ok || function.Type.Params == nil {
			return true
		}
		for _, field := range function.Type.Params.List {
			if isHTTPRequestType(field.Type) {
				for _, name := range field.Names {
					aliases[requestHeaderVariablePrefix+name.Name] = true
				}
			}
		}
		return true
	})
	ast.Inspect(file, func(node ast.Node) bool {
		declaration, ok := node.(*ast.TypeSpec)
		if !ok {
			return true
		}
		if mapType, ok := declaration.Type.(*ast.MapType); ok {
			key, keyOK := mapType.Key.(*ast.Ident)
			value, valueOK := mapType.Value.(*ast.ArrayType)
			if keyOK && valueOK && key.Name == "string" {
				if _, byteOK := value.Elt.(*ast.Ident); byteOK {
					mapTypes[declaration.Name.Name] = true
				}
			}
		}
		return true
	})
	ast.Inspect(file, func(node ast.Node) bool {
		var names []*ast.Ident
		var typ ast.Expr
		switch declaration := node.(type) {
		case *ast.Field:
			names, typ = declaration.Names, declaration.Type
		case *ast.ValueSpec:
			names, typ = declaration.Names, declaration.Type
		}
		if typ == nil {
			return true
		}
		selector, ok := typ.(*ast.SelectorExpr)
		if ok && selector.Sel.Name == "Header" {
			for _, name := range names {
				aliases[name.Name] = true
			}
		}
		if mapType, ok := typ.(*ast.MapType); ok {
			key, keyOK := mapType.Key.(*ast.Ident)
			value, valueOK := mapType.Value.(*ast.ArrayType)
			if keyOK && valueOK && key.Name == "string" {
				if _, byteOK := value.Elt.(*ast.Ident); byteOK {
					for _, name := range names {
						lower := strings.ToLower(name.Name)
						if strings.Contains(lower, "header") && (strings.Contains(lower, "response") || strings.Contains(lower, "writer")) {
							aliases[name.Name] = true
						}
					}
				}
			}
		}
		if id, ok := typ.(*ast.Ident); ok && mapTypes[id.Name] {
			for _, name := range names {
				aliases[name.Name] = true
			}
		}
		return true
	})
	for changed := true; changed; {
		changed = false
		ast.Inspect(file, func(node ast.Node) bool {
			var left []ast.Expr
			var right []ast.Expr
			switch assignment := node.(type) {
			case *ast.AssignStmt:
				left, right = assignment.Lhs, assignment.Rhs
			case *ast.ValueSpec:
				for _, name := range assignment.Names {
					left = append(left, name)
				}
				if assignment.Type != nil {
					for range assignment.Names {
						right = append(right, assignment.Type)
					}
				}
			}
			if len(right) == 0 {
				return true
			}
			for i, rhs := range right {
				if i < len(left) && isResponseHeaderReceiverOrAlias(rhs, aliases) {
					if id, ok := left[i].(*ast.Ident); ok && !aliases[id.Name] {
						aliases[id.Name] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	return aliases
}

func isHTTPRequestType(expr ast.Expr) bool {
	pointer, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	selector, ok := pointer.X.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "Request" {
		return false
	}
	packageName, ok := selector.X.(*ast.Ident)
	return ok && packageName.Name == "http"
}

func isResponseHeaderMapIndex(index *ast.IndexExpr, aliases map[string]bool) bool {
	if isResponseHeaderReceiverOrAlias(index.X, aliases) {
		return true
	}
	if id, ok := index.X.(*ast.Ident); ok {
		return aliases[id.Name]
	}
	return false
}

func apiCompactAliasesForGuard() map[string]bool {
	aliases := make(map[string]bool)
	for _, alias := range crypto.CompactAliases() {
		aliases[strings.ToLower(alias)] = true
	}
	return aliases
}

func TestDriftGuard_APIRegisteredCompactAliases(t *testing.T) {
	aliases := apiCompactAliasesForGuard()
	for _, path := range productionGoFiles(t) {
		if filepath.Base(path) == "metakeys.go" {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(lit.Value)
			if err == nil && aliases[strings.ToLower(value)] {
				t.Errorf("%s contains registered compact alias %q outside metakeys.go", filepath.Base(path), value)
			}
			return true
		})
	}
}

func TestDriftGuard_APIObjectHeaderWriterAndMetadataMarkers(t *testing.T) {
	ownedHeaders := map[string]bool{"Content-Length": true, "Content-Range": true, "ETag": true, "x-amz-version-id": true}
	for _, path := range productionGoFiles(t) {
		base := filepath.Base(path)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "Set" && selector.Sel.Name != "Del" && selector.Sel.Name != "Add" {
				return true
			}
			recv, ok := selector.X.(*ast.CallExpr)
			if !ok {
				return true
			}
			headerMethod, ok := recv.Fun.(*ast.SelectorExpr)
			if !ok || headerMethod.Sel.Name != "Header" || len(call.Args) == 0 {
				return true
			}
			key, ok := call.Args[0].(*ast.BasicLit)
			if !ok || key.Kind != token.STRING {
				return true
			}
			value := strings.Trim(key.Value, "\"` ")
			if ownedHeaders[value] && base != "object_response.go" {
				t.Errorf("%s writes object response header %q outside object_response.go", base, value)
			}
			return true
		})
	}
}

func TestDriftGuard_MetadataSuffixAndClassifierPredicates(t *testing.T) {
	for _, path := range productionGoFiles(t) {
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Base(path)
		ast.Inspect(file, func(node ast.Node) bool {
			switch n := node.(type) {
			case *ast.BasicLit:
				if n.Kind != token.STRING || base == "object_format.go" || base == "metakeys.go" || base == "engine.go" {
					return true
				}
				value := strings.Trim(n.Value, "\"` ")
				lower := strings.ToLower(value)
				if value == ".mpu-manifest" {
					t.Errorf("%s contains inline manifest suffix", base)
				}
				if strings.HasPrefix(lower, "x-amz-meta-enc") || strings.HasPrefix(lower, "x-amz-meta-encrypt") {
					t.Errorf("%s contains inline gateway metadata marker %q", base, value)
				}
			case *ast.IndexExpr:
				selector, ok := n.Index.(*ast.SelectorExpr)
				if !ok || selector.Sel.Name != "MetaMPUEncrypted" || base == "object_view.go" {
					return true
				}
				t.Errorf("%s indexes MetaMPUEncrypted outside object_view.go", base)
			}
			return true
		})
	}
}
