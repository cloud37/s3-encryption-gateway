package api_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/middleware"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

const literalRoutingKey = "literal/../plus+percent%25/name.bin"

type literalRoutingBackend struct {
	s3.Client
	mu            sync.Mutex
	objects       map[string][]byte
	metadata      map[string]map[string]string
	writes, reads []string
}

func (b *literalRoutingBackend) PutObject(ctx context.Context, bucket, key string, body io.Reader, metadata map[string]string, length *int64, tags string, lock *s3.ObjectLockInput, acl, full, read, readACP, writeACP string) (string, error) {
	data, err := io.ReadAll(body)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.writes = append(b.writes, key)
	b.objects[bucket+"/"+key] = data
	metadata["Content-Length"] = fmt.Sprint(len(data))
	b.metadata[bucket+"/"+key] = metadata
	return "", nil
}

func (b *literalRoutingBackend) GetObject(ctx context.Context, bucket, key string, version, interval *string) (io.ReadCloser, map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reads = append(b.reads, key)
	data := b.objects[bucket+"/"+key]
	if interval != nil && *interval != "" {
		var start, end int
		if _, err := fmt.Sscanf(*interval, "bytes=%d-%d", &start, &end); err != nil || start < 0 || end >= len(data) || start > end {
			return nil, nil, fmt.Errorf("invalid range")
		}
		data = data[start : end+1]
	}
	return io.NopCloser(bytes.NewReader(data)), b.metadata[bucket+"/"+key], nil
}

func (b *literalRoutingBackend) HeadObject(ctx context.Context, bucket, key string, version *string) (map[string]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reads = append(b.reads, key)
	return b.metadata[bucket+"/"+key], nil
}

func (b *literalRoutingBackend) ListObjects(context.Context, string, string, s3.ListOptions) (s3.ListResult, error) {
	return s3.ListResult{}, nil
}

func literalPost(t *testing.T, key, filename, payload, status string) *http.Request {
	t.Helper()
	date := time.Now().UTC().Format("20060102T150405Z")
	scope := chainAccessKey + "/" + date[:8] + "/us-east-1/s3/aws4_request"
	base := filename[strings.LastIndexAny(filename, `/\`)+1:]
	expanded := strings.ReplaceAll(key, "${filename}", base)
	extra := ""
	if status != "" {
		extra = fmt.Sprintf(`,{"success_action_status":%q}`, status)
	}
	policy := fmt.Sprintf(`{"expiration":%q,"conditions":[{"bucket":"bucket"},{"key":%q},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":%q},{"x-amz-date":%q}%s]}`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339), expanded, scope, date, extra)
	encoded := base64.StdEncoding.EncodeToString([]byte(policy))
	fields := map[string]string{"bucket": "bucket", "key": key, "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date, "policy": encoded, "x-amz-signature": chainSignPolicy(encoded, date[:8])}
	if status != "" {
		fields["success_action_status"] = status
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range fields {
		if err := writer.WriteField(name, value); err != nil {
			t.Fatal("form field failure")
		}
	}
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal("form file failure")
	}
	_, _ = io.WriteString(part, payload)
	_ = writer.Close()
	req := httptest.NewRequest(http.MethodPost, "http://gateway.test/bucket", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func literalHMAC(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = io.WriteString(h, value)
	return h.Sum(nil)
}

// Sign the decoded S3 path independently of the gateway canonicalizer.
func literalRoutingSign(t *testing.T, req *http.Request, secret string) {
	t.Helper()
	now := time.Now().UTC()
	date, timestamp := now.Format("20060102"), now.Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", timestamp)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	segments := strings.Split(req.URL.Path, "/")
	for i, part := range segments {
		segments[i] = strings.ReplaceAll(url.QueryEscape(part), "+", "%20")
	}
	var query []string
	for key, values := range req.URL.Query() {
		for _, value := range values {
			query = append(query, strings.ReplaceAll(url.QueryEscape(key), "+", "%20")+"="+strings.ReplaceAll(url.QueryEscape(value), "+", "%20"))
		}
	}
	sort.Strings(query)
	canonical := req.Method + "\n" + strings.Join(segments, "/") + "\n" + strings.Join(query, "&") + "\nhost:" + req.URL.Host + "\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:" + timestamp + "\n\nhost;x-amz-content-sha256;x-amz-date\nUNSIGNED-PAYLOAD"
	scope := date + "/us-east-1/s3/aws4_request"
	hash := sha256.Sum256([]byte(canonical))
	k := literalHMAC([]byte("AWS4"+secret), date)
	k = literalHMAC(k, "us-east-1")
	k = literalHMAC(k, "s3")
	k = literalHMAC(k, "aws4_request")
	sig := literalHMAC(k, "AWS4-HMAC-SHA256\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(hash[:]))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"+scope+", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+hex.EncodeToString(sig))
}

func TestGH353LiteralRouting_HTTPRoundTrip(t *testing.T) {
	backend := &literalRoutingBackend{objects: map[string][]byte{}, metadata: map[string]map[string]string{}}
	engine, err := crypto.NewEngineWithOpts([]byte("test encryption password"), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	if err != nil {
		t.Fatal("engine fixture")
	}
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	h := api.NewHandlerWithFeatures(backend, engine, logger, nil, nil, nil, nil, &config.Config{}, nil)
	manager := api.NewSpoolManager(8<<20, t.TempDir())
	limits := api.NewSpoolLimitSource(api.SpoolLimits{Global: 2 << 20, Part: 1 << 20})
	h.WithSpoolManager(manager).WithSpoolLimitSource(limits)
	router := mux.NewRouter().SkipClean(true)
	h.RegisterRoutes(router)
	store, err := api.NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: chainPermission(config.ObjectPermissionReadWrite)}})
	if err != nil {
		t.Fatal("credential fixture")
	}
	var chain http.Handler = middleware.StripBucketTrailingSlash(router)
	chain = api.AuthorizationMiddleware("bucket", nil)(chain)
	chain = api.AuthMiddleware(store, time.Minute, logger, nil, false, manager, limits)(chain)
	chain = middleware.RecoveryMiddleware(logger)(chain)
	server := httptest.NewServer(chain)
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	post := literalPost(t, "literal/../plus+percent%25/${filename}", "dir/sub/name.bin", "literal payload", "")
	post.URL, _ = url.Parse(server.URL + "/bucket")
	post.RequestURI = ""
	post.Host = post.URL.Host
	resp, err := client.Do(post)
	if err != nil {
		t.Fatal("POST transport failed")
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent || len(backend.writes) != 1 || backend.writes[0] != literalRoutingKey {
		t.Fatalf("POST status=%d exact_write=%t", resp.StatusCode, len(backend.writes) == 1 && backend.writes[0] == literalRoutingKey)
	}
	if _, ok := backend.objects["bucket/"+literalRoutingKey]; !ok {
		t.Fatal("exact destination missing")
	}
	if _, ok := backend.objects["bucket/plus+percent%25/name.bin"]; ok {
		t.Fatal("normalized neighbor unexpectedly stored")
	}

	for _, tc := range []struct {
		method, suffix, interval string
		status                   int
		body                     string
	}{
		{http.MethodGet, "literal/%2E%2E/plus%2Bpercent%2525/name%2Ebin", "", 200, "literal payload"},
		{http.MethodHead, "literal/%2E%2E/plus%2Bpercent%2525/name%2Ebin", "", 200, ""},
		{http.MethodGet, "literal/%2E%2E/plus%2Bpercent%2525/name%2Ebin", "bytes=0-6", 206, "literal"},
	} {
		req, _ := http.NewRequest(tc.method, server.URL+"/bucket/"+tc.suffix, nil)
		if tc.interval != "" {
			req.Header.Set("Range", tc.interval)
		}
		literalRoutingSign(t, req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("read transport failed")
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != tc.status || !bytes.Equal(body, []byte(tc.body)) || (tc.method == http.MethodHead && resp.ContentLength != int64(len("literal payload"))) {
			t.Fatalf("read method=%s status=%d want=%d body_match=%t", tc.method, resp.StatusCode, tc.status, bytes.Equal(body, []byte(tc.body)))
		}
	}
	if len(backend.reads) == 0 {
		t.Fatal("no backend reads")
	}
	for _, key := range backend.reads {
		if key != literalRoutingKey {
			t.Fatal("backend read used a different key")
		}
	}

	for _, tc := range []struct{ name, formKey, wire, expected string }{
		{"percent-as-data", "literal/%2F+value", "literal/%252F%2Bvalue", "literal/%2F+value"},
		{"repeated slash", "repeated//item", "repeated//item", "repeated//item"},
		{"leading slash", "/leading/item", "/leading/item", "/leading/item"},
		{"ordinary", "ordinary/item", "ordinary/item", "ordinary/item"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			post := literalPost(t, tc.formKey, "file.bin", "other payload", "")
			post.URL, _ = url.Parse(server.URL + "/bucket")
			post.RequestURI = ""
			post.Host = post.URL.Host
			resp, err := client.Do(post)
			if err != nil {
				t.Fatal("POST transport failed")
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			exactWrite := len(backend.writes) > 0 && backend.writes[len(backend.writes)-1] == tc.expected
			if resp.StatusCode != 204 || !exactWrite {
				t.Fatalf("POST status=%d exact=%t", resp.StatusCode, exactWrite)
			}
			start := len(backend.reads)
			req, _ := http.NewRequest(http.MethodGet, server.URL+"/bucket/"+tc.wire, nil)
			literalRoutingSign(t, req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
			resp, err = client.Do(req)
			if err != nil {
				t.Fatal("GET transport failed")
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || string(body) != "other payload" || len(backend.reads) == start {
				t.Fatalf("GET status=%d payload_match=%t backend_seen=%t", resp.StatusCode, string(body) == "other payload", len(backend.reads) > start)
			}
			for _, key := range backend.reads[start:] {
				if key != tc.expected {
					t.Fatal("read routed to wrong key")
				}
			}
		})
	}
	post201 := literalPost(t, "literal/../plus+percent%25/${filename}", "dir/sub/name.bin", "literal payload", "201")
	post201.URL, _ = url.Parse(server.URL + "/bucket")
	post201.RequestURI = ""
	post201.Host = post201.URL.Host
	response201, err := client.Do(post201)
	if err != nil {
		t.Fatal("201 POST transport failed")
	}
	var result struct {
		Key      string `xml:"Key"`
		Location string `xml:"Location"`
	}
	decodeErr := xml.NewDecoder(response201.Body).Decode(&result)
	response201.Body.Close()
	if response201.StatusCode != http.StatusCreated || decodeErr != nil || result.Key != literalRoutingKey {
		t.Fatalf("201 response status=%d exact_key=%t", response201.StatusCode, result.Key == literalRoutingKey)
	}
	location, err := url.Parse(result.Location)
	if err != nil || location.Scheme != "http" || location.Host != post201.URL.Host || location.Path != "/bucket/"+literalRoutingKey {
		t.Fatal("201 Location identity mismatch")
	}
	locationRead, err := http.NewRequest(http.MethodGet, result.Location, nil)
	if err != nil {
		t.Fatal("Location request construction failed")
	}
	literalRoutingSign(t, locationRead, chainSecretKey)
	start := len(backend.reads)
	locationResp, err := client.Do(locationRead)
	if err != nil {
		t.Fatal("Location read failed")
	}
	locationBody, err := io.ReadAll(locationResp.Body)
	locationResp.Body.Close()
	if err != nil || locationResp.StatusCode != http.StatusOK || string(locationBody) != "literal payload" || len(backend.reads) == start {
		t.Fatalf("Location read status=%d payload_match=%t", locationResp.StatusCode, string(locationBody) == "literal payload")
	}
	for _, key := range backend.reads[start:] {
		if key != literalRoutingKey {
			t.Fatal("Location read used different key")
		}
	}
	for _, target := range []string{"/bucket", "/bucket/"} {
		req, _ := http.NewRequest(http.MethodHead, server.URL+target, nil)
		literalRoutingSign(t, req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal("bucket HEAD transport failed")
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("bucket HEAD status=%d", resp.StatusCode)
		}
	}

	for _, tc := range []struct{ name, target, secret string }{
		{"bad signature", "/bucket/literal/%2E%2E/plus%2Bpercent%2525/name%2Ebin", "incorrect"},
		{"bucket scope", "/other/literal/%2E%2E/plus%2Bpercent%2525/name%2Ebin", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"proxy denial", "/bucket/literal/%2E%2E/name?unrecognized=1", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := len(backend.reads)
			req, _ := http.NewRequest(http.MethodGet, server.URL+tc.target, nil)
			literalRoutingSign(t, req, tc.secret)
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal("denial transport failed")
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden || len(backend.reads) != before {
				t.Fatalf("denial status=%d backend_unchanged=%t", resp.StatusCode, len(backend.reads) == before)
			}
		})
	}
}

func TestGH353LiteralRouting_RootConfiguration(t *testing.T) {
	for _, root := range []struct{ path, function string }{{"../../cmd/server/main.go", "main"}, {"../../test/harness/gateway.go", "StartGateway"}} {
		file, err := parser.ParseFile(token.NewFileSet(), root.path, nil, 0)
		if err != nil {
			t.Fatal("root source unavailable")
		}
		found, registered, encoded := token.NoPos, token.NoPos, false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != root.function {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if assign, ok := n.(*ast.AssignStmt); ok && len(assign.Lhs) == 1 && len(assign.Rhs) == 1 {
					id, idOK := assign.Lhs[0].(*ast.Ident)
					call, callOK := assign.Rhs[0].(*ast.CallExpr)
					if idOK && id.Name == "router" && callOK && len(call.Args) == 1 {
						sel, ok := call.Fun.(*ast.SelectorExpr)
						arg, argOK := call.Args[0].(*ast.Ident)
						if ok && sel.Sel.Name == "SkipClean" && argOK && arg.Name == "true" {
							if inner, ok := sel.X.(*ast.CallExpr); ok {
								if fn, ok := inner.Fun.(*ast.SelectorExpr); ok && fn.Sel.Name == "NewRouter" {
									if pkg, ok := fn.X.(*ast.Ident); ok && pkg.Name == "mux" {
										found = assign.Pos()
									}
								}
							}
						}
					}
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "UseEncodedPath" {
					encoded = true
				}
				if sel.Sel.Name == "RegisterRoutes" && len(call.Args) == 1 {
					if arg, ok := call.Args[0].(*ast.Ident); ok && arg.Name == "router" {
						registered = call.Pos()
					}
				}
				return true
			})
		}
		if found == token.NoPos || registered == token.NoPos || found >= registered || encoded {
			t.Fatal("production or harness root does not construct a SkipClean router")
		}
	}
}
