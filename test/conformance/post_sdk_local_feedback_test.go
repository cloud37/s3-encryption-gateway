//go:build conformance

package conformance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// sdkShapedPost independently creates a form with the runner's fields and
// SDK-style implicit bucket condition. It is not an actual SDK-generated form.
func sdkShapedPost(t *testing.T, endpoint, style string, credential config.GatewayCredential, fields map[string]string, mutation string, payload []byte) *http.Request {
	t.Helper()
	now := time.Now().UTC()
	date := now.Format("20060102T150405Z")
	scope := credential.AccessKey + "/" + date[:8] + "/" + testRegion + "/s3/aws4_request"
	values := make(map[string]string, len(fields)+6)
	conditions := make([]any, 0, len(fields)+7)
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values[name] = fields[name]
		conditions = append(conditions, map[string]string{name: fields[name]})
	}
	values["key"] = "sdk-local-key"
	values["x-amz-algorithm"] = "AWS4-HMAC-SHA256"
	values["x-amz-credential"] = scope
	values["x-amz-date"] = date
	conditions = append(conditions, []any{"content-length-range", 32768, 32768}, map[string]string{"bucket": "bucket"}, map[string]string{"key": values["key"]}, map[string]string{"x-amz-algorithm": values["x-amz-algorithm"]}, map[string]string{"x-amz-credential": scope}, map[string]string{"x-amz-date": date})
	if style != "boto" {
		values["bucket"] = "bucket"
		for _, name := range []string{"algorithm", "credential", "date"} {
			lower, sdkName := "x-amz-"+name, "X-Amz-"+strings.ToUpper(name[:1])+name[1:]
			values[sdkName] = values[lower]
			delete(values, lower)
		}
	}
	tokenField, signatureField := "x-amz-security-token", "x-amz-signature"
	if style != "boto" {
		tokenField, signatureField = "X-Amz-Security-Token", "X-Amz-Signature"
	}
	if credential.SessionToken != "" {
		values[tokenField] = credential.SessionToken
		if mutation != "uncovered" {
			conditions = append(conditions, map[string]string{tokenField: credential.SessionToken})
		}
	}
	policy, err := json.Marshal(map[string]any{"expiration": now.Add(10 * time.Minute).Format(time.RFC3339), "conditions": conditions})
	if err != nil {
		t.Fatal("marshal fixture policy")
	}
	encoded := base64.StdEncoding.EncodeToString(policy)
	policyField := "policy"
	if style != "boto" {
		policyField = "Policy"
	}
	values[policyField] = encoded
	values[signatureField] = postPolicySignature(credential.SecretKey, date[:8], testRegion, encoded)
	switch mutation {
	case "wrong":
		values[tokenField] = "wrong-token"
	case "missing":
		delete(values, tokenField)
	case "policy":
		values["x-amz-meta-purpose"] = "different"
	case "length":
		payload = payload[:len(payload)-1]
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if style == "boto" {
		if err := w.SetBoundary("gh353-sdk-boundary-9d2f"); err != nil {
			t.Fatal("fixture boundary")
		}
	}
	names = names[:0]
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := w.WriteField(name, values[name]); err != nil {
			t.Fatal("fixture field")
		}
	}
	file, err := w.CreateFormFile("file", "sdk.bin")
	if err != nil {
		t.Fatal("fixture file")
	}
	if _, err = file.Write(payload); err != nil {
		t.Fatal("fixture payload")
	}
	if err = w.Close(); err != nil {
		t.Fatal("fixture close")
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, &body)
	if err != nil {
		t.Fatal("fixture request")
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}

func TestGH353SDKShapedStaticSessionProductionChain(t *testing.T) {
	for _, style := range []string{"boto", "js", "browser"} {
		for _, session := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/session=%t", style, session), func(t *testing.T) {
				var mu sync.Mutex
				var stored []byte
				var headers http.Header
				puts := 0
				backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					if r.Method == http.MethodPut {
						stored, _ = io.ReadAll(r.Body)
						headers = r.Header.Clone()
						puts++
						w.Header().Set("ETag", `"backend-etag"`)
						return
					}
					if stored == nil {
						w.WriteHeader(404)
						return
					}
					for k, v := range headers {
						if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") || strings.EqualFold(k, "Content-Type") || strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Content-Disposition") || strings.EqualFold(k, "Content-Language") || strings.EqualFold(k, "Cache-Control") || strings.EqualFold(k, "Expires") {
							w.Header()[k] = v
						}
					}
					w.Header().Set("ETag", `"backend-etag"`)
					w.Header().Set("Content-Length", fmt.Sprint(len(stored)))
					if r.Method == http.MethodGet {
						_, _ = w.Write(stored)
					}
				}))
				defer backend.Close()
				inst := provider.Instance{ProviderName: provider.GH353FeedbackCompactingProvider().Name(), Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
				var deadline *time.Time
				token := ""
				if session {
					d := time.Now().UTC().Add(2 * time.Hour)
					deadline = &d
					token = postSessionToken
				}
				credential := postCredential(token, deadline)
				gw := postGateway(t, inst, credential, harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
				fields := map[string]string{"Content-Type": "application/octet-stream", "Content-Encoding": "identity", "Content-Disposition": "attachment", "Cache-Control": "private", "Content-Language": "en-GB", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT", "x-amz-meta-owner": "sdk-post", "x-amz-meta-purpose": "awsjs"}
				if style == "boto" {
					fields["x-amz-meta-purpose"] = "boto3"
				}
				if style == "browser" {
					fields["Content-Disposition"] = "inline"
					fields["Cache-Control"] = "no-cache"
					fields["Content-Language"] = "en"
					fields["Expires"] = "Wed, 21 Oct 2030 07:28:00 GMT"
					fields["x-amz-meta-owner"] = "browser-post"
					fields["x-amz-meta-purpose"] = "browser"
				}
				payload := make([]byte, 32768)
				for i := range payload {
					payload[i] = byte(i % 251)
				}
				send := func(mutation string, status int, code string) {
					t.Helper()
					r := sdkShapedPost(t, postFormURL(gw, "bucket"), style, credential, fields, mutation, payload)
					if style == "browser" {
						r.Header.Set("Origin", "http://browser.example")
					}
					resp, body := postHTTP(t, gw, credential, r)
					if resp.StatusCode != status || (code != "" && postSafeErrorCode(body) != code) || (status == 204 && len(body) != 0) {
						t.Fatalf("fixture mutation=%s status=%d code=%s", mutation, resp.StatusCode, postSafeErrorCode(body))
					}
				}
				send("", 204, "")
				send("policy", 403, "AccessDenied")
				send("length", 400, "EntityTooSmall")
				if session {
					send("wrong", 403, "InvalidToken")
					send("missing", 403, "InvalidToken")
					send("uncovered", 403, "AccessDenied")
				}
				mu.Lock()
				count := puts
				encrypted := len(stored) > 0 && !bytes.Equal(stored, payload)
				mu.Unlock()
				if count != 1 || !encrypted {
					t.Fatal("positive or denial backend invariant failed")
				}
				resp, data := postGatewayGet(t, gw, "bucket", "sdk-local-key", token, nil)
				if resp.StatusCode != 200 || !bytes.Equal(data, payload) {
					t.Fatalf("GET status=%d bytes_match=%t", resp.StatusCode, bytes.Equal(data, payload))
				}
				head := postGatewayHead(t, gw, "bucket", "sdk-local-key", token, nil)
				if head.StatusCode != 200 || head.ContentLength != int64(len(payload)) || head.Header.Get("ETag") != resp.Header.Get("ETag") {
					t.Fatal("fixture HEAD or ETag mismatch")
				}
				for name, want := range fields {
					if resp.Header.Get(name) != want || head.Header.Get(name) != want {
						t.Fatalf("fixture GET/HEAD metadata mismatch for %s", name)
					}
				}
				rangeResp, rangeBody := postGatewayGet(t, gw, "bucket", "sdk-local-key", token, http.Header{"Range": []string{"bytes=0-127"}})
				if rangeResp.StatusCode != 206 || !bytes.Equal(rangeBody, payload[:128]) || rangeResp.Header.Get("Content-Range") != "bytes 0-127/32768" || rangeResp.Header.Get("ETag") != head.Header.Get("ETag") {
					t.Fatal("fixture range mismatch")
				}
				for name, want := range fields {
					if rangeResp.Header.Get(name) != want {
						t.Fatalf("fixture range metadata mismatch for %s", name)
					}
				}
				if style == "boto" && !session {
					testBotoMetadataWire(t, gw)
				}
			})
		}
	}
}

// Model urllib3's original-case header iteration and botocore 1.43.111's
// HeadersDict and _parse_header_map over actual gateway HTTP/1.1 responses.
// This is a source-backed local model, not an SDK or provider runtime test.
func testBotoMetadataWire(t *testing.T, gw *harness.Gateway) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable for wire fixture")
	}
	type wireRequest struct {
		Method string              `json:"method"`
		URL    string              `json:"url"`
		Header map[string][]string `json:"header"`
	}
	var requests []wireRequest
	for _, method := range []string{"HEAD", "GET", "RANGE"} {
		verb := method
		var headers http.Header
		if method == "RANGE" {
			verb = "GET"
			headers = http.Header{"Range": []string{"bytes=0-127"}}
		}
		req := signedGatewayRequest(t, verb, postObjectURL(gw, "bucket", "sdk-local-key"), nil, "", headers)
		requests = append(requests, wireRequest{verb, req.URL.String(), req.Header})
	}
	input, err := json.Marshal(requests)
	if err != nil {
		t.Fatal("wire fixture encoding failed")
	}
	source := (&boto3PresignedPostRunner{}).Script(sdkTestEnv{})
	normalize := dedentPython(boundaryExtract(t, source, "    def normalized_user_metadata(", "\n    def verify_readback("))
	fixture := `import http.client, json, sys, urllib.parse
` + normalize + `
for request in json.load(sys.stdin):
    u=urllib.parse.urlsplit(request['url'])
    conn=http.client.HTTPConnection(u.hostname,u.port)
    headers={k:', '.join(v) for k,v in request['header'].items()}
    conn.request(request['method'],u.path,headers=headers)
    response=conn.getresponse()
    assert response.status in (200,206)
    # urllib3 HTTPHeaderDict iterates original header spelling; HeadersDict
    # stores that spelling while comparing keys case-insensitively.
    original={}
    for name,value in response.getheaders():
        original.setdefault(name.lower(),(name,value))
    headers={name:value for name,value in original.values()}
    prefix='x-amz-meta-'
    parsed={}
    for header_name in headers:
        if header_name.lower().startswith(prefix):
            name=header_name[len(prefix):]
            parsed[name]=headers[header_name]
    assert 'Owner' in parsed and 'owner' not in parsed
    assert 'Purpose' in parsed and 'purpose' not in parsed
    try: parsed['owner']
    except KeyError: pass
    else: raise AssertionError('old assertion unexpectedly passed')
    normalized=normalized_user_metadata({'Metadata':parsed})
    assert normalized['owner']=='sdk-post' and normalized['purpose']=='boto3'
    response.read()
    conn.close()
`
	cmd := exec.Command(python, "-c", fixture)
	cmd.Stdin = bytes.NewReader(input)
	if err := cmd.Run(); err != nil {
		t.Fatal("source-backed boto metadata wire fixture failed; output suppressed")
	}
}
