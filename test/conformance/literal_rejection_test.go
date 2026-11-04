//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func TestConformanceLiteralNativeRejection(t *testing.T) {
	if externalOnlyMode() {
		t.Skip("local-only mandatory native rejection proofs; not external evidence")
	}
	providers := provider.GH353LiteralRejectionProviders()
	if len(providers) != 2 {
		t.Fatal("mandatory native rejection fixtures missing or ambiguous")
	}
	for _, p := range providers {
		completed := false
		t.Run(p.Name()+"/PostObject_LiteralNativeRejection", func(t *testing.T) {
			inst := p.Start(context.Background(), t)
			expect, ok := provider.LiteralPostRejectionForInstance(inst)
			if !ok || inst.ProviderName != p.Name() || inst.Endpoint == "" || inst.Bucket == "" || inst.AccessKey == "" || inst.SecretKey == "" || p.CleanupPolicy() != provider.CleanupPolicyDelete {
				t.Fatal("mandatory native rejection fixture incomplete")
			}
			testLiteralNativeRejection(t, inst, expect)
			completed = true
		})
		if !completed {
			t.Error("mandatory native rejection scenario did not complete")
		}
	}
}

type literalRejectionRecorder struct {
	base               http.RoundTripper
	bucket, key        string
	mu                 sync.Mutex
	count, status      int
	exact, transportOK bool
	code               string
}

func (r *literalRejectionRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if req.Method != http.MethodPut {
		return resp, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.count++
	r.exact = req.URL.Path == "/"+r.bucket+"/"+r.key && req.Header.Get("Authorization") != ""
	r.transportOK = err == nil && resp != nil
	if !r.transportOK {
		return resp, err
	}
	r.status = resp.StatusCode
	if resp.Body == nil {
		return resp, err
	}
	// Capture a bounded error without changing the bytes consumed by the SDK.
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if readErr != nil || len(data) > 65536 {
		r.transportOK = false
	}
	var payload struct {
		Code string `xml:"Code"`
	}
	if xml.Unmarshal(data, &payload) == nil {
		r.code = payload.Code
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(data), resp.Body), resp.Body}
	return resp, err
}

func (r *literalRejectionRecorder) matches(expect provider.LiteralPostRejection) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count == 1 && r.exact && r.transportOK && r.status == expect.BackendStatus && r.code == expect.BackendCode
}

func literalRejectionFrontend(resp *http.Response, body []byte, expect provider.LiteralPostRejection, secrets ...string) bool {
	var result struct {
		XMLName xml.Name
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if resp == nil || xml.Unmarshal(body, &result) != nil || result.XMLName.Local != "Error" || resp.StatusCode != expect.GatewayStatus || result.Code != expect.GatewayCode {
		return false
	}
	message := "We encountered an internal error. Please try again."
	if expect.GatewayCode == "InvalidArgument" {
		message = "The request contains an invalid argument."
	}
	if result.Message != message || resp.Header.Get("ETag") != "" || resp.Header.Get("Location") != "" || resp.Header.Get("x-amz-version-id") != "" || bytes.Contains(body, []byte("<PostResponse")) {
		return false
	}
	secrets = append(secrets, postGatewaySecret, postGatewayAccess, postSessionToken)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if bytes.Contains(body, []byte(secret)) {
			return false
		}
		for _, values := range resp.Header {
			for _, value := range values {
				if strings.Contains(value, secret) {
					return false
				}
			}
		}
	}
	return true
}

func testLiteralNativeRejection(t *testing.T, inst provider.Instance, expect provider.LiteralPostRejection) {
	t.Helper()
	prefix := "gh353negative-" + uniqueSuffix(t) + "/"
	exact := prefix + "literal/../plus+percent%25/name.bin"
	neighbor := prefix + "plus+percent%25/name.bin"
	backend := newS3CompatClient(t, inst)
	before, err := literalInventory(t.Context(), backend, inst.Bucket, prefix)
	if err != nil || len(before) != 0 {
		t.Fatal("negative namespace inventory not empty")
	}
	want := []byte("owned neighbor sentinel")
	put, err := backend.PutObject(t.Context(), &awss3.PutObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(neighbor), Body: bytes.NewReader(want), Metadata: map[string]string{"purpose": "neighbor-proof"}, ContentType: aws.String("application/octet-stream")})
	if err != nil || put == nil {
		t.Fatal("neighbor seed failed")
	}
	t.Cleanup(func() {
		input := &awss3.DeleteObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(neighbor)}
		if aws.ToString(put.VersionId) != "" {
			input.VersionId = put.VersionId
		}
		if _, err := backend.DeleteObject(context.Background(), input); err != nil {
			t.Error("owned neighbor cleanup failed")
		}
	})
	headBefore, err := backend.HeadObject(t.Context(), &awss3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(neighbor)})
	if err != nil || headBefore == nil || headBefore.Metadata["purpose"] != "neighbor-proof" || aws.ToString(headBefore.ContentType) != "application/octet-stream" {
		t.Fatal("neighbor seed metadata unavailable")
	}
	recorder := &literalRejectionRecorder{base: http.DefaultTransport, bucket: inst.Bucket, key: exact}
	gw := postGateway(t, inst, postCredential("", nil), harness.WithChunking(true), harness.WithBackendTransport(recorder))
	formKey := prefix + "literal/../plus+percent%25/${filename}"
	req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, formKey, postCredential("", nil), postFormCase{startsWithConditions: map[string]string{"key": strings.TrimSuffix(formKey, "${filename}")}, file: []byte("rejected payload"), fileName: "dir/sub/name.bin"})
	client := gw.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, body := postHTTPWithClient(t, client, req)
	if !recorder.matches(expect) || !literalRejectionFrontend(resp, body, expect, inst.AccessKey, inst.SecretKey) {
		t.Fatalf("native rejection mismatch backend_match=%t frontend_match=%t status=%d", recorder.matches(expect), literalRejectionFrontend(resp, body, expect, inst.AccessKey, inst.SecretKey), resp.StatusCode)
	}
	after, err := literalInventory(t.Context(), backend, inst.Bucket, prefix)
	if err != nil || len(after) != 1 || !after[neighbor] || after[exact] {
		t.Fatal("post-rejection native inventory mismatch")
	}
	headAfter, err := backend.HeadObject(t.Context(), &awss3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(neighbor)})
	if err != nil || headAfter == nil || aws.ToString(headAfter.ETag) != aws.ToString(headBefore.ETag) || aws.ToString(headAfter.VersionId) != aws.ToString(headBefore.VersionId) || aws.ToString(headAfter.ContentType) != aws.ToString(headBefore.ContentType) || !reflect.DeepEqual(headAfter.Metadata, headBefore.Metadata) {
		t.Fatal("neighbor metadata or version changed")
	}
	got, err := backend.GetObject(t.Context(), &awss3.GetObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(neighbor)})
	if err != nil {
		t.Fatal("neighbor read failed")
	}
	data, readErr := io.ReadAll(got.Body)
	closeErr := got.Body.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(data, want) {
		t.Fatal("neighbor payload changed")
	}
}
