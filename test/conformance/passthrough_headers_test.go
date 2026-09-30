//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

type passthroughObservation struct {
	headers       http.Header
	before, after error
}

// A provider-independent S3 frontend: validate the original signature,
// append to X-Forwarded-For, validate again, then forward to the real provider.
// Clients inject frontend proxy headers; no extra Docker fixture is needed.
func passthroughBackendFrontend(t *testing.T, inst provider.Instance) (string, <-chan passthroughObservation) {
	t.Helper()
	target, err := url.Parse(inst.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	observations := make(chan passthroughObservation, 32)
	proxy := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(target)
		// Verification above proves the gateway's signature survived the
		// mutation. Re-sign the final hop for the real provider's host so
		// external frontends can route it just like an ordinary S3 request.
		// Add the transport-only XFF after signing this final hop.
		pr.Out.Header.Del("X-Forwarded-For")
		if err := v4.NewSigner().SignHTTP(pr.Out.Context(), aws.Credentials{AccessKeyID: inst.AccessKey, SecretAccessKey: inst.SecretKey}, pr.Out, pr.Out.Header.Get("X-Amz-Content-Sha256"), "s3", inst.Region, time.Now()); err != nil {
			t.Errorf("sign backend frontend final hop: %v", err)
		}
		pr.Out.Header.Set("X-Forwarded-For", pr.In.Header.Get("X-Forwarded-For"))
	}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs := passthroughObservation{headers: r.Header.Clone()}
		ctx, err := api.ValidateSignatureV4(r, inst.SecretKey, 5*time.Minute)
		obs.before = err
		if ctx != nil {
			ctx.Close()
		}
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			xff += ", "
		}
		r.Header.Set("X-Forwarded-For", xff+"192.0.2.20")
		ctx, obs.after = api.ValidateSignatureV4(r, inst.SecretKey, 5*time.Minute)
		if ctx != nil {
			ctx.Close()
		}
		observations <- obs
		if obs.before != nil || obs.after != nil {
			(&api.S3Error{Code: "SignatureDoesNotMatch", Message: "The request signature does not match.", HTTPStatus: http.StatusForbidden}).WriteXML(w)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server.URL, observations
}

func passthroughProxyHeaders(req *http.Request) {
	for key, value := range map[string]string{
		"X-Forwarded-For": "203.0.113.10", "X-Forwarded-Host": "gateway.example",
		"X-Forwarded-Proto": "https", "X-Forwarded-Port": "443",
		"Forwarded": "for=203.0.113.10;proto=https", "Via": "1.1 frontend",
		"X-Real-IP": "203.0.113.10", "X-Unrelated": "must-not-reach-provider",
	} {
		req.Header.Set(key, value)
	}
}

func passthroughGateway(t *testing.T, inst provider.Instance, c config.GatewayCredential, options ...harness.Option) (*harness.Gateway, <-chan passthroughObservation) {
	t.Helper()
	endpoint, observations := passthroughBackendFrontend(t, inst)
	opts := []harness.Option{harness.WithAuth(c), harness.WithConfigMutator(func(cfg *config.Config) { cfg.Backend.Endpoint = endpoint })}
	opts = append(opts, options...)
	return harness.StartGateway(t, inst, opts...), observations
}

func passthroughRequest(t *testing.T, gw *harness.Gateway, observations <-chan passthroughObservation, c config.GatewayCredential, method, path string, body []byte, headers http.Header, forwarded bool) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, gw.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if headers != nil {
		req.Header = headers.Clone()
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, c.AccessKey, c.SecretKey, body)
	// Like Caddy, append these after the client signs its S3 request.
	if forwarded {
		passthroughProxyHeaders(req)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case obs := <-observations:
		if obs.before != nil || obs.after != nil {
			t.Errorf("backend signature before=%v after=%v", obs.before, obs.after)
		}
		for _, key := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "Forwarded", "Via", "X-Real-IP", "X-Unrelated"} {
			if obs.headers.Get(key) != "" {
				t.Errorf("gateway forwarded prohibited %s", key)
			}
		}
		for key, want := range headers {
			if got := obs.headers.Values(key); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("backend %s=%q want=%q", key, got, want)
			}
		}
	default:
		t.Fatal("request did not reach the backend frontend")
	}
	return resp, data
}

func testPassthroughProxyHeadersLocation(t *testing.T, inst provider.Instance) {
	// Positive control proves the fixture detects a signed header mutation,
	// independently of the provider's own frontend behavior.
	endpoint, observations := passthroughBackendFrontend(t, inst)
	req, err := http.NewRequest("GET", endpoint+"/"+inst.Bucket+"?location", nil)
	if err != nil {
		t.Fatal(err)
	}
	passthroughProxyHeaders(req)
	hash := sha256.Sum256(nil)
	payloadHash := hex.EncodeToString(hash[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: inst.AccessKey, SecretAccessKey: inst.SecretKey}, req, payloadHash, "s3", inst.Region, time.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	obs := <-observations
	if resp.StatusCode != http.StatusForbidden || obs.before != nil || obs.after == nil {
		t.Fatalf("frontend control: status=%d before=%v after=%v", resp.StatusCode, obs.before, obs.after)
	}
	c := config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}
	gw, observations := passthroughGateway(t, inst, c)
	for _, forwarded := range []bool{false, true} {
		resp, data := passthroughRequest(t, gw, observations, c, "GET", "/"+inst.Bucket+"?location", nil, nil, forwarded)
		var result struct {
			Location string `xml:",chardata"`
		}
		if resp.StatusCode != http.StatusOK || xml.Unmarshal(data, &result) != nil || result.Location != "" && result.Location != inst.Region {
			t.Fatalf("GetBucketLocation forwarded=%t: status=%d body=%s", forwarded, resp.StatusCode, data)
		}
	}
}

func testPassthroughProxyHeadersCreateBucket(t *testing.T, inst provider.Instance) {
	name := "gh338-" + uniqueSuffix(t)
	c := bucketManagementCredential(name, config.BucketPermissionCreate, config.BucketPermissionDelete)
	gw, observations := passthroughGateway(t, inst, c, harness.WithBucketCreation(true))
	body := []byte("<CreateBucketConfiguration><LocationConstraint>" + inst.Region + "</LocationConstraint></CreateBucketConfiguration>")
	resp, data := passthroughRequest(t, gw, observations, c, "PUT", "/"+name, body, http.Header{"Content-Type": {"application/xml"}}, true)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("CreateBucket: status=%d body=%s", resp.StatusCode, data)
	}
	t.Cleanup(func() { _, _ = bucketManagementRequest(t, gw, "DELETE", name, nil, c) })
	resp, data = passthroughRequest(t, gw, observations, c, "GET", "/"+name+"?location", nil, nil, true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("new bucket location: status=%d body=%s", resp.StatusCode, data)
	}
}

func testPassthroughProxyHeadersMultipartListing(t *testing.T, inst provider.Instance) {
	c := config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}
	gw, observations := passthroughGateway(t, inst, c)
	resp, data := passthroughRequest(t, gw, observations, c, "GET", "/"+inst.Bucket+"?uploads", nil, nil, true)
	var result struct{ XMLName xml.Name }
	if resp.StatusCode != http.StatusOK || xml.Unmarshal(data, &result) != nil || result.XMLName.Local != "ListMultipartUploadsResult" {
		t.Fatalf("ListMultipartUploads: status=%d body=%s", resp.StatusCode, data)
	}
}

func testPassthroughProxyHeadersListBuckets(t *testing.T, inst provider.Instance) {
	backend := newS3CompatClient(t, inst)
	if _, err := backend.ListBuckets(t.Context(), &s3.ListBucketsInput{}); err != nil {
		if strings.Contains(err.Error(), "AccessDenied") || strings.Contains(err.Error(), "Forbidden") {
			t.Skipf("backend credential does not permit account-wide ListBuckets: %v", err)
		}
		t.Fatal(err)
	}
	c := config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey, Buckets: []string{inst.Bucket}}
	gw, observations := passthroughGateway(t, inst, c)
	resp, data := passthroughRequest(t, gw, observations, c, "GET", "/", nil, nil, true)
	var result struct {
		Buckets []struct{ Name string } `xml:"Buckets>Bucket"`
	}
	if resp.StatusCode != http.StatusOK || xml.Unmarshal(data, &result) != nil || len(result.Buckets) != 1 || result.Buckets[0].Name != inst.Bucket {
		t.Fatalf("ListBuckets filtered inventory: status=%d body=%s", resp.StatusCode, data)
	}
}

func testPassthroughProxyHeadersTagging(t *testing.T, inst provider.Instance) {
	c := config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}
	gw, observations := passthroughGateway(t, inst, c)
	key := uniqueKey(t)
	// Direct setup/cleanup keeps the observation channel specific to passthrough.
	backend := newS3CompatClient(t, inst)
	if _, err := backend.PutObject(t.Context(), &s3.PutObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key), Body: strings.NewReader("data")}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = backend.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
	})
	body := []byte("<Tagging><TagSet><Tag><Key>gh338</Key><Value>preserved</Value></Tag></TagSet></Tagging>")
	digest := md5.Sum(body) // #nosec G401 -- S3 Content-MD5 compatibility header
	headers := http.Header{"Content-Type": {"application/xml"}, "Content-Md5": {base64.StdEncoding.EncodeToString(digest[:])}}
	resp, data := passthroughRequest(t, gw, observations, c, "PUT", "/"+inst.Bucket+"/"+key+"?tagging", body, headers, true)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PutObjectTagging: status=%d body=%s", resp.StatusCode, data)
	}
	resp, data = passthroughRequest(t, gw, observations, c, "GET", "/"+inst.Bucket+"/"+key+"?tagging", nil, nil, true)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(data, []byte("<Key>gh338</Key>")) || !bytes.Contains(data, []byte("<Value>preserved</Value>")) {
		t.Fatalf("GetObjectTagging: status=%d body=%s", resp.StatusCode, data)
	}
}

func testPassthroughProxyHeadersCORS(t *testing.T, inst provider.Instance) {
	backend := newS3CompatClient(t, inst)
	_, err := backend.PutBucketCors(t.Context(), &s3.PutBucketCorsInput{Bucket: aws.String(inst.Bucket), CORSConfiguration: &types.CORSConfiguration{CORSRules: []types.CORSRule{{AllowedOrigins: []string{"https://client.example"}, AllowedMethods: []string{"PUT"}, AllowedHeaders: []string{"*"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = backend.DeleteBucketCors(context.Background(), &s3.DeleteBucketCorsInput{Bucket: aws.String(inst.Bucket)})
	})
	c := config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}
	gw, observations := passthroughGateway(t, inst, c)
	headers := http.Header{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"PUT"}, "Access-Control-Request-Headers": {"content-type"}}
	resp, data := passthroughRequest(t, gw, observations, c, "OPTIONS", "/"+inst.Bucket+"/key", nil, headers, true)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || resp.Header.Get("Access-Control-Allow-Origin") != "https://client.example" || !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "PUT") {
		t.Fatalf("CORS: status=%d headers=%v body=%s", resp.StatusCode, resp.Header, data)
	}
}

// Providers need not implement bucket CORS configuration to prove that the
// gateway preserves preflight inputs and the backend's native response.
func testPassthroughProxyHeadersCORSForwarding(t *testing.T, inst provider.Instance) {
	headers := http.Header{"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"PUT"}, "Access-Control-Request-Headers": {"content-type"}}
	req, err := http.NewRequest("OPTIONS", inst.Endpoint+"/"+inst.Bucket+"/key", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header = headers.Clone()
	hash := sha256.Sum256(nil)
	payloadHash := hex.EncodeToString(hash[:])
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: inst.AccessKey, SecretAccessKey: inst.SecretKey}, req, payloadHash, "s3", inst.Region, time.Now()); err != nil {
		t.Fatal(err)
	}
	direct, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, direct.Body)
	_ = direct.Body.Close()
	c := config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}
	gw, observations := passthroughGateway(t, inst, c)
	resp, data := passthroughRequest(t, gw, observations, c, "OPTIONS", "/"+inst.Bucket+"/key", nil, headers, true)
	if resp.StatusCode != direct.StatusCode || bytes.Contains(data, []byte("<Code>SignatureDoesNotMatch</Code>")) {
		t.Fatalf("preflight: gateway status=%d direct=%d body=%s", resp.StatusCode, direct.StatusCode, data)
	}
	for _, key := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"} {
		if resp.Header.Get(key) != direct.Header.Get(key) {
			t.Errorf("preflight %s=%q direct=%q", key, resp.Header.Get(key), direct.Header.Get(key))
		}
	}
}
