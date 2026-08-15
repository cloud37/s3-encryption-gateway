//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

const (
	testAccessKey = "AKIAIOSFODNN7EXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	testRegion    = "us-east-1"
	testService   = "s3"
)

// --- SigV4 signing helpers ---

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func getSignatureKey(secretKey, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func buildStringToSign(timestamp, credentialScope, canonicalRequest string) string {
	return fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s", timestamp, credentialScope, sha256Hex([]byte(canonicalRequest)))
}

func buildCanonicalRequest(req *http.Request, isPresigned bool, signedHeaders []string) string {
	var buf strings.Builder

	buf.WriteString(req.Method)
	buf.WriteByte('\n')

	uri := req.URL.Path
	if uri == "" {
		uri = "/"
	}
	buf.WriteString(uri)
	buf.WriteByte('\n')

	query := req.URL.Query()
	if isPresigned {
		query.Del("X-Amz-Signature")
	}
	var keys []string
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qparts []string
	for _, k := range keys {
		vals := query[k]
		sort.Strings(vals)
		for _, v := range vals {
			qparts = append(qparts, uriEncodeV4(k)+"="+uriEncodeV4(v))
		}
	}
	buf.WriteString(strings.Join(qparts, "&"))
	buf.WriteByte('\n')

	hdr := make(map[string][]string)
	for k, v := range req.Header {
		hdr[strings.ToLower(k)] = v
	}
	if _, ok := hdr["host"]; !ok && req.Host != "" {
		hdr["host"] = []string{req.Host}
	}

	sort.Strings(signedHeaders)
	for _, h := range signedHeaders {
		lh := strings.ToLower(h)
		vals := hdr[lh]
		var trimmed []string
		for _, v := range vals {
			trimmed = append(trimmed, strings.TrimSpace(v))
		}
		buf.WriteString(lh)
		buf.WriteByte(':')
		buf.WriteString(strings.Join(trimmed, ","))
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')

	buf.WriteString(strings.Join(signedHeaders, ";"))
	buf.WriteByte('\n')

	ph := req.Header.Get("X-Amz-Content-Sha256")
	if ph == "" {
		ph = "UNSIGNED-PAYLOAD"
	}
	buf.WriteString(ph)

	return buf.String()
}

func uriEncodeV4(s string) string {
	encoded := url.QueryEscape(s)
	return strings.ReplaceAll(encoded, "+", "%20")
}

func signV4Headers(t *testing.T, req *http.Request, accessKey, secretKey string, body []byte) {
	t.Helper()
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, testRegion, testService)

	req.Header.Set("X-Amz-Date", timestamp)

	payloadHash := "UNSIGNED-PAYLOAD"
	if len(body) > 0 {
		payloadHash = sha256Hex(body)
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	signedHdrs := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalReq := buildCanonicalRequest(req, false, signedHdrs)
	stringToSign := buildStringToSign(timestamp, credScope, canonicalReq)
	signingKey := getSignatureKey(secretKey, date, testRegion, testService)
	sig := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credScope, strings.Join(signedHdrs, ";"), sig))
}

func presignV4GET(t *testing.T, gw *harness.Gateway, bucket, key, accessKey, secretKey string, expiry time.Duration) string {
	t.Helper()
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, testRegion, testService)

	rawURL := objectURL(gw, bucket, key)
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("presignV4GET: parse URL: %v", err)
	}

	q := u.Query()
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+credScope)
	q.Set("X-Amz-Date", timestamp)
	expiresSeconds := int(expiry.Seconds())
	q.Set("X-Amz-Expires", fmt.Sprintf("%d", expiresSeconds))
	q.Set("X-Amz-SignedHeaders", "host")

	req := &http.Request{
		Method: "GET",
		URL:    u,
		Host:   u.Host,
		Header: make(http.Header),
	}
	req.URL.RawQuery = q.Encode()

	canonicalReq := buildCanonicalRequest(req, true, []string{"host"})
	stringToSign := buildStringToSign(timestamp, credScope, canonicalReq)
	signingKey := getSignatureKey(secretKey, date, testRegion, testService)
	sig := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	q.Set("X-Amz-Signature", sig)
	u.RawQuery = q.Encode()

	return u.String()
}

// --- Signed request helpers ---

func putSigned(t *testing.T, gw *harness.Gateway, bucket, key string, data []byte, accessKey, secretKey string) {
	t.Helper()
	req, err := http.NewRequest("PUT", objectURL(gw, bucket, key), bytes.NewReader(data))
	if err != nil {
		t.Fatalf("putSigned: new request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, accessKey, secretKey, data)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("putSigned %q: %v", key, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("putSigned %q: status %d: %s", key, resp.StatusCode, string(body))
	}
}

func getSigned(t *testing.T, gw *harness.Gateway, bucket, key string, accessKey, secretKey string) []byte {
	t.Helper()
	req, err := http.NewRequest("GET", objectURL(gw, bucket, key), nil)
	if err != nil {
		t.Fatalf("getSigned: new request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, accessKey, secretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("getSigned %q: %v", key, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("getSigned %q: read body: %v", key, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("getSigned %q: status %d: %s", key, resp.StatusCode, string(body))
	}
	return body
}

func deleteSigned(t *testing.T, gw *harness.Gateway, bucket, key string, accessKey, secretKey string) {
	t.Helper()
	req, err := http.NewRequest("DELETE", objectURL(gw, bucket, key), nil)
	if err != nil {
		t.Fatalf("deleteSigned: new request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, accessKey, secretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("deleteSigned %q: %v", key, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("deleteSigned %q: status %d: %s", key, resp.StatusCode, string(body))
	}
}

// --- Test cases ---

// testAuth_V4_PutGetDelete verifies the full PUT→GET→DELETE cycle with
// SigV4 header authentication.
func testAuth_V4_PutGetDelete(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{
			AccessKey: testAccessKey, SecretKey: testSecretKey, Label: "test-user",
		}),
	)

	key := uniqueKey(t)
	data := []byte("auth-v4-put-get-delete")

	putSigned(t, gw, inst.Bucket, key, data, testAccessKey, testSecretKey)
	got := getSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey)
	if !bytes.Equal(got, data) {
		t.Fatal("V4 PUT then GET: data mismatch")
	}
	deleteSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey)
}

// testAuth_Unauthenticated_Rejected verifies that requests without any
// credentials return 403 AccessDenied.
func testAuth_Unauthenticated_Rejected(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{
			AccessKey: testAccessKey, SecretKey: testSecretKey, Label: "test-user",
		}),
	)

	key := uniqueKey(t)
	resp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatalf("unsigned GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unsigned GET: status %d, want 403: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "AccessDenied") {
		t.Fatalf("unsigned GET: body missing AccessDenied: %s", string(body))
	}
}

// testAuth_WrongSecret_Rejected verifies that requests signed with an
// incorrect secret key return 403 SignatureDoesNotMatch.
func testAuth_WrongSecret_Rejected(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{
			AccessKey: testAccessKey, SecretKey: testSecretKey, Label: "test-user",
		}),
	)

	key := uniqueKey(t)
	req, err := http.NewRequest("GET", objectURL(gw, inst.Bucket, key), nil)
	if err != nil {
		t.Fatalf("wrong-secret: new request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, testAccessKey, "wrong-"+testSecretKey, nil)

	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("wrong-secret request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong-secret: status %d, want 403: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "SignatureDoesNotMatch") {
		t.Fatalf("wrong-secret: body missing SignatureDoesNotMatch: %s", string(body))
	}
}

// testAuth_PresignedURL_Valid verifies that a presigned GET URL signed with
// valid credentials allows unsigned access within the expiry window.
func testAuth_PresignedURL_Valid(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{
			AccessKey: testAccessKey, SecretKey: testSecretKey, Label: "test-user",
		}),
	)

	key := uniqueKey(t)
	data := []byte("presigned-valid-data")

	putSigned(t, gw, inst.Bucket, key, data, testAccessKey, testSecretKey)

	presignedURL := presignV4GET(t, gw, inst.Bucket, key, testAccessKey, testSecretKey, 3600*time.Second)
	resp, err := gw.HTTPClient().Get(presignedURL)
	if err != nil {
		t.Fatalf("presigned GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("presigned GET: status %d: %s", resp.StatusCode, string(body))
	}
	if !bytes.Equal(body, data) {
		t.Fatal("presigned GET: data mismatch")
	}
}

// testAuth_PresignedURL_Expired verifies that a presigned URL with zero
// expiry (X-Amz-Expires=0) is rejected with 403.
func testAuth_PresignedURL_Expired(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{
			AccessKey: testAccessKey, SecretKey: testSecretKey, Label: "test-user",
		}),
	)

	key := uniqueKey(t)
	data := []byte("presigned-expired-data")

	putSigned(t, gw, inst.Bucket, key, data, testAccessKey, testSecretKey)

	presignedURL := presignV4GET(t, gw, inst.Bucket, key, testAccessKey, testSecretKey, 0)
	resp, err := gw.HTTPClient().Get(presignedURL)
	if err != nil {
		t.Fatalf("expired presigned GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expired presigned: status %d, want 403: %s", resp.StatusCode, string(body))
	}
}

// testAuth_MultiCredential verifies that two independently configured
// credentials both authenticate successfully, and that an unknown access
// key is rejected.
func testAuth_MultiCredential(t *testing.T, inst provider.Instance) {
	t.Helper()
	cred1 := config.GatewayCredential{AccessKey: "AKIAID1", SecretKey: "s3kr1t1", Label: "user1"}
	cred2 := config.GatewayCredential{AccessKey: "AKIAID2", SecretKey: "s3kr1t2", Label: "user2"}
	gw := harness.StartGateway(t, inst, harness.WithAuth(cred1, cred2))

	key := uniqueKey(t)
	data := []byte("multi-credential-data")

	putSigned(t, gw, inst.Bucket, key, data, "AKIAID1", "s3kr1t1")
	got := getSigned(t, gw, inst.Bucket, key, "AKIAID2", "s3kr1t2")
	if !bytes.Equal(got, data) {
		t.Fatal("multi-credential: data mismatch when read with cred2")
	}
	deleteSigned(t, gw, inst.Bucket, key, "AKIAID1", "s3kr1t1")

	req, err := http.NewRequest("GET", objectURL(gw, inst.Bucket, key), nil)
	if err != nil {
		t.Fatalf("multi-credential: new request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, "UNKNOWN_KEY", "whatever", nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("multi-credential unknown: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("multi-credential unknown: status %d, want 403: %s", resp.StatusCode, string(body))
	}
}

// testAuth_ProxiedBucketFilter verifies that when proxied_bucket is
// configured, requests to other buckets are rejected with 403 AccessDenied.
func testAuth_ProxiedBucketFilter(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{
			AccessKey: testAccessKey, SecretKey: testSecretKey, Label: "test-user",
		}),
		harness.WithConfigMutator(func(cfg *config.Config) {
			cfg.ProxiedBucket = inst.Bucket
		}),
	)

	key := uniqueKey(t)
	data := []byte("proxied-bucket-data")

	putSigned(t, gw, inst.Bucket, key, data, testAccessKey, testSecretKey)
	got := getSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey)
	if !bytes.Equal(got, data) {
		t.Fatal("proxied-bucket: data mismatch")
	}

	otherBucket := inst.Bucket + "-nope"
	req, err := http.NewRequest("GET", objectURL(gw, otherBucket, key), nil)
	if err != nil {
		t.Fatalf("proxied-bucket other: new request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, testAccessKey, testSecretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("proxied-bucket other: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("proxied-bucket other: status %d, want 403: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "AccessDenied") {
		t.Fatalf("proxied-bucket other: body missing AccessDenied: %s", string(body))
	}
}

// testAuth_ProxiedBucketMetricsPrefixRejected verifies that an authenticated
// request cannot use a metrics-prefixed S3 bucket path to bypass the
// proxied_bucket authorization boundary.
func testAuth_ProxiedBucketMetricsPrefixRejected(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{
			AccessKey: testAccessKey, SecretKey: testSecretKey, Label: "test-user",
		}),
		harness.WithConfigMutator(func(cfg *config.Config) {
			cfg.ProxiedBucket = inst.Bucket
		}),
	)

	otherBucket := "metrics-" + inst.Bucket
	key := uniqueKey(t)
	req, err := http.NewRequest("GET", objectURL(gw, otherBucket, key), nil)
	if err != nil {
		t.Fatalf("metrics-prefix bypass: new request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, testAccessKey, testSecretKey, nil)

	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("metrics-prefix bypass: request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("metrics-prefix bypass: status %d, want 403: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), "AccessDenied") {
		t.Fatalf("metrics-prefix bypass: body missing AccessDenied: %s", string(body))
	}
}

// testAuthorization_ExactAndWildcardBucketScopes verifies that a credential
// can access only its exact bucket scope, and that a trailing-prefix scope
// matches that bucket without widening access to unrelated buckets.
func testAuthorization_ExactAndWildcardBucketScopes(t *testing.T, inst provider.Instance) {
	t.Helper()
	if len(inst.Bucket) < 2 {
		t.Skip("provider test bucket is too short to derive a wildcard scope")
	}

	for _, tc := range []struct {
		name    string
		buckets []string
	}{
		{name: "exact", buckets: []string{inst.Bucket}},
		{name: "wildcard", buckets: []string{inst.Bucket[:len(inst.Bucket)-1] + "*"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			credential := config.GatewayCredential{
				AccessKey: testAccessKey,
				SecretKey: testSecretKey,
				Label:     "scoped-user",
				Buckets:   tc.buckets,
			}
			gw := harness.StartGateway(t, inst, harness.WithAuth(credential))

			key := uniqueKey(t)
			data := []byte("credential-scope-data")
			putSigned(t, gw, inst.Bucket, key, data, testAccessKey, testSecretKey)
			if got := getSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey); !bytes.Equal(got, data) {
				t.Fatal("scoped credential returned incorrect object data")
			}

			assertSignedAccessDenied(t, gw, http.MethodGet, "outside-"+inst.Bucket, key, nil, testAccessKey, testSecretKey)
		})
	}
}

// testAuthorization_ExplicitEmptyScopeDeniesAll verifies that an explicitly
// empty bucket list is not treated as the backwards-compatible unrestricted
// policy, including for the account-level ListBuckets operation.
func testAuthorization_ExplicitEmptyScopeDeniesAll(t *testing.T, inst provider.Instance) {
	t.Helper()
	credential := config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Label:     "deny-all-user",
		Buckets:   []string{},
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(credential))
	assertSignedAccessDenied(t, gw, http.MethodGet, inst.Bucket, uniqueKey(t), nil, credential.AccessKey, credential.SecretKey)

	req, err := http.NewRequest(http.MethodGet, gw.URL+"/", nil)
	if err != nil {
		t.Fatalf("create ListBuckets request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListBuckets: status %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Buckets []struct{} `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode ListBuckets response: %v: %s", err, body)
	}
	if len(result.Buckets) != 0 {
		t.Fatalf("ListBuckets returned %d buckets for deny-all credential", len(result.Buckets))
	}
}

// testAuthorization_ReadOnlyCredential verifies that a read-only principal can
// read objects written by another credential but cannot mutate them.
func testAuthorization_ReadOnlyCredential(t *testing.T, inst provider.Instance) {
	t.Helper()
	readOnly := config.ObjectPermissionReadOnly
	writer := config.GatewayCredential{AccessKey: "AUTH2WRITER", SecretKey: "writer-secret", Label: "writer", Buckets: []string{inst.Bucket}}
	reader := config.GatewayCredential{
		AccessKey:   "AUTH2READER",
		SecretKey:   "reader-secret",
		Label:       "reader",
		Buckets:     []string{inst.Bucket},
		Permissions: &readOnly,
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(writer, reader))

	key := uniqueKey(t)
	data := []byte("read-only-credential-data")
	putSigned(t, gw, inst.Bucket, key, data, writer.AccessKey, writer.SecretKey)
	if got := getSigned(t, gw, inst.Bucket, key, reader.AccessKey, reader.SecretKey); !bytes.Equal(got, data) {
		t.Fatal("read-only credential returned incorrect object data")
	}

	assertSignedAccessDenied(t, gw, http.MethodPut, inst.Bucket, uniqueKey(t), []byte("forbidden-write"), reader.AccessKey, reader.SecretKey)
	assertSignedAccessDenied(t, gw, http.MethodDelete, inst.Bucket, key, nil, reader.AccessKey, reader.SecretKey)
}

// testAuthorization_CopySourceAndDestinationScopes verifies that both sides of
// a CopyObject request are independently constrained before the backend sees it.
func testAuthorization_CopySourceAndDestinationScopes(t *testing.T, inst provider.Instance) {
	t.Helper()
	credential := config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Label:     "copy-scoped-user",
		Buckets:   []string{inst.Bucket},
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(credential))
	key := uniqueKey(t)

	assertSignedCopyAccessDenied(t, gw, inst.Bucket, key, inst.Bucket+"-source-outside", key, credential)
	assertSignedCopyAccessDenied(t, gw, inst.Bucket+"-destination-outside", key, inst.Bucket, key, credential)
}

// testAuthorization_UploadPartCopySourceScope verifies that UploadPartCopy
// applies the same independent source-bucket authorization as CopyObject.
func testAuthorization_UploadPartCopySourceScope(t *testing.T, inst provider.Instance) {
	t.Helper()
	credential := config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Label:     "upload-part-copy-scoped-user",
		Buckets:   []string{inst.Bucket},
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(credential))
	key := uniqueKey(t)

	initReq, err := http.NewRequest(http.MethodPost, objectURL(gw, inst.Bucket, key)+"?uploads", nil)
	if err != nil {
		t.Fatalf("create multipart initiation request: %v", err)
	}
	initReq.Host = initReq.URL.Host
	signV4Headers(t, initReq, credential.AccessKey, credential.SecretKey, nil)
	initResp, err := gw.HTTPClient().Do(initReq)
	if err != nil {
		t.Fatalf("initiate multipart upload: %v", err)
	}
	initBody, _ := io.ReadAll(initResp.Body)
	initResp.Body.Close()
	if initResp.StatusCode != http.StatusOK {
		t.Fatalf("initiate multipart upload: status %d: %s", initResp.StatusCode, initBody)
	}
	var initResult struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(initBody, &initResult); err != nil || initResult.UploadID == "" {
		t.Fatalf("decode multipart initiation response: %v: %s", err, initBody)
	}
	t.Cleanup(func() { abortSignedMultipartUpload(t, gw, inst.Bucket, key, initResult.UploadID, credential) })

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s?partNumber=1&uploadId=%s", objectURL(gw, inst.Bucket, key), initResult.UploadID), nil)
	if err != nil {
		t.Fatalf("create UploadPartCopy request: %v", err)
	}
	req.Header.Set("x-amz-copy-source", fmt.Sprintf("/%s/%s", "outside-"+inst.Bucket, key))
	req.Host = req.URL.Host
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("UploadPartCopy request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "AccessDenied") {
		t.Fatalf("UploadPartCopy status %d, want 403 AccessDenied: %s", resp.StatusCode, body)
	}
}

// testAuthorization_ListBucketsFiltered verifies that a restricted credential
// only receives its effective bucket inventory. It creates a second backend
// bucket directly so the assertion is meaningful on all providers that permit
// bucket creation for the configured test identity.
func testAuthorization_ListBucketsFiltered(t *testing.T, inst provider.Instance) {
	t.Helper()
	extraBucket := "auth2-list-" + uniqueSuffix(t)
	backend := newS3CompatClient(t, inst)
	if _, err := backend.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(extraBucket)}); err != nil {
		t.Skipf("provider credentials cannot create an isolated ListBuckets fixture: %v", err)
	}
	t.Cleanup(func() {
		if _, err := backend.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: aws.String(extraBucket)}); err != nil {
			t.Logf("delete ListBuckets fixture %q: %v", extraBucket, err)
		}
	})

	credential := config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Label:     "list-scoped-user",
		Buckets:   []string{inst.Bucket},
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(credential))
	req, err := http.NewRequest(http.MethodGet, gw.URL+"/", nil)
	if err != nil {
		t.Fatalf("ListBuckets request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListBuckets: status %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Buckets []struct {
			Name string `xml:"Name"`
		} `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode ListBuckets response: %v: %s", err, body)
	}
	foundScopedBucket := false
	for _, bucket := range result.Buckets {
		if bucket.Name == extraBucket {
			t.Fatalf("ListBuckets exposed out-of-scope bucket %q", extraBucket)
		}
		if bucket.Name != inst.Bucket {
			t.Fatalf("ListBuckets exposed unexpected bucket %q", bucket.Name)
		}
		foundScopedBucket = true
	}
	if !foundScopedBucket {
		t.Fatalf("ListBuckets omitted in-scope bucket %q", inst.Bucket)
	}
}

// testAuthorization_ProxiedBucketIntersection verifies that PROXIED_BUCKET
// narrows an otherwise valid credential scope and its ListBuckets inventory.
func testAuthorization_ProxiedBucketIntersection(t *testing.T, inst provider.Instance) {
	t.Helper()
	credential := config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Label:     "intersection-user",
		Buckets:   []string{inst.Bucket},
	}
	gw := harness.StartGateway(t, inst,
		harness.WithAuth(credential),
		harness.WithConfigMutator(func(cfg *config.Config) { cfg.ProxiedBucket = "other-" + inst.Bucket }),
	)
	assertSignedAccessDenied(t, gw, http.MethodGet, inst.Bucket, uniqueKey(t), nil, credential.AccessKey, credential.SecretKey)

	req, err := http.NewRequest(http.MethodGet, gw.URL+"/", nil)
	if err != nil {
		t.Fatalf("create ListBuckets request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListBuckets: status %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Buckets []struct{} `xml:"Buckets>Bucket"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode ListBuckets response: %v: %s", err, body)
	}
	if len(result.Buckets) != 0 {
		t.Fatalf("ListBuckets returned %d buckets outside the effective intersection", len(result.Buckets))
	}
}

// testAuthorization_PresignedScopeEnforced verifies that authorization applies
// after SigV4 query authentication, not only to header-signed requests.
func testAuthorization_PresignedScopeEnforced(t *testing.T, inst provider.Instance) {
	t.Helper()
	credential := config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Label:     "presigned-scoped-user",
		Buckets:   []string{inst.Bucket},
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(credential))
	key := uniqueKey(t)
	data := []byte("presigned-scope-data")
	putSigned(t, gw, inst.Bucket, key, data, credential.AccessKey, credential.SecretKey)

	allowedURL := presignV4GET(t, gw, inst.Bucket, key, credential.AccessKey, credential.SecretKey, time.Hour)
	assertPresignedStatus(t, gw, allowedURL, http.StatusOK)
	deniedURL := presignV4GET(t, gw, "outside-"+inst.Bucket, key, credential.AccessKey, credential.SecretKey, time.Hour)
	assertPresignedStatus(t, gw, deniedURL, http.StatusForbidden)
}

// testAuthorization_BucketLifecycleGrants verifies that rw does not imply
// bucket creation or deletion, while the independent grants permit middleware
// traversal to the real S3 handlers.
func testAuthorization_BucketLifecycleGrants(t *testing.T, inst provider.Instance) {
	t.Helper()
	createBucket := "auth2-create-" + uniqueSuffix(t)
	withoutGrants := config.GatewayCredential{
		AccessKey: testAccessKey,
		SecretKey: testSecretKey,
		Label:     "no-lifecycle-grants",
		Buckets:   []string{inst.Bucket, createBucket},
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(withoutGrants))
	assertSignedBucketAccessDenied(t, gw, http.MethodPut, createBucket, withoutGrants)
	assertSignedBucketAccessDenied(t, gw, http.MethodDelete, inst.Bucket, withoutGrants)

	fixtureBucket := "auth2-delete-" + uniqueSuffix(t)
	backend := newS3CompatClient(t, inst)
	if _, err := backend.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String(fixtureBucket)}); err != nil {
		t.Skipf("provider credentials cannot create a DeleteBucket grant fixture: %v", err)
	}
	fixtureDeleted := false
	t.Cleanup(func() {
		if fixtureDeleted {
			return
		}
		if _, err := backend.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: aws.String(fixtureBucket)}); err != nil {
			t.Logf("delete DeleteBucket grant fixture %q: %v", fixtureBucket, err)
		}
	})

	withDeleteGrant := withoutGrants
	withDeleteGrant.AccessKey = "AUTH2DELETE"
	withDeleteGrant.SecretKey = "delete-secret"
	withDeleteGrant.Buckets = []string{fixtureBucket}
	withDeleteGrant.BucketPermissions = []config.BucketPermission{config.BucketPermissionDelete}
	grantedGateway := harness.StartGateway(t, inst, harness.WithAuth(withDeleteGrant))
	assertSignedBucketStatus(t, grantedGateway, http.MethodDelete, fixtureBucket, withDeleteGrant, http.StatusNoContent)
	fixtureDeleted = true
}

// testAuthorization_OperationPermissionMatrix drives every authorization
// operation class through the live gateway. The expected backend result is
// intentionally not asserted: providers vary in their implementation of many
// S3 subresources. The assertion is that ro reaches every read route but is
// stopped before every mutation, while rw is not stopped by authorization.
func testAuthorization_OperationPermissionMatrix(t *testing.T, inst provider.Instance) {
	t.Helper()
	readOnly := config.ObjectPermissionReadOnly
	reader := config.GatewayCredential{
		AccessKey:   "AUTH2MATRIXRO",
		SecretKey:   "matrix-read-secret",
		Label:       "matrix-read-only",
		Buckets:     []string{inst.Bucket},
		Permissions: &readOnly,
	}
	writer := config.GatewayCredential{
		AccessKey: "AUTH2MATRIXRW",
		SecretKey: "matrix-write-secret",
		Label:     "matrix-read-write",
		Buckets:   []string{inst.Bucket},
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(reader, writer))
	key := uniqueKey(t)

	reads := []struct {
		name, method, suffix string
	}{
		{"GetObject", http.MethodGet, "/" + inst.Bucket + "/" + key},
		{"HeadObject", http.MethodHead, "/" + inst.Bucket + "/" + key},
		{"ListObjects", http.MethodGet, "/" + inst.Bucket + "?list-type=2&prefix=conf/"},
		{"HeadBucket", http.MethodHead, "/" + inst.Bucket},
		{"GetBucketLocation", http.MethodGet, "/" + inst.Bucket + "?location"},
		{"ListMultipartUploads", http.MethodGet, "/" + inst.Bucket + "?uploads"},
		{"ListParts", http.MethodGet, "/" + inst.Bucket + "/" + key + "?uploadId=not-a-real-upload"},
		{"CORSPreflightBucket", http.MethodOptions, "/" + inst.Bucket},
		{"CORSPreflightObject", http.MethodOptions, "/" + inst.Bucket + "/" + key},
		{"SelectObjectContent", http.MethodPost, "/" + inst.Bucket + "/" + key + "?select"},
	}
	for _, selector := range []string{"acl", "analytics", "cors", "encryption", "inventory", "lifecycle", "location", "logging", "notification", "object-lock", "policy", "replication", "requestPayment", "uploads", "versioning", "website"} {
		reads = append(reads, struct {
			name, method, suffix string
		}{"GetBucket_" + selector, http.MethodGet, "/" + inst.Bucket + "?" + selector})
	}
	for _, selector := range []string{"acl", "retention", "legal-hold", "tagging"} {
		reads = append(reads, struct {
			name, method, suffix string
		}{"GetObject_" + selector, http.MethodGet, "/" + inst.Bucket + "/" + key + "?" + selector})
	}
	for _, tc := range reads {
		tc := tc
		t.Run("ro_allows_"+tc.name, func(t *testing.T) {
			assertSignedOperationNotAuthorizationDenied(t, gw, tc.method, tc.suffix, nil, reader)
		})
	}

	writes := []struct {
		name, method, suffix string
		body                 []byte
	}{
		{"PutObject", http.MethodPut, "/" + inst.Bucket + "/" + key, []byte("matrix-write")},
		{"DeleteObject", http.MethodDelete, "/" + inst.Bucket + "/" + key, nil},
		{"DeleteObjects", http.MethodPost, "/" + inst.Bucket + "?delete", []byte("<Delete></Delete>")},
		{"CreateMultipartUpload", http.MethodPost, "/" + inst.Bucket + "/" + key + "?uploads", nil},
		{"UploadPart", http.MethodPut, "/" + inst.Bucket + "/" + key + "?partNumber=1&uploadId=not-a-real-upload", []byte("part")},
		{"CompleteMultipartUpload", http.MethodPost, "/" + inst.Bucket + "/" + key + "?uploadId=not-a-real-upload", []byte("<CompleteMultipartUpload></CompleteMultipartUpload>")},
		{"AbortMultipartUpload", http.MethodDelete, "/" + inst.Bucket + "/" + key + "?uploadId=not-a-real-upload", nil},
		{"RestoreObject", http.MethodPost, "/" + inst.Bucket + "/" + key + "?restore", []byte("<RestoreRequest></RestoreRequest>")},
	}
	for _, selector := range []string{"acl", "cors", "encryption", "intelligent-tiering", "inventory", "lifecycle", "logging", "notification", "object-lock", "policy", "replication", "requestPayment", "versioning", "website"} {
		writes = append(writes, struct {
			name, method, suffix string
			body                 []byte
		}{"PutBucket_" + selector, http.MethodPut, "/" + inst.Bucket + "?" + selector, []byte("<Configuration></Configuration>")})
	}
	for _, selector := range []string{"acl", "retention", "legal-hold", "tagging"} {
		writes = append(writes, struct {
			name, method, suffix string
			body                 []byte
		}{"PutObject_" + selector, http.MethodPut, "/" + inst.Bucket + "/" + key + "?" + selector, []byte("<Configuration></Configuration>")})
	}
	for _, selector := range []string{"lifecycle", "policy", "cors", "encryption", "replication", "website", "inventory"} {
		writes = append(writes, struct {
			name, method, suffix string
			body                 []byte
		}{"DeleteBucket_" + selector, http.MethodDelete, "/" + inst.Bucket + "?" + selector, nil})
	}
	writes = append(writes, struct {
		name, method, suffix string
		body                 []byte
	}{"DeleteObject_tagging", http.MethodDelete, "/" + inst.Bucket + "/" + key + "?tagging", nil})
	for _, tc := range writes {
		tc := tc
		t.Run("ro_denies_"+tc.name, func(t *testing.T) {
			assertSignedOperationAccessDenied(t, gw, tc.method, tc.suffix, tc.body, reader)
		})
		t.Run("rw_allows_"+tc.name, func(t *testing.T) {
			assertSignedOperationNotAuthorizationDenied(t, gw, tc.method, tc.suffix, tc.body, writer)
		})
	}
}

// testAuthorization_UnknownOperationsFailClosed verifies that malformed route
// shapes cannot fall through to a generic handler with either ro or rw policy.
func testAuthorization_UnknownOperationsFailClosed(t *testing.T, inst provider.Instance) {
	t.Helper()
	readOnly := config.ObjectPermissionReadOnly
	credentials := []config.GatewayCredential{
		{AccessKey: "AUTH2UNKNOWNRO", SecretKey: "unknown-read-secret", Label: "unknown-ro", Buckets: []string{inst.Bucket}, Permissions: &readOnly},
		{AccessKey: "AUTH2UNKNOWNRW", SecretKey: "unknown-write-secret", Label: "unknown-rw", Buckets: []string{inst.Bucket}},
	}
	gw := harness.StartGateway(t, inst, harness.WithAuth(credentials...))
	key := uniqueKey(t)
	operations := []struct{ method, suffix string }{
		{http.MethodPatch, "/" + inst.Bucket + "/" + key},
		{http.MethodGet, "/" + inst.Bucket + "?unknown=1"},
		{http.MethodPut, "/" + inst.Bucket + "?unknown=1"},
		{http.MethodPost, "/" + inst.Bucket + "/" + key + "?unknown=1"},
		{http.MethodDelete, "/" + inst.Bucket + "/" + key + "?unknown=1"},
		{http.MethodGet, "/" + inst.Bucket + "/" + key + "?uploadId="},
		{http.MethodPut, "/" + inst.Bucket + "/" + key + "?partNumber=1"},
	}
	for _, credential := range credentials {
		for _, operation := range operations {
			credential, operation := credential, operation
			t.Run(credential.Label+"_"+operation.method+operation.suffix, func(t *testing.T) {
				assertSignedOperationAccessDenied(t, gw, operation.method, operation.suffix, nil, credential)
			})
		}
	}
}

func assertSignedAccessDenied(t *testing.T, gw *harness.Gateway, method, bucket, key string, body []byte, accessKey, secretKey string) {
	t.Helper()
	req, err := http.NewRequest(method, objectURL(gw, bucket, key), bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create signed %s request: %v", method, err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, accessKey, secretKey, body)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("signed %s request: %v", method, err)
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(responseBody), "AccessDenied") {
		t.Fatalf("signed %s request: status %d, want 403 AccessDenied: %s", method, resp.StatusCode, responseBody)
	}
}

func assertSignedCopyAccessDenied(t *testing.T, gw *harness.Gateway, destinationBucket, destinationKey, sourceBucket, sourceKey string, credential config.GatewayCredential) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, objectURL(gw, destinationBucket, destinationKey), nil)
	if err != nil {
		t.Fatalf("create CopyObject request: %v", err)
	}
	req.Header.Set("x-amz-copy-source", fmt.Sprintf("/%s/%s", sourceBucket, sourceKey))
	req.Host = req.URL.Host
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("CopyObject request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "AccessDenied") {
		t.Fatalf("CopyObject status %d, want 403 AccessDenied: %s", resp.StatusCode, body)
	}
}

func abortSignedMultipartUpload(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string, credential config.GatewayCredential) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, objectURL(gw, bucket, key)+"?uploadId="+url.QueryEscape(uploadID), nil)
	if err != nil {
		t.Fatalf("create multipart abort request: %v", err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("abort multipart upload: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("abort multipart upload: status %d: %s", resp.StatusCode, body)
	}
}

func assertPresignedStatus(t *testing.T, gw *harness.Gateway, rawURL string, wantStatus int) {
	t.Helper()
	resp, err := gw.HTTPClient().Get(rawURL)
	if err != nil {
		t.Fatalf("presigned GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("presigned GET: status %d, want %d: %s", resp.StatusCode, wantStatus, body)
	}
}

func assertSignedBucketAccessDenied(t *testing.T, gw *harness.Gateway, method, bucket string, credential config.GatewayCredential) {
	t.Helper()
	assertSignedBucketStatus(t, gw, method, bucket, credential, http.StatusForbidden)
}

func assertSignedBucketStatus(t *testing.T, gw *harness.Gateway, method, bucket string, credential config.GatewayCredential, wantStatus int) {
	t.Helper()
	req, err := http.NewRequest(method, gw.URL+"/"+bucket, nil)
	if err != nil {
		t.Fatalf("create signed bucket %s request: %v", method, err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("signed bucket %s request: %v", method, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != wantStatus {
		t.Fatalf("signed bucket %s request: status %d, want %d: %s", method, resp.StatusCode, wantStatus, body)
	}
	if wantStatus == http.StatusForbidden && !strings.Contains(string(body), "AccessDenied") {
		t.Fatalf("signed bucket %s request: missing AccessDenied: %s", method, body)
	}
}

func assertSignedOperationAccessDenied(t *testing.T, gw *harness.Gateway, method, suffix string, body []byte, credential config.GatewayCredential) {
	t.Helper()
	resp, responseBody := signedOperation(t, gw, method, suffix, body, credential)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(responseBody), "AccessDenied") {
		t.Fatalf("%s %s: status %d, want 403 AccessDenied: %s", method, suffix, resp.StatusCode, responseBody)
	}
}

func assertSignedOperationNotAuthorizationDenied(t *testing.T, gw *harness.Gateway, method, suffix string, body []byte, credential config.GatewayCredential) {
	t.Helper()
	resp, responseBody := signedOperation(t, gw, method, suffix, body, credential)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden && strings.Contains(string(responseBody), "AccessDenied") {
		t.Fatalf("%s %s was denied by gateway authorization: %s", method, suffix, responseBody)
	}
}

func signedOperation(t *testing.T, gw *harness.Gateway, method, suffix string, body []byte, credential config.GatewayCredential) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, gw.URL+suffix, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create %s %s request: %v", method, suffix, err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, credential.AccessKey, credential.SecretKey, body)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("perform %s %s request: %v", method, suffix, err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		t.Fatalf("read %s %s response: %v", method, suffix, err)
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return resp, bodyBytes
}
