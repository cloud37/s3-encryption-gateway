//go:build conformance

package conformance

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func testSEC40_Auth_SigV2PresignedGET_RedactsAccessLog(t *testing.T, inst provider.Instance) {
	var logs bytes.Buffer
	gateway := harness.StartGateway(t, inst,
		harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey, Label: "test-user"}),
		harness.WithLogLevel("info"), harness.WithAccessLogCapture(&logs),
		harness.WithConfigMutator(func(cfg *config.Config) { cfg.Auth.AllowLegacySignatureV2 = true }),
	)
	key := uniqueKey(t)
	data := []byte("sec40-sigv2-data")
	putSigned(t, gateway, inst.Bucket, key, data, testAccessKey, testSecretKey)

	// Expires is required by the SigV2 query contract. The response-content-type
	// parameter is a standard, provider-neutral benign query field.
	q := url.Values{
		"AWSAccessKeyId":        {testAccessKey},
		"Expires":               {fmt.Sprint(time.Now().Add(time.Hour).Unix())},
		"response-content-type": {"text/plain"},
	}
	req, err := http.NewRequest("GET", objectURL(gateway, inst.Bucket, key)+"?"+q.Encode(), nil)
	if err != nil {
		t.Fatalf("create SigV2 request: %v", err)
	}
	req.Host = req.URL.Host
	stringToSign := fmt.Sprintf("GET\n\n\n%s\n%s?response-content-type=text/plain", q.Get("Expires"), req.URL.EscapedPath())
	h := hmac.New(sha1.New, []byte(testSecretKey))
	_, _ = h.Write([]byte(stringToSign))
	q.Set("Signature", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	resp, err := gateway.HTTPClient().Get(objectURL(gateway, inst.Bucket, key) + "?" + q.Encode())
	if err != nil {
		t.Fatalf("SigV2 GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, data) {
		t.Fatalf("SigV2 GET: status %d body %q", resp.StatusCode, body)
	}
	if strings.Contains(logs.String(), q.Get("Signature")) {
		t.Fatal("SigV2 signature leaked into access log")
	}
	if !strings.Contains(logs.String(), "response-content-type=text%2Fplain") {
		t.Fatal("benign response-content-type query value missing from access log")
	}
}

func sigV2PresignedRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	expires := fmt.Sprint(time.Now().Add(time.Hour).Unix())
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	resource := parsed.EscapedPath()
	if resource == "" {
		resource = "/"
	}
	keys := make([]string, 0)
	for key := range query {
		if sigV2TestResourceKey(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for i, key := range keys {
		if i == 0 {
			resource += "?"
		} else {
			resource += "&"
		}
		resource += key
		if query.Get(key) != "" {
			resource += "=" + query.Get(key)
		}
	}
	q := query
	q.Set("AWSAccessKeyId", testAccessKey)
	q.Set("Expires", expires)
	parsed.RawQuery = q.Encode()
	req, err := http.NewRequest(method, parsed.String(), body)
	if err != nil {
		t.Fatal(err)
	}
	if method == "PUT" {
		req.Header.Set("Content-Type", "application/xml")
	}
	contentType := req.Header.Get("Content-Type")
	// SigV2 lines are method, Content-MD5, Content-Type, Date, headers, resource.
	stringToSign := method + "\n\n" + contentType + "\n" + expires + "\n" + resource
	h := hmac.New(sha1.New, []byte(testSecretKey))
	_, _ = h.Write([]byte(stringToSign))
	q.Set("Signature", base64.StdEncoding.EncodeToString(h.Sum(nil)))
	req.URL.RawQuery = q.Encode()
	return req
}

func sigV2TestResourceKey(key string) bool {
	for _, allowed := range []string{"acl", "analytics", "cors", "delete", "encryption", "intelligent-tiering", "inventory", "legal-hold", "lifecycle", "location", "logging", "notification", "object-lock", "partNumber", "policy", "replication", "requestPayment", "response-cache-control", "response-content-disposition", "response-content-encoding", "response-content-language", "response-content-type", "response-expires", "restore", "retention", "select", "select-type", "tagging", "torrent", "uploadId", "uploads", "versionId", "versioning", "versions", "website"} {
		if key == allowed {
			return true
		}
	}
	return false
}

func testSEC44_Auth_SigV2PresignedSubresourceAccepted(t *testing.T, inst provider.Instance) {
	gw := harness.StartGateway(t, inst, harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}), harness.WithConfigMutator(func(cfg *config.Config) { cfg.Auth.AllowLegacySignatureV2 = true }))
	key := uniqueKey(t)
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey) })
	putSigned(t, gw, inst.Bucket, key, []byte("data"), testAccessKey, testSecretKey)
	body := strings.NewReader(`<Tagging><TagSet><Tag><Key>sec44</Key><Value>ok</Value></Tag></TagSet></Tagging>`)
	req := sigV2PresignedRequest(t, "PUT", objectURL(gw, inst.Bucket, key)+"?tagging", body)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		failure, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d: %s", resp.StatusCode, failure)
	}
	check := sigV2PresignedRequest(t, "GET", objectURL(gw, inst.Bucket, key)+"?tagging", nil)
	checked, err := gw.HTTPClient().Do(check)
	if err != nil {
		t.Fatal(err)
	}
	defer checked.Body.Close()
	data, _ := io.ReadAll(checked.Body)
	if checked.StatusCode != http.StatusOK || !bytes.Contains(data, []byte("sec44")) {
		t.Fatalf("tagging state not persisted: %d %s", checked.StatusCode, data)
	}
}

func testSEC44_Auth_SigV2PresignedSubresourceSubstitutionRejected(t *testing.T, inst provider.Instance) {
	gw := harness.StartGateway(t, inst, harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}), harness.WithConfigMutator(func(cfg *config.Config) { cfg.Auth.AllowLegacySignatureV2 = true }))
	key := uniqueKey(t)
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey) })
	putSigned(t, gw, inst.Bucket, key, []byte("data"), testAccessKey, testSecretKey)
	baseline := sigV2PresignedRequest(t, "PUT", objectURL(gw, inst.Bucket, key)+"?tagging", strings.NewReader(`<Tagging><TagSet><Tag><Key>baseline</Key><Value>keep</Value></Tag></TagSet></Tagging>`))
	resp, err := gw.HTTPClient().Do(baseline)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		failure, _ := io.ReadAll(resp.Body)
		t.Fatalf("baseline tagging status %d: %s", resp.StatusCode, failure)
	}
	req := sigV2PresignedRequest(t, "PUT", objectURL(gw, inst.Bucket, key)+"?tagging", strings.NewReader(`<Tagging><TagSet><Tag><Key>forged</Key><Value>bad</Value></Tag></TagSet></Tagging>`))
	values := req.URL.Query()
	values.Del("tagging")
	values.Set("acl", "")
	req.URL.RawQuery = values.Encode()
	resp, err = gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d, want forbidden", resp.StatusCode)
	}
	errorBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(errorBody), "SignatureDoesNotMatch") {
		t.Fatal("missing SignatureDoesNotMatch")
	}
	state := sigV2PresignedRequest(t, "GET", objectURL(gw, inst.Bucket, key)+"?tagging", nil)
	checked, err := gw.HTTPClient().Do(state)
	if err != nil {
		t.Fatal(err)
	}
	defer checked.Body.Close()
	data, _ := io.ReadAll(checked.Body)
	if checked.StatusCode != http.StatusOK {
		t.Fatalf("tagging GET status %d: %s", checked.StatusCode, data)
	}
	if !bytes.Contains(data, []byte("baseline")) || bytes.Contains(data, []byte("forged")) {
		t.Fatalf("tagging changed: %s", data)
	}
}

func testSEC44_Auth_SigV2HeaderSubresourceAccepted(t *testing.T, inst provider.Instance) {
	gw := harness.StartGateway(t, inst, harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}), harness.WithConfigMutator(func(cfg *config.Config) { cfg.Auth.AllowLegacySignatureV2 = true }))
	key := uniqueKey(t)
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey) })
	putSigned(t, gw, inst.Bucket, key, []byte("data"), testAccessKey, testSecretKey)
	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, key)+"?acl", nil)
	req.Header.Set("x-amz-acl", "public-read")
	date := time.Now().UTC().Format(time.RFC1123)
	req.Header.Set("Date", date)
	s := "PUT\n\n\n" + date + "\nx-amz-acl:public-read\n" + req.URL.EscapedPath() + "?acl"
	h := hmac.New(sha1.New, []byte(testSecretKey))
	_, _ = h.Write([]byte(s))
	req.Header.Set("Authorization", "AWS "+testAccessKey+":"+base64.StdEncoding.EncodeToString(h.Sum(nil)))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
	acl := signedACLGet(t, gw, inst.Bucket, key)
	if !bytes.Contains(acl, []byte("public-read")) {
		t.Fatal("signed ACL operation did not persist state")
	}
}

func testSEC44_Auth_SigV2HeaderSubresourceSubstitutionRejected(t *testing.T, inst provider.Instance) {
	gw := harness.StartGateway(t, inst, harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}), harness.WithConfigMutator(func(cfg *config.Config) { cfg.Auth.AllowLegacySignatureV2 = true }))
	key := uniqueKey(t)
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, testAccessKey, testSecretKey) })
	putSigned(t, gw, inst.Bucket, key, []byte("data"), testAccessKey, testSecretKey)
	baseline := signedACLGet(t, gw, inst.Bucket, key)
	req, _ := http.NewRequest("PUT", objectURL(gw, inst.Bucket, key)+"?acl", nil)
	req.Header.Set("x-amz-acl", "public-read")
	date := time.Now().UTC().Format(time.RFC1123)
	req.Header.Set("Date", date)
	s := "PUT\n\n\n" + date + "\nx-amz-acl:public-read\n" + req.URL.EscapedPath() + "?acl"
	h := hmac.New(sha1.New, []byte(testSecretKey))
	_, _ = h.Write([]byte(s))
	req.Header.Set("Authorization", "AWS "+testAccessKey+":"+base64.StdEncoding.EncodeToString(h.Sum(nil)))
	req.URL.RawQuery = "versionId=one"
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	errorBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(errorBody), "SignatureDoesNotMatch") {
		t.Fatal("missing SignatureDoesNotMatch")
	}
	after := signedACLGet(t, gw, inst.Bucket, key)
	if !bytes.Equal(baseline, after) {
		t.Fatalf("ACL state changed: before=%s after=%s", baseline, after)
	}
}

func signedACLGet(t *testing.T, gw *harness.Gateway, bucket, key string) []byte {
	t.Helper()
	req, _ := http.NewRequest("GET", objectURL(gw, bucket, key)+"?acl", nil)
	date := time.Now().UTC().Format(time.RFC1123)
	req.Header.Set("Date", date)
	h := hmac.New(sha1.New, []byte(testSecretKey))
	_, _ = h.Write([]byte("GET\n\n\n" + date + "\n" + req.URL.EscapedPath() + "?acl"))
	req.Header.Set("Authorization", "AWS "+testAccessKey+":"+base64.StdEncoding.EncodeToString(h.Sum(nil)))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ACL get status %d: %s", resp.StatusCode, data)
	}
	return data
}

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
