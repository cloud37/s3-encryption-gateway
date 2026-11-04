//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// This separate mandatory gate must not silently pass when the fixture is
// disabled, cannot start, or the selected subtest never executes.
func TestConformanceLiteralPositiveProof(t *testing.T) {
	if externalOnlyMode() {
		t.Skip("local-only mandatory literal positive proof; not external evidence")
	}
	providers := provider.LiteralPostPositiveProofProviders()
	if !literalProofFixtureCountValid(len(providers)) {
		t.Fatal("mandatory literal positive fixture is missing or ambiguous")
	}
	completed := false
	p := providers[0]
	t.Run(p.Name()+"/PostObject_Literal201Inventory", func(t *testing.T) {
		inst := p.Start(context.Background(), t)
		if inst.ProviderName != p.Name() || inst.Endpoint == "" || inst.Bucket == "" || inst.AccessKey == "" || inst.SecretKey == "" || p.CleanupPolicy() != provider.CleanupPolicyDelete {
			t.Fatal("mandatory literal positive fixture incomplete")
		}
		testLiteralPositive201(t, inst)
		completed = true
	})
	if !literalProofCompleted(completed) {
		t.Fatal("mandatory literal positive scenario did not complete")
	}
}

func literalProofFixtureCountValid(count int) bool { return count == 1 }
func literalProofCompleted(completed bool) bool    { return completed }

type literalLister interface {
	ListObjectsV2(context.Context, *awss3.ListObjectsV2Input, ...func(*awss3.Options)) (*awss3.ListObjectsV2Output, error)
}

// Inventory is read directly from the backend LIST response rather than from
// either gateway routing or object-GET URL construction.
func literalInventory(ctx context.Context, client literalLister, bucket, prefix string) (map[string]bool, error) {
	keys := make(map[string]bool)
	var token *string
	seen := make(map[string]bool)
	for {
		page, err := client.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String(bucket), Prefix: aws.String(prefix), ContinuationToken: token})
		if err != nil || page == nil {
			return nil, errors.New("backend inventory failed")
		}
		for _, item := range page.Contents {
			if item.Key == nil || !strings.HasPrefix(*item.Key, prefix) || keys[*item.Key] {
				return nil, errors.New("backend inventory invalid")
			}
			keys[*item.Key] = true
		}
		if !aws.ToBool(page.IsTruncated) {
			return keys, nil
		}
		if page.NextContinuationToken == nil || *page.NextContinuationToken == "" || seen[*page.NextContinuationToken] {
			return nil, errors.New("backend inventory pagination invalid")
		}
		seen[*page.NextContinuationToken] = true
		token = page.NextContinuationToken
	}
}

// A valid Location has one transport decode to exactly the expected key and
// protects dots, plus and the literal percent from reinterpretation.
type literal201Checks struct {
	Status, XMLDecode, XMLNamespace, Bucket, Key, ETag                                            bool
	GatewayParse, LocationParse, Scheme, Host, NoUser, NoQuery, NoFragment, Path, Decode, Escaped bool
}

func (c literal201Checks) valid() bool {
	return c.Status && c.XMLDecode && c.XMLNamespace && c.Bucket && c.Key && c.ETag && c.GatewayParse && c.LocationParse && c.Scheme && c.Host && c.NoUser && c.NoQuery && c.NoFragment && c.Path && c.Decode && c.Escaped
}

func inspectLiteralLocation(c *literal201Checks, raw, gateway, bucket, namespace, exact string) {
	u, err := url.Parse(raw)
	base, baseErr := url.Parse(gateway)
	c.GatewayParse = baseErr == nil && base != nil && base.Scheme != "" && base.Host != ""
	c.LocationParse = err == nil && u != nil && u.Scheme != "" && u.Host != ""
	if !c.GatewayParse || !c.LocationParse {
		return
	}
	c.Scheme, c.Host = u.Scheme == base.Scheme, u.Host == base.Host
	c.NoUser, c.NoQuery, c.NoFragment = u.User == nil, u.RawQuery == "" && !u.ForceQuery, u.Fragment == ""
	c.Path = u.Path == "/"+bucket+"/"+exact
	// PathEscape preserves '+' in a path segment (unlike query escaping).
	want := "/" + bucket + "/" + namespace + "/literal/%2E%2E/plus+percent%2525/name%2Ebin"
	decoded, decodeErr := url.PathUnescape(u.EscapedPath())
	c.Decode = decodeErr == nil && decoded == "/"+bucket+"/"+exact
	c.Escaped = u.EscapedPath() == want
}

func validateLiteralLocation(raw, gateway, bucket, namespace, exact string) bool {
	var c literal201Checks
	inspectLiteralLocation(&c, raw, gateway, bucket, namespace, exact)
	return c.GatewayParse && c.LocationParse && c.Scheme && c.Host && c.NoUser && c.NoQuery && c.NoFragment && c.Path && c.Decode && c.Escaped
}

func validateLiteral201(status int, body []byte, gateway, bucket, namespace, exact, etag string) (string, literal201Checks) {
	var result struct {
		XMLName  xml.Name
		Key      string `xml:"Key"`
		Bucket   string `xml:"Bucket"`
		Location string `xml:"Location"`
		ETag     string `xml:"ETag"`
	}
	var c literal201Checks
	c.Status = status == http.StatusCreated
	c.XMLDecode = xml.Unmarshal(body, &result) == nil
	c.XMLNamespace = result.XMLName.Local == "PostResponse" && result.XMLName.Space == "http://s3.amazonaws.com/doc/2006-03-01/"
	c.Bucket, c.Key, c.ETag = result.Bucket == bucket, result.Key == exact, result.ETag == etag
	inspectLiteralLocation(&c, result.Location, gateway, bucket, namespace, exact)
	return result.Location, c
}

func literalInventoryMatches(keys map[string]bool, exact, neighbor string) bool {
	return exact != neighbor && len(keys) == 2 && keys[exact] && keys[neighbor]
}

func literalLocationRead(t *testing.T, client *http.Client, location, method, interval string) (*http.Response, []byte) {
	t.Helper()
	headers := make(http.Header)
	if interval != "" {
		headers.Set("Range", interval)
	}
	req := signedGatewayRequest(t, method, location, nil, "", headers)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("literal Location read transport failed")
	}
	body, err := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if err != nil || closeErr != nil {
		t.Fatal("literal Location response read failed")
	}
	return resp, body
}

func testLiteralPositive201(t *testing.T, inst provider.Instance) {
	t.Helper()
	namespace := "gh353literal-" + uniqueSuffix(t)
	prefix := namespace + "/"
	exact := prefix + "literal/../plus+percent%25/name.bin"
	neighbor := prefix + "plus+percent%25/name.bin"
	backend := newS3CompatClient(t, inst)
	before, err := literalInventory(t.Context(), backend, inst.Bucket, prefix)
	if err != nil || len(before) != 0 {
		t.Fatal("owned namespace is not empty")
	}
	// Only keys in the freshly empty namespace are ever deleted.
	for _, key := range []string{exact, neighbor} {
		key := key
		t.Cleanup(func() { cleanupPostObject(t, inst, key) })
	}
	sentinel := []byte("independent normalized neighbor")
	if _, err := backend.PutObject(t.Context(), &awss3.PutObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(neighbor), Body: bytes.NewReader(sentinel)}); err != nil {
		t.Fatal("neighbor fixture write failed")
	}
	gw := postGateway(t, inst, postCredential("", nil), harness.WithChunking(true))
	want := bytes.Repeat([]byte("literal provider plaintext-"), 64)
	formKey := prefix + "literal/../plus+percent%25/${filename}"
	req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, formKey, postCredential("", nil), postFormCase{
		fields:               map[string]string{"success_action_status": "201", "Content-Type": "application/octet-stream", "x-amz-meta-purpose": "literal-proof"},
		startsWithConditions: map[string]string{"key": strings.TrimSuffix(formKey, "${filename}")}, file: want, fileName: "dir/sub/name.bin",
	})
	client := gw.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, body := postHTTPWithClient(t, client, req)
	wantETag := `"` + fmt.Sprintf("%x", md5Sum(want)) + `"`
	location, checks := validateLiteral201(resp.StatusCode, body, gw.URL, inst.Bucket, namespace, exact, wantETag)
	if !checks.valid() {
		t.Fatalf("literal 201 response invalid status=%d status_match=%t xml_decode=%t xml_namespace=%t bucket_match=%t key_match=%t etag_match=%t gateway_parse=%t location_parse=%t scheme_match=%t host_match=%t no_user=%t no_query=%t no_fragment=%t path_match=%t decode_match=%t escaped_match=%t", resp.StatusCode, checks.Status, checks.XMLDecode, checks.XMLNamespace, checks.Bucket, checks.Key, checks.ETag, checks.GatewayParse, checks.LocationParse, checks.Scheme, checks.Host, checks.NoUser, checks.NoQuery, checks.NoFragment, checks.Path, checks.Decode, checks.Escaped)
	}
	for _, tc := range []struct {
		method, interval string
		status           int
		body             []byte
	}{
		{http.MethodGet, "", http.StatusOK, want},
		{http.MethodHead, "", http.StatusOK, nil},
		{http.MethodGet, "bytes=1-7", http.StatusPartialContent, want[1:8]},
	} {
		read, data := literalLocationRead(t, client, location, tc.method, tc.interval)
		if read.StatusCode != tc.status || !bytes.Equal(data, tc.body) || read.Header.Get("ETag") != wantETag || read.Header.Get("Content-Type") != "application/octet-stream" || read.Header.Get("X-Amz-Meta-Purpose") != "literal-proof" {
			t.Fatalf("literal Location read mismatch method=%s status=%d", tc.method, read.StatusCode)
		}
		if tc.method == http.MethodHead && read.ContentLength != int64(len(want)) {
			t.Fatal("literal Location HEAD length mismatch")
		}
		if tc.interval != "" && read.Header.Get("Content-Range") != fmt.Sprintf("bytes 1-7/%d", len(want)) {
			t.Fatal("literal Location range mismatch")
		}
	}
	inventory, err := literalInventory(t.Context(), backend, inst.Bucket, prefix)
	if err != nil || !literalInventoryMatches(inventory, exact, neighbor) {
		t.Fatal("backend inventory did not distinguish exact and neighbor keys")
	}
	neighborResult, err := backend.GetObject(t.Context(), &awss3.GetObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(neighbor)})
	if err != nil {
		t.Fatal("neighbor read failed")
	}
	neighborData, err := io.ReadAll(neighborResult.Body)
	neighborResult.Body.Close()
	if err != nil || !bytes.Equal(neighborData, sentinel) {
		t.Fatal("normalized neighbor changed")
	}
	stored, metadata, err := directPostBackend(t, inst).GetObject(t.Context(), inst.Bucket, exact, nil, nil)
	if err != nil {
		t.Fatal("literal backend ciphertext read failed")
	}
	ciphertext, err := io.ReadAll(stored)
	stored.Close()
	if err != nil || len(ciphertext) == 0 || bytes.Equal(ciphertext, want) || metadata[crypto.MetaEncrypted] != "true" {
		t.Fatal("literal backend encryption proof failed")
	}
}
