//go:build conformance

package conformance

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/api"
)

func TestGH353LiteralPositiveFixtureGate(t *testing.T) {
	if literalProofFixtureCountValid(0) || literalProofFixtureCountValid(2) || !literalProofFixtureCountValid(1) || literalProofCompleted(false) || !literalProofCompleted(true) {
		t.Fatal("mandatory fixture gate accepted missing, ambiguous, or skipped execution")
	}
}

func TestGH353LiteralPositiveLocationAndInventoryWire(t *testing.T) {
	const namespace = "gh353literal-fixed"
	const exact = namespace + "/literal/../plus+percent%25/name.bin"
	const neighbor = namespace + "/plus+percent%25/name.bin"
	const escaped = "/bucket/" + namespace + "/literal/%2E%2E/plus+percent%2525/name%2Ebin"
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bucket/"+exact || r.URL.EscapedPath() != escaped || r.Header.Get("Authorization") == "" {
			t.Error("frontend identity/signature missing")
		}
		if _, err := api.ValidateSignatureV4(r, postGatewaySecret, time.Minute); err != nil {
			t.Error("frontend signature invalid")
		}
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusPartialContent)
		}
	}))
	defer frontend.Close()
	location := frontend.URL + escaped
	if !validateLiteralLocation(location, frontend.URL, "bucket", namespace, exact) || validateLiteralLocation(frontend.URL+"/bucket/"+neighbor, frontend.URL, "bucket", namespace, exact) || validateLiteralLocation(frontend.URL+"/bucket/"+namespace+"/literal/%2E%2E/plus%2Bpercent%25/name%2Ebin", frontend.URL, "bucket", namespace, exact) {
		t.Fatal("Location identity/decode guard failed")
	}
	response, err := xml.Marshal(struct {
		XMLName                     xml.Name `xml:"http://s3.amazonaws.com/doc/2006-03-01/ PostResponse"`
		Bucket, Key, Location, ETag string
	}{Bucket: "bucket", Key: exact, Location: location, ETag: `"fixture"`})
	if err != nil {
		t.Fatal("construct XML fixture")
	}
	if got, checks := validateLiteral201(201, response, frontend.URL, "bucket", namespace, exact, `"fixture"`); !checks.valid() || got != location {
		t.Fatal("valid 201 response rejected")
	}
	if _, checks := validateLiteral201(201, response, frontend.URL, "bucket", namespace, neighbor, `"fixture"`); checks.valid() {
		t.Fatal("201 response accepted normalized neighbor")
	}
	if _, checks := validateLiteral201(204, response, frontend.URL, "bucket", namespace, exact, `"fixture"`); checks.valid() {
		t.Fatal("incorrect success status accepted")
	}
	_, wrongETag := validateLiteral201(201, response, frontend.URL, "bucket", namespace, exact, `"wrong"`)
	if wrongETag.ETag || wrongETag.valid() || !wrongETag.Key || !wrongETag.Escaped {
		t.Fatal("ETag diagnostic failed")
	}
	_, malformed := validateLiteral201(201, []byte("<"), frontend.URL, "bucket", namespace, exact, `"fixture"`)
	if malformed.XMLDecode || malformed.valid() {
		t.Fatal("malformed XML accepted")
	}
	for _, tc := range []struct {
		name, raw string
		rejected  func(literal201Checks) bool
	}{
		{"foreign host", "http://different.example" + escaped, func(c literal201Checks) bool { return !c.Host }},
		{"scheme", "https://" + frontend.Listener.Addr().String() + escaped, func(c literal201Checks) bool { return !c.Scheme }},
		{"userinfo", "http://u@" + frontend.Listener.Addr().String() + escaped, func(c literal201Checks) bool { return !c.NoUser }},
		{"query", location + "?x=1", func(c literal201Checks) bool { return !c.NoQuery }},
		{"fragment", location + "#x", func(c literal201Checks) bool { return !c.NoFragment }},
		{"normalized", frontend.URL + "/bucket/" + neighbor, func(c literal201Checks) bool { return !c.Path }},
		{"invalid escape", frontend.URL + "/%ZZ", func(c literal201Checks) bool { return !c.LocationParse }},
		{"old plus encoding", frontend.URL + "/bucket/" + namespace + "/literal/%2E%2E/plus%2Bpercent%2525/name%2Ebin", func(c literal201Checks) bool { return c.Path && c.Decode && !c.Escaped }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var checks literal201Checks
			inspectLiteralLocation(&checks, tc.raw, frontend.URL, "bucket", namespace, exact)
			if !tc.rejected(checks) || validateLiteralLocation(tc.raw, frontend.URL, "bucket", namespace, exact) {
				t.Fatal("Location diagnostic failed")
			}
		})
	}
	client := frontend.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for _, tc := range []struct {
		method, interval string
		status           int
	}{{"GET", "", 200}, {"HEAD", "", 200}, {"GET", "bytes=1-7", 206}} {
		resp, _ := literalLocationRead(t, client, location, tc.method, tc.interval)
		if resp.StatusCode != tc.status {
			t.Fatalf("frontend status=%d", resp.StatusCode)
		}
	}

	listCalls, getCalls := 0, 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		clone := r.Clone(r.Context())
		clone.Header = r.Header.Clone()
		clone.Header.Del("Authorization")
		signedAt, err := time.Parse("20060102T150405Z", r.Header.Get("X-Amz-Date"))
		signer := v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
		if err != nil || authorization == "" || signer.SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture-secret"}, clone, r.Header.Get("X-Amz-Content-Sha256"), "s3", "us-east-1", signedAt) != nil || clone.Header.Get("Authorization") != authorization {
			t.Error("backend SDK signature invalid")
		}
		if r.URL.Query().Get("list-type") == "2" {
			listCalls++
			if r.URL.Query().Get("prefix") != namespace+"/" {
				t.Error("inventory prefix mismatch")
			}
			w.Header().Set("Content-Type", "application/xml")
			if r.URL.Query().Get("continuation-token") == "" {
				fmt.Fprintf(w, `<ListBucketResult><IsTruncated>true</IsTruncated><NextContinuationToken>next</NextContinuationToken><Contents><Key>%s</Key></Contents></ListBucketResult>`, exact)
			} else {
				fmt.Fprintf(w, `<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>%s</Key></Contents></ListBucketResult>`, neighbor)
			}
			return
		}
		getCalls++
		if r.URL.Path != "/bucket/"+exact && r.URL.Path != "/bucket/"+neighbor {
			t.Error("backend SDK key changed")
		}
		_, _ = io.WriteString(w, "fixture")
	}))
	defer backend.Close()
	sdk := awss3.New(awss3.Options{Region: "us-east-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "fixture", SecretAccessKey: "fixture-secret"}, nil
	}), BaseEndpoint: aws.String(backend.URL), UsePathStyle: true, Retryer: aws.NopRetryer{}})
	keys, err := literalInventory(context.Background(), sdk, "bucket", namespace+"/")
	if err != nil || !literalInventoryMatches(keys, exact, neighbor) || listCalls != 2 || literalInventoryMatches(map[string]bool{neighbor: true}, exact, neighbor) || literalInventoryMatches(map[string]bool{exact: true, neighbor: true, "extra": true}, exact, neighbor) {
		t.Fatal("SDK inventory lost distinct keys or pagination")
	}
	for _, key := range []string{exact, neighbor} {
		out, err := sdk.GetObject(context.Background(), &awss3.GetObjectInput{Bucket: aws.String("bucket"), Key: aws.String(key)})
		if err != nil {
			t.Fatal("SDK object read failed")
		}
		out.Body.Close()
	}
	if getCalls != 2 {
		t.Fatal("SDK did not read both distinct objects")
	}
}
