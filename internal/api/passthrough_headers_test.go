package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func passthroughHeaderHandler(endpoint string) *Handler {
	logger := logrus.New()
	logger.SetLevel(logrus.PanicLevel)
	return NewHandlerWithFeatures(nil, crypto.PassthroughEngine{}, logger, getTestMetrics(), nil, nil, nil, &config.Config{
		AllowBucketCreation: true,
		Backend:             config.BackendConfig{Endpoint: endpoint, AccessKey: "backend-access", SecretKey: "backend-secret", Region: "us-east-1"},
	}, nil)
}

// GH-338 needs no frontend proxy: an injected header is exactly what the
// gateway receives from one. The backend simulates an S3 frontend appending
// its peer address before SigV4 verification, after the gateway has signed.
func TestPassthroughHeaders_BackendAppendsForwardedFor(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body, reply string
	}{
		{"GetBucketLocation", "GET", "/bucket?location", "", "<LocationConstraint/>"},
		{"CreateBucket", "PUT", "/bucket", "<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>", ""},
		{"ListBuckets", "GET", "/", "", "<ListAllMyBucketsResult><Buckets><Bucket><Name>bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>"},
		{"ListMultipartUploads", "GET", "/bucket?uploads", "", "<ListMultipartUploadsResult/>"},
		{"PutObjectTagging", "PUT", "/bucket/key?tagging", "<Tagging><TagSet/></Tagging>", ""},
		{"CORSPreflight", "OPTIONS", "/bucket/key", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, forwarded := range []bool{false, true} {
				name := "direct"
				if forwarded {
					name = "frontend-header"
				}
				t.Run(name, func(t *testing.T) {
					calls := 0
					backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						ctx, err := ValidateSignatureV4(r, "backend-secret", 5*time.Minute)
						if err != nil {
							t.Errorf("signature invalid before frontend mutation: %v", err)
							w.WriteHeader(http.StatusInternalServerError)
							return
						}
						ctx.Close()
						xff := r.Header.Get("X-Forwarded-For")
						if xff != "" {
							xff += ", "
						}
						r.Header.Set("X-Forwarded-For", xff+"192.0.2.20")
						ctx, err = ValidateSignatureV4(r, "backend-secret", 5*time.Minute)
						if err != nil {
							w.WriteHeader(http.StatusForbidden)
							_, _ = io.WriteString(w, "<Error><Code>SignatureDoesNotMatch</Code></Error>")
							return
						}
						ctx.Close()
						body, err := io.ReadAll(r.Body)
						if err != nil || string(body) != tc.body {
							t.Errorf("body=%q err=%v, want %q", body, err, tc.body)
						}
						w.Header().Set("Content-Type", "application/xml")
						_, _ = io.WriteString(w, tc.reply)
					}))
					defer backend.Close()
					h := passthroughHeaderHandler(backend.URL)
					router := mux.NewRouter()
					h.RegisterRoutes(router)
					credential := Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}
					req := managementRequest(tc.method, tc.path, strings.NewReader(tc.body), credential)
					if tc.body != "" {
						req.Header.Set("Content-Type", "application/xml")
					}
					if forwarded {
						req.Header.Set("X-Forwarded-For", "203.0.113.10")
					}
					w := httptest.NewRecorder()
					router.ServeHTTP(w, req)
					if w.Code != http.StatusOK || calls != 1 {
						t.Fatalf("status=%d calls=%d body=%s", w.Code, calls, w.Body.String())
					}
				})
			}
		})
	}
}

func TestForwardToBackend_HeaderBoundary(t *testing.T) {
	for _, signed := range []bool{false, true} {
		name := "unsigned-backend"
		if signed {
			name = "signed-backend"
		}
		t.Run(name, func(t *testing.T) {
			preserved := http.Header{
				"Content-Type": {"application/xml"}, "Content-Md5": {"test-checksum"},
				"Cache-Control": {"no-cache"}, "Content-Disposition": {"inline"},
				"Content-Encoding": {"identity"}, "Content-Language": {"en"}, "Expires": {"Wed, 30 Sep 2026 12:00:00 GMT"},
				"If-Match": {"\"etag\""}, "If-None-Match": {"*"}, "If-Modified-Since": {"Tue, 29 Sep 2026 12:00:00 GMT"},
				"If-Unmodified-Since": {"Tue, 29 Sep 2026 12:00:00 GMT"}, "If-Range": {"\"etag\""}, "Range": {"bytes=0-9"},
				"X-Amz-Expected-Bucket-Owner": {"owner"}, "X-Amz-Request-Payer": {"requester"},
				"X-Amz-Checksum-Sha256": {"checksum"}, "X-Amz-Acl": {"private"},
				"X-Amz-Meta-User": {"first", "second"}, "X-Amz-Mfa": {"serial code"},
				"Origin": {"https://client.example"}, "Access-Control-Request-Method": {"PUT"}, "Access-Control-Request-Headers": {"content-type,x-amz-date"},
			}
			dropped := http.Header{
				"X-Forwarded-For": {"203.0.113.10"}, "X-Forwarded-Host": {"gateway.example"},
				"X-Forwarded-Proto": {"https"}, "X-Forwarded-Port": {"443"},
				"Forwarded": {"for=203.0.113.10;proto=https"}, "Via": {"1.1 frontend"}, "X-Real-Ip": {"203.0.113.10"},
				"Connection": {"keep-alive, X-Amz-Meta-Hop", "x-amz-meta-other-hop"},
				"Keep-Alive": {"timeout=5"}, "Proxy-Authenticate": {"Basic realm=proxy"}, "Proxy-Authorization": {"Basic secret"},
				"Te": {"trailers"}, "Trailer": {"X-Checksum"}, "Trailers": {"X-Checksum"},
				"Transfer-Encoding": {"chunked"}, "Upgrade": {"websocket"}, "Expect": {"100-continue"},
				"X-Amz-Meta-Hop": {"hop-only"}, "X-Amz-Meta-Other-Hop": {"hop-only"},
				"Cookie": {"private=session"}, "X-Test": {"unrelated"}, "X-Request-Id": {"client-id"},
				"Traceparent": {"client-trace"}, "Date": {"Tue, 29 Sep 2026 12:00:00 GMT"},
			}
			body := []byte("<Tagging><TagSet/></Tagging>")
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for key, values := range preserved {
					if got := r.Header.Values(key); !reflect.DeepEqual(got, values) {
						t.Errorf("%s=%q, want %q", key, got, values)
					}
				}
				for key := range dropped {
					if got := r.Header.Values(key); len(got) != 0 {
						t.Errorf("backend received prohibited %s=%q", key, got)
					}
					authorization := r.Header.Get("Authorization")
					_, list, _ := strings.Cut(authorization, "SignedHeaders=")
					list, _, _ = strings.Cut(list, ",")
					for _, header := range strings.Split(list, ";") {
						if header == strings.ToLower(key) {
							t.Errorf("backend signature includes prohibited %s", key)
						}
					}
				}
				if r.Header.Get("X-Amz-Security-Token") != "" || strings.Contains(r.Header.Get("Authorization"), "client-access") {
					t.Error("client credentials leaked")
				}
				if signed {
					ctx, err := ValidateSignatureV4(r, "backend-secret", 5*time.Minute)
					if err != nil {
						t.Errorf("backend signature: %v", err)
					} else {
						ctx.Close()
					}
				} else if r.Header.Get("Authorization") != "" || r.Header.Get("X-Amz-Date") != "" || r.Header.Get("X-Amz-Content-Sha256") != "" {
					t.Error("unsigned backend received client signing fields")
				}
				got, err := io.ReadAll(r.Body)
				if err != nil || !bytes.Equal(got, body) || r.ContentLength != int64(len(body)) {
					t.Errorf("body=%q length=%d err=%v", got, r.ContentLength, err)
				}
				if r.URL.RawQuery != "tagging&versionId=version" {
					t.Errorf("query=%q", r.URL.RawQuery)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer backend.Close()
			h := passthroughHeaderHandler(backend.URL)
			if !signed {
				h.config.Backend.AccessKey = ""
				h.config.Backend.SecretKey = ""
			}
			req := httptest.NewRequest("PUT", "/bucket/key?tagging&versionId=version&X-Amz-Signature=client-signature&X-Amz-Credential=client-access", bytes.NewReader(body))
			req.Header = preserved.Clone()
			for key, values := range dropped {
				req.Header[key] = append([]string(nil), values...)
			}
			req.Header.Set("Authorization", "client-access")
			req.Header.Set("X-Amz-Date", "20260929T120000Z")
			req.Header.Set("X-Amz-Content-Sha256", "client-hash")
			req.Header.Set("X-Amz-Security-Token", "client-token")
			req.Header.Set("Content-Length", "999") // Must be derived from the buffered body instead.
			original := req.Header.Clone()
			resp, err := h.forwardToBackend(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if !reflect.DeepEqual(req.Header, original) {
				t.Error("outbound filtering mutated inbound headers used by auditing")
			}
		})
	}
}

func TestCopyProxyResponse_ConnectionTokensAndTrailer(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{
		"Connection": {"keep-alive, X-Hop", "x-other-hop"}, "X-Hop": {"private"}, "X-Other-Hop": {"private"},
		"Trailer": {"X-Checksum"}, "X-Amz-Request-Id": {"backend-id"},
	}, Body: io.NopCloser(strings.NewReader("body"))}
	w := httptest.NewRecorder()
	if _, err := copyProxyResponse(w, resp); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"Connection", "X-Hop", "X-Other-Hop", "Trailer"} {
		if w.Header().Get(key) != "" {
			t.Errorf("response leaked hop-by-hop header %s", key)
		}
	}
	if w.Header().Get("X-Amz-Request-Id") != "backend-id" || w.Body.String() != "body" {
		t.Fatal("end-to-end response changed")
	}
}

func TestBackendRequestHeaders_CaseInsensitiveAndIndependent(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in, want http.Header
	}{
		{"nil", nil, http.Header{}},
		{"noncanonical", http.Header{
			"content-type": {"application/xml"}, "x-amz-meta-user": {"first", "second"},
			"x-forwarded-for": {"203.0.113.10"}, "AUTHORIZATION": {"client"},
			"x-amz-date": {"client-date"}, "X-AMZ-CONTENT-SHA256": {"client-hash"}, "x-amz-security-token": {"client-token"},
		}, http.Header{"Content-Type": {"application/xml"}, "X-Amz-Meta-User": {"first", "second"}}},
		{"connection-tokens", http.Header{
			"connection":   {" Content-Type, X-Amz-Meta-Hop ", "ORIGIN"},
			"CONTENT-TYPE": {"hop-only"}, "x-amz-meta-hop": {"hop-only"}, "origin": {"hop-only"},
			"x-amz-checksum-sha256": {"end-to-end"}, "trailer": {"checksum"},
		}, http.Header{"X-Amz-Checksum-Sha256": {"end-to-end"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.in.Clone()
			got := backendRequestHeaders(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("headers=%v, want %v", got, tc.want)
			}
			for key := range got {
				got[key][0] = "outbound-only"
			}
			if !reflect.DeepEqual(tc.in, original) {
				t.Fatal("outbound headers share mutable input state")
			}
		})
	}
}
