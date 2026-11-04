package api

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/sirupsen/logrus"
)

func livePostRequest(t *testing.T, file string, extra map[string]string, extraConditions []string) *http.Request {
	return livePostRequestFor(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "bucket", "test.jpg", file, extra, extraConditions)
}

func livePostRequestFor(t *testing.T, secret, bucket, key, file string, extra map[string]string, extraConditions []string) *http.Request {
	return livePostRequestForExpiry(t, secret, bucket, key, file, extra, extraConditions, time.Now().UTC().Add(20*time.Minute))
}

func livePostRequestForExpiry(t *testing.T, secret, bucket, key, file string, extra map[string]string, extraConditions []string, expiration time.Time) *http.Request {
	return livePostRequestWithOptions(t, secret, bucket, key, file, extra, extraConditions, expiration, nil, "live-post-boundary")
}

func livePostRequestWithOptions(t *testing.T, secret, bucket, key, file string, extra map[string]string, extraConditions []string, expiration time.Time, mutation func(*bytes.Buffer) error, boundary string) *http.Request {
	t.Helper()
	const accessKey = "AKIAIOSFODNN7EXAMPLE"
	date := time.Now().UTC().Format("20060102T150405Z")
	day := date[:8]
	scope := accessKey + "/" + day + "/us-east-1/s3/aws4_request"
	fields := map[string]string{
		"bucket": bucket, "key": key, "x-amz-algorithm": "AWS4-HMAC-SHA256",
		"x-amz-credential": scope, "x-amz-date": date,
	}
	for name, value := range extra {
		fields[name] = value
	}
	conditions := []string{
		fmt.Sprintf(`{"bucket":%q}`, bucket), fmt.Sprintf(`{"key":%q}`, key), `{"x-amz-algorithm":"AWS4-HMAC-SHA256"}`,
		fmt.Sprintf(`{"x-amz-credential":%q}`, scope), fmt.Sprintf(`{"x-amz-date":%q}`, date),
	}
	conditions = append(conditions, extraConditions...)
	policyText := fmt.Sprintf(`{"expiration":%q,"conditions":[%s]}`, expiration.Format(time.RFC3339Nano), strings.Join(conditions, ","))
	fields["policy"] = base64.StdEncoding.EncodeToString([]byte(policyText))
	fields["x-amz-signature"] = signPostPolicy(secret, day, "us-east-1", fields["policy"])
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.SetBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	for name, value := range fields {
		part, err := writer.CreateFormField(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("file", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, file); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if mutation != nil {
		if err := mutation(&body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "http://gateway.test/bucket", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.ContentLength = int64(body.Len())
	return req
}

func livePostChain(t *testing.T, backend s3.Client, registry *prometheus.Registry) (*Handler, http.Handler) {
	return livePostChainForCredential(t, backend, registry, config.GatewayCredential{
		AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite),
	})
}

func livePostChainForCredential(t *testing.T, backend s3.Client, registry *prometheus.Registry, gatewayCredential config.GatewayCredential) (*Handler, http.Handler) {
	return livePostChainForCredentialAndObserver(t, backend, registry, gatewayCredential, nil)
}

func livePostChainForCredentialAndObserver(t *testing.T, backend s3.Client, registry *prometheus.Registry, gatewayCredential config.GatewayCredential, observe func(*http.Request)) (*Handler, http.Handler) {
	return livePostChainForCredentialObserverAndConfig(t, backend, registry, gatewayCredential, observe, &config.Config{})
}

func livePostChainForCredentialObserverAndConfig(t *testing.T, backend s3.Client, registry *prometheus.Registry, gatewayCredential config.GatewayCredential, observe func(*http.Request), cfg *config.Config) (*Handler, http.Handler) {
	t.Helper()
	engine, err := newAPIUnitEngine([]byte("test encryption password"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewStaticCredentialStore([]config.GatewayCredential{gatewayCredential})
	if err != nil {
		t.Fatal(err)
	}
	var m *metrics.Metrics
	if registry != nil {
		m = metrics.NewMetricsWithRegistry(registry)
	}
	h := NewHandlerWithFeatures(backend, engine, logrus.New(), m, nil, nil, nil, cfg, nil)
	h.spoolManager = NewSpoolManager(8<<20, t.TempDir())
	h.spoolLimits = NewSpoolLimitSource(SpoolLimits{Global: 2 << 20, Part: 1 << 20})
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	if observe != nil {
		router.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				observe(r)
				next.ServeHTTP(w, r)
				observe(r)
			})
		})
	}
	return h, AuthMiddleware(store, time.Minute, logrus.New(), nil, true, h.spoolManager, h.spoolLimits)(AuthorizationMiddleware("", nil)(router))
}

func TestGH353PostObject_RoundTripFormatsAndMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, engineKind         string
		body                     []byte
		minimumSize, maximumSize int64
		status                   int
		options                  map[string]string
		conditions               []string
		session                  bool
		unknownLength            bool
		realTransport            bool
	}{
		{name: "buffered nonempty", engineKind: "buffered", body: []byte("full request-path POST payload"), status: http.StatusCreated, options: map[string]string{"success_action_status": "201", "Content-Type": "text/plain", "Content-Encoding": "identity", "Content-Disposition": "inline", "Cache-Control": "no-cache", "Content-Language": "en", "Expires": "Wed, 21 Oct 2030 07:28:00 GMT", "x-amz-meta-owner": "alice", "x-amz-meta-project": "post"}, conditions: []string{`{"success_action_status":"201"}`, `{"Content-Type":"text/plain"}`, `{"Content-Encoding":"identity"}`, `{"Content-Disposition":"inline"}`, `{"Cache-Control":"no-cache"}`, `{"Content-Language":"en"}`, `{"Expires":"Wed, 21 Oct 2030 07:28:00 GMT"}`, `{"x-amz-meta-owner":"alice"}`, `{"x-amz-meta-project":"post"}`}},
		{name: "buffered medium known length", engineKind: "buffered", body: bytes.Repeat([]byte("buffered-medium-☃"), 4096), status: http.StatusNoContent},
		{name: "signed range exact inclusive minimum", engineKind: "buffered", body: []byte("min!"), status: http.StatusNoContent, conditions: []string{`["content-length-range",4,8]`}},
		{name: "signed range exact inclusive maximum", engineKind: "buffered", body: []byte("12345678"), status: http.StatusNoContent, conditions: []string{`["content-length-range",4,8]`}},
		{name: "buffered medium unknown length", engineKind: "buffered", body: bytes.Repeat([]byte("buffered-unknown-☃"), 4096), status: http.StatusNoContent, unknownLength: true},
		{name: "chunked stream multi-record session", engineKind: "chunked", body: bytes.Repeat([]byte("multi-record-☃"), 4096), status: http.StatusNoContent, session: true},
		{name: "chunked stream unknown HTTP content length", engineKind: "chunked", body: bytes.Repeat([]byte("stream-unknown-☃"), 4096), status: http.StatusNoContent, unknownLength: true},
		{name: "chunked live HTTP transport framing", engineKind: "chunked", body: bytes.Repeat([]byte("transport-chunk-☃"), 1024), status: http.StatusNoContent, realTransport: true},
		{name: "chunked metadata-overflow streaming-prefix fallback", engineKind: "fallback", body: bytes.Repeat([]byte("metadata overflow record/"), 3072), status: http.StatusNoContent, unknownLength: true, options: map[string]string{"x-amz-meta-overflow": strings.Repeat("v", 7900)}, conditions: []string{fmt.Sprintf(`{"x-amz-meta-overflow":%q}`, strings.Repeat("v", 7900))}},
		{name: "passthrough bypass policy", engineKind: "passthrough", body: []byte("deliberate plaintext bypass"), status: http.StatusNoContent, options: map[string]string{"Content-Type": "text/plain", "x-amz-meta-owner": "bypass-owner"}, conditions: []string{`{"Content-Type":"text/plain"}`, `{"x-amz-meta-owner":"bypass-owner"}`}},
		{name: "buffered zero bytes", engineKind: "buffered", body: nil, status: http.StatusOK, options: map[string]string{"success_action_status": "200"}, conditions: []string{`{"success_action_status":"200"}`}},
		{name: "chunked zero bytes", engineKind: "chunked", body: nil, status: http.StatusNoContent},
		{name: "zero content-length range", engineKind: "buffered", body: nil, minimumSize: 0, maximumSize: 0, status: http.StatusNoContent, conditions: []string{`["content-length-range",0,0]`}},
		{name: "inclusive signed minimum", engineKind: "buffered", body: []byte("min!"), minimumSize: 4, maximumSize: 8, status: http.StatusNoContent, conditions: []string{`["content-length-range",4,8]`}},
		{name: "inclusive signed maximum", engineKind: "buffered", body: []byte("12345678"), minimumSize: 4, maximumSize: 8, status: http.StatusNoContent, conditions: []string{`["content-length-range",4,8]`}},
		{name: "encrypted control without bypass policy", engineKind: "buffered", body: []byte("policy control remains encrypted"), status: http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			registry := prometheus.NewRegistry()
			credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
			if tc.session {
				credential.SessionToken = "valid-live-post-session"
				expires := time.Now().UTC().Add(20 * time.Minute)
				credential.ExpiresAt = &expires
				if tc.options == nil {
					tc.options = make(map[string]string)
				}
				tc.options["x-amz-security-token"] = credential.SessionToken
				tc.conditions = append(tc.conditions, fmt.Sprintf(`{"x-amz-security-token":%q}`, credential.SessionToken))
			}
			var engine crypto.EncryptionEngine
			switch tc.engineKind {
			case "buffered":
				var err error
				engine, err = crypto.NewEngineWithOpts([]byte("live-post-buffered-engine"), crypto.WithProvider("aws"), crypto.WithMetadataKey(bytes.Repeat([]byte{0x42}, 32)), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
				if err != nil {
					t.Fatal(err)
				}
			case "chunked", "fallback":
				chunked, err := crypto.NewEngineWithOpts([]byte("live-post-chunked-engine"), crypto.WithProvider("aws"), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
				if err != nil {
					t.Fatal(err)
				}
				engine = chunked
			case "passthrough":
				var err error
				engine, err = crypto.NewEngineWithOpts([]byte("live-post-policy-engine"), crypto.WithProvider("aws"), crypto.WithMetadataKey(bytes.Repeat([]byte{0x44}, 32)), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
				if err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unknown engine kind %q", tc.engineKind)
			}
			h, chain := livePostChainForCredential(t, backend, registry, credential)
			h.encryptionEngine = engine
			if tc.engineKind == "passthrough" {
				// Use a policy file through the same production policy loader; bypass
				// remains a bucket-scoped decision, not a test-only engine shortcut.
				policyPath := t.TempDir() + "/bypass.yaml"
				if err := os.WriteFile(policyPath, []byte("id: post-bypass\nbuckets: [bucket]\ndisable_encryption: true\n"), 0600); err != nil {
					t.Fatal(err)
				}
				h.policyManager = config.NewPolicyManager()
				if err := h.policyManager.LoadPolicies([]string{policyPath}); err != nil {
					t.Fatal(err)
				}
			}
			request := livePostRequest(t, string(tc.body), tc.options, tc.conditions)
			if tc.unknownLength {
				// A synthetic request ContentLength=-1 exercises unknown-length
				// handling, not HTTP transfer-chunk framing on a real transport.
				request.ContentLength = -1
			}
			request.Host = "canonical.gateway.example"
			request.Header.Set("X-Forwarded-Host", "spoof.invalid")
			response := httptest.NewRecorder()
			if tc.realTransport {
				server := httptest.NewServer(chain)
				formBody, readErr := io.ReadAll(request.Body)
				if readErr != nil {
					server.Close()
					t.Fatal(readErr)
				}
				realReq, reqErr := http.NewRequest(http.MethodPost, server.URL+"/bucket", bytes.NewReader(formBody))
				if reqErr != nil {
					server.Close()
					t.Fatal(reqErr)
				}
				realReq.Header.Set("Content-Type", request.Header.Get("Content-Type"))
				realReq.Host = request.Host
				realReq.ContentLength = -1
				resp, doErr := server.Client().Do(realReq)
				if doErr != nil {
					server.Close()
					t.Fatal(doErr)
				}
				response.Code = resp.StatusCode
				_, _ = io.Copy(response.Body, resp.Body)
				_ = resp.Body.Close()
				server.Close()
			} else {
				chain.ServeHTTP(response, request)
			}
			if response.Code != tc.status || backend.putObjectCallCount != 1 {
				t.Fatalf("status=%d want=%d puts=%d body=%s", response.Code, tc.status, backend.putObjectCallCount, response.Body.String())
			}
			stored := backend.objects["bucket/test.jpg"]
			meta := backend.metadata["bucket/test.jpg"]
			if backend.lastPutContentLength == nil || *backend.lastPutContentLength != int64(len(stored)) {
				t.Fatalf("backend ciphertext length=%v stored bytes=%d plaintext=%d", backend.lastPutContentLength, len(stored), len(tc.body))
			}
			if tc.minimumSize != 0 || tc.maximumSize != 0 {
				if int64(len(tc.body)) < tc.minimumSize || int64(len(tc.body)) > tc.maximumSize {
					t.Fatalf("invalid signed-bound fixture size=%d range=[%d,%d]", len(tc.body), tc.minimumSize, tc.maximumSize)
				}
			}
			if tc.engineKind == "passthrough" {
				if !bytes.Equal(stored, tc.body) || meta[crypto.MetaEncrypted] != "" || meta[crypto.MetaAlgorithm] != "" || meta[crypto.MetaObjectFormatVersion] != "" || meta["Content-Length"] != fmt.Sprint(len(tc.body)) || meta["Content-Type"] != "text/plain" || meta["x-amz-meta-owner"] != "bypass-owner" {
					t.Fatalf("bypass stored=%d metadata=%v", len(stored), meta)
				}
				if metricSample(t, registry, "s3_client_bytes_total", `bucket="bucket"`, `direction="in"`) != float64(len(tc.body)) {
					t.Fatal("bypass plaintext accounting did not match uploaded bytes")
				}
				if got := metricSample(t, registry, "encryption_operations_total", `operation="encrypt"`); got != 0 {
					t.Fatalf("plaintext bypass emitted encryption metric=%v", got)
				}
			} else {
				if tc.name == "encrypted control without bypass policy" && (meta[crypto.MetaEncrypted] != "true" || bytes.Equal(stored, tc.body)) {
					t.Fatalf("normal policy control not encrypted: metadata=%v stored=%d", meta, len(stored))
				}
				if bytes.Equal(stored, tc.body) && len(tc.body) > 0 {
					t.Fatal("encrypted POST stored plaintext bytes")
				}
				readEngine := engine
				reader, decryptedMeta, err := readEngine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "test.jpg"}, bytes.NewReader(stored), meta)
				if err != nil {
					t.Fatalf("decrypt stored POST: %v", err)
				}
				plain, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(plain, tc.body) {
					t.Fatalf("decrypted bytes=%d want=%d err=%v", len(plain), len(tc.body), err)
				}
				if tc.engineKind == "fallback" {
					expanded, expandErr := crypto.ExpandMetadataForAPI(meta)
					if expandErr != nil || expanded[crypto.MetaChunkedFormat] != "true" || expanded[crypto.MetaFallbackMode] != "true" || expanded[crypto.MetaFallbackVersion] != "2" || meta["x-amz-meta-overflow"] != "" || decryptedMeta["x-amz-meta-overflow"] != strings.Repeat("v", 7900) {
						t.Fatalf("real chunked fallback contract not met: err=%v", expandErr)
					}
					if err := crypto.GetProviderProfile("aws").ValidateMetadataSize(meta); err != nil {
						t.Fatal(err)
					}
				}
				if tc.name == "buffered nonempty" {
					for name, want := range map[string]string{"Content-Type": "text/plain", "Content-Encoding": "identity", "Content-Disposition": "inline", "Cache-Control": "no-cache", "Content-Language": "en", "Expires": "Wed, 21 Oct 2030 07:28:00 GMT", "x-amz-meta-owner": "alice", "x-amz-meta-project": "post"} {
						if decryptedMeta[name] != want {
							t.Errorf("decrypted metadata %s=%q want=%q", name, decryptedMeta[name], want)
						}
					}
					for _, name := range []string{"Content-Type", "Content-Encoding", "Content-Disposition", "Cache-Control", "Content-Language", "Expires"} {
						if _, found := meta[name]; found {
							t.Errorf("standard metadata %q must be stored encrypted, not raw", name)
						}
					}
					if meta[crypto.MetaEncryptedMetadata] == "" && meta[crypto.MetaEncryptedMetadataCompact] == "" {
						t.Error("user metadata protection blob missing from persisted metadata")
					}
				}
			}
			metricsResponse := httptest.NewRecorder()
			promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
			if got := metricSample(t, registry, "s3_client_bytes_total", `bucket="bucket"`, `direction="in"`); got != float64(len(tc.body)) {
				t.Fatalf("plaintext file-byte counter wrong: %s", metricsResponse.Body.String())
			}
			if tc.engineKind == "passthrough" {
				if got := metricSample(t, registry, "encryption_operations_total", `operation="encrypt"`); got != 0 {
					t.Fatalf("plaintext bypass emitted encryption metric=%v", got)
				}
			}
			if !strings.Contains(metricsResponse.Body.String(), fmt.Sprintf(`s3_client_requests_total{bucket="bucket",operation="PostObject",status_code="%d"} 1`, tc.status)) {
				t.Fatalf("PostObject status metric missing: %s", metricsResponse.Body.String())
			}
			if tc.status == http.StatusCreated {
				var postXML postResponse
				if err := xml.Unmarshal(response.Body.Bytes(), &postXML); err != nil || !strings.Contains(postXML.Location, "canonical.gateway.example") || strings.Contains(postXML.Location, "spoof.invalid") {
					t.Fatalf("Location=%q err=%v", postXML.Location, err)
				}
			}
		})
	}
}

func TestGH353PostObject_LiveTypedOptionsAndSSE(t *testing.T) {
	key := bytes.Repeat([]byte{0x37}, 32)
	keyMD5 := md5.Sum(key)
	kmsContext := base64.StdEncoding.EncodeToString([]byte(`{"purpose":"archive"}`))
	for _, tc := range []struct {
		name       string
		fields     map[string]string
		conditions []string
		secure     bool
		check      func(s3.ObjectPutOptions) bool
	}{
		{
			name:       "SSE-S3",
			fields:     map[string]string{"x-amz-server-side-encryption": "AES256"},
			conditions: []string{`{"x-amz-server-side-encryption":"AES256"}`},
			check:      func(o s3.ObjectPutOptions) bool { return o.SSE != nil && o.SSE.Algorithm == "AES256" },
		},
		{
			name:       "SSE-KMS",
			fields:     map[string]string{"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "kms-key-123", "x-amz-server-side-encryption-context": kmsContext, "x-amz-server-side-encryption-bucket-key-enabled": "true"},
			conditions: []string{`{"x-amz-server-side-encryption":"aws:kms"}`, `{"x-amz-server-side-encryption-aws-kms-key-id":"kms-key-123"}`, fmt.Sprintf(`{"x-amz-server-side-encryption-context":%q}`, kmsContext), `{"x-amz-server-side-encryption-bucket-key-enabled":"true"}`},
			check: func(o s3.ObjectPutOptions) bool {
				return o.SSE != nil && o.SSE.Algorithm == "aws:kms" && o.SSE.KMSKeyID == "kms-key-123" && o.SSE.KMSContext == kmsContext && o.SSE.BucketKeyEnabled != nil && *o.SSE.BucketKeyEnabled
			},
		},
		{
			name:       "SSE-C trusted-proxy HTTPS",
			fields:     map[string]string{"x-amz-server-side-encryption-customer-algorithm": "AES256", "x-amz-server-side-encryption-customer-key": base64.StdEncoding.EncodeToString(key), "x-amz-server-side-encryption-customer-key-md5": base64.StdEncoding.EncodeToString(keyMD5[:])},
			conditions: []string{`{"x-amz-server-side-encryption-customer-algorithm":"AES256"}`, fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key":%q}`, base64.StdEncoding.EncodeToString(key)), fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key-md5":%q}`, base64.StdEncoding.EncodeToString(keyMD5[:]))},
			secure:     true,
			check: func(o s3.ObjectPutOptions) bool {
				return o.SSE != nil && o.SSE.Customer != nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client()}
			switch tc.name {
			case "SSE-S3":
				backend.responseHeaders = map[string]string{"x-amz-server-side-encryption": "AES256"}
			case "SSE-KMS":
				backend.responseHeaders = map[string]string{"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "kms-key-123", "x-amz-server-side-encryption-bucket-key-enabled": "true"}
			case "SSE-C trusted-proxy HTTPS":
				backend.responseHeaders = map[string]string{sseCustomerAlg: "AES256", sseCustomerMD5: base64.StdEncoding.EncodeToString(keyMD5[:]), sseCustomerKey: base64.StdEncoding.EncodeToString(key)}
			}
			credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
			h, chain := livePostChainForCredentialObserverAndConfig(t, backend, nil, credential, nil, &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"127.0.0.0/8"}}, Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}})
			fields := map[string]string{
				"acl":                             "bucket-owner-full-control",
				"tagging":                         `<Tagging><TagSet><Tag><Key>雪国</Key><Value>北方</Value></Tag><Tag><Key>team</Key><Value>gateway</Value></Tag></TagSet></Tagging>`,
				"x-amz-storage-class":             "STANDARD_IA",
				"x-amz-website-redirect-location": "/archive/item",
			}
			conditions := []string{
				`{"acl":"bucket-owner-full-control"}`,
				fmt.Sprintf(`{"tagging":%q}`, fields["tagging"]),
				`{"x-amz-storage-class":"STANDARD_IA"}`,
				`{"x-amz-website-redirect-location":"/archive/item"}`,
			}
			for name, value := range tc.fields {
				fields[name] = value
			}
			conditions = append(conditions, tc.conditions...)
			request := livePostRequest(t, "typed option payload", fields, conditions)
			if tc.secure {
				request.RemoteAddr = "127.0.0.1:1234"
				request.Header.Set("X-Forwarded-Proto", "https")
			}
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent || backend.puts != 1 {
				t.Fatalf("status=%d puts=%d body=%s", response.Code, backend.puts, response.Body.String())
			}
			if response.Header().Get("x-amz-version-id") != "version-1" || response.Header().Get("x-amz-storage-class") != "STANDARD_IA" || response.Header().Get(sseCustomerKey) != "" {
				t.Fatalf("unexpected projected typed-option response headers: %v", response.Header())
			}
			if tc.name == "SSE-S3" && response.Header().Get("x-amz-server-side-encryption") != "AES256" || tc.name == "SSE-KMS" && (response.Header().Get("x-amz-server-side-encryption") != "aws:kms" || response.Header().Get("x-amz-server-side-encryption-aws-kms-key-id") != "kms-key-123") || tc.secure && response.Header().Get(sseCustomerKey) != "" {
				t.Fatalf("SSE projection was missing allowed headers or leaked customer key: %v", response.Header())
			}
			for name, value := range map[string]string{"x-amz-server-side-encryption": tc.fields["x-amz-server-side-encryption"], "x-amz-server-side-encryption-aws-kms-key-id": tc.fields["x-amz-server-side-encryption-aws-kms-key-id"], "x-amz-server-side-encryption-bucket-key-enabled": tc.fields["x-amz-server-side-encryption-bucket-key-enabled"], sseCustomerAlg: tc.fields[sseCustomerAlg], sseCustomerMD5: tc.fields[sseCustomerMD5]} {
				if value != "" && response.Header().Get(name) != value {
					t.Errorf("permitted backend header %s=%q want=%q", name, response.Header().Get(name), value)
				}
			}
			if backend.acl != "bucket-owner-full-control" || backend.tags != "team=gateway&%E9%9B%AA%E5%9B%BD=%E5%8C%97%E6%96%B9" || backend.options.StorageClass != "STANDARD_IA" || backend.options.WebsiteRedirectLocation != "/archive/item" || !tc.check(backend.options) {
				t.Fatalf("acl=%q tags=%q options=%+v", backend.acl, backend.tags, backend.options)
			}
			if backend.plainLength == nil || *backend.plainLength != int64(len(backend.readBody)) {
				t.Fatalf("backend ciphertext length=%v body bytes=%d", backend.plainLength, len(backend.readBody))
			}
			if tc.secure && (len(backend.customerKeyBacking) != len(key) || !bytesAreZero(backend.customerKeyBacking)) {
				t.Fatal("live SSE-C request key was not wiped after backend completion")
			}
			if tc.secure && !bytes.Equal(backend.customerKeyAtBackend, key) {
				t.Fatal("backend did not receive the authenticated SSE-C key")
			}
			if tc.secure && !backend.customerKeyLiveAtBackend {
				t.Fatal("SSE-C key bytes were not live at backend invocation")
			}
			storedMeta := backend.mockS3Client.metadata["bucket/test.jpg"]
			body := backend.mockS3Client.objects["bucket/test.jpg"]
			reader, decryptedMeta, err := h.encryptionEngine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "test.jpg"}, bytes.NewReader(body), storedMeta)
			if err != nil {
				t.Fatalf("decrypt typed-option POST object: %v", err)
			}
			plain, err := io.ReadAll(reader)
			if err != nil || string(plain) != "typed option payload" {
				t.Fatalf("typed option plaintext=%q err=%v", plain, err)
			}
			for _, forbidden := range []string{"policy", "x-amz-signature", "x-amz-credential", "x-amz-security-token", "x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-md5", "Content-MD5", "x-amz-checksum-sha256"} {
				for name := range storedMeta {
					if strings.EqualFold(name, forbidden) {
						t.Errorf("request control field %q persisted", name)
					}
				}
			}
			if tc.secure && (storedMeta[sseCustomerAlg] != "" || storedMeta[sseCustomerMD5] != "" || storedMeta["ETag"] == `"opaque-customer-etag"`) {
				t.Fatal("test backend injected customer response fields into the persisted writer metadata")
			}
			if tc.secure {
				for _, forbidden := range []string{sseCustomerKey, sseCustomerMD5} {
					if _, ok := decryptedMeta[forbidden]; ok {
						t.Errorf("customer secret response field %q appeared in decrypted object metadata", forbidden)
					}
				}
			}
		})
	}
}

func TestGH353PostObject_SSECKeyWipedAfterBackendFailure(t *testing.T) {
	key := bytes.Repeat([]byte{0x29}, 32)
	keyMD5 := md5.Sum(key)
	backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client(), putError: errors.New("injected backend failure")}
	credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
	_, chain := livePostChainForCredentialObserverAndConfig(t, backend, prometheus.NewRegistry(), credential, nil, &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"127.0.0.0/8"}}, Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}})
	extra := map[string]string{sseCustomerAlg: "AES256", sseCustomerKey: base64.StdEncoding.EncodeToString(key), sseCustomerMD5: base64.StdEncoding.EncodeToString(keyMD5[:])}
	conditions := []string{`{"x-amz-server-side-encryption-customer-algorithm":"AES256"}`, fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key":%q}`, extra[sseCustomerKey]), fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key-md5":%q}`, extra[sseCustomerMD5])}
	req := livePostRequest(t, "backend failure cleanup", extra, conditions)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, req)
	if w.Code < http.StatusInternalServerError || backend.puts != 1 {
		t.Fatalf("status=%d puts=%d body=%s", w.Code, backend.puts, w.Body.String())
	}
	if len(backend.customerKeyBacking) != len(key) || !bytesAreZero(backend.customerKeyBacking) || !bytes.Equal(backend.customerKeyAtBackend, key) || !backend.customerKeyLiveAtBackend {
		t.Fatal("SSE-C key was not live during failed backend call and wiped afterward")
	}
	if strings.Contains(w.Body.String(), extra[sseCustomerKey]) {
		t.Fatal("backend failure response leaked customer key")
	}
}

type gh353PostCustomerBackend struct {
	*gh353AdvancedPutClient
	wantKey          []byte
	reads            []sseReadCall
	omitCustomerMode bool
}

type gh353PostCacheSpy struct {
	cache.Cache
	gets int
}

func (c *gh353PostCacheSpy) Get(ctx context.Context, bucket, key string) (*cache.CacheEntry, bool) {
	c.gets++
	return c.Cache.Get(ctx, bucket, key)
}

func (b *gh353PostCustomerBackend) PutObjectWithOptions(ctx context.Context, bucket, key string, body io.Reader, metadata map[string]string, length *int64, tags string, lock *s3.ObjectLockInput, acl, full, read, readACP, writeACP string, options s3.ObjectPutOptions) (s3.PutObjectResult, error) {
	if options.SSE == nil || options.SSE.Customer == nil || !bytes.Equal(options.SSE.Customer.Key, b.wantKey) {
		return s3.PutObjectResult{}, errors.New("backend rejected missing or wrong SSE-C key on write")
	}
	result, err := b.gh353AdvancedPutClient.PutObjectWithOptions(ctx, bucket, key, body, metadata, length, tags, lock, acl, full, read, readACP, writeACP, options)
	if err != nil {
		return result, err
	}
	b.mockS3Client.metadata[bucket+"/"+key][sseCustomerAlg] = "AES256"
	b.mockS3Client.metadata[bucket+"/"+key]["ETag"] = `"opaque-customer-etag"`
	result.ETag = `"opaque-customer-etag"`
	keyMD5 := md5.Sum(b.wantKey)
	result.Headers = map[string]string{sseCustomerAlg: "AES256", sseCustomerMD5: base64.StdEncoding.EncodeToString(keyMD5[:])}
	if b.omitCustomerMode {
		result.Headers = nil
	}
	return result, nil
}

func (b *gh353PostCustomerBackend) GetObjectWithOptions(ctx context.Context, bucket, key string, version, rg *string, options s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	return b.read(ctx, "GET", bucket, key, version, rg, options)
}
func (b *gh353PostCustomerBackend) HeadObjectWithOptions(ctx context.Context, bucket, key string, version *string, options s3.ObjectReadOptions) (map[string]string, error) {
	_, meta, err := b.read(context.Background(), "HEAD", bucket, key, version, nil, options)
	return meta, err
}
func (b *gh353PostCustomerBackend) GetObject(ctx context.Context, bucket, key string, version, rg *string) (io.ReadCloser, map[string]string, error) {
	return nil, nil, &mockAPIError{code: "AccessDenied", message: "backend requires SSE-C key for this stored object"}
}
func (b *gh353PostCustomerBackend) HeadObject(ctx context.Context, bucket, key string, version *string) (map[string]string, error) {
	return nil, &mockAPIError{code: "AccessDenied", message: "backend requires SSE-C key for this stored object"}
}
func (b *gh353PostCustomerBackend) read(ctx context.Context, method, bucket, key string, version, rg *string, options s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	call := sseReadCall{bucket: bucket, key: key, method: method, keyed: options.Customer != nil, keyMatches: options.Customer != nil && bytes.Equal(options.Customer.Key, b.wantKey)}
	if version != nil {
		call.version = *version
	}
	if rg != nil {
		call.rangeHeader = *rg
	}
	b.reads = append(b.reads, call)
	if bucket != "bucket" || key != "test.jpg" || !call.keyMatches {
		return nil, nil, &mockAPIError{code: "AccessDenied", message: "backend rejected absent/wrong customer key"}
	}
	if method == "HEAD" {
		meta, err := b.mockS3Client.HeadObject(ctx, bucket, key, version)
		return nil, meta, err
	}
	return b.mockS3Client.GetObject(ctx, bucket, key, version, rg)
}

func signedPostCustomerRead(t *testing.T, method, rangeHeader string, customerKey []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, "https://gateway.example/bucket/test.jpg", nil)
	if customerKey != nil {
		md := md5.Sum(customerKey)
		r.Header.Set(sseCustomerAlg, "AES256")
		r.Header.Set(sseCustomerKey, base64.StdEncoding.EncodeToString(customerKey))
		r.Header.Set(sseCustomerMD5, base64.StdEncoding.EncodeToString(md[:]))
	}
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, r, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestGH353PostObject_SSECEncryptedOrdinaryReadback(t *testing.T) {
	key := bytes.Repeat([]byte{0x6b}, 32)
	base := newMockS3Client()
	backend := &gh353PostCustomerBackend{gh353AdvancedPutClient: &gh353AdvancedPutClient{mockS3Client: base}, wantKey: key}
	credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
	h, chain := livePostChainForCredentialObserverAndConfig(t, backend, prometheus.NewRegistry(), credential, nil, &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"127.0.0.0/8"}}, Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}})
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
	h.cache = &gh353PostCacheSpy{Cache: cache.NewMemoryCache(1<<20, 8, time.Minute)}
	plain := bytes.Repeat([]byte("POST-customer-readback-☃"), 1800)
	kmd5 := md5.Sum(key)
	extra := map[string]string{sseCustomerAlg: "AES256", sseCustomerKey: base64.StdEncoding.EncodeToString(key), sseCustomerMD5: base64.StdEncoding.EncodeToString(kmd5[:])}
	conds := []string{`{"x-amz-server-side-encryption-customer-algorithm":"AES256"}`, fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key":%q}`, extra[sseCustomerKey]), fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key-md5":%q}`, extra[sseCustomerMD5])}
	post := livePostRequest(t, string(plain), extra, conds)
	post.RemoteAddr = "127.0.0.1:1234"
	post.Header.Set("X-Forwarded-Proto", "https")
	pr := httptest.NewRecorder()
	chain.ServeHTTP(pr, post)
	if pr.Code != http.StatusNoContent || base.putObjectCallCount != 1 {
		t.Fatalf("POST status=%d puts=%d body=%s", pr.Code, base.putObjectCallCount, pr.Body.String())
	}
	if bytes.Equal(base.objects["bucket/test.jpg"], plain) {
		t.Fatal("SSE-C POST stored plaintext")
	}
	base.metadata["bucket/test.jpg"][sseCustomerAlg] = "AES256"
	base.metadata["bucket/test.jpg"]["ETag"] = `"opaque-customer-etag"`
	for name, value := range map[string]string{"Content-MD5": extra["Content-MD5"], "x-amz-signature": "sentinel-signature", "policy": "sentinel-policy", sseCustomerKey: "sentinel-key", "x-amz-security-token": "sentinel-token"} {
		if value == "" {
			continue
		}
		if _, present := base.metadata["bucket/test.jpg"][name]; present {
			t.Errorf("request/control metadata %s persisted", name)
		}
	}
	for _, tc := range []struct {
		method, rg string
		code       int
		want       []byte
	}{{http.MethodGet, "", 200, plain}, {http.MethodGet, "bytes=3-19", 206, plain[3:20]}, {http.MethodHead, "", 200, nil}} {
		r := signedPostCustomerRead(t, tc.method, tc.rg, key)
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, r)
		if w.Code != tc.code || !bytes.Equal(w.Body.Bytes(), tc.want) {
			t.Fatalf("%s %s status=%d body=%d want=%d err=%s", tc.method, tc.rg, w.Code, w.Body.Len(), len(tc.want), w.Body.String())
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("ETag") != `"opaque-customer-etag"` || w.Header().Get(sseCustomerKey) != "" {
			t.Fatalf("unsafe headers: %v", w.Header())
		}
	}
	if len(backend.reads) < 3 {
		t.Fatalf("signed read calls missing: %+v", backend.reads)
	}
	for _, call := range backend.reads {
		if !call.keyMatches || !call.keyed || call.bucket != "bucket" || call.key != "test.jpg" {
			t.Fatalf("customer credentials/target not forwarded: %+v", call)
		}
	}
	if cacheEntryExists(h.cache, "bucket", "test.jpg") {
		t.Fatal("keyed SSE-C read unexpectedly captured plaintext in the cache")
	}
	for _, mode := range []string{"201", "303"} {
		fields := map[string]string{sseCustomerAlg: "AES256", sseCustomerKey: base64.StdEncoding.EncodeToString(key), sseCustomerMD5: base64.StdEncoding.EncodeToString(kmd5[:])}
		conditions := append([]string(nil), conds...)
		wantStatus := http.StatusCreated
		if mode == "201" {
			fields["success_action_status"] = "201"
			conditions = append(conditions, `{"success_action_status":"201"}`)
		} else {
			fields["success_action_redirect"] = "https://post.example/done?keep=yes"
			conditions = append(conditions, `{"success_action_redirect":"https://post.example/done?keep=yes"}`)
			wantStatus = http.StatusSeeOther
		}
		backend.omitCustomerMode = mode == "303"
		req := livePostRequest(t, string(plain), fields, conditions)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, req)
		if w.Code != wantStatus || w.Header().Get("ETag") != `"opaque-customer-etag"` || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("mode=%s status=%d headers=%v body=%s", mode, w.Code, w.Header(), w.Body.String())
		}
		if mode == "303" && (w.Header().Get(sseCustomerAlg) != "" || w.Header().Get(sseCustomerMD5) != "" || w.Header().Get(sseCustomerKey) != "") {
			t.Fatalf("mode-omitted response projected untrusted backend customer headers: %v", w.Header())
		}
		if mode == "201" {
			var result postResponse
			if err := xml.Unmarshal(w.Body.Bytes(), &result); err != nil || result.ETag != `"opaque-customer-etag"` {
				t.Fatalf("201 XML etag=%q err=%v", result.ETag, err)
			}
		} else {
			u, err := url.Parse(w.Header().Get("Location"))
			if err != nil || u.Query().Get("etag") != `"opaque-customer-etag"` {
				t.Fatalf("303 redirect=%q err=%v", w.Header().Get("Location"), err)
			}
		}
	}
	for _, tc := range []struct {
		name, method, rangeHeader string
		key                       []byte
	}{
		{"missing key GET", http.MethodGet, "", nil},
		{"wrong key GET", http.MethodGet, "", bytes.Repeat([]byte{0x7c}, 32)},
		{"missing key range", http.MethodGet, "bytes=0-15", nil},
		{"wrong key range", http.MethodGet, "bytes=0-15", bytes.Repeat([]byte{0x7c}, 32)},
		{"missing key HEAD", http.MethodHead, "", nil},
		{"wrong key HEAD", http.MethodHead, "", bytes.Repeat([]byte{0x7c}, 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cacheSpy := h.cache.(*gh353PostCacheSpy)
			cacheSpy.gets = 0
			if err := h.cache.Set(context.Background(), "bucket", "test.jpg", []byte("cached-plaintext-canary"), map[string]string{"owner": "cache"}, time.Minute); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			chain.ServeHTTP(w, signedPostCustomerRead(t, tc.method, tc.rangeHeader, tc.key))
			if w.Code != http.StatusForbidden {
				t.Fatalf("missing/wrong key status=%d expected translated backend AccessDenied", w.Code)
			}
			if tc.method != http.MethodHead && !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") {
				t.Fatalf("missing/wrong key response missing translated AccessDenied: %s", w.Body.String())
			}
			if bytes.Contains(w.Body.Bytes(), plain[:min(16, len(plain))]) || bytes.Equal(w.Body.Bytes(), plain) || bytes.Contains(w.Body.Bytes(), []byte("cached-plaintext-canary")) {
				t.Fatal("missing/wrong key response included object plaintext")
			}
			if cacheSpy.gets != 0 {
				t.Fatalf("missing/wrong customer key consulted plaintext cache %d times", cacheSpy.gets)
			}
			if tc.method == http.MethodGet && tc.rangeHeader == "" {
				if entry, ok := h.cache.Get(context.Background(), "bucket", "test.jpg"); ok && bytes.Contains(w.Body.Bytes(), entry.Data) {
					t.Fatal("missing customer key response replayed the cached plaintext entry")
				}
			}
		})
	}
}

func cacheEntryExists(store cache.Cache, bucket, key string) bool {
	if store == nil {
		return false
	}
	_, ok := store.Get(context.Background(), bucket, key)
	return ok
}

type gh353LiveProfileEngine struct {
	crypto.EncryptionEngine
	profile crypto.EncryptionWriteProfile
	calls   atomic.Int64
}

func (e *gh353LiveProfileEngine) WriteProfile() crypto.EncryptionWriteProfile { return e.profile }
func (e *gh353LiveProfileEngine) Encrypt(ctx context.Context, object crypto.ObjectContext, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	e.calls.Add(1)
	return e.EncryptionEngine.Encrypt(ctx, object, reader, metadata)
}

func TestGH353PostObject_LiveStreamingAndBufferedPartCap(t *testing.T) {
	for _, tc := range []struct {
		name       string
		streaming  bool
		wantStatus int
	}{
		{"real chunked profile spools above captured part cap", true, http.StatusNoContent},
		{"real buffered profile rejects cap plus one", false, http.StatusRequestEntityTooLarge},
		{"legacy engine without WriteProfiler rejects cap plus one", false, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newMockS3Client()
			backend := &gh353AdvancedPutClient{mockS3Client: base}
			credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
			h, chain := livePostChainForCredentialObserverAndConfig(t, backend, prometheus.NewRegistry(), credential, nil, &config.Config{Server: config.ServerConfig{MaxPartBuffer: 32, MaxAggregateSpoolBytes: 1 << 20, SpoolDirectory: t.TempDir()}})
			h.spoolLimits.Set(SpoolLimits{Global: 1 << 20, Part: 32})
			var engine crypto.EncryptionEngine
			var err error
			if tc.streaming {
				engine, err = crypto.NewEngineWithOpts([]byte("live-stream-profile"), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
			} else if strings.Contains(tc.name, "without WriteProfiler") {
				engine = &gh353NoProfileEngine{}
			} else {
				engine, err = crypto.NewEngineWithOpts([]byte("live-buffer-profile"), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
			}
			if err != nil {
				t.Fatal(err)
			}
			wrapper := &gh353LiveProfileEngine{EncryptionEngine: engine}
			if profiler, ok := engine.(crypto.EncryptionWriteProfiler); ok {
				wrapper.profile = profiler.WriteProfile()
			}
			if tc.streaming && !wrapper.profile.StreamsPlaintext {
				t.Fatalf("engine profile=%+v", wrapper.profile)
			}
			if strings.Contains(tc.name, "without WriteProfiler") {
				h.encryptionEngine = engine
			} else {
				h.encryptionEngine = wrapper
			}
			var acquisitions atomic.Int64
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions.Add(1); return backend, nil }
			body := strings.Repeat("x", 128)
			req := livePostRequest(t, body, nil, nil)
			w := httptest.NewRecorder()
			original := streamingSpoolOps
			var cipherCreates, cipherWrites atomic.Int64
			streamingSpoolOps.createTemp = func(dir, pattern string) (*os.File, error) {
				if strings.HasPrefix(pattern, "s3gw-post-cipher-") {
					cipherCreates.Add(1)
				}
				return original.createTemp(dir, pattern)
			}
			streamingSpoolOps.write = func(f *os.File, p []byte) (int, error) {
				if strings.Contains(f.Name(), "s3gw-post-cipher-") {
					cipherWrites.Add(int64(len(p)))
				}
				return original.write(f, p)
			}
			t.Cleanup(func() { streamingSpoolOps = original })
			chain.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.streaming {
				if wrapper.calls.Load() != 1 || acquisitions.Load() != 1 || backend.puts != 1 || cipherCreates.Load() != 1 || cipherWrites.Load() == 0 || bytes.Equal(backend.readBody, []byte(body)) {
					t.Fatalf("streaming encrypt=%d clients=%d puts=%d cipher temp=%d written=%d", wrapper.calls.Load(), acquisitions.Load(), backend.puts, cipherCreates.Load(), cipherWrites.Load())
				}
				readEngine := engine
				reader, _, decryptErr := readEngine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "test.jpg"}, bytes.NewReader(base.objects["bucket/test.jpg"]), base.metadata["bucket/test.jpg"])
				if decryptErr != nil {
					t.Fatal(decryptErr)
				}
				restored, readErr := io.ReadAll(reader)
				if readErr != nil || string(restored) != body {
					t.Fatalf("restored=%q err=%v", restored, readErr)
				}
				if base.metadata["bucket/test.jpg"][crypto.MetaChunkedFormat] != "true" {
					t.Fatalf("expected actual chunked object format: %v", base.metadata["bucket/test.jpg"])
				}
			} else {
				calls := wrapper.calls.Load()
				if strings.Contains(tc.name, "without WriteProfiler") {
					calls = int64(engine.(*gh353NoProfileEngine).calls)
				}
				if calls != 0 || acquisitions.Load() != 1 || backend.puts != 0 || cipherCreates.Load() != 0 || cipherWrites.Load() != 0 {
					t.Fatalf("buffered over-cap crossed encrypt/cache/backend boundary: encrypt=%d clients=%d puts=%d", calls, acquisitions.Load(), backend.puts)
				}
			}
			if entries, readErr := os.ReadDir(h.spoolManager.(*spoolManager).tempDirectory()); readErr != nil || len(entries) != 0 {
				t.Fatalf("live spool cleanup files=%v err=%v", entries, readErr)
			}
		})
	}
}

func TestGH353PostObject_RejectionPreservesDestination(t *testing.T) {
	backend := newMockS3Client()
	backend.objects["bucket/test.jpg"] = []byte("existing ciphertext")
	backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "previous"}
	before := append([]byte(nil), backend.objects["bucket/test.jpg"]...)
	var acquisitions int
	h, chain := livePostChain(t, backend, nil)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions++; return backend, nil }
	request := livePostRequest(t, "replacement", map[string]string{"unexpected": "sentinel-form-value"}, nil)
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented || acquisitions != 0 || backend.putObjectCallCount != 0 {
		t.Fatalf("status=%d acquisitions=%d puts=%d response=%s", response.Code, acquisitions, backend.putObjectCallCount, response.Body.String())
	}
	if !bytes.Equal(before, backend.objects["bucket/test.jpg"]) || backend.metadata["bucket/test.jpg"]["owner"] != "previous" {
		t.Fatalf("denied upload modified existing object: %q metadata=%v", backend.objects["bucket/test.jpg"], backend.metadata["bucket/test.jpg"])
	}
	if strings.Contains(response.Body.String(), "sentinel-form-value") {
		t.Fatalf("response leaked submitted form: %s", response.Body.String())
	}
}

func TestGH353PostObject_MetadataTooLargePreservesDestination(t *testing.T) {
	for _, mode := range []string{"auto", "compact"} {
		for _, bypass := range []bool{false, true} {
			t.Run(fmt.Sprint("mode=", mode, "/bypass=", bypass), func(t *testing.T) {
				backend := newMockS3Client()
				backend.objects["bucket/test.jpg"] = []byte("old")
				backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "old"}
				reg := prometheus.NewRegistry()
				h, chain := livePostChain(t, backend, reg)
				h.config.Backend.Provider = "backblaze-b2"
				h.config.Backend.MetadataProfile = mode
				spy := &gh353DeleteCallbackCache{}
				h.cache = spy
				if bypass {
					h.encryptionEngine = crypto.PassthroughEngine{}
				} else {
					engine, err := crypto.NewEngineWithOpts([]byte("metadata-limit-test-password"), crypto.WithMetadataProfile("backblaze-b2", mode), crypto.WithChunking(true), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = engine.(io.Closer).Close() })
					h.encryptionEngine = engine
				}
				name := "Content-Type"
				if bypass {
					name = "x-amz-meta-large"
				}
				value := strings.Repeat("v", 3000)
				req := livePostRequest(t, "replacement", map[string]string{name: value}, []string{fmt.Sprintf(`{%q:%q}`, name, value)})
				w := httptest.NewRecorder()
				chain.ServeHTTP(w, req)
				if w.Code != 400 || !strings.Contains(w.Body.String(), "<Code>MetadataTooLarge</Code>") || strings.Contains(w.Body.String(), value) {
					t.Fatalf("response=%d %s", w.Code, w.Body.String())
				}
				if backend.putObjectCallCount != 0 || spy.deletes != 0 || string(backend.objects["bucket/test.jpg"]) != "old" || backend.metadata["bucket/test.jpg"]["owner"] != "old" {
					t.Fatal("rejection mutated destination or cache")
				}
				if metricTotal(t, reg, "s3_operation_errors_total", `operation="PostObject"`, `error_type="MetadataTooLarge"`) != 1 {
					t.Fatal("incorrect error metric")
				}
			})
		}
	}
}

func TestGH353PostObject_ClientAcquisitionLogDoesNotExposeBackendDiagnostic(t *testing.T) {
	backend := newMockS3Client()
	registry := prometheus.NewRegistry()
	var output strings.Builder
	logger := logrus.New()
	logger.SetOutput(&output)
	logger.SetLevel(logrus.ErrorLevel)
	// Build the fixture again with the captured logger attached to the actual
	// handler. The signed POST still traverses auth, authorization, mux, handler,
	// and the real client-acquisition error boundary.
	h, chain := livePostChain(t, backend, registry)
	h.logger = logger
	const diagnostic = "backend-secret-diagnostic-canary"
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return nil, errors.New(diagnostic) }
	request := livePostRequest(t, "client acquisition failure", map[string]string{"x-amz-meta-owner": "benign-owner"}, []string{`{"x-amz-meta-owner":"benign-owner"}`})
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "<Code>InternalError</Code>") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), diagnostic) || strings.Contains(output.String(), diagnostic) {
		t.Fatalf("backend diagnostic leaked: log=%q response=%q", output.String(), response.Body.String())
	}
	if !strings.Contains(output.String(), "Failed to acquire backend client") {
		t.Fatalf("safe operation context missing from log: %s", output.String())
	}
	if !strings.Contains(output.String(), "stage=backend_acquisition") {
		t.Fatalf("fixed backend-acquisition stage missing: %s", output.String())
	}
	metrics, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if got := postMetricsCount(t, metrics, "http_requests_total", "method", http.MethodPost, "path", "/bucket", "status", http.StatusText(http.StatusInternalServerError)); got != 1 {
		t.Fatalf("backend acquisition HTTP metric count=%v want=1", got)
	}
}

func TestGH353PostObject_WriteFailureLogsFixedStageOnly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stage objectWriteStage
		want  string
	}{
		{name: "preparation", stage: objectWritePreparation, want: "preparation"},
		{name: "encryption", stage: objectWriteCrypto, want: "encryption"},
		{name: "classification", stage: objectWriteClassify, want: "classification"},
		{name: "backend", stage: objectWriteBackend, want: "backend"},
		{name: "validation client error", stage: objectWriteInvalid, want: "validation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			registry := prometheus.NewRegistry()
			var output strings.Builder
			logger := logrus.New()
			logger.SetOutput(&output)
			logger.SetLevel(logrus.ErrorLevel)
			h, _ := livePostChain(t, backend, registry)
			h.logger = logger
			request := httptest.NewRequest(http.MethodPost, "/bucket/test.jpg", nil)
			recorder := httptest.NewRecorder()
			var err error
			const canary = "secret-backend-or-crypto-detail"
			err = objectWriteFailure(tc.stage, errors.New(canary))
			writePostError(recorder, request, h, err, time.Now())
			if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "<Code>InternalError</Code>") {
				t.Fatalf("client response changed status=%d body=%q", recorder.Code, recorder.Body.String())
			}
			logText := output.String()
			if !strings.Contains(logText, "stage="+tc.want) || !strings.Contains(logText, "operation=PostObject") {
				t.Fatalf("fixed stage fields missing from log: %q", logText)
			}
			if strings.Contains(logText, canary) || strings.Contains(recorder.Body.String(), canary) || strings.Contains(logText, "/bucket/test.jpg") {
				t.Fatalf("private diagnostic or request identity leaked: log=%q response=%q", logText, recorder.Body.String())
			}
			metrics, gatherErr := registry.Gather()
			if gatherErr != nil {
				t.Fatal(gatherErr)
			}
			if got := postMetricsCount(t, metrics, "s3_operation_errors_total", "operation", "PostObject", "error_type", "InternalError"); got != 1 {
				t.Fatalf("operation error metric count=%v want=1", got)
			}
			if got := postMetricsSum(t, metrics, "http_requests_total", "method", http.MethodPost, "status", http.StatusText(http.StatusInternalServerError)); got != 1 {
				t.Fatalf("request metric count=%v want=1", got)
			}
		})
	}

	var output strings.Builder
	logger := logrus.New()
	logger.SetOutput(&output)
	h, _ := livePostChain(t, newMockS3Client(), nil)
	h.logger = logger
	request := httptest.NewRequest(http.MethodPost, "/bucket/test.jpg", nil)
	response := httptest.NewRecorder()
	writePostError(response, request, h, errors.New("secret-untyped-diagnostic"), time.Now())
	if !strings.Contains(output.String(), "stage=unknown") || strings.Contains(output.String(), "secret-untyped-diagnostic") {
		t.Fatalf("untyped internal error did not map to safe unknown stage: %q", output.String())
	}

	// A missing logger remains a supported no-op for the safe diagnostic path.
	noLoggerHandler, _ := livePostChain(t, newMockS3Client(), nil)
	noLoggerHandler.logger = nil
	writePostError(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/bucket", nil), noLoggerHandler, objectWriteFailure(objectWriteBackend, errors.New("private")), time.Now())
}

func postMetricsCount(t *testing.T, families []*dto.MetricFamily, familyName string, labels ...string) float64 {
	t.Helper()
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, metric := range family.Metric {
			match := true
			for index := 0; index+1 < len(labels); index += 2 {
				found := false
				for _, label := range metric.Label {
					if label.GetName() == labels[index] && label.GetValue() == labels[index+1] {
						found = true
						break
					}
				}
				match = match && found
			}
			if match {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func postMetricsSum(t *testing.T, families []*dto.MetricFamily, familyName string, labels ...string) float64 {
	t.Helper()
	var sum float64
	for _, family := range families {
		if family.GetName() != familyName {
			continue
		}
		for _, metric := range family.Metric {
			match := true
			for index := 0; index+1 < len(labels); index += 2 {
				found := false
				for _, label := range metric.Label {
					if label.GetName() == labels[index] && label.GetValue() == labels[index+1] {
						found = true
						break
					}
				}
				match = match && found
			}
			if match {
				sum += metric.GetCounter().GetValue()
			}
		}
	}
	return sum
}

func TestGH353PostInstrumentation_HandlerFailureRequestStatus(t *testing.T) {
	registry := prometheus.NewRegistry()
	backend := newMockS3Client()
	_, chain := livePostChain(t, backend, registry)
	request := livePostRequest(t, "valid file body", nil, nil)
	request.Host = "invalid authority"
	recorder := httptest.NewRecorder()
	chain.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest || backend.putObjectCallCount != 0 {
		t.Fatalf("status=%d backend puts=%d response=%s", recorder.Code, backend.putObjectCallCount, recorder.Body.String())
	}
	metricOutput := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(metricOutput, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricOutput.Body.String(), `s3_client_requests_total{bucket="bucket",operation="PostObject",status_code="400"} 1`) {
		t.Fatalf("handler validation failure not counted by named route: %s", metricOutput.Body.String())
	}
}

func TestGH353PostInstrumentation_RealAuthFailure(t *testing.T) {
	registry := prometheus.NewRegistry()
	backend := newMockS3Client()
	_, chain := livePostChain(t, backend, registry)
	request := livePostRequest(t, "must not be consumed", nil, nil)
	observed := &observedRequestBody{Reader: request.Body}
	request.Body = observed
	request.Header.Set("Authorization", "forbidden alternate authentication")
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || backend.putObjectCallCount != 0 {
		t.Fatalf("status=%d puts=%d body=%s", response.Code, backend.putObjectCallCount, response.Body.String())
	}
	if observed.read != 0 {
		t.Fatalf("alternate-auth rejection consumed %d request bytes", observed.read)
	}
	metricOutput := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(metricOutput, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(metricOutput.Body.String(), `operation="PostObject",status_code="400"`) {
		t.Fatalf("pre-router auth rejection was incorrectly attributed to route instrumentation: %s", metricOutput.Body.String())
	}
}

func TestGH353PostInstrumentation_AuthFailureFileBytesAreCountedOnce(t *testing.T) {
	registry := prometheus.NewRegistry()
	_, chain := livePostChain(t, newMockS3Client(), registry)
	request := livePostRequest(t, strings.Repeat("x", 4096), nil, nil)
	request.Header.Set("Authorization", "simultaneous auth is prohibited")
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	metricsResponse := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricsResponse.Body.String(), `s3_client_bytes_total{bucket="bucket",direction="in"} 0`) {
		if strings.Contains(metricsResponse.Body.String(), `direction="in"`) {
			t.Fatalf("auth rejection counted form wire bytes: %s", metricsResponse.Body.String())
		}
	}
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestGH353PostObject_UnknownQueryRemainsUnmatched(t *testing.T) {
	router := mux.NewRouter()
	(&Handler{}).RegisterRoutes(router)
	for _, target := range []string{"/bucket?x=1", "/bucket?uploads", "/bucket?uploadId=u", "/bucket?delete"} {
		r := httptest.NewRequest(http.MethodPost, target, nil)
		r.Header.Set("Content-Type", "multipart/form-data; boundary=valid")
		var match mux.RouteMatch
		if router.Match(r, &match) && match.Route != nil && match.Route.GetName() == "PostObject" {
			t.Errorf("POST %s incorrectly matched PostObject", target)
		}
	}
}

func TestGH353PostObject_ScopeReadOnlyAndMixedRoutes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		credential config.GatewayCredential
		proxied    string
		wantStatus int
		wantReason string
	}{
		{"read only principal", config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadOnly)}, "", http.StatusForbidden, "read_only"},
		{"principal scope", config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"other"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}, "", http.StatusForbidden, "bucket_scope"},
		{"deployment scope", config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}, "other", http.StatusForbidden, "bucket_scope"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			engine, err := newAPIUnitEngine([]byte("test encryption password"))
			if err != nil {
				t.Fatal(err)
			}
			store, err := NewStaticCredentialStore([]config.GatewayCredential{tc.credential})
			if err != nil {
				t.Fatal(err)
			}
			h := NewHandlerWithFeatures(backend, engine, logrus.New(), nil, nil, nil, nil, &config.Config{}, nil)
			var acquisitions int
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions++; return backend, nil }
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			var auditSpy mockAuditLogger
			chain := AuthMiddleware(store, time.Minute, logrus.New(), &auditSpy, true, h.spoolManager, SpoolLimits{Global: 1 << 20, Part: 1 << 20})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upload, ok := postUploadFromContext(r)
				if !ok || upload.authenticatedAccessKey != tc.credential.AccessKey || upload.fileCounter.wire.fileBytes != 0 {
					t.Errorf("authorization did not receive same principal before file read: upload=%+v ok=%v", upload, ok)
				}
				AuthorizationMiddleware(tc.proxied, &auditSpy)(router).ServeHTTP(w, r)
			}))
			req := livePostRequestFor(t, tc.credential.SecretKey, "bucket", "test.jpg", "small file", nil, nil)
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, req)
			if response.Code != tc.wantStatus || acquisitions != 0 || backend.putObjectCallCount != 0 {
				t.Fatalf("status=%d want=%d acquisitions=%d puts=%d body=%s", response.Code, tc.wantStatus, acquisitions, backend.putObjectCallCount, response.Body.String())
			}
			if len(auditSpy.events) == 0 || auditSpy.events[len(auditSpy.events)-1].eventType != string(audit.EventTypeAuthorizationDenied) || auditSpy.events[len(auditSpy.events)-1].reason != tc.wantReason {
				t.Fatalf("authorization event=%+v want reason=%q", auditSpy.events, tc.wantReason)
			}
		})
	}
}

func TestGH353PostObject_ExpiryBeforeCommit(t *testing.T) {
	backend := newMockS3Client()
	var acquisitions int
	h, _ := livePostChain(t, backend, nil)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions++; return backend, nil }
	request := livePostRequest(t, "expiry payload", nil, nil)
	defer request.Body.Close()
	upload, err := parsePostUpload(request, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer upload.Close()
	credential := Credential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	if err := upload.bindDestination("bucket"); err != nil {
		t.Fatal(err)
	}
	if err := validatePostPolicyAt(upload, credential, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
	upload.deadline = time.Now().Add(-time.Second)
	upload.authenticatedAccessKey = credential.AccessKey
	request = request.WithContext(context.WithValue(request.Context(), credentialKey, credential))
	request = request.WithContext(context.WithValue(request.Context(), postUploadContextKey{}, upload))
	request = mux.SetURLVars(request, map[string]string{"bucket": "bucket"})
	response := httptest.NewRecorder()
	// Exercise the live handler directly with the authenticated snapshot but an
	// expired request deadline, which must fail before the backend acquisition.
	h.handlePostObject(response, request)
	if response.Code != http.StatusForbidden || acquisitions != 0 || backend.putObjectCallCount != 0 || !strings.Contains(response.Body.String(), "Request has expired.") {
		t.Fatalf("status=%d acquisitions=%d puts=%d body=%s", response.Code, acquisitions, backend.putObjectCallCount, response.Body.String())
	}
}

func TestGH353PostObject_NilURLUsesSingleErrorOwner(t *testing.T) {
	registry := prometheus.NewRegistry()
	h, _ := livePostChain(t, newMockS3Client(), registry)
	request := &http.Request{Method: http.MethodPost, URL: nil, Header: make(http.Header)}
	response := httptest.NewRecorder()
	h.handlePostObject(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "<Code>InvalidRequest</Code>") {
		t.Fatalf("nil-URL POST error was not classified by the shared owner: status=%d body=%s", response.Code, response.Body.String())
	}
	metrics, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var errorFamilyFound, requestFamilyFound bool
	var errorSeries, requestSeries int
	var errorCount, requestCount float64
	for _, family := range metrics {
		if family.GetName() == "s3_operation_errors_total" {
			errorFamilyFound = true
			for _, metric := range family.Metric {
				labels := make(map[string]string, len(metric.Label))
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["operation"] == "PostObject" && labels["bucket"] == "" && labels["error_type"] == "InvalidRequest" {
					errorSeries++
					errorCount += metric.GetCounter().GetValue()
				}
			}
		}
		if family.GetName() == "http_requests_total" {
			requestFamilyFound = true
			for _, metric := range family.Metric {
				labels := make(map[string]string, len(metric.Label))
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["method"] == http.MethodPost && labels["path"] == "/" && labels["status"] == http.StatusText(http.StatusBadRequest) {
					requestSeries++
					requestCount += metric.GetCounter().GetValue()
				}
			}
		}
	}
	if !errorFamilyFound || !requestFamilyFound || errorSeries != 1 || requestSeries != 1 || errorCount != 1 || requestCount != 1 {
		t.Fatalf("shared POST error accounting missing, duplicated, or mislabeled: s3_operation_errors family=%t series=%d count=%v; http_requests family=%t series=%d count=%v", errorFamilyFound, errorSeries, errorCount, requestFamilyFound, requestSeries, requestCount)
	}
}

func TestGH353PostObject_ErrorIdentityFallbacksAndNilWriteGuards(t *testing.T) {
	if bucket, key := postErrorObjectIdentity(nil); bucket != "" || key != "" {
		t.Fatalf("nil request identity=%q/%q", bucket, key)
	}
	withoutURL := &http.Request{}
	if bucket, key := postErrorObjectIdentity(withoutURL); bucket != "" || key != "" {
		t.Fatalf("nil URL identity=%q/%q", bucket, key)
	}
	request := httptest.NewRequest(http.MethodPost, "/bucket", nil)
	if bucket, key := postErrorObjectIdentity(request); bucket != "bucket" || key != "" {
		t.Fatalf("path identity=%q/%q", bucket, key)
	}
	request = mux.SetURLVars(request, map[string]string{"bucket": "route-bucket", "key": "route-key"})
	if bucket, key := postErrorObjectIdentity(request); bucket != "route-bucket" || key != "route-key" {
		t.Fatalf("route identity=%q/%q", bucket, key)
	}
	upload := &postUpload{bucket: "signed-bucket", key: "signed-key"}
	request = request.WithContext(context.WithValue(request.Context(), postUploadContextKey{}, upload))
	if bucket, key := postErrorObjectIdentity(request); bucket != "signed-bucket" || key != "signed-key" {
		t.Fatalf("authenticated snapshot identity=%q/%q", bucket, key)
	}
	if got, ok := postUploadFromContext(nil); ok || got != nil {
		t.Fatalf("nil request upload context=%p ok=%t", got, ok)
	}
	if got, ok := postUploadFromContext(httptest.NewRequest(http.MethodPost, "/bucket", nil)); ok || got != nil {
		t.Fatalf("missing upload context=%p ok=%t", got, ok)
	}
	writePostError(nil, request, nil, errors.New("ignored"), time.Now())
	writePostClientAcquisitionError(nil, request, nil, upload, errors.New("ignored"), time.Now())
	writePostClientAcquisitionError(httptest.NewRecorder(), nil, nil, upload, errors.New("ignored"), time.Now())
	writePostClientAcquisitionError(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/bucket", nil), nil, upload, errors.New("ignored"), time.Now())
}

func TestGH353PostObject_ClientAcquisitionFallbackResponseOwnership(t *testing.T) {
	for _, tc := range []struct {
		name       string
		upload     *postUpload
		requestURL string
		wantCode   string
	}{
		{name: "classifiable backend acquisition error", upload: &postUpload{bucket: "signed-bucket", key: "signed-key"}, requestURL: "/route-bucket", wantCode: "InternalError"},
		{name: "nil translation uses auth fallback", requestURL: "/route-bucket", wantCode: "InternalError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			h, _ := livePostChain(t, newMockS3Client(), registry)
			h.logger = nil
			request := httptest.NewRequest(http.MethodPost, tc.requestURL, nil)
			if tc.upload != nil {
				request = request.WithContext(context.WithValue(request.Context(), postUploadContextKey{}, tc.upload))
			}
			recorder := httptest.NewRecorder()
			if tc.upload == nil {
				writePostClientAcquisitionError(recorder, request, h, nil, nil, time.Now())
			} else {
				writePostClientAcquisitionError(recorder, request, h, tc.upload, errors.New("backend acquisition failed"), time.Now())
			}
			if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "<Code>InternalError</Code>") {
				t.Fatalf("acquisition error response status=%d body=%s want HTTP 500 XML InternalError", recorder.Code, recorder.Body.String())
			}
			if tc.upload != nil && !strings.Contains(recorder.Body.String(), "<Resource>/signed-bucket/signed-key</Resource>") {
				t.Fatalf("error resource did not retain authenticated object identity: %s", recorder.Body.String())
			}
			if tc.upload == nil && !strings.Contains(recorder.Body.String(), "<Resource>/route-bucket</Resource>") {
				t.Fatalf("fallback error did not retain request bucket identity: %s", recorder.Body.String())
			}
			metrics, err := registry.Gather()
			if err != nil {
				t.Fatal(err)
			}
			var errorFamilyFound, requestFamilyFound bool
			var errorSeries, requestSeries int
			var errorCount, requestCount float64
			for _, family := range metrics {
				if family.GetName() != "s3_operation_errors_total" {
					if family.GetName() == "http_requests_total" {
						requestFamilyFound = true
						for _, metric := range family.Metric {
							labels := make(map[string]string, len(metric.Label))
							for _, label := range metric.Label {
								labels[label.GetName()] = label.GetValue()
							}
							if labels["method"] == http.MethodPost && labels["path"] == tc.requestURL && labels["status"] == http.StatusText(http.StatusInternalServerError) {
								requestSeries++
								requestCount += metric.GetCounter().GetValue()
							}
						}
					}
					continue
				}
				errorFamilyFound = true
				for _, metric := range family.Metric {
					labels := make(map[string]string, len(metric.Label))
					for _, label := range metric.Label {
						labels[label.GetName()] = label.GetValue()
					}
					// livePostChain registers a test registry, whose metrics enable
					// bucket labels; retain the actual chosen bucket identity.
					wantBucket := "route-bucket"
					if tc.upload != nil {
						wantBucket = tc.upload.bucket
					}
					if labels["operation"] == "PostObject" && labels["bucket"] == wantBucket && labels["error_type"] == "InternalError" {
						errorSeries++
						errorCount += metric.GetCounter().GetValue()
					}
				}
			}
			if !errorFamilyFound || !requestFamilyFound || errorSeries != 1 || requestSeries != 1 || errorCount != 1 || requestCount != 1 {
				t.Fatalf("shared acquisition error ownership mismatch: error family=%t series=%d count=%v; request family=%t series=%d count=%v", errorFamilyFound, errorSeries, errorCount, requestFamilyFound, requestSeries, requestCount)
			}
		})
	}
}

func TestGH353PostObject_HandlerNilAndSnapshotGuardOwnership(t *testing.T) {
	h, _ := livePostChain(t, newMockS3Client(), nil)
	request := httptest.NewRequest(http.MethodPost, "/bucket", nil)
	response := httptest.NewRecorder()
	(*Handler)(nil).handlePostObject(response, request)
	h.handlePostObject(nil, request)
	if response.Code != 200 || response.Body.Len() != 0 {
		t.Fatalf("nil handler unexpectedly wrote response: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/bucket", nil)
	request.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	request = request.WithContext(context.WithValue(request.Context(), postUploadContextKey{}, (*postUpload)(nil)))
	response = httptest.NewRecorder()
	h.handlePostObject(response, request)
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "<Code>AccessDenied</Code>") {
		t.Fatalf("nil snapshot did not fail closed through auth owner: status=%d body=%s", response.Code, response.Body.String())
	}
}

type livePostReadBarrier struct {
	reader  io.Reader
	entered chan struct{}
	release chan struct{}
	onRead  func(int)
	once    atomic.Bool
	readErr error
}

func (r *livePostReadBarrier) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && r.once.CompareAndSwap(false, true) {
		if r.onRead != nil {
			r.onRead(n)
		}
		close(r.entered)
		<-r.release
		if r.readErr != nil {
			return n, r.readErr
		}
	}
	return n, err
}

func blockLivePostFileRead(r *http.Request, entered, release chan struct{}, onRead func(int)) *livePostReadBarrier {
	upload, ok := postUploadFromContext(r)
	if !ok {
		panic("live POST auth chain did not attach upload snapshot")
	}
	barrier := &livePostReadBarrier{reader: upload.fileRead, entered: entered, release: release, onRead: onRead}
	upload.fileRead = barrier
	return barrier
}

func TestGH353PostObject_DeadlineCrossedDuringAuthenticatedPlaintextRead(t *testing.T) {
	for _, tc := range []struct {
		name        string
		policyEnds  bool
		session     bool
		bodyTimeout bool
		bodyEOF     bool
	}{
		{name: "policy deadline", policyEnds: true},
		{name: "configured session deadline", session: true},
		{name: "request context deadline with data", bodyTimeout: true},
		{name: "request context deadline with data and EOF", bodyTimeout: true, bodyEOF: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
			expires := time.Now().UTC().Add(3 * time.Second)
			ctx := context.Background()
			cancel := context.CancelFunc(func() {})
			if tc.bodyTimeout {
				ctx, cancel = context.WithDeadline(ctx, expires)
			}
			defer cancel()
			if tc.session {
				credential.SessionToken = "post-session-token"
				credential.ExpiresAt = &expires
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			releaseBarrier := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseBarrier()
			var fileBytes atomic.Int64
			h, chain := livePostChainForCredentialAndObserver(t, backend, nil, credential, func(r *http.Request) {
				onRead := func(n int) { fileBytes.Add(int64(n)) }
				if tc.bodyTimeout {
					onRead = func(n int) { fileBytes.Add(int64(n)); cancel() }
				}
				barrier := blockLivePostFileRead(r, entered, release, onRead)
				if tc.bodyEOF {
					barrier.readErr = io.EOF
				}
			})
			cacheSpy := &postCacheSpy{Cache: cache.NewMemoryCache(1024, 8, time.Minute)}
			if err := cacheSpy.Cache.Set(context.Background(), "bucket", "test.jpg", []byte("preserved deadline cache"), map[string]string{"owner": "cache-prior"}, time.Minute); err != nil {
				t.Fatal(err)
			}
			h.cache = cacheSpy
			var acquisitions, engineLoads atomic.Int64
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions.Add(1); return backend, nil }
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { engineLoads.Add(1); return h.encryptionEngine, nil }
			extra, conditions := map[string]string(nil), []string(nil)
			if tc.session {
				extra = map[string]string{"x-amz-security-token": credential.SessionToken}
				conditions = []string{fmt.Sprintf(`{"x-amz-security-token":%q}`, credential.SessionToken)}
			}
			policyExpiration := time.Now().UTC().Add(20 * time.Minute)
			if tc.policyEnds {
				policyExpiration = expires
			}
			body := strings.Repeat("p", 96*1024)
			request := livePostRequestForExpiry(t, credential.SecretKey, "bucket", "test.jpg", body, extra, conditions, policyExpiration)
			spoolReader := &maxReadSizeReader{ReadCloser: request.Body}
			request.Body = spoolReader
			request = request.WithContext(ctx)
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { chain.ServeHTTP(response, request); close(done) }()
			// The authenticated snapshot carries the effective deadline (policy or
			// session); observe it only after auth has completed.
			var deadline time.Time
			select {
			case <-entered:
				// The first blocked read has already crossed into live spool consumption.
				// Derive the deadline from the input that controls this case.
				deadline = expires
			case <-time.After(10 * time.Second):
				releaseBarrier()
				<-done
				t.Fatal("live POST did not reach the file-byte read barrier")
			}
			delay := time.Until(deadline.Add(20 * time.Millisecond))
			if tc.bodyTimeout {
				select {
				case <-ctx.Done():
				case <-time.After(10 * time.Second):
					releaseBarrier()
					<-done
					t.Fatal("request context deadline did not fire")
				}
				delay = 0
			}
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-time.After(10 * time.Second):
					releaseBarrier()
					<-done
					t.Fatal("deadline wait timed out")
				}
			}
			releaseBarrier()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("live POST handler did not return after releasing read barrier")
			}
			wantCode, wantMessage, wantStatus := "AccessDenied", "Request has expired.", http.StatusForbidden
			if tc.bodyTimeout {
				wantCode, wantMessage, wantStatus = "IncompleteBody", "The request body is incomplete.", http.StatusBadRequest
			}
			if response.Code != wantStatus || !strings.Contains(response.Body.String(), "<Code>"+wantCode+"</Code>") || !strings.Contains(response.Body.String(), wantMessage) || cacheSpy.deletes != 0 {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			entry, ok := cacheSpy.Get(context.Background(), "bucket", "test.jpg")
			if !ok || string(entry.Data) != "preserved deadline cache" || entry.Metadata["owner"] != "cache-prior" {
				t.Fatalf("deadline/cancellation changed cache: entry=%+v found=%t", entry, ok)
			}
			if fileBytes.Load() == 0 || spoolReader.maximumSeen() > 7 || acquisitions.Load() != 0 || engineLoads.Load() != 0 || backend.putObjectCallCount != 0 {
				t.Fatalf("file bytes=%d raw max read=%d acquisitions=%d engines=%d puts=%d", fileBytes.Load(), spoolReader.maximumSeen(), acquisitions.Load(), engineLoads.Load(), backend.putObjectCallCount)
			}
			manager := h.spoolManager.(*spoolManager)
			entries, err := os.ReadDir(manager.tempDirectory())
			if err != nil || len(entries) != 0 || manager.CurrentBytes() != 0 {
				t.Fatalf("plaintext cleanup entries=%v quota=%d err=%v", entries, manager.CurrentBytes(), err)
			}
		})
	}
}

type maxReadSizeReader struct {
	io.ReadCloser
	max     atomic.Int64
	maxRead int
}

func (r *maxReadSizeReader) Read(p []byte) (int, error) {
	bound := r.maxRead
	if bound <= 0 {
		bound = 7
	}
	if len(p) > bound {
		p = p[:bound]
	}
	n, err := r.ReadCloser.Read(p)
	for {
		old := r.max.Load()
		if int64(n) <= old || r.max.CompareAndSwap(old, int64(n)) {
			break
		}
	}
	return n, err
}

func (r *maxReadSizeReader) maximumSeen() int64 { return r.max.Load() }

type boundedRawReadCloser struct {
	io.ReadCloser
	max     int
	maxSeen atomic.Int64
}

func (r *boundedRawReadCloser) Read(p []byte) (int, error) {
	for {
		old := r.maxSeen.Load()
		if int64(len(p)) <= old || r.maxSeen.CompareAndSwap(old, int64(len(p))) {
			break
		}
	}
	if len(p) > r.max {
		return 0, fmt.Errorf("raw request read of %d exceeds bound %d", len(p), r.max)
	}
	return r.ReadCloser.Read(p)
}

func TestGH353PostObject_LiveMalformedMultipartCompletionBeforeBackend(t *testing.T) {
	for _, tc := range []struct {
		name, ending  string
		contentLen    int64
		wantStatus    int
		wantCode      string
		headerPadding int
		secondPart    string
		unknownLength bool
	}{
		{name: "invalid non-whitespace epilogue", ending: "epilogue", contentLen: -1, wantStatus: http.StatusBadRequest, wantCode: "InvalidRequest"},
		{name: "LF-only closing delimiter", ending: "lf-closing", contentLen: -1, wantStatus: http.StatusBadRequest, wantCode: "IncompleteBody"},
		{name: "truncated closing delimiter", ending: "truncated-closing", contentLen: -1, wantStatus: http.StatusBadRequest, wantCode: "IncompleteBody"},
		{name: "content length mismatch", ending: "", contentLen: 1, wantStatus: http.StatusBadRequest, wantCode: "IncompleteBody"},
		{name: "file is not final part", secondPart: "--live-post-boundary\r\nContent-Disposition: form-data; name=\"x-ignore-after-file\"\r\n\r\nframing-probe\r\n--live-post-boundary--\r\n", unknownLength: true, wantStatus: http.StatusBadRequest, wantCode: "InvalidRequest"},
		{name: "second file part", secondPart: "--live-post-boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"second.bin\"\r\n\r\nsecond\r\n--live-post-boundary--\r\n", unknownLength: true, wantStatus: http.StatusBadRequest, wantCode: "InvalidRequest"},
		{name: "signed scalar overhead limit", ending: "", contentLen: -1, wantStatus: http.StatusRequestEntityTooLarge, wantCode: "EntityTooLarge", headerPadding: -1},
		{name: "oversized pre-file MIME header", ending: "", contentLen: -1, wantStatus: http.StatusRequestEntityTooLarge, wantCode: "EntityTooLarge", headerPadding: 21 * 1024},
		{name: "oversized post-file epilogue", ending: "large-epilogue", contentLen: -1, wantStatus: http.StatusRequestEntityTooLarge, wantCode: "EntityTooLarge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			backend.objects["bucket/test.jpg"] = []byte("existing ciphertext")
			backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "prior"}
			h, chain := livePostChain(t, backend, nil)
			var clients, engines atomic.Int64
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { clients.Add(1); return backend, nil }
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { engines.Add(1); return h.encryptionEngine, nil }
			mutation := func(body *bytes.Buffer) error {
				if tc.headerPadding > 0 {
					contents := strings.Replace(body.String(), `Content-Disposition: form-data; name="file"; filename="test.jpg"`, "Content-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\nX-Pad: "+strings.Repeat("x", tc.headerPadding), 1)
					body.Reset()
					_, _ = body.WriteString(contents)
					return nil
				}
				if tc.headerPadding < 0 {
					contents := body.String()
					marker := `name="key"` + "\r\n\r\n"
					contents = strings.Replace(contents, marker, marker+strings.Repeat("s", 20*1024), 1)
					body.Reset()
					_, _ = body.WriteString(contents)
					return nil
				}
				if tc.ending == "epilogue" {
					_, _ = body.WriteString("!")
				}
				if tc.ending == "large-epilogue" {
					_, _ = body.WriteString(strings.Repeat(" ", 21*1024))
				}
				if tc.ending == "lf-closing" {
					contents := body.String()
					contents = strings.Replace(contents, "\r\n--live-post-boundary--\r\n", "\n--live-post-boundary--\n", 1)
					body.Reset()
					_, _ = body.WriteString(contents)
				}
				if tc.ending == "truncated-closing" {
					contents := strings.TrimSuffix(body.String(), "\r\n--live-post-boundary--\r\n") + "\r\n--live-post-boundary-"
					body.Reset()
					_, _ = body.WriteString(contents)
				}
				if tc.secondPart != "" {
					contents := strings.TrimSuffix(body.String(), "\r\n--live-post-boundary--\r\n") + "\r\n" + tc.secondPart
					body.Reset()
					_, _ = body.WriteString(contents)
				}
				return nil
			}
			expiry := time.Now().UTC().Add(20 * time.Minute)
			request := livePostRequestWithOptions(t, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "bucket", "test.jpg", "malformed completion", nil, nil, expiry, mutation, "live-post-boundary")
			if tc.unknownLength {
				request.ContentLength = -1
			} else if tc.contentLen >= 0 {
				request.ContentLength = tc.contentLen
			}
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.wantStatus || !strings.Contains(response.Body.String(), "<Code>"+tc.wantCode+"</Code>") || clients.Load() != 0 || engines.Load() != 0 || backend.putObjectCallCount != 0 {
				t.Fatalf("status=%d want=%d clients=%d engines=%d puts=%d body=%s", response.Code, tc.wantStatus, clients.Load(), engines.Load(), backend.putObjectCallCount, response.Body.String())
			}
			if tc.name == "file is not final part" && !strings.Contains(response.Body.String(), "<Message>Invalid POST form.</Message>") {
				t.Fatalf("authenticated non-final file did not reach exact framing error: %s", response.Body.String())
			}
			if string(backend.objects["bucket/test.jpg"]) != "existing ciphertext" || backend.metadata["bucket/test.jpg"]["owner"] != "prior" {
				t.Fatalf("malformed body changed destination: object=%q metadata=%v", backend.objects["bucket/test.jpg"], backend.metadata["bucket/test.jpg"])
			}
			manager := h.spoolManager.(*spoolManager)
			if manager.CurrentBytes() != 0 {
				t.Fatalf("plaintext reservation leaked: %d", manager.CurrentBytes())
			}
		})
	}
}

func TestGH353PostObject_SignedClosedOptionFailuresBeforeFileRead(t *testing.T) {
	for _, tc := range []struct {
		name, field, value string
		wantStatus         int
		wantCode           string
	}{
		{"invalid acl", "acl", "log-delivery-write", http.StatusBadRequest, "InvalidArgument"},
		{"invalid storage class", "x-amz-storage-class", "UNKNOWN", http.StatusBadRequest, "InvalidArgument"},
		{"invalid website redirect", "x-amz-website-redirect-location", "ftp://example.test/path", http.StatusBadRequest, "InvalidArgument"},
		{"invalid tagging", "tagging", "<Tagging><TagSet><Tag/>", http.StatusBadRequest, "MalformedXML"},
		{"reserved metadata", "x-amz-meta-original-content-length", "private-value", http.StatusBadRequest, "InvalidArgument"},
		{"invalid sse mix", "x-amz-server-side-encryption", "AES256", http.StatusBadRequest, "InvalidArgument"},
		{"unsupported field", "x-amz-checksum-crc64nvme", "AAAAAA==", http.StatusNotImplemented, "NotImplemented"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			backend.objects["bucket/test.jpg"] = []byte("existing ciphertext")
			backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "prior"}
			var clients, engines, fileBytes atomic.Int64
			h, chain := livePostChainForCredentialAndObserver(t, backend, nil, config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}, func(r *http.Request) {
				upload, ok := postUploadFromContext(r)
				if !ok {
					t.Error("signed auth did not provide parsed POST snapshot")
					return
				}
				upload.fileCounter.onRead = func(n int64) { fileBytes.Add(n) }
			})
			manager := h.spoolManager.(*spoolManager)
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { clients.Add(1); return backend, nil }
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { engines.Add(1); return h.encryptionEngine, nil }
			extra := map[string]string{tc.field: tc.value}
			conditions := []string{fmt.Sprintf(`{%q:%q}`, tc.field, tc.value)}
			if tc.field == "x-amz-server-side-encryption" {
				extra["x-amz-server-side-encryption-customer-algorithm"] = "AES256"
				conditions = append(conditions, `{"x-amz-server-side-encryption-customer-algorithm":"AES256"}`)
			}
			request := livePostRequest(t, strings.Repeat("f", 64*1024), extra, conditions)
			maxRaw := 7
			if tc.field == "acl" || tc.field == "x-amz-storage-class" {
				maxRaw = 1
			}
			limitedBody := &maxReadSizeReader{ReadCloser: request.Body, maxRead: maxRaw}
			request.Body = limitedBody
			originalSpoolOps := streamingSpoolOps
			var createCalls atomic.Int64
			streamingSpoolOps.createTemp = func(dir, pattern string) (*os.File, error) {
				createCalls.Add(1)
				return originalSpoolOps.createTemp(dir, pattern)
			}
			t.Cleanup(func() { streamingSpoolOps = originalSpoolOps })
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			entries, readDirErr := os.ReadDir(manager.tempDirectory())
			if response.Code != tc.wantStatus || !strings.Contains(response.Body.String(), "<Code>"+tc.wantCode+"</Code>") || clients.Load() != 0 || engines.Load() != 0 || fileBytes.Load() != 0 || manager.CurrentBytes() != 0 || backend.putObjectCallCount != 0 || len(entries) != 0 || readDirErr != nil || limitedBody.maximumSeen() > int64(maxRaw) || createCalls.Load() != 0 {
				t.Fatalf("status=%d want=%d clients=%d engines=%d fileBytes=%d quota=%d puts=%d rawMaxRead=%d bound=%d spoolCreates=%d spoolEntries=%v spoolErr=%v body=%s", response.Code, tc.wantStatus, clients.Load(), engines.Load(), fileBytes.Load(), manager.CurrentBytes(), backend.putObjectCallCount, limitedBody.maximumSeen(), maxRaw, createCalls.Load(), entries, readDirErr, response.Body.String())
			}
			if string(backend.objects["bucket/test.jpg"]) != "existing ciphertext" || backend.metadata["bucket/test.jpg"]["owner"] != "prior" {
				t.Fatalf("option rejection changed destination: object=%q metadata=%v", backend.objects["bucket/test.jpg"], backend.metadata["bucket/test.jpg"])
			}
			if strings.Contains(response.Body.String(), tc.value) {
				t.Fatalf("option value leaked in error: %s", response.Body.String())
			}
		})
	}
}

func TestGH353PostObject_UnsupportedInlineTagging(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		status      int
		code        string
	}{
		{"tagged", `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`, 501, "NotImplemented"},
		{"empty tag set", `<Tagging><TagSet></TagSet></Tagging>`, 501, "NotImplemented"},
		{"malformed", `<Tagging><TagSet>`, 400, "MalformedXML"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			backend.objects["bucket/test.jpg"] = []byte("previous ciphertext")
			backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "prior"}
			credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
			var clients, engines, fileBytes atomic.Int64
			h, chain := livePostChainForCredentialObserverAndConfig(t, backend, nil, credential, func(r *http.Request) {
				if upload, ok := postUploadFromContext(r); ok && !upload.fileCounter.eof {
					upload.fileCounter.onRead = func(n int64) { fileBytes.Add(n) }
				}
			}, &config.Config{Backend: config.BackendConfig{PostInlineTagging: "unsupported"}})
			store := cache.NewMemoryCache(1024, 8, time.Minute)
			if err := store.Set(context.Background(), "bucket", "test.jpg", []byte("cached"), map[string]string{"owner": "cache"}, time.Minute); err != nil {
				t.Fatal(err)
			}
			spy := &postCacheSpy{Cache: store}
			h.cache = spy
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { clients.Add(1); return backend, nil }
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { engines.Add(1); return h.encryptionEngine, nil }
			manager := h.spoolManager.(*spoolManager)
			original := streamingSpoolOps
			var creates atomic.Int64
			streamingSpoolOps.createTemp = func(dir, pattern string) (*os.File, error) { creates.Add(1); return original.createTemp(dir, pattern) }
			t.Cleanup(func() { streamingSpoolOps = original })
			request := livePostRequest(t, strings.Repeat("x", 65536), map[string]string{"tagging": tc.value}, []string{fmt.Sprintf(`{"tagging":%q}`, tc.value)})
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			entry, ok := store.Get(context.Background(), "bucket", "test.jpg")
			if response.Code != tc.status || !strings.Contains(response.Body.String(), "<Code>"+tc.code+"</Code>") || (tc.status == 501 && !strings.Contains(response.Body.String(), "The requested POST option is not supported.")) || clients.Load() != 0 || engines.Load() != 0 || fileBytes.Load() != 0 || creates.Load() != 0 || manager.CurrentBytes() != 0 || backend.putObjectCallCount != 0 || spy.deletes != 0 || spy.sets != 0 || !ok || string(entry.Data) != "cached" || string(backend.objects["bucket/test.jpg"]) != "previous ciphertext" || backend.metadata["bucket/test.jpg"]["owner"] != "prior" {
				t.Fatalf("unsafe rejection: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestGH353PostObject_SSECKeyWipedAfterLiveTransportRejection(t *testing.T) {
	backend := newMockS3Client()
	key := bytes.Repeat([]byte("k"), 32)
	keyDigest := md5.Sum(key)
	encodedKey := base64.StdEncoding.EncodeToString(key)
	encodedMD5 := base64.StdEncoding.EncodeToString(keyDigest[:])
	var clientAcquisitions, engineLoads, fileBytes atomic.Int64
	var customerKeyBacking []byte
	credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
	h, chain := livePostChainForCredentialAndObserver(t, backend, nil, credential, func(r *http.Request) {
		upload, ok := postUploadFromContext(r)
		if ok && upload.options.SSE != nil && upload.options.SSE.Customer != nil {
			customerKeyBacking = upload.options.SSE.Customer.Key
		} else if ok && !upload.fileCounter.eof {
			upload.fileCounter.onRead = func(n int64) { fileBytes.Add(n) }
		} else if !ok {
			t.Error("signed auth did not supply upload")
		}
	})
	manager := h.spoolManager.(*spoolManager)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { clientAcquisitions.Add(1); return backend, nil }
	h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { engineLoads.Add(1); return h.encryptionEngine, nil }
	extra := map[string]string{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       encodedKey,
		"x-amz-server-side-encryption-customer-key-md5":   encodedMD5,
	}
	conditions := []string{
		`{"x-amz-server-side-encryption-customer-algorithm":"AES256"}`,
		fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key":%q}`, encodedKey),
		fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key-md5":%q}`, encodedMD5),
	}
	request := livePostRequest(t, strings.Repeat("x", 64*1024), extra, conditions)
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "<Code>InvalidRequest</Code>") || !strings.Contains(response.Body.String(), "SSE-C requires a secure transport.") || clientAcquisitions.Load() != 0 || engineLoads.Load() != 0 || fileBytes.Load() != 0 || manager.CurrentBytes() != 0 || backend.putObjectCallCount != 0 {
		t.Fatalf("status=%d clients=%d engines=%d fileBytes=%d quota=%d puts=%d body=%s", response.Code, clientAcquisitions.Load(), engineLoads.Load(), fileBytes.Load(), manager.CurrentBytes(), backend.putObjectCallCount, response.Body.String())
	}
	if len(customerKeyBacking) != len(key) || !bytesAreZero(customerKeyBacking) {
		t.Fatal("live authenticated upload did not wipe its SSE-C key backing bytes")
	}
	if strings.Contains(response.Body.String(), encodedKey) {
		t.Fatal("live option error disclosed SSE-C key")
	}
}

func TestGH353PostObject_UnsupportedTaggingWipesSSEC(t *testing.T) {
	backend := newMockS3Client()
	key := bytes.Repeat([]byte("k"), 32)
	digest := md5.Sum(key)
	encoded, encodedDigest := base64.StdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(digest[:])
	var backing []byte
	credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
	h, chain := livePostChainForCredentialObserverAndConfig(t, backend, nil, credential, func(r *http.Request) {
		if u, ok := postUploadFromContext(r); ok && u.options.SSE != nil && u.options.SSE.Customer != nil {
			backing = u.options.SSE.Customer.Key
		}
	}, &config.Config{Backend: config.BackendConfig{PostInlineTagging: "unsupported"}})
	var clients atomic.Int64
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { clients.Add(1); return backend, nil }
	tags := `<Tagging><TagSet></TagSet></Tagging>`
	fields := map[string]string{"tagging": tags, "x-amz-server-side-encryption-customer-algorithm": "AES256", "x-amz-server-side-encryption-customer-key": encoded, "x-amz-server-side-encryption-customer-key-md5": encodedDigest}
	conditions := []string{fmt.Sprintf(`{"tagging":%q}`, tags), `{"x-amz-server-side-encryption-customer-algorithm":"AES256"}`, fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key":%q}`, encoded), fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key-md5":%q}`, encodedDigest)}
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, livePostRequest(t, "data", fields, conditions))
	if response.Code != 501 || len(backing) != len(key) || !bytesAreZero(backing) || clients.Load() != 0 || strings.Contains(response.Body.String(), encoded) {
		t.Fatal("unsupported tagging did not wipe SSE-C key before acquisition")
	}
}

func TestGH353PostObject_UnsupportedTaggingAuthPolicyPrecedence(t *testing.T) {
	tags := `<Tagging><TagSet></TagSet></Tagging>`
	for _, tc := range []struct {
		name, secret string
		conditions   []string
	}{
		{"bad signature", "wrong-signing-secret", []string{fmt.Sprintf(`{"tagging":%q}`, tags)}},
		{"unsigned tagging", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
			h, chain := livePostChainForCredentialObserverAndConfig(t, backend, nil, credential, nil, &config.Config{Backend: config.BackendConfig{PostInlineTagging: "unsupported"}})
			var clients atomic.Int64
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { clients.Add(1); return backend, nil }
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, livePostRequestFor(t, tc.secret, "bucket", "test.jpg", "data", map[string]string{"tagging": tags}, tc.conditions))
			if response.Code != http.StatusForbidden || clients.Load() != 0 || strings.Contains(response.Body.String(), "NotImplemented") {
				t.Fatalf("authentication/policy did not precede tagging: %d", response.Code)
			}
		})
	}
}

func TestGH353PolicyEngineMetadataProfile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(file, []byte("id: profile-test\nbuckets: [bucket]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{file}); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{Backend: config.BackendConfig{Provider: "backblaze-b2", MetadataProfile: "compact"}}
	cfg.Encryption.Password = "policy-profile-password"
	h := &Handler{config: cfg, policyManager: pm}
	engine, err := h.getEncryptionEngine("bucket")
	if err != nil {
		t.Fatal(err)
	}
	defer engine.(io.Closer).Close()
	_, meta, err := engine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, strings.NewReader("data"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := meta["x-amz-meta-a"]; !ok {
		t.Fatal("policy engine ignored compact profile")
	}
	cfg.Backend.MetadataProfile = "invalid"
	if _, err := h.getEncryptionEngine("bucket"); err == nil {
		t.Fatal("invalid policy profile accepted")
	}
}

func TestGH353PostObject_LiveSignedSizeBoundsBeforeBackend(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fileSize   int
		minimum    int
		maximum    int
		global     int64
		wantStatus int
		wantCode   string
	}{
		{name: "below signed minimum", fileSize: 32, minimum: 33, maximum: 128, global: 1 << 20, wantStatus: http.StatusBadRequest, wantCode: "EntityTooSmall"},
		{name: "above signed maximum", fileSize: 129, minimum: 1, maximum: 128, global: 1 << 20, wantStatus: http.StatusRequestEntityTooLarge, wantCode: "EntityTooLarge"},
		{name: "captured global file limit", fileSize: 256, minimum: 1, maximum: 1024, global: 128, wantStatus: http.StatusRequestEntityTooLarge, wantCode: "EntityTooLarge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			backend.objects["bucket/test.jpg"] = []byte("prior ciphertext")
			backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "prior"}
			h, chain := livePostChain(t, backend, nil)
			h.spoolLimits.Set(SpoolLimits{Global: tc.global, Part: 1 << 20})
			var clients, engines atomic.Int64
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { clients.Add(1); return backend, nil }
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { engines.Add(1); return h.encryptionEngine, nil }
			conditions := []string{fmt.Sprintf(`["content-length-range",%d,%d]`, tc.minimum, tc.maximum)}
			request := livePostRequest(t, strings.Repeat("b", tc.fileSize), nil, conditions)
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.wantStatus || !strings.Contains(response.Body.String(), "<Code>"+tc.wantCode+"</Code>") || clients.Load() != 0 || engines.Load() != 0 || backend.putObjectCallCount != 0 {
				t.Fatalf("status=%d want=%d clients=%d engines=%d puts=%d body=%s", response.Code, tc.wantStatus, clients.Load(), engines.Load(), backend.putObjectCallCount, response.Body.String())
			}
			if string(backend.objects["bucket/test.jpg"]) != "prior ciphertext" || backend.metadata["bucket/test.jpg"]["owner"] != "prior" || h.spoolManager.(*spoolManager).CurrentBytes() != 0 {
				t.Fatalf("signed size rejection modified destination or leaked quota: object=%q meta=%v spool=%d", backend.objects["bucket/test.jpg"], backend.metadata["bucket/test.jpg"], h.spoolManager.(*spoolManager).CurrentBytes())
			}
		})
	}
}

type postFailGrowManager struct {
	SpoolManager
	targetAcquire int64
	acquires      atomic.Int64
}

func (m *postFailGrowManager) Acquire(ctx context.Context, size, limit int64) (SpoolReservation, error) {
	reservation, err := m.SpoolManager.Acquire(ctx, size, limit)
	if err != nil {
		return nil, err
	}
	if m.acquires.Add(1) == m.targetAcquire {
		return &postFailGrowReservation{SpoolReservation: reservation}, nil
	}
	return reservation, nil
}

type postFailGrowReservation struct{ SpoolReservation }

func (r *postFailGrowReservation) Grow(int64) error { return ErrSpoolCapacity }

func TestGH353PostObject_LivePlaintextAndCiphertextSpoolFailures(t *testing.T) {
	for _, stage := range []string{"plain", "cipher"} {
		for _, fault := range []string{"create", "chmod", "write", "short-write", "seek", "grow"} {
			t.Run(stage+"/"+fault, func(t *testing.T) {
				backend := newMockS3Client()
				backend.objects["bucket/test.jpg"] = []byte("prior ciphertext")
				backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "prior"}
				manager := NewSpoolManager(2<<20, t.TempDir())
				h, chain := livePostChain(t, backend, nil)
				h.spoolManager = manager
				if fault == "grow" {
					target := int64(1)
					if stage == "cipher" {
						target = 2
					}
					h.spoolManager = &postFailGrowManager{SpoolManager: manager, targetAcquire: target}
				}
				var clients, engines atomic.Int64
				h.clientAcquirer = func(*http.Request) (s3.Client, error) { clients.Add(1); return backend, nil }
				h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { engines.Add(1); return h.encryptionEngine, nil }
				cacheStore := cache.NewMemoryCache(1<<20, 8, time.Minute)
				seed := &cache.CacheEntry{Data: []byte("cached old object"), Metadata: map[string]string{"owner": "cache-prior"}, BackendETag: "prior"}
				if err := cacheStore.(cache.EntryWriter).SetEntry(context.Background(), "bucket", "test.jpg", seed, time.Minute); err != nil {
					t.Fatal(err)
				}
				cacheSpy := &postCacheSpy{Cache: cacheStore}
				h.cache = cacheSpy
				original := streamingSpoolOps
				paths := make([]string, 0, 2)
				streamingSpoolOps = original
				streamingSpoolOps.createTemp = func(dir, pattern string) (*os.File, error) {
					isTarget := stage == "plain" && strings.HasPrefix(pattern, "s3gw-post-plain-") || stage == "cipher" && strings.HasPrefix(pattern, "s3gw-post-cipher-")
					if isTarget && fault == "create" {
						return nil, errors.New("injected create")
					}
					f, err := original.createTemp(dir, pattern)
					if err == nil {
						paths = append(paths, f.Name())
					}
					return f, err
				}
				streamingSpoolOps.chmod = func(f *os.File, mode os.FileMode) error {
					if isLivePostSpoolTarget(f, stage) && fault == "chmod" {
						return errors.New("injected chmod")
					}
					return original.chmod(f, mode)
				}
				streamingSpoolOps.write = func(f *os.File, data []byte) (int, error) {
					if isLivePostSpoolTarget(f, stage) {
						switch fault {
						case "write":
							return 0, errors.New("injected write")
						case "short-write":
							n, _ := original.write(f, data)
							if n > 0 {
								return n - 1, nil
							}
						}
					}
					return original.write(f, data)
				}
				streamingSpoolOps.seek = func(f *os.File, offset int64, whence int) (int64, error) {
					if isLivePostSpoolTarget(f, stage) && fault == "seek" {
						return 0, errors.New("injected seek")
					}
					return original.seek(f, offset, whence)
				}
				t.Cleanup(func() { streamingSpoolOps = original })
				response := httptest.NewRecorder()
				chain.ServeHTTP(response, livePostRequest(t, strings.Repeat("f", 64*1024), nil, nil))
				wantStatus := http.StatusInternalServerError
				wantCode := "InternalError"
				if fault == "grow" {
					wantStatus, wantCode = http.StatusServiceUnavailable, "SlowDown"
				}
				wantClients, wantEngines := int64(0), int64(0)
				if stage == "cipher" {
					wantClients, wantEngines = 1, 1
				}
				if response.Code != wantStatus || !strings.Contains(response.Body.String(), "<Code>"+wantCode+"</Code>") || clients.Load() != wantClients || engines.Load() != wantEngines || backend.putObjectCallCount != 0 || cacheSpy.deletes != 0 {
					t.Fatalf("status=%d want=%d clients=%d/%d engines=%d/%d puts=%d cache deletes=%d body=%s", response.Code, wantStatus, clients.Load(), wantClients, engines.Load(), wantEngines, backend.putObjectCallCount, cacheSpy.deletes, response.Body.String())
				}
				if string(backend.objects["bucket/test.jpg"]) != "prior ciphertext" || backend.metadata["bucket/test.jpg"]["owner"] != "prior" {
					t.Fatalf("spool failure changed backend destination object=%q metadata=%v", backend.objects["bucket/test.jpg"], backend.metadata["bucket/test.jpg"])
				}
				entry, ok := cacheStore.Get(context.Background(), "bucket", "test.jpg")
				if !ok || string(entry.Data) != "cached old object" || entry.Metadata["owner"] != "cache-prior" {
					t.Fatalf("cache entry changed after spool failure: entry=%+v found=%t", entry, ok)
				}
				if actual := manager.(*spoolManager).CurrentBytes(); actual != 0 {
					t.Fatalf("quota leaked after %s/%s: %d", stage, fault, actual)
				}
				for _, path := range paths {
					if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("spool path remains after cleanup: %s err=%v", path, err)
					}
				}
			})
		}
	}
}

func isLivePostSpoolTarget(file *os.File, stage string) bool {
	if file == nil {
		return false
	}
	name := file.Name()
	if stage == "plain" {
		return strings.Contains(name, "s3gw-post-plain-")
	}
	return strings.Contains(name, "s3gw-post-cipher-")
}

type livePostEncryptOverride struct {
	crypto.EncryptionEngine
	override func(io.Reader) io.Reader
}

func (e livePostEncryptOverride) Encrypt(ctx context.Context, object crypto.ObjectContext, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	encrypted, encryptedMetadata, err := e.EncryptionEngine.Encrypt(ctx, object, reader, metadata)
	if err != nil {
		return nil, nil, err
	}
	return e.override(encrypted), encryptedMetadata, nil
}

type livePostCipherReadBarrier struct {
	reader  io.Reader
	entered chan struct{}
	release chan struct{}
	onRead  func()
	once    atomic.Bool
	readErr error
}

type cancelCipherReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelCipherReadCloser) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 {
		r.cancel()
	}
	return n, err
}

func (r *livePostCipherReadBarrier) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n > 0 && r.once.CompareAndSwap(false, true) {
		if r.onRead != nil {
			r.onRead()
		}
		close(r.entered)
		<-r.release
		if r.readErr != nil {
			return n, r.readErr
		}
	}
	return n, err
}

type cancellationGrowSpy struct {
	SpoolReservation
	ctx      context.Context
	deadline time.Time
	grew     atomic.Int64
}

func (r *cancellationGrowSpy) Grow(n int64) error {
	if r.ctx.Err() != nil || !r.deadline.IsZero() && !time.Now().Before(r.deadline) {
		r.grew.Add(n)
	}
	return r.SpoolReservation.Grow(n)
}

type cancellationSpoolManager struct {
	SpoolManager
	ctx      context.Context
	deadline time.Time
	grew     atomic.Int64
}

func (m *cancellationSpoolManager) Acquire(ctx context.Context, size, limit int64) (SpoolReservation, error) {
	r, err := m.SpoolManager.Acquire(ctx, size, limit)
	if err != nil {
		return nil, err
	}
	return &cancellationGrowSpy{SpoolReservation: r, ctx: m.ctx, deadline: m.deadline, grew: m.grew}, nil
}

func TestGH353PostObject_CancellationDuringCiphertextReadCleansBothSpools(t *testing.T) {
	for _, tc := range []struct {
		name    string
		readErr error
		withEOF bool
	}{
		{name: "context cancellation"},
		{name: "reader data with cancellation sentinel", readErr: ErrStreamingCanceled},
		{name: "reader data EOF while canceled", readErr: io.EOF, withEOF: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			entered, release := make(chan struct{}), make(chan struct{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var releaseOnce sync.Once
			releaseBarrier := func() { releaseOnce.Do(func() { close(release) }) }
			defer releaseBarrier()
			h, chain := livePostChain(t, backend, nil)
			baseManager := h.spoolManager
			manager := &cancellationSpoolManager{SpoolManager: baseManager, ctx: ctx}
			h.spoolManager = manager
			var acquisitions atomic.Int64
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions.Add(1); return backend, nil }
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) {
				return livePostEncryptOverride{EncryptionEngine: h.encryptionEngine, override: func(reader io.Reader) io.Reader {
					return &livePostCipherReadBarrier{reader: reader, entered: entered, release: release, readErr: tc.readErr, onRead: func() {
						if tc.readErr == nil {
							cancel()
						} else if tc.withEOF {
							cancel()
						}
					}}
				}}, nil
			}
			request := livePostRequest(t, strings.Repeat("c", 64*1024), nil, nil).WithContext(ctx)
			response := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { chain.ServeHTTP(response, request); close(done) }()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				releaseBarrier()
				<-done
				t.Fatal("ciphertext output was not consumed")
			}
			if baseManager.(*spoolManager).CurrentBytes() == 0 || acquisitions.Load() != 1 {
				t.Fatalf("plain reservation=%d client acquisitions=%d", baseManager.(*spoolManager).CurrentBytes(), acquisitions.Load())
			}
			if tc.withEOF {
				cancel()
				manager.grew.Store(0)
			}
			releaseBarrier()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("handler did not return after ciphertext failure")
			}
			wantCode := "IncompleteBody"
			if tc.withEOF {
				wantCode = "IncompleteBody"
			}
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "<Code>"+wantCode+"</Code>") || backend.putObjectCallCount != 0 {
				t.Fatalf("status=%d puts=%d body=%s", response.Code, backend.putObjectCallCount, response.Body.String())
			}
			if baseManager.(*spoolManager).CurrentBytes() != 0 || manager.grew.Load() != 0 {
				t.Fatalf("cipher/plain quota leaked=%d ciphertext quota grew after cancellation=%d", baseManager.(*spoolManager).CurrentBytes(), manager.grew.Load())
			}
			entries, err := os.ReadDir(baseManager.(*spoolManager).tempDirectory())
			if err != nil || len(entries) != 0 {
				t.Fatalf("spool files=%v err=%v", entries, err)
			}
		})
	}
}

func TestGH353PostObject_DeadlineCrossedDuringCiphertextPreparation(t *testing.T) {
	backend := newMockS3Client()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseBarrier := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseBarrier()
	expiration := time.Now().UTC().Add(3 * time.Second)
	credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
	h, chain := livePostChainForCredential(t, backend, nil, credential)
	baseManager := h.spoolManager
	managerWithGrowSpy := &cancellationSpoolManager{SpoolManager: baseManager, ctx: context.Background(), deadline: expiration}
	h.spoolManager = managerWithGrowSpy
	cacheSpy := &postCacheSpy{Cache: cache.NewMemoryCache(1024, 8, time.Minute)}
	if err := cacheSpy.Cache.Set(context.Background(), "bucket", "test.jpg", []byte("cached pre-deadline"), map[string]string{"owner": "cache-prior"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	h.cache = cacheSpy
	sizeSpy := &gh353MemorySizeCache{values: make(map[string]int64)}
	h.sizeCache = sizeSpy
	var acquisitions atomic.Int64
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions.Add(1); return backend, nil }
	h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) {
		return livePostEncryptOverride{EncryptionEngine: h.encryptionEngine, override: func(reader io.Reader) io.Reader {
			return &livePostCipherReadBarrier{reader: reader, entered: entered, release: release}
		}}, nil
	}
	body := strings.Repeat("c", 96*1024)
	request := livePostRequestForExpiry(t, credential.SecretKey, "bucket", "test.jpg", body, nil, nil, expiration)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { chain.ServeHTTP(response, request); close(done) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		releaseBarrier()
		<-done
		t.Fatal("encryption output was not consumed by ciphertext spool")
	}
	if acquisitions.Load() != 1 {
		releaseBarrier()
		<-done
		t.Fatalf("backend acquisition before completed plaintext validation=%d", acquisitions.Load())
	}
	manager := baseManager.(*spoolManager)
	if manager.CurrentBytes() == 0 {
		releaseBarrier()
		<-done
		t.Fatal("plaintext reservation was not held while ciphertext preparation began")
	}
	if delay := time.Until(expiration.Add(20 * time.Millisecond)); delay > 0 {
		select {
		case <-time.After(delay):
		case <-time.After(10 * time.Second):
			releaseBarrier()
			<-done
			t.Fatal("deadline wait timed out")
		}
	}
	releaseBarrier()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("handler did not return after ciphertext read was released")
	}
	if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "Request has expired.") || backend.putObjectCallCount != 0 || cacheSpy.deletes != 0 || cacheSpy.sets != 0 || sizeSpy.sets != 0 {
		t.Fatalf("status=%d puts=%d object-cache writes=%d size-cache writes=%d body=%s", response.Code, backend.putObjectCallCount, cacheSpy.sets, sizeSpy.sets, response.Body.String())
	}
	entry, ok := cacheSpy.Get(context.Background(), "bucket", "test.jpg")
	if !ok || string(entry.Data) != "cached pre-deadline" || entry.Metadata["owner"] != "cache-prior" {
		t.Fatalf("deadline changed cache entry: entry=%+v found=%t", entry, ok)
	}
	if manager.CurrentBytes() != 0 || managerWithGrowSpy.grew.Load() != 0 {
		t.Fatalf("plaintext/ciphertext quota=%d ciphertext quota grew after deadline=%d", manager.CurrentBytes(), managerWithGrowSpy.grew.Load())
	}
	entries, err := os.ReadDir(manager.tempDirectory())
	if err != nil || len(entries) != 0 {
		t.Fatalf("spool files=%v err=%v", entries, err)
	}
}

func TestGH353PostObject_DeadlineCancellationDuringPlaintextReadCleansSpool(t *testing.T) {
	backend := newMockS3Client()
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseBarrier := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseBarrier()
	h, chain := livePostChainForCredentialAndObserver(t, backend, nil, config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}, func(r *http.Request) {
		blockLivePostFileRead(r, entered, release, nil)
	})
	var acquisitions atomic.Int64
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions.Add(1); return backend, nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := livePostRequest(t, strings.Repeat("x", 64*1024), nil, nil).WithContext(ctx)
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { chain.ServeHTTP(response, request); close(done) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		releaseBarrier()
		<-done
		t.Fatal("live POST did not reach file read before cancellation")
	}
	cancel()
	releaseBarrier()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("live POST did not return after request cancellation")
	}
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "<Code>IncompleteBody</Code>") || acquisitions.Load() != 0 || backend.putObjectCallCount != 0 {
		t.Fatalf("status=%d acquisitions=%d puts=%d body=%s", response.Code, acquisitions.Load(), backend.putObjectCallCount, response.Body.String())
	}
	manager := h.spoolManager.(*spoolManager)
	entries, err := os.ReadDir(manager.tempDirectory())
	if err != nil || len(entries) != 0 || manager.CurrentBytes() != 0 {
		t.Fatalf("plaintext cleanup entries=%v quota=%d err=%v", entries, manager.CurrentBytes(), err)
	}
}

func TestGH353PostObject_AdvancedCapabilityRequired(t *testing.T) {
	backend := newMockS3Client()
	var acquisitions int
	h, chain := livePostChain(t, backend, nil)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions++; return backend, nil }
	engineLoads := 0
	h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) {
		engineLoads++
		if engineLoads > 1 {
			return nil, errors.New("engine changed after snapshot")
		}
		return h.encryptionEngine, nil
	}
	request := livePostRequest(t, "sse option", map[string]string{"x-amz-server-side-encryption": "AES256"}, []string{`{"x-amz-server-side-encryption":"AES256"}`})
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented || acquisitions != 1 || backend.putObjectCallCount != 0 || engineLoads != 0 {
		t.Fatalf("status=%d acquisitions=%d engine loads=%d puts=%d body=%s", response.Code, acquisitions, engineLoads, backend.putObjectCallCount, response.Body.String())
	}
}

func TestGH353PostObject_EngineSelectedOnceAfterCompleteValidation(t *testing.T) {
	backend := newMockS3Client()
	h, chain := livePostChain(t, backend, nil)
	var loads atomic.Int64
	first, err := newAPIUnitEngine([]byte("first engine"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := newAPIUnitEngine([]byte("second engine"))
	if err != nil {
		t.Fatal(err)
	}
	h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) {
		if loads.Add(1) == 1 {
			return first, nil
		}
		return second, nil
	}
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, livePostRequest(t, "engine snapshot", nil, nil))
	if response.Code != http.StatusNoContent || loads.Load() != 1 || backend.putObjectCallCount != 1 {
		t.Fatalf("status=%d engine loads=%d puts=%d body=%s", response.Code, loads.Load(), backend.putObjectCallCount, response.Body.String())
	}
}

type replaceLimitOnRead struct {
	io.ReadCloser
	source *SpoolLimitSource
	limits SpoolLimits
	done   bool
}

func (r *replaceLimitOnRead) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		r.source.Set(r.limits)
	}
	return r.ReadCloser.Read(p)
}

func TestGH353PostObject_LiveSpoolLimitSnapshot(t *testing.T) {
	backend := newMockS3Client()
	h, chain := livePostChain(t, backend, nil)
	h.spoolLimits.Set(SpoolLimits{Global: 8, Part: 8})
	request := livePostRequest(t, "sixteen-byte-file", nil, nil)
	request.Body = &replaceLimitOnRead{ReadCloser: request.Body, source: h.spoolLimits, limits: SpoolLimits{Global: 1024, Part: 1024}}
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge || backend.putObjectCallCount != 0 {
		t.Fatalf("active request status=%d puts=%d body=%s", response.Code, backend.putObjectCallCount, response.Body.String())
	}
	response = httptest.NewRecorder()
	chain.ServeHTTP(response, livePostRequest(t, "sixteen-byte-file", nil, nil))
	if response.Code != http.StatusNoContent || backend.putObjectCallCount != 1 {
		t.Fatalf("reloaded next request status=%d puts=%d body=%s", response.Code, backend.putObjectCallCount, response.Body.String())
	}
}

func TestGH353PostObject_ExpandedLiteralKeysAndFilenameVariants(t *testing.T) {
	for _, tc := range []struct {
		name, key, filename, expected string
	}{
		{"expanded filename with literal percent plus dots and unicode", "folder/%2F+../${filename}", `C:\fake\雪.txt`, "folder/%2F+../雪.txt"},
		{"no filename text file", "plain-key", "", "plain-key"},
		{"optional trailing slash", "literal/raw\\key", `raw\name.txt`, "literal/raw\\key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			_, chain := livePostChain(t, backend, nil)
			body := buildLivePostWithKey(t, tc.key, tc.filename, "literal file bytes")
			if tc.name == "optional trailing slash" {
				body.URL.Path = "/bucket/"
			}
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, body)
			if response.Code != http.StatusNoContent || backend.putObjectCallCount != 1 {
				t.Fatalf("status=%d puts=%d body=%s", response.Code, backend.putObjectCallCount, response.Body.String())
			}
			if _, ok := backend.objects["bucket/"+tc.expected]; !ok {
				t.Fatalf("literal expanded key not stored: %q keys=%v", tc.expected, backend.objects)
			}
		})
	}
}

func TestGH353PostObject_SuccessStatusesChecksumsAndStandardHeaders(t *testing.T) {
	file := []byte("POST checksum and headers ☃")
	md5sum := md5.Sum(file)
	sha256sum := sha256.Sum256(file)
	crc32sum := crc32.ChecksumIEEE(file)
	for _, tc := range []struct {
		name, checksumField, algorithm string
		status                         int
	}{
		{"MD5 200", "Content-MD5", "", http.StatusOK},
		{"CRC32 201", "x-amz-checksum-crc32", "CRC32", http.StatusCreated},
		{"CRC32C 204", "x-amz-checksum-crc32c", "CRC32C", http.StatusNoContent},
		{"SHA1 200", "x-amz-checksum-sha1", "SHA1", http.StatusOK},
		{"SHA256 204", "x-amz-checksum-sha256", "SHA256", http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			digest := ""
			switch tc.checksumField {
			case "Content-MD5":
				digest = base64.StdEncoding.EncodeToString(md5sum[:])
			case "x-amz-checksum-crc32":
				digest = base64.StdEncoding.EncodeToString([]byte{byte(crc32sum >> 24), byte(crc32sum >> 16), byte(crc32sum >> 8), byte(crc32sum)})
			case "x-amz-checksum-crc32c":
				crc32c := crc32.Checksum(file, crc32.MakeTable(crc32.Castagnoli))
				digest = base64.StdEncoding.EncodeToString([]byte{byte(crc32c >> 24), byte(crc32c >> 16), byte(crc32c >> 8), byte(crc32c)})
			case "x-amz-checksum-sha1":
				sha1sum := sha1.Sum(file)
				digest = base64.StdEncoding.EncodeToString(sha1sum[:])
			case "x-amz-checksum-sha256":
				digest = base64.StdEncoding.EncodeToString(sha256sum[:])
			}
			extra := map[string]string{"success_action_status": fmt.Sprint(tc.status), "Content-Type": "text/plain", "Content-Encoding": "identity", "Content-Disposition": "inline", "Cache-Control": "no-cache", "Content-Language": "en", "Expires": "Wed, 21 Oct 2030 07:28:00 GMT", "acl": "private", "tagging": `<Tagging><TagSet><Tag><Key>kind</Key><Value>snowman</Value></Tag></TagSet></Tagging>`}
			conditions := []string{fmt.Sprintf(`{"success_action_status":%q}`, fmt.Sprint(tc.status)), `{"Content-Type":"text/plain"}`, `{"Content-Encoding":"identity"}`, `{"Content-Disposition":"inline"}`, `{"Cache-Control":"no-cache"}`, `{"Content-Language":"en"}`, `{"Expires":"Wed, 21 Oct 2030 07:28:00 GMT"}`, `{"acl":"private"}`, fmt.Sprintf(`{"tagging":%q}`, extra["tagging"])}
			if tc.algorithm != "" {
				extra["x-amz-checksum-algorithm"] = tc.algorithm
				conditions = append(conditions, fmt.Sprintf(`{"x-amz-checksum-algorithm":%q}`, tc.algorithm))
			}
			extra[tc.checksumField] = digest
			conditions = append(conditions, fmt.Sprintf(`{%q:%q}`, tc.checksumField, digest))
			backend := newMockS3Client()
			_, chain := livePostChain(t, backend, nil)
			request := livePostRequest(t, string(file), extra, conditions)
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.status || backend.putObjectCallCount != 1 {
				t.Fatalf("status=%d want=%d puts=%d body=%s", response.Code, tc.status, backend.putObjectCallCount, response.Body.String())
			}
			meta := backend.metadata["bucket/test.jpg"]
			engine, err := newAPIUnitEngine([]byte("test encryption password"))
			if err != nil {
				t.Fatal(err)
			}
			reader, decrypted, err := engine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "test.jpg"}, bytes.NewReader(backend.objects["bucket/test.jpg"]), meta)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, reader)
			if decrypted["Content-Type"] != "text/plain" || decrypted["Content-Encoding"] != "identity" || decrypted["Content-Disposition"] != "inline" || decrypted["Cache-Control"] != "no-cache" || decrypted["Content-Language"] != "en" || decrypted["Expires"] == "" {
				t.Fatalf("standard headers lost: %v", decrypted)
			}
			if bytes.Contains(backend.objects["bucket/test.jpg"], file) {
				t.Fatal("plaintext checksum/input bytes persisted directly")
			}
		})
	}
}

func TestGH353PostObject_InvalidSuccessStatusFallsBackTo204(t *testing.T) {
	backend := newMockS3Client()
	_, chain := livePostChain(t, backend, nil)
	extra := map[string]string{"success_action_status": "303"}
	conditions := []string{`{"success_action_status":"303"}`}
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, livePostRequest(t, "fallback status", extra, conditions))
	if response.Code != http.StatusNoContent || backend.putObjectCallCount != 1 {
		t.Fatalf("status=%d puts=%d body=%s", response.Code, backend.putObjectCallCount, response.Body.String())
	}
}

type failPostBodyWriter struct {
	http.ResponseWriter
}

func (w failPostBodyWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestGH353PostObject_ResponseWriteFailureDoesNotWriteSecondError(t *testing.T) {
	backend := newMockS3Client()
	h, chain := livePostChain(t, backend, nil)
	manager := h.spoolManager.(*spoolManager)
	inner := httptest.NewRecorder()
	writer := failPostBodyWriter{ResponseWriter: inner}
	request := livePostRequest(t, "response body failure", map[string]string{"success_action_status": "201"}, []string{`{"success_action_status":"201"}`})
	chain.ServeHTTP(writer, request)
	if inner.Code != http.StatusCreated || backend.putObjectCallCount != 1 || strings.Contains(inner.Body.String(), "<Error>") || manager.CurrentBytes() != 0 {
		t.Fatalf("status=%d puts=%d spool=%d response=%s", inner.Code, backend.putObjectCallCount, manager.CurrentBytes(), inner.Body.String())
	}
}

func buildLivePostWithKey(t *testing.T, key, filename, file string) *http.Request {
	t.Helper()
	date := time.Now().UTC().Format("20060102T150405Z")
	scope := "AKIAIOSFODNN7EXAMPLE/" + date[:8] + "/us-east-1/s3/aws4_request"
	fields := map[string]string{"bucket": "bucket", "key": key, "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date}
	filenameBase := filename
	if index := strings.LastIndexAny(filenameBase, `/\`); index >= 0 {
		filenameBase = filenameBase[index+1:]
	}
	effectiveKey := strings.ReplaceAll(key, "${filename}", filenameBase)
	conditions := []string{`{"bucket":"bucket"}`, fmt.Sprintf(`{"key":%q}`, effectiveKey), `{"x-amz-algorithm":"AWS4-HMAC-SHA256"}`, fmt.Sprintf(`{"x-amz-credential":%q}`, scope), fmt.Sprintf(`{"x-amz-date":%q}`, date)}
	policy := fmt.Sprintf(`{"expiration":%q,"conditions":[%s]}`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), strings.Join(conditions, ","))
	fields["policy"] = base64.StdEncoding.EncodeToString([]byte(policy))
	fields["x-amz-signature"] = signPostPolicy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", date[:8], "us-east-1", fields["policy"])
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.SetBoundary("live-special-key")
	for name, value := range fields {
		part, err := writer.CreateFormField(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(part, value)
	}
	var filePart io.Writer
	var err error
	if filename == "" {
		filePart, err = writer.CreatePart(textproto.MIMEHeader{"Content-Disposition": {`form-data; name="file"`}})
	} else {
		filePart, err = writer.CreateFormFile("file", filename)
	}
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(filePart, file)
	_ = writer.Close()
	r := httptest.NewRequest(http.MethodPost, "http://gateway.test/bucket", bytes.NewReader(body.Bytes()))
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.ContentLength = int64(body.Len())
	return r
}

func TestGH353PostObject_ChecksumAndBackendFailurePreserveDestination(t *testing.T) {
	for _, tc := range []struct {
		name       string
		file       string
		digest     string
		backendErr error
		wantStatus int
	}{
		{name: "checksum mismatch", file: "changed body", digest: base64.StdEncoding.EncodeToString(make([]byte, md5.Size)), wantStatus: http.StatusBadRequest},
		{name: "backend failure", file: "backend rejected body", wantStatus: http.StatusInternalServerError, backendErr: errors.New("backend secret diagnostic")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			backend.objects["bucket/test.jpg"] = []byte("original ciphertext")
			backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "existing"}
			before := append([]byte(nil), backend.objects["bucket/test.jpg"]...)
			if tc.backendErr != nil {
				backend.errors = map[string]error{"bucket/test.jpg/put": tc.backendErr}
			}
			var acquisitions int
			h, chain := livePostChain(t, backend, nil)
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions++; return backend, nil }
			extra := map[string]string{}
			conditions := []string(nil)
			if tc.digest != "" {
				extra["Content-MD5"] = tc.digest
				conditions = append(conditions, fmt.Sprintf(`{"Content-MD5":%q}`, tc.digest))
			}
			request := livePostRequest(t, tc.file, extra, conditions)
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.wantStatus || !bytes.Equal(before, backend.objects["bucket/test.jpg"]) || backend.metadata["bucket/test.jpg"]["owner"] != "existing" {
				t.Fatalf("status=%d want=%d object=%q metadata=%v body=%s", response.Code, tc.wantStatus, backend.objects["bucket/test.jpg"], backend.metadata["bucket/test.jpg"], response.Body.String())
			}
			if tc.backendErr == nil && acquisitions != 0 {
				t.Fatalf("checksum failure acquired backend %d times", acquisitions)
			}
			if strings.Contains(response.Body.String(), "backend secret diagnostic") {
				t.Fatalf("backend diagnostic leaked: %s", response.Body.String())
			}
		})
	}
}

func TestGH353PostObject_RejectUnknownFieldOnlyAfterValidAuthentication(t *testing.T) {
	backend := newMockS3Client()
	_, chain := livePostChain(t, backend, nil)
	request := livePostRequest(t, "signed unsupported checksum", map[string]string{"x-amz-checksum-crc64nvme": "AAAAAA=="}, []string{`{"x-amz-checksum-crc64nvme":"AAAAAA=="}`})
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented || !strings.Contains(response.Body.String(), "<Code>NotImplemented</Code>") || backend.putObjectCallCount != 0 {
		t.Fatalf("status=%d puts=%d body=%s", response.Code, backend.putObjectCallCount, response.Body.String())
	}
}

type postCacheSpy struct {
	cache.Cache
	deletes int
	sets    int
}

func (c *postCacheSpy) Delete(context.Context, string, string) error { c.deletes++; return nil }
func (c *postCacheSpy) Set(context.Context, string, string, []byte, map[string]string, time.Duration) error {
	c.sets++
	return nil
}
func (c *postCacheSpy) SetEntry(context.Context, string, string, *cache.CacheEntry, time.Duration) error {
	c.sets++
	return nil
}

func TestGH353PostObject_PrevalidationFailuresPreserveObjectAndCache(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		extra      map[string]string
		conditions []string
		wantStatus int
	}{
		{"bad checksum", "replace", map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(make([]byte, md5.Size))}, nil, http.StatusBadRequest},
		{"below signed minimum", "short", nil, []string{`["content-length-range",6,100]`}, http.StatusBadRequest},
		{"signed unsupported checksum", "replace", map[string]string{"x-amz-checksum-crc64nvme": "AAAAAA=="}, []string{`{"x-amz-checksum-crc64nvme":"AAAAAA=="}`}, http.StatusNotImplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			backend.objects["bucket/test.jpg"] = []byte("previous-ciphertext")
			backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "prior"}
			before := append([]byte(nil), backend.objects["bucket/test.jpg"]...)
			h, chain := livePostChain(t, backend, nil)
			cacheSpy := &postCacheSpy{Cache: cache.NewMemoryCache(1024, 8, time.Minute)}
			h.cache = cacheSpy
			var engines, clients, puts atomic.Int64
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { engines.Add(1); return h.encryptionEngine, nil }
			backendSpy := &postPutCountingClient{mockS3Client: backend, puts: &puts}
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { clients.Add(1); return backendSpy, nil }
			conditions := append([]string(nil), tc.conditions...)
			if digest, ok := tc.extra["Content-MD5"]; ok {
				conditions = append(conditions, fmt.Sprintf(`{"Content-MD5":%q}`, digest))
			}
			request := livePostRequest(t, tc.file, tc.extra, conditions)
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.wantStatus || !bytes.Equal(before, backend.objects["bucket/test.jpg"]) || backend.metadata["bucket/test.jpg"]["owner"] != "prior" || clients.Load() != 0 || engines.Load() != 0 || puts.Load() != 0 || cacheSpy.deletes != 0 {
				t.Fatalf("status=%d want=%d clients=%d engines=%d puts=%d cache deletes=%d body=%s", response.Code, tc.wantStatus, clients.Load(), engines.Load(), puts.Load(), cacheSpy.deletes, response.Body.String())
			}
			entries, err := os.ReadDir(h.spoolManager.(*spoolManager).tempDirectory())
			if err != nil || len(entries) != 0 || h.spoolManager.(*spoolManager).CurrentBytes() != 0 {
				t.Fatalf("plaintext spool cleanup entries=%v quota=%d err=%v", entries, h.spoolManager.(*spoolManager).CurrentBytes(), err)
			}
		})
	}
}

type postPutCountingClient struct {
	*mockS3Client
	puts *atomic.Int64
}

func (c *postPutCountingClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *s3.ObjectLockInput, acl, full, read, readACP, writeACP string) (string, error) {
	c.puts.Add(1)
	return c.mockS3Client.PutObject(ctx, bucket, key, reader, metadata, contentLength, tags, lock, acl, full, read, readACP, writeACP)
}

func TestGH353PostObject_RedirectAndRequestHost(t *testing.T) {
	backend := newMockS3Client()
	h, chain := livePostChain(t, backend, nil)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
	redirectRequests := atomic.Int64{}
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectRequests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer redirectServer.Close()
	redirect := redirectServer.URL + "/landing?keep=one&key=old#section"
	request := livePostRequest(t, "redirect payload", map[string]string{"success_action_redirect": redirect}, []string{fmt.Sprintf(`{"success_action_redirect":%q}`, redirect)})
	request.Host = "canonical.gateway.example"
	request.Header.Set("X-Forwarded-Host", "spoof.invalid")
	request.URL.Scheme = "http"
	request.URL.Host = request.Host
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || response.Code != http.StatusSeeOther || location.Host == "" || location.Query().Get("keep") != "one" || location.Query().Get("key") != "test.jpg" || location.Fragment != "section" {
		t.Fatalf("status=%d location=%q err=%v body=%s", response.Code, response.Header().Get("Location"), err, response.Body.String())
	}
	if redirectRequests.Load() != 0 {
		t.Fatalf("redirect target unexpectedly fetched %d times", redirectRequests.Load())
	}
	// On the ordinary 201 response, Location is formed from the request's
	// authoritative Host and never from X-Forwarded-Host.
	plainRequest := livePostRequest(t, "host response", map[string]string{"success_action_status": "201"}, []string{`{"success_action_status":"201"}`})
	plainRequest.Host = "canonical.gateway.example"
	plainRequest.Header.Set("X-Forwarded-Host", "spoof.invalid")
	plainRequest.URL.Scheme = "http"
	plainRequest.URL.Host = plainRequest.Host
	plainResponse := httptest.NewRecorder()
	chain.ServeHTTP(plainResponse, plainRequest)
	var success postResponse
	if err := xml.Unmarshal(plainResponse.Body.Bytes(), &success); err != nil || !strings.Contains(success.Location, "canonical.gateway.example") || strings.Contains(success.Location, "spoof.invalid") {
		t.Fatalf("status=%d Location=%q err=%v", plainResponse.Code, success.Location, err)
	}
}

func TestGH353PostObject_InvalidHostBeforeBackend(t *testing.T) {
	backend := newMockS3Client()
	h, chain := livePostChain(t, backend, nil)
	var acquisitions int
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions++; return backend, nil }
	request := livePostRequest(t, "host rejection", nil, nil)
	request.Host = "untrusted host"
	response := httptest.NewRecorder()
	chain.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || acquisitions != 0 || backend.putObjectCallCount != 0 {
		t.Fatalf("status=%d acquisitions=%d puts=%d body=%s", response.Code, acquisitions, backend.putObjectCallCount, response.Body.String())
	}
}

func TestGH353PostObject_GatewayCORS(t *testing.T) {
	for _, tc := range []struct {
		name, origin, status, checksum string
		wantCode                       int
		allowed                        bool
	}{
		{"allowed 200", "https://app.example", "200", "", http.StatusOK, true},
		{"allowed 201 checksum", "https://app.example", "201", "x-amz-checksum-sha256", http.StatusCreated, true},
		{"allowed 204", "https://app.example", "204", "", http.StatusNoContent, true},
		{"allowed redirect 303", "https://app.example", "", "", http.StatusSeeOther, true},
		{"denied origin still writes", "https://denied.example", "201", "", http.StatusCreated, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			registry := prometheus.NewRegistry()
			advanced := &gh353AdvancedPutClient{mockS3Client: backend, responseETag: `"cors-etag"`, responseHeaders: map[string]string{"x-amz-server-side-encryption": "AES256"}}
			h, apiChain := livePostChain(t, advanced, registry)
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { return advanced, nil }
			corsStore := &postMemoryCORSStore{configs: map[string]*CORSConfiguration{
				"bucket": {Rules: []CORSRule{{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"}, AllowedHeaders: []string{"content-type"}, ExposeHeaders: []string{"ETag", "x-amz-version-id", "x-amz-checksum-sha256", "x-amz-server-side-encryption"}}}},
			}}
			chain := liveGatewayCORSPostChain(t, h, apiChain, corsStore, logrus.New())
			extra := map[string]string(nil)
			conditions := []string(nil)
			if tc.status != "" {
				extra = map[string]string{"success_action_status": tc.status}
				conditions = []string{fmt.Sprintf(`{"success_action_status":%q}`, tc.status)}
			}
			if tc.checksum != "" {
				file := "cors upload"
				sum := sha256.Sum256([]byte(file))
				digest := base64.StdEncoding.EncodeToString(sum[:])
				extra[tc.checksum] = digest
				extra["x-amz-checksum-algorithm"] = "SHA256"
				conditions = append(conditions, fmt.Sprintf(`{%q:%q}`, tc.checksum, digest), `{"x-amz-checksum-algorithm":"SHA256"}`)
			}
			if tc.wantCode == http.StatusSeeOther {
				extra = map[string]string{"success_action_redirect": "https://app.example/complete"}
				conditions = []string{`{"success_action_redirect":"https://app.example/complete"}`}
			}
			request := livePostRequest(t, "cors upload", extra, conditions)
			request.Header.Set("Origin", tc.origin)
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.wantCode || backend.putObjectCallCount != 1 {
				t.Fatalf("status=%d want=%d puts=%d body=%s", response.Code, tc.wantCode, backend.putObjectCallCount, response.Body.String())
			}
			allowOrigin := response.Header().Get("Access-Control-Allow-Origin")
			if tc.allowed {
				if allowOrigin != tc.origin || !strings.Contains(response.Header().Get("Vary"), "Origin") {
					t.Fatalf("allowed response CORS origin=%q vary=%q", allowOrigin, response.Header().Get("Vary"))
				}
				for _, exposed := range []string{"ETag", "x-amz-version-id", "x-amz-server-side-encryption"} {
					if !strings.Contains(strings.ToLower(response.Header().Get("Access-Control-Expose-Headers")), strings.ToLower(exposed)) {
						t.Errorf("exposed headers=%q missing %q", response.Header().Get("Access-Control-Expose-Headers"), exposed)
					}
				}
				if response.Header().Get("ETag") == "" || response.Header().Get("x-amz-version-id") != "version-1" || response.Header().Get("x-amz-server-side-encryption") != "AES256" {
					t.Fatalf("response headers did not exercise ETag/version/SSE projection: %v", response.Header())
				}
				if tc.checksum != "" && response.Header().Get("x-amz-checksum-sha256") == "" {
					t.Fatalf("checksum response header missing: %v", response.Header())
				}
			} else if allowOrigin != "" || response.Header().Get("Access-Control-Expose-Headers") != "" {
				t.Fatalf("denied-origin successful write exposed response headers: %v", response.Header())
			}
			if metricSample(t, registry, "s3_client_bytes_total", `bucket="bucket"`, `direction="in"`) != float64(len("cors upload")) {
				t.Fatal("CORS decision changed POST file-byte accounting")
			}
		})
	}
}

func TestGH353PostObject_GatewayCORSFailureResponse(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		store                       CORSStore
		badChecksum, backendFailure bool
		wantStatus                  int
		wantCORS                    bool
		storeUnavailable            bool
	}{
		{name: "signed option error", store: &postMemoryCORSStore{configs: map[string]*CORSConfiguration{"bucket": {Rules: []CORSRule{{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"}}}}}}, wantStatus: http.StatusNotImplemented, wantCORS: true},
		{name: "bad signed checksum", store: &postMemoryCORSStore{configs: map[string]*CORSConfiguration{"bucket": {Rules: []CORSRule{{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"}}}}}}, badChecksum: true, wantStatus: http.StatusBadRequest, wantCORS: true},
		{name: "missing session token", store: &postMemoryCORSStore{configs: map[string]*CORSConfiguration{"bucket": {Rules: []CORSRule{{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"}}}}}}, wantStatus: http.StatusForbidden, wantCORS: true},
		{name: "wrong session token", store: &postMemoryCORSStore{configs: map[string]*CORSConfiguration{"bucket": {Rules: []CORSRule{{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"}}}}}}, wantStatus: http.StatusForbidden, wantCORS: true},
		{name: "backend 500 remains readable", store: &postMemoryCORSStore{configs: map[string]*CORSConfiguration{"bucket": {Rules: []CORSRule{{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"}}}}}}, backendFailure: true, wantStatus: http.StatusInternalServerError, wantCORS: true},
		{name: "store unavailable executes write but suppresses grant", store: &postErrorCORSStore{err: ErrCORSUnavailable}, wantStatus: http.StatusNoContent, wantCORS: false, storeUnavailable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			h, apiChain := livePostChain(t, backend, nil)
			var sessionCredential *config.GatewayCredential
			if tc.name == "missing session token" || tc.name == "wrong session token" {
				credential := config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", SessionToken: "valid-cors-session-token", ExpiresAt: postTimePtr(time.Now().UTC().Add(time.Hour)), Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}
				sessionCredential = &credential
				h, apiChain = livePostChainForCredential(t, backend, nil, credential)
			}
			var acquisitions int
			h.clientAcquirer = func(*http.Request) (s3.Client, error) {
				acquisitions++
				if tc.backendFailure {
					backend.errors["bucket/test.jpg/put"] = &s3Error{code: "InternalError", message: "private backend diagnostic"}
				}
				return backend, nil
			}
			chain := liveGatewayCORSPostChain(t, h, apiChain, tc.store, logrus.New())
			extra := map[string]string{"success_action_status": "204"}
			conditions := []string{`{"success_action_status":"204"}`}
			if tc.badChecksum {
				bad := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x7a}, 32))
				extra = map[string]string{"x-amz-checksum-sha256": bad, "x-amz-checksum-algorithm": "SHA256", "success_action_status": "204"}
				conditions = []string{fmt.Sprintf(`{"x-amz-checksum-sha256":%q}`, bad), `{"x-amz-checksum-algorithm":"SHA256"}`, `{"success_action_status":"204"}`}
			}
			if tc.name == "signed option error" {
				extra["unknown-option"] = "private-marker"
				conditions = append(conditions, `{"unknown-option":"private-marker"}`)
			}
			request := livePostRequest(t, "cors rejection", extra, conditions)
			if sessionCredential != nil {
				if tc.name == "wrong session token" {
					extra["x-amz-security-token"] = "wrong-cors-session-token"
				}
				request = livePostRequestFor(t, sessionCredential.SecretKey, "bucket", "test.jpg", "cors rejection", extra, append(conditions, fmt.Sprintf(`{"x-amz-security-token":%q}`, extra["x-amz-security-token"])))
				if tc.name == "missing session token" {
					request = livePostRequest(t, "cors rejection", map[string]string{"success_action_status": "204"}, []string{`{"success_action_status":"204"}`})
				}
			}
			request.Header.Set("Origin", "https://app.example")
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tc.wantStatus, response.Body.String())
			}
			if (response.Header().Get("Access-Control-Allow-Origin") == "https://app.example") != tc.wantCORS {
				t.Fatalf("status=%d CORS headers=%v wantReadable=%t", response.Code, response.Header(), tc.wantCORS)
			}
			if tc.wantCORS && response.Header().Get("Vary") != "Origin" {
				t.Fatalf("Vary=%q want exact Origin", response.Header().Get("Vary"))
			}
			wantPuts := 0
			if tc.backendFailure || tc.storeUnavailable {
				wantPuts = 1
			}
			if backend.putObjectCallCount != wantPuts {
				t.Fatalf("backend writes=%d want=%d acquisitions=%d", backend.putObjectCallCount, wantPuts, acquisitions)
			}
			if strings.Contains(response.Body.String(), "private-marker") || strings.Contains(response.Body.String(), "private backend diagnostic") {
				t.Fatalf("form/backend diagnostic leaked: %s", response.Body.String())
			}
			if tc.name == "missing session token" && (!strings.Contains(response.Body.String(), "<Code>InvalidToken</Code>") || acquisitions != 0) {
				t.Fatalf("missing session token classification/acquisition=%d body=%s", acquisitions, response.Body.String())
			}
			if tc.name == "wrong session token" && (!strings.Contains(response.Body.String(), "<Code>InvalidToken</Code>") || acquisitions != 0) {
				t.Fatalf("wrong session token classification/acquisition=%d body=%s", acquisitions, response.Body.String())
			}
		})
	}
}

func TestGH353PostObject_GatewayCORSPreflightRealRoute(t *testing.T) {
	backend := newMockS3Client()
	h, router := livePostChain(t, backend, prometheus.NewRegistry())
	h.metrics = nil
	store := &postMemoryCORSStore{configs: map[string]*CORSConfiguration{
		"bucket": {Rules: []CORSRule{{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"}, AllowedHeaders: []string{"content-type", "x-amz-server-side-encryption-customer-algorithm", "x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-md5"}, ExposeHeaders: []string{"ETag"}}}},
	}}
	chain := liveGatewayCORSPostChain(t, h, router, store, logrus.New())
	for _, tc := range []struct {
		name, origin string
		wantStatus   int
		wantAllowed  bool
	}{
		{"permitted requested headers", "https://app.example", http.StatusOK, true},
		{"denied origin", "https://denied.example", http.StatusForbidden, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, "/bucket", nil)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Access-Control-Request-Method", "POST")
			request.Header.Set("Access-Control-Request-Headers", "content-type,x-amz-server-side-encryption-customer-key")
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.wantStatus || backend.putObjectCallCount != 0 {
				t.Fatalf("status=%d want=%d writes=%d body=%s", response.Code, tc.wantStatus, backend.putObjectCallCount, response.Body.String())
			}
			if tc.wantAllowed {
				if response.Header().Get("Access-Control-Allow-Origin") != tc.origin || response.Header().Get("Access-Control-Allow-Methods") != "POST" || !strings.Contains(strings.ToLower(response.Header().Get("Access-Control-Allow-Headers")), "x-amz-server-side-encryption-customer-key") {
					t.Fatalf("permitted preflight headers=%v", response.Header())
				}
			} else if response.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("denied preflight gained CORS permission: %v", response.Header())
			}
		})
	}
}

func liveGatewayCORSPostChain(t *testing.T, h *Handler, router http.Handler, store CORSStore, logger *logrus.Logger) http.Handler {
	t.Helper()
	h.config = &config.Config{CORS: config.CORSConfig{Mode: "gateway"}}
	h.WithCORSStore(store)
	return CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logger)(router)
}

func postTimePtr(value time.Time) *time.Time { return &value }

type postMemoryCORSStore struct{ configs map[string]*CORSConfiguration }

type postErrorCORSStore struct {
	postMemoryCORSStore
	err error
}

func (s *postMemoryCORSStore) Get(_ context.Context, bucket string) (*CORSConfiguration, error) {
	value := s.configs[bucket]
	if value == nil {
		return nil, ErrCORSNotFound
	}
	return value, nil
}
func (s *postErrorCORSStore) Get(context.Context, string) (*CORSConfiguration, error) {
	return nil, s.err
}
func (*postMemoryCORSStore) Put(context.Context, string, *CORSConfiguration) error { return nil }
func (*postMemoryCORSStore) Delete(context.Context, string) error                  { return nil }
func (*postMemoryCORSStore) HealthCheck(context.Context) error                     { return nil }
func (*postErrorCORSStore) Put(context.Context, string, *CORSConfiguration) error  { return nil }
func (*postErrorCORSStore) Delete(context.Context, string) error                   { return nil }
func (*postErrorCORSStore) HealthCheck(context.Context) error                      { return nil }
