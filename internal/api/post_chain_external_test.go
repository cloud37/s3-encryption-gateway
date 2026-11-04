package api_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
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

const (
	chainAccessKey = "AKIAIOSFODNN7EXAMPLE"
	chainSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

type chainCORSStore struct{ value *api.CORSConfiguration }

func (s *chainCORSStore) Get(context.Context, string) (*api.CORSConfiguration, error) {
	return s.value, nil
}
func (*chainCORSStore) Put(context.Context, string, *api.CORSConfiguration) error { return nil }
func (*chainCORSStore) Delete(context.Context, string) error                      { return nil }
func (*chainCORSStore) HealthCheck(context.Context) error                         { return nil }

type chainBackend struct {
	s3.Client
	puts int
	err  error
}

func (b *chainBackend) PutObject(_ context.Context, _, _ string, body io.Reader, _ map[string]string, _ *int64, _ string, _ *s3.ObjectLockInput, _, _, _, _, _ string) (string, error) {
	b.puts++
	if _, err := io.Copy(io.Discard, body); err != nil {
		return "", err
	}
	return `"backend-etag"`, b.err
}

func TestGH353PostObject_FullProductionMiddlewareChain(t *testing.T) {
	for _, tc := range []struct {
		name, status, origin                   string
		badSignature, mismatch, backendFailure bool
		preflight                              bool
		wantStatus                             int
		wantWrites                             int
		wantCORS                               bool
		wantCode                               string
	}{
		{name: "accepted 200", status: "200", origin: "https://app.example", wantStatus: http.StatusOK, wantWrites: 1, wantCORS: true},
		{name: "accepted 201", status: "201", origin: "https://app.example", wantStatus: http.StatusCreated, wantWrites: 1, wantCORS: true},
		{name: "accepted 204", status: "204", origin: "https://app.example", wantStatus: http.StatusNoContent, wantWrites: 1, wantCORS: true},
		{name: "accepted 303", origin: "https://app.example", wantStatus: http.StatusSeeOther, wantWrites: 1, wantCORS: true},
		{name: "signature failure reaches readable CORS", status: "204", origin: "https://app.example", badSignature: true, wantStatus: http.StatusForbidden, wantCORS: true, wantCode: "SignatureDoesNotMatch"},
		{name: "signed policy mismatch reaches readable CORS", status: "204", origin: "https://app.example", mismatch: true, wantStatus: http.StatusForbidden, wantCORS: true, wantCode: "AccessDenied"},
		{name: "denied origin upload still succeeds", status: "204", origin: "https://evil.example", wantStatus: http.StatusNoContent, wantWrites: 1},
		{name: "backend error reaches readable CORS", status: "204", origin: "https://app.example", backendFailure: true, wantStatus: http.StatusInternalServerError, wantWrites: 1, wantCORS: true},
		{name: "permitted unauthenticated preflight", origin: "https://app.example", preflight: true, wantStatus: http.StatusOK, wantCORS: true},
		{name: "denied unauthenticated preflight", origin: "https://evil.example", preflight: true, wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &chainBackend{}
			if tc.backendFailure {
				backend.err = fmt.Errorf("injected backend failure")
			}
			engine, err := crypto.NewEngine([]byte("test encryption password"))
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{CORS: config.CORSConfig{Mode: "gateway"}}
			h := api.NewHandlerWithFeatures(backend, engine, logrus.New(), nil, nil, nil, nil, cfg, nil)
			spoolManager := api.NewSpoolManager(8<<20, t.TempDir())
			spoolLimits := api.NewSpoolLimitSource(api.SpoolLimits{Global: 2 << 20, Part: 1 << 20})
			h.WithSpoolManager(spoolManager).WithSpoolLimitSource(spoolLimits)
			corsStore := &chainCORSStore{value: &api.CORSConfiguration{Rules: []api.CORSRule{{
				AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"},
				AllowedHeaders: []string{"content-type"},
				ExposeHeaders:  []string{"ETag", "x-amz-version-id", "x-amz-server-side-encryption"},
			}}}}
			h.WithCORSStore(corsStore)
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			credentials, err := api.NewStaticCredentialStore([]config.GatewayCredential{{
				AccessKey: chainAccessKey, SecretKey: func() string {
					if tc.badSignature {
						return "different-secret"
					}
					return chainSecretKey
				}(), Buckets: []string{"bucket"},
				Permissions: chainPermission(config.ObjectPermissionReadWrite),
			}})
			if err != nil {
				t.Fatal(err)
			}
			logger := logrus.New()
			var chain http.Handler = router
			chain = api.AuthorizationMiddleware("", nil)(chain)
			chain = api.AuthMiddleware(credentials, time.Minute, logger, nil, false, spoolManager, spoolLimits)(chain)
			chain = api.CORSMiddleware(cfg.CORS, corsStore, logger)(chain)
			chain = middleware.RecoveryMiddleware(logger)(chain)

			var request *http.Request
			if tc.preflight {
				request = httptest.NewRequest(http.MethodOptions, "/bucket", nil)
				request.Header.Set("Access-Control-Request-Method", "POST")
				request.Header.Set("Access-Control-Request-Headers", "content-type")
			} else {
				request = signedChainPost(t, tc.status)
				if tc.mismatch {
					request = signedChainPostWithBucket(t, tc.status, "other-bucket")
				}
			}
			request.Header.Set("Origin", tc.origin)
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.wantStatus || backend.puts != tc.wantWrites {
				t.Fatalf("status=%d want=%d backend puts=%d want=%d body=%s", response.Code, tc.wantStatus, backend.puts, tc.wantWrites, response.Body.String())
			}
			if tc.wantCode != "" && !strings.Contains(response.Body.String(), "<Code>"+tc.wantCode+"</Code>") {
				t.Fatalf("S3 error code body=%s want=%s", response.Body.String(), tc.wantCode)
			}
			if (response.Header().Get("Access-Control-Allow-Origin") == tc.origin) != tc.wantCORS {
				t.Fatalf("CORS grant=%q want=%t headers=%v", response.Header().Get("Access-Control-Allow-Origin"), tc.wantCORS, response.Header())
			}
			if tc.wantWrites > 0 && response.Header().Get("Access-Control-Expose-Headers") != "" && !tc.wantCORS {
				t.Fatalf("denied origin received exposed headers: %v", response.Header())
			}
			if tc.wantCORS && !strings.Contains(response.Header().Get("Vary"), "Origin") {
				t.Fatalf("missing Origin Vary: %v", response.Header())
			}
		})
	}
}

func signedChainPost(t *testing.T, status string) *http.Request {
	return signedChainPostWithBucket(t, status, "bucket")
}

func signedChainPostWithBucket(t *testing.T, status, bucket string) *http.Request {
	t.Helper()
	date := time.Now().UTC().Format("20060102T150405Z")
	day := date[:8]
	scope := chainAccessKey + "/" + day + "/us-east-1/s3/aws4_request"
	fields := map[string]string{"bucket": bucket, "key": "object", "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date}
	conditions := []string{fmt.Sprintf(`{"bucket":%q}`, bucket), `{"key":"object"}`, `{"x-amz-algorithm":"AWS4-HMAC-SHA256"}`, fmt.Sprintf(`{"x-amz-credential":%q}`, scope), fmt.Sprintf(`{"x-amz-date":%q}`, date)}
	if status != "" {
		fields["success_action_status"] = status
		conditions = append(conditions, fmt.Sprintf(`{"success_action_status":%q}`, status))
	} else {
		fields["success_action_redirect"] = "https://app.example/uploaded"
		conditions = append(conditions, `{"success_action_redirect":"https://app.example/uploaded"}`)
	}
	expires := time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano)
	policy := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"expiration":%q,"conditions":[%s]}`, expires, strings.Join(conditions, ","))))
	fields["policy"] = policy
	fields["x-amz-signature"] = chainSignPolicy(policy, day)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range fields {
		part, err := writer.CreateFormField(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("file", "object")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "signed post payload"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://gateway.example/bucket", bytes.NewReader(body.Bytes()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	return request
}

func chainSignPolicy(policy, date string) string {
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = io.WriteString(h, value)
		return h.Sum(nil)
	}
	dateKey := mac([]byte("AWS4"+chainSecretKey), date)
	regionKey := mac(dateKey, "us-east-1")
	serviceKey := mac(regionKey, "s3")
	return hex.EncodeToString(mac(mac(serviceKey, "aws4_request"), policy))
}

func chainPermission(permission config.ObjectPermission) *config.ObjectPermission { return &permission }
