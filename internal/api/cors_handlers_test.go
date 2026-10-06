package api

import (
	"context"
	"crypto/md5" // #nosec G401 -- validates S3 Content-MD5 compatibility
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	awstypes "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func newCORSTestHandler(t *testing.T) (*Handler, *mockS3Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	backend := newMockS3Client()
	cfg := &config.Config{CORS: config.CORSConfig{Mode: "gateway"}}
	h := NewHandlerWithFeatures(backend, nil, logrus.New(), getTestMetrics(), nil, nil, nil, cfg, nil).WithCORSStore(NewValkeyCORSStore(client))
	return h, backend, mr
}

func corsRequest(method, path string, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	return mux.SetURLVars(r, map[string]string{"bucket": "bucket", "key": "object"})
}

func corsRuleStore(t *testing.T, h *Handler, xmlBody string) {
	t.Helper()
	cfg, err := parseCORSXML([]byte(xmlBody))
	require.NoError(t, err)
	require.NoError(t, h.corsStore.Put(context.Background(), "bucket", cfg))
}

func TestBucketCORS_ManageGrantAndReadOnly(t *testing.T) {
	for _, tc := range []struct {
		method string
		grant  config.BucketPermission
		want   int
	}{
		{http.MethodGet, "", http.StatusOK},
		{http.MethodPut, config.BucketPermissionManage, http.StatusOK},
		{http.MethodPut, "", http.StatusForbidden},
		{http.MethodDelete, config.BucketPermissionManage, http.StatusOK},
		{http.MethodDelete, "", http.StatusForbidden},
	} {
		credential := Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadOnly}}
		if tc.grant != "" {
			credential.Policy.BucketPermissions = []config.BucketPermission{tc.grant}
		}
		called := false
		router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) })
		rec := httptest.NewRecorder()
		AuthorizationMiddleware("", nil)(router).ServeHTTP(rec, authorizedRequest(tc.method, "/bucket?cors", credential))
		require.Equal(t, tc.want, rec.Code)
		require.Equal(t, tc.want == http.StatusOK, called)
	}
}

func TestBucketCORS_ManagementRequiresBucketExistence(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	metricsRegistry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(metricsRegistry)
	backend.errors["bucket/list"] = &mockAPIError{code: "NoSuchBucket", message: "missing"}
	w := httptest.NewRecorder()
	h.handleGetBucketCors(w, corsRequest(http.MethodGet, "/bucket?cors", ""))
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "NoSuchBucket")
	_, err := h.corsStore.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSNotFound)
}

func TestBucketCORS_ManagementProbeUnavailableReturns503(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return nil, ErrBackendNotConfigured }
	w := httptest.NewRecorder()
	h.handleGetBucketCors(w, corsRequest(http.MethodGet, "/bucket?cors", ""))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestBucketCORS_OnlyNoSuchBucketAllowsCreateCleanup(t *testing.T) {
	for _, code := range []string{"AccessDenied", "SlowDown", "Unknown"} {
		t.Run(code, func(t *testing.T) {
			h, backend, mr := newCORSTestHandler(t)
			corsRuleStore(t, h, corsTestXML)
			corsRuleStore(t, h, corsTestXML)
			backend.errors["bucket/list"] = &mockAPIError{code: code, message: "probe ambiguous"}
			h.SetAllowBucketCreation(true)
			h.config.Backend.Endpoint = "http://backend.example"
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
			forwarded := false
			h.proxyTransport = corsRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				forwarded = true
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
			})
			r := corsRequest(http.MethodPut, "/bucket", "")
			r = r.WithContext(context.WithValue(r.Context(), credentialKey, Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}))
			w := httptest.NewRecorder()
			h.handleCreateBucket(w, r)
			require.Equal(t, http.StatusServiceUnavailable, w.Code)
			require.False(t, forwarded)
			require.True(t, mr.Exists(corsKey("bucket")))
			got, getErr := h.corsStore.Get(context.Background(), "bucket")
			require.NoError(t, getErr)
			require.Equal(t, "web", got.Rules[0].ID)
		})
	}
}

func TestBucketCORS_InvalidBucketNeverReadsValkey(t *testing.T) {
	h, _, mr := newCORSTestHandler(t)
	// A directly routed malformed bucket name must not access or create policy.
	r := httptest.NewRequest(http.MethodOptions, "/bad/bucket", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	h.handleGatewayCORSPreflight(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.False(t, mr.Exists(corsKey("bad")))
}

func TestAuthMiddleware_GatewayCORSPreflightStillRejectsPartialAuth(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	called := false
	h := AuthMiddleware(testCredentialStore(), 0, logger, nil, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	r := httptest.NewRequest(http.MethodOptions, "/bucket", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	r.URL.RawQuery = "X-Amz-Signature=partial"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	require.False(t, called)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuthorizationMiddleware_GatewayCORSScopesAndManagement(t *testing.T) {
	tests := []struct {
		method, path string
		grant        []config.BucketPermission
		scope, proxy string
		want         bool
	}{
		{http.MethodGet, "/bucket?cors", nil, "bucket", "", true},
		{http.MethodPut, "/bucket?cors", []config.BucketPermission{config.BucketPermissionManage}, "bucket", "", true},
		{http.MethodDelete, "/bucket?cors", []config.BucketPermission{config.BucketPermissionManage}, "bucket", "", true},
		{http.MethodPut, "/bucket?cors", nil, "bucket", "", false},
		{http.MethodGet, "/bucket?cors", nil, "other", "", false},
		{http.MethodOptions, "/bucket", nil, "bucket", "other", false},
	}
	for _, tc := range tests {
		cred := Credential{Policy: AuthorizationPolicy{Buckets: []string{tc.scope}, Permissions: config.ObjectPermissionReadOnly, BucketPermissions: tc.grant}}
		r := authorizedRequest(tc.method, tc.path, cred)
		if tc.method == http.MethodOptions {
			r.Header.Set("Origin", "https://app.example.com")
			r.Header.Set("Access-Control-Request-Method", "GET")
			r.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
			resignV4Request(t, r, "UNSIGNED-PAYLOAD")
		}
		called := false
		w := httptest.NewRecorder()
		terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(http.StatusOK) })
		var chain http.Handler = AuthorizationMiddleware(tc.proxy, nil)(terminal)
		if tc.method == http.MethodOptions {
			chain = AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(chain)
		}
		if tc.method == http.MethodOptions {
			chain.ServeHTTP(w, r)
		} else {
			AuthorizationMiddleware(tc.proxy, nil)(terminal).ServeHTTP(w, r)
		}
		require.Equal(t, tc.want, called, "%s %s", tc.method, tc.path)
	}
}

func TestBucketCORS_ManagementRoundTripAndDelete(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	body := corsTestXML
	put := corsRequest(http.MethodPut, "/bucket?cors", body)
	w := httptest.NewRecorder()
	h.handlePutBucketCors(w, put)
	require.Equal(t, http.StatusOK, w.Code)
	get := corsRequest(http.MethodGet, "/bucket?cors", "")
	w = httptest.NewRecorder()
	h.handleGetBucketCors(w, get)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "application/xml", w.Header().Get("Content-Type"))
	require.Contains(t, w.Body.String(), corsXMLNamespace)
	del := corsRequest(http.MethodDelete, "/bucket?cors", "")
	w = httptest.NewRecorder()
	h.handleDeleteBucketCors(w, del)
	require.Equal(t, http.StatusNoContent, w.Code)
	w = httptest.NewRecorder()
	h.handleGetBucketCors(w, get)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "NoSuchCORSConfiguration")
}

func TestBucketCORS_PublicPutRejectsMalformedAuthorityAndPreservesPolicy(t *testing.T) {
	h, _, mr := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	publicRoute := AuthorizationMiddleware("", nil)(router)

	for _, tc := range []struct{ name, xmlOrigin string }{
		{"closing bracket", "https://host]"},
		{"quote", `https://ho"st`},
		{"less-than", "https://ho&lt;st"},
		{"greater-than", "https://ho&gt;st"},
		{"empty hostname", "https://:8443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `<CORSConfiguration><CORSRule><AllowedOrigin>` + tc.xmlOrigin + `</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`
			r := httptest.NewRequest(http.MethodPut, "/bucket?cors", strings.NewReader(body))
			r = r.WithContext(context.WithValue(r.Context(), credentialKey, Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionManage}}}))
			w := httptest.NewRecorder()
			publicRoute.ServeHTTP(w, r)
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, w.Body.String(), "<Code>MalformedXML</Code>")
			require.True(t, mr.Exists(corsKey("bucket")))
			stored, err := h.corsStore.Get(context.Background(), "bucket")
			require.NoError(t, err)
			require.Equal(t, []string{"https://app.example.com"}, stored.Rules[0].AllowedOrigins)
		})
	}
}

func TestBucketCORS_BadDigestAndOversizePreserveOldRule(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	bad := corsRequest(http.MethodPut, "/bucket?cors", corsTestXML)
	wrongDigest := md5.Sum([]byte("different body"))
	bad.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(wrongDigest[:]))
	w := httptest.NewRecorder()
	h.handlePutBucketCors(w, bad)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "BadDigest")
	tooLarge := corsRequest(http.MethodPut, "/bucket?cors", strings.Repeat("x", maxCORSXMLBytes+1))
	w = httptest.NewRecorder()
	h.handlePutBucketCors(w, tooLarge)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	stored, err := h.corsStore.Get(context.Background(), "bucket")
	require.NoError(t, err)
	require.Equal(t, "web", stored.Rules[0].ID)
}

func TestBucketCORS_NoSuchBucketAndStoreFailure(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	backend.errors["bucket/list"] = &mockAPIError{code: "NoSuchBucket", message: "missing"}
	w := httptest.NewRecorder()
	h.handlePutBucketCors(w, corsRequest(http.MethodPut, "/bucket?cors", corsTestXML))
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Contains(t, w.Body.String(), "NoSuchBucket")
	delete(backend.errors, "bucket/list")
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer client.Close()
	h.corsStore = NewValkeyCORSStore(client)
	w = httptest.NewRecorder()
	h.handlePutBucketCors(w, corsRequest(http.MethodPut, "/bucket?cors", corsTestXML))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCORSPreflight_NoBackendRequestAndFirstMatch(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	backendCalls := 0
	h.clientAcquirer = func(*http.Request) (s3.Client, error) {
		backendCalls++
		return backend, nil
	}
	body := `<CORSConfiguration><CORSRule><ID>first</ID><AllowedOrigin>https://app.example.com</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedHeader>content-type</AllowedHeader><ExposeHeader>X-First</ExposeHeader></CORSRule><CORSRule><ID>second</ID><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedHeader>*</AllowedHeader><ExposeHeader>ETag</ExposeHeader></CORSRule></CORSConfiguration>`
	corsRuleStore(t, h, body)
	r := corsRequest(http.MethodOptions, "/bucket/key", "")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	r.Header.Set("Access-Control-Request-Headers", "Content-Type")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "PUT", w.Header().Get("Access-Control-Allow-Methods"))
	require.Equal(t, "content-type", w.Header().Get("Access-Control-Allow-Headers"))
	require.Equal(t, "X-First", w.Header().Get("Access-Control-Expose-Headers"))
	require.Zero(t, backendCalls, "preflight must not acquire/invoke any backend client")
}

func TestCORSPreflight_ForbiddenAndMissingConfig(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	r := corsRequest(http.MethodOptions, "/bucket", "")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, w.Header().Get("Vary"), "Access-Control-Request-Method")
}

func TestCORSPreflight_FallbackOnlyOnMissingKey(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.config.CORS.Fallback = config.CORSFallbackConfig{AllowedOrigins: []string{"https://fallback.example"}, AllowedMethods: []string{"PUT"}}
	r := corsRequest(http.MethodOptions, "/bucket", "")
	r.Header.Set("Origin", "https://fallback.example")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	// A present but nonmatching bucket document must not fall through.
	corsRuleStore(t, h, `<CORSConfiguration><CORSRule><AllowedOrigin>https://other.example</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>`)
	w = httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestCORSPreflight_StoreFailureFailClosed(t *testing.T) {
	h, _, mr := newCORSTestHandler(t)
	h.config.CORS.Fallback = config.CORSFallbackConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"PUT"}}
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer client.Close()
	h.corsStore = NewValkeyCORSStore(client)
	_ = mr
	r := corsRequest(http.MethodOptions, "/bucket", "")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSPreflight_MalformedRequestIs400(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	r := corsRequest(http.MethodOptions, "/bucket", "")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "CONNECT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "InvalidArgument")
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, w.Header().Get("Vary"), "Access-Control-Request-Headers")
}

func TestCORSPreflight_SignedInScopeAndTamperedSignature(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, `<CORSConfiguration><CORSRule><AllowedOrigin>https://app.example.com</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>`)
	var clientAcquires atomic.Int64
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { clientAcquires.Add(1); return backend, nil }
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	credential := Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite}}
	chain := http.Handler(router)
	chain = AuthorizationMiddleware("", nil)(chain)
	chain = AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, false)(chain)
	chain = CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(chain)
	request := func(tamper bool) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodOptions, "/bucket/object", nil)
		r.Header.Set("Origin", "https://app.example.com")
		r.Header.Set("Access-Control-Request-Method", "PUT")
		r.Host = "localhost"
		r.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
		resignV4Request(t, r, "UNSIGNED-PAYLOAD")
		if tamper {
			r.Host = "tampered.example"
		}
		r = r.WithContext(context.WithValue(r.Context(), credentialKey, credential))
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, r)
		return w
	}
	valid := request(false)
	require.Equal(t, http.StatusOK, valid.Code, valid.Body.String())
	require.Equal(t, "https://app.example.com", valid.Header().Get("Access-Control-Allow-Origin"))
	invalid := request(true)
	require.Equal(t, http.StatusForbidden, invalid.Code)
	require.Empty(t, invalid.Header().Get("Access-Control-Allow-Origin"))
	require.Zero(t, clientAcquires.Load(), "signed preflight is evaluated locally after auth and authorization")
}

func TestCORSPreflight_InvalidOriginHasNoAuthorizationHeadersWithCredentials(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.config.CORS.AllowCredentials = true
	corsRuleStore(t, h, `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>`)
	for _, origin := range []string{"*", "null", "https://", "https://host:", "https://host:65536", "https://host/path", "https://a.example,https://b.example", "\rhttps://host", "https://host]", "https://ho\"st", "https://ho<st"} {
		r := corsRequest(http.MethodOptions, "/bucket", "")
		r.Header.Add("Origin", origin)
		r.Header.Set("Access-Control-Request-Method", "PUT")
		w := httptest.NewRecorder()
		CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code, origin)
		for name := range w.Header() {
			require.NotContains(t, strings.ToLower(name), "access-control-", origin)
		}
	}
}

func TestCORSMiddleware_RejectsMalformedAuthoritiesForStoredWildcardAndFallback(t *testing.T) {
	for _, policy := range []string{"stored-wildcard", "fallback-wildcard"} {
		t.Run(policy, func(t *testing.T) {
			h, _, _ := newCORSTestHandler(t)
			h.config.CORS.AllowCredentials = true
			if policy == "stored-wildcard" {
				corsRuleStore(t, h, `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>`)
			} else {
				h.config.CORS.Fallback = config.CORSFallbackConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET", "PUT"}}
			}
			for _, origin := range []string{"https://host]", "https://ho\"st", "https://ho<st"} {
				actual := httptest.NewRequest(http.MethodGet, "/bucket/object", nil)
				actual.Header.Set("Origin", origin)
				actualWriter := httptest.NewRecorder()
				CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
					w.WriteHeader(http.StatusOK)
				})).ServeHTTP(actualWriter, actual)
				require.Equal(t, http.StatusOK, actualWriter.Code)
				assertNoAccessControlHeaders(t, actualWriter.Header())

				preflight := corsRequest(http.MethodOptions, "/bucket/object", "")
				preflight.Header.Set("Origin", origin)
				preflight.Header.Set("Access-Control-Request-Method", "PUT")
				preflightWriter := httptest.NewRecorder()
				CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(preflightWriter, preflight)
				require.Equal(t, http.StatusBadRequest, preflightWriter.Code)
				assertNoAccessControlHeaders(t, preflightWriter.Header())
			}
		})
	}
}

func TestCORSMiddleware_StoredAndFallbackWildcardWithCredentialsEchoConcreteOrigin(t *testing.T) {
	for _, policy := range []string{"stored-wildcard", "fallback-wildcard"} {
		t.Run(policy, func(t *testing.T) {
			h, _, _ := newCORSTestHandler(t)
			h.config.CORS.AllowCredentials = true
			if policy == "stored-wildcard" {
				corsRuleStore(t, h, `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`)
			} else {
				h.config.CORS.Fallback = config.CORSFallbackConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET"}}
			}
			r := httptest.NewRequest(http.MethodGet, "/bucket/object", nil)
			r.Header.Set("Origin", "https://app.example.com")
			w := httptest.NewRecorder()
			CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, r)
			require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
			require.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
			require.NotEqual(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
		})
	}
}

func TestCORSManagementSDKFullCanonicalRoundTripRejectsUnknownAndDuplicates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		cfg, err := parseCORSXML(body)
		require.NoError(t, err, string(body))
		wire, err := marshalCORSXML(cfg)
		require.NoError(t, err)
		parsed, err := parseCORSXML(wire)
		require.NoError(t, err)
		require.Equal(t, cfg, parsed)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := awss3.New(awss3.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), UsePathStyle: true})
	input := &awss3.PutBucketCorsInput{Bucket: aws.String("bucket"), CORSConfiguration: &awstypes.CORSConfiguration{CORSRules: []awstypes.CORSRule{
		{AllowedHeaders: []string{"content-type", "x-amz-*"}, AllowedMethods: []string{"PUT", "POST"}, AllowedOrigins: []string{"https://one.example", "https://two.example"}, ExposeHeaders: []string{"ETag", "X-Trace"}, ID: aws.String("first"), MaxAgeSeconds: aws.Int32(600)},
		{AllowedHeaders: []string{"authorization"}, AllowedMethods: []string{"GET"}, AllowedOrigins: []string{"https://read.example"}, ID: aws.String("second")},
	}}}
	_, err := client.PutBucketCors(context.Background(), input)
	require.NoError(t, err)
	for _, body := range []string{
		`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><Unknown>x</Unknown></CORSRule></CORSConfiguration>`,
		`<CORSConfiguration><CORSRule><ID>first</ID><ID>second</ID><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
	} {
		_, err := parseCORSXML([]byte(body))
		require.Error(t, err)
	}
}

func assertNoAccessControlHeaders(t *testing.T, headers http.Header) {
	t.Helper()
	for name := range headers {
		require.NotContains(t, strings.ToLower(name), "access-control-")
	}
}

func TestCORSPreflight_CredentialsEchoWildcardAndMaxAge(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.config.CORS.AllowCredentials = true
	cfg, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><MaxAgeSeconds>120</MaxAgeSeconds></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	require.NoError(t, h.corsStore.Put(context.Background(), "bucket", cfg))
	r := corsRequest(http.MethodOptions, "/bucket", "")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	require.Equal(t, "120", w.Header().Get("Access-Control-Max-Age"))
}

func TestCORSPreflight_PresentCorruptPolicyNeverUsesFallback(t *testing.T) {
	h, _, mr := newCORSTestHandler(t)
	h.config.CORS.Fallback = config.CORSFallbackConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"PUT"}}
	mr.Set(corsKey("bucket"), `<CORSConfiguration><CORSRule><Unknown>x</Unknown></CORSRule></CORSConfiguration>`)
	r := corsRequest(http.MethodOptions, "/bucket", "")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSPreflight_ResetChangesToFallback(t *testing.T) {
	h, _, mr := newCORSTestHandler(t)
	corsRuleStore(t, h, `<CORSConfiguration><CORSRule><AllowedOrigin>https://restricted.example</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>`)
	mr.FlushAll()
	r := corsRequest(http.MethodOptions, "/bucket", "")
	r.Header.Set("Origin", "https://fallback.example")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	h.config.CORS.Fallback = config.CORSFallbackConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"PUT"}}
	w = httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSPreflight_PublicResetRecoveryFlow(t *testing.T) {
	h, _, mr := newCORSTestHandler(t)
	firstClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer firstClient.Close()
	secondClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer secondClient.Close()
	h.corsStore = NewValkeyCORSStore(firstClient)
	h.config.CORS.Fallback = config.CORSFallbackConfig{AllowedOrigins: []string{"https://broad.example"}, AllowedMethods: []string{"PUT"}}
	permission := config.ObjectPermissionReadWrite
	credentials, err := NewStaticCredentialStore([]config.GatewayCredential{{
		AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Buckets: []string{"bucket"}, Permissions: &permission,
		BucketPermissions: []config.BucketPermission{config.BucketPermissionManage},
	}})
	require.NoError(t, err)
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	chain := http.Handler(router)
	chain = AuthorizationMiddleware("", nil)(chain)
	chain = AuthMiddleware(credentials, time.Minute, logrus.New(), nil, false)(chain)
	chain = CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(chain)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return newMockS3Client(), nil }
	storedXML := `<CORSConfiguration><CORSRule><ID>restricted</ID><AllowedOrigin>https://restricted.example</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule></CORSConfiguration>`
	cfg, err := parseCORSXML([]byte(storedXML))
	require.NoError(t, err)
	require.NoError(t, firstClient.Set(context.Background(), corsKey("bucket"), mustMarshalCORS(t, cfg), 0).Err())

	public := func(method, target, origin string, signed bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if method == http.MethodOptions {
			r.Header.Set("Access-Control-Request-Method", "PUT")
		}
		if signed {
			signGatewayCORSRequest(t, r)
		}
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, r)
		return w
	}

	// Empty-but-healthy store is observed through the public management and
	// preflight routes; the configured fallback deliberately widens exposure.
	mr.FlushAll()
	get := public(http.MethodGet, "/bucket?cors", "", true)
	require.Equal(t, http.StatusNotFound, get.Code)
	require.Contains(t, get.Body.String(), "NoSuchCORSConfiguration")
	denied := public(http.MethodOptions, "/bucket/object", "https://restricted.example", false)
	require.Equal(t, http.StatusForbidden, denied.Code)
	broad := public(http.MethodOptions, "/bucket/object", "https://broad.example", false)
	require.Equal(t, http.StatusOK, broad.Code)
	require.Equal(t, "https://broad.example", broad.Header().Get("Access-Control-Allow-Origin"))

	// PUT restores the desired restrictive policy through the authenticated S3
	// route; a second store client immediately observes it.
	put := httptest.NewRequest(http.MethodPut, "/bucket?cors", strings.NewReader(storedXML))
	signGatewayCORSRequest(t, put)
	putWriter := httptest.NewRecorder()
	chain.ServeHTTP(putWriter, put)
	require.Equal(t, http.StatusOK, putWriter.Code, putWriter.Body.String())
	restored, err := NewValkeyCORSStore(secondClient).Get(context.Background(), "bucket")
	require.NoError(t, err)
	require.Equal(t, "restricted", restored.Rules[0].ID)
	get = public(http.MethodGet, "/bucket?cors", "", true)
	require.Equal(t, http.StatusOK, get.Code)
	require.Contains(t, get.Body.String(), "restricted")
	denied = public(http.MethodOptions, "/bucket/object", "https://broad.example", false)
	require.Equal(t, http.StatusForbidden, denied.Code)
	require.Empty(t, denied.Header().Get("Access-Control-Allow-Origin"))
	allowed := public(http.MethodOptions, "/bucket/object", "https://restricted.example", false)
	require.Equal(t, http.StatusOK, allowed.Code)
	require.Equal(t, "https://restricted.example", allowed.Header().Get("Access-Control-Allow-Origin"))
}

func TestBucketCORS_DefaultPassthroughThroughRouterForCorsMethodsAndPreflight(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.config.CORS.Mode = "passthrough"
	h.config.Backend.Endpoint = "http://backend.example"
	var calls atomic.Int64
	h.proxyTransport = corsRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls.Add(1)
		status, body := http.StatusOK, "provider-cors"
		if req.Method == http.MethodDelete {
			status, body = http.StatusNoContent, ""
		}
		if req.Method == http.MethodOptions {
			status, body = http.StatusAccepted, "provider-preflight"
		}
		return &http.Response{StatusCode: status, Status: http.StatusText(status), Header: http.Header{"Access-Control-Allow-Origin": {"https://backend.example"}}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	for _, tc := range []struct {
		method string
		query  string
		status int
		body   string
	}{
		{http.MethodGet, "?cors", http.StatusOK, "provider-cors"},
		{http.MethodPut, "?cors", http.StatusOK, "provider-cors"},
		{http.MethodDelete, "?cors", http.StatusNoContent, ""},
		{http.MethodOptions, "", http.StatusAccepted, "provider-preflight"},
	} {
		router := mux.NewRouter()
		h.RegisterRoutes(router)
		r := httptest.NewRequest(tc.method, "/bucket"+tc.query, strings.NewReader(corsTestXML))
		if tc.method == http.MethodOptions {
			r.Header.Set("Origin", "https://app.example.com")
			r.Header.Set("Access-Control-Request-Method", "PUT")
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Equal(t, tc.status, w.Code)
		require.Equal(t, tc.body, w.Body.String())
		require.Equal(t, "https://backend.example", w.Header().Get("Access-Control-Allow-Origin"))
	}
	require.EqualValues(t, 4, calls.Load(), "the real routes must proxy all three CORS subresources and OPTIONS")
}

func signGatewayCORSRequest(t *testing.T, r *http.Request) {
	t.Helper()
	r.Host = "localhost"
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	r.Header.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
	resignV4Request(t, r, "UNSIGNED-PAYLOAD")
}

func mustMarshalCORS(t *testing.T, cfg *CORSConfiguration) string {
	t.Helper()
	wire, err := marshalCORSXML(cfg)
	require.NoError(t, err)
	return string(wire)
}

func TestBucketCORS_BucketReuseCannotInheritStaleRules(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	backend.errors["bucket/list"] = &mockAPIError{code: "NoSuchBucket", message: "missing"}
	r := corsRequest(http.MethodPut, "/bucket", "")
	r = r.WithContext(context.WithValue(r.Context(), credentialKey, Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}))
	h.SetAllowBucketCreation(true)
	h.config.Backend.Endpoint = "http://backend.example"
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
	h.proxyTransport = corsRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: http.NoBody}, nil
	})
	h.handleCreateBucket(httptest.NewRecorder(), r)
	_, err := h.corsStore.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSNotFound)
}

func TestBucketCORS_FailedDeletePreservesRules(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	h.config.Backend.Endpoint = "http://backend.example"
	h.proxyTransport = corsRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Header: make(http.Header), Body: http.NoBody}, nil
	})
	r := attachTestCredential(corsRequest(http.MethodDelete, "/bucket", ""))
	r = r.WithContext(context.WithValue(r.Context(), credentialKey, Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete}}}))
	w := httptest.NewRecorder()
	h.handleDeleteBucket(w, r)
	require.Equal(t, http.StatusConflict, w.Code)
	got, err := h.corsStore.Get(context.Background(), "bucket")
	require.NoError(t, err)
	require.Equal(t, "web", got.Rules[0].ID)
}

func TestBucketCORS_FailedCreatePreservesExistingRules(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	h.SetAllowBucketCreation(true)
	h.config.Backend.Endpoint = "http://backend.example"
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
	h.proxyTransport = corsRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusConflict, Status: "409 Conflict", Header: make(http.Header), Body: http.NoBody}, nil
	})
	r := corsRequest(http.MethodPut, "/bucket", "")
	r = r.WithContext(context.WithValue(r.Context(), credentialKey, Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}))
	w := httptest.NewRecorder()
	h.handleCreateBucket(w, r)
	require.Equal(t, http.StatusConflict, w.Code)
	got, err := h.corsStore.Get(context.Background(), "bucket")
	require.NoError(t, err)
	require.Equal(t, "web", got.Rules[0].ID)
}

func TestBucketCORS_DefaultPassthroughStillForwards(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.config.CORS.Mode = ""
	h.config.Backend.Endpoint = "http://backend.example"
	var called atomic.Int64
	h.proxyTransport = corsRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		called.Add(1)
		if req.Method == http.MethodOptions {
			return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Access-Control-Allow-Origin": {"https://app.example.com"}}, Body: io.NopCloser(strings.NewReader("backend-options"))}, nil
		}
		if req.Method == http.MethodDelete {
			return &http.Response{StatusCode: http.StatusNoContent, Status: "204 No Content", Header: http.Header{"Access-Control-Allow-Origin": {"https://app.example.com"}}, Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Access-Control-Allow-Origin": {"https://app.example.com"}}, Body: io.NopCloser(strings.NewReader("<CORSConfiguration/>"))}, nil
	})
	h.config.Backend.AccessKey = ""
	h.config.Backend.SecretKey = ""
	for _, tc := range []struct {
		method, query string
		status        int
	}{{http.MethodGet, "?cors", http.StatusOK}, {http.MethodPut, "?cors", http.StatusOK}, {http.MethodDelete, "?cors", http.StatusNoContent}} {
		r := corsRequest(tc.method, "/bucket"+tc.query, corsTestXML)
		router := mux.NewRouter()
		h.RegisterRoutes(router)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		require.Equal(t, tc.status, w.Code)
		require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
		if tc.method != http.MethodDelete {
			require.Equal(t, "<CORSConfiguration/>", w.Body.String())
		}
	}
	h.proxyTransport = corsRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		called.Add(1)
		return &http.Response{StatusCode: http.StatusAccepted, Status: "202 Accepted", Header: http.Header{"Access-Control-Allow-Origin": {"https://app.example.com"}, "X-Backend": {"passthrough"}}, Body: io.NopCloser(strings.NewReader("backend-options"))}, nil
	})
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		router := mux.NewRouter()
		h.RegisterRoutes(router)
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, "/bucket?cors", strings.NewReader(corsTestXML))
		router.ServeHTTP(w, r)
		require.Equal(t, http.StatusAccepted, w.Code)
		require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
		require.Equal(t, "passthrough", w.Header().Get("X-Backend"))
		require.Equal(t, "backend-options", w.Body.String())
	}
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	w := httptest.NewRecorder()
	preflight := corsRequest(http.MethodOptions, "/bucket", "")
	preflight.Header.Set("Origin", "https://app.example.com")
	preflight.Header.Set("Access-Control-Request-Method", "PUT")
	router.ServeHTTP(w, preflight)
	require.Equal(t, http.StatusAccepted, w.Code)
	require.Equal(t, "backend-options", w.Body.String())
	require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	require.EqualValues(t, 7, called.Load())
}

func TestCORSPreflight_NoBackendClientForEveryResponse(t *testing.T) {
	for _, tc := range []struct {
		name, origin, policy string
		status               int
	}{
		{"match", "https://app.example.com", corsTestXML, http.StatusOK},
		{"unmatched", "https://evil.example", corsTestXML, http.StatusForbidden},
		{"missing", "https://app.example.com", "", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := newCORSTestHandler(t)
			if tc.policy != "" {
				corsRuleStore(t, h, tc.policy)
			}
			var acquisitions atomic.Int64
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions.Add(1); return newMockS3Client(), nil }
			r := corsRequest(http.MethodOptions, "/bucket/key", "")
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Access-Control-Request-Method", "PUT")
			w := httptest.NewRecorder()
			chain := CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight))
			chain.ServeHTTP(w, r)
			require.Equal(t, tc.status, w.Code)
			require.Zero(t, acquisitions.Load())
		})
	}
}

func TestCORSPreflight_UnmatchedHasNoBackendAndNoAuthorizationHeaders(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	var calls atomic.Int64
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { calls.Add(1); return newMockS3Client(), nil }
	r := corsRequest(http.MethodOptions, "/bucket/key", "")
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code)
	require.Zero(t, calls.Load())
	for name := range w.Header() {
		require.NotContains(t, strings.ToLower(name), "access-control-")
	}
}

func TestCORSPreflight_RequestedHeadersRejectRawControls(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	for _, header := range []string{"content-type\t", "content-type\x01", "content-type,\r\nx-evil"} {
		r := corsRequest(http.MethodOptions, "/bucket/key", "")
		r.Header.Set("Origin", "https://app.example.com")
		r.Header.Set("Access-Control-Request-Method", "PUT")
		r.Header.Set("Access-Control-Request-Headers", header)
		w := httptest.NewRecorder()
		CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
		for name := range w.Header() {
			require.NotContains(t, strings.ToLower(name), "access-control-")
		}
	}
}

func TestCORSManagementRecordsOneAuditEvent(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	var events atomic.Int64
	h.auditLogger = &corsAuditSpy{events: &events}
	w := httptest.NewRecorder()
	h.serveGatewayCORSManagement(w, corsRequest(http.MethodPut, "/bucket?cors", ""), "PutBucketCors", func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(http.StatusOK) })
	require.Equal(t, http.StatusOK, w.Code)
	require.EqualValues(t, 1, events.Load())
}

func TestCORSManagementRouterRecordsSingleMetricsAndAudit(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	metricsRegistry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(metricsRegistry)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
	var events atomic.Int64
	h.auditLogger = &corsAuditSpy{events: &events}
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	r := httptest.NewRequest(http.MethodGet, "/bucket?cors", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.EqualValues(t, 1, events.Load())
	families, err := metricsRegistry.Gather()
	require.NoError(t, err)
	clientCount, operationCount, errorCount := 0.0, 0.0, 0.0
	for _, family := range families {
		for _, metric := range family.Metric {
			if family.GetName() == "s3_client_requests_total" && metric.GetCounter() != nil {
				clientCount += metric.GetCounter().GetValue()
			}
			if family.GetName() == "s3_operations_total" && metric.GetCounter() != nil {
				for _, label := range metric.Label {
					if label.GetName() == "operation" && label.GetValue() == "GetBucketCors" {
						operationCount += metric.GetCounter().GetValue()
					}
				}
			}
			if family.GetName() == "s3_operation_errors_total" && metric.GetCounter() != nil {
				for _, label := range metric.Label {
					if label.GetName() == "operation" && label.GetValue() == "GetBucketCors" {
						errorCount += metric.GetCounter().GetValue()
					}
				}
			}
		}
	}
	require.Equal(t, 1.0, clientCount)
	require.Equal(t, 1.0, operationCount, "the route instrumentation records one operation attempt on failure")
	require.Equal(t, 1.0, errorCount, "failed management probe has one error metric")
}

func TestCORSManagementRouterSuccessfulMutationHasOneAuditAndOperationMetric(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	metricsRegistry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(metricsRegistry)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
	var events atomic.Int64
	h.auditLogger = &corsAuditSpy{events: &events}
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	r := httptest.NewRequest(http.MethodPut, "/bucket?cors", strings.NewReader(corsTestXML))
	r = mux.SetURLVars(r, map[string]string{"bucket": "bucket"})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.EqualValues(t, 1, events.Load())
	families, err := metricsRegistry.Gather()
	require.NoError(t, err)
	clientCount, operationCount := 0.0, 0.0
	for _, family := range families {
		for _, metric := range family.Metric {
			if family.GetName() == "s3_client_requests_total" && metric.GetCounter() != nil {
				clientCount += metric.GetCounter().GetValue()
			}
			if family.GetName() == "s3_operations_total" && metric.GetCounter() != nil {
				operationCount += metric.GetCounter().GetValue()
			}
		}
	}
	require.Equal(t, 1.0, clientCount)
	require.Equal(t, 1.0, operationCount)
}

func TestCORSManagementFailureThroughRouterHasOneAuditAndFailureMetrics(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	registry := prometheus.NewRegistry()
	h.metrics = metrics.NewMetricsWithRegistry(registry)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return nil, errors.New("backend unavailable") }
	var events atomic.Int64
	h.auditLogger = &corsAuditSpy{events: &events}
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	r := httptest.NewRequest(http.MethodGet, "/bucket?cors", nil)
	r = r.WithContext(context.WithValue(r.Context(), credentialKey, Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadOnly}}))
	w := httptest.NewRecorder()
	AuthorizationMiddleware("", nil)(router).ServeHTTP(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.EqualValues(t, 1, events.Load())
	families, err := registry.Gather()
	require.NoError(t, err)
	ops, errs := 0.0, 0.0
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if label.GetName() != "operation" || label.GetValue() != "GetBucketCors" {
					continue
				}
				if family.GetName() == "s3_operations_total" {
					ops += metric.GetCounter().GetValue()
				}
				if family.GetName() == "s3_operation_errors_total" {
					errs += metric.GetCounter().GetValue()
				}
			}
		}
	}
	require.Equal(t, 1.0, ops)
	require.Equal(t, 1.0, errs)
}

func TestBucketCORS_ProbeMapsAmbiguousErrorsToFixed503(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	for _, err := range []error{ErrBackendNotConfigured, context.DeadlineExceeded, &mockAPIError{code: "AccessDenied", message: "hidden backend details"}} {
		w := httptest.NewRecorder()
		h.corsBucketProbeResponse(w, corsRequest(http.MethodPut, "/bucket?cors", ""), "PutBucketCors", "bucket", err)
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Contains(t, w.Body.String(), "ServiceUnavailable")
		require.NotContains(t, w.Body.String(), "hidden backend details")
	}
}

func TestBucketLifecycleFailureUsesFixed503AndSingleCompletionAccounting(t *testing.T) {
	for _, tc := range []struct {
		name      string
		operation string
		method    string
		setup     func(*Handler)
	}{
		{
			name:      "create client acquisition",
			operation: "CreateBucket",
			method:    http.MethodPut,
			setup: func(h *Handler) {
				h.SetAllowBucketCreation(true)
				h.clientAcquirer = func(*http.Request) (s3.Client, error) { return nil, errors.New("backend credentials leaked detail") }
			},
		},
		{
			name:      "delete cleanup after upstream success",
			operation: "DeleteBucket",
			method:    http.MethodDelete,
			setup: func(h *Handler) {
				h.config.Backend.Endpoint = "http://backend.example"
				h.proxyTransport = corsRoundTripperFunc(func(*http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
				})
				h.corsStore = corsLifecycleDeleteFailureStore{CORSStore: h.corsStore, err: errors.New("valkey detail")}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := newCORSTestHandler(t)
			registry := prometheus.NewRegistry()
			h.metrics = metrics.NewMetricsWithRegistry(registry)
			var events atomic.Int64
			h.auditLogger = &corsAuditSpy{events: &events}
			tc.setup(h)
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			r := httptest.NewRequest(tc.method, "/bucket", nil)
			permission := config.BucketPermissionCreate
			if tc.operation == "DeleteBucket" {
				permission = config.BucketPermissionDelete
			}
			credential := Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{permission}}}
			r = r.WithContext(context.WithValue(r.Context(), credentialKey, credential))
			w := httptest.NewRecorder()
			chain := AuthorizationMiddleware("", nil)(router)
			chain.ServeHTTP(w, r)
			require.Equal(t, http.StatusServiceUnavailable, w.Code)
			require.Contains(t, w.Body.String(), "<Code>ServiceUnavailable</Code>")
			require.NotContains(t, w.Body.String(), "backend credentials leaked detail")
			require.NotContains(t, w.Body.String(), "valkey detail")
			if tc.operation == "DeleteBucket" {
				require.Contains(t, w.Body.String(), "deleted upstream")
			}
			require.EqualValues(t, 1, events.Load(), "lifecycle completion has one audit owner")
			families, err := registry.Gather()
			require.NoError(t, err)
			operations, errorsCount := 0.0, 0.0
			for _, family := range families {
				for _, metric := range family.Metric {
					if family.GetName() == "s3_operations_total" {
						for _, label := range metric.Label {
							if label.GetName() == "operation" && label.GetValue() == tc.operation {
								operations += metric.GetCounter().GetValue()
							}
						}
					}
					if family.GetName() == "s3_operation_errors_total" {
						for _, label := range metric.Label {
							if label.GetName() == "operation" && label.GetValue() == tc.operation {
								errorsCount += metric.GetCounter().GetValue()
							}
						}
					}
				}
			}
			require.Equal(t, 1.0, operations)
			require.Equal(t, 1.0, errorsCount)
			h.logger = logrus.New()
		})
	}
}

func TestGatewayCreateBucketClientAcquisitionIs503WithOneAudit(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.SetAllowBucketCreation(true)
	var events atomic.Int64
	h.auditLogger = &corsAuditSpy{events: &events}
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return nil, errors.New("unavailable") }
	r := httptest.NewRequest(http.MethodPut, "/bucket", nil)
	r = r.WithContext(context.WithValue(r.Context(), credentialKey, Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}))
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	w := httptest.NewRecorder()
	AuthorizationMiddleware("", nil)(router).ServeHTTP(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Contains(t, w.Body.String(), "ServiceUnavailable")
	require.EqualValues(t, 1, events.Load())
}

type corsLifecycleDeleteFailureStore struct {
	CORSStore
	err error
}

func (s corsLifecycleDeleteFailureStore) Delete(context.Context, string) error { return s.err }

func (a *corsAuditSpy) Log(*audit.AuditEvent) error { a.events.Add(1); return nil }
func (a *corsAuditSpy) LogEncrypt(string, string, string, int, bool, error, time.Duration, map[string]interface{}) {
	a.events.Add(1)
}
func (a *corsAuditSpy) LogDecrypt(string, string, string, int, bool, error, time.Duration, map[string]interface{}) {
	a.events.Add(1)
}
func (a *corsAuditSpy) LogKeyRotation(int, bool, error) { a.events.Add(1) }
func (a *corsAuditSpy) GetEvents() []*audit.AuditEvent  { return nil }
func (a *corsAuditSpy) Close() error                    { return nil }

type corsAuditSpy struct{ events *atomic.Int64 }

func (a *corsAuditSpy) LogAccess(string, string, string, string, string, string, bool, error, time.Duration) {
	a.events.Add(1)
}
func (a *corsAuditSpy) LogAccessWithMetadata(string, string, string, string, string, string, bool, error, time.Duration, map[string]interface{}) {
	a.events.Add(1)
}

type corsRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f corsRoundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCORSPreflight_RejectsMalformedHeaders(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	r := corsRequest(http.MethodOptions, "/bucket", "")
	r.Header.Add("Origin", "https://app.example.com")
	r.Header.Add("Origin", "https://other.example")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestBucketCORS_ContentMD5Valid(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	digest := md5.Sum([]byte(corsTestXML))
	r := corsRequest(http.MethodPut, "/bucket?cors", corsTestXML)
	r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(digest[:]))
	w := httptest.NewRecorder()
	h.handlePutBucketCors(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

func TestBucketCORS_InvalidDigestAndMalformedXML(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	for _, tc := range []struct {
		digest string
		body   string
		code   string
	}{
		{"not-base64", corsTestXML, "InvalidDigest"},
		{base64.StdEncoding.EncodeToString([]byte("short")), corsTestXML, "InvalidDigest"},
		{"", `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><Unknown>x</Unknown></CORSRule></CORSConfiguration>`, "MalformedXML"},
	} {
		r := corsRequest(http.MethodPut, "/bucket?cors", tc.body)
		if tc.digest != "" {
			r.Header.Set("Content-MD5", tc.digest)
		}
		w := httptest.NewRecorder()
		h.handlePutBucketCors(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
		require.Contains(t, w.Body.String(), tc.code)
	}
}

func TestBucketCORS_PutStoreUnavailableIs503(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer client.Close()
	h.corsStore = NewValkeyCORSStore(client)
	w := httptest.NewRecorder()
	h.handlePutBucketCors(w, corsRequest(http.MethodPut, "/bucket?cors", corsTestXML))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.NotContains(t, w.Body.String(), "200")
}

func TestCheckCORSBucketUsesMinimalList(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	require.NoError(t, h.checkCORSBucket(corsRequest(http.MethodGet, "/bucket?cors", ""), "bucket"))
	_, err := backend.ListObjects(context.Background(), "bucket", "", s3.ListOptions{MaxKeys: 1})
	require.NoError(t, err)
}

func TestCORSPreflight_StoreErrorIsNotFallback(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.config.CORS.Fallback = config.CORSFallbackConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"PUT"}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := corsRequest(http.MethodOptions, "/bucket", "").WithContext(ctx)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Contains(t, w.Body.String(), "ServiceUnavailable")
}

func TestCORSPreflight_CanceledStoreOperationIs503(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := corsRequest(http.MethodOptions, "/bucket", "").WithContext(ctx)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}
