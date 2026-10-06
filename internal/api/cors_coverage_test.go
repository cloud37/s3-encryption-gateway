package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5" // #nosec G401 -- fixture for invalid/oversized CORS digests
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type corsOptionalWriter struct {
	header       http.Header
	status       int
	body         bytes.Buffer
	flushed      int
	readFromUsed int
	hijackUsed   int
	pushUsed     int
}

func newCORSOptionalWriter() *corsOptionalWriter {
	return &corsOptionalWriter{header: make(http.Header)}
}
func (w *corsOptionalWriter) Header() http.Header { return w.header }
func (w *corsOptionalWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *corsOptionalWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}
func (w *corsOptionalWriter) Flush() { w.flushed++ }
func (w *corsOptionalWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFromUsed++
	return io.Copy(&w.body, r)
}

type corsBasicWriter struct{ w *corsOptionalWriter }

func (w corsBasicWriter) Header() http.Header            { return w.w.Header() }
func (w corsBasicWriter) WriteHeader(status int)         { w.w.WriteHeader(status) }
func (w corsBasicWriter) Write(data []byte) (int, error) { return w.w.Write(data) }
func (w *corsOptionalWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijackUsed++
	server, client := net.Pipe()
	client.Close()
	return server, bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server)), nil
}
func (w *corsOptionalWriter) Push(target string, _ *http.PushOptions) error {
	w.pushUsed++
	if target == "" {
		return errors.New("target required")
	}
	return nil
}

func TestCORSMiddleware_OptionalWriterDelegationAndFallback(t *testing.T) {
	base := newCORSOptionalWriter()
	w := &corsResponseWriter{ResponseWriter: base, request: httptest.NewRequest(http.MethodGet, "/bucket/key", nil), decision: &corsResponseDecision{}}
	w.Flush()
	require.Equal(t, 1, base.flushed)
	_, err := w.ReadFrom(strings.NewReader("delegated"))
	require.NoError(t, err)
	require.Equal(t, 1, base.readFromUsed)
	conn, _, err := w.Hijack()
	require.NoError(t, err)
	require.NotNil(t, conn)
	conn.Close()
	require.NoError(t, w.Push("/asset", nil))
	require.Equal(t, 1, base.hijackUsed)
	require.Equal(t, 1, base.pushUsed)
	require.Same(t, base, w.Unwrap())

	noReadFrom := newCORSOptionalWriter()
	fallbackReadFrom := &corsResponseWriter{ResponseWriter: corsBasicWriter{w: noReadFrom}, request: httptest.NewRequest(http.MethodGet, "/bucket/key", nil), decision: &corsResponseDecision{}}
	_, err = fallbackReadFrom.ReadFrom(strings.NewReader("manual copy"))
	require.NoError(t, err)
	require.Equal(t, "manual copy", noReadFrom.body.String())

	unsupported := httptest.NewRecorder()
	unsupportedWriter := &corsResponseWriter{ResponseWriter: corsNoPushHijackWriter{w: unsupported}, request: httptest.NewRequest(http.MethodGet, "/bucket/key", nil), decision: &corsResponseDecision{}}
	_, _, err = unsupportedWriter.Hijack()
	require.ErrorIs(t, err, http.ErrNotSupported)
	require.ErrorIs(t, unsupportedWriter.Push("/asset", nil), http.ErrNotSupported)
	_, err = unsupportedWriter.ReadFrom(strings.NewReader("fallback"))
	require.NoError(t, err)
	require.Equal(t, "fallback", unsupported.Body.String())
	plainBase := &corsNoOptionalWriter{header: make(http.Header)}
	plainFallback := &corsResponseWriter{ResponseWriter: plainBase, request: httptest.NewRequest(http.MethodGet, "/bucket/key", nil), decision: &corsResponseDecision{}}
	plainFallback.decision.allowed = false
	_, err = plainFallback.ReadFrom(strings.NewReader("plain fallback"))
	require.NoError(t, err)
	require.Equal(t, "plain fallback", plainBase.body.String())
}

func TestCORSMiddleware_SuccessfulFlushAndReadFromReconcilePolicy(t *testing.T) {
	for _, useReadFrom := range []bool{false, true} {
		base := newCORSOptionalWriter()
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Header.Set("Origin", "https://app.example.com")
		wrapped := &corsResponseWriter{ResponseWriter: base, request: r, decision: &corsResponseDecision{allowed: true, allowOrigin: r.Header.Get("Origin"), expose: "ETag"}}
		if useReadFrom {
			_, err := wrapped.ReadFrom(strings.NewReader("payload"))
			require.NoError(t, err)
		} else {
			wrapped.Flush()
		}
		wrapped.Flush()
		require.Equal(t, r.Header.Get("Origin"), base.Header().Get("Access-Control-Allow-Origin"))
		require.Contains(t, base.Header().Get("Vary"), "Origin")
	}
}

func TestCORSMiddleware_ImplicitWriteFlushAndUnwrap(t *testing.T) {
	base := httptest.NewRecorder()
	w := &corsResponseWriter{ResponseWriter: base, request: httptest.NewRequest(http.MethodGet, "/bucket/key", nil), decision: &corsResponseDecision{}}
	require.Same(t, base, w.Unwrap())
	n, err := w.Write([]byte("body"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, http.StatusOK, base.Code)
	base2 := httptest.NewRecorder()
	w2 := &corsResponseWriter{ResponseWriter: base2, request: httptest.NewRequest(http.MethodGet, "/bucket/key", nil), decision: &corsResponseDecision{}}
	w2.Flush()
	require.Equal(t, http.StatusOK, base2.Code)
}

func TestCORSMiddleware_InvalidModeIsNoop(t *testing.T) {
	calls := 0
	h := CORSMiddleware(config.CORSConfig{Mode: "unknown"}, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(http.StatusNoContent) }))
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	require.Equal(t, 1, calls)
	require.Equal(t, http.StatusNoContent, w.Code)
}

func TestCORSMiddleware_AbsentStoreAndMissingFallback(t *testing.T) {
	for _, cfg := range []config.CORSConfig{{Mode: "gateway"}, {Mode: "gateway", Fallback: config.CORSFallbackConfig{AllowedOrigins: []string{"https://other.example"}, AllowedMethods: []string{"GET"}}}} {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
		r.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		CORSMiddleware(cfg, nil, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(http.StatusOK)
		})).ServeHTTP(w, r)
		require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
		require.Contains(t, w.Header().Get("Vary"), "Origin")
	}
}

func TestCORSManagementRecorderOptionalInterfaces(t *testing.T) {
	base := newCORSOptionalWriter()
	w := &corsManagementRecorder{ResponseWriter: base}
	_, err := w.WriteString("one")
	require.NoError(t, err)
	_, err = w.ReadFrom(strings.NewReader("two"))
	require.NoError(t, err)
	require.Equal(t, "onetwo", base.body.String())
	require.EqualValues(t, 6, w.bytes)
	w.Flush()
	require.Equal(t, 1, base.flushed)
	conn, _, err := w.Hijack()
	require.NoError(t, err)
	conn.Close()
	require.NoError(t, w.Push("/asset", nil))
	require.Same(t, base, w.Unwrap())

	plain := httptest.NewRecorder()
	unsupported := &corsManagementRecorder{ResponseWriter: corsNoPushHijackWriter{w: plain}}
	_, _, err = unsupported.Hijack()
	require.ErrorIs(t, err, http.ErrNotSupported)
	require.ErrorIs(t, unsupported.Push("/asset", nil), http.ErrNotSupported)
	_, err = unsupported.ReadFrom(strings.NewReader("fallback"))
	require.NoError(t, err)
	require.Equal(t, "fallback", plain.Body.String())
	unsupported.Flush()
	require.Equal(t, http.StatusOK, plain.Code)
	failed := &corsManagementRecorder{ResponseWriter: corsFailWriteWriter{}}
	_, err = failed.ReadFrom(strings.NewReader("fail"))
	require.Error(t, err)
}

func TestValkeyCORSStore_HealthCheckAndInvalidValueType(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	require.NoError(t, store.HealthCheck(context.Background()))
	require.ErrorIs(t, store.HealthCheck(nil), ErrCORSUnavailable)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, store.HealthCheck(ctx), ErrCORSUnavailable)
	require.NoError(t, client.LPush(context.Background(), corsKey("bucket"), "wrong type").Err())
	_, err := store.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSUnavailable)
}

func TestValkeyCORSStore_HealthCheckUnavailable(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer client.Close()
	require.ErrorIs(t, NewValkeyCORSStore(client).HealthCheck(context.Background()), ErrCORSUnavailable)
}

func TestValkeyCORSStore_NilClientAndOversizedRecord(t *testing.T) {
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	nilStore := NewValkeyCORSStore(nil)
	_, err = nilStore.Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSUnavailable)
	require.ErrorIs(t, nilStore.Put(context.Background(), "bucket", cfg), ErrCORSUnavailable)
	require.ErrorIs(t, nilStore.Delete(context.Background(), "bucket"), ErrCORSUnavailable)
	require.ErrorIs(t, nilStore.HealthCheck(context.Background()), ErrCORSUnavailable)

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	require.NoError(t, client.Set(context.Background(), corsKey("bucket"), strings.Repeat("x", maxCORSXMLBytes+1), 0).Err())
	_, err = NewValkeyCORSStore(client).Get(context.Background(), "bucket")
	require.ErrorIs(t, err, ErrCORSUnavailable)
}

func TestValkeyCORSStore_DeleteUnavailable(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer client.Close()
	require.ErrorIs(t, NewValkeyCORSStore(client).Delete(context.Background(), "bucket"), ErrCORSUnavailable)
}

func TestValkeyCORSStore_InvalidBucketMatrix(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	for _, bucket := range []string{"", "ab", "a..b", "-bucket", "bucket-", "192.168.1.1", "bad_bucket", strings.Repeat("a", 64)} {
		t.Run(bucket, func(t *testing.T) {
			require.ErrorIs(t, store.Put(context.Background(), bucket, cfg), ErrCORSUnavailable)
		})
	}
}

func TestMarshalCORSXML_RejectsInvalidAndOversizedModels(t *testing.T) {
	for _, cfg := range []*CORSConfiguration{
		nil,
		{},
		{Rules: []CORSRule{{AllowedOrigins: []string{"*"}}}},
		{Rules: []CORSRule{{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"TRACE"}}}},
		{Rules: []CORSRule{{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET"}, AllowedHeaders: []string{"bad header"}}}},
		{Rules: []CORSRule{{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET"}, ExposeHeaders: []string{"x-*"}}}},
		{Rules: []CORSRule{{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET"}, MaxAgeSeconds: intPointer(-1)}}},
	} {
		_, err := marshalCORSXML(cfg)
		require.Error(t, err)
	}
	label := strings.Repeat("a", 63)
	host := strings.Join([]string{label, label, label, strings.Repeat("a", 61)}, ".")
	largeOrigin := "https://" + host
	large := &CORSConfiguration{Rules: make([]CORSRule, 100)}
	for i := range large.Rules {
		large.Rules[i] = CORSRule{AllowedOrigins: []string{largeOrigin, largeOrigin, largeOrigin}, AllowedMethods: []string{"GET"}}
	}
	_, err := marshalCORSXML(large)
	require.ErrorIs(t, err, ErrCORSTooLarge)
}

func intPointer(value int) *int { return &value }

func TestCORSDeleteBucket_CleanupAndFailureResponses(t *testing.T) {
	for _, tc := range []struct {
		name          string
		storeDown     bool
		backendStatus int
		wantStatus    int
		wantRetained  bool
	}{
		{"success removes policy", false, http.StatusNoContent, http.StatusNoContent, false},
		{"backend failure retains policy", false, http.StatusConflict, http.StatusConflict, true},
		{"cleanup failure reports service unavailable", true, http.StatusNoContent, http.StatusServiceUnavailable, true},
		{"backend transport failure reports service unavailable", false, http.StatusBadGateway, http.StatusServiceUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := newCORSTestHandler(t)
			corsRuleStore(t, h, corsTestXML)
			h.config.Backend.Endpoint = "http://backend.example"
			var bodyClosed atomic.Bool
			h.proxyTransport = corsRoundTripperFunc(func(*http.Request) (*http.Response, error) {
				if tc.backendStatus == http.StatusBadGateway {
					return nil, errors.New("injected backend failure")
				}
				return &http.Response{StatusCode: tc.backendStatus, Status: http.StatusText(tc.backendStatus), Header: make(http.Header), Body: &trackingCORSBody{closed: &bodyClosed}}, nil
			})
			if tc.storeDown {
				h.corsStore = corsDeleteFailureStore{CORSStore: h.corsStore}
			}
			r := corsRequest(http.MethodDelete, "/bucket", "")
			r = r.WithContext(context.WithValue(r.Context(), credentialKey, Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket"}, Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete}}}))
			w := httptest.NewRecorder()
			h.handleDeleteBucket(w, r)
			require.Equal(t, tc.wantStatus, w.Code)
			if tc.storeDown || tc.backendStatus == http.StatusBadGateway {
				require.Contains(t, w.Body.String(), "<Code>ServiceUnavailable</Code>")
				require.NotContains(t, w.Body.String(), "injected backend failure")
			}
			require.Equal(t, tc.backendStatus != http.StatusBadGateway, bodyClosed.Load())
			if tc.wantRetained {
				store := h.corsStore
				if failing, ok := store.(corsDeleteFailureStore); ok {
					store = failing.CORSStore
				}
				_, err := store.Get(context.Background(), "bucket")
				require.NoError(t, err)
			} else {
				_, err := h.corsStore.Get(context.Background(), "bucket")
				require.ErrorIs(t, err, ErrCORSNotFound)
			}
		})
	}
}

func TestCORSManagementFallbackAndStoreDownResponses(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	require.Error(t, writeCORSXML(corsFailWriteWriter{}, cfg))
	bad := &CORSConfiguration{}
	require.Error(t, writeCORSXML(httptest.NewRecorder(), bad))
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer client.Close()
	h.corsStore = NewValkeyCORSStore(client)
	r := corsRequest(http.MethodDelete, "/bucket?cors", "")
	w := httptest.NewRecorder()
	backend := newMockS3Client()
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
	h.handleGatewayDeleteBucketCors(w, r, "bucket")
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCORSManagementGetStoreUnavailableAndCorruptXML(t *testing.T) {
	h, _, mr := newCORSTestHandler(t)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return newMockS3Client(), nil }
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	require.NoError(t, client.Set(context.Background(), corsKey("bucket"), `<CORSConfiguration><CORSRule><Unknown/></CORSRule></CORSConfiguration>`, 0).Err())
	h.corsStore = NewValkeyCORSStore(client)
	w := httptest.NewRecorder()
	h.handleGetBucketCors(w, corsRequest(http.MethodGet, "/bucket?cors", ""))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Contains(t, w.Body.String(), "ServiceUnavailable")
	require.NoError(t, client.Close())
}

func TestCORSManagementGetCorruptXMLWriterErrorAndSuccess(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return newMockS3Client(), nil }
	corsRuleStore(t, h, corsTestXML)
	r := corsRequest(http.MethodGet, "/bucket?cors", "")
	failedWriter := corsFailWriteWriter{}
	h.handleGatewayGetBucketCors(failedWriter, r, "bucket")
	// A successful decode/write was attempted; the failing client writer must not panic.
	w := httptest.NewRecorder()
	h.handleGatewayGetBucketCors(w, r, "bucket")
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "CORSConfiguration")
}

func TestCORSManagementGetStoredPolicySerializationError(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return newMockS3Client(), nil }
	h.corsStore = corsFixedStore{cfg: &CORSConfiguration{Rules: []CORSRule{{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET"}, AllowedHeaders: []string{"bad header"}}}}}
	w := httptest.NewRecorder()
	r := corsRequest(http.MethodGet, "/bucket?cors", "")
	h.handleGatewayGetBucketCors(w, r, "bucket")
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "<Code>InternalError</Code>")
}

func TestCORSManagementGetBucketProbeAndStoreFailures(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	backend.errors["bucket/list"] = &mockAPIError{code: "NoSuchBucket", message: "missing"}
	w := httptest.NewRecorder()
	h.serveGatewayCORSManagement(w, corsRequest(http.MethodGet, "/bucket?cors", ""), "GetBucketCors", h.handleGatewayGetBucketCors)
	require.Equal(t, http.StatusNotFound, w.Code)
	delete(backend.errors, "bucket/list")
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer client.Close()
	h.corsStore = NewValkeyCORSStore(client)
	w = httptest.NewRecorder()
	h.serveGatewayCORSManagement(w, corsRequest(http.MethodGet, "/bucket?cors", ""), "GetBucketCors", h.handleGatewayGetBucketCors)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

type corsFixedStore struct {
	CORSStore
	cfg *CORSConfiguration
}

func (s corsFixedStore) Get(context.Context, string) (*CORSConfiguration, error) { return s.cfg, nil }
func (corsFixedStore) Put(context.Context, string, *CORSConfiguration) error     { return nil }
func (corsFixedStore) Delete(context.Context, string) error                      { return nil }
func (corsFixedStore) HealthCheck(context.Context) error                         { return nil }

type corsFailWriteWriter struct{ header http.Header }

func (w corsFailWriteWriter) Header() http.Header {
	if w.header == nil {
		return make(http.Header)
	}
	return w.header
}
func (corsFailWriteWriter) WriteHeader(int) {}
func (corsFailWriteWriter) Write([]byte) (int, error) {
	return 0, errors.New("injected client write failure")
}

type corsNoOptionalWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

type corsNoPushHijackWriter struct{ w http.ResponseWriter }

func (w corsNoPushHijackWriter) Header() http.Header            { return w.w.Header() }
func (w corsNoPushHijackWriter) WriteHeader(status int)         { w.w.WriteHeader(status) }
func (w corsNoPushHijackWriter) Write(data []byte) (int, error) { return w.w.Write(data) }

func (w *corsNoOptionalWriter) Header() http.Header { return w.header }
func (w *corsNoOptionalWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *corsNoOptionalWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(p)
}

func TestCORSGatewayDeleteBucketCors_StoreDeleteFailure(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	underlying := h.corsStore
	h.corsStore = corsDeleteFailureStore{CORSStore: underlying}
	backend := newMockS3Client()
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return backend, nil }
	r := corsRequest(http.MethodDelete, "/bucket?cors", "")
	w := httptest.NewRecorder()
	h.handleDeleteBucketCors(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Contains(t, w.Body.String(), "<Code>ServiceUnavailable</Code>")
	require.NotContains(t, w.Body.String(), "valkey")
}

func TestCORSGatewayDeleteBucketCors_ExistingBucketAndNilStore(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	h.corsStore = nil
	r := corsRequest(http.MethodDelete, "/bucket?cors", "")
	w := httptest.NewRecorder()
	h.handleDeleteBucketCors(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestCORSGatewayDeleteBucketCors_BackendProbeFailure(t *testing.T) {
	h, backend, _ := newCORSTestHandler(t)
	backend.errors["bucket/list"] = errors.New("temporary backend outage")
	w := httptest.NewRecorder()
	h.handleDeleteBucketCors(w, corsRequest(http.MethodDelete, "/bucket?cors", ""))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Contains(t, w.Body.String(), "ServiceUnavailable")
}

func TestCORSManagementRecorder_ImplicitWriteAndHeaderOnly(t *testing.T) {
	base := httptest.NewRecorder()
	wrapped := &corsManagementRecorder{ResponseWriter: base}
	n, err := wrapped.Write([]byte("body"))
	require.NoError(t, err)
	require.Equal(t, 4, n)
	require.Equal(t, http.StatusOK, base.Code)
	require.EqualValues(t, 4, wrapped.bytes)
	base2 := httptest.NewRecorder()
	wrapped2 := &corsManagementRecorder{ResponseWriter: base2}
	wrapped2.WriteHeader(http.StatusOK)
	wrapped2.WriteHeader(http.StatusInternalServerError)
	require.Equal(t, http.StatusOK, base2.Code)
}

func TestCORSManagementRecorder_NilOptionalInterfaces(t *testing.T) {
	base := httptest.NewRecorder()
	w := &corsManagementRecorder{ResponseWriter: base}
	w.Flush()
	require.Equal(t, http.StatusOK, base.Code)
	require.ErrorIs(t, w.Push("/asset", nil), http.ErrNotSupported)
	_, _, err := w.Hijack()
	require.ErrorIs(t, err, http.ErrNotSupported)
}

func TestCORSManagementRecorder_ReadFromFallbackDelegation(t *testing.T) {
	base := httptest.NewRecorder()
	wrapped := &corsManagementRecorder{ResponseWriter: corsNoPushHijackWriter{w: base}}
	n, err := wrapped.ReadFrom(strings.NewReader("fallback read"))
	require.NoError(t, err)
	require.EqualValues(t, len("fallback read"), n)
	require.Equal(t, "fallback read", base.Body.String())
	require.EqualValues(t, n, wrapped.bytes)
}

func TestCORSManagementRecorder_WriteHeaderAndStringAccounting(t *testing.T) {
	base := httptest.NewRecorder()
	w := &corsManagementRecorder{ResponseWriter: base}
	w.WriteHeader(http.StatusOK)
	w.WriteHeader(http.StatusInternalServerError)
	_, err := w.WriteString("written")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, base.Code)
	require.Equal(t, int64(len("written")), w.bytes)
}

func TestCORSManagementErrorMappingAndBodyLimits(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	for _, tc := range []struct {
		name       string
		body       string
		length     int64
		md5        string
		wantCode   string
		wantStatus int
	}{
		{"malformed XML body", "<broken", -1, "", "MalformedXML", http.StatusBadRequest},
		{"bad digest encoding", corsTestXML, -1, "not-base64", "InvalidDigest", http.StatusBadRequest},
		{"bad digest value", corsTestXML, -1, base64.StdEncoding.EncodeToString([]byte("0123456789abcdef")), "BadDigest", http.StatusBadRequest},
		{"oversize declared", corsTestXML, maxCORSXMLBytes + 1, "", "EntityTooLarge", http.StatusRequestEntityTooLarge},
		{"oversize body", strings.Repeat("x", maxCORSXMLBytes+1), -1, "", "EntityTooLarge", http.StatusRequestEntityTooLarge},
		{"unknown XML child", `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><Unknown>x</Unknown></CORSRule></CORSConfiguration>`, -1, "", "MalformedXML", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := corsRequest(http.MethodPut, "/bucket?cors", tc.body)
			r.ContentLength = tc.length
			if tc.md5 != "" {
				r.Header.Set("Content-MD5", tc.md5)
			}
			w := httptest.NewRecorder()
			h.serveGatewayCORSManagement(w, r, "PutBucketCors", h.handleGatewayPutBucketCors)
			require.Equal(t, tc.wantStatus, w.Code)
			require.Contains(t, w.Body.String(), tc.wantCode)
		})
	}
}

func TestCORSManagementDigestAndBodyLimitBranches(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	for _, tc := range []struct {
		body   []byte
		digest string
		want   string
	}{
		{[]byte(corsTestXML), "%%%", "InvalidDigest"},
		{[]byte(corsTestXML), base64.StdEncoding.EncodeToString([]byte("bad")), "InvalidDigest"},
		{[]byte(corsTestXML), "", ""},
	} {
		r := httptest.NewRequest(http.MethodPut, "/bucket?cors", bytes.NewReader(tc.body))
		r = mux.SetURLVars(r, map[string]string{"bucket": "bucket"})
		if tc.digest != "" {
			r.Header.Set("Content-MD5", tc.digest)
		}
		if tc.want == "" {
			sum := md5.Sum(tc.body)
			r.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
		}
		w := httptest.NewRecorder()
		h.serveGatewayCORSManagement(w, r, "PutBucketCors", h.handleGatewayPutBucketCors)
		if tc.want != "" {
			require.Contains(t, w.Body.String(), tc.want)
		} else {
			require.Equal(t, http.StatusOK, w.Code)
		}
	}
	oversize := httptest.NewRequest(http.MethodPut, "/bucket?cors", strings.NewReader(strings.Repeat("x", maxCORSXMLBytes+1)))
	oversize = mux.SetURLVars(oversize, map[string]string{"bucket": "bucket"})
	oversize.ContentLength = -1
	w := httptest.NewRecorder()
	h.serveGatewayCORSManagement(w, oversize, "PutBucketCors", h.handleGatewayPutBucketCors)
	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestCORSMiddleware_StoreNotFoundAndRuleMismatchDoNotGrant(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	h := &Handler{config: &config.Config{CORS: config.CORSConfig{Mode: "gateway"}}, corsStore: store}
	for _, tc := range []struct {
		name, origin, method string
		store                bool
	}{
		{"missing", "https://app.example.com", http.MethodGet, false},
		{"method mismatch", "https://app.example.com", http.MethodDelete, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mr.FlushAll()
			if tc.store {
				corsRuleStore(t, h, corsTestXML)
			}
			r := httptest.NewRequest(tc.method, "/bucket/key", nil)
			r.Header.Set("Origin", tc.origin)
			w := httptest.NewRecorder()
			CORSMiddleware(h.config.CORS, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, r)
			require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
			require.Contains(t, w.Header().Get("Vary"), "Origin")
		})
	}
}

func TestCORSMiddleware_ExplicitPreflightDecisionAndBucketPathGuard(t *testing.T) {
	base := httptest.NewRecorder()
	preflight := &corsPreflightDecision{}
	req := httptest.NewRequest(http.MethodOptions, "/bucket", nil)
	req = mux.SetURLVars(req, map[string]string{"bucket": "bucket"})
	ctx := context.WithValue(req.Context(), corsPreflightContextKey{}, preflight)
	wrapped := &corsResponseWriter{ResponseWriter: base, request: req.WithContext(ctx), decision: &corsResponseDecision{preflight: preflight, addVary: true}}
	wrapped.Header().Set("Access-Control-Allow-Origin", "*")
	wrapped.WriteHeader(http.StatusForbidden)
	require.Empty(t, base.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, base.Header().Get("Vary"), "Access-Control-Request-Method")
	for _, path := range []string{"/", "/admin/health", "/metrics"} {
		require.False(t, isCORSPath(httptest.NewRequest(http.MethodGet, path, nil)), path)
	}
	require.True(t, isCORSPath(httptest.NewRequest(http.MethodGet, "/bucket/a//b", nil)), "repeated key slashes remain in S3 CORS scope")
	require.True(t, isCORSPath(mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), map[string]string{"bucket": "bucket"})))
}

func TestCORSMiddleware_ValidPreflightPolicyRetention(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	h.config.CORS.AllowCredentials = true
	r := httptest.NewRequest(http.MethodOptions, "/bucket", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	r.Header.Set("Access-Control-Request-Headers", "content-type")
	base := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(base, r)
	require.Equal(t, http.StatusOK, base.Code)
	require.Equal(t, "https://app.example.com", base.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "true", base.Header().Get("Access-Control-Allow-Credentials"))
	require.Equal(t, "PUT", base.Header().Get("Access-Control-Allow-Methods"))
	require.Equal(t, "content-type", base.Header().Get("Access-Control-Allow-Headers"))
	require.Equal(t, "ETag", base.Header().Get("Access-Control-Expose-Headers"))
	require.Equal(t, "3600", base.Header().Get("Access-Control-Max-Age"))
}

func TestCORSMiddleware_ValidPreflightKeepsHandlerPolicy(t *testing.T) {
	h, _, _ := newCORSTestHandler(t)
	corsRuleStore(t, h, corsTestXML)
	r := httptest.NewRequest(http.MethodOptions, "/bucket", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	r.Header.Set("Access-Control-Request-Headers", "content-type")
	base := httptest.NewRecorder()
	CORSMiddleware(h.config.CORS, h.corsStore, h.logger)(http.HandlerFunc(h.handleCORSPreflight)).ServeHTTP(base, r)
	require.Equal(t, http.StatusOK, base.Code)
	require.Equal(t, "https://app.example.com", base.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "PUT", base.Header().Get("Access-Control-Allow-Methods"))
	require.Equal(t, "content-type", base.Header().Get("Access-Control-Allow-Headers"))
	require.Equal(t, "ETag", base.Header().Get("Access-Control-Expose-Headers"))
	require.Contains(t, base.Header().Get("Vary"), "Access-Control-Request-Headers")
}

func TestCORSMiddleware_OptionsEarlyAuthResponseStripsWithoutOrigin(t *testing.T) {
	base := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodOptions, "/bucket", nil)
	w := &corsResponseWriter{ResponseWriter: base, request: r, decision: &corsResponseDecision{preflight: &corsPreflightDecision{}, addVary: true}}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusForbidden)
	require.Empty(t, base.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, base.Header().Get("Vary"), "Access-Control-Request-Method")
}

func TestParseRequestedCORSHeaders_AllowsEmptyAndRejectsDuplicateOrInjection(t *testing.T) {
	headers, ok := parseRequestedCORSHeaders(nil)
	require.True(t, ok)
	require.Empty(t, headers)
	_, ok = parseRequestedCORSHeaders([]string{"x-safe, bad header"})
	require.False(t, ok)
	_, ok = parseRequestedCORSHeaders([]string{"x-safe", "x-other"})
	require.False(t, ok)
}

type corsDeleteFailureStore struct{ CORSStore }

func (corsDeleteFailureStore) Delete(context.Context, string) error {
	return errors.New("injected CORS delete failure")
}

type trackingCORSBody struct{ closed *atomic.Bool }

func (b *trackingCORSBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b *trackingCORSBody) Close() error             { b.closed.Store(true); return nil }
