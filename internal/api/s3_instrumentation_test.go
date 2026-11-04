package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

func TestS3ResponseRecorder_ImplicitStatusOK(t *testing.T) {
	r := httptest.NewRecorder()
	w := &s3ResponseRecorder{ResponseWriter: r}
	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if w.StatusCode() != http.StatusOK || w.BytesWritten() != 5 {
		t.Fatalf("status=%d bytes=%d", w.StatusCode(), w.BytesWritten())
	}
}

func TestS3ResponseRecorder_FirstWriteHeaderWins(t *testing.T) {
	r := httptest.NewRecorder()
	w := &s3ResponseRecorder{ResponseWriter: r}
	w.WriteHeader(http.StatusCreated)
	w.WriteHeader(http.StatusBadGateway)
	if w.StatusCode() != http.StatusCreated || r.Code != http.StatusCreated {
		t.Fatalf("status=%d recorder=%d", w.StatusCode(), r.Code)
	}
}

func TestS3ResponseRecorder_PreservesOptionalInterfaces(t *testing.T) {
	r := httptest.NewRecorder()
	w := &s3ResponseRecorder{ResponseWriter: r}
	if _, ok := any(w).(http.Flusher); !ok {
		t.Fatal("missing Flusher")
	}
	if _, ok := any(w).(io.ReaderFrom); !ok {
		t.Fatal("missing ReaderFrom")
	}
	if got := w.Unwrap(); got != r {
		t.Fatal("Unwrap did not return underlying writer")
	}
}

type optionalResponseWriter struct {
	http.ResponseWriter
	flushed bool
	pushed  string
}

func (w *optionalResponseWriter) Flush() { w.flushed = true }
func (w *optionalResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	client, server := net.Pipe()
	_ = server.Close()
	return client, bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client)), nil
}
func (w *optionalResponseWriter) Push(target string, _ *http.PushOptions) error {
	w.pushed = target
	return nil
}

func TestS3ResponseRecorder_OptionalInterfacesDelegate(t *testing.T) {
	base := &optionalResponseWriter{ResponseWriter: httptest.NewRecorder()}
	w := &s3ResponseRecorder{ResponseWriter: base}
	w.Flush()
	if !base.flushed {
		t.Fatal("Flush was not delegated")
	}
	if err := w.Push("/asset", nil); err != nil || base.pushed != "/asset" {
		t.Fatalf("Push delegation: %v %q", err, base.pushed)
	}
	conn, _, err := w.Hijack()
	if err != nil {
		t.Fatalf("Hijack delegation: %v", err)
	}
	_ = conn.Close()
}

func TestS3ResponseRecorder_ReadFromCountsBytes(t *testing.T) {
	w := &s3ResponseRecorder{ResponseWriter: httptest.NewRecorder()}
	n, err := w.ReadFrom(strings.NewReader("reader-from"))
	if err != nil || n != 11 || w.BytesWritten() != 11 {
		t.Fatalf("ReadFrom n=%d err=%v bytes=%d", n, err, w.BytesWritten())
	}
}

type readerFromResponseWriter struct {
	http.ResponseWriter
	readFromBytes int64
}

func (w *readerFromResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	n, err := io.Copy(io.Discard, r)
	w.readFromBytes += n
	return n, err
}

func TestS3ResponseRecorder_ReadFromDelegates(t *testing.T) {
	base := &readerFromResponseWriter{ResponseWriter: httptest.NewRecorder()}
	w := &s3ResponseRecorder{ResponseWriter: base}
	n, err := w.ReadFrom(strings.NewReader("delegated"))
	if err != nil || n != 9 || w.BytesWritten() != 9 || base.readFromBytes != 9 {
		t.Fatalf("n=%d err=%v recorder=%d underlying=%d", n, err, w.BytesWritten(), base.readFromBytes)
	}
}

func TestS3ResponseRecorder_UnsupportedOptionalInterfaces(t *testing.T) {
	w := &s3ResponseRecorder{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := w.Hijack(); err != http.ErrNotSupported {
		t.Fatalf("Hijack err=%v", err)
	}
	if err := w.Push("/asset", nil); err != http.ErrNotSupported {
		t.Fatalf("Push err=%v", err)
	}
}

type partialResponseWriter struct{ http.ResponseWriter }

func (w *partialResponseWriter) Write(p []byte) (int, error) { return len(p) / 2, io.ErrShortWrite }

func TestS3Instrumentation_GetObjectPartialWriteCountsSuccessfulBytes(t *testing.T) {
	w := &s3ResponseRecorder{ResponseWriter: &partialResponseWriter{ResponseWriter: httptest.NewRecorder()}}
	n, err := w.Write([]byte("123456"))
	if n != 3 || err == nil || w.BytesWritten() != 3 {
		t.Fatalf("partial write n=%d err=%v bytes=%d", n, err, w.BytesWritten())
	}
}

func TestS3Instrumentation_GetObjectCountsActualPlaintextBytesOut(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)
	h := &Handler{metrics: m}
	r := mux.NewRouter()
	r.Handle("/{bucket}/{key}", h.instrumentS3("GetObject", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("plain")) })).Methods("GET")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/b/k", nil))
	if got := gatheredMetricValue(reg, `s3_client_bytes_total{bucket="b",direction="out"}`); got != 5 {
		t.Fatalf("bytes=%v", got)
	}
}

func TestS3Instrumentation_GetObjectRangeCountsOnlyWrittenRange(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)
	h := &Handler{metrics: m}
	r := mux.NewRouter()
	r.Handle("/{bucket}/{key}", h.instrumentS3("GetObject", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("range")) })).Methods("GET")
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/b/k", nil))
	if got := gatheredMetricValue(reg, `s3_client_bytes_total{bucket="b",direction="out"}`); got != 5 {
		t.Fatalf("range bytes=%v", got)
	}
}

func TestS3Instrumentation_PutObjectCountsActualPlaintextBytesIn(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)
	h := &Handler{metrics: m}
	r := mux.NewRouter()
	r.Handle("/{bucket}/{key}", h.instrumentS3("PutObject", func(_ http.ResponseWriter, req *http.Request) { _, _ = io.ReadAll(req.Body) })).Methods("PUT")
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/b/k", strings.NewReader("plain")))
	if got := gatheredMetricValue(reg, `s3_client_bytes_total{bucket="b",direction="in"}`); got != 5 {
		t.Fatalf("input bytes=%v", got)
	}
}

func TestS3Instrumentation_PutObjectStreamingAWSChunkedCountsDecodedBytes(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)
	h := &Handler{metrics: m}
	r := mux.NewRouter()
	r.Handle("/{bucket}/{key}", h.instrumentS3("PutObject", func(_ http.ResponseWriter, req *http.Request) {
		decoded := req.Body
		_, _ = io.ReadAll(decoded)
	})).Methods("PUT")
	// The verifier replaces the request body with its decoded spool before this
	// instrumentation boundary; exercise that boundary with the decoded bytes.
	req := httptest.NewRequest(http.MethodPut, "/b/k", strings.NewReader("hello"))
	r.ServeHTTP(httptest.NewRecorder(), req)
	if got := gatheredMetricValue(reg, `s3_client_bytes_total{bucket="b",direction="in"}`); got != 5 {
		t.Fatalf("decoded bytes=%v", got)
	}
}

type postRetryBackend struct {
	*mockS3Client
	putCalls      int
	putAttempts   int
	capturedWire  []byte
	retryWireSame bool
}

func (b *postRetryBackend) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *s3.ObjectLockInput, acl, full, read, readACP, writeACP string) (string, error) {
	b.putCalls++
	b.retryWireSame = true
	seeker, ok := reader.(io.Seeker)
	if !ok {
		return "", fmt.Errorf("retry body %T is not replayable", reader)
	}
	var captured []byte
	for attempt := 0; attempt < 2; attempt++ {
		b.putAttempts++
		body, err := io.ReadAll(reader)
		if err != nil {
			return "", err
		}
		if attempt == 0 {
			captured = append([]byte(nil), body...)
			b.capturedWire = append([]byte(nil), body...)
		} else if !bytes.Equal(body, captured) {
			b.retryWireSame = false
			return "", fmt.Errorf("backend retry body differs from first attempt")
		}
		if attempt == 0 {
			if _, err := seeker.Seek(0, io.SeekStart); err != nil {
				return "", err
			}
		}
	}
	return b.mockS3Client.PutObject(ctx, bucket, key, bytes.NewReader(captured), metadata, contentLength, tags, lock, acl, full, read, readACP, writeACP)
}

func (b *postRetryBackend) PutObjectWithOptions(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *s3.ObjectLockInput, acl, full, read, readACP, writeACP string, _ s3.ObjectPutOptions) (s3.PutObjectResult, error) {
	etag, err := b.PutObject(ctx, bucket, key, reader, metadata, contentLength, tags, lock, acl, full, read, readACP, writeACP)
	if err != nil {
		return s3.PutObjectResult{}, err
	}
	return s3.PutObjectResult{ETag: etag, VersionID: "retry-version"}, nil
}

func TestGH353PostInstrumentation_FileBytesOnce(t *testing.T) {
	for _, tc := range []struct {
		name   string
		extra  map[string]string
		conds  []string
		status int
	}{
		{name: "default 204", status: http.StatusNoContent},
		{name: "created 201", extra: map[string]string{"success_action_status": "201"}, conds: []string{`{"success_action_status":"201"}`}, status: http.StatusCreated},
		{name: "explicit 200", extra: map[string]string{"success_action_status": "200"}, conds: []string{`{"success_action_status":"200"}`}, status: http.StatusOK},
		{name: "redirect 303", extra: map[string]string{"success_action_redirect": "https://app.example/uploaded"}, conds: []string{`{"success_action_redirect":"https://app.example/uploaded"}`}, status: http.StatusSeeOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			backend := &postRetryBackend{mockS3Client: newMockS3Client()}
			h, chain := livePostChain(t, backend, registry)
			writer := &gh353AuditWriter{}
			h.auditLogger = audit.NewLogger(16, writer)
			cacheStore := cache.NewMemoryCache(1024, 8, time.Minute)
			if err := cacheStore.Set(context.Background(), "bucket", "test.jpg", []byte("preserved cache"), map[string]string{"owner": "prior"}, time.Minute); err != nil {
				t.Fatal(err)
			}
			h.cache = cacheStore
			file := "file byte metrics are counted once"
			request := livePostRequest(t, file, tc.extra, tc.conds)
			request.Header.Set("Origin", "https://denied.example")
			store := postMemoryCORSStore{configs: map[string]*CORSConfiguration{"bucket": {Rules: []CORSRule{{AllowedOrigins: []string{"https://app.example"}, AllowedMethods: []string{"POST"}}}}}}
			chain = CORSMiddleware(config.CORSConfig{Mode: "gateway"}, &store, logrus.New())(chain)
			response := httptest.NewRecorder()
			chain.ServeHTTP(response, request)
			if response.Code != tc.status || backend.putCalls != 1 {
				t.Fatalf("status=%d want=%d backend PutObject operations=%d body=%s", response.Code, tc.status, backend.putCalls, response.Body.String())
			}
			if backend.putAttempts != 2 || !backend.retryWireSame || len(backend.capturedWire) == 0 || string(backend.capturedWire) == "ciphertext" {
				t.Fatalf("retry must replay captured ciphertext: attempts=%d same=%t bytes=%d", backend.putAttempts, backend.retryWireSame, len(backend.capturedWire))
			}
			if response.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("denied origin received readable CORS grant: %v", response.Header())
			}
			if got := gatheredMetricValue(registry, `s3_client_bytes_total{bucket="bucket",direction="in"}`); got != float64(len(file)) {
				t.Fatalf("file-byte metric=%v want=%d (multipart framing must be excluded)", got, len(file))
			}
			if got := gatheredMetricValue(registry, `s3_client_requests_total{bucket="bucket",operation="PostObject",status_code="`+strconv.Itoa(tc.status)+`"}`); got != 1 {
				t.Fatalf("PostObject/status request ledger=%v want=1", got)
			}
			if got := gatheredMetricValue(registry, `s3_client_requests_total{bucket="bucket",operation="PutObject",status_code="200"}`); got != 0 {
				t.Fatalf("backend retry leaked into client operation counter=%v", got)
			}
			for _, tc := range []struct {
				operation string
				status    int
				want      float64
			}{{"PostObject", tc.status, 1}, {"PostObject", http.StatusInternalServerError, 0}} {
				name := fmt.Sprintf(`s3_client_requests_total{bucket="bucket",operation="%s",status_code="%d"}`, tc.operation, tc.status)
				if got := gatheredMetricValue(registry, name); got != tc.want {
					t.Fatalf("client request ledger %s=%v want=%v", name, got, tc.want)
				}
			}
			if got := gatheredMetricValue(registry, `s3_operations_total{bucket="bucket",operation="PostObject"}`); got != 1 {
				t.Fatalf("backend operation metric=%v want one logical PostObject", got)
			}
			if got := gatheredMetricValue(registry, `encryption_operations_total{operation="encrypt"}`); got != 1 {
				t.Fatalf("encryption metric=%v want=1", got)
			}
			if len(writer.events) != 1 || writer.events[0].Operation != "encrypt" || !writer.events[0].Success {
				t.Fatalf("encryption audit events=%+v want exactly one success", writer.events)
			}
			if strings.Contains(gatherMetrics(registry), "denied.example") || strings.Contains(gatherMetrics(registry), "app.example") {
				t.Fatal("origin was emitted as a metric label")
			}
			if _, ok := cacheStore.Get(context.Background(), "bucket", "test.jpg"); ok {
				t.Fatal("successful write did not invalidate the destination cache entry")
			}
		})
	}

	t.Run("checksum validation failure consumes file once and does not route to backend", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		backend := newMockS3Client()
		_, chain := livePostChain(t, backend, registry)
		file := "checksum failure after reading"
		request := livePostRequest(t, file, map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16))}, []string{fmt.Sprintf(`{"Content-MD5":%q}`, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 16)))})
		response := httptest.NewRecorder()
		chain.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || backend.putObjectCallCount != 0 {
			t.Fatalf("status=%d puts=%d body=%s", response.Code, backend.putObjectCallCount, response.Body.String())
		}
		if got := gatheredMetricValue(registry, `s3_client_bytes_total{bucket="bucket",direction="in"}`); got != float64(len(file)) {
			t.Fatalf("consumed file bytes=%v want=%d", got, len(file))
		}
		if got := gatheredMetricValue(registry, `s3_client_requests_total{bucket="bucket",operation="PostObject",status_code="400"}`); got != 1 {
			t.Fatalf("checksum failure route requests=%v want=1", got)
		}
	})

	t.Run("partial file read failure counts only delivered plaintext and preserves state", func(t *testing.T) {
		registry := prometheus.NewRegistry()
		backend := newMockS3Client()
		backend.objects["bucket/test.jpg"] = []byte("existing ciphertext")
		backend.metadata["bucket/test.jpg"] = map[string]string{"owner": "prior"}
		var observed atomic.Int64
		const delivered = 7
		file := "partial bytes before the injected failure"
		var wrapped atomic.Bool
		h, chain := livePostChainForCredentialAndObserver(t, backend, registry, config.GatewayCredential{
			AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite),
		}, func(r *http.Request) {
			if upload, ok := postUploadFromContext(r); ok && wrapped.CompareAndSwap(false, true) {
				upload.fileRead = &postInstrumentationFaultReader{reader: upload.fileRead, limit: delivered, observed: &observed}
			}
		})
		cacheStore := cache.NewMemoryCache(1024, 8, time.Minute)
		if err := cacheStore.Set(context.Background(), "bucket", "test.jpg", []byte("cached prior"), map[string]string{"owner": "prior"}, time.Minute); err != nil {
			t.Fatal(err)
		}
		h.cache = cacheStore
		manager := h.spoolManager.(*spoolManager)
		var acquisitions atomic.Int64
		h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions.Add(1); return backend, nil }
		request := livePostRequest(t, file, nil, nil)
		response := httptest.NewRecorder()
		chain.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || backend.putObjectCallCount != 0 || acquisitions.Load() != 0 {
			t.Fatalf("status=%d puts=%d acquisitions=%d body=%s", response.Code, backend.putObjectCallCount, acquisitions.Load(), response.Body.String())
		}
		if got := gatheredMetricValue(registry, `s3_client_bytes_total{bucket="bucket",direction="in"}`); got != delivered || observed.Load() != delivered {
			t.Fatalf("recorded delivered bytes=%d metric=%v want=%d", observed.Load(), got, delivered)
		}
		if got := gatheredMetricValue(registry, `s3_client_requests_total{bucket="bucket",operation="PostObject",status_code="400"}`); got != 1 {
			t.Fatalf("PostObject 400 ledger=%v", got)
		}
		if manager.CurrentBytes() != 0 {
			t.Fatalf("spool quota leaked: %d", manager.CurrentBytes())
		}
		entries, err := os.ReadDir(manager.tempDirectory())
		if err != nil || len(entries) != 0 {
			t.Fatalf("temporary spool remains: entries=%v err=%v", entries, err)
		}
		if _, ok := cacheStore.Get(context.Background(), "bucket", "test.jpg"); !ok || string(backend.objects["bucket/test.jpg"]) != "existing ciphertext" || backend.metadata["bucket/test.jpg"]["owner"] != "prior" {
			t.Fatal("partial read failure changed cached or stored destination state")
		}
	})
}

type postInstrumentationFaultReader struct {
	reader    io.Reader
	limit     int
	delivered int
	observed  *atomic.Int64
}

func (r *postInstrumentationFaultReader) Read(p []byte) (int, error) {
	remaining := r.limit - r.delivered
	if remaining <= 0 {
		return 0, errors.New("injected client file read failure")
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	n, err := r.reader.Read(p)
	r.delivered += n
	if n > 0 && r.observed != nil {
		r.observed.Add(int64(n))
	}
	if r.delivered >= r.limit {
		return n, errors.New("injected client file read failure")
	}
	return n, err
}

func gatherMetrics(reg *prometheus.Registry) string {
	r := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return r.Body.String()
}

func TestS3Instrumentation_UploadPartSDKRetryDoesNotDoubleCountInput(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)
	h := &Handler{metrics: m}
	r := mux.NewRouter()
	r.Handle("/{bucket}/{key}", h.instrumentS3("UploadPart", func(_ http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		_, _ = io.Copy(io.Discard, strings.NewReader(string(body)))
	})).Methods("PUT")
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/b/k", strings.NewReader("retry-safe")))
	if got := gatheredMetricValue(reg, `s3_client_bytes_total{bucket="b",direction="in"}`); got != 10 {
		t.Fatalf("input bytes=%v", got)
	}
}

func gatheredMetricValue(reg *prometheus.Registry, metric string) float64 {
	r := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(r.Body.String(), "\n") {
		if strings.HasPrefix(line, metric+" ") {
			var value float64
			_, _ = fmt.Sscanf(line, metric+" %f", &value)
			return value
		}
	}
	return 0
}

func TestS3Instrumentation_RecordsClientVisibleErrorStatusOnce(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)
	h := &Handler{metrics: m}
	router := mux.NewRouter()
	router.Handle("/{bucket}", h.instrumentS3("TestOperation", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("error"))
	})).Methods("GET")
	r := httptest.NewRequest(http.MethodGet, "/bucket", nil)
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, r)
	if resp.Code != http.StatusNotFound {
		t.Fatalf("status=%d", resp.Code)
	}
	metricsResponse := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := metricsResponse.Body.String()
	if !strings.Contains(body, `s3_client_requests_total{bucket="bucket",operation="TestOperation",status_code="404"} 1`) {
		t.Fatalf("missing request metric: %s", body)
	}
	if !strings.Contains(body, `s3_client_bytes_total{bucket="bucket",direction="out"} 5`) {
		t.Fatalf("missing output metric: %s", body)
	}
}

func TestS3Instrumentation_RecordsRequestBodyInput(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)
	h := &Handler{metrics: m}
	router := mux.NewRouter()
	router.Handle("/{bucket}", h.instrumentS3("DeleteObjects", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	})).Methods("POST")
	request := httptest.NewRequest(http.MethodPost, "/bucket?delete", strings.NewReader("<Delete/>"))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	metricsResponse := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metricsResponse.Body.String(), `s3_client_bytes_total{bucket="bucket",direction="in"} 9`) {
		t.Fatalf("missing input metric: %s", metricsResponse.Body.String())
	}
}

func TestS3OperationName_DistinguishesSpecializedRoutes(t *testing.T) {
	cases := []struct{ method, target, want string }{
		{http.MethodGet, "/bucket?uploads", "ListMultipartUploads"},
		{http.MethodOptions, "/bucket/key", "CORSPreflight"},
		{http.MethodGet, "/bucket/key?tagging", "GetObjectTagging"},
		{http.MethodPut, "/bucket?versioning", "PutBucketVersioning"},
		{http.MethodPost, "/bucket/key?select-type=2", "SelectObjectContent"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, tc.target, nil)
		r = mux.SetURLVars(r, map[string]string{"bucket": "bucket", "key": "key"})
		if got := s3OperationName(r); got != tc.want {
			t.Errorf("%s %s = %q, want %q", tc.method, tc.target, got, tc.want)
		}
	}
}

func TestS3Instrumentation_HealthRoutesDoNotEmitS3ClientMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	h := &Handler{metrics: metrics.NewMetricsWithRegistry(reg)}
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	for _, path := range []string{
		"/health", "/ready", "/readyz", "/live", "/livez",
		"/minio/health/live", "/minio/health/ready",
		"/health/live", "/health/ready",
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	}
	metricsResponse := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(metricsResponse.Body.String(), "s3_client_requests_total") || strings.Contains(metricsResponse.Body.String(), "s3_client_bytes_total") {
		t.Fatalf("system routes emitted S3 client metrics: %s", metricsResponse.Body.String())
	}
}
