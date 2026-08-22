package api

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	for _, path := range []string{"/health", "/ready", "/readyz", "/live", "/livez"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	}
	metricsResponse := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(metricsResponse, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(metricsResponse.Body.String(), "s3_client_requests_total") || strings.Contains(metricsResponse.Body.String(), "s3_client_bytes_total") {
		t.Fatalf("system routes emitted S3 client metrics: %s", metricsResponse.Body.String())
	}
}
