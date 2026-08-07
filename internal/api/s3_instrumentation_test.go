package api

import (
	"io"
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
