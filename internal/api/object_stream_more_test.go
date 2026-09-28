package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestWriteObjectDecryptError_ConfigurationMismatchCanonicalPath(t *testing.T) {
	registry := prometheus.NewRegistry()
	h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry)}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	w := httptest.NewRecorder()
	h.writeObjectDecryptError(w, req, "GET", "bucket", "key", crypto.ErrEncryptedObjectInBypassBucket, time.Now())
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "EncryptionConfigurationMismatch") {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	if got := metricSample(t, registry, "s3_operation_errors_total", `operation="GET"`, `error_type="EncryptionConfigurationMismatch"`); got != 1 {
		t.Fatalf("S3 error metric=%v, want one; metrics=%s", got, metricsText(t, registry))
	}
	if got := metricSample(t, registry, "encryption_errors_total", `operation="decrypt"`, `error_type="decryption_failed"`); got != 1 {
		t.Fatalf("decrypt failure metric=%v, want one", got)
	}
}

func metricsText(t *testing.T, registry *prometheus.Registry) string {
	t.Helper()
	w := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return w.Body.String()
}
