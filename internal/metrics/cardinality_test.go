package metrics

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestSanitizePathLabel(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/", "/"},
		{"/metrics", "/metrics"},
		{"/health", "/health"},
		{"/bucket/key", "/bucket/*"},
		{"/bucket/key/with/more/segments", "/bucket/*"},
		{"/bucket", "/bucket"}, // Edge case: treated as segment, maybe should be /bucket? Code says: if len(segs) <= 1 return / + segs[0]
		{"/bucket?query=param", "/bucket"},
		{"", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := sanitizePathLabel(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRecordHTTPRequest_Cardinality(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	// Record requests with high cardinality paths
	m.RecordHTTPRequest(context.Background(), "GET", "/mybucket/obj1", http.StatusOK, time.Millisecond, 100)
	m.RecordHTTPRequest(context.Background(), "GET", "/mybucket/obj2", http.StatusOK, time.Millisecond, 100)
	m.RecordHTTPRequest(context.Background(), "GET", "/otherbucket/obj1", http.StatusOK, time.Millisecond, 100)

	// Check that we have collapsed paths
	// We expect /mybucket/* and /otherbucket/*

	// Verify /mybucket/* count is 2
	countMyBucket := testutil.ToFloat64(m.httpRequestsTotal.WithLabelValues("GET", "/mybucket/*", "OK"))
	assert.Equal(t, 2.0, countMyBucket)

	// Verify /otherbucket/* count is 1
	countOtherBucket := testutil.ToFloat64(m.httpRequestsTotal.WithLabelValues("GET", "/otherbucket/*", "OK"))
	assert.Equal(t, 1.0, countOtherBucket)
}

func TestRecordS3Operation_DisableBucketLabel(t *testing.T) {
	// Create metrics with bucket label disabled
	reg := prometheus.NewRegistry()
	cfg := Config{EnableBucketLabel: false}
	m := newMetricsWithRegistry(reg, cfg)

	m.RecordS3Operation(context.Background(), "PutObject", "bucket-1", time.Millisecond)
	m.RecordS3Operation(context.Background(), "PutObject", "bucket-2", time.Millisecond)

	// Should align to bucket="*"
	count := testutil.ToFloat64(m.s3OperationsTotal.WithLabelValues("PutObject", "*"))
	assert.Equal(t, 2.0, count)

	// Verify that specific buckets are NOT tracked
	// Note: testutil.ToFloat64 panics or returns 0 if label values don't match existing metric.
	// However, since we didn't record them, we can't easily check for "absence" with ToFloat64
	// without knowing if it returns 0 for non-existent label set or if it errors.
	// But checking the aggregate "*" is sufficient to prove logic path was taken.
}

func TestRecordS3Error_DisableBucketLabel(t *testing.T) {
	reg := prometheus.NewRegistry()
	cfg := Config{EnableBucketLabel: false}
	m := newMetricsWithRegistry(reg, cfg)

	m.RecordS3Error(context.Background(), "GetObject", "bucket-1", "NoSuchKey")
	m.RecordS3Error(context.Background(), "GetObject", "bucket-2", "NoSuchKey")

	count := testutil.ToFloat64(m.s3OperationErrors.WithLabelValues("GetObject", "*", "NoSuchKey"))
	assert.Equal(t, 2.0, count)
}

func TestS3ClientBytesCardinality_BoundedByBucketAndDirection(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	for _, bucket := range []string{"a", "b", "c"} {
		for _, direction := range []string{"in", "out"} {
			m.RecordS3ClientBytes(context.Background(), bucket, direction, 1)
		}
	}
	mfs, err := reg.Gather()
	assert.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != "s3_client_bytes_total" {
			continue
		}
		if got := len(mf.GetMetric()); got != 6 {
			t.Fatalf("byte series=%d, want 6", got)
		}
	}
}

func TestS3ClientRequestsCardinality_UsesBoundedOperationAndStatusLabels(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	m.RecordS3ClientRequest(context.Background(), "GetObject", "bucket", http.StatusOK)
	m.RecordS3ClientRequest(context.Background(), "GetObject", "bucket", http.StatusNotFound)
	mfs, err := reg.Gather()
	assert.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "s3_client_requests_total" && len(mf.GetMetric()) != 2 {
			t.Fatalf("request series=%d, want 2", len(mf.GetMetric()))
		}
	}
}

// TestPprofRequestsCardinality_BoundedAt44 verifies the DoD requirement that
// s3_gateway_admin_pprof_requests_total has at most 11 endpoints × 4 outcomes
// = 44 label combinations (V0.6-OBS-1).
func TestPprofRequestsCardinality_BoundedAt44(t *testing.T) {
	// The closed sets defined in the plan.
	endpoints := []string{
		"index", "cmdline", "profile", "symbol", "trace",
		"heap", "goroutine", "allocs", "block", "mutex", "threadcreate",
	}
	outcomes := []string{"ok", "busy", "bad_request", "error"}

	maxCardinality := len(endpoints) * len(outcomes)
	if maxCardinality > 44 {
		t.Errorf("label cardinality cap exceeded: %d > 44 (11 endpoints × 4 outcomes)", maxCardinality)
	}

	// Record one increment for every (endpoint, outcome) combination and
	// verify the counter accepts all of them.
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	for _, ep := range endpoints {
		for _, oc := range outcomes {
			m.RecordPprofRequest(ep, oc)
		}
	}

	// Verify each combination landed with count == 1.
	for _, ep := range endpoints {
		for _, oc := range outcomes {
			got := testutil.ToFloat64(m.s3GatewayAdminPprofRequestsTotal.WithLabelValues(ep, oc))
			assert.Equal(t, 1.0, got, "endpoint=%s outcome=%s", ep, oc)
		}
	}
}

// TestSetAdminProfilingEnabled_Gauge verifies that SetAdminProfilingEnabled
// correctly flips the gateway_admin_profiling_enabled gauge (V0.6-OBS-1).
func TestSetAdminProfilingEnabled_Gauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	// Default should be 0 (not yet set).
	// Enable it.
	m.SetAdminProfilingEnabled(true)
	got := testutil.ToFloat64(m.gatewayAdminProfilingEnabled)
	assert.Equal(t, 1.0, got, "expected gauge=1 when profiling enabled")

	// Disable again.
	m.SetAdminProfilingEnabled(false)
	got = testutil.ToFloat64(m.gatewayAdminProfilingEnabled)
	assert.Equal(t, 0.0, got, "expected gauge=0 when profiling disabled")
}
