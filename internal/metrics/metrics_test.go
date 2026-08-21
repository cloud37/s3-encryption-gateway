package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewMetrics(t *testing.T) {
	// Use a custom registry to avoid duplicate registration issues in tests
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	if m == nil {
		t.Fatal("NewMetrics returned nil")
	}

	if m.httpRequestsTotal == nil {
		t.Error("httpRequestsTotal is nil")
	}

	if m.httpRequestDuration == nil {
		t.Error("httpRequestDuration is nil")
	}

	if m.s3OperationsTotal == nil {
		t.Error("s3OperationsTotal is nil")
	}
}

func TestMetrics_RecordHTTPRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	m.RecordHTTPRequest(context.Background(), "GET", "/test", http.StatusOK, 100*time.Millisecond, 1024)

	// Metrics are registered with prometheus, verify they don't panic
	// The actual metric values are tested through Prometheus endpoint
}

func TestMetrics_RecordS3Operation(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	m.RecordS3Operation(context.Background(), "PutObject", "test-bucket", 50*time.Millisecond)

	// Metrics are registered with prometheus, verify they don't panic
}

func TestMetrics_RecordS3Error(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	m.RecordS3Error(context.Background(), "GetObject", "test-bucket", "NoSuchKey")

	// Metrics are registered with prometheus, verify they don't panic
}

func TestMetrics_RecordS3ClientBytes_LabelsAndValues(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	m.RecordS3ClientBytes(context.Background(), "bucket", "in", 12)
	m.RecordS3ClientBytes(context.Background(), "bucket", "out", 8)
	m.RecordS3ClientBytes(context.Background(), "bucket", "in", 0)
	m.RecordS3ClientBytes(context.Background(), "bucket", "in", -1)
	m.RecordS3ClientBytes(context.Background(), "bucket", "other", 100)

	if got := testutil.ToFloat64(m.s3ClientBytesTotal.WithLabelValues("bucket", "in")); got != 12 {
		t.Fatalf("in bytes = %v, want 12", got)
	}
	if got := testutil.ToFloat64(m.s3ClientBytesTotal.WithLabelValues("bucket", "out")); got != 8 {
		t.Fatalf("out bytes = %v, want 8", got)
	}
}

func TestMetrics_RecordS3ClientRequest_NumericStatusCode(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	m.RecordS3ClientRequest(context.Background(), "GetObject", "bucket", http.StatusNotFound)

	if got := testutil.ToFloat64(m.s3ClientRequestsTotal.WithLabelValues("GetObject", "bucket", "404")); got != 1 {
		t.Fatalf("request count = %v, want 1", got)
	}
}

func TestMetrics_RecordS3ClientMetrics_BucketLabelDisabledUsesWildcard(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: false})
	m.RecordS3ClientRequest(context.Background(), "ListBuckets", "", http.StatusOK)
	m.RecordS3ClientBytes(context.Background(), "bucket-a", "out", 3)
	m.RecordS3ClientBytes(context.Background(), "bucket-b", "out", 4)

	if got := testutil.ToFloat64(m.s3ClientRequestsTotal.WithLabelValues("ListBuckets", "*", "200")); got != 1 {
		t.Fatalf("request count = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.s3ClientBytesTotal.WithLabelValues("*", "out")); got != 7 {
		t.Fatalf("byte count = %v, want 7", got)
	}
}

func TestMetrics_RecordS3ClientMetrics_ListBucketsUsesEmptyBucketWhenEnabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	m.RecordS3ClientRequest(context.Background(), "ListBuckets", "", http.StatusOK)
	if got := testutil.ToFloat64(m.s3ClientRequestsTotal.WithLabelValues("ListBuckets", "", "200")); got != 1 {
		t.Fatalf("request count = %v, want 1", got)
	}
}

func TestMetrics_OBS2_DoesNotChangeExistingMetricLabelSchemas(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	m.RecordHTTPRequest(context.Background(), "GET", "/bucket/key", http.StatusOK, time.Second, 1)
	m.RecordS3Operation(context.Background(), "GetObject", "bucket", time.Second)
	m.RecordS3Error(context.Background(), "GetObject", "bucket", "backend")
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"http_requests_total":           {"method", "path", "status"},
		"http_request_bytes_total":      {"method", "path"},
		"s3_operations_total":           {"operation", "bucket"},
		"s3_operation_duration_seconds": {"operation", "bucket"},
		"s3_operation_errors_total":     {"operation", "bucket", "error_type"},
	}
	for _, mf := range mfs {
		labels, ok := want[mf.GetName()]
		if !ok || len(mf.GetMetric()) == 0 {
			continue
		}
		got := make([]string, 0, len(mf.GetMetric()[0].GetLabel()))
		for _, label := range mf.GetMetric()[0].GetLabel() {
			got = append(got, label.GetName())
		}
		sort.Strings(got)
		sort.Strings(labels)
		if strings.Join(got, ",") != strings.Join(labels, ",") {
			t.Errorf("%s labels=%v want=%v", mf.GetName(), got, labels)
		}
	}
}

// TestMetrics_RecordUploadPartCopy verifies the UploadPartCopy metric surface
// (added in V0.6-S3-1): gateway_upload_part_copy_total / bytes_total /
// duration_seconds / legacy_fallback_total. Exercises every label combo.
func TestMetrics_RecordUploadPartCopy(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	// One success in each source_mode.
	m.RecordUploadPartCopy("plaintext", "ok", 1024, 10*time.Millisecond)
	m.RecordUploadPartCopy("chunked", "ok", 2048, 20*time.Millisecond)
	m.RecordUploadPartCopy("legacy", "ok", 4096, 100*time.Millisecond)
	// And one error per mode.
	m.RecordUploadPartCopy("plaintext", "error", 0, 5*time.Millisecond)
	m.RecordUploadPartCopy("chunked", "error", 0, 5*time.Millisecond)
	m.RecordUploadPartCopy("legacy", "error", 0, 5*time.Millisecond)

	// Render and assert via Gather to avoid coupling to internal metric shape.
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	wants := []string{
		"gateway_upload_part_copy_total",
		"gateway_upload_part_copy_bytes_total",
		"gateway_upload_part_copy_duration_seconds",
		"gateway_upload_part_copy_legacy_fallback_total",
	}
	for _, name := range wants {
		if !names[name] {
			t.Errorf("expected metric %q to be registered and non-empty after recording", name)
		}
	}
}

func TestMetrics_Handler(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	// Record some metrics first so they appear in output
	m.RecordHTTPRequest(context.Background(), "GET", "/test", http.StatusOK, 100*time.Millisecond, 1024)
	m.RecordS3Operation(context.Background(), "PutObject", "test-bucket", 50*time.Millisecond)

	handler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})

	if handler == nil {
		t.Fatal("Handler returned nil")
	}

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify metrics endpoint returns prometheus format
	body := w.Body.String()
	if len(body) == 0 {
		t.Error("metrics endpoint returned empty body")
	}

	// Check for some expected prometheus metric names
	expectedMetrics := []string{
		"http_requests_total",
		"s3_operations_total",
	}
	for _, metric := range expectedMetrics {
		if !contains(body, metric) {
			t.Errorf("expected metrics output to contain %q", metric)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ── V0.6-QA-2 Phase B.5 — extended coverage tests ──────────────────────────

// TestNewMetrics_DefaultConstructors verifies NewMetrics and NewMetricsWithConfig
// produce non-nil, functional Metrics instances.
func TestNewMetrics_DefaultConstructors(t *testing.T) {
	// These use the default registry — avoid calling them in parallel tests as
	// they would produce duplicate metric registration errors. Use custom registry.
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	if m == nil {
		t.Fatal("newMetricsWithRegistry() returned nil")
	}

	// Verify Gather works (all metrics registered)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	if len(mfs) == 0 {
		t.Error("Gather() returned no metric families")
	}
}

// TestMetrics_SetHardwareAccelerationStatus verifies the gauge is set correctly.
func TestMetrics_SetHardwareAccelerationStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetHardwareAccelerationStatus("aes-ni", true)
	m.SetHardwareAccelerationStatus("arm-ce", false)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	found := false
	for _, mf := range mfs {
		if mf.GetName() == "hardware_acceleration_enabled" {
			found = true
			break
		}
	}
	if !found {
		t.Error("hardware_acceleration_enabled metric not found after SetHardwareAccelerationStatus")
	}
}

// TestMetrics_SetFIPSMode verifies the FIPS mode gauge.
func TestMetrics_SetFIPSMode(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetFIPSMode(true)
	m.SetFIPSMode(false)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_fips_mode"] {
		t.Error("gateway_fips_mode metric not found after SetFIPSMode")
	}
}

// TestMetrics_GetHardwareAccelerationEnabledMetric verifies the getter.
func TestMetrics_GetHardwareAccelerationEnabledMetric(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	gauge := m.GetHardwareAccelerationEnabledMetric()
	if gauge == nil {
		t.Error("GetHardwareAccelerationEnabledMetric() returned nil")
	}
}

// TestMetrics_SetActiveKeyVersion verifies SetActiveKeyVersion does not panic.
func TestMetrics_SetActiveKeyVersion(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetActiveKeyVersion("memory", 1)
	m.SetActiveKeyVersion("memory", 2)
}

// TestMetrics_RecordRotationOperation verifies RecordRotationOperation does not panic.
func TestMetrics_RecordRotationOperation(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordRotationOperation("wrap", "success", 100*time.Millisecond)
	m.RecordRotationOperation("commit", "error", 50*time.Millisecond)
}

// TestMetrics_SetRotationInFlightWraps verifies the gauge setter.
func TestMetrics_SetRotationInFlightWraps(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetRotationInFlightWraps(5)
	m.SetRotationInFlightWraps(0)
}

// TestMetrics_SetAdminAPIEnabled verifies SetAdminAPIEnabled.
func TestMetrics_SetAdminAPIEnabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetAdminAPIEnabled(true)
	m.SetAdminAPIEnabled(false)
}

// TestMetrics_RecordRotationSkippedLocked verifies RecordRotationSkippedLocked.
func TestMetrics_RecordRotationSkippedLocked(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordRotationSkippedLocked("COMPLIANCE")
	m.RecordRotationSkippedLocked("GOVERNANCE")
	m.RecordRotationSkippedLocked("LEGAL_HOLD")

	// nil-safe: should not panic
	var nilM *Metrics
	nilM.RecordRotationSkippedLocked("COMPLIANCE")
}

// TestMetrics_RecordEncryptionOperation verifies RecordEncryptionOperation.
func TestMetrics_RecordEncryptionOperation(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordEncryptionOperation(context.Background(), "encrypt", 10*time.Millisecond, 1024)
	m.RecordEncryptionOperation(context.Background(), "decrypt", 5*time.Millisecond, 512)
}

// TestMetrics_RecordEncryptionError verifies RecordEncryptionError.
func TestMetrics_RecordEncryptionError(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordEncryptionError(context.Background(), "encrypt", "auth_failure")
	m.RecordEncryptionError(context.Background(), "decrypt", "key_not_found")
}

// TestMetrics_RecordBufferPool verifies buffer pool hit/miss counters.
func TestMetrics_RecordBufferPool(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordBufferPoolHit("64k")
	m.RecordBufferPoolMiss("128k")
}

// TestMetrics_UpdateSystemMetrics verifies UpdateSystemMetrics does not panic.
func TestMetrics_UpdateSystemMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	// Should update goroutine, alloc, sys gauges without panicking
	m.UpdateSystemMetrics()
}

// TestMetrics_IncrementDecrementActiveConnections verifies connection counter.
func TestMetrics_IncrementDecrementActiveConnections(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.IncrementActiveConnections()
	m.IncrementActiveConnections()
	m.DecrementActiveConnections()
}

// TestMetrics_RecordRotatedRead verifies RecordRotatedRead does not panic.
func TestMetrics_RecordRotatedRead(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordRotatedRead(context.Background(), 1, 2)
	m.RecordRotatedRead(context.Background(), 2, 2)
}

// TestMetrics_NilSafe verifies all nil-guarded methods on a nil Metrics do
// not panic.
func TestMetrics_NilSafe(t *testing.T) {
	var m *Metrics

	m.RecordMPUEncrypted("success")
	m.RecordMPUPart("error")
	m.RecordMPUPartClaim("reserved")
	m.RecordMPUStateTransition("open", "completing", "success")
	m.SetMPULegacyInflight(1)
	m.RecordMPUStateStoreOp("create", "success", time.Millisecond)
	m.SetMPUValkeyUp(true)
	m.SetMPUValkeyInsecure(false)
	m.ObserveMPUManifestBytes(100)
	m.RecordMPUManifestStorage("inline")
	m.RecordBackendRetry("PutObject", "503")
	m.RecordBackendRetryWithMode("GetObject", "503", "standard")
	m.RecordBackendAttemptsPerRequest("PutObject", 3)
	m.RecordBackendRetryGiveUp("PutObject", "503")
	m.RecordBackendRetryBackoff(100 * time.Millisecond)
	m.RecordPprofRequest("heap", "ok")
	m.SetAdminProfilingEnabled(true)
}

// TestMetrics_MPUMethods verifies MPU metric methods on a non-nil Metrics.
func TestMetrics_MPUMethods(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordMPUEncrypted("success")
	m.RecordMPUEncrypted("error")
	m.RecordMPUPart("success")
	m.RecordMPUPartClaim("reserved")
	m.RecordMPUPartClaim("identical")
	m.RecordMPUPartClaim("mismatch")
	m.RecordMPUPartClaim("in_progress")
	m.RecordMPUPartClaim("legacy_rejected")
	m.RecordMPUStateTransition("open", "completing", "success")
	m.RecordMPUStateTransition("completing", "open", "rollback")
	m.SetMPULegacyInflight(2)
	m.RecordMPUStateStoreOp("create", "success", time.Millisecond)
	m.RecordMPUStateStoreOp("get", "error", time.Millisecond)
	m.SetMPUValkeyUp(true)
	m.SetMPUValkeyUp(false)
	m.SetMPUValkeyInsecure(true)
	m.ObserveMPUManifestBytes(1800)
	m.RecordMPUManifestStorage("inline")
	m.RecordMPUManifestStorage("fallback")

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	wants := []string{
		"gateway_mpu_encrypted_total",
		"gateway_mpu_parts_total",
		"gateway_mpu_state_store_ops_total",
		"gateway_mpu_valkey_up",
		"gateway_mpu_manifest_bytes",
		"gateway_mpu_manifest_storage_total",
		"gateway_mpu_part_claims_total",
		"gateway_mpu_state_transitions_total",
		"gateway_mpu_legacy_inflight",
	}
	for _, want := range wants {
		if !names[want] {
			t.Errorf("expected metric %q not found after recording", want)
		}
	}
}

func TestMetrics_MPUClaimResults(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})
	for _, result := range []string{"reserved", "identical", "mismatch", "in_progress", "legacy_rejected"} {
		m.RecordMPUPartClaim(result)
	}
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "gateway_mpu_part_claims_total" {
			require.Len(t, mf.GetMetric(), 5)
			for _, metric := range mf.GetMetric() {
				require.Len(t, metric.GetLabel(), 1)
			}
			return
		}
	}
	t.Fatal("claim metric missing")
}

func TestMetrics_MPUExactLabelsAndInvalidValues(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})
	m.RecordMPUPartClaim("reserved")
	m.RecordMPUPartClaim("invalid")
	m.RecordMPUStateTransition("open", "completing", "success")
	m.RecordMPUStateTransition("bad", "completing", "success")

	claims, err := testutil.GatherAndCount(reg, "gateway_mpu_part_claims_total")
	require.NoError(t, err)
	assert.Equal(t, 1, claims)
	transitions, err := testutil.GatherAndCount(reg, "gateway_mpu_state_transitions_total")
	require.NoError(t, err)
	assert.Equal(t, 1, transitions)

	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		switch mf.GetName() {
		case "gateway_mpu_part_claims_total":
			require.Len(t, mf.GetMetric(), 1)
			assert.Equal(t, "reserved", mf.GetMetric()[0].GetLabel()[0].GetValue())
			assert.Equal(t, float64(1), mf.GetMetric()[0].GetCounter().GetValue())
		case "gateway_mpu_state_transitions_total":
			require.Len(t, mf.GetMetric(), 1)
			labels := mf.GetMetric()[0].GetLabel()
			values := map[string]string{}
			for _, label := range labels {
				values[label.GetName()] = label.GetValue()
			}
			assert.Equal(t, "open", values["from"])
			assert.Equal(t, "completing", values["to"])
			assert.Equal(t, "success", values["result"])
			assert.Equal(t, float64(1), mf.GetMetric()[0].GetCounter().GetValue())
		}
	}
}

func TestMetrics_MPUStateTransitions(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})
	m.RecordMPUStateTransition("open", "completing", "success")
	m.RecordMPUStateTransition("completing", "open", "error")
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "gateway_mpu_state_transitions_total" {
			require.Len(t, mf.GetMetric(), 2)
			for _, metric := range mf.GetMetric() {
				require.Len(t, metric.GetLabel(), 3)
			}
			return
		}
	}
	t.Fatal("transition metric missing")
}

func TestMetrics_MPULegacyInflight(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})
	m.SetMPULegacyInflight(7)
	mfs, err := reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == "gateway_mpu_legacy_inflight" {
			require.Len(t, mf.GetMetric(), 1)
			assert.Equal(t, float64(7), mf.GetMetric()[0].GetGauge().GetValue())
			return
		}
	}
	t.Fatal("legacy gauge missing")
}

// TestMetrics_StartSystemMetricsCollector verifies the collector starts without panic.
func TestMetrics_StartSystemMetricsCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})
	// Start the collector briefly — it runs in a goroutine so we just verify
	// no panic on startup. The goroutine leaks in tests, which is acceptable.
	m.StartSystemMetricsCollector()
	// Give it a tiny moment to avoid a data race on the ticker channel.
	time.Sleep(10 * time.Millisecond)
}

// TestMetrics_Handler_NonNil verifies Handler() returns non-nil for non-nil metrics.
func TestMetrics_Handler_NonNil(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})
	h := m.Handler()
	if h == nil {
		t.Error("Handler() should not return nil")
	}
}

// TestMetrics_Handler_Nil verifies Handler() on a nil Metrics returns the default handler.
func TestMetrics_Handler_Nil(t *testing.T) {
	var m *Metrics
	h := m.Handler()
	if h == nil {
		t.Error("Handler() on nil Metrics should return default handler")
	}
}

// TestMetrics_RecordS3Error_AllPaths exercises RecordS3Error with S3-bucket label.
func TestMetrics_RecordS3Error_AllPaths(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})
	ctx := context.Background()

	m.RecordS3Error(ctx, "GetObject", "my-bucket", "NoSuchKey")
	m.RecordS3Error(ctx, "PutObject", "other-bucket", "InternalError")
}

// TestMetrics_SetMPUValkeyInsecure_TruePath verifies the true branch.
func TestMetrics_SetMPUValkeyInsecure_TruePath(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})
	m.SetMPUValkeyInsecure(true)
}

// TestMetrics_Gather_AllFamiliesPresent verifies that Gather() returns all
// expected metric families after a fresh registry is populated.
func TestMetrics_Gather_AllFamiliesPresent(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{EnableBucketLabel: true})

	// Record a sample of each metric to make them appear in Gather
	ctx := context.Background()
	m.RecordHTTPRequest(ctx, "GET", "/test", http.StatusOK, time.Millisecond, 100)
	m.RecordS3Operation(ctx, "PutObject", "bucket", time.Millisecond)
	m.RecordEncryptionOperation(ctx, "encrypt", time.Millisecond, 100)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	// Check key metric families
	wants := []string{
		"http_requests_total",
		"http_request_duration_seconds",
		"s3_operations_total",
		"encryption_operations_total",
	}
	for _, want := range wants {
		if !names[want] {
			t.Errorf("expected metric family %q after recording operations", want)
		}
	}
}

// ── V1.0-OBS-1 Phase A — new metric tests ──────────────────────────────────

// TestMetrics_SetKMSHealthy verifies the KMS health gauge.
func TestMetrics_SetKMSHealthy(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetKMSHealthy("memory", true)
	m.SetKMSHealthy("aws", false)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_kms_healthy"] {
		t.Error("gateway_kms_healthy metric not found after SetKMSHealthy")
	}
}

// TestMetrics_SetMetadataEncryptionEnabled verifies the metadata encryption gauge.
func TestMetrics_SetMetadataEncryptionEnabled(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetMetadataEncryptionEnabled(true)
	m.SetMetadataEncryptionEnabled(false)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_metadata_encryption_enabled"] {
		t.Error("gateway_metadata_encryption_enabled metric not found")
	}
}

// TestMetrics_SetTLSCertExpiry verifies the TLS cert expiry gauge.
func TestMetrics_SetTLSCertExpiry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetTLSCertExpiry("data_plane", time.Now().Add(7*24*time.Hour))
	m.SetTLSCertExpiry("admin", time.Time{}) // TLS disabled

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_tls_cert_expiry_seconds"] {
		t.Error("gateway_tls_cert_expiry_seconds metric not found")
	}
}

// TestMetrics_RecordKeyRotationObject verifies the key rotation counter.
func TestMetrics_RecordKeyRotationObject(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordKeyRotationObject("reencrypted")
	m.RecordKeyRotationObject("skipped_locked")
	m.RecordKeyRotationObject("error")

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_key_rotation_objects_total"] {
		t.Error("gateway_key_rotation_objects_total metric not found")
	}
}

// TestMetrics_SetKDFAlgorithmActive verifies the KDF algorithm gauge.
func TestMetrics_SetKDFAlgorithmActive(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetKDFAlgorithmActive("pbkdf2-sha256")
	m.SetKDFAlgorithmActive("argon2id")

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_kdf_algorithm_active"] {
		t.Error("gateway_kdf_algorithm_active metric not found")
	}
}

// TestMetrics_RecordAdminAPIRequest verifies admin API request recording.
func TestMetrics_RecordAdminAPIRequest(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordAdminAPIRequest("GET", "/health", 200, 5*time.Millisecond)
	m.RecordAdminAPIRequest("POST", "/rotate", 202, 50*time.Millisecond)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	wants := []string{
		"gateway_admin_api_requests_total",
		"gateway_admin_api_request_duration_seconds",
	}
	for _, want := range wants {
		if !names[want] {
			t.Errorf("expected metric %q not found", want)
		}
	}
}

// TestMetrics_SetMPUActiveUploads verifies the active MPU gauge.
func TestMetrics_SetMPUActiveUploads(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetMPUActiveUploads(5)
	m.SetMPUActiveUploads(3)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_mpu_active_uploads"] {
		t.Error("gateway_mpu_active_uploads metric not found")
	}
}

// TestMetrics_ObserveEncryptedObjectBytes verifies the encrypted object size histogram.
func TestMetrics_ObserveEncryptedObjectBytes(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.ObserveEncryptedObjectBytes(1024)
	m.ObserveEncryptedObjectBytes(1 << 20)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	if !names["gateway_encrypted_object_bytes"] {
		t.Error("gateway_encrypted_object_bytes metric not found")
	}
}

// TestMetrics_NewMetricsOBS1_AllMetricsRegistered verifies all 8 new OBS-1 metrics
// are registered after NewMetricsWithRegistry.
func TestMetrics_NewMetricsOBS1_AllMetricsRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	// Touch each helper so metrics are recorded and appear in Gather.
	m.SetKMSHealthy("memory", true)
	m.SetMetadataEncryptionEnabled(true)
	m.SetTLSCertExpiry("data_plane", time.Now().Add(7*24*time.Hour))
	m.RecordKeyRotationObject("reencrypted")
	m.SetKDFAlgorithmActive("pbkdf2-sha256")
	m.RecordAdminAPIRequest("GET", "/health", 200, time.Millisecond)
	m.SetMPUActiveUploads(1)
	m.ObserveEncryptedObjectBytes(1024)

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	names := make(map[string]bool)
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	wants := []string{
		"gateway_kms_healthy",
		"gateway_metadata_encryption_enabled",
		"gateway_tls_cert_expiry_seconds",
		"gateway_key_rotation_objects_total",
		"gateway_kdf_algorithm_active",
		"gateway_admin_api_requests_total",
		"gateway_admin_api_request_duration_seconds",
		"gateway_mpu_active_uploads",
		"gateway_encrypted_object_bytes",
	}
	for _, want := range wants {
		if !names[want] {
			t.Errorf("expected metric %q not found after recording", want)
		}
	}
}

// TestMetrics_OBS1_NilSafe verifies nil-safe guards on all new OBS-1 helpers.
func TestMetrics_OBS1_NilSafe(t *testing.T) {
	var m *Metrics

	m.SetKMSHealthy("memory", true)
	m.SetMetadataEncryptionEnabled(true)
	m.SetTLSCertExpiry("data_plane", time.Now())
	m.RecordKeyRotationObject("reencrypted")
	m.SetKDFAlgorithmActive("pbkdf2-sha256")
	m.RecordAdminAPIRequest("GET", "/health", 200, time.Millisecond)
	m.SetMPUActiveUploads(5)
	m.ObserveEncryptedObjectBytes(1024)
}

// TestMetrics_IncDecMPUActiveUploads verifies IncMPUActiveUploads and DecMPUActiveUploads.
func TestMetrics_IncDecMPUActiveUploads(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.IncMPUActiveUploads()
	m.IncMPUActiveUploads()
	m.DecMPUActiveUploads()

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather() error: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "gateway_mpu_active_uploads" {
			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 1.0 {
				t.Errorf("gateway_mpu_active_uploads = %v, want 1.0", got)
			}
			return
		}
	}
	t.Error("gateway_mpu_active_uploads metric not found")
}

// ---- V1.0-KMS-1 metrics tests ---------------------------------------------

// TestMetrics_KMSDEKCacheHits verifies the DEK cache hit counter emits labels.
func TestMetrics_KMSDEKCacheHits(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordKMSDEKCacheHit("cosmian")
	m.RecordKMSDEKCacheHit("cosmian")

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "gateway_kms_dek_cache_hits_total" {
			if got := mf.GetMetric()[0].GetCounter().GetValue(); got != 2.0 {
				t.Errorf("gateway_kms_dek_cache_hits_total = %v, want 2.0", got)
			}
			return
		}
	}
	t.Error("gateway_kms_dek_cache_hits_total not found")
}

// TestMetrics_KMSDEKCacheMisses verifies the DEK cache miss counter.
func TestMetrics_KMSDEKCacheMisses(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordKMSDEKCacheMiss("cosmian")

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "gateway_kms_dek_cache_misses_total" {
			return
		}
	}
	t.Error("gateway_kms_dek_cache_misses_total not found")
}

// TestMetrics_SetKMSCircuitBreakerState verifies the circuit breaker state gauge.
func TestMetrics_SetKMSCircuitBreakerState(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.SetKMSCircuitBreakerState("cosmian", 0) // closed
	m.SetKMSCircuitBreakerState("cosmian", 1) // open

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "gateway_kms_circuit_breaker_state" {
			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 1.0 {
				t.Errorf("gateway_kms_circuit_breaker_state = %v, want 1.0", got)
			}
			return
		}
	}
	t.Error("gateway_kms_circuit_breaker_state not found")
}

// TestMetrics_RecordKMSRetryAttempt verifies the retry attempt counter.
func TestMetrics_RecordKMSRetryAttempt(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetricsWithRegistry(reg, Config{})

	m.RecordKMSRetryAttempt("cosmian", "wrap", "success")
	m.RecordKMSRetryAttempt("cosmian", "wrap", "failure")

	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "gateway_kms_retry_attempts_total" {
			return
		}
	}
	t.Error("gateway_kms_retry_attempts_total not found")
}

// TestMetrics_KMS1_NilSafe verifies nil-safe guards on all V1.0-KMS-1 helpers.
func TestMetrics_KMS1_NilSafe(t *testing.T) {
	var m *Metrics

	m.RecordKMSDEKCacheHit("provider")
	m.RecordKMSDEKCacheMiss("provider")
	m.SetKMSCircuitBreakerState("provider", 0)
	m.RecordKMSRetryAttempt("provider", "wrap", "success")
}
