package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestSpoolMetrics_BoundedGaugeAndRejectionReasons(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)
	m.SetSpoolBytes(7)
	m.RecordSpoolRejection("request_limit")
	m.RecordSpoolRejection("aggregate_limit")
	m.RecordSpoolRejection("path-or-bucket")
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range families {
		seen[f.GetName()] = true
		if f.GetName() == "s3_gateway_spool_rejections_total" {
			for _, sample := range f.GetMetric()[0:] {
				reason := sample.GetLabel()[0].GetValue()
				if reason != "request_limit" && reason != "aggregate_limit" {
					t.Fatalf("unbounded reason %q", reason)
				}
			}
		}
	}
	if !seen["s3_gateway_spool_bytes"] || !seen["s3_gateway_spool_rejections_total"] {
		t.Fatalf("spool metrics absent: %v", seen)
	}
}
