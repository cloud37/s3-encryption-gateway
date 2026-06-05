// Package perfguard provides CI-gated quality checks for V1.0-PERF-1
// scale and throughput guidance documentation.
//
// These tests run under the default `go test ./...` (no build tag required).
package perfguard

import (
	"os"
	"strings"
	"testing"
)

// TestSLOSummaryMinioNoTBD ensures that the MinIO column in the V0.6-QA-1
// SLO annex has been populated with measured values (no "TBD" placeholder).
// Garage, RustFS, and SeaweedFS may remain TBD until the full
// performance-baseline CI workflow runs on main.
//
// V1.0-PERF-1 Plan SS6 (Test Strategy), Gap 2.
func TestSLOSummaryMinioNoTBD(t *testing.T) {
	const path = "../../docs/perf/v0.6-qa-1/slo-summary.md"

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	// Look through all table rows that contain "MinIO".
	// The MinIO column is the first data column in every table.
	content := string(data)
	var tbdLines []string
	for _, line := range strings.Split(content, "\n") {
		// Only check table rows (those starting with "|") that reference MinIO.
		if strings.HasPrefix(line, "|") && strings.Contains(line, "MinIO") && strings.Contains(line, "TBD") {
			tbdLines = append(tbdLines, line)
		}
	}

	if len(tbdLines) > 0 {
		t.Errorf("MinIO column still has %d TBD value(s):\n%s",
			len(tbdLines),
			strings.Join(tbdLines, "\n"))
	}
}

// TestPerfCorpusNotEmpty ensures the docs/perf/v1.0-perf-1/ directory contains
// NDJSON files for all four named load profiles.
//
// V1.0-PERF-1 Plan §6 (Test Strategy).
func TestPerfCorpusNotEmpty(t *testing.T) {
	required := []string{
		"../../docs/perf/v1.0-perf-1/smoke.ndjson",
		"../../docs/perf/v1.0-perf-1/soak.ndjson",
		"../../docs/perf/v1.0-perf-1/spike.ndjson",
		"../../docs/perf/v1.0-perf-1/high-throughput.ndjson",
	}

	for _, path := range required {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("missing required profile output: %s (%v)", path, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("profile output is empty: %s", path)
		}
	}
}
