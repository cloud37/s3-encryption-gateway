//go:build load

package api

import "testing"

// TestMPU_LargeObjectGoldenPath is the full-size issue #135 regression:
// 80 parts of 5 MiB, for a total of 400 MiB. Run with -tags=load.
func TestMPU_LargeObjectGoldenPath(t *testing.T) {
	runMPUMultipartRoundTrip(t, 80, 5*1024*1024)
}
