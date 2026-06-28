package crypto

import (
	"testing"
	"time"
)

// TestOpenBaoTransitManager_Conformance runs the shared KeyManager contract
// suite against the OpenBao Transit adapter backed by the in-memory mock
// server, with no build tags required.
func TestOpenBaoTransitManager_Conformance(t *testing.T) {
	srv := newMockBaoServer(t)
	opts := ConformanceOptions{
		WrapUnwrapTimeout:  2 * time.Second,
		HealthCheckTimeout: 2 * time.Second,
		ConcurrencyCount:   64,
	}
	ConformanceSuite(t, func(t *testing.T) KeyManager {
		return newTestManager(t, srv)
	}, opts)
}

// TestOpenBaoTransitManager_Conformance_Rotation runs the optional rotation
// contract suite. addVersion is a no-op: OpenBao Transit mints the next version
// server-side during PromoteActiveVersion (via the rotate RPC), so no version
// needs to be pre-staged.
func TestOpenBaoTransitManager_Conformance_Rotation(t *testing.T) {
	srv := newMockBaoServer(t)
	ConformanceSuite_Rotation(t,
		func(t *testing.T) KeyManager { return newTestManager(t, srv) },
		func(t *testing.T, km KeyManager, version int) error { return nil },
		ConformanceOptions{WrapUnwrapTimeout: 2 * time.Second},
	)
}
