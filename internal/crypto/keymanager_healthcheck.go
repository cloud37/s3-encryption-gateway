package crypto

import (
	"context"
	"time"
)

// StartKMSHealthCheck starts a background goroutine that calls km.HealthCheck
// every interval and updates the gateway_kms_healthy Prometheus gauge via the
// callback registered by SetKMSHealthyObserver.
//
// It returns a stop function; the caller must invoke stop() on shutdown.
// If interval is 0, the goroutine is not started and stop is a no-op.
//
// An immediate probe fires synchronously before the goroutine is launched, so
// the gauge is set to a non-zero value at startup.
func StartKMSHealthCheck(ctx context.Context, km KeyManager, interval time.Duration) func() {
	// Initial probe — fire immediately so the gauge is non-zero at startup.
	probeOnce(ctx, km)

	if interval <= 0 {
		return func() {}
	}

	stopCh := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				probeOnce(ctx, km)
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return func() {
		close(stopCh)
	}
}

// probeOnce performs a single health check probe and records the result.
func probeOnce(ctx context.Context, km KeyManager) {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := km.HealthCheck(hctx)
	if setKMSHealthyFn != nil {
		setKMSHealthyFn(km.Provider(), err == nil)
	}
}
