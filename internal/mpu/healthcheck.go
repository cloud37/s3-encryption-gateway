package mpu

import (
	"context"
	"sync"
	"time"
)

const defaultHealthCheckInterval = 30 * time.Second

type healthChecker interface {
	HealthCheck(context.Context) error
}

// StartHealthCheck starts a background liveness probe for the state store.
// The initial probe runs synchronously so the caller can publish an accurate
// gauge before serving traffic. The returned stop function is idempotent.
func StartHealthCheck(ctx context.Context, store healthChecker, interval time.Duration, observe func(bool)) func() {
	if interval <= 0 {
		interval = defaultHealthCheckInterval
	}

	probe := func() {
		hctx, cancel := context.WithTimeout(ctx, time.Second)
		err := store.HealthCheck(hctx)
		cancel()
		if observe != nil {
			observe(err == nil)
		}
	}
	probe()

	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				probe()
			case <-stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			close(stopCh)
			<-doneCh
		})
	}
}
