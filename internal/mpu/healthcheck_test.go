package mpu

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type healthCheckStore struct {
	mu    sync.Mutex
	err   error
	calls atomic.Int32
}

func (s *healthCheckStore) HealthCheck(context.Context) error {
	s.calls.Add(1)
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return nil
}

func TestStartHealthCheck_InitialAndPeriodicProbe(t *testing.T) {
	store := &healthCheckStore{}
	var mu sync.Mutex
	var observed []bool
	stop := StartHealthCheck(context.Background(), store, 10*time.Millisecond, func(healthy bool) {
		mu.Lock()
		observed = append(observed, healthy)
		mu.Unlock()
	})
	time.Sleep(25 * time.Millisecond)
	stop()
	stop()

	if got := store.calls.Load(); got < 2 {
		t.Fatalf("health checks = %d, want initial probe plus periodic probe", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(observed) < 2 || !observed[0] {
		t.Fatalf("observed health states = %v, want initial healthy state and periodic state", observed)
	}
}

func TestStartHealthCheck_ReportsFailureAndRecovery(t *testing.T) {
	store := &healthCheckStore{}
	store.mu.Lock()
	store.err = errors.New("valkey unavailable")
	store.mu.Unlock()
	var mu sync.Mutex
	var observed []bool
	stop := StartHealthCheck(context.Background(), store, 10*time.Millisecond, func(healthy bool) {
		mu.Lock()
		observed = append(observed, healthy)
		mu.Unlock()
	})
	store.mu.Lock()
	store.err = nil
	store.mu.Unlock()
	time.Sleep(25 * time.Millisecond)
	stop()

	mu.Lock()
	defer mu.Unlock()
	if len(observed) < 2 || observed[0] || !observed[len(observed)-1] {
		t.Fatalf("observed health states = %v, want failure followed by recovery", observed)
	}
}
