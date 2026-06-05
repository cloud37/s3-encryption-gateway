package crypto

import "sync"

// Package-level callback variables for KMS metrics.
//
// These avoid a circular import between internal/crypto and internal/metrics
// (internal/metrics/test imports internal/crypto, which would create a cycle
// if internal/crypto also imported internal/metrics).
//
// The functions are set by cmd/server/main.go at startup. If nil, metric
// recording is a no-op.
//
// All callbacks are protected by metricsMu to allow safe concurrent read from
// the decorator hot paths and safe write from the Set*Observer setters
// (called during test cleanup or server startup).

var (
	metricsMu sync.RWMutex

	recordKMSDEKCacheHitFn      func(provider string)
	recordKMSDEKCacheMissFn     func(provider string)
	setKMSCircuitBreakerStateFn func(provider string, state int)
	recordKMSRetryAttemptFn     func(provider, operation, outcome string)
	setKMSHealthyFn             func(provider string, healthy bool)
)

func getRecordKMSDEKCacheHitFn() func(provider string) {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return recordKMSDEKCacheHitFn
}

func getRecordKMSDEKCacheMissFn() func(provider string) {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return recordKMSDEKCacheMissFn
}

func getSetKMSCircuitBreakerStateFn() func(provider string, state int) {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return setKMSCircuitBreakerStateFn
}

func getRecordKMSRetryAttemptFn() func(provider, operation, outcome string) {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return recordKMSRetryAttemptFn
}

func getSetKMSHealthyFn() func(provider string, healthy bool) {
	metricsMu.RLock()
	defer metricsMu.RUnlock()
	return setKMSHealthyFn
}

// SetKMSDEKCacheHitObserver wires the DEK cache hit counter callback.
func SetKMSDEKCacheHitObserver(fn func(provider string)) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	recordKMSDEKCacheHitFn = fn
}

// SetKMSDEKCacheMissObserver wires the DEK cache miss counter callback.
func SetKMSDEKCacheMissObserver(fn func(provider string)) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	recordKMSDEKCacheMissFn = fn
}

// SetKMSCircuitBreakerStateObserver wires the circuit-breaker state gauge callback.
func SetKMSCircuitBreakerStateObserver(fn func(provider string, state int)) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	setKMSCircuitBreakerStateFn = fn
}

// SetKMSRetryAttemptObserver wires the retry-attempt counter callback.
func SetKMSRetryAttemptObserver(fn func(provider, operation, outcome string)) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	recordKMSRetryAttemptFn = fn
}

// SetKMSHealthyObserver wires the KMS health gauge callback.
func SetKMSHealthyObserver(fn func(provider string, healthy bool)) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	setKMSHealthyFn = fn
}
