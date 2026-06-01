package crypto

// Package-level callback variables for KMS metrics.
//
// These avoid a circular import between internal/crypto and internal/metrics
// (internal/metrics/test imports internal/crypto, which would create a cycle
// if internal/crypto also imported internal/metrics).
//
// The functions are set by cmd/server/main.go at startup. If nil, metric
// recording is a no-op.

var (
	recordKMSDEKCacheHitFn     func(provider string)
	recordKMSDEKCacheMissFn    func(provider string)
	setKMSCircuitBreakerStateFn func(provider string, state int)
	recordKMSRetryAttemptFn    func(provider, operation, outcome string)
	setKMSHealthyFn             func(provider string, healthy bool)
)

// SetKMSDEKCacheHitObserver wires the DEK cache hit counter callback.
func SetKMSDEKCacheHitObserver(fn func(provider string)) {
	recordKMSDEKCacheHitFn = fn
}

// SetKMSDEKCacheMissObserver wires the DEK cache miss counter callback.
func SetKMSDEKCacheMissObserver(fn func(provider string)) {
	recordKMSDEKCacheMissFn = fn
}

// SetKMSCircuitBreakerStateObserver wires the circuit-breaker state gauge callback.
func SetKMSCircuitBreakerStateObserver(fn func(provider string, state int)) {
	setKMSCircuitBreakerStateFn = fn
}

// SetKMSRetryAttemptObserver wires the retry-attempt counter callback.
func SetKMSRetryAttemptObserver(fn func(provider, operation, outcome string)) {
	recordKMSRetryAttemptFn = fn
}

// SetKMSHealthyObserver wires the KMS health gauge callback.
func SetKMSHealthyObserver(fn func(provider string, healthy bool)) {
	setKMSHealthyFn = fn
}
