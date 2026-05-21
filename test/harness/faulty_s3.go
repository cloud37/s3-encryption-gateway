// Package harness provides test utilities for the s3-encryption-gateway.
// faulty_s3.go implements a FaultyRoundTripper that wraps http.RoundTripper
// and injects configurable faults for retry policy testing (V0.6-PERF-2 Phase A).
package harness

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"
)

// FaultClass enumerates the types of faults the injector can produce.
type FaultClass int

const (
	// FaultHTTPStatus injects a specific HTTP status code response.
	FaultHTTPStatus FaultClass = iota
	// FaultNetworkError injects a network-level error (e.g. io.EOF, ECONNRESET).
	FaultNetworkError
	// FaultLatency injects artificial latency before forwarding.
	FaultLatency
)

// FaultRule describes when and how to inject a fault.
type FaultRule struct {
	// Class is the type of fault.
	Class FaultClass
	// StatusCode is the HTTP status to return (used when Class == FaultHTTPStatus).
	StatusCode int
	// StatusBody is the response body for status faults (optional; defaults to a plausible S3 XML error).
	StatusBody string
	// RetryAfterSeconds, if > 0, adds a Retry-After header (valid for 429/503 status faults).
	RetryAfterSeconds int
	// NetworkErr is the error to return (used when Class == FaultNetworkError).
	// Defaults to io.EOF if nil.
	NetworkErr error
	// LatencyMin / LatencyMax define the range of artificial latency to add.
	LatencyMin time.Duration
	LatencyMax time.Duration
	// OperationFilter, if set, restricts this rule to HTTP requests whose path
	// contains one of the supplied substrings (case-insensitive).
	// An empty slice matches all operations.
	OperationFilter []string
	// ProbabilityPct is the fault injection probability in percent [0,100].
	// 0 means never inject; 100 means always inject.
	ProbabilityPct int
}

// FaultyRoundTripper wraps an http.RoundTripper and injects faults according
// to a deterministic, seedable RNG. It is safe for concurrent use.
//
// Usage:
//
//	faulty := harness.NewFaultyRoundTripper(http.DefaultTransport, 42, rules)
//	httpClient := &http.Client{Transport: faulty}
type FaultyRoundTripper struct {
	inner http.RoundTripper
	rules []FaultRule
	mu    sync.Mutex
	rng   *rand.Rand
}

// NewFaultyRoundTripper creates a FaultyRoundTripper that applies rules in order.
// seed is used to initialise the RNG so that tests are fully deterministic across
// multiple runs when the seed is fixed.
func NewFaultyRoundTripper(inner http.RoundTripper, seed int64, rules []FaultRule) *FaultyRoundTripper {
	return &FaultyRoundTripper{
		inner: inner,
		rules: rules,
		rng:   rand.New(rand.NewSource(seed)), // #nosec G404 //nolint:gosec // intentionally non-crypto
	}
}

// RoundTrip implements http.RoundTripper by optionally injecting a fault and
// then forwarding to the inner transport.
func (f *FaultyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for _, rule := range f.rules {
		if !f.matches(rule, req) {
			continue
		}
		f.mu.Lock()
		roll := f.rng.Intn(100)
		f.mu.Unlock()
		if roll >= rule.ProbabilityPct {
			continue
		}
		return f.inject(rule, req)
	}
	return f.inner.RoundTrip(req)
}

// matches reports whether rule applies to req.
func (f *FaultyRoundTripper) matches(rule FaultRule, req *http.Request) bool {
	if len(rule.OperationFilter) == 0 {
		return true
	}
	path := strings.ToLower(req.URL.Path + "?" + req.URL.RawQuery)
	for _, op := range rule.OperationFilter {
		if strings.Contains(path, strings.ToLower(op)) {
			return true
		}
	}
	return false
}

// inject applies the fault described by rule and returns the resulting
// response/error pair. For FaultLatency rules, it sleeps then forwards.
func (f *FaultyRoundTripper) inject(rule FaultRule, req *http.Request) (*http.Response, error) {
	switch rule.Class {
	case FaultHTTPStatus:
		body := rule.StatusBody
		if body == "" {
			body = defaultS3ErrorBody(rule.StatusCode)
		}
		resp := &http.Response{
			StatusCode: rule.StatusCode,
			Status:     fmt.Sprintf("%d %s", rule.StatusCode, http.StatusText(rule.StatusCode)),
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}
		resp.Header.Set("Content-Type", "application/xml")
		resp.Header.Set("x-amz-request-id", "FAULTINJECTED0000001")
		if rule.RetryAfterSeconds > 0 {
			resp.Header.Set("Retry-After", fmt.Sprintf("%d", rule.RetryAfterSeconds))
		}
		return resp, nil

	case FaultNetworkError:
		err := rule.NetworkErr
		if err == nil {
			err = io.EOF
		}
		return nil, err

	case FaultLatency:
		f.mu.Lock()
		var delay time.Duration
		if rule.LatencyMax > rule.LatencyMin && rule.LatencyMin >= 0 {
			window := int64(rule.LatencyMax - rule.LatencyMin)
			delay = rule.LatencyMin + time.Duration(f.rng.Int63n(window))
		} else {
			delay = rule.LatencyMin
		}
		f.mu.Unlock()
		select {
		case <-req.Context().Done():
			return nil, req.Context().Err()
		case <-time.After(delay):
		}
		return f.inner.RoundTrip(req)
	}
	return f.inner.RoundTrip(req)
}

// ErrConnectionReset is a synthetic ECONNRESET that the classifier should
// treat as retryable. Exposed for use in test assertions.
var ErrConnectionReset = syscall.ECONNRESET

// defaultS3ErrorBody returns a minimal AWS S3 XML error body for the given status.
func defaultS3ErrorBody(status int) string {
	switch status {
	case 429:
		return `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>SlowDown</Code><Message>Reduce your request rate.</Message><RequestId>FAULTINJECTED</RequestId></Error>`
	case 503:
		return `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>ServiceUnavailable</Code><Message>Service unavailable.</Message><RequestId>FAULTINJECTED</RequestId></Error>`
	case 500:
		return `<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>InternalError</Code><Message>Internal server error.</Message><RequestId>FAULTINJECTED</RequestId></Error>`
	default:
		return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>Error%d</Code><Message>Injected error %d.</Message><RequestId>FAULTINJECTED</RequestId></Error>`, status, status)
	}
}

// ThrottleRule returns a FaultRule that injects HTTP 429 (SlowDown) at the
// given probability. A helper for the most common benchmark scenario.
func ThrottleRule(probabilityPct int) FaultRule {
	return FaultRule{
		Class:          FaultHTTPStatus,
		StatusCode:     429,
		ProbabilityPct: probabilityPct,
	}
}

// UnavailableRule returns a FaultRule that injects HTTP 503 at the given probability.
func UnavailableRule(probabilityPct int) FaultRule {
	return FaultRule{
		Class:          FaultHTTPStatus,
		StatusCode:     503,
		ProbabilityPct: probabilityPct,
	}
}

// NetworkResetRule returns a FaultRule that injects syscall.ECONNRESET at the given probability.
func NetworkResetRule(probabilityPct int) FaultRule {
	return FaultRule{
		Class:          FaultNetworkError,
		NetworkErr:     ErrConnectionReset,
		ProbabilityPct: probabilityPct,
	}
}
