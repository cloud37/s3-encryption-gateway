// Package admin — pprof handler registration for V0.6-OBS-1.
//
// This file owns all pprof wiring for the admin listener. It does NOT rely on
// the global http.DefaultServeMux side-effect (i.e. no blank import of
// net/http/pprof). Instead it wires the individual handler constructors
// exported by net/http/pprof directly onto the admin mux.
//
// Design rationale: Adkins et al., Building Secure and Reliable Systems
// (O'Reilly, 2020), Ch. 15 — debug surfaces must be authenticated,
// authorised, and audited. All three properties are inherited from the
// existing admin subsystem (bearer auth, rate limiter, audit).

package admin

import (
	"fmt"
	"net/http"
	"net/http/pprof"
	"runtime"
	"strconv"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// ProfilingMetrics is the subset of metrics.Metrics required by the pprof handlers.
// Keeping it as a narrow interface preserves testability and avoids a hard dep on
// internal/metrics from internal/admin.
type ProfilingMetrics interface {
	// RecordPprofRequest increments the bounded-cardinality counter
	// s3_gateway_admin_pprof_requests_total{endpoint, outcome}.
	RecordPprofRequest(endpoint, outcome string)
	// SetAdminProfilingEnabled sets the gateway_admin_profiling_enabled gauge.
	SetAdminProfilingEnabled(v bool)
}

// ProfilingAudit is the subset of audit.Logger required by the pprof handlers.
type ProfilingAudit interface {
	// LogAccessWithMetadata emits an audit event for each profile fetch.
	LogAccessWithMetadata(eventType, bucket, key, clientIP, userAgent, requestID string,
		success bool, err error, duration time.Duration, metadata map[string]interface{})
}

// pprofRoute maps a URL path suffix to the underlying net/http/pprof handler.
type pprofRoute struct {
	path    string
	handler http.Handler
}

// allPprofRoutes returns the full set of 11 pprof endpoint descriptors.
// We materialise these once so they can be used for both registration and
// testing the route table.
func allPprofRoutes() []pprofRoute {
	return []pprofRoute{
		{path: "/debug/pprof/", handler: http.HandlerFunc(pprof.Index)},
		{path: "/debug/pprof/cmdline", handler: http.HandlerFunc(pprof.Cmdline)},
		{path: "/debug/pprof/profile", handler: http.HandlerFunc(pprof.Profile)},
		{path: "/debug/pprof/symbol", handler: http.HandlerFunc(pprof.Symbol)},
		{path: "/debug/pprof/trace", handler: http.HandlerFunc(pprof.Trace)},
		{path: "/debug/pprof/heap", handler: pprof.Handler("heap")},
		{path: "/debug/pprof/goroutine", handler: pprof.Handler("goroutine")},
		{path: "/debug/pprof/allocs", handler: pprof.Handler("allocs")},
		{path: "/debug/pprof/block", handler: pprof.Handler("block")},
		{path: "/debug/pprof/mutex", handler: pprof.Handler("mutex")},
		{path: "/debug/pprof/threadcreate", handler: pprof.Handler("threadcreate")},
	}
}

// endpointLabel converts a /debug/pprof/... path to the short label used in
// metrics and audit events (e.g. "/debug/pprof/heap" → "heap").
func endpointLabel(path string) string {
	const prefix = "/debug/pprof/"
	if len(path) > len(prefix) {
		return path[len(prefix):]
	}
	// The index page itself.
	return "index"
}

// profilingHandler wraps an upstream pprof handler with:
//  1. admin.IsAdminRequest defence-in-depth assertion.
//  2. semaphore guard (long-running profile/trace only).
//  3. seconds= query-parameter validation (profile/trace only).
//  4. Prometheus counter increment.
//  5. Audit event emission.
type profilingHandler struct {
	endpoint  string // short label, e.g. "heap"
	upstream  http.Handler
	sem       chan struct{} // nil means no semaphore (fast endpoints)
	maxSecs   int
	hasSecs   bool // whether this endpoint honours ?seconds=
	metrics   ProfilingMetrics
	audit     ProfilingAudit
	logger    *logrus.Logger
}

func (h *profilingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Defence-in-depth: this handler must only be reached via the admin mux.
	if !IsAdminRequest(r) {
		h.logger.Error("pprof handler reached without admin context — wiring bug")
		http.Error(w, "internal error", http.StatusInternalServerError)
		h.metrics.RecordPprofRequest(h.endpoint, "error")
		return
	}

	// Validate seconds= for time-bounded profiles.
	if h.hasSecs {
		if secsStr := r.URL.Query().Get("seconds"); secsStr != "" {
			secs, err := strconv.Atoi(secsStr)
			if err != nil || secs < 1 || secs > h.maxSecs {
				msg := fmt.Sprintf("seconds must be an integer in [1, %d]", h.maxSecs)
				http.Error(w, msg, http.StatusBadRequest)
				h.metrics.RecordPprofRequest(h.endpoint, "bad_request")
				return
			}
		}
	}

	// Semaphore for long-running endpoints (profile, trace).
	if h.sem != nil {
		select {
		case h.sem <- struct{}{}:
			defer func() { <-h.sem }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many concurrent profiles; retry in 1s", http.StatusTooManyRequests)
			h.metrics.RecordPprofRequest(h.endpoint, "busy")
			return
		}
	}

	// Delegate to the upstream pprof handler. We use a responseRecorder only
	// to capture the status code for the outcome label — low overhead since
	// pprof responses are already buffered by the upstream handler.
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.upstream.ServeHTTP(rec, r)

	duration := time.Since(start)
	outcome := "ok"
	if rec.status >= 500 {
		outcome = "error"
	}
	h.metrics.RecordPprofRequest(h.endpoint, outcome)

	if h.audit != nil {
		remoteAddr := r.RemoteAddr
		h.audit.LogAccessWithMetadata(
			"pprof_fetch",
			"", // bucket — not applicable
			"", // key — not applicable
			remoteAddr,
			r.UserAgent(),
			r.Header.Get("X-Request-Id"),
			rec.status < 400,
			nil,
			duration,
			map[string]interface{}{
				"endpoint":    h.endpoint,
				"duration_ms": duration.Milliseconds(),
				"status":      rec.status,
			},
		)
	}
}

// statusRecorder captures the HTTP status code written by the upstream handler.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.written {
		r.status = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.written = true
	}
	return r.ResponseWriter.Write(b)
}

// ApplyRuntimeProfilingRates calls runtime.SetBlockProfileRate and
// runtime.SetMutexProfileFraction once at startup per cfg. This function is
// separate from RegisterPprofRoutes because the runtime state lives at the
// process level, not per-mux, and must be called exactly once.
func ApplyRuntimeProfilingRates(cfg config.AdminProfilingConfig, logger *logrus.Logger) {
	if cfg.BlockRate != 0 {
		runtime.SetBlockProfileRate(cfg.BlockRate)
		logger.WithField("block_rate", cfg.BlockRate).Info("admin_profiling: block profile rate set")
	}
	if cfg.MutexFraction != 0 {
		runtime.SetMutexProfileFraction(cfg.MutexFraction)
		logger.WithField("mutex_fraction", cfg.MutexFraction).Info("admin_profiling: mutex profile fraction set")
	}
}

// RegisterPprofRoutes mounts profiling handlers on mux under /debug/pprof.
// It is a no-op when cfg.Enabled is false.
//
// The caller is responsible for the authn / rate-limit middleware (the admin
// Server already chains those on every request). The semaphore for
// long-running endpoints and the seconds= validator are handled internally.
func RegisterPprofRoutes(
	mux *http.ServeMux,
	cfg config.AdminProfilingConfig,
	m ProfilingMetrics,
	a ProfilingAudit,
	logger *logrus.Logger,
) {
	if !cfg.Enabled {
		return
	}

	maxConcurrent := cfg.MaxConcurrentProfiles
	if maxConcurrent < 1 {
		maxConcurrent = 1
		logger.Warn("admin.profiling.max_concurrent_profiles was < 1; normalised to 1")
	}
	// One semaphore is shared across profile + trace (the two long-running
	// endpoints). Both can block for up to MaxProfileSeconds.
	sem := make(chan struct{}, maxConcurrent)

	for _, route := range allPprofRoutes() {
		route := route // capture loop var

		label := endpointLabel(route.path)
		var routeSem chan struct{}
		hasSecs := false
		if label == "profile" || label == "trace" {
			routeSem = sem
			hasSecs = true
		}

		wrapped := &profilingHandler{
			endpoint: label,
			upstream: route.handler,
			sem:      routeSem,
			maxSecs:  cfg.MaxProfileSeconds,
			hasSecs:  hasSecs,
			metrics:  m,
			audit:    a,
			logger:   logger,
		}
		mux.Handle(route.path, wrapped)
	}

	logger.WithFields(logrus.Fields{
		"max_concurrent": maxConcurrent,
		"max_seconds":    cfg.MaxProfileSeconds,
		"block_rate":     cfg.BlockRate,
		"mutex_fraction": cfg.MutexFraction,
	}).Info("admin_profiling: pprof routes registered")
}
