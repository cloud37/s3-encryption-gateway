package middleware

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/util"
	"github.com/sirupsen/logrus"
)

// ipExtractor is the shared IP extractor instance configured with trusted proxies.
// It is set during server initialization via SetIPExtractor.
var ipExtractor atomic.Pointer[util.IPExtractor]

// SetIPExtractor sets the global IP extractor instance for the middleware package.
// This should be called once during server initialization.
func SetIPExtractor(extractor *util.IPExtractor) {
	ipExtractor.Store(extractor)
}

// SecurityHeadersMiddleware adds security headers to all responses.
// Pass forceHTTPS=true to send the HSTS header even when r.TLS is nil
// (required behind TLS-terminating reverse proxies).
func SecurityHeadersMiddleware(forceHTTPS bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Prevent clickjacking
			w.Header().Set("X-Frame-Options", "DENY")
			// Prevent MIME type sniffing
			w.Header().Set("X-Content-Type-Options", "nosniff")
			// Enable XSS protection
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			// Strict Transport Security (only if TLS or ForceHTTPS)
			if r.TLS != nil || forceHTTPS {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			// Content Security Policy
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			// Referrer Policy
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			// Permissions Policy
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			next.ServeHTTP(w, r)
		})
	}
}

const maxRateLimitClients = 100_000

// minAllowTime is the minimum execution time for RateLimiter.Allow to mitigate
// timing side-channels that could reveal token-bucket state.
const minAllowTime = 50 * time.Microsecond

// RateLimiter implements a simple token bucket rate limiter.
type RateLimiter struct {
	mu              sync.Mutex
	requests        map[string]*tokenBucket
	limit           int           // requests per window
	window          time.Duration // time window
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	logger          *logrus.Logger
}

type tokenBucket struct {
	tokens     int
	lastUpdate time.Time
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(limit int, window time.Duration, logger *logrus.Logger) *RateLimiter {
	rl := &RateLimiter{
		requests:        make(map[string]*tokenBucket),
		limit:           limit,
		window:          window,
		cleanupInterval: window * 2,
		stopCleanup:     make(chan struct{}),
		logger:          logger,
	}

	// Start cleanup goroutine
	go rl.cleanup()

	return rl
}

// cleanup periodically removes old entries to prevent memory leaks.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, bucket := range rl.requests {
				// Remove entries that are older than the cleanup interval
				if now.Sub(bucket.lastUpdate) > rl.cleanupInterval {
					delete(rl.requests, key)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCleanup:
			return
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *RateLimiter) Stop() {
	close(rl.stopCleanup)
}

// Allow checks if a request from the given key should be allowed.
func (rl *RateLimiter) Allow(key string) bool {
	start := time.Now()
	defer func() {
		if elapsed := time.Since(start); elapsed < minAllowTime {
			// Use a precise spin-wait instead of time.Sleep because
			// time.Sleep has coarse granularity (~1 ms on standard Linux
			// tickless kernels) which would defeat the purpose of a
			// microsecond-level constant-time guarantee.
			deadline := start.Add(minAllowTime)
			for time.Now().Before(deadline) {
			}
		}
	}()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if _, exists := rl.requests[key]; !exists && len(rl.requests) >= maxRateLimitClients {
		return false
	}

	now := time.Now()
	bucket, exists := rl.requests[key]

	if !exists {
		// Create new bucket
		rl.requests[key] = &tokenBucket{
			tokens:     rl.limit - 1,
			lastUpdate: now,
		}
		return true
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(bucket.lastUpdate)
	if elapsed >= rl.window {
		// Reset bucket
		bucket.tokens = rl.limit - 1
		bucket.lastUpdate = now
		return true
	}

	// Check if tokens available
	if bucket.tokens > 0 {
		bucket.tokens--
		bucket.lastUpdate = now
		return true
	}

	// Rate limit exceeded
	return false
}

// getClientKey extracts a key to identify the client (IP address).
// It uses the same trusted proxy-aware logic as getClientIP to ensure
// rate limiting cannot be bypassed via X-Forwarded-For spoofing.
func getClientKey(r *http.Request) string {
	if ext := ipExtractor.Load(); ext != nil {
		return ext.GetClientIP(r)
	}
	// Fallback: use RemoteAddr directly (fail-safe)
	return util.ExtractIP(r.RemoteAddr)
}

// RateLimitMiddleware creates a middleware that enforces rate limiting.
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientKey := getClientKey(r)

			if !limiter.Allow(clientKey) {
				limiter.logger.WithFields(logrus.Fields{
					"client": clientKey,
					"path":   r.URL.Path,
				}).Warn("Rate limit exceeded")

				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
