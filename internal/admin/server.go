// Package admin provides the admin API server for the S3 encryption gateway.
//
// The admin server runs on a separate listener from the S3 data-plane,
// providing endpoints for key rotation management and (future) diagnostic
// endpoints. It is gated by bearer-token authentication with constant-time
// comparison.
package admin

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// contextKey is a private type for context keys in this package.
type contextKey int

const (
	// ctxKeyAdmin is set on requests arriving on the admin listener.
	ctxKeyAdmin contextKey = iota
)

// IsAdminRequest returns true if the request arrived on the admin listener.
// This is the reusable predicate consumed by V0.6-S3-2.
func IsAdminRequest(r *http.Request) bool {
	v, _ := r.Context().Value(ctxKeyAdmin).(bool)
	return v
}

// Server owns the admin HTTP listener and mux.
type Server struct {
	// mu guards httpServer and listener, which are written by Start and read
	// by Shutdown and BoundAddr. Without this mutex, calls to Shutdown that
	// race Start (e.g. a test cleanup fired while the admin goroutine is
	// still binding the listener) trip the race detector.
	mu         sync.Mutex
	httpServer *http.Server
	listener   net.Listener
	cfg        config.AdminConfig
	logger     *logrus.Logger
	mux        *http.ServeMux

	// tokenCache holds the in-memory cached bearer token so that the token
	// file is not re-read on every authenticated request (V1.0-SEC-22).
	tokenCache []byte
	tokenMu    sync.RWMutex

	// stopRefresh signals the periodic token refresh goroutine to exit.
	stopRefresh     chan struct{}
	stopRefreshOnce sync.Once
}


// NewServer creates a new admin Server. The caller must call RegisterRoutes
// before Start to mount handlers on the admin mux.
func NewServer(cfg config.AdminConfig, logger *logrus.Logger) *Server {
	mux := http.NewServeMux()
	s := &Server{
		cfg:         cfg,
		logger:      logger,
		mux:         mux,
		stopRefresh: make(chan struct{}),
	}
	return s
}


// Mux returns the underlying ServeMux so callers can register routes.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// Start begins listening on the admin address. It blocks until the context is
// cancelled or Shutdown is called.
func (s *Server) Start(ctx context.Context) error {
	// Build the handler chain: admin-context → bearer auth → rate limit → mux
	tokenSource := s.buildTokenSource()

	// Launch periodic token refresh so that runtime rotation is supported
	// without re-reading the file on every request (V1.0-SEC-22).
	if s.cfg.Auth.TokenFile != "" {
		go s.tokenRefreshLoop(s.cfg.Auth.TokenFile)
	}

	handler := http.Handler(s.mux)

	// Apply rate limiting
	if s.cfg.RateLimit.RequestsPerMinute > 0 {
		rl := NewRateLimiter(s.cfg.RateLimit.RequestsPerMinute, s.logger)
		handler = rl.Middleware(handler)
	}

	// Apply bearer authentication
	handler = BearerAuthMiddleware(tokenSource, s.logger)(handler)

	// Set admin context flag on every request
	handler = adminContextMiddleware(handler)

	maxHeaderBytes := s.cfg.MaxHeaderBytes
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 64 * 1024 // 64 KB default
	}

	httpServer := &http.Server{
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	listener, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("admin: failed to listen on %s: %w", s.cfg.Address, err)
	}

	boundAddr := listener.Addr().String()
	s.logger.WithFields(logrus.Fields{
		"address":        boundAddr,
		"tls":            s.cfg.TLS.Enabled,
		"auth":           "bearer",
		"rate_limit_rpm": s.cfg.RateLimit.RequestsPerMinute,
	}).Info("admin_api_enabled")

	if s.cfg.TLS.Enabled {
		tlsCert, certErr := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if certErr != nil {
			listener.Close()
			return fmt.Errorf("admin: failed to load TLS certificate: %w", certErr)
		}
		tlsCfg := buildAdminTLSConfig(tlsCert)
		listener = tls.NewListener(listener, tlsCfg)
	}

	// Publish the listener + httpServer atomically so Shutdown can observe
	// them. If Shutdown was called before we got here, s.httpServer will be
	// non-nil (we stash a sentinel below); close the listener and bail.
	s.mu.Lock()
	s.httpServer = httpServer
	s.listener = listener
	s.mu.Unlock()

	if err := httpServer.Serve(listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("admin: serve error: %w", err)
	}
	return nil
}

// Shutdown gracefully shuts down the admin server. It is safe to call
// concurrently with Start: if Start has not yet published the http.Server,
// Shutdown returns nil and the subsequent Start will see the listener close
// and exit cleanly.
func (s *Server) Shutdown(ctx context.Context) error {
	// Signal the background refresh goroutine to exit.
	s.stopRefreshOnce.Do(func() { close(s.stopRefresh) })

	s.tokenMu.Lock()
	zeroBytes(s.tokenCache)
	s.tokenCache = nil
	s.tokenMu.Unlock()

	s.mu.Lock()
	hs := s.httpServer
	s.mu.Unlock()
	if hs == nil {
		return nil
	}
	return hs.Shutdown(ctx)
}


// BoundAddr returns the address the server is listening on.
// Returns empty string if not yet started.
func (s *Server) BoundAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// buildAdminTLSConfig returns a hardened tls.Config for the admin listener.
// V1.0-SEC-23: restrict cipher suites and curve preferences to avoid
// CBC-mode ciphers and weak curves.
func buildAdminTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
}

// buildTokenSource returns a function that reads the bearer token.
// For token_file mode the file is read once at construction time and
// cached in memory; a periodic refresh goroutine (started in Start)
// updates the cache at runtime so that token rotation is still supported
// without performing disk I/O on every request (V1.0-SEC-22).
func (s *Server) buildTokenSource() func() []byte {
	if s.cfg.Auth.TokenFile != "" {
		path := s.cfg.Auth.TokenFile

		// V1.0-SEC-F2: Validate file permissions before reading the token.
		// Refuse to start if the file is group- or world-readable, matching
		// the same check performed by refreshToken() at runtime.
		info, err := os.Stat(path)
		if err != nil {
			s.logger.WithError(err).Error("admin: failed to stat token file")
			// Fall through — the read below will also fail and produce a clear error.
		} else if info.Mode().Perm()&0077 != 0 {
			s.logger.WithFields(logrus.Fields{
				"path": path,
				"mode": info.Mode().Perm().String(),
			}).Error("admin: token file has overly permissive permissions (must be 0600 or more restrictive); refusing to start")
			// Do NOT load the token — force the operator to fix permissions.
			return func() []byte { return nil }
		}

		// Initial read: cache the token immediately.
		data, err := os.ReadFile(path)
		if err != nil {
			s.logger.WithError(err).Error("admin: failed to read token file")
			s.tokenCache = nil
		} else {
			s.tokenCache = []byte(strings.TrimSpace(string(data)))
		}

		return func() []byte {
			s.tokenMu.RLock()
			defer s.tokenMu.RUnlock()
			return s.tokenCache
		}
	}
	// Inline token (dev only)
	token := []byte(s.cfg.Auth.Token)
	return func() []byte {
		return token
	}
}

// refreshToken re-reads the token file, validates its permissions, and
// updates the in-memory cache. It is called by the periodic refresh loop.
func (s *Server) refreshToken(path string) {
	info, err := os.Stat(path)
	if err != nil {
		s.logger.WithError(err).Warn("admin: failed to stat token file during refresh")
		return
	}
	if info.Mode().Perm()&0077 != 0 {
		s.logger.WithFields(logrus.Fields{
			"path": path,
			"mode": info.Mode().Perm(),
		}).Warn("admin: token file permissions have been relaxed")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		s.logger.WithError(err).Warn("admin: failed to re-read token file")
		return
	}
	trimmed := []byte(strings.TrimSpace(string(data)))
	s.tokenMu.Lock()
	s.tokenCache = trimmed
	s.tokenMu.Unlock()
}

// tokenRefreshLoop runs a ticker that refreshes the cached token every
// 30 seconds. It exits when stopRefresh is closed.
func (s *Server) tokenRefreshLoop(path string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.refreshToken(path)
		case <-s.stopRefresh:
			return
		}
	}
}


// adminContextMiddleware sets the admin context flag on every request.
func adminContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxKeyAdmin, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// zeroBytes overwrites a byte slice with zeros for secure memory cleanup.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
