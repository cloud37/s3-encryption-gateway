package api

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

type corsResponseDecision struct {
	allowed     bool
	allowOrigin string
	expose      string
	credentials bool
	addVary     bool
	preflight   *corsPreflightDecision
}

// CORSMiddleware applies gateway-owned policy at the response boundary so
// locally generated, encrypted, proxied, and error responses share one policy.
func CORSMiddleware(cfg config.CORSConfig, store CORSStore, logger *logrus.Logger) func(http.Handler) http.Handler {
	if config.EffectiveCORSMode(cfg.Mode) != "gateway" {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isCORSPath(r) {
				next.ServeHTTP(w, r)
				return
			}
			decision := &corsResponseDecision{}
			request := r
			if r.Method == http.MethodOptions {
				decision.preflight = &corsPreflightDecision{}
				decision.addVary = true
				ctx := context.WithValue(r.Context(), corsPreflightContextKey{}, decision.preflight)
				request = r.WithContext(ctx)
			} else {
				decision.addVary = len(r.Header.Values("Origin")) > 0
				origins := r.Header.Values("Origin")
				if len(origins) == 1 && r.Header.Get("Origin") == strings.TrimSpace(origins[0]) && validOriginHeader(origins[0]) {
					bucket := corsBucketFromRequest(r)
					var corsCfg *CORSConfiguration
					var err error
					if store == nil {
						err = ErrCORSUnavailable
					} else {
						corsCfg, err = store.Get(r.Context(), bucket)
						if errorsIsCORSNotFound(err) {
							if len(cfg.Fallback.AllowedOrigins) > 0 && len(cfg.Fallback.AllowedMethods) > 0 {
								corsCfg = &CORSConfiguration{Rules: []CORSRule{{AllowedOrigins: cfg.Fallback.AllowedOrigins, AllowedMethods: cfg.Fallback.AllowedMethods, AllowedHeaders: cfg.Fallback.AllowedHeaders, ExposeHeaders: cfg.Fallback.ExposeHeaders, MaxAgeSeconds: corsMaxAgePointer(cfg.Fallback.MaxAgeSeconds)}}}
								err = nil
							}
						}
					}
					if err == nil || errorsIsCORSNotFound(err) {
						if corsCfg != nil {
							if rule, ok := matchCORSRule(corsCfg, origins[0], r.Method, nil); ok {
								decision.allowed = true
								decision.allowOrigin = origins[0]
								if len(rule.AllowedOrigins) == 1 && rule.AllowedOrigins[0] == "*" && !cfg.AllowCredentials {
									decision.allowOrigin = "*"
								}
								decision.expose = strings.Join(rule.ExposeHeaders, ", ")
								decision.credentials = cfg.AllowCredentials
							}
						}
					} else {
						if logger != nil {
							logger.WithError(err).WithField("bucket", bucket).Error("gateway CORS policy lookup failed")
						}
					}
				} else if len(r.Header.Values("Origin")) > 0 && logger != nil {
					logger.WithField("bucket", corsBucketFromRequest(r)).Warn("gateway CORS response suppressed for malformed or duplicate Origin")
				}
			}
			if decision.addVary {
				prepareCORSResponseHeaders(w.Header(), decision)
			}
			wrapped := &corsResponseWriter{ResponseWriter: w, request: request, decision: decision}
			next.ServeHTTP(wrapped, request)
			wrapped.finish()
		})
	}
}

func prepareCORSResponseHeaders(h http.Header, decision *corsResponseDecision) {
	if decision.allowed {
		setCORSResponseHeader(h, "Access-Control-Allow-Origin", decision.allowOrigin)
		if decision.expose != "" {
			setCORSResponseHeader(h, "Access-Control-Expose-Headers", decision.expose)
		}
		if decision.credentials {
			setCORSResponseHeader(h, "Access-Control-Allow-Credentials", "true")
		}
	}
	if decision.addVary {
		addVary(h, "Origin")
	}
}

func errorsIsCORSNotFound(err error) bool { return errors.Is(err, ErrCORSNotFound) }

func isCORSPath(r *http.Request) bool {
	if r == nil || r.URL == nil || r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/admin/") {
		return false
	}
	path := r.URL.Path
	if corsBucketTrailingSlash(path) {
		path = strings.TrimSuffix(path, "/")
	}
	path = strings.TrimPrefix(path, "/")
	if path == "" || path == "metrics" || isSystemEndpoint("/"+path) || strings.HasPrefix(path, "admin/") {
		return false
	}
	bucket, _, hasKey := strings.Cut(path, "/")
	if !hasKey {
		return ValidateBucketName(bucket) == nil
	}
	if ValidateBucketName(bucket) != nil {
		return false
	}
	// The S3 object routes use {key:.+}; repeated slash characters in the
	// remainder are meaningful object-key bytes, not a system-path boundary.
	key := path[len(bucket)+1:]
	return key != ""
}

// corsBucketTrailingSlash mirrors the production normalizer's exact
// single-segment rule without importing middleware (which depends on api).
func corsBucketTrailingSlash(path string) bool {
	// Keep this byte-for-byte equivalent to middleware's production
	// single-segment trailing slash normalizer; importing middleware here would
	// create a cycle because it validates bucket names through api.
	if len(path) < 3 || path[0] != '/' || path[len(path)-1] != '/' || path == "//" {
		return false
	}
	body := path[1 : len(path)-1]
	return body != "" && !strings.Contains(body, "/")
}

type corsResponseWriter struct {
	http.ResponseWriter
	request  *http.Request
	decision *corsResponseDecision
	wrote    bool
	hijacked bool
}

func (w *corsResponseWriter) reconcile() {
	if w.wrote {
		return
	}
	h := w.ResponseWriter.Header()
	if w.request.Method == http.MethodOptions {
		stripCORSResponseHeaders(h)
		if w.decision.preflight != nil && w.decision.preflight.allowed {
			replaceCORSResponseHeaders(h, w.decision.preflight.headers)
		}
		if w.decision.addVary {
			addVary(h, "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers")
		}
		w.wrote = true
		return
	}
	stripCORSResponseHeaders(h)
	if w.decision.addVary {
		addVary(h, "Origin")
	}
	if w.decision.allowed {
		setCORSResponseHeader(h, "Access-Control-Allow-Origin", w.decision.allowOrigin)
		if w.decision.expose != "" {
			setCORSResponseHeader(h, "Access-Control-Expose-Headers", w.decision.expose)
		}
		if w.decision.credentials {
			setCORSResponseHeader(h, "Access-Control-Allow-Credentials", "true")
		}
		addVary(h, "Origin")
	}
	w.wrote = true
}

func (w *corsResponseWriter) finish() {
	if !w.wrote && !w.hijacked {
		w.commit(http.StatusOK)
	}
}

func (w *corsResponseWriter) commit(status int) {
	// Informational responses do not commit the final response. The policy is
	// reconciled for every header block and may be changed before the final one.
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		// A 1xx response is its own header block. Reconcile it without
		// committing the final response so later handler header changes are
		// reconciled independently at the final status.
		if w.request.Method == http.MethodOptions {
			stripCORSResponseHeaders(w.ResponseWriter.Header())
			if w.decision.preflight != nil && w.decision.preflight.allowed {
				replaceCORSResponseHeaders(w.ResponseWriter.Header(), w.decision.preflight.headers)
			}
			if w.decision.addVary {
				addVary(w.ResponseWriter.Header(), "Origin", "Access-Control-Request-Method", "Access-Control-Request-Headers")
			}
		} else {
			stripCORSResponseHeaders(w.ResponseWriter.Header())
			if w.decision.addVary {
				addVary(w.ResponseWriter.Header(), "Origin")
			}
			if w.decision.allowed {
				setCORSResponseHeader(w.ResponseWriter.Header(), "Access-Control-Allow-Origin", w.decision.allowOrigin)
				if w.decision.expose != "" {
					setCORSResponseHeader(w.ResponseWriter.Header(), "Access-Control-Expose-Headers", w.decision.expose)
				}
				if w.decision.credentials {
					setCORSResponseHeader(w.ResponseWriter.Header(), "Access-Control-Allow-Credentials", "true")
				}
			}
		}
		w.ResponseWriter.WriteHeader(status)
		return
	}
	w.reconcile()
	w.ResponseWriter.WriteHeader(status)
}

func (w *corsResponseWriter) WriteHeader(status int) {
	w.commit(status)
}

func (w *corsResponseWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}
func (w *corsResponseWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *corsResponseWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{w.ResponseWriter}, r)
}
func (w *corsResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	conn, rw, err := h.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return conn, rw, err
}
func (w *corsResponseWriter) Push(target string, opts *http.PushOptions) error {
	p, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return p.Push(target, opts)
}
func (w *corsResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func addVary(h http.Header, names ...string) {
	var values []string
	for _, v := range h.Values("Vary") {
		values = append(values, strings.Split(v, ",")...)
	}
	for _, name := range names {
		found := false
		for _, value := range values {
			if strings.EqualFold(strings.TrimSpace(value), name) {
				found = true
				break
			}
		}
		if !found {
			values = append(values, name)
		}
	}
	if len(values) > 0 {
		h.Set("Vary", strings.Join(trimVary(values), ", "))
	}
}

func trimVary(values []string) []string {
	result := values[:0]
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			result = append(result, v)
		}
	}
	return result
}

var _ http.Flusher = (*corsResponseWriter)(nil)
var _ http.Hijacker = (*corsResponseWriter)(nil)
var _ http.Pusher = (*corsResponseWriter)(nil)
var _ io.ReaderFrom = (*corsResponseWriter)(nil)
