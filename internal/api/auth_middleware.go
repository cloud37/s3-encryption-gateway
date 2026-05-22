package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/audit"
	"github.com/sirupsen/logrus"
)

// contextKey is a private type for context keys to avoid collisions.
type contextKey int

const (
	// credentialLabelKey stores the resolved credential label in the request context.
	credentialLabelKey contextKey = iota
)

// CredentialLabelFromContext returns the credential label attached to the
// request context by AuthMiddleware, or empty string if none is present.
func CredentialLabelFromContext(r *http.Request) string {
	if label, ok := r.Context().Value(credentialLabelKey).(string); ok {
		return label
	}
	return ""
}

// writeS3ClientError writes an S3-formatted error response for authentication
// failures. It is a package-level helper so AuthMiddleware does not depend on
// Handler state.
func writeS3ClientError(w http.ResponseWriter, r *http.Request, err error, method string) {
	s3Err := classifyAuthError(err, r.URL.Path)
	s3Err.WriteXML(w)
}

// AuthMiddleware returns an HTTP middleware that validates every request
// against the credential store before passing it to next.
//
// Auth flow:
//  1. ExtractCredentials — extract access key from request.
//  2. store.Lookup       — check access key is known.
//  3. ValidateSignature  — verify HMAC (V4 or V2) using stored secret.
//  4. Attach resolved label to request context for audit logging.
//  5. Call next; on any failure return S3-formatted error and emit audit event.
//
// allowSigV2 controls whether AWS Signature Version 2 requests are accepted.
// Set to false to enforce a V4-only policy (see AuthConfig.AllowLegacySignatureV2).
//
// auditLog may be nil; when nil, audit events are silently skipped so callers
// that do not configure an audit sink still function correctly.
func AuthMiddleware(store CredentialStore, clockSkew time.Duration, logger *logrus.Logger, auditLog audit.Logger, allowSigV2 bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Allow health check, readiness, liveness, and metrics endpoints
			// without authentication so Kubernetes probes and Prometheus
			// scraping work without credentials.
			path := r.URL.Path
			if path == "/health" || path == "/ready" || path == "/live" || path == "/metrics" || strings.HasPrefix(path, "/metrics") {
				next.ServeHTTP(w, r)
				return
			}

			clientIP := r.RemoteAddr
			userAgent := r.UserAgent()
			requestID := r.Header.Get("X-Request-Id")

			// emitAuthFailure is a local helper that emits an auth.failure audit
			// event with the request context already resolved. accessKey may be
			// empty when credentials could not be extracted at all.
			emitAuthFailure := func(accessKey string, reason error) {
				if auditLog == nil {
					return
				}
				meta := map[string]interface{}{
					"method": r.Method,
					"path":   r.URL.Path,
				}
				if accessKey != "" {
					meta["access_key"] = accessKey
				}
				auditLog.LogAccessWithMetadata(
					string(audit.EventTypeAuthFailure),
					"", "", clientIP, userAgent, requestID,
					false, reason, 0, meta,
				)
			}

			// 1. Extract credentials
			creds, err := ExtractCredentials(r)
			if err != nil {
				logger.WithField("path", r.URL.Path).Warn("Request with no credentials")
				emitAuthFailure("", ErrMissingCredentials)
				writeS3ClientError(w, r, ErrMissingCredentials, r.Method)
				return
			}

			// 2. Look up access key in credential store
			secretKey, label, err := store.Lookup(creds.AccessKey)
			if err != nil {
				if err == ErrUnknownAccessKey {
					logger.WithField("access_key", creds.AccessKey).Warn("Unknown access key")
					emitAuthFailure(creds.AccessKey, ErrUnknownAccessKey)
					writeS3ClientError(w, r, ErrUnknownAccessKey, r.Method)
					return
				}
				logger.WithError(err).WithField("access_key", creds.AccessKey).Warn("Credential store lookup failed")
				emitAuthFailure(creds.AccessKey, ErrUnknownAccessKey)
				writeS3ClientError(w, r, ErrUnknownAccessKey, r.Method)
				return
			}

			// 3. Validate signature
			var sigErr error
			if IsSignatureV4Request(r) {
				sigErr = ValidateSignatureV4(r, secretKey, clockSkew)
			} else if IsSignatureV2Request(r) {
				// Enforce V4-only policy when configured.
				if !allowSigV2 {
					logger.WithField("access_key", creds.AccessKey).Warn(
						"SigV2 request rejected: legacy Signature Version 2 is disabled by policy")
					emitAuthFailure(creds.AccessKey, ErrSignatureMismatch)
					writeS3ClientError(w, r, ErrSignatureMismatch, r.Method)
					return
				}
				// Warn when credentials were submitted in the query string
				// (legacy SigV2 query-param style). The secret key travelled
				// in the URL and may have been logged by intermediaries
				// (proxies, CDNs, browser history).
				if creds.FromQueryParam {
					logger.WithField("access_key", creds.AccessKey).Warn(
						"SigV2 request with credentials in query string; " +
							"secret key was exposed to intermediaries")
				}
				sigErr = ValidateSignatureV2(r, secretKey, clockSkew)
			} else {
				// Credentials were extracted but no recognizable signature format
				logger.WithField("access_key", creds.AccessKey).Warn("No recognizable signature in request")
				emitAuthFailure(creds.AccessKey, ErrMissingCredentials)
				writeS3ClientError(w, r, ErrMissingCredentials, r.Method)
				return
			}

			if sigErr != nil {
				if sigErr == ErrSignatureMismatch {
					logger.WithField("access_key", creds.AccessKey).Warn("Signature mismatch")
					emitAuthFailure(creds.AccessKey, ErrSignatureMismatch)
					writeS3ClientError(w, r, ErrSignatureMismatch, r.Method)
					return
				}
				// Other validation errors (expired, bad format, clock skew, etc.)
				logger.WithError(sigErr).WithField("access_key", creds.AccessKey).Warn("Signature validation failed")
				emitAuthFailure(creds.AccessKey, sigErr)
				writeS3ClientError(w, r, ErrSignatureMismatch, r.Method)
				return
			}

			// 4. Attach label to context for downstream audit logging
			if label != "" {
				r = r.WithContext(context.WithValue(r.Context(), credentialLabelKey, label))
			}

			// 5. Call next handler
			next.ServeHTTP(w, r)
		})
	}
}
