package admin

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kenchrcum/s3-encryption-gateway/internal/audit"
	"github.com/sirupsen/logrus"
)

// Sentinel errors for admin authentication failures.
var (
	errAdminMissingAuthHeader  = errors.New("missing Authorization header")
	errAdminMalformedAuthHeader = errors.New("malformed Authorization header")
	errAdminWrongScheme        = errors.New("only Bearer authentication is supported")
	errAdminInvalidToken       = errors.New("invalid bearer token")
)

// BearerAuthMiddleware returns HTTP middleware that validates an
// Authorization: Bearer <token> header using constant-time comparison.
// tokenSource is called on every request to support runtime token rotation
// (e.g. via file-watch).
//
// auditLog may be nil; when nil, audit events are silently skipped so callers
// that do not configure an audit sink still function correctly.
func BearerAuthMiddleware(tokenSource func() []byte, logger *logrus.Logger, auditLog audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := r.RemoteAddr
			userAgent := r.UserAgent()
			requestID := r.Header.Get("X-Request-Id")

			emitAuthFailure := func(reason error) {
				if auditLog == nil {
					return
				}
				auditLog.LogAccessWithMetadata(
					string(audit.EventTypeAuthFailure),
					"", "", clientIP, userAgent, requestID,
					false, reason, 0,
					map[string]interface{}{
						"method":    r.Method,
						"path":      r.URL.Path,
						"subsystem": "admin",
					},
				)
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				emitAuthFailure(errAdminMissingAuthHeader)
				writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "missing Authorization header")
				return
			}

			// Expect "Bearer <token>"
			// Use constant-time comparison for the scheme prefix to
			// eliminate any timing distinguisher between "wrong scheme" and
			// "correct scheme, wrong token". The prefix "Bearer " is a public
			// constant so the practical risk is negligible, but defense-in-depth
			// requires the entire auth header to be handled in constant time.
			const prefix = "Bearer "
			if len(authHeader) <= len(prefix) {
				emitAuthFailure(errAdminMalformedAuthHeader)
				writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "malformed Authorization header")
				return
			}
			if subtle.ConstantTimeCompare([]byte(authHeader[:len(prefix)]), []byte(prefix)) != 1 {
				emitAuthFailure(errAdminWrongScheme)
				writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "only Bearer authentication is supported")
				return
			}

			got := []byte(authHeader[len(prefix):])
			want := tokenSource()
			if want == nil || len(want) == 0 {
				logger.Error("admin: bearer token source returned empty token")
				writeAdminError(w, http.StatusInternalServerError, "InternalError", "admin authentication misconfigured")
				return
			}

			// Constant-time comparison to prevent timing side-channels.
			if subtle.ConstantTimeCompare(got, want) != 1 {
				emitAuthFailure(errAdminInvalidToken)
				writeAdminError(w, http.StatusUnauthorized, "Unauthorized", "invalid bearer token")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// adminErrorResponse is the JSON error shape for admin endpoints.
type adminErrorResponse struct {
	Error struct {
		Code       string `json:"code"`
		Message    string `json:"message"`
		RotationID string `json:"rotation_id,omitempty"`
	} `json:"error"`
}

// writeAdminError writes a JSON error response for admin endpoints.
func writeAdminError(w http.ResponseWriter, status int, code, message string) {
	resp := adminErrorResponse{}
	resp.Error.Code = code
	resp.Error.Message = message
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

// WriteAdminErrorWithRotation writes a JSON error response including a rotation_id.
func WriteAdminErrorWithRotation(w http.ResponseWriter, status int, code, message, rotationID string) {
	resp := adminErrorResponse{}
	resp.Error.Code = code
	resp.Error.Message = message
	resp.Error.RotationID = rotationID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}
