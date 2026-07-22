package middleware

import (
	"encoding/xml"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// BucketValidationMiddleware validates that requests only access the configured proxied bucket.
// If ProxiedBucket is set, only requests to that bucket will be allowed.
// Health check endpoints and other non-S3 routes are always allowed.
func BucketValidationMiddleware(proxiedBucket string, logger *logrus.Logger) func(http.Handler) http.Handler {
	// If no proxied bucket is configured, allow all buckets
	if proxiedBucket == "" {
		return func(next http.Handler) http.Handler {
			return next
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only exact system endpoints bypass bucket validation. Prefix matching
			// would treat S3 buckets such as "metrics-tenant" as system routes.
			path := r.URL.Path
			if path == "/health" || path == "/ready" || path == "/live" || path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			// Extract bucket from URL path (middleware runs before routing, so we parse the path directly)
			// Remove leading slash and get first segment
			pathParts := strings.Split(strings.TrimPrefix(path, "/"), "/")
			bucket := ""
			if len(pathParts) > 0 && pathParts[0] != "" {
				bucket = pathParts[0]
			}

			// Validate bucket access - deny if bucket doesn't match proxied bucket
			// If bucket is still empty after extraction, deny access in single bucket mode
			if bucket == "" || bucket != proxiedBucket {
				if bucket != "" {
					logger.WithFields(logrus.Fields{
						"requested_bucket": bucket,
						"proxied_bucket":   proxiedBucket,
						"path":             path,
						"method":           r.Method,
					}).Warn("Access denied: bucket does not match proxied bucket")
				} else {
					logger.WithFields(logrus.Fields{
						"proxied_bucket": proxiedBucket,
						"path":           path,
						"method":         r.Method,
					}).Warn("Access denied: no bucket specified in request")
				}

				// Return S3-compatible error response
				writeBucketAccessDeniedError(w, bucket, path)
				return
			}

			// Also validate copy source bucket if present
			if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
				// Parse copy source: format is "bucket/key" or "/bucket/key"
				sourceParts := strings.Split(strings.TrimPrefix(copySource, "/"), "/")
				if len(sourceParts) > 0 {
					sourceBucket := sourceParts[0]
					// Remove version ID if present
					if strings.Contains(sourceBucket, "?") {
						sourceBucket = strings.Split(sourceBucket, "?")[0]
					}
					if sourceBucket != "" && sourceBucket != proxiedBucket {
						logger.WithFields(logrus.Fields{
							"source_bucket":  sourceBucket,
							"proxied_bucket": proxiedBucket,
							"path":           path,
							"method":         r.Method,
						}).Warn("Access denied: copy source bucket does not match proxied bucket")

						writeBucketAccessDeniedError(w, sourceBucket, path)
						return
					}
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// writeBucketAccessDeniedError writes an S3-compatible AccessDenied error response.
func writeBucketAccessDeniedError(w http.ResponseWriter, bucket, resource string) {
	type S3Error struct {
		XMLName    xml.Name `xml:"Error"`
		Code       string   `xml:"Code"`
		Message    string   `xml:"Message"`
		Resource   string   `xml:"Resource"`
		HTTPStatus int
	}

	s3Err := S3Error{
		Code:       "AccessDenied",
		Message:    "Access Denied. This gateway is configured to proxy a single bucket only.",
		Resource:   resource,
		HTTPStatus: http.StatusForbidden,
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(s3Err.HTTPStatus)
	xml.NewEncoder(w).Encode(s3Err)
}
