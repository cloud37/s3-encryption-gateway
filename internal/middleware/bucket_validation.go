package middleware

import (
	"encoding/xml"
	"net/http"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/api"
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

			// Validate bucket access - deny if bucket doesn't match proxied bucket.
			// Allow empty bucket (root path, e.g. ListBuckets) to pass through.
			if bucket != "" && bucket != proxiedBucket {
				logger.WithFields(logrus.Fields{
					"requested_bucket": bucket,
					"proxied_bucket":   proxiedBucket,
					"path":             path,
					"method":           r.Method,
				}).Warn("Access denied: bucket does not match proxied bucket")

				// Return S3-compatible error response
				writeBucketAccessDeniedError(w, bucket, path)
				return
			}

			// Also validate copy source bucket if present
			if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
				srcBucket, _, _, err := api.ParseCopySource(copySource)
				if err != nil {
					logger.WithFields(logrus.Fields{
						"copy_source": copySource,
						"error":       err,
					}).Warn("Access denied: malformed copy source")
					writeBucketAccessDeniedError(w, "", path)
					return
				}
				if srcBucket != "" && srcBucket != proxiedBucket {
					logger.WithFields(logrus.Fields{
						"source_bucket":  srcBucket,
						"proxied_bucket": proxiedBucket,
						"path":           path,
						"method":         r.Method,
					}).Warn("Access denied: copy source bucket does not match proxied bucket")

					writeBucketAccessDeniedError(w, srcBucket, path)
					return
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
