package middleware

import (
	"net/http"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/util"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// TracingMiddleware wraps handlers with OpenTelemetry tracing.
func TracingMiddleware(redactSensitive bool, extractor *util.IPExtractor) func(http.Handler) http.Handler {
	tracer := otel.Tracer("s3-encryption-gateway")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract bucket and key from URL path for S3 operations
			bucket, key := extractBucketAndKey(r.URL.Path)

			// Build a sanitised URL for the span — never include query string in HTTPURL.
			sanitisedURL := r.URL.Scheme + "://" + r.Host + r.URL.Path

			// Create span with appropriate name and attributes
			spanName := getSpanName(r.Method, bucket, key)
			ctx, span := tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			semconv.HTTPMethod(r.Method),
			semconv.HTTPScheme(r.URL.Scheme),
			semconv.HTTPTarget(r.URL.Path),
			semconv.HTTPURL(sanitisedURL),
			semconv.HTTPRoute(r.URL.Path),
			attribute.String("http.host", r.Host),
			attribute.String("http.user_agent", r.UserAgent()),
			attribute.String("http.remote_addr", getRemoteAddr(r, extractor)),
		),
			)

			// Add bucket and key attributes if available
			if bucket != "" {
				span.SetAttributes(attribute.String("s3.bucket", bucket))
			}
			if key != "" && !redactSensitive {
				span.SetAttributes(attribute.String("s3.key", key))
			}

			// Add query parameters (redacted if sensitive)
			if r.URL.RawQuery != "" {
				if redactSensitive {
					span.SetAttributes(attribute.String("http.query", "[REDACTED]"))
				} else {
					span.SetAttributes(attribute.String("http.query", r.URL.RawQuery))
				}
			}

			// Add headers (redact sensitive ones)
			addHeadersToSpan(span, r.Header, redactSensitive)

			// Wrap response writer to capture status code
			rw := &tracingResponseWriter{
				ResponseWriter: w,
				span:          span,
			}

			// Update request context
			r = r.WithContext(ctx)

			defer func() {
				// Record final span attributes
				span.SetAttributes(
					semconv.HTTPStatusCode(rw.statusCode),
				)

				// Set span status based on response code
				if rw.statusCode >= 400 {
					span.SetStatus(codes.Error, http.StatusText(rw.statusCode))
				} else {
					span.SetStatus(codes.Ok, "")
				}

				span.End()
			}()

			next.ServeHTTP(rw, r)
		})
	}
}

// extractBucketAndKey extracts bucket and key from S3-style URL path
func extractBucketAndKey(path string) (bucket, key string) {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Split by first slash
	parts := strings.SplitN(path, "/", 2)
	if len(parts) >= 1 {
		bucket = parts[0]
	}
	if len(parts) >= 2 {
		key = parts[1]
	}

	return bucket, key
}

// getSpanName generates an appropriate span name based on HTTP method and S3 operation
func getSpanName(method, bucket, key string) string {
	if bucket == "" {
		return "HTTP " + method
	}

	// For S3 operations, create more descriptive span names
	switch method {
	case "GET":
		if key == "" {
			return "S3 ListObjects"
		}
		return "S3 GetObject"
	case "PUT":
		return "S3 PutObject"
	case "DELETE":
		return "S3 DeleteObject"
	case "HEAD":
		return "S3 HeadObject"
	case "POST":
		if strings.Contains(key, "multipart") {
			return "S3 CompleteMultipartUpload"
		}
		return "HTTP " + method
	default:
		return "HTTP " + method
	}
}

// getRemoteAddr extracts the real remote address using the configured IP extractor.
// If extractor is nil, it falls back to RemoteAddr directly (fail-safe).
func getRemoteAddr(r *http.Request, extractor *util.IPExtractor) string {
	if extractor != nil {
		return extractor.GetClientIP(r)
	}
	return util.ExtractIP(r.RemoteAddr)
}

// addHeadersToSpan adds relevant headers to the span, redacting sensitive ones
func addHeadersToSpan(span trace.Span, headers http.Header, redactSensitive bool) {
	// Headers to include (non-sensitive)
	safeHeaders := []string{
		"content-type",
		"content-length",
		"content-encoding",
		"accept",
		"accept-encoding",
		"cache-control",
		"if-match",
		"if-none-match",
		"if-modified-since",
		"if-unmodified-since",
		"range",
		"x-amz-date",
		"x-amz-version-id",
		"x-amz-request-payer",
	}

	// Headers to redact
	sensitiveHeaders := []string{
		"authorization",
		"x-amz-security-token",
		"x-amz-server-side-encryption-aws-kms-key-id",
		"x-amz-server-side-encryption-context",
		"x-amz-tagging", // May contain PII, credentials, or business-sensitive metadata
		"cookie",
		"x-forwarded-for", // Already handled separately
		"x-real-ip",      // Already handled separately
	}

	for _, header := range safeHeaders {
		if value := headers.Get(header); value != "" {
			span.SetAttributes(attribute.String("http.request.header."+header, value))
		}
	}

	// Add redacted sensitive headers
	if redactSensitive {
		for _, header := range sensitiveHeaders {
			if value := headers.Get(header); value != "" {
				span.SetAttributes(attribute.String("http.request.header."+header, "[REDACTED]"))
			}
		}
	} else {
		for _, header := range sensitiveHeaders {
			if value := headers.Get(header); value != "" {
				span.SetAttributes(attribute.String("http.request.header."+header, value))
			}
		}
	}
}

// tracingResponseWriter wraps http.ResponseWriter to capture status code for tracing
type tracingResponseWriter struct {
	http.ResponseWriter
	span       trace.Span
	statusCode int
}

func (w *tracingResponseWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *tracingResponseWriter) Write(b []byte) (int, error) {
	if w.statusCode == 0 {
		w.statusCode = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}
