package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// sensitiveQueryParams lists query-string keys that must never appear in logs.
// Keys are matched case-insensitively after URL decoding.
var sensitiveQueryParams = []string{
	"awssecretaccesskey",
	"x-amz-security-token",
	"x-amz-signature",
	"x-amz-tagging",
}

// redactQueryString parses rawQuery, replaces the value of every sensitive
// parameter with "[REDACTED]", and returns the rebuilt query string.
func redactQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		// Unparseable query — drop it entirely rather than risk leaking secrets.
		return "[REDACTED]"
	}
	for key := range values {
		for _, sensitive := range sensitiveQueryParams {
			if strings.ToLower(key) == sensitive {
				values[key] = []string{"[REDACTED]"}
				break
			}
		}
	}
	return values.Encode()
}

// LoggingMiddleware wraps handlers with request logging.
func LoggingMiddleware(logger *logrus.Logger, cfg *config.LoggingConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Get request body size from Content-Length header for PUT/POST requests
			var requestBytes int64
			if r.Method == "PUT" || r.Method == "POST" {
				if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
					if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
						requestBytes = size
					}
				}
			}

			// Wrap response writer to capture status code
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(rw, r)

			duration := time.Since(start)

			// For PUT/POST, log request bytes; for GET/HEAD, log response bytes
			bytesLogged := rw.bytesWritten
			if requestBytes > 0 {
				bytesLogged = requestBytes
			}

			// Create log entry with redaction
			logEntry := createLogEntry(r, rw, duration, bytesLogged, cfg)

			// Log based on configured format
			switch cfg.AccessLogFormat {
			case "json":
				logJSON(logger, logEntry)
			case "clf":
				logCLF(logger, logEntry)
			default:
				logDefault(logger, logEntry)
			}
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += int64(n)
	return n, err
}

// LogEntry represents a structured log entry.
type LogEntry struct {
	Timestamp  string            `json:"timestamp"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      string            `json:"query,omitempty"`
	RemoteAddr string            `json:"remote_addr"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Status     int               `json:"status"`
	DurationMs int64             `json:"duration_ms"`
	Bytes      int64             `json:"bytes"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// createLogEntry creates a log entry with header redaction.
func createLogEntry(r *http.Request, rw *responseWriter, duration time.Duration, bytesLogged int64, cfg *config.LoggingConfig) *LogEntry {
	entry := &LogEntry{
		Timestamp:  time.Now().Format(time.RFC3339),
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      redactQueryString(r.URL.RawQuery),
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.UserAgent(),
		Status:     rw.statusCode,
		DurationMs: duration.Milliseconds(),
		Bytes:      bytesLogged,
	}

	// Add redacted headers for structured formats
	if cfg.AccessLogFormat == "json" {
		entry.Headers = make(map[string]string)
		for name, values := range r.Header {
			lowerName := strings.ToLower(name)
			if shouldRedactHeader(lowerName, cfg.RedactHeaders) {
				entry.Headers[lowerName] = "[REDACTED]"
			} else {
				// Join multiple values with comma
				entry.Headers[lowerName] = strings.Join(values, ",")
			}
		}
	}

	return entry
}

// shouldRedactHeader checks if a header should be redacted.
func shouldRedactHeader(headerName string, redactHeaders []string) bool {
	lowerHeaderName := strings.ToLower(headerName)
	for _, redact := range redactHeaders {
		if strings.ToLower(redact) == lowerHeaderName {
			return true
		}
	}
	return false
}

// logDefault logs in the default structured format (backward compatible).
func logDefault(logger *logrus.Logger, entry *LogEntry) {
	fields := logrus.Fields{
		"method":      entry.Method,
		"path":        entry.Path,
		"remote_addr": entry.RemoteAddr,
		"status":      entry.Status,
		"duration_ms": entry.DurationMs,
		"bytes":       entry.Bytes,
	}

	if entry.Query != "" {
		fields["query"] = entry.Query
	}

	if entry.UserAgent != "" {
		fields["user_agent"] = entry.UserAgent
	}

	logger.WithFields(fields).Info("HTTP request")
}

// logJSON logs in JSON format.
func logJSON(logger *logrus.Logger, entry *LogEntry) {
	// Use logger to output JSON directly
	if jsonData, err := json.Marshal(entry); err == nil {
		logger.WithField("json", string(jsonData)).Info("HTTP request")
	} else {
		// Fallback to default logging on JSON marshal error
		logDefault(logger, entry)
	}
}

// logCLF logs in Common Log Format (similar to Apache CLF).
func logCLF(logger *logrus.Logger, entry *LogEntry) {
	// CLF format: %h %l %u %t \"%r\" %>s %b
	// Example: 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
	clf := fmt.Sprintf(`%s - - [%s] "%s %s%s HTTP/1.1" %d %d`,
		entry.RemoteAddr,
		entry.Timestamp,
		entry.Method,
		entry.Path,
		func() string {
			if entry.Query != "" {
				return "?" + entry.Query
			}
			return ""
		}(),
		entry.Status,
		entry.Bytes,
	)

	logger.WithField("clf", clf).Info("HTTP request")
}
