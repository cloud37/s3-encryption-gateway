package middleware

import (
	"net/http"
	"strings"
)

// StripBucketTrailingSlash normalises bucket-level request paths so that
// requests addressed as "/<bucket>/" are treated identically to
// "/<bucket>".
//
// Why this exists
//
// S3 clients do not agree on a canonical form for bucket-level requests:
//
//   - AWS SDK v2 / awscli            → "HEAD /bucket"        (no trailing slash)
//   - minio-go (used by restic, mc) → "HEAD /bucket/"       (trailing slash)
//
// The gateway uses gorilla/mux, where the route template "/{bucket}" matches
// "/bucket" but NOT "/bucket/" (the suffix slash creates an empty extra
// segment that no registered handler owns, so the router falls through to
// its NotFoundHandler). Many popular S3 tools — most notably restic —
// therefore see HTTP 404 on every bucket-level probe (HeadBucket, MakeBucket,
// ListObjectsV2) and abort with "The specified bucket does not exist."
// (s3-encryption-gateway issue #198).
//
// S3 object keys may legitimately end with "/" (a "folder" prefix is just a
// key whose name happens to end with a slash). This is why we MUST NOT
// blindly strip a trailing slash from every path: doing so would corrupt
// object-level requests such as "GET /bucket/dir/" where key == "dir/".
//
// Rule implemented
//
// Strip the trailing slash IFF the path has exactly one non-empty path
// segment — i.e. matches the shape "/<single-segment>/". This catches
// "/backups/" → "/backups" while preserving "/backups/data/" (key ends with
// "/"), "/backups/keys/" (restic's prefix path), and every multi-segment URL.
//
// Edge cases:
//   - "/"          → left alone (root, ListBuckets)
//   - "/bucket/"   → "/bucket"
//   - "/bucket/a/" → "/bucket/a/"  (preserve; key ends with "/")
//   - "/a/b/c/"    → "/a/b/c/"     (preserve)
//   - "//"         → left alone (already invalid; router will 404 naturally)
//
// The middleware handles both raw path ("/bucket/") and cleaned path forms.
// It mutates r.URL.Path in place; r.RequestURI is left untouched so the
// logging middleware's request line still shows the original wire-form path,
// preserving operational diagnostic output while routing succeeds.
func StripBucketTrailingSlash(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if shouldStripBucketTrailingSlash(p) {
			// Make a shallow copy of the URL so we don't mutate the
			// *http.Request's pooled URL struct unexpectedly. In Go's
			// net/http the *url.URL inside *http.Request is unique to the
			// request, but copying before mutating is defensive and
			// clarifies intent.
			u := *r.URL
			u.Path = p[:len(p)-1]
			if u.RawPath != "" {
				// RawPath is the encoded form; if it is set (which happens
				// only when the path contained percent-encoded bytes) apply
				// the same trailing-slash strip to it.
				if strings.HasSuffix(u.RawPath, "/") {
					u.RawPath = u.RawPath[:len(u.RawPath)-1]
				}
			}
			r.URL = &u
		}
		next.ServeHTTP(w, r)
	})
}

// shouldStripBucketTrailingSlash reports whether p matches the shape of a
// bucket-level path with an unwanted trailing slash: it starts with "/",
// contains exactly one non-empty path segment, and ends with "/".
//
// Formally: p matches ^/[^/]+/$ — i.e. "/<segment>/" where <segment> is at
// least one non-slash character. The leading "/" is required; the trailing
// "/" is what we strip.
func shouldStripBucketTrailingSlash(p string) bool {
	if len(p) < 3 {
		// Smallest valid input is "/X/" (3 chars); shorter paths cannot
		// possibly match.
		return false
	}
	if p[0] != '/' || p[len(p)-1] != '/' {
		return false
	}
	// Body between the two slashes must contain at least one character and
	// must NOT contain any further slash.
	body := p[1 : len(p)-1]
	if body == "" || strings.Contains(body, "/") {
		return false
	}
	return true
}