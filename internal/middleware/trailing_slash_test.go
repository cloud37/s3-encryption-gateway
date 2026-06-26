package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStripBucketTrailingSlash(t *testing.T) {
	cases := []struct {
		name        string
		path        string
		wantPath    string // path seen by the inner handler
		wantPathEq  bool   // inner should see same path
		wantStatus  int
		rawPath     string // optional RawPath input (for encoded-path cases)
		wantRawPath string
	}{
		{
			name:       "single-segment trailing slash stripped",
			path:       "/backups/",
			wantPath:   "/backups",
			wantStatus: 200,
		},
		{
			name:       "two-char single segment",
			path:       "/b/",
			wantPath:   "/b",
			wantStatus: 200,
		},
		{
			name:       "root left alone",
			path:       "/",
			wantPath:   "/",
			wantStatus: 200,
		},
		{
			name:       "already clean bucket path stays",
			path:       "/backups",
			wantPath:   "/backups",
			wantStatus: 200,
		},
		{
			name:       "multi-segment with trailing slash preserved (object key ends with '/')",
			path:       "/backups/data/",
			wantPath:   "/backups/data/",
			wantStatus: 200,
		},
		{
			name:       "three-segment path preserved",
			path:       "/bucket/keys/file/",
			wantPath:   "/bucket/keys/file/",
			wantStatus: 200,
		},
		{
			name:       "empty segment between slashes left alone (router 404)",
			path:       "//",
			wantPath:   "//",
			wantStatus: 200,
		},
		{
			name:        "encoded trailing slash stripped too when RawPath set",
			path:        "/backups/",
			rawPath:     "/backups/",
			wantPath:    "/backups",
			wantRawPath: "/backups",
			wantStatus:  200,
		},
		{
			// Encoded bucket name. httptest.NewRequest decodes %C3%A4 → ä
			// into URL.Path and keeps the encoded form in RawPath.
			// Middleware should strip the trailing slash from both Path and
			// RawPath.
			name:        "encoded bucket name trailing slash stripped",
			path:        "/b%C3%A4ckup/",
			rawPath:     "/b%C3%A4ckup/",
			wantPath:    "/bäckup",
			wantRawPath: "/b%C3%A4ckup",
			wantStatus:  200,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			gotPath := ""
			gotRawPath := ""
			inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotRawPath = r.URL.RawPath
				w.WriteHeader(tc.wantStatus)
			})
			req := httptest.NewRequest(http.MethodHead, tc.path, nil)
			// httptest.NewRequest decodes %XX escapes into URL.Path and
			// keeps the escaped form in URL.RawPath. Don't overwrite
			// URL.Path from tc.path here — that would re-escape it.
			if tc.rawPath != "" {
				req.URL.RawPath = tc.rawPath
			}
			rec := httptest.NewRecorder()
			StripBucketTrailingSlash(inner).ServeHTTP(rec, req)
			if gotPath != tc.wantPath {
				t.Errorf("Path: got %q, want %q", gotPath, tc.wantPath)
			}
			if tc.wantRawPath != "" && gotRawPath != tc.wantRawPath {
				t.Errorf("RawPath: got %q, want %q", gotRawPath, tc.wantRawPath)
			}
			if rec.Code != tc.wantStatus {
				t.Errorf("status: got %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

// TestStripBucketTrailingSlash_PreservesOriginalRequestURI asserts that the
// middleware does NOT mutate r.RequestURI, so logging middleware (which
// runs outermost) still records the wire-form path the client actually sent.
func TestStripBucketTrailingSlash_PreservesOriginalRequestURI(t *testing.T) {
	var seenURI string
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seenURI = r.RequestURI
	})
	req := httptest.NewRequest(http.MethodHead, "/backups/", nil)
	req.RequestURI = "/backups/"
	rec := httptest.NewRecorder()
	StripBucketTrailingSlash(inner).ServeHTTP(rec, req)
	if seenURI != "/backups/" {
		t.Errorf("RequestURI mutated: got %q, want \"/backups/\"", seenURI)
	}
	if req.URL.Path != "/backups" {
		t.Errorf("URL.Path should be normalized: got %q, want \"/backups\"", req.URL.Path)
	}
}

// TestShouldStripBucketTrailingSlash_Table exercises the predicate directly
// for fast failure isolation.
func TestShouldStripBucketTrailingSlash_Table(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"", false},
		{"/", false},
		{"//", false},
		{"//x", false}, // missing leading-slash body
		{"x/", false},  // missing leading slash
		{"/x", false},  // missing trailing slash
		{"/x/", true},
		{"/backups/", true},
		{"/backups", false},
		{"/backups/data/", false}, // multi-segment
		{"/a/b/c/", false},
		{"/a/b/c", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.path, func(t *testing.T) {
			if got := shouldStripBucketTrailingSlash(tc.path); got != tc.want {
				t.Errorf("shouldStripBucketTrailingSlash(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}