package util

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGH353HTTPS_TrustedImmediatePeer(t *testing.T) {
	input := []string{"10.0.0.0/8", "fd00::/8"}
	e, err := NewIPExtractor(input)
	require.NoError(t, err)
	input[0] = "0.0.0.0/0" // extractor does not retain caller configuration
	for _, tc := range []struct {
		name, remote         string
		header               http.Header
		tls, trusted, secure bool
	}{
		{"trusted_v4", "10.1.2.3:8080", http.Header{"X-Forwarded-Proto": {"https"}}, false, true, true},
		{"trusted_v6", "[fd00::1]:8080", http.Header{"X-Forwarded-Proto": {"HTTPS"}}, false, true, true},
		{"untrusted_v4", "192.0.2.1:8080", http.Header{"X-Forwarded-Proto": {"https"}, "X-Forwarded-For": {"10.1.2.3"}}, false, false, false},
		{"untrusted_v6", "[2001:db8::1]:8080", http.Header{"X-Forwarded-Proto": {"https"}}, false, false, false},
		{"no_xfp", "10.1.2.3:8080", nil, false, true, false},
		{"empty", "10.1.2.3:8080", http.Header{"X-Forwarded-Proto": {""}}, false, true, false},
		{"duplicate", "10.1.2.3:8080", http.Header{"X-Forwarded-Proto": {"https", "https"}}, false, true, false},
		{"conflict", "10.1.2.3:8080", http.Header{"X-Forwarded-Proto": {"https", "http"}}, false, true, false},
		{"comma", "10.1.2.3:8080", http.Header{"X-Forwarded-Proto": {"https,http"}}, false, true, false},
		{"space", "10.1.2.3:8080", http.Header{"X-Forwarded-Proto": {" https"}}, false, true, false},
		{"control", "10.1.2.3:8080", http.Header{"X-Forwarded-Proto": {"https\r\n"}}, false, true, false},
		{"aliases", "10.1.2.3:8080", http.Header{"X-Forwarded-Proto": {"https"}, "x-forwarded-proto": {"https"}}, false, true, false},
		{"other_authority", "10.1.2.3:8080", http.Header{"Forwarded": {"proto=https"}, "X-Forwarded-SSL": {"on"}, "Strict-Transport-Security": {"max-age=1"}}, false, true, false},
		{"malformed_peer", "10.1.2.3", http.Header{"X-Forwarded-Proto": {"https"}}, false, false, false},
		{"direct_tls", "192.0.2.1:8080", http.Header{"X-Forwarded-Proto": {"http"}}, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://gateway/bucket/key", nil)
			r.RemoteAddr = tc.remote
			r.Header = tc.header
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			assert.Equal(t, tc.trusted, e.IsTrustedPeer(r))
			assert.Equal(t, tc.secure, e.IsHTTPSRequest(r))
		})
	}
	empty, err := NewIPExtractor(nil)
	require.NoError(t, err)
	r := httptest.NewRequest("GET", "http://gateway/", nil)
	r.RemoteAddr = "10.1.2.3:8080"
	r.Header.Set("X-Forwarded-Proto", "https")
	assert.False(t, empty.IsHTTPSRequest(r))
	assert.False(t, (*IPExtractor)(nil).IsTrustedPeer(r))
	assert.False(t, (*IPExtractor)(nil).IsHTTPSRequest(r))
	assert.False(t, e.IsHTTPSRequest(nil))
	assert.False(t, e.IsTrustedPeer(nil))
}
