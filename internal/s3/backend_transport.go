package s3

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

// NewBackendHTTPTransport builds the transport used for backend HTTP traffic.
// The caller owns the returned transport and may tune operation-specific
// timeout fields before first use.
func NewBackendHTTPTransport(cfg config.BackendTLSConfig) (*http.Transport, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http.DefaultTransport is not an *http.Transport")
	}
	transport := base.Clone()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}, InsecureSkipVerify: cfg.InsecureSkipVerify} // #nosec G402 -- explicit operator-controlled diagnostic configuration; startup emits a warning
	if cfg.CAFile != "" {
		info, err := os.Stat(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read backend CA file %q: %w", cfg.CAFile, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("backend CA file %q is not regular", cfg.CAFile)
		}
		data, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read backend CA file %q: %w", cfg.CAFile, err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if len(data) == 0 || !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("backend CA file %q contains no certificates", cfg.CAFile)
		}
		tlsConfig.RootCAs = roots
	}
	transport.TLSClientConfig = tlsConfig
	return transport, nil
}
