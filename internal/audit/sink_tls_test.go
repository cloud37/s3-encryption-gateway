package audit

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestHTTPSink_InvalidTLSFailsClosed(t *testing.T) {
	invalidPEM := filepath.Join(t.TempDir(), "invalid.pem")
	require.NoError(t, os.WriteFile(invalidPEM, []byte("not a PEM certificate"), 0600))
	missing := filepath.Join(t.TempDir(), "missing.pem")

	for _, tc := range []struct {
		name string
		cfg  config.SinkTLSConfig
		want string
	}{
		{"missing_ca", config.SinkTLSConfig{CAFile: missing}, "failed to read CA file"},
		{"invalid_ca", config.SinkTLSConfig{CAFile: invalidPEM}, "failed to parse CA certificate"},
		{"invalid_min_version", config.SinkTLSConfig{MinVersion: "1.1"}, "unsupported TLS min_version"},
		{"missing_client_pair", config.SinkTLSConfig{CertFile: missing, KeyFile: missing}, "failed to load client certificate"},
		{"invalid_client_pair", config.SinkTLSConfig{CertFile: invalidPEM, KeyFile: invalidPEM}, "failed to load client certificate"},
		{"cert_without_key", config.SinkTLSConfig{CertFile: invalidPEM}, "requires both cert_file and key_file"},
		{"key_without_cert", config.SinkTLSConfig{KeyFile: invalidPEM}, "requires both cert_file and key_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			// Even a reachable plain HTTP endpoint must receive no request when
			// the operator's TLS configuration is invalid.
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			sink := NewHTTPSinkWithConfig(server.URL, nil, config.HTTPTransportConfig{}, tc.cfg)
			require.ErrorContains(t, sink.initErr, tc.want)
			before := testutil.ToFloat64(droppedAuditEventsTotal)
			err := sink.WriteBatch([]*AuditEvent{{Operation: "first"}, {Operation: "second"}})
			require.ErrorIs(t, err, sink.initErr)
			require.ErrorContains(t, err, tc.want)
			require.ErrorIs(t, sink.WriteEvent(&AuditEvent{Operation: "retry"}), sink.initErr)
			require.NoError(t, sink.WriteBatch(nil), "an empty batch remains a no-op")
			require.Equal(t, int32(0), calls.Load(), "invalid custom TLS must not fall back to a working transport")
			require.Equal(t, before+3, testutil.ToFloat64(droppedAuditEventsTotal), "all rejected events must be counted")
		})
	}
}

func TestHTTPSink_InsecureSkipVerifyWarning(t *testing.T) {
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	for _, tc := range []struct {
		name string
		skip bool
	}{{"secure_default", false}, {"explicit_insecure_opt_in", true}} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
			sink := NewHTTPSinkWithConfig("https://audit.internal", nil, config.HTTPTransportConfig{}, config.SinkTLSConfig{InsecureSkipVerify: tc.skip})
			require.NoError(t, sink.initErr)
			if !tc.skip {
				require.Empty(t, output.String(), "secure defaults must not emit an insecure warning")
				return
			}
			var entry map[string]any
			require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &entry))
			require.Equal(t, "WARN", entry["level"])
			require.Equal(t, "AUDIT_SINK_TLS_INSECURE_SKIP_VERIFY", entry["setting"])
			require.Contains(t, entry["msg"], "certificate and hostname verification are DISABLED")
			require.Contains(t, entry["msg"], "MITM")
		})
	}
}

func TestHTTPSink_TLSHandshakeTrustAndExplicitOptIn(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	trustedPath := filepath.Join(t.TempDir(), "trusted.pem")
	require.NoError(t, os.WriteFile(trustedPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600))

	// httptest TLS servers share one certificate, so generate an independent CA
	// rather than using a second httptest server as the untrusted fixture.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "unrelated audit CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	require.NoError(t, err)
	untrustedPath := filepath.Join(t.TempDir(), "untrusted.pem")
	require.NoError(t, os.WriteFile(untrustedPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))

	for _, tc := range []struct {
		name string
		cfg  config.SinkTLSConfig
		ok   bool
	}{
		{"system_roots_reject_private_ca", config.SinkTLSConfig{}, false},
		{"custom_ca_accepts", config.SinkTLSConfig{CAFile: trustedPath}, true},
		{"unrelated_custom_ca_rejects", config.SinkTLSConfig{CAFile: untrustedPath}, false},
		{"explicit_full_bypass", config.SinkTLSConfig{CAFile: untrustedPath, InsecureSkipVerify: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sink := NewHTTPSinkWithConfig(server.URL, nil, config.HTTPTransportConfig{Timeout: 5 * time.Second}, tc.cfg)
			defer sink.client.CloseIdleConnections()
			require.NoError(t, sink.initErr)
			before := calls.Load()
			err := sink.WriteEvent(&AuditEvent{Operation: "TLS trust regression"})
			if tc.ok {
				require.NoError(t, err)
				require.Equal(t, before+1, calls.Load())
				return
			}
			require.Error(t, err)
			var unknownCA x509.UnknownAuthorityError
			require.True(t, errors.As(err, &unknownCA), "expected actual CA verification error, got %v", err)
			require.False(t, strings.Contains(err.Error(), "initialization failed"), "must exercise handshake rejection, not invalid config")
			require.Equal(t, before, calls.Load(), "untrusted TLS must not deliver audit events")
		})
	}
}
