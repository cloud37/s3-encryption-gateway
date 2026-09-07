package s3

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/stretchr/testify/require"
)

type tlsFixture struct {
	server *httptest.Server
	caFile string
}

func newTLSFixture(t *testing.T) tlsFixture {
	t.Helper()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serverCert := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost", "127.0.0.1"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverCert, ca, &serverKey.PublicKey, caKey)
	require.NoError(t, err)
	cert := tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	caFile := t.TempDir() + "/ca.pem"
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0600))
	t.Cleanup(srv.Close)
	return tlsFixture{srv, caFile}
}

func TestNewBackendHTTPTransport_DefaultVerification(t *testing.T) {
	tr, err := newBackendHTTPTransport(config.BackendTLSConfig{})
	require.NoError(t, err)
	require.NotNil(t, tr.TLSClientConfig)
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default must verify certificates")
	}
	if tr.TLSClientConfig.RootCAs != nil {
		t.Fatal("default should use system roots without replacement")
	}
}

func TestNewBackendHTTPTransport_CustomCA(t *testing.T) {
	f := newTLSFixture(t)
	tr, err := newBackendHTTPTransport(config.BackendTLSConfig{CAFile: f.caFile})
	require.NoError(t, err)
	client := &http.Client{Transport: tr}
	resp, err := client.Get(f.server.URL)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestNewBackendHTTPTransport_InsecureSkipVerify(t *testing.T) {
	f := newTLSFixture(t)
	tr, err := newBackendHTTPTransport(config.BackendTLSConfig{InsecureSkipVerify: true})
	require.NoError(t, err)
	require.True(t, tr.TLSClientConfig.InsecureSkipVerify)
	resp, err := (&http.Client{Transport: tr}).Get(f.server.URL)
	require.NoError(t, err)
	resp.Body.Close()
}

func TestNewBackendHTTPTransport_InvalidCA_ReturnsError(t *testing.T) {
	path := t.TempDir() + "/bad.pem"
	require.NoError(t, os.WriteFile(path, []byte("not pem"), 0600))
	_, err := newBackendHTTPTransport(config.BackendTLSConfig{CAFile: path})
	require.Error(t, err)
	require.Contains(t, err.Error(), path)
}

func TestNewBackendHTTPTransport_CAFileErrors(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		path := t.TempDir() + "/missing.pem"
		_, err := newBackendHTTPTransport(config.BackendTLSConfig{CAFile: path})
		require.Error(t, err)
		require.Contains(t, err.Error(), path)
	})

	t.Run("directory", func(t *testing.T) {
		path := t.TempDir()
		_, err := newBackendHTTPTransport(config.BackendTLSConfig{CAFile: path})
		require.Error(t, err)
		require.Contains(t, err.Error(), "not regular")
	})

	t.Run("empty", func(t *testing.T) {
		path := t.TempDir() + "/empty.pem"
		require.NoError(t, os.WriteFile(path, nil, 0600))
		_, err := newBackendHTTPTransport(config.BackendTLSConfig{CAFile: path})
		require.Error(t, err)
		require.Contains(t, err.Error(), "contains no certificates")
	})
}

func TestNewBackendHTTPTransport_DefaultTransportMustBeHTTPTransport(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = roundTripperFunc(func(*http.Request) (*http.Response, error) { return nil, nil })
	t.Cleanup(func() { http.DefaultTransport = original })

	_, err := newBackendHTTPTransport(config.BackendTLSConfig{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an *http.Transport")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestNewBackendHTTPTransport_ConcurrentConstruction(t *testing.T) {
	f := newTLSFixture(t)
	const workers = 16
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr, err := newBackendHTTPTransport(config.BackendTLSConfig{CAFile: f.caFile})
			if err != nil {
				errs <- err
				return
			}
			if tr == http.DefaultTransport || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
				errs <- fmt.Errorf("transport was not independently configured")
				return
			}
			resp, err := (&http.Client{Transport: tr}).Get(f.server.URL)
			if err != nil {
				errs <- err
				return
			}
			_ = resp.Body.Close()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}

func TestNewClientFactory_BackendTLSCustomCA(t *testing.T) {
	f := newTLSFixture(t)
	cfg := &config.BackendConfig{Endpoint: f.server.URL, UseSSL: true, AccessKey: "a", SecretKey: "b", TLS: config.BackendTLSConfig{CAFile: f.caFile}}
	client, err := NewClientFactory(cfg).GetClient()
	require.NoError(t, err)
	body, _, err := client.GetObject(context.Background(), "bucket", "key", nil, nil)
	require.NoError(t, err)
	body.Close()
}

func TestNewClientFactory_BackendTLSUntrustedFails(t *testing.T) {
	f := newTLSFixture(t)
	cfg := &config.BackendConfig{Endpoint: f.server.URL, UseSSL: true, AccessKey: "a", SecretKey: "b"}
	client, err := NewClientFactory(cfg).GetClient()
	require.NoError(t, err)
	_, _, err = client.GetObject(context.Background(), "bucket", "key", nil, nil)
	require.Error(t, err)
}

func TestNewClientFactory_BackendTLSInvalidCA_ReturnsErrorBeforeRequest(t *testing.T) {
	cfg := &config.BackendConfig{
		Endpoint:  "https://backend.example.test",
		UseSSL:    true,
		AccessKey: "a",
		SecretKey: "b",
		TLS:       config.BackendTLSConfig{CAFile: t.TempDir() + "/missing.pem"},
	}
	_, err := NewClientFactory(cfg).GetClient()
	require.Error(t, err)
	require.Contains(t, err.Error(), "build backend HTTP transport")
}

func proxyTLSRequest(t *testing.T, f tlsFixture, tlsConfig config.BackendTLSConfig) error {
	pc, err := NewProxyClient(&config.BackendConfig{Endpoint: f.server.URL, UseSSL: true, TLS: tlsConfig})
	if err != nil {
		return err
	}
	req, _ := http.NewRequest("GET", "/", nil)
	resp, err := pc.ForwardRequest(context.Background(), req, "GET", "bucket", "key", nil)
	if resp != nil {
		resp.Body.Close()
	}
	return err
}

func TestNewProxyClient_CustomCA_VerifiesServer(t *testing.T) {
	f := newTLSFixture(t)
	require.NoError(t, proxyTLSRequest(t, f, config.BackendTLSConfig{CAFile: f.caFile}))
}
func TestNewProxyClient_UntrustedCertificateFails(t *testing.T) {
	f := newTLSFixture(t)
	require.Error(t, proxyTLSRequest(t, f, config.BackendTLSConfig{}))
}
func TestNewProxyClient_InsecureSkipVerify_AllowsUntrustedServer(t *testing.T) {
	f := newTLSFixture(t)
	require.NoError(t, proxyTLSRequest(t, f, config.BackendTLSConfig{InsecureSkipVerify: true}))
}

func TestNewProxyClient_InvalidCA_ReturnsErrorBeforeRequest(t *testing.T) {
	_, err := NewProxyClient(&config.BackendConfig{
		Endpoint: "https://backend.example.test",
		TLS:      config.BackendTLSConfig{CAFile: t.TempDir() + "/missing.pem"},
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "build backend HTTP transport")
}
