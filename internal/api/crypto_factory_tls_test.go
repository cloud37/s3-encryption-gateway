package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

func genTestCA(t *testing.T) (pemPath string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemPath = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(pemPath, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return pemPath, caCert, caKey
}

func genTestLeaf(t *testing.T, signer *x509.Certificate, signerKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "bao.internal"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &leafKey.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// TestBuildOpenBaoTLSConfig_Semantics verifies the honest TLS verification
// behaviour: a pinned CA combined with insecure_skip_verify must perform REAL
// chain verification via VerifyConnection rather than silently trusting any
// certificate (InsecureSkipVerify alone would make RootCAs a no-op).
func TestBuildOpenBaoTLSConfig_Semantics(t *testing.T) {
	caPath, caCert, caKey := genTestCA(t)

	t.Run("no_ca_secure", func(t *testing.T) {
		c, err := buildOpenBaoTLSConfig(config.OpenBaoTLSConfig{})
		if err != nil {
			t.Fatal(err)
		}
		if c.InsecureSkipVerify || c.RootCAs != nil || c.VerifyConnection != nil {
			t.Fatalf("expected default secure config, got skip=%v rootCAs=%v verifyConn=%v", c.InsecureSkipVerify, c.RootCAs != nil, c.VerifyConnection != nil)
		}
	})

	t.Run("no_ca_insecure_dev", func(t *testing.T) {
		c, err := buildOpenBaoTLSConfig(config.OpenBaoTLSConfig{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		if !c.InsecureSkipVerify || c.VerifyConnection != nil {
			t.Fatalf("dev insecure: want skip=true verifyConn=nil, got skip=%v verifyConn=%v", c.InsecureSkipVerify, c.VerifyConnection != nil)
		}
	})

	t.Run("ca_secure", func(t *testing.T) {
		c, err := buildOpenBaoTLSConfig(config.OpenBaoTLSConfig{CACert: caPath})
		if err != nil {
			t.Fatal(err)
		}
		if c.InsecureSkipVerify || c.RootCAs == nil || c.VerifyConnection != nil {
			t.Fatalf("ca secure: want skip=false rootCAs!=nil verifyConn=nil, got skip=%v rootCAs=%v verifyConn=%v", c.InsecureSkipVerify, c.RootCAs != nil, c.VerifyConnection != nil)
		}
	})

	t.Run("ca_insecure_pins_via_verifyconnection", func(t *testing.T) {
		c, err := buildOpenBaoTLSConfig(config.OpenBaoTLSConfig{CACert: caPath, InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		if !c.InsecureSkipVerify || c.VerifyConnection == nil {
			t.Fatalf("ca+insecure: want skip=true verifyConn!=nil, got skip=%v verifyConn=%v", c.InsecureSkipVerify, c.VerifyConnection != nil)
		}

		// A leaf signed by the pinned CA must be accepted.
		good := genTestLeaf(t, caCert, caKey)
		if err := c.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{good}}); err != nil {
			t.Errorf("VerifyConnection rejected a cert signed by the pinned CA: %v", err)
		}

		// A leaf signed by a different CA must be rejected (this is the bug the
		// old code had: it would have been silently trusted).
		_, otherCA, otherKey := genTestCA(t)
		bad := genTestLeaf(t, otherCA, otherKey)
		if err := c.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{bad}}); err == nil {
			t.Error("VerifyConnection accepted a cert NOT signed by the pinned CA — pinning is ineffective")
		}
	})
}

func genTestTLSCertificate(t *testing.T, template, signer *x509.Certificate, signerKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestBuildCosmianTLSConfig_VerifyConnection(t *testing.T) {
	caPath, ca, caKey := genTestCA(t)
	cfg, err := buildCosmianTLSConfig(config.CosmianConfig{CACert: caPath, InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VerifyConnection == nil {
		t.Fatal("hostname-only bypass must retain pinned chain verification")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("accepted a connection without peer certificates")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{genTestLeaf(t, ca, caKey)}}); err != nil {
		t.Fatalf("rejected trusted leaf: %v", err)
	}

	for _, tc := range []struct {
		name  string
		after time.Time
		usage x509.ExtKeyUsage
	}{
		{"expired", time.Now().Add(-time.Minute), x509.ExtKeyUsageServerAuth},
		{"wrong_key_usage", time.Now().Add(time.Hour), x509.ExtKeyUsageClientAuth},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := genTestTLSCertificate(t, &x509.Certificate{
				SerialNumber: big.NewInt(3), NotBefore: time.Now().Add(-time.Hour), NotAfter: tc.after,
				KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{tc.usage},
			}, ca, caKey)
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err == nil {
				t.Fatal("accepted invalid server certificate")
			}
		})
	}

	// The server supplies the intermediate; it need not be in the pinned file.
	intermediate := genTestTLSCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(4), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, ca, caKey)
	intermediateCA, err := x509.ParseCertificate(intermediate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf := genTestLeaf(t, intermediateCA, intermediate.PrivateKey.(*ecdsa.PrivateKey))
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf, intermediateCA}}); err != nil {
		t.Fatalf("rejected trusted intermediate chain: %v", err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err == nil {
		t.Fatal("accepted incomplete chain without required intermediate")
	}
}

// Exercise real handshakes, not just callbacks: trusted SAN mismatches work
// only under the explicit opt-in, while an unrelated CA is always rejected.
func TestBuildKMSTLSConfig_PinnedCAHandshake(t *testing.T) {
	caPath, ca, caKey := genTestCA(t)
	_, otherCA, otherKey := genTestCA(t)
	for _, provider := range []struct {
		name  string
		build func(bool) (*tls.Config, error)
	}{
		{"cosmian", func(skip bool) (*tls.Config, error) {
			return buildCosmianTLSConfig(config.CosmianConfig{CACert: caPath, InsecureSkipVerify: skip})
		}},
		{"openbao", func(skip bool) (*tls.Config, error) {
			return buildOpenBaoTLSConfig(config.OpenBaoTLSConfig{CACert: caPath, InsecureSkipVerify: skip})
		}},
	} {
		t.Run(provider.name, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				skip    bool
				trusted bool
			}{
				{"trusted_hostname_opt_in", true, true},
				{"trusted_hostname_mismatch_secure", false, true},
				{"untrusted_ca_with_opt_in", true, false},
				{"untrusted_ca_secure", false, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					signer, key := ca, caKey
					if !tc.trusted {
						signer, key = otherCA, otherKey
					}
					cert := genTestTLSCertificate(t, &x509.Certificate{
						SerialNumber: big.NewInt(5), DNSNames: []string{"kms.internal"},
						NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
						KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
					}, signer, key)
					var calls atomic.Int32
					server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						w.WriteHeader(http.StatusNoContent)
					}))
					server.Config.ErrorLog = log.New(io.Discard, "", 0)
					server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
					server.StartTLS()
					defer server.Close()
					cfg, err := provider.build(tc.skip)
					if err != nil {
						t.Fatal(err)
					}
					transport := &http.Transport{TLSClientConfig: cfg}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
					resp, err := client.Get(server.URL)
					if tc.trusted && tc.skip {
						if err != nil {
							t.Fatalf("trusted chain with hostname opt-in failed: %v", err)
						}
						defer resp.Body.Close()
						if resp.StatusCode != http.StatusNoContent || calls.Load() != 1 {
							t.Fatalf("trusted request: status=%d calls=%d", resp.StatusCode, calls.Load())
						}
						return
					}
					if resp != nil {
						resp.Body.Close()
					}
					if err == nil || calls.Load() != 0 {
						t.Fatalf("unverified request reached server: err=%v calls=%d", err, calls.Load())
					}
					if tc.skip {
						var unknownCA x509.UnknownAuthorityError
						if !errors.As(err, &unknownCA) {
							t.Fatalf("expected pinned CA rejection, got %v", err)
						}
					} else {
						var verification *tls.CertificateVerificationError
						if !errors.As(err, &verification) {
							t.Fatalf("expected standard TLS verification failure, got %v", err)
						}
					}
				})
			}
		})
	}
}
