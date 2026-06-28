package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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
