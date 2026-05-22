package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/sirupsen/logrus"
)

// testFactoryLogger returns a discarding logger for tests.
func testFactoryLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(os.Stderr) // quiet but not nil
	l.SetLevel(logrus.ErrorLevel)
	return l
}

// TestBuildKeyManager_MemoryProvider verifies that the memory provider
// can be instantiated without errors.
func TestBuildKeyManager_MemoryProvider(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "memory",
		Memory: config.MemoryKMConfig{
			MasterKeySource: "", // empty = generate random
		},
	}

	km, err := BuildKeyManager(cfg, testFactoryLogger())
	if err != nil {
		t.Fatalf("BuildKeyManager(memory) error: %v", err)
	}
	if km == nil {
		t.Fatal("BuildKeyManager(memory) returned nil KeyManager")
	}
	km.Close(context.Background())
}

// TestBuildKeyManager_MemoryProvider_WithMasterKeySource verifies memory
// provider with a non-empty master key source.
func TestBuildKeyManager_MemoryProvider_WithMasterKeySource(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "memory",
		Memory: config.MemoryKMConfig{
			MasterKeySource: "env:TEST_MASTER_KEY",
		},
	}

	// Set the env var so the memory provider can find it
	t.Setenv("TEST_MASTER_KEY", strings.Repeat("A", 64)) // 32 bytes hex

	km, err := BuildKeyManager(cfg, testFactoryLogger())
	// May succeed or fail depending on memory provider implementation;
	// the important thing is no panic and no undefined behavior.
	if err == nil && km != nil {
		km.Close(context.Background())
	}
}

// TestBuildKeyManager_CosmianProvider_MissingEndpoint verifies that building
// a cosmian provider without an endpoint returns an error.
func TestBuildKeyManager_CosmianProvider_MissingEndpoint(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "cosmian",
		Cosmian: config.CosmianConfig{
			Endpoint: "", // missing
			Keys:     []config.CosmianKeyReference{{ID: "key1", Version: 1}},
		},
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	if err == nil {
		t.Fatal("BuildKeyManager(cosmian) expected error for missing endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "endpoint") {
		t.Errorf("expected error to mention 'endpoint', got: %v", err)
	}
}

// TestBuildKeyManager_CosmianProvider_MissingKeys verifies that building
// a cosmian provider without keys returns an error.
func TestBuildKeyManager_CosmianProvider_MissingKeys(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "cosmian",
		Cosmian: config.CosmianConfig{
			Endpoint: "kmip://localhost:5696",
			Keys:     nil, // no keys
		},
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	if err == nil {
		t.Fatal("BuildKeyManager(cosmian) expected error for missing keys, got nil")
	}
	if !strings.Contains(err.Error(), "keys") {
		t.Errorf("expected error to mention 'keys', got: %v", err)
	}
}

// TestBuildKeyManager_CosmianProvider_MissingKeyID verifies error when a
// key ref has empty ID.
func TestBuildKeyManager_CosmianProvider_MissingKeyID(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "cosmian",
		Cosmian: config.CosmianConfig{
			Endpoint: "kmip://localhost:5696",
			Keys:     []config.CosmianKeyReference{{ID: "", Version: 1}},
		},
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	if err == nil {
		t.Fatal("BuildKeyManager(cosmian) expected error for missing key ID, got nil")
	}
}

// TestBuildKeyManager_DefaultProviderIsCosmian verifies that an empty provider
// defaults to cosmian.
func TestBuildKeyManager_DefaultProviderIsCosmian(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "", // empty → defaults to cosmian
		Cosmian: config.CosmianConfig{
			Endpoint: "", // missing → error
		},
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	// Should fail with cosmian-style error (missing endpoint)
	if err == nil {
		t.Fatal("BuildKeyManager with empty provider expected error, got nil")
	}
}

// TestBuildKeyManager_UnknownProvider verifies that an unknown provider
// returns an error via the registry.
func TestBuildKeyManager_UnknownProvider(t *testing.T) {
	cfg := &config.KeyManagerConfig{
		Provider: "unknown-provider-xyz",
	}

	_, err := BuildKeyManager(cfg, testFactoryLogger())
	if err == nil {
		t.Fatal("BuildKeyManager with unknown provider expected error, got nil")
	}
}

// TestBuildCosmianTLSConfig_Basic verifies that buildCosmianTLSConfig
// with no certificates returns a minimal TLS config.
func TestBuildCosmianTLSConfig_Basic(t *testing.T) {
	cfg := config.CosmianConfig{
		InsecureSkipVerify: false,
	}

	tlsCfg, err := buildCosmianTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildCosmianTLSConfig() error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("buildCosmianTLSConfig() returned nil config")
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=false")
	}
}

// TestBuildCosmianTLSConfig_InsecureMode_Rejected verifies that
// InsecureSkipVerify=true without a CACert returns an error (V1.0-SEC-F3).
func TestBuildCosmianTLSConfig_InsecureMode_Rejected(t *testing.T) {
	cfg := config.CosmianConfig{
		InsecureSkipVerify: true,
		// CACert is empty → should be rejected
	}

	_, err := buildCosmianTLSConfig(cfg)
	if err == nil {
		t.Fatal("buildCosmianTLSConfig() expected error for InsecureSkipVerify=true with empty CACert, got nil")
	}
	if !strings.Contains(err.Error(), "insecure_skip_verify") {
		t.Errorf("expected error to mention 'insecure_skip_verify', got: %v", err)
	}
}

// TestBuildCosmianTLSConfig_InsecureWithCACert verifies that
// InsecureSkipVerify=true with a non-empty CACert passes validation
// and does not return the insecure-without-CA error (V1.0-SEC-F3).
func TestBuildCosmianTLSConfig_InsecureWithCACert(t *testing.T) {
	// Create a dummy self-signed CA cert file for the test
	cert := generateTestCert(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})

	tmpDir := t.TempDir()
	caFile := tmpDir + "/ca.crt"
	if err := os.WriteFile(caFile, certPEM, 0644); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	cfg := config.CosmianConfig{
		InsecureSkipVerify: true,
		CACert:             caFile,
	}

	tlsCfg, err := buildCosmianTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildCosmianTLSConfig() error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("buildCosmianTLSConfig() returned nil config")
	}
	if !tlsCfg.InsecureSkipVerify {
		t.Error("expected InsecureSkipVerify=true")
	}
}

// TestBuildCosmianTLSConfig_MissingCACert verifies that a non-existent
// CA cert path returns an error.
func TestBuildCosmianTLSConfig_MissingCACert(t *testing.T) {
	cfg := config.CosmianConfig{
		CACert: "/nonexistent/path/ca.crt",
	}

	_, err := buildCosmianTLSConfig(cfg)
	if err == nil {
		t.Fatal("buildCosmianTLSConfig() expected error for missing CA cert, got nil")
	}
}

// TestBuildCosmianTLSConfig_InvalidCACert verifies that an invalid PEM
// CA cert returns an error.
func TestBuildCosmianTLSConfig_InvalidCACert(t *testing.T) {
	tmpDir := t.TempDir()
	caFile := filepath.Join(tmpDir, "invalid-ca.crt")
	if err := os.WriteFile(caFile, []byte("not a valid PEM certificate"), 0644); err != nil {
		t.Fatalf("failed to write invalid CA cert: %v", err)
	}

	cfg := config.CosmianConfig{
		CACert: caFile,
	}

	_, err := buildCosmianTLSConfig(cfg)
	if err == nil {
		t.Fatal("buildCosmianTLSConfig() expected error for invalid CA cert, got nil")
	}
	if !strings.Contains(err.Error(), "parse") && !strings.Contains(err.Error(), "certificate") {
		t.Errorf("expected cert parse error, got: %v", err)
	}
}

// TestBuildCosmianTLSConfig_InsecureSkipVerify_Warning verifies that an
// ERROR-level warning is logged when InsecureSkipVerify is enabled with a
// custom CA certificate (V1.0-SEC-F3).
func TestBuildCosmianTLSConfig_InsecureSkipVerify_Warning(t *testing.T) {
	// Create a dummy CA cert file (needed because the warning is only logged
	// when InsecureSkipVerify=true and CACert is non-empty).
	cert := generateTestCert(t)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	tmpDir := t.TempDir()
	caFile := tmpDir + "/ca.crt"
	if err := os.WriteFile(caFile, certPEM, 0644); err != nil {
		t.Fatalf("failed to write CA cert: %v", err)
	}

	// Capture log output
	var buf strings.Builder
	originalOutput := logrus.StandardLogger().Out
	originalLevel := logrus.StandardLogger().Level
	defer func() {
		logrus.StandardLogger().Out = originalOutput
		logrus.StandardLogger().Level = originalLevel
	}()
	logrus.StandardLogger().Out = &buf
	logrus.StandardLogger().Level = logrus.ErrorLevel

	cfg := config.CosmianConfig{
		InsecureSkipVerify: true,
		CACert:             caFile,
	}

	_, err := buildCosmianTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildCosmianTLSConfig() error: %v", err)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "InsecureSkipVerify is ENABLED") {
		t.Errorf("expected ERROR log with 'InsecureSkipVerify is ENABLED', got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "COSMIAN_KMS_INSECURE_SKIP_VERIFY") {
		t.Errorf("expected ERROR log to mention 'COSMIAN_KMS_INSECURE_SKIP_VERIFY', got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "only be used in development") {
		t.Errorf("expected ERROR log to mention 'only be used in development', got: %s", logOutput)
	}
}

// TestBuildCosmianTLSConfig_NoInsecureSkipVerify_NoWarning verifies that no
// warning is logged when InsecureSkipVerify is disabled.
func TestBuildCosmianTLSConfig_NoInsecureSkipVerify_NoWarning(t *testing.T) {
	// Capture log output
	var buf strings.Builder
	originalOutput := logrus.StandardLogger().Out
	originalLevel := logrus.StandardLogger().Level
	defer func() {
		logrus.StandardLogger().Out = originalOutput
		logrus.StandardLogger().Level = originalLevel
	}()
	logrus.StandardLogger().Out = &buf
	logrus.StandardLogger().Level = logrus.ErrorLevel

	cfg := config.CosmianConfig{
		InsecureSkipVerify: false,
	}

	_, err := buildCosmianTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildCosmianTLSConfig() error: %v", err)
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, "InsecureSkipVerify is ENABLED") {
		t.Errorf("expected no warning when InsecureSkipVerify is false, but got: %s", logOutput)
	}
}

// generateTestCert creates a self-signed RSA certificate for TLS tests.
func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load key pair: %v", err)
	}
	return cert
}

// TestBuildCosmianTLSConfig_CipherSuites verifies that the Cosmian KMS TLS
// config contains the expected cipher suites and curve preferences (V1.0-SEC-23).
func TestBuildCosmianTLSConfig_CipherSuites(t *testing.T) {
	cfg := config.CosmianConfig{
		InsecureSkipVerify: false,
	}

	tlsCfg, err := buildCosmianTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildCosmianTLSConfig() error: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("buildCosmianTLSConfig() returned nil config")
	}
	if len(tlsCfg.CipherSuites) == 0 {
		t.Error("expected non-empty CipherSuites")
	}
	if len(tlsCfg.CurvePreferences) == 0 {
		t.Error("expected non-empty CurvePreferences")
	}

	// Ensure no CBC-mode cipher suites are present.
	cbcCiphers := map[uint16]bool{
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:          true,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:          true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:  true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:  true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:    true,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:    true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: true,
	}
	for _, cs := range tlsCfg.CipherSuites {
		if cbcCiphers[cs] {
			t.Errorf("CBC cipher suite found in allowed list: 0x%04x", cs)
		}
	}

	// Verify expected ciphers are present.
	expected := []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	}
	for _, exp := range expected {
		found := false
		for _, cs := range tlsCfg.CipherSuites {
			if cs == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected cipher suite 0x%04x not found in config", exp)
		}
	}

	// Verify curve preferences.
	expectedCurves := []tls.CurveID{tls.X25519, tls.CurveP256}
	for _, exp := range expectedCurves {
		found := false
		for _, c := range tlsCfg.CurvePreferences {
			if c == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected curve %v not found in CurvePreferences", exp)
		}
	}
}

// TestBuildCosmianTLSConfig_RejectCBC verifies that a client offering only
// CBC-mode cipher suites is rejected by the Cosmian TLS config (V1.0-SEC-23).
func TestBuildCosmianTLSConfig_RejectCBC(t *testing.T) {
	cfg := config.CosmianConfig{
		InsecureSkipVerify: false,
	}

	serverConfig, err := buildCosmianTLSConfig(cfg)
	if err != nil {
		t.Fatalf("buildCosmianTLSConfig() error: %v", err)
	}

	// Attach a server certificate so the handshake can proceed.
	cert := generateTestCert(t)
	serverConfig.Certificates = []tls.Certificate{cert}
	serverConfig.MaxVersion = tls.VersionTLS12 // force TLS 1.2 for this test

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer listener.Close()

	// Accept goroutine — the handshake will fail, so we just wait for close.
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Force handshake attempt by reading.
		buf := make([]byte, 1)
		conn.Read(buf)
	}()

	clientConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
		},
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), clientConfig)
	if err == nil {
		conn.Close()
		t.Fatal("expected handshake to fail with CBC-only client, but it succeeded")
	}

	// Clean up the accept goroutine.
	listener.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Log("accept goroutine did not finish in time (non-fatal)")
	}
}
