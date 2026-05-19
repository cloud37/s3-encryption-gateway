//go:build !fips

package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gorilla/mux"
	"github.com/kenneth/s3-encryption-gateway/internal/config"
	"github.com/kenneth/s3-encryption-gateway/internal/crypto"
	"github.com/kenneth/s3-encryption-gateway/internal/mpu"
	"github.com/sirupsen/logrus"
)

// TestMPU_InitAlgorithm_ThreadsPreferredAlgorithm verifies that
// initMPUEncryptionState stores the engine's preferred algorithm in
// UploadState (V1.0-SEC-25).
func TestMPU_InitAlgorithm_ThreadsPreferredAlgorithm(t *testing.T) {
	// Build a handler with a ChaCha20-Poly1305 preferred engine.
	engine, err := crypto.NewEngineWithOptions([]byte(mpuTestPassword), nil, crypto.AlgorithmChaCha20Poly1305, nil)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	mockClient := newMPUMockS3Client()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	policyDir := t.TempDir()
	policyYAML := fmt.Sprintf(`id: test-mpu-chacha20
buckets:
  - "chacha20-*"
encrypt_multipart_uploads: true
`)
	policyPath := policyDir + "/policy.yaml"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{policyPath}); err != nil {
		t.Fatalf("load policies: %v", err)
	}

	cfg := &config.Config{
		Server:     config.ServerConfig{},
		Encryption: config.EncryptionConfig{Password: mpuTestPassword},
	}

	// Password-mode KeyManager — mirrors what cmd/server/main.go does.
	km, err := crypto.NewPasswordKeyManager([]byte(mpuTestPassword), crypto.DefaultPBKDF2Iterations)
	if err != nil {
		t.Fatalf("password keymanager: %v", err)
	}

	mr := miniredis.RunT(t)
	stateStore, err := mpu.NewValkeyStateStore(context.Background(), config.ValkeyConfig{
		EncryptState:           config.BoolPtr(false),
		Addr:                   mr.Addr(),
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             3600,
		DialTimeout:            2 * time.Second,
		ReadTimeout:            1 * time.Second,
		WriteTimeout:           1 * time.Second,
		PoolSize:               2,
	}, "")
	if err != nil {
		t.Fatalf("new valkey state store: %v", err)
	}
	t.Cleanup(func() { _ = stateStore.Close() })

	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(), km, nil, nil, cfg, pm)
	handler.WithMPUStateStore(stateStore)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "chacha20-bucket", "obj.bin"
	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// Retrieve the state from the store and verify the algorithm field.
	state, err := stateStore.Get(context.Background(), uploadID)
	if err != nil {
		t.Fatalf("get state: %v", err)
	}
	if state.Algorithm != crypto.AlgorithmChaCha20Poly1305 {
		t.Errorf("UploadState.Algorithm = %q, want %q", state.Algorithm, crypto.AlgorithmChaCha20Poly1305)
	}
}

// TestMPU_ChaCha20Poly1305_EndToEnd verifies a full upload → complete → GET
// round-trip when the engine is configured for ChaCha20-Poly1305.
func TestMPU_ChaCha20Poly1305_EndToEnd(t *testing.T) {
	engine, err := crypto.NewEngineWithOptions([]byte(mpuTestPassword), nil, crypto.AlgorithmChaCha20Poly1305, nil)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	mockClient := newMPUMockS3Client()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	policyDir := t.TempDir()
	policyYAML := fmt.Sprintf(`id: test-mpu-chacha20
buckets:
  - "chacha20e2e-*"
encrypt_multipart_uploads: true
`)
	policyPath := policyDir + "/policy.yaml"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{policyPath}); err != nil {
		t.Fatalf("load policies: %v", err)
	}

	cfg := &config.Config{
		Server:     config.ServerConfig{},
		Encryption: config.EncryptionConfig{Password: mpuTestPassword},
	}

	// Password-mode KeyManager — mirrors what cmd/server/main.go does.
	km, err := crypto.NewPasswordKeyManager([]byte(mpuTestPassword), crypto.DefaultPBKDF2Iterations)
	if err != nil {
		t.Fatalf("password keymanager: %v", err)
	}

	mr := miniredis.RunT(t)
	stateStore, err := mpu.NewValkeyStateStore(context.Background(), config.ValkeyConfig{
		EncryptState:           config.BoolPtr(false),
		Addr:                   mr.Addr(),
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             3600,
		DialTimeout:            2 * time.Second,
		ReadTimeout:            1 * time.Second,
		WriteTimeout:           1 * time.Second,
		PoolSize:               2,
	}, "")
	if err != nil {
		t.Fatalf("new valkey state store: %v", err)
	}
	t.Cleanup(func() { _ = stateStore.Close() })

	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(), km, nil, nil, cfg, pm)
	handler.WithMPUStateStore(stateStore)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "chacha20e2e-bucket", "obj.bin"
	plain := bytes.Repeat([]byte("C"), 1024*1024)
	doCompleteUpload(t, router, bucket, key, plain)

	req := httptest.NewRequest("GET", "/"+bucket+"/"+key, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), plain) {
		t.Fatalf("plaintext mismatch: want %d bytes, got %d bytes", len(plain), len(w.Body.Bytes()))
	}
}
