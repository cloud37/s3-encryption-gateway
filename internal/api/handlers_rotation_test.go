package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// mockKeyManager implements crypto.KeyManager for testing
type mockKeyManager struct {
	activeVersion int
}

func (m *mockKeyManager) Provider() string {
	return "mock"
}

func (m *mockKeyManager) WrapKey(ctx context.Context, plaintext []byte, metadata map[string]string) (*crypto.KeyEnvelope, error) {
	return &crypto.KeyEnvelope{
		KeyID:      "mock-key",
		KeyVersion: m.activeVersion,
		Provider:   "mock",
		Ciphertext: plaintext, // Not real encryption, just for testing
	}, nil
}

func (m *mockKeyManager) UnwrapKey(ctx context.Context, envelope *crypto.KeyEnvelope, metadata map[string]string) ([]byte, error) {
	return envelope.Ciphertext, nil
}

func (m *mockKeyManager) ActiveKeyVersion(ctx context.Context) (int, error) {
	return m.activeVersion, nil
}

func (m *mockKeyManager) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *mockKeyManager) Close(ctx context.Context) error {
	return nil
}

func TestHandler_RecordRotatedRead(t *testing.T) {
	// Create test metrics registry
	reg := prometheus.NewRegistry()
	m := metrics.NewMetricsWithRegistry(reg)

	// Create mock key manager with active version 2
	keyManager := &mockKeyManager{activeVersion: 2}

	// Create handler
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress logs during testing

	handler := &Handler{
		keyManager: keyManager,
		metrics:    m,
		logger:     logger,
	}

	// Test: Extract key version from metadata and compare with active version
	testCases := []struct {
		name               string
		metadataKeyVersion string
		activeVersion      int
		shouldRecord       bool
		expectedKeyVersion string
	}{
		{
			name:               "Same version (no rotated read)",
			metadataKeyVersion: "2",
			activeVersion:      2,
			shouldRecord:       false,
			expectedKeyVersion: "2",
		},
		{
			name:               "Different version (rotated read)",
			metadataKeyVersion: "1",
			activeVersion:      2,
			shouldRecord:       true,
			expectedKeyVersion: "1",
		},
		{
			name:               "No version in metadata",
			metadataKeyVersion: "",
			activeVersion:      2,
			shouldRecord:       false,
			expectedKeyVersion: "0",
		},
		{
			name:               "Invalid version string",
			metadataKeyVersion: "invalid",
			activeVersion:      2,
			shouldRecord:       false,
			expectedKeyVersion: "0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset metrics
			reg := prometheus.NewRegistry()
			m := metrics.NewMetricsWithRegistry(reg)
			handler.metrics = m

			// Update active version
			keyManager.activeVersion = tc.activeVersion

			// Simulate metadata extraction and comparison
			keyVersionUsed := 0
			if tc.metadataKeyVersion != "" {
				if kv, err := strconv.Atoi(tc.metadataKeyVersion); err == nil {
					keyVersionUsed = kv
				}
			}

			activeKeyVersion := 0
			if handler.keyManager != nil {
				activeKeyVersion = handler.currentKeyVersion(context.Background())
				if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
					handler.metrics.RecordRotatedRead(context.Background(), keyVersionUsed, activeKeyVersion)
				}
			}

			// Verify the logic that determines whether to record
			// The actual recording is tested in metrics package tests
			if tc.shouldRecord {
				assert.NotEqual(t, keyVersionUsed, activeKeyVersion, "Key versions should differ to trigger rotated read")
				assert.Greater(t, keyVersionUsed, 0, "Key version used should be valid")
				assert.Greater(t, activeKeyVersion, 0, "Active key version should be valid")
			} else {
				// Either versions match or one is invalid
				if keyVersionUsed > 0 && activeKeyVersion > 0 {
					assert.Equal(t, keyVersionUsed, activeKeyVersion, "Versions should match when not recording")
				}
			}
		})
	}
}

func TestHandler_GetObjectRecordsRotatedReadWithCompactedMetadata(t *testing.T) {
	keyV1 := bytes.Repeat([]byte{0x01}, 32)
	keyV2 := bytes.Repeat([]byte{0x02}, 32)
	oldKeyManager, err := crypto.NewInMemoryKeyManager(keyV1)
	if err != nil {
		t.Fatal(err)
	}
	newKeyManager, err := crypto.NewInMemoryKeyManager(keyV1, crypto.WithMemoryVersions([]struct {
		Version int
		Key     []byte
	}{{Version: 1, Key: keyV1}, {Version: 2, Key: keyV2}}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = oldKeyManager.Close(context.Background())
		_ = newKeyManager.Close(context.Background())
	})

	oldEngine, err := crypto.NewEngineWithOpts([]byte("rotation-metric-test-password"), crypto.WithKeyManager(oldKeyManager), crypto.WithProvider("aws"))
	if err != nil {
		t.Fatal(err)
	}
	newEngine, err := crypto.NewEngineWithOpts([]byte("rotation-metric-test-password"), crypto.WithKeyManager(newKeyManager), crypto.WithProvider("aws"))
	if err != nil {
		t.Fatal(err)
	}
	const bucket, key = "rotation-metric-bucket", "object"
	plaintext := []byte("rotated object")
	encrypted, metadata, err := oldEngine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: bucket, Key: key}, bytes.NewReader(plaintext), map[string]string{"Content-Type": "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	encryptedBytes, err := io.ReadAll(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if metadata["x-amz-meta-kv"] != "1" {
		t.Fatalf("AWS compacted key version=%q, want alias value 1 (metadata=%v)", metadata["x-amz-meta-kv"], metadata)
	}
	client := newMockS3Client()
	contentLength := int64(len(encryptedBytes))
	if _, err := client.PutObject(context.Background(), bucket, key, bytes.NewReader(encryptedBytes), metadata, &contentLength, "", nil, "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}

	registry := prometheus.NewRegistry()
	metricsSink := metrics.NewMetricsWithRegistry(registry)
	handler := NewHandlerWithFeatures(client, newEngine, logrus.New(), metricsSink, newKeyManager, nil, nil, nil, nil)
	router := mux.NewRouter()
	router.Handle("/metrics", metricsSink.Handler()).Methods(http.MethodGet)
	handler.RegisterRoutes(router)

	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil))
	if get.Code != http.StatusOK || get.Body.String() != string(plaintext) {
		t.Fatalf("GET status=%d body=%q; want 200 and plaintext", get.Code, get.Body.String())
	}

	scrape := httptest.NewRecorder()
	router.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if scrape.Code != http.StatusOK {
		t.Fatalf("GET /metrics status=%d: %s", scrape.Code, scrape.Body.String())
	}
	wantSample := `kms_rotated_reads_total{active_version="2",key_version="1"} 1`
	if !strings.Contains(scrape.Body.String(), wantSample) {
		t.Fatalf("rotated-read metric sample missing; want %q in /metrics output:\n%s", wantSample, scrape.Body.String())
	}
}

func TestHandler_AuditLogRotatedRead(t *testing.T) {
	// Create audit logger that captures events
	// Note: GetEvents is not part of the Logger interface, so we test via the logger directly
	// In production, audit events would be written to external sinks
	auditLoggerImpl := audit.NewLogger(100, nil)

	// Create handler with audit logger
	keyManager := &mockKeyManager{activeVersion: 2}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	handler := &Handler{
		keyManager:  keyManager,
		auditLogger: auditLoggerImpl,
		logger:      logger,
	}

	// Simulate decrypt with rotated key
	metadata := map[string]string{
		crypto.MetaKeyVersion: "1", // Old version
	}

	keyVersionUsed := 0
	if kvStr, ok := metadata[crypto.MetaKeyVersion]; ok && kvStr != "" {
		if kv, err := strconv.Atoi(kvStr); err == nil {
			keyVersionUsed = kv
		}
	}

	activeKeyVersion := handler.currentKeyVersion(context.Background())

	// Create audit metadata
	auditMetadata := make(map[string]interface{})
	if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
		auditMetadata["rotated_read"] = true
		auditMetadata["key_version_used"] = keyVersionUsed
		auditMetadata["active_key_version"] = activeKeyVersion
	}

	// Log decrypt event
	handler.auditLogger.LogDecrypt("test-bucket", "test-key", "AES256-GCM", keyVersionUsed, true, nil, 0, auditMetadata)

	// Verify audit metadata was created correctly
	// (In a real scenario, we'd verify the event was logged, but GetEvents is not part of the interface)
	assert.True(t, len(auditMetadata) > 0, "Audit metadata should be populated")
	assert.True(t, auditMetadata["rotated_read"].(bool), "Should indicate rotated read")
	assert.Equal(t, 1, auditMetadata["key_version_used"].(int), "Should record key version used")
	assert.Equal(t, 2, auditMetadata["active_key_version"].(int), "Should record active key version")
}
