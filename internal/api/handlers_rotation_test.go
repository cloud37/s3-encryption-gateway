package api

import (
	"context"
	"strconv"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/audit"
	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
	"github.com/kenchrcum/s3-encryption-gateway/internal/metrics"
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
		name              string
		metadataKeyVersion string
		activeVersion     int
		shouldRecord      bool
		expectedKeyVersion string
	}{
		{
			name:              "Same version (no rotated read)",
			metadataKeyVersion: "2",
			activeVersion:     2,
			shouldRecord:      false,
			expectedKeyVersion: "2",
		},
		{
			name:              "Different version (rotated read)",
			metadataKeyVersion: "1",
			activeVersion:     2,
			shouldRecord:      true,
			expectedKeyVersion: "1",
		},
		{
			name:              "No version in metadata",
			metadataKeyVersion: "",
			activeVersion:     2,
			shouldRecord:      false,
			expectedKeyVersion: "0",
		},
		{
			name:              "Invalid version string",
			metadataKeyVersion: "invalid",
			activeVersion:     2,
			shouldRecord:      false,
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

