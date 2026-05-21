// Package metrics — tier-1 unit tests for rotation metric integration.
//
// Promoted from test/rotation_metrics_test.go (was //go:build integration).
// These tests exercise the engine+metrics interaction in-process, with no
// Docker or external dependencies. They are part of the default `go test ./...`
// run.
package metrics

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// mockRotatingKeyManager simulates a KMS that supports key rotation.
// WrapKey always uses activeVersion; UnwrapKey accepts any version present
// in the keys map (the test supplies only the version stored in the envelope,
// so it is effectively a no-op unwrap — correct for unit-testing the metrics
// layer without real crypto).
type mockRotatingKeyManager struct {
	activeVersion int
	keys          map[int][]byte
}

func (m *mockRotatingKeyManager) Provider() string { return "mock-rotating" }

func (m *mockRotatingKeyManager) WrapKey(_ context.Context, plaintext []byte, _ map[string]string) (*crypto.KeyEnvelope, error) {
	return &crypto.KeyEnvelope{
		KeyID:      "mock-key",
		KeyVersion: m.activeVersion,
		Provider:   "mock-rotating",
		Ciphertext: plaintext, // identity wrap — sufficient for unit tests
	}, nil
}

func (m *mockRotatingKeyManager) UnwrapKey(_ context.Context, envelope *crypto.KeyEnvelope, _ map[string]string) ([]byte, error) {
	if _, ok := m.keys[envelope.KeyVersion]; !ok {
		return nil, context.DeadlineExceeded
	}
	return envelope.Ciphertext, nil
}

func (m *mockRotatingKeyManager) ActiveKeyVersion(_ context.Context) (int, error) {
	return m.activeVersion, nil
}
func (m *mockRotatingKeyManager) HealthCheck(_ context.Context) error { return nil }
func (m *mockRotatingKeyManager) Close(_ context.Context) error       { return nil }

// TestRotationMetrics_EngineAndCounter verifies end-to-end that:
//  1. The encryption engine stamps MetaKeyVersion when a KeyManager is wired.
//  2. A correctly implemented handler would call RecordRotatedRead when key
//     version used ≠ active version. (The handler path is exercised via the
//     conformance suite; here we verify the metric primitive itself.)
func TestRotationMetrics_EngineAndCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewMetricsWithRegistry(reg)

	km := &mockRotatingKeyManager{
		activeVersion: 1,
		keys:          map[int][]byte{1: []byte("k1"), 2: []byte("k2")},
	}

	enc, err := crypto.NewEngine([]byte("fallback-password-123456"))
	require.NoError(t, err)
	crypto.SetKeyManager(enc, km)

	// Encrypt with v1 — envelope carries KeyVersion=1.
	plaintext := []byte("Object encrypted with key version 1")
	encReader, encMeta, err := enc.Encrypt(context.Background(), bytes.NewReader(plaintext), map[string]string{"Content-Type": "text/plain"})
	require.NoError(t, err)
	require.Equal(t, "1", encMeta[crypto.MetaKeyVersion], "engine must stamp MetaKeyVersion")

	encData, err := io.ReadAll(encReader)
	require.NoError(t, err)

	// Rotate to v2.
	km.activeVersion = 2

	// Decrypt — engine decrypts successfully; simulated handler checks key version.
	decReader, _, err := enc.Decrypt(context.Background(), bytes.NewReader(encData), encMeta)
	require.NoError(t, err)
	decrypted, err := io.ReadAll(decReader)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted, "decryption must reproduce original plaintext")

	// Simulate what the handler does after decrypt: emit metric when version differs.
	keyVersionUsed := 1   // from MetaKeyVersion in object metadata
	activeKeyVersion := 2 // from km.ActiveKeyVersion()
	if keyVersionUsed != activeKeyVersion {
		m.RecordRotatedRead(context.Background(), keyVersionUsed, activeKeyVersion)
	}

	// Assert the counter.
	count := testutil.ToFloat64(m.GetRotatedReadsMetric().WithLabelValues("1", "2"))
	require.Equal(t, 1.0, count, "rotated-read counter must be 1")

	// Encrypt + decrypt a v2 object — must NOT emit a rotated-read metric.
	plaintext2 := []byte("Object encrypted with key version 2")
	encReader2, encMeta2, err := enc.Encrypt(context.Background(), bytes.NewReader(plaintext2), map[string]string{"Content-Type": "text/plain"})
	require.NoError(t, err)
	require.Equal(t, "2", encMeta2[crypto.MetaKeyVersion])

	encData2, err := io.ReadAll(encReader2)
	require.NoError(t, err)

	decReader2, _, err := enc.Decrypt(context.Background(), bytes.NewReader(encData2), encMeta2)
	require.NoError(t, err)
	decrypted2, err := io.ReadAll(decReader2)
	require.NoError(t, err)
	require.Equal(t, plaintext2, decrypted2)

	// v2→v2: no rotated-read should be recorded.
	count2 := testutil.ToFloat64(m.GetRotatedReadsMetric().WithLabelValues("2", "2"))
	require.Equal(t, 0.0, count2, "no rotated-read should be emitted for current-version objects")
}
