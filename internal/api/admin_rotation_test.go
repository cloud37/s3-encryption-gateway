package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func testRotationLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(io.Discard)
	return l
}

func testMetrics() *metrics.Metrics {
	reg := prometheus.NewRegistry()
	return metrics.NewMetricsWithRegistry(reg)
}

// setupMemoryKMAndEngine creates an engine with a memory KeyManager configured
// with two versions (1 and 2) for testing rotation.
func setupMemoryKMAndEngine(t *testing.T) (crypto.EncryptionEngine, crypto.KeyManager) {
	t.Helper()

	masterKey1 := make([]byte, 32)
	if _, err := rand.Read(masterKey1); err != nil {
		t.Fatal(err)
	}

	cfg := map[string]any{
		"source":  "env",
		"version": float64(1),
	}

	km, err := crypto.Open(context.Background(), "memory", cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Add a second version for rotation target
	rkm := km.(crypto.RotatableKeyManager)
	masterKey2 := make([]byte, 32)
	if _, err := rand.Read(masterKey2); err != nil {
		t.Fatal(err)
	}

	memKM := km.(*crypto.InMemoryKeyManagerForTest)
	if memKM == nil {
		// Fallback: use AddVersion via the interface
		if adder, ok := km.(interface {
			AddVersion(ctx context.Context, version int, material []byte) error
		}); ok {
			if err := adder.AddVersion(context.Background(), 2, masterKey2); err != nil {
				t.Fatal(err)
			}
		}
	}
	_ = rkm // just verify the assertion succeeds

	eng, err := crypto.NewEngineWithChunking(
		[]byte("test-password1234"),
		"", nil, false, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	crypto.SetKeyManager(eng, km)

	return eng, km
}

func TestAdminRotateStart_NoKeyManager(t *testing.T) {
	eng, err := crypto.NewEngine([]byte("test-password1234"))
	if err != nil {
		t.Fatal(err)
	}

	h := NewAdminRotationHandler(eng, testRotationLogger(), testMetrics(), nil)
	req := httptest.NewRequest("POST", "/admin/kms/rotate/start", nil)
	w := httptest.NewRecorder()
	h.handleRotateStart(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminRotateStatus_Idle(t *testing.T) {
	eng, err := crypto.NewEngine([]byte("test-password1234"))
	if err != nil {
		t.Fatal(err)
	}

	h := NewAdminRotationHandler(eng, testRotationLogger(), testMetrics(), nil)
	req := httptest.NewRequest("GET", "/admin/kms/rotate/status", nil)
	w := httptest.NewRecorder()
	h.handleRotateStatus(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var snap crypto.RotationSnapshot
	if err := json.NewDecoder(w.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	if snap.Phase != "idle" {
		t.Fatalf("expected idle, got %s", snap.Phase)
	}
}

func TestAdminRotateAbort_NoRotation(t *testing.T) {
	eng, err := crypto.NewEngine([]byte("test-password1234"))
	if err != nil {
		t.Fatal(err)
	}

	h := NewAdminRotationHandler(eng, testRotationLogger(), testMetrics(), nil)
	req := httptest.NewRequest("POST", "/admin/kms/rotate/abort", nil)
	w := httptest.NewRecorder()
	h.handleRotateAbort(w, req)

	// Should return 409 because there's nothing to abort
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminRotateCommit_NoKeyManager(t *testing.T) {
	eng, err := crypto.NewEngine([]byte("test-password1234"))
	if err != nil {
		t.Fatal(err)
	}

	h := NewAdminRotationHandler(eng, testRotationLogger(), testMetrics(), nil)
	req := httptest.NewRequest("POST", "/admin/kms/rotate/commit", nil)
	w := httptest.NewRecorder()
	h.handleRotateCommit(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminRotateStartCommit_Happy(t *testing.T) {
	// Create an in-memory key manager with 2 versions
	masterKey1 := make([]byte, 32)
	rand.Read(masterKey1)
	masterKey2 := make([]byte, 32)
	rand.Read(masterKey2)

	km := crypto.NewInMemoryKeyManagerForTestWithKeys(masterKey1, 1)
	km.AddVersion(context.Background(), 2, masterKey2)

	eng, err := crypto.NewEngineWithChunking([]byte("test-password1234"), "", nil, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	crypto.SetKeyManager(eng, km)

	m := testMetrics()
	h := NewAdminRotationHandler(eng, testRotationLogger(), m, nil)

	// Start rotation
	body := `{"grace_period": "100ms"}`
	req := httptest.NewRequest("POST", "/admin/kms/rotate/start", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleRotateStart(w, req)

	if w.Code != http.StatusAccepted {
		t.Fatalf("start: expected 202, got %d: %s", w.Code, w.Body.String())
	}

	var startResp rotateStartResponse
	if err := json.NewDecoder(w.Body).Decode(&startResp); err != nil {
		t.Fatal(err)
	}
	if startResp.Phase != "draining" {
		t.Fatalf("expected draining, got %s", startResp.Phase)
	}
	if startResp.TargetVersion != 2 {
		t.Fatalf("expected target_version=2, got %d", startResp.TargetVersion)
	}

	// Wait for drain to complete
	time.Sleep(300 * time.Millisecond)

	// Commit
	req = httptest.NewRequest("POST", "/admin/kms/rotate/commit", nil)
	w = httptest.NewRecorder()
	h.handleRotateCommit(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("commit: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var commitSnap crypto.RotationSnapshot
	if err := json.NewDecoder(w.Body).Decode(&commitSnap); err != nil {
		t.Fatal(err)
	}
	if commitSnap.Phase != "committed" {
		t.Fatalf("expected committed, got %s", commitSnap.Phase)
	}

	// Verify active version changed
	ver, err := km.ActiveKeyVersion(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ver != 2 {
		t.Fatalf("expected active version 2, got %d", ver)
	}
}

func TestAdminRotateStart_ConflictOnSecond(t *testing.T) {
	masterKey1 := make([]byte, 32)
	rand.Read(masterKey1)
	masterKey2 := make([]byte, 32)
	rand.Read(masterKey2)

	km := crypto.NewInMemoryKeyManagerForTestWithKeys(masterKey1, 1)
	km.AddVersion(context.Background(), 2, masterKey2)

	eng, err := crypto.NewEngineWithChunking([]byte("test-password1234"), "", nil, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	crypto.SetKeyManager(eng, km)

	h := NewAdminRotationHandler(eng, testRotationLogger(), testMetrics(), nil)

	// Start first rotation
	req := httptest.NewRequest("POST", "/admin/kms/rotate/start", nil)
	w := httptest.NewRecorder()
	h.handleRotateStart(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("first start: expected 202, got %d", w.Code)
	}

	// Second start should conflict
	req = httptest.NewRequest("POST", "/admin/kms/rotate/start", nil)
	w = httptest.NewRecorder()
	h.handleRotateStart(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("second start: expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminRotateAbort_FromDraining(t *testing.T) {
	masterKey1 := make([]byte, 32)
	rand.Read(masterKey1)
	masterKey2 := make([]byte, 32)
	rand.Read(masterKey2)

	km := crypto.NewInMemoryKeyManagerForTestWithKeys(masterKey1, 1)
	km.AddVersion(context.Background(), 2, masterKey2)

	eng, err := crypto.NewEngineWithChunking([]byte("test-password1234"), "", nil, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	crypto.SetKeyManager(eng, km)

	h := NewAdminRotationHandler(eng, testRotationLogger(), testMetrics(), nil)

	// Start rotation with long grace period
	body := `{"grace_period": "10m"}`
	req := httptest.NewRequest("POST", "/admin/kms/rotate/start", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleRotateStart(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("start: expected 202, got %d", w.Code)
	}

	// Simulate in-flight wraps to keep us draining
	rs := crypto.GetRotationState(eng)
	rs.BeginWrap()

	// Abort
	req = httptest.NewRequest("POST", "/admin/kms/rotate/abort", nil)
	w = httptest.NewRecorder()
	h.handleRotateAbort(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("abort: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	rs.EndWrap()

	var snap crypto.RotationSnapshot
	json.NewDecoder(w.Body).Decode(&snap)
	if snap.Phase != "aborted" {
		t.Fatalf("expected aborted, got %s", snap.Phase)
	}

	// Verify active version did NOT change
	ver, _ := km.ActiveKeyVersion(context.Background())
	if ver != 1 {
		t.Fatalf("expected active version 1 (unchanged), got %d", ver)
	}
}
