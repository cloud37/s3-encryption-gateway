package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/internal/mpu"
	"github.com/sirupsen/logrus"
)

// fakeMPUStore is a minimal test double implementing MPUStateStore.
type fakeMPUStore struct {
	states    map[string]*mpu.UploadState
	getErr    error
	deleteErr error
	listErr   error
}

func (f *fakeMPUStore) Get(ctx context.Context, uploadID string) (*mpu.UploadState, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	s, ok := f.states[uploadID]
	if !ok {
		return nil, mpu.ErrUploadNotFound
	}
	return s, nil
}

func (f *fakeMPUStore) Delete(ctx context.Context, uploadID string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.states, uploadID)
	return nil
}

func (f *fakeMPUStore) List(ctx context.Context) ([]mpu.UploadState, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]mpu.UploadState, 0, len(f.states))
	for _, s := range f.states {
		out = append(out, *s)
	}
	return out, nil
}

func newTestMPUMux() (*http.ServeMux, *fakeMPUStore, *[]string) {
	mux := http.NewServeMux()
	store := &fakeMPUStore{states: map[string]*mpu.UploadState{}}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	aborted := []string{}
	abortFn := func(ctx context.Context, bucket, key, uploadID string) error {
		aborted = append(aborted, bucket+"/"+key+":"+uploadID)
		return nil
	}
	RegisterMPUAdminRoutes(mux, store, abortFn, logger)
	return mux, store, &aborted
}

// ─── /admin/mpu/abort/{uploadId} ──────────────────────────────────────────────

func TestMPUAdmin_Abort_Happy(t *testing.T) {
	mux, store, aborted := newTestMPUMux()
	store.states["u-1"] = &mpu.UploadState{UploadID: "u-1", Bucket: "b", Key: "k"}

	req := httptest.NewRequest("POST", "/admin/mpu/abort/u-1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if _, exists := store.states["u-1"]; exists {
		t.Errorf("state should be deleted after abort")
	}
	if len(*aborted) != 1 || (*aborted)[0] != "b/k:u-1" {
		t.Errorf("expected backend abort to be called once; got %v", *aborted)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if body["status"] != "aborted" || body["upload_id"] != "u-1" {
		t.Errorf("unexpected response body: %v", body)
	}
}

func TestMPUAdmin_Abort_NotFound(t *testing.T) {
	mux, _, _ := newTestMPUMux()
	req := httptest.NewRequest("POST", "/admin/mpu/abort/does-not-exist", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestMPUAdmin_Abort_MissingUploadID(t *testing.T) {
	mux, _, _ := newTestMPUMux()
	req := httptest.NewRequest("POST", "/admin/mpu/abort/", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestMPUAdmin_Abort_WrongMethod(t *testing.T) {
	mux, _, _ := newTestMPUMux()
	req := httptest.NewRequest("GET", "/admin/mpu/abort/u-1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestMPUAdmin_Abort_BackendAbortFailsButStateDeleted(t *testing.T) {
	mux := http.NewServeMux()
	store := &fakeMPUStore{states: map[string]*mpu.UploadState{
		"u-2": {UploadID: "u-2", Bucket: "b", Key: "k"},
	}}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	abortFn := func(ctx context.Context, bucket, key, uploadID string) error {
		return errors.New("backend transient failure")
	}
	RegisterMPUAdminRoutes(mux, store, abortFn, logger)

	req := httptest.NewRequest("POST", "/admin/mpu/abort/u-2", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Backend abort failure is best-effort; state must still be deleted and we
	// return 200 so the operator sees the orphan is cleaned from Valkey.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 even when backend abort fails; got %d body=%s", w.Code, w.Body.String())
	}
	if _, exists := store.states["u-2"]; exists {
		t.Errorf("state should still be deleted when backend abort fails")
	}
}

func TestMPUAdmin_Abort_StateGetError(t *testing.T) {
	mux := http.NewServeMux()
	store := &fakeMPUStore{
		states: map[string]*mpu.UploadState{},
		getErr: errors.New("valkey connection refused"),
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	RegisterMPUAdminRoutes(mux, store, nil, logger)

	req := httptest.NewRequest("POST", "/admin/mpu/abort/u-3", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when store.Get errors; got %d", w.Code)
	}
}

func TestMPUAdmin_Abort_StateDeleteError(t *testing.T) {
	mux := http.NewServeMux()
	store := &fakeMPUStore{
		states: map[string]*mpu.UploadState{
			"u-4": {UploadID: "u-4", Bucket: "b", Key: "k"},
		},
		deleteErr: errors.New("valkey write failure"),
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	RegisterMPUAdminRoutes(mux, store, nil, logger)

	req := httptest.NewRequest("POST", "/admin/mpu/abort/u-4", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 when store.Delete errors; got %d", w.Code)
	}
}

// ─── /admin/mpu/list ──────────────────────────────────────────────────────────

func TestMPUAdmin_List_Happy(t *testing.T) {
	mux, store, _ := newTestMPUMux()
	store.states["u-a"] = &mpu.UploadState{UploadID: "u-a", Bucket: "b1", Key: "k1"}
	store.states["u-b"] = &mpu.UploadState{UploadID: "u-b", Bucket: "b2", Key: "k2"}

	req := httptest.NewRequest("GET", "/admin/mpu/list", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	var body struct {
		ActiveUploads []mpu.UploadState `json:"active_uploads"`
		Count         int               `json:"count"`
		Timestamp     string            `json:"timestamp"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if body.Count != 2 || len(body.ActiveUploads) != 2 {
		t.Errorf("expected count=2, got count=%d len=%d", body.Count, len(body.ActiveUploads))
	}
	if body.Timestamp == "" {
		t.Error("timestamp missing")
	}
}

func TestMPUAdmin_List_Empty(t *testing.T) {
	mux, _, _ := newTestMPUMux()
	req := httptest.NewRequest("GET", "/admin/mpu/list", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"count":0`) {
		t.Errorf("expected count=0 in body; got %s", w.Body.String())
	}
	// Empty list must be `[]`, not `null`.
	if strings.Contains(w.Body.String(), `"active_uploads":null`) {
		t.Error("empty active_uploads should be [], not null")
	}
}

func TestMPUAdmin_List_StoreError(t *testing.T) {
	mux := http.NewServeMux()
	store := &fakeMPUStore{listErr: errors.New("SCAN failed")}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	RegisterMPUAdminRoutes(mux, store, nil, logger)

	req := httptest.NewRequest("GET", "/admin/mpu/list", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", w.Code)
	}
}

func TestMPUAdmin_List_WrongMethod(t *testing.T) {
	mux, _, _ := newTestMPUMux()
	req := httptest.NewRequest("POST", "/admin/mpu/list", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

// TestMPUAdmin_List_NilStates exercises the nil states branch in the list handler.
func TestMPUAdmin_List_NilStates(t *testing.T) {
	// Use a store whose List() returns nil (not an empty slice).
	nilStore := &nilListStore{}
	mux := http.NewServeMux()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	RegisterMPUAdminRoutes(mux, nilStore, nil, logger)

	req := httptest.NewRequest("GET", "/admin/mpu/list", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

// nilListStore is a StateStore whose List returns nil.
type nilListStore struct{}

func (n *nilListStore) Get(_ context.Context, _ string) (*mpu.UploadState, error) {
	return nil, mpu.ErrUploadNotFound
}
func (n *nilListStore) Delete(_ context.Context, _ string) error { return nil }
func (n *nilListStore) List(_ context.Context) ([]mpu.UploadState, error) {
	return nil, nil // deliberately return nil
}

// TestIsNotFound_Nil verifies isNotFound returns false for nil error.
func TestIsNotFound_Nil(t *testing.T) {
	if isNotFound(nil) {
		t.Error("isNotFound(nil) should return false")
	}
}

// TestIsNotFound_Other verifies isNotFound returns false for other errors.
func TestIsNotFound_Other(t *testing.T) {
	if isNotFound(errors.New("some other error")) {
		t.Error("isNotFound(other) should return false")
	}
}

// TestIsNotFound_ErrUploadNotFound verifies isNotFound returns true for ErrUploadNotFound.
func TestIsNotFound_ErrUploadNotFound(t *testing.T) {
	if !isNotFound(mpu.ErrUploadNotFound) {
		t.Error("isNotFound(ErrUploadNotFound) should return true")
	}
}
