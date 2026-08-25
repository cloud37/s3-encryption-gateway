package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func managementRequest(method, path string, body io.Reader, c Credential) *http.Request {
	r := httptest.NewRequest(method, path, body)
	ctx := context.WithValue(r.Context(), credentialKey, c)
	if c.Label != "" {
		ctx = context.WithValue(ctx, credentialLabelKey, c.Label)
	}
	r = r.WithContext(ctx)
	return mux.SetURLVars(r, map[string]string{"bucket": strings.TrimPrefix(strings.Split(path, "?")[0], "/")})
}

func managementHandler(t *testing.T, endpoint string, enabled bool) *Handler {
	t.Helper()
	engine, err := crypto.NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatal(err)
	}
	return NewHandlerWithFeatures(nil, engine, logrus.New(), getTestMetrics(), nil, nil, nil, &config.Config{AllowBucketCreation: enabled, Backend: config.BackendConfig{Endpoint: endpoint, Region: "us-east-1"}}, nil)
}

type managementAuditEvent struct {
	operation string
	bucket    string
	success   bool
	metadata  map[string]interface{}
	err       string
}

type managementAuditLogger struct {
	events      []managementAuditEvent
	accessCalls int
}

func (m *managementAuditLogger) Log(*audit.AuditEvent) error { return nil }
func (m *managementAuditLogger) LogEncrypt(string, string, string, int, bool, error, time.Duration, map[string]interface{}) {
}
func (m *managementAuditLogger) LogDecrypt(string, string, string, int, bool, error, time.Duration, map[string]interface{}) {
}
func (m *managementAuditLogger) LogKeyRotation(int, bool, error) {}
func (m *managementAuditLogger) LogAccess(string, string, string, string, string, string, bool, error, time.Duration) {
	m.accessCalls++
}
func (m *managementAuditLogger) LogAccessWithMetadata(operation, bucket, _ string, _ string, _ string, _ string, success bool, err error, _ time.Duration, metadata map[string]interface{}) {
	e := managementAuditEvent{operation: operation, bucket: bucket, success: success, metadata: metadata}
	if err != nil {
		e.err = err.Error()
	}
	m.events = append(m.events, e)
}
func (m *managementAuditLogger) GetEvents() []*audit.AuditEvent { return nil }
func (m *managementAuditLogger) Close() error                   { return nil }

func serveManagement(t *testing.T, h *Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.handleCreateBucket(w, r)
	return w
}

func TestHandleCreateBucket_DisabledByDefault_DoesNotReachBackend(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer b.Close()
	h := managementHandler(t, b.URL, false)
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/abc", nil, Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}))
	if w.Code != http.StatusNotImplemented || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestBucketManagementAudit_DeniedCreateAndAllowedDelete(t *testing.T) {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer b.Close()
	logger := &managementAuditLogger{}
	engine, err := crypto.NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithFeatures(nil, engine, logrus.New(), getTestMetrics(), nil, nil, logger, &config.Config{AllowBucketCreation: true, Backend: config.BackendConfig{Endpoint: b.URL}}, nil)
	denied := Credential{Label: "audit-user", Policy: AuthorizationPolicy{Buckets: []string{"other"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/audit-create", nil, denied))
	if w.Code != http.StatusForbidden || len(logger.events) != 1 {
		t.Fatalf("status=%d events=%d", w.Code, len(logger.events))
	}
	if logger.events[0].operation != "CreateBucket" || logger.events[0].bucket != "audit-create" || logger.events[0].success {
		t.Fatalf("bad denied event: %+v", logger.events[0])
	}
	if logger.events[0].metadata["credential_label"] != "audit-user" || logger.events[0].metadata["result"] != "denied" {
		t.Fatalf("bad denied metadata: %+v", logger.events[0].metadata)
	}
	allowedCreate := Credential{Label: "audit-user", Policy: AuthorizationPolicy{Buckets: []string{"audit-created"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}
	w = serveManagement(t, h, managementRequest(http.MethodPut, "/audit-created", nil, allowedCreate))
	if w.Code != http.StatusNoContent || len(logger.events) != 2 {
		t.Fatalf("status=%d events=%d", w.Code, len(logger.events))
	}
	if logger.events[1].operation != "CreateBucket" || logger.events[1].bucket != "audit-created" || !logger.events[1].success {
		t.Fatalf("bad allowed create event: %+v", logger.events[1])
	}
	if logger.events[1].metadata["credential_label"] != "audit-user" || logger.events[1].metadata["result"] != "allowed" {
		t.Fatalf("bad allowed create metadata: %+v", logger.events[1].metadata)
	}
	allowed := Credential{Label: "audit-user", Policy: AuthorizationPolicy{Buckets: []string{"audit-delete"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete}}}
	w = httptest.NewRecorder()
	h.handleDeleteBucket(w, managementRequest(http.MethodDelete, "/audit-delete", nil, allowed))
	if w.Code != http.StatusNoContent || len(logger.events) != 3 {
		t.Fatalf("status=%d events=%d", w.Code, len(logger.events))
	}
	if logger.events[2].operation != "DeleteBucket" || logger.events[2].bucket != "audit-delete" || !logger.events[2].success {
		t.Fatalf("bad allowed event: %+v", logger.events[2])
	}
	if logger.events[2].metadata["credential_label"] != "audit-user" || logger.events[2].metadata["result"] != "allowed" {
		t.Fatalf("bad allowed metadata: %+v", logger.events[2].metadata)
	}
	for _, event := range logger.events {
		if strings.Contains(event.err, "audit-user") || strings.Contains(event.err, "secret") {
			t.Fatalf("secret in event: %+v", event)
		}
	}
}

func TestBucketManagementAudit_DeniedDeleteWithPolicyDoesNotLeakPolicyID(t *testing.T) {
	policyFile := t.TempDir() + "/policy.yaml"
	if err := os.WriteFile(policyFile, []byte("id: POLICY-MARKER-9472\nbuckets: [audit-policy]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{policyFile}); err != nil {
		t.Fatal(err)
	}
	logger := &managementAuditLogger{}
	engine, err := crypto.NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithFeatures(nil, engine, logrus.New(), getTestMetrics(), nil, nil, logger, &config.Config{AllowBucketCreation: true}, pm)
	secret, accessKey := "SECRET-MARKER-5821", "ACCESS-MARKER-7394"
	c := Credential{AccessKey: accessKey, SecretKey: secret, Label: "policy-audit-user", Policy: AuthorizationPolicy{Buckets: []string{"other"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete}}}
	w := httptest.NewRecorder()
	h.handleDeleteBucket(w, managementRequest(http.MethodDelete, "/audit-policy", nil, c))
	if w.Code != http.StatusForbidden || len(logger.events) != 1 || logger.accessCalls != 0 {
		t.Fatalf("status=%d events=%d generic=%d", w.Code, len(logger.events), logger.accessCalls)
	}
	e := logger.events[0]
	if e.operation != "DeleteBucket" || e.bucket != "audit-policy" || e.success || e.metadata["credential_label"] != c.Label || e.metadata["result"] != "denied" {
		t.Fatalf("bad event: %+v", e)
	}
	serialized := fmt.Sprintf("%+v", e)
	for _, marker := range []string{secret, accessKey, "POLICY-MARKER-9472"} {
		if strings.Contains(serialized, marker) {
			t.Fatalf("event leaked %q: %s", marker, serialized)
		}
	}
}

func TestHandleCreateBucket_EnabledAuthorized_ForwardsToBackend(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("X-Backend", "yes")
		w.WriteHeader(http.StatusCreated)
	}))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	c := Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/abc", strings.NewReader("<x/>"), c))
	if w.Code != http.StatusCreated || w.Header().Get("X-Backend") != "yes" || calls.Load() != 1 {
		t.Fatalf("status=%d header=%q calls=%d", w.Code, w.Header().Get("X-Backend"), calls.Load())
	}
}

func TestHandleCreateBucket_EnabledOutOfScope_AccessDenied_DoesNotReachBackend(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/abc", nil, Credential{Policy: AuthorizationPolicy{Buckets: []string{"other"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestHandleCreateBucket_RWDoesNotGrantCreate_DoesNotReachBackend(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/abc", nil, Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, Permissions: config.ObjectPermissionReadWrite}}))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestHandleCreateBucket_InvalidName_DoesNotReachBackend(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	c := Credential{Policy: AuthorizationPolicy{Buckets: []string{"ABC"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/ABC", nil, c))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<Code>InvalidBucketName</Code>") || calls.Load() != 0 {
		t.Fatalf("status=%d body=%s calls=%d", w.Code, w.Body.String(), calls.Load())
	}
}

func TestHandleCreateBucket_EmptyBucket_InvalidName(t *testing.T) {
	h := managementHandler(t, "", true)
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/", nil, Credential{}))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<Code>InvalidBucketName</Code>") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestHandleCreateBucket_LocationConstraintBodyForwardedUnchanged(t *testing.T) {
	var got []byte
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	body := []byte("<CreateBucketConfiguration><LocationConstraint>eu</LocationConstraint></CreateBucketConfiguration>")
	serveManagement(t, h, managementRequest(http.MethodPut, "/abc", bytes.NewReader(body), Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}))
	if !bytes.Equal(got, body) {
		t.Fatalf("body changed: %q", got)
	}
}

func TestHandleCreateBucket_BackendErrorForwardedVerbatim(t *testing.T) {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Error", "yes")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("<Error><Code>BucketAlreadyExists</Code></Error>"))
	}))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/abc", nil, Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}))
	if w.Code != http.StatusConflict || w.Header().Get("X-Error") != "yes" || !strings.Contains(w.Body.String(), "BucketAlreadyExists") {
		t.Fatalf("response=%d %q", w.Code, w.Body.String())
	}
}

func TestHandleCreateBucket_OverLimitDoesNotReachBackend(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	c := Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}
	w := serveManagement(t, h, managementRequest(http.MethodPut, "/abc", strings.NewReader(strings.Repeat("x", 64<<10+1)), c))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "<Code>InvalidRequest</Code>") || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestHandleDeleteBucket_AuthorizedWithDeletePermission_ForwardsToBackend(t *testing.T) {
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	w := httptest.NewRecorder()
	h.handleDeleteBucket(w, managementRequest(http.MethodDelete, "/abc", nil, Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete}}}))
	if w.Code != http.StatusNoContent || calls.Load() != 1 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestHandleDeleteBucket_OutOfScope_AccessDenied_DoesNotReachBackend(t *testing.T) {
	testDeleteDenied(t, Credential{Policy: AuthorizationPolicy{Buckets: []string{"other"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete}}})
}
func TestHandleDeleteBucket_RWDoesNotGrantDelete_DoesNotReachBackend(t *testing.T) {
	testDeleteDenied(t, Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, Permissions: config.ObjectPermissionReadWrite}})
}
func TestHandleDeleteBucket_CreatePermissionDoesNotGrantDelete_DoesNotReachBackend(t *testing.T) {
	testDeleteDenied(t, Credential{Policy: AuthorizationPolicy{Buckets: []string{"abc"}, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}})
}

func testDeleteDenied(t *testing.T, c Credential) {
	t.Helper()
	var calls atomic.Int64
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }))
	defer b.Close()
	h := managementHandler(t, b.URL, true)
	w := httptest.NewRecorder()
	h.handleDeleteBucket(w, managementRequest(http.MethodDelete, "/abc", nil, c))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "<Code>AccessDenied</Code>") || calls.Load() != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls.Load())
	}
}
