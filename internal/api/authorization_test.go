package api

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func authorizedRequest(method, target string, credential Credential) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	return r.WithContext(withCredential(r, credential))
}

func withCredential(r *http.Request, credential Credential) context.Context {
	return context.WithValue(r.Context(), credentialKey, credential)
}

func TestAuthorizationMiddleware_ReadOnlyAllowsObjectReads(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Buckets: []string{"tenant-*"}, Permissions: config.ObjectPermissionReadOnly}}
	called := false
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodGet, "/tenant-a/key", credential))
	if !called {
		t.Fatal("read request was denied")
	}
}

func TestAuthorizationMiddleware_ReadOnlyDeniesObjectWrites(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Buckets: []string{"tenant"}, Permissions: config.ObjectPermissionReadOnly}}
	called := false
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPut, "/tenant/key", credential))
	if called || recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "AccessDenied") {
		t.Fatalf("called=%v status=%d body=%s", called, recorder.Code, recorder.Body.String())
	}
}

func TestAuthorizationMiddleware_CreateBucketRequiresExplicitPermission(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPut, "/tenant", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d", recorder.Code)
	}
}

func TestAuthorizationMiddleware_DeleteBucketRequiresExplicitPermission(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodDelete, "/tenant", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d", recorder.Code)
	}
}

func TestAuthorizationMiddleware_AccessDeniedIsS3XML(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPatch, "/tenant/key", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "AccessDenied") {
		t.Fatalf("expected AccessDenied in body, got: %s", body)
	}
	if !strings.Contains(body, "<?xml") {
		t.Fatalf("expected XML response, got: %s", body)
	}
}

func TestAuthorizationMiddleware_UnknownOperationFailsClosed(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPatch, "/tenant/key", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d", recorder.Code)
	}
}

func TestAuthorizationMiddleware_BucketSubresourcesAndCreateClassification(t *testing.T) {
	tests := []struct {
		method, target string
		want           authorizationOperation
	}{
		{http.MethodPut, "/bucket?anything=1", authorizationUnknown},
		{http.MethodPut, "/bucket?lifecycle", authorizationWrite},
		{http.MethodDelete, "/bucket?policy", authorizationWrite},
		{http.MethodDelete, "/bucket", authorizationDeleteBucket},
		{http.MethodGet, "/bucket?unknown=1", authorizationUnknown},
		{http.MethodPost, "/bucket?unknown=1", authorizationUnknown},
		{http.MethodPut, "/bucket", authorizationCreateBucket},
		{http.MethodGet, "/bucket?list-type=2&prefix=a&max-keys=10", authorizationRead},
		{http.MethodGet, "/bucket?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=key", authorizationRead},
		{http.MethodOptions, "/bucket", authorizationRead},
		{http.MethodOptions, "/bucket/key", authorizationRead},
		{http.MethodGet, "/bucket?cors", authorizationRead},
		{http.MethodGet, "/bucket?cors&unknown=1", authorizationUnknown},
		{http.MethodGet, "/?X-Amz-Algorithm=AWS4-HMAC-SHA256", authorizationListBuckets},
		{http.MethodPost, "/bucket/key?select", authorizationRead},
		{http.MethodGet, "/?foo=bar", authorizationUnknown},
		{http.MethodPost, "/bucket", authorizationUnknown},
		{http.MethodPatch, "/bucket", authorizationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.method+tt.target, func(t *testing.T) {
			op, _ := classifyAuthorizationOperation(httptest.NewRequest(tt.method, tt.target, nil))
			if op != tt.want {
				t.Fatalf("operation=%v want=%v", op, tt.want)
			}
		})
	}
}

func TestClassifyAuthorizationOperation_FailClosedFixes(t *testing.T) {
	tests := []struct {
		method, target string
		want           authorizationOperation
	}{
		{http.MethodGet, "/bucket/key?partNumber=1", authorizationRead},
		{http.MethodPut, "/bucket/key?partNumber=1&uploadId=u", authorizationWrite},
		{http.MethodGet, "/bucket/key?restore", authorizationUnknown},
		{http.MethodPut, "/bucket/key?uploadId=u", authorizationWrite},
		{http.MethodPost, "/bucket/key?uploads", authorizationWrite},
		{http.MethodGet, "/bucket/key?uploads", authorizationUnknown},
		{http.MethodPatch, "/bucket/key", authorizationUnknown},
		{http.MethodPut, "/bucket/key?unknown=1", authorizationUnknown},
		{http.MethodDelete, "/bucket/key?unknown=1", authorizationUnknown},
		{http.MethodPost, "/bucket/key?unknown=1", authorizationUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.method+tt.target, func(t *testing.T) {
			op, _ := classifyAuthorizationOperation(httptest.NewRequest(tt.method, tt.target, nil))
			if op != tt.want {
				t.Fatalf("operation=%v want=%v", op, tt.want)
			}
		})
	}
}

func TestAuthorizationMiddleware_DeleteSubresourceRequiresWriteNotDeleteGrant(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	called := false
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodDelete, "/bucket?policy", credential))
	if !called {
		t.Fatal("rw credential should delete a bucket subresource")
	}
}

func TestAuthorizationMiddleware_PolicyAndCopyScope(t *testing.T) {
	tests := []struct {
		name, method, target, source string
		credential                   Credential
		proxied                      string
		wantStatus                   int
	}{
		{"missing principal", http.MethodGet, "/bucket/key", "", Credential{}, "", http.StatusForbidden},
		{"system endpoint", http.MethodGet, "/health", "", Credential{}, "", http.StatusOK},
		{"deny all scope", http.MethodGet, "/bucket/key", "", Credential{Policy: AuthorizationPolicy{Buckets: []string{}, Permissions: config.ObjectPermissionReadWrite}}, "", http.StatusForbidden},
		{"proxied intersection", http.MethodGet, "/tenant/key", "", Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}, "other", http.StatusForbidden},
		{"copy source denied", http.MethodPut, "/destination/key", "outside/key", Credential{Policy: AuthorizationPolicy{Buckets: []string{"destination"}, Permissions: config.ObjectPermissionReadWrite}}, "", http.StatusForbidden},
		{"copy source allowed", http.MethodPut, "/destination/key", "source/key", Credential{Policy: AuthorizationPolicy{Buckets: []string{"destination", "source"}, Permissions: config.ObjectPermissionReadWrite}}, "", http.StatusOK},
		{"copy source ignored on get", http.MethodGet, "/bucket/key", "source/key", Credential{Policy: AuthorizationPolicy{Buckets: []string{"bucket", "source"}, Permissions: config.ObjectPermissionReadWrite}}, "", http.StatusOK},
		{"create granted", http.MethodPut, "/bucket", "", Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}}}, "", http.StatusOK},
		{"delete requires grant", http.MethodDelete, "/bucket", "", Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}, "", http.StatusForbidden},
		{"delete granted", http.MethodDelete, "/bucket", "", Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete}}}, "", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := AuthorizationMiddleware(tt.proxied, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) }))
			request := httptest.NewRequest(tt.method, tt.target, nil)
			if tt.name != "missing principal" && tt.name != "system endpoint" {
				request = request.WithContext(withCredential(request, tt.credential))
			}
			if tt.source != "" {
				request.Header.Set("x-amz-copy-source", tt.source)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status=%d want=%d", recorder.Code, tt.wantStatus)
			}
			if (tt.wantStatus == http.StatusOK) != called {
				t.Fatalf("called=%v", called)
			}
		})
	}
}

func TestAuthorizationMiddleware_SelectWithUploadIdIsWriteNotRead(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	// POST /bucket/key?select&uploadId=u should be classified as a write (CompleteMultipartUpload
	// with a malformed select query), NOT as SelectObjectContent read.
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPost, "/bucket/key?select&uploadId=u", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=403", recorder.Code)
	}
}

func TestAuthorizationMiddleware_CopySourceCheckedOnPutWithUploadIdOnly(t *testing.T) {
	// PUT /bucket/key?uploadId=u with x-amz-copy-source must still validate source
	// even when partNumber is absent (malformed multipart, but header must be enforced).
	credential := Credential{Policy: AuthorizationPolicy{Buckets: []string{"dest"}, Permissions: config.ObjectPermissionReadWrite}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	req := authorizedRequest(http.MethodPut, "/dest/key?uploadId=u", credential)
	req.Header.Set("x-amz-copy-source", "outside/key")
	h.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=403", recorder.Code)
	}
}

func TestAuthorizationMiddleware_CopySourceIgnoredOnObjectSubresource(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{
		Buckets:     []string{"destination"},
		Permissions: config.ObjectPermissionReadWrite,
	}}
	called := false
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	request := authorizedRequest(http.MethodPut, "/destination/key?acl", credential)
	request.Header.Set("x-amz-copy-source", "outside/key")
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, request)
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d body=%s", called, recorder.Code, recorder.Body.String())
	}
}

func TestAuthorizationMiddleware_ReadOnlyDeniedOnAllMutations(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}}
	tests := []struct {
		method, target string
	}{
		{http.MethodPut, "/bucket/key"},
		{http.MethodPost, "/bucket/key?uploadId=u"},
		{http.MethodPost, "/bucket/key?delete"},
		{http.MethodPost, "/bucket/key?restore"},
		{http.MethodDelete, "/bucket/key"},
		{http.MethodPut, "/bucket/key?tagging"},
	}
	for _, tt := range tests {
		t.Run(tt.method+tt.target, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
			h.ServeHTTP(recorder, authorizedRequest(tt.method, tt.target, credential))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status=%d want=403", recorder.Code)
			}
		})
	}
}

func TestAuthorizationMiddleware_ListBucketsAllowedWithReadPermission(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}}
	called := false
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodGet, "/", credential))
	if !called {
		t.Fatal("GET / should be allowed for ro credential")
	}
}

func TestAuthorizationMiddleware_HeadBucketNoQueryAllowed(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}}
	called := false
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodHead, "/bucket", credential))
	if !called {
		t.Fatal("HEAD /bucket should be allowed for ro credential")
	}
}

func TestAuthorizationMiddleware_PostBucketDeleteAllowedForRW(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	called := false
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodPost, "/bucket?delete", credential))
	if !called {
		t.Fatal("POST /bucket?delete should be allowed for rw credential")
	}
}

func TestAuthorizationMiddleware_DeleteObjectTaggingAllowedForRW(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	called := false
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodDelete, "/bucket/key?tagging", credential))
	if !called {
		t.Fatal("DELETE /bucket/key?tagging should be allowed for rw credential")
	}
}

func TestAuthorizationMiddleware_ObjectUnknownMethodWithQueryDenied(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPatch, "/bucket/key?foo=bar", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=403", recorder.Code)
	}
}

func TestAuthorizationMiddleware_AuditEventEmittedOnDenial(t *testing.T) {
	// Verify that a non-nil audit logger receives an authorization_denied event
	// with bounded reason. This exercises the writeAuthorizationDenied branch
	// that is otherwise uncovered when auditLog is nil.
	events := &mockAuditLogger{}
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", events)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPut, "/bucket/key", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=403", recorder.Code)
	}
	if len(events.events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events.events))
	}
	if events.events[0].reason != "read_only" {
		t.Fatalf("expected audit reason 'read_only', got %q", events.events[0].reason)
	}
}

type mockAuditEvent struct {
	eventType string
	reason    string
}

type mockAuditLogger struct {
	events []mockAuditEvent
}

func (m *mockAuditLogger) Log(_ *audit.AuditEvent) error { return nil }
func (m *mockAuditLogger) LogEncrypt(_, _, _ string, _ int, _ bool, _ error, _ time.Duration, _ map[string]interface{}) {
}
func (m *mockAuditLogger) LogDecrypt(_, _, _ string, _ int, _ bool, _ error, _ time.Duration, _ map[string]interface{}) {
}
func (m *mockAuditLogger) LogKeyRotation(_ int, _ bool, _ error)                               {}
func (m *mockAuditLogger) LogAccess(_, _, _, _, _, _ string, _ bool, _ error, _ time.Duration) {}
func (m *mockAuditLogger) LogAccessWithMetadata(eventType, _, _, _, _, _ string, _ bool, _ error, _ time.Duration, metadata map[string]interface{}) {
	reason := ""
	if metadata != nil {
		if r, ok := metadata["reason"].(string); ok {
			reason = r
		}
	}
	m.events = append(m.events, mockAuditEvent{eventType: eventType, reason: reason})
}
func (m *mockAuditLogger) GetEvents() []*audit.AuditEvent { return nil }
func (m *mockAuditLogger) Close() error                   { return nil }

// Tests for verifier finding: bucket DELETE must only accept query keys that
// have corresponding DELETE routes. Keys like ?acl without a route would fall
// through to handleDeleteBucket and bypass the explicit delete grant.
func TestAuthorizationMiddleware_BucketDeleteWithUnsupportedKeyIsUnknown(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{}}}
	for _, key := range []string{"acl", "intelligent-tiering", "logging", "notification", "object-lock", "requestPayment", "versioning"} {
		t.Run(key, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
			h.ServeHTTP(recorder, authorizedRequest(http.MethodDelete, "/bucket?"+key, credential))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("DELETE /bucket?%s: status=%d want=403", key, recorder.Code)
			}
		})
	}
}

func TestAuthorizationMiddleware_BucketDeleteWithSupportedKeyRequiresWriteNotDeleteGrant(t *testing.T) {
	// These keys have corresponding DELETE routes and are ordinary writes.
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	for _, key := range []string{"lifecycle", "policy", "cors", "encryption", "replication", "website", "inventory"} {
		t.Run(key, func(t *testing.T) {
			called := false
			h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodDelete, "/bucket?"+key, credential))
			if !called {
				t.Fatalf("DELETE /bucket?%s should be allowed for rw credential", key)
			}
		})
	}
}

func TestAuthorizationMiddleware_PostObjectUploadsIsWrite(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	called := false
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodPost, "/bucket/key?uploads", credential))
	if !called {
		t.Fatal("POST /bucket/key?uploads should be allowed for rw credential")
	}
}

func TestAuthorizationMiddleware_GetObjectWithPartNumberIsRead(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			called := false
			h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(method, "/bucket/key?partNumber=1", credential))
			if !called {
				t.Fatalf("%s /bucket/key?partNumber=1 should be allowed for ro credential", method)
			}
		})
	}
}

// Tests for verifier finding: valid registered S3 parameters must not be falsely denied.
func TestAuthorizationMiddleware_RegisteredS3ParametersAllowed(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}}

	// ListMultipartUploads bucket-level parameters
	t.Run("ListMultipartUploads with pagination", func(t *testing.T) {
		called := false
		h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodGet, "/bucket?uploads&key-marker=abc&upload-id-marker=def&max-uploads=100", credential))
		if !called {
			t.Fatal("GET /bucket?uploads with pagination should be allowed")
		}
	})

	// Inventory/analytics subresource with id
	t.Run("GetBucketInventory with id", func(t *testing.T) {
		called := false
		h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodGet, "/bucket?inventory&id=report-1", credential))
		if !called {
			t.Fatal("GET /bucket?inventory&id=x should be allowed")
		}
	})

	// ListParts object-level parameters
	t.Run("ListParts with max-parts and part-number-marker", func(t *testing.T) {
		called := false
		h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodGet, "/bucket/key?uploadId=u&max-parts=100&part-number-marker=5", credential))
		if !called {
			t.Fatal("GET /bucket/key?uploadId&u&max-parts&part-number-marker should be allowed")
		}
	})
}

// Tests for verifier finding: unregistered object POST shapes must fail closed.
func TestAuthorizationMiddleware_BarePostObjectIsUnknown(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPost, "/bucket/key", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("bare POST /bucket/key: status=%d want=403", recorder.Code)
	}
}

func TestAuthorizationMiddleware_PostObjectWithDeleteIsUnknown(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
	recorder := httptest.NewRecorder()
	h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
	h.ServeHTTP(recorder, authorizedRequest(http.MethodPost, "/bucket/key?delete", credential))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("POST /bucket/key?delete: status=%d want=403", recorder.Code)
	}
}

// Tests for verifier P0 finding: non-empty subresource selector values bypass
// authorization because gorilla/mux Queries("key", "") only matches empty
// values. A request like DELETE /bucket?policy=x falls through to generic
// DELETE /{bucket} and deletes the bucket without requiring
// bucket_permissions:delete.
func TestAuthorizationMiddleware_NonEmptySelectorFailsClosed(t *testing.T) {
	// Test DELETE with non-empty values for all supported subresource keys
	subresourceKeys := []string{"lifecycle", "policy", "cors", "encryption", "replication", "website", "inventory"}
	for _, key := range subresourceKeys {
		t.Run("DELETE/"+key+"=x", func(t *testing.T) {
			credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{}}}
			recorder := httptest.NewRecorder()
			h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
			h.ServeHTTP(recorder, authorizedRequest(http.MethodDelete, "/bucket?"+key+"=x", credential))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("DELETE /bucket?%s=x: status=%d want=403", key, recorder.Code)
			}
		})
	}

	// Test PUT with non-empty values for all supported subresource keys
	for _, key := range subresourceKeys {
		t.Run("PUT/"+key+"=x", func(t *testing.T) {
			credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite, BucketPermissions: []config.BucketPermission{}}}
			recorder := httptest.NewRecorder()
			h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
			h.ServeHTTP(recorder, authorizedRequest(http.MethodPut, "/bucket?"+key+"=x", credential))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("PUT /bucket?%s=x: status=%d want=403", key, recorder.Code)
			}
		})
	}

	// Test POST /bucket?delete=x (non-empty value on delete)
	t.Run("POST/delete=x", func(t *testing.T) {
		credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}
		recorder := httptest.NewRecorder()
		h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))
		h.ServeHTTP(recorder, authorizedRequest(http.MethodPost, "/bucket?delete=x", credential))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("POST /bucket?delete=x: status=%d want=403", recorder.Code)
		}
	})
}

// Test that empty subresource values and x-id pass-through are allowed.
func TestAuthorizationMiddleware_EmptySelectorAndXidAllowed(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}

	// Empty subresource value should match the route
	t.Run("DELETE/policy=empty", func(t *testing.T) {
		called := false
		h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodDelete, "/bucket?policy", credential))
		if !called {
			t.Fatal("DELETE /bucket?policy should be allowed for rw credential")
		}
	})

	// x-id pass-through should be allowed on top of empty subresource
	t.Run("DELETE/policy&x-id", func(t *testing.T) {
		called := false
		h := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
		h.ServeHTTP(httptest.NewRecorder(), authorizedRequest(http.MethodDelete, "/bucket?policy&x-id=123", credential))
		if !called {
			t.Fatal("DELETE /bucket?policy&x-id=123 should be allowed for rw credential")
		}
	})
}

// TestRouterClassifierParity is a comprehensive table-driven test for every
// registered S3 route family and supported parameter set. It instantiates the
// real RegisterRoutes router and proves that the classifier and router agree:
//   - every non-unknown classification matches the semantically expected
//     named route — never the generic CreateBucket/DeleteBucket fallback
//     unless the operation IS a bucket lifecycle operation;
//   - every unknown classification is denied by AuthorizationMiddleware
//     before the router can run any handler.
func TestRouterClassifierParity(t *testing.T) {
	handler := &Handler{logger: logrus.New(), metrics: getTestMetrics()}
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		method    string
		target    string
		want      authorizationOperation
		wantRoute string // expected matched route name; "" for unknown
	}{
		// Root route. x-id never identifies an operation.
		{http.MethodGet, "/", authorizationListBuckets, "ListBuckets"},
		{http.MethodGet, "/?x-id=anything", authorizationListBuckets, "ListBuckets"},

		// Bucket-level without query — lifecycle operations
		{http.MethodGet, "/bucket", authorizationRead, "ListObjects"},
		{http.MethodHead, "/bucket", authorizationRead, "HeadBucket"},
		{http.MethodPut, "/bucket", authorizationCreateBucket, "CreateBucket"},
		{http.MethodDelete, "/bucket", authorizationDeleteBucket, "DeleteBucket"},

		// x-id-only bucket PUT/DELETE classify as the base lifecycle
		// operation (x-id is pass-through, never a selector) and therefore
		// require the explicit create/delete grants.
		{http.MethodPut, "/bucket?x-id=anything", authorizationCreateBucket, "CreateBucket"},
		{http.MethodDelete, "/bucket?x-id=anything", authorizationDeleteBucket, "DeleteBucket"},

		// Bucket subresources — empty selectors (valid S3)
		{http.MethodGet, "/bucket?acl", authorizationRead, "GetBucketACL"},
		{http.MethodGet, "/bucket?cors", authorizationRead, "GetBucketCors"},
		{http.MethodGet, "/bucket?encryption", authorizationRead, "GetBucketEncryption"},
		{http.MethodGet, "/bucket?inventory", authorizationRead, "GetBucketInventory"},
		{http.MethodGet, "/bucket?lifecycle", authorizationRead, "GetBucketLifecycle"},
		{http.MethodGet, "/bucket?location", authorizationRead, "GetBucketLocation"},
		{http.MethodGet, "/bucket?logging", authorizationRead, "GetBucketLogging"},
		{http.MethodGet, "/bucket?notification", authorizationRead, "GetBucketNotification"},
		{http.MethodGet, "/bucket?object-lock", authorizationRead, "GetObjectLockConfiguration"},
		{http.MethodGet, "/bucket?policy", authorizationRead, "GetBucketPolicy"},
		{http.MethodGet, "/bucket?replication", authorizationRead, "GetBucketReplication"},
		{http.MethodGet, "/bucket?requestPayment", authorizationRead, "GetBucketRequestPayment"},
		{http.MethodGet, "/bucket?uploads", authorizationRead, "ListMultipartUploads"},
		{http.MethodGet, "/bucket?versioning", authorizationRead, "GetBucketVersioning"},
		{http.MethodGet, "/bucket?website", authorizationRead, "GetBucketWebsite"},
		{http.MethodGet, "/bucket?analytics", authorizationRead, "GetBucketAnalytics"},

		{http.MethodPut, "/bucket?acl", authorizationWrite, "PutBucketACL"},
		{http.MethodPut, "/bucket?cors", authorizationWrite, "PutBucketCors"},
		{http.MethodPut, "/bucket?encryption", authorizationWrite, "PutBucketEncryption"},
		{http.MethodPut, "/bucket?inventory", authorizationWrite, "PutBucketInventory"},
		{http.MethodPut, "/bucket?lifecycle", authorizationWrite, "PutBucketLifecycle"},
		{http.MethodPut, "/bucket?logging", authorizationWrite, "PutBucketLogging"},
		{http.MethodPut, "/bucket?notification", authorizationWrite, "PutBucketNotification"},
		{http.MethodPut, "/bucket?object-lock", authorizationWrite, "PutObjectLockConfiguration"},
		{http.MethodPut, "/bucket?policy", authorizationWrite, "PutBucketPolicy"},
		{http.MethodPut, "/bucket?replication", authorizationWrite, "PutBucketReplication"},
		{http.MethodPut, "/bucket?requestPayment", authorizationWrite, "PutBucketRequestPayment"},
		{http.MethodPut, "/bucket?versioning", authorizationWrite, "PutBucketVersioning"},
		{http.MethodPut, "/bucket?website", authorizationWrite, "PutBucketWebsite"},
		{http.MethodPut, "/bucket?intelligent-tiering", authorizationWrite, "PutBucketIntelligentTiering"},
		{http.MethodPut, "/bucket?intelligent-tiering&id=cfg-1", authorizationWrite, "PutBucketIntelligentTiering"},

		{http.MethodDelete, "/bucket?lifecycle", authorizationWrite, "DeleteBucketLifecycle"},
		{http.MethodDelete, "/bucket?policy", authorizationWrite, "DeleteBucketPolicy"},
		{http.MethodDelete, "/bucket?cors", authorizationWrite, "DeleteBucketCors"},
		{http.MethodDelete, "/bucket?encryption", authorizationWrite, "DeleteBucketEncryption"},
		{http.MethodDelete, "/bucket?replication", authorizationWrite, "DeleteBucketReplication"},
		{http.MethodDelete, "/bucket?website", authorizationWrite, "DeleteBucketWebsite"},
		{http.MethodDelete, "/bucket?inventory", authorizationWrite, "DeleteBucketInventory"},
		{http.MethodDelete, "/bucket?inventory&id=report", authorizationWrite, "DeleteBucketInventory"},

		// Batch delete
		{http.MethodPost, "/bucket?delete", authorizationWrite, "DeleteObjects"},

		// Selector + x-id pass-through stays on the intended handler
		{http.MethodGet, "/bucket?policy&x-id=123", authorizationRead, "GetBucketPolicy"},
		{http.MethodDelete, "/bucket?policy&x-id=123", authorizationWrite, "DeleteBucketPolicy"},

		// ListObjects pagination parameters
		{http.MethodGet, "/bucket?list-type=2", authorizationRead, "ListObjects"},
		{http.MethodGet, "/bucket?list-type=2&prefix=a&max-keys=10", authorizationRead, "ListObjects"},
		{http.MethodGet, "/bucket?delimiter=/&encoding-type=url&fetch-owner=true", authorizationRead, "ListObjects"},

		// ListMultipartUploads parameter group (uploads + optional pagination)
		{http.MethodGet, "/bucket?uploads&max-uploads=100", authorizationRead, "ListMultipartUploads"},
		{http.MethodGet, "/bucket?uploads&key-marker=abc", authorizationRead, "ListMultipartUploads"},
		{http.MethodGet, "/bucket?uploads&upload-id-marker=def", authorizationRead, "ListMultipartUploads"},
		{http.MethodGet, "/bucket?uploads&prefix=p&delimiter=/&encoding-type=url&key-marker=a&upload-id-marker=b&max-uploads=5", authorizationRead, "ListMultipartUploads"},

		// inventory/analytics subresource + id parameter
		{http.MethodGet, "/bucket?inventory&id=report", authorizationRead, "GetBucketInventory"},
		{http.MethodGet, "/bucket?analytics&id=report", authorizationRead, "GetBucketAnalytics"},
		{http.MethodPut, "/bucket?inventory&id=report", authorizationWrite, "PutBucketInventory"},

		// Object-level routes
		{http.MethodGet, "/bucket/key", authorizationRead, "GetObject"},
		{http.MethodHead, "/bucket/key", authorizationRead, "HeadObject"},
		{http.MethodPut, "/bucket/key", authorizationWrite, "PutObject"},
		{http.MethodDelete, "/bucket/key", authorizationWrite, "DeleteObject"},

		// Object subresources
		{http.MethodGet, "/bucket/key?acl", authorizationRead, "GetObjectACL"},
		{http.MethodGet, "/bucket/key?retention", authorizationRead, "GetObjectRetention"},
		{http.MethodGet, "/bucket/key?legal-hold", authorizationRead, "GetObjectLegalHold"},
		{http.MethodGet, "/bucket/key?tagging", authorizationRead, "GetObjectTagging"},
		{http.MethodGet, "/bucket/key?versionId=abc", authorizationRead, "GetObject"},
		{http.MethodGet, "/bucket/key?partNumber=1", authorizationRead, "GetObject"},
		{http.MethodPut, "/bucket/key?acl", authorizationWrite, "PutObjectACL"},
		{http.MethodPut, "/bucket/key?retention", authorizationWrite, "PutObjectRetention"},
		{http.MethodPut, "/bucket/key?legal-hold", authorizationWrite, "PutObjectLegalHold"},
		{http.MethodPut, "/bucket/key?tagging", authorizationWrite, "PutObjectTagging"},
		{http.MethodDelete, "/bucket/key?tagging", authorizationWrite, "DeleteObjectTagging"},
		{http.MethodDelete, "/bucket/key?versionId=abc", authorizationWrite, "DeleteObject"},

		// ListParts parameter group (uploadId + optional pagination)
		{http.MethodGet, "/bucket/key?uploadId=u", authorizationRead, "ListParts"},
		{http.MethodGet, "/bucket/key?uploadId=u&max-parts=100", authorizationRead, "ListParts"},
		{http.MethodGet, "/bucket/key?uploadId=u&max-parts=100&part-number-marker=5", authorizationRead, "ListParts"},

		// Multipart mutations
		{http.MethodPut, "/bucket/key?partNumber=1&uploadId=u", authorizationWrite, "UploadPart"},
		{http.MethodPut, "/bucket/key?uploadId=u", authorizationWrite, "PutObject"},
		{http.MethodDelete, "/bucket/key?uploadId=u", authorizationWrite, "AbortMultipartUpload"},
		{http.MethodPost, "/bucket/key?uploads", authorizationWrite, "CreateMultipartUpload"},
		{http.MethodPost, "/bucket/key?uploadId=u", authorizationWrite, "CompleteMultipartUpload"},
		{http.MethodPost, "/bucket/key?restore", authorizationWrite, "RestoreObject"},
		{http.MethodPost, "/bucket/key?select", authorizationRead, "SelectObjectContent"},
		{http.MethodPost, "/bucket/key?select-type=2", authorizationRead, "SelectObjectContent"},

		// Select keys mixed with mutation keys stay classified as writes and
		// match mutation handlers.
		{http.MethodPost, "/bucket/key?select&uploadId=u", authorizationWrite, "CompleteMultipartUpload"},
		{http.MethodPost, "/bucket/key?select&restore", authorizationWrite, "RestoreObject"},

		// Invalid selector values and mixed selectors fail closed.
		{http.MethodDelete, "/bucket?policy=x", authorizationUnknown, ""},
		{http.MethodDelete, "/bucket?acl=x", authorizationUnknown, ""},
		{http.MethodPut, "/bucket?policy=x", authorizationUnknown, ""},
		{http.MethodPut, "/bucket?cors=x", authorizationUnknown, ""},
		{http.MethodPut, "/bucket?intelligent-tiering=x", authorizationUnknown, ""},
		{http.MethodGet, "/bucket?uploads&inventory", authorizationUnknown, ""},
		{http.MethodGet, "/bucket?inventory&analytics", authorizationUnknown, ""},
		{http.MethodGet, "/bucket?policy&inventory", authorizationUnknown, ""},
		{http.MethodGet, "/bucket?key-marker=a", authorizationUnknown, ""},
		{http.MethodGet, "/bucket?max-uploads=1", authorizationUnknown, ""},
		{http.MethodGet, "/bucket?id=report", authorizationUnknown, ""},
		{http.MethodGet, "/bucket?acl&id=x", authorizationUnknown, ""},
		{http.MethodGet, "/bucket/key?max-parts=5", authorizationUnknown, ""},
		{http.MethodGet, "/bucket/key?part-number-marker=3", authorizationUnknown, ""},
		{http.MethodGet, "/bucket/key?uploadId=u&tagging", authorizationUnknown, ""},
		{http.MethodGet, "/bucket/key?tagging=x", authorizationUnknown, ""},
		{http.MethodPost, "/bucket/key?select-type=3", authorizationUnknown, ""},
		{http.MethodPost, "/bucket?delete=x", authorizationUnknown, ""},

		// Object unknown/malformed
		{http.MethodPost, "/bucket/key", authorizationUnknown, ""},
		{http.MethodPost, "/bucket/key?delete", authorizationUnknown, ""},
		{http.MethodGet, "/bucket/key?unknown=1", authorizationUnknown, ""},
		{http.MethodGet, "/bucket/key?uploads", authorizationUnknown, ""},
		{http.MethodPut, "/bucket/key?partNumber=1", authorizationUnknown, ""},
		{http.MethodPatch, "/bucket/key", authorizationUnknown, ""},

		// Bucket unknown
		{http.MethodGet, "/bucket?foo=bar", authorizationUnknown, ""},
		{http.MethodPut, "/bucket?foo=bar", authorizationUnknown, ""},
		{http.MethodPost, "/bucket", authorizationUnknown, ""},
		{http.MethodPatch, "/bucket", authorizationUnknown, ""},
	}

	for _, tt := range tests {
		t.Run(tt.method+tt.target, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			op, _ := classifyAuthorizationOperation(req)
			if op != tt.want {
				t.Fatalf("classifier: operation=%v want=%v for %s %s", op, tt.want, tt.method, tt.target)
			}

			if tt.want == authorizationUnknown {
				// Fail closed: even a fully-permissive credential must be
				// denied before the router can run any handler.
				credential := Credential{Policy: AuthorizationPolicy{
					Permissions:       config.ObjectPermissionReadWrite,
					BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate, config.BucketPermissionDelete},
				}}
				called := false
				middleware := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
				recorder := httptest.NewRecorder()
				middleware.ServeHTTP(recorder, authorizedRequest(tt.method, tt.target, credential))
				if called || recorder.Code != http.StatusForbidden {
					t.Fatalf("unknown operation not denied: called=%v status=%d", called, recorder.Code)
				}
				return
			}

			// The classifier allows the request; the real router must select
			// the semantically matching named route — never the generic
			// CreateBucket/DeleteBucket fallback.
			match := &mux.RouteMatch{}
			if !router.Match(req, match) {
				t.Fatalf("router: no route matched %s %s (classifier allowed it)", tt.method, tt.target)
			}
			name := match.Route.GetName()
			if name != tt.wantRoute {
				t.Fatalf("router: matched route %q want %q for %s %s (op=%v)", name, tt.wantRoute, tt.method, tt.target, tt.want)
			}
			if tt.want != authorizationCreateBucket && name == "CreateBucket" {
				t.Fatalf("router: %s %s fell through to generic CreateBucket without the create grant", tt.method, tt.target)
			}
			if tt.want != authorizationDeleteBucket && name == "DeleteBucket" {
				t.Fatalf("router: %s %s fell through to generic DeleteBucket without the delete grant", tt.method, tt.target)
			}
		})
	}
}

// TestAllFiveAuditReasons exhaustively tests every bounded authorization audit reason.
func TestAllFiveAuditReasons(t *testing.T) {
	events := &mockAuditLogger{}
	tests := []struct {
		name       string
		method     string
		target     string
		credential Credential
		proxied    string
		wantReason string
		wantCode   int
	}{
		{
			name:       "unknown_operation",
			method:     http.MethodPatch,
			target:     "/bucket/key",
			credential: Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}},
			wantReason: "unknown_operation",
			wantCode:   http.StatusForbidden,
		},
		{
			name:       "bucket_scope",
			method:     http.MethodGet,
			target:     "/outside/key",
			credential: Credential{Policy: AuthorizationPolicy{Buckets: []string{"inside"}, Permissions: config.ObjectPermissionReadWrite}},
			wantReason: "bucket_scope",
			wantCode:   http.StatusForbidden,
		},
		{
			name:       "read_only_put",
			method:     http.MethodPut,
			target:     "/bucket/key",
			credential: Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}},
			wantReason: "read_only",
			wantCode:   http.StatusForbidden,
		},
		{
			name:       "read_only_listbuckets",
			method:     http.MethodGet,
			target:     "/",
			credential: Credential{Policy: AuthorizationPolicy{Permissions: ""}},
			wantReason: "read_only",
			wantCode:   http.StatusForbidden,
		},
		{
			name:       "bucket_create",
			method:     http.MethodPut,
			target:     "/bucket",
			credential: Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}},
			wantReason: "bucket_create",
			wantCode:   http.StatusForbidden,
		},
		{
			name:       "bucket_delete",
			method:     http.MethodDelete,
			target:     "/bucket",
			credential: Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}},
			wantReason: "bucket_delete",
			wantCode:   http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			events.events = nil
			recorder := httptest.NewRecorder()
			h := AuthorizationMiddleware(tt.proxied, events)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			h.ServeHTTP(recorder, authorizedRequest(tt.method, tt.target, tt.credential))
			if recorder.Code != tt.wantCode {
				t.Fatalf("status=%d want=%d", recorder.Code, tt.wantCode)
			}
			if len(events.events) != 1 {
				t.Fatalf("expected 1 audit event, got %d", len(events.events))
			}
			if events.events[0].reason != tt.wantReason {
				t.Fatalf("expected reason %q, got %q", tt.wantReason, events.events[0].reason)
			}
			// Verify S3 XML response structure
			body := recorder.Body.String()
			if !strings.Contains(body, "<Code>AccessDenied</Code>") {
				t.Fatalf("response missing AccessDenied code: %s", body)
			}
			if !strings.Contains(body, "<Message>Access Denied</Message>") {
				t.Fatalf("response missing Access Denied message: %s", body)
			}
			if recorder.Header().Get("Content-Type") != "application/xml" {
				t.Fatalf("content-type=%q want=application/xml", recorder.Header().Get("Content-Type"))
			}
		})
	}
}

// TestAuthorizationMiddleware_SelectorBypassesRejected proves that query
// shapes which fall through to the generic CreateBucket/DeleteBucket handlers
// are denied before routing: x-id never identifies an operation by itself and
// a non-empty intelligent-tiering selector misses its empty-value route. Each
// denial must produce zero backend-client acquisitions and zero handler
// invocations.
func TestAuthorizationMiddleware_SelectorBypassesRejected(t *testing.T) {
	handler := &Handler{logger: logrus.New(), metrics: getTestMetrics()}
	handler.clientAcquirer = func(*http.Request) (s3.Client, error) {
		t.Error("backend client acquired before authorization denial")
		return nil, nil
	}
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// rw without any bucket lifecycle grants: any fallthrough to
	// CreateBucket/DeleteBucket must be impossible.
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite}}

	tests := []struct{ method, target string }{
		{http.MethodPut, "/bucket?x-id=Anything"},
		{http.MethodDelete, "/bucket?x-id=Anything"},
		{http.MethodPut, "/bucket?intelligent-tiering=x"},
	}
	for _, tt := range tests {
		t.Run(tt.method+tt.target, func(t *testing.T) {
			rec := httptest.NewRecorder()
			middleware := AuthorizationMiddleware("", nil)(router)
			middleware.ServeHTTP(rec, authorizedRequest(tt.method, tt.target, credential))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status=%d want=403 body=%s", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "<Code>AccessDenied</Code>") {
				t.Fatalf("response missing AccessDenied code: %s", rec.Body.String())
			}
		})
	}

	// The same PUT shape with the explicit create grant reaches the real
	// CreateBucket route — x-id is a pass-through, never a selector.
	credentialWithCreate := Credential{Policy: AuthorizationPolicy{
		Permissions:       config.ObjectPermissionReadWrite,
		BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate},
	}}
	rec := httptest.NewRecorder()
	req := authorizedRequest(http.MethodPut, "/bucket?x-id=Anything", credentialWithCreate)
	match := &mux.RouteMatch{}
	if !router.Match(req, match) || match.Route.GetName() != "CreateBucket" {
		t.Fatalf("granted PUT with x-id did not select CreateBucket route")
	}
	_ = rec

	// The same DELETE shape with the explicit delete grant selects the real
	// DeleteBucket route.
	credentialWithDelete := Credential{Policy: AuthorizationPolicy{
		Permissions:       config.ObjectPermissionReadWrite,
		BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete},
	}}
	req = authorizedRequest(http.MethodDelete, "/bucket?x-id=Anything", credentialWithDelete)
	match = &mux.RouteMatch{}
	if !router.Match(req, match) || match.Route.GetName() != "DeleteBucket" {
		t.Fatalf("granted DELETE with x-id did not select DeleteBucket route")
	}
}

// TestAuthorizationMiddleware_AccessDeniedXMLStructure parses the AccessDenied
// response XML and asserts the exact code, message, resource path,
// Content-Type, status, and per-request resource isolation.
func TestAuthorizationMiddleware_AccessDeniedXMLStructure(t *testing.T) {
	credential := Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadOnly}}
	middleware := AuthorizationMiddleware("", nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Fatal("handler called") }))

	type errorResponse struct {
		XMLName  xml.Name `xml:"Error"`
		Code     string   `xml:"Code"`
		Message  string   `xml:"Message"`
		Resource string   `xml:"Resource"`
	}

	// First denial: resource /bucket-a/key
	recA := httptest.NewRecorder()
	middleware.ServeHTTP(recA, authorizedRequest(http.MethodPut, "/bucket-a/key", credential))
	if recA.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=403", recA.Code)
	}
	if ct := recA.Header().Get("Content-Type"); ct != "application/xml" {
		t.Fatalf("content-type=%q want=application/xml", ct)
	}
	var errA errorResponse
	if err := xml.Unmarshal(recA.Body.Bytes(), &errA); err != nil {
		t.Fatalf("failed to parse AccessDenied XML: %v\nbody=%s", err, recA.Body.String())
	}
	if errA.XMLName.Local != "Error" {
		t.Fatalf("XMLName.Local=%q want=Error", errA.XMLName.Local)
	}
	if errA.Code != "AccessDenied" {
		t.Fatalf("Code=%q want=AccessDenied", errA.Code)
	}
	if errA.Message != "Access Denied" {
		t.Fatalf("Message=%q want=\"Access Denied\"", errA.Message)
	}
	if errA.Resource != "/bucket-a/key" {
		t.Fatalf("Resource=%q want=/bucket-a/key", errA.Resource)
	}

	// Second denial: the shared ErrAccessDenied error must not leak the first
	// request's resource path (request isolation).
	recB := httptest.NewRecorder()
	middleware.ServeHTTP(recB, authorizedRequest(http.MethodDelete, "/bucket-b/other", credential))
	var errB errorResponse
	if err := xml.Unmarshal(recB.Body.Bytes(), &errB); err != nil {
		t.Fatalf("failed to parse second AccessDenied XML: %v", err)
	}
	if errB.Resource != "/bucket-b/other" {
		t.Fatalf("second denial Resource=%q want=/bucket-b/other (request isolation broken)", errB.Resource)
	}
	if errA.Resource == errB.Resource {
		t.Fatalf("denial resources must be request-local")
	}
}
