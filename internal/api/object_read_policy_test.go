package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

func gh380Policy(t *testing.T, text string) *config.PolicyManager {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	pm := config.NewPolicyManager()
	if err := pm.ReloadPolicies([]string{path}); err != nil {
		t.Fatal(err)
	}
	return pm
}

func gh380Handler(t *testing.T, client *mockS3Client) *Handler {
	t.Helper()
	engine, err := newAPIUnitEngine([]byte("gh380-test-password"))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(client, engine, logrus.New(), getTestMetrics())
	h.policyManager = gh380Policy(t, "id: strict\nbuckets: [test-bucket]\nrequire_encryption: true\n")
	return h
}

func TestGH380ReadPolicyMatrix(t *testing.T) {
	h := &Handler{}
	if err := h.enforceObjectReadPolicy("test-bucket", crypto.ObjectClass{}); err != nil {
		t.Fatal(err)
	}
	h.policyManager = gh380Policy(t, "id: strict\nbuckets: ['secure-*']\nrequire_encryption: true\n")
	if err := h.enforceObjectReadPolicy("other", crypto.ObjectClass{}); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(h.enforceObjectReadPolicy("secure-a", crypto.ObjectClass{}), errPlaintextReadForbidden) {
		t.Fatal("plaintext was not denied")
	}
	for f := crypto.FormatBufferedLegacy; f <= crypto.FormatMPUV2; f++ {
		if err := h.enforceObjectReadPolicy("secure-a", crypto.ObjectClass{Format: f, Encrypted: true}); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	first := filepath.Join(dir, "1.yaml")
	second := filepath.Join(dir, "2.yaml")
	if err := os.WriteFile(first, []byte("id: first\nbuckets: ['secure-open-*']\nrequire_encryption: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("id: second\nbuckets: ['secure-*']\nrequire_encryption: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	pm := config.NewPolicyManager()
	if err := pm.ReloadPolicies([]string{first, second}); err != nil {
		t.Fatal(err)
	}
	h.policyManager = pm
	if err := h.enforceObjectReadPolicy("secure-open-1", crypto.ObjectClass{}); err != nil {
		t.Fatalf("first match false: %v", err)
	}
	if !errors.Is(h.enforceObjectReadPolicy("secure-closed", crypto.ObjectClass{}), errPlaintextReadForbidden) {
		t.Fatal("second match must deny")
	}
}

func TestGH380ReadableViewClassification(t *testing.T) {
	h := gh380Handler(t, newMockS3Client())
	for _, tc := range []struct {
		name     string
		metadata map[string]string
		want     error
	}{
		{"ordinary", map[string]string{"x-amz-meta-user": "value", "x-amz-server-side-encryption": "AES256"}, errPlaintextReadForbidden},
		{"unknown", map[string]string{crypto.MetaMPUEncrypted: "unknown"}, crypto.ErrUnsupportedObjectFormat},
		{"encrypted", map[string]string{crypto.MetaEncrypted: "true"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := cloneStringMap(tc.metadata)
			view, err := h.loadReadableObjectView("test-bucket", "key", nil, tc.metadata)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
			if tc.want != nil && view != nil {
				t.Fatal("view returned on error")
			}
			if !reflect.DeepEqual(before, tc.metadata) {
				t.Fatal("metadata mutated")
			}
		})
	}
}

type gh380ParentBody struct {
	io.Reader
	reads, closes int
}

func (b *gh380ParentBody) Read(p []byte) (int, error) { b.reads++; return b.Reader.Read(p) }
func (b *gh380ParentBody) Close() error               { b.closes++; return nil }

type gh380ParentBackend struct {
	s3.Client
	body               *gh380ParentBody
	metadata           map[string]string
	err                error
	bucket, key        string
	version, byteRange *string
}

func (b *gh380ParentBackend) GetObject(_ context.Context, bucket, key string, version, byteRange *string) (io.ReadCloser, map[string]string, error) {
	b.bucket, b.key, b.version, b.byteRange = bucket, key, version, byteRange
	if b.err != nil {
		return nil, nil, b.err
	}
	return b.body, b.metadata, nil
}

func TestGH380ReadableParentClient(t *testing.T) {
	backendErr := errors.New("backend acquisition failed")
	expandErr := errors.New("metadata normalization failed")
	for _, tc := range []struct {
		name, bucket, key                     string
		metadata                              map[string]string
		backendErr, normalizationErr, wantErr error
	}{
		{"allowed", "test-bucket", "parent", map[string]string{crypto.MetaEncrypted: "true"}, nil, nil, nil},
		{"policy-denied", "test-bucket", "parent", map[string]string{"Content-Length": "10"}, nil, nil, errPlaintextReadForbidden},
		{"classification-error", "test-bucket", "parent", map[string]string{crypto.MetaMPUEncrypted: "unknown"}, nil, nil, crypto.ErrUnsupportedObjectFormat},
		{"normalization-error", "test-bucket", "parent", map[string]string{crypto.MetaEncrypted: "true"}, nil, expandErr, expandErr},
		{"other-bucket", "other-bucket", "parent", map[string]string{"Content-Length": "10"}, nil, nil, nil},
		{"other-key", "test-bucket", "parent.mpu-manifest", map[string]string{"Content-Length": "10"}, nil, nil, nil},
		{"backend-error", "test-bucket", "parent", nil, backendErr, nil, backendErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &gh380ParentBody{Reader: strings.NewReader("data")}
			backend := &gh380ParentBackend{body: body, metadata: tc.metadata, err: tc.backendErr}
			h := gh380Handler(t, newMockS3Client())
			if tc.normalizationErr != nil {
				h.apiMetadataExpander = func(map[string]string) (map[string]string, error) { return nil, tc.normalizationErr }
			}
			client := readableParentClient{Client: backend, h: h, bucket: "test-bucket", key: "parent"}
			version, byteRange := "selected-version", "bytes=1-2"
			r, metadata, err := client.GetObject(context.Background(), tc.bucket, tc.key, &version, &byteRange)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error=%v want=%v", err, tc.wantErr)
			}
			if backend.bucket != tc.bucket || backend.key != tc.key || backend.version != &version || backend.byteRange != &byteRange {
				t.Fatal("backend arguments changed")
			}
			if body.reads != 0 {
				t.Fatalf("wrapper read body %d times", body.reads)
			}
			if tc.wantErr != nil {
				wantCloses := 1
				if tc.backendErr != nil {
					wantCloses = 0
				}
				if r != nil || metadata != nil || body.closes != wantCloses {
					t.Fatalf("error result reader=%v metadata=%v closes=%d", r, metadata, body.closes)
				}
				return
			}
			if r != body || !reflect.DeepEqual(metadata, tc.metadata) || body.closes != 0 {
				t.Fatalf("passthrough reader=%v metadata=%v closes=%d", r, metadata, body.closes)
			}
			if err := r.Close(); err != nil || body.closes != 1 {
				t.Fatalf("caller close err=%v closes=%d", err, body.closes)
			}
		})
	}
}

func TestGH380ReadPolicyErrorSurface(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		registry := prometheus.NewRegistry()
		logger := audit.NewLogger(10, nil)
		h := &Handler{metrics: metrics.NewMetricsWithRegistry(registry), auditLogger: logger}
		r := httptest.NewRequest(method, "/destination/key", nil)
		w := httptest.NewRecorder()
		if !h.writeObjectReadPolicyError(w, r, method, "source", "key", fmt.Errorf("wrapped: %w", errPlaintextReadForbidden), time.Now()) {
			t.Fatal("not handled")
		}
		if w.Code != 403 {
			t.Fatalf("status=%d", w.Code)
		}
		if method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatalf("HEAD body=%q", w.Body.String())
		}
		if method == http.MethodGet && !containsGH380Message(w.Body.String()) {
			t.Fatalf("unexpected XML: %s", w.Body.String())
		}
		events := logger.GetEvents()
		if len(events) != 1 {
			t.Fatalf("audit count=%d", len(events))
		}
		e := events[0]
		op := "GetObject"
		if method == http.MethodHead {
			op = "HeadObject"
		}
		if string(e.EventType) != "plaintext_read_refused" || e.Bucket != "source" || e.Key != "key" || e.Success || e.Metadata["reason"] != "source_requires_encryption" || e.Metadata["operation"] != op || e.Metadata["source_bucket"] != "source" || e.Metadata["source_key"] != "key" {
			t.Fatalf("audit: %+v", e)
		}
		if got := metricSample(t, registry, "s3_operation_errors_total", `operation="`+op+`"`, `bucket="source"`, `error_type="AccessDenied"`); got != 1 {
			t.Fatalf("s3 errors=%v", got)
		}
		if got := metricTotal(t, registry, "encryption_errors_total", `operation="decrypt"`); got != 0 {
			t.Fatalf("decrypt errors=%v", got)
		}
	}
	h := &Handler{}
	if h.writeObjectReadPolicyError(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), "GET", "", "", errors.New("other"), time.Now()) {
		t.Fatal("unrelated error handled")
	}
	(&Handler{}).writeObjectReadPolicyError(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), "GET", "", "", errPlaintextReadForbidden, time.Now())
}
