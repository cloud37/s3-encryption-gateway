package api

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// Fail only the selected backend acquisition, not metadata parsing or crypto.
// Embedding the ordinary mock retains authentic ciphertext/range behavior.
type objectReadFaultClient struct {
	*mockS3Client
	fault                         error
	failHead                      bool
	fullGets, terminalGets, heads int
	fullClosed                    bool
	versions                      []string
}

type objectReadTrackingCloser struct {
	io.ReadCloser
	closed *bool
}

func (r objectReadTrackingCloser) Close() error {
	*r.closed = true
	return r.ReadCloser.Close()
}

func (c *objectReadFaultClient) GetObject(ctx context.Context, bucket, key string, versionID, byteRange *string) (io.ReadCloser, map[string]string, error) {
	c.versions = append(c.versions, requestVersionID(versionID))
	if byteRange != nil {
		c.terminalGets++
		return nil, nil, c.fault
	}
	c.fullGets++
	r, meta, err := c.mockS3Client.GetObject(ctx, bucket, key, versionID, byteRange)
	if err != nil {
		return nil, nil, err
	}
	return objectReadTrackingCloser{ReadCloser: r, closed: &c.fullClosed}, meta, nil
}

func (c *objectReadFaultClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	c.heads++
	c.versions = append(c.versions, requestVersionID(versionID))
	if c.failHead {
		return nil, c.fault
	}
	return c.mockS3Client.HeadObject(ctx, bucket, key, versionID)
}

func TestObjectRead_BackendFailures(t *testing.T) {
	for _, fault := range []struct {
		name, code string
		status     int
		err        error
	}{
		{"missing", "NoSuchKey", 404, &smithy.GenericAPIError{Code: "NoSuchKey", Message: "private backend detail"}},
		{"denied", "AccessDenied", 403, &smithy.GenericAPIError{Code: "AccessDenied", Message: "private backend detail"}},
		{"throttle", "SlowDown", 503, &smithy.GenericAPIError{Code: "SlowDown", Message: "private backend detail"}},
		{"unavailable", "ServiceUnavailable", 503, &smithy.GenericAPIError{Code: "ServiceUnavailable", Message: "private backend detail"}},
		{"deadline", "InternalError", 500, context.DeadlineExceeded},
		{"unknown", "InternalError", 500, errors.New("private backend detail")},
	} {
		for _, route := range []struct {
			name, method, path, op         string
			ranged, copy, cached, failHead bool
			fullGets, heads                int
		}{
			{name: "full", method: "GET", path: "/test-bucket/source?versionId=v-source", op: "GetObject", fullGets: 1},
			{name: "range", method: "GET", path: "/test-bucket/source?versionId=v-source", op: "GetObject", ranged: true, heads: 1},
			{name: "head", method: "HEAD", path: "/test-bucket/source?versionId=v-source", op: "HeadObject", heads: 1},
			{name: "copy", method: "PUT", path: "/test-bucket/destination", op: "CopyObject", copy: true, heads: 1},
			{name: "part-copy", method: "PUT", path: "/test-bucket/destination?partNumber=1&uploadId=plain-upload", op: "UploadPartCopy", copy: true, heads: 1},
			{name: "cache-terminal", method: "GET", path: "/test-bucket/source", op: "GetObject", cached: true, heads: 1},
			{name: "cache-head", method: "GET", path: "/test-bucket/source", op: "GetObject", cached: true, failHead: true, heads: 1},
			{name: "range-head", method: "GET", path: "/test-bucket/source?versionId=v-source", op: "GetObject", ranged: true, failHead: true, heads: 1},
		} {
			t.Run(fault.name+"/"+route.name, func(t *testing.T) {
				engine, err := newAPIUnitChunkedEngine([]byte("gh344-password"), "", nil, true, crypto.MinChunkSize)
				if err != nil {
					t.Fatal(err)
				}
				client := &objectReadFaultClient{mockS3Client: newMockS3Client(), fault: fmt.Errorf("backend acquisition: %w", &smithy.OperationError{ServiceID: "S3", OperationName: "GetObject", Err: fault.err}), failHead: route.failHead}
				putSEC37Object(t, client.mockS3Client, engine, "source", []byte("healthy plaintext"))
				registry := prometheus.NewRegistry()
				auditLog := audit.NewLogger(10, nil)
				h := NewHandler(client, engine, logrus.New(), metrics.NewMetricsWithRegistry(registry))
				h.auditLogger = auditLog
				if route.cached {
					h.cache = cache.NewMemoryCache(1024, 1, time.Hour)
					if err := h.cache.Set(context.Background(), "test-bucket", "source", []byte("stale cached plaintext"), nil, time.Hour); err != nil {
						t.Fatal(err)
					}
				}
				router := mux.NewRouter()
				h.RegisterRoutes(router)
				req := httptest.NewRequest(route.method, route.path, nil)
				if route.ranged {
					req.Header.Set("Range", "bytes=0-1")
				}
				if route.copy {
					req.Header.Set("x-amz-copy-source", "/test-bucket/source?versionId=v-source")
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				if w.Code != fault.status {
					t.Errorf("HTTP status=%d want=%d; body=%q", w.Code, fault.status, w.Body.String())
				}
				if req.Method == http.MethodHead {
					if w.Body.Len() != 0 {
						t.Errorf("HEAD error body=%q", w.Body.String())
					}
				} else {
					var response struct{ Code, Message, Resource string }
					if err := xml.Unmarshal(w.Body.Bytes(), &response); err != nil {
						t.Fatal(err)
					}
					if response.Code != fault.code || response.Resource != "/test-bucket/source" {
						t.Errorf("S3 response=%+v want code=%s source resource", response, fault.code)
					}
					if bytes.Contains(w.Body.Bytes(), []byte("private backend detail")) || bytes.Contains(w.Body.Bytes(), []byte("plaintext")) {
						t.Errorf("response leaks diagnostics/plaintext: %q", w.Body.String())
					}
				}
				if w.Header().Get("Content-Range") != "" {
					t.Error("error response has successful range headers")
				}
				terminalGets := 1
				if route.failHead {
					terminalGets = 0
				}
				if client.fullGets != route.fullGets || client.terminalGets != terminalGets || client.heads != route.heads {
					t.Errorf("full/terminal/head=%d/%d/%d want=%d/%d/%d", client.fullGets, client.terminalGets, client.heads, route.fullGets, terminalGets, route.heads)
				}
				if route.fullGets == 1 && (!client.fullClosed || client.bodyReadCount.Load() != 0) {
					t.Errorf("full body closed=%t reads=%d; preflight failure must close without consuming", client.fullClosed, client.bodyReadCount.Load())
				}
				for _, version := range client.versions {
					want := "v-source"
					if route.cached {
						want = ""
					}
					if version != want {
						t.Errorf("backend version=%q want=%q", version, want)
					}
				}
				if _, exists := client.objects["test-bucket/destination"]; exists {
					t.Error("failed copy wrote destination")
				}
				if events := auditLog.GetEvents(); len(events) != 0 {
					t.Errorf("backend failure emitted crypto audit: %+v", events)
				}
				if got := metricTotal(t, registry, "encryption_errors_total", `operation="decrypt"`); got != 0 {
					t.Errorf("backend failure recorded %v decrypt/tamper errors", got)
				}
				if got := metricTotal(t, registry, "http_requests_total", `method="`+route.method+`"`); got != 1 {
					t.Errorf("request accounting=%v want once", got)
				}
				if got := metricSample(t, registry, "http_requests_total", `method="`+route.method+`"`, `status="`+http.StatusText(fault.status)+`"`); got != 1 {
					t.Errorf("status accounting=%v want once", got)
				}
				if got := metricSample(t, registry, "s3_operation_errors_total", `operation="`+route.op+`"`, `error_type="`+fault.code+`"`); got != 1 {
					t.Errorf("S3 error accounting=%v want once", got)
				}
			})
		}
	}
}

func TestObjectRead_KEKBackendFailureAndIntegrityControl(t *testing.T) {
	for _, mode := range []string{"backend-missing", "tampered-terminal", "valid"} {
		t.Run(mode, func(t *testing.T) {
			km, err := crypto.NewAESKEKManager(map[int][]byte{1: bytes.Repeat([]byte{0x42}, 32)}, 1)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = km.Close(context.Background()) })
			engine, err := newAPIUnitChunkedEngine([]byte("unused-password"), "", nil, true, crypto.MinChunkSize)
			if err != nil {
				t.Fatal(err)
			}
			crypto.SetKeyManager(engine, km)
			client := newMockS3Client()
			plain := []byte("self-contained healthy plaintext")
			putSEC37Object(t, client, engine, "source", plain)
			auditLog := audit.NewLogger(10, nil)
			registry := prometheus.NewRegistry()
			h := NewHandler(client, engine, logrus.New(), metrics.NewMetricsWithRegistry(registry))
			h.auditLogger = auditLog
			wantStatus, wantCode := 200, ""
			if mode == "backend-missing" {
				h.s3Client = &objectReadFaultClient{mockS3Client: client, fault: &smithy.GenericAPIError{Code: "NoSuchKey", Message: "missing"}}
				wantStatus, wantCode = 404, "NoSuchKey"
			} else if mode == "tampered-terminal" {
				ciphertext := client.objects["test-bucket/source"]
				ciphertext[len(ciphertext)-1] ^= 1
				wantStatus, wantCode = 500, "InternalError"
			}
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("GET", "/test-bucket/source", nil))
			if w.Code != wantStatus {
				t.Errorf("status=%d want=%d", w.Code, wantStatus)
			}
			if mode == "valid" {
				if !bytes.Equal(w.Body.Bytes(), plain) || w.Header().Get("Content-Length") != strconv.Itoa(len(plain)) {
					t.Errorf("valid response=%q headers=%v", w.Body.String(), w.Header())
				}
			} else if !bytes.Contains(w.Body.Bytes(), []byte("<Code>"+wantCode+"</Code>")) || bytes.Contains(w.Body.Bytes(), plain) {
				t.Errorf("error body=%q", w.Body.String())
			}
			events := auditLog.GetEvents()
			wantEvents := 1
			if mode == "backend-missing" {
				wantEvents = 0
			}
			if len(events) != wantEvents {
				t.Errorf("audit=%+v", events)
			}
			if mode == "tampered-terminal" {
				if len(events) == 1 && events[0].Operation != "object_stream_integrity_failure" {
					t.Errorf("wrong integrity audit=%+v", events)
				}
				if got := metricSample(t, registry, "encryption_errors_total", `error_type="object_integrity_failure"`); got != 1 {
					t.Errorf("integrity metric=%v want once", got)
				}
			}
		})
	}
}
