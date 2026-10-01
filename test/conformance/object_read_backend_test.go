//go:build conformance

package conformance

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	"github.com/prometheus/client_golang/prometheus"
)

// The real provider handles PUT, HEAD, full GET and DELETE. Only a terminal
// acquisition is faulted. A frozen successful full response can also model
// read-after-delete inconsistency deterministically, without sleeps or retries.
type terminalFaultTransport struct {
	base           http.RoundTripper
	mu             sync.Mutex
	code           string
	status         int
	replay         bool
	header         http.Header
	body           []byte
	full, terminal int
}

func (f *terminalFaultTransport) arm(code string, status int, replay bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.code, f.status, f.replay = code, status, replay
	f.full, f.terminal = 0, 0
}

func (f *terminalFaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	if req.Method == http.MethodGet && f.code != "" {
		if req.Header.Get("Range") != "" {
			f.terminal++
			body := fmt.Sprintf("<Error><Code>%s</Code><Message>private backend diagnostic</Message></Error>", f.code)
			resp := &http.Response{StatusCode: f.status, Header: http.Header{"Content-Type": {"application/xml"}}, Body: io.NopCloser(bytes.NewBufferString(body)), ContentLength: int64(len(body)), Request: req}
			f.mu.Unlock()
			return resp, nil
		}
		f.full++
		if f.replay {
			resp := &http.Response{StatusCode: 200, Header: f.header.Clone(), Body: io.NopCloser(bytes.NewReader(f.body)), ContentLength: int64(len(f.body)), Request: req}
			f.mu.Unlock()
			return resp, nil
		}
	}
	f.mu.Unlock()
	resp, err := f.base.RoundTrip(req)
	if err == nil && req.Method == http.MethodGet && req.Header.Get("Range") == "" && resp.StatusCode == 200 {
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		f.mu.Lock()
		f.body, f.header = body, resp.Header.Clone()
		f.mu.Unlock()
	}
	return resp, err
}

func objectReadCounter(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) float64 {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var total float64
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			found := map[string]string{}
			for _, label := range metric.Label {
				found[label.GetName()] = label.GetValue()
			}
			match := true
			for key, value := range labels {
				if found[key] != value {
					match = false
				}
			}
			if match {
				total += metric.GetCounter().GetValue()
			}
		}
	}
	return total
}

func testObjectReadBackendErrors(t *testing.T, inst provider.Instance) {
	for _, code := range []string{"NoSuchKey", "SlowDown", "ServiceUnavailable"} {
		for _, route := range []string{"full", "range", "head", "copy", "cache"} {
			t.Run(code+"/"+route, func(t *testing.T) { testObjectReadBackendError(t, inst, code, route, false) })
		}
	}
}

func testObjectReadBackendDeleteRace(t *testing.T, inst provider.Instance) {
	testObjectReadBackendError(t, inst, "NoSuchKey", "full", true)
}

func testObjectReadBackendPartCopy(t *testing.T, inst provider.Instance) {
	for _, code := range []string{"NoSuchKey", "SlowDown", "ServiceUnavailable"} {
		t.Run(code, func(t *testing.T) { testObjectReadBackendError(t, inst, code, "part-copy", false) })
	}
}

func testObjectReadBackendError(t *testing.T, inst provider.Instance, code, route string, deleted bool) {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	fault := &terminalFaultTransport{base: transport}
	auditLog := audit.NewLogger(100, nil)
	gw := harness.StartGateway(t, inst, harness.WithChunking(true), harness.WithKeyManager(makeAESKEKManager(t)), harness.WithAuditLogger(auditLog), harness.WithBackendTransport(fault), harness.WithConfigMutator(func(cfg *config.Config) {
		cfg.Backend.Retry.MaxAttempts = 1
		if route == "cache" {
			cfg.Cache.Enabled, cfg.Cache.MaxSize, cfg.Cache.MaxItems, cfg.Cache.DefaultTTL = true, 1024*1024, 10, time.Hour
		}
	}))
	key := uniqueKey(t)
	plain := []byte("healthy self-contained chunked-v2 object")
	put(t, gw, inst.Bucket, key, plain)
	if got := get(t, gw, inst.Bucket, key); !bytes.Equal(got, plain) {
		t.Fatalf("positive control body=%q", got)
	}
	meta := headMeta(t, newS3Client(t, inst), inst.Bucket, key)
	expanded, err := crypto.ExpandMetadataForAPI(meta)
	if err != nil {
		t.Fatal(err)
	}
	class, err := crypto.ClassifyObject(key, expanded)
	if err != nil || class.Format != crypto.FormatChunkedV2 {
		t.Fatalf("provider object class=%+v error=%v", class, err)
	}
	if deleted {
		req, err := http.NewRequestWithContext(t.Context(), "DELETE", objectURL(gw, inst.Bucket, key), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := gw.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 204 {
			t.Fatalf("DELETE status=%d", resp.StatusCode)
		}
	}
	wantStatus := 503
	if code == "NoSuchKey" {
		wantStatus = 404
	}
	method, op, path := "GET", "GetObject", objectURL(gw, inst.Bucket, key)
	if route == "head" {
		method, op = "HEAD", "HeadObject"
	}
	if route == "copy" || route == "part-copy" {
		method, op, path = "PUT", "CopyObject", objectURL(gw, inst.Bucket, key+"-destination")
		if route == "part-copy" {
			op = "UploadPartCopy"
			uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key+"-destination")
			t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key+"-destination", uploadID) })
			path += "?partNumber=1&uploadId=" + uploadID
		}
	}
	beforeRequests := objectReadCounter(t, gw.Metrics, "http_requests_total", map[string]string{"method": method})
	beforeErrors := objectReadCounter(t, gw.Metrics, "s3_operation_errors_total", map[string]string{"operation": op, "error_type": code})
	beforeCrypto := objectReadCounter(t, gw.Metrics, "encryption_errors_total", nil)
	beforeEvents := len(auditLog.GetEvents())
	fault.arm(code, wantStatus, deleted)
	req, err := http.NewRequestWithContext(t.Context(), method, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if route == "range" {
		req.Header.Set("Range", "bytes=0-1")
	}
	if route == "copy" || route == "part-copy" {
		req.Header.Set("x-amz-copy-source", "/"+inst.Bucket+"/"+key)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus {
		t.Errorf("status=%d want=%d body=%q", resp.StatusCode, wantStatus, body)
	}
	if method == "HEAD" {
		if len(body) != 0 {
			t.Errorf("HEAD body=%q", body)
		}
	} else {
		var response struct{ Code, Message, Resource string }
		if err := xml.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		if response.Code != code || response.Resource != "/"+inst.Bucket+"/"+key {
			t.Errorf("S3 error=%+v", response)
		}
	}
	if bytes.Contains(body, plain) || bytes.Contains(body, []byte("private backend diagnostic")) || resp.Header.Get("Content-Range") != "" {
		t.Errorf("error leaks success/diagnostics: headers=%v body=%q", resp.Header, body)
	}
	fault.mu.Lock()
	full, terminal := fault.full, fault.terminal
	fault.mu.Unlock()
	wantFull := 0
	if route == "full" {
		wantFull = 1
	}
	if full != wantFull || terminal != 1 {
		t.Errorf("full/terminal=%d/%d want=%d/1", full, terminal, wantFull)
	}
	if len(auditLog.GetEvents()) != beforeEvents {
		t.Errorf("backend failure emitted crypto audit: %+v", auditLog.GetEvents()[beforeEvents:])
	}
	if delta := objectReadCounter(t, gw.Metrics, "encryption_errors_total", nil) - beforeCrypto; delta != 0 {
		t.Errorf("crypto error delta=%v want zero", delta)
	}
	if delta := objectReadCounter(t, gw.Metrics, "http_requests_total", map[string]string{"method": method}) - beforeRequests; delta != 1 {
		t.Errorf("HTTP request delta=%v want once", delta)
	}
	if delta := objectReadCounter(t, gw.Metrics, "s3_operation_errors_total", map[string]string{"operation": op, "error_type": code}) - beforeErrors; delta != 1 {
		t.Errorf("S3 error delta=%v want once", delta)
	}
	fault.arm("", 0, false)
	if !deleted {
		if got := get(t, gw, inst.Bucket, key); !bytes.Equal(got, plain) {
			t.Errorf("recovery body=%q", got)
		}
	} else {
		resp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			t.Errorf("consistent post-delete GET status=%d", resp.StatusCode)
		}
	}
}
