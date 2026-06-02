package s3

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

// newTestProxyClient creates a ProxyClient pointed at the given test server URL.
func newTestProxyClient(t *testing.T, serverURL string) *ProxyClient {
	t.Helper()
	cfg := &config.BackendConfig{
		Endpoint: serverURL,
	}
	pc, err := NewProxyClient(cfg)
	if err != nil {
		t.Fatalf("NewProxyClient() error: %v", err)
	}
	return pc
}

// TestNewProxyClient_MissingEndpoint verifies that creating a ProxyClient with
// an empty endpoint returns an error.
func TestNewProxyClient_MissingEndpoint(t *testing.T) {
	cfg := &config.BackendConfig{Endpoint: ""}
	_, err := NewProxyClient(cfg)
	if err == nil {
		t.Fatal("NewProxyClient() expected error for empty endpoint, got nil")
	}
}

// TestNewProxyClient_ValidEndpoint verifies that a valid endpoint creates a client.
func TestNewProxyClient_ValidEndpoint(t *testing.T) {
	cfg := &config.BackendConfig{Endpoint: "http://localhost:9000"}
	pc, err := NewProxyClient(cfg)
	if err != nil {
		t.Fatalf("NewProxyClient() error: %v", err)
	}
	if pc == nil {
		t.Fatal("NewProxyClient() returned nil client without error")
	}
}

// TestNewProxyClient_TLSConfig verifies that the ProxyClient's http.Client
// has a Transport with TLS min version 1.2, non-empty cipher suites, and
// timeouts (V1.0-SEC-F5+F6).
func TestNewProxyClient_TLSConfig(t *testing.T) {
	cfg := &config.BackendConfig{Endpoint: "http://localhost:9000"}
	pc, err := NewProxyClient(cfg)
	if err != nil {
		t.Fatalf("NewProxyClient() error: %v", err)
	}
	if pc == nil {
		t.Fatal("NewProxyClient() returned nil")
	}

	transport, ok := pc.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatal("httpClient.Transport is not *http.Transport")
	}

	if transport.TLSClientConfig == nil {
		t.Fatal("TLSClientConfig is nil")
	}

	if transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %d, want %d (VersionTLS12)", transport.TLSClientConfig.MinVersion, tls.VersionTLS12)
	}

	if len(transport.TLSClientConfig.CipherSuites) == 0 {
		t.Error("CipherSuites is empty, expected non-empty")
	}

	expectedTimeouts := []struct {
		name string
		d    time.Duration
		got  time.Duration
	}{
		{"IdleConnTimeout", 90 * time.Second, transport.IdleConnTimeout},
		{"ResponseHeaderTimeout", 10 * time.Second, transport.ResponseHeaderTimeout},
	}
	for _, tc := range expectedTimeouts {
		if tc.got != tc.d {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.d)
		}
	}
}

// TestNewProxyClient_NoScheme verifies that a URL without a scheme is
// auto-prefixed with https://.
func TestNewProxyClient_NoScheme(t *testing.T) {
	cfg := &config.BackendConfig{Endpoint: "s3.example.com"}
	pc, err := NewProxyClient(cfg)
	if err != nil {
		t.Fatalf("NewProxyClient() error: %v", err)
	}
	if pc == nil {
		t.Fatal("NewProxyClient() returned nil client without error")
	}
	if pc.backendURL.Scheme != "https" {
		t.Errorf("expected scheme=https, got %q", pc.backendURL.Scheme)
	}
}

// TestProxyClient_ForwardRequest_PassThrough verifies that ForwardRequest
// copies the original request headers to the backend and returns the response.
func TestProxyClient_ForwardRequest_PassThrough(t *testing.T) {
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	// Build an original request with headers to forward
	origReq, _ := http.NewRequestWithContext(context.Background(), "GET", "/bucket/key", nil)
	origReq.Header.Set("X-Custom-Header", "custom-value")
	origReq.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/...")
	origReq.Header.Set("Host", "original-host") // Should NOT be forwarded
	origReq.URL.RawQuery = "versionId=v1"

	resp, err := pc.ForwardRequest(context.Background(), origReq, "GET", "bucket", "key", nil)
	if err != nil {
		t.Fatalf("ForwardRequest() error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("ForwardRequest() status = %d, want 200", resp.StatusCode)
	}

	// Custom header should be forwarded
	if gotHeaders.Get("X-Custom-Header") != "custom-value" {
		t.Errorf("X-Custom-Header not forwarded: %v", gotHeaders)
	}

	// Authorization should be forwarded
	if gotHeaders.Get("Authorization") == "" {
		t.Errorf("Authorization header not forwarded: %v", gotHeaders)
	}
}

// TestProxyClient_ForwardRequest_BackendError verifies that a backend error
// response (5xx) is returned without an error (HTTP errors are not Go errors).
func TestProxyClient_ForwardRequest_BackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	origReq, _ := http.NewRequestWithContext(context.Background(), "GET", "/bucket/key", nil)
	origReq.URL.RawQuery = ""

	resp, err := pc.ForwardRequest(context.Background(), origReq, "GET", "bucket", "key", nil)
	if err != nil {
		t.Fatalf("ForwardRequest() unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("ForwardRequest() status = %d, want 500", resp.StatusCode)
	}
}

// TestProxyClient_ForwardRequest_NoBucket verifies that a request without a key
// builds the path as /bucket only.
func TestProxyClient_ForwardRequest_NoBucket(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	origReq, _ := http.NewRequestWithContext(context.Background(), "GET", "/", nil)
	origReq.URL.RawQuery = ""

	resp, err := pc.ForwardRequest(context.Background(), origReq, "GET", "my-bucket", "", nil)
	if err != nil {
		t.Fatalf("ForwardRequest() error: %v", err)
	}
	defer resp.Body.Close()

	if gotPath != "/my-bucket" {
		t.Errorf("expected path /my-bucket, got %q", gotPath)
	}
}

// TestProxyClient_ForwardRequest_WithBody verifies that a request body is
// forwarded to the backend.
func TestProxyClient_ForwardRequest_WithBody(t *testing.T) {
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	body := []byte("test body content")
	origReq, _ := http.NewRequestWithContext(context.Background(), "PUT", "/bucket/key", nil)
	origReq.URL.RawQuery = ""

	resp, err := pc.ForwardRequest(context.Background(), origReq, "PUT", "bucket", "key", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("ForwardRequest() error: %v", err)
	}
	defer resp.Body.Close()

	if string(gotBody) != string(body) {
		t.Errorf("ForwardRequest() body = %q, want %q", string(gotBody), string(body))
	}
}

// TestProxyClient_CopyObject_Success verifies CopyObject parses a successful
// CopyObjectResult XML response.
func TestProxyClient_CopyObject_Success(t *testing.T) {
	copyResult := `<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult>
  <ETag>"etag-abc123"</ETag>
  <LastModified>2024-01-15T10:30:00Z</LastModified>
</CopyObjectResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(copyResult))
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	etag, metadata, err := pc.CopyObject(context.Background(),
		"dst-bucket", "dst-key",
		"src-bucket", "src-key",
		nil, nil, nil)
	if err != nil {
		t.Fatalf("CopyObject() error: %v", err)
	}
	if etag != "etag-abc123" {
		t.Errorf("CopyObject() ETag = %q, want %q", etag, "etag-abc123")
	}
	if metadata["ETag"] != "etag-abc123" {
		t.Errorf("CopyObject() metadata[ETag] = %q, want %q", metadata["ETag"], "etag-abc123")
	}
}

// TestProxyClient_CopyObject_BackendError verifies CopyObject returns an error
// when the backend returns a 4xx/5xx status.
func TestProxyClient_CopyObject_BackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPreconditionFailed)
		w.Write([]byte("precondition failed"))
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	_, _, err := pc.CopyObject(context.Background(),
		"dst-bucket", "dst-key",
		"src-bucket", "src-key",
		nil, nil, nil)
	if err == nil {
		t.Fatal("CopyObject() expected error for 412 status, got nil")
	}
	if !strings.Contains(err.Error(), "412") {
		t.Errorf("CopyObject() error should mention 412, got: %v", err)
	}
}

// TestProxyClient_CopyObject_WithVersionID verifies that a source versionID is
// appended to the x-amz-copy-source header.
func TestProxyClient_CopyObject_WithVersionID(t *testing.T) {
	var gotCopySource string
	copyResult := `<CopyObjectResult><ETag>"abc"</ETag></CopyObjectResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCopySource = r.Header.Get("x-amz-copy-source")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(copyResult))
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	versionID := "version-v1"
	_, _, err := pc.CopyObject(context.Background(),
		"dst-bucket", "dst-key",
		"src-bucket", "src-key",
		&versionID, nil, nil)
	if err != nil {
		t.Fatalf("CopyObject() error: %v", err)
	}
	if !strings.Contains(gotCopySource, "version-v1") {
		t.Errorf("CopyObject() x-amz-copy-source = %q, expected to contain version-v1", gotCopySource)
	}
}

// TestProxyClient_UploadPartCopy_Success verifies UploadPartCopy parses a
// successful CopyPartResult XML response.
func TestProxyClient_UploadPartCopy_Success(t *testing.T) {
	copyResult := `<?xml version="1.0" encoding="UTF-8"?>
<CopyPartResult>
  <ETag>"etag-part1"</ETag>
  <LastModified>2024-01-15T10:30:00.000Z</LastModified>
</CopyPartResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify query params
		if r.URL.Query().Get("partNumber") != "1" {
			t.Errorf("UploadPartCopy missing partNumber=1 in query: %s", r.URL.RawQuery)
		}
		if r.URL.Query().Get("uploadId") != "upload-123" {
			t.Errorf("UploadPartCopy missing uploadId in query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(copyResult))
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	result, err := pc.UploadPartCopy(context.Background(),
		"dst-bucket", "dst-key", "upload-123", 1,
		"src-bucket", "src-key", nil, nil)
	if err != nil {
		t.Fatalf("UploadPartCopy() error: %v", err)
	}
	if result.ETag != "etag-part1" {
		t.Errorf("UploadPartCopy() ETag = %q, want %q", result.ETag, "etag-part1")
	}
}

// TestProxyClient_UploadPartCopy_WithRange verifies that a CopyPartRange is
// encoded as x-amz-copy-source-range.
func TestProxyClient_UploadPartCopy_WithRange(t *testing.T) {
	var gotRange string
	copyResult := `<CopyPartResult><ETag>"abc"</ETag></CopyPartResult>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("x-amz-copy-source-range")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(copyResult))
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	srcRange := &CopyPartRange{First: 0, Last: 1048575}
	result, err := pc.UploadPartCopy(context.Background(),
		"dst-bucket", "dst-key", "upload-123", 1,
		"src-bucket", "src-key", nil, srcRange)
	if err != nil {
		t.Fatalf("UploadPartCopy() error: %v", err)
	}
	if result == nil {
		t.Fatal("UploadPartCopy() returned nil result")
	}
	if gotRange != "bytes=0-1048575" {
		t.Errorf("UploadPartCopy() x-amz-copy-source-range = %q, want bytes=0-1048575", gotRange)
	}
}

// TestProxyClient_UploadPartCopy_BackendError verifies that a backend error
// returns an error from UploadPartCopy.
func TestProxyClient_UploadPartCopy_BackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	pc := newTestProxyClient(t, srv.URL)

	_, err := pc.UploadPartCopy(context.Background(),
		"dst-bucket", "dst-key", "upload-123", 1,
		"src-bucket", "src-key", nil, nil)
	if err == nil {
		t.Fatal("UploadPartCopy() expected error for 400 status, got nil")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("UploadPartCopy() error should mention 400, got: %v", err)
	}
}

// TestProxyClient_NotImplemented verifies that the stub methods return errors.
func TestProxyClient_NotImplemented(t *testing.T) {
	cfg := &config.BackendConfig{Endpoint: "http://localhost:9000"}
	pc, err := NewProxyClient(cfg)
	if err != nil {
		t.Fatalf("NewProxyClient() error: %v", err)
	}

	ctx := context.Background()

	if err := pc.PutObject(ctx, "b", "k", nil, nil, nil, "", nil, "", "", "", "", ""); err == nil {
		t.Error("PutObject() expected not-implemented error, got nil")
	}

	if _, _, err := pc.GetObject(ctx, "b", "k", nil, nil); err == nil {
		t.Error("GetObject() expected not-implemented error, got nil")
	}

	if err := pc.DeleteObject(ctx, "b", "k", nil); err == nil {
		t.Error("DeleteObject() expected not-implemented error, got nil")
	}

	if _, err := pc.HeadObject(ctx, "b", "k", nil); err == nil {
		t.Error("HeadObject() expected not-implemented error, got nil")
	}

	if _, err := pc.ListObjects(ctx, "b", "", ListOptions{}); err == nil {
		t.Error("ListObjects() expected not-implemented error, got nil")
	}

	if _, err := pc.CreateMultipartUpload(ctx, "b", "k", nil, "", "", "", "", ""); err == nil {
		t.Error("CreateMultipartUpload() expected not-implemented error, got nil")
	}

	if _, err := pc.UploadPart(ctx, "b", "k", "id", 1, nil, nil); err == nil {
		t.Error("UploadPart() expected not-implemented error, got nil")
	}

	if _, err := pc.CompleteMultipartUpload(ctx, "b", "k", "id", nil, nil); err == nil {
		t.Error("CompleteMultipartUpload() expected not-implemented error, got nil")
	}

	if err := pc.AbortMultipartUpload(ctx, "b", "k", "id"); err == nil {
		t.Error("AbortMultipartUpload() expected not-implemented error, got nil")
	}

	if _, err := pc.ListParts(ctx, "b", "k", "id"); err == nil {
		t.Error("ListParts() expected not-implemented error, got nil")
	}

	if _, _, err := pc.DeleteObjects(ctx, "b", nil); err == nil {
		t.Error("DeleteObjects() expected not-implemented error, got nil")
	}

	if err := pc.PutObjectRetention(ctx, "b", "k", nil, nil); err == nil {
		t.Error("PutObjectRetention() expected not-implemented error, got nil")
	}

	if _, err := pc.GetObjectRetention(ctx, "b", "k", nil); err == nil {
		t.Error("GetObjectRetention() expected not-implemented error, got nil")
	}

	if err := pc.PutObjectLegalHold(ctx, "b", "k", nil, ""); err == nil {
		t.Error("PutObjectLegalHold() expected not-implemented error, got nil")
	}

	if _, err := pc.GetObjectLegalHold(ctx, "b", "k", nil); err == nil {
		t.Error("GetObjectLegalHold() expected not-implemented error, got nil")
	}

	if err := pc.PutObjectLockConfiguration(ctx, "b", nil); err == nil {
		t.Error("PutObjectLockConfiguration() expected not-implemented error, got nil")
	}

	if _, err := pc.GetObjectLockConfiguration(ctx, "b"); err == nil {
		t.Error("GetObjectLockConfiguration() expected not-implemented error, got nil")
	}
}

// TestNormalizeEndpoint_Table verifies the normalizeEndpoint helper.
func TestNormalizeEndpoint_Table(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://localhost:9000", "http://localhost:9000"},
		{"https://s3.amazonaws.com", "https://s3.amazonaws.com"},
		{"http://localhost:9000/", "http://localhost:9000"},
		{"  http://localhost:9000  ", "http://localhost:9000"},
		{"localhost:9000", "https://localhost:9000"},
	}

	for _, tc := range tests {
		got := normalizeEndpoint(tc.input)
		if got != tc.want {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestValidateEndpoint_Table verifies the validateEndpoint helper.
func TestValidateEndpoint_Table(t *testing.T) {
	tests := []struct {
		endpoint string
		wantErr  bool
	}{
		{"http://localhost:9000", false},
		{"https://s3.amazonaws.com", false},
		{"ftp://invalid", true},
		{"http://", true},
		{"not-a-url", true},
	}

	for _, tc := range tests {
		err := validateEndpoint(tc.endpoint)
		if (err != nil) != tc.wantErr {
			t.Errorf("validateEndpoint(%q) error = %v, wantErr %v", tc.endpoint, err, tc.wantErr)
		}
	}
}

// helper for creating a fake XML response with a specific error code
func xmlError(code, message string) string {
	return fmt.Sprintf(`<Error><Code>%s</Code><Message>%s</Message></Error>`, code, message)
}

// xmlMarshalTest verifies that the CopyObjectResult XML type is parses correctly.
// This is a white-box test of the XML struct used inside CopyObject.
func TestXMLCopyObjectResult_Parse(t *testing.T) {
	xmlBody := `<?xml version="1.0" encoding="UTF-8"?>
<CopyObjectResult>
  <ETag>"etag-value"</ETag>
  <LastModified>2024-01-15T10:30:00Z</LastModified>
</CopyObjectResult>`

	type CopyObjectResultXML struct {
		XMLName      xml.Name `xml:"CopyObjectResult"`
		ETag         string   `xml:"ETag"`
		LastModified string   `xml:"LastModified"`
	}

	var result CopyObjectResultXML
	if err := xml.NewDecoder(strings.NewReader(xmlBody)).Decode(&result); err != nil {
		t.Fatalf("XML parse error: %v", err)
	}
	if result.ETag != `"etag-value"` {
		t.Errorf("ETag = %q, want %q", result.ETag, `"etag-value"`)
	}
}
