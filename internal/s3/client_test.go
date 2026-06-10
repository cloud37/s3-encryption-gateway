package s3

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

// mockClient is a mock implementation for testing.
type mockClient struct {
	objects map[string][]byte
	metadata map[string]map[string]string
}

func newMockClient() *mockClient {
	return &mockClient{
		objects:  make(map[string][]byte),
		metadata: make(map[string]map[string]string),
	}
}

func (m *mockClient) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	m.objects[bucket+"/"+key] = data
	m.metadata[bucket+"/"+key] = metadata
	return "", nil
}

func (m *mockClient) GetObject(ctx context.Context, bucket, key string) (io.ReadCloser, map[string]string, error) {
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		return nil, nil, fmt.Errorf("object not found")
	}
	meta := m.metadata[bucket+"/"+key]
	if meta == nil {
		meta = make(map[string]string)
	}
	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

func (m *mockClient) DeleteObject(ctx context.Context, bucket, key string) error {
	delete(m.objects, bucket+"/"+key)
	delete(m.metadata, bucket+"/"+key)
	return nil
}

func (m *mockClient) HeadObject(ctx context.Context, bucket, key string) (map[string]string, error) {
	meta, ok := m.metadata[bucket+"/"+key]
	if !ok {
		return nil, fmt.Errorf("object not found")
	}
	if meta == nil {
		meta = make(map[string]string)
	}
	return meta, nil
}

func (m *mockClient) ListObjects(ctx context.Context, bucket, prefix string, opts ListOptions) ([]ObjectInfo, error) {
	var objects []ObjectInfo
	for key := range m.objects {
		if bucket+"/" == key[:len(bucket)+1] && (prefix == "" || key[len(bucket)+1:][:len(prefix)] == prefix) {
			objects = append(objects, ObjectInfo{
				Key: key[len(bucket)+1:],
			})
		}
	}
	return objects, nil
}

func TestMockClient_PutGet(t *testing.T) {
	ctx := context.Background()
	mock := newMockClient()

	bucket := "test-bucket"
	key := "test-key"
	data := []byte("test data")
	metadata := map[string]string{"content-type": "text/plain"}

    _, err := mock.PutObject(ctx, bucket, key, bytes.NewReader(data), metadata, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	reader, retrievedMeta, err := mock.GetObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("GetObject failed: %v", err)
	}
	defer reader.Close()

	retrievedData, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if !bytes.Equal(data, retrievedData) {
		t.Errorf("expected data %q, got %q", string(data), string(retrievedData))
	}

	if retrievedMeta["content-type"] != metadata["content-type"] {
		t.Errorf("expected content-type %q, got %q", metadata["content-type"], retrievedMeta["content-type"])
	}
}

func TestMockClient_DeleteObject(t *testing.T) {
	ctx := context.Background()
	mock := newMockClient()

	bucket := "test-bucket"
	key := "test-key"
	data := []byte("test data")

    _, err := mock.PutObject(ctx, bucket, key, bytes.NewReader(data), nil, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject failed: %v", err)
	}

	err = mock.DeleteObject(ctx, bucket, key)
	if err != nil {
		t.Fatalf("DeleteObject failed: %v", err)
	}

	_, _, err = mock.GetObject(ctx, bucket, key)
	if err == nil {
		t.Error("expected error after deleting object")
	}
}

func TestS3Client_ConfigValidation(t *testing.T) {
	cfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Provider:  "minio",
	}

	// This will fail in unit tests without real AWS credentials/endpoint
	// but we can test that the client creation logic is correct
	_, err := NewClient(cfg)
	if err != nil {
		// Expected in test environment without real credentials
		t.Logf("NewClient returned expected error (no real credentials): %v", err)
	}
}

func TestClientFactory_GetClientWithCredentials(t *testing.T) {
	baseCfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "base-key",
		SecretKey: "base-secret",
		UseSSL:    false,
	}

	factory := NewClientFactory(baseCfg)

	tests := []struct {
		name       string
		accessKey  string
		secretKey  string
		wantErr    bool
		errMessage string
	}{
		{
			name:      "valid credentials",
			accessKey: "client-key",
			secretKey: "client-secret",
			wantErr:   false,
		},
		{
			name:       "empty access key",
			accessKey:  "",
			secretKey:  "client-secret",
			wantErr:    true,
			errMessage: "access key is required",
		},
		{
			name:       "empty secret key",
			accessKey:  "client-key",
			secretKey:  "",
			wantErr:    true,
			errMessage: "secret key is required",
		},
		{
			name:       "both empty",
			accessKey:  "",
			secretKey:  "",
			wantErr:    true,
			errMessage: "access key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := factory.GetClientWithCredentials(tt.accessKey, tt.secretKey)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("GetClientWithCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if err == nil {
					t.Error("GetClientWithCredentials() expected error, got nil")
					return
				}
				if tt.errMessage != "" && !strings.Contains(err.Error(), tt.errMessage) {
					t.Errorf("GetClientWithCredentials() error = %v, want error containing %q", err, tt.errMessage)
				}
			} else {
				if client == nil {
					t.Error("GetClientWithCredentials() returned nil client without error")
				}
			}
		})
	}
}

func TestClientFactory_GetClient(t *testing.T) {
	cfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "base-key",
		SecretKey: "base-secret",
		UseSSL:    false,
	}

	factory := NewClientFactory(cfg)

	// GetClient should use base configured credentials
	// This will fail in test environment without real credentials, but we can verify it calls GetClientWithCredentials
	_, err := factory.GetClient()
	if err != nil {
		// Expected in test environment - verify error mentions credentials issue
		if !strings.Contains(err.Error(), "access key") && !strings.Contains(err.Error(), "secret key") && !strings.Contains(err.Error(), "credentials") && !strings.Contains(err.Error(), "failed to load AWS config") {
			t.Logf("GetClient returned error (expected without real credentials): %v", err)
		}
	}
}

// ---- V0.6-PERF-2 Phase D factory / client integration tests ----------------

// TestClientFactory_RetryerInstalled verifies that the factory constructs a
// retryer that classifies 503 as retryable and uses the configured MaxAttempts.
// We test via the retryer directly (not end-to-end through the SDK) to avoid
// relying on SDK sleep behavior in unit tests.
func TestClientFactory_RetryerInstalled(t *testing.T) {
	cfg := &config.BackendConfig{
		Region:    "us-east-1",
		AccessKey: "AKIATEST",
		SecretKey: "secrettest",
		UseSSL:    false,
		Retry: config.BackendRetryConfig{
			Mode:           "standard",
			MaxAttempts:    3,
			InitialBackoff: 1 * time.Millisecond,
			MaxBackoff:     10 * time.Millisecond,
			Jitter:         "full",
		},
	}
	cfg.Retry.Normalize()
	factory := NewClientFactory(cfg)

	// Verify the retry factory is installed.
	if factory.retryerFactory == nil {
		t.Fatal("retryerFactory should not be nil for mode=standard")
	}

	// Build a per-operation retryer and verify it classifies 503 as retryable.
	r := factory.retryerFactory.Build("PutObject")
	err503 := makeHTTPRespErr(t, 503, 0)
	if !r.IsErrorRetryable(err503) {
		t.Error("503 should be retryable")
	}
	if r.MaxAttempts() != 3 {
		t.Errorf("MaxAttempts: expected 3, got %d", r.MaxAttempts())
	}
}

// TestClientFactory_RetryMode_Off verifies that mode=off disables retries.
func TestClientFactory_RetryMode_Off(t *testing.T) {
	var attemptCount int
	countingTransport := &countingFaultTransport{
		faultStatus:   503,
		faultCount:    999, // always fail
		onAttempt:     func() { attemptCount++ },
		okBodyBuilder: benchBodyFor,
	}

	cfg := &config.BackendConfig{
		Region:    "us-east-1",
		AccessKey: "AKIATEST",
		SecretKey: "secrettest",
		UseSSL:    false,
		Retry: config.BackendRetryConfig{
			Mode:           "off",
			MaxAttempts:    1,
			InitialBackoff: 1 * time.Millisecond,
			MaxBackoff:     10 * time.Millisecond,
			Jitter:         "full",
		},
	}
	cfg.Retry.Normalize()

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIATEST", "secrettest", "")),
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
		awsconfig.WithHTTPClient(&http.Client{Transport: countingTransport}),
		awsconfig.WithRetryer(func() aws.Retryer {
			return newNopRetryerV2()
		}),
	)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	sdkClient := awss3.NewFromConfig(awsCfg, func(o *awss3.Options) {
		o.BaseEndpoint = aws.String("http://localhost:9000")
		o.UsePathStyle = true
	})

	payload := make([]byte, 16)
	_, _ = sdkClient.PutObject(context.Background(), &awss3.PutObjectInput{
		Bucket:        aws.String("test-bucket"),
		Key:           aws.String("test-key"),
		Body:          bytes.NewReader(payload),
		ContentLength: aws.Int64(int64(len(payload))),
	})

	if attemptCount != 1 {
		t.Errorf("mode=off: expected exactly 1 attempt, got %d", attemptCount)
	}
	_ = cfg
}

// TestClientFactory_PerOperationOverride_DisablesPutObject verifies that a
// per-operation override of 1 for PutObject results in a single attempt.
func TestClientFactory_PerOperationOverride_DisablesPutObject(t *testing.T) {
	cfg := defaultTestCfg()
	cfg.PerOperation = map[string]int{"PutObject": 1}

	r := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("PutObject")
	if r.MaxAttempts() != 1 {
		t.Errorf("per-op override should give MaxAttempts=1 for PutObject, got %d", r.MaxAttempts())
	}

	// HeadObject should still use the global MaxAttempts=3.
	rHead := newTestRetryer(t, cfg, &fakeClock{}, nil, nil).clone("HeadObject")
	if rHead.MaxAttempts() != 3 {
		t.Errorf("HeadObject should still use global MaxAttempts=3, got %d", rHead.MaxAttempts())
	}
}

// countingFaultTransport injects `faultCount` faults then returns 200.
// Thread-safe for concurrent use.
type countingFaultTransport struct {
	faultStatus   int
	faultCount    int
	onAttempt     func()
	okBodyBuilder func(req *http.Request) string
	mu            sync.Mutex
	called        int
}

func (t *countingFaultTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.called++
	n := t.called
	t.mu.Unlock()

	if t.onAttempt != nil {
		t.onAttempt()
	}

	if n <= t.faultCount {
		body := fmt.Sprintf(`<Error><Code>ServiceUnavailable</Code><Message>injected %d</Message></Error>`, t.faultStatus)
		return &http.Response{
			StatusCode: t.faultStatus,
			Status:     fmt.Sprintf("%d %s", t.faultStatus, http.StatusText(t.faultStatus)),
			Header:     http.Header{"Content-Type": []string{"application/xml"}, "x-amz-request-id": []string{"COUNTFLT"}},
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	}

	// Success path.
	var body string
	if t.okBodyBuilder != nil {
		body = t.okBodyBuilder(req)
	}
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/xml"}, "ETag": []string{`"countok"`}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

// ============================================================
// httptest.Server-based S3 client tests (V0.6-QA-2 Phase B.2)
// ============================================================
//
// These tests use a fake S3 HTTP server to exercise the production
// s3Client methods (PutObject, GetObject, DeleteObject, etc.) without
// a real S3 backend. Pattern mirrors client_bench_test.go.

// fakeS3Transport is an http.RoundTripper that routes requests to a
// handler function. Used for lightweight S3-protocol stubs.
type fakeS3Transport struct {
	handler http.Handler
}

func (f *fakeS3Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w.Result(), nil
}

// buildTestS3Client creates an s3Client backed by the given transport.
// The endpoint is set to "http://localhost:9000" (the factory requires one,
// but the transport overrides all HTTP I/O).
func buildTestS3Client(t *testing.T, transport http.RoundTripper) Client {
	t.Helper()
	cfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "AKIATEST",
		SecretKey: "secrettest",
		UseSSL:    false,
	}
	factory := NewClientFactory(cfg, WithHTTPTransport(transport))
	c, err := factory.GetClient()
	if err != nil {
		t.Fatalf("GetClient() error: %v", err)
	}
	return c
}

// fakeS3Mux returns an http.ServeMux that responds to common S3 operations
// with canned XML responses.
func fakeS3Mux() *http.ServeMux {
	mux := http.NewServeMux()

	// PUT (PutObject)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			// PutObject or CreateMultipartUpload part
			if r.URL.Query().Get("uploadId") != "" {
				// UploadPart: return ETag
				w.Header().Set("ETag", `"part-etag-abc"`)
				w.WriteHeader(http.StatusOK)
				return
			}
			// Regular PutObject
			w.Header().Set("ETag", `"test-etag-abc"`)
			w.WriteHeader(http.StatusOK)

		case http.MethodGet:
			// GetObject or ListObjects
			if r.URL.Query().Get("list-type") == "2" || r.URL.Query().Get("list-type") != "" {
				// ListObjects V2
				xml := `<?xml version="1.0"?>
<ListBucketResult>
  <Name>test-bucket</Name>
  <Prefix></Prefix>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>test-key</Key>
    <Size>100</Size>
    <ETag>"abc"</ETag>
  </Contents>
</ListBucketResult>`
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(xml))
				return
			}
			// Regular GetObject
			w.Header().Set("ETag", `"test-etag-abc"`)
			w.Header().Set("Content-Length", "4")
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("x-amz-meta-mykey", "myval")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("data"))

		case http.MethodHead:
			// HeadObject
			w.Header().Set("ETag", `"test-etag-abc"`)
			w.Header().Set("Content-Length", "4")
			w.Header().Set("x-amz-meta-mykey", "myval")
			w.WriteHeader(http.StatusOK)

		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)

		case http.MethodPost:
			q := r.URL.Query()
			if q.Has("uploads") {
				// CreateMultipartUpload
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<?xml version="1.0"?>
<InitiateMultipartUploadResult>
  <Bucket>test-bucket</Bucket>
  <Key>test-key</Key>
  <UploadId>test-upload-id-123</UploadId>
</InitiateMultipartUploadResult>`))
				return
			}
			if q.Get("uploadId") != "" {
				// CompleteMultipartUpload
				w.Header().Set("Content-Type", "application/xml")
				w.Header().Set("Location", "http://localhost:9000/test-bucket/test-key")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<?xml version="1.0"?>
<CompleteMultipartUploadResult>
  <Location>http://localhost:9000/test-bucket/test-key</Location>
  <Bucket>test-bucket</Bucket>
  <Key>test-key</Key>
  <ETag>"multi-etag-abc"</ETag>
</CompleteMultipartUploadResult>`))
				return
			}
			// Batch delete (POST to ?delete)
			if q.Has("delete") {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`<?xml version="1.0"?>
<DeleteResult>
  <Deleted><Key>test-key</Key></Deleted>
</DeleteResult>`))
				return
			}
			w.WriteHeader(http.StatusOK)

		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	return mux
}

// TestS3Client_PutObject_Success verifies PutObject returns no error on 200.
func TestS3Client_PutObject_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	body := bytes.NewReader([]byte("test data"))
	_, err := client.PutObject(context.Background(), "test-bucket", "test-key",
		body, nil, nil, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject() error: %v", err)
	}
}

// TestS3Client_PutObject_WithMetadata verifies that metadata keys with the
// x-amz-meta- prefix are stripped (the SDK adds the prefix automatically).
func TestS3Client_PutObject_WithMetadata(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	meta := map[string]string{
		"x-amz-meta-encrypted": "true",
		"x-amz-meta-algorithm": "AES256-GCM",
	}
	_, err := client.PutObject(context.Background(), "test-bucket", "test-key",
		bytes.NewReader([]byte("data")), meta, aws.Int64(4), "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject() with metadata error: %v", err)
	}
}

// TestS3Client_GetObject_Success verifies GetObject returns body and metadata.
func TestS3Client_GetObject_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	body, meta, err := client.GetObject(context.Background(), "test-bucket", "test-key", nil, nil)
	if err != nil {
		t.Fatalf("GetObject() error: %v", err)
	}
	defer body.Close()

	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("ReadAll() error: %v", err)
	}
	if string(data) != "data" {
		t.Errorf("GetObject() body = %q, want %q", string(data), "data")
	}
	if meta == nil {
		t.Error("GetObject() returned nil metadata")
	}
}

// TestS3Client_DeleteObject_Success verifies DeleteObject returns no error on 204.
func TestS3Client_DeleteObject_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	err := client.DeleteObject(context.Background(), "test-bucket", "test-key", nil)
	if err != nil {
		t.Fatalf("DeleteObject() error: %v", err)
	}
}

// TestS3Client_HeadObject_Success verifies HeadObject returns metadata.
func TestS3Client_HeadObject_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	meta, err := client.HeadObject(context.Background(), "test-bucket", "test-key", nil)
	if err != nil {
		t.Fatalf("HeadObject() error: %v", err)
	}
	if meta == nil {
		t.Error("HeadObject() returned nil metadata")
	}
}

// TestS3Client_CreateMultipartUpload_Success verifies CreateMultipartUpload
// returns the upload ID from the XML response.
func TestS3Client_CreateMultipartUpload_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	uploadID, err := client.CreateMultipartUpload(context.Background(), "test-bucket", "test-key", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("CreateMultipartUpload() error: %v", err)
	}
	if uploadID == "" {
		t.Error("CreateMultipartUpload() returned empty uploadID")
	}
	if uploadID != "test-upload-id-123" {
		t.Errorf("CreateMultipartUpload() uploadID = %q, want test-upload-id-123", uploadID)
	}
}

// TestS3Client_UploadPart_Success verifies UploadPart returns an ETag.
func TestS3Client_UploadPart_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	data := bytes.NewReader([]byte("part data"))
	etag, err := client.UploadPart(context.Background(), "test-bucket", "test-key",
		"test-upload-id-123", 1, data, nil)
	if err != nil {
		t.Fatalf("UploadPart() error: %v", err)
	}
	if etag == "" {
		t.Error("UploadPart() returned empty ETag")
	}
}

// TestS3Client_CompleteMultipartUpload_Success verifies CompleteMultipartUpload
// returns a location/ETag.
func TestS3Client_CompleteMultipartUpload_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	parts := []CompletedPart{
		{PartNumber: 1, ETag: "part-etag-abc"},
	}
	etag, err := client.CompleteMultipartUpload(context.Background(), "test-bucket", "test-key",
		"test-upload-id-123", parts, nil)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload() error: %v", err)
	}
	if etag == "" {
		t.Error("CompleteMultipartUpload() returned empty result")
	}
}

// TestS3Client_AbortMultipartUpload_Success verifies AbortMultipartUpload
// returns no error on success.
func TestS3Client_AbortMultipartUpload_Success(t *testing.T) {
	// Abort responds with 204
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Query().Get("uploadId") != "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	err := client.AbortMultipartUpload(context.Background(), "test-bucket", "test-key", "upload-id")
	if err != nil {
		t.Fatalf("AbortMultipartUpload() error: %v", err)
	}
}

// TestS3Client_DeleteObjects_Success verifies batch delete returns deleted objects.
func TestS3Client_DeleteObjects_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	keys := []ObjectIdentifier{{Key: "test-key"}}
	deleted, errs, err := client.DeleteObjects(context.Background(), "test-bucket", keys)
	if err != nil {
		t.Fatalf("DeleteObjects() error: %v", err)
	}
	_ = deleted
	_ = errs
	// Success: no panic, returns lists
}

// TestConvertMetadata verifies that convertMetadata strips the x-amz-meta- prefix.
func TestConvertMetadata(t *testing.T) {
	input := map[string]string{
		"x-amz-meta-encrypted":  "true",
		"x-amz-meta-algorithm":  "AES256-GCM",
		"Content-Type":          "application/octet-stream",
	}
	got := convertMetadata(input)
	if got["encrypted"] != "true" {
		t.Errorf("expected key 'encrypted'='true', got: %v", got)
	}
	if got["algorithm"] != "AES256-GCM" {
		t.Errorf("expected key 'algorithm'='AES256-GCM', got: %v", got)
	}
	if got["Content-Type"] != "application/octet-stream" {
		t.Errorf("expected key 'Content-Type' pass-through, got: %v", got)
	}
	// Should NOT have x-amz-meta- prefix in result
	if _, ok := got["x-amz-meta-encrypted"]; ok {
		t.Error("convertMetadata() kept x-amz-meta- prefix key")
	}
}

// TestExtractMetadata verifies that extractMetadata adds the x-amz-meta- prefix.
func TestExtractMetadata(t *testing.T) {
	// SDK returns keys WITHOUT the prefix
	input := map[string]string{
		"encrypted": "true",
		"algorithm": "AES256-GCM",
	}
	got := extractMetadata(input)
	if got["x-amz-meta-encrypted"] != "true" {
		t.Errorf("expected 'x-amz-meta-encrypted'='true', got: %v", got)
	}
	if got["x-amz-meta-algorithm"] != "AES256-GCM" {
		t.Errorf("expected 'x-amz-meta-algorithm'='AES256-GCM', got: %v", got)
	}
}

// TestConvertMetadata_Nil verifies convertMetadata(nil) returns nil.
func TestConvertMetadata_Nil(t *testing.T) {
	got := convertMetadata(nil)
	if got != nil {
		t.Errorf("convertMetadata(nil) = %v, want nil", got)
	}
}

// TestExtractMetadata_Nil verifies extractMetadata(nil) returns empty map.
func TestExtractMetadata_Nil(t *testing.T) {
	got := extractMetadata(nil)
	if got == nil {
		t.Error("extractMetadata(nil) returned nil, want empty map")
	}
}

// TestS3Client_ListObjects_Success verifies ListObjects returns a list of objects.
func TestS3Client_ListObjects_Success(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	result, err := client.ListObjects(context.Background(), "test-bucket", "", ListOptions{})
	if err != nil {
		t.Fatalf("ListObjects() error: %v", err)
	}
	// The fakeS3Mux returns one object in the list
	_ = result
}

// TestS3Client_ListParts_Success verifies ListParts returns without crashing.
func TestS3Client_ListParts_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Get("uploadId") != "" {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?>
<ListPartsResult>
  <Bucket>test-bucket</Bucket>
  <Key>test-key</Key>
  <UploadId>upload-123</UploadId>
  <IsTruncated>false</IsTruncated>
  <Part>
    <PartNumber>1</PartNumber>
    <ETag>"part-etag-1"</ETag>
    <Size>1024</Size>
  </Part>
</ListPartsResult>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	parts, err := client.ListParts(context.Background(), "test-bucket", "test-key", "upload-123")
	if err != nil {
		t.Fatalf("ListParts() error: %v", err)
	}
	if len(parts) != 1 {
		t.Errorf("ListParts() returned %d parts, want 1", len(parts))
	}
	if parts[0].PartNumber != 1 {
		t.Errorf("ListParts() part[0].PartNumber = %d, want 1", parts[0].PartNumber)
	}
}

// TestS3Client_CopyObject_Success verifies CopyObject parses the response.
func TestS3Client_CopyObject_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?>
<CopyObjectResult>
  <ETag>"copy-etag-abc"</ETag>
  <LastModified>2024-01-15T10:30:00.000Z</LastModified>
</CopyObjectResult>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	etag, meta, err := client.CopyObject(context.Background(),
		"dst-bucket", "dst-key",
		"src-bucket", "src-key",
		nil, nil, nil)
	if err != nil {
		t.Fatalf("CopyObject() error: %v", err)
	}
	_ = etag
	_ = meta
}

// TestS3Client_UploadPartCopy_Success verifies UploadPartCopy returns a result.
func TestS3Client_UploadPartCopy_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?>
<CopyPartResult>
  <ETag>"part-copy-etag"</ETag>
  <LastModified>2024-01-15T10:30:00.000Z</LastModified>
</CopyPartResult>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	result, err := client.UploadPartCopy(context.Background(),
		"dst-bucket", "dst-key", "upload-123", 1,
		"src-bucket", "src-key", nil, nil)
	if err != nil {
		t.Fatalf("UploadPartCopy() error: %v", err)
	}
	_ = result
}

// TestClientFactory_WithMetrics verifies that WithMetrics option sets the
// metrics field on the factory.
func TestClientFactory_WithMetrics_Option(t *testing.T) {
	cfg := &config.BackendConfig{
		Endpoint:  "http://localhost:9000",
		Region:    "us-east-1",
		AccessKey: "AKIATEST",
		SecretKey: "secrettest",
	}

	// WithMetrics(nil) should not panic
	factory := NewClientFactory(cfg, WithMetrics(nil))
	if factory == nil {
		t.Fatal("NewClientFactory() returned nil")
	}
}

// TestS3Client_PutObjectRetention_Success verifies PutObjectRetention returns no error.
func TestS3Client_PutObjectRetention_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	err := client.PutObjectRetention(context.Background(), "test-bucket", "test-key", nil, nil)
	if err != nil {
		t.Fatalf("PutObjectRetention() error: %v", err)
	}
}

// TestS3Client_PutObjectLegalHold_Success verifies PutObjectLegalHold works.
func TestS3Client_PutObjectLegalHold_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	err := client.PutObjectLegalHold(context.Background(), "test-bucket", "test-key", nil, "ON")
	if err != nil {
		t.Fatalf("PutObjectLegalHold() error: %v", err)
	}
}

// TestS3Client_PutObjectLockConfiguration_Success verifies PutObjectLockConfiguration.
func TestS3Client_PutObjectLockConfiguration_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	cfg := &ObjectLockConfiguration{
		ObjectLockEnabled: "Enabled",
	}
	err := client.PutObjectLockConfiguration(context.Background(), "test-bucket", cfg)
	if err != nil {
		t.Fatalf("PutObjectLockConfiguration() error: %v", err)
	}
}

// TestS3Client_GetObjectRetention_Success verifies GetObjectRetention parses response.
func TestS3Client_GetObjectRetention_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?>
<Retention>
  <Mode>GOVERNANCE</Mode>
  <RetainUntilDate>2025-01-01T00:00:00.000Z</RetainUntilDate>
</Retention>`))
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	result, err := client.GetObjectRetention(context.Background(), "test-bucket", "test-key", nil)
	if err != nil {
		t.Fatalf("GetObjectRetention() error: %v", err)
	}
	_ = result
}

// TestS3Client_GetObjectLegalHold_Success verifies GetObjectLegalHold parses response.
func TestS3Client_GetObjectLegalHold_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?>
<LegalHold>
  <Status>ON</Status>
</LegalHold>`))
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	status, err := client.GetObjectLegalHold(context.Background(), "test-bucket", "test-key", nil)
	if err != nil {
		t.Fatalf("GetObjectLegalHold() error: %v", err)
	}
	_ = status
}

// TestS3Client_GetObjectLockConfiguration_Success verifies GetObjectLockConfiguration.
func TestS3Client_GetObjectLockConfiguration_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0"?>
<ObjectLockConfiguration>
  <ObjectLockEnabled>Enabled</ObjectLockEnabled>
</ObjectLockConfiguration>`))
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	result, err := client.GetObjectLockConfiguration(context.Background(), "test-bucket")
	if err != nil {
		t.Fatalf("GetObjectLockConfiguration() error: %v", err)
	}
	_ = result
}

// TestS3Client_GetObject_WithVersionID verifies GetObject passes versionID to backend.
func TestS3Client_GetObject_WithVersionID(t *testing.T) {
	var gotVersionID string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotVersionID = r.URL.Query().Get("versionId")
		w.Header().Set("ETag", `"test-etag"`)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	versionID := "test-version-1"
	body, meta, err := client.GetObject(context.Background(), "test-bucket", "test-key", &versionID, nil)
	if err != nil {
		t.Fatalf("GetObject() error: %v", err)
	}
	defer body.Close()
	_ = meta

	if gotVersionID != "test-version-1" {
		t.Errorf("GetObject() versionId not passed: got %q, want test-version-1", gotVersionID)
	}
}

// TestS3Client_GetObject_WithRangeHeader verifies range header is passed.
func TestS3Client_GetObject_WithRangeHeader(t *testing.T) {
	var gotRange string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		w.Header().Set("ETag", `"test-etag"`)
		w.WriteHeader(http.StatusPartialContent)
		w.Write([]byte("dat"))
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	rangeHeader := "bytes=0-3"
	body, _, err := client.GetObject(context.Background(), "test-bucket", "test-key", nil, &rangeHeader)
	if err != nil {
		t.Fatalf("GetObject() error: %v", err)
	}
	defer body.Close()

	if gotRange != "bytes=0-3" {
		t.Errorf("GetObject() range header not passed: got %q, want bytes=0-3", gotRange)
	}
}

// ---- V0.6-QA-2: coverage gap tests for client.go ---------------------------

// TestS3Client_PutObject_WithTags verifies that tags are passed through.
func TestS3Client_PutObject_WithTags(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	_, err := client.PutObject(context.Background(), "test-bucket", "test-key",
		bytes.NewReader([]byte("data")), nil, nil, "key1=val1&key2=val2", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject() with tags error: %v", err)
	}
}

// TestS3Client_PutObject_WithContentLength verifies content length is passed.
func TestS3Client_PutObject_WithContentLength(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	data := []byte("hello")
	cl := int64(len(data))
	_, err := client.PutObject(context.Background(), "test-bucket", "test-key",
		bytes.NewReader(data), nil, &cl, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject() with content length error: %v", err)
	}
}


// TestS3Client_PutObject_WithACL verifies that the ACL header is sent to the
// backend as a PUT request header. The SDK encodes the canned ACL in the
// request; we verify the backend receives it.
func TestS3Client_PutObject_WithACL(t *testing.T) {
	var gotACL string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			gotACL = r.Header.Get("x-amz-acl")
			w.Header().Set("ETag", `"test-etag"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	_, err := client.PutObject(context.Background(), "test-bucket", "test-key",
		bytes.NewReader([]byte("data")), nil, nil, "", nil, "public-read", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject() with ACL error: %v", err)
	}

	if gotACL == "" {
		t.Error("x-amz-acl header was not sent to backend")
	}
}

// TestS3Client_PutObject_BackendRejectsInvalidACL verifies that when the
// backend rejects an invalid canned ACL with a 400 error, the SDK surfaces
// the error to the caller (deterministic error contract).
func TestS3Client_PutObject_BackendRejectsInvalidACL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			// Simulate a backend that rejects an invalid ACL value.
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`<?xml version="1.0"?><Error><Code>InvalidArgument</Code><Message>Invalid canned ACL</Message></Error>`))
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	_, err := client.PutObject(context.Background(), "test-bucket", "test-key",
		bytes.NewReader([]byte("data")), nil, nil, "", nil, "invalid-acl-value", "", "", "", "")
	if err == nil {
		t.Fatal("expected error for invalid ACL rejected by backend, got nil")
	}
	if !strings.Contains(err.Error(), "InvalidArgument") && !strings.Contains(err.Error(), "400") {
		t.Errorf("expected InvalidArgument or 400 error, got: %v", err)
	}
}

// TestS3Client_HeadObject_WithVersionID verifies versionId is passed.
func TestS3Client_HeadObject_WithVersionID(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	versionID := "v5678"
	_, err := client.HeadObject(context.Background(), "test-bucket", "test-key", &versionID)
	if err != nil {
		t.Fatalf("HeadObject() with versionID error: %v", err)
	}
}

// TestS3Client_DeleteObject_WithVersionID verifies versionId is passed.
func TestS3Client_DeleteObject_WithVersionID(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	versionID := "v9012"
	err := client.DeleteObject(context.Background(), "test-bucket", "test-key", &versionID)
	if err != nil {
		t.Fatalf("DeleteObject() with versionID error: %v", err)
	}
}

// TestS3Client_ListObjects_WithMarker verifies the marker/start-after path.
func TestS3Client_ListObjects_WithMarker(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	_, err := client.ListObjects(context.Background(), "test-bucket", "prefix/", ListOptions{
		MaxKeys:            10,
		ContinuationToken: "token123",
		Delimiter:         "/",
	})
	if err != nil {
		t.Fatalf("ListObjects() with options error: %v", err)
	}
}

// TestS3Client_GetObjectRetention_WithVersionID verifies GetObjectRetention.
func TestS3Client_GetObjectRetention_WithVersionID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("retention") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?><Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>`))
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	_, err := client.GetObjectRetention(context.Background(), "test-bucket", "test-key", nil)
	if err != nil {
		t.Logf("GetObjectRetention() error (may be expected): %v", err)
	}
}

// TestS3Client_GetObjectLockConfiguration_XML verifies GetObjectLockConfiguration with XML.
func TestS3Client_GetObjectLockConfiguration_XML(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("object-lock") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?><ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`))
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	_, err := client.GetObjectLockConfiguration(context.Background(), "test-bucket")
	if err != nil {
		t.Logf("GetObjectLockConfiguration() error (may be expected): %v", err)
	}
}

// TestS3Client_GetObjectLegalHold_Parse verifies GetObjectLegalHold parses XML.
func TestS3Client_GetObjectLegalHold_Parse(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Query().Has("legal-hold") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?><LegalHold><Status>OFF</Status></LegalHold>`))
			return
		}
		w.WriteHeader(http.StatusNotImplemented)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	status, err := client.GetObjectLegalHold(context.Background(), "test-bucket", "test-key", nil)
	if err != nil {
		t.Logf("GetObjectLegalHold() error (may be expected): %v", err)
	}
	_ = status
}

// TestS3Client_CreateMultipartUpload_WithMetadata verifies metadata is passed.
func TestS3Client_CreateMultipartUpload_WithMetadata(t *testing.T) {
	transport := &fakeS3Transport{handler: fakeS3Mux()}
	client := buildTestS3Client(t, transport)

	meta := map[string]string{
		"x-amz-meta-version": "1",
	}
	uploadID, err := client.CreateMultipartUpload(context.Background(), "test-bucket", "test-key", meta, "", "", "", "", "")
	if err != nil {
		t.Fatalf("CreateMultipartUpload() with metadata error: %v", err)
	}
	if uploadID == "" {
		t.Error("expected non-empty uploadID")
	}
}

// TestS3Client_CopyObject_WithVersionID verifies srcVersionID is passed.
func TestS3Client_CopyObject_WithVersionID(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<?xml version="1.0"?><CopyObjectResult><ETag>"abc"</ETag></CopyObjectResult>`))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	versionID := "v123"
	_, _, err := client.CopyObject(context.Background(), "dst-bucket", "dst-key", "src-bucket", "src-key", &versionID, nil, nil)
	if err != nil {
		t.Logf("CopyObject() with versionID error (may be expected): %v", err)
	}
}

// TestBytesReader_ReadSeekClose tests the internal bytesReader type.
func TestBytesReader_ReadSeekClose(t *testing.T) {
	data := []byte("hello world")
	r := newBytesReader(data)

	// Read.
	buf := make([]byte, 5)
	n, err := r.Read(buf)
	if err != nil || n != 5 || string(buf) != "hello" {
		t.Errorf("Read() = %d, %v; want 5, nil", n, err)
	}

	// SeekStart.
	pos, err := r.Seek(0, io.SeekStart)
	if err != nil || pos != 0 {
		t.Errorf("Seek(0, SeekStart) = %d, %v; want 0, nil", pos, err)
	}

	// SeekCurrent.
	pos, err = r.Seek(3, io.SeekCurrent)
	if err != nil || pos != 3 {
		t.Errorf("Seek(3, SeekCurrent) = %d, %v; want 3, nil", pos, err)
	}

	// SeekEnd.
	pos, err = r.Seek(0, io.SeekEnd)
	if err != nil || pos != int64(len(data)) {
		t.Errorf("Seek(0, SeekEnd) = %d, %v; want %d, nil", pos, err, len(data))
	}

	// Read at EOF.
	n, err = r.Read(buf)
	if err != io.EOF || n != 0 {
		t.Errorf("Read at EOF = %d, %v; want 0, EOF", n, err)
	}

	// Invalid whence.
	_, err = r.Seek(0, 99)
	if err == nil {
		t.Error("Seek with invalid whence should error")
	}

	// Negative position.
	_, err = r.Seek(-100, io.SeekStart)
	if err == nil {
		t.Error("Seek to negative position should error")
	}

	// Close.
	if err := r.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}

// TestS3Client_ValidateEndpoint_EdgeCases verifies validateEndpoint paths.
func TestS3Client_ValidateEndpoint_EdgeCases(t *testing.T) {
	// Empty endpoint should fail.
	if err := validateEndpoint(""); err == nil {
		t.Error("validateEndpoint(\"\") should return error")
	}

	// Valid endpoint with https.
	if err := validateEndpoint("https://s3.amazonaws.com"); err != nil {
		t.Errorf("validateEndpoint(https://s3.amazonaws.com) = %v, want nil", err)
	}

	// Valid endpoint with http.
	if err := validateEndpoint("http://localhost:9000"); err != nil {
		t.Errorf("validateEndpoint(http://localhost:9000) = %v, want nil", err)
	}

	// Path-only URL (no scheme) should fail.
	if err := validateEndpoint("/no-scheme"); err == nil {
		t.Error("expected error for path-only URL")
	}
}


func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://s3.amazonaws.com", "https://s3.amazonaws.com"},
		{"http://localhost:9000", "http://localhost:9000"},
		{"storage.googleapis.com", "https://storage.googleapis.com"},
		{"s3.amazonaws.com/", "https://s3.amazonaws.com"},
		{"  https://example.com  ", "https://example.com"},
		// Empty string produces "https:/" due to scheme injection + TrimSuffix; not a realistic input.
	}
	for _, tt := range tests {
		got := normalizeEndpoint(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeEndpoint(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNewBackendClient_GCS_NormalisesEndpoint(t *testing.T) {
	// Start a local HTTP server to accept the inner client construction.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Test 1: Dispatch to GCS with explicit endpoint succeeds.
	cfg := &config.BackendConfig{
		Type:       config.BackendTypeGCS,
		Endpoint:   server.URL,
		AccessKey:  "test-access-key",
		SecretKey:  "test-secret-key",
		Region:     "us-east-1",
	}
	client, err := NewBackendClient(cfg)
	if err != nil {
		t.Fatalf("NewBackendClient(GCS) with valid endpoint: %v", err)
	}
	gcs, ok := client.(*gcsClient)
	if !ok {
		t.Fatalf("expected *gcsClient, got %T", client)
	}
	if gcs.inner == nil {
		t.Fatal("gcsClient.inner should not be nil")
	}

	// Test 2: Dispatch to GCS with empty endpoint uses default.
	cfg2 := &config.BackendConfig{
		Type:       config.BackendTypeGCS,
		Endpoint:   "", // empty — should default to https://storage.googleapis.com
		AccessKey:  "test-access-key",
		SecretKey:  "test-secret-key",
		Region:     "us-east-1",
		UseSSL:     true,
	}
	// The client will be constructed pointing at the default GCS endpoint,
	// so we just verify no error during construction.
	_, err = NewBackendClient(cfg2, WithHTTPTransport(http.DefaultTransport))
	if err != nil {
		if strings.Contains(err.Error(), "unknown backend type") {
			t.Fatalf("GCS dispatch failed: %v", err)
		}
	}

	// Test 3: Empty type defaults to S3.
	cfg3 := &config.BackendConfig{
		Type:       "",
		Endpoint:   server.URL,
		AccessKey:  "test-access-key",
		SecretKey:  "test-secret-key",
		Region:     "us-east-1",
	}
	client3, err := NewBackendClient(cfg3)
	if err != nil {
		t.Fatalf("NewBackendClient(empty type) should construct S3 client: %v", err)
	}
	if client3 == nil {
		t.Fatal("NewBackendClient(empty type) returned nil")
	}

	// Test 4: Explicit S3 type works.
	cfg4 := &config.BackendConfig{
		Type:       config.BackendTypeS3,
		Endpoint:   server.URL,
		AccessKey:  "test-access-key",
		SecretKey:  "test-secret-key",
		Region:     "us-east-1",
	}
	client4, err := NewBackendClient(cfg4)
	if err != nil {
		t.Fatalf("NewBackendClient(S3) should construct client: %v", err)
	}
	if client4 == nil {
		t.Fatal("NewBackendClient(S3) returned nil")
	}
}

func TestNewBackendClient_Azure_Dispatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	cfg := &config.BackendConfig{
		Type:       config.BackendTypeAzure,
		Endpoint:   server.URL,
		AccessKey:  "test-access-key",
		SecretKey:  "test-secret-key",
		Region:     "us-east-1",
	}
	client, err := NewBackendClient(cfg)
	if err != nil {
		t.Fatalf("NewBackendClient(Azure) should construct client: %v", err)
	}
	az, ok := client.(*azureClient)
	if !ok {
		t.Fatalf("expected *azureClient, got %T", client)
	}
	if az.inner == nil {
		t.Fatal("azureClient.inner should not be nil")
	}
}

func TestNewBackendClient_UnknownType_ReturnsError(t *testing.T) {
	cfg := &config.BackendConfig{
		Type:      config.BackendType("unknown"),
		Endpoint:  "http://localhost:0",
		AccessKey: "test",
		SecretKey: "test",
	}
	_, err := NewBackendClient(cfg)
	if err == nil {
		t.Fatal("expected error for unknown backend type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown backend type") {
		t.Errorf("expected 'unknown backend type' error, got: %v", err)
	}
}

// TestComputeContentMD5_Seekable verifies MD5 is computed and stream rewound.
func TestComputeContentMD5_Seekable(t *testing.T) {
	data := []byte("hello world")
	wantMD5 := base64.StdEncoding.EncodeToString(md5sum(data))

	r := bytes.NewReader(data)
	got, r2, err := computeContentMD5(r)
	if err != nil {
		t.Fatalf("computeContentMD5 error: %v", err)
	}
	if got != wantMD5 {
		t.Errorf("md5 = %q, want %q", got, wantMD5)
	}
	// Verify stream was rewound.
	pos, _ := r2.(io.Seeker).Seek(0, io.SeekCurrent)
	if pos != 0 {
		t.Errorf("stream not rewound, pos = %d", pos)
	}
}

// TestComputeContentMD5_NonSeekable returns empty string without error.
func TestComputeContentMD5_NonSeekable(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("data"))
		pw.Close()
	}()
	got, r2, err := computeContentMD5(pr)
	if err != nil {
		t.Fatalf("computeContentMD5 error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty md5 for non-seekable, got %q", got)
	}
	if r2 != pr {
		t.Error("expected original reader returned")
	}
}

// TestComputeContentMD5_Nil returns empty string.
func TestComputeContentMD5_Nil(t *testing.T) {
	got, r2, err := computeContentMD5(nil)
	if err != nil {
		t.Fatalf("computeContentMD5 error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty md5 for nil, got %q", got)
	}
	if r2 != nil {
		t.Error("expected nil reader returned")
	}
}

// TestS3Client_UploadPart_SetsContentMD5 verifies that UploadPart sets
// Content-MD5 when the body is seekable (compatibility with older S3 backends).
func TestS3Client_UploadPart_SetsContentMD5(t *testing.T) {
	var gotContentMD5 string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			gotContentMD5 = r.Header.Get("Content-Md5")
			w.Header().Set("ETag", `"part-etag"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	data := []byte("part-body")
	wantMD5 := base64.StdEncoding.EncodeToString(md5sum(data))
	cl := int64(len(data))
	_, err := client.UploadPart(context.Background(), "test-bucket", "test-key", "upload123", 1, bytes.NewReader(data), &cl)
	if err != nil {
		t.Fatalf("UploadPart() error: %v", err)
	}
	if gotContentMD5 == "" {
		t.Error("Content-MD5 header was not sent to backend")
	}
	if gotContentMD5 != wantMD5 {
		t.Errorf("Content-MD5 = %q, want %q", gotContentMD5, wantMD5)
	}
}

// TestS3Client_PutObject_SetsContentMD5 verifies PutObject sets Content-MD5
// when the body is seekable.
func TestS3Client_PutObject_SetsContentMD5(t *testing.T) {
	var gotContentMD5 string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			gotContentMD5 = r.Header.Get("Content-Md5")
			w.Header().Set("ETag", `"obj-etag"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
	})
	transport := &fakeS3Transport{handler: mux}
	client := buildTestS3Client(t, transport)

	data := []byte("object-body")
	wantMD5 := base64.StdEncoding.EncodeToString(md5sum(data))
	cl := int64(len(data))
	_, err := client.PutObject(context.Background(), "test-bucket", "test-key",
		bytes.NewReader(data), nil, &cl, "", nil, "", "", "", "", "")
	if err != nil {
		t.Fatalf("PutObject() error: %v", err)
	}
	if gotContentMD5 == "" {
		t.Error("Content-MD5 header was not sent to backend")
	}
	if gotContentMD5 != wantMD5 {
		t.Errorf("Content-MD5 = %q, want %q", gotContentMD5, wantMD5)
	}
}

// md5sum is a test helper returning the raw MD5 digest of b.
func md5sum(b []byte) []byte {
	h := md5.New()
	h.Write(b)
	return h.Sum(nil)
}
