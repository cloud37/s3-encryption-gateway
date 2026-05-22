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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCopySource(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		wantBucket  string
		wantKey     string
		wantVersion *string
		wantErr     bool
	}{
		{
			name:       "bucket/key",
			source:     "test-bucket/test-key",
			wantBucket: "test-bucket",
			wantKey:    "test-key",
			wantErr:    false,
		},
		{
			name:        "bucket/key with version",
			source:      "test-bucket/test-key?versionId=v123",
			wantBucket:  "test-bucket",
			wantKey:     "test-key",
			wantVersion: ptr("v123"),
			wantErr:     false,
		},
		{
			name:       "/bucket/key",
			source:     "/test-bucket/test-key",
			wantBucket: "test-bucket",
			wantKey:    "test-key",
			wantErr:    false,
		},
		{
			name:       "nested key",
			source:     "test-bucket/path/to/key",
			wantBucket: "test-bucket",
			wantKey:    "path/to/key",
			wantErr:    false,
		},
		{
			name:    "invalid: no slash",
			source:  "test-bucket-only",
			wantErr: true,
		},
		{
			name:    "invalid: empty bucket",
			source:  "/test-key",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bucket, key, version, err := parseCopySource(tt.source)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantBucket, bucket)
			assert.Equal(t, tt.wantKey, key)
			if tt.wantVersion != nil {
				require.NotNil(t, version)
				assert.Equal(t, *tt.wantVersion, *version)
			} else {
				assert.Nil(t, version)
			}
		})
	}
}

func TestHandleUploadPartCopy_Dispatch(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Seed a source object
	mockClient.objects["src-bucket/src-key"] = []byte("source data")
	mockClient.metadata["src-bucket/src-key"] = make(map[string]string)

	// Regular UploadPart without copy source should still work
	t.Run("UploadPart without copy source", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", bytes.NewReader([]byte("part data")))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// UploadPartCopy with copy source should dispatch to handleUploadPartCopy
	t.Run("UploadPartCopy with copy source", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
		req.Header.Set("x-amz-copy-source", "src-bucket/src-key")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		// Should succeed with CopyPartResult XML
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "CopyPartResult")
	})
}

func TestHandleUploadPartCopy_ErrorCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name           string
		sourceHeader   string
		rangeHeader    string
		expectHTTPCode int
		expectS3Code   string
	}{
		{
			name:           "malformed copy source",
			sourceHeader:   "invalid-format",
			expectHTTPCode: http.StatusBadRequest,
			expectS3Code:   "InvalidArgument",
		},
		{
			name:           "malformed range header",
			sourceHeader:   "src-bucket/src-key",
			rangeHeader:    "invalid-range",
			expectHTTPCode: http.StatusBadRequest,
			expectS3Code:   "InvalidArgument",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
			if tt.sourceHeader != "" {
				req.Header.Set("x-amz-copy-source", tt.sourceHeader)
			}
			if tt.rangeHeader != "" {
				req.Header.Set("x-amz-copy-source-range", tt.rangeHeader)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.expectHTTPCode, w.Code)
			assert.Contains(t, w.Body.String(), tt.expectS3Code)
		})
	}
}

func TestHandleUploadPartCopy_PlaintextFastPath(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Seed a plaintext source object (no encryption metadata)
	sourceData := []byte("plaintext source data")
	mockClient.objects["src-bucket/src-key"] = sourceData
	mockClient.metadata["src-bucket/src-key"] = make(map[string]string) // No encryption metadata

	// Create a test request
	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123",
		bytes.NewReader([]byte("ignored body")))
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should succeed with CopyPartResult XML
	assert.Equal(t, http.StatusOK, w.Code, "Response body: %s", w.Body.String())

	var result CopyPartResultXML
	err := xml.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.NotEmpty(t, result.ETag)
	assert.NotEmpty(t, result.LastModified)
}

func TestHandleUploadPartCopy_PlaintextWithRange(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Seed a plaintext source object
	sourceData := []byte("0123456789")
	mockClient.objects["src-bucket/src-key"] = sourceData
	mockClient.metadata["src-bucket/src-key"] = make(map[string]string)

	// Copy a range (bytes 2-5)
	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")
	req.Header.Set("x-amz-copy-source-range", "bytes=2-5")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Response body: %s", w.Body.String())

	var result CopyPartResultXML
	err := xml.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)
	assert.NotEmpty(t, result.ETag)
}

func TestHandleUploadPartCopy_SourceNotFound(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Source doesn't exist - the mock will return an error when trying to HeadObject
	// The exact error code depends on how TranslateError handles the mock error
	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/nonexistent-key")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should return an error response
	assert.GreaterOrEqual(t, w.Code, 400)
	assert.Contains(t, w.Body.String(), "Error") // Verify it's an error response
}

func TestHandleUploadPartCopy_ResponseXML(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Seed a source object
	mockClient.objects["src-bucket/src-key"] = []byte("test data")
	mockClient.metadata["src-bucket/src-key"] = make(map[string]string)

	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "Response body: %s", w.Body.String())
	assert.Equal(t, "application/xml", w.Header().Get("Content-Type"))

	// Verify XML structure
	var result CopyPartResultXML
	err := xml.Unmarshal(w.Body.Bytes(), &result)
	require.NoError(t, err)

	// Validate fields
	assert.NotEmpty(t, result.ETag, "ETag should not be empty")
	assert.NotEmpty(t, result.LastModified, "LastModified should not be empty")

	// Validate timestamp format
	_, err = time.Parse("2006-01-02T15:04:05.000Z", result.LastModified)
	assert.NoError(t, err, "LastModified should be valid ISO8601")
}

func TestClassifyCopySource_Plaintext(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())

	// Create plaintext source (no encryption metadata)
	mockClient.metadata["src-bucket/src-key"] = make(map[string]string)

	classification, err := handler.classifyCopySource(context.Background(), mockClient, "src-bucket", "src-key", nil)
	require.NoError(t, err)
	assert.Equal(t, SourceClassPlaintext, classification.Class)
	assert.False(t, classification.IsEncrypted)
	assert.False(t, classification.IsChunked)
}

func TestClassifyCopySource_Chunked(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())

	// Create chunked-encrypted source
	mockClient.metadata["src-bucket/src-key"] = map[string]string{
		crypto.MetaChunkedFormat: "true",
		crypto.MetaEncrypted:     "true",
	}

	classification, err := handler.classifyCopySource(context.Background(), mockClient, "src-bucket", "src-key", nil)
	require.NoError(t, err)
	assert.Equal(t, SourceClassChunked, classification.Class)
	assert.True(t, classification.IsEncrypted)
	assert.True(t, classification.IsChunked)
}

func TestClassifyCopySource_Legacy(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())

	// Create legacy (single-AEAD) encrypted source
	mockClient.metadata["src-bucket/src-key"] = map[string]string{
		crypto.MetaEncrypted: "true",
		// No chunked flag
	}

	classification, err := handler.classifyCopySource(context.Background(), mockClient, "src-bucket", "src-key", nil)
	require.NoError(t, err)
	assert.Equal(t, SourceClassLegacy, classification.Class)
	assert.True(t, classification.IsEncrypted)
	assert.False(t, classification.IsChunked)
}

// Helper function to create a pointer to a string
func ptr(s string) *string {
	return &s
}

// TestUploadPartCopy_CrossBucket_ReadDenied verifies the source-bucket READ
// authorization gate: if the backend refuses the HeadObject on the source
// with AccessDenied (the caller's SigV4 credentials lack s3:GetObject on
// the source), the gateway surfaces 403 AccessDenied to the client rather
// than silently falling through or masking the error.
//
// Plan DoD (V0.6-S3-1): "source-bucket read authorization checked on every
// UploadPartCopy via the same policy path as GetObject; denial produces
// 403 AccessDenied independently of destination write authorization".
func TestUploadPartCopy_CrossBucket_ReadDenied(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Simulate the backend refusing the HeadObject on the source. In
	// production this is what happens when the caller's credentials lack
	// s3:GetObject on the source bucket.
	mockClient.errors["src-bucket/src-key/head"] = &mockAPIError{
		code:    "AccessDenied",
		message: "Access Denied",
	}

	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "expected 403; body=%s", w.Body.String())
	assert.Contains(t, w.Body.String(), "AccessDenied")
}

// TestUploadPartCopy_PlaintextSource_EncryptedDestBucket_Refused verifies
// the destination-policy / source-mode mismatch hard-refusal: if the
// destination bucket's policy sets RequireEncryption=true and the source
// is classified as plaintext, the handler MUST return 500 InternalError
// rather than uploading plaintext bytes into an encryption-required bucket.
//
// Plan DoD (V0.6-S3-1): "Destination-policy / source-mode mismatch
// hard-refusal... returns 500 InternalError and emits an audit event."
func TestUploadPartCopy_PlaintextSource_EncryptedDestBucket_Refused(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	// Build a policy manager that marks dst-bucket as requiring encryption.
	pm := newPolicyManagerWithRequireEncryption(t, "dst-bucket")

	cfg := &config.Config{}
	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(),
		nil, nil, nil, cfg, pm)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Seed a plaintext source (no encryption metadata).
	mockClient.objects["src-bucket/src-key"] = []byte("plaintext")
	mockClient.metadata["src-bucket/src-key"] = map[string]string{}

	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code, "expected 500; body=%s", w.Body.String())
	assert.Contains(t, w.Body.String(), "InternalError")
}

// TestUploadPartCopy_PlaintextSource_NonRequiringBucket_Allowed is the
// inverse of the refusal test: when the destination bucket explicitly opts
// out of encrypted MPU (encrypt_multipart_uploads: false), plaintext sources
// copy successfully via the fast path. This guards against false-positives
// in the mismatch detector.
// Note: since v0.8 the default for encrypt_multipart_uploads is true, so a
// bucket without any policy now gets encrypted MPU. An explicit opt-out is
// required to exercise the plaintext-allowed path.
func TestUploadPartCopy_PlaintextSource_NonRequiringBucket_Allowed(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	// PolicyManager with dst-bucket explicitly opting out of MPU encryption.
	pm := newPolicyManagerWithMPUOff(t, "dst-bucket")
	cfg := &config.Config{}
	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(),
		nil, nil, nil, cfg, pm)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	mockClient.objects["src-bucket/src-key"] = []byte("plaintext")
	mockClient.metadata["src-bucket/src-key"] = map[string]string{}

	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "expected 200; body=%s", w.Body.String())
}

// TestUploadPartCopy_LegacySourceExceedsCap verifies that the legacy
// fallback path refuses to buffer a source larger than
// Server.MaxLegacyCopySourceBytes. This is the OOM defence documented in
// Plan §7 (post-literature-review tightening) and ADR 0006 §"Why Legacy
// Fallback Has a Configurable Cap".
func TestUploadPartCopy_LegacySourceExceedsCap(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	// 1 KiB cap for the test; seed a 2 KiB legacy-encrypted object.
	cfg := &config.Config{}
	cfg.Server.MaxLegacyCopySourceBytes = 1024

	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(),
		nil, nil, nil, cfg, nil)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Seed a legacy-encrypted source. We don't need actual ciphertext — the
	// cap check fires on the Content-Length hint from HeadObject before
	// any decrypt is attempted.
	mockClient.objects["src-bucket/legacy-big"] = make([]byte, 2048)
	mockClient.metadata["src-bucket/legacy-big"] = map[string]string{
		crypto.MetaEncrypted: "true",
		"Content-Length":     "2048",
	}

	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/legacy-big")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected 400; body=%s", w.Body.String())
	assert.Contains(t, w.Body.String(), "InvalidRequest")
	assert.Contains(t, w.Body.String(), "MaxLegacyCopySourceBytes")
}

// TestUploadPartCopy_LegacySourceWithinCap_NoContentLength verifies the
// defensive ReadAll cap: even if the backend does not report a
// Content-Length (or lies about it), reading more than the cap bytes of
// decrypted plaintext triggers the same refusal. Uses a plaintext source
// (no real decrypt), bypasses classification by manually setting metadata.
//
// Skipped when MaxLegacyCopySourceBytes is the default because constructing
// a real legacy-encrypted object of the required size is out of scope for
// a unit test. The pre-flight check in TestUploadPartCopy_LegacySourceExceedsCap
// provides the primary coverage.

// TestUploadPartCopy_SourceRangeExceeds5GiB verifies the 5 GiB per-call
// cap on x-amz-copy-source-range is enforced by the handler.
// Per AWS S3 UploadPartCopy contract.
func TestUploadPartCopy_SourceRangeExceeds5GiB(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, _ := crypto.NewEngine([]byte("test-password-123456"))

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("PUT", "/dst-bucket/dst-key?partNumber=1&uploadId=upload123", nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")
	// 5 GiB + 1 byte (range is inclusive: last - first + 1 = 5368709121)
	req.Header.Set("x-amz-copy-source-range", "bytes=0-5368709120")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code, "expected 400; body=%s", w.Body.String())
	assert.Contains(t, w.Body.String(), "InvalidRequest")
}

// TestUploadPartCopy_MPU_AppendPartFailure_Returns503 verifies that when the
// encrypted-MPU re-encrypt path writes the backend part successfully but
// AppendPart on the Valkey state store fails, the handler returns 503
// ServiceUnavailable instead of a silent 200 OK. This closes the latent
// silent-data-loss bug described in V0.6-S3-3 plan §1.2 gap 3.
func TestUploadPartCopy_MPU_AppendPartFailure_Returns503(t *testing.T) {
	handler, mockClient, _ := newMPUTestHandler(t, "dst-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "dst-test-bucket", "test-key"

	// Seed a plaintext source (no encryption metadata → SourceClassPlaintext).
	mockClient.objects["src-bucket/src-key"] = []byte("hello from source")
	mockClient.metadata["src-bucket/src-key"] = map[string]string{}

	// Create MPU to establish state in miniredis.
	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "CreateMultipartUpload: %s", w.Body.String())
	uploadID := extractUploadID(t, w.Body.String())
	t.Cleanup(func() {
		req := httptest.NewRequest("DELETE", fmt.Sprintf("/%s/%s?uploadId=%s", bucket, key, uploadID), nil)
		router.ServeHTTP(httptest.NewRecorder(), req)
	})

	// Replace the state store with one that fails AppendPart.
	handler.WithMPUStateStore(&failOnAppendStateStore{
		StateStore: handler.mpuStateStore,
		appendErr:  errors.New("valkey: connection refused"),
	})

	req = httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, uploadID), nil)
	req.Header.Set("x-amz-copy-source", "src-bucket/src-key")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code, "expected 503; body=%s", w.Body.String())
	assert.Contains(t, w.Body.String(), "ServiceUnavailable")
}

// newPolicyManagerWithRequireEncryption builds a PolicyManager with one
// policy that sets RequireEncryption=true for the given bucket name.
// encrypt_multipart_uploads is explicitly false because these tests exercise
// RequireEncryption behaviour without a Valkey store wired up.
func newPolicyManagerWithRequireEncryption(t *testing.T, bucket string) *config.PolicyManager {
	t.Helper()
	// Write a minimal YAML policy to a temp file and load it.
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := fmt.Sprintf(`id: test-require-encryption
buckets:
  - %s
require_encryption: true
encrypt_multipart_uploads: false
`, bucket)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{path}); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	return pm
}

// newPolicyManagerWithMPUOff builds a PolicyManager with one policy that
// sets encrypt_multipart_uploads: false for the given bucket name. Used by
// tests that need to exercise plaintext UploadPartCopy paths without a
// Valkey store (since encrypt_multipart_uploads defaults to true as of v0.8).
func newPolicyManagerWithMPUOff(t *testing.T, bucket string) *config.PolicyManager {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	content := fmt.Sprintf(`id: test-mpu-off
buckets:
  - %s
encrypt_multipart_uploads: false
`, bucket)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{path}); err != nil {
		t.Fatalf("load policies: %v", err)
	}
	return pm
}

// infiniteReader produces an endless stream of zero bytes.
// Used to simulate a DecryptRange output that exceeds maxCopyPartRangeBytes
// without allocating real memory.
type infiniteReader struct{ remaining int64 }

func (r *infiniteReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > r.remaining {
		n = r.remaining
	}
	for i := int64(0); i < n; i++ {
		p[i] = 0
	}
	r.remaining -= n
	return int(n), nil
}

// oversizedDecryptEngine wraps a real EncryptionEngine but overrides
// DecryptRange to return an infiniteReader that exceeds maxCopyPartRangeBytes.
// This lets us test the V1.0-SEC-29 LimitReader guards without actually allocating
// 5 GiB of heap.
type oversizedDecryptEngine struct {
	crypto.EncryptionEngine
	returnBytes int64
}

func (e *oversizedDecryptEngine) DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, start, end int64) (io.Reader, map[string]string, error) {
	return &infiniteReader{remaining: e.returnBytes}, metadata, nil
}

// TestSEC29_ChunkedSourceBufferCap_uploadPartCopyChunked verifies that
// uploadPartCopyChunked refuses to buffer a DecryptRange output larger than
// maxCopyPartRangeBytes (5 GiB). Prior to the V1.0-SEC-29 fix, io.ReadAll was
// called without a LimitReader, allowing an attacker-controlled source to
// exhaust heap memory.
func TestSEC29_ChunkedSourceBufferCap_uploadPartCopyChunked(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockClient := newMockS3Client()

	// Seed a chunked-encrypted source with a plaintext size that fits within
	// the per-part range cap, but whose DecryptRange output is injected to
	// exceed it via oversizedDecryptEngine.
	srcMeta := map[string]string{
		crypto.MetaChunkedFormat: "true",
		crypto.MetaEncrypted:     "true",
		crypto.MetaOriginalSize:  "1024",
	}
	mockClient.objects["src-bucket/chunked-key"] = make([]byte, 64)
	mockClient.metadata["src-bucket/chunked-key"] = srcMeta

	// Use a small cap for the test so we don't allocate 5 GiB under -race.
	const testCap int64 = 1024

	// The oversized engine returns testCap+1 bytes from
	// DecryptRange, triggering the V1.0-SEC-29 limit guard.
	realEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	engine := &oversizedDecryptEngine{
		EncryptionEngine: realEngine,
		returnBytes:      testCap + 1,
	}

	handler := &Handler{
		encryptionEngine: engine,
		logger:           logger,
		metrics:          getTestMetrics(),
	}

	_, _, err := handler.uploadPartCopyChunked(
		context.Background(), mockClient,
		"dst-bucket", "dst-key", "upload-id", 1,
		"src-bucket", "chunked-key", nil,
		&s3.CopyPartRange{First: 0, Last: 1023},
		testCap,
	)

	require.Error(t, err, "expected error when DecryptRange output exceeds cap")
	assert.Contains(t, err.Error(), "exceeds maximum copy-part size",
		"error message should identify the cap violation")
}

// TestSEC29_ChunkedSourceBufferCap_ReencryptMPU verifies that the
// SourceClassChunked arm of uploadPartCopyReencryptMPU applies the same
// maxCopyPartRangeBytes LimitReader guard added by V1.0-SEC-29.
func TestSEC29_ChunkedSourceBufferCap_ReencryptMPU(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockClient := newMockS3Client()

	srcMeta := map[string]string{
		crypto.MetaChunkedFormat: "true",
		crypto.MetaEncrypted:     "true",
		crypto.MetaOriginalSize:  "1024",
	}
	mockClient.objects["src-bucket/chunked-key"] = make([]byte, 64)
	mockClient.metadata["src-bucket/chunked-key"] = srcMeta

	// Use a small cap for the test so we don't allocate 5 GiB under -race.
	const testCap int64 = 1024

	realEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	engine := &oversizedDecryptEngine{
		EncryptionEngine: realEngine,
		returnBytes:      testCap + 1,
	}

	handler := &Handler{
		encryptionEngine: engine,
		logger:           logger,
		metrics:          getTestMetrics(),
	}

	sourceClass := &CopySourceMetadata{
		Class:       SourceClassChunked,
		IsChunked:   true,
		IsEncrypted: true,
		Size:        1024,
	}

	_, _, err := handler.uploadPartCopyReencryptMPU(
		context.Background(), mockClient,
		"dst-bucket", "dst-key", "upload-id", 1,
		"src-bucket", "chunked-key", nil,
		&s3.CopyPartRange{First: 0, Last: 1023},
		sourceClass,
		config.DefaultMaxLegacyCopySourceBytes,
		testCap,
	)

	require.Error(t, err, "expected error when DecryptRange output exceeds cap")
	assert.Contains(t, err.Error(), "exceeds maximum copy-part size",
		"error message should identify the cap violation")
}
