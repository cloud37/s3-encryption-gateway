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
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/gorilla/mux"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

// mockAPIError implements smithy.APIError for testing
type mockAPIError struct {
	code    string
	message string
}

func (e *mockAPIError) Error() string {
	return e.message
}

func (e *mockAPIError) ErrorCode() string {
	return e.code
}

func (e *mockAPIError) ErrorMessage() string {
	return e.message
}

func (e *mockAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultUnknown
}

// mockS3Client is a mock implementation of s3.Client for testing.
type mockS3Client struct {
	objects  map[string][]byte
	metadata map[string]map[string]string
	errors   map[string]error

	// Object-Lock recording (V0.6-S3-2). Readers MUST hold mu; writers
	// hold mu for write.
	locksMu          sync.Mutex
	lastPutLock      *s3.ObjectLockInput
	lastCopyLock     *s3.ObjectLockInput
	lastCompleteLock *s3.ObjectLockInput
	retentions       map[string]*s3.RetentionConfig
	legalHolds       map[string]string
	lockConfigs      map[string]*s3.ObjectLockConfiguration
}

func newMockS3Client() *mockS3Client {
	return &mockS3Client{
		objects:     make(map[string][]byte),
		metadata:    make(map[string]map[string]string),
		errors:      make(map[string]error),
		retentions:  make(map[string]*s3.RetentionConfig),
		legalHolds:  make(map[string]string),
		lockConfigs: make(map[string]*s3.ObjectLockConfiguration),
	}
}

func (m *mockS3Client) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *s3.ObjectLockInput) error {
	if err := m.errors[bucket+"/"+key+"/put"]; err != nil {
		return err
	}
	data, _ := io.ReadAll(reader)
	m.objects[bucket+"/"+key] = data
	m.metadata[bucket+"/"+key] = metadata
	m.locksMu.Lock()
	m.lastPutLock = lock
	m.locksMu.Unlock()
	return nil
}

func (m *mockS3Client) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if err := m.errors[bucket+"/"+key+"/get"]; err != nil {
		return nil, nil, err
	}
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		return nil, nil, &s3Error{code: "NoSuchKey", message: "Object not found"}
	}
	meta := m.metadata[bucket+"/"+key]
	if meta == nil {
		meta = make(map[string]string)
	}

	// Serve byte-range on GET — required for ranged-GET tests.
	if rangeHeader != nil && *rangeHeader != "" {
		var first, last int64
		parts := strings.Split(strings.TrimPrefix(*rangeHeader, "bytes="), "-")
		if len(parts) == 2 {
			f, err1 := strconv.Atoi(parts[0])
			l, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil {
				first = int64(f)
				last = int64(l)
				if last >= int64(len(data)) {
					last = int64(len(data)) - 1
				}
				if first < 0 || first > last {
					return nil, nil, fmt.Errorf("invalid range %q", *rangeHeader)
				}
				return io.NopCloser(bytes.NewReader(data[first : last+1])), meta, nil
			}
		}
	}
	return io.NopCloser(bytes.NewReader(data)), meta, nil
}

func (m *mockS3Client) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	if err := m.errors[bucket+"/"+key+"/delete"]; err != nil {
		return err
	}
	delete(m.objects, bucket+"/"+key)
	delete(m.metadata, bucket+"/"+key)
	return nil
}

func (m *mockS3Client) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	if err := m.errors[bucket+"/"+key+"/head"]; err != nil {
		return nil, err
	}
	meta, ok := m.metadata[bucket+"/"+key]
	if !ok {
		return nil, &s3Error{code: "NoSuchKey", message: "Object not found"}
	}
	if meta == nil {
		meta = make(map[string]string)
	}
	return meta, nil
}

func (m *mockS3Client) ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) (s3.ListResult, error) {
	if err := m.errors[bucket+"/list"]; err != nil {
		return s3.ListResult{}, err
	}

	var allObjects []s3.ObjectInfo
	commonPrefixesMap := make(map[string]bool)

	for key := range m.objects {
		if len(key) > len(bucket)+1 && key[:len(bucket)+1] == bucket+"/" {
			objKey := key[len(bucket)+1:]

			// Apply prefix filter
			if prefix != "" && !strings.HasPrefix(objKey, prefix) {
				continue
			}

			if opts.Delimiter != "" {
				// With delimiter, we need to check for common prefixes
				afterPrefix := objKey
				if prefix != "" {
					afterPrefix = objKey[len(prefix):]
				}

				if idx := strings.Index(afterPrefix, opts.Delimiter); idx >= 0 {
					// This is a "directory" - add to common prefixes
					commonPrefix := prefix + afterPrefix[:idx+len(opts.Delimiter)]
					commonPrefixesMap[commonPrefix] = true
				} else {
					// This is a regular object
					allObjects = append(allObjects, s3.ObjectInfo{Key: objKey, Size: int64(len(m.objects[key]))})
				}
			} else {
				// No delimiter, just add all objects
				allObjects = append(allObjects, s3.ObjectInfo{Key: objKey, Size: int64(len(m.objects[key]))})
			}
		}
	}

	// Convert common prefixes map to slice
	var commonPrefixes []string
	for cp := range commonPrefixesMap {
		commonPrefixes = append(commonPrefixes, cp)
	}

	// Apply StartAfter filter (v1 marker semantics)
	if opts.StartAfter != "" {
		var filtered []s3.ObjectInfo
		for _, obj := range allObjects {
			if obj.Key > opts.StartAfter {
				filtered = append(filtered, obj)
			}
		}
		allObjects = filtered
	}

	// Sort for deterministic pagination
	 sort.Slice(allObjects, func(i, j int) bool {
		return allObjects[i].Key < allObjects[j].Key
	})

	// Apply MaxKeys limit and pagination
	maxKeys := int(opts.MaxKeys)
	if maxKeys <= 0 {
		maxKeys = 1000 // Default
	}

	var objects []s3.ObjectInfo
	isTruncated := false
	nextToken := ""

	totalItems := len(allObjects) + len(commonPrefixes)
	if totalItems > maxKeys {
		isTruncated = true
		if len(allObjects) > maxKeys {
			objects = allObjects[:maxKeys]
		} else {
			objects = allObjects
		}
		// Generate a mock continuation token
		nextToken = "mock-continuation-token"
	} else {
		objects = allObjects
	}

	return s3.ListResult{
		Objects:               objects,
		CommonPrefixes:        commonPrefixes,
		NextContinuationToken: nextToken,
		IsTruncated:           isTruncated,
	}, nil
}

func (m *mockS3Client) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string) (string, error) {
	return "upload-id-123", nil
}

func (m *mockS3Client) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	return "\"etag-123\"", nil
}

func (m *mockS3Client) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []s3.CompletedPart, lock *s3.ObjectLockInput) (string, error) {
	m.locksMu.Lock()
	m.lastCompleteLock = lock
	m.locksMu.Unlock()
	return "\"final-etag\"", nil
}

func (m *mockS3Client) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	return nil
}

func (m *mockS3Client) ListParts(ctx context.Context, bucket, key, uploadID string) ([]s3.PartInfo, error) {
	return []s3.PartInfo{}, nil
}

func (m *mockS3Client) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *s3.ObjectLockInput) (string, map[string]string, error) {
	m.locksMu.Lock()
	m.lastCopyLock = lock
	m.locksMu.Unlock()

	// Get source
	srcReader, srcMeta, err := m.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		return "", nil, err
	}
	defer srcReader.Close()
	data, _ := io.ReadAll(srcReader)

	// Put as destination. Pass the received lock through so the
	// destination PutObject records it as lastPutLock as well (mirrors
	// real-world behaviour).
	if err := m.PutObject(ctx, dstBucket, dstKey, bytes.NewReader(data), metadata, nil, "", lock); err != nil {
		return "", nil, err
	}

	resultMeta := make(map[string]string)
	if srcMeta != nil {
		for k, v := range srcMeta {
			resultMeta[k] = v
		}
	}
	return "\"copied-etag\"", resultMeta, nil
}

func (m *mockS3Client) UploadPartCopy(ctx context.Context, dstBucket, dstKey, uploadID string, partNumber int32, srcBucket, srcKey string, srcVersionID *string, srcRange *s3.CopyPartRange) (*s3.CopyPartResult, error) {
	// Get source range or full object
	srcReader, _, err := m.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		return nil, err
	}
	defer srcReader.Close()
	data, _ := io.ReadAll(srcReader)

	// Apply range if provided
	var partData []byte
	if srcRange != nil {
		if srcRange.First >= int64(len(data)) {
			return nil, fmt.Errorf("range start is beyond object size")
		}
		end := srcRange.Last + 1
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		partData = data[srcRange.First:end]
	} else {
		partData = data
	}

	// Upload part
	key := fmt.Sprintf("%s/%s/%s/%d", dstBucket, dstKey, uploadID, partNumber)
	m.objects[key] = partData
	m.metadata[key] = make(map[string]string)

	return &s3.CopyPartResult{
		ETag:         "\"part-etag\"",
		LastModified: time.Now(),
	}, nil
}

func (m *mockS3Client) DeleteObjects(ctx context.Context, bucket string, keys []s3.ObjectIdentifier) ([]s3.DeletedObject, []s3.ErrorObject, error) {
	deleted := []s3.DeletedObject{}
	errObjects := []s3.ErrorObject{}

	for _, k := range keys {
		if err := m.DeleteObject(ctx, bucket, k.Key, nil); err != nil {
			errCode := "InternalError"
			// Propagate the original error code if available.
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) {
				errCode = apiErr.ErrorCode()
			} else if se, ok := err.(*s3Error); ok {
				errCode = se.code
			}
			errObjects = append(errObjects, s3.ErrorObject{
				Key:     k.Key,
				Code:    errCode,
				Message: err.Error(),
			})
		} else {
			deleted = append(deleted, s3.DeletedObject{
				Key: k.Key,
			})
		}
	}

	return deleted, errObjects, nil
}

type s3Error struct {
	code    string
	message string
}

func (e *s3Error) Error() string {
	return e.message
}

var (
	sharedTestMetrics *metrics.Metrics
	metricsOnce       sync.Once
)

func getTestMetrics() *metrics.Metrics {
	metricsOnce.Do(func() {
		sharedTestMetrics = metrics.NewMetrics()
	})
	return sharedTestMetrics
}

func TestHandler_HandleHealth(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(newMockS3Client(), mockEngine, logger, getTestMetrics())

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHandler_HandlePutObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// For missing bucket test, simulate NoSuchBucket error
	mockClient.errors["missing/bucket/test/put"] = &mockAPIError{code: "NoSuchBucket", message: "The specified bucket does not exist"}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name     string
		bucket   string
		key      string
		body     string
		wantCode int
	}{
		{
			name:     "valid put",
			bucket:   "test-bucket",
			key:      "test-key",
			body:     "test data",
			wantCode: http.StatusOK,
		},
		{
			name:     "missing bucket",
			bucket:   "",
			key:      "test-key",
			body:     "test data",
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var url string
			if tt.bucket == "" {
				// For missing bucket, use a URL that doesn't match the route pattern
				url = "/missing/bucket/test"
			} else {
				url = "/" + tt.bucket + "/" + tt.key
			}
			req := httptest.NewRequest("PUT", url, bytes.NewReader([]byte(tt.body)))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("expected status %d, got %d", tt.wantCode, w.Code)
			}

			if tt.wantCode == http.StatusOK {
				// Verify object was stored
				_, _, err := mockClient.GetObject(context.Background(), tt.bucket, tt.key, nil, nil)
				if err != nil {
					t.Errorf("object should have been stored: %v", err)
				}
			}
		})
	}
}

func TestHandler_HandleGetObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Body.String() != "test data" {
		t.Errorf("expected body 'test data', got %q", w.Body.String())
	}
}

func TestHandler_HandleDeleteObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	// Verify object was deleted
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "test-key", nil, nil)
	if err == nil {
		t.Error("object should have been deleted")
	}
}

func TestHandler_HandleHeadObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	metadata := map[string]string{"content-type": "text/plain"}
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test")), metadata, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("HEAD", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHandler_HandleHeadBucket(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("HEAD", "/test-bucket", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestHandler_HandleHeadBucket_NotFound(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())
	mockClient.errors["missing-bucket/list"] = &mockAPIError{code: "NoSuchBucket", message: "The specified bucket does not exist"}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("HEAD", "/missing-bucket", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestHandler_HeadBucketTrailingSlash_NotRoutedAsHeadObject(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("HEAD", "/test-bucket/", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestHandler_HandleListObjects(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data
	mockClient.PutObject(context.Background(), "test-bucket", "key1", bytes.NewReader([]byte("data1")), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "key2", bytes.NewReader([]byte("data2")), nil, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("Content-Type") != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got %s", w.Header().Get("Content-Type"))
	}
}

func TestHandler_HandleListObjects_Delimiter(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data for delimiter testing
	testObjects := []struct {
		key  string
		data string
	}{
		{"folder1/file1.txt", "data1"},
		{"folder1/file2.txt", "data2"},
		{"folder2/file3.txt", "data3"},
		{"root-file.txt", "root"},
	}

	for _, obj := range testObjects {
		mockClient.PutObject(context.Background(), "test-bucket", obj.key, strings.NewReader(obj.data), nil, nil, "", nil)
	}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name           string
		delimiter      string
		prefix         string
		expectedBodies []string // substrings that should be in response
	}{
		{
			name:      "delimiter slash no prefix",
			delimiter: "/",
			expectedBodies: []string{
				"<Prefix>folder1/</Prefix>",
				"<Prefix>folder2/</Prefix>",
				"<Key>root-file.txt</Key>",
			},
		},
		{
			name:      "delimiter slash with prefix",
			delimiter: "/",
			prefix:    "folder1/",
			expectedBodies: []string{
				"<Key>folder1/file1.txt</Key>",
				"<Key>folder1/file2.txt</Key>",
			},
		},
		{
			name:      "no delimiter",
			delimiter: "",
			expectedBodies: []string{
				"<Key>folder1/file1.txt</Key>",
				"<Key>folder1/file2.txt</Key>",
				"<Key>folder2/file3.txt</Key>",
				"<Key>root-file.txt</Key>",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/test-bucket"
			if tt.prefix != "" {
				url += "?prefix=" + tt.prefix
			}
			if tt.delimiter != "" {
				if tt.prefix != "" {
					url += "&delimiter=" + tt.delimiter
				} else {
					url += "?delimiter=" + tt.delimiter
				}
			}

			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
			}

			body := w.Body.String()
			for _, expected := range tt.expectedBodies {
				if !strings.Contains(body, expected) {
					t.Errorf("expected response to contain %q, but it didn't.\nResponse: %s", expected, body)
				}
			}
		})
	}
}

func TestHandler_HandleListObjects_ContinuationToken(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with many objects for pagination testing
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("object%03d.txt", i)
		data := fmt.Sprintf("data%d", i)
		mockClient.PutObject(context.Background(), "test-bucket", key, strings.NewReader(data), nil, nil, "", nil)
	}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// First request with max-keys=3
	req := httptest.NewRequest("GET", "/test-bucket?max-keys=3", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	// Should contain NextContinuationToken and IsTruncated=true
	if !strings.Contains(body, "<IsTruncated>true</IsTruncated>") {
		t.Errorf("expected response to be truncated, but it wasn't.\nResponse: %s", body)
	}
	if !strings.Contains(body, "<NextContinuationToken>") {
		t.Errorf("expected response to contain NextContinuationToken, but it didn't.\nResponse: %s", body)
	}
}

func TestHandler_HandleListObjects_Prefix(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data
	testObjects := []string{
		"app/logs/error.log",
		"app/logs/info.log",
		"app/config/settings.json",
		"data/file1.txt",
		"data/file2.txt",
	}

	for _, key := range testObjects {
		mockClient.PutObject(context.Background(), "test-bucket", key, strings.NewReader("test data"), nil, nil, "", nil)
	}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name        string
		prefix      string
		expected    []string
		notExpected []string
	}{
		{
			name:        "prefix app/",
			prefix:      "app/",
			expected:    []string{"app/logs/error.log", "app/logs/info.log", "app/config/settings.json"},
			notExpected: []string{"data/file1.txt", "data/file2.txt"},
		},
		{
			name:        "prefix app/logs/",
			prefix:      "app/logs/",
			expected:    []string{"app/logs/error.log", "app/logs/info.log"},
			notExpected: []string{"app/config/settings.json", "data/file1.txt"},
		},
		{
			name:     "no prefix",
			prefix:   "",
			expected: []string{"app/logs/error.log", "app/logs/info.log", "app/config/settings.json", "data/file1.txt", "data/file2.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/test-bucket"
			if tt.prefix != "" {
				url += "?prefix=" + tt.prefix
			}

			req := httptest.NewRequest("GET", url, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
			}

			body := w.Body.String()
			for _, expected := range tt.expected {
				if !strings.Contains(body, "<Key>"+expected+"</Key>") {
					t.Errorf("expected response to contain key %q, but it didn't.\nResponse: %s", expected, body)
				}
			}
			for _, notExpected := range tt.notExpected {
				if strings.Contains(body, "<Key>"+notExpected+"</Key>") {
					t.Errorf("expected response to NOT contain key %q, but it did.\nResponse: %s", notExpected, body)
				}
			}
		})
	}
}

func TestHandler_HandleListObjects_MaxKeys(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with test data
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("object%d.txt", i)
		data := fmt.Sprintf("data%d", i)
		mockClient.PutObject(context.Background(), "test-bucket", key, strings.NewReader(data), nil, nil, "", nil)
	}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket?max-keys=2", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()

	// Count how many <Contents> elements we have
	contentsCount := strings.Count(body, "<Contents>")
	if contentsCount != 2 {
		t.Errorf("expected 2 objects with max-keys=2, got %d.\nResponse: %s", contentsCount, body)
	}

	// Should be truncated
	if !strings.Contains(body, "<IsTruncated>true</IsTruncated>") {
		t.Errorf("expected response to be truncated, but it wasn't.\nResponse: %s", body)
	}
}

// TestHandler_HandleListObjects_Marker verifies that the v1 marker query
// parameter is respected and that NextMarker is emitted when truncated.
func TestHandler_HandleListObjects_Marker(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	keys := []string{"aaa.txt", "bbb.txt", "ccc.txt"}
	for _, k := range keys {
		mockClient.PutObject(context.Background(), "test-bucket", k, strings.NewReader("data"), nil, nil, "", nil)
	}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// First page: max-keys=1, no marker
	req1 := httptest.NewRequest("GET", "/test-bucket?max-keys=1", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("page 1: expected 200, got %d", w1.Code)
	}
	body1 := w1.Body.String()
	if !strings.Contains(body1, "<Key>aaa.txt</Key>") {
		t.Errorf("page 1: expected aaa.txt, got:\n%s", body1)
	}
	if strings.Contains(body1, "<Key>bbb.txt</Key>") {
		t.Errorf("page 1: bbb.txt should not appear")
	}
	if !strings.Contains(body1, "<IsTruncated>true</IsTruncated>") {
		t.Errorf("page 1: expected truncated")
	}
	if !strings.Contains(body1, "<NextMarker>aaa.txt</NextMarker>") {
		t.Errorf("page 1: expected NextMarker = aaa.txt, got:\n%s", body1)
	}

	// Second page: use marker from first page
	req2 := httptest.NewRequest("GET", "/test-bucket?max-keys=1&marker=aaa.txt", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("page 2: expected 200, got %d", w2.Code)
	}
	body2 := w2.Body.String()
	if !strings.Contains(body2, "<Key>bbb.txt</Key>") {
		t.Errorf("page 2: expected bbb.txt, got:\n%s", body2)
	}
	if strings.Contains(body2, "<Key>aaa.txt</Key>") {
		t.Errorf("page 2: aaa.txt should not appear (marker filtered it)")
	}
	if !strings.Contains(body2, "<NextMarker>bbb.txt</NextMarker>") {
		t.Errorf("page 2: expected NextMarker = bbb.txt, got:\n%s", body2)
	}

	// Third page
	req3 := httptest.NewRequest("GET", "/test-bucket?max-keys=1&marker=bbb.txt", nil)
	w3 := httptest.NewRecorder()
	router.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("page 3: expected 200, got %d", w3.Code)
	}
	body3 := w3.Body.String()
	if !strings.Contains(body3, "<Key>ccc.txt</Key>") {
		t.Errorf("page 3: expected ccc.txt, got:\n%s", body3)
	}
	if strings.Contains(body3, "<IsTruncated>true</IsTruncated>") {
		t.Errorf("page 3: should not be truncated")
	}
	if strings.Contains(body3, "<NextMarker>") {
		t.Errorf("page 3: NextMarker should be absent when not truncated")
	}
}

// TestHandler_HandleListObjects_MarkerNotDuplicated verifies that when
// marker is supplied the gateway does NOT return the same first page again.
// This is the exact bug that caused AWS CLI v1 to abort with
// "Same token was used...".
func TestHandler_HandleListObjects_MarkerNotDuplicated(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	mockClient.PutObject(context.Background(), "test-bucket", "first.txt", strings.NewReader("1"), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "second.txt", strings.NewReader("2"), nil, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Request with marker=first.txt
	req := httptest.NewRequest("GET", "/test-bucket?marker=first.txt", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()

	// first.txt must NOT appear because marker excludes it
	if strings.Contains(body, "<Key>first.txt</Key>") {
		t.Errorf("marker=first.txt should exclude first.txt, but it appeared:\n%s", body)
	}
	if !strings.Contains(body, "<Key>second.txt</Key>") {
		t.Errorf("marker=first.txt should include second.txt, but it didn't:\n%s", body)
	}
}

// TestContentRangeMapping tests Content-Range and Content-Length header mapping for range requests
func TestContentRangeMapping(t *testing.T) {
	// Create a crypto engine that supports chunking and range decryption
	engine, err := crypto.NewEngineWithChunking([]byte("test-password-123456"), nil, "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Create test data (32KB to ensure chunking)
	testData := make([]byte, 32*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Encrypt the data with original ETag
	originalMetadata := map[string]string{
		"ETag": "\"original-etag-12345\"", // Mock original ETag
	}
	encryptedReader, metadata, err := engine.Encrypt(context.Background(), bytes.NewReader(testData), originalMetadata)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	// Check that original ETag was stored
	if metadata[crypto.MetaOriginalETag] == "" {
		t.Fatalf("Original ETag not stored in metadata: %+v", metadata)
	}

	// Update metadata for chunked format
	metadata[crypto.MetaEncrypted] = "true"
	metadata[crypto.MetaChunkCount] = "2"    // 32KB / 16KB = 2 chunks
	metadata[crypto.MetaChunkSize] = "16384" // 16KB
	metadata[crypto.MetaChunkedFormat] = "true"

	// Create mock S3 client and populate it
	mockClient := newMockS3Client()
	mockClient.PutObject(context.Background(), "test-bucket", "range-test", bytes.NewReader(encryptedData), metadata, nil, "", nil)

	// Create handler
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewHandler(mockClient, engine, logger, getTestMetrics())

	// Test various range requests
	testCases := []struct {
		name                  string
		rangeHeader           string
		expectedStatus        int
		expectedContentRange  string
		expectedContentLength string
		expectedDataLength    int
	}{
		{
			name:                  "simple range",
			rangeHeader:           "bytes=1000-1999",
			expectedStatus:        http.StatusPartialContent,
			expectedContentRange:  "bytes 1000-1999/32768",
			expectedContentLength: "1000",
			expectedDataLength:    1000,
		},
		{
			name:                  "first byte",
			rangeHeader:           "bytes=0-0",
			expectedStatus:        http.StatusPartialContent,
			expectedContentRange:  "bytes 0-0/32768",
			expectedContentLength: "1",
			expectedDataLength:    1,
		},
		{
			name:                  "last byte",
			rangeHeader:           "bytes=32767-32767",
			expectedStatus:        http.StatusPartialContent,
			expectedContentRange:  "bytes 32767-32767/32768",
			expectedContentLength: "1",
			expectedDataLength:    1,
		},
		{
			name:                  "cross chunk boundary",
			rangeHeader:           "bytes=16380-16390", // Spans chunk boundary
			expectedStatus:        http.StatusPartialContent,
			expectedContentRange:  "bytes 16380-16390/32768",
			expectedContentLength: "11",
			expectedDataLength:    11,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			router := mux.NewRouter()
			handler.RegisterRoutes(router)

			req := httptest.NewRequest("GET", "/test-bucket/range-test", nil)
			req.Header.Set("Range", tc.rangeHeader)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, w.Code)
			}

			if tc.expectedStatus == http.StatusPartialContent {
				contentRange := w.Header().Get("Content-Range")
				if contentRange != tc.expectedContentRange {
					t.Errorf("Content-Range mismatch: expected %q, got %q", tc.expectedContentRange, contentRange)
				}

				contentLength := w.Header().Get("Content-Length")
				if contentLength != tc.expectedContentLength {
					t.Errorf("Content-Length mismatch: expected %q, got %q", tc.expectedContentLength, contentLength)
				}

				body := w.Body.Bytes()
				if len(body) != tc.expectedDataLength {
					t.Errorf("Body length mismatch: expected %d, got %d", tc.expectedDataLength, len(body))
				}

				// Verify Content-Length header matches actual body length
				if contentLength != fmt.Sprintf("%d", len(body)) {
					t.Errorf("Content-Length header (%s) doesn't match body length (%d)", contentLength, len(body))
				}

				// Verify ETag is preserved in range responses
				etag := w.Header().Get("ETag")
				if etag == "" {
					t.Errorf("ETag header should be present in range response")
				}
				// The ETag should be the original ETag (not the encrypted object's ETag)
				// We can't easily verify the exact value without more setup, but presence is key
			}
		})
	}
}

// FuzzParseCompleteMultipartUploadXML fuzzes the XML parser for CompleteMultipartUpload requests.
// This tests various edge cases including malformed XML, invalid part numbers, duplicate parts, and invalid ETags.
func FuzzParseCompleteMultipartUploadXML(f *testing.F) {
	// Add seed corpus with valid and invalid examples
	validXML := `<CompleteMultipartUpload>
	<Part>
		<PartNumber>1</PartNumber>
		<ETag>"abc123"</ETag>
	</Part>
	<Part>
		<PartNumber>2</PartNumber>
		<ETag>"def456"</ETag>
	</Part>
</CompleteMultipartUpload>`

	invalidXML := `<CompleteMultipartUpload>
	<Part>
		<PartNumber>invalid</PartNumber>
		<ETag>"abc123"</ETag>
	</Part>
</CompleteMultipartUpload>`

	duplicatePartsXML := `<CompleteMultipartUpload>
	<Part>
		<PartNumber>1</PartNumber>
		<ETag>"abc123"</ETag>
	</Part>
	<Part>
		<PartNumber>1</PartNumber>
		<ETag>"def456"</ETag>
	</Part>
</CompleteMultipartUpload>`

	invalidETagXML := `<CompleteMultipartUpload>
	<Part>
		<PartNumber>1</PartNumber>
		<ETag>invalid-etag</ETag>
	</Part>
</CompleteMultipartUpload>`

	outOfRangePartXML := `<CompleteMultipartUpload>
	<Part>
		<PartNumber>10001</PartNumber>
		<ETag>"abc123"</ETag>
	</Part>
</CompleteMultipartUpload>`

	// Add seed inputs
	f.Add([]byte(validXML))
	f.Add([]byte(invalidXML))
	f.Add([]byte(duplicatePartsXML))
	f.Add([]byte(invalidETagXML))
	f.Add([]byte(outOfRangePartXML))

	f.Fuzz(func(t *testing.T, input []byte) {
		// Create a handler with minimal setup for fuzzing
		logger := logrus.New()
		logger.SetLevel(logrus.ErrorLevel) // Reduce log noise during fuzzing

		handler := &Handler{
			logger: logger,
		}

		// Parse the XML - this should not panic regardless of input
		_, err := handler.parseCompleteMultipartUploadXML(bytes.NewReader(input))

		// We don't assert on the error since fuzzing is about finding crashes,
		// not validating correctness. The function should handle all inputs gracefully.
		_ = err
	})
}

// TestValidateCompleteMultipartUploadRequest tests the validation logic.
func TestValidateCompleteMultipartUploadRequest(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := &Handler{logger: logger}

	tests := []struct {
		name        string
		req         *CompleteMultipartUpload
		expectError bool
		errorCode   string
	}{
		{
			name: "valid request",
			req: &CompleteMultipartUpload{
				Parts: []struct {
					XMLName    xml.Name `xml:"Part"`
					PartNumber int32    `xml:"PartNumber"`
					ETag       string   `xml:"ETag"`
				}{
					{PartNumber: 1, ETag: `"abc123"`},
					{PartNumber: 2, ETag: `"def456"`},
				},
			},
			expectError: false,
		},
		{
			name: "empty parts",
			req: &CompleteMultipartUpload{
				Parts: []struct {
					XMLName    xml.Name `xml:"Part"`
					PartNumber int32    `xml:"PartNumber"`
					ETag       string   `xml:"ETag"`
				}{},
			},
			expectError: true,
			errorCode:   "InvalidArgument",
		},
		{
			name: "duplicate part numbers",
			req: &CompleteMultipartUpload{
				Parts: []struct {
					XMLName    xml.Name `xml:"Part"`
					PartNumber int32    `xml:"PartNumber"`
					ETag       string   `xml:"ETag"`
				}{
					{PartNumber: 1, ETag: `"abc123"`},
					{PartNumber: 1, ETag: `"def456"`},
				},
			},
			expectError: true,
			errorCode:   "InvalidArgument",
		},
		{
			name: "invalid part number (zero)",
			req: &CompleteMultipartUpload{
				Parts: []struct {
					XMLName    xml.Name `xml:"Part"`
					PartNumber int32    `xml:"PartNumber"`
					ETag       string   `xml:"ETag"`
				}{
					{PartNumber: 0, ETag: `"abc123"`},
				},
			},
			expectError: true,
			errorCode:   "InvalidArgument",
		},
		{
			name: "invalid part number (too high)",
			req: &CompleteMultipartUpload{
				Parts: []struct {
					XMLName    xml.Name `xml:"Part"`
					PartNumber int32    `xml:"PartNumber"`
					ETag       string   `xml:"ETag"`
				}{
					{PartNumber: 10001, ETag: `"abc123"`},
				},
			},
			expectError: true,
			errorCode:   "InvalidArgument",
		},
		{
			name: "invalid ETag format",
			req: &CompleteMultipartUpload{
				Parts: []struct {
					XMLName    xml.Name `xml:"Part"`
					PartNumber int32    `xml:"PartNumber"`
					ETag       string   `xml:"ETag"`
				}{
					{PartNumber: 1, ETag: `invalid-etag`},
				},
			},
			expectError: true,
			errorCode:   "InvalidArgument",
		},
		{
			name: "unquoted ETag",
			req: &CompleteMultipartUpload{
				Parts: []struct {
					XMLName    xml.Name `xml:"Part"`
					PartNumber int32    `xml:"PartNumber"`
					ETag       string   `xml:"ETag"`
				}{
					{PartNumber: 1, ETag: `abc123`},
				},
			},
			expectError: true,
			errorCode:   "InvalidArgument",
		},
		{
			name: "parts not in ascending order (should warn but not error)",
			req: &CompleteMultipartUpload{
				Parts: []struct {
					XMLName    xml.Name `xml:"Part"`
					PartNumber int32    `xml:"PartNumber"`
					ETag       string   `xml:"ETag"`
				}{
					{PartNumber: 2, ETag: `"abc123"`},
					{PartNumber: 1, ETag: `"def456"`},
				},
			},
			expectError: false, // AWS allows this but logs a warning
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateCompleteMultipartUploadRequest(tt.req)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if s3Err, ok := err.(*S3Error); ok {
					if s3Err.Code != tt.errorCode {
						t.Errorf("Expected error code %s, got %s", tt.errorCode, s3Err.Code)
					}
				} else {
					t.Errorf("Expected S3Error, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestIsValidETag tests the ETag validation function.
func TestIsValidETag(t *testing.T) {
	tests := []struct {
		etag    string
		isValid bool
	}{
		{`"abc123"`, true},
		{`"ABCDEF123"`, true},
		{`"a-b-c-d-e"`, true},
		{`"1234567890abcdef"`, true},
		{`""`, false},        // Empty
		{`"abc`, false},      // Unclosed quote
		{`abc"`, false},      // Unopened quote
		{`abc123`, false},    // No quotes
		{`"abc 123"`, false}, // Invalid character (space)
		{`"abc@123"`, false}, // Invalid character (@)
		{`"abc_123"`, false}, // Invalid character (_)
	}

	for _, tt := range tests {
		t.Run(tt.etag, func(t *testing.T) {
			result := isValidETag(tt.etag)
			if result != tt.isValid {
				t.Errorf("isValidETag(%q) = %v, want %v", tt.etag, result, tt.isValid)
			}
		})
	}
}

func TestHandler_HandleCreateBucket(t *testing.T) {
	tests := []struct {
		name           string
		bucket         string
		proxiedBucket  string
		setupMock      func(*mockS3Client)
		expectedCode   string
		expectedStatus int
	}{
		{
			name:           "nil config manages all buckets",
			bucket:         "test-bucket",
			proxiedBucket:  "",                     // nil config case handled separately
			setupMock:      func(*mockS3Client) {}, // no setup needed
			expectedCode:   "BucketAlreadyExists",
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "empty proxied bucket manages all buckets - bucket exists",
			bucket:         "test-bucket",
			proxiedBucket:  "",
			setupMock:      func(*mockS3Client) {}, // no setup needed, bucket "exists"
			expectedCode:   "BucketAlreadyExists",
			expectedStatus: http.StatusConflict,
		},
		{
			name:          "empty proxied bucket manages all buckets - bucket does not exist",
			bucket:        "nonexistent-bucket",
			proxiedBucket: "",
			setupMock: func(m *mockS3Client) {
				// Simulate bucket not existing by making ListObjects fail
				m.errors["nonexistent-bucket/list"] = &mockAPIError{code: "NoSuchBucket", message: "The specified bucket does not exist"}
			},
			expectedCode:   "NotImplemented",
			expectedStatus: http.StatusNotImplemented,
		},
		{
			name:           "proxied bucket matches request",
			bucket:         "specific-bucket",
			proxiedBucket:  "specific-bucket",
			setupMock:      func(*mockS3Client) {}, // no setup needed
			expectedCode:   "BucketAlreadyExists",
			expectedStatus: http.StatusConflict,
		},
		{
			name:           "proxied bucket does not match request",
			bucket:         "other-bucket",
			proxiedBucket:  "specific-bucket",
			setupMock:      func(*mockS3Client) {}, // no setup needed
			expectedCode:   "NotImplemented",
			expectedStatus: http.StatusNotImplemented,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)
			mockClient := newMockS3Client()
			mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))

			// Setup mock client
			tt.setupMock(mockClient)

			var handler *Handler
			if tt.name == "nil config manages all buckets" {
				// Test nil config case
				handler = NewHandler(mockClient, mockEngine, logger, getTestMetrics())
			} else {
				// Test with config
				cfg := &config.Config{
					ProxiedBucket: tt.proxiedBucket,
				}
				handler = NewHandlerWithFeatures(mockClient, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg, nil)
			}

			router := mux.NewRouter()
			handler.RegisterRoutes(router)

			req := httptest.NewRequest("PUT", "/"+tt.bucket, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			body, err := io.ReadAll(w.Body)
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}

			expectedCode := "<Code>" + tt.expectedCode + "</Code>"
			if !bytes.Contains(body, []byte(expectedCode)) {
				t.Errorf("Expected error code %s, got response: %s", tt.expectedCode, string(body))
			}
		})
	}
}

// Object Lock mock methods (V0.6-S3-2). These record and recall state
// so unit tests can assert round-trips.
func (m *mockS3Client) PutObjectRetention(ctx context.Context, bucket, key string, versionID *string, retention *s3.RetentionConfig) error {
	if err := m.errors[bucket+"/"+key+"/put_retention"]; err != nil {
		return err
	}
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	if retention != nil {
		cp := *retention
		m.retentions[bucket+"/"+key] = &cp
	} else {
		delete(m.retentions, bucket+"/"+key)
	}
	return nil
}

func (m *mockS3Client) GetObjectRetention(ctx context.Context, bucket, key string, versionID *string) (*s3.RetentionConfig, error) {
	if err := m.errors[bucket+"/"+key+"/get_retention"]; err != nil {
		return nil, err
	}
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	if r, ok := m.retentions[bucket+"/"+key]; ok {
		cp := *r
		return &cp, nil
	}
	return nil, nil
}

func (m *mockS3Client) PutObjectLegalHold(ctx context.Context, bucket, key string, versionID *string, status string) error {
	if err := m.errors[bucket+"/"+key+"/put_legal_hold"]; err != nil {
		return err
	}
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	m.legalHolds[bucket+"/"+key] = status
	return nil
}

func (m *mockS3Client) GetObjectLegalHold(ctx context.Context, bucket, key string, versionID *string) (string, error) {
	if err := m.errors[bucket+"/"+key+"/get_legal_hold"]; err != nil {
		return "", err
	}
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	return m.legalHolds[bucket+"/"+key], nil
}

func (m *mockS3Client) PutObjectLockConfiguration(ctx context.Context, bucket string, config *s3.ObjectLockConfiguration) error {
	if err := m.errors[bucket+"/put_lock_config"]; err != nil {
		return err
	}
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	if config != nil {
		cp := *config
		m.lockConfigs[bucket] = &cp
	} else {
		delete(m.lockConfigs, bucket)
	}
	return nil
}

func (m *mockS3Client) GetObjectLockConfiguration(ctx context.Context, bucket string) (*s3.ObjectLockConfiguration, error) {
	if err := m.errors[bucket+"/get_lock_config"]; err != nil {
		return nil, err
	}
	m.locksMu.Lock()
	defer m.locksMu.Unlock()
	if c, ok := m.lockConfigs[bucket]; ok {
		cp := *c
		return &cp, nil
	}
	return nil, nil
}

// ---------------------------------------------------------------------------
// MPU manifest cleanup tests
// ---------------------------------------------------------------------------

func TestDeleteObject_CleansUpMPUManifest(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with primary object AND its MPU manifest
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "test-key.mpu-manifest", bytes.NewReader([]byte("manifest data")), nil, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	// Verify primary object is gone
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "test-key", nil, nil)
	if err == nil {
		t.Error("primary object should have been deleted")
	}

	// Verify manifest object is also gone
	_, _, err = mockClient.GetObject(context.Background(), "test-bucket", "test-key.mpu-manifest", nil, nil)
	if err == nil {
		t.Error("MPU manifest should have been cleaned up")
	}
}

func TestDeleteObject_ManifestNotFoundIsNoop(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with primary object only (NO manifest)
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil, nil, "", nil)

	// Simulate NoSuchKey for the manifest delete
	mockClient.errors["test-bucket/test-key.mpu-manifest/delete"] = &mockAPIError{code: "NoSuchKey", message: "not found"}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}

	// Verify primary object is gone
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "test-key", nil, nil)
	if err == nil {
		t.Error("primary object should have been deleted")
	}
}

func TestDeleteObject_ManifestCleanupFailureDoesNotAffectPrimary(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with primary object
	mockClient.PutObject(context.Background(), "test-bucket", "test-key", bytes.NewReader([]byte("test data")), nil, nil, "", nil)

	// Simulate an AccessDenied error for the manifest delete
	mockClient.errors["test-bucket/test-key.mpu-manifest/delete"] = &mockAPIError{code: "AccessDenied", message: "access denied"}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("DELETE", "/test-bucket/test-key", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Primary delete MUST still succeed
	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d despite manifest cleanup failure, got %d", http.StatusNoContent, w.Code)
	}

	// Verify primary object is gone despite manifest cleanup failure
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "test-key", nil, nil)
	if err == nil {
		t.Error("primary object should have been deleted")
	}
}

func TestDeleteObjects_CleansUpMPUManifests(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with objects AND their manifests
	mockClient.PutObject(context.Background(), "test-bucket", "key1", bytes.NewReader([]byte("data1")), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "key2", bytes.NewReader([]byte("data2")), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "key1.mpu-manifest", bytes.NewReader([]byte("manifest1")), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "key2.mpu-manifest", bytes.NewReader([]byte("manifest2")), nil, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := `<Delete><Object><Key>key1</Key></Object><Object><Key>key2</Key></Object></Delete>`
	req := httptest.NewRequest("POST", "/test-bucket?delete", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify both primary objects are gone
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "key1", nil, nil)
	if err == nil {
		t.Error("key1 should have been deleted")
	}
	_, _, err = mockClient.GetObject(context.Background(), "test-bucket", "key2", nil, nil)
	if err == nil {
		t.Error("key2 should have been deleted")
	}

	// Verify both manifests are cleaned up
	_, _, err = mockClient.GetObject(context.Background(), "test-bucket", "key1.mpu-manifest", nil, nil)
	if err == nil {
		t.Error("key1 manifest should have been cleaned up")
	}
	_, _, err = mockClient.GetObject(context.Background(), "test-bucket", "key2.mpu-manifest", nil, nil)
	if err == nil {
		t.Error("key2 manifest should have been cleaned up")
	}
}

func TestDeleteObjects_ManifestNotFoundIsNoop(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with primary objects only (NO manifests)
	mockClient.PutObject(context.Background(), "test-bucket", "key1", bytes.NewReader([]byte("data1")), nil, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := `<Delete><Object><Key>key1</Key></Object></Delete>`
	req := httptest.NewRequest("POST", "/test-bucket?delete", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify primary object is gone
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "key1", nil, nil)
	if err == nil {
		t.Error("key1 should have been deleted")
	}
}

func TestDeleteObjects_PartialManifestCleanupFailure(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	// Pre-populate with objects AND their manifests
	mockClient.PutObject(context.Background(), "test-bucket", "key1", bytes.NewReader([]byte("data1")), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "key2", bytes.NewReader([]byte("data2")), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "key1.mpu-manifest", bytes.NewReader([]byte("manifest1")), nil, nil, "", nil)
	mockClient.PutObject(context.Background(), "test-bucket", "key2.mpu-manifest", bytes.NewReader([]byte("manifest2")), nil, nil, "", nil)

	// Simulate AccessDenied for key2's manifest cleanup
	mockClient.errors["test-bucket/key2.mpu-manifest/delete"] = &mockAPIError{code: "AccessDenied", message: "access denied"}

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := `<Delete><Object><Key>key1</Key></Object><Object><Key>key2</Key></Object></Delete>`
	req := httptest.NewRequest("POST", "/test-bucket?delete", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Verify both primary objects are gone
	_, _, err := mockClient.GetObject(context.Background(), "test-bucket", "key1", nil, nil)
	if err == nil {
		t.Error("key1 should have been deleted")
	}
	_, _, err = mockClient.GetObject(context.Background(), "test-bucket", "key2", nil, nil)
	if err == nil {
		t.Error("key2 should have been deleted")
	}

	// Verify key1's manifest WAS cleaned up (no error for it)
	_, _, err = mockClient.GetObject(context.Background(), "test-bucket", "key1.mpu-manifest", nil, nil)
	if err == nil {
		t.Error("key1 manifest should have been cleaned up")
	}

	// Verify key2's manifest still EXISTS (cleanup was denied)
	_, _, err = mockClient.GetObject(context.Background(), "test-bucket", "key2.mpu-manifest", nil, nil)
	if err != nil {
		t.Error("key2 manifest should still exist because cleanup was denied")
	}
}

func TestIsS3NotFoundError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "NoSuchKey via APIError",
			err:  &mockAPIError{code: "NoSuchKey", message: "not found"},
			want: true,
		},
		{
			name: "NotFound via APIError",
			err:  &mockAPIError{code: "NotFound", message: "not found"},
			want: true,
		},
		{
			name: "AccessDenied via APIError",
			err:  &mockAPIError{code: "AccessDenied", message: "denied"},
			want: false,
		},
		{
			name: "NoSuchKey via s3Error (string match fallback)",
			err:  &s3Error{code: "NoSuchKey", message: "NoSuchKey: The specified key does not exist"},
			want: true,
		},
		{
			name: "NotFound string in error message",
			err:  fmt.Errorf("something NotFound happened"),
			want: true,
		},
		{
			name: "unrelated error",
			err:  fmt.Errorf("unrelated error"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isS3NotFoundError(tt.err)
			if got != tt.want {
				t.Errorf("isS3NotFoundError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestHandleDeleteBucket(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE method, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint: backend.URL,
			UseSSL:   false,
		},
	}
	handler := NewHandlerWithFeatures(mockClient, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg, nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("DELETE", "/test-bucket", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}
}

func TestHandleDeleteBucket_WithPolicyManager(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint: backend.URL,
			UseSSL:   false,
		},
	}

	pm := config.NewPolicyManager()
	pm.LoadPolicies([]string{})

	handler := NewHandlerWithFeatures(mockClient, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg, pm)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("DELETE", "/test-bucket", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected status %d, got %d", http.StatusNoContent, w.Code)
	}
}

func TestHandleListBuckets(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("expected path /, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Buckets><Bucket><Name>test-bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>`))
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint: backend.URL,
			UseSSL:   false,
		},
	}
	handler := NewHandlerWithFeatures(mockClient, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg, nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "test-bucket") {
		t.Errorf("expected response to contain 'test-bucket', got: %s", body)
	}
}

func TestHandleSelectObjectContent_501(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("POST", "/test-bucket/test-key?select", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotImplemented {
		t.Errorf("expected status %d, got %d", http.StatusNotImplemented, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "<Code>NotImplemented</Code>") {
		t.Errorf("expected NotImplemented error code, got: %s", body)
	}
}

func TestHandleCORSPreflight_OPTIONS(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, DELETE, HEAD, POST")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint: backend.URL,
			UseSSL:   false,
		},
	}
	handler := NewHandlerWithFeatures(mockClient, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg, nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("OPTIONS", "/test-bucket", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("expected Access-Control-Allow-Origin header, got: %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestHandlePassthrough_Proxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/test-bucket" {
			t.Errorf("expected path /test-bucket, got %s", r.URL.Path)
		}
		if r.URL.Query().Get("location") != "" {
			t.Errorf("expected location query parameter")
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>us-east-1</LocationConstraint></LocationConstraint>`))
	}))
	defer backend.Close()

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	cfg := &config.Config{
		Backend: config.BackendConfig{
			Endpoint: backend.URL,
			UseSSL:   false,
		},
	}
	handler := NewHandlerWithFeatures(mockClient, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg, nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket?location", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "us-east-1") {
		t.Errorf("expected response to contain 'us-east-1', got: %s", body)
	}
}

// TestObjectKeyPassthrough_RoutingVars verifies that every object-level passthrough handler
// correctly extracts both {bucket} and {key} from the mux route variables and forwards the
// right path to the backend. A typo of mux.Vars(r)["bucket"] instead of mux.Vars(r)["key"]
// would cause the key segment to be silently dropped — this test catches that regression.
func TestObjectKeyPassthrough_RoutingVars(t *testing.T) {
	cases := []struct {
		name            string
		method          string
		url             string
		wantBackendPath string
		wantQuery       string
	}{
		{
			name:            "GetObjectTagging",
			method:          "GET",
			url:             "/my-bucket/path/to/object?tagging",
			wantBackendPath: "/my-bucket/path/to/object",
			wantQuery:       "tagging",
		},
		{
			name:            "PutObjectTagging",
			method:          "PUT",
			url:             "/my-bucket/path/to/object?tagging",
			wantBackendPath: "/my-bucket/path/to/object",
			wantQuery:       "tagging",
		},
		{
			name:            "DeleteObjectTagging",
			method:          "DELETE",
			url:             "/my-bucket/path/to/object?tagging",
			wantBackendPath: "/my-bucket/path/to/object",
			wantQuery:       "tagging",
		},
		{
			name:            "GetObjectACL",
			method:          "GET",
			url:             "/my-bucket/path/to/object?acl",
			wantBackendPath: "/my-bucket/path/to/object",
			wantQuery:       "acl",
		},
		{
			name:            "PutObjectACL",
			method:          "PUT",
			url:             "/my-bucket/path/to/object?acl",
			wantBackendPath: "/my-bucket/path/to/object",
			wantQuery:       "acl",
		},
		{
			name:            "RestoreObject",
			method:          "POST",
			url:             "/my-bucket/path/to/object?restore",
			wantBackendPath: "/my-bucket/path/to/object",
			wantQuery:       "restore",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotQuery string
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotQuery = r.URL.RawQuery
				w.WriteHeader(http.StatusOK)
			}))
			defer backend.Close()

			logger := logrus.New()
			logger.SetLevel(logrus.ErrorLevel)
			mockClient := newMockS3Client()
			mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
			cfg := &config.Config{
				Backend: config.BackendConfig{
					Endpoint: backend.URL,
					UseSSL:   false,
				},
			}
			handler := NewHandlerWithFeatures(mockClient, mockEngine, logger, getTestMetrics(), nil, nil, nil, cfg, nil)

			router := mux.NewRouter()
			handler.RegisterRoutes(router)

			req := httptest.NewRequest(tc.method, tc.url, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", w.Code)
			}
			if gotPath != tc.wantBackendPath {
				t.Errorf("backend path: want %q, got %q — likely wrong mux.Vars key in handler", tc.wantBackendPath, gotPath)
			}
			if gotQuery != tc.wantQuery {
				t.Errorf("backend query: want %q, got %q", tc.wantQuery, gotQuery)
			}
		})
	}
}

// TestHandler_ListObjects_ReturnsCiphertextSize verifies that ListObjects
// returns backend (ciphertext) sizes without per-object HEAD translation.
// HeadObject and GetObject are responsible for returning decrypted sizes.
func TestHandler_ListObjects_ReturnsCiphertextSize(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	plaintext := "hello world this is some plaintext"
	originalSize := int64(len(plaintext))

	// Encrypt data inline
	encReader, encMeta, err := mockEngine.Encrypt(context.Background(), strings.NewReader(plaintext), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll encrypted: %v", err)
	}
	ciphertextSize := int64(len(encData))

	// Store encrypted object in mock
	mockClient.PutObject(context.Background(), "test-bucket", "encrypted-key", bytes.NewReader(encData), encMeta, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()

	// Verify the listed size is the ciphertext size, not plaintext size
	var result struct {
		Contents []struct {
			Key  string `xml:"Key"`
			Size int64  `xml:"Size"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(result.Contents) != 1 {
		t.Fatalf("expected 1 object, got %d", len(result.Contents))
	}
	listedSize := result.Contents[0].Size
	if listedSize != ciphertextSize {
		t.Errorf("ListObjects size mismatch: expected ciphertext size %d, got %d (would be plaintext size %d)", ciphertextSize, listedSize, originalSize)
	}
	if listedSize == originalSize {
		t.Errorf("ListObjects returned plaintext size %d — HEAD translation may still be active", originalSize)
	}
}

// TestHandler_HeadObject_ReturnsDecryptedSize verifies that HeadObject
// restores the original plaintext Content-Length for encrypted objects.
func TestHandler_HeadObject_ReturnsDecryptedSize(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	plaintext := "hello world this is some plaintext for headobject test"
	originalSize := int64(len(plaintext))

	encReader, encMeta, err := mockEngine.Encrypt(context.Background(), strings.NewReader(plaintext), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll encrypted: %v", err)
	}

	mockClient.PutObject(context.Background(), "test-bucket", "enc-key", bytes.NewReader(encData), encMeta, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("HEAD", "/test-bucket/enc-key", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	cl := w.Header().Get("Content-Length")
	if cl == "" {
		t.Fatalf("missing Content-Length header in HeadObject response")
	}
	var headSize int64
	if _, err := fmt.Sscanf(cl, "%d", &headSize); err != nil {
		t.Fatalf("invalid Content-Length %q: %v", cl, err)
	}
	if headSize != originalSize {
		t.Errorf("HeadObject Content-Length mismatch: expected decrypted size %d, got %d", originalSize, headSize)
	}
}

// TestHandler_GetObject_ReturnsDecryptedContentLength verifies that GetObject
// returns Content-Length equal to the original plaintext size for encrypted objects.
func TestHandler_GetObject_ReturnsDecryptedContentLength(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))
	handler := NewHandler(mockClient, mockEngine, logger, getTestMetrics())

	plaintext := "hello world this is plaintext for getobject test"
	originalSize := int64(len(plaintext))

	encReader, encMeta, err := mockEngine.Encrypt(context.Background(), strings.NewReader(plaintext), map[string]string{
		"Content-Type": "text/plain",
	})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	encData, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll encrypted: %v", err)
	}

	mockClient.PutObject(context.Background(), "test-bucket", "enc-key", bytes.NewReader(encData), encMeta, nil, "", nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket/enc-key", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	cl := w.Header().Get("Content-Length")
	if cl == "" {
		t.Fatalf("missing Content-Length header in GetObject response")
	}
	var getSize int64
	if _, err := fmt.Sscanf(cl, "%d", &getSize); err != nil {
		t.Fatalf("invalid Content-Length %q: %v", cl, err)
	}
	if getSize != originalSize {
		t.Errorf("GetObject Content-Length mismatch: expected decrypted size %d, got %d", originalSize, getSize)
	}

	// Verify body is the original plaintext
	if w.Body.String() != plaintext {
		t.Errorf("GetObject body mismatch: expected %q, got %q", plaintext, w.Body.String())
	}
}
