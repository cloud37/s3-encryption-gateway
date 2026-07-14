package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestReproChunkedUploadIssue(t *testing.T) {
	// Setup
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	mockClient := newMockS3Client()

	engine, err := crypto.NewEngine([]byte("test-password-123456"))
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Construct AWS Chunked Body
	chunk1 := "5;chunk-signature=sig1\r\nhello\r\n"
	chunk2 := "6;chunk-signature=sig2\r\n world\r\n"
	chunkEnd := "0;chunk-signature=final-signature\r\n"

	body := chunk1 + chunk2 + chunkEnd
	realDataSize := 11 // "hello world"
	chunkedSize := len(body)

	req := httptest.NewRequest("PUT", "/test-bucket/test-key", bytes.NewReader([]byte(body)))

	// 1. Send STREAMING-UNSIGNED-PAYLOAD-TRAILER (Regression check 1)
	req.Header.Set("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")

	// 2. Set Content-Length to chunked size, but x-amz-decoded-content-length to real size
	req.Header.Set("Content-Length", strconv.Itoa(chunkedSize))                // ~hundreds bytes
	req.Header.Set("x-amz-decoded-content-length", strconv.Itoa(realDataSize)) // 11 bytes

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify stored object
	storedData, ok := mockClient.objects["test-bucket/test-key"]
	assert.True(t, ok, "Object should be stored")

	storedMeta := mockClient.metadata["test-bucket/test-key"]

	// Check content
	decryptedReader, _, err := engine.Decrypt(context.Background(), bytes.NewReader(storedData), storedMeta)
	assert.NoError(t, err)
	decryptedContent, err := io.ReadAll(decryptedReader)
	assert.NoError(t, err)

	expectedContent := "hello world"
	assert.Equal(t, expectedContent, string(decryptedContent), "Decrypted content should match original payload without signatures")

	// Check Original Content Length metadata (Regression check 2)
	// It SHOULD be 11, not the chunked size
	storedLen := storedMeta[crypto.MetaOriginalSize]
	assert.Equal(t, strconv.Itoa(realDataSize), storedLen, "Stored original content length should match decoded size")
}

func TestLegacyChunkedRangeGetFallsBackToFullFetch(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()

	engine, err := crypto.NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	plaintext := bytes.Repeat([]byte("legacy-range-data-"), 3000)
	encryptedReader, metadata, err := engine.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	delete(metadata, crypto.MetaOriginalSize)
	delete(metadata, crypto.MetaChunkCount)
	metadata["Content-Length"] = strconv.Itoa(len(encryptedData))

	mockClient.PutObject(context.Background(), "test-bucket", "legacy-key", bytes.NewReader(encryptedData), metadata, nil, "", nil, "", "", "", "", "")

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	headReq := httptest.NewRequest("HEAD", "/test-bucket/legacy-key", nil)
	headW := httptest.NewRecorder()
	router.ServeHTTP(headW, headReq)

	if headW.Code != http.StatusOK {
		t.Fatalf("HEAD expected 200, got %d body=%s", headW.Code, headW.Body.String())
	}
	if got := headW.Header().Get("Content-Length"); got != strconv.Itoa(len(plaintext)) {
		t.Fatalf("HEAD Content-Length = %q, want %d", got, len(plaintext))
	}

	req := httptest.NewRequest("GET", "/test-bucket/legacy-key", nil)
	req.Header.Set("Range", "bytes=0-")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusPartialContent {
		t.Fatalf("GET expected 206, got %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Length"); got != strconv.Itoa(len(plaintext)) {
		t.Fatalf("GET Content-Length = %q, want %d", got, len(plaintext))
	}
	wantRange := fmt.Sprintf("bytes 0-%d/%d", len(plaintext)-1, len(plaintext))
	if got := w.Header().Get("Content-Range"); got != wantRange {
		t.Fatalf("GET Content-Range = %q, want %q", got, wantRange)
	}
	if !bytes.Equal(w.Body.Bytes(), plaintext) {
		t.Fatalf("GET body mismatch: got %d bytes, want %d", len(w.Body.Bytes()), len(plaintext))
	}
	if mockClient.lastGetRange != nil {
		t.Fatalf("expected full backend fetch for legacy chunked object, got backend range %q", *mockClient.lastGetRange)
	}
}

func TestLegacyChunkedGetReportsDecryptedContentLength(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()

	engine, err := crypto.NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	plaintext := bytes.Repeat([]byte("legacy-full-get-"), 400)
	encryptedReader, metadata, err := engine.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	delete(metadata, crypto.MetaOriginalSize)
	delete(metadata, crypto.MetaChunkCount)
	metadata["Content-Length"] = strconv.Itoa(len(encryptedData))
	mockClient.PutObject(context.Background(), "test-bucket", "legacy-full", bytes.NewReader(encryptedData), metadata, nil, "", nil, "", "", "", "", "")

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/test-bucket/legacy-full", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), plaintext) {
		t.Fatalf("GET body mismatch: got %d bytes, want %d", len(w.Body.Bytes()), len(plaintext))
	}
	if got := w.Header().Get("Content-Length"); got != strconv.Itoa(len(plaintext)) {
		t.Fatalf("GET Content-Length = %q, want %d", got, len(plaintext))
	}
}

func TestChunkedGetUsesExactSizeWhenChunkCountIsPresent(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()
	engine, err := crypto.NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	plaintext := bytes.Repeat([]byte("short-final-chunk-"), 400)
	encryptedReader, metadata, err := engine.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	delete(metadata, crypto.MetaOriginalSize)
	metadata[crypto.MetaChunkCount] = "1"
	metadata["Content-Length"] = strconv.Itoa(len(encryptedData))
	mockClient.PutObject(context.Background(), "test-bucket", "chunk-count", bytes.NewReader(encryptedData), metadata, nil, "", nil, "", "", "", "", "")

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/test-bucket/chunk-count", nil))
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), plaintext) {
		t.Fatalf("GET returned status %d and %d bytes, want 200 and %d bytes", w.Code, len(w.Body.Bytes()), len(plaintext))
	}
	if got := w.Header().Get("Content-Length"); got != strconv.Itoa(len(plaintext)) {
		t.Fatalf("GET Content-Length = %q, want %d", got, len(plaintext))
	}
}

func TestLegacyChunkedListObjectsReportsPlaintextSize(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()

	engine, err := crypto.NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	plaintext := bytes.Repeat([]byte("legacy-list-size-"), 400)
	encryptedReader, metadata, err := engine.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}

	delete(metadata, crypto.MetaOriginalSize)
	delete(metadata, crypto.MetaChunkCount)
	metadata["Content-Length"] = strconv.Itoa(len(encryptedData))

	objectKey := "docker/registry/v2/blobs/sha256/39/legacy/data"
	mockClient.PutObject(context.Background(), "test-bucket", objectKey, bytes.NewReader(encryptedData), metadata, nil, "", nil, "", "", "", "", "")

	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket?prefix=docker/registry/v2/blobs/sha256/39/legacy/&max-keys=1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("ListObjects expected 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), fmt.Sprintf("<Size>%d</Size>", len(plaintext))) {
		t.Fatalf("ListObjects body missing plaintext size %d: %s", len(plaintext), w.Body.String())
	}
	if strings.Contains(w.Body.String(), fmt.Sprintf("<Size>%d</Size>", len(encryptedData))) {
		t.Fatalf("ListObjects body still exposes ciphertext size %d: %s", len(encryptedData), w.Body.String())
	}
}

func TestChunkedRangeGetClampsFinalCiphertextChunk(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockClient := newMockS3Client()

	engine, err := crypto.NewEngineWithChunking([]byte("test-password-123456"), "", nil, true, 16*1024)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Make the final chunk short. The nominal encrypted chunk size is 16 KiB
	// plus a 16-byte AEAD tag, but the final ciphertext is shorter than that.
	plaintext := bytes.Repeat([]byte("final-chunk-range-"), 1700)
	encryptedReader, metadata, err := engine.Encrypt(context.Background(), bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	encryptedData, err := io.ReadAll(encryptedReader)
	if err != nil {
		t.Fatalf("Failed to read encrypted data: %v", err)
	}
	metadata[crypto.MetaChunkCount] = strconv.Itoa((len(plaintext) + 16*1024 - 1) / (16 * 1024))
	metadata[crypto.MetaOriginalSize] = strconv.Itoa(len(plaintext))
	metadata["Content-Length"] = strconv.Itoa(len(encryptedData))

	mockClient.PutObject(context.Background(), "test-bucket", "final-chunk", bytes.NewReader(encryptedData), metadata, nil, "", nil, "", "", "", "", "")
	handler := NewHandler(mockClient, engine, logger, getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("GET", "/test-bucket/final-chunk", nil)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", len(plaintext)-1, len(plaintext)-1))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusPartialContent {
		t.Fatalf("GET expected 206, got %d body=%s", w.Code, w.Body.String())
	}
	if len(w.Body.Bytes()) != 1 || w.Body.Bytes()[0] != plaintext[len(plaintext)-1] {
		t.Fatalf("GET final byte mismatch: got %v, want %v", w.Body.Bytes(), plaintext[len(plaintext)-1])
	}
	if got := mockClient.lastGetRange; got == nil || !strings.HasSuffix(*got, strconv.Itoa(len(encryptedData)-1)) {
		t.Fatalf("backend range was not clamped to ciphertext end: got %v, ciphertext size %d", got, len(encryptedData))
	}
}
