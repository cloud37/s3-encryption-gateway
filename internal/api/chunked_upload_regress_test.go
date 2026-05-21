package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gorilla/mux"
	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
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
