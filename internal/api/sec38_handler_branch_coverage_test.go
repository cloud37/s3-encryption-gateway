package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func sec38Request(method, path string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, path, body)
	return mux.SetURLVars(r, map[string]string{"bucket": "b", "key": "k", "uploadId": "u", "partNumber": "1"})
}

func TestSEC38_CompleteHandler_GuardsAndStateErrors(t *testing.T) {
	t.Run("invalid vars", func(t *testing.T) {
		h, _, _ := newMPUTestHandler(t, "branch-*")
		r := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/b/k", bytes.NewReader(nil)), map[string]string{})
		w := httptest.NewRecorder()
		h.handleCompleteMultipartUpload(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("disabled", func(t *testing.T) {
		h, _, _ := newMPUTestHandler(t, "branch-*")
		h.config = &config.Config{Server: config.ServerConfig{DisableMultipartUploads: true}}
		w := httptest.NewRecorder()
		h.handleCompleteMultipartUpload(w, sec38Request(http.MethodPost, "/b/k?uploadId=u", bytes.NewReader(nil)))
		require.Equal(t, http.StatusNotImplemented, w.Code)
	})
	t.Run("malformed XML", func(t *testing.T) {
		h, _, _ := newMPUTestHandler(t, "branch-*")
		w := httptest.NewRecorder()
		h.handleCompleteMultipartUpload(w, sec38Request(http.MethodPost, "/b/k?uploadId=u", bytes.NewReader([]byte("not xml"))))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("state unavailable", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "branch-*")
		base.objects["src/key"] = []byte("source")
		base.metadata["src/key"] = map[string]string{}
		h.mpuStateStore = &failOnGetStateStore{StateStore: h.mpuStateStore, getErr: errors.New("valkey down")}
		body := []byte(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag></Part></CompleteMultipartUpload>`)
		w := httptest.NewRecorder()
		h.handleCompleteMultipartUpload(w, sec38Request(http.MethodPost, "/b/k?uploadId=u", bytes.NewReader(body)))
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestSEC38_AbortHandler_GuardsAndBeginFailure(t *testing.T) {
	t.Run("invalid vars", func(t *testing.T) {
		h, _, _ := newMPUTestHandler(t, "branch-*")
		r := mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/b/k", nil), map[string]string{})
		w := httptest.NewRecorder()
		h.handleAbortMultipartUpload(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("disabled", func(t *testing.T) {
		h, _, _ := newMPUTestHandler(t, "branch-*")
		h.config = &config.Config{Server: config.ServerConfig{DisableMultipartUploads: true}}
		w := httptest.NewRecorder()
		h.handleAbortMultipartUpload(w, sec38Request(http.MethodDelete, "/b/k?uploadId=u", nil))
		require.Equal(t, http.StatusNotImplemented, w.Code)
	})
	t.Run("state unavailable", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "branch-*")
		base.objects["src/key"] = []byte("source")
		base.metadata["src/key"] = map[string]string{}
		h.mpuStateStore = &failOnGetStateStore{StateStore: h.mpuStateStore, getErr: errors.New("valkey down")}
		w := httptest.NewRecorder()
		h.handleAbortMultipartUpload(w, sec38Request(http.MethodDelete, "/b/k?uploadId=u", nil))
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestSEC38_CopyHandler_ValidationAndPreflightErrors(t *testing.T) {
	t.Run("invalid vars", func(t *testing.T) {
		h, _, _ := newMPUTestHandler(t, "branch-*")
		r := mux.SetURLVars(httptest.NewRequest(http.MethodPut, "/b/k", nil), map[string]string{})
		w := httptest.NewRecorder()
		h.handleUploadPartCopy(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("invalid part", func(t *testing.T) {
		h, _, _ := newMPUTestHandler(t, "branch-*")
		r := mux.SetURLVars(httptest.NewRequest(http.MethodPut, "/b/k?partNumber=no", nil), map[string]string{"bucket": "b", "key": "k", "uploadId": "u", "partNumber": "no"})
		r.Header.Set("x-amz-copy-source", "src/key")
		w := httptest.NewRecorder()
		h.handleUploadPartCopy(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("source too large", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "branch-*")
		base.metadata["src/key"] = map[string]string{"Content-Length": fmt.Sprint(maxCopySourceSizeBytes + 1)}
		base.objects["src/key"] = []byte("source")
		w := httptest.NewRecorder()
		r := sec38Request(http.MethodPut, "/b/k?partNumber=1&uploadId=u", nil)
		r.Header.Set("x-amz-copy-source", "src/key")
		h.handleUploadPartCopy(w, r)
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("missing source header", func(t *testing.T) {
		h, _, _ := newMPUTestHandler(t, "branch-*")
		w := httptest.NewRecorder()
		h.handleUploadPartCopy(w, sec38Request(http.MethodPut, "/b/k?partNumber=1&uploadId=u", nil))
		require.Equal(t, http.StatusBadRequest, w.Code)
	})
	t.Run("state unavailable", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "branch-*")
		base.objects["src/key"] = []byte("source")
		base.metadata["src/key"] = map[string]string{}
		h.mpuStateStore = &failOnGetStateStore{StateStore: h.mpuStateStore, getErr: errors.New("valkey down")}
		r := sec38Request(http.MethodPut, "/b/k?partNumber=1&uploadId=u", nil)
		r.Header.Set("x-amz-copy-source", "src/key")
		w := httptest.NewRecorder()
		h.handleUploadPartCopy(w, r)
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestSEC38_UploadStateEncrypted_InfrastructureBranches(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "branch-*")
	h.mpuStateStore = nil
	state, encrypted, err := h.uploadStateEncrypted(context.Background(), "u")
	require.NoError(t, err)
	require.Nil(t, state)
	require.False(t, encrypted)
}
