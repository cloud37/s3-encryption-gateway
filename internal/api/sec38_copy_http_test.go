package api

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadPartCopy_EncryptedMPU_HTTP_ChangedSourceRejected(t *testing.T) {
	h, base, _ := newMPUTestHandler(t, "copy-http-*")
	c := &sec38CountingClient{mpuMockS3Client: base}
	h.s3Client = c
	encryptionCalls := 0
	h.destinationEncryptionConstructed = func() { encryptionCalls++ }
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	base.objects["source/plain"], base.metadata["source/plain"] = []byte("first"), map[string]string{}
	id, _ := sec38CreateUpload(t, h, "copy-http-bucket", "dest")
	req := httptest.NewRequest("PUT", fmt.Sprintf("/copy-http-bucket/dest?partNumber=1&uploadId=%s", id), nil)
	req.Header.Set("x-amz-copy-source", "/source/plain")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, 200, w.Code)
	firstEncryptionCalls := encryptionCalls
	firstUploadCalls := c.uploadPartCalls
	base.objects["source/plain"] = []byte("changed")
	req = httptest.NewRequest("PUT", fmt.Sprintf("/copy-http-bucket/dest?partNumber=1&uploadId=%s", id), nil)
	req.Header.Set("x-amz-copy-source", "/source/plain")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), "OperationAborted")
	require.Greater(t, c.sourceHeadCalls, 0)
	require.Greater(t, c.sourceGetCalls, 0)
	require.Greater(t, c.sourceReadCalls, 0)
	require.Equal(t, firstUploadCalls, c.uploadPartCalls)
	require.Equal(t, firstEncryptionCalls, encryptionCalls)
}

func TestUploadPartCopy_EncryptedMPU_LegacyStateRejected(t *testing.T) {
	h, base, mr := newMPUTestHandler(t, "copy-legacy-http-*")
	c := &sec38CountingClient{mpuMockS3Client: base}
	h.s3Client = c
	encryptionCalls := 0
	h.destinationEncryptionConstructed = func() { encryptionCalls++ }
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	base.objects["source/plain"] = []byte("first")
	base.metadata["source/plain"] = map[string]string{}
	id, _ := sec38CreateUpload(t, h, "copy-legacy-http-bucket", "dest")
	makeSEC38HistoricalEncryptedState(t, h, id, mr)
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "mpu:") && key != "mpu:writer-version" {
			mr.HDel(key, "state_version")
			mr.HDel(key, "phase")
			mr.HDel(key, "revision")
		}
	}
	req := httptest.NewRequest("PUT", fmt.Sprintf("/copy-legacy-http-bucket/dest?partNumber=1&uploadId=%s", id), nil)
	req.Header.Set("x-amz-copy-source", "/source/plain")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), "OperationAborted")
	require.Equal(t, 0, c.uploadPartCalls)
	require.Equal(t, 0, encryptionCalls)
	aw := httptest.NewRecorder()
	r.ServeHTTP(aw, httptest.NewRequest("DELETE", fmt.Sprintf("/copy-legacy-http-bucket/dest?uploadId=%s", id), nil))
	require.Equal(t, http.StatusNoContent, aw.Code)
	require.Equal(t, 1, c.abortCalls)
}
