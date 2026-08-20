package api

import (
	"encoding/json"
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

func TestUploadPartCopy_EncryptedMPU_HTTP_LegacyStateRejected(t *testing.T) {
	h, base, mr := newMPUTestHandler(t, "copy-legacy-http-*")
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	base.objects["source/plain"] = []byte("first")
	base.metadata["source/plain"] = map[string]string{}
	id, _ := sec38CreateUpload(t, h, "copy-legacy-http-bucket", "dest")
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "mpu:") && key != "mpu:writer-version" {
			mr.HSet(key, "state_version", "1")
			mr.HSet(key, "phase", "open")
			var meta map[string]interface{}
			_ = json.Unmarshal([]byte(mr.HGet(key, "meta")), &meta)
			meta["state_version"] = float64(1)
			encoded, _ := json.Marshal(meta)
			mr.HSet(key, "meta", string(encoded))
		}
	}
	req := httptest.NewRequest("PUT", fmt.Sprintf("/copy-legacy-http-bucket/dest?partNumber=1&uploadId=%s", id), nil)
	req.Header.Set("x-amz-copy-source", "/source/plain")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), "OperationAborted")
	aw := httptest.NewRecorder()
	r.ServeHTTP(aw, httptest.NewRequest("DELETE", fmt.Sprintf("/copy-legacy-http-bucket/dest?uploadId=%s", id), nil))
	require.Equal(t, http.StatusNoContent, aw.Code)
}
