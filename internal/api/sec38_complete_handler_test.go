package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func TestMPU_PartClaim_LegacyStateRequiresAbort(t *testing.T) {
	h, _, mr := newMPUTestHandler(t, "legacy-http-*")
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	id, _ := sec38CreateUpload(t, h, "legacy-http-bucket", "obj")
	makeSEC38HistoricalEncryptedState(t, h, id, mr)
	w := sec38UploadPart(t, r, "legacy-http-bucket", "obj", id, 1, []byte("data"))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "predates nonce-safety") {
		t.Fatalf("legacy upload: %d %s", w.Code, w.Body.String())
	}
	aw := httptest.NewRecorder()
	r.ServeHTTP(aw, httptest.NewRequest("DELETE", fmt.Sprintf("/legacy-http-bucket/obj?uploadId=%s", id), nil))
	requireStatus(t, aw, http.StatusNoContent)
}

func TestMPU_Complete_LegacyEncryptedStateRejected(t *testing.T) {
	h, _, mr := newMPUTestHandler(t, "legacy-complete-*")
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	id, _ := sec38CreateUpload(t, h, "legacy-complete-bucket", "obj")
	rawPart := sec38UploadPart(t, r, "legacy-complete-bucket", "obj", id, 1, []byte("legacy"))
	requireStatus(t, rawPart, http.StatusOK)
	makeSEC38HistoricalEncryptedState(t, h, id, mr)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/legacy-complete-bucket/obj?uploadId="+id,
		strings.NewReader(fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, rawPart.Header().Get("ETag")))))
	require.Equal(t, http.StatusConflict, w.Code)
	require.Contains(t, w.Body.String(), "OperationAborted")
}

func makeSEC38HistoricalEncryptedState(t *testing.T, h *Handler, id string, mr *miniredis.Miniredis) {
	t.Helper()
	state, err := h.mpuStateStore.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get state: %v", err)
	}
	state.PolicySnapshot.EncryptMultipartUploads = true
	state.StateVersion, state.Phase, state.Revision = 0, "", 0
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	delete(fields, "state_version")
	delete(fields, "phase")
	delete(fields, "revision")
	encoded, _ := json.Marshal(fields)
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "mpu:") && key != "mpu:writer-version" {
			mr.HSet(key, "meta", string(encoded))
			mr.HDel(key, "state_version")
			mr.HDel(key, "phase")
			mr.HDel(key, "revision")
			return
		}
	}
	t.Fatal("historical MPU key not found")
}

func TestMPU_Handler_LegacyEncryptedAbortFinalizesAndDeletes(t *testing.T) {
	h, base, mr := newMPUTestHandler(t, "legacy-abort-handler-*")
	c := &sec38CountingClient{mpuMockS3Client: base}
	h.s3Client = c
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	id, _ := sec38CreateUpload(t, h, "legacy-abort-handler-bucket", "obj")
	makeSEC38HistoricalEncryptedState(t, h, id, mr)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("DELETE", "/legacy-abort-handler-bucket/obj?uploadId="+id, nil))
	require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
	require.Equal(t, 1, c.abortCalls)
	_, err := h.mpuStateStore.Get(context.Background(), id)
	require.ErrorIs(t, err, mpu.ErrUploadNotFound)
}

func TestMPU_Complete_SelectedSubsetManifestMatchesBackend(t *testing.T) {
	h, base, _ := newMPUTestHandler(t, "subset-http-*")
	c := &sec38CountingClient{mpuMockS3Client: base}
	h.s3Client = c
	id, r := sec38CreateUpload(t, h, "subset-http-bucket", "obj")
	etags := make(map[int]string)
	for i := 1; i <= 3; i++ {
		w := sec38UploadPart(t, r, "subset-http-bucket", "obj", id, i, []byte(fmt.Sprintf("part-%d", i)))
		requireStatus(t, w, 200)
		etags[i] = w.Header().Get("ETag")
	}
	xml := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part><Part><PartNumber>3</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etags[1], etags[3])
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/subset-http-bucket/obj?uploadId="+id, strings.NewReader(xml)))
	requireStatus(t, w, 200)
	if len(c.completeParts) != 2 || c.completeParts[0].PartNumber != 1 || c.completeParts[1].PartNumber != 3 {
		t.Fatalf("selected backend parts: %+v", c.completeParts)
	}
	manifestBytes, ok := base.objects["subset-http-bucket/obj.mpu-manifest"]
	require.True(t, ok, "selected MPU manifest missing")
	manifestMeta := base.metadata["subset-http-bucket/obj.mpu-manifest"]
	encodedBinding := base.metadata["subset-http-bucket/obj"][crypto.MetaObjectBindingID]
	binding, err := base64.RawURLEncoding.DecodeString(encodedBinding)
	require.NoError(t, err)
	require.Len(t, binding, 16)
	var bindingID [16]byte
	copy(bindingID[:], binding)
	plainManifest, err := crypto.DecryptMPUManifest(context.Background(), h.encryptionEngine, crypto.ObjectContext{Bucket: "subset-http-bucket", Key: "obj.mpu-manifest"}, bindingID, manifestBytes, manifestMeta)
	require.NoError(t, err)
	manifest, err := crypto.UnmarshalMultipartManifest(plainManifest)
	require.NoError(t, err)
	require.Equal(t, []int32{1, 3}, []int32{manifest.Parts[0].PartNumber, manifest.Parts[1].PartNumber})
	require.Equal(t, []string{etags[1], etags[3]}, []string{manifest.Parts[0].ETag, manifest.Parts[1].ETag})
}

func TestMPU_Complete_FinalizationAndBackendFailurePaths(t *testing.T) {
	for name, configure := range map[string]func(*sec38CountingClient){
		"backend failure":   func(c *sec38CountingClient) { c.completeErr = errors.New("backend failed") },
		"finalize conflict": func(c *sec38CountingClient) {},
	} {
		t.Run(name, func(t *testing.T) {
			h, base, _ := newMPUTestHandler(t, "complete-branches-*")
			c := &sec38CountingClient{mpuMockS3Client: base}
			h.s3Client = c
			id, r := sec38CreateUpload(t, h, "complete-branches-bucket", "obj")
			part := sec38UploadPart(t, r, "complete-branches-bucket", "obj", id, 1, []byte("part"))
			requireStatus(t, part, http.StatusOK)
			configure(c)
			if name == "finalize conflict" {
				store := &lifecycleFailureStore{StateStore: h.mpuStateStore, finalizeCompleteErr: mpu.ErrRevisionConflict}
				h.mpuStateStore = store
			}
			body := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, part.Header().Get("ETag"))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/complete-branches-bucket/obj?uploadId="+id, strings.NewReader(body)))
			require.NotEqual(t, http.StatusOK, w.Code)
		})
	}
}

func TestMPU_Complete_ManifestWriteFailureReopensState(t *testing.T) {
	h, base, _ := newMPUTestHandler(t, "complete-manifest-error-*")
	c := &sec38CountingClient{mpuMockS3Client: base}
	h.s3Client = c
	id, r := sec38CreateUpload(t, h, "complete-manifest-error-bucket", "obj")
	part := sec38UploadPart(t, r, "complete-manifest-error-bucket", "obj", id, 1, []byte("part"))
	requireStatus(t, part, http.StatusOK)
	c.putObjectErr = errors.New("manifest backend failed")
	body := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, part.Header().Get("ETag"))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/complete-manifest-error-bucket/obj?uploadId="+id, strings.NewReader(body)))
	require.Equal(t, http.StatusInternalServerError, w.Code)
	_, err := h.mpuStateStore.Get(context.Background(), id)
	require.NoError(t, err, "manifest failure must reopen encrypted MPU state")
}

func TestMPU_Complete_ETagMismatchInvalidPartNoIO(t *testing.T) {
	h, base, _ := newMPUTestHandler(t, "etag-http-*")
	c := &sec38CountingClient{mpuMockS3Client: base}
	h.s3Client = c
	id, r := sec38CreateUpload(t, h, "etag-http-bucket", "obj")
	w := sec38UploadPart(t, r, "etag-http-bucket", "obj", id, 1, []byte("part"))
	requireStatus(t, w, 200)
	xml := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"deadbeef"</ETag></Part></CompleteMultipartUpload>`
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/etag-http-bucket/obj?uploadId="+id, strings.NewReader(xml)))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "InvalidPart") || c.completeCalls != 0 || c.putObjectCalls != 0 {
		t.Fatalf("mismatch: %d %s complete=%d put=%d", w.Code, w.Body.String(), c.completeCalls, c.putObjectCalls)
	}
}

func TestMPU_Complete_PartOrderInvalidPartOrder(t *testing.T) {
	h, base, _ := newMPUTestHandler(t, "order-http-*")
	c := &sec38CountingClient{mpuMockS3Client: base}
	h.s3Client = c
	id, r := sec38CreateUpload(t, h, "order-http-bucket", "obj")
	for i := 1; i <= 2; i++ {
		requireStatus(t, sec38UploadPart(t, r, "order-http-bucket", "obj", id, i, []byte("part")), 200)
	}
	xml := `<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>"deadbeef"</ETag></Part><Part><PartNumber>1</PartNumber><ETag>"deadbeef"</ETag></Part></CompleteMultipartUpload>`
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/order-http-bucket/obj?uploadId="+id, strings.NewReader(xml)))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "InvalidPartOrder") || c.completeCalls != 0 {
		t.Fatalf("order: %d %s complete=%d", w.Code, w.Body.String(), c.completeCalls)
	}
}

func TestMPU_Complete_BackendFailureReopensMatchingRevision(t *testing.T) {
	h, base, _ := newMPUTestHandler(t, "reopen-http-*")
	c := &sec38CountingClient{mpuMockS3Client: base, completeErr: errors.New("backend complete failed")}
	h.s3Client = c
	id, r := sec38CreateUpload(t, h, "reopen-http-bucket", "obj")
	w := sec38UploadPart(t, r, "reopen-http-bucket", "obj", id, 1, []byte("part"))
	requireStatus(t, w, 200)
	etag := w.Header().Get("ETag")
	xml := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etag)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", "/reopen-http-bucket/obj?uploadId="+id, strings.NewReader(xml)))
	if w.Code == 200 {
		t.Fatal("backend failure unexpectedly succeeded")
	}
	state, err := h.mpuStateStore.Get(context.Background(), id)
	if err != nil || state.Phase != mpu.UploadPhaseOpen {
		t.Fatalf("state not reopened: %+v err=%v", state, err)
	}
	// Read repeatedly to catch stale snapshot/cached metadata regressions.
	for i := 0; i < 3; i++ {
		state, err = h.mpuStateStore.Get(context.Background(), id)
		if err != nil || state.Phase != mpu.UploadPhaseOpen || state.Revision == 0 {
			t.Fatalf("reopened state changed on read %d: %+v err=%v", i, state, err)
		}
	}
}

func TestMPU_BeginEncryptedCompleteSelectedSnapshot(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "begin-complete-helper-*")
	id, r := sec38CreateUpload(t, h, "begin-complete-helper-bucket", "obj")
	w := sec38UploadPart(t, r, "begin-complete-helper-bucket", "obj", id, 1, []byte("part"))
	requireStatus(t, w, http.StatusOK)
	state, err := h.beginEncryptedMPUComplete(context.Background(), id, &CompleteMultipartUpload{Parts: []struct {
		XMLName    xml.Name `xml:"Part"`
		PartNumber int32    `xml:"PartNumber"`
		ETag       string   `xml:"ETag"`
	}{{PartNumber: 1, ETag: w.Header().Get("ETag")}}})
	if err != nil || state == nil || len(state.Parts) != 1 {
		t.Fatalf("begin complete: state=%+v err=%v", state, err)
	}
}
