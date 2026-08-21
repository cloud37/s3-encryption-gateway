package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

type lifecycleFailureStore struct {
	mpu.StateStore
	beginAbortErr       error
	finalizeCompleteErr error
	finalizeAbortErr    error
	deleteCalls         int
}

func (s *lifecycleFailureStore) BeginAbort(ctx context.Context, uploadID string) (uint64, error) {
	if s.beginAbortErr != nil {
		return 0, s.beginAbortErr
	}
	return s.StateStore.BeginAbort(ctx, uploadID)
}

func (s *lifecycleFailureStore) FinalizeComplete(context.Context, string, uint64) error {
	return s.finalizeCompleteErr
}

func (s *lifecycleFailureStore) FinalizeAbort(context.Context, string, uint64) error {
	return s.finalizeAbortErr
}

func (s *lifecycleFailureStore) Delete(context.Context, string) error {
	s.deleteCalls++
	return nil
}

func TestMPU_Handler_CompleteMalformedAndStateUnavailable(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "handler-errors-*")
	id, r := sec38CreateUpload(t, h, "handler-errors-bucket", "obj")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", fmt.Sprintf("/handler-errors-bucket/obj?uploadId=%s", id), strings.NewReader("not xml")))
	require.Equal(t, 400, w.Code)
	realStore := h.mpuStateStore
	h.mpuStateStore = &failOnGetStateStore{StateStore: realStore, getErr: errors.New("state unavailable")}
	t.Cleanup(func() { h.mpuStateStore = realStore })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", fmt.Sprintf("/handler-errors-bucket/obj?partNumber=1&uploadId=%s", id), strings.NewReader("body")))
	require.GreaterOrEqual(t, w.Code, 500)
}

func TestMPU_Handler_AbortStateUnavailableMakesNoBackendCall(t *testing.T) {
	h, base, _ := newMPUTestHandler(t, "abort-state-unavailable-*")
	client := &sec38CountingClient{mpuMockS3Client: base}
	h.s3Client = client
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	id, _ := sec38CreateUpload(t, h, "abort-state-unavailable-bucket", "obj")
	realStore := h.mpuStateStore
	h.mpuStateStore = &failOnGetStateStore{StateStore: realStore, getErr: errors.New("state unavailable")}
	t.Cleanup(func() { h.mpuStateStore = realStore })
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/abort-state-unavailable-bucket/obj?uploadId="+id, nil))
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Equal(t, 0, client.abortCalls)
}

func TestMPU_Handler_FinalizationFailureDoesNotDeleteState(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "complete-finalize-failure-*")
		client := &sec38CountingClient{mpuMockS3Client: base}
		h.s3Client = client
		r := mux.NewRouter()
		h.RegisterRoutes(r)
		id, _ := sec38CreateUpload(t, h, "complete-finalize-failure-bucket", "obj")
		part := sec38UploadPart(t, r, "complete-finalize-failure-bucket", "obj", id, 1, []byte("part"))
		requireStatus(t, part, http.StatusOK)
		store := &lifecycleFailureStore{StateStore: h.mpuStateStore, finalizeCompleteErr: errors.New("finalize failed")}
		h.mpuStateStore = store
		body := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, part.Header().Get("ETag"))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/complete-finalize-failure-bucket/obj?uploadId="+id, strings.NewReader(body)))
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Equal(t, 1, client.completeCalls)
		require.Equal(t, 0, store.deleteCalls)
	})

	t.Run("abort", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "abort-finalize-failure-*")
		client := &sec38CountingClient{mpuMockS3Client: base}
		h.s3Client = client
		r := mux.NewRouter()
		h.RegisterRoutes(r)
		id, _ := sec38CreateUpload(t, h, "abort-finalize-failure-bucket", "obj")
		store := &lifecycleFailureStore{StateStore: h.mpuStateStore, finalizeAbortErr: errors.New("finalize failed")}
		h.mpuStateStore = store
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/abort-finalize-failure-bucket/obj?uploadId="+id, nil))
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		require.Equal(t, 1, client.abortCalls)
		require.Equal(t, 0, store.deleteCalls)
	})
}

func TestMPU_Handler_AbortLifecycleBranches(t *testing.T) {
	t.Run("backend failure reopens", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "abort-branches-*")
		client := &sec38CountingClient{mpuMockS3Client: base, abortErr: errors.New("backend failed")}
		h.s3Client = client
		id, _ := sec38CreateUpload(t, h, "abort-branches-bucket", "obj")
		r := mux.NewRouter()
		h.RegisterRoutes(r)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/abort-branches-bucket/obj?uploadId="+id, nil))
		require.NotEqual(t, http.StatusNoContent, w.Code)
	})
	t.Run("finalize conflict", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "abort-finalize-branch-*")
		client := &sec38CountingClient{mpuMockS3Client: base}
		h.s3Client = client
		id, _ := sec38CreateUpload(t, h, "abort-finalize-branch-bucket", "obj")
		h.mpuStateStore = &lifecycleFailureStore{StateStore: h.mpuStateStore, finalizeAbortErr: mpu.ErrRevisionConflict}
		r := mux.NewRouter()
		h.RegisterRoutes(r)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/abort-finalize-branch-bucket/obj?uploadId="+id, nil))
		require.Equal(t, http.StatusConflict, w.Code)
	})
	t.Run("begin abort conflict", func(t *testing.T) {
		h, base, _ := newMPUTestHandler(t, "abort-begin-branch-*")
		client := &sec38CountingClient{mpuMockS3Client: base}
		h.s3Client = client
		id, _ := sec38CreateUpload(t, h, "abort-begin-branch-bucket", "obj")
		h.mpuStateStore = &lifecycleFailureStore{StateStore: h.mpuStateStore, beginAbortErr: mpu.ErrRevisionConflict}
		r := mux.NewRouter()
		h.RegisterRoutes(r)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/abort-begin-branch-bucket/obj?uploadId="+id, nil))
		require.Equal(t, http.StatusConflict, w.Code)
	})
}

func TestMPU_Handler_CompleteDuplicateAndInvalidETag(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "complete-validation-*")
	id, r := sec38CreateUpload(t, h, "complete-validation-bucket", "obj")
	for _, xml := range []string{
		`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"aa"</ETag></Part><Part><PartNumber>1</PartNumber><ETag>"bb"</ETag></Part></CompleteMultipartUpload>`,
		`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>"not valid!"</ETag></Part></CompleteMultipartUpload>`,
	} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("POST", fmt.Sprintf("/complete-validation-bucket/obj?uploadId=%s", id), strings.NewReader(xml)))
		require.Equal(t, 400, w.Code)
	}
}

func TestMPU_Handler_CompleteReservedMissingAndUncommitted(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "complete-state-errors-*")
	id, r := sec38CreateUpload(t, h, "complete-state-errors-bucket", "obj")
	for _, etag := range []string{`"missing"`, `"reserved"`} {
		w := httptest.NewRecorder()
		xml := fmt.Sprintf(`<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etag)
		r.ServeHTTP(w, httptest.NewRequest("POST", fmt.Sprintf("/complete-state-errors-bucket/obj?uploadId=%s", id), strings.NewReader(xml)))
		require.Equal(t, 400, w.Code)
	}
}
