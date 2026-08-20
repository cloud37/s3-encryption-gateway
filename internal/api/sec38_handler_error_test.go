package api

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

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
