package api

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/gorilla/mux"
)

func TestMPU_PartClaim_LegacyStateRequiresAbort(t *testing.T) {
	h, _, mr := newMPUTestHandler(t, "legacy-http-*")
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	id, _ := sec38CreateUpload(t, h, "legacy-http-bucket", "obj")
	key := "mpu:"
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, key) && k != "mpu:writer-version" {
			var raw map[string]interface{}
			_ = json.Unmarshal([]byte(mr.HGet(k, "meta")), &raw)
			raw["state_version"] = float64(1)
			encoded, _ := json.Marshal(raw)
			mr.HSet(k, "meta", string(encoded))
			mr.HSet(k, "state_version", "1")
		}
	}
	w := sec38UploadPart(t, r, "legacy-http-bucket", "obj", id, 1, []byte("data"))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "predates nonce-safety") {
		t.Fatalf("legacy upload: %d %s", w.Code, w.Body.String())
	}
	aw := httptest.NewRecorder()
	r.ServeHTTP(aw, httptest.NewRequest("DELETE", fmt.Sprintf("/legacy-http-bucket/obj?uploadId=%s", id), nil))
	requireStatus(t, aw, http.StatusNoContent)
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
