package api

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/stretchr/testify/require"
)

type corruptCompleteStateStore struct {
	mpu.StateStore
	mutate func(*mpu.UploadState)
}

func (s *corruptCompleteStateStore) BeginComplete(ctx context.Context, id string, parts []mpu.SelectedPart) (*mpu.UploadState, uint64, error) {
	state, revision, err := s.StateStore.BeginComplete(ctx, id, parts)
	if err == nil {
		s.mutate(state)
	}
	return state, revision, err
}

func TestMPUCompleteRejectsInvalidManifestBeforeBackendMutation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*mpu.UploadState)
	}{
		{"wrong ciphertext size", func(s *mpu.UploadState) { s.Parts[0].EncLen++ }},
		{"negative plaintext", func(s *mpu.UploadState) { s.Parts[0].PlainLen = -1 }},
		{"overflowing plaintext total", func(s *mpu.UploadState) { s.Parts[0].PlainLen = math.MaxInt64; s.Parts[1].PlainLen = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, base, _ := newMPUTestHandler(t, "manifest-validation-*")
			client := &sec38CountingClient{mpuMockS3Client: base}
			h.s3Client = client
			id, router := sec38CreateUpload(t, h, "manifest-validation-bucket", "obj")
			var parts strings.Builder
			for number := 1; number <= 2; number++ {
				w := sec38UploadPart(t, router, "manifest-validation-bucket", "obj", id, number, []byte("part"))
				requireStatus(t, w, http.StatusOK)
				fmt.Fprintf(&parts, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", number, w.Header().Get("ETag"))
			}
			h.mpuStateStore = &corruptCompleteStateStore{StateStore: h.mpuStateStore, mutate: tc.mutate}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("POST", "/manifest-validation-bucket/obj?uploadId="+id, strings.NewReader("<CompleteMultipartUpload>"+parts.String()+"</CompleteMultipartUpload>")))
			require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
			require.Zero(t, client.putObjectCalls, "invalid manifest must not be persisted")
			require.Zero(t, client.completeCalls, "invalid manifest must not complete backend upload")
			state, err := h.mpuStateStore.Get(t.Context(), id)
			require.NoError(t, err)
			require.Equal(t, mpu.UploadPhaseOpen, state.Phase, "failed validation must reopen lifecycle")
		})
	}
}
