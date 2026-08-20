package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/stretchr/testify/require"
)

type sec38FailingKM struct{ crypto.KeyManager }

type sec38ReserveErrorStore struct {
	mpu.StateStore
	reserveErr error
}

func (s *sec38ReserveErrorStore) ReservePart(context.Context, string, mpu.PartClaim) (mpu.Reservation, error) {
	return mpu.Reservation{}, s.reserveErr
}

func (sec38FailingKM) UnwrapKey(context.Context, *crypto.KeyEnvelope, map[string]string) ([]byte, error) {
	return nil, errors.New("unwrap failed")
}

func TestMPU_Handler_UnwrapAndMalformedCompleteBranches(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "branch-errors-*")
	id, r := sec38CreateUpload(t, h, "branch-errors-bucket", "obj")
	h.keyManager = sec38FailingKM{h.keyManager}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("PUT", fmt.Sprintf("/branch-errors-bucket/obj?partNumber=1&uploadId=%s", id), bytes.NewReader([]byte("data"))))
	require.GreaterOrEqual(t, w.Code, 400)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("POST", fmt.Sprintf("/branch-errors-bucket/obj?uploadId=%s", id), strings.NewReader("<bad")))
	require.Equal(t, 400, w.Code)
	require.Contains(t, w.Body.String(), "MalformedXML")
}

func TestMPU_Handler_ReservationOutcomeErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		want   string
	}{
		{name: "backend", err: errors.New("reserve unavailable"), status: 503, want: "ServiceUnavailable"},
		{name: "mismatch", err: mpu.ErrPartContentMismatch, status: 409, want: "OperationAborted"},
		{name: "in-progress", err: mpu.ErrPartInProgress, status: 409, want: "OperationAborted"},
		{name: "legacy-rejected", err: mpu.ErrInvalidStateVersion, status: 409, want: "OperationAborted"},
		{name: "invalid-phase", err: mpu.ErrInvalidPhase, status: 409, want: "OperationAborted"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bucket := "reserve-outcome-" + strings.ReplaceAll(tc.name, "-", "") + "-bucket"
			h, base, _ := newMPUTestHandler(t, bucket+"-*")
			client := &sec38CountingClient{mpuMockS3Client: base}
			h.s3Client = client
			id, r := sec38CreateUpload(t, h, bucket, "obj")
			realStore := h.mpuStateStore
			h.mpuStateStore = &sec38ReserveErrorStore{StateStore: realStore, reserveErr: tc.err}
			t.Cleanup(func() { h.mpuStateStore = realStore })

			w := sec38UploadPart(t, r, bucket, "obj", id, 1, []byte("data"))
			require.Equal(t, tc.status, w.Code, w.Body.String())
			require.Contains(t, w.Body.String(), tc.want)
			require.Zero(t, client.uploadPartCalls)
			require.Zero(t, client.destinationEncryptCalls)
		})
	}
}

func TestMPU_Handler_ReservationBufferAndUnwrapErrors(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "reserve-buffer-*")
	id, r := sec38CreateUpload(t, h, "reserve-buffer-bucket", "obj")
	h.config.Server.MaxPartBuffer = 2
	w := sec38UploadPart(t, r, "reserve-buffer-bucket", "obj", id, 1, []byte("too large"))
	require.Equal(t, 413, w.Code)
	require.Contains(t, w.Body.String(), "EntityTooLarge")

	h.config.Server.MaxPartBuffer = 64 << 20
	h.keyManager = sec38FailingKM{h.keyManager}
	w = sec38UploadPart(t, r, "reserve-buffer-bucket", "obj", id, 1, []byte("data"))
	require.Equal(t, 500, w.Code)
	require.Contains(t, w.Body.String(), "Failed to prepare")
}

func TestCopyPartClaimErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		name, code, result string
		err                error
		status             int
	}{
		{"backend", "ServiceUnavailable", "mismatch", errors.New("backend"), 503},
		{"mismatch", "OperationAborted", "mismatch", mpu.ErrPartContentMismatch, 409},
		{"in-progress", "OperationAborted", "in_progress", mpu.ErrPartInProgress, 409},
		{"legacy", "OperationAborted", "legacy_rejected", mpu.ErrInvalidStateVersion, 409},
		{"phase", "OperationAborted", "mismatch", mpu.ErrInvalidPhase, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, status, _, result := copyPartClaimError(tc.err)
			require.Equal(t, tc.code, code)
			require.Equal(t, tc.status, status)
			require.Equal(t, tc.result, result)
		})
	}
}
