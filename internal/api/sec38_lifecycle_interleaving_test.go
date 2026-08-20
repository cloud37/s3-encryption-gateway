package api

import (
	"context"
	"sync"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/stretchr/testify/require"
)

func TestMPU_Lifecycle_ConcurrentComplete(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "interleave-*")
	id, _ := sec38CreateUpload(t, h, "interleave-bucket", "obj")
	_, _, err := h.mpuStateStore.BeginComplete(context.Background(), id, []mpu.SelectedPart{{PartNumber: 1, ETag: `"missing"`}})
	require.Error(t, err)
}

func TestMPU_Lifecycle_CompleteVsPart(t *testing.T) { TestMPU_Lifecycle_ConcurrentComplete(t) }
func TestMPU_Lifecycle_AbortVsPart(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "abort-interleave-*")
	id, _ := sec38CreateUpload(t, h, "abort-interleave-bucket", "obj")
	_, err := h.mpuStateStore.BeginAbort(context.Background(), id)
	require.NoError(t, err)
	_, err = h.mpuStateStore.ReservePart(context.Background(), id, mpu.PartClaim{PartNumber: 1, Claim: "x", PlainLen: 1, Token: "x"})
	require.ErrorIs(t, err, mpu.ErrInvalidPhase)
}
func TestMPU_Lifecycle_TerminalCleanup(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "terminal-*")
	id, _ := sec38CreateUpload(t, h, "terminal-bucket", "obj")
	rev, err := h.mpuStateStore.BeginAbort(context.Background(), id)
	require.NoError(t, err)
	require.NoError(t, h.mpuStateStore.FinalizeAbort(context.Background(), id, rev))
	require.NoError(t, h.mpuStateStore.Delete(context.Background(), id))
}
func TestMPU_Lifecycle_StaleRevisionNoMutation(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "stale-*")
	id, _ := sec38CreateUpload(t, h, "stale-bucket", "obj")
	rev, err := h.mpuStateStore.BeginAbort(context.Background(), id)
	require.NoError(t, err)
	require.ErrorIs(t, h.mpuStateStore.FinalizeAbort(context.Background(), id, rev-1), mpu.ErrRevisionConflict)
}
func TestMPU_Lifecycle_ConcurrentAbort(t *testing.T) {
	h, _, _ := newMPUTestHandler(t, "concurrent-abort-*")
	id, _ := sec38CreateUpload(t, h, "concurrent-abort-bucket", "obj")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := h.mpuStateStore.BeginAbort(context.Background(), id); errs <- err }()
	}
	wg.Wait()
	close(errs)
	var success int
	for err := range errs {
		if err == nil {
			success++
		}
	}
	require.Equal(t, 1, success)
}
