package mpu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputePartClaim_InvalidInputsAndLengthMismatch(t *testing.T) {
	validKey := bytes.Repeat([]byte{1}, 32)
	for name, key := range map[string][]byte{"nil key": nil, "empty key": {}} {
		t.Run(name, func(t *testing.T) {
			_, err := ComputePartClaim(key, 1, 1, bytes.NewReader([]byte("x")))
			assert.Error(t, err)
		})
	}
	for name, tc := range map[string]struct {
		part   int32
		length int64
		reader io.Reader
	}{
		"zero part":       {0, 1, bytes.NewReader([]byte("x"))},
		"too large part":  {10001, 1, bytes.NewReader([]byte("x"))},
		"negative length": {1, -1, bytes.NewReader(nil)},
		"nil reader":      {1, 1, nil},
		"short reader":    {1, 2, bytes.NewReader([]byte("x"))},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ComputePartClaim(validKey, tc.part, tc.length, tc.reader)
			assert.Error(t, err)
		})
	}
	_, err := ComputePartClaim(validKey, 1, 1, errorReader{})
	assert.Error(t, err)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestStateStore_CommitPart_ResultGuards(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("commit-guards")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	p.Claim = "wrong"
	assert.ErrorIs(t, s.CommitPart(context.Background(), st.UploadID, p), ErrRevisionConflict)
	p.Claim = "a"
	p.Token = "wrong"
	assert.ErrorIs(t, s.CommitPart(context.Background(), st.UploadID, p), ErrRevisionConflict)
}

func TestStateStore_CommitPart_AlreadyCommittedIdempotent(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("commit-idempotent")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	commitTestPart(t, s, st.UploadID, p, `"e"`)
	p.ETag = `"different"`
	assert.ErrorIs(t, s.CommitPart(context.Background(), st.UploadID, p), ErrRevisionConflict)
	got, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	require.Equal(t, `"e"`, got.Parts[0].ETag)
}

func TestStateStore_CommitPart_MissingPart(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("commit-missing")
	require.NoError(t, s.Create(context.Background(), st))
	assert.ErrorIs(t, s.CommitPart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "a", Token: "a"}), ErrUploadNotFound)
}

func TestStateStore_BeginComplete_EmptyAndWrongOrder(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("complete-errors")
	require.NoError(t, s.Create(context.Background(), st))
	_, _, err := s.BeginComplete(context.Background(), st.UploadID, nil)
	assert.ErrorIs(t, err, ErrCompleteMismatch)
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "a")
	commitTestPart(t, s, st.UploadID, p, `"a"`)
	p = reserveTestPart(t, s, st.UploadID, 2, "b", "b")
	commitTestPart(t, s, st.UploadID, p, `"b"`)
	_, _, err = s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{2, `"b"`}, {1, `"a"`}})
	assert.ErrorIs(t, err, ErrCompleteMismatch)
}

func TestStateStore_ReservePart_AlreadyDoneAndInvalidPhase(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("reserve-matrix")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	commitTestPart(t, s, st.UploadID, p, `"etag"`)
	retry, err := s.ReservePart(context.Background(), st.UploadID, p)
	require.NoError(t, err)
	assert.True(t, retry.AlreadyDone)
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	_, err = s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 2, Claim: "b", PlainLen: 1, Token: "tb"})
	assert.ErrorIs(t, err, ErrInvalidPhase)
	_ = rev
}

func TestStateStore_ReleasePart_RemovesOwnedReservation(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("release-owned")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "claim", "token")
	require.NoError(t, s.ReleasePart(context.Background(), st.UploadID, p.PartNumber, p.Token))

	got, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.Empty(t, got.Parts)
	second, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{
		PartNumber: 1,
		Claim:      "replacement-claim",
		PlainLen:   11,
		Token:      "replacement-token",
	})
	require.NoError(t, err)
	assert.Equal(t, "replacement-token", second.Token)
}

func TestStateStore_ReleasePart_WrongTokenPreservesReservation(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("release-wrong-token")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "claim", "token")
	assert.ErrorIs(t, s.ReleasePart(context.Background(), st.UploadID, p.PartNumber, "other-token"), ErrRevisionConflict)

	got, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	require.Len(t, got.Parts, 1)
	assert.Equal(t, PartStatusReserved, got.Parts[0].Status)
}

func TestStateStore_CompleteLifecycle_SuccessfulReopenAndFinalize(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("complete-lifecycle-success")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "claim", "token")
	commitTestPart(t, s, st.UploadID, p, `"etag"`)
	selected, completingRevision, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"etag"`}})
	require.NoError(t, err)
	require.NotNil(t, selected)
	require.NoError(t, s.Reopen(context.Background(), st.UploadID, completingRevision))
	open, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.Equal(t, UploadPhaseOpen, open.Phase)

	selected, completingRevision, err = s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"etag"`}})
	require.NoError(t, err)
	require.NotNil(t, selected)
	require.NoError(t, s.FinalizeComplete(context.Background(), st.UploadID, completingRevision))
	completed, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.Equal(t, UploadPhaseCompleted, completed.Phase)
}

func TestStateStore_CommitPart_InvalidClaims(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("commit-invalid-inputs")
	require.NoError(t, s.Create(context.Background(), st))
	for name, part := range map[string]PartClaim{
		"zero part":   {PartNumber: 0, Claim: "claim", Token: "token"},
		"large part":  {PartNumber: 10001, Claim: "claim", Token: "token"},
		"empty token": {PartNumber: 1, Claim: "claim"},
		"empty claim": {PartNumber: 1, Token: "token"},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, s.CommitPart(context.Background(), st.UploadID, part))
		})
	}
}

func TestStateStore_LifecycleRejectsTerminalAndStaleRequests(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("lifecycle-terminal-stale")
	require.NoError(t, s.Create(context.Background(), st))
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	_, err = s.BeginAbort(context.Background(), st.UploadID)
	assert.ErrorIs(t, err, ErrInvalidPhase)
	assert.ErrorIs(t, s.FinalizeAbort(context.Background(), st.UploadID, rev-1), ErrRevisionConflict)
	require.NoError(t, s.FinalizeAbort(context.Background(), st.UploadID, rev))
	assert.ErrorIs(t, s.FinalizeAbort(context.Background(), st.UploadID, rev), ErrInvalidPhase)
}

func TestStateStore_ClaimOperations_BackendFailure(t *testing.T) {
	t.Run("reserve", func(t *testing.T) {
		s, mr := newTestStore(t)
		st := sampleState("reserve-backend-failure")
		require.NoError(t, s.Create(context.Background(), st))
		mr.Close()
		_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStateUnavailable)
	})

	t.Run("commit", func(t *testing.T) {
		s, mr := newTestStore(t)
		st := sampleState("commit-backend-failure")
		require.NoError(t, s.Create(context.Background(), st))
		mr.Close()
		err := s.CommitPart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "claim", Token: "token"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStateUnavailable)
	})
}

func TestStateStore_LifecycleOperations_BackendFailure(t *testing.T) {
	t.Run("complete", func(t *testing.T) {
		s, mr := newTestStore(t)
		st := sampleState("complete-backend-failure")
		require.NoError(t, s.Create(context.Background(), st))
		mr.Close()
		_, _, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"etag"`}})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStateUnavailable)
	})

	t.Run("atomic lifecycle", func(t *testing.T) {
		s, mr := newTestStore(t)
		st := sampleState("atomic-backend-failure")
		require.NoError(t, s.Create(context.Background(), st))
		mr.Close()
		err := s.atomicLifecycle(context.Background(), st.UploadID, UploadPhaseOpen, st.Revision, UploadPhaseAborting, st)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStateUnavailable)
	})
}

func TestStateStore_CreateAndReleaseValidation(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	assert.Error(t, s.Create(ctx, nil))

	st := sampleState("release-validation")
	require.NoError(t, s.Create(ctx, st))
	assert.Error(t, s.Create(ctx, st), "duplicate upload must not overwrite state")
	assert.Error(t, s.ReleasePart(ctx, st.UploadID, 0, "token"))
	assert.Error(t, s.ReleasePart(ctx, st.UploadID, 10001, "token"))
	assert.Error(t, s.ReleasePart(ctx, st.UploadID, 1, ""))
	assert.ErrorIs(t, s.ReleasePart(ctx, "missing-release", 1, "token"), ErrUploadNotFound)
}

func TestStateStore_ReleasePart_BackendFailure(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("release-backend-failure")
	require.NoError(t, s.Create(context.Background(), st))
	mr.Close()
	err := s.ReleasePart(context.Background(), st.UploadID, 1, "token")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStateUnavailable)
}

func TestStateStore_SyncControlMeta_EncryptedMetadataFailure(t *testing.T) {
	s, mr := newEncryptedTestStore(t, "sync-meta-failure")
	st := sampleState("sync-meta-failure")
	require.NoError(t, s.Create(context.Background(), st))
	mr.HSet(uploadKey(st.UploadID), fieldMeta, "not ciphertext")
	_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStateDecryptFailed)
}

func TestStateStore_SyncControlMeta_MalformedMetadata(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("sync-meta-malformed")
	require.NoError(t, s.Create(context.Background(), st))
	mr.HSet(uploadKey(st.UploadID), fieldMeta, "not json")
	_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid character")
}

func TestStateStore_ScriptResultValidation(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("script-result-validation")
	require.NoError(t, s.Create(context.Background(), st))
	part := PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"}

	originalReserve := runReservePart
	t.Cleanup(func() { runReservePart = originalReserve })
	for name, result := range map[string]interface{}{
		"not array":        "bad",
		"empty array":      []interface{}{},
		"bad code":         []interface{}{"bad"},
		"missing revision": []interface{}{int64(6)},
		"bad revision":     []interface{}{int64(6), "bad"},
		"unknown code":     []interface{}{int64(99)},
	} {
		t.Run("reserve/"+name, func(t *testing.T) {
			runReservePart = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
				return result, nil
			}
			_, err := s.ReservePart(context.Background(), st.UploadID, part)
			assert.Error(t, err)
		})
	}

	originalCommit := runCommitPart
	t.Cleanup(func() { runCommitPart = originalCommit })
	for name, result := range map[string]interface{}{
		"bad result": "bad", "bad code": "bad", "unknown code": int64(99),
	} {
		t.Run("commit/"+name, func(t *testing.T) {
			runCommitPart = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
				return result, nil
			}
			assert.Error(t, s.CommitPart(context.Background(), st.UploadID, part))
		})
	}

	originalComplete := runBeginComplete
	t.Cleanup(func() { runBeginComplete = originalComplete })
	for name, result := range map[string]interface{}{
		"bad result": "bad", "empty result": []interface{}{}, "bad code": []interface{}{"bad"}, "unknown code": []interface{}{int64(99)},
	} {
		t.Run("complete/"+name, func(t *testing.T) {
			runBeginComplete = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
				return result, nil
			}
			_, _, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"etag"`}})
			assert.Error(t, err)
		})
	}
}

func TestStateStore_AtomicLifecycleResultValidation(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("atomic-result-validation")
	require.NoError(t, s.Create(context.Background(), st))
	original := runAtomicLifecycle
	t.Cleanup(func() { runAtomicLifecycle = original })
	for name, result := range map[string]interface{}{
		"bad result": "bad", "bad code": "bad", "unknown code": int64(99),
	} {
		t.Run(name, func(t *testing.T) {
			runAtomicLifecycle = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
				return result, nil
			}
			err := s.atomicLifecycle(context.Background(), st.UploadID, UploadPhaseOpen, st.Revision, UploadPhaseAborting, st)
			assert.Error(t, err)
		})
	}
}

func TestStateStore_AtomicLifecycleResultCodes(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("atomic-result-codes")
	require.NoError(t, s.Create(context.Background(), st))
	original := runAtomicLifecycle
	t.Cleanup(func() { runAtomicLifecycle = original })
	for _, tc := range []struct {
		name string
		code int64
		want error
	}{
		{"missing", 0, ErrUploadNotFound},
		{"version", 1, ErrInvalidStateVersion},
		{"phase", 2, ErrInvalidPhase},
		{"revision", 3, ErrRevisionConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runAtomicLifecycle = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
				return tc.code, nil
			}
			err := s.atomicLifecycle(context.Background(), st.UploadID, UploadPhaseOpen, st.Revision, UploadPhaseAborting, st)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestStateStore_BeginComplete_MalformedSelectedPart(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("malformed-selected-part")
	require.NoError(t, s.Create(context.Background(), st))
	original := runBeginComplete
	t.Cleanup(func() { runBeginComplete = original })
	runBeginComplete = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
		return []interface{}{int64(4), "not json"}, nil
	}
	_, _, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"etag"`}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "malformed selected part")
	state, getErr := s.Get(context.Background(), st.UploadID)
	require.NoError(t, getErr)
	assert.Equal(t, UploadPhaseOpen, state.Phase)
}

func TestStateStore_BeginAbort_InvalidStateAndTransitionFailure(t *testing.T) {
	t.Run("invalid version", func(t *testing.T) {
		s, mr := newTestStore(t)
		st := sampleState("abort-invalid-version")
		require.NoError(t, s.Create(context.Background(), st))
		meta := mr.HGet(uploadKey(st.UploadID), fieldMeta)
		var state UploadState
		require.NoError(t, json.Unmarshal([]byte(meta), &state))
		state.StateVersion = 9
		updated, err := json.Marshal(&state)
		require.NoError(t, err)
		mr.HSet(uploadKey(st.UploadID), fieldMeta, string(updated), fieldStateVersion, "9")
		_, err = s.BeginAbort(context.Background(), st.UploadID)
		assert.ErrorIs(t, err, ErrInvalidStateVersion)
	})

	t.Run("transition failure", func(t *testing.T) {
		s, _ := newTestStore(t)
		st := sampleState("abort-transition-failure")
		require.NoError(t, s.Create(context.Background(), st))
		original := runAtomicLifecycle
		t.Cleanup(func() { runAtomicLifecycle = original })
		runAtomicLifecycle = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
			return nil, errors.New("lifecycle backend failure")
		}
		_, err := s.BeginAbort(context.Background(), st.UploadID)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStateUnavailable)
		state, getErr := s.Get(context.Background(), st.UploadID)
		require.NoError(t, getErr)
		assert.Equal(t, UploadPhaseOpen, state.Phase)
	})
}

func TestStateStore_LegacyAbortUpgradesAndCleansUp(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("legacy-abort-upgrade")
	require.NoError(t, s.Create(context.Background(), st))
	key := uploadKey(st.UploadID)
	meta := mr.HGet(key, fieldMeta)
	var legacy UploadState
	require.NoError(t, json.Unmarshal([]byte(meta), &legacy))
	legacy.StateVersion = 1
	legacy.Phase = UploadPhaseOpen
	updated, err := json.Marshal(&legacy)
	require.NoError(t, err)
	mr.HSet(key, fieldMeta, string(updated), fieldStateVersion, "1", fieldPhase, "open")

	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	require.NoError(t, s.FinalizeAbort(context.Background(), st.UploadID, rev))
	got, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.Equal(t, UploadPhaseAborted, got.Phase)
	assert.Equal(t, uint8(CurrentStateVersion), got.StateVersion)
	require.NoError(t, s.Delete(context.Background(), st.UploadID))
	assert.Empty(t, mr.HGet(key, fieldMeta))
}

func TestStateStore_V2AbortDoesNotUseLegacyFlag(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("v2-abort")
	st.StateVersion = CurrentStateVersion
	require.NoError(t, s.Create(context.Background(), st))
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	require.NoError(t, s.FinalizeAbort(context.Background(), st.UploadID, rev))
}

func TestStateStore_AtomicLifecycle_EncryptedFailure(t *testing.T) {
	s, _ := newEncryptedTestStore(t, "atomic-encryption-failure")
	st := sampleState("atomic-encryption-failure")
	require.NoError(t, s.Create(context.Background(), st))
	s.stateDEK = nil
	err := s.atomicLifecycle(context.Background(), st.UploadID, UploadPhaseOpen, st.Revision, UploadPhaseAborting, st)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid key size")
}

func TestStateStore_SyncControlMeta_RetryAndBackendFailure(t *testing.T) {
	t.Run("revision retry", func(t *testing.T) {
		s, _ := newTestStore(t)
		st := sampleState("sync-meta-retry")
		require.NoError(t, s.Create(context.Background(), st))
		original := runSyncMeta
		t.Cleanup(func() { runSyncMeta = original })
		calls := 0
		runSyncMeta = func(ctx context.Context, client redis.UniversalClient, keys []string, args ...interface{}) (interface{}, error) {
			calls++
			if calls == 1 {
				return int64(0), nil
			}
			return int64(1), nil
		}
		_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"})
		require.NoError(t, err)
		assert.Equal(t, 2, calls)
	})

	t.Run("backend error", func(t *testing.T) {
		s, _ := newTestStore(t)
		st := sampleState("sync-meta-backend-error")
		require.NoError(t, s.Create(context.Background(), st))
		original := runSyncMeta
		t.Cleanup(func() { runSyncMeta = original })
		runSyncMeta = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
			return nil, errors.New("sync metadata unavailable")
		}
		_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrStateUnavailable)
	})
}
