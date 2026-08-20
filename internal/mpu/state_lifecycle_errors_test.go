package mpu

import (
	"context"
	"fmt"
	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestStateStore_BeginComplete_MissingVersionAndRevision(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("complete-lifecycle-errors")
	require.NoError(t, s.Create(context.Background(), st))
	key := uploadKey(st.UploadID)
	mr.HSet(key, fieldStateVersion, "1")
	_, _, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"x"`}})
	assert.Error(t, err)
	mr.HSet(key, fieldStateVersion, "2", fieldRevision, "99")
	_, _, err = s.BeginComplete(context.Background(), st.UploadID, nil)
	assert.ErrorIs(t, err, ErrCompleteMismatch)
}

func TestStateStore_BeginAbort_MissingAndRevision(t *testing.T) {
	s, _ := newTestStore(t)
	_, err := s.BeginAbort(context.Background(), "no-upload")
	assert.ErrorIs(t, err, ErrUploadNotFound)
	st := sampleState("abort-revision-errors")
	require.NoError(t, s.Create(context.Background(), st))
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.ErrorIs(t, s.FinalizeAbort(context.Background(), st.UploadID, rev-1), ErrRevisionConflict)
}

func TestStateStore_ReopenAbortingRequiresMatchingRevision(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("reopen-aborting-revision")
	require.NoError(t, s.Create(context.Background(), st))
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.ErrorIs(t, s.Reopen(context.Background(), st.UploadID, rev-1), ErrRevisionConflict)
	state, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.Equal(t, UploadPhaseAborting, state.Phase)
	require.NoError(t, s.Reopen(context.Background(), st.UploadID, rev))
	state, err = s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.Equal(t, UploadPhaseOpen, state.Phase)
}

func TestStateStore_ReopenRejectsOpenPhase(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("reopen-open-phase")
	require.NoError(t, s.Create(context.Background(), st))
	assert.ErrorIs(t, s.Reopen(context.Background(), st.UploadID, st.Revision), ErrInvalidPhase)
}

func TestStateStore_ReopenAbortingBackendFailure(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("reopen-aborting-backend")
	require.NoError(t, s.Create(context.Background(), st))
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	mr.Close()
	assert.ErrorIs(t, s.Reopen(context.Background(), st.UploadID, rev), ErrStateUnavailable)
}

func TestStateStore_Get_RejectsAuthenticatedControlMirrorDrift(t *testing.T) {
	for name, mutate := range map[string]func(*miniredis.Miniredis, string){
		"version":  func(mr *miniredis.Miniredis, key string) { mr.HSet(key, fieldStateVersion, "9") },
		"phase":    func(mr *miniredis.Miniredis, key string) { mr.HSet(key, fieldPhase, string(UploadPhaseAborting)) },
		"revision": func(mr *miniredis.Miniredis, key string) { mr.HSet(key, fieldRevision, "99") },
	} {
		t.Run(name, func(t *testing.T) {
			s, mr := newTestStore(t)
			st := sampleState("mirror-drift-" + name)
			require.NoError(t, s.Create(context.Background(), st))
			mutate(mr, uploadKey(st.UploadID))
			_, err := s.Get(context.Background(), st.UploadID)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "mirror mismatch")
		})
	}
}

func TestStateStore_Get_ControlMirrorsStaySynchronizedAcrossTransitions(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("mirror-sync")
	require.NoError(t, s.Create(context.Background(), st))
	assertMirrorsMatch(t, mr, st.UploadID, s)
	part := reserveTestPart(t, s, st.UploadID, 1, "claim", "token")
	commitTestPart(t, s, st.UploadID, part, `"etag"`)
	assertMirrorsMatch(t, mr, st.UploadID, s)
	_, revision, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"etag"`}})
	require.NoError(t, err)
	assertMirrorsMatch(t, mr, st.UploadID, s)
	require.NoError(t, s.Reopen(context.Background(), st.UploadID, revision))
	assertMirrorsMatch(t, mr, st.UploadID, s)
}

func assertMirrorsMatch(t *testing.T, mr *miniredis.Miniredis, uploadID string, s *ValkeyStateStore) {
	t.Helper()
	state, err := s.Get(context.Background(), uploadID)
	require.NoError(t, err)
	key := uploadKey(uploadID)
	assert.Equal(t, fmt.Sprint(state.StateVersion), mr.HGet(key, fieldStateVersion))
	assert.Equal(t, string(state.Phase), mr.HGet(key, fieldPhase))
	assert.Equal(t, fmt.Sprint(state.Revision), mr.HGet(key, fieldRevision))
}
