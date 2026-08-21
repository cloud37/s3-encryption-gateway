package mpu

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	metricsmod "github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestComputePartClaim_DomainAndEncoding(t *testing.T) {
	dek := bytes.Repeat([]byte{0x01}, 32)
	claim, err := ComputePartClaim(dek, 7, 5, bytes.NewReader([]byte("hello")))
	require.NoError(t, err)
	assert.Equal(t, "58147e9be6cf9baffe1c19707befc5b8989c25a901f89de21e52f161cca89e09", fmt.Sprintf("%x", claim))
}

func TestComputePartClaim_IdenticalInputStable(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, 32)
	a, err := ComputePartClaim(dek, 1, 3, bytes.NewReader([]byte("abc")))
	require.NoError(t, err)
	b, err := ComputePartClaim(dek, 1, 3, bytes.NewReader([]byte("abc")))
	require.NoError(t, err)
	assert.Equal(t, a, b)
}

func TestComputePartClaim_PartLengthOrContentDiffers(t *testing.T) {
	dek := bytes.Repeat([]byte{0x42}, 32)
	a, err := ComputePartClaim(dek, 1, 3, bytes.NewReader([]byte("abc")))
	require.NoError(t, err)
	b, err := ComputePartClaim(dek, 1, 4, bytes.NewReader([]byte("abcd")))
	require.NoError(t, err)
	c, err := ComputePartClaim(dek, 1, 3, bytes.NewReader([]byte("abd")))
	require.NoError(t, err)
	assert.NotEqual(t, a, b)
	assert.NotEqual(t, a, c)
}

func TestStateStore_CommitPart_LegacyNoMutation(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("legacy-commit")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	mr.HSet(uploadKey(st.UploadID), fieldStateVersion, "1")
	err := s.CommitPart(context.Background(), st.UploadID, p)
	assert.ErrorIs(t, err, ErrInvalidStateVersion)
	raw := mr.HGet(uploadKey(st.UploadID), "part:1")
	assert.Contains(t, raw, "reserved")
}

func TestStateStore_CreateOverridesLifecycleControls(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("create-controls")
	st.StateVersion = 1
	st.Phase = UploadPhaseAborting
	st.Revision = 99
	require.NoError(t, s.Create(context.Background(), st))
	key := uploadKey(st.UploadID)
	assert.Equal(t, "2", mr.HGet(key, fieldStateVersion))
	assert.Equal(t, "open", mr.HGet(key, fieldPhase))
	assert.Equal(t, "1", mr.HGet(key, fieldRevision))
}

func FuzzReservePartScriptResult(f *testing.F) {
	f.Add("bad", "", true)
	f.Add("0", "", false)
	f.Add("5", `"stored-etag"`, false)
	f.Add("6", "2", false)
	f.Fuzz(func(t *testing.T, value, revision string, injectedError bool) {
		s, _ := newTestStore(t)
		st := sampleState("fuzz-reserve-" + value)
		require.NoError(t, s.Create(context.Background(), st))
		before, err := s.Get(context.Background(), st.UploadID)
		require.NoError(t, err)
		original := runReservePart
		t.Cleanup(func() { runReservePart = original })
		runReservePart = func(context.Context, redis.UniversalClient, []string, ...interface{}) (interface{}, error) {
			if injectedError {
				return nil, errors.New(value)
			}
			if value == "5" || value == "6" {
				return []interface{}{value, revision}, nil
			}
			return []interface{}{value}, nil
		}
		reservation, reserveErr := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"})
		after, getErr := s.Get(context.Background(), st.UploadID)
		require.NoError(t, getErr)
		if value == "5" && revision == `"stored-etag"` && !injectedError {
			require.NoError(t, reserveErr)
			require.True(t, reservation.AlreadyDone)
			require.Equal(t, `"stored-etag"`, reservation.CommittedETag)
			require.Equal(t, before.Revision, after.Revision)
			require.Empty(t, after.Parts)
		} else if value == "6" && revision == "2" && !injectedError {
			require.NoError(t, reserveErr)
			require.Equal(t, uint64(2), reservation.Revision)
			require.Equal(t, before.Revision, after.Revision)
			require.Empty(t, after.Parts)
		} else {
			require.Error(t, reserveErr)
			require.Equal(t, before.Revision, after.Revision)
			require.Empty(t, after.Parts)
		}
	})
}

func FuzzComputePartClaim(f *testing.F) {
	f.Add([]byte("seed"), int32(1))
	f.Fuzz(func(t *testing.T, data []byte, part int32) {
		if part < 1 || part > 10000 {
			return
		}
		_, _ = ComputePartClaim(bytes.Repeat([]byte{1}, 32), part, int64(len(data)), bytes.NewReader(data))
	})
}

func TestStateStore_WriterCapabilityFleetAndLegacyReadiness(t *testing.T) {
	s, mr := newTestStore(t)
	reg := prometheus.NewRegistry()
	s.metrics = metricsmod.NewMetricsWithRegistry(reg)
	assertLegacyGauge := func(want float64) {
		mfs, err := reg.Gather()
		require.NoError(t, err)
		for _, mf := range mfs {
			if mf.GetName() == "gateway_mpu_legacy_inflight" {
				require.Equal(t, want, mf.GetMetric()[0].GetGauge().GetValue())
				return
			}
		}
		t.Fatalf("gateway_mpu_legacy_inflight metric not found")
	}
	s.writerCapability = "deploy-a"
	require.NoError(t, mr.Set(writerCapabilityKey, "deploy-a"))
	require.NoError(t, s.WriterCapabilityReady(context.Background()))
	require.NoError(t, mr.Set("mpu:writer:incompatible", "deploy-b"))
	mr.SetTTL("mpu:writer:incompatible", writerPresenceTTL)
	require.ErrorIs(t, s.WriterCapabilityReady(context.Background()), ErrInvalidStateVersion)
	mr.FastForward(writerPresenceTTL + time.Second)
	require.NoError(t, s.WriterCapabilityReady(context.Background()))
	assertLegacyGauge(0)

	legacy := sampleState("legacy-readiness")
	legacy.StateVersion = 1
	legacy.Phase = ""
	legacy.Revision = 0
	data, err := json.Marshal(legacy)
	require.NoError(t, err)
	mr.HSet(uploadKey(legacy.UploadID), fieldMeta, string(data))
	require.Error(t, s.WriterCapabilityReady(context.Background()))
	assertLegacyGauge(1)
	mr.Del(uploadKey(legacy.UploadID))
	require.NoError(t, s.WriterCapabilityReady(context.Background()))
	assertLegacyGauge(0)
}

func TestValkeyStateStore_WriterCapabilityReady(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	if err := s.WriterCapabilityReady(ctx); err == nil {
		t.Fatal("missing capability must fail closed")
	}
	s.writerCapability = "deploy-a"
	if err := s.WriterCapabilityReady(ctx); err == nil {
		t.Fatal("absent capability must fail closed")
	}
	_ = mr.Set("mpu:writer-version", "deploy-b")
	if err := s.WriterCapabilityReady(ctx); err == nil {
		t.Fatal("mismatched capability must fail")
	}
	_ = mr.Set("mpu:writer-version", "deploy-a")
	if err := s.WriterCapabilityReady(ctx); err != nil {
		t.Fatalf("matching capability: %v", err)
	}
}

func TestValkeyStateStore_LegacyWriterDrainGate(t *testing.T) {
	s, mr := newTestStore(t)
	s.writerCapability = "deploy-a"
	// Legacy binaries never publish writer-presence keys; activation is explicit.
	require.NoError(t, mr.Set(writerCapabilityKey, "legacy-writers-active"))
	require.ErrorIs(t, s.WriterCapabilityReady(context.Background()), ErrInvalidStateVersion)
	require.NoError(t, mr.Set(writerCapabilityKey, "deploy-a"))
	require.NoError(t, s.WriterCapabilityReady(context.Background()))
}

func TestValkeyStateStore_WriterCapabilityBackendFailure(t *testing.T) {
	s, mr := newTestStore(t)
	s.writerCapability = "deploy-a"
	require.NoError(t, mr.Set(writerCapabilityKey, "deploy-a"))
	require.NoError(t, s.client.Close())
	require.ErrorIs(t, s.WriterCapabilityReady(context.Background()), ErrStateUnavailable)
}

func TestValkeyStateStore_LegacyInflightInventoryBranches(t *testing.T) {
	assertGauge := func(t *testing.T, s *ValkeyStateStore, reg *prometheus.Registry, want float64) {
		t.Helper()
		mfs, err := reg.Gather()
		require.NoError(t, err)
		for _, mf := range mfs {
			if mf.GetName() == "gateway_mpu_legacy_inflight" {
				require.Equal(t, want, mf.GetMetric()[0].GetGauge().GetValue())
				return
			}
		}
		t.Fatalf("gateway_mpu_legacy_inflight metric not found")
	}

	newInventoryStore := func(t *testing.T) (*ValkeyStateStore, *miniredis.Miniredis, *prometheus.Registry) {
		t.Helper()
		s, mr := newTestStore(t)
		reg := prometheus.NewRegistry()
		s.metrics = metricsmod.NewMetricsWithRegistry(reg)
		return s, mr, reg
	}

	t.Run("missing meta", func(t *testing.T) {
		s, mr, _ := newInventoryStore(t)
		mr.HSet("mpu:missing-meta", "phase", "open")
		_, err := s.legacyInflightCount(context.Background())
		require.Error(t, err)
	})
	t.Run("bad encrypted metadata", func(t *testing.T) {
		s, mr, _ := newInventoryStore(t)
		s.encryptState = true
		s.stateDEK = bytes.Repeat([]byte{1}, 32)
		mr.HSet("mpu:bad-encrypted", fieldMeta, "not-ciphertext")
		_, err := s.legacyInflightCount(context.Background())
		require.ErrorIs(t, err, ErrStateUnavailable)
	})
	t.Run("allowed plaintext and malformed json", func(t *testing.T) {
		s, mr, _ := newInventoryStore(t)
		s.encryptState = true
		s.allowLegacyPlaintext = true
		s.stateDEK = bytes.Repeat([]byte{1}, 32)
		mr.HSet("mpu:malformed", fieldMeta, "{")
		_, err := s.legacyInflightCount(context.Background())
		require.Error(t, err)
	})
	t.Run("allowed plaintext counted and non-encrypted ignored", func(t *testing.T) {
		s, mr, reg := newInventoryStore(t)
		s.encryptState = true
		s.allowLegacyPlaintext = true
		s.stateDEK = bytes.Repeat([]byte{1}, 32)
		legacy := sampleState("inventory-plaintext")
		legacy.StateVersion = 1
		plaintext, err := json.Marshal(legacy)
		require.NoError(t, err)
		mr.HSet(uploadKey(legacy.UploadID), fieldMeta, string(plaintext))
		mr.HSet("mpu:non-encrypted", fieldMeta, string(plaintext))
		count, err := s.legacyInflightCount(context.Background())
		require.NoError(t, err)
		require.Equal(t, 2, count)
		assertGauge(t, s, reg, 2)
	})
	t.Run("non-encrypted current state ignored", func(t *testing.T) {
		s, mr, reg := newInventoryStore(t)
		current := sampleState("inventory-current-plain")
		current.StateVersion = CurrentStateVersion
		plaintext, err := json.Marshal(current)
		require.NoError(t, err)
		mr.HSet(uploadKey(current.UploadID), fieldMeta, string(plaintext))
		count, err := s.legacyInflightCount(context.Background())
		require.NoError(t, err)
		require.Zero(t, count)
		assertGauge(t, s, reg, 0)
	})
	t.Run("historical encrypted and current ignored", func(t *testing.T) {
		s, mr, reg := newInventoryStore(t)
		s.encryptState = true
		s.stateDEK = bytes.Repeat([]byte{1}, 32)
		legacy := sampleState("inventory-legacy")
		legacy.StateVersion = 1
		current := sampleState("inventory-current")
		current.StateVersion = CurrentStateVersion
		for _, state := range []*UploadState{legacy, current} {
			plaintext, err := json.Marshal(state)
			require.NoError(t, err)
			meta, err := s.EncryptState(plaintext)
			require.NoError(t, err)
			mr.HSet(uploadKey(state.UploadID), fieldMeta, string(meta))
		}
		count, err := s.legacyInflightCount(context.Background())
		require.NoError(t, err)
		require.Equal(t, 1, count)
		assertGauge(t, s, reg, 1)
		mr.Del(uploadKey(legacy.UploadID))
		count, err = s.legacyInflightCount(context.Background())
		require.NoError(t, err)
		require.Zero(t, count)
		assertGauge(t, s, reg, 0)
	})
	t.Run("scan failure", func(t *testing.T) {
		s, _, _ := newInventoryStore(t)
		require.NoError(t, s.client.Close())
		_, err := s.legacyInflightCount(context.Background())
		require.ErrorIs(t, err, ErrStateUnavailable)
	})
}

func TestStateStore_LifecycleMirrorIntegrity(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("mirror-integrity")
	require.NoError(t, s.Create(context.Background(), st))
	key := uploadKey(st.UploadID)
	mr.HSet(key, fieldPhase, "completing")
	_, err := s.Get(context.Background(), st.UploadID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "phase mirror mismatch")
	assert.Equal(t, "completing", mr.HGet(key, fieldPhase))
}

func TestStateStore_ReopenAndFinalizeComplete(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("reopen-finalize")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "a")
	commitTestPart(t, s, st.UploadID, p, `"a"`)
	_, rev, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"a"`}})
	require.NoError(t, err)
	require.NoError(t, s.Reopen(context.Background(), st.UploadID, rev))
	_, rev, err = s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"a"`}})
	require.NoError(t, err)
	require.NoError(t, s.FinalizeComplete(context.Background(), st.UploadID, rev))
}

func TestStateStore_FinalizeAbort(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("finalize-abort")
	require.NoError(t, s.Create(context.Background(), st))
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	require.NoError(t, s.FinalizeAbort(context.Background(), st.UploadID, rev))
	got, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.Equal(t, UploadPhaseAborted, got.Phase)
}

func reserveTestPart(t *testing.T, s *ValkeyStateStore, id string, pn int32, claim, token string) PartClaim {
	t.Helper()
	p := PartClaim{PartNumber: pn, Claim: claim, PlainLen: 3, Token: token}
	_, err := s.ReservePart(context.Background(), id, p)
	require.NoError(t, err)
	return p
}

func commitTestPart(t *testing.T, s *ValkeyStateStore, id string, p PartClaim, etag string) {
	t.Helper()
	p.ETag, p.EncLen, p.ChunkCount = etag, 19, 1
	require.NoError(t, s.CommitPart(context.Background(), id, p))
}

func TestStateStore_ReservePart_FirstClaimWins(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("first-claim")
	require.NoError(t, s.Create(context.Background(), st))
	reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	got, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	require.Len(t, got.Parts, 1)
	assert.Equal(t, "a", got.Parts[0].Claim)
}

func TestStateStore_ReservePart_IdenticalCommittedRetry(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("identical-retry")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	commitTestPart(t, s, st.UploadID, p, `"etag"`)
	r, err := s.ReservePart(context.Background(), st.UploadID, p)
	require.NoError(t, err)
	assert.True(t, r.AlreadyDone)
	assert.Equal(t, `"etag"`, r.CommittedETag)
}

func TestStateStore_ReservePart_ChangedContentRejected(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("changed-retry")
	require.NoError(t, s.Create(context.Background(), st))
	reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "b", PlainLen: 3, Token: "tb"})
	assert.ErrorIs(t, err, ErrPartContentMismatch)
}

func TestStateStore_ReservePart_InProgress(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("in-progress")
	require.NoError(t, s.Create(context.Background(), st))
	reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "a", PlainLen: 3, Token: "tb"})
	assert.ErrorIs(t, err, ErrPartInProgress)
}

func TestStateStore_ReservePart_ConcurrentDifferentContent(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("concurrent-content")
	require.NoError(t, s.Create(context.Background(), st))
	errs := make(chan error, 2)
	for _, claim := range []string{"a", "b"} {
		go func(c string) {
			_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: c, PlainLen: 3, Token: c})
			errs <- err
		}(claim)
	}
	var success, mismatch int
	for i := 0; i < 2; i++ {
		if err := <-errs; err == nil {
			success++
		} else if errors.Is(err, ErrPartContentMismatch) {
			mismatch++
		}
	}
	assert.Equal(t, 1, success)
	assert.Equal(t, 1, mismatch)
}

func TestStateStore_CommitPart_StaleTokenRejected(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("stale-token")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	p.Token = "wrong"
	assert.ErrorIs(t, s.CommitPart(context.Background(), st.UploadID, p), ErrRevisionConflict)
}

func TestStateStore_CommitPart_MatchingRetryAndChangedFieldsRejected(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("commit-fields")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "claim", "token")
	p.ETag, p.EncLen, p.ChunkCount = `"etag"`, 19, 1
	require.NoError(t, s.CommitPart(context.Background(), st.UploadID, p))
	require.NoError(t, s.CommitPart(context.Background(), st.UploadID, p))

	for name, mutate := range map[string]func(*PartClaim){
		"etag":             func(v *PartClaim) { v.ETag = `"other"` },
		"plain length":     func(v *PartClaim) { v.PlainLen++ },
		"encrypted length": func(v *PartClaim) { v.EncLen++ },
		"chunk count":      func(v *PartClaim) { v.ChunkCount++ },
		"token":            func(v *PartClaim) { v.Token = "other-token" },
		"claim":            func(v *PartClaim) { v.Claim = "other-claim" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := p
			mutate(&changed)
			assert.ErrorIs(t, s.CommitPart(context.Background(), st.UploadID, changed), ErrRevisionConflict)
		})
	}
	got, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	require.Len(t, got.Parts, 1)
	assert.Equal(t, p.ETag, got.Parts[0].ETag)
	assert.Equal(t, p.PlainLen, got.Parts[0].PlainLen)
	assert.Equal(t, p.EncLen, got.Parts[0].EncLen)
	assert.Equal(t, p.ChunkCount, got.Parts[0].ChunkCount)
}

func TestStateStore_Lifecycle_StaleRevisionRejected(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("stale-revision")
	require.NoError(t, s.Create(context.Background(), st))
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.ErrorIs(t, s.FinalizeAbort(context.Background(), st.UploadID, rev-1), ErrRevisionConflict)
}

func TestStateStore_BeginComplete_ExactSelectedParts(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("selected-parts")
	require.NoError(t, s.Create(context.Background(), st))
	p1 := reserveTestPart(t, s, st.UploadID, 1, "a", "a")
	commitTestPart(t, s, st.UploadID, p1, `"a"`)
	p2 := reserveTestPart(t, s, st.UploadID, 2, "b", "b")
	commitTestPart(t, s, st.UploadID, p2, `"b"`)
	got, _, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{PartNumber: 2, ETag: `"b"`}})
	require.NoError(t, err)
	require.Len(t, got.Parts, 1)
	assert.Equal(t, int32(2), got.Parts[0].PartNumber)
}

func TestStateStore_BeginComplete_ETagMismatch(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("etag-mismatch")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "a")
	commitTestPart(t, s, st.UploadID, p, `"a"`)
	_, _, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"wrong"`}})
	assert.ErrorIs(t, err, ErrCompleteMismatch)
}

func TestStateStore_BeginComplete_UncommittedPart(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("uncommitted")
	require.NoError(t, s.Create(context.Background(), st))
	reserveTestPart(t, s, st.UploadID, 1, "a", "a")
	_, _, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"a"`}})
	assert.ErrorIs(t, err, ErrCompleteMismatch)
}

func TestStateStore_CompleteAndAbortMutuallyExclusive(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("exclusive")
	require.NoError(t, s.Create(context.Background(), st))
	_, _, err := s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"a"`}})
	assert.ErrorIs(t, err, ErrCompleteMismatch)
	_, err = s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	_, _, err = s.BeginComplete(context.Background(), st.UploadID, []SelectedPart{{1, `"a"`}})
	assert.ErrorIs(t, err, ErrInvalidPhase)
}

// newTestStore starts a miniredis server and returns a ValkeyStateStore backed by it.
func newTestStore(t *testing.T) (*ValkeyStateStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	s := &ValkeyStateStore{
		client: client,
		ttl:    7 * 24 * time.Hour,
	}
	return s, mr
}

func sampleState(uploadID string) *UploadState {
	return &UploadState{
		UploadID:       uploadID,
		Bucket:         "test-bucket",
		Key:            "test/key",
		UploadIDHash:   UploadIDHashB64(uploadID),
		WrappedDEK:     "c29tZXdyYXBwZWRkZWs=",
		IVPrefixHex:    "aabbccddeeff11223344556677889900"[:24], // 12 bytes hex
		Algorithm:      "AES256GCM",
		ChunkSize:      65536,
		PolicySnapshot: PolicySnapshot{EncryptMultipartUploads: true},
		CreatedAt:      time.Now().UTC().Truncate(time.Second),
	}
}

// TestStateStore_RoundTrip exercises Create → ReservePart/CommitPart × 3 → Get → Delete.
func TestStateStore_RoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	state := sampleState("upload-roundtrip")
	require.NoError(t, s.Create(ctx, state))

	for i := 1; i <= 3; i++ {
		claim := PartClaim{PartNumber: int32(i), Claim: fmt.Sprintf("claim-%d", i), PlainLen: 8 * 1024 * 1024, Token: fmt.Sprintf("token-%d", i)}
		_, err := s.ReservePart(ctx, state.UploadID, claim)
		require.NoError(t, err)
		claim.ETag, claim.EncLen, claim.ChunkCount = "\"etag\"", 8*1024*1024+2080, 128
		require.NoError(t, s.CommitPart(ctx, state.UploadID, claim))
	}

	got, err := s.Get(ctx, state.UploadID)
	require.NoError(t, err)
	assert.Equal(t, state.UploadID, got.UploadID)
	assert.Equal(t, state.Bucket, got.Bucket)
	assert.Equal(t, state.WrappedDEK, got.WrappedDEK)
	assert.Equal(t, 3, len(got.Parts))

	require.NoError(t, s.Delete(ctx, state.UploadID))

	_, err = s.Get(ctx, state.UploadID)
	assert.ErrorIs(t, err, ErrUploadNotFound)
}

// TestStateStore_TTLRefresh verifies that ReservePart refreshes the expiry.
func TestStateStore_TTLRefresh(t *testing.T) {
	s, mr := newTestStore(t)
	s.ttl = 10 * time.Second
	ctx := context.Background()

	state := sampleState("upload-ttl")
	require.NoError(t, s.Create(ctx, state))

	// Fast-forward 5 seconds — key should still exist.
	mr.FastForward(5 * time.Second)
	_, err := s.ReservePart(ctx, state.UploadID, PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"})
	require.NoError(t, err)

	// Fast-forward another 8 seconds (total 13 s). Without the TTL refresh the
	// key would have expired at 10 s; after the refresh it lives another 10 s.
	mr.FastForward(8 * time.Second)
	got, err := s.Get(ctx, state.UploadID)
	require.NoError(t, err)
	assert.Equal(t, 1, len(got.Parts))
}

// TestStateStore_WrappedDEK_NotPlaintext asserts the raw Valkey value is not
// the plaintext DEK (it is base64-encoded JSON, not the literal key material).
func TestStateStore_WrappedDEK_NotPlaintext(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	const plaintextDEK = "supersecretkey12345678901234567"
	state := sampleState("upload-dek")
	state.WrappedDEK = "c29tZXdyYXBwZWRkZWs=" // base64 of ciphertext, not the plaintext above

	require.NoError(t, s.Create(ctx, state))

	key := uploadKey(state.UploadID)
	raw := mr.HGet(key, fieldMeta)

	assert.NotContains(t, raw, plaintextDEK, "plaintext DEK must not appear in Valkey value")
}

// TestStateStore_Create_Idempotency verifies that creating the same upload twice
// returns ErrUploadAlreadyExists.
func TestStateStore_Create_Idempotency(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	state := sampleState("upload-idem")
	require.NoError(t, s.Create(ctx, state))
	err := s.Create(ctx, state)
	assert.ErrorIs(t, err, ErrUploadAlreadyExists)
}

// TestStateStore_Get_Missing verifies ErrUploadNotFound on missing key.
func TestStateStore_Get_Missing(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	_, err := s.Get(ctx, "nonexistent-upload")
	assert.ErrorIs(t, err, ErrUploadNotFound)
}

// TestStateStore_ReservePart_Missing verifies ErrUploadNotFound when the upload
// does not exist in Valkey.
func TestStateStore_ReservePart_Missing(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	_, err := s.ReservePart(ctx, "nonexistent-upload", PartClaim{PartNumber: 1, Claim: "claim", PlainLen: 1, Token: "token"})
	assert.ErrorIs(t, err, ErrUploadNotFound)
}

func TestStateStore_ReservePart_InvalidAndLegacyPaths(t *testing.T) {
	s, mr := newTestStore(t)
	st := sampleState("reserve-errors")
	require.NoError(t, s.Create(context.Background(), st))
	_, err := s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 0, Claim: "x", PlainLen: 1, Token: "x"})
	require.Error(t, err)
	mr.HSet(uploadKey(st.UploadID), fieldStateVersion, "1")
	_, err = s.ReservePart(context.Background(), st.UploadID, PartClaim{PartNumber: 1, Claim: "x", PlainLen: 1, Token: "x"})
	assert.ErrorIs(t, err, ErrInvalidStateVersion)
}

func TestStateStore_ReleasePart_Outcomes(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("release-outcomes")
	require.NoError(t, s.Create(context.Background(), st))
	p := reserveTestPart(t, s, st.UploadID, 1, "a", "ta")
	require.NoError(t, s.ReleasePart(context.Background(), st.UploadID, p.PartNumber, p.Token))
	_, err := s.Get(context.Background(), st.UploadID)
	require.NoError(t, err)
	assert.Error(t, s.ReleasePart(context.Background(), st.UploadID, 1, "wrong"))
}

func TestStateStore_BeginAbort_NonOpenRejected(t *testing.T) {
	s, _ := newTestStore(t)
	st := sampleState("abort-nonopen")
	require.NoError(t, s.Create(context.Background(), st))
	rev, err := s.BeginAbort(context.Background(), st.UploadID)
	require.NoError(t, err)
	require.NoError(t, s.FinalizeAbort(context.Background(), st.UploadID, rev))
	_, err = s.BeginAbort(context.Background(), st.UploadID)
	assert.ErrorIs(t, err, ErrInvalidPhase)
}

func TestStateStore_CommitPart_InvalidAndMissing(t *testing.T) {
	s, _ := newTestStore(t)
	require.Error(t, s.CommitPart(context.Background(), "missing", PartClaim{PartNumber: 0}))
}

// TestStateStore_Delete_Missing verifies that deleting a non-existent key is a no-op.
func TestStateStore_Delete_Missing(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	assert.NoError(t, s.Delete(ctx, "no-such-upload"))
}

// TestStateStore_Concurrent_ReservePart verifies that concurrent reservations for
// distinct part numbers all survive and appear in the final Get.
func TestStateStore_Concurrent_ReservePart(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	state := sampleState("upload-concurrent")
	require.NoError(t, s.Create(ctx, state))

	const numParts = 10
	errs := make(chan error, numParts)
	for i := 1; i <= numParts; i++ {
		go func(pn int) {
			_, err := s.ReservePart(ctx, state.UploadID, PartClaim{PartNumber: int32(pn), Claim: fmt.Sprintf("claim-%d", pn), PlainLen: 1, Token: fmt.Sprintf("token-%d", pn)})
			errs <- err
		}(i)
	}

	for i := 0; i < numParts; i++ {
		assert.NoError(t, <-errs)
	}

	got, err := s.Get(ctx, state.UploadID)
	require.NoError(t, err)
	assert.Equal(t, numParts, len(got.Parts))
}

// TestStateStore_HealthCheck_Closed verifies that HealthCheck fails on a
// stopped miniredis.
func TestStateStore_HealthCheck_Closed(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, s.HealthCheck(ctx))

	mr.Close()
	err := s.HealthCheck(ctx)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrStateUnavailable)
}

// TestStateStore_Close verifies graceful Close.
func TestStateStore_Close(t *testing.T) {
	s, _ := newTestStore(t)
	assert.NoError(t, s.Close())
	// Second close should not panic.
	_ = s.Close()
}

// TestNewValkeyStateStore_TLSRequired verifies that startup fails when
// InsecureAllowPlaintext=false and TLS is disabled.
func TestNewValkeyStateStore_TLSRequired(t *testing.T) {
	ctx := context.Background()
	cfg := config.ValkeyConfig{
		Addr:                   "127.0.0.1:6379",
		EncryptState:           config.BoolPtr(false),
		InsecureAllowPlaintext: false,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             604800,
	}
	_, err := NewValkeyStateStore(ctx, cfg, nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStateUnavailable)
	assert.Contains(t, err.Error(), "TLS is required")
}

// TestIVPrefixFromHex roundtrip.
func TestIVPrefixFromHex(t *testing.T) {
	prefix := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	h := "0102030405060708090a0b0c"
	got, err := IVPrefixFromHex(h)
	require.NoError(t, err)
	assert.Equal(t, prefix, got)
}

// TestIVPrefixFromHex_InvalidHex checks error on invalid hex.
func TestIVPrefixFromHex_InvalidHex(t *testing.T) {
	_, err := IVPrefixFromHex("nothex")
	require.Error(t, err)
}

// TestIVPrefixFromHex_WrongLength checks error on wrong byte count.
func TestIVPrefixFromHex_WrongLength(t *testing.T) {
	_, err := IVPrefixFromHex("0102") // only 2 bytes
	require.Error(t, err)
	assert.Contains(t, err.Error(), "12 bytes")
}

// TestNewValkeyStateStore_InsecurePlaintext verifies startup succeeds when
// insecure_allow_plaintext=true and uses a real miniredis.
func TestNewValkeyStateStore_InsecurePlaintext(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()
	cfg := config.ValkeyConfig{
		Addr:                   mr.Addr(),
		EncryptState:           config.BoolPtr(false),
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             60,
		DialTimeout:            2 * time.Second,
		ReadTimeout:            1 * time.Second,
		WriteTimeout:           1 * time.Second,
		PoolSize:               2,
	}
	store, err := NewValkeyStateStore(ctx, cfg, nil, "")
	require.NoError(t, err)
	require.NotNil(t, store)
	assert.NoError(t, store.Close())
}

// TestNewValkeyStateStore_UnreachableAddr verifies startup fails when Valkey is unreachable.
func TestNewValkeyStateStore_UnreachableAddr(t *testing.T) {
	ctx := context.Background()
	cfg := config.ValkeyConfig{
		Addr:                   "127.0.0.1:19999", // nothing listening here
		EncryptState:           config.BoolPtr(false),
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             60,
		DialTimeout:            200 * time.Millisecond,
		ReadTimeout:            200 * time.Millisecond,
		WriteTimeout:           200 * time.Millisecond,
		PoolSize:               1,
	}
	_, err := NewValkeyStateStore(ctx, cfg, nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStateUnavailable)
}

// TestBuildTLSConfig_InvalidCAFile verifies error on bad CA file.
func TestBuildTLSConfig_InvalidCAFile(t *testing.T) {
	_, err := buildTLSConfig(config.ValkeyTLSConfig{
		Enabled: true,
		CAFile:  "/nonexistent/ca.pem",
	})
	require.Error(t, err)
}

// TestBuildTLSConfig_TLS12 verifies TLS 1.2 minimum version is accepted.
func TestBuildTLSConfig_TLS12(t *testing.T) {
	cfg, err := buildTLSConfig(config.ValkeyTLSConfig{
		Enabled:    true,
		MinVersion: "1.2",
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)
}

// TestBuildTLSConfig_TLS13 verifies TLS 1.3 minimum version is accepted.
func TestBuildTLSConfig_TLS13(t *testing.T) {
	cfg, err := buildTLSConfig(config.ValkeyTLSConfig{
		Enabled:    true,
		MinVersion: "1.3",
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
}

// TestBuildTLSConfig_InvalidMinVersion verifies an invalid min_version returns an error.
func TestBuildTLSConfig_InvalidMinVersion(t *testing.T) {
	_, err := buildTLSConfig(config.ValkeyTLSConfig{
		Enabled:    true,
		MinVersion: "1.4",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "min_version")
}

// TestWrapRedisErr_Nil verifies redis.Nil maps to ErrUploadNotFound.
func TestWrapRedisErr_Nil(t *testing.T) {
	err := wrapRedisErr(redis.Nil)
	assert.ErrorIs(t, err, ErrUploadNotFound)
}

// TestWrapRedisErr_Other verifies other errors map to ErrStateUnavailable.
func TestWrapRedisErr_Other(t *testing.T) {
	err := wrapRedisErr(fmt.Errorf("connection refused"))
	assert.ErrorIs(t, err, ErrStateUnavailable)
}

// TestBuildTLSConfig_EmptyCAFile checks error when CA file exists but has no valid certs.
func TestBuildTLSConfig_EmptyCAFile(t *testing.T) {
	// Write an empty file (no valid PEM certs).
	f, err := os.CreateTemp(t.TempDir(), "ca*.pem")
	require.NoError(t, err)
	f.WriteString("not a real cert")
	f.Close()

	_, err = buildTLSConfig(config.ValkeyTLSConfig{
		Enabled: true,
		CAFile:  f.Name(),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no valid certs")
}

// TestBuildTLSConfig_InvalidCertKeyPair checks error on bad cert/key files.
func TestBuildTLSConfig_InvalidCertKeyPair(t *testing.T) {
	dir := t.TempDir()
	certFile := dir + "/cert.pem"
	keyFile := dir + "/key.pem"
	os.WriteFile(certFile, []byte("not a cert"), 0600)
	os.WriteFile(keyFile, []byte("not a key"), 0600)

	_, err := buildTLSConfig(config.ValkeyTLSConfig{
		Enabled:  true,
		CertFile: certFile,
		KeyFile:  keyFile,
	})
	require.Error(t, err)
}

// TestNewValkeyStateStore_PasswordEnv verifies env var password path.
func TestNewValkeyStateStore_PasswordEnv(t *testing.T) {
	mr := miniredis.RunT(t)
	t.Setenv("TEST_VALKEY_PASS", "secret")
	ctx := context.Background()
	cfg := config.ValkeyConfig{
		Addr:                   mr.Addr(),
		EncryptState:           config.BoolPtr(false),
		PasswordEnv:            "TEST_VALKEY_PASS",
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             60,
		DialTimeout:            2 * time.Second,
		ReadTimeout:            1 * time.Second,
		WriteTimeout:           1 * time.Second,
		PoolSize:               2,
	}
	// miniredis doesn't enforce passwords, so the connection succeeds.
	store, err := NewValkeyStateStore(ctx, cfg, nil, "")
	require.NoError(t, err)
	assert.NoError(t, store.Close())
}

// TestStateStore_Delete_NilError verifies Delete on a valid key returns nil.
func TestStateStore_Delete_NilError(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	state := sampleState("upload-del-valid")
	require.NoError(t, s.Create(ctx, state))
	require.NoError(t, s.Delete(ctx, state.UploadID))
}

// TestStateStore_Get_MissingMetaField verifies error when the meta field is absent.
func TestStateStore_Get_MissingMetaField(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	// Manually create a Valkey hash with no "meta" field.
	key := uploadKey("upload-no-meta")
	mr.HSet(key, "part:1", `{"pn":1}`)

	_, err := s.Get(ctx, "upload-no-meta")
	require.Error(t, err)
}

// TestStateStore_Get_InvalidMetaJSON verifies error when meta JSON is malformed.
func TestStateStore_Get_InvalidMetaJSON(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	key := uploadKey("upload-bad-json")
	mr.HSet(key, fieldMeta, "not json at all")

	_, err := s.Get(ctx, "upload-bad-json")
	require.Error(t, err)
}

// TestStateStore_List verifies that List returns all stored upload states.
func TestStateStore_List(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Create a couple of uploads.
	state1 := sampleState("upload-list-1")
	state1.Bucket = "bucket1"
	state2 := sampleState("upload-list-2")
	state2.Bucket = "bucket2"

	require.NoError(t, s.Create(ctx, state1))
	require.NoError(t, s.Create(ctx, state2))

	states, err := s.List(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(states), 2, "expected at least 2 upload states")

	// Verify the results contain both upload IDs.
	found := make(map[string]bool)
	for _, st := range states {
		found[st.UploadID] = true
	}
	assert.True(t, found["upload-list-1"], "missing upload-list-1")
	assert.True(t, found["upload-list-2"], "missing upload-list-2")
}

// TestStateStore_List_Empty verifies List returns empty slice when no uploads exist.
func TestStateStore_List_Empty(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	states, err := s.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, states)
}

// TestBuildTLSConfig_InsecureSkipVerify_Warning verifies that an
// ERROR-level warning is logged when InsecureSkipVerify is enabled.
func TestBuildTLSConfig_InsecureSkipVerify_Warning(t *testing.T) {
	// Capture log output
	var buf strings.Builder
	originalOutput := logrus.StandardLogger().Out
	originalLevel := logrus.StandardLogger().Level
	defer func() {
		logrus.StandardLogger().Out = originalOutput
		logrus.StandardLogger().Level = originalLevel
	}()
	logrus.StandardLogger().Out = &buf
	logrus.StandardLogger().Level = logrus.ErrorLevel

	cfg := config.ValkeyTLSConfig{
		Enabled:            true,
		InsecureSkipVerify: true,
	}

	_, err := buildTLSConfig(cfg)
	require.NoError(t, err)

	logOutput := buf.String()
	assert.Contains(t, logOutput, "InsecureSkipVerify is ENABLED", "expected ERROR log with warning")
	assert.Contains(t, logOutput, "VALKEY_TLS_INSECURE_SKIP_VERIFY", "expected log to mention env var")
	assert.Contains(t, logOutput, "UNSAFE in production", "expected log to mention UNSAFE")
}

// TestBuildTLSConfig_NoInsecureSkipVerify_NoWarning verifies that no
// warning is logged when InsecureSkipVerify is disabled.
func TestBuildTLSConfig_NoInsecureSkipVerify_NoWarning(t *testing.T) {
	// Capture log output
	var buf strings.Builder
	originalOutput := logrus.StandardLogger().Out
	originalLevel := logrus.StandardLogger().Level
	defer func() {
		logrus.StandardLogger().Out = originalOutput
		logrus.StandardLogger().Level = originalLevel
	}()
	logrus.StandardLogger().Out = &buf
	logrus.StandardLogger().Level = logrus.ErrorLevel

	cfg := config.ValkeyTLSConfig{
		Enabled:            true,
		InsecureSkipVerify: false,
	}

	_, err := buildTLSConfig(cfg)
	require.NoError(t, err)

	logOutput := buf.String()
	assert.NotContains(t, logOutput, "InsecureSkipVerify is ENABLED", "expected no warning when InsecureSkipVerify is false")
}

// TestMPUState_ActiveUploadsGauge_IncDec verifies that Create increments and
// Delete decrements the gateway_mpu_active_uploads gauge (V1.0-OBS-1 G7).
func TestMPUState_ActiveUploadsGauge_IncDec(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := metricsmod.NewMetricsWithRegistry(reg)

	s, _ := newTestStore(t)
	s.metrics = m

	ctx := context.Background()
	state := sampleState("upload-gauge-test")

	// Create should increment the gauge.
	require.NoError(t, s.Create(ctx, state))

	assertGauge := func(want float64) {
		t.Helper()
		mfs, err := reg.Gather()
		require.NoError(t, err)
		for _, mf := range mfs {
			if mf.GetName() == "gateway_mpu_active_uploads" {
				got := mf.GetMetric()[0].GetGauge().GetValue()
				if got != want {
					t.Errorf("gateway_mpu_active_uploads = %v, want %v", got, want)
				}
				return
			}
		}
		t.Errorf("gateway_mpu_active_uploads metric not found (want %v)", want)
	}

	assertGauge(1)

	// Delete should decrement the gauge.
	require.NoError(t, s.Delete(ctx, state.UploadID))
	assertGauge(0)
}
