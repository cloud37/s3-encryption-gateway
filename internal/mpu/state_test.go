package mpu

import (
	"context"
	"crypto/tls"
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
		UploadID:      uploadID,
		Bucket:        "test-bucket",
		Key:           "test/key",
		UploadIDHash:  UploadIDHashB64(uploadID),
		WrappedDEK:    "c29tZXdyYXBwZWRkZWs=",
		IVPrefixHex:   "aabbccddeeff11223344556677889900"[:24], // 12 bytes hex
		Algorithm:     "AES256GCM",
		ChunkSize:     65536,
		PolicySnapshot: PolicySnapshot{EncryptMultipartUploads: true},
		CreatedAt:     time.Now().UTC().Truncate(time.Second),
	}
}

// TestStateStore_RoundTrip exercises Create → AppendPart × 3 → Get → Delete.
func TestStateStore_RoundTrip(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	state := sampleState("upload-roundtrip")
	require.NoError(t, s.Create(ctx, state))

	for i := 1; i <= 3; i++ {
		require.NoError(t, s.AppendPart(ctx, state.UploadID, PartRecord{
			PartNumber: int32(i),
			ETag:       "\"etag\"",
			PlainLen:   8 * 1024 * 1024,
			EncLen:     8*1024*1024 + 2080,
			ChunkCount: 128,
		}))
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

// TestStateStore_TTLRefresh verifies that AppendPart refreshes the expiry.
func TestStateStore_TTLRefresh(t *testing.T) {
	s, mr := newTestStore(t)
	s.ttl = 10 * time.Second
	ctx := context.Background()

	state := sampleState("upload-ttl")
	require.NoError(t, s.Create(ctx, state))

	// Fast-forward 5 seconds — key should still exist.
	mr.FastForward(5 * time.Second)
	require.NoError(t, s.AppendPart(ctx, state.UploadID, PartRecord{PartNumber: 1}))

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

// TestStateStore_AppendPart_Missing verifies ErrUploadNotFound when the upload
// does not exist in Valkey.
func TestStateStore_AppendPart_Missing(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	err := s.AppendPart(ctx, "nonexistent-upload", PartRecord{PartNumber: 1})
	assert.ErrorIs(t, err, ErrUploadNotFound)
}

// TestStateStore_Delete_Missing verifies that deleting a non-existent key is a no-op.
func TestStateStore_Delete_Missing(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	assert.NoError(t, s.Delete(ctx, "no-such-upload"))
}

// TestStateStore_Concurrent_AppendPart verifies that concurrent appends for
// distinct part numbers all survive and appear in the final Get.
func TestStateStore_Concurrent_AppendPart(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	state := sampleState("upload-concurrent")
	require.NoError(t, s.Create(ctx, state))

	const numParts = 10
	errs := make(chan error, numParts)
	for i := 1; i <= numParts; i++ {
		go func(pn int) {
			errs <- s.AppendPart(ctx, state.UploadID, PartRecord{
				PartNumber: int32(pn),
				ETag:       "\"etag\"",
			})
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
	_, err := NewValkeyStateStore(ctx, cfg, "")
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
	store, err := NewValkeyStateStore(ctx, cfg, "")
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
	_, err := NewValkeyStateStore(ctx, cfg, "")
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
	store, err := NewValkeyStateStore(ctx, cfg, "")
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
