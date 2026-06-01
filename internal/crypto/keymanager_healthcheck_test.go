package crypto

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockHCKM implements KeyManager for health check tests.
type mockHCKM struct {
	provider       string
	healthErr      error
	healthCallCount atomic.Int32
	mu             sync.Mutex
	blockHealth    chan struct{} // if set, HealthCheck blocks until closed
}

func (m *mockHCKM) Provider() string { return m.provider }

func (m *mockHCKM) WrapKey(_ context.Context, _ []byte, _ map[string]string) (*KeyEnvelope, error) {
	return &KeyEnvelope{KeyID: "k1"}, nil
}

func (m *mockHCKM) UnwrapKey(_ context.Context, _ *KeyEnvelope, _ map[string]string) ([]byte, error) {
	return []byte("pt"), nil
}

func (m *mockHCKM) HealthCheck(_ context.Context) error {
	m.healthCallCount.Add(1)
	if m.blockHealth != nil {
		<-m.blockHealth
	}
	return m.healthErr
}

func (m *mockHCKM) ActiveKeyVersion(_ context.Context) (int, error) { return 1, nil }

func (m *mockHCKM) Close(_ context.Context) error { return nil }

func TestStartKMSHealthCheck_IntervalZero_Noop(t *testing.T) {
	km := &mockHCKM{provider: "test"}
	stop := StartKMSHealthCheck(context.Background(), km, 0)
	require.NotNil(t, stop)
	stop() // should be safe
	time.Sleep(10 * time.Millisecond)
	// HealthCheck should have been called exactly once (initial probe)
	require.Equal(t, int32(1), km.healthCallCount.Load())
}

func TestStartKMSHealthCheck_InitialProbeFires(t *testing.T) {
	var healthy atomic.Bool
	SetKMSHealthyObserver(func(provider string, h bool) {
		healthy.Store(h)
	})
	t.Cleanup(func() { SetKMSHealthyObserver(nil) })

	km := &mockHCKM{provider: "test"}
	stop := StartKMSHealthCheck(context.Background(), km, time.Hour)
	defer stop()

	// Initial probe should have fired synchronously
	require.True(t, healthy.Load(), "initial probe should report healthy")
	require.Equal(t, int32(1), km.healthCallCount.Load(), "initial probe should call HealthCheck once")
}

func TestStartKMSHealthCheck_SetsHealthyTrue(t *testing.T) {
	var (
		recordedProvider string
		recordedHealthy  bool
	)
	SetKMSHealthyObserver(func(provider string, h bool) {
		recordedProvider = provider
		recordedHealthy = h
	})
	t.Cleanup(func() { SetKMSHealthyObserver(nil) })

	km := &mockHCKM{provider: "memory"}
	stop := StartKMSHealthCheck(context.Background(), km, 50*time.Millisecond)
	defer stop()

	// Wait for at least one tick
	time.Sleep(80 * time.Millisecond)

	require.Equal(t, "memory", recordedProvider)
	require.True(t, recordedHealthy)
}

func TestStartKMSHealthCheck_SetsHealthyFalse(t *testing.T) {
	var (
		recordedProvider string
		recordedHealthy  bool
	)
	SetKMSHealthyObserver(func(provider string, h bool) {
		recordedProvider = provider
		recordedHealthy = h
	})
	t.Cleanup(func() { SetKMSHealthyObserver(nil) })

	km := &mockHCKM{
		provider:  "cosmian-kmip",
		healthErr: errors.New("kms unreachable"),
	}
	stop := StartKMSHealthCheck(context.Background(), km, 50*time.Millisecond)
	defer stop()

	// Wait for at least one tick
	time.Sleep(80 * time.Millisecond)

	require.Equal(t, "cosmian-kmip", recordedProvider)
	require.False(t, recordedHealthy)
}

func TestStartKMSHealthCheck_StopExitsGoroutine(t *testing.T) {
	km := &mockHCKM{provider: "test"}

	stop := StartKMSHealthCheck(context.Background(), km, 10*time.Millisecond)
	// Let one tick happen
	time.Sleep(30 * time.Millisecond)

	// Now stop — goroutine should exit
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
		// stop returned — goroutine exited
	case <-time.After(time.Second):
		t.Fatal("stop() did not cause goroutine to exit within 1s")
	}
}

func TestStartKMSHealthCheck_TickInterval(t *testing.T) {
	var callCount atomic.Int32
	SetKMSHealthyObserver(func(_ string, _ bool) {
		callCount.Add(1)
	})
	t.Cleanup(func() { SetKMSHealthyObserver(nil) })

	km := &mockHCKM{provider: "test"}
	// Use a very short interval to verify multiple ticks
	stop := StartKMSHealthCheck(context.Background(), km, 20*time.Millisecond)
	defer stop()

	time.Sleep(65 * time.Millisecond)

	// Initial probe (1) + ticks at 20ms, 40ms, 60ms ≈ 3-4 calls
	calls := callCount.Load()
	require.GreaterOrEqual(t, calls, int32(3), "expected at least 3 health check calls in 65ms with 20ms interval")
	require.LessOrEqual(t, calls, int32(6), "expected at most 6 health check calls in 65ms")
}

func TestStartKMSHealthCheck_CtxCancelled_ExitsGoroutine(t *testing.T) {
	km := &mockHCKM{provider: "test"}

	ctx, cancel := context.WithCancel(context.Background())
	stop := StartKMSHealthCheck(ctx, km, 20*time.Millisecond)

	// Cancel the context — goroutine should exit
	cancel()

	// stop should be safe to call after ctx cancellation
	done := make(chan struct{})
	go func() {
		stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("goroutine did not exit within 1s after ctx cancellation")
	}
}
