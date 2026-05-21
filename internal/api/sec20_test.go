package api

// V1.0-SEC-20: Cached Policy Engines Never Closed — Passwords Linger
//
// These tests verify that the TTL-based engine cache properly evicts
// expired engines and calls Close() on them, and that the Handler shutdown
// path closes all remaining cached engines.

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
)

// mockEngine is a minimal EncryptionEngine that tracks Close() calls.
type mockEngine struct {
	closeCount int
}

func (m *mockEngine) Encrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	return reader, metadata, nil
}

func (m *mockEngine) Decrypt(ctx context.Context, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	return reader, metadata, nil
}

func (m *mockEngine) DecryptRange(ctx context.Context, reader io.Reader, metadata map[string]string, _, _ int64) (io.Reader, map[string]string, error) {
	return reader, metadata, nil
}

func (m *mockEngine) IsEncrypted(metadata map[string]string) bool {
	return false
}

func (m *mockEngine) PreferredAlgorithm() string {
	return crypto.AlgorithmAES256GCM
}

func (m *mockEngine) Close() error {
	m.closeCount++
	return nil
}

// TestSEC20_TTLCache_GetOrStore_Deduplication verifies that when two
// engines are concurrently created for the same policy ID, only one is kept
// in the cache and the redundant one is closed.
func TestSEC20_TTLCache_GetOrStore_Deduplication(t *testing.T) {
	c := newTTLEngineCache(time.Hour, time.Minute)
	// Prevent the sweep goroutine from running so we control timing.
	// We call start() manually only when needed, but here GetOrStore starts it.

	e1 := &mockEngine{}
	e2 := &mockEngine{}

	ret1 := c.GetOrStore("policy-1", e1)
	ret2 := c.GetOrStore("policy-1", e2)

	if ret1 != ret2 {
		t.Errorf("GetOrStore should return the same engine for the same key; got different pointers")
	}
	if ret1 != e1 && ret2 != e1 {
		t.Errorf("expected the first stored engine to win")
	}
	if e2.closeCount != 1 {
		t.Errorf("redundant engine should be closed exactly once; got %d", e2.closeCount)
	}
	if e1.closeCount != 0 {
		t.Errorf("winning engine should not be closed; got %d", e1.closeCount)
	}

	c.Stop()
}

// TestSEC20_TTLCache_Get_EvictsExpiredEntry verifies that Get() detects an
// expired entry, removes it from the cache, and calls Close().
func TestSEC20_TTLCache_Get_EvictsExpiredEntry(t *testing.T) {
	c := newTTLEngineCache(1*time.Millisecond, time.Hour) // long sweep, short TTL

	e := &mockEngine{}
	c.GetOrStore("policy-1", e)

	// Wait for the entry to expire.
	time.Sleep(50 * time.Millisecond)

	eng, ok := c.Get("policy-1")
	if ok {
		t.Error("expected Get to return false for expired entry")
	}
	if eng != nil {
		t.Error("expected Get to return nil engine for expired entry")
	}
	if e.closeCount != 1 {
		t.Errorf("expired engine should be closed; got %d", e.closeCount)
	}

	c.Stop()
}

// TestSEC20_TTLCache_Get_ReturnsActiveEntry verifies that Get() returns an
// unexpired engine and does not close it.
func TestSEC20_TTLCache_Get_ReturnsActiveEntry(t *testing.T) {
	c := newTTLEngineCache(time.Hour, time.Minute)

	e := &mockEngine{}
	c.GetOrStore("policy-1", e)

	eng, ok := c.Get("policy-1")
	if !ok {
		t.Error("expected Get to return true for active entry")
	}
	if eng != e {
		t.Error("expected Get to return the exact stored engine")
	}
	if e.closeCount != 0 {
		t.Errorf("active engine should not be closed; got %d", e.closeCount)
	}

	c.Stop()
}

// TestSEC20_TTLCache_SweepClosesExpiredEntries verifies that the background
// sweep goroutine closes expired entries.
func TestSEC20_TTLCache_SweepClosesExpiredEntries(t *testing.T) {
	c := newTTLEngineCache(1*time.Millisecond, 20*time.Millisecond)

	e := &mockEngine{}
	c.GetOrStore("policy-1", e)

	// Wait for both the TTL to expire and the sweep to run.
	time.Sleep(100 * time.Millisecond)

	// Stop the cache to ensure the sweep goroutine has exited before we
	// inspect the close counter (avoids a benign test race).
	c.Stop()

	if e.closeCount != 1 {
		t.Errorf("sweep should close expired engine; got %d", e.closeCount)
	}
}

// TestSEC20_TTLCache_StopClosesAllRemaining verifies that Stop() calls Close()
// on every engine still in the cache.
func TestSEC20_TTLCache_StopClosesAllRemaining(t *testing.T) {
	c := newTTLEngineCache(time.Hour, time.Minute)

	e1 := &mockEngine{}
	e2 := &mockEngine{}
	c.GetOrStore("policy-1", e1)
	c.GetOrStore("policy-2", e2)

	c.Stop()

	if e1.closeCount != 1 {
		t.Errorf("Stop should close engine-1; got %d", e1.closeCount)
	}
	if e2.closeCount != 1 {
		t.Errorf("Stop should close engine-2; got %d", e2.closeCount)
	}
}

// TestSEC20_HandlerClose_CallsEngineClose verifies that Handler.Close()
// delegates to the underlying TTL cache and closes all cached engines.
func TestSEC20_HandlerClose_CallsEngineClose(t *testing.T) {
	// Construct a minimal handler with only the engineCache field set.
	h := &Handler{
		engineCache: newTTLEngineCache(time.Hour, time.Minute),
	}

	e1 := &mockEngine{}
	e2 := &mockEngine{}
	h.engineCache.GetOrStore("policy-a", e1)
	h.engineCache.GetOrStore("policy-b", e2)

	h.Close()

	if e1.closeCount != 1 {
		t.Errorf("Handler.Close should close engine-a; got %d", e1.closeCount)
	}
	if e2.closeCount != 1 {
		t.Errorf("Handler.Close should close engine-b; got %d", e2.closeCount)
	}
	if h.engineCache != nil {
		t.Error("Handler.Close should nil out engineCache")
	}
}

// TestSEC20_HandlerNoPolicyManager_NoLeak verifies that a Handler created
// without a PolicyManager does not start a sweep goroutine and Close() is a
// safe no-op.
func TestSEC20_HandlerNoPolicyManager_NoLeak(t *testing.T) {
	// A handler created without a policyManager has a nil engineCache.
	h := &Handler{}

	// Close should be a safe no-op.
	h.Close()
}

// TestSEC20_TTLCache_StopIdempotent verifies that calling Stop() multiple
// times does not panic.
func TestSEC20_TTLCache_StopIdempotent(t *testing.T) {
	c := newTTLEngineCache(time.Hour, time.Minute)
	c.Stop()
	c.Stop() // should not panic
}

// enforce that mockEngine satisfies the EncryptionEngine interface.
var _ crypto.EncryptionEngine = (*mockEngine)(nil)
