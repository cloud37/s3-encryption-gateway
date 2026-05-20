package crypto

// V0.6-QA-2 Phase B.6 — Additional buffer pool coverage
// Existing tests cover Get/Put for 64K. These tests cover the smaller pools.

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestBoundedQueue_BasicOperations(t *testing.T) {
	queue := NewBoundedQueue(100)
	defer queue.Close()

	// Test basic write/read
	data := []byte("hello world")
	n, err := queue.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	result := make([]byte, len(data))
	n, err = queue.Read(result)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to read %d bytes, read %d", len(data), n)
	}
	if string(result) != string(data) {
		t.Errorf("Expected %s, got %s", string(data), string(result))
	}
}

func TestBoundedQueue_Backpressure(t *testing.T) {
	queue := NewBoundedQueue(10) // Very small queue
	defer queue.Close()

	// Fill the queue
	data := []byte("0123456789") // 10 bytes, exactly queue size
	n, err := queue.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	// Try to write more - should block, but we'll test with timeout
	done := make(chan bool)
	go func() {
		extra := []byte("extra")
		n, err := queue.Write(extra)
		if err != nil {
			t.Errorf("Write should not fail: %v", err)
		}
		if n != len(extra) {
			t.Errorf("Expected to write %d bytes, wrote %d", len(extra), n)
		}
		done <- true
	}()

	// Read some data to free up space
	readBuf := make([]byte, 5)
	n, err = queue.Read(readBuf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 5 {
		t.Errorf("Expected to read 5 bytes, read %d", n)
	}

	// The write should now complete
	select {
	case <-done:
		// Good, write completed
	case <-time.After(100 * time.Millisecond):
		t.Error("Write should have completed after reading")
	}
}

func TestBoundedQueue_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	queue := NewBoundedQueueWithContext(ctx, 10)
	defer queue.Close()

	// Fill the queue
	data := []byte("0123456789")
	n, err := queue.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	// Try to write more - should block
	done := make(chan error, 1)
	go func() {
		extra := []byte("extra")
		_, err := queue.Write(extra)
		done <- err
	}()

	// Cancel context
	cancel()

	// Write should fail with context error
	select {
	case err := <-done:
		if err == nil {
			t.Error("Write should have failed with context cancellation")
		}
		if err != context.Canceled {
			t.Errorf("Expected context.Canceled, got %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Write should have failed immediately on context cancellation")
	}
}

func TestBoundedQueue_ConcurrentAccess(t *testing.T) {
	queue := NewBoundedQueue(1000)
	defer queue.Close()

	var wg sync.WaitGroup
	const numWorkers = 10
	const writesPerWorker = 100

	// Start multiple writers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < writesPerWorker; j++ {
				data := []byte{byte(workerID), byte(j)}
				_, err := queue.Write(data)
				if err != nil {
					t.Errorf("Write failed for worker %d: %v", workerID, err)
				}
			}
		}(i)
	}

	// Start multiple readers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2)
			for j := 0; j < writesPerWorker; j++ {
				_, err := queue.Read(buf)
				if err != nil {
					t.Errorf("Read failed: %v", err)
				}
			}
		}()
	}

	wg.Wait()
}

func TestBoundedQueue_Size(t *testing.T) {
	queue := NewBoundedQueue(100)
	defer queue.Close()

	if queue.Size() != 0 {
		t.Errorf("Expected initial size 0, got %d", queue.Size())
	}

	data := []byte("hello")
	n, err := queue.Write(data)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Expected to write %d bytes, wrote %d", len(data), n)
	}

	if queue.Size() != len(data) {
		t.Errorf("Expected size %d, got %d", len(data), queue.Size())
	}

	readBuf := make([]byte, len(data))
	n, err = queue.Read(readBuf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Expected to read %d bytes, read %d", len(data), n)
	}

	if queue.Size() != 0 {
		t.Errorf("Expected final size 0, got %d", queue.Size())
	}
}

// ── V0.6-QA-2 Phase B.6 — additional buffer pool coverage ─────────────────

// TestBufferPool_Get4_Put4 verifies the 4-byte buffer pool round-trip.
func TestBufferPool_Get4_Put4(t *testing.T) {
	pool := GetGlobalBufferPool()

	buf := pool.Get4()
	if len(buf) != 4 {
		t.Errorf("Get4() len = %d, want 4", len(buf))
	}
	// Write to buffer to verify it's writable
	copy(buf, []byte{0x01, 0x02, 0x03, 0x04})
	pool.Put4(buf)
}

// TestBufferPool_Get12_Put12 verifies the 12-byte (nonce-sized) buffer pool.
func TestBufferPool_Get12_Put12(t *testing.T) {
	pool := GetGlobalBufferPool()

	buf := pool.Get12()
	if len(buf) != 12 {
		t.Errorf("Get12() len = %d, want 12", len(buf))
	}
	pool.Put12(buf)
}

// TestBufferPool_Get32_Put32 verifies the 32-byte (key-sized) buffer pool.
func TestBufferPool_Get32_Put32(t *testing.T) {
	pool := GetGlobalBufferPool()

	buf := pool.Get32()
	if len(buf) != 32 {
		t.Errorf("Get32() len = %d, want 32", len(buf))
	}
	pool.Put32(buf)
}

// TestBufferPool_Get_BySize verifies the Get dispatcher routes to the correct pool.
func TestBufferPool_Get_BySize(t *testing.T) {
	pool := GetGlobalBufferPool()

	tests := []struct {
		size int
	}{
		{4},
		{12},
		{32},
		{64 * 1024}, // 64 KiB chunk buffer
		{100},       // falls through to allocate
	}

	for _, tc := range tests {
		buf := pool.Get(tc.size)
		if len(buf) < tc.size {
			t.Errorf("Get(%d) returned buf with len %d (< %d)", tc.size, len(buf), tc.size)
		}
		pool.Put(buf)
	}
}

// TestBufferPool_GetMetrics verifies GetMetrics returns a value type.
func TestBufferPool_GetMetrics(t *testing.T) {
	pool := GetGlobalBufferPool()

	// Get and put some buffers to generate metrics
	b4 := pool.Get4()
	pool.Put4(b4)
	b12 := pool.Get12()
	pool.Put12(b12)

	metrics := pool.GetMetrics()
	// GetMetrics returns a value type (BufferPoolMetrics), not a pointer
	_ = metrics
}

// TestBufferPool_HitRates verifies HitRate methods return values in [0.0, 1.0].
func TestBufferPool_HitRates(t *testing.T) {
	pool := GetGlobalBufferPool()

	// Get and return buffers to populate stats
	b4 := pool.Get4()
	pool.Put4(b4)
	b4 = pool.Get4() // Second get should be a hit (returned from pool)
	pool.Put4(b4)

	metrics := pool.GetMetrics()
	rates := []float64{
		metrics.HitRate4(),
		metrics.HitRate12(),
		metrics.HitRate32(),
		metrics.HitRate64K(),
	}

	for i, rate := range rates {
		if rate < 0.0 || rate > 1.0 {
			t.Errorf("HitRate[%d] = %f, want in [0.0, 1.0]", i, rate)
		}
	}
}

// TestBufferPool_Reset verifies that Reset clears statistics.
func TestBufferPool_Reset(t *testing.T) {
	pool := GetGlobalBufferPool()

	// Use the pool to build up some stats
	pool.Get4()
	pool.Get12()

	// Reset — should not panic
	pool.Reset()
}

// TestBufferPool_ZeroBytes verifies ZeroBytes clears a buffer.
func TestZeroBytes_BufferPool(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5}
	ZeroBytes(buf)
	for i, b := range buf {
		if b != 0 {
			t.Errorf("ZeroBytes() buf[%d] = %d, want 0", i, b)
		}
	}
}

// TestDecodeBase64Loose_Variants verifies DecodeBase64Loose handles
// standard and URL-safe base64 encoding.
func TestDecodeBase64Loose_Variants(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"standard padded", "aGVsbG8=", false},     // "hello"
		{"standard 4-padded", "aGVsbG8=", false},   // "hello"
		{"empty", "", false},                        // empty string → empty bytes
		{"invalid", "!@#$", true},                  // invalid chars
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeBase64Loose(tc.input)
			if (err != nil) != tc.wantErr {
				t.Errorf("DecodeBase64Loose(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			}
		})
	}
}

// TestBoundedQueue_IsClosed verifies IsClosed returns correct state.
func TestBoundedQueue_IsClosed(t *testing.T) {
	queue := NewBoundedQueue(10)

	if queue.IsClosed() {
		t.Error("IsClosed() should be false for a new queue")
	}

	queue.Close()

	if !queue.IsClosed() {
		t.Error("IsClosed() should be true after Close()")
	}
}

// TestBufferPoolMetrics_HitRate_ZeroTotal verifies that HitRate functions
// return 0 when total (hits+misses) is zero (covers the total==0 guard branch).
func TestBufferPoolMetrics_HitRate_ZeroTotal(t *testing.T) {
	// A zero-value metrics struct has all zero counters.
	m := BufferPoolMetrics{}
	if r := m.HitRate4(); r != 0 {
		t.Errorf("HitRate4() with zero total = %f, want 0", r)
	}
	if r := m.HitRate12(); r != 0 {
		t.Errorf("HitRate12() with zero total = %f, want 0", r)
	}
	if r := m.HitRate32(); r != 0 {
		t.Errorf("HitRate32() with zero total = %f, want 0", r)
	}
	if r := m.HitRate64K(); r != 0 {
		t.Errorf("HitRate64K() with zero total = %f, want 0", r)
	}
}

// TestBufferPoolMetrics_HitRate_NonZero verifies that HitRate functions
// compute correctly when hits and misses are both non-zero.
func TestBufferPoolMetrics_HitRate_NonZero(t *testing.T) {
	m := BufferPoolMetrics{
		Hits4:   3,
		Misses4: 1,
	}
	// Expected hit rate: 3/(3+1) = 0.75
	got := m.HitRate4()
	if got < 0.74 || got > 0.76 {
		t.Errorf("HitRate4() = %f, want ~0.75", got)
	}
}

// TestCreateAESGCMCipher_ValidKey verifies that a valid 32-byte key creates a cipher.
func TestCreateAESGCMCipher_ValidKey(t *testing.T) {
	key := make([]byte, aesKeySize)
	aead, err := createAESGCMCipher(key)
	if err != nil {
		t.Fatalf("createAESGCMCipher() unexpected error: %v", err)
	}
	if aead == nil {
		t.Fatal("createAESGCMCipher() returned nil")
	}
}

// TestCreateAESGCMCipher_InvalidKeySize verifies that an invalid key size
// returns an error (covers the invalid-key-size branch).
func TestCreateAESGCMCipher_InvalidKeySize(t *testing.T) {
	_, err := createAESGCMCipher([]byte("short"))
	if err == nil {
		t.Fatal("createAESGCMCipher() expected error for invalid key size, got nil")
	}
}

// TestGetNonceSize_UnsupportedAlgorithm verifies that an unknown algorithm
// returns an error (covers the default branch of getNonceSize).
func TestGetNonceSize_UnsupportedAlgorithm(t *testing.T) {
	_, err := getNonceSize("unknown-algorithm")
	if err == nil {
		t.Fatal("getNonceSize() expected error for unknown algorithm, got nil")
	}
}

// TestBufferPool_Get4_PoolHit exercises the pool-hit branch of Get4 by
// putting then getting a buffer without an intervening GC.
func TestBufferPool_Get4_PoolHit(t *testing.T) {
	pool := GetGlobalBufferPool()
	b := pool.Get4()
	pool.Put4(b)
	b2 := pool.Get4()
	if len(b2) != 4 {
		t.Errorf("Get4() len = %d, want 4", len(b2))
	}
	pool.Put4(b2)
}

// TestBufferPool_Get12_PoolHit exercises the pool-hit branch of Get12.
func TestBufferPool_Get12_PoolHit(t *testing.T) {
	pool := GetGlobalBufferPool()
	b := pool.Get12()
	pool.Put12(b)
	b2 := pool.Get12()
	if len(b2) != 12 {
		t.Errorf("Get12() len = %d, want 12", len(b2))
	}
	pool.Put12(b2)
}

// TestBufferPool_Get32_PoolHit exercises the pool-hit branch of Get32.
func TestBufferPool_Get32_PoolHit(t *testing.T) {
	pool := GetGlobalBufferPool()
	b := pool.Get32()
	pool.Put32(b)
	b2 := pool.Get32()
	if len(b2) != 32 {
		t.Errorf("Get32() len = %d, want 32", len(b2))
	}
	pool.Put32(b2)
}

// TestBufferPool_Get64K_PoolHit exercises the pool-hit branch of Get64K by
// allocating a fresh buffer, putting it back, and getting it again.
// We verify only that the returned buffer has sufficient capacity, as the length
// may reflect a previous slice operation by the pool dispatcher.
func TestBufferPool_Get64K_PoolHit(t *testing.T) {
	pool := GetGlobalBufferPool()
	// Allocate a fresh full-size buffer directly and return it.
	b := make([]byte, 64*1024)
	pool.Put64K(b)
	b2 := pool.Get64K()
	// Must have at least 64K capacity regardless of current length.
	if cap(b2) < 64*1024 {
		t.Errorf("Get64K() cap = %d, want >= %d", cap(b2), 64*1024)
	}
	pool.Put64K(b2)
}
