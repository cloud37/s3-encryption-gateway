package crypto

import (
	"context"
	"sync"
	"sync/atomic"
)

// BufferPool provides thread-safe pooling of byte buffers to reduce allocations.
// Buffers are zeroized before returning to pools to prevent data leakage.
type BufferPool struct {
	pool4   *sync.Pool // 4-byte buffers (metadata lengths, chunk indices)
	pool12  *sync.Pool // 12-byte buffers (GCM nonces)
	pool32  *sync.Pool // 32-byte buffers (AES keys, salts)
	pool64K *sync.Pool // 64KB+ buffers (chunk buffers)

	// Metrics for monitoring pool performance
	hits4, misses4     int64
	hits12, misses12   int64
	hits32, misses32   int64
	hits64K, misses64K int64
}

// Global buffer pool instance
var globalBufferPool = &BufferPool{
	pool4: &sync.Pool{
		New: func() interface{} { return make([]byte, 4) },
	},
	pool12: &sync.Pool{
		New: func() interface{} { return make([]byte, 12) },
	},
	pool32: &sync.Pool{
		New: func() interface{} { return make([]byte, 32) },
	},
	pool64K: &sync.Pool{
		New: func() interface{} { return make([]byte, 64*1024+128) }, // Slightly larger for overhead/tags
	},
}

// GetGlobalBufferPool returns the global buffer pool instance.
func GetGlobalBufferPool() *BufferPool {
	return globalBufferPool
}

// Get returns a buffer of the requested size from the appropriate pool if available.
// If no pool matches the size, a new buffer is allocated.
func (p *BufferPool) Get(size int) []byte {
	// Check common sizes
	if size == 32 {
		return p.Get32()
	}
	if size == 12 {
		return p.Get12()
	}
	if size == 4 {
		return p.Get4()
	}

	// For chunk buffers, we support anything up to the pool size
	// This covers default chunks (64KB) plus encryption overhead
	if size <= 64*1024+128 && size > 32 {
		buf := p.Get64K()
		if cap(buf) >= size {
			return buf[:size]
		}
		// If we got a buffer that's too small (shouldn't happen with correct New), discard it
	}

	return make([]byte, size)
}

// Put returns a buffer to the appropriate pool if it matches a pool size.
// The buffer is zeroized before being returned to the pool.
func (p *BufferPool) Put(buf []byte) {
	c := cap(buf)
	if c >= 64*1024 && c <= 64*1024+128 {
		p.Put64K(buf)
		return
	}
	if c == 32 {
		p.Put32(buf)
		return
	}
	if c == 12 {
		p.Put12(buf)
		return
	}
	if c == 4 {
		p.Put4(buf)
		return
	}
	// If size doesn't match any pool, let GC handle it
}

// Get4 returns a 4-byte buffer from the pool.
func (p *BufferPool) Get4() []byte {
	if buf := p.pool4.Get(); buf != nil {
		atomic.AddInt64(&p.hits4, 1)
		return buf.([]byte)
	}
	atomic.AddInt64(&p.misses4, 1)
	return make([]byte, 4)
}

// Put4 returns a 4-byte buffer to the pool after zeroizing it.
func (p *BufferPool) Put4(buf []byte) {
	if cap(buf) != 4 {
		return // Don't pool incorrectly sized buffers
	}
	// Zeroize buffer to prevent data leakage
	for i := range buf {
		buf[i] = 0
	}
	p.pool4.Put(buf)
}

// Get12 returns a 12-byte buffer from the pool.
func (p *BufferPool) Get12() []byte {
	if buf := p.pool12.Get(); buf != nil {
		atomic.AddInt64(&p.hits12, 1)
		return buf.([]byte)
	}
	atomic.AddInt64(&p.misses12, 1)
	return make([]byte, 12)
}

// Put12 returns a 12-byte buffer to the pool after zeroizing it.
func (p *BufferPool) Put12(buf []byte) {
	if cap(buf) != 12 {
		return // Don't pool incorrectly sized buffers
	}
	// Zeroize buffer to prevent data leakage
	for i := range buf {
		buf[i] = 0
	}
	p.pool12.Put(buf)
}

// Get32 returns a 32-byte buffer from the pool.
func (p *BufferPool) Get32() []byte {
	if buf := p.pool32.Get(); buf != nil {
		atomic.AddInt64(&p.hits32, 1)
		return buf.([]byte)
	}
	atomic.AddInt64(&p.misses32, 1)
	return make([]byte, 32)
}

// Put32 returns a 32-byte buffer to the pool after zeroizing it.
func (p *BufferPool) Put32(buf []byte) {
	if cap(buf) != 32 {
		return // Don't pool incorrectly sized buffers
	}
	// Zeroize buffer to prevent data leakage
	for i := range buf {
		buf[i] = 0
	}
	p.pool32.Put(buf)
}

// Get64K returns a 64KB buffer from the pool.
func (p *BufferPool) Get64K() []byte {
	if buf := p.pool64K.Get(); buf != nil {
		atomic.AddInt64(&p.hits64K, 1)
		return buf.([]byte)
	}
	atomic.AddInt64(&p.misses64K, 1)
	return make([]byte, 64*1024)
}

// Put64K returns a 64KB buffer to the pool after zeroizing it.
func (p *BufferPool) Put64K(buf []byte) {
	if cap(buf) < 64*1024 {
		return // Don't pool incorrectly sized buffers
	}
	// Zeroize buffer to prevent data leakage
	for i := range buf {
		buf[i] = 0
	}
	p.pool64K.Put(buf)
}

// GetMetrics returns current pool metrics.
func (p *BufferPool) GetMetrics() BufferPoolMetrics {
	return BufferPoolMetrics{
		Hits4:     atomic.LoadInt64(&p.hits4),
		Misses4:   atomic.LoadInt64(&p.misses4),
		Hits12:    atomic.LoadInt64(&p.hits12),
		Misses12:  atomic.LoadInt64(&p.misses12),
		Hits32:    atomic.LoadInt64(&p.hits32),
		Misses32:  atomic.LoadInt64(&p.misses32),
		Hits64K:   atomic.LoadInt64(&p.hits64K),
		Misses64K: atomic.LoadInt64(&p.misses64K),
	}
}

// BufferPoolMetrics contains pool performance metrics.
type BufferPoolMetrics struct {
	Hits4, Misses4     int64
	Hits12, Misses12   int64
	Hits32, Misses32   int64
	Hits64K, Misses64K int64
}

// HitRate4 returns the hit rate for 4-byte buffers.
func (m BufferPoolMetrics) HitRate4() float64 {
	total := m.Hits4 + m.Misses4
	if total == 0 {
		return 0
	}
	return float64(m.Hits4) / float64(total)
}

// HitRate12 returns the hit rate for 12-byte buffers.
func (m BufferPoolMetrics) HitRate12() float64 {
	total := m.Hits12 + m.Misses12
	if total == 0 {
		return 0
	}
	return float64(m.Hits12) / float64(total)
}

// HitRate32 returns the hit rate for 32-byte buffers.
func (m BufferPoolMetrics) HitRate32() float64 {
	total := m.Hits32 + m.Misses32
	if total == 0 {
		return 0
	}
	return float64(m.Hits32) / float64(total)
}

// HitRate64K returns the hit rate for 64KB buffers.
func (m BufferPoolMetrics) HitRate64K() float64 {
	total := m.Hits64K + m.Misses64K
	if total == 0 {
		return 0
	}
	return float64(m.Hits64K) / float64(total)
}

// Reset resets all metrics counters to zero.
func (p *BufferPool) Reset() {
	atomic.StoreInt64(&p.hits4, 0)
	atomic.StoreInt64(&p.misses4, 0)
	atomic.StoreInt64(&p.hits12, 0)
	atomic.StoreInt64(&p.misses12, 0)
	atomic.StoreInt64(&p.hits32, 0)
	atomic.StoreInt64(&p.misses32, 0)
	atomic.StoreInt64(&p.hits64K, 0)
	atomic.StoreInt64(&p.misses64K, 0)
}

// BoundedQueue provides a bounded queue for streaming data with backpressure.
// It supports context-aware cancellation and blocking/non-blocking operations.
type BoundedQueue struct {
	buffer   []byte
	size     int
	maxSize  int
	pos      int
	mu       sync.Mutex
	notEmpty *sync.Cond
	notFull  *sync.Cond
	closed   bool
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewBoundedQueue creates a new bounded queue with the specified maximum size.
func NewBoundedQueue(maxSize int) *BoundedQueue {
	ctx, cancel := context.WithCancel(context.Background())
	q := &BoundedQueue{
		buffer:  make([]byte, maxSize),
		maxSize: maxSize,
		ctx:     ctx,
		cancel:  cancel,
	}
	q.notEmpty = sync.NewCond(&q.mu)
	q.notFull = sync.NewCond(&q.mu)
	return q
}

// NewBoundedQueueWithContext creates a new bounded queue with context support.
func NewBoundedQueueWithContext(ctx context.Context, maxSize int) *BoundedQueue {
	ctx, cancel := context.WithCancel(ctx)
	q := &BoundedQueue{
		buffer:  make([]byte, maxSize),
		maxSize: maxSize,
		ctx:     ctx,
		cancel:  cancel,
	}
	q.notEmpty = sync.NewCond(&q.mu)
	q.notFull = sync.NewCond(&q.mu)

	// Wake blocked Read/Write waiters when context is cancelled.
	// sync.Cond.Wait() only returns on Broadcast/Signal, so we need
	// this goroutine to translate context cancellation into a broadcast.
	go func() {
		<-ctx.Done()
		q.notEmpty.Broadcast()
		q.notFull.Broadcast()
	}()

	return q
}

// Write adds data to the queue, blocking if the queue is full.
// Returns the number of bytes written and any error.
func (q *BoundedQueue) Write(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	totalWritten := 0

	for len(p) > 0 {
		// Wait for space or context cancellation
		for q.size == q.maxSize && !q.closed {
			select {
			case <-q.ctx.Done():
				return totalWritten, q.ctx.Err()
			default:
				q.notFull.Wait()
			}
		}

		if q.closed {
			return totalWritten, context.Canceled
		}

		// Calculate how much we can write
		available := q.maxSize - q.size
		if available == 0 {
			continue // Should not happen due to wait above
		}

		toWrite := len(p)
		if toWrite > available {
			toWrite = available
		}

		// Write to buffer (circular)
		endPos := (q.pos + q.size) % q.maxSize
		copyLen := toWrite
		if endPos+copyLen > q.maxSize {
			copyLen = q.maxSize - endPos
		}

		copy(q.buffer[endPos:], p[:copyLen])
		q.size += copyLen
		totalWritten += copyLen
		p = p[copyLen:]

		// Signal readers
		q.notEmpty.Signal()
	}

	return totalWritten, nil
}

// Read reads data from the queue, blocking if the queue is empty.
// Returns the number of bytes read and any error.
func (q *BoundedQueue) Read(p []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	totalRead := 0

	for len(p) > 0 {
		// Wait for data or context cancellation
		for q.size == 0 && !q.closed {
			select {
			case <-q.ctx.Done():
				return totalRead, q.ctx.Err()
			default:
				q.notEmpty.Wait()
			}
		}

		if q.closed && q.size == 0 {
			return totalRead, context.Canceled
		}

		// Calculate how much we can read
		toRead := len(p)
		if toRead > q.size {
			toRead = q.size
		}

		if toRead == 0 {
			break
		}

		// Read from buffer (circular)
		copyLen := toRead
		if q.pos+copyLen > q.maxSize {
			copyLen = q.maxSize - q.pos
		}

		copy(p[:copyLen], q.buffer[q.pos:])
		q.pos = (q.pos + copyLen) % q.maxSize
		q.size -= copyLen
		totalRead += copyLen
		p = p[copyLen:]

		// Signal writers
		q.notFull.Signal()
	}

	return totalRead, nil
}

// Close closes the queue, unblocking all waiting operations.
func (q *BoundedQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.closed = true
	q.cancel()
	q.notEmpty.Broadcast()
	q.notFull.Broadcast()
}

// Size returns the current number of bytes in the queue.
func (q *BoundedQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.size
}

// IsClosed returns true if the queue is closed.
func (q *BoundedQueue) IsClosed() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.closed
}
