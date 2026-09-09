package api

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestSpoolManager_DeclaredLengthAdmission(t *testing.T) {
	m := NewSpoolManager(10)
	if _, err := m.Acquire(context.Background(), 11, 20); !errors.Is(err, ErrSpoolCapacity) {
		t.Fatalf("want capacity, got %v", err)
	}
	if _, err := m.Acquire(context.Background(), 11, 10); !errors.Is(err, ErrSpoolRequestLimit) {
		t.Fatalf("want request limit, got %v", err)
	}
}
func TestSpoolManager_UnknownLengthGrowth(t *testing.T) {
	m := NewSpoolManager(5)
	r, err := m.Acquire(context.Background(), 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Grow(4); err != nil {
		t.Fatal(err)
	}
	if err := r.Grow(1); !errors.Is(err, ErrSpoolRequestLimit) {
		t.Fatalf("got %v", err)
	}
	r.Release()
}
func TestSpoolManager_AggregateConcurrentLimit(t *testing.T) {
	m := NewSpoolManager(10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	current := int64(0)
	max := int64(0)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := m.Acquire(context.Background(), 1, 10)
			if e == nil {
				mu.Lock()
				current++
				if current > max {
					max = current
				}
				mu.Unlock()
				r.Release()
				mu.Lock()
				current--
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if max > 10 || m.(*spoolManager).CurrentBytes() != 0 {
		t.Fatalf("max=%d current=%d", max, m.(*spoolManager).CurrentBytes())
	}
}
func TestSpoolReservation_ReleaseIdempotent(t *testing.T) {
	m := NewSpoolManager(10)
	r, _ := m.Acquire(context.Background(), 3, 3)
	r.Release()
	r.Release()
	if m.(*spoolManager).CurrentBytes() != 0 {
		t.Fatal("leaked reservation")
	}
}

func TestSpoolManager_ConcurrentAcquireGrowReleaseNeverExceedsBudget(t *testing.T) {
	observer := &spoolTestObserver{}
	m := NewSpoolManager(32, observer).(*spoolManager)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := m.Acquire(context.Background(), 0, 4)
			if err == nil {
				_ = r.Grow(4)
				r.Release()
			}
		}()
	}
	wg.Wait()
	if got := m.CurrentBytes(); got != 0 {
		t.Fatalf("current bytes=%d, want zero", got)
	}
	for _, got := range observer.samples() {
		if got > 32 {
			t.Fatalf("observed bytes=%d over capacity", got)
		}
	}
}

type spoolTestObserver struct {
	mu     sync.Mutex
	values []int64
}

func (o *spoolTestObserver) SetSpoolBytes(n int64) {
	o.mu.Lock()
	o.values = append(o.values, n)
	o.mu.Unlock()
}
func (o *spoolTestObserver) RecordSpoolRejection(string) {}
func (o *spoolTestObserver) samples() []int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]int64(nil), o.values...)
}

func TestSpoolManager_ReconfigureCapacity(t *testing.T) {
	m := NewSpoolManager(10).(*spoolManager)
	if err := m.ReconfigureCapacity(20); err != nil {
		t.Fatal(err)
	}
	r, err := m.Acquire(context.Background(), 20, 20)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ReconfigureCapacity(10); !errors.Is(err, ErrSpoolCapacity) {
		t.Fatalf("err=%v", err)
	}
	r.Release()
	if err := m.ReconfigureCapacity(10); err != nil {
		t.Fatal(err)
	}
}
func BenchmarkSpoolManager_Grow(b *testing.B) {
	m := NewSpoolManager(int64(b.N))
	r, _ := m.Acquire(context.Background(), 0, int64(b.N))
	b.ReportAllocs()
	b.SetBytes(1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.Grow(1)
	}
	r.Release()
}
