package api

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

var (
	ErrSpoolRequestLimit = errors.New("verified spool request limit exceeded")
	ErrSpoolCapacity     = errors.New("verified spool aggregate capacity exhausted")
)

type SpoolManager interface {
	// Acquire reserves declared bytes; n must be non-negative and no greater
	// than requestLimit. It fails fast when aggregate capacity is unavailable.
	Acquire(context.Context, int64, int64) (SpoolReservation, error)
}
type SpoolLimits struct{ Global, Part int64 }

// SpoolLimitSource provides request limits that can be changed without
// rebuilding the middleware or handlers. Values are read atomically per
// request, so a reload cannot expose a partially updated pair.
type SpoolLimitSource struct {
	limits atomic.Value // stores SpoolLimits
}

func NewSpoolLimitSource(limits SpoolLimits) *SpoolLimitSource {
	s := &SpoolLimitSource{}
	s.limits.Store(SpoolLimits{Global: 5 << 30, Part: config.DefaultMaxPartBuffer})
	s.Set(limits)
	return s
}

func (s *SpoolLimitSource) Set(limits SpoolLimits) {
	if limits.Global <= 0 || limits.Part <= 0 {
		return
	}
	s.limits.Store(limits)
}

func (s *SpoolLimitSource) Limits() SpoolLimits {
	return s.limits.Load().(SpoolLimits)
}

func SpoolLimitsForConfig(cfg *config.Config) SpoolLimits {
	limits := SpoolLimits{Global: 5 << 30, Part: config.DefaultMaxPartBuffer}
	if cfg != nil {
		if cfg.Server.MaxVerifiedSpoolBytes > 0 {
			limits.Global = cfg.Server.MaxVerifiedSpoolBytes
		}
		if cfg.Server.MaxPartBuffer > 0 {
			limits.Part = cfg.Server.MaxPartBuffer
		}
	}
	return limits
}

type SpoolReservation interface {
	// Grow atomically charges additional bytes against request and aggregate
	// limits. Release is idempotent and safe to call from every cleanup path.
	Grow(int64) error
	Release()
}
type spoolObserver interface {
	SetSpoolBytes(int64)
	RecordSpoolRejection(string)
}

type spoolManager struct {
	mu                sync.Mutex
	current, capacity int64
	directory         string
	observer          spoolObserver
}

// ReconfigureCapacity updates the aggregate budget without changing the
// manager identity shared by middleware and handlers. Existing reservations
// remain valid; a smaller budget takes effect as soon as headroom permits.
func (m *spoolManager) ReconfigureCapacity(capacity int64) error {
	if capacity <= 0 {
		return ErrSpoolCapacity
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current > capacity {
		return ErrSpoolCapacity
	}
	m.capacity = capacity
	m.observeLocked()
	return nil
}

type spoolReservation struct {
	manager     *spoolManager
	limit, used int64
	released    bool
}

func NewSpoolManager(capacity int64, options ...interface{}) SpoolManager {
	m := &spoolManager{capacity: capacity}
	for _, o := range options {
		switch v := o.(type) {
		case string:
			m.directory = v
		case spoolObserver:
			m.observer = v
		}
	}
	return m
}
func (m *spoolManager) CurrentBytes() int64 { m.mu.Lock(); defer m.mu.Unlock(); return m.current }

func (m *spoolManager) Acquire(ctx context.Context, n, limit int64) (SpoolReservation, error) {
	if n < 0 || limit < 0 || n > limit {
		m.reject("request_limit")
		return nil, ErrSpoolRequestLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current < 0 || n > m.capacity || m.current > m.capacity-n {
		m.rejectLocked("aggregate_limit")
		return nil, ErrSpoolCapacity
	}
	m.current += n
	m.observeLocked()
	return &spoolReservation{manager: m, limit: limit, used: n}, nil
}
func (r *spoolReservation) Grow(delta int64) error {
	if delta < 0 {
		r.manager.reject("request_limit")
		return ErrSpoolRequestLimit
	}
	r.manager.mu.Lock()
	defer r.manager.mu.Unlock()
	if r.released {
		return ErrSpoolRequestLimit
	}
	if delta > r.limit-r.used {
		r.manager.rejectLocked("request_limit")
		return ErrSpoolRequestLimit
	}
	if r.used > r.limit-delta || r.manager.current > r.manager.capacity-delta {
		reason := "request_limit"
		if r.manager.current <= r.manager.capacity-delta {
			reason = "request_limit"
		} else {
			reason = "aggregate_limit"
		}
		r.manager.rejectLocked(reason)
		if reason == "request_limit" {
			return ErrSpoolRequestLimit
		}
		return ErrSpoolCapacity
	}
	r.used += delta
	r.manager.current += delta
	r.manager.observeLocked()
	return nil
}
func (r *spoolReservation) Release() {
	r.manager.mu.Lock()
	defer r.manager.mu.Unlock()
	if !r.released {
		r.manager.current -= r.used
		r.released = true
		r.manager.observeLocked()
	}
}

func DefaultSpoolManager() SpoolManager { return NewSpoolManager(10 << 30) }

func spoolLimitForRequest(r *http.Request, global, part int64) int64 {
	if global <= 0 {
		global = 5 << 30
	}
	if r == nil {
		return minSpoolLimit(global, 1<<20)
	}
	if r.Method == http.MethodPut && r.URL != nil {
		// Keep this classification in step with the query-scoped PUT routes in
		// RegisterRoutes. In particular, partNumber by itself is not UploadPart:
		// treating it as one would let an unknown/deceptive request use the
		// potentially much larger part buffer.
		query := operationQuery(r)
		if isUploadPartSpoolRequest(query) {
			return minSpoolLimit(global, part)
		}
		// Only the plain object route (with the route's versionId parameter) is
		// a PutObject-sized body. CopyObject, bucket PUTs, and all selected or
		// ambiguous XML routes use the conservative control-plane cap.
		path := strings.TrimPrefix(r.URL.Path, "/")
		objectRoute := strings.Contains(path, "/") && !strings.HasSuffix(path, "/")
		if objectRoute && r.Header.Get("X-Amz-Copy-Source") == "" && (len(query) == 0 || (len(query) == 1 && len(query["versionId"]) > 0)) {
			return global
		}
	}
	return minSpoolLimit(global, 1<<20)
}

func isUploadPartSpoolRequest(query map[string][]string) bool {
	if len(query) != 2 || len(query["uploadId"]) == 0 || query["uploadId"][0] == "" || len(query["partNumber"]) == 0 {
		return false
	}
	partNumber := query["partNumber"][0]
	if partNumber == "" {
		return false
	}
	for _, c := range partNumber {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(partNumber, 10, 32)
	return err == nil
}
func minSpoolLimit(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func isSpoolQuotaError(err error) bool {
	return errors.Is(err, ErrSpoolRequestLimit) || errors.Is(err, ErrSpoolCapacity)
}
func spoolReason(err error) string {
	if errors.Is(err, ErrSpoolCapacity) {
		return "aggregate_limit"
	}
	return "request_limit"
}

func (m *spoolManager) reject(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejectLocked(reason)
}
func (m *spoolManager) rejectLocked(reason string) {
	if m.observer != nil {
		m.observer.RecordSpoolRejection(reason)
	}
}
func (m *spoolManager) observeLocked() {
	if m.observer != nil {
		m.observer.SetSpoolBytes(m.current)
	}
}
func (m *spoolManager) tempDirectory() string { return m.directory }

type reservingWriter struct {
	w           interface{ Write([]byte) (int, error) }
	reservation SpoolReservation
	remaining   int64
}

func (w *reservingWriter) Write(p []byte) (int, error) {
	n := int64(len(p))
	extra := n
	if w.remaining >= n {
		extra = 0
	} else {
		extra -= w.remaining
	}
	if extra > math.MaxInt64 || extra < 0 {
		return 0, ErrSpoolRequestLimit
	}
	if err := w.reservation.Grow(extra); err != nil {
		return 0, err
	}
	if w.remaining >= n {
		w.remaining -= n
	} else {
		w.remaining = 0
	}
	return w.w.Write(p)
}
