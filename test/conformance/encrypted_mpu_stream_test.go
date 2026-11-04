//go:build conformance

package conformance

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

type mpuPatternReader struct {
	pos, total, partSize, maxRead, limit int
	corrupt                              int
	failAt                               int
}

func (r *mpuPatternReader) Read(p []byte) (int, error) {
	if len(p) > r.maxRead {
		r.maxRead = len(p)
	}
	if r.failAt >= 0 && r.pos >= r.failAt {
		return 0, errors.New("injected")
	}
	if r.pos >= r.total {
		return 0, io.EOF
	}
	n := min(len(p), r.total-r.pos)
	if r.limit > 0 {
		n = min(n, r.limit)
	}
	if r.failAt >= 0 {
		n = min(n, r.failAt-r.pos)
	}
	for i := 0; i < n; i++ {
		p[i] = byte('A' + ((r.pos+i)/r.partSize)%26)
		if r.pos+i == r.corrupt {
			p[i] ^= 1
		}
	}
	r.pos += n
	return n, nil
}

func TestGH353MPUPatternStreaming(t *testing.T) {
	const parts, size = 80, 5 * 1024 * 1024
	r := &mpuPatternReader{total: parts * size, partSize: size, corrupt: -1, failAt: -1}
	if err := verifyMPUPattern(r, parts, size); err != nil || r.pos != parts*size || r.maxRead > 32*1024 {
		t.Fatal("full 400 MiB streamed pattern failed")
	}
}

func TestGH353MPUPatternStreamingFailures(t *testing.T) {
	const parts, size = 3, 17
	for _, tc := range []struct {
		name                          string
		total, corrupt, failAt, limit int
		ok                            bool
	}{
		{"short reads", parts * size, -1, -1, 2, true}, {"truncated", parts*size - 1, -1, -1, 0, false}, {"extra", parts*size + 1, -1, -1, 0, false},
		{"first", parts * size, 0, -1, 0, false}, {"middle", parts * size, size + 3, -1, 0, false}, {"boundary", parts * size, size, -1, 0, false}, {"last", parts * size, parts*size - 1, -1, 0, false},
		{"read error", parts * size, -1, 7, 0, false}, {"trailing read error", parts * size, -1, parts * size, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &mpuPatternReader{total: tc.total, partSize: size, corrupt: tc.corrupt, failAt: tc.failAt, limit: tc.limit}
			if (verifyMPUPattern(r, parts, size) == nil) != tc.ok {
				t.Fatal("stream verification outcome mismatch")
			}
		})
	}
	if verifyMPUPattern(bytes.NewReader(nil), 0, size) == nil {
		t.Fatal("invalid dimensions accepted")
	}
}
