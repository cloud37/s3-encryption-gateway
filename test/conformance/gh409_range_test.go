//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"sync"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

type gh409BackendObserver struct {
	mu     sync.Mutex
	key    string
	ranges []string
}

func (o *gh409BackendObserver) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet {
		o.mu.Lock()
		if o.key != "" && req.URL.Path == o.key {
			value := req.Header.Get("Range")
			if value == "" {
				value = "full"
			}
			o.ranges = append(o.ranges, value)
		}
		o.mu.Unlock()
	}
	return http.DefaultTransport.RoundTrip(req)
}

func (o *gh409BackendObserver) take() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := append([]string(nil), o.ranges...)
	o.ranges = nil
	return result
}

func testGH409_ChunkedSinglePutRanges(t *testing.T, inst provider.Instance) {
	const chunk = crypto.DefaultChunkSize
	observer := &gh409BackendObserver{}
	gw := harness.StartGateway(t, inst, harness.WithChunking(true), harness.WithBackendTransport(observer))
	key := uniqueKey(t)
	data := make([]byte, 3*chunk+137)
	for i := range data {
		data[i] = byte(i % 251)
	}
	put(t, gw, inst.Bucket, key, data)
	backend := newS3Client(t, inst)
	meta, err := backend.HeadObject(context.Background(), inst.Bucket, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := crypto.ExpandMetadataForAPI(meta)
	if err != nil || expanded[crypto.MetaObjectFormatVersion] != "chunked-v2" || expanded[crypto.MetaChunkCount] != "" {
		t.Fatalf("unexpected single-PUT encryption metadata: %v err=%v", expanded, err)
	}
	size, err := strconv.Atoi(meta["Content-Length"])
	if err != nil {
		t.Fatal(err)
	}
	observer.mu.Lock()
	observer.key = "/" + inst.Bucket + "/" + key
	observer.mu.Unlock()
	terminal := fmt.Sprintf("bytes=%d-%d", size-crypto.ChunkedTerminalSize, size-1)
	tests := []struct {
		name, header            string
		start, end, first, last int
	}{
		{"start", "bytes=0-20", 0, 20, 0, 0},
		{"middle", fmt.Sprintf("bytes=%d-%d", chunk+5, chunk+15), chunk + 5, chunk + 15, 1, 1},
		{"boundary", fmt.Sprintf("bytes=%d-%d", chunk-4, chunk+4), chunk - 4, chunk + 4, 0, 1},
		{"suffix", "bytes=-10", len(data) - 10, len(data) - 1, 3, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_ = observer.take()
			req, err := http.NewRequest(http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Range", tc.header)
			resp, err := gw.HTTPClient().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, readErr := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if resp.StatusCode != http.StatusPartialContent || !bytes.Equal(body, data[tc.start:tc.end+1]) {
				t.Fatalf("status=%d length=%d body=%q", resp.StatusCode, len(body), body)
			}
			if got, want := resp.Header.Get("Content-Range"), fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, len(data)); got != want {
				t.Fatalf("Content-Range=%q want=%q", got, want)
			}
			if got, want := resp.Header.Get("Content-Length"), strconv.Itoa(tc.end-tc.start+1); got != want {
				t.Fatalf("Content-Length=%q want=%q", got, want)
			}
			first := tc.first * (chunk + 16)
			last := (tc.last+1)*(chunk+16) - 1
			if last >= size-crypto.ChunkedTerminalSize {
				last = size - crypto.ChunkedTerminalSize - 1
			}
			want := []string{terminal, fmt.Sprintf("bytes=%d-%d", first, last)}
			if got := observer.take(); !reflect.DeepEqual(got, want) {
				t.Fatalf("backend reads=%v want=%v", got, want)
			}
		})
	}
}
