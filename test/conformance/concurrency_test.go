//go:build conformance

package conformance

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// testConcurrentPutGet verifies that concurrent PUT and GET operations
// against a single gateway instance do not corrupt data. Detects race
// conditions when combined with -race.
func testConcurrentPutGet(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	const goroutines = 8
	const objectsPerGoroutine = 4

	var wg sync.WaitGroup
	errs := make(chan string, goroutines*objectsPerGoroutine*2)

	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < objectsPerGoroutine; i++ {
				key := fmt.Sprintf("concurrent/%d/%d/%s", g, i, uniqueSuffix(t))
				data := bytes.Repeat([]byte{byte(g*objectsPerGoroutine + i)}, 1024+i*100)

				// PUT
				req, err := newPutRequest(gw, inst.Bucket, key, data)
				if err != nil {
					errs <- fmt.Sprintf("PUT new request [%d/%d]: %v", g, i, err)
					continue
				}
				resp, err := gw.HTTPClient().Do(req)
				if err != nil {
					errs <- fmt.Sprintf("PUT [%d/%d]: %v", g, i, err)
					continue
				}
				resp.Body.Close()
				if resp.StatusCode != 200 {
					errs <- fmt.Sprintf("PUT [%d/%d]: status %d", g, i, resp.StatusCode)
					continue
				}

				// GET
				got := getNoFail(gw, inst.Bucket, key)
				if got == nil {
					errs <- fmt.Sprintf("GET [%d/%d]: nil response", g, i)
					continue
				}
				if !bytes.Equal(got, data) {
					errs <- fmt.Sprintf("GET [%d/%d]: data mismatch (%d vs %d bytes)",
						g, i, len(got), len(data))
				}
			}
		}()
	}

	wg.Wait()
	close(errs)

	for e := range errs {
		t.Error(e)
	}
}

// newPutRequest creates an HTTP PUT request; shared helper for concurrent tests.
func newPutRequest(gw *harness.Gateway, bucket, key string, data []byte) (*http.Request, error) {
	return http.NewRequest("PUT", objectURL(gw, bucket, key), bytes.NewReader(data))
}

// getNoFail performs a GET and returns nil on non-200 responses (for concurrent test use).
func getNoFail(gw *harness.Gateway, bucket, key string) []byte {
	resp, err := gw.HTTPClient().Get(objectURL(gw, bucket, key))
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		io.Copy(io.Discard, resp.Body)
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return body
}
