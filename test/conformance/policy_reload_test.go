//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func reloadBypassFixture(t *testing.T, inst provider.Instance) (*config.PolicyManager, string, *harness.Gateway) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: reload-bypass\nbuckets: [%q]\ndisable_encryption: true\n", inst.Bucket)), 0600))
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm), harness.WithChunking(true), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	return pm, path, gw
}

func assertReloadBypassObject(t *testing.T, inst provider.Instance, gw *harness.Gateway, backend s3.Client, key string, data []byte) {
	t.Helper()
	body, meta, err := backend.GetObject(context.Background(), inst.Bucket, key, nil, nil)
	require.NoError(t, err)
	raw, err := io.ReadAll(body)
	require.NoError(t, body.Close())
	require.NoError(t, err)
	assert.Equal(t, data, raw, "backend bytes for %s must remain plaintext", key)
	assert.False(t, crypto.IsEncryptedMetadata(meta), "backend encryption markers for %s", key)
	assert.Equal(t, fmt.Sprint(len(data)), meta["Content-Length"])
	resp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	require.NoError(t, err)
	got, err := io.ReadAll(resp.Body)
	require.NoError(t, resp.Body.Close())
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "gateway GET: %s", got)
	assert.Equal(t, data, got)
	assert.Equal(t, int64(len(data)), resp.ContentLength)
}

// Deterministically reproduces the failed-reload variant of GH-339: the
// complete previous snapshot must survive a late file parse failure.
func testPolicyReload_FailedLoadPreservesBypass(t *testing.T, inst provider.Instance) {
	pm, path, gw := reloadBypassFixture(t, inst)
	backend := newS3Client(t, inst)
	data := bytes.Repeat([]byte("r"), 1024)
	before, after := uniqueKey(t), uniqueKey(t)
	put(t, gw, inst.Bucket, before, data)
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	require.NoError(t, os.WriteFile(bad, []byte("id: [malformed\n"), 0600))
	// A valid unrelated policy before the error must not become a partial set.
	unrelated := filepath.Join(t.TempDir(), "unrelated.yaml")
	require.NoError(t, os.WriteFile(unrelated, []byte("id: unrelated\nbuckets: [unrelated-bucket]\n"), 0600))
	require.Error(t, pm.ReloadPolicies([]string{unrelated, bad}))
	assert.True(t, pm.BucketDisablesEncryption(inst.Bucket))
	put(t, gw, inst.Bucket, after, data)
	// Restore policies before GET to reveal silently mis-encrypted writes.
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	assertReloadBypassObject(t, inst, gw, backend, before, data)
	assertReloadBypassObject(t, inst, gw, backend, after, data)
}

// Bounded concurrent functional coverage, not a time-based load workload.
// The deterministic source-boundary test lives in Tier 1.
func testPolicyReload_ConcurrentBypassWrites(t *testing.T, inst provider.Instance) {
	pm, path, gw := reloadBypassFixture(t, inst)
	backend := newS3Client(t, inst)
	const workers, writes = 4, 8
	data := bytes.Repeat([]byte("b"), 1024)
	prefix := uniqueKey(t) + "/"
	// Positive control before any reload.
	put(t, gw, inst.Bucket, prefix+"control", data)
	assertReloadBypassObject(t, inst, gw, backend, prefix+"control", data)
	stop, firstReload := make(chan struct{}), make(chan struct{})
	reloadDone := make(chan error, 1)
	go func() {
		first := true
		for {
			if err := pm.ReloadPolicies([]string{path}); err != nil {
				if first {
					close(firstReload)
				}
				reloadDone <- err
				return
			}
			if first {
				close(firstReload)
				first = false
			}
			select {
			case <-stop:
				reloadDone <- nil
				return
			default:
			}
		}
	}()
	<-firstReload
	var wg sync.WaitGroup
	client := gw.HTTPClient()
	errors := make(chan error, workers*writes)
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < writes; i++ {
				key := fmt.Sprintf("%s%d-%d", prefix, worker, i)
				req, err := http.NewRequest(http.MethodPut, objectURL(gw, inst.Bucket, key), bytes.NewReader(data))
				if err == nil {
					var resp *http.Response
					resp, err = client.Do(req)
					if err == nil {
						body, readErr := io.ReadAll(resp.Body)
						closeErr := resp.Body.Close()
						if resp.StatusCode != http.StatusOK {
							err = fmt.Errorf("PUT %s: %d: %s", key, resp.StatusCode, body)
						} else if readErr != nil {
							err = readErr
						} else {
							err = closeErr
						}
					}
				}
				if err != nil {
					errors <- err
				}
			}
		}(worker)
	}
	wg.Wait()
	close(stop)
	require.NoError(t, <-reloadDone)
	close(errors)
	for err := range errors {
		assert.NoError(t, err)
	}
	for worker := 0; worker < workers; worker++ {
		for i := 0; i < writes; i++ {
			assertReloadBypassObject(t, inst, gw, backend, fmt.Sprintf("%s%d-%d", prefix, worker, i), data)
		}
	}
	resp, err := client.Get(gw.URL + "/" + inst.Bucket + "?list-type=2&prefix=" + prefix)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var listing struct {
		Contents []struct {
			Key  string
			Size int64
		}
	}
	require.NoError(t, xml.NewDecoder(resp.Body).Decode(&listing))
	require.Len(t, listing.Contents, workers*writes+1)
	for _, obj := range listing.Contents {
		assert.Equal(t, int64(len(data)), obj.Size, "listing size for %s", obj.Key)
	}
}
