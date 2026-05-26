//go:build conformance && benchmark_local

// Package conformance — benchmark_local_test.go
//
// Local benchmark suite that exercises every local provider (MinIO, Garage,
// RustFS, SeaweedFS) against every relevant encryption configuration. Unlike
// the standard conformance tests this file is gated on the "benchmark_local"
// build tag so it never runs in CI.
//
// Run via:
//
//	make benchmark-local
//
// Environment variables (all optional):
//
//	BENCH_LOCAL_WORKERS       int           goroutines per config   default: 4
//	BENCH_LOCAL_DURATION      duration str  test duration           default: 30s
//	BENCH_LOCAL_OBJECT_SIZE   int (bytes)   single-object size      default: 1048576 (1 MiB)
//	BENCH_LOCAL_MPU_SIZE      int (bytes)   per-part MPU size       default: 5242880 (5 MiB, assembled from 4 parts = 20 MiB total)
//	BENCH_LOCAL_JSON_OUT      string        NDJSON output path      default: "" (no file)
//
// Results are reported via t.Logf (always) and, when BENCH_LOCAL_JSON_OUT is
// set, appended to that file as NDJSON (one JSON object per config × provider).
package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// ── Parameter resolution ─────────────────────────────────────────────────────

type benchLocalParams struct {
	workers    int
	duration   time.Duration
	objectSize int64 // single-object PutObject size
	mpuSize    int64 // per-part size for 4-part MPU upload
	jsonOut    string
}

func resolveBenchLocalParams() benchLocalParams {
	p := benchLocalParams{
		workers:    4,
		duration:   30 * time.Second,
		objectSize: 1 * 1024 * 1024,  // 1 MiB
		mpuSize:    5 * 1024 * 1024,  // 5 MiB per part × 4 parts = 20 MiB total
		jsonOut:    os.Getenv("BENCH_LOCAL_JSON_OUT"),
	}
	if v := envInt("BENCH_LOCAL_WORKERS"); v > 0 {
		p.workers = v
	}
	if v := envDuration("BENCH_LOCAL_DURATION"); v > 0 {
		p.duration = v
	}
	if v := envInt64("BENCH_LOCAL_OBJECT_SIZE"); v > 0 {
		p.objectSize = v
	}
	if v := envInt64("BENCH_LOCAL_MPU_SIZE"); v > 0 {
		p.mpuSize = v
	}
	return p
}

// ── Encryption config descriptors ───────────────────────────────────────────

// benchConfig defines one encryption variant for the benchmark matrix.
type benchConfig struct {
	// name is the short label used in t.Run names and JSON output.
	name string
	// buildOpts returns the harness options for this config given a test
	// context. It may allocate key material and register cleanup.
	buildOpts func(t *testing.T, inst provider.Instance) []harness.Option
	// mpu indicates this config requires a Valkey container and an
	// WithEncryptedMPUForBucket option.
	mpu bool
	// ranged indicates the benchmark performs ranged GETs (200 KiB object,
	// 5 sub-ranges) instead of full-object reads.
	ranged bool
}

const benchLocalPassword = "benchmark-local-password-long-enough"

// allBenchConfigs returns the complete matrix of 8 encryption configurations.
func allBenchConfigs(t *testing.T) []benchConfig {
	t.Helper()
	return []benchConfig{
		{
			name: "Password_PBKDF2_Chunked",
			buildOpts: func(t *testing.T, _ provider.Instance) []harness.Option {
				return []harness.Option{
					harness.WithEncryptionPassword(benchLocalPassword),
					harness.WithChunking(true),
				}
			},
		},
		{
			name: "Password_Argon2id_Chunked",
			buildOpts: func(t *testing.T, _ provider.Instance) []harness.Option {
				return []harness.Option{
					harness.WithEncryptionPassword(benchLocalPassword),
					harness.WithChunking(true),
					harness.WithKDFAlgorithm("argon2id"),
					harness.WithArgon2idParams(2, 19456, 1), // OWASP recommendations — equivalent to PBKDF2 600k
				}
			},
		},
		{
			name: "AES256GCM_KEK_Chunked",
			buildOpts: func(t *testing.T, _ provider.Instance) []harness.Option {
				kek := make([]byte, 32)
				if _, err := rand.Read(kek); err != nil {
					t.Fatalf("rand.Read kek: %v", err)
				}
				km, err := crypto.NewAESKEKManager(map[int][]byte{1: kek}, 1)
				if err != nil {
					t.Fatalf("NewAESKEKManager: %v", err)
				}
				t.Cleanup(func() { _ = km.Close(context.Background()) })
				return []harness.Option{
					harness.WithEncryptionPassword(benchLocalPassword),
					harness.WithKeyManager(km),
					harness.WithChunking(true),
				}
			},
		},
		{
			name: "RSA_OAEP_KEK_Chunked",
			buildOpts: func(t *testing.T, _ provider.Instance) []harness.Option {
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("rsa.GenerateKey: %v", err)
				}
				km, err := crypto.NewRSAKEKManager(privKey, 1)
				if err != nil {
					t.Fatalf("NewRSAKEKManager: %v", err)
				}
				t.Cleanup(func() { _ = km.Close(context.Background()) })
				return []harness.Option{
					harness.WithEncryptionPassword(benchLocalPassword),
					harness.WithKeyManager(km),
					harness.WithChunking(true),
				}
			},
		},
		{
			name: "AES256GCM_KEK_EncryptedMPU_50MiB",
			mpu:  true,
			buildOpts: func(t *testing.T, inst provider.Instance) []harness.Option {
				kek := make([]byte, 32)
				if _, err := rand.Read(kek); err != nil {
					t.Fatalf("rand.Read kek: %v", err)
				}
				km, err := crypto.NewAESKEKManager(map[int][]byte{1: kek}, 1)
				if err != nil {
					t.Fatalf("NewAESKEKManager: %v", err)
				}
				t.Cleanup(func() { _ = km.Close(context.Background()) })
				return []harness.Option{
					harness.WithEncryptionPassword(benchLocalPassword),
					harness.WithKeyManager(km),
				}
			},
		},
		{
			name: "Password_PBKDF2_EncryptedMPU_50MiB",
			mpu:  true,
			buildOpts: func(t *testing.T, inst provider.Instance) []harness.Option {
				km, err := crypto.NewPasswordKeyManager([]byte(benchLocalPassword), crypto.DefaultPBKDF2Iterations)
				if err != nil {
					t.Fatalf("NewPasswordKeyManager: %v", err)
				}
				t.Cleanup(func() { _ = km.Close(context.Background()) })
				return []harness.Option{
					harness.WithEncryptionPassword(benchLocalPassword),
					harness.WithKeyManager(km),
				}
			},
		},
		{
			name: "RSA_OAEP_KEK_EncryptedMPU_50MiB",
			mpu:  true,
			buildOpts: func(t *testing.T, inst provider.Instance) []harness.Option {
				privKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatalf("rsa.GenerateKey: %v", err)
				}
				km, err := crypto.NewRSAKEKManager(privKey, 1)
				if err != nil {
					t.Fatalf("NewRSAKEKManager: %v", err)
				}
				t.Cleanup(func() { _ = km.Close(context.Background()) })
				return []harness.Option{
					harness.WithEncryptionPassword(benchLocalPassword),
					harness.WithKeyManager(km),
				}
			},
		},
		{
			name:   "AES256GCM_KEK_RangedGet_MultiChunk",
			ranged: true,
			buildOpts: func(t *testing.T, _ provider.Instance) []harness.Option {
				kek := make([]byte, 32)
				if _, err := rand.Read(kek); err != nil {
					t.Fatalf("rand.Read kek: %v", err)
				}
				km, err := crypto.NewAESKEKManager(map[int][]byte{1: kek}, 1)
				if err != nil {
					t.Fatalf("NewAESKEKManager: %v", err)
				}
				t.Cleanup(func() { _ = km.Close(context.Background()) })
				return []harness.Option{
					harness.WithEncryptionPassword(benchLocalPassword),
					harness.WithKeyManager(km),
					harness.WithChunking(true),
				}
			},
		},
	}
}

// ── Top-level benchmark runner ───────────────────────────────────────────────

// TestBenchmarkLocal is the entry point for the local benchmark suite.
// It runs every local provider × every encryption config, reports throughput /
// latency percentiles, and optionally writes NDJSON to BENCH_LOCAL_JSON_OUT.
func TestBenchmarkLocal(t *testing.T) {
	p := resolveBenchLocalParams()
	t.Logf("benchmark-local params: workers=%d duration=%s object=%s mpu-part=%s",
		p.workers, p.duration, humanBytes(p.objectSize), humanBytes(p.mpuSize))

	providers := provider.All()
	if len(providers) == 0 {
		t.Skip("No providers registered; ensure Docker is available")
	}

	configs := allBenchConfigs(t)

	for _, prov := range providers {
		prov := prov
		// Only run against local providers (skip if external creds are required).
		if prov.Capabilities()&provider.CapLoadTest == 0 {
			t.Logf("skipping non-local provider %q (no CapLoadTest)", prov.Name())
			continue
		}

		t.Run(prov.Name(), func(t *testing.T) {
			ctx := context.Background()
			inst := prov.Start(ctx, t)

			for _, cfg := range configs {
				cfg := cfg
				t.Run(cfg.name, func(t *testing.T) {
					runBenchConfig(t, inst, p, cfg)
				})
			}
		})
	}
}

// ── Per-config runner ────────────────────────────────────────────────────────

func runBenchConfig(t *testing.T, inst provider.Instance, p benchLocalParams, cfg benchConfig) {
	t.Helper()
	ctx := context.Background()

	opts := cfg.buildOpts(t, inst)

	var gw *harness.Gateway
	if cfg.mpu {
		vk := provider.StartValkey(ctx, t)
		opts = append(opts,
			harness.WithValkeyAddr(vk.Addr),
			harness.WithEncryptedMPUForBucket(inst.Bucket),
		)
		gw = harness.StartGateway(t, inst, opts...)
		runBenchMPU(t, inst, gw, p, cfg)
		return
	}

	if cfg.ranged {
		gw = harness.StartGateway(t, inst, opts...)
		runBenchRangedGet(t, inst, gw, p, cfg)
		return
	}

	gw = harness.StartGateway(t, inst, opts...)
	runBenchPutGet(t, inst, gw, p, cfg)
}

// ── PutObject / GetObject benchmark ─────────────────────────────────────────

func runBenchPutGet(t *testing.T, inst provider.Instance, gw *harness.Gateway, p benchLocalParams, cfg benchConfig) {
	t.Helper()

	// Seed object (written once, read by all workers).
	objectKey := uniqueKey(t)
	data := make([]byte, p.objectSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand.Read data: %v", err)
	}
	put(t, gw, inst.Bucket, objectKey, data)

	var (
		total   int64
		success int64
		failed  int64
		mu      sync.Mutex
		lats    []time.Duration
		totBytes int64
	)

	benchCtx, benchCancel := context.WithTimeout(context.Background(), p.duration)
	defer benchCancel()

	var wg sync.WaitGroup
	client := gw.HTTPClient()

	for w := 0; w < p.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-benchCtx.Done():
					return
				default:
				}
				req, _ := http.NewRequestWithContext(benchCtx, "GET", objectURL(gw, inst.Bucket, objectKey), nil)
				t0 := time.Now()
				resp, err := client.Do(req)
				elapsed := time.Since(t0)
				atomic.AddInt64(&total, 1)
				if err != nil || resp.StatusCode != http.StatusOK {
					if resp != nil {
						resp.Body.Close()
					}
					atomic.AddInt64(&failed, 1)
					continue
				}
				n, _ := drainBody(resp)
				resp.Body.Close()
				atomic.AddInt64(&success, 1)
				mu.Lock()
				lats = append(lats, elapsed)
				totBytes += n
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	reportBenchResults(t, inst.ProviderName, cfg.name, total, success, failed, lats, totBytes, p.duration, p.jsonOut)
}

// ── Ranged GET benchmark (200 KiB object, 5 sub-ranges, cycling) ─────────────

func runBenchRangedGet(t *testing.T, inst provider.Instance, gw *harness.Gateway, p benchLocalParams, cfg benchConfig) {
	t.Helper()

	const rangedObjSize = 200 * 1024

	data := make([]byte, rangedObjSize)
	for i := range data {
		data[i] = byte(i & 0xFF)
	}
	objectKey := uniqueKey(t)
	put(t, gw, inst.Bucket, objectKey, data)

	const chunkSize = 64 * 1024
	rangeHeaders := []string{
		"bytes=0-1023",
		fmt.Sprintf("bytes=%d-%d", chunkSize-512, chunkSize+511),
		fmt.Sprintf("bytes=%d-%d", chunkSize, 2*chunkSize-1),
		fmt.Sprintf("bytes=%d-%d", 2*chunkSize-256, 2*chunkSize+255),
		fmt.Sprintf("bytes=0-%d", rangedObjSize-1),
	}

	var (
		total    int64
		success  int64
		failed   int64
		mu       sync.Mutex
		lats     []time.Duration
		totBytes int64
	)

	benchCtx, benchCancel := context.WithTimeout(context.Background(), p.duration)
	defer benchCancel()

	var wg sync.WaitGroup
	client := gw.HTTPClient()

	for w := 0; w < p.workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			var idx int64
			for {
				select {
				case <-benchCtx.Done():
					return
				default:
				}
				rh := rangeHeaders[idx%int64(len(rangeHeaders))]
				idx++
				req, _ := http.NewRequestWithContext(benchCtx, "GET", objectURL(gw, inst.Bucket, objectKey), nil)
				req.Header.Set("Range", rh)
				t0 := time.Now()
				resp, err := client.Do(req)
				elapsed := time.Since(t0)
				atomic.AddInt64(&total, 1)
				if err != nil || resp.StatusCode != http.StatusPartialContent {
					if resp != nil {
						resp.Body.Close()
					}
					atomic.AddInt64(&failed, 1)
					continue
				}
				n, _ := drainBody(resp)
				resp.Body.Close()
				atomic.AddInt64(&success, 1)
				mu.Lock()
				lats = append(lats, elapsed)
				totBytes += n
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()

	reportBenchResults(t, inst.ProviderName, cfg.name, total, success, failed, lats, totBytes, p.duration, p.jsonOut)
}

// ── Encrypted MPU benchmark (4 parts × mpuSize, single upload + GET) ─────────

// xmlUnmarshal is a small helper that unmarshals XML into a value pointer.
func xmlUnmarshal(data []byte, v interface{}) error {
	return xml.Unmarshal(data, v)
}

// mpuUploadOnce performs a single 4-part encrypted MPU cycle using raw HTTP
// calls (no t.Fatal) so it is safe to invoke from worker goroutines.
// Returns (bytesTransferred, error). Any transient backend error (5xx, network
// issue) is returned as a non-nil error so the caller can count it as a failed
// iteration without panicking.
// mpuUploadOnce performs a single 4-part encrypted MPU cycle using raw HTTP
// calls (no t.Fatal) so it is safe to invoke from worker goroutines.
// ctx is propagated into every HTTP request so callers can cancel in-flight
// work when the benchmark deadline expires.
// Returns (bytesTransferred, error). Any transient backend error (5xx, network
// issue, context cancellation) is returned as a non-nil error so the caller
// can count it as a failed iteration without panicking.
func mpuUploadOnce(ctx context.Context, client *http.Client, gwURL, bucket, key string, partData []byte, numParts int) (int64, error) {
	totalExpected := int64(numParts) * int64(len(partData))

	// --- Initiate ---
	initURL := fmt.Sprintf("%s/%s/%s?uploads", gwURL, bucket, key)
	req, _ := http.NewRequestWithContext(ctx, "POST", initURL, nil)
	req.Header.Set("Content-Type", "application/xml")
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("InitiateMultipartUpload: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("InitiateMultipartUpload: status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var initResult struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xmlUnmarshal(body, &initResult); err != nil || initResult.UploadID == "" {
		return 0, fmt.Errorf("InitiateMultipartUpload: parse uploadId: %v", err)
	}
	uploadID := initResult.UploadID

	// --- Upload parts ---
	etags := make([]string, numParts)
	for i := 0; i < numParts; i++ {
		partURL := fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s",
			gwURL, bucket, key, i+1, uploadID)
		req, _ := http.NewRequestWithContext(ctx, "PUT", partURL, bytes.NewReader(partData))
		resp, err := client.Do(req)
		if err != nil {
			_, _ = abortMPURaw(context.Background(), client, gwURL, bucket, key, uploadID)
			return 0, fmt.Errorf("UploadPart #%d: %w", i+1, err)
		}
		partBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			_, _ = abortMPURaw(context.Background(), client, gwURL, bucket, key, uploadID)
			return 0, fmt.Errorf("UploadPart #%d: status %d: %s", i+1, resp.StatusCode, truncate(string(partBody), 200))
		}
		etags[i] = resp.Header.Get("ETag")
	}

	// --- Complete ---
	xmlBody := buildCompleteXML(etags)
	completeURL := fmt.Sprintf("%s/%s/%s?uploadId=%s", gwURL, bucket, key, uploadID)
	req, _ = http.NewRequestWithContext(ctx, "POST", completeURL, strings.NewReader(xmlBody))
	req.Header.Set("Content-Type", "application/xml")
	resp, err = client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("CompleteMultipartUpload: %w", err)
	}
	completeBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("CompleteMultipartUpload: status %d: %s", resp.StatusCode, truncate(string(completeBody), 200))
	}

	// --- Read back ---
	getReq, _ := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/%s/%s", gwURL, bucket, key), nil)
	getResp, err := client.Do(getReq)
	if err != nil {
		return 0, fmt.Errorf("GET assembled object: %w", err)
	}
	n, copyErr := io.Copy(io.Discard, getResp.Body)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET assembled object: status %d", getResp.StatusCode)
	}
	if copyErr != nil {
		return 0, fmt.Errorf("GET assembled object: read body: %w", copyErr)
	}
	if n != totalExpected {
		return 0, fmt.Errorf("GET assembled object: got %d bytes, want %d", n, totalExpected)
	}
	return totalExpected, nil
}

// abortMPURaw sends an AbortMultipartUpload request (best-effort, errors ignored).
// Pass context.Background() so abort attempts always complete even after the
// benchmark deadline context is cancelled.
func abortMPURaw(ctx context.Context, client *http.Client, gwURL, bucket, key, uploadID string) (int, error) {
	u := fmt.Sprintf("%s/%s/%s?uploadId=%s", gwURL, bucket, key, uploadID)
	req, _ := http.NewRequestWithContext(ctx, "DELETE", u, nil)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, nil
}

// buildCompleteXML builds the CompleteMultipartUpload XML body from a slice of ETags.
func buildCompleteXML(etags []string) string {
	var b strings.Builder
	b.WriteString("<CompleteMultipartUpload>")
	for i, e := range etags {
		fmt.Fprintf(&b, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", i+1, e)
	}
	b.WriteString("</CompleteMultipartUpload>")
	return b.String()
}

// truncate shortens a string to maxLen for log messages.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "…"
}

func runBenchMPU(t *testing.T, inst provider.Instance, gw *harness.Gateway, p benchLocalParams, cfg benchConfig) {
	t.Helper()

	// Build per-part payload once (shared read-only across goroutines).
	const numParts = 4
	partData := make([]byte, p.mpuSize)
	if _, err := rand.Read(partData); err != nil {
		t.Fatalf("rand.Read part: %v", err)
	}

	var (
		total    int64
		success  int64
		failed   int64
		mu       sync.Mutex
		lats     []time.Duration
		totBytes int64
	)

	// benchCtx is cancelled at the benchmark deadline so all in-flight HTTP
	// requests (which can block indefinitely on slow backends like SeaweedFS)
	// are forcefully terminated when time is up.
	benchCtx, benchCancel := context.WithTimeout(context.Background(), p.duration)
	defer benchCancel()

	var wg sync.WaitGroup
	client := gw.HTTPClient()

	for w := 0; w < p.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-benchCtx.Done():
					return
				default:
				}
				key := uniqueKey(t)
				t0 := time.Now()
				n, err := mpuUploadOnce(benchCtx, client, gw.URL, inst.Bucket, key, partData, numParts)
				elapsed := time.Since(t0)
				atomic.AddInt64(&total, 1)
				if err != nil {
					atomic.AddInt64(&failed, 1)
					continue
				}
				atomic.AddInt64(&success, 1)
				mu.Lock()
				lats = append(lats, elapsed)
				totBytes += n
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	reportBenchResults(t, inst.ProviderName, cfg.name, total, success, failed, lats, totBytes, p.duration, p.jsonOut)
}

// ── Reporting ────────────────────────────────────────────────────────────────

// benchLocalRecord is the JSON schema for BENCH_LOCAL_JSON_OUT output.
// It extends the SummaryRecord with provider, config, duration, and timestamp
// so every line is independently identifiable.
type benchLocalRecord struct {
	SummaryRecord
	Provider  string `json:"provider"`
	Config    string `json:"config"`
	Duration  string `json:"duration"`
	Timestamp string `json:"timestamp"`
}

func reportBenchResults(
	t *testing.T,
	providerName string,
	cfgName string,
	total, success, failed int64,
	lats []time.Duration,
	totBytes int64,
	duration time.Duration,
	jsonOut string,
) {
	t.Helper()

	percentiles := Percentiles(lats)
	throughputMBPS := float64(totBytes) / 1024 / 1024 / duration.Seconds()

	t.Logf("[%s] %-45s total=%d ok=%d fail=%d throughput=%.2f MiB/s p50=%s p95=%s p99=%s",
		providerName,
		cfgName,
		total, success, failed,
		throughputMBPS,
		time.Duration(percentiles.P50),
		time.Duration(percentiles.P95),
		time.Duration(percentiles.P99),
	)

	// A non-zero failure count is logged but does not fail the test.
	// In benchmark mode, "failures" are expected: context-cancelled in-flight
	// requests when the deadline fires, and transient backend errors (e.g.
	// SeaweedFS queue saturation) that do not indicate a gateway bug.
	if failed > 0 {
		t.Logf("WARN: %s: %d/%d iterations did not complete (context cancelled or transient error)", cfgName, failed, total)
	}

	if jsonOut != "" {
		rec := benchLocalRecord{
			Provider:  providerName,
			Config:    cfgName,
			Duration:  duration.String(),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			SummaryRecord: SummaryRecord{
				Test:           providerName + "/" + cfgName,
				ThroughputMBPS: throughputMBPS,
				LatencyNS:      percentiles,
				Errors:         failed,
			},
		}
		b, err := json.Marshal(rec)
		if err != nil {
			t.Logf("WARN: marshal benchmark record: %v", err)
			return
		}
		f, err := os.OpenFile(jsonOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			t.Logf("WARN: open %s: %v", jsonOut, err)
			return
		}
		defer f.Close()
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Logf("WARN: write %s: %v", jsonOut, err)
		}
	}
}

// ── Utilities ────────────────────────────────────────────────────────────────

// envInt parses an int from the named environment variable; returns 0 on error.
// NOTE: envInt is also defined in load_test.go (same package), so we only need
// it if load_test.go is NOT in scope. Since both files share the same build tag
// "conformance", the function from load_test.go is reused — this file must NOT
// redefine it. We guard with the helper below to avoid duplicate declarations
// at compile time.
// The helpers envDuration and envInt64 from load_test.go are also available.

// drainBody reads the response body to completion and returns the number of
// bytes consumed. It does NOT close the body — the caller must do that.
// io.Copy handles all EOF variants correctly, including wrapped errors from
// HTTP/1.1 chunked transports (e.g. SeaweedFS).
func drainBody(resp *http.Response) (int64, error) {
	return io.Copy(io.Discard, resp.Body)
}

// strconvInt is a local alias for strconv.Atoi to avoid lint warnings about
// the blank identifier when the helper is already provided by load_test.go.
var _ = strconv.Atoi
