package s3

// V0.6-PERF-2 Phase A — Baseline benchmarks for the S3 client retry path.
// These benchmarks capture pre-change behaviour (SDK default retryer) so that
// the Phase F "after" measurements can compute a benchstat delta.
//
// To capture the baseline:
//   go test -run=^$ -bench=BenchmarkS3Client -benchmem -benchtime=10s -count=5 \
//       ./internal/s3/ > docs/perf/v0.6-perf-2-baseline.txt
//
// Note: fault injection is inline here (not imported from test/harness) to
// avoid circular imports (harness imports internal/s3). The same fault logic
// lives in test/harness/faulty_s3.go for integration test use.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ---- inline fault injector --------------------------------------------------

// benchFaultRule describes when and how to inject a fault for benchmarks.
type benchFaultRule struct {
	statusCode     int
	probabilityPct int
}

// benchFaultyTransport wraps an http.RoundTripper and injects HTTP status
// faults at a configurable rate using a seeded, deterministic RNG.
type benchFaultyTransport struct {
	inner http.RoundTripper
	rules []benchFaultRule
	mu    sync.Mutex
	rng   *rand.Rand
}

func newBenchFaultyTransport(inner http.RoundTripper, seed int64, rules []benchFaultRule) *benchFaultyTransport {
	return &benchFaultyTransport{
		inner: inner,
		rules: rules,
		rng:   rand.New(rand.NewSource(seed)), // #nosec G404 -- deterministic benchmark fault timing only; never keys, tokens, or authorization
	}
}

func (f *benchFaultyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for _, rule := range f.rules {
		f.mu.Lock()
		roll := f.rng.Intn(100)
		f.mu.Unlock()
		if roll < rule.probabilityPct {
			body := fmt.Sprintf(`<Error><Code>ServiceUnavailable</Code><Message>Injected %d</Message></Error>`, rule.statusCode)
			return &http.Response{
				StatusCode: rule.statusCode,
				Status:     fmt.Sprintf("%d %s", rule.statusCode, http.StatusText(rule.statusCode)),
				Header:     http.Header{"Content-Type": []string{"application/xml"}, "x-amz-request-id": []string{"BENCH01"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    req,
			}, nil
		}
	}
	return f.inner.RoundTrip(req)
}

// ---- stub OK transports -------------------------------------------------------

// benchOKTransport always returns HTTP 200 with an empty body.
type benchOKTransport struct{}

func (benchOKTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := benchBodyFor(req)
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     http.Header{"Content-Type": []string{"application/xml"}, "ETag": []string{`"benchetag"`}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func benchBodyFor(req *http.Request) string {
	q := req.URL.RawQuery
	if strings.Contains(q, "uploadId") && req.Method == http.MethodPost {
		return `<CompleteMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><ETag>"abc"</ETag></CompleteMultipartUploadResult>`
	}
	if strings.Contains(q, "uploads") && req.Method == http.MethodPost {
		return `<InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>uid</UploadId></InitiateMultipartUploadResult>`
	}
	return ``
}

// benchHeadOKTransport always returns a 200 HEAD response.
type benchHeadOKTransport struct{}

func (benchHeadOKTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	h := make(http.Header)
	h.Set("Content-Length", "1024")
	h.Set("Last-Modified", time.Now().Format(http.TimeFormat))
	return &http.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     h,
		Body:       io.NopCloser(http.NoBody),
		Request:    req,
	}, nil
}

// ---- helpers ----------------------------------------------------------------

// buildBenchClient constructs a raw *s3.Client using the supplied transport.
// This bypasses the ClientFactory intentionally: we want to benchmark the
// SDK + custom transport layer directly, not the factory machinery.
func buildBenchClient(b testing.TB, transport http.RoundTripper) *s3.Client {
	b.Helper()
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIATEST", "secrettest", "")),
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
		awsconfig.WithHTTPClient(&http.Client{Transport: transport}),
	)
	if err != nil {
		b.Fatalf("buildBenchClient: %v", err)
	}
	return s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String("http://localhost:9000")
		o.UsePathStyle = true
	})
}

// ---- benchmarks -------------------------------------------------------------

// BenchmarkS3Client_PutObject_NoFault measures PutObject throughput with no
// injected faults.  Establishes the happy-path baseline.
func BenchmarkS3Client_PutObject_NoFault(b *testing.B) {
	client := buildBenchClient(b, benchOKTransport{})
	payload := bytes.Repeat([]byte("x"), 4*1024) // 4 KiB body
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := client.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket:        aws.String("bench-bucket"),
			Key:           aws.String("bench-key"),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
		})
		if err != nil {
			b.Fatalf("PutObject failed: %v", err)
		}
	}
}

// BenchmarkS3Client_PutObject_ThunderingHerd_10pct503 injects 503 responses
// at a 10 % rate to simulate moderate backend pressure.  The SDK default
// retryer (3 attempts, exponential backoff with jitter) is used.
func BenchmarkS3Client_PutObject_ThunderingHerd_10pct503(b *testing.B) {
	rules := []benchFaultRule{{statusCode: 503, probabilityPct: 10}}
	transport := newBenchFaultyTransport(benchOKTransport{}, 42, rules)
	client := buildBenchClient(b, transport)
	payload := bytes.Repeat([]byte("x"), 4*1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = client.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket:        aws.String("bench-bucket"),
			Key:           aws.String("bench-key"),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
		})
		// Errors are expected when all 3 SDK attempts fail; do not fatal.
	}
}

// BenchmarkS3Client_PutObject_ThunderingHerd_50pct503 measures behaviour
// under heavy fault load (50 % 503).  Decorrelated jitter should shine here.
func BenchmarkS3Client_PutObject_ThunderingHerd_50pct503(b *testing.B) {
	rules := []benchFaultRule{{statusCode: 503, probabilityPct: 50}}
	transport := newBenchFaultyTransport(benchOKTransport{}, 42, rules)
	client := buildBenchClient(b, transport)
	payload := bytes.Repeat([]byte("x"), 4*1024)
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = client.PutObject(context.Background(), &s3.PutObjectInput{
			Bucket:        aws.String("bench-bucket"),
			Key:           aws.String("bench-key"),
			Body:          bytes.NewReader(payload),
			ContentLength: aws.Int64(int64(len(payload))),
		})
	}
}

// BenchmarkS3Client_HeadObject_ThunderingHerd_50pct503 exercises the
// read-path (idempotent) retry under heavy fault load.
// b.SetBytes omitted because HEAD has no payload body; the benchmark measures
// per-request control-plane latency and retry cost, not throughput.
func BenchmarkS3Client_HeadObject_ThunderingHerd_50pct503(b *testing.B) {
	rules := []benchFaultRule{{statusCode: 503, probabilityPct: 50}}
	transport := newBenchFaultyTransport(benchHeadOKTransport{}, 42, rules)
	client := buildBenchClient(b, transport)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = client.HeadObject(context.Background(), &s3.HeadObjectInput{
			Bucket: aws.String("bench-bucket"),
			Key:    aws.String("bench-key"),
		})
	}
}
