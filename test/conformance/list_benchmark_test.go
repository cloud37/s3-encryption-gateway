//go:build conformance && benchmark_list

// Package conformance contains the manually-run large-list benchmark.
//
// This file deliberately has a second build tag in addition to conformance.
// It is not registered in TestConformance and therefore cannot run as part of
// any CI conformance target.
package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	internalS3 "github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	dto "github.com/prometheus/client_model/go"
)

type listBenchmarkParams struct {
	objects    int
	objectSize int
	pageSize   int32
	rounds     int
	jsonOut    string
}

type listBenchmarkScenario struct {
	name               string
	populateViaGateway bool
	translate          bool
	fallbackHead       bool
}

type listBenchmarkResult struct {
	Provider       string  `json:"provider"`
	Scenario       string  `json:"scenario"`
	Objects        int     `json:"objects"`
	PageSize       int32   `json:"page_size"`
	Rounds         int     `json:"rounds"`
	DirectSeconds  float64 `json:"direct_seconds"`
	GatewaySeconds float64 `json:"gateway_seconds"`
	DirectObjects  int     `json:"direct_objects"`
	GatewayObjects int     `json:"gateway_objects"`
	GatewayListOps float64 `json:"gateway_list_operations"`
	GatewayHeadOps float64 `json:"gateway_head_operations"`
	CacheHits      float64 `json:"cache_hits"`
	CacheMisses    float64 `json:"cache_misses"`
	FallbackHeads  float64 `json:"fallback_heads"`
}

func listBenchmarkParamsFromEnv() listBenchmarkParams {
	return listBenchmarkParams{
		objects:    listBenchInt("BENCH_LIST_OBJECTS", 1000),
		objectSize: listBenchInt("BENCH_LIST_OBJECT_SIZE", 1024),
		pageSize:   int32(listBenchInt("BENCH_LIST_PAGE_SIZE", 1000)),
		rounds:     listBenchInt("BENCH_LIST_ROUNDS", 1),
		jsonOut:    os.Getenv("BENCH_LIST_JSON_OUT"),
	}
}

func listBenchInt(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func TestBenchmarkListEnumeration(t *testing.T) {
	p := listBenchmarkParamsFromEnv()
	if p.pageSize > 1000 {
		p.pageSize = 1000
	}
	if len(provider.All()) == 0 {
		t.Skip("no providers registered; start Docker or set external provider credentials")
	}

	scenarios := []listBenchmarkScenario{
		{name: "warm-cache", populateViaGateway: true, translate: true},
		{name: "cold-cache", translate: true},
		{name: "fallback-head", translate: true, fallbackHead: true},
		{name: "translation-disabled", translate: false},
	}
	for _, backend := range provider.All() {
		backend := backend
		t.Run(backend.Name(), func(t *testing.T) {
			inst := backend.Start(context.Background(), t)
			for _, scenario := range scenarios {
				runListBenchmarkScenario(t, inst, scenario, p)
			}
		})
	}
}

func runListBenchmarkScenario(t *testing.T, inst provider.Instance, scenario listBenchmarkScenario, p listBenchmarkParams) {
	t.Helper()
	prefix := fmt.Sprintf("conformance-list-bench/%s/%s/", scenario.name, uniqueSuffix(t))
	directClient := newS3Client(t, inst)

	var valkeyAddr string
	if scenario.translate {
		valkeyAddr = provider.StartValkey(context.Background(), t).Addr
	}

	var gw *harness.Gateway
	if scenario.populateViaGateway {
		gw = harness.StartGateway(t, inst, listBenchGatewayOptions(valkeyAddr, scenario)...)
		listBenchPutGateway(t, gw, inst.Bucket, prefix, p)
	} else {
		listBenchPutBackend(t, directClient, inst, prefix, p)
		gw = harness.StartGateway(t, inst, listBenchGatewayOptions(valkeyAddr, scenario)...)
	}

	directStart := time.Now()
	directObjects := 0
	for i := 0; i < p.rounds; i++ {
		directObjects = listBenchListBackend(t, directClient, inst.Bucket, prefix, p.pageSize)
	}
	directSeconds := time.Since(directStart).Seconds()

	gatewayStart := time.Now()
	gatewayObjects := 0
	for i := 0; i < p.rounds; i++ {
		gatewayObjects = listBenchListGateway(t, gw, inst.Bucket, prefix, p.pageSize)
	}
	gatewaySeconds := time.Since(gatewayStart).Seconds()

	if directObjects != p.objects || gatewayObjects != p.objects {
		t.Fatalf("listing count mismatch: direct=%d gateway=%d want=%d", directObjects, gatewayObjects, p.objects)
	}

	result := listBenchmarkResult{
		Provider: inst.ProviderName, Scenario: scenario.name, Objects: p.objects,
		PageSize: p.pageSize, Rounds: p.rounds, DirectSeconds: directSeconds,
		GatewaySeconds: gatewaySeconds, DirectObjects: directObjects,
		GatewayObjects: gatewayObjects,
		GatewayListOps: gatewayMetric(t, gw, "s3_operations_total", "operation", "ListObjects"),
		GatewayHeadOps: gatewayMetric(t, gw, "s3_operations_total", "operation", "HeadObject"),
		CacheHits:      gatewayMetric(t, gw, "list_size_cache_hits_total", "", ""),
		CacheMisses:    gatewayMetric(t, gw, "list_size_cache_misses_total", "", ""),
		FallbackHeads:  gatewayMetric(t, gw, "list_size_fallback_head_total", "", ""),
	}
	t.Logf("%s/%s: direct=%.3fs gateway=%.3fs direct_objects=%d gateway_objects=%d list_ops=%.0f head_ops=%.0f cache_hits=%.0f cache_misses=%.0f fallback_heads=%.0f",
		inst.ProviderName, scenario.name, directSeconds, gatewaySeconds, directObjects,
		gatewayObjects, result.GatewayListOps, result.GatewayHeadOps, result.CacheHits,
		result.CacheMisses, result.FallbackHeads)
	appendListBenchmarkResult(t, p.jsonOut, result)
}

func listBenchGatewayOptions(valkeyAddr string, scenario listBenchmarkScenario) []harness.Option {
	options := make([]harness.Option, 0, 2)
	if valkeyAddr != "" {
		options = append(options, harness.WithValkeyAddr(valkeyAddr))
	}
	options = append(options, harness.WithConfigMutator(func(cfg *config.Config) {
		cfg.ListSizeTranslate.Enabled = scenario.translate
		cfg.ListSizeTranslate.FallbackHeadEnabled = scenario.fallbackHead
		cfg.ListSizeTranslate.FallbackHeadConcurrency = 32
		cfg.ListSizeTranslate.FallbackHeadTimeout = 30 * time.Second
	}))
	return options
}

func listBenchPutGateway(t *testing.T, gw *harness.Gateway, bucket, prefix string, p listBenchmarkParams) {
	t.Helper()
	data := bytes.Repeat([]byte("x"), p.objectSize)
	for i := 0; i < p.objects; i++ {
		put(t, gw, bucket, fmt.Sprintf("%sobj-%06d", prefix, i), data)
	}
}

func listBenchPutBackend(t *testing.T, client internalS3.Client, inst provider.Instance, prefix string, p listBenchmarkParams) {
	t.Helper()
	engine, err := crypto.NewEngine([]byte("test-encryption-password-123456"))
	if err != nil {
		t.Fatalf("create benchmark encryption engine: %v", err)
	}
	data := bytes.Repeat([]byte("x"), p.objectSize)
	for i := 0; i < p.objects; i++ {
		putEncryptedObject(t, client, engine, inst.Bucket, fmt.Sprintf("%sobj-%06d", prefix, i), data, nil)
	}
}

func listBenchListBackend(t *testing.T, client internalS3.Client, bucket, prefix string, pageSize int32) int {
	t.Helper()
	count := 0
	token := ""
	for {
		result, err := client.ListObjects(context.Background(), bucket, prefix, internalS3.ListOptions{
			ContinuationToken: token,
			MaxKeys:           pageSize,
		})
		if err != nil {
			t.Fatalf("direct list: %v", err)
		}
		count += len(result.Objects)
		if !result.IsTruncated || result.NextContinuationToken == "" {
			return count
		}
		token = result.NextContinuationToken
	}
}

func listBenchListGateway(t *testing.T, gw *harness.Gateway, bucket, prefix string, pageSize int32) int {
	t.Helper()
	count := 0
	token := ""
	client := gw.HTTPClient()
	for {
		q := url.Values{"list-type": {"2"}, "prefix": {prefix}, "max-keys": {strconv.FormatInt(int64(pageSize), 10)}}
		if token != "" {
			q.Set("continuation-token", token)
		}
		resp, err := client.Get(fmt.Sprintf("%s/%s?%s", gw.URL, bucket, q.Encode()))
		if err != nil {
			t.Fatalf("gateway list: %v", err)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("gateway list: status=%d read=%v body=%s", resp.StatusCode, readErr, body)
		}
		var result s3ListBucketResult
		if err := xml.Unmarshal(body, &result); err != nil {
			t.Fatalf("gateway list XML: %v", err)
		}
		count += len(result.Contents)
		if !result.IsTruncated || result.NextContinuationToken == "" {
			return count
		}
		token = result.NextContinuationToken
	}
}

func gatewayMetric(t *testing.T, gw *harness.Gateway, name, label, value string) float64 {
	t.Helper()
	families, err := gw.Metrics.Gather()
	if err != nil {
		t.Fatalf("gather gateway metrics: %v", err)
	}
	var total float64
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if label != "" && !metricHasLabel(metric, label, value) {
				continue
			}
			if metric.Counter != nil {
				total += metric.Counter.GetValue()
			} else if metric.Gauge != nil {
				total += metric.Gauge.GetValue()
			}
		}
	}
	return total
}

func metricHasLabel(metric *dto.Metric, label, value string) bool {
	for _, pair := range metric.GetLabel() {
		if pair.GetName() == label && pair.GetValue() == value {
			return true
		}
	}
	return false
}

func appendListBenchmarkResult(t *testing.T, path string, result listBenchmarkResult) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Logf("open benchmark result %q: %v", path, err)
		return
	}
	defer f.Close()
	data, err := json.Marshal(result)
	if err == nil {
		_, _ = f.Write(append(data, '\n'))
	}
}
