//go:build conformance && benchmark_rclone_ncdu

// Package conformance contains the manually-run rclone ncdu benchmark.
//
// The extra build tag is intentional: this benchmark is never part of the
// conformance suite or any CI target. It launches the real interactive rclone
// ncdu command in a pseudo-terminal and stops it after a configurable settle
// period.
package conformance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	container "github.com/moby/moby/api/types/container"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type rcloneNcduBenchmarkParams struct {
	objects    int
	objectSize int
	settle     time.Duration
	jsonOut    string
}

type rcloneNcduBenchmarkResult struct {
	Provider           string  `json:"provider"`
	Objects            int     `json:"objects"`
	ObjectSize         int     `json:"object_size"`
	SettleSeconds      float64 `json:"settle_seconds"`
	DirectSeconds      float64 `json:"direct_seconds"`
	GatewaySeconds     float64 `json:"gateway_seconds"`
	DirectExitCode     int     `json:"direct_exit_code"`
	GatewayExitCode    int     `json:"gateway_exit_code"`
	DirectObjectsSeen  int64   `json:"direct_objects_seen"`
	GatewayObjectsSeen int64   `json:"gateway_objects_seen"`
	CacheHits          float64 `json:"cache_hits"`
	CacheMisses        float64 `json:"cache_misses"`
	FallbackHeads      float64 `json:"fallback_heads"`
}

var rcloneNcduMarker = regexp.MustCompile(`NCDU_BENCH elapsed_seconds=([0-9]+) objects=([0-9]+) rc=([0-9]+) completed=([01])`)

func TestBenchmarkRcloneNcdu(t *testing.T) {
	p := rcloneNcduBenchmarkParams{
		objects:    rcloneNcduInt("BENCH_RCLONE_NCDU_OBJECTS", 1000),
		objectSize: rcloneNcduInt("BENCH_RCLONE_NCDU_OBJECT_SIZE", 1024),
		settle:     rcloneNcduDuration("BENCH_RCLONE_NCDU_SETTLE", 5*time.Minute),
		jsonOut:    os.Getenv("BENCH_RCLONE_NCDU_JSON_OUT"),
	}
	if len(provider.All()) == 0 {
		t.Skip("no providers registered; start Docker or set external provider credentials")
	}

	for _, backend := range provider.All() {
		backend := backend
		t.Run(backend.Name(), func(t *testing.T) {
			inst := backend.Start(context.Background(), t)
			vk := provider.StartValkey(context.Background(), t)
			gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr))

			prefix := fmt.Sprintf("rclone-ncdu-bench/%s/", uniqueSuffix(t))
			data := make([]byte, p.objectSize)
			for i := 0; i < p.objects; i++ {
				key := fmt.Sprintf("%slevel-%02d/object-%06d.bin", prefix, i%10, i)
				put(t, gw, inst.Bucket, key, data)
			}

			direct := runRcloneNcdu(t, inst.Endpoint, inst, prefix, p)
			gateway := runRcloneNcdu(t, gw.URL, inst, prefix, p)
			result := rcloneNcduBenchmarkResult{
				Provider: inst.ProviderName, Objects: p.objects, ObjectSize: p.objectSize,
				SettleSeconds: p.settle.Seconds(), DirectSeconds: direct.seconds,
				GatewaySeconds: gateway.seconds, DirectExitCode: direct.exitCode,
				GatewayExitCode: gateway.exitCode, DirectObjectsSeen: direct.objects,
				GatewayObjectsSeen: gateway.objects,
				CacheHits:          rcloneNcduMetric(t, gw, "list_size_cache_hits_total"),
				CacheMisses:        rcloneNcduMetric(t, gw, "list_size_cache_misses_total"),
				FallbackHeads:      rcloneNcduMetric(t, gw, "list_size_fallback_head_total"),
			}
			if direct.objects != int64(p.objects) || gateway.objects != int64(p.objects) {
				t.Fatalf("rclone ncdu object count mismatch: direct=%d gateway=%d want=%d", direct.objects, gateway.objects, p.objects)
			}
			t.Logf("rclone ncdu %s: direct=%.3fs gateway=%.3fs direct_objects=%d gateway_objects=%d cache_hits=%.0f cache_misses=%.0f fallback_heads=%.0f",
				inst.ProviderName, result.DirectSeconds, result.GatewaySeconds,
				result.DirectObjectsSeen, result.GatewayObjectsSeen, result.CacheHits,
				result.CacheMisses, result.FallbackHeads)
			appendRcloneNcduResult(t, p.jsonOut, result)
		})
	}
}

type rcloneNcduRun struct {
	seconds  float64
	objects  int64
	exitCode int
}

func runRcloneNcdu(t *testing.T, endpoint string, inst provider.Instance, prefix string, p rcloneNcduBenchmarkParams) rcloneNcduRun {
	t.Helper()
	script := `set -u
apk add --no-cache util-linux >/dev/null 2>&1
log=/tmp/rclone-ncdu.log
rm -f "$log"
start=$(date +%s)
# script supplies a second pseudo-terminal so ncdu remains interactive while
# its screen updates can be inspected. The scan is stopped only after the
# expected object count appears, or when the safety deadline expires.
script -q -e -c 'rclone ncdu \
  --s3-provider=Other \
  --s3-endpoint="$S3_ENDPOINT" \
  --s3-env-auth=false \
  --s3-access-key-id="$AWS_ACCESS_KEY_ID" \
  --s3-secret-access-key="$AWS_SECRET_ACCESS_KEY" \
  --s3-region="$AWS_DEFAULT_REGION" \
  --s3-force-path-style=true \
  --s3-no-check-bucket=true \
  ":s3:$S3_BUCKET/$S3_PREFIX"' "$log" &
pid=$!
deadline=$(( $(date +%s) + NCDU_DEADLINE_SECONDS ))
completed=0
while kill -0 "$pid" 2>/dev/null; do
  if grep -a -q "Objects: $NCDU_OBJECTS" "$log"; then
    completed=1
    kill -TERM "$pid" 2>/dev/null || true
    break
  fi
	if [ "$(date +%s)" -ge "$deadline" ]; then
    kill -TERM "$pid" 2>/dev/null || true
    break
	fi
	sleep 0.1
done
wait "$pid"
rc=$?
end=$(date +%s)
objects="$NCDU_OBJECTS"
printf 'NCDU_BENCH elapsed_seconds=%s objects=%s rc=%s completed=%s\n' "$((end-start))" "$objects" "$rc" "$completed"
cat "$log"
exit 0`

	req := tc.ContainerRequest{
		Image:      "rclone/rclone:1.68",
		Entrypoint: []string{},
		Cmd:        []string{"/bin/sh", "-c", script},
		Env: map[string]string{
			"S3_ENDPOINT":           endpoint,
			"S3_BUCKET":             inst.Bucket,
			"S3_PREFIX":             prefix,
			"AWS_ACCESS_KEY_ID":     inst.AccessKey,
			"AWS_SECRET_ACCESS_KEY": inst.SecretKey,
			"AWS_DEFAULT_REGION":    inst.Region,
			"NCDU_DEADLINE_SECONDS": strconv.FormatInt(int64(p.settle/time.Second), 10),
			"NCDU_PREFIX":           prefix,
			"NCDU_OBJECTS":          strconv.Itoa(p.objects),
		},
		ConfigModifier: func(cfg *container.Config) {
			cfg.Tty = true
			cfg.OpenStdin = true
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.NetworkMode = container.NetworkMode("host")
		},
		WaitingFor: wait.ForExit().WithExitTimeout(p.settle + 2*time.Minute),
	}
	c, err := tc.GenericContainer(context.Background(), tc.GenericContainerRequest{ContainerRequest: req, Started: true})
	if err != nil {
		t.Fatalf("start rclone ncdu container: %v", err)
	}
	defer func() { _ = c.Terminate(context.Background()) }()

	logs, err := c.Logs(context.Background())
	if err != nil {
		t.Fatalf("read rclone ncdu logs: %v", err)
	}
	defer logs.Close()
	outputBytes, err := io.ReadAll(logs)
	if err != nil {
		t.Fatalf("read rclone ncdu output: %v", err)
	}
	output := string(outputBytes)
	t.Logf("rclone ncdu endpoint=%s output:\n%s", endpoint, output)

	matches := rcloneNcduMarker.FindStringSubmatch(output)
	if len(matches) != 5 {
		t.Fatalf("rclone ncdu benchmark marker missing; output=%q", output)
	}
	elapsedSeconds, _ := strconv.ParseInt(matches[1], 10, 64)
	objects, _ := strconv.ParseInt(matches[2], 10, 64)
	exitCode, _ := strconv.Atoi(matches[3])
	if matches[4] != "1" {
		t.Fatalf("rclone ncdu safety deadline expired; output=%q", output)
	}
	return rcloneNcduRun{seconds: float64(elapsedSeconds), objects: objects, exitCode: exitCode}
}

func rcloneNcduInt(name string, fallback int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func rcloneNcduDuration(name string, fallback time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return fallback
}

func rcloneNcduMetric(t *testing.T, gw *harness.Gateway, name string) float64 {
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
			if metric.Counter != nil {
				total += metric.Counter.GetValue()
			}
		}
	}
	return total
}

func appendRcloneNcduResult(t *testing.T, path string, result rcloneNcduBenchmarkResult) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Logf("open rclone ncdu result %q: %v", path, err)
		return
	}
	defer f.Close()
	data, err := json.Marshal(result)
	if err == nil {
		_, _ = f.Write(append(data, '\n'))
	}
}
