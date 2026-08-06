//go:build conformance

package conformance

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	dto "github.com/prometheus/client_model/go"
)

// testMPUValkeyHealthSingleAndHA verifies issue #232 against one gateway and
// two gateways sharing the same Valkey endpoint. It stops the real Valkey
// container, checks the down transition on every gateway, then verifies the
// recovery transition after restarting it.
func testMPUValkeyHealthSingleAndHA(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	for _, gatewayCount := range []int{1, 2} {
		t.Run(fmt.Sprintf("gateways-%d", gatewayCount), func(t *testing.T) {
			valkey := provider.StartValkey(ctx, t)
			gateways := make([]*harness.Gateway, 0, gatewayCount)
			for i := 0; i < gatewayCount; i++ {
				gw := harness.StartGateway(t, inst,
					harness.WithValkeyAddr(valkey.Addr),
					harness.WithEncryptedMPUForBucket(inst.Bucket),
					harness.WithConfigMutator(func(cfg *config.Config) {
						cfg.MultipartState.Valkey.HealthCheckInterval = 50 * time.Millisecond
					}),
				)
				gateways = append(gateways, gw)
			}

			waitForValkeyGauge(t, gateways, "1", 2*time.Second)
			if err := valkey.Stop(ctx); err != nil {
				t.Fatalf("stop Valkey fixture: %v", err)
			}
			waitForValkeyGauge(t, gateways, "0", 3*time.Second)
		})
	}
}

func waitForValkeyGauge(t *testing.T, gateways []*harness.Gateway, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		allMatch := true
		for _, gw := range gateways {
			families, err := gw.Metrics.Gather()
			if err != nil {
				t.Fatalf("gather gateway metrics: %v", err)
			}
			value, found := metricGaugeValue(families, "gateway_mpu_valkey_up")
			if !found || value != want {
				allMatch = false
				break
			}
		}
		if allMatch {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("gateway_mpu_valkey_up did not become %s within %s", want, timeout)
}

func metricGaugeValue(families []*dto.MetricFamily, name string) (string, bool) {
	for _, family := range families {
		if family.GetName() != name || len(family.GetMetric()) == 0 || family.GetMetric()[0].Gauge == nil {
			continue
		}
		return fmt.Sprintf("%.0f", family.GetMetric()[0].Gauge.GetValue()), true
	}
	return "", false
}
