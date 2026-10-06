package harness_test

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	"github.com/stretchr/testify/require"
)

// TestGateway_LifecycleNoProvider verifies the harness can start and stop a
// gateway even when the provider Instance is minimal (no real backend). The
// gateway will fail all S3 operations, but the start/stop lifecycle itself
// should be clean.
//
// NOTE: This is a tier-1 test. It does not start a MinIO container.
func TestGateway_LifecycleNoProvider(t *testing.T) {
	// Use a dummy provider instance pointing at localhost:1 (no server).
	// The gateway will start successfully; S3 operations will fail, but
	// the lifecycle test only verifies the harness itself.
	inst := provider.Instance{
		Endpoint:     "http://127.0.0.1:1",
		Region:       "us-east-1",
		AccessKey:    "DUMMYACCESSKEY",
		SecretKey:    "dummysecretkey00000000000000000000",
		Bucket:       "test-bucket",
		ProviderName: "minio",
	}

	gw := harness.StartGateway(t, inst)

	if gw.URL == "" {
		t.Fatal("gateway URL is empty")
	}
	if gw.Addr == "" {
		t.Fatal("gateway Addr is empty")
	}
	if gw.Metrics == nil {
		t.Fatal("gateway Metrics registry is nil")
	}

	// The health endpoint must return 200.
	resp, err := gw.HTTPClient().Get(gw.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health returned %d, want 200", resp.StatusCode)
	}

	// The metrics endpoint must return 200.
	resp2, err := gw.HTTPClient().Get(gw.URL + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp2.Body.Close()
	io.Copy(io.Discard, resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("GET /metrics returned %d, want 200", resp2.StatusCode)
	}
}

func TestGateway_GatewayCORSRejectsNonValkeyMPUStore(t *testing.T) {
	require.ErrorContains(t, harness.ValidateGatewayCORSStateStore(nonValkeyMPUStore{}), "shared Valkey-backed MPU state store")
}

type nonValkeyMPUStore struct{}

func (nonValkeyMPUStore) Create(context.Context, *mpu.UploadState) error        { return nil }
func (nonValkeyMPUStore) Get(context.Context, string) (*mpu.UploadState, error) { return nil, nil }
func (nonValkeyMPUStore) ReservePart(context.Context, string, mpu.PartClaim) (mpu.Reservation, error) {
	return mpu.Reservation{}, nil
}
func (nonValkeyMPUStore) RenewPart(context.Context, string, int32, string) error   { return nil }
func (nonValkeyMPUStore) ReleasePart(context.Context, string, int32, string) error { return nil }
func (nonValkeyMPUStore) CommitPart(context.Context, string, mpu.PartClaim) error  { return nil }
func (nonValkeyMPUStore) BeginComplete(context.Context, string, []mpu.SelectedPart) (*mpu.UploadState, uint64, error) {
	return nil, 0, nil
}
func (nonValkeyMPUStore) Reopen(context.Context, string, uint64) error           { return nil }
func (nonValkeyMPUStore) FinalizeComplete(context.Context, string, uint64) error { return nil }
func (nonValkeyMPUStore) BeginAbort(context.Context, string) (uint64, error)     { return 0, nil }
func (nonValkeyMPUStore) FinalizeAbort(context.Context, string, uint64) error    { return nil }
func (nonValkeyMPUStore) Delete(context.Context, string) error                   { return nil }
func (nonValkeyMPUStore) List(context.Context) ([]mpu.UploadState, error)        { return nil, nil }
func (nonValkeyMPUStore) HealthCheck(context.Context) error                      { return nil }
func (nonValkeyMPUStore) Close() error                                           { return nil }

func TestGateway_ConfigMutatorOnlyGatewayCORSUsesSharedValkey(t *testing.T) {
	inst := provider.Instance{Endpoint: "http://127.0.0.1:1", Region: "us-east-1", AccessKey: "DUMMYACCESSKEY", SecretKey: "dummysecretkey00000000000000000000", Bucket: "test-bucket", ProviderName: "minio"}
	// A real in-memory Valkey protocol fixture supplies the same client type
	// used by production; policy still lives in shared Valkey, not process memory.
	mr := miniredis.RunT(t)
	gateway := harness.StartGateway(t, inst, harness.WithValkeyAddr(mr.Addr()), harness.WithConfigMutator(func(cfg *config.Config) { cfg.CORS.Mode = "gateway" }))
	require.NotEmpty(t, gateway.URL)
	req, err := http.NewRequest(http.MethodOptions, gateway.URL+"/test-bucket", nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "PUT")
	resp, err := gateway.HTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode, "empty Valkey policy is missing; no allow policy should be returned")
	require.Contains(t, resp.Header.Get("Vary"), "Origin")
}
