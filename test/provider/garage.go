package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_GARAGE") == "" {
		Register(&garageProvider{})
	}
}

type garageProvider struct{}

func (p *garageProvider) Name() string { return "garage" }

func (p *garageProvider) Capabilities() Capabilities {
	// Garage v2.x supports Object Lock only when the bucket is created with
	// Object Lock enabled. The conformance bucket here is created without
	// Object Lock, so CapObjectLock is omitted. Re-enable when we add
	// opt-in per-test bucket configuration.
	//
	// Garage v2.3.x does not implement PutObjectTagging / GetObjectTagging
	// via the ?tagging subresource (returns 501 NotImplemented). Inline
	// tagging via x-amz-tagging on PutObject (CapInlinePutTagging) works.
	// Re-enable CapObjectTagging when a supported Garage version ships.
	return CapMultipartUpload |
		CapMultipartCopy |
		CapInlinePutTagging |
		CapPresignedURL |
		CapBatchDelete |
		CapVersioning |
		CapEncryptedMPU |
		CapKMSIntegration |
		CapLoadTest
}

func (p *garageProvider) CleanupPolicy() CleanupPolicy { return CleanupPolicyDelete }

func (p *garageProvider) BackendConfig(inst Instance) config.BackendConfig {
	return config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     "s3",
		UseSSL:       false,
		UsePathStyle: true,
	}
}

func (p *garageProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	const (
		s3Port    = "3900/tcp"
		adminPort = "3903/tcp"
		rpcPort   = "3901/tcp"
	)

	rpcSecret := "3fb5c4e9d0e2f8a1b7c6d5e4f3a2b1c03fb5c4e9d0e2f8a1b7c6d5e4f3a2b1c0"

	req := tc.ContainerRequest{
		Image:        "dxflrs/garage:v2.3.0",
		ExposedPorts: []string{s3Port, adminPort, rpcPort},
		Env: map[string]string{
			"GARAGE_LOG_LEVEL": "warn",
		},
		Cmd: []string{"/garage", "server"},
		Files: []tc.ContainerFile{
			{
				ContainerFilePath: "/etc/garage.toml",
				Reader:            strings.NewReader(garageToml(rpcSecret)),
				FileMode:          0644,
			},
		},
		WaitingFor: wait.ForListeningPort(s3Port).WithStartupTimeout(60 * time.Second),
	}

	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("garage provider: failed to start container (Docker unavailable?): %v", err)
		return Instance{}
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("garage provider: host: %v", err)
	}

	s3Mapped, err := c.MappedPort(ctx, s3Port)
	if err != nil {
		t.Fatalf("garage provider: s3 port: %v", err)
	}
	adminMapped, err := c.MappedPort(ctx, adminPort)
	if err != nil {
		t.Fatalf("garage provider: admin port: %v", err)
	}

	s3Endpoint := fmt.Sprintf("http://%s:%s", host, s3Mapped.Port())
	adminEndpoint := fmt.Sprintf("http://%s:%s", host, adminMapped.Port())

	bucket := fmt.Sprintf("conf-%s-%d", p.Name(), time.Now().UnixNano())
	ak, sk, err := bootstrapGarage(ctx, t, adminEndpoint, bucket)
	if err != nil {
		t.Fatalf("garage provider: bootstrap: %v", err)
	}

	return Instance{
		Endpoint:     s3Endpoint,
		Region:       "garage",
		AccessKey:    ak,
		SecretKey:    sk,
		Bucket:       bucket,
		ProviderName: p.Name(),
	}
}

// garageAdminToken is the bearer token baked into garage.toml. It only
// protects the admin REST API within an ephemeral test container and is not
// a security-sensitive value.
const garageAdminToken = "conformance-admin-token-" +
	"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// garageToml returns an embedded Garage config TOML string.
func garageToml(rpcSecret string) string {
	return fmt.Sprintf(`
metadata_dir = "/tmp/garage/meta"
data_dir     = "/tmp/garage/data"
db_engine    = "sqlite"

rpc_bind_addr   = "0.0.0.0:3901"
rpc_public_addr = "127.0.0.1:3901"
rpc_secret      = %q

replication_factor = 1

[s3_api]
s3_region      = "garage"
api_bind_addr  = "0.0.0.0:3900"

[admin]
api_bind_addr = "0.0.0.0:3903"
admin_token   = %q
`, rpcSecret, garageAdminToken)
}

// garageAdminReq issues an authenticated request to the Garage admin API.
func garageAdminReq(ctx context.Context, method, url string, body io.Reader, adminToken string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if adminToken != "" {
		req.Header.Set("Authorization", "Bearer "+adminToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

// bootstrapGarage performs the minimum Garage v2.x cluster setup via its
// REST admin API (served on the admin port, authenticated with the
// admin_token from garage.toml):
//
//  1. GET  /v2/GetClusterStatus   → obtain the node ID.
//  2. POST /v2/UpdateClusterLayout → assign zone + capacity to that node.
//  3. POST /v2/ApplyClusterLayout  → apply layout version 1.
//  4. POST /v2/CreateKey           → create an access key.
//  5. POST /v2/CreateBucket        → create the test bucket.
//  6. POST /v2/AllowBucketKey      → grant the access key rw on the bucket.
//
// Returns the access key and secret key.
func bootstrapGarage(ctx context.Context, t *testing.T, adminEndpoint, bucket string) (ak, sk string, err error) {
	t.Helper()

	tok := garageAdminToken

	// 1. GET /v2/GetClusterStatus → node ID (poll briefly; admin listener is
	// up before the cluster is fully initialised).
	var statusResp struct {
		Nodes []struct {
			ID string `json:"id"`
		} `json:"nodes"`
	}
	for attempt := 0; attempt < 30; attempt++ {
		data, status, err := garageAdminReq(ctx, "GET", adminEndpoint+"/v2/GetClusterStatus", nil, tok)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if status == http.StatusOK {
			if err := json.Unmarshal(data, &statusResp); err != nil {
				return "", "", fmt.Errorf("parse /v2/GetClusterStatus: %w (body=%s)", err, string(data))
			}
			if len(statusResp.Nodes) > 0 {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(statusResp.Nodes) == 0 {
		return "", "", fmt.Errorf("bootstrap: no node ID reported")
	}
	nodeID := statusResp.Nodes[0].ID

	// 2. UpdateClusterLayout assigning the node to zone dc1.
	layoutBody := fmt.Sprintf(
		`{"roles":[{"id":%q,"zone":"dc1","capacity":1073741824,"tags":[]}]}`,
		nodeID)
	data, status, err := garageAdminReq(ctx, "POST",
		adminEndpoint+"/v2/UpdateClusterLayout",
		strings.NewReader(layoutBody), tok)
	if err != nil {
		return "", "", fmt.Errorf("UpdateClusterLayout: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return "", "", fmt.Errorf("UpdateClusterLayout returned %d: %s", status, string(data))
	}

	// 3. ApplyClusterLayout version 1.
	applyBody := `{"version":1}`
	data, status, err = garageAdminReq(ctx, "POST",
		adminEndpoint+"/v2/ApplyClusterLayout",
		strings.NewReader(applyBody), tok)
	if err != nil {
		return "", "", fmt.Errorf("ApplyClusterLayout: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return "", "", fmt.Errorf("ApplyClusterLayout returned %d: %s", status, string(data))
	}

	// Wait for the cluster to become healthy before issuing writes.
	for attempt := 0; attempt < 50; attempt++ {
		data, status, err := garageAdminReq(ctx, "GET",
			adminEndpoint+"/v2/GetClusterHealth", nil, tok)
		if err == nil && status == http.StatusOK {
			// Best-effort: as soon as the storage partitions are up, proceed.
			if strings.Contains(string(data), `"status": "healthy"`) ||
				strings.Contains(string(data), `"status":"healthy"`) {
				break
			}
		}
		time.Sleep(200 * time.Millisecond)
	}

	// 4. CreateKey.
	createKeyBody := `{"name":"conformance-key"}`
	data, status, err = garageAdminReq(ctx, "POST",
		adminEndpoint+"/v2/CreateKey",
		strings.NewReader(createKeyBody), tok)
	if err != nil {
		return "", "", fmt.Errorf("CreateKey: %w", err)
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return "", "", fmt.Errorf("CreateKey returned %d: %s", status, string(data))
	}
	var keyResp struct {
		AccessKeyID     string `json:"accessKeyId"`
		SecretAccessKey string `json:"secretAccessKey"`
	}
	if err := json.Unmarshal(data, &keyResp); err != nil {
		return "", "", fmt.Errorf("parse CreateKey response: %w", err)
	}
	if keyResp.AccessKeyID == "" || keyResp.SecretAccessKey == "" {
		return "", "", fmt.Errorf("empty credentials in CreateKey response: %s", string(data))
	}

	// 5. CreateBucket.
	createBucketBody := fmt.Sprintf(`{"globalAlias":%q}`, bucket)
	data, status, err = garageAdminReq(ctx, "POST",
		adminEndpoint+"/v2/CreateBucket",
		strings.NewReader(createBucketBody), tok)
	if err != nil {
		return "", "", fmt.Errorf("CreateBucket: %w", err)
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return "", "", fmt.Errorf("CreateBucket returned %d: %s", status, string(data))
	}
	var bucketResp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(data, &bucketResp); err != nil {
		return "", "", fmt.Errorf("parse CreateBucket response: %w", err)
	}
	if bucketResp.ID == "" {
		return "", "", fmt.Errorf("empty bucket ID in CreateBucket response: %s", string(data))
	}

	// 6. AllowBucketKey.
	allowBody := fmt.Sprintf(
		`{"bucketId":%q,"accessKeyId":%q,"permissions":{"read":true,"write":true,"owner":true}}`,
		bucketResp.ID, keyResp.AccessKeyID)
	data, status, err = garageAdminReq(ctx, "POST",
		adminEndpoint+"/v2/AllowBucketKey",
		strings.NewReader(allowBody), tok)
	if err != nil {
		return "", "", fmt.Errorf("AllowBucketKey: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return "", "", fmt.Errorf("AllowBucketKey returned %d: %s", status, string(data))
	}

	return keyResp.AccessKeyID, keyResp.SecretAccessKey, nil
}
