package provider

// RustFS provider for the conformance test suite.
//
// RustFS is a Rust-based S3-compatible object storage server.
// Image: rustfs/rustfs:latest (Docker Hub, always latest)
//
// WARNING: RustFS is currently in active development and explicitly labelled
// "Do NOT use in production" by its authors. We test against it to catch
// regressions early and to help the project improve.
//
// Health endpoint: GET /health (returns 200+JSON); NOT /minio/health/live
// (that path returns 403 on RustFS).
//
// Known gaps confirmed by full conformance run (2026-04-22):
//   - Object Lock: bucket accepts the configuration but mode/hold headers are
//     not persisted — CapObjectLock is absent.
//
// Skip env var: GATEWAY_TEST_SKIP_RUSTFS=1

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_RUSTFS") == "" {
		Register(&rustfsProvider{})
	}
}

type rustfsProvider struct{}

func (p *rustfsProvider) Name() string { return "rustfs" }

// Capabilities returns the verified capability bitmap for RustFS based on
// a full conformance run.  The following capabilities are intentionally absent:
//
//   - CapObjectLock: RustFS accepts the Object Lock configuration at bucket
//     creation time but does not enforce the mode/hold headers — both
//     ObjectLock_Retention and ObjectLock_LegalHold return empty header values.
//     Re-enable once the upstream implementation is complete.
//
//   - CapVersioning: not exercised by a dedicated conformance test today;
//     will be added when a Versioning test case is introduced.
//
//   - CapServerSideEncryption: the gateway performs its own client-side
//     encryption; backend SSE is not tested in the conformance suite.
//
//   - CapConditionalWrites: not yet verified for RustFS.
func (p *rustfsProvider) Capabilities() Capabilities {
	return CapObjectTagging |
		CapMultipartUpload |
		CapMultipartCopy |
		CapPresignedURL |
		CapBatchDelete |
		CapKMSIntegration |
		CapInlinePutTagging |
		CapEncryptedMPU |
		CapLoadTest
}

func (p *rustfsProvider) CleanupPolicy() CleanupPolicy { return CleanupPolicyDelete }

func (p *rustfsProvider) BackendConfig(inst Instance) config.BackendConfig {
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

func (p *rustfsProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	const (
		s3Port      = "9000/tcp"
		consolePort = "9001/tcp"
		accessKey   = "rustfsadmin"
		secretKey   = "rustfsadmin"
	)

	req := tc.ContainerRequest{
		Image:        "rustfs/rustfs:latest",
		ExposedPorts: []string{s3Port, consolePort},
		Env: map[string]string{
			"RUSTFS_ACCESS_KEY": accessKey,
			"RUSTFS_SECRET_KEY": secretKey,
		},
		// Use the image's own /data directory (already owned by UID 10001
		// inside the image).  Do NOT mount anything at /data or /logs —
		// any overlay (tmpfs, bind, named volume) replaces the image
		// directory with a root-owned mount, causing EACCES for UID 10001.
		// The container's writable layer is ephemeral and disappears on
		// Terminate(), which is exactly what we want for CI.
		Cmd: []string{
			"--access-key", accessKey,
			"--secret-key", secretKey,
			"/data",
		},
		// RustFS health endpoint — returns 200 + JSON when ready.
		// (Unlike MinIO, /minio/health/live returns 403 on RustFS.)
		WaitingFor: wait.ForHTTP("/health").
			WithPort(s3Port).
			WithStatusCodeMatcher(func(status int) bool { return status == http.StatusOK }).
			WithStartupTimeout(60 * time.Second),
	}

	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("rustfs provider: failed to start container (Docker unavailable?): %v", err)
		return Instance{}
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("rustfs provider: host: %v", err)
	}
	s3Mapped, err := c.MappedPort(ctx, s3Port)
	if err != nil {
		t.Fatalf("rustfs provider: s3 port: %v", err)
	}

	bucket := fmt.Sprintf("conf-%s-%d", p.Name(), time.Now().UnixNano())
	inst := Instance{
		Endpoint:     fmt.Sprintf("http://%s:%s", host, s3Mapped.Port()),
		Region:       "us-east-1",
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		Bucket:       bucket,
		ProviderName: p.Name(),
	}
	createBucketS3(ctx, t, inst)
	return inst
}
