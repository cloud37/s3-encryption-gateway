package provider

// SeaweedFS provider for the conformance test suite.
//
// SeaweedFS runs as a single-node S3-compatible server via the `weed server
// -s3` sub-command.  An S3 identity config is injected via shell entrypoint
// so that credential-authenticated requests work without a running filer
// config.
//
// Image: chrislusf/seaweedfs:latest (Docker Hub)
// S3 port: 8333
//
// Known gaps confirmed by full conformance run (2026-04-22):
//   - Object Lock (CapObjectLock absent): SeaweedFS accepts the
//     ObjectLockConfiguration at bucket-creation time but does not persist or
//     return x-amz-object-lock-mode / x-amz-object-lock-legal-hold — identical
//     behaviour to RustFS.  ObjectLock_BypassRefused passes; Retention and
//     LegalHold fail.
//   - Conditional PUT (CapConditionalWrites absent): If-None-Match / If-Match
//     on PUT not verified.
//   - CapServerSideEncryption absent: the gateway performs its own client-side
//     encryption; backend SSE is not tested in the conformance suite.
//
// Skip env var: GATEWAY_TEST_SKIP_SEAWEEDFS=1

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_SEAWEEDFS") == "" {
		Register(&seaweedfsProvider{})
	}
}

type seaweedfsProvider struct{}

func (p *seaweedfsProvider) Name() string { return "seaweedfs" }

// Capabilities returns the verified capability bitmap for SeaweedFS based on
// a full conformance run.  The following capabilities are intentionally absent:
//
//   - CapObjectLock: SeaweedFS accepts the ObjectLockConfiguration at bucket
//     creation time but does not persist or return the mode/hold headers —
//     ObjectLock_Retention and ObjectLock_LegalHold both fail with empty
//     header values.  ObjectLock_BypassRefused passes.
//     Re-enable once upstream Object Lock enforcement is complete.
//
//   - CapConditionalWrites: If-None-Match / If-Match on PUT not verified.
//
//   - CapServerSideEncryption: the gateway performs its own client-side
//     encryption; backend SSE is not tested in the conformance suite.
func (p *seaweedfsProvider) Capabilities() Capabilities {
	return CapObjectTagging |
		CapMultipartUpload |
		CapMultipartCopy |
		CapVersioning |
		CapPresignedURL |
		CapBatchDelete |
		CapKMSIntegration |
		CapInlinePutTagging |
		CapEncryptedMPU |
		CapLoadTest
}

func (p *seaweedfsProvider) CleanupPolicy() CleanupPolicy { return CleanupPolicyDelete }

func (p *seaweedfsProvider) BackendConfig(inst Instance) config.BackendConfig {
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

// seaweedS3Config is the JSON identity config written into the container by
// the shell entrypoint.  It grants a single admin identity full read/write
// access to all buckets.
const seaweedS3Config = `{"identities":[{"name":"admin","credentials":[{"accessKey":"seaweedadmin","secretKey":"seaweedadmin"}],"actions":["Admin","Read","Write","List","Tagging"]}]}`

func (p *seaweedfsProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	const (
		s3Port    = "8333/tcp"
		accessKey = "seaweedadmin"
		secretKey = "seaweedadmin"
	)

	// The shell entrypoint writes the S3 identity config file then launches
	// weed server with the S3 gateway enabled.
	//
	//   -master.volumeSizeLimitMB=128  caps volume pre-allocation to 128 MiB
	//                                  (default is 30 GiB — CI-hostile; 128 MiB
	//                                   provides enough headroom for the
	//                                   400 MiB EncryptedMPU_LargeObject test)
	//   -volume.max=8                  limits the number of pre-allocated
	//                                  volumes; 8×128 MiB = 1024 MiB total
	//                                  capacity, preventing "no free volumes"
	//                                  errors and volume-full 500 responses
	//                                  during large-object tests
	shellCmd := fmt.Sprintf(
		`mkdir -p /etc/seaweedfs && `+
			`printf '%%s' %q > /etc/seaweedfs/s3.json && `+
			`weed server -s3 `+
			`-s3.config=/etc/seaweedfs/s3.json `+
			`-master.volumeSizeLimitMB=128 `+
			`-volume.max=8`,
		seaweedS3Config,
	)

	req := tc.ContainerRequest{
		Image:        "chrislusf/seaweedfs:latest",
		ExposedPorts: []string{s3Port},
		Entrypoint:   []string{"/bin/sh", "-c"},
		Cmd:          []string{shellCmd},
		// Any S3 request that reaches the gateway returns < 500, even if
		// the response is 403 (auth error) or 404 (bucket not found).
		WaitingFor: wait.ForHTTP("/").
			WithPort(s3Port).
			WithStatusCodeMatcher(func(status int) bool { return status < 500 }).
			WithStartupTimeout(90 * time.Second),
	}

	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("seaweedfs provider: failed to start container (Docker unavailable?): %v", err)
		return Instance{}
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("seaweedfs provider: host: %v", err)
	}
	s3Mapped, err := c.MappedPort(ctx, s3Port)
	if err != nil {
		t.Fatalf("seaweedfs provider: s3 port: %v", err)
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
