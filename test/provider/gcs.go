package provider

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

func init() {
	if os.Getenv("GATEWAY_TEST_GCS_ENDPOINT") != "" {
		Register(&gcsProvider{})
	}
}

// gcsProvider implements Provider for Google Cloud Storage via its S3-compatible
// XML API. It requires manual credentials and runs only when the environment
// variables are set.
//
// Required env vars:
//
//	GATEWAY_TEST_GCS_ENDPOINT       — e.g. "https://storage.googleapis.com"
//	GATEWAY_TEST_GCS_ACCESS_KEY    — HMAC access key
//	GATEWAY_TEST_GCS_SECRET_KEY    — HMAC secret key
type gcsProvider struct{}

func (p *gcsProvider) Name() string { return "gcs" }

func (p *gcsProvider) Capabilities() Capabilities {
	return CapMultipartUpload |
		CapObjectTagging |
		CapBatchDelete |
		CapPresignedURL |
		CapConditionalWrites
}

func (p *gcsProvider) CleanupPolicy() CleanupPolicy { return CleanupPolicyDelete }

func (p *gcsProvider) BackendConfig(inst Instance) config.BackendConfig {
	return config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     "gcs",
		Type:         config.BackendTypeGCS,
		UseSSL:       true,
		UsePathStyle: false,
	}
}

func (p *gcsProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	endpoint := os.Getenv("GATEWAY_TEST_GCS_ENDPOINT")
	accessKey := os.Getenv("GATEWAY_TEST_GCS_ACCESS_KEY")
	secretKey := os.Getenv("GATEWAY_TEST_GCS_SECRET_KEY")

	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skip("gcs provider: set GATEWAY_TEST_GCS_ENDPOINT, GATEWAY_TEST_GCS_ACCESS_KEY, and GATEWAY_TEST_GCS_SECRET_KEY")
		return Instance{}
	}

	bucket := "s3-encryption-gateway-gcs-conf-" + time.Now().Format("20060102150405")
	inst := Instance{
		Endpoint:     endpoint,
		Region:       "us-east-1",
		AccessKey:    accessKey,
		SecretKey:    secretKey,
		Bucket:       bucket,
		ProviderName: p.Name(),
	}

	createBucketS3(ctx, t, inst)
	return inst
}
