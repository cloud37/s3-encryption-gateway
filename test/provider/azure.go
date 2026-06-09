package provider

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

func init() {
	// Azure is external-only (Azurite S3-compatible API is not suitable for
	// local testing as an S3 storage provider).  The provider registers itself
	// only when GATEWAY_TEST_AZURE_ENDPOINT is set.
	if ep := os.Getenv("GATEWAY_TEST_AZURE_ENDPOINT"); ep != "" {
		if os.Getenv("GATEWAY_TEST_AZURE_ACCESS_KEY") != "" &&
			os.Getenv("GATEWAY_TEST_AZURE_SECRET_KEY") != "" {
			Register(&azureProvider{})
		}
	}
}

// azureProvider implements Provider for Azure Blob Storage via its
// S3-compatible API.  Requires manual credentials.
//
// Required env vars:
//
//	GATEWAY_TEST_AZURE_ENDPOINT    — Azure Blob S3 endpoint
//	GATEWAY_TEST_AZURE_ACCESS_KEY — access key
//	GATEWAY_TEST_AZURE_SECRET_KEY — secret key
type azureProvider struct{}

func (p *azureProvider) Name() string { return "azure" }

func (p *azureProvider) Capabilities() Capabilities {
	return CapMultipartUpload |
		CapObjectTagging |
		CapBatchDelete |
		CapPresignedURL |
		CapConditionalWrites
}

func (p *azureProvider) CleanupPolicy() CleanupPolicy { return CleanupPolicyDelete }

func (p *azureProvider) BackendConfig(inst Instance) config.BackendConfig {
	return config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     "azure",
		Type:         config.BackendTypeAzure,
		UseSSL:       false,
		UsePathStyle: false,
	}
}

func (p *azureProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	endpoint := os.Getenv("GATEWAY_TEST_AZURE_ENDPOINT")
	accessKey := os.Getenv("GATEWAY_TEST_AZURE_ACCESS_KEY")
	secretKey := os.Getenv("GATEWAY_TEST_AZURE_SECRET_KEY")

	if endpoint == "" || accessKey == "" || secretKey == "" {
		t.Skip("azure provider: set GATEWAY_TEST_AZURE_ENDPOINT, GATEWAY_TEST_AZURE_ACCESS_KEY, and GATEWAY_TEST_AZURE_SECRET_KEY")
		return Instance{}
	}

	bucket := "s3-encryption-gateway-azure-conf-" + time.Now().Format("20060102150405")
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
