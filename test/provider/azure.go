package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	tc "github.com/testcontainers/testcontainers-go"
	tcwait "github.com/testcontainers/testcontainers-go/wait"
)

func init() {
	// Skip Azure in local-only mode; Azurite does not support the S3 protocol.
	// Requires GATEWAY_TEST_AZURE_ENDPOINT to be set for real Azure integration testing.
	if os.Getenv("GATEWAY_TEST_SKIP_AZURE") != "" || os.Getenv("GATEWAY_TEST_SKIP_EXTERNAL") != "" {
		return
	}
	Register(&azureProvider{})
}

// azureProvider implements Provider for Azure Blob Storage via its
// S3-compatible API.  When GATEWAY_TEST_AZURE_ENDPOINT is set, it uses
// that endpoint (manual/external mode).  Otherwise it starts an Azurite
// emulator container via Testcontainers.
//
// Azurite always uses the well-known credentials:
//
//	AccessKey: "devstoreaccount1"
//	SecretKey: "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
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

	if external := os.Getenv("GATEWAY_TEST_AZURE_ENDPOINT"); external != "" {
		return p.startExternal(ctx, external, t)
	}
	t.Skip("azure provider: GATEWAY_TEST_AZURE_ENDPOINT not set (Azurite does not support the S3 protocol)")
	return Instance{}
}

func (p *azureProvider) startExternal(ctx context.Context, endpoint string, t *testing.T) Instance {
	t.Helper()

	accessKey := os.Getenv("GATEWAY_TEST_AZURE_ACCESS_KEY")
	secretKey := os.Getenv("GATEWAY_TEST_AZURE_SECRET_KEY")
	if accessKey == "" || secretKey == "" {
		t.Skip("azure provider (external): set GATEWAY_TEST_AZURE_ENDPOINT, GATEWAY_TEST_AZURE_ACCESS_KEY, and GATEWAY_TEST_AZURE_SECRET_KEY")
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

func (p *azureProvider) startAzurite(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	req := tc.ContainerRequest{
		Image:        "mcr.microsoft.com/azure-storage/azurite:latest",
		ExposedPorts: []string{"10000/tcp"},
		Env: map[string]string{
			"AZURITE_ACCOUNTS": "devstoreaccount1:Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==",
		},
		WaitingFor: tcwait.ForListeningPort("10000/tcp"),
	}
	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("azure provider: failed to start Azurite container (Docker unavailable?): %v", err)
		return Instance{}
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	port, err := c.MappedPort(ctx, "10000/tcp")
	if err != nil {
		t.Fatalf("azure provider: get mapped port: %v", err)
	}
	host, err := c.Host(ctx)
	if err != nil {
		t.Fatalf("azure provider: get host: %v", err)
	}
	endpoint := fmt.Sprintf("http://%s:%s", host, port.Port())

	bucket := fmt.Sprintf("conf-%s-%d", p.Name(), time.Now().UnixNano())
	inst := Instance{
		Endpoint:     endpoint,
		Region:       "us-east-1",
		AccessKey:    "devstoreaccount1",         // #nosec G101 -- Azurite well-known emulator credential
		SecretKey:    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==", // #nosec G101 -- Azurite well-known emulator credential
		Bucket:       bucket,
		ProviderName: p.Name(),
	}

	createBucketS3(ctx, t, inst)
	return inst
}
