package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	tc "github.com/testcontainers/testcontainers-go"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_MINIO") == "" {
		Register(&minioProvider{})
	}
}

type minioProvider struct{}

func (p *minioProvider) Name() string { return "minio" }

func (p *minioProvider) Capabilities() Capabilities {
	// BucketPolicy, BucketLifecycle, BucketCors, BucketACL, ObjectACL, and
	// BucketEncryption are omitted because the default MinIO test container
	// does not enable these features (canned ACLs, KMS, Content-MD5 signing).
	// The gateway's passthrough for these operations is verified by unit tests.
	return CapMultipartUpload |
		CapMultipartCopy |
		CapObjectTagging |
		CapInlinePutTagging |
		CapPresignedURL |
		CapConditionalWrites |
		CapBatchDelete |
		CapEncryptedMPU |
		CapKMSIntegration |
		CapLoadTest
}

func (p *minioProvider) CleanupPolicy() CleanupPolicy { return CleanupPolicyDelete }

func (p *minioProvider) BackendConfig(inst Instance) config.BackendConfig {
	return config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     "minio",
		UseSSL:       false,
		UsePathStyle: true,
	}
}

func (p *minioProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	c, err := tcminio.Run(ctx,
		"minio/minio:RELEASE.2024-11-07T00-52-20Z",
		tc.WithEnv(map[string]string{
			"MINIO_ROOT_USER":     "minioadmin",
			"MINIO_ROOT_PASSWORD": "minioadmin",
		}),
	)
	if err != nil {
		t.Skipf("minio provider: failed to start container (Docker unavailable?): %v", err)
		return Instance{}
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	endpoint, err := c.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("minio provider: failed to get connection string: %v", err)
	}
	endpoint = "http://" + endpoint

	bucket := fmt.Sprintf("conf-%s-%d", p.Name(), time.Now().UnixNano())
	inst := Instance{
		Endpoint:     endpoint,
		Region:       "us-east-1",
		AccessKey:    "minioadmin",
		SecretKey:    "minioadmin",
		Bucket:       bucket,
		ProviderName: p.Name(),
	}
	createBucketS3(ctx, t, inst)
	return inst
}

// createBucketS3 creates the bucket named in inst.Bucket using the AWS SDK v2.
// It is a shared helper used by all provider implementations that need to
// pre-create their test bucket.
func createBucketS3(ctx context.Context, t *testing.T, inst Instance) {
	t.Helper()

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(inst.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, ""),
		),
		awsconfig.WithEndpointResolverWithOptions(
			aws.EndpointResolverWithOptionsFunc(func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
				return aws.Endpoint{URL: inst.Endpoint, HostnameImmutable: true}, nil
			}),
		),
	)
	if err != nil {
		t.Fatalf("createBucketS3: load config: %v", err)
	}

	svc := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	_, err = svc.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("createBucketS3: create bucket %q: %v", inst.Bucket, err)
	}
}
