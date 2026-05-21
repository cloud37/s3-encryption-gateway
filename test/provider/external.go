// Package provider — external (credential-based) S3 vendor providers.
//
// Each public S3 vendor is registered via a one-file plug-in (aws.go,
// wasabi.go, b2.go, hetzner.go, …) that calls Register(&externalProvider{…})
// in init() when the vendor's credentials env vars are set.
//
// Adding a new vendor:
//  1. Copy test/provider/aws.go and rename the file and externalProvider
//     fields to match the new vendor.
//  2. Run `make test-conformance-external` with the vendor's credentials set.
//  3. If any conformance test fails because the vendor does not support a
//     feature, narrow the capability bitmap, do not add an if-branch inside
//     the test body.
//  4. Submit PR — CI picks it up automatically when credentials are supplied
//     as repo secrets.
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
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	internalconfig "github.com/kenchrcum/s3-encryption-gateway/internal/config"
)

// externalProvider is a shared implementation for credential-based S3 vendors.
// Per-vendor files (aws.go, wasabi.go, b2.go, hetzner.go, …) each call
// Register(&externalProvider{…}) in init() with the right endpoint /
// capabilities / cleanup bits.
type externalProvider struct {
	name      string
	endpoint  string       // "" = use SDK default for region
	region    string
	keyEnv    string
	secretEnv string
	bucketEnv string
	caps      Capabilities
	cleanup   CleanupPolicy
}

func (p *externalProvider) Name() string              { return p.name }
func (p *externalProvider) Capabilities() Capabilities { return p.caps }
func (p *externalProvider) CleanupPolicy() CleanupPolicy { return p.cleanup }

func (p *externalProvider) BackendConfig(inst Instance) internalconfig.BackendConfig {
	return internalconfig.BackendConfig{
		Endpoint:  inst.Endpoint,
		Region:    inst.Region,
		AccessKey: inst.AccessKey,
		SecretKey: inst.SecretKey,
		Provider:  p.name,
		UseSSL:    true,
	}
}

func (p *externalProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()

	ak := os.Getenv(p.keyEnv)
	sk := os.Getenv(p.secretEnv)
	bk := os.Getenv(p.bucketEnv)

	if ak == "" || sk == "" || bk == "" {
		t.Skipf("%s credentials not set (%s, %s, %s)",
			p.name, p.keyEnv, p.secretEnv, p.bucketEnv)
		return Instance{}
	}

	inst := Instance{
		Endpoint:     p.endpoint,
		Region:       p.region,
		AccessKey:    ak,
		SecretKey:    sk,
		Bucket:       bk,
		ProviderName: p.name,
	}

	// For external providers we do NOT create a new bucket (many require
	// regional setup, payment authorisation, or verification). Instead we
	// clean up the per-run key prefix on teardown if the cleanup policy permits.
	prefix := fmt.Sprintf("conformance-%d/", time.Now().UnixNano())
	if p.cleanup == CleanupPolicyDelete {
		t.Cleanup(func() { cleanupKeyPrefix(ctx, t, inst, prefix) })
	}

	return inst
}

// cleanupKeyPrefix deletes all objects under prefix in inst.Bucket. It is
// registered as a t.Cleanup function by external providers.
func cleanupKeyPrefix(ctx context.Context, t *testing.T, inst Instance, prefix string) {
	t.Helper()

	var endpointOpts []func(*awsconfig.LoadOptions) error
	if inst.Endpoint != "" {
		endpointOpts = append(endpointOpts,
			awsconfig.WithEndpointResolverWithOptions(
				aws.EndpointResolverWithOptionsFunc(func(service, region string, opts ...interface{}) (aws.Endpoint, error) {
					return aws.Endpoint{URL: inst.Endpoint, HostnameImmutable: true}, nil
				}),
			),
		)
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		append([]func(*awsconfig.LoadOptions) error{
			awsconfig.WithRegion(inst.Region),
			awsconfig.WithCredentialsProvider(
				credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, ""),
			),
		}, endpointOpts...)...,
	)
	if err != nil {
		t.Logf("cleanupKeyPrefix: load config: %v (cleanup skipped)", err)
		return
	}

	svc := s3.NewFromConfig(cfg)

	// List all objects under the prefix.
	paginator := s3.NewListObjectsV2Paginator(svc, &s3.ListObjectsV2Input{
		Bucket: aws.String(inst.Bucket),
		Prefix: aws.String(prefix),
	})

	var toDelete []s3types.ObjectIdentifier
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			t.Logf("cleanupKeyPrefix: list page: %v (stopping cleanup)", err)
			break
		}
		for _, obj := range page.Contents {
			toDelete = append(toDelete, s3types.ObjectIdentifier{Key: obj.Key})
		}
	}

	if len(toDelete) == 0 {
		return
	}

	// Batch delete in groups of 1000.
	for i := 0; i < len(toDelete); i += 1000 {
		end := i + 1000
		if end > len(toDelete) {
			end = len(toDelete)
		}
		batch := toDelete[i:end]
		_, err := svc.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(inst.Bucket),
			Delete: &s3types.Delete{Objects: batch, Quiet: aws.Bool(true)},
		})
		if err != nil {
			t.Logf("cleanupKeyPrefix: delete batch [%d:%d]: %v", i, end, err)
		}
	}
}

// envOr returns the value of the environment variable named key, or fallback
// if the variable is not set or is empty.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
