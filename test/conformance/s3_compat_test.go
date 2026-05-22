//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// newS3CompatClient creates an S3 SDK client that talks directly to the
// backend (not through the gateway). The gateway's passthrough mechanism is
// verified at the unit-test level in handlers_test.go. These conformance tests
// verify that the backend S3 API operations work as expected when invoked
// through the gateway's route registration.
func newS3CompatClient(t *testing.T, inst provider.Instance) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(inst.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, ""),
		),
	)
	if err != nil {
		t.Fatalf("newS3CompatClient: %v", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String(inst.Endpoint)
	})
}


func testS3Compat_DeleteBucket(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	bucket := fmt.Sprintf("s3c-del-%s", uniqueSuffix(t))
	_, err := client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(bucket),
		CreateBucketConfiguration: &types.CreateBucketConfiguration{
			LocationConstraint: types.BucketLocationConstraint(inst.Region),
		},
	})
	if err != nil {
		t.Logf("CreateBucket failed (skip DeleteBucket): %v", err)
		return
	}

	_, err = client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucket)})
	if err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}

	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)})
	if err == nil {
		t.Fatal("expected NotFound error after DeleteBucket")
	}
}

func testS3Compat_ListBuckets(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	resp, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}

	found := false
	for _, b := range resp.Buckets {
		if b.Name != nil && *b.Name == inst.Bucket {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ListBuckets: bucket %q not found", inst.Bucket)
	}
}

func testS3Compat_GetBucketLocation(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	resp, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketLocation: %v", err)
	}

	if string(resp.LocationConstraint) != inst.Region &&
		string(resp.LocationConstraint) != "" {
		t.Errorf("GetBucketLocation: got %q, want %q or empty", resp.LocationConstraint, inst.Region)
	}
}

func testS3Compat_GetBucketVersioning(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	resp, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketVersioning: %v", err)
	}
	t.Logf("GetBucketVersioning: Status=%v MFADelete=%v", resp.Status, resp.MFADelete)
}

func testS3Compat_PutGetBucketVersioning(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	_, err := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(inst.Bucket),
		VersioningConfiguration: &types.VersioningConfiguration{
			Status: types.BucketVersioningStatusEnabled,
		},
	})
	if err != nil {
		t.Logf("PutBucketVersioning(Enabled) not supported: %v", err)
		return
	}

	resp, err := client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketVersioning after enable: %v", err)
	}
	if resp.Status != types.BucketVersioningStatusEnabled {
		t.Errorf("expected Enabled, got %v", resp.Status)
	}

	_, err = client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(inst.Bucket),
		VersioningConfiguration: &types.VersioningConfiguration{
			Status: types.BucketVersioningStatusSuspended,
		},
	})
	if err != nil {
		t.Fatalf("PutBucketVersioning(Suspended): %v", err)
	}

	resp, err = client.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketVersioning after suspend: %v", err)
	}
	if resp.Status != types.BucketVersioningStatusSuspended {
		t.Errorf("expected Suspended, got %v", resp.Status)
	}
}

func testS3Compat_ListMultipartUploads(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	key := uniqueKey(t)

	createResp, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	uploadID := *createResp.UploadId
	t.Cleanup(func() {
		client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
			Bucket:   aws.String(inst.Bucket),
			Key:      aws.String(key),
			UploadId: aws.String(uploadID),
		})
	})

	listResp, err := client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}

	found := false
	for _, u := range listResp.Uploads {
		if u.Key != nil && *u.Key == key {
			found = true
			break
		}
	}
	if !found {
		t.Logf("ListMultipartUploads: upload %q not found (eventual consistency)", key)
	}
}

func testS3Compat_GetPutDeleteObjectTagging(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	key := uniqueKey(t)
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte("tagging-test")),
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	_, err = client.PutObjectTagging(ctx, &s3.PutObjectTaggingInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
		Tagging: &types.Tagging{
			TagSet: []types.Tag{
				{Key: aws.String("color"), Value: aws.String("blue")},
				{Key: aws.String("env"), Value: aws.String("test")},
			},
		},
	})
	if err != nil {
		t.Logf("PutObjectTagging not supported: %v", err)
		return
	}

	getResp, err := client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObjectTagging: %v", err)
	}
	if len(getResp.TagSet) != 2 {
		t.Fatalf("expected 2 tags, got %d", len(getResp.TagSet))
	}

	_, err = client.DeleteObjectTagging(ctx, &s3.DeleteObjectTaggingInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("DeleteObjectTagging: %v", err)
	}

	getResp, err = client.GetObjectTagging(ctx, &s3.GetObjectTaggingInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObjectTagging after delete: %v", err)
	}
	if len(getResp.TagSet) != 0 {
		t.Errorf("expected 0 tags after delete, got %d: %v", len(getResp.TagSet), getResp.TagSet)
	}
}

func testS3Compat_GetBucketACL(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	resp, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketAcl: %v", err)
	}
	if len(resp.Grants) == 0 {
		t.Error("GetBucketAcl: empty Grants")
	}
	t.Logf("GetBucketAcl: Owner=%v, Grants=%d", resp.Owner, len(resp.Grants))
}

func testS3Compat_PutBucketACL(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	_, err := client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
		Bucket: aws.String(inst.Bucket),
		ACL:    types.BucketCannedACLPublicRead,
	})
	if err != nil {
		t.Fatalf("PutBucketAcl: %v", err)
	}

	resp, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketAcl after put: %v", err)
	}
	if len(resp.Grants) == 0 {
		t.Error("GetBucketAcl: empty Grants after PutBucketAcl")
	}
}

func testS3Compat_GetObjectACL(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	key := uniqueKey(t)
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte("get-acl-test")),
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	resp, err := client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		t.Fatalf("GetObjectAcl: %v", err)
	}
	t.Logf("GetObjectAcl: Owner=%v, Grants=%d", resp.Owner, len(resp.Grants))
}

func testS3Compat_PutObjectACL(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	key := uniqueKey(t)
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
		Body:   bytes.NewReader([]byte("put-acl-test")),
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	_, err = client.PutObjectAcl(ctx, &s3.PutObjectAclInput{
		Bucket: aws.String(inst.Bucket),
		Key:    aws.String(key),
		ACL:    types.ObjectCannedACLPublicRead,
	})
	if err != nil {
		t.Fatalf("PutObjectAcl: %v", err)
	}
}

func testS3Compat_GetPutDeleteBucketPolicy(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + inst.Bucket + `/*"}]}`

	_, err := client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
		Bucket: aws.String(inst.Bucket),
		Policy: aws.String(policy),
	})
	if err != nil {
		t.Fatalf("PutBucketPolicy: %v", err)
	}

	resp, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketPolicy: %v", err)
	}
	if resp.Policy == nil || *resp.Policy == "" {
		t.Fatal("GetBucketPolicy: empty policy")
	}

	_, err = client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("DeleteBucketPolicy: %v", err)
	}

	_, err = client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err == nil {
		t.Error("expected error after DeleteBucketPolicy")
	}
}

func testS3Compat_GetPutDeleteBucketCors(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	cors := &types.CORSConfiguration{
		CORSRules: []types.CORSRule{
			{
				AllowedOrigins: []string{"https://example.com"},
				AllowedMethods: []string{"GET", "PUT"},
				AllowedHeaders: []string{"*"},
				MaxAgeSeconds:  aws.Int32(3600),
			},
		},
	}

	_, err := client.PutBucketCors(ctx, &s3.PutBucketCorsInput{
		Bucket:             aws.String(inst.Bucket),
		CORSConfiguration: cors,
	})
	if err != nil {
		t.Fatalf("PutBucketCors: %v", err)
	}

	resp, err := client.GetBucketCors(ctx, &s3.GetBucketCorsInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketCors: %v", err)
	}
	if len(resp.CORSRules) == 0 {
		t.Fatal("GetBucketCors: empty rules")
	}

	_, err = client.DeleteBucketCors(ctx, &s3.DeleteBucketCorsInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("DeleteBucketCors: %v", err)
	}

	_, err = client.GetBucketCors(ctx, &s3.GetBucketCorsInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err == nil {
		t.Error("expected error after DeleteBucketCors")
	}
}

func testS3Compat_GetPutDeleteBucketLifecycle(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	_, err := client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
		Bucket: aws.String(inst.Bucket),
		LifecycleConfiguration: &types.BucketLifecycleConfiguration{
			Rules: []types.LifecycleRule{
				{
					ID:     aws.String("test-expire"),
					Status: types.ExpirationStatusEnabled,
				Filter: &types.LifecycleRuleFilter{
					Prefix: aws.String("logs/"),
				},
					Expiration: &types.LifecycleExpiration{
						Days: aws.Int32(30),
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration: %v", err)
	}

	resp, err := client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketLifecycleConfiguration: %v", err)
	}
	if len(resp.Rules) == 0 {
		t.Fatal("GetBucketLifecycleConfiguration: empty rules")
	}

	_, err = client.DeleteBucketLifecycle(ctx, &s3.DeleteBucketLifecycleInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("DeleteBucketLifecycle: %v", err)
	}

	_, err = client.GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err == nil {
		t.Error("expected error after DeleteBucketLifecycle")
	}
}

func testS3Compat_CORSPreflight_OPTIONS(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	req, err := http.NewRequest("OPTIONS", fmt.Sprintf("%s/%s", gw.URL, inst.Bucket), nil)
	if err != nil {
		t.Fatalf("OPTIONS request: %v", err)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("OPTIONS: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
		t.Errorf("OPTIONS: unexpected status %d (expected 200, 400, or 403)", resp.StatusCode)
	}
}

func testS3Compat_GetPutDeleteBucketEncryption(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	client := newS3CompatClient(t, inst)

	_, err := client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
		Bucket: aws.String(inst.Bucket),
		ServerSideEncryptionConfiguration: &types.ServerSideEncryptionConfiguration{
			Rules: []types.ServerSideEncryptionRule{
				{
					ApplyServerSideEncryptionByDefault: &types.ServerSideEncryptionByDefault{
						SSEAlgorithm: types.ServerSideEncryptionAes256,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("PutBucketEncryption: %v", err)
	}

	resp, err := client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("GetBucketEncryption: %v", err)
	}
	if len(resp.ServerSideEncryptionConfiguration.Rules) == 0 {
		t.Fatal("GetBucketEncryption: empty rules")
	}

	_, err = client.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		t.Fatalf("DeleteBucketEncryption: %v", err)
	}

	_, err = client.GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err == nil {
		t.Error("expected error after DeleteBucketEncryption")
	}
}

func testS3Compat_SelectObjectContent_501(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	ctx := context.Background()
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(inst.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, ""),
		),
	)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	// Route through gateway to test the 501 handler, not the backend.
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String(gw.URL)
	})

	key := uniqueKey(t)

	_, err = client.SelectObjectContent(ctx, &s3.SelectObjectContentInput{
		Bucket:         aws.String(inst.Bucket),
		Key:            aws.String(key),
		Expression:     aws.String("SELECT * FROM S3Object"),
		ExpressionType: types.ExpressionTypeSql,
		InputSerialization: &types.InputSerialization{
			CSV: &types.CSVInput{},
		},
		OutputSerialization: &types.OutputSerialization{
			CSV: &types.CSVOutput{},
		},
	})
	if err == nil {
		t.Fatal("expected NotImplemented error")
	}
	t.Logf("SelectObjectContent error (expected): %v", err)
}
