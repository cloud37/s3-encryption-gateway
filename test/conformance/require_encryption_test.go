//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	"github.com/stretchr/testify/require"
)

// A failed or unsupported versioning query does not establish that old
// versions cannot exist. Fail closed rather than deleting only current keys.
func gh380CleanupVersioned(output *awss3.GetBucketVersioningOutput, err error) (bool, error) {
	if err != nil {
		return false, fmt.Errorf("get cleanup versioning: %w", err)
	}
	if output == nil {
		return false, errors.New("get cleanup versioning: missing response")
	}
	switch output.Status {
	case "":
		return false, nil
	case types.BucketVersioningStatusEnabled, types.BucketVersioningStatusSuspended:
		return true, nil
	default:
		return false, fmt.Errorf("get cleanup versioning: unrecognized status %q", output.Status)
	}
}

func TestGH380CleanupVersionSelection(t *testing.T) {
	for _, tc := range []struct {
		name               string
		output             *awss3.GetBucketVersioningOutput
		err                error
		versioned, wantErr bool
	}{
		{"never-enabled", &awss3.GetBucketVersioningOutput{}, nil, false, false},
		{"enabled", &awss3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusEnabled}, nil, true, false},
		{"suspended", &awss3.GetBucketVersioningOutput{Status: types.BucketVersioningStatusSuspended}, nil, true, false},
		{"unknown-status", &awss3.GetBucketVersioningOutput{Status: "unexpected"}, nil, false, true},
		{"missing-response", nil, nil, false, true},
		{"unsupported", nil, &smithy.GenericAPIError{Code: "NotImplemented"}, false, true},
		{"access-denied", nil, &smithy.GenericAPIError{Code: "AccessDenied"}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			versioned, err := gh380CleanupVersioned(tc.output, tc.err)
			if versioned != tc.versioned || (err != nil) != tc.wantErr {
				t.Fatalf("versioned=%t err=%v", versioned, err)
			}
		})
	}
}

// Cleanup only this callback's unique prefix, including every version and
// delete marker when versioning is enabled or suspended. SkipDelete never deletes objects.
func gh380CleanupPrefix(t *testing.T, inst provider.Instance, prefix string) {
	t.Helper()
	var selected provider.Provider
	for _, p := range provider.All() {
		if p.Name() == inst.ProviderName {
			selected = p
			break
		}
	}
	if selected == nil {
		t.Fatal("provider cleanup policy not found")
	}
	if selected.CleanupPolicy() != provider.CleanupPolicyDelete {
		return
	}
	client := newS3CompatClient(t, inst)
	t.Cleanup(func() {
		ctx := context.Background()
		v, err := client.GetBucketVersioning(ctx, &awss3.GetBucketVersioningInput{Bucket: aws.String(inst.Bucket)})
		versioned, err := gh380CleanupVersioned(v, err)
		if err != nil {
			t.Errorf("%v", err)
			return
		}
		if versioned {
			pages := awss3.NewListObjectVersionsPaginator(client, &awss3.ListObjectVersionsInput{Bucket: aws.String(inst.Bucket), Prefix: aws.String(prefix)})
			var objects []types.ObjectIdentifier
			for pages.HasMorePages() {
				page, err := pages.NextPage(ctx)
				if err != nil {
					t.Errorf("list cleanup versions: %v", err)
					return
				}
				for _, v := range page.Versions {
					objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
				}
				for _, v := range page.DeleteMarkers {
					objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
				}
			}
			for _, obj := range objects {
				if !strings.HasPrefix(aws.ToString(obj.Key), prefix) || obj.VersionId == nil || aws.ToString(obj.VersionId) == "" {
					t.Errorf("invalid cleanup version key=%q version=%q", aws.ToString(obj.Key), aws.ToString(obj.VersionId))
					continue
				}
				if _, err := client.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(inst.Bucket), Key: obj.Key, VersionId: obj.VersionId}); err != nil {
					t.Errorf("delete cleanup version %s: %v", aws.ToString(obj.Key), err)
				}
			}
			return
		}
		pages := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{Bucket: aws.String(inst.Bucket), Prefix: aws.String(prefix)})
		var keys []*string
		for pages.HasMorePages() {
			page, err := pages.NextPage(ctx)
			if err != nil {
				t.Errorf("list cleanup objects: %v", err)
				return
			}
			for _, obj := range page.Contents {
				keys = append(keys, obj.Key)
			}
		}
		for _, key := range keys {
			if !strings.HasPrefix(aws.ToString(key), prefix) {
				t.Errorf("invalid cleanup object key=%q", aws.ToString(key))
				continue
			}
			if _, err := client.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(inst.Bucket), Key: key}); err != nil {
				t.Errorf("delete cleanup object %s: %v", aws.ToString(key), err)
			}
		}
	})
}

func gh380Plant(t *testing.T, inst provider.Instance, backend s3.Client, key string, data []byte) {
	t.Helper()
	_, err := backend.PutObject(t.Context(), inst.Bucket, key, bytes.NewReader(data), nil, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)
	_, err = backend.HeadObject(t.Context(), inst.Bucket, key, nil)
	require.NoError(t, err)
}

func gh380Request(t *testing.T, gw *harness.Gateway, method, target string, headers map[string]string, status int) {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	require.NoError(t, err)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := gw.HTTPClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, status, resp.StatusCode, "%s", body)
	if status == http.StatusForbidden && method != http.MethodHead {
		require.Contains(t, string(body), "<Code>AccessDenied</Code>")
	}
	if method == http.MethodHead {
		require.Empty(t, body)
	}
}

func gh380PlaintextReads(t *testing.T, inst provider.Instance) {
	prefix := "conformance-gh380-" + uniqueSuffix(t) + "/"
	gh380CleanupPrefix(t, inst, prefix)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: gh380\nbuckets: [%q]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n", inst.Bucket)), 0600))
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	backend, err := s3.NewBackendClient(&config.BackendConfig{Endpoint: inst.Endpoint, Region: inst.Region, AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Provider: inst.ProviderName, UsePathStyle: true})
	require.NoError(t, err)
	key := prefix + uniqueSuffix(t)
	gh380Plant(t, inst, backend, key, []byte("planted plaintext"))
	url := objectURL(gw, inst.Bucket, key)
	gh380Request(t, gw, "GET", url, nil, 403)
	gh380Request(t, gw, "HEAD", url, nil, 403)
	for _, r := range []string{"bytes=0-2", "bytes=2-", "bytes=-2"} {
		gh380Request(t, gw, "GET", url, map[string]string{"Range": r}, 403)
	}
	control := prefix + uniqueSuffix(t)
	put(t, gw, inst.Bucket, control, []byte("encrypted"))
	require.Equal(t, []byte("encrypted"), get(t, gw, inst.Bucket, control))
}

func gh380EncryptedReads(t *testing.T, inst provider.Instance) {
	for _, tc := range []struct {
		name string
		opts []harness.Option
	}{
		{"buffered", []harness.Option{harness.WithChunking(false)}},
		{"chunked", []harness.Option{harness.WithChunking(true)}},
		{"encrypted-metadata", []harness.Option{harness.WithChunking(true), harness.WithMetadataEncryptionKey(bytes.Repeat([]byte{42}, 32))}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := "conformance-gh380-" + uniqueSuffix(t) + "/"
			gh380CleanupPrefix(t, inst, prefix)
			path := filepath.Join(t.TempDir(), "policy.yaml")
			require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: gh380\nbuckets: [%q]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n", inst.Bucket)), 0600))
			pm := config.NewPolicyManager()
			require.NoError(t, pm.ReloadPolicies([]string{path}))
			opts := []harness.Option{harness.WithPolicyManager(pm), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations)}
			opts = append(opts, tc.opts...)
			gw := harness.StartGateway(t, inst, opts...)
			key := prefix + uniqueSuffix(t)
			data := []byte("encrypted control")
			put(t, gw, inst.Bucket, key, data)
			gh380Request(t, gw, "HEAD", objectURL(gw, inst.Bucket, key), nil, 200)
			require.Equal(t, data, get(t, gw, inst.Bucket, key))
			require.Equal(t, data[1:4], getRange(t, gw, inst.Bucket, key, 1, 3))
		})
	}
}

func gh380CachePolicyReload(t *testing.T, inst provider.Instance) {
	prefix := "conformance-gh380-" + uniqueSuffix(t) + "/"
	gh380CleanupPrefix(t, inst, prefix)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: gh380\nbuckets: [%q]\nrequire_encryption: false\nencrypt_multipart_uploads: false\n", inst.Bucket)), 0600))
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations), harness.WithConfigMutator(func(c *config.Config) {
		c.Cache = config.CacheConfig{Enabled: true, MaxSize: 1 << 20, MaxItems: 100, DefaultTTL: time.Minute}
	}))
	backend, err := s3.NewBackendClient(&config.BackendConfig{Endpoint: inst.Endpoint, Region: inst.Region, AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Provider: inst.ProviderName, UsePathStyle: true})
	require.NoError(t, err)
	key := prefix + uniqueSuffix(t)
	gh380Plant(t, inst, backend, key, []byte("cache plaintext"))
	require.Equal(t, []byte("cache plaintext"), get(t, gw, inst.Bucket, key))
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: gh380\nbuckets: [%q]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n", inst.Bucket)), 0600))
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	gh380Request(t, gw, "GET", objectURL(gw, inst.Bucket, key), nil, 403)
	encrypted := prefix + uniqueSuffix(t)
	put(t, gw, inst.Bucket, encrypted, []byte("cached encrypted"))
	require.Equal(t, []byte("cached encrypted"), get(t, gw, inst.Bucket, encrypted))
	gh380Plant(t, inst, backend, encrypted, []byte("replacement plaintext"))
	gh380Request(t, gw, "GET", objectURL(gw, inst.Bucket, encrypted), nil, 403)
}

func gh380VersionedReads(t *testing.T, inst provider.Instance) {
	prefix := "conformance-gh380-" + uniqueSuffix(t) + "/"
	gh380CleanupPrefix(t, inst, prefix)
	client := newS3CompatClient(t, inst)
	_, err := client.PutBucketVersioning(t.Context(), &awss3.PutBucketVersioningInput{Bucket: aws.String(inst.Bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}})
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: gh380\nbuckets: [%q]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n", inst.Bucket)), 0600))
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	backend, err := s3.NewBackendClient(&config.BackendConfig{Endpoint: inst.Endpoint, Region: inst.Region, AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Provider: inst.ProviderName, UsePathStyle: true})
	require.NoError(t, err)
	key := prefix + uniqueSuffix(t)
	gh380Plant(t, inst, backend, key, []byte("old plaintext"))
	head, err := client.HeadObject(t.Context(), &awss3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
	require.NoError(t, err)
	require.NotEmpty(t, aws.ToString(head.VersionId))
	put(t, gw, inst.Bucket, key, []byte("encrypted current"))
	gh380Request(t, gw, "GET", objectURL(gw, inst.Bucket, key)+"?versionId="+aws.ToString(head.VersionId), nil, 403)
	require.Equal(t, []byte("encrypted current"), get(t, gw, inst.Bucket, key))
}

func gh380CopyObjectSources(t *testing.T, inst provider.Instance) {
	prefix := "conformance-gh380-" + uniqueSuffix(t) + "/"
	gh380CleanupPrefix(t, inst, prefix)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: gh380\nbuckets: [%q]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n", inst.Bucket)), 0600))
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	backend, err := s3.NewBackendClient(&config.BackendConfig{Endpoint: inst.Endpoint, Region: inst.Region, AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Provider: inst.ProviderName, UsePathStyle: true})
	require.NoError(t, err)
	src, dst := prefix+uniqueSuffix(t), prefix+uniqueSuffix(t)
	gh380Plant(t, inst, backend, src, []byte("source"))
	put(t, gw, inst.Bucket, dst, []byte("unchanged"))
	gh380Request(t, gw, "PUT", objectURL(gw, inst.Bucket, dst), map[string]string{"x-amz-copy-source": "/" + inst.Bucket + "/" + src}, 403)
	require.Equal(t, []byte("unchanged"), get(t, gw, inst.Bucket, dst))
	t.Run("unprotected-source-import", func(t *testing.T) {
		backendSDK := newS3CompatClient(t, inst)
		sourceBucket := "gh380-" + uniqueSuffix(t)
		sourceKey := "source"
		cleanup := provider.CleanupPolicySkipDelete
		for _, p := range provider.All() {
			if p.Name() == inst.ProviderName {
				cleanup = p.CleanupPolicy()
				break
			}
		}
		input := &awss3.CreateBucketInput{Bucket: aws.String(sourceBucket)}
		if inst.Region != "" && inst.Region != "us-east-1" {
			input.CreateBucketConfiguration = &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(inst.Region)}
		}
		_, err := backendSDK.CreateBucket(t.Context(), input)
		if err != nil {
			var apiErr smithy.APIError
			if errors.As(err, &apiErr) && (apiErr.ErrorCode() == "AccessDenied" || apiErr.ErrorCode() == "NotImplemented" || apiErr.ErrorCode() == "MethodNotAllowed" || apiErr.ErrorCode() == "UnsupportedOperation") {
				t.Skipf("provider cannot create an independent source bucket (%s): %v", apiErr.ErrorCode(), err)
			}
			t.Fatalf("create independent source bucket: %v", err)
		}
		if cleanup == provider.CleanupPolicyDelete {
			t.Cleanup(func() {
				_, err := backendSDK.DeleteObject(context.Background(), &awss3.DeleteObjectInput{Bucket: aws.String(sourceBucket), Key: aws.String(sourceKey)})
				if err != nil {
					var apiErr smithy.APIError
					if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchKey" {
						t.Errorf("cleanup source object: %v", err)
					}
				}
				_, err = backendSDK.DeleteBucket(context.Background(), &awss3.DeleteBucketInput{Bucket: aws.String(sourceBucket)})
				if err != nil {
					t.Errorf("cleanup source bucket: %v", err)
				}
			})
		}
		plain := []byte("unprotected source import")
		_, err = backend.PutObject(t.Context(), sourceBucket, sourceKey, bytes.NewReader(plain), nil, nil, "", nil, "", "", "", "", "")
		require.NoError(t, err)
		_, err = backend.HeadObject(t.Context(), sourceBucket, sourceKey, nil)
		require.NoError(t, err)
		destination := prefix + uniqueSuffix(t)
		gh380Request(t, gw, "PUT", objectURL(gw, inst.Bucket, destination), map[string]string{"x-amz-copy-source": "/" + sourceBucket + "/" + sourceKey}, 200)
		require.Equal(t, plain, get(t, gw, inst.Bucket, destination))
		reader, meta, err := backend.GetObject(t.Context(), inst.Bucket, destination, nil, nil)
		require.NoError(t, err)
		raw, err := io.ReadAll(reader)
		require.NoError(t, err)
		require.NoError(t, reader.Close())
		require.True(t, crypto.IsEncryptedMetadata(meta))
		require.NotEqual(t, plain, raw)
	})
}

func gh380UploadPartCopySources(t *testing.T, inst provider.Instance) {
	prefix := "conformance-gh380-" + uniqueSuffix(t) + "/"
	gh380CleanupPrefix(t, inst, prefix)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: gh380\nbuckets: [%q]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n", inst.Bucket)), 0600))
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	backend, err := s3.NewBackendClient(&config.BackendConfig{Endpoint: inst.Endpoint, Region: inst.Region, AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Provider: inst.ProviderName, UsePathStyle: true})
	require.NoError(t, err)
	src, dst := prefix+uniqueSuffix(t), prefix+uniqueSuffix(t)
	gh380Plant(t, inst, backend, src, []byte("plaintext source"))
	upload := initiateMultipartUpload(t, gw, inst.Bucket, dst)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dst, upload) })
	original := bytes.Repeat([]byte("existing part"), 1024)
	etag := uploadPart(t, gw, inst.Bucket, dst, upload, 1, original)
	for _, r := range []string{"", "bytes=0-2"} {
		headers := map[string]string{"x-amz-copy-source": "/" + inst.Bucket + "/" + src}
		if r != "" {
			headers["x-amz-copy-source-range"] = r
		}
		gh380Request(t, gw, "PUT", fmt.Sprintf("%s?partNumber=1&uploadId=%s", objectURL(gw, inst.Bucket, dst), upload), headers, 403)
	}
	parts, err := backend.ListParts(t.Context(), inst.Bucket, dst, upload)
	require.NoError(t, err)
	require.Len(t, parts, 1)
	require.Equal(t, etag, parts[0].ETag)
}

func gh380EncryptedMPUCopySources(t *testing.T, inst provider.Instance) {
	prefix := "conformance-gh380-" + uniqueSuffix(t) + "/"
	gh380CleanupPrefix(t, inst, prefix)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("id: gh380\nbuckets: [%q]\nrequire_encryption: true\nencrypt_multipart_uploads: true\n", inst.Bucket)), 0600))
	pm := config.NewPolicyManager()
	require.NoError(t, pm.ReloadPolicies([]string{path}))
	vk := provider.StartValkey(context.Background(), t)
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations), harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket), harness.WithKeyManager(makeAESKEKManager(t)))
	backend, err := s3.NewBackendClient(&config.BackendConfig{Endpoint: inst.Endpoint, Region: inst.Region, AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Provider: inst.ProviderName, UsePathStyle: true})
	require.NoError(t, err)
	src, dst := prefix+uniqueSuffix(t), prefix+uniqueSuffix(t)
	gh380Plant(t, inst, backend, src, []byte("plaintext source"))
	upload := initiateMultipartUpload(t, gw, inst.Bucket, dst)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, dst, upload) })
	good := prefix + uniqueSuffix(t)
	put(t, gw, inst.Bucket, good, []byte("encrypted source"))
	first := doUploadPartCopy(t, gw, inst.Bucket, dst, upload, 1, inst.Bucket, good, "")
	before, err := backend.ListParts(t.Context(), inst.Bucket, dst, upload)
	require.NoError(t, err)
	gh380Request(t, gw, "PUT", fmt.Sprintf("%s?partNumber=1&uploadId=%s", objectURL(gw, inst.Bucket, dst), upload), map[string]string{"x-amz-copy-source": "/" + inst.Bucket + "/" + src}, 403)
	after, err := backend.ListParts(t.Context(), inst.Bucket, dst, upload)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Equal(t, first, doUploadPartCopy(t, gw, inst.Bucket, dst, upload, 1, inst.Bucket, good, ""))
}
