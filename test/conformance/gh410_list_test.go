//go:build conformance

package conformance

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// Exercise actual encrypted MPU manifests and the AWS SDK's v2 paginator.
func testGH410_EncryptedMPUPagination(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket))
	client := newCompatS3Client(t, gw, inst)
	backend := newS3Client(t, inst)
	prefix := uniqueKey(t) + "/"
	want := make(map[string]bool)
	for i := 0; i < 7; i++ {
		key := fmt.Sprintf("%sobj-%02d", prefix, i)
		want[key] = true
		if i == 0 || i == 2 || i == 5 {
			uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
			etag := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, []byte("encrypted multipart payload"))
			completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{{1, etag}})
			if _, err := backend.HeadObject(ctx, inst.Bucket, key+crypto.MPUManifestSuffix, nil); err != nil {
				t.Fatalf("missing backend manifest for %s: %v", key, err)
			}
		} else {
			put(t, gw, inst.Bucket, key, []byte("single PUT"))
		}
	}
	for _, maxKeys := range []int32{1, 2, 3, 5, 7} {
		t.Run(fmt.Sprintf("max-keys-%d", maxKeys), func(t *testing.T) {
			paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{Bucket: aws.String(inst.Bucket), Prefix: aws.String(prefix), MaxKeys: aws.Int32(maxKeys)})
			seen := make(map[string]bool)
			pages := 0
			for paginator.HasMorePages() {
				pages++
				if pages > 20 {
					t.Fatal("pagination did not terminate")
				}
				page, err := paginator.NextPage(ctx)
				if err != nil {
					t.Fatalf("page %d: %v", pages, err)
				}
				if aws.ToBool(page.IsTruncated) && aws.ToString(page.NextContinuationToken) == "" {
					t.Fatalf("page %d is truncated without a continuation token", pages)
				}
				for _, obj := range page.Contents {
					key := aws.ToString(obj.Key)
					if !want[key] || seen[key] {
						t.Fatalf("unexpected or duplicate key %q", key)
					}
					seen[key] = true
				}
			}
			if len(seen) != len(want) {
				var missing []string
				for key := range want {
					if !seen[key] {
						missing = append(missing, key)
					}
				}
				sort.Strings(missing)
				t.Fatalf("missing keys: %v", missing)
			}
		})
		t.Run(fmt.Sprintf("v1-max-keys-%d", maxKeys), func(t *testing.T) {
			var marker *string
			seen := make(map[string]bool)
			for pages := 0; ; pages++ {
				if pages > 20 {
					t.Fatal("v1 pagination did not terminate")
				}
				page, err := client.ListObjects(ctx, &awss3.ListObjectsInput{Bucket: aws.String(inst.Bucket), Prefix: aws.String(prefix), MaxKeys: aws.Int32(maxKeys), Marker: marker})
				if err != nil {
					t.Fatalf("v1 page %d: %v", pages, err)
				}
				for _, obj := range page.Contents {
					key := aws.ToString(obj.Key)
					if !want[key] || seen[key] {
						t.Fatalf("unexpected or duplicate v1 key %q", key)
					}
					seen[key] = true
				}
				if !aws.ToBool(page.IsTruncated) {
					break
				}
				if aws.ToString(page.NextMarker) == "" || aws.ToString(page.NextMarker) == aws.ToString(marker) {
					t.Fatalf("v1 page %d has missing or repeated marker", pages)
				}
				marker = page.NextMarker
			}
			if len(seen) != len(want) {
				t.Fatalf("incomplete v1 listing: got %d of %d keys", len(seen), len(want))
			}
		})
	}

	// Common prefixes consume page capacity too. Include a direct MPU object
	// whose manifest must be filtered alongside multiple rolled-up prefixes.
	delimiterPrefix := prefix + "tree/"
	key := delimiterPrefix + "a"
	cleanupKeys := []string{key, delimiterPrefix + "b/one", delimiterPrefix + "c/two", delimiterPrefix + "d/three"}
	wantObjects := map[string]bool{key: true}
	wantPrefixes := map[string]bool{delimiterPrefix + "b/": true, delimiterPrefix + "c/": true, delimiterPrefix + "d/": true}
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	etag := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, []byte("prefix pagination"))
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{{1, etag}})
	for _, item := range cleanupKeys[1:] {
		put(t, gw, inst.Bucket, item, []byte("nested"))
	}
	t.Run("delimiter", func(t *testing.T) {
		paginator := awss3.NewListObjectsV2Paginator(client, &awss3.ListObjectsV2Input{Bucket: aws.String(inst.Bucket), Prefix: aws.String(delimiterPrefix), Delimiter: aws.String("/"), MaxKeys: aws.Int32(2)})
		seenObjects, seenPrefixes := make(map[string]bool), make(map[string]bool)
		pages := 0
		for paginator.HasMorePages() {
			pages++
			if pages > 10 {
				t.Fatal("delimiter pagination did not terminate")
			}
			page, err := paginator.NextPage(ctx)
			if err != nil {
				t.Fatalf("delimiter page %d: %v", pages, err)
			}
			if len(page.Contents)+len(page.CommonPrefixes) > 2 || (aws.ToBool(page.IsTruncated) && aws.ToString(page.NextContinuationToken) == "") {
				t.Fatalf("invalid delimiter page %d: %+v", pages, page)
			}
			for _, object := range page.Contents {
				name := aws.ToString(object.Key)
				if !wantObjects[name] || seenObjects[name] {
					t.Fatalf("unexpected or duplicate object %q", name)
				}
				seenObjects[name] = true
			}
			for _, item := range page.CommonPrefixes {
				name := aws.ToString(item.Prefix)
				if !wantPrefixes[name] || seenPrefixes[name] {
					t.Fatalf("unexpected or duplicate prefix %q", name)
				}
				seenPrefixes[name] = true
			}
		}
		if len(seenObjects) != len(wantObjects) || len(seenPrefixes) != len(wantPrefixes) {
			t.Fatalf("incomplete delimiter listing: objects=%v prefixes=%v", seenObjects, seenPrefixes)
		}
	})
}
