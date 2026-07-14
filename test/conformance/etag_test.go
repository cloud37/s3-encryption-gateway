//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// testMultipartUploadPartETagQuoted verifies issue #215: UploadPart must
// return an HTTP ETag header enclosed in double quotes, as required by S3
// clients such as minio-go.
func testMultipartUploadPartETagQuoted(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	etag := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, bytes.Repeat([]byte("p"), 128))
	if len(etag) < 2 || !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) {
		t.Fatalf("UploadPart ETag = %q, want a double-quoted value", etag)
	}
}

// testMultipartUploadMinioGo verifies the complete multipart flow through the
// minio-go client. minio-go strips quotes from the UploadPart response before
// sending the ETag in CompleteMultipartUpload, so this catches incompatibility
// in the client-facing protocol that a raw HTTP header assertion misses.
func testMultipartUploadMinioGo(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	endpoint, err := url.Parse(gw.URL)
	if err != nil {
		t.Fatalf("parse gateway URL: %v", err)
	}
	client, err := minio.NewCore(endpoint.Host, &minio.Options{
		Creds:  credentials.NewStaticV4(inst.AccessKey, inst.SecretKey, ""),
		Secure: endpoint.Scheme == "https",
	})
	if err != nil {
		t.Fatalf("create minio-go client: %v", err)
	}

	ctx := context.Background()
	key := uniqueKey(t)
	uploadID, err := client.NewMultipartUpload(ctx, inst.Bucket, key, minio.PutObjectOptions{})
	if err != nil {
		t.Fatalf("NewMultipartUpload: %v", err)
	}
	completed := false
	t.Cleanup(func() {
		if !completed {
			_ = client.AbortMultipartUpload(ctx, inst.Bucket, key, uploadID)
		}
	})

	partData := bytes.Repeat([]byte("minio-go-part"), 128)
	part, err := client.PutObjectPart(ctx, inst.Bucket, key, uploadID, 1,
		bytes.NewReader(partData), int64(len(partData)), minio.PutObjectPartOptions{})
	if err != nil {
		t.Fatalf("PutObjectPart: %v", err)
	}

	if part.ETag == "" {
		t.Fatal("PutObjectPart returned an empty ETag")
	}
	_, err = client.CompleteMultipartUpload(ctx, inst.Bucket, key, uploadID,
		[]minio.CompletePart{{PartNumber: 1, ETag: part.ETag}}, minio.PutObjectOptions{})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	completed = true
}
