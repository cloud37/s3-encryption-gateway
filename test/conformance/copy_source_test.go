//go:build conformance

package conformance

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
	"github.com/stretchr/testify/require"
)

type copySourceTransport struct {
	base  http.RoundTripper
	calls atomic.Int64
}

func (c *copySourceTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return c.base.RoundTrip(r)
}

func copySourceGateway(t *testing.T, inst provider.Instance, mode string) (*harness.Gateway, *awss3.Client, *copySourceTransport) {
	t.Helper()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	counted := &copySourceTransport{base: transport}
	opts := []harness.Option{
		harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}),
		harness.WithKeyManager(makeAESKEKManager(t)), harness.WithChunking(mode != "buffered"),
		harness.WithPBKDF2Iterations(100000), harness.WithBackendTransport(counted),
		harness.WithConfigMutator(func(cfg *config.Config) {
			cfg.ProxiedBucket = inst.Bucket
			cfg.Backend.Retry.MaxAttempts = 1
		}),
	}
	if mode == "plaintext" {
		opts = append(opts, harness.WithPolicyManager(newBypassPolicyManager(t, inst.Bucket)))
	}
	gw := harness.StartGateway(t, inst, opts...)
	client := awss3.New(awss3.Options{
		Region: "us-east-1", BaseEndpoint: aws.String(gw.URL), UsePathStyle: true,
		Credentials: credentials.NewStaticCredentialsProvider(testAccessKey, testSecretKey, ""),
		HTTPClient:  gw.HTTPClient(), RetryMaxAttempts: 1,
	})
	t.Cleanup(client.Options().HTTPClient.(*http.Client).CloseIdleConnections)
	return gw, client, counted
}

func copySourcePut(t *testing.T, client *awss3.Client, bucket, key string, data []byte) *awss3.PutObjectOutput {
	t.Helper()
	out, err := client.PutObject(t.Context(), &awss3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(data), ContentType: aws.String("text/plain"), Metadata: map[string]string{"purpose": "gh346"}})
	require.NoError(t, err)
	return out
}

func copySourceCheck(t *testing.T, client *awss3.Client, bucket, key string, want []byte) {
	t.Helper()
	out, err := client.GetObject(t.Context(), &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	require.NoError(t, err)
	defer out.Body.Close()
	got, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	require.True(t, bytes.Equal(want, got), "copied bytes differ: got %d bytes, want %d", len(got), len(want))
	require.Equal(t, int64(len(want)), aws.ToInt64(out.ContentLength))
	require.NotEmpty(t, aws.ToString(out.ETag))
}

func copySourceCopy(t *testing.T, client *awss3.Client, bucket, destination, header string, part bool) {
	t.Helper()
	if !part {
		out, err := client.CopyObject(t.Context(), &awss3.CopyObjectInput{Bucket: aws.String(bucket), Key: aws.String(destination), CopySource: aws.String(header)})
		require.NoError(t, err)
		require.NotNil(t, out.CopyObjectResult)
		require.NotEmpty(t, aws.ToString(out.CopyObjectResult.ETag))
		return
	}
	init, err := client.CreateMultipartUpload(t.Context(), &awss3.CreateMultipartUploadInput{Bucket: aws.String(bucket), Key: aws.String(destination)})
	require.NoError(t, err)
	require.NotEmpty(t, aws.ToString(init.UploadId))
	completed := false
	defer func() {
		if !completed {
			_, err := client.AbortMultipartUpload(t.Context(), &awss3.AbortMultipartUploadInput{Bucket: aws.String(bucket), Key: aws.String(destination), UploadId: init.UploadId})
			if err != nil {
				t.Errorf("abort failed copied upload: %v", err)
			}
		}
	}()
	out, err := client.UploadPartCopy(t.Context(), &awss3.UploadPartCopyInput{Bucket: aws.String(bucket), Key: aws.String(destination), UploadId: init.UploadId, PartNumber: aws.Int32(1), CopySource: aws.String(header)})
	require.NoError(t, err)
	require.NotNil(t, out.CopyPartResult)
	require.NotEmpty(t, aws.ToString(out.CopyPartResult.ETag))
	_, err = client.CompleteMultipartUpload(t.Context(), &awss3.CompleteMultipartUploadInput{Bucket: aws.String(bucket), Key: aws.String(destination), UploadId: init.UploadId, MultipartUpload: &types.CompletedMultipartUpload{Parts: []types.CompletedPart{{PartNumber: aws.Int32(1), ETag: out.CopyPartResult.ETag}}}})
	require.NoError(t, err)
	completed = true
}

func testCopySourceEncodedObject(t *testing.T, inst provider.Instance) {
	runCopySourceEncoded(t, inst, false)
}

func testCopySourceEncodedPart(t *testing.T, inst provider.Instance) {
	runCopySourceEncoded(t, inst, true)
}

// Exact SDK CopySource headers model AWS CLI escaping and PHP's escaped key
// slashes. Real provider reads verify bytes, not only a successful XML status.
func runCopySourceEncoded(t *testing.T, inst provider.Instance, part bool) {
	for _, mode := range []string{"chunked", "buffered", "plaintext"} {
		t.Run(mode, func(t *testing.T) {
			_, client, _ := copySourceGateway(t, inst, mode)
			for _, tc := range []struct{ name, key, wire string }{
				{"control", "dir/plain.txt", "dir/plain.txt"},
				{"space", "dir/with space.txt", "dir/with%20space.txt"},
				{"unicode", "dir/umlaut-ä.txt", "dir/umlaut-%C3%A4.txt"},
				{"symbols", "dir/a+b&c.txt", "dir/a%2Bb%26c.txt"},
				{"literal-plus", "dir/a+b.txt", "dir/a+b.txt"},
				{"php-slashes", "dir/plain.txt", "dir%2Fplain.txt"},
				{"literal-percent", "dir/literal%2F.txt", "dir/literal%252F.txt"},
				{"query-in-key", "dir/name?versionId=literal#hash", "dir/name%3FversionId%3Dliteral%23hash"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					prefix := uniqueKey(t) + "/"
					key, destination := prefix+tc.key, uniqueKey(t)
					plain := []byte("GH-346 intended source bytes " + tc.name)
					if part && mode == "plaintext" {
						// Backend-native part-copy implementations can enforce the
						// S3 minimum part size even for a single final part.
						plain = bytes.Repeat([]byte("i"), 5*1024*1024)
					}
					copySourcePut(t, client, inst.Bucket, key, plain)
					copySourceCheck(t, client, inst.Bucket, key, plain)
					if tc.key != tc.wire {
						// With both objects present the old parser can silently copy
						// the wrong object instead of returning NoSuchKey.
						wrong := []byte("wrong encoded-looking source")
						if part && mode == "plaintext" {
							wrong = bytes.Repeat([]byte("w"), 5*1024*1024)
						}
						copySourcePut(t, client, inst.Bucket, prefix+tc.wire, wrong)
					}
					header := inst.Bucket + "/" + prefix + tc.wire
					if tc.name == "php-slashes" {
						header = "/" + inst.Bucket + "/" + url.PathEscape(key)
					}
					copySourceCopy(t, client, inst.Bucket, destination, header, part)
					copySourceCheck(t, client, inst.Bucket, destination, plain)
				})
			}
		})
	}
}

func testCopySourceMalformed(t *testing.T, inst provider.Instance) {
	gw, _, counted := copySourceGateway(t, inst, "chunked")
	for _, part := range []bool{false, true} {
		for _, tc := range []struct {
			source string
			status int
			code   string
		}{
			{inst.Bucket + "/key%", 400, "InvalidArgument"},
			{inst.Bucket + "/key%2", 400, "InvalidArgument"},
			{inst.Bucket + "/key%ZZ", 400, "InvalidArgument"},
			{"%ZZ/key", 400, "InvalidArgument"},
			{inst.Bucket + "/?versionId=v", 400, "InvalidArgument"},
			{inst.Bucket + "/key?versionId=%ZZ", 400, "InvalidArgument"},
			{"%6Futside/key%20name", 403, "AccessDenied"},
		} {
			t.Run(tc.source+map[bool]string{true: "/part", false: "/object"}[part], func(t *testing.T) {
				path := objectURL(gw, inst.Bucket, uniqueKey(t))
				if part {
					path += "?partNumber=1&uploadId=never-accessed"
				}
				req, err := http.NewRequestWithContext(t.Context(), http.MethodPut, path, nil)
				require.NoError(t, err)
				req.Header.Set("x-amz-copy-source", tc.source)
				req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
				require.NoError(t, v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC()))
				before := counted.calls.Load()
				resp, err := gw.HTTPClient().Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()
				body, err := io.ReadAll(resp.Body)
				require.NoError(t, err)
				require.Equal(t, tc.status, resp.StatusCode, string(body))
				var response struct{ Code, Message, Resource string }
				require.NoError(t, xml.Unmarshal(body, &response))
				require.Equal(t, tc.code, response.Code)
				require.Equal(t, req.URL.Path, response.Resource)
				if tc.status == 400 {
					require.Equal(t, "Invalid x-amz-copy-source header", response.Message)
				}
				require.Equal(t, before, counted.calls.Load(), "rejected source must not access backend")
			})
		}
	}
}

func testCopySourceVersionedObject(t *testing.T, inst provider.Instance) {
	runCopySourceVersioned(t, inst, false)
}
func testCopySourceVersionedPart(t *testing.T, inst provider.Instance) {
	runCopySourceVersioned(t, inst, true)
}

func runCopySourceVersioned(t *testing.T, inst provider.Instance, part bool) {
	backend := newS3CompatClient(t, inst)
	_, err := backend.PutBucketVersioning(t.Context(), &awss3.PutBucketVersioningInput{Bucket: aws.String(inst.Bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}})
	require.NoError(t, err)
	_, client, _ := copySourceGateway(t, inst, "chunked")
	key := uniqueKey(t) + "/with space.txt"
	first := []byte("selected old version")
	copySourcePut(t, client, inst.Bucket, key, first)
	head, err := backend.HeadObject(t.Context(), &awss3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
	require.NoError(t, err)
	require.NotEmpty(t, aws.ToString(head.VersionId))
	copySourcePut(t, client, inst.Bucket, key, []byte("latest version must not be selected"))
	destination := uniqueKey(t)
	header := inst.Bucket + "/" + strings.ReplaceAll(url.QueryEscape(key), "+", "%20") + "?versionId=" + strings.ReplaceAll(url.QueryEscape(aws.ToString(head.VersionId)), "+", "%20")
	copySourceCopy(t, client, inst.Bucket, destination, header, part)
	copySourceCheck(t, client, inst.Bucket, destination, first)
}
