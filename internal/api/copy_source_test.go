package api

import (
	"bytes"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestCopySource_ParseEncodedIdentity(t *testing.T) {
	for _, tc := range []struct{ source, bucket, key, version string }{
		{"b/dir/plain.txt", "b", "dir/plain.txt", ""},
		{"/b/dir%2Fplain.txt", "b", "dir/plain.txt", ""},
		{"b/with%20space", "b", "with space", ""},
		{"b/umlaut-%C3%A4", "b", "umlaut-ä", ""},
		{"b/a%2Bb%26c", "b", "a+b&c", ""},
		{"b/a+b", "b", "a+b", ""},
		{"b/literal%252F", "b", "literal%2F", ""},
		{"b/percent%25", "b", "percent%", ""},
		{"b/name%3FversionId%3Dliteral", "b", "name?versionId=literal", ""},
		{"b/hash%23name", "b", "hash#name", ""},
		{"b/with%20space?versionId=v123", "b", "with space", "v123"},
		{"b/name%3FversionId%3Dliteral?versionId=v%2B%2F%3D%25", "b", "name?versionId=literal", "v+/=%"},
		{"b/key?versionId=v+/=", "b", "key", "v+/="},
		{"b/key?versionId=", "b", "key", ""},
		{"%62/key", "b", "key", ""},
		{"b%2Fdir%2Fkey", "b", "dir/key", ""},
		{"b/%2Fleading", "b", "/leading", ""},
		{"b//leading", "b", "/leading", ""},
		{"b/dir//key", "b", "dir//key", ""},
		{"b/dir/../key", "b", "dir/../key", ""},
	} {
		t.Run(tc.source, func(t *testing.T) {
			bucket, key, version, err := ParseCopySource(tc.source)
			require.NoError(t, err)
			require.Equal(t, tc.bucket, bucket)
			require.Equal(t, tc.key, key)
			if tc.version == "" {
				require.Nil(t, version)
			} else {
				require.NotNil(t, version)
				require.Equal(t, tc.version, *version)
			}
		})
	}
}

func TestCopySource_ParseMalformed(t *testing.T) {
	for _, source := range []string{"", "bucket", "/key", "/", "b/", "b/?versionId=v", "b/key%", "b/key%2", "b/key%ZZ", "%ZZ/key", "b/key?versionId=%ZZ"} {
		t.Run(source, func(t *testing.T) {
			bucket, key, version, err := ParseCopySource(source)
			require.Error(t, err)
			require.Empty(t, bucket)
			require.Empty(t, key)
			require.Nil(t, version)
		})
	}
}

// Use the independent SDK signer: parsing must not mutate a signed header.
func signCopySourceRequest(t *testing.T, req *http.Request) {
	t.Helper()
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	require.NoError(t, v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: presignedTestSecret,
	}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC()))
}

type copySourceRecordingClient struct {
	*mockS3Client
	part []byte
}

func (c *copySourceRecordingClient) UploadPart(ctx context.Context, bucket, key, uploadID string, number int32, reader io.Reader, length *int64) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	c.part = data
	return `"part-etag"`, nil
}

func (c *copySourceRecordingClient) UploadPartCopy(ctx context.Context, bucket, key, uploadID string, number int32, srcBucket, srcKey string, version *string, byteRange *s3.CopyPartRange) (*s3.CopyPartResult, error) {
	result, err := c.mockS3Client.UploadPartCopy(ctx, bucket, key, uploadID, number, srcBucket, srcKey, version, byteRange)
	if err == nil {
		c.part = c.objects[bucket+"/"+key+"/"+uploadID+"/1"]
	}
	return result, err
}

func TestCopySource_HandlersPreserveExactObject(t *testing.T) {
	for _, mode := range []string{"plaintext", "buffered", "chunked"} {
		for _, partCopy := range []bool{false, true} {
			for _, tc := range []struct{ name, key, wire string }{
				{"control", "dir/plain.txt", "dir/plain.txt"},
				{"space", "dir/with space.txt", "dir/with%20space.txt"},
				{"unicode", "dir/umlaut-ä.txt", "dir/umlaut-%C3%A4.txt"},
				{"symbols", "dir/a+b&c.txt", "dir/a%2Bb%26c.txt"},
				{"literal-plus", "dir/a+b.txt", "dir/a+b.txt"},
				{"php-slashes", "dir/plain.txt", "dir%2Fplain.txt"},
				{"literal-percent", "dir/literal%2F.txt", "dir/literal%252F.txt"},
				{"query-in-key", "dir/name?versionId=literal", "dir/name%3FversionId%3Dliteral"},
				{"leading-slash", "/leading.txt", "%2Fleading.txt"},
				{"repeated-slash", "dir//name.txt", "dir%2F%2Fname.txt"},
			} {
				operation := "CopyObject"
				if partCopy {
					operation = "UploadPartCopy"
				}
				t.Run(mode+"/"+operation+"/"+tc.name, func(t *testing.T) {
					engine, err := newAPIUnitChunkedEngine([]byte("gh346-password"), "", nil, mode == "chunked", crypto.MinChunkSize)
					require.NoError(t, err)
					km, err := crypto.NewAESKEKManager(map[int][]byte{1: bytes.Repeat([]byte{0x46}, 32)}, 1)
					require.NoError(t, err)
					t.Cleanup(func() { _ = km.Close(context.Background()) })
					crypto.SetKeyManager(engine, km)
					client := &copySourceRecordingClient{mockS3Client: newMockS3Client()}
					plain := []byte("the intended source plaintext")
					seed := func(key string, data []byte) {
						if mode == "plaintext" {
							client.objects["test-bucket/"+key] = data
							client.metadata["test-bucket/"+key] = map[string]string{}
						} else {
							putSEC37Object(t, client.mockS3Client, engine, key, data)
						}
						// The selected source version must reach every backend read.
						client.metadata["test-bucket/"+key]["x-amz-version-id"] = "v+/="
					}
					seed(tc.key, plain)
					if tc.wire != tc.key {
						seed(tc.wire, []byte("wrong encoded-looking object"))
					}
					h := NewHandler(client, engine, logrus.New(), getTestMetrics())
					router := mux.NewRouter()
					h.RegisterRoutes(router)
					path := "http://localhost/test-bucket/destination"
					if partCopy {
						path += "?partNumber=1&uploadId=plain-upload"
					}
					req := httptest.NewRequest(http.MethodPut, path, nil)
					header := "/test-bucket/" + tc.wire + "?versionId=v+/="
					if tc.name == "space" {
						header = "/%74est-bucket/" + tc.wire + "?versionId=v%2B%2F%3D"
					}
					req.Header.Set("x-amz-copy-source", header)
					signCopySourceRequest(t, req)
					w := httptest.NewRecorder()
					AuthMiddleware(testCredentialStore(), 5*time.Minute, logrus.New(), nil, false)(AuthorizationMiddleware("test-bucket", nil)(router)).ServeHTTP(w, req)
					require.Equal(t, http.StatusOK, w.Code, w.Body.String())
					require.Equal(t, header, req.Header.Get("x-amz-copy-source"))
					require.NotEmpty(t, client.headVersionHistory)
					require.NotEmpty(t, client.getVersionHistory)
					for _, call := range client.headVersionHistory {
						if call.key == "test-bucket/destination" {
							require.Nil(t, call.versionID)
							continue
						}
						require.Equal(t, "test-bucket/"+tc.key, call.key)
						require.Equal(t, ptr("v+/="), call.versionID)
					}
					for _, call := range client.getVersionHistory {
						require.Equal(t, "test-bucket/"+tc.key, call.key)
						require.Equal(t, ptr("v+/="), call.versionID)
					}
					if partCopy {
						require.Equal(t, plain, client.part)
					} else {
						reader, _, err := engine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "destination"}, bytes.NewReader(client.objects["test-bucket/destination"]), client.metadata["test-bucket/destination"])
						require.NoError(t, err)
						got, err := io.ReadAll(reader)
						require.NoError(t, err)
						require.Equal(t, plain, got)
					}
				})
			}
		}
	}
}

type copySourceRejectClient struct {
	*failOnAnyCallS3Client
	heads int
}

func (c *copySourceRejectClient) HeadObject(context.Context, string, string, *string) (map[string]string, error) {
	c.heads++
	return nil, &smithy.GenericAPIError{Code: "NoSuchKey", Message: "unexpected backend access"}
}

func TestCopySource_RejectionBeforeBackend(t *testing.T) {
	for _, middleware := range []bool{false, true} {
		for _, path := range []string{"/test-bucket/destination", "/test-bucket/destination?partNumber=1&uploadId=plain-upload"} {
			for _, tc := range []struct {
				name, source string
				status       int
				code         string
				readOnly     bool
			}{
				{"truncated-escape", "test-bucket/key%2", 400, "InvalidArgument", false},
				{"bad-escape", "test-bucket/key%ZZ", 400, "InvalidArgument", false},
				{"bad-bucket-escape", "%ZZ/key", 400, "InvalidArgument", false},
				{"bad-version-escape", "test-bucket/key?versionId=%ZZ", 400, "InvalidArgument", false},
				{"empty-key", "test-bucket/?versionId=v", 400, "InvalidArgument", false},
				{"denied-decoded-bucket", "%6Futside/key%20name", 403, "AccessDenied", false},
				{"read-only-precedence", "test-bucket/key%ZZ", 403, "AccessDenied", true},
			} {
				t.Run(strings.Join([]string{path, tc.name, map[bool]string{true: "middleware", false: "handler"}[middleware]}, "/"), func(t *testing.T) {
					engine, err := newAPIUnitEngine([]byte("gh346-password"))
					require.NoError(t, err)
					client := &copySourceRejectClient{failOnAnyCallS3Client: &failOnAnyCallS3Client{t: t}}
					h := NewHandler(client, engine, logrus.New(), getTestMetrics())
					h.config = &config.Config{ProxiedBucket: "test-bucket"}
					router := mux.NewRouter()
					h.RegisterRoutes(router)
					credential := Credential{Policy: AuthorizationPolicy{Buckets: []string{"test-bucket"}, Permissions: config.ObjectPermissionReadWrite}}
					if tc.readOnly {
						credential.Policy.Permissions = config.ObjectPermissionReadOnly
					}
					req := authorizedRequest(http.MethodPut, path, credential)
					req.Header.Set("x-amz-copy-source", tc.source)
					w := httptest.NewRecorder()
					var handler http.Handler = router
					if middleware {
						handler = AuthorizationMiddleware("test-bucket", nil)(handler)
					}
					handler.ServeHTTP(w, req)
					require.Zero(t, client.heads, "rejected header accessed backend")
					require.Equal(t, tc.status, w.Code, w.Body.String())
					var response struct{ Code, Message, Resource string }
					require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &response))
					require.Equal(t, tc.code, response.Code)
					require.Equal(t, "/test-bucket/destination", response.Resource)
					if tc.status == 400 {
						require.Equal(t, "Invalid x-amz-copy-source header", response.Message)
					}
				})
			}
		}
	}
}

func TestCopySource_UnauthenticatedMalformedBeforeClientAcquisition(t *testing.T) {
	for _, path := range []string{"/test-bucket/destination", "/test-bucket/destination?partNumber=1&uploadId=plain-upload"} {
		t.Run(path, func(t *testing.T) {
			engine, err := newAPIUnitEngine([]byte("gh346-password"))
			require.NoError(t, err)
			h := NewHandler(&failOnAnyCallS3Client{t: t}, engine, logrus.New(), getTestMetrics())
			h.clientAcquirer = func(*http.Request) (s3.Client, error) {
				t.Fatal("malformed header acquired backend client")
				return nil, nil
			}
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			req := httptest.NewRequest(http.MethodPut, path, nil)
			req.Header.Set("x-amz-copy-source", "test-bucket/key%ZZ")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			require.Equal(t, http.StatusBadRequest, w.Code)
			var response struct{ Code, Message, Resource string }
			require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &response))
			require.Equal(t, "InvalidArgument", response.Code)
			require.Equal(t, "Invalid x-amz-copy-source header", response.Message)
			require.Equal(t, "/test-bucket/destination", response.Resource)
		})
	}
}

// A percent sequence is data only when its percent sign is itself encoded.
func FuzzCopySource_EncodedRoundTrip(f *testing.F) {
	for _, key := range []string{"dir/with space", "a+b", "literal%2F", "?versionId=x", "/leading", "ä"} {
		f.Add(key)
	}
	f.Fuzz(func(t *testing.T, key string) {
		if key == "" {
			t.Skip("empty S3 key")
		}
		bucket, got, version, err := ParseCopySource("b/" + url.PathEscape(key))
		require.NoError(t, err)
		require.Equal(t, "b", bucket)
		require.Equal(t, key, got)
		require.Nil(t, version)
	})
}
