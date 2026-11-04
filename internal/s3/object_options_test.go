package s3

import (
	"bytes"
	"context"
	"crypto/md5" // S3 protocol interoperability, not authentication.
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func gh353WireClient(t *testing.T, handler http.HandlerFunc) (AdvancedObjectClient, *ClientFactory) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	f := NewClientFactory(&config.BackendConfig{Endpoint: server.URL, AccessKey: "backend", SecretKey: "backend-secret", SessionToken: "backend-token", UsePathStyle: true, Retry: config.BackendRetryConfig{Mode: "off"}})
	c, err := f.GetClient()
	require.NoError(t, err)
	advanced, ok := c.(AdvancedObjectClient)
	require.True(t, ok)
	return advanced, f
}

func gh353Customer() *SSECustomerKey {
	key := bytes.Repeat([]byte{0x4a}, 32)
	digest := md5.Sum(key)
	return &SSECustomerKey{Key: key, MD5: base64.StdEncoding.EncodeToString(digest[:])}
}

func gh353Put(t *testing.T, c AdvancedObjectClient, body io.Reader, meta map[string]string, options ObjectPutOptions) (PutObjectResult, error) {
	t.Helper()
	declared := int64(99999) // seekable remaining length must override this
	return c.PutObjectWithOptions(t.Context(), "bucket", "key", body, meta, &declared, "a=b", nil, "private", "", "", "", "", options)
}

func TestGH353AdvancedPut_SDKWireOptionsAndResult(t *testing.T) {
	for _, mode := range []string{"zero", "s3", "kms", "customer"} {
		t.Run(mode, func(t *testing.T) {
			customer := gh353Customer()
			defer customer.Close()
			flag := true
			options := ObjectPutOptions{}
			switch mode {
			case "s3":
				options = ObjectPutOptions{StorageClass: "STANDARD_IA", WebsiteRedirectLocation: "/next", SSE: &SSEOptions{Algorithm: "AES256"}}
			case "kms":
				options.SSE = &SSEOptions{Algorithm: "aws:kms", KMSKeyID: "backend-kms", KMSContext: "eyJhIjoiYiJ9", BucketKeyEnabled: &flag}
			case "customer":
				options.SSE = &SSEOptions{Customer: customer}
			}
			calls := 0
			c, _ := gh353WireClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				data, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.Equal(t, "ciphertext", string(data))
				assert.Equal(t, int64(10), r.ContentLength)
				digest := md5.Sum(data)
				assert.Equal(t, base64.StdEncoding.EncodeToString(digest[:]), r.Header.Get("Content-MD5"))
				assert.Equal(t, "text/plain", r.Header.Get("Content-Type"))
				assert.Equal(t, "max-age=10", r.Header.Get("Cache-Control"))
				assert.Equal(t, "attachment", r.Header.Get("Content-Disposition"))
				assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
				assert.Equal(t, "en", r.Header.Get("Content-Language"))
				assert.Equal(t, "Wed, 21 Oct 2015 07:28:00 GMT", r.Header.Get("Expires"))
				assert.Equal(t, "metadata", r.Header.Get("X-Amz-Meta-User"))
				assert.Equal(t, "a=b", r.Header.Get("X-Amz-Tagging"))
				assert.Equal(t, "private", r.Header.Get("X-Amz-Acl"))
				assert.Equal(t, options.StorageClass, r.Header.Get("X-Amz-Storage-Class"))
				assert.Equal(t, options.WebsiteRedirectLocation, r.Header.Get("X-Amz-Website-Redirect-Location"))
				if options.SSE != nil {
					assert.Equal(t, options.SSE.Algorithm, r.Header.Get("X-Amz-Server-Side-Encryption"))
					assert.Equal(t, options.SSE.KMSKeyID, r.Header.Get("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"))
					assert.Equal(t, options.SSE.KMSContext, r.Header.Get("X-Amz-Server-Side-Encryption-Context"))
					if mode == "kms" {
						assert.Equal(t, "true", r.Header.Get("X-Amz-Server-Side-Encryption-Bucket-Key-Enabled"))
					}
				}
				if mode == "customer" {
					assert.Equal(t, "AES256", r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Algorithm"))
					assert.Equal(t, base64.StdEncoding.EncodeToString(customer.Key), r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key"))
					assert.Equal(t, customer.MD5, r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key-Md5"))
				} else {
					assert.Empty(t, r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key"))
				}
				w.Header().Set("ETag", `"opaque"`)
				w.Header().Set("X-Amz-Version-Id", "version")
				w.Header().Set("X-Amz-Server-Side-Encryption", "aws:kms")
				w.Header().Set("X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "result-kms")
				w.Header().Set("X-Amz-Server-Side-Encryption-Bucket-Key-Enabled", "false")
				w.Header().Set("X-Amz-Server-Side-Encryption-Customer-Algorithm", "AES256")
				w.Header().Set("X-Amz-Server-Side-Encryption-Customer-Key-Md5", "result-md5")
				w.Header().Set("X-Amz-Expiration", "expiry")
				w.Header().Set("X-Amz-Storage-Class", "STANDARD_IA")
				w.Header().Set("X-Amz-Server-Side-Encryption-Customer-Key", "response-secret")
				w.Header().Set("X-Amz-Server-Side-Encryption-Context", "response-context")
				w.WriteHeader(200)
			})
			meta := map[string]string{"Content-Type": "text/plain", "Cache-Control": "max-age=10", "Content-Disposition": "attachment", "Content-Encoding": "gzip", "Content-Language": "en", "Expires": "Wed, 21 Oct 2015 07:28:00 GMT", "x-amz-meta-user": "metadata"}
			body := strings.NewReader("prefixciphertext")
			_, err := body.Seek(6, io.SeekStart)
			require.NoError(t, err)
			result, err := gh353Put(t, c, body, meta, options)
			require.NoError(t, err)
			assert.Equal(t, `"opaque"`, result.ETag)
			assert.Equal(t, "version", result.VersionID)
			assert.Equal(t, "result-kms", result.Headers["x-amz-server-side-encryption-aws-kms-key-id"])
			assert.Equal(t, "false", result.Headers["x-amz-server-side-encryption-bucket-key-enabled"])
			assert.Equal(t, "expiry", result.Headers["x-amz-expiration"])
			assert.NotContains(t, fmt.Sprint(result), "response-secret")
			assert.NotContains(t, fmt.Sprint(result), "response-context")
			assert.Len(t, result.Headers, 7)
			assert.Equal(t, "STANDARD_IA", result.Headers["x-amz-storage-class"])
			assert.Equal(t, "metadata", meta["x-amz-meta-user"])
			assert.Equal(t, 1, calls)
			if mode == "zero" {
				body = strings.NewReader("ciphertext")
				etag, err := c.PutObject(t.Context(), "bucket", "key", body, meta, nil, "a=b", nil, "private", "", "", "", "")
				require.NoError(t, err)
				assert.Equal(t, result.ETag, etag)
			}
		})
	}
}

func TestGH353AdvancedRead_CustomerKeyWire(t *testing.T) {
	customer := gh353Customer()
	defer customer.Close()
	calls := 0
	c, _ := gh353WireClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("versionId") == "selected" {
			assert.Equal(t, "AES256", r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Algorithm"))
			assert.Equal(t, base64.StdEncoding.EncodeToString(customer.Key), r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key"))
			assert.Equal(t, customer.MD5, r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key-Md5"))
			if r.Method == "GET" {
				assert.Equal(t, "bytes=1-3", r.Header.Get("Range"))
			}
		} else {
			assert.Empty(t, r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key"))
		}
		w.Header().Set("Content-Length", "3")
		w.Header().Set("Content-Type", "application/test")
		w.Header().Set("ETag", `"read"`)
		w.Header().Set("X-Amz-Meta-User", "value")
		w.Header().Set("X-Amz-Version-Id", "returned")
		w.Header().Set("X-Amz-Server-Side-Encryption-Customer-Algorithm", "AES256")
		w.Header().Set("X-Amz-Server-Side-Encryption-Customer-Key-Md5", customer.MD5)
		w.Header().Set("X-Amz-Storage-Class", "STANDARD_IA")
		w.Header().Set("X-Amz-Website-Redirect-Location", "/target")
		w.Header().Set("X-Amz-Server-Side-Encryption-Customer-Key", "response-secret")
		w.Header().Set("X-Amz-Server-Side-Encryption-Context", "response-context")
		if r.Method == "GET" {
			_, _ = w.Write([]byte("abc"))
		} else {
			w.WriteHeader(200)
		}
	})
	version, interval := "selected", "bytes=1-3"
	for _, advanced := range []bool{true, false} {
		var body io.ReadCloser
		var meta map[string]string
		var err error
		if advanced {
			body, meta, err = c.GetObjectWithOptions(t.Context(), "bucket", "key", &version, &interval, ObjectReadOptions{Customer: customer})
		} else {
			body, meta, err = c.GetObject(t.Context(), "bucket", "key", nil, nil)
		}
		require.NoError(t, err)
		data, err := io.ReadAll(body)
		require.NoError(t, err)
		require.NoError(t, body.Close())
		assert.Equal(t, "abc", string(data))
		assert.Equal(t, "AES256", meta["x-amz-server-side-encryption-customer-algorithm"])
		assert.Equal(t, "3", meta["Content-Length"])
		assert.Equal(t, "value", meta["x-amz-meta-user"])
		assert.Equal(t, "/target", meta["x-amz-website-redirect-location"])
		assert.NotContains(t, fmt.Sprint(meta), "response-secret")
		assert.NotContains(t, fmt.Sprint(meta), "response-context")
		if advanced {
			meta, err = c.HeadObjectWithOptions(t.Context(), "bucket", "key", &version, ObjectReadOptions{Customer: customer})
		} else {
			meta, err = c.HeadObject(t.Context(), "bucket", "key", nil)
		}
		require.NoError(t, err)
		assert.Equal(t, "returned", meta["x-amz-version-id"])
		assert.Equal(t, "STANDARD_IA", meta["x-amz-storage-class"])
	}
	assert.Equal(t, 4, calls)
	decorated, err := WithSSECustomerReadClient(c, "bucket", "key", customer)
	require.NoError(t, err)
	for _, key := range []string{"key", "companion"} {
		var selected *string
		if key == "key" {
			selected = &version
		}
		body, _, err := decorated.GetObject(t.Context(), "bucket", key, selected, &interval)
		require.NoError(t, err)
		require.NoError(t, body.Close())
		_, err = decorated.HeadObject(t.Context(), "bucket", key, selected)
		require.NoError(t, err)
	}
	assert.Equal(t, 8, calls)
	_, _, err = c.GetObjectWithOptions(nil, "bucket", "key", nil, nil, ObjectReadOptions{})
	require.Error(t, err)
	_, err = c.HeadObjectWithOptions(nil, "bucket", "key", nil, ObjectReadOptions{})
	require.Error(t, err)
	_, _, err = c.GetObjectWithOptions(t.Context(), "bucket", "key", nil, nil, ObjectReadOptions{Customer: &SSECustomerKey{}})
	require.Error(t, err)
	_, err = c.HeadObjectWithOptions(t.Context(), "bucket", "key", nil, ObjectReadOptions{Customer: &SSECustomerKey{}})
	require.Error(t, err)
	_, err = gh353Put(t, c, (*bytes.Reader)(nil), nil, ObjectPutOptions{})
	require.Error(t, err)
	_, err = c.PutObjectWithOptions(nil, "bucket", "key", strings.NewReader("data"), nil, nil, "", nil, "", "", "", "", "", ObjectPutOptions{})
	require.Error(t, err)
	bad := gh353Customer()
	bad.MD5 = "bad-checksum"
	_, err = gh353Put(t, c, strings.NewReader("data"), nil, ObjectPutOptions{SSE: &SSEOptions{Customer: bad}})
	require.Error(t, err)
	bad.Close()
}

func TestGH353AdvancedRead_UnkeyedSDKErrorCodeProvenance(t *testing.T) {
	const secret = "backend-secret-message-canary"
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			c, _ := gh353WireClient(t, func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, method, r.Method)
				require.Empty(t, r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key"))
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusBadRequest)
				if method != http.MethodHead {
					_, _ = io.WriteString(w, `<Error><Code>InvalidRequest</Code><Message>`+secret+`</Message></Error>`)
				}
			})
			var err error
			if method == http.MethodGet {
				_, _, err = c.GetObjectWithOptions(t.Context(), "bucket", "key", nil, nil, ObjectReadOptions{})
			} else {
				_, err = c.HeadObjectWithOptions(t.Context(), "bucket", "key", nil, ObjectReadOptions{})
			}
			require.Error(t, err)
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) {
				t.Fatal("wire error lost its finite SDK API code")
			}
			wantCode := "InvalidRequest"
			if method == http.MethodHead {
				wantCode = "BadRequest"
			}
			if apiErr.ErrorCode() != wantCode {
				t.Fatal("wire error mapped to an unexpected finite SDK API code")
			}
		})
	}
}

func TestGH353BackendSessionToken_IsIndependent(t *testing.T) {
	var tokens, identities []string
	_, f := gh353WireClient(t, func(w http.ResponseWriter, r *http.Request) {
		tokens = append(tokens, r.Header.Get("X-Amz-Security-Token"))
		identities = append(identities, r.Header.Get("Authorization"))
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(200)
	})
	for i := 0; i < 3; i++ {
		var c Client
		var err error
		switch i {
		case 0:
			c, err = f.GetClient()
		case 1:
			c, err = f.GetClientWithCredentials("compat", "compat-secret")
		case 2:
			c, err = f.GetClientWithSessionCredentials("explicit", "explicit-secret", "explicit-token")
		}
		require.NoError(t, err)
		_, err = c.HeadObject(t.Context(), "bucket", "key", nil)
		require.NoError(t, err)
	}
	assert.Equal(t, []string{"backend-token", "", "explicit-token"}, tokens)
	for i, key := range []string{"backend", "compat", "explicit"} {
		assert.Contains(t, identities[i], "Credential="+key+"/")
		assert.NotContains(t, identities[i], "gateway")
	}
	_, err := f.GetClientWithSessionCredentials("", "secret", "token")
	require.Error(t, err)
	_, err = f.GetClientWithSessionCredentials("key", "", "token")
	require.Error(t, err)
}

type gh353CountingBody struct{ reads int }

func (r *gh353CountingBody) Read([]byte) (int, error) { r.reads++; return 0, io.EOF }

// Embedding legacy Client keeps tests source-compatible without extending every
// existing mock. These explicit methods are the only operations under test.
type gh353AdvancedStub struct {
	Client
	metadata          map[string]string
	customer          *SSECustomerKey
	calls             []string
	err               error
	version, interval *string
}

func (s *gh353AdvancedStub) PutObjectWithOptions(ctx context.Context, bucket, key string, body io.Reader, meta map[string]string, length *int64, tags string, lock *ObjectLockInput, acl, gf, gr, gra, gwa string, options ObjectPutOptions) (PutObjectResult, error) {
	s.metadata = meta
	s.calls = append(s.calls, "put")
	return PutObjectResult{ETag: "etag"}, s.err
}
func (s *gh353AdvancedStub) GetObjectWithOptions(ctx context.Context, bucket, key string, version, interval *string, options ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	s.version, s.interval = version, interval
	s.customer = options.Customer
	s.calls = append(s.calls, "advanced-get:"+bucket+"/"+key)
	return io.NopCloser(strings.NewReader("data")), map[string]string{"content-type": "test"}, s.err
}
func (s *gh353AdvancedStub) HeadObjectWithOptions(ctx context.Context, bucket, key string, version *string, options ObjectReadOptions) (map[string]string, error) {
	s.version = version
	s.customer = options.Customer
	s.calls = append(s.calls, "advanced-head:"+bucket+"/"+key)
	return map[string]string{"content-type": "test"}, s.err
}
func (s *gh353AdvancedStub) GetObject(ctx context.Context, bucket, key string, version, interval *string) (io.ReadCloser, map[string]string, error) {
	s.customer = nil
	s.calls = append(s.calls, "legacy-get:"+bucket+"/"+key)
	return io.NopCloser(strings.NewReader("data")), nil, nil
}
func (s *gh353AdvancedStub) HeadObject(ctx context.Context, bucket, key string, version *string) (map[string]string, error) {
	s.customer = nil
	s.calls = append(s.calls, "legacy-head:"+bucket+"/"+key)
	return nil, nil
}

func TestGH353AdvancedAdapters_FailBeforeBodyRead(t *testing.T) {
	t.Run("proxy", func(t *testing.T) {
		c := &ProxyClient{}
		body := &gh353CountingBody{}
		_, err := c.PutObjectWithOptions(t.Context(), "bucket", "key", body, nil, nil, "", nil, "", "", "", "", "", ObjectPutOptions{})
		assert.ErrorIs(t, err, ErrNotImplemented)
		assert.Zero(t, body.reads)
		_, _, err = c.GetObjectWithOptions(t.Context(), "bucket", "key", nil, nil, ObjectReadOptions{})
		assert.ErrorIs(t, err, ErrNotImplemented)
		_, err = c.HeadObjectWithOptions(t.Context(), "bucket", "key", nil, ObjectReadOptions{})
		assert.ErrorIs(t, err, ErrNotImplemented)
	})
	for _, name := range []string{"gcs", "azure"} {
		t.Run(name, func(t *testing.T) {
			inner := &gh353AdvancedStub{}
			var c AdvancedObjectClient
			switch name {
			case "gcs":
				c = &gcsClient{inner: inner}
			case "azure":
				c = &azureClient{inner: inner}
			}
			for _, options := range []ObjectPutOptions{{SSE: &SSEOptions{Algorithm: "AES256"}}, {StorageClass: "GLACIER"}, {WebsiteRedirectLocation: "/target"}} {
				body := &gh353CountingBody{}
				_, err := gh353Put(t, c, body, nil, options)
				assert.ErrorIs(t, err, ErrNotImplemented)
				assert.Zero(t, body.reads)
			}
			_, _, err := c.GetObjectWithOptions(t.Context(), "bucket", "key", nil, nil, ObjectReadOptions{Customer: gh353Customer()})
			assert.ErrorIs(t, err, ErrNotImplemented)
			_, err = c.HeadObjectWithOptions(t.Context(), "bucket", "key", nil, ObjectReadOptions{Customer: gh353Customer()})
			assert.ErrorIs(t, err, ErrNotImplemented)
			for _, storage := range []string{"", "STANDARD"} {
				meta := map[string]string{"User_KEY": "value"}
				if name == "gcs" {
					meta = map[string]string{"X-Amz-Meta-User": "value", "Content-Type": "text/plain"}
				}
				_, err := gh353Put(t, c, &gh353CountingBody{}, meta, ObjectPutOptions{StorageClass: storage})
				require.NoError(t, err)
				if name == "gcs" {
					assert.Equal(t, "value", inner.metadata["x-amz-meta-user"])
					assert.Equal(t, "text/plain", inner.metadata["Content-Type"])
				} else {
					assert.Equal(t, meta, inner.metadata)
				}
			}
			body, meta, err := c.GetObjectWithOptions(t.Context(), "bucket", "key", nil, nil, ObjectReadOptions{})
			require.NoError(t, err)
			require.NoError(t, body.Close())
			assert.Equal(t, "test", meta["Content-Type"])
			meta, err = c.HeadObjectWithOptions(t.Context(), "bucket", "key", nil, ObjectReadOptions{})
			require.NoError(t, err)
			assert.Equal(t, "test", meta["Content-Type"])
			_, err = gh353Put(t, c, (*bytes.Reader)(nil), nil, ObjectPutOptions{})
			require.Error(t, err)
			_, _, err = c.GetObjectWithOptions(nil, "bucket", "key", nil, nil, ObjectReadOptions{})
			require.Error(t, err)
			_, err = c.HeadObjectWithOptions(nil, "bucket", "key", nil, ObjectReadOptions{})
			require.Error(t, err)
			inner.err = fmt.Errorf("BlobNotFound")
			body, _, err = c.GetObjectWithOptions(t.Context(), "bucket", "key", nil, nil, ObjectReadOptions{})
			require.Error(t, err)
			require.NoError(t, body.Close())
			_, err = c.HeadObjectWithOptions(t.Context(), "bucket", "key", nil, ObjectReadOptions{})
			require.Error(t, err)
			if name == "azure" {
				assert.Contains(t, err.Error(), "NoSuchKey")
				body := &gh353CountingBody{}
				_, err = gh353Put(t, c, body, map[string]string{"bad-key": "value"}, ObjectPutOptions{})
				require.Error(t, err)
				assert.Zero(t, body.reads)
			}
			var unsupported AdvancedObjectClient
			if name == "gcs" {
				unsupported = &gcsClient{inner: &struct{ Client }{}}
			} else {
				unsupported = &azureClient{inner: (*gh353AdvancedStub)(nil)}
			}
			_, err = gh353Put(t, unsupported, &gh353CountingBody{}, nil, ObjectPutOptions{})
			assert.ErrorIs(t, err, ErrNotImplemented)
			_, _, err = unsupported.GetObjectWithOptions(t.Context(), "bucket", "key", nil, nil, ObjectReadOptions{})
			assert.ErrorIs(t, err, ErrNotImplemented)
			_, err = unsupported.HeadObjectWithOptions(t.Context(), "bucket", "key", nil, ObjectReadOptions{})
			assert.ErrorIs(t, err, ErrNotImplemented)
		})
	}
}

func TestGH353CustomerReadClient_TargetIsolationAndClose(t *testing.T) {
	customer := gh353Customer()
	backing := customer.Key
	stub := &gh353AdvancedStub{}
	c, err := WithSSECustomerReadClient(stub, "bucket", "key", customer)
	require.NoError(t, err)
	version, interval := "version", "bytes=1-3"
	for _, target := range []struct {
		bucket, key string
		primary     bool
	}{{"bucket", "key", true}, {"bucket", "companion", false}, {"other", "key", false}} {
		body, _, err := c.GetObject(t.Context(), target.bucket, target.key, &version, &interval)
		require.NoError(t, err)
		require.NoError(t, body.Close())
		if target.primary {
			assert.Same(t, customer, stub.customer)
			assert.Same(t, &version, stub.version)
			assert.Same(t, &interval, stub.interval)
		} else {
			assert.Nil(t, stub.customer)
		}
		_, err = c.HeadObject(t.Context(), target.bucket, target.key, &version)
		require.NoError(t, err)
		if target.primary {
			assert.Same(t, customer, stub.customer)
			assert.Same(t, &version, stub.version)
		} else {
			assert.Nil(t, stub.customer)
		}
	}
	assert.Equal(t, []string{"advanced-get:bucket/key", "advanced-head:bucket/key", "legacy-get:bucket/companion", "legacy-head:bucket/companion", "legacy-get:other/key", "legacy-head:other/key"}, stub.calls)
	customer.Close()
	customer.Close()
	(*SSECustomerKey)(nil).Close()
	assert.Equal(t, make([]byte, 32), backing)
	assert.Nil(t, customer.Key)
	assert.Empty(t, customer.MD5)
	badChecksum := gh353Customer()
	badChecksum.MD5 = base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err = WithSSECustomerReadClient(stub, "bucket", "key", badChecksum)
	require.Error(t, err)
	badChecksum.Close()
	for _, client := range []Client{nil, (*gh353AdvancedStub)(nil), &struct{ Client }{}} {
		_, err := WithSSECustomerReadClient(client, "bucket", "key", gh353Customer())
		require.Error(t, err)
	}
	_, err = WithSSECustomerReadClient(stub, "bucket", "key", nil)
	require.Error(t, err)
	_, err = WithSSECustomerReadClient(stub, "bucket", "key", &SSECustomerKey{})
	require.Error(t, err)
	_, _, err = c.GetObject(nil, "bucket", "key", nil, nil)
	require.Error(t, err)
	_, err = c.HeadObject(nil, "bucket", "key", nil)
	require.Error(t, err)
	assert.True(t, nilObjectInput((*bytes.Reader)(nil)))
	assert.False(t, nilObjectInput(context.Background()))
	assert.False(t, nilObjectInput(1))
}
