package s3

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"testing"

	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/require"
)

func TestGH353ConditionalRead_SDKWireAndAdapters(t *testing.T) {
	const etag = `"ciphertext-opaque-42"`
	customer := gh353Customer()
	t.Cleanup(customer.Close)
	var calls int
	c, _ := gh353WireClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		require.Equal(t, http.MethodGet, r.Method)
		if r.URL.Path == "/bucket/default" {
			require.Empty(t, r.Header.Get("If-Match"))
			require.Empty(t, r.Header.Get("Range"))
			require.Empty(t, r.URL.Query().Get("versionId"))
			require.Empty(t, r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key"))
			_, _ = io.WriteString(w, "ordinary")
			return
		}
		require.Equal(t, etag, r.Header.Get("If-Match"))
		require.Equal(t, "bytes=0-3", r.Header.Get("Range"))
		wantVersion := "version-42"
		if r.URL.Path == "/bucket/null-version" {
			wantVersion = "null"
		}
		require.Equal(t, wantVersion, r.URL.Query().Get("versionId"))
		if r.URL.Path == "/bucket/key" || r.URL.Path == "/bucket/key-fail" {
			require.Equal(t, "AES256", r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Algorithm"))
			require.Equal(t, base64.StdEncoding.EncodeToString(customer.Key), r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key"))
			require.Equal(t, customer.MD5, r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key-Md5"))
		} else {
			require.Empty(t, r.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key"))
		}
		if r.URL.Path == "/bucket/precondition" || r.URL.Path == "/bucket/key-fail" {
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = io.WriteString(w, `<Error><Code>PreconditionFailed</Code></Error>`)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Amz-Version-Id", wantVersion)
		w.Header().Set("Content-Range", "bytes 0-3/100")
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, "abcd")
	})
	version, interval := "version-42", "bytes=0-3"
	decorated, err := WithSSECustomerReadClient(c, "bucket", "key", customer)
	require.NoError(t, err)
	for _, tc := range []struct {
		name    string
		client  ConditionalObjectReader
		key     string
		options ObjectReadOptions
	}{
		{"sdk", c.(ConditionalObjectReader), "raw", ObjectReadOptions{}},
		{"sdk-sse-c", c.(ConditionalObjectReader), "key", ObjectReadOptions{Customer: customer}},
		{"gcs", &gcsClient{inner: c}, "raw", ObjectReadOptions{}},
		{"azure", &azureClient{inner: c}, "raw", ObjectReadOptions{}},
		{"sse-c", decorated.(ConditionalObjectReader), "key", ObjectReadOptions{}},
		{"companion", decorated.(ConditionalObjectReader), "companion", ObjectReadOptions{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, meta, err := tc.client.GetObjectIfMatch(t.Context(), "bucket", tc.key, &version, &interval, etag, tc.options)
			require.NoError(t, err)
			data, err := io.ReadAll(body)
			require.NoError(t, err)
			require.NoError(t, body.Close())
			require.Equal(t, "abcd", string(data))
			require.Equal(t, etag, meta["ETag"])
			require.Equal(t, "version-42", meta["x-amz-version-id"])
			require.Equal(t, "bytes 0-3/100", meta["Content-Range"])
		})
	}
	body, _, err := c.GetObject(t.Context(), "bucket", "default", nil, nil)
	require.NoError(t, err)
	data, err := io.ReadAll(body)
	require.NoError(t, err)
	require.NoError(t, body.Close())
	require.Equal(t, "ordinary", string(data))
	for _, client := range []ConditionalObjectReader{c.(ConditionalObjectReader), &gcsClient{inner: c}, &azureClient{inner: c}, decorated.(ConditionalObjectReader)} {
		_, _, err := client.GetObjectIfMatch(t.Context(), "bucket", "precondition", &version, &interval, etag, ObjectReadOptions{})
		require.Error(t, err)
		var responseErr *smithyhttp.ResponseError
		require.True(t, errors.As(err, &responseErr))
		require.Equal(t, http.StatusPreconditionFailed, responseErr.HTTPStatusCode())
	}
	keyedFailure, err := WithSSECustomerReadClient(c, "bucket", "key-fail", customer)
	require.NoError(t, err)
	_, _, err = keyedFailure.(ConditionalObjectReader).GetObjectIfMatch(t.Context(), "bucket", "key-fail", &version, &interval, etag, ObjectReadOptions{})
	var responseErr *smithyhttp.ResponseError
	require.Error(t, err)
	require.True(t, errors.As(err, &responseErr))
	require.Equal(t, http.StatusPreconditionFailed, responseErr.HTTPStatusCode())
	null := "null"
	body, meta, err := c.(ConditionalObjectReader).GetObjectIfMatch(t.Context(), "bucket", "null-version", &null, &interval, etag, ObjectReadOptions{})
	require.NoError(t, err)
	require.NoError(t, body.Close())
	require.Equal(t, "null", meta["x-amz-version-id"])
	_, _, err = c.(ConditionalObjectReader).GetObjectIfMatch(t.Context(), "bucket", "raw", &version, &interval, "", ObjectReadOptions{})
	require.Error(t, err)
	require.Equal(t, 13, calls)
}

func TestGH353ConditionalRead_UnsupportedFailsClosed(t *testing.T) {
	customer := gh353Customer()
	t.Cleanup(customer.Close)
	advancedOnly := &gh353AdvancedStub{}
	decorated, err := WithSSECustomerReadClient(advancedOnly, "bucket", "key", customer)
	require.NoError(t, err)
	clients := []ConditionalObjectReader{&ProxyClient{}, &gcsClient{inner: advancedOnly}, &azureClient{inner: advancedOnly}, decorated.(ConditionalObjectReader)}
	for _, client := range clients {
		body, _, err := client.GetObjectIfMatch(t.Context(), "bucket", "key", nil, nil, `"etag"`, ObjectReadOptions{})
		require.ErrorIs(t, err, ErrNotImplemented)
		require.Nil(t, body)
	}
	require.Empty(t, advancedOnly.calls)
	_, _, err = decorated.(ConditionalObjectReader).GetObjectIfMatch(t.Context(), "bucket", "key", nil, nil, "", ObjectReadOptions{})
	require.Error(t, err)
	_, _, err = decorated.(ConditionalObjectReader).GetObjectIfMatch(t.Context(), "bucket", "companion", nil, nil, `"etag"`, ObjectReadOptions{Customer: customer})
	require.Error(t, err)
	require.Empty(t, advancedOnly.calls)
	for _, client := range []ConditionalObjectReader{&gcsClient{inner: advancedOnly}, &azureClient{inner: advancedOnly}} {
		_, _, err = client.GetObjectIfMatch(t.Context(), "bucket", "key", nil, nil, `"etag"`, ObjectReadOptions{Customer: customer})
		require.ErrorIs(t, err, ErrNotImplemented)
	}
	require.Empty(t, advancedOnly.calls)
}
