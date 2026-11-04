package api

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type fallbackHeadStub struct {
	s3.Client
	head, get                    map[string]string
	data                         []byte
	version, interval, condition string
	closed                       bool
	err                          error
}

type fallbackTestStream struct {
	data          []byte
	cancel        context.CancelFunc
	failure       error
	reads, closes int
}

func (s *fallbackTestStream) Read(p []byte) (int, error) {
	s.reads++
	n := copy(p, s.data)
	s.data = s.data[n:]
	if s.cancel != nil {
		s.cancel()
	}
	return n, s.failure
}
func (s *fallbackTestStream) Close() error { s.closes++; return nil }

type fallbackStreamClient struct {
	*fallbackHeadStub
	body *fallbackTestStream
}

func (s *fallbackStreamClient) GetObjectIfMatch(context.Context, string, string, *string, *string, string, s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	return s.body, s.get, nil
}

type fallbackDeniedClient struct {
	*fallbackHeadStub
	body *fallbackTestStream
	err  error
}

func (s *fallbackDeniedClient) GetObjectIfMatch(context.Context, string, string, *string, *string, string, s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	return s.body, nil, s.err
}

func TestGH353FallbackHeadStreamCancellationAndProvenance(t *testing.T) {
	for _, tc := range []struct {
		name   string
		cancel bool
	}{{"cancel", true}, {"backend error", false}} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := fallbackFixture()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			failure := errors.New("private stream failure")
			stream := &fallbackTestStream{data: fixture.data, failure: failure}
			if tc.cancel {
				stream.cancel = cancel
				stream.failure = nil
			}
			client := &fallbackStreamClient{fallbackHeadStub: fixture, body: stream}
			view := &objectView{Bucket: "bucket", Key: "key", Raw: fixture.head, Expanded: fixture.head}
			meta, err := restoreFallbackHead(ctx, client, view)
			require.Nil(t, meta)
			if tc.cancel {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorIs(t, err, failure)
				var backend *objectBackendError
				require.ErrorAs(t, err, &backend)
				require.Equal(t, http.MethodGet, backend.method)
			}
			require.Equal(t, 1, stream.reads)
			require.Equal(t, 1, stream.closes)
		})
	}
}

func TestGH353FallbackHeadCancelledStreamHandler(t *testing.T) {
	fixture := fallbackFixture()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stream := &fallbackTestStream{data: fixture.data, cancel: cancel}
	client := &fallbackStreamClient{fallbackHeadStub: fixture, body: stream}
	e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.(io.Closer).Close() })
	reg := prometheus.NewRegistry()
	h := NewHandlerWithFeatures(client, e, logrus.New(), metrics.NewMetricsWithRegistry(reg), nil, nil, nil, &config.Config{}, nil)
	req := mux.SetURLVars(httptest.NewRequest(http.MethodHead, "/bucket/key", nil).WithContext(ctx), map[string]string{"bucket": "bucket", "key": "key"})
	w := httptest.NewRecorder()
	h.handleHeadObject(w, req)
	require.Equal(t, 500, w.Code)
	require.Empty(t, w.Header().Get("x-amz-meta-extra"))
	require.Empty(t, w.Header().Get("ETag"))
	require.Equal(t, 1, stream.reads)
	require.Equal(t, 1, stream.closes)
	require.Equal(t, float64(1), metricTotal(t, reg, "s3_operation_errors_total", `operation="HeadObject"`, `error_type="InternalError"`))
	require.Equal(t, float64(1), metricTotal(t, reg, "s3_operation_errors_total"))
}

func TestGH353FallbackHeadDeniedBodyClosure(t *testing.T) {
	fixture := fallbackFixture()
	body := &fallbackTestStream{}
	failure := errors.New("denied")
	client := &fallbackDeniedClient{fallbackHeadStub: fixture, body: body, err: failure}
	_, err := restoreFallbackHead(t.Context(), client, &objectView{Bucket: "bucket", Key: "key", Raw: fixture.head, Expanded: fixture.head})
	require.ErrorIs(t, err, failure)
	require.Equal(t, 1, body.closes)
	require.Zero(t, body.reads)
}

func TestGH353FallbackHeadSSECustomerWire(t *testing.T) {
	fixture := fallbackFixture()
	fields := sseCustomerFields()
	var gets int
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(sseCustomerKey) != fields[sseCustomerKey] {
			w.WriteHeader(http.StatusBadRequest)
			if r.Method == http.MethodGet {
				_, _ = io.WriteString(w, `<Error><Code>InvalidRequest</Code></Error>`)
			}
			return
		}
		for k, v := range fixture.head {
			if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
				w.Header().Set(k, v)
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("ETag", `"cipher"`)
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
		w.Header().Set("x-amz-server-side-encryption-customer-key-md5", fields[sseCustomerMD5])
		w.Header().Set("Content-Length", strconv.Itoa(len(fixture.data)))
		if r.Method == http.MethodHead {
			return
		}
		gets++
		require.Equal(t, `"cipher"`, r.Header.Get("If-Match"))
		require.Equal(t, fmt.Sprintf("bytes=0-%d", crypto.MaxFallbackPrefixBytes-1), r.Header.Get("Range"))
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(fixture.data)-1, len(fixture.data)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(fixture.data)
	}))
	t.Cleanup(backend.Close)
	cfg := config.BackendConfig{Endpoint: backend.URL, AccessKey: "backend", SecretKey: "secret", UsePathStyle: true, Retry: config.BackendRetryConfig{Mode: "off"}}
	client, err := s3.NewClientFactory(&cfg).GetClient()
	require.NoError(t, err)
	e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.(io.Closer).Close() })
	registry := prometheus.NewRegistry()
	h := NewHandlerWithFeatures(client, e, logrus.New(), metrics.NewMetricsWithRegistry(registry), nil, nil, nil, &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}, nil)
	h.backendEndpointScheme = "https"
	wrong := bytes.Repeat([]byte{0x25}, 32)
	sum := md5.Sum(wrong)
	bad := map[string]string{sseCustomerAlg: "AES256", sseCustomerKey: base64.StdEncoding.EncodeToString(wrong), sseCustomerMD5: base64.StdEncoding.EncodeToString(sum[:])}
	for _, tc := range []struct {
		name   string
		fields map[string]string
		ok     bool
	}{{"missing", nil, false}, {"wrong", bad, false}, {"correct", fields, true}} {
		t.Run(tc.name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodHead, "https://gateway.example/bucket/key", nil), map[string]string{"bucket": "bucket", "key": "key"})
			req.TLS = &tls.ConnectionState{}
			req.RemoteAddr = "127.0.0.1:1234"
			if tc.fields != nil {
				for k, v := range tc.fields {
					req.Header.Set(k, v)
				}
				req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
			}
			before := metricTotal(t, registry, "s3_operation_errors_total")
			beforeSuccess := metricTotal(t, registry, "s3_operations_total")
			w := httptest.NewRecorder()
			h.handleHeadObject(w, req)
			if tc.ok {
				require.Equal(t, 200, w.Code)
				require.Equal(t, beforeSuccess+1, metricTotal(t, registry, "s3_operations_total"))
				require.Equal(t, before, metricTotal(t, registry, "s3_operation_errors_total"))
				require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
				require.Equal(t, "restored", w.Header().Get("x-amz-meta-extra"))
			} else {
				require.NotEqual(t, 200, w.Code)
				require.Empty(t, w.Header().Get("x-amz-meta-extra"))
				require.Equal(t, before+1, metricTotal(t, registry, "s3_operation_errors_total"))
				require.Equal(t, beforeSuccess, metricTotal(t, registry, "s3_operations_total"))
			}
		})
	}
	require.Equal(t, 1, gets)
}

func TestGH353FallbackHeadSSEPrefixFailuresWire(t *testing.T) {
	for _, tc := range []struct {
		name, version, requested, code, metric string
		status, want                           int
	}{
		{"invalid key null", "null", "null", "InvalidRequest", "InvalidArgument", 400, 400},
		{"precondition null", "null", "null", "PreconditionFailed", "InternalError", 412, 500},
		{"requested version", "v1", "v1", "InvalidRequest", "InvalidArgument", 400, 400},
		{"returned version", "v1", "", "InvalidRequest", "InvalidArgument", 400, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := fallbackFixture()
			fields := sseCustomerFields()
			fail := true
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				require.Equal(t, fields[sseCustomerKey], r.Header.Get(sseCustomerKey))
				require.Equal(t, fields[sseCustomerMD5], r.Header.Get(sseCustomerMD5))
				require.Equal(t, "AES256", r.Header.Get(sseCustomerAlg))
				for k, v := range fixture.head {
					if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
						w.Header().Set(k, v)
					}
				}
				w.Header().Set("ETag", `"cipher"`)
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("x-amz-version-id", tc.version)
				w.Header().Set("x-amz-server-side-encryption-customer-algorithm", "AES256")
				w.Header().Set("x-amz-server-side-encryption-customer-key-md5", fields[sseCustomerMD5])
				if r.Method == http.MethodHead {
					w.Header().Set("Content-Length", strconv.Itoa(len(fixture.data)))
					return
				}
				require.Equal(t, tc.version, r.URL.Query().Get("versionId"))
				require.Equal(t, fmt.Sprintf("bytes=0-%d", crypto.MaxFallbackPrefixBytes-1), r.Header.Get("Range"))
				if tc.version == "null" {
					require.Equal(t, `"cipher"`, r.Header.Get("If-Match"))
				} else {
					require.Empty(t, r.Header.Get("If-Match"))
				}
				if fail {
					w.WriteHeader(tc.status)
					_, _ = fmt.Fprintf(w, "<Error><Code>%s</Code><Message>private-canary</Message></Error>", tc.code)
					return
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(fixture.data)-1, len(fixture.data)))
				w.Header().Set("Content-Length", strconv.Itoa(len(fixture.data)))
				w.WriteHeader(206)
				_, _ = w.Write(fixture.data)
			}))
			t.Cleanup(server.Close)
			cfg := config.BackendConfig{Endpoint: server.URL, AccessKey: "backend", SecretKey: "secret", UsePathStyle: true, Retry: config.BackendRetryConfig{Mode: "off"}}
			client, err := s3.NewClientFactory(&cfg).GetClient()
			require.NoError(t, err)
			e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
			require.NoError(t, err)
			t.Cleanup(func() { _ = e.(io.Closer).Close() })
			reg := prometheus.NewRegistry()
			h := NewHandlerWithFeatures(client, e, logrus.New(), metrics.NewMetricsWithRegistry(reg), nil, nil, nil, &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}, nil)
			h.backendEndpointScheme = "https"
			request := func() *http.Request {
				target := "https://gateway.example/bucket/key"
				if tc.requested != "" {
					target += "?versionId=" + tc.requested
				}
				r := mux.SetURLVars(httptest.NewRequest(http.MethodHead, target, nil), map[string]string{"bucket": "bucket", "key": "key"})
				r.TLS = &tls.ConnectionState{}
				r.RemoteAddr = "127.0.0.1:1234"
				for k, v := range fields {
					r.Header.Set(k, v)
				}
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
				return r
			}
			w := httptest.NewRecorder()
			h.handleHeadObject(w, request())
			require.Equal(t, tc.want, w.Code)
			require.Empty(t, w.Body.String())
			require.Empty(t, w.Header().Get("ETag"))
			require.Empty(t, w.Header().Get("x-amz-meta-extra"))
			require.Equal(t, float64(1), metricTotal(t, reg, "s3_operation_errors_total", `operation="HeadObject"`, `error_type="`+tc.metric+`"`))
			require.Equal(t, float64(1), metricTotal(t, reg, "s3_operation_errors_total"))
			fail = false
			w = httptest.NewRecorder()
			h.handleHeadObject(w, request())
			require.Equal(t, 200, w.Code)
			require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
			require.Equal(t, "restored", w.Header().Get("x-amz-meta-extra"))
			require.Equal(t, 4, calls)
		})
	}
}

func (s *fallbackHeadStub) HeadObject(context.Context, string, string, *string) (map[string]string, error) {
	return s.head, nil
}
func (s *fallbackHeadStub) GetObject(ctx context.Context, bucket, key string, version, interval *string) (io.ReadCloser, map[string]string, error) {
	if version != nil {
		s.version = *version
	}
	if interval != nil {
		s.interval = *interval
	}
	return &fallbackBody{Reader: bytes.NewReader(s.data), owner: s}, s.get, s.err
}
func (s *fallbackHeadStub) GetObjectIfMatch(ctx context.Context, bucket, key string, version, interval *string, match string, options s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	s.condition = match
	return s.GetObject(ctx, bucket, key, version, interval)
}

type fallbackBody struct {
	*bytes.Reader
	owner *fallbackHeadStub
}

func (b *fallbackBody) Close() error { b.owner.closed = true; return nil }

func fallbackFixture() *fallbackHeadStub {
	json := []byte(`{"x-amz-meta-extra":"restored"}`)
	data := make([]byte, 4, len(json)+4)
	binary.BigEndian.PutUint32(data, uint32(len(json)))
	data = append(data, json...)
	head := map[string]string{crypto.MetaEncrypted: "true", crypto.MetaFallbackMode: "true", crypto.MetaFallbackVersion: "2", crypto.MetaOriginalSize: "3", "ETag": `"cipher"`, "Content-Length": strconv.Itoa(len(data))}
	get := map[string]string{}
	for k, v := range head {
		get[k] = v
	}
	get["Content-Range"] = fmt.Sprintf("bytes 0-%d/%d", len(data)-1, len(data))
	return &fallbackHeadStub{Client: newMockS3Client(), head: head, get: get, data: data}
}

func TestGH353FallbackHeadSnapshot(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*fallbackHeadStub)
		ok     bool
	}{
		{"matching clipped range", func(*fallbackHeadStub) {}, true},
		{"ignored condition changed etag", func(s *fallbackHeadStub) { s.get["ETag"] = `"other"` }, false},
		{"same etag changed metadata", func(s *fallbackHeadStub) { s.get[crypto.MetaOriginalSize] = "4" }, false},
		{"ignored range", func(s *fallbackHeadStub) { delete(s.get, "Content-Range") }, false},
		{"truncated body", func(s *fallbackHeadStub) { s.data = s.data[:len(s.data)-1] }, false},
		{"oversized body", func(s *fallbackHeadStub) { s.data = append(s.data, 'x') }, false},
		{"missing etag", func(s *fallbackHeadStub) { delete(s.head, "ETag") }, false},
		{"immutable version", func(s *fallbackHeadStub) { s.head["x-amz-version-id"] = "v1"; s.get["x-amz-version-id"] = "v1" }, true},
		{"null version", func(s *fallbackHeadStub) { s.head["x-amz-version-id"] = "null"; s.get["x-amz-version-id"] = "null" }, true},
		{"changed version", func(s *fallbackHeadStub) { s.head["x-amz-version-id"] = "v1"; s.get["x-amz-version-id"] = "v2" }, false},
		{"malformed prefix", func(s *fallbackHeadStub) { s.data[4] = '!' }, false},
		{"missing response etag", func(s *fallbackHeadStub) { delete(s.get, "ETag") }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := fallbackFixture()
			tc.mutate(s)
			view := &objectView{Bucket: "bucket", Key: "key", Raw: s.head, Expanded: s.head}
			meta, err := restoreFallbackHead(t.Context(), s, view)
			if tc.ok {
				require.NoError(t, err)
				require.Equal(t, "restored", meta["x-amz-meta-extra"])
				require.Equal(t, fmt.Sprintf("bytes=0-%d", crypto.MaxFallbackPrefixBytes-1), s.interval)
				if s.head["x-amz-version-id"] != "v1" {
					require.Equal(t, `"cipher"`, s.condition)
				}
			} else {
				require.Error(t, err)
			}
			if s.interval != "" {
				require.True(t, s.closed)
			}
		})
	}
}

func TestGH353FallbackHeadUnsupportedAndRequestedVersion(t *testing.T) {
	s := fallbackFixture()
	view := &objectView{Bucket: "bucket", Key: "key", Raw: s.head, Expanded: s.head}
	_, err := restoreFallbackHead(t.Context(), s.Client, view)
	require.ErrorIs(t, err, s3.ErrNotImplemented)
	version := "v1"
	view.VersionID = &version
	s.get["x-amz-version-id"] = "v1"
	meta, err := restoreFallbackHead(t.Context(), s, view)
	require.NoError(t, err)
	require.Equal(t, "v1", s.version)
	require.Empty(t, s.condition)
	require.Equal(t, "restored", meta["x-amz-meta-extra"])
}

func TestGH353FallbackHeadHandler(t *testing.T) {
	s := fallbackFixture()
	e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.(io.Closer).Close() })
	h := NewHandlerWithFeatures(s, e, logrus.New(), getTestMetrics(), nil, nil, nil, &config.Config{}, nil)
	req := mux.SetURLVars(httptest.NewRequest(http.MethodHead, "/bucket/key", nil), map[string]string{"bucket": "bucket", "key": "key"})
	w := httptest.NewRecorder()
	h.handleHeadObject(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "restored", w.Header().Get("x-amz-meta-extra"))
	require.Equal(t, "3", w.Header().Get("Content-Length"))
	s.get["ETag"] = `"other"`
	w = httptest.NewRecorder()
	h.handleHeadObject(w, req)
	require.NotEqual(t, http.StatusOK, w.Code)
	require.Empty(t, w.Header().Get("x-amz-meta-extra"))
}

func TestGH353FallbackHeadProtectedBlobAuthority(t *testing.T) {
	e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithProvider("aws"), crypto.WithChunking(true), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.(io.Closer).Close() })
	key := bytes.Repeat([]byte{5}, 32)
	crypto.SetMetadataKey(e, key)
	t.Cleanup(func() { clear(key) })
	stream, header, err := e.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader([]byte("body")), map[string]string{"Content-Type": "application/safe", "x-amz-meta-extra": strings.Repeat("v", 7900)})
	require.NoError(t, err)
	data, err := io.ReadAll(stream)
	require.NoError(t, err)
	expanded, err := crypto.ExpandMetadataForAPI(header)
	require.NoError(t, err)
	require.Equal(t, "2", expanded[crypto.MetaFallbackVersion])
	n := int(binary.BigEndian.Uint32(data[:4]))
	var prefix map[string]string
	require.NoError(t, json.Unmarshal(data[4:4+n], &prefix))
	prefix[crypto.MetaContentType] = "application/attacker"
	prefix[crypto.MetaEncryptedMetadata] = "attacker"
	prefixData, err := json.Marshal(prefix)
	require.NoError(t, err)
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(len(prefixData)))
	data = append(append(frame, prefixData...), data[4+n:]...)
	delete(header, "x-amz-meta-extra")
	header["Content-Length"] = strconv.Itoa(len(data))
	header["ETag"] = `"cipher"`
	get := map[string]string{}
	for k, v := range header {
		get[k] = v
	}
	get["Content-Range"] = fmt.Sprintf("bytes 0-%d/%d", len(data)-1, len(data))
	s := &fallbackHeadStub{Client: newMockS3Client(), head: header, get: get, data: data}
	h := NewHandlerWithFeatures(s, e, logrus.New(), getTestMetrics(), nil, nil, nil, &config.Config{}, nil)
	req := mux.SetURLVars(httptest.NewRequest(http.MethodHead, "/bucket/key", nil), map[string]string{"bucket": "bucket", "key": "key"})
	w := httptest.NewRecorder()
	h.handleHeadObject(w, req)
	require.Equal(t, 200, w.Code)
	require.Equal(t, "application/safe", w.Header().Get("Content-Type"))
	require.Equal(t, strings.Repeat("v", 7900), w.Header().Get("x-amz-meta-extra"))
}

func TestGH353FallbackLegacyGETAndRange(t *testing.T) {
	e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithProvider("aws"), crypto.WithChunking(true), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.(io.Closer).Close() })
	plain := []byte("0123456789-fallback-legacy-payload")
	stream, header, err := e.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), map[string]string{"Content-Type": "application/safe", "x-amz-meta-extra": strings.Repeat("v", 9000), "Content-Length": strconv.Itoa(len(plain))})
	require.NoError(t, err)
	data, err := io.ReadAll(stream)
	require.NoError(t, err)
	exp, err := crypto.ExpandMetadataForAPI(header)
	require.NoError(t, err)
	require.Equal(t, "2", exp[crypto.MetaFallbackVersion])
	n := int(binary.BigEndian.Uint32(data[:4]))
	var prefix map[string]string
	require.NoError(t, json.Unmarshal(data[4:4+n], &prefix))
	require.NotEmpty(t, prefix[crypto.MetaKDFParams])
	prefix["X-Amz-Meta-A"] = "evil"
	prefix[crypto.MetaObjectFormatVersion] = "evil"
	prefix[crypto.MetaContentType] = "application/evil"
	prefix["x-amz-meta-extra"] = strings.Repeat("v", 9000)
	p, err := json.Marshal(prefix)
	require.NoError(t, err)
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(len(p)))
	data = append(append(frame, p...), data[4+n:]...)
	delete(header, crypto.MetaKDFParams)
	delete(header, "x-amz-meta-kdf")
	delete(header, "x-amz-meta-extra")
	header["Content-Length"] = strconv.Itoa(len(data))
	header["ETag"] = `"cipher"`
	client := newMockS3Client()
	client.objects["bucket/key"] = data
	client.metadata["bucket/key"] = header
	h := NewHandlerWithFeatures(client, e, logrus.New(), getTestMetrics(), nil, nil, nil, &config.Config{}, nil)
	for _, tc := range []struct {
		name, interval string
		want           []byte
		status         int
	}{{"full", "", plain, 200}, {"range", "bytes=2-7", plain[2:8], 206}} {
		t.Run(tc.name, func(t *testing.T) {
			r := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), map[string]string{"bucket": "bucket", "key": "key"})
			if tc.interval != "" {
				r.Header.Set("Range", tc.interval)
			}
			w := httptest.NewRecorder()
			h.handleGetObject(w, r)
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, tc.want, w.Body.Bytes())
			require.Equal(t, "application/safe", w.Header().Get("Content-Type"))
			require.Equal(t, strings.Repeat("v", 9000), w.Header().Get("x-amz-meta-extra"))
			if tc.interval != "" {
				require.Equal(t, fmt.Sprintf("bytes 2-7/%d", len(plain)), w.Header().Get("Content-Range"))
			}
		})
	}
}

func TestGH353FallbackHeadSDKWire(t *testing.T) {
	for _, tc := range []struct {
		name, requested, headVersion, gotETag string
		altered                               bool
		status                                int
	}{
		{"unversioned", "", "", `"cipher"`, false, 200},
		{"null", "null", "null", `"cipher"`, false, 200},
		{"requested immutable", "v1", "v1", `"cipher"`, false, 200},
		{"returned immutable", "", "v1", `"cipher"`, false, 200},
		{"ignored condition", "", "", `"other"`, false, 500},
		{"same etag changed metadata", "", "", `"cipher"`, true, 500},
		{"precondition", "", "", "412", false, 412},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := fallbackFixture()
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				for k, v := range fixture.head {
					if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
						w.Header().Set(k, v)
					}
				}
				w.Header().Set("ETag", `"cipher"`)
				w.Header().Set("Content-Type", "application/octet-stream")
				if tc.headVersion != "" {
					w.Header().Set("x-amz-version-id", tc.headVersion)
				}
				if r.Method == http.MethodHead {
					w.Header().Set("Content-Length", strconv.Itoa(len(fixture.data)))
					return
				}
				require.Equal(t, fmt.Sprintf("bytes=0-%d", crypto.MaxFallbackPrefixBytes-1), r.Header.Get("Range"))
				require.Equal(t, tc.headVersion, r.URL.Query().Get("versionId"))
				if tc.headVersion == "" || tc.headVersion == "null" {
					require.Equal(t, `"cipher"`, r.Header.Get("If-Match"))
				} else {
					require.Empty(t, r.Header.Get("If-Match"))
				}
				if tc.gotETag == "412" {
					w.WriteHeader(http.StatusPreconditionFailed)
					_, _ = io.WriteString(w, `<Error><Code>PreconditionFailed</Code></Error>`)
					return
				}
				w.Header().Set("ETag", tc.gotETag)
				if tc.altered {
					w.Header().Set(crypto.MetaOriginalSize, "4")
				}
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(fixture.data)-1, len(fixture.data)))
				w.Header().Set("Content-Length", strconv.Itoa(len(fixture.data)))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(fixture.data)
			}))
			t.Cleanup(server.Close)
			cfg := config.BackendConfig{Endpoint: server.URL, AccessKey: "backend", SecretKey: "secret", UsePathStyle: true, Retry: config.BackendRetryConfig{Mode: "off"}}
			client, err := s3.NewClientFactory(&cfg).GetClient()
			require.NoError(t, err)
			e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
			require.NoError(t, err)
			t.Cleanup(func() { _ = e.(io.Closer).Close() })
			h := NewHandlerWithFeatures(client, e, logrus.New(), getTestMetrics(), nil, nil, nil, &config.Config{Backend: cfg}, nil)
			url := "/bucket/key"
			if tc.requested != "" {
				url += "?versionId=" + tc.requested
			}
			req := mux.SetURLVars(httptest.NewRequest(http.MethodHead, url, nil), map[string]string{"bucket": "bucket", "key": "key"})
			w := httptest.NewRecorder()
			h.handleHeadObject(w, req)
			if tc.status == 412 {
				require.Equal(t, 500, w.Code) // existing translator does not map 412
			} else {
				require.Equal(t, tc.status, w.Code)
			}
			if tc.status == 200 {
				require.Equal(t, "restored", w.Header().Get("x-amz-meta-extra"))
			} else {
				require.Empty(t, w.Header().Get("x-amz-meta-extra"))
			}
			require.Equal(t, 2, calls)
		})
	}
}
