package api

import (
	"bytes"
	"context"
	"crypto/md5" // S3 SSE-C protocol checksum, not authentication.
	"crypto/tls"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func sseCustomerFields() map[string]string {
	key := bytes.Repeat([]byte{0x6b}, 32)
	sum := md5.Sum(key)
	return map[string]string{sseCustomerAlg: "AES256", sseCustomerKey: base64.StdEncoding.EncodeToString(key), sseCustomerMD5: base64.StdEncoding.EncodeToString(sum[:])}
}

func noncanonicalBase64(canonical string) string {
	for i := len(canonical) - 1; i >= 0; i-- {
		if canonical[i] == '=' {
			continue
		}
		alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		index := strings.IndexByte(alphabet, canonical[i])
		if index >= 0 && index%16 != 0 {
			return canonical[:i] + string(alphabet[index&^15]) + canonical[i+1:]
		}
	}
	return canonical
}

func TestGH353SSE_ValidationAndTransport(t *testing.T) {
	validContext := base64.StdEncoding.EncodeToString([]byte(`{"purpose":"archive","team":"storage"}`))
	emptyStringContext := base64.StdEncoding.EncodeToString([]byte(`{"empty":""}`))
	dupContext := base64.StdEncoding.EncodeToString([]byte(`{"a":"1","a":"2"}`))
	invalidSurrogateContext := base64.StdEncoding.EncodeToString([]byte(`{"a":"\ud800"}`))
	validUnicodeContext := base64.StdEncoding.EncodeToString([]byte(`{"city":"Zürich","symbol":"\ud83d\ude80"}`))
	tests := []struct {
		name    string
		fields  map[string]string
		wantErr error
		want    *s3.SSEOptions
	}{
		{"absent", map[string]string{}, nil, nil},
		{"empty algorithm rejected", map[string]string{sseAlgorithmHeader: ""}, ErrPostInvalidOption, nil},
		{"sse s3", map[string]string{sseAlgorithmHeader: "AES256"}, nil, &s3.SSEOptions{Algorithm: "AES256"}},
		{"kms context", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: validContext}, nil, &s3.SSEOptions{Algorithm: "aws:kms", KMSContext: validContext}},
		{"kms unicode and surrogate pair context", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: validUnicodeContext}, nil, &s3.SSEOptions{Algorithm: "aws:kms", KMSContext: validUnicodeContext}},
		{"kms empty string context value", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: emptyStringContext}, nil, &s3.SSEOptions{Algorithm: "aws:kms", KMSContext: emptyStringContext}},
		{"duplicate context", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: dupContext}, ErrPostInvalidOption, nil},
		{"null context value", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte(`{"a":null}`))}, ErrPostInvalidOption, nil},
		{"object context value", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte(`{"a":{}}`))}, ErrPostInvalidOption, nil},
		{"array context value", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte(`{"a":[]}`))}, ErrPostInvalidOption, nil},
		{"number context value", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte(`{"a":1}`))}, ErrPostInvalidOption, nil},
		{"boolean context value", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte(`{"a":true}`))}, ErrPostInvalidOption, nil},
		{"trailing context JSON", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte(`{"a":"b"} {}`))}, ErrPostInvalidOption, nil},
		{"malformed surrogate context", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: invalidSurrogateContext}, ErrPostInvalidOption, nil},
		{"invalid UTF-8 context", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte{'{', '"', 'a', '"', ':', '"', 0xff, '"', '}'})}, ErrPostInvalidOption, nil},
		{"invalid context base64", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: "%%%"}, ErrPostInvalidOption, nil},
		{"context base64 line break", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: validContext + "\n"}, ErrPostInvalidOption, nil},
		{"context base64 noncanonical trailing bits", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: noncanonicalBase64(base64.StdEncoding.EncodeToString([]byte(`{"a":"abc"}`)))}, ErrPostInvalidOption, nil},
		{"root null context", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte(`null`))}, ErrPostInvalidOption, nil},
		{"root array context", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: base64.StdEncoding.EncodeToString([]byte(`[]`))}, ErrPostInvalidOption, nil},
		{"mixed mode", map[string]string{sseAlgorithmHeader: "AES256", sseKMSKeyHeader: "id"}, ErrPostInvalidOption, nil},
		{"SSE-S3 with KMS context", map[string]string{sseAlgorithmHeader: "AES256", sseKMSContextHeader: validContext}, ErrPostInvalidOption, nil},
		{"SSE-S3 with bucket key", map[string]string{sseAlgorithmHeader: "AES256", sseBucketKeyHeader: "true"}, ErrPostInvalidOption, nil},
		{"empty kms key", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSKeyHeader: ""}, ErrPostInvalidOption, nil},
		{"empty context", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSContextHeader: ""}, ErrPostInvalidOption, nil},
		{"bucket key true", map[string]string{sseAlgorithmHeader: "aws:kms", sseBucketKeyHeader: "true"}, nil, &s3.SSEOptions{Algorithm: "aws:kms", BucketKeyEnabled: aws.Bool(true)}},
		{"bucket key false", map[string]string{sseAlgorithmHeader: "aws:kms", sseBucketKeyHeader: "false"}, nil, &s3.SSEOptions{Algorithm: "aws:kms", BucketKeyEnabled: aws.Bool(false)}},
		{"invalid bucket key", map[string]string{sseAlgorithmHeader: "aws:kms", sseBucketKeyHeader: "yes"}, ErrPostInvalidOption, nil},
		{"dsse unsupported", map[string]string{sseAlgorithmHeader: "aws:kms:dsse"}, ErrPostUnsupported, nil},
		{"unknown mode", map[string]string{sseAlgorithmHeader: "unknown"}, ErrPostUnsupported, nil},
		{"customer triplet", sseCustomerFields(), nil, nil},
		{"missing customer member", map[string]string{sseCustomerAlg: "AES256"}, ErrPostInvalidOption, nil},
		{"customer with explicit empty SSE algorithm", func() map[string]string {
			fields := sseCustomerFields()
			fields[sseAlgorithmHeader] = ""
			return fields
		}(), ErrPostInvalidOption, nil},
		{"customer with KMS key", func() map[string]string { f := sseCustomerFields(); f[sseKMSKeyHeader] = "id"; return f }(), ErrPostInvalidOption, nil},
		{"customer with KMS context", func() map[string]string { f := sseCustomerFields(); f[sseKMSContextHeader] = validContext; return f }(), ErrPostInvalidOption, nil},
		{"customer with bucket key", func() map[string]string { f := sseCustomerFields(); f[sseBucketKeyHeader] = "false"; return f }(), ErrPostInvalidOption, nil},
		{"incomplete customer missing algorithm", map[string]string{sseCustomerKey: sseCustomerFields()[sseCustomerKey], sseCustomerMD5: sseCustomerFields()[sseCustomerMD5]}, ErrPostInvalidOption, nil},
		{"incomplete customer missing key", map[string]string{sseCustomerAlg: "AES256", sseCustomerMD5: sseCustomerFields()[sseCustomerMD5]}, ErrPostInvalidOption, nil},
		{"incomplete customer missing MD5", map[string]string{sseCustomerAlg: "AES256", sseCustomerKey: sseCustomerFields()[sseCustomerKey]}, ErrPostInvalidOption, nil},
		{"empty customer algorithm", map[string]string{sseCustomerAlg: "", sseCustomerKey: sseCustomerFields()[sseCustomerKey], sseCustomerMD5: sseCustomerFields()[sseCustomerMD5]}, ErrPostInvalidOption, nil},
		{"empty customer MD5", map[string]string{sseCustomerAlg: "AES256", sseCustomerKey: sseCustomerFields()[sseCustomerKey], sseCustomerMD5: ""}, ErrPostInvalidOption, nil},
	}

	for _, tc := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"key wrong length", func(fields map[string]string) {
			fields[sseCustomerKey] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 31))
		}},
		{"key invalid base64", func(fields map[string]string) { fields[sseCustomerKey] = "%%%" }},
		{"key noncanonical base64", func(fields map[string]string) {
			fields[sseCustomerKey] = strings.TrimRight(fields[sseCustomerKey], "=")
		}},
		{"md5 wrong length", func(fields map[string]string) { fields[sseCustomerMD5] = base64.StdEncoding.EncodeToString([]byte{1}) }},
		{"md5 mismatch", func(fields map[string]string) {
			fields[sseCustomerMD5] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, md5.Size))
		}},
		{"md5 invalid base64", func(fields map[string]string) { fields[sseCustomerMD5] = "%%%" }},
		{"md5 noncanonical base64", func(fields map[string]string) {
			fields[sseCustomerMD5] = strings.TrimRight(fields[sseCustomerMD5], "=")
		}},
		{"customer explicit empty", func(fields map[string]string) { fields[sseCustomerKey] = "" }},
		{"customer mixed kms", func(fields map[string]string) { fields[sseAlgorithmHeader] = "aws:kms" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := sseCustomerFields()
			tc.mutate(fields)
			_, err := parseSSEOptions(fields)
			require.ErrorIs(t, err, ErrPostInvalidOption)
		})
	}

	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"/folder/naïve file", true},
		{"https://example.test/path?q=one", true},
		{"https://example.test/café", true},
		{"/with\tcontrol", false},
		{"/with\x7fdel", false},
		{"https://user@example.test/path", false},
		{"https:///missing-host", false},
		{"https://example.test:bad/path", false},
		{"ftp://example.test/path", false},
	} {
		t.Run("website redirect "+tc.value, func(t *testing.T) {
			require.Equal(t, tc.valid, validWebsiteRedirect(tc.value))
		})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSSEOptions(tc.fields)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			if tc.want != nil {
				require.Equal(t, tc.want, got)
			}
			if tc.name == "absent" {
				require.Nil(t, got)
			}
			if got != nil && got.Customer != nil {
				wantFields := sseCustomerFields()
				wantKey, decodeErr := base64.StdEncoding.DecodeString(wantFields[sseCustomerKey])
				require.NoError(t, decodeErr)
				require.Equal(t, wantKey, got.Customer.Key)
				require.Equal(t, wantFields[sseCustomerMD5], got.Customer.MD5)
				got.Customer.Close()
			}
		})
	}

	for _, tc := range []struct {
		name, endpoint string
		tls            config.BackendTLSConfig
		remote, xfp    string
		secure         bool
	}{
		{"direct TLS and verified HTTPS backend", "https://store.example", config.BackendTLSConfig{}, "198.51.100.2:2", "", true},
		{"untrusted forwarded scheme", "https://store.example", config.BackendTLSConfig{}, "198.51.100.2:2", "https", false},
		{"trusted immediate peer", "https://store.example", config.BackendTLSConfig{}, "10.1.2.3:99", "HTTPS", true},
		{"trusted but ambiguous forwarded scheme", "https://store.example", config.BackendTLSConfig{}, "10.1.2.3:99", "https, https", false},
		{"backend HTTP", "http://store.example", config.BackendTLSConfig{}, "10.1.2.3:99", "https", false},
		{"backend tls verification disabled", "https://store.example", config.BackendTLSConfig{InsecureSkipVerify: true}, "10.1.2.3:99", "https", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"10.0.0.0/8"}}, Backend: config.BackendConfig{Endpoint: tc.endpoint, UseSSL: true, TLS: tc.tls}}
			h := NewHandlerWithFeatures(newMockS3Client(), nil, nil, nil, nil, nil, nil, cfg, nil)
			r := httptest.NewRequest(http.MethodPut, "/bucket/key", nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
			if tc.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", tc.xfp)
			}
			if tc.name == "direct TLS and verified HTTPS backend" {
				r.TLS = &tls.ConnectionState{}
			}
			if tc.secure {
				require.NoError(t, h.validateSSECustomerTransport(r))
			} else {
				require.ErrorIs(t, h.validateSSECustomerTransport(r), ErrSSEInsecureTransport)
			}
		})
	}
}

func TestGH353SSE_CustomerHeaderParserRejectsDuplicatesAndAcceptsExactTriplet(t *testing.T) {
	fields := sseCustomerFields()
	for _, header := range []http.Header{
		{},
		{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256", "AES256"}},
		{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}, "x-amz-server-side-encryption-customer-algorithm": {"AES256"}},
	} {
		customer, err := parseSSECustomerHeaders(header)
		if len(header) == 0 {
			if err != nil || customer != nil {
				t.Fatalf("empty headers parsed customer=%v err=%v", customer, err)
			}
			continue
		}
		if !errors.Is(err, ErrPostInvalidOption) || customer != nil {
			t.Fatalf("duplicate customer headers parsed customer=%v err=%v", customer, err)
		}
	}
	header := make(http.Header)
	for name, value := range fields {
		header.Set(name, value)
	}
	customer, err := parseSSECustomerHeaders(header)
	require.NoError(t, err)
	require.NotNil(t, customer)
	backing := customer.Key
	wantKey, decodeErr := base64.StdEncoding.DecodeString(fields[sseCustomerKey])
	require.NoError(t, decodeErr)
	require.Equal(t, wantKey, backing)
	customer.Close()
	require.Equal(t, make([]byte, len(backing)), backing)
}

func TestGH353SSE_PutOptionsNilAndMalformedQueryAreRejected(t *testing.T) {
	if _, err := parsePutObjectOptions(nil); !errors.Is(err, ErrPostInvalidOption) {
		t.Fatalf("nil request options error=%v", err)
	}
	request := httptest.NewRequest(http.MethodPut, "/bucket/key?%zz", nil)
	if _, err := parsePutObjectOptions(request); !errors.Is(err, ErrPostInvalidOption) {
		t.Fatalf("malformed query options error=%v", err)
	}
	if hasSSECustomerHeaders(http.Header{}) || !hasSSECustomerHeaders(http.Header{sseCustomerKey: nil}) {
		t.Fatal("customer-header presence predicate did not distinguish absent and explicitly empty header")
	}
}

func TestGH353SSE_PutOptionFailuresZeroizeCustomerKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		invalid func(*http.Request)
	}{
		{"invalid storage", func(r *http.Request) { r.Header.Set("x-amz-storage-class", "not-a-class") }},
		{"duplicate storage", func(r *http.Request) { r.Header["X-Amz-Storage-Class"] = []string{"STANDARD", "STANDARD_IA"} }},
		{"invalid website", func(r *http.Request) { r.Header.Set("x-amz-website-redirect-location", "https://user@example.test/") }},
		{"duplicate website", func(r *http.Request) { r.Header["X-Amz-Website-Redirect-Location"] = []string{"/one", "/two"} }},
		{"missing signed headers", func(r *http.Request) {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host, Signature=x")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "https://gateway.example/bucket/key", nil)
			fields := sseCustomerFields()
			for name, value := range fields {
				r.Header.Set(name, value)
			}
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
			tc.invalid(r)
			parsed, err := parseSSEFieldSet(sseFieldSet(fields))
			require.NoError(t, err)
			backing := parsed.Customer.Key
			_, err = validateParsedPutObjectOptions(r, s3.ObjectPutOptions{SSE: parsed})
			require.Error(t, err)
			require.Equal(t, bytes.Repeat([]byte{0}, 32), backing, "raw backing bytes must be zeroed on every post-parse validation failure")
		})
	}
}

func TestGH353SSE_UnsupportedCapabilityErrorMapping(t *testing.T) {
	for _, err := range []error{ErrPostUnsupported, fmt.Errorf("wrapped capability: %w", s3.ErrNotImplemented)} {
		code, message, status := classifySSEOptionError(err)
		require.Equal(t, "NotImplemented", code)
		require.Equal(t, http.StatusNotImplemented, status)
		require.NotEmpty(t, message)
		require.NotContains(t, message, err.Error())
	}
	code, _, status := classifySSEOptionError(ErrSSEInsecureTransport)
	require.Equal(t, "InvalidRequest", code)
	require.Equal(t, http.StatusBadRequest, status)

	legacy := &failOnAnyCallS3Client{t: t}
	h := NewHandlerWithFeatures(legacy, nil, logrus.New(), getTestMetrics(), nil, nil, nil, &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}, nil)
	r := signedCustomerRequest()
	_, _, err := h.objectReadClient(r, legacy, "bucket", "key")
	require.ErrorIs(t, err, s3.ErrNotImplemented)
	response := httptest.NewRecorder()
	h.writeSSEOptionError(response, r, "GetObject", err, time.Now())
	require.Equal(t, http.StatusNotImplemented, response.Code)
	require.Contains(t, response.Body.String(), "<Code>NotImplemented</Code>")
	require.Zero(t, legacy.callCount.Load(), "unsupported advanced capability must fail before backend reads")

	router := mux.NewRouter()
	h.RegisterRoutes(router)
	request := signedHeaderCustomerRequest(t, http.MethodGet, "/bucket/key", "", "")
	productionResponse := httptest.NewRecorder()
	productionHandler := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(AuthorizationMiddleware("", nil)(router))
	productionHandler.ServeHTTP(productionResponse, request)
	require.Equal(t, http.StatusNotImplemented, productionResponse.Code)
	require.Contains(t, productionResponse.Body.String(), "<Code>NotImplemented</Code>")
	require.NotContains(t, productionResponse.Body.String(), string(bytes.Repeat([]byte("k"), 32)))
	require.NotContains(t, productionResponse.Body.String(), "unsupported-client-plaintext")
	require.Zero(t, legacy.callCount.Load(), "legacy client capability rejection happens before backend I/O")
}

func TestGH353SSE_TransportPolicySnapshot(t *testing.T) {
	proxies := []string{"10.0.0.0/8"}
	cfg := &config.Config{Server: config.ServerConfig{TrustedProxies: proxies}, Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}
	h := NewHandlerWithFeatures(newMockS3Client(), nil, nil, nil, nil, nil, nil, cfg, nil)
	proxies[0] = "192.0.2.0/24"
	cfg.Server.TrustedProxies[0] = "192.0.2.0/24"
	cfg.Backend.Endpoint = "http://store.example"
	cfg.Backend.TLS.InsecureSkipVerify = true
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	r.RemoteAddr = "10.1.2.3:44"
	r.Header.Set("X-Forwarded-Proto", "https")
	require.NoError(t, h.validateSSECustomerTransport(r), "construction-time trusted proxy and HTTPS endpoint are snapshotted")
	require.False(t, h.backendTLS.InsecureSkipVerify, "TLS policy is snapshotted independently of mutable config")

	badCIDR := &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"not-a-cidr"}}, Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}
	badHandler := NewHandlerWithFeatures(newMockS3Client(), nil, nil, nil, nil, nil, nil, badCIDR, nil)
	require.ErrorIs(t, badHandler.validateSSECustomerTransport(r), ErrSSEInsecureTransport)

	tlsHandler := NewHandlerWithFeatures(newMockS3Client(), nil, nil, nil, nil, nil, nil, &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}, nil)
	plain := []byte("trusted-backend-encrypted-object-plaintext")
	writeEngine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	if closer, ok := writeEngine.(io.Closer); ok {
		defer closer.Close()
	}
	sealed, metadata, err := writeEngine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), nil)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(sealed)
	require.NoError(t, err)
	metadata["Content-Length"] = strconv.Itoa(len(ciphertext))
	metadata[sseCustomerAlg] = "AES256"
	var requestCount atomic.Int32
	var sawCustomer atomic.Bool
	var observedHeaders http.Header
	var observedHeadersMu sync.Mutex
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestCount.Add(1)
		observedHeadersMu.Lock()
		observedHeaders = request.Header.Clone()
		observedHeadersMu.Unlock()
		if request.Header.Get("x-amz-server-side-encryption-customer-algorithm") == "AES256" && request.Header.Get("x-amz-server-side-encryption-customer-key") != "" && request.Header.Get("x-amz-server-side-encryption-customer-key-md5") != "" {
			sawCustomer.Store(true)
		}
		for name, value := range metadata {
			if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") || strings.EqualFold(name, "ETag") {
				w.Header().Set(name, value)
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(ciphertext)))
		if request.Method != http.MethodHead {
			_, _ = w.Write(ciphertext)
		}
	}))
	defer backend.Close()
	tlsHandler.backendEndpointScheme = "https"
	tlsHandler.backendTLS = config.BackendTLSConfig{}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: backend.Certificate().Raw})
	caFile := t.TempDir() + "/test-ca.pem"
	require.NoError(t, os.WriteFile(caFile, certPEM, 0600))
	runThroughBackend := func(t *testing.T, ca, method string) (*httptest.ResponseRecorder, int32, bool, string) {
		t.Helper()
		backendConfig := &config.BackendConfig{Endpoint: backend.URL, AccessKey: "backend", SecretKey: "secret", SessionToken: "backend-session-token", UsePathStyle: true, Retry: config.BackendRetryConfig{Mode: "off"}, TLS: config.BackendTLSConfig{CAFile: ca}}
		factory := s3.NewClientFactory(backendConfig)
		apiConfig := &config.Config{Backend: *backendConfig}
		readEngine, engineErr := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
		require.NoError(t, engineErr)
		logger := logrus.New()
		var logBuffer bytes.Buffer
		logger.SetOutput(&logBuffer)
		h := NewHandlerWithFeatures(nil, readEngine, logger, metrics.NewMetricsWithRegistry(prometheus.NewRegistry()), nil, nil, nil, apiConfig, nil)
		h.clientAcquirer = func(*http.Request) (s3.Client, error) { return factory.GetClient() }
		router := mux.NewRouter()
		h.RegisterRoutes(router)
		handler := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(AuthorizationMiddleware("", nil)(router))
		before := requestCount.Load()
		response := httptest.NewRecorder()
		request := signedHeaderCustomerRequest(t, method, "/bucket/key", "", "")
		handler.ServeHTTP(response, request)
		if closer, ok := readEngine.(io.Closer); ok {
			_ = closer.Close()
		}
		return response, requestCount.Load() - before, sawCustomer.Load(), logBuffer.String()
	}
	unknownCAResponse, unknownCARequests, _, unknownCALogs := runThroughBackend(t, "", http.MethodGet)
	require.Equal(t, http.StatusInternalServerError, unknownCAResponse.Code)
	require.Contains(t, unknownCAResponse.Body.String(), "<Code>InternalError</Code>")
	require.NotContains(t, unknownCAResponse.Body.String(), string(plain))
	require.NotContains(t, unknownCAResponse.Body.String(), sseCustomerFields()[sseCustomerKey])
	require.NotContains(t, unknownCAResponse.Body.String(), "backend-session-token")
	require.NotContains(t, unknownCALogs, sseCustomerFields()[sseCustomerKey])
	require.NotContains(t, unknownCALogs, "backend-session-token")
	require.Zero(t, unknownCARequests, "untrusted TLS certificate fails before any HTTP request carries SSE-C key")

	requestCount.Store(0)
	sawCustomer.Store(false)
	trustedResponse, trustedRequests, customerSeen, trustedLogs := runThroughBackend(t, caFile, http.MethodGet)
	require.Equal(t, http.StatusOK, trustedResponse.Code, trustedResponse.Body.String())
	require.Equal(t, plain, trustedResponse.Body.Bytes())
	require.Equal(t, "no-store", trustedResponse.Header().Get("Cache-Control"))
	require.Positive(t, trustedRequests)
	require.True(t, customerSeen, "trusted backend receives the complete SSE-C customer triplet")
	require.NotContains(t, trustedResponse.Body.String(), "backend-session-token")
	require.NotContains(t, trustedLogs, sseCustomerFields()[sseCustomerKey])
	require.NotContains(t, trustedLogs, "backend-session-token")
	wantSSE := sseCustomerFields()
	observedHeadersMu.Lock()
	require.Equal(t, wantSSE[sseCustomerAlg], observedHeaders.Get(sseCustomerAlg))
	require.Equal(t, wantSSE[sseCustomerKey], observedHeaders.Get(sseCustomerKey))
	require.Equal(t, wantSSE[sseCustomerMD5], observedHeaders.Get(sseCustomerMD5))
	observedHeadersMu.Unlock()

	requestCount.Store(0)
	sawCustomer.Store(false)
	trustedHead, headRequests, headCustomerSeen, headLogs := runThroughBackend(t, caFile, http.MethodHead)
	require.Equal(t, http.StatusOK, trustedHead.Code)
	require.Empty(t, trustedHead.Body.Bytes())
	require.Positive(t, headRequests)
	require.True(t, headCustomerSeen, "trusted backend receives the complete SSE-C triplet on HEAD")
	require.NotContains(t, headLogs, sseCustomerFields()[sseCustomerKey])
	require.NotContains(t, headLogs, "backend-session-token")
}

func mustNewRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, target, nil)
	require.NoError(t, err)
	return r
}

type sseAdvancedStub struct {
	s3.Client
	keySeen          bool
	ranges           []string
	heads            int
	fail             error
	metadata         map[string]string
	wantKey          []byte
	body             []byte
	calls            []sseReadCall
	keyBacking       []byte
	denyUnkeyedSSE   bool
	unkeyedFault     error
	unkeyedHeadFault error
	wrongKeyFault    error
	headFault        error
	headReadFault    error
	wrongHeadFault   error
}

type sseReadCall struct {
	bucket, key, version, rangeHeader string
	method                            string
	keyed, keyMatches                 bool
}

func (c *sseAdvancedStub) PutObjectWithOptions(context.Context, string, string, io.Reader, map[string]string, *int64, string, *s3.ObjectLockInput, string, string, string, string, string, s3.ObjectPutOptions) (s3.PutObjectResult, error) {
	return s3.PutObjectResult{}, nil
}
func (c *sseAdvancedStub) GetObjectWithOptions(_ context.Context, bucket, key string, version, rg *string, options s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	c.keySeen = options.Customer != nil
	c.keyBacking = nil
	call := sseReadCall{bucket: bucket, key: key, method: "GET", keyed: options.Customer != nil, keyMatches: options.Customer != nil && bytes.Equal(options.Customer.Key, c.wantKey)}
	if version != nil {
		call.version = *version
	}
	if rg != nil {
		call.rangeHeader = *rg
	}
	c.calls = append(c.calls, call)
	if options.Customer != nil && c.wantKey != nil && !bytes.Equal(options.Customer.Key, c.wantKey) {
		if c.wrongKeyFault != nil {
			return nil, nil, c.wrongKeyFault
		}
		return nil, nil, errors.New("backend rejected customer key")
	}
	if options.Customer != nil {
		c.keyBacking = options.Customer.Key
	}
	if rg != nil {
		c.ranges = append(c.ranges, *rg)
	}
	if c.fail != nil {
		return nil, nil, c.fail
	}
	body := c.body
	if body == nil {
		body = []byte("cipher")
	}
	if rg != nil && *rg != "" {
		parts := strings.Split(strings.TrimPrefix(*rg, "bytes="), "-")
		if len(parts) == 2 {
			start, startErr := strconv.Atoi(parts[0])
			end, endErr := strconv.Atoi(parts[1])
			if startErr == nil && endErr == nil && start >= 0 && end >= start && start < len(body) {
				if end >= len(body) {
					end = len(body) - 1
				}
				body = body[start : end+1]
			}
		}
	}
	return io.NopCloser(bytes.NewReader(body)), c.metadata, nil
}
func (c *sseAdvancedStub) HeadObjectWithOptions(_ context.Context, bucket, key string, version *string, options s3.ObjectReadOptions) (map[string]string, error) {
	c.heads++
	c.keySeen = options.Customer != nil
	call := sseReadCall{bucket: bucket, key: key, method: "HEAD", keyed: options.Customer != nil, keyMatches: options.Customer != nil && bytes.Equal(options.Customer.Key, c.wantKey)}
	if version != nil {
		call.version = *version
	}
	c.calls = append(c.calls, call)
	if c.headReadFault != nil && options.Customer == nil {
		return nil, c.headReadFault
	}
	if c.headFault != nil && options.Customer == nil {
		return nil, c.headFault
	}
	if options.Customer != nil && c.wantKey != nil && !bytes.Equal(options.Customer.Key, c.wantKey) {
		if c.wrongHeadFault != nil {
			return nil, c.wrongHeadFault
		}
		if c.wrongKeyFault != nil {
			return nil, c.wrongKeyFault
		}
		return nil, errors.New("backend rejected customer key")
	}
	if options.Customer != nil {
		c.keyBacking = options.Customer.Key
	}
	if c.fail != nil {
		return nil, c.fail
	}
	return c.metadata, nil
}
func (c *sseAdvancedStub) HeadObject(ctx context.Context, b, k string, v *string) (map[string]string, error) {
	call := sseReadCall{bucket: b, key: k, method: "HEAD"}
	if v != nil {
		call.version = *v
	}
	c.calls = append(c.calls, call)
	if c.headFault != nil {
		return nil, c.headFault
	}
	if c.denyUnkeyedSSE && isSSECustomerBackendObject(c.metadata) {
		c.heads++
		if c.unkeyedHeadFault != nil {
			return nil, c.unkeyedHeadFault
		}
		if c.unkeyedFault != nil {
			return nil, c.unkeyedFault
		}
		return nil, errors.New("customer key required")
	}
	return c.Client.HeadObject(ctx, b, k, v)
}

func (c *sseAdvancedStub) GetObject(ctx context.Context, b, k string, v, rg *string) (io.ReadCloser, map[string]string, error) {
	call := sseReadCall{bucket: b, key: k, method: "GET"}
	if v != nil {
		call.version = *v
	}
	if rg != nil {
		call.rangeHeader = *rg
	}
	c.calls = append(c.calls, call)
	if isSSECustomerBackendObject(c.metadata) {
		if c.unkeyedFault != nil {
			return nil, nil, c.unkeyedFault
		}
		return nil, nil, errors.New("customer key required")
	}
	return c.Client.GetObject(ctx, b, k, v, rg)
}

func signedCustomerRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://gateway.example/bucket/key", nil)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
	for key, value := range sseCustomerFields() {
		r.Header.Set(key, value)
	}
	return r
}

func signedPresignedCustomerRequest(t *testing.T, method string, fields map[string]string, version, rangeHeader string) *http.Request {
	t.Helper()
	query := url.Values{}
	for key, value := range fields {
		canonical := map[string]string{sseCustomerAlg: "X-Amz-Server-Side-Encryption-Customer-Algorithm", sseCustomerKey: "X-Amz-Server-Side-Encryption-Customer-Key", sseCustomerMD5: "X-Amz-Server-Side-Encryption-Customer-Key-MD5"}[key]
		if canonical != "" {
			query.Set(canonical, value)
		}
	}
	query.Set("X-Amz-Expires", "300")
	if version != "" {
		query.Set("versionId", version)
	}
	query.Set("response-cache-control", "public")
	return signPresignedRawRequest(t, method, "/bucket/key", query.Encode(), nil, rangeHeader)
}

func signPresignedRawRequest(t *testing.T, method, path, rawQuery string, headers http.Header, rangeHeader string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, "https://gateway.example"+path+"?"+rawQuery, nil)
	for name, values := range headers {
		for _, value := range values {
			r.Header.Add(name, value)
		}
	}
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	rawURL, _, err := v4.NewSigner().PresignHTTP(t.Context(), aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, r, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC())
	require.NoError(t, err)
	signed := httptest.NewRequest(method, rawURL, nil)
	for name, values := range headers {
		for _, value := range values {
			signed.Header.Add(name, value)
		}
	}
	if rangeHeader != "" {
		signed.Header.Set("Range", rangeHeader)
	}
	signed.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	signed.TLS = &tls.ConnectionState{}
	return signed
}

func signedPresignedRequestWithMalformedSuffix(t *testing.T, method, path, rawQuery string) *http.Request {
	t.Helper()
	req := signPresignedRawRequest(t, method, path, rawQuery, nil, "")
	req.URL.RawQuery += "&malformed=%ZZ"
	return req
}

func signedHeaderCustomerRequest(t *testing.T, method, path, version, rangeHeader string) *http.Request {
	t.Helper()
	target := path
	if version != "" {
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		target += separator + "versionId=" + url.QueryEscape(version)
	}
	r := httptest.NewRequest(method, "https://gateway.example"+target, nil)
	for name, value := range sseCustomerFields() {
		r.Header.Set(name, value)
	}
	if rangeHeader != "" {
		r.Header.Set("Range", rangeHeader)
	}
	r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	r.TLS = &tls.ConnectionState{}
	err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, r, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC())
	require.NoError(t, err)
	return r
}

func TestGH353SSEC_ReadPreflightRangeAndHEAD(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{0x6b}, 32)
	for _, fixtureName := range []string{"buffered-v2", "chunked-v2"} {
		t.Run(fixtureName, func(t *testing.T) {
			plain := bytes.Repeat([]byte("authenticated-presigned-plaintext-"), 2400)
			var opts []crypto.Option
			if fixtureName == "chunked-v2" {
				opts = append(opts, crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize))
			}
			engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), append(opts, crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))...)
			require.NoError(t, err)
			if closer, ok := engine.(io.Closer); ok {
				defer closer.Close()
			}
			sealed, metadata, err := engine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), nil)
			require.NoError(t, err)
			body, err := io.ReadAll(sealed)
			require.NoError(t, err)
			metadata["Content-Length"] = strconv.Itoa(len(body))
			metadata["ETag"] = `"backend-opaque-etag"`
			metadata["Cache-Control"] = "stored-private"
			metadata[sseCustomerAlg] = "AES256"
			if fixtureName == "chunked-v2" {
				metadata[crypto.MetaOriginalSize] = strconv.Itoa(len(plain))
				metadata[crypto.MetaChunkCount] = strconv.Itoa((len(plain) + crypto.MinChunkSize - 1) / crypto.MinChunkSize)
			}
			base := newMockS3Client()
			base.objects["bucket/key"] = body
			base.metadata["bucket/key"] = metadata
			advanced := &sseAdvancedStub{Client: base, wantKey: keyBytes, body: body, metadata: metadata}
			readEngine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), append(opts, crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))...)
			require.NoError(t, err)
			if closer, ok := readEngine.(io.Closer); ok {
				defer closer.Close()
			}
			cfg := &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}
			h := NewHandlerWithFeatures(advanced, readEngine, logrus.New(), metrics.NewMetricsWithRegistry(prometheus.NewRegistry()), nil, nil, nil, cfg, nil)
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { return advanced, nil }
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			handler := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(AuthorizationMiddleware("", nil)(router))
			for _, tc := range []struct {
				method, rg string
				status     int
				want       []byte
			}{
				{http.MethodGet, "", http.StatusOK, plain},
				{http.MethodGet, "bytes=1-8", http.StatusPartialContent, plain[1:9]},
				{http.MethodHead, "", http.StatusOK, nil},
			} {
				req := signedPresignedCustomerRequest(t, tc.method, sseCustomerFields(), "version-3", tc.rg)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				require.Equalf(t, tc.status, response.Code, "%s %s body=%s", tc.method, tc.rg, response.Body.String())
				require.Equal(t, tc.want, response.Body.Bytes())
				require.Equal(t, `"backend-opaque-etag"`, response.Header().Get("ETag"))
				require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
				require.Empty(t, response.Header().Get(sseCustomerKey))
			}
			for _, tc := range []struct {
				method, rangeHeader string
			}{
				{http.MethodGet, ""},
				{http.MethodGet, "bytes=1-8"},
				{http.MethodHead, ""},
			} {
				req := signedHeaderCustomerRequest(t, tc.method, "/bucket/key", "version-3", tc.rangeHeader)
				signing, sigErr := ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", time.Minute)
				require.NoError(t, sigErr, "independently signed header-auth request must validate")
				signing.Close()
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				wantStatus := http.StatusOK
				if tc.rangeHeader != "" {
					wantStatus = http.StatusPartialContent
				}
				require.Equal(t, wantStatus, response.Code, response.Body.String())
				if tc.method == http.MethodGet && tc.rangeHeader == "" {
					require.Equal(t, plain, response.Body.Bytes())
				}
				require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			}
			productionReadCalls := append([]sseReadCall(nil), advanced.calls...)
			require.NotEmpty(t, advanced.calls)
			for _, call := range productionReadCalls {
				if call.method != "GET" && call.method != "HEAD" {
					continue
				}
				require.Equalf(t, "version-3", call.version, "version semantics for backend request: %+v; all=%+v", call, advanced.calls)
				require.Equal(t, "bucket", call.bucket)
				require.Equal(t, "key", call.key)
				require.True(t, call.keyed, "every primary read and preflight carries customer key: %+v", call)
				require.True(t, call.keyMatches, "backend read received exact customer key: %+v", call)
			}
			if fixtureName == "chunked-v2" {
				ciphertextSize, parseErr := strconv.ParseInt(metadata["Content-Length"], 10, 64)
				require.NoError(t, parseErr)
				terminalStart := ciphertextSize - crypto.ChunkedTerminalSize
				terminalRange := fmt.Sprintf("bytes=%d-%d", terminalStart, ciphertextSize-1)
				var gotTerminal bool
				for _, call := range advanced.calls {
					if call.method == http.MethodGet && call.rangeHeader == terminalRange && call.version == "version-3" && call.keyMatches {
						gotTerminal = true
					}
				}
				require.True(t, gotTerminal, "terminal preflight must use independently calculated actual trailer span/version/customer key: %s", terminalRange)
				expectedOptimizedStart := int64(0)
				expectedOptimizedEnd := int64(crypto.MinChunkSize + 16 - 1)
				optimizedRange := fmt.Sprintf("bytes=%d-%d", expectedOptimizedStart, expectedOptimizedEnd)
				var gotOptimized bool
				for _, call := range advanced.calls {
					if call.method == http.MethodGet && call.rangeHeader == optimizedRange && call.version == "version-3" && call.keyMatches {
						gotOptimized = true
					}
				}
				require.True(t, gotOptimized, "optimized plaintext bytes=1-8 must fetch expected first ciphertext record %s; calls=%+v metadata=%v", optimizedRange, advanced.calls, metadata)
			} else {
				require.Empty(t, advanced.ranges, "buffered-v2 range uses a full ciphertext read before plaintext projection")
			}
			malformedQueries := []struct {
				name         string
				query        url.Values
				alias        string
				rawMalformed bool
			}{
				{"duplicate algorithm", url.Values{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256", "AES256"}}, "", false},
				{"case alias", url.Values{"x-amz-server-side-encryption-customer-algorithm": {"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Key": {sseCustomerFields()[sseCustomerKey]}, "X-Amz-Server-Side-Encryption-Customer-Key-MD5": {sseCustomerFields()[sseCustomerMD5]}}, "", false},
				{"empty algorithm", url.Values{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {""}}, "", false},
				{"missing key", url.Values{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Key-MD5": {sseCustomerFields()[sseCustomerMD5]}}, "", false},
				{"malformed key", url.Values{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Key": {"bad"}, "X-Amz-Server-Side-Encryption-Customer-Key-MD5": {sseCustomerFields()[sseCustomerMD5]}}, "", false},
				{"malformed MD5", url.Values{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Key": {sseCustomerFields()[sseCustomerKey]}, "X-Amz-Server-Side-Encryption-Customer-Key-MD5": {"bad"}}, "", false},
				{"mixed header and query", url.Values{"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Key": {sseCustomerFields()[sseCustomerKey]}, "X-Amz-Server-Side-Encryption-Customer-Key-MD5": {sseCustomerFields()[sseCustomerMD5]}}, "header", false},
				{"malformed raw query", nil, "X-Amz-Algorithm=%ZZ", true},
			}
			for _, bad := range malformedQueries {
				for _, method := range []string{http.MethodGet, http.MethodHead} {
					t.Run(bad.name+"/"+method, func(t *testing.T) {
						query := url.Values{}
						for k, values := range bad.query {
							query[k] = append([]string(nil), values...)
						}
						query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
						query.Set("X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/"+time.Now().UTC().Format("20060102")+"/us-east-1/s3/aws4_request")
						query.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
						query.Set("X-Amz-Expires", "300")
						query.Set("X-Amz-SignedHeaders", "host")
						headers := make(http.Header)
						if bad.alias == "header" {
							for k, v := range sseCustomerFields() {
								headers.Set(k, v)
							}
						}
						rawQuery := query.Encode()
						var req *http.Request
						if bad.rawMalformed {
							req = signedPresignedRequestWithMalformedSuffix(t, method, "/bucket/key", rawQuery)
							query.Set("malformed", "%")
						} else {
							req = signPresignedRawRequest(t, method, "/bucket/key", rawQuery, headers, "")
						}
						if !bad.rawMalformed {
							signing, sigErr := ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", time.Minute)
							require.NoError(t, sigErr, "test shape must have an authentic valid SigV4 presign")
							signing.Close()
						} else {
							signing, sigErr := ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", time.Minute)
							require.NoError(t, sigErr, "the signer authenticates the canonicalized query; the parser then rejects malformed raw encoding")
							signing.Close()
						}
						before := len(advanced.calls)
						response := httptest.NewRecorder()
						handler.ServeHTTP(response, req)
						require.Len(t, advanced.calls, before, "invalid query must be rejected before backend reads")
						if bad.rawMalformed {
							require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
							if method != http.MethodHead {
								require.Contains(t, response.Body.String(), "<Code>InvalidToken</Code>")
							}
						} else {
							require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
							if method != http.MethodHead {
								require.Contains(t, response.Body.String(), "<Code>InvalidArgument</Code>")
							}
						}
					})
				}
			}

			wrapped, closeKey, err := h.objectReadClient(signedCustomerRequest(), advanced, "bucket", "key")
			require.NoError(t, err)
			_, _, err = wrapped.GetObject(context.Background(), "bucket", "key", nil, nil)
			require.NoError(t, err)
			backing := advanced.keyBacking
			_, _, err = wrapped.GetObject(context.Background(), "bucket", "companion", nil, nil)
			require.Error(t, err, "companion is delegated unkeyed")
			require.False(t, advanced.calls[len(advanced.calls)-1].keyed)
			closeKey()
			require.Equal(t, bytes.Repeat([]byte{0}, 32), backing, "request cleanup zeroizes backing key bytes")

			wrongKey := bytes.Repeat([]byte{1}, 32)
			wrongFields := sseCustomerFields()
			wrongFields[sseCustomerKey] = base64.StdEncoding.EncodeToString(wrongKey)
			wrongMD5 := md5.Sum(wrongKey)
			wrongFields[sseCustomerMD5] = base64.StdEncoding.EncodeToString(wrongMD5[:])
			wrongResponse := httptest.NewRecorder()
			handler.ServeHTTP(wrongResponse, signedPresignedCustomerRequest(t, http.MethodGet, wrongFields, "version-3", ""))
			require.NotEqual(t, http.StatusOK, wrongResponse.Code)
			require.Equal(t, http.StatusInternalServerError, wrongResponse.Code)
			require.Contains(t, wrongResponse.Body.String(), "<Code>InternalError</Code>")
			require.NotContains(t, wrongResponse.Body.String(), string(plain))
			missingResponse := httptest.NewRecorder()
			beforeMissing := len(advanced.calls)
			missing := signedPresignedCustomerRequest(t, http.MethodGet, nil, "version-3", "")
			handler.ServeHTTP(missingResponse, missing)
			require.NotEqual(t, http.StatusOK, missingResponse.Code)
			require.Equal(t, http.StatusInternalServerError, missingResponse.Code)
			require.Contains(t, missingResponse.Body.String(), "<Code>InternalError</Code>")
			require.NotContains(t, missingResponse.Body.String(), string(plain))
			require.Greater(t, len(advanced.calls), beforeMissing, "authenticated unkeyed request reaches backend preflight")
			require.False(t, advanced.calls[len(advanced.calls)-1].keyed)
		})
	}
}

func TestGH353SSEC_UnkeyedInvalidRequestIsFixedDenial(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{0x6b}, 32)
	for _, cacheEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cache=%t", cacheEnabled), func(t *testing.T) {
			plain := []byte("authenticated SSE-C plaintext canary")
			engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
			require.NoError(t, err)
			if closer, ok := engine.(io.Closer); ok {
				defer closer.Close()
			}
			sealed, metadata, err := engine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), nil)
			require.NoError(t, err)
			ciphertext, err := io.ReadAll(sealed)
			require.NoError(t, err)
			metadata["Content-Length"] = strconv.Itoa(len(ciphertext))
			metadata["ETag"] = `"opaque-cipher-etag"`
			metadata[sseCustomerAlg] = "AES256"
			base := newMockS3Client()
			base.objects["bucket/key"] = ciphertext
			base.metadata["bucket/key"] = metadata
			backendErr := &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
				Err:      &smithy.GenericAPIError{Code: "InvalidRequest", Message: "private backend detail"},
			}
			headBackendErr := &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
				Err:      &smithy.GenericAPIError{Code: "BadRequest", Message: "private backend detail"},
			}
			advanced := &sseAdvancedStub{Client: base, wantKey: keyBytes, body: ciphertext, metadata: metadata, denyUnkeyedSSE: true, unkeyedFault: backendErr, unkeyedHeadFault: headBackendErr}
			registry := prometheus.NewRegistry()
			h := NewHandlerWithFeatures(advanced, engine, logrus.New(), metrics.NewMetricsWithRegistry(registry), nil, nil, nil,
				&config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}, nil)
			h.backendEndpointScheme = "https"
			h.backendEndpointScheme = "https"
			h.backendEndpointError = nil
			h.backendTLS = config.BackendTLSConfig{}
			if cacheEnabled {
				h.cache = cache.NewMemoryCache(1<<20, 4, time.Minute)
				require.NoError(t, h.cache.Set(t.Context(), "bucket", "key", plain, map[string]string{"ETag": metadata["ETag"]}, time.Minute))
			}
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			for _, tc := range []struct {
				method, rangeHeader string
			}{
				{method: http.MethodGet},
				{method: http.MethodHead},
				{method: http.MethodGet, rangeHeader: "bytes=0-7"},
			} {
				advanced.calls = nil
				advanced.fail = backendErr
				advanced.headReadFault = headBackendErr
				req := httptest.NewRequest(tc.method, "https://gateway.example/bucket/key", nil)
				req.TLS = &tls.ConnectionState{}
				if tc.rangeHeader != "" {
					req.Header.Set("Range", tc.rangeHeader)
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				require.Equal(t, http.StatusBadRequest, w.Code)
				if tc.method != http.MethodHead {
					require.Contains(t, w.Body.String(), "<Code>InvalidArgument</Code>")
					require.NotContains(t, w.Body.String(), "private backend detail")
					require.NotContains(t, w.Body.String(), string(plain))
				} else {
					require.Empty(t, w.Body.String())
				}
				require.Empty(t, w.Header().Get("ETag"))
				require.Empty(t, w.Header().Get("Content-Range"))
				require.Empty(t, w.Header().Get("Content-Length"))
				require.NotEmpty(t, advanced.calls)
			}
			require.NotEmpty(t, advanced.calls)
			for _, call := range advanced.calls {
				if call.method == "HEAD" || call.method == "GET" {
					require.False(t, call.keyed, "missing-key request must remain unkeyed at backend")
				}
			}
			require.Equal(t, http.StatusInternalServerError, translateSSECustomerReadError(&smithy.GenericAPIError{Code: "BadRequest", Message: "private"}, "bucket", "key", http.MethodHead, 0).HTTPStatus)
			require.Equal(t, http.StatusInternalServerError, translateSSECustomerReadError(&smithy.GenericAPIError{Code: "BadRequest", Message: "private"}, "bucket", "key", http.MethodHead, http.StatusInternalServerError).HTTPStatus)
			require.Equal(t, http.StatusInternalServerError, TranslateError(&smithy.GenericAPIError{Code: "InvalidRequest", Message: "private"}, "bucket", "key").HTTPStatus)
			require.Equal(t, float64(3), metricTotal(t, registry, "http_requests_total"))
			require.Equal(t, float64(3), metricTotal(t, registry, "s3_operation_errors_total"))
			require.Zero(t, metricTotal(t, registry, "encryption_errors_total"))
		})
	}
}

func TestGH353SSEC_InvalidArgumentBackendReadDenialAndMetrics(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{0x6b}, 32)
	for _, cacheEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("cache=%t", cacheEnabled), func(t *testing.T) {
			plain := []byte("SSE-C valid plaintext canary")
			engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
			require.NoError(t, err)
			if closer, ok := engine.(io.Closer); ok {
				defer closer.Close()
			}
			sealed, metadata, err := engine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), nil)
			require.NoError(t, err)
			ciphertext, err := io.ReadAll(sealed)
			require.NoError(t, err)
			metadata["Content-Length"] = strconv.Itoa(len(ciphertext))
			metadata["ETag"] = `"opaque-etag"`
			metadata[sseCustomerAlg] = "AES256"
			base := newMockS3Client()
			base.objects["bucket/key"] = ciphertext
			base.metadata["bucket/key"] = metadata
			backendErr := &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
				Err:      &smithy.GenericAPIError{Code: "InvalidRequest", Message: "private backend message canary"},
			}
			headBackendErr := &smithyhttp.ResponseError{
				Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
				Err:      &smithy.GenericAPIError{Code: "BadRequest", Message: "private backend message canary"},
			}
			advanced := &sseAdvancedStub{Client: base, wantKey: keyBytes, body: ciphertext, metadata: metadata, denyUnkeyedSSE: true, unkeyedFault: backendErr, unkeyedHeadFault: headBackendErr, wrongKeyFault: backendErr, headReadFault: headBackendErr, wrongHeadFault: headBackendErr}
			registry := prometheus.NewRegistry()
			h := NewHandlerWithFeatures(advanced, engine, logrus.New(), metrics.NewMetricsWithRegistry(registry), nil, nil, nil,
				&config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}, nil)
			h.backendEndpointScheme = "https"
			if cacheEnabled {
				h.cache = cache.NewMemoryCache(1<<20, 4, time.Minute)
				require.NoError(t, h.cache.Set(t.Context(), "bucket", "key", plain, map[string]string{"ETag": metadata["ETag"]}, time.Minute))
			}
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			badKeyFields := sseCustomerFields()
			wrong := bytes.Repeat([]byte{0x25}, 32)
			wrongMD5 := md5.Sum(wrong)
			badKeyFields[sseCustomerKey] = base64.StdEncoding.EncodeToString(wrong)
			badKeyFields[sseCustomerMD5] = base64.StdEncoding.EncodeToString(wrongMD5[:])
			clear(wrong)
			clear(wrongMD5[:])
			cases := []struct {
				name, method, rangeHeader string
				keyed                     bool
			}{
				{name: "missing GET", method: http.MethodGet},
				{name: "missing HEAD", method: http.MethodHead},
				{name: "missing range", method: http.MethodGet, rangeHeader: "bytes=0-7"},
				{name: "wrong GET", method: http.MethodGet, keyed: true},
				{name: "wrong HEAD", method: http.MethodHead, keyed: true},
				{name: "wrong range", method: http.MethodGet, rangeHeader: "bytes=0-7", keyed: true},
			}
			for _, tc := range cases {
				beforeHTTP := metricTotal(t, registry, "http_requests_total")
				beforeS3 := metricTotal(t, registry, "s3_operation_errors_total")
				req := httptest.NewRequest(tc.method, "https://gateway.example/bucket/key", nil)
				req.TLS = &tls.ConnectionState{}
				req.Header.Set("X-Forwarded-Proto", "https")
				if tc.keyed {
					req.RemoteAddr = "127.0.0.1:1234"
				}
				if tc.rangeHeader != "" {
					req.Header.Set("Range", tc.rangeHeader)
				}
				if tc.keyed {
					for name, value := range badKeyFields {
						req.Header.Set(name, value)
					}
					req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
				}
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				require.Equalf(t, http.StatusBadRequest, w.Code, "%s response=%q", tc.name, w.Body.String())
				if tc.method == http.MethodHead {
					require.Empty(t, w.Body.String())
				} else {
					var responseError struct {
						Code string `xml:"Code"`
					}
					require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &responseError))
					wantCode := "InvalidArgument"
					if tc.keyed {
						wantCode = "InvalidArgument"
					}
					require.Equal(t, wantCode, responseError.Code)
					require.NotContains(t, w.Body.String(), "private backend message canary")
					require.NotContains(t, w.Body.String(), string(plain))
				}
				require.Empty(t, w.Header().Get("ETag"))
				require.Empty(t, w.Header().Get("Content-Range"))
				require.Empty(t, w.Header().Get("Content-Length"))
				require.Equal(t, beforeHTTP+1, metricTotal(t, registry, "http_requests_total"), "HTTP request metric exactly once")
				require.Equal(t, beforeS3+1, metricTotal(t, registry, "s3_operation_errors_total"), "S3 error metric exactly once")
				require.Zero(t, metricTotal(t, registry, "encryption_errors_total"))
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				req := httptest.NewRequest(method, "https://gateway.example/bucket/key", nil)
				req.TLS = &tls.ConnectionState{}
				req.RemoteAddr = "127.0.0.1:1234"
				req.Header.Set("X-Forwarded-Proto", "https")
				fields := sseCustomerFields()
				for name, value := range fields {
					req.Header.Set(name, value)
				}
				req.Header.Set("X-Forwarded-Proto", "https")
				req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				require.Equalf(t, http.StatusOK, w.Code, "valid keyed %s response=%q", method, w.Body.String())
				if method == http.MethodGet {
					require.Equal(t, plain, w.Body.Bytes())
				}
			}
		})
	}
}

func TestGH353SSEC_CachedGETPreflightUsesBackendHEADStatus(t *testing.T) {
	plain := []byte("real SDK SSE-C cache preflight plaintext")
	engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	if closer, ok := engine.(io.Closer); ok {
		defer closer.Close()
	}
	sealed, metadata, err := engine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), nil)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(sealed)
	require.NoError(t, err)
	metadata["Content-Length"] = strconv.Itoa(len(ciphertext))
	metadata["ETag"] = `"real-sdk-etag"`
	metadata[sseCustomerAlg] = "AES256"
	correctCustomerKey := sseCustomerFields()[sseCustomerKey]

	type backendCall struct {
		method             string
		customerKeyPresent bool
	}
	var callsMu sync.Mutex
	var calls []backendCall
	var sawWrongKey atomic.Bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callsMu.Lock()
		defer callsMu.Unlock()
		call := backendCall{method: r.Method, customerKeyPresent: r.Header.Get("x-amz-server-side-encryption-customer-key") != ""}
		calls = append(calls, call)
		if (r.Method == http.MethodHead || r.Method == http.MethodGet) && call.customerKeyPresent && r.Header.Get("x-amz-server-side-encryption-customer-key") != correctCustomerKey {
			sawWrongKey.Store(true)
			// Wrong-key denials from this fixture are bodyless, matching the
			// backend behavior that motivated the HEAD 403 follow-up.
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.Method == http.MethodHead && !call.customerKeyPresent {
			// Deliberately bodyless: the SDK reports BadRequest based on HTTP status.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.Method == http.MethodGet && !call.customerKeyPresent {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `<Error><Code>InvalidRequest</Code><Message>private backend canary</Message></Error>`)
			return
		}
		for name, value := range metadata {
			if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") || strings.EqualFold(name, "ETag") || strings.EqualFold(name, "Content-Type") {
				w.Header().Set(name, value)
			}
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(ciphertext)))
		if r.Method != http.MethodHead {
			_, _ = w.Write(ciphertext)
		}
	}))
	defer backend.Close()
	head400 := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}}, Err: &smithy.GenericAPIError{Code: "BadRequest", Message: "private"}}
	require.Equal(t, http.StatusBadRequest, translateSSECustomerReadError(head400, "bucket", "key", http.MethodHead, backendReadStatus(head400)).HTTPStatus)
	wrongStatus := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}}, Err: &smithy.GenericAPIError{Code: "BadRequest", Message: "private"}}
	require.Equal(t, http.StatusInternalServerError, translateSSECustomerReadError(wrongStatus, "bucket", "key", http.MethodHead, backendReadStatus(wrongStatus)).HTTPStatus)
	getWrongStatus := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}}, Err: &smithy.GenericAPIError{Code: "InvalidRequest", Message: "private"}}
	require.Equal(t, http.StatusInternalServerError, translateSSECustomerReadError(getWrongStatus, "bucket", "key", http.MethodGet, backendReadStatus(getWrongStatus)).HTTPStatus)
	headWrongCode := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}}, Err: &smithy.GenericAPIError{Code: "InvalidRequest", Message: "private"}}
	require.Equal(t, http.StatusInternalServerError, translateSSECustomerReadError(headWrongCode, "bucket", "key", http.MethodHead, backendReadStatus(headWrongCode)).HTTPStatus)
	head403 := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden}}, Err: &smithy.GenericAPIError{Code: "Forbidden", Message: "private"}}
	require.Equal(t, http.StatusForbidden, translateSSECustomerReadError(head403, "bucket", "key", http.MethodHead, backendReadStatus(head403)).HTTPStatus)
	require.Equal(t, "AccessDenied", translateSSECustomerReadError(head403, "bucket", "key", http.MethodHead, backendReadStatus(head403)).Code)
	require.Equal(t, http.StatusInternalServerError, translateSSECustomerReadError(&smithy.GenericAPIError{Code: "Forbidden", Message: "private"}, "bucket", "key", http.MethodHead, 0).HTTPStatus, "without backend status, the generic SDK code is not enough")
	head403WrongCode := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden}}, Err: &smithy.GenericAPIError{Code: "AccessDenied", Message: "private"}}
	require.Equal(t, "AccessDenied", translateSSECustomerReadError(head403WrongCode, "bucket", "key", http.MethodHead, backendReadStatus(head403WrongCode)).Code)
	head403WrongStatus := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusInternalServerError}}, Err: &smithy.GenericAPIError{Code: "Forbidden", Message: "private"}}
	require.Equal(t, http.StatusInternalServerError, translateSSECustomerReadError(head403WrongStatus, "bucket", "key", http.MethodHead, backendReadStatus(head403WrongStatus)).HTTPStatus)
	head404 := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusNotFound}}, Err: &smithy.GenericAPIError{Code: "NoSuchKey", Message: "private"}}
	require.Equal(t, http.StatusNotFound, translateSSECustomerReadError(head404, "bucket", "key", http.MethodHead, backendReadStatus(head404)).HTTPStatus)
	require.Equal(t, "NoSuchKey", translateSSECustomerReadError(head404, "bucket", "key", http.MethodHead, backendReadStatus(head404)).Code)
	get403Forbidden := &smithyhttp.ResponseError{Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusForbidden}}, Err: &smithy.GenericAPIError{Code: "Forbidden", Message: "private"}}
	require.Equal(t, http.StatusInternalServerError, translateSSECustomerReadError(get403Forbidden, "bucket", "key", http.MethodGet, backendReadStatus(get403Forbidden)).HTTPStatus, "Forbidden mapping is HEAD-only")

	backendConfig := &config.BackendConfig{Endpoint: backend.URL, AccessKey: "backend", SecretKey: "backend-secret", UsePathStyle: true, Retry: config.BackendRetryConfig{Mode: "off"}}
	factory := s3.NewClientFactory(backendConfig)
	backendClient, err := factory.GetClient()
	require.NoError(t, err)
	advancedBackend, ok := backendClient.(s3.AdvancedObjectClient)
	require.True(t, ok)
	wrongCustomerKey := bytes.Repeat([]byte{0x25}, 32)
	wrongCustomerDigest := md5.Sum(wrongCustomerKey)
	_, sdkWrongKeyErr := advancedBackend.HeadObjectWithOptions(t.Context(), "bucket", "key", nil, s3.ObjectReadOptions{Customer: &s3.SSECustomerKey{Key: wrongCustomerKey, MD5: base64.StdEncoding.EncodeToString(wrongCustomerDigest[:])}})
	clear(wrongCustomerKey)
	clear(wrongCustomerDigest[:])
	require.Error(t, sdkWrongKeyErr)
	var sdkWrongKeyAPIError smithy.APIError
	require.True(t, errors.As(sdkWrongKeyErr, &sdkWrongKeyAPIError), "actual SDK error must expose its API error code")
	t.Logf("bodyless HEAD 403 SDK provenance: code=%q status=%d", sdkWrongKeyAPIError.ErrorCode(), backendReadStatus(sdkWrongKeyErr))
	require.Equal(t, "Forbidden", sdkWrongKeyAPIError.ErrorCode())
	require.Equal(t, http.StatusForbidden, backendReadStatus(sdkWrongKeyErr))
	callsMu.Lock()
	calls = nil
	callsMu.Unlock()
	var clientAcquires atomic.Int32
	registry := prometheus.NewRegistry()
	apiConfig := &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}, Server: config.ServerConfig{TrustedProxies: []string{"127.0.0.1/32"}}}
	h := NewHandlerWithFeatures(nil, engine, logrus.New(), metrics.NewMetricsWithRegistry(registry), nil, nil, nil, apiConfig, nil)
	h.backendEndpointScheme = "https"
	h.clientAcquirer = func(*http.Request) (s3.Client, error) {
		clientAcquires.Add(1)
		return factory.GetClient()
	}
	h.logger.SetOutput(io.Discard)
	h.cache = cache.NewMemoryCache(1<<20, 4, time.Minute)
	require.NoError(t, h.cache.Set(t.Context(), "bucket", "key", plain, map[string]string{"ETag": metadata["ETag"]}, time.Minute))
	router := mux.NewRouter()
	h.RegisterRoutes(router)

	wrongKeyRequest := signedCustomerRequest()
	wrongKeyRequest.Method = http.MethodHead
	wrongKeyRequest.URL.Path = "/bucket/key"
	wrongKeyRequest.RemoteAddr = "127.0.0.1:1234"
	wrongKeyRequest.Header.Set("X-Forwarded-Proto", "https")
	wrongCustomer := bytes.Repeat([]byte{0x25}, 32)
	wrongDigest := md5.Sum(wrongCustomer)
	wrongKeyRequest.Header.Set(sseCustomerKey, base64.StdEncoding.EncodeToString(wrongCustomer))
	wrongKeyRequest.Header.Set(sseCustomerMD5, base64.StdEncoding.EncodeToString(wrongDigest[:]))
	clear(wrongCustomer)
	clear(wrongDigest[:])
	wrongKeyRequest.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
	wrongKeyResponse := httptest.NewRecorder()
	router.ServeHTTP(wrongKeyResponse, wrongKeyRequest)
	require.Equalf(t, http.StatusForbidden, wrongKeyResponse.Code, "wrong-key frontend HEAD response=%q", wrongKeyResponse.Body.String())
	require.Empty(t, wrongKeyResponse.Body.String(), "frontend HEAD responses are bodyless")
	require.Empty(t, wrongKeyResponse.Header().Get("ETag"))
	require.Empty(t, wrongKeyResponse.Header().Get("Content-Range"))
	require.Empty(t, wrongKeyResponse.Header().Get("Content-Length"))
	wrongKeyRequest.Header.Set(sseCustomerKey, "")
	wrongKeyRequest.Header.Set(sseCustomerMD5, "")
	require.True(t, sawWrongKey.Load(), "fixture must reject the wrong key value, not merely observe a key header")
	callsMu.Lock()
	gotCalls := append([]backendCall(nil), calls...)
	calls = nil
	callsMu.Unlock()
	require.Equal(t, []backendCall{{method: http.MethodHead, customerKeyPresent: true}}, gotCalls)
	require.Equal(t, float64(1), metricTotal(t, registry, "s3_operation_errors_total", `operation="HeadObject"`, `error_type="AccessDenied"`))
	require.Equal(t, float64(1), metricTotal(t, registry, "http_requests_total", `method="HEAD"`, `status="Forbidden"`))
	_, wrongKeyCacheRetained := h.cache.Get(t.Context(), "bucket", "key")
	require.True(t, wrongKeyCacheRetained, "keyed wrong-key denial must not consume or evict the unkeyed plaintext entry")
	validHeadForRecovery := signedCustomerRequest()
	validHeadForRecovery.Method = http.MethodHead
	validHeadForRecovery.URL.Path = "/bucket/key"
	validHeadForRecovery.RemoteAddr = "127.0.0.1:1234"
	validHeadForRecovery.Header.Set("X-Forwarded-Proto", "https")
	validHeadForRecovery.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, SignedHeaders=host;x-amz-server-side-encryption-customer-algorithm;x-amz-server-side-encryption-customer-key;x-amz-server-side-encryption-customer-key-md5, Signature=x")
	sawWrongKey.Store(false)
	callsMu.Lock()
	calls = nil
	callsMu.Unlock()
	headRecovery := httptest.NewRecorder()
	router.ServeHTTP(headRecovery, validHeadForRecovery)
	require.Equalf(t, http.StatusOK, headRecovery.Code, "correct-key HEAD response=%q", headRecovery.Body.String())
	require.Empty(t, headRecovery.Body.String())
	require.False(t, sawWrongKey.Load(), "correct key should not trip the backend's wrong-key oracle")
	callsMu.Lock()
	gotCalls = append([]backendCall(nil), calls...)
	calls = nil
	callsMu.Unlock()
	require.Equal(t, []backendCall{{method: http.MethodHead, customerKeyPresent: true}}, gotCalls, "correct-key recovery must use backend HEAD")

	issue := httptest.NewRequest(http.MethodGet, "https://gateway.example/bucket/key", nil)
	issue.TLS = &tls.ConnectionState{}
	issue.RemoteAddr = "127.0.0.1:1234"
	issue.Header.Set("X-Forwarded-Proto", "https")
	failed := httptest.NewRecorder()
	router.ServeHTTP(failed, issue)
	callsMu.Lock()
	gotCalls = append([]backendCall(nil), calls...)
	callsMu.Unlock()
	require.Equalf(t, http.StatusBadRequest, failed.Code, "actual SDK HEAD error response=%q backendCalls=%+v clientAcquires=%d", failed.Body.String(), gotCalls, clientAcquires.Load())
	require.Contains(t, failed.Body.String(), "<Code>InvalidArgument</Code>")
	require.NotContains(t, failed.Body.String(), "private backend canary")
	require.NotContains(t, failed.Body.Bytes(), plain)
	require.Empty(t, failed.Header().Get("ETag"))
	require.Empty(t, failed.Header().Get("Content-Range"))
	require.Empty(t, failed.Header().Get("Content-Length"))
	require.Equal(t, []backendCall{{method: http.MethodHead}}, gotCalls, "cache preflight must use exactly one unkeyed backend HEAD")
	require.Equal(t, float64(1), metricTotal(t, registry, "http_requests_total", `method="GET"`, `status="Bad Request"`))
	require.Equal(t, float64(1), metricTotal(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="InvalidArgument"`))
	_, stillCached := h.cache.Get(t.Context(), "bucket", "key")
	require.False(t, stillCached, "failed cache preflight must evict and never replay the seeded plaintext")

	// Frontend HEAD with cache disabled exercises the direct backend HEAD path.
	callsMu.Lock()
	calls = nil
	callsMu.Unlock()
	frontendHead := httptest.NewRequest(http.MethodHead, "https://gateway.example/bucket/key", nil)
	frontendHead.TLS = &tls.ConnectionState{}
	frontendHead.RemoteAddr = "127.0.0.1:1234"
	frontendHead.Header.Set("X-Forwarded-Proto", "https")
	deniedHead := httptest.NewRecorder()
	router.ServeHTTP(deniedHead, frontendHead)
	require.Equal(t, http.StatusBadRequest, deniedHead.Code)
	require.Empty(t, deniedHead.Body.String())
	callsMu.Lock()
	gotCalls = append([]backendCall(nil), calls...)
	callsMu.Unlock()
	require.Equal(t, []backendCall{{method: http.MethodHead}}, gotCalls)
	require.Equal(t, float64(1), metricTotal(t, registry, "s3_operation_errors_total", `operation="HeadObject"`, `error_type="InvalidArgument"`))

	// With cache disabled, a full missing-key GET reaches backend GET and the
	// SDK's XML InvalidRequest remains translated as the same fixed denial.
	callsMu.Lock()
	calls = nil
	callsMu.Unlock()
	h.cache = nil
	noCacheGet := httptest.NewRequest(http.MethodGet, "https://gateway.example/bucket/key", nil)
	noCacheGet.TLS = &tls.ConnectionState{}
	noCacheGet.RemoteAddr = "127.0.0.1:1234"
	noCacheGet.Header.Set("X-Forwarded-Proto", "https")
	deniedNoCache := httptest.NewRecorder()
	router.ServeHTTP(deniedNoCache, noCacheGet)
	require.Equal(t, http.StatusBadRequest, deniedNoCache.Code)
	require.Contains(t, deniedNoCache.Body.String(), "<Code>InvalidArgument</Code>")
	require.NotContains(t, deniedNoCache.Body.Bytes(), plain)
	require.Empty(t, deniedNoCache.Header().Get("ETag"))
	callsMu.Lock()
	gotCalls = append([]backendCall(nil), calls...)
	callsMu.Unlock()
	require.Equal(t, []backendCall{{method: http.MethodGet}}, gotCalls)
	require.Equal(t, float64(2), metricTotal(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="InvalidArgument"`))

	// A valid keyed read must succeed after the denied preflight and prove that
	// neither the cache nor the previous denial poisoned the request-local key.
	callsMu.Lock()
	calls = nil
	callsMu.Unlock()
	validGet := signedCustomerRequest()
	validGet.URL.Path = "/bucket/key"
	validGet.RemoteAddr = "127.0.0.1:1234"
	validGet.Header.Set("X-Forwarded-Proto", "https")
	getResponse := httptest.NewRecorder()
	router.ServeHTTP(getResponse, validGet)
	require.Equalf(t, http.StatusOK, getResponse.Code, "correct-key GET response=%q", getResponse.Body.String())
	require.Equal(t, plain, getResponse.Body.Bytes())
	callsMu.Lock()
	gotCalls = append([]backendCall(nil), calls...)
	callsMu.Unlock()
	require.Equal(t, []backendCall{{method: http.MethodGet, customerKeyPresent: true}}, gotCalls)

	callsMu.Lock()
	calls = nil
	callsMu.Unlock()
	validHead := signedCustomerRequest()
	validHead.Method = http.MethodHead
	validHead.URL.Path = "/bucket/key"
	validHead.RemoteAddr = "127.0.0.1:1234"
	validHead.Header.Set("X-Forwarded-Proto", "https")
	headResponse := httptest.NewRecorder()
	router.ServeHTTP(headResponse, validHead)
	require.Equal(t, http.StatusOK, headResponse.Code)
	require.Empty(t, headResponse.Body.String())
	callsMu.Lock()
	gotCalls = append([]backendCall(nil), calls...)
	callsMu.Unlock()
	require.Equal(t, []backendCall{{method: http.MethodHead, customerKeyPresent: true}}, gotCalls)

	// The same bodyless SDK HEAD error translates identically for range
	// planning, whose frontend operation is still GET.
	callsMu.Lock()
	calls = nil
	callsMu.Unlock()
	rangeRequest := httptest.NewRequest(http.MethodGet, "https://gateway.example/bucket/key", nil)
	rangeRequest.TLS = &tls.ConnectionState{}
	rangeRequest.Header.Set("Range", "bytes=0-7")
	rangeResponse := httptest.NewRecorder()
	router.ServeHTTP(rangeResponse, rangeRequest)
	require.Equal(t, http.StatusBadRequest, rangeResponse.Code)
	require.Contains(t, rangeResponse.Body.String(), "<Code>InvalidArgument</Code>")
	require.NotContains(t, rangeResponse.Body.Bytes(), plain)
	callsMu.Lock()
	gotCalls = append([]backendCall(nil), calls...)
	callsMu.Unlock()
	require.Equal(t, []backendCall{{method: http.MethodHead}}, gotCalls)
	require.Equal(t, float64(3), metricTotal(t, registry, "s3_operation_errors_total", `operation="GetObject"`, `error_type="InvalidArgument"`), "cached, un-cached, and ranged GET failures each count once as GetObject")
}

func TestGH353SSEC_NoCacheReplayOrCapture(t *testing.T) {
	oldEngine, err := crypto.NewEngineWithOpts([]byte("sse cache rotation fixture"), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	defer func() {
		if c, ok := oldEngine.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	activeEngine, err := crypto.NewEngineWithOpts([]byte("sse cache rotation fixture"), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	defer func() {
		if c, ok := activeEngine.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	plain := bytes.Repeat([]byte("cache-body-"), 1000)
	sealed, metadata, err := oldEngine.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), nil)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(sealed)
	require.NoError(t, err)
	metadata["Content-Length"] = strconv.Itoa(len(ciphertext))
	metadata["ETag"] = `"sse-backend"`
	metadata[sseCustomerAlg] = "AES256"
	metadata["Cache-Control"] = "private"
	base := newMockS3Client()
	base.objects["bucket/key"] = ciphertext
	base.metadata["bucket/key"] = metadata
	client := &sseAdvancedStub{Client: base, metadata: metadata, body: ciphertext, wantKey: bytes.Repeat([]byte{0x6b}, 32), denyUnkeyedSSE: true}
	counted := &sseCountingCache{Cache: cache.NewMemoryCache(1<<20, 4, time.Minute)}
	cfg := &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}, Cache: config.CacheConfig{MaxSize: 1 << 20}}
	h := NewHandlerWithFeatures(client, activeEngine, logrus.New(), metrics.NewMetricsWithRegistry(prometheus.NewRegistry()), nil, counted, nil, cfg, nil)
	h.clientAcquirer = func(*http.Request) (s3.Client, error) { return client, nil }
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	handler := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(AuthorizationMiddleware("", nil)(router))
	entryWriter := counted.Cache.(cache.EntryWriter)
	require.NoError(t, entryWriter.SetEntry(t.Context(), "bucket", "key", &cache.CacheEntry{Data: []byte("cached plaintext"), BackendETag: `"old"`, Source: []byte(`{"PlainSize":16}`)}, time.Minute))
	counted.resetCounts()
	request := signedCustomerRequest()
	require.NoError(t, v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, request, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	require.Equal(t, plain, recorder.Body.Bytes())
	require.Equal(t, 0, counted.getCalls, "incoming SSE-C skips cache lookup")
	require.Equal(t, 0, counted.setCalls, "incoming SSE-C plaintext is never captured")
	entry, cacheFound := counted.Cache.Get(context.Background(), "bucket", "key")
	require.True(t, cacheFound)
	require.Equal(t, []byte("cached plaintext"), entry.Data)
	require.NotZero(t, len(client.keyBacking))
	require.Equal(t, bytes.Repeat([]byte{0}, 32), client.keyBacking, "key bytes are zeroized after synchronous handler cleanup")

	// No request key: HEAD is always performed before cache lookup and its key
	// requirement cannot be bypassed by a seeded plaintext cache entry.
	keyRequired := httptest.NewRecorder()
	noKey := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	noKey = mux.SetURLVars(attachTestCredential(noKey), map[string]string{"bucket": "bucket", "key": "key"})
	h.handleGetObject(keyRequired, noKey)
	require.NotEqual(t, http.StatusOK, keyRequired.Code)
	require.NotContains(t, keyRequired.Body.String(), "cached plaintext")
	_, cacheFound = counted.Cache.Get(context.Background(), "bucket", "key")
	require.False(t, cacheFound, "backend key-required denial evicts cached plaintext")

	// A successful unkeyed HEAD that identifies backend SSE-C still cannot
	// replay a seeded cache entry; the subsequent body read must receive a key.
	metaOnly := map[string]string{sseCustomerAlg: "AES256", "Content-Length": strconv.Itoa(len(ciphertext)), "ETag": `"sse-backend"`}
	client.metadata = metaOnly
	base.metadata["bucket/key"] = metaOnly
	client.denyUnkeyedSSE = false
	require.NoError(t, entryWriter.SetEntry(t.Context(), "bucket", "key", &cache.CacheEntry{Data: []byte("cached plaintext"), BackendETag: `"sse-backend"`, Source: []byte(`{"PlainSize":16}`)}, time.Minute))
	declared := httptest.NewRecorder()
	declaredRequest := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	declaredRequest = mux.SetURLVars(attachTestCredential(declaredRequest), map[string]string{"bucket": "bucket", "key": "key"})
	h.handleGetObject(declared, declaredRequest)
	require.NotEqual(t, http.StatusOK, declared.Code)
	require.NotContains(t, declared.Body.String(), "cached plaintext")
	_, cacheFound = counted.Cache.Get(context.Background(), "bucket", "key")
	require.False(t, cacheFound, "HEAD-detected SSE-C entry is evicted, not replayed")

	// Positive control: a non-SSE encrypted GET fills and then reuses cache.
	plainMetadata := cloneStringMap(metadata)
	delete(plainMetadata, sseCustomerAlg)
	plainBase := newMockS3Client()
	plainBase.objects["bucket/key"] = ciphertext
	plainBase.metadata["bucket/key"] = plainMetadata
	plainClient := &sseAdvancedStub{Client: plainBase, metadata: plainMetadata, body: ciphertext}
	plainHandler := NewHandlerWithFeatures(plainClient, activeEngine, logrus.New(), metrics.NewMetricsWithRegistry(prometheus.NewRegistry()), nil, counted, nil, cfg, nil)
	plainHandler.clientAcquirer = func(*http.Request) (s3.Client, error) { return plainClient, nil }
	counted.resetCounts()
	first := httptest.NewRecorder()
	firstRequest := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	firstRequest = mux.SetURLVars(attachTestCredential(firstRequest), map[string]string{"bucket": "bucket", "key": "key"})
	plainHandler.handleGetObject(first, firstRequest)
	require.Equal(t, http.StatusOK, first.Code)
	require.Equal(t, plain, first.Body.Bytes())
	require.Equal(t, 1, counted.setCalls)
	counted.resetCounts()
	second := httptest.NewRecorder()
	secondRequest := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	secondRequest = mux.SetURLVars(attachTestCredential(secondRequest), map[string]string{"bucket": "bucket", "key": "key"})
	plainHandler.handleGetObject(second, secondRequest)
	require.Equal(t, http.StatusOK, second.Code)
	require.Equal(t, plain, second.Body.Bytes())
	require.Equal(t, 1, counted.getCalls)
}

type sseCountingCache struct {
	cache.Cache
	getCalls, setCalls, deleteCalls int
}

type countingSSEStateStore struct{ calls atomic.Int32 }

func (s *countingSSEStateStore) Create(context.Context, *mpu.UploadState) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) Get(context.Context, string) (*mpu.UploadState, error) {
	s.calls.Add(1)
	return nil, errors.New("unexpected state call")
}
func (s *countingSSEStateStore) ReservePart(context.Context, string, mpu.PartClaim) (mpu.Reservation, error) {
	s.calls.Add(1)
	return mpu.Reservation{}, errors.New("unexpected state call")
}
func (s *countingSSEStateStore) RenewPart(context.Context, string, int32, string) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) ReleasePart(context.Context, string, int32, string) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) CommitPart(context.Context, string, mpu.PartClaim) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) BeginComplete(context.Context, string, []mpu.SelectedPart) (*mpu.UploadState, uint64, error) {
	s.calls.Add(1)
	return nil, 0, errors.New("unexpected state call")
}
func (s *countingSSEStateStore) Reopen(context.Context, string, uint64) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) FinalizeComplete(context.Context, string, uint64) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) BeginAbort(context.Context, string) (uint64, error) {
	s.calls.Add(1)
	return 0, errors.New("unexpected state call")
}
func (s *countingSSEStateStore) FinalizeAbort(context.Context, string, uint64) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) Delete(context.Context, string) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) List(context.Context) ([]mpu.UploadState, error) {
	s.calls.Add(1)
	return nil, errors.New("unexpected state call")
}
func (s *countingSSEStateStore) HealthCheck(context.Context) error {
	s.calls.Add(1)
	return errors.New("unexpected state call")
}
func (s *countingSSEStateStore) Close() error { return nil }

func (c *sseCountingCache) Get(ctx context.Context, bucket, key string) (*cache.CacheEntry, bool) {
	c.getCalls++
	return c.Cache.Get(ctx, bucket, key)
}
func (c *sseCountingCache) Set(ctx context.Context, bucket, key string, data []byte, metadata map[string]string, ttl time.Duration) error {
	c.setCalls++
	return c.Cache.Set(ctx, bucket, key, data, metadata, ttl)
}
func (c *sseCountingCache) SetEntry(ctx context.Context, bucket, key string, entry *cache.CacheEntry, ttl time.Duration) error {
	c.setCalls++
	return c.Cache.(cache.EntryWriter).SetEntry(ctx, bucket, key, entry, ttl)
}
func (c *sseCountingCache) Delete(ctx context.Context, bucket, key string) error {
	c.deleteCalls++
	return c.Cache.Delete(ctx, bucket, key)
}
func (c *sseCountingCache) resetCounts() { c.getCalls, c.setCalls, c.deleteCalls = 0, 0, 0 }

type rotationSSEAdvancedClient struct {
	*mockS3Client
	body     []byte
	metadata map[string]string
}

func (c *rotationSSEAdvancedClient) GetObject(_ context.Context, _, _ string, _, _ *string) (io.ReadCloser, map[string]string, error) {
	c.getObjectCallCount++
	return io.NopCloser(bytes.NewReader(c.body)), c.metadata, nil
}
func (c *rotationSSEAdvancedClient) HeadObject(_ context.Context, _, _ string, _ *string) (map[string]string, error) {
	c.headObjectCallCount++
	return c.metadata, nil
}
func (c *rotationSSEAdvancedClient) PutObject(_ context.Context, _, _ string, _ io.Reader, _ map[string]string, _ *int64, _ string, _ *s3.ObjectLockInput, _, _, _, _, _ string) (string, error) {
	c.putObjectCallCount++
	return "", nil
}

func TestGH353SSEC_NoAutomaticRotation(t *testing.T) {
	oldKey, err := crypto.NewInMemoryKeyManager(bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	defer oldKey.Close(context.Background())
	activeKey, err := crypto.NewInMemoryKeyManager(bytes.Repeat([]byte{1}, 32), crypto.WithMemoryVersions([]struct {
		Version int
		Key     []byte
	}{{Version: 1, Key: bytes.Repeat([]byte{1}, 32)}, {Version: 2, Key: bytes.Repeat([]byte{2}, 32)}}))
	require.NoError(t, err)
	defer activeKey.Close(context.Background())
	oldEngine, err := crypto.NewEngineWithOpts([]byte("rotation test password"), crypto.WithKeyManager(oldKey), crypto.WithProvider("aws"))
	require.NoError(t, err)
	activeEngine, err := crypto.NewEngineWithOpts([]byte("rotation test password"), crypto.WithKeyManager(activeKey), crypto.WithProvider("aws"))
	require.NoError(t, err)
	plain := []byte("encrypted old version")
	sealed, metadata, err := oldEngine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), nil)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(sealed)
	require.NoError(t, err)
	metadata["x-amz-server-side-encryption-customer-algorithm"] = "AES256"
	client := &rotationSSEAdvancedClient{mockS3Client: newMockS3Client(), body: ciphertext, metadata: metadata}
	h := &Handler{keyManager: activeKey}
	plan := objectReadPlan{Bucket: "bucket", Key: "key", Mode: objectReadFull, CacheEligible: true, Source: objectResponseSource{Meta: metadata}}
	r := signedCustomerRequest()
	out := httptest.NewRecorder()
	h.servePlannedGetObject(out, r, client, activeEngine, nil, plan, time.Now())
	require.Equal(t, http.StatusOK, out.Code)
	require.Equal(t, plain, out.Body.Bytes())
	require.Equal(t, 0, client.putObjectCallCount)
}

func TestGH353SSEC_CopyAndMPURejected(t *testing.T) {
	operations := []struct {
		name, method, path string
		selector           string
		copy               bool
	}{
		{"CopyObject", http.MethodPut, "/bucket/destination", "", true},
		{"CreateMultipartUpload", http.MethodPost, "/bucket/key?uploads=", "uploads", false},
		{"UploadPart", http.MethodPut, "/bucket/key?partNumber=1&uploadId=u", "partNumber", false},
		{"UploadPartCopy", http.MethodPut, "/bucket/key?partNumber=1&uploadId=u", "partNumber", true},
		{"CompleteMultipartUpload", http.MethodPost, "/bucket/key?uploadId=u", "uploadId", false},
		{"AbortMultipartUpload", http.MethodDelete, "/bucket/key?uploadId=u", "uploadId", false},
		{"ListParts", http.MethodGet, "/bucket/key?uploadId=u", "uploadId", false},
	}
	state := &countingSSEStateStore{}
	for _, op := range operations {
		for _, input := range []string{"header", "presigned-query"} {
			t.Run(op.name+"/"+input, func(t *testing.T) {
				backend := &failOnAnyCallS3Client{t: t}
				h := NewHandlerWithFeatures(backend, nil, logrus.New(), getTestMetrics(), nil, nil, nil, &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}, nil)
				h.WithMPUStateStore(state)
				rawQuery := ""
				if op.path != "" {
					if i := strings.IndexByte(op.path, '?'); i >= 0 {
						rawQuery = op.path[i+1:]
					}
				}
				path := op.path
				if i := strings.IndexByte(path, '?'); i >= 0 {
					path = path[:i]
				}
				req := httptest.NewRequest(op.method, "https://gateway.example"+path, strings.NewReader("unread body"))
				req.URL.RawQuery = rawQuery
				req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
				if op.copy {
					req.Header.Set("x-amz-copy-source", "/bucket/source")
				}
				if input == "header" {
					for name, value := range sseCustomerFields() {
						req.Header.Set(name, value)
					}
					if op.copy {
						for name, value := range sseCustomerFields() {
							req.Header.Set(strings.Replace(name, "x-amz-server-side-encryption-customer-", "x-amz-copy-source-server-side-encryption-customer-", 1), value)
						}
					}
				} else {
					query, err := url.ParseQuery(rawQuery)
					require.NoError(t, err)
					for name, value := range sseCustomerFields() {
						canonical := map[string]string{sseCustomerAlg: "X-Amz-Server-Side-Encryption-Customer-Algorithm", sseCustomerKey: "X-Amz-Server-Side-Encryption-Customer-Key", sseCustomerMD5: "X-Amz-Server-Side-Encryption-Customer-Key-MD5"}[name]
						query.Set(canonical, value)
						if op.copy {
							query.Set(strings.Replace(canonical, "X-Amz-Server-Side-Encryption-Customer-", "X-Amz-Copy-Source-Server-Side-Encryption-Customer-", 1), value)
						}
					}
					query.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
					query.Set("X-Amz-Credential", "AKIAIOSFODNN7EXAMPLE/"+time.Now().UTC().Format("20060102")+"/us-east-1/s3/aws4_request")
					query.Set("X-Amz-Date", time.Now().UTC().Format("20060102T150405Z"))
					query.Set("X-Amz-Expires", "300")
					query.Set("X-Amz-SignedHeaders", "host")
					headers := make(http.Header)
					if op.copy {
						headers.Set("x-amz-copy-source", "/bucket/source")
					}
					req = signPresignedRawRequest(t, op.method, path, query.Encode(), headers, "")
					req.Body = io.NopCloser(strings.NewReader("unread body"))
				}
				bodyReader := strings.NewReader("unread body")
				req.Body = io.NopCloser(bodyReader)
				if input == "header" {
					req.TLS = &tls.ConnectionState{}
					require.NoError(t, v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC()))
				}
				signing, sigErr := ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", time.Minute)
				require.NoError(t, sigErr, "independently signed operation shape must authenticate")
				signing.Close()
				router := mux.NewRouter()
				h.RegisterRoutes(router)
				matched := mux.RouteMatch{}
				require.True(t, router.Match(req, &matched), "request should match a registered route: method=%s path=%q rawquery=%q url=%s", req.Method, req.URL.Path, req.URL.RawQuery, req.URL.String())
				wantRoute := op.name
				if op.name == "CopyObject" {
					wantRoute = "PutObject"
				}
				if op.name == "UploadPartCopy" {
					wantRoute = "UploadPart"
				}
				require.Equal(t, wantRoute, matched.Route.GetName())
				acquisitions := 0
				h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions++; return backend, nil }
				var handler http.Handler = AuthorizationMiddleware("", nil)(router)
				handler = AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(handler)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				require.Equal(t, http.StatusNotImplemented, response.Code)
				require.Contains(t, response.Body.String(), "<Code>NotImplemented</Code>")
				require.Zero(t, backend.callCount.Load())
				require.Zero(t, acquisitions)
				require.Zero(t, state.calls.Load(), "rejection precedes persistent MPU state access")
				require.Equal(t, len("unread body"), bodyReader.Len(), "test body remains unconsumed")
			})
		}
	}

	for _, tc := range []struct {
		name, method, path, operation string
		field, value                  string
	}{
		{"copy destination triplet", http.MethodPut, "/bucket/destination", "PutObject", sseCustomerAlg, "AES256"},
		{"copy source triplet", http.MethodPut, "/bucket/destination", "PutObject", "x-amz-copy-source-server-side-encryption-customer-key", "secret"},
		{"create MPU", http.MethodPost, "/bucket/key?uploads", "CreateMultipartUpload", sseCustomerAlg, "AES256"},
		{"upload part", http.MethodPut, "/bucket/key?partNumber=1&uploadId=u", "UploadPart", sseCustomerAlg, "AES256"},
		{"upload part copy", http.MethodPut, "/bucket/key?partNumber=1&uploadId=u", "UploadPartCopy", "x-amz-copy-source-server-side-encryption-customer-key", "secret"},
		{"complete MPU", http.MethodPost, "/bucket/key?uploadId=u", "CompleteMultipartUpload", sseCustomerAlg, "AES256"},
		{"abort MPU", http.MethodDelete, "/bucket/key?uploadId=u", "AbortMultipartUpload", sseCustomerMD5, "secret"},
		{"list parts", http.MethodGet, "/bucket/key?uploadId=u", "ListParts", sseCustomerAlg, "AES256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &failOnAnyCallS3Client{t: t}
			cfg := &config.Config{Backend: config.BackendConfig{Endpoint: "https://store.example", UseSSL: true}}
			h := NewHandlerWithFeatures(backend, nil, logrus.New(), getTestMetrics(), nil, nil, nil, cfg, nil)
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("unread body"))
			req.Header.Set(tc.field, tc.value)
			req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
			req = mux.SetURLVars(req, map[string]string{"bucket": "bucket", "key": "key", "uploadId": "u", "partNumber": "1"})
			if strings.Contains(tc.name, "copy") {
				req.Header.Set("x-amz-copy-source", "/bucket/source")
			}
			if tc.name == "copy destination triplet" || tc.name == "create MPU" || tc.name == "upload part" || tc.name == "complete MPU" || tc.name == "list parts" {
				for name, value := range sseCustomerFields() {
					req.Header.Set(name, value)
				}
			}
			req.TLS = &tls.ConnectionState{}
			require.NoError(t, v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC()))
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			acquisitions := 0
			h.clientAcquirer = func(*http.Request) (s3.Client, error) { acquisitions++; return backend, nil }
			handler := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(AuthorizationMiddleware("", nil)(router))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			require.Equal(t, http.StatusNotImplemented, recorder.Code, recorder.Body.String())
			require.Contains(t, recorder.Body.String(), "<Code>NotImplemented</Code>")
			require.Zero(t, backend.callCount.Load(), "backend/client work must not precede fixed rejection")
			require.Zero(t, acquisitions, "client acquisition must not precede fixed rejection")
			body, err := io.ReadAll(req.Body)
			require.NoError(t, err)
			require.Equal(t, "unread body", string(body), "handler rejection occurs before body consumption")
		})
	}
}
