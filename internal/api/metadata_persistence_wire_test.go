package api

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestGH353MetadataPersistenceSDKWire(t *testing.T) {
	value := strings.Repeat("v", 7900)
	var stored []byte
	var headers http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		stored, err = io.ReadAll(r.Body)
		require.NoError(t, err)
		headers = r.Header.Clone()
		require.Equal(t, int64(len(stored)), r.ContentLength)
		digest := md5.Sum(stored)
		require.Equal(t, base64.StdEncoding.EncodeToString(digest[:]), r.Header.Get("Content-MD5"))
		w.Header().Set("ETag", `"cipher"`)
	}))
	t.Cleanup(server.Close)
	cfg := &config.Config{Backend: config.BackendConfig{Endpoint: server.URL, Provider: "backblaze-b2", MetadataProfile: "compact", AccessKey: "backend", SecretKey: "secret", UsePathStyle: true, Retry: config.BackendRetryConfig{Mode: "off"}}}
	client, err := s3.NewClientFactory(&cfg.Backend).GetClient()
	require.NoError(t, err)
	engine, err := crypto.NewEngineWithOpts([]byte("wire-metadata-test-password"), crypto.WithMetadataProfile(cfg.Backend.Provider, cfg.Backend.MetadataProfile), crypto.WithChunking(true), crypto.WithMetadataKey(bytes.Repeat([]byte{4}, 32)), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	t.Cleanup(func() { _ = engine.(io.Closer).Close() })
	h := NewHandlerWithFeatures(client, engine, logrus.New(), getTestMetrics(), nil, nil, nil, cfg, nil)
	h.spoolManager = NewSpoolManager(4<<20, t.TempDir())
	plain := []byte("actual spooled ciphertext over sdk")
	_, err = h.putObjectData(t.Context(), client, objectWriteInput{Bucket: "bucket", Key: "key", Operation: "PostObject", Body: bytes.NewReader(plain), PlainLength: int64(len(plain)), HaveLength: true, Metadata: writeMetadata{User: map[string]string{"x-amz-meta-overflow": value, "x-amz-meta-owner": "owner"}}})
	require.NoError(t, err)
	require.NotEqual(t, plain, stored)
	require.Empty(t, headers.Get("X-Amz-Meta-Overflow"))
	require.Equal(t, "owner", headers.Get("X-Amz-Meta-Owner"))
	require.NotEmpty(t, headers.Get("X-Amz-Meta-Em"))
	require.Empty(t, headers.Get("X-Amz-Meta-Enc-Metadata"))
	require.Equal(t, "true", headers.Get("X-Amz-Meta-Encrypted"))
	require.Empty(t, headers.Get("X-Amz-Meta-E"))
	meta := map[string]string{}
	for k, vals := range headers {
		if strings.HasPrefix(strings.ToLower(k), "x-amz-meta-") {
			require.Len(t, vals, 1)
			meta[strings.ToLower(k)] = vals[0]
		}
	}
	profile, err := crypto.ResolveMetadataProfile(cfg.Backend.Provider, cfg.Backend.MetadataProfile)
	require.NoError(t, err)
	require.NoError(t, profile.ValidateMetadataSize(meta))
	prefix, err := crypto.ReadFallbackV2Prefix(t.Context(), bytes.NewReader(stored))
	require.NoError(t, err)
	require.Equal(t, value, prefix["x-amz-meta-overflow"])
	reader, restored, err := engine.Decrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(stored), meta)
	require.NoError(t, err)
	data, err := io.ReadAll(reader)
	require.NoError(t, err)
	require.Equal(t, plain, data)
	require.Equal(t, value, restored["x-amz-meta-overflow"])
}

func TestGH353MetadataPersistencePUTErrorCompatibility(t *testing.T) {
	engine, err := crypto.NewEngineWithOpts([]byte("wire-metadata-test-password"), crypto.WithProvider("aws"), crypto.WithChunking(true), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	t.Cleanup(func() { _ = engine.(io.Closer).Close() })
	backend := newMockS3Client()
	h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
	request := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("data"))
	request.Header.Set("Content-Type", strings.Repeat("x", 3000))
	request = mux.SetURLVars(request, map[string]string{"bucket": "bucket", "key": "key"})
	w := httptest.NewRecorder()
	h.handlePutObject(w, request)
	require.Equal(t, http.StatusInternalServerError, w.Code)
	require.Contains(t, w.Body.String(), "<Code>InternalError</Code>")
	require.NotContains(t, w.Body.String(), "MetadataTooLarge")
	require.Zero(t, backend.putObjectCallCount)
}
