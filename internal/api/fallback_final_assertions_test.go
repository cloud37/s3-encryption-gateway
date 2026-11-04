package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestGH353FallbackKeyedGETAndRangeHeaderAuthority(t *testing.T) {
	e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithProvider("aws"), crypto.WithChunking(true), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	require.NoError(t, err)
	t.Cleanup(func() { _ = e.(io.Closer).Close() })
	key := bytes.Repeat([]byte{5}, 32)
	crypto.SetMetadataKey(e, key)
	t.Cleanup(func() { clear(key) })
	plain := []byte("0123456789-keyed-fallback-plaintext")
	ordinary := strings.Repeat("v", 7900)
	standards := map[string]string{
		"Content-Type": "application/safe", "Cache-Control": "private, max-age=42",
		"Content-Disposition": "attachment; filename=safe.txt", "Content-Encoding": "gzip",
		"Content-Language": "en", "Expires": "Wed, 21 Oct 2037 07:28:00 GMT",
	}
	input := map[string]string{"x-amz-meta-extra": ordinary, "Content-Length": strconv.Itoa(len(plain))}
	for k, v := range standards {
		input[k] = v
	}
	stream, header, err := e.Encrypt(t.Context(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(plain), input)
	require.NoError(t, err)
	data, err := io.ReadAll(stream)
	require.NoError(t, err)
	expanded, err := crypto.ExpandMetadataForAPI(header)
	require.NoError(t, err)
	require.Equal(t, "2", expanded[crypto.MetaFallbackVersion])
	require.NotEmpty(t, expanded[crypto.MetaEncryptedMetadata])
	require.Empty(t, header["x-amz-meta-extra"])
	require.NoError(t, crypto.GetProviderProfile("aws").ValidateMetadataSize(header))
	// Demonstrate the header blob authenticates and supplies every protected value.
	authenticated, err := e.(interface {
		APIExpandedMetadata(map[string]string) (map[string]string, error)
	}).APIExpandedMetadata(header)
	require.NoError(t, err)
	for _, spec := range crypto.ProtectedStandardKeys() {
		require.Equal(t, standards[spec.Header], authenticated[spec.Canonical], spec.Header)
	}
	n := int(binary.BigEndian.Uint32(data[:4]))
	var prefix map[string]string
	require.NoError(t, json.Unmarshal(data[4:4+n], &prefix))
	for _, spec := range crypto.ProtectedStandardKeys() {
		delete(prefix, spec.Canonical)
		prefix[spec.Header] = "attacker"
		if spec.Compact != "" {
			prefix[strings.ToUpper(spec.Compact)] = "attacker"
		}
	}
	delete(prefix, crypto.MetaEncryptedMetadata)
	prefix[crypto.MetaEncryptedMetadataCompact] = "substituted-blob"
	prefix["X-Amz-Meta-A"] = "invalid-algorithm"
	prefix[crypto.MetaObjectFormatVersion] = "invalid-format"
	prefix[crypto.MetaManifest] = "invalid-manifest"
	encoded, err := json.Marshal(prefix)
	require.NoError(t, err)
	frame := make([]byte, 4)
	binary.BigEndian.PutUint32(frame, uint32(len(encoded)))
	data = append(append(frame, encoded...), data[4+n:]...)
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
	}{
		{"full", "", plain, http.StatusOK}, {"range", "bytes=2-7", plain[2:8], http.StatusPartialContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), map[string]string{"bucket": "bucket", "key": "key"})
			if tc.interval != "" {
				req.Header.Set("Range", tc.interval)
			}
			w := httptest.NewRecorder()
			h.handleGetObject(w, req)
			require.Equal(t, tc.status, w.Code)
			require.Equal(t, tc.want, w.Body.Bytes())
			require.Equal(t, ordinary, w.Header().Get("x-amz-meta-extra"))
			for k, v := range standards {
				require.Equal(t, v, w.Header().Get(k), k)
			}
			if tc.interval != "" {
				require.Equal(t, fmt.Sprintf("bytes 2-7/%d", len(plain)), w.Header().Get("Content-Range"))
			}
		})
	}
	// A substituted header blob cannot be rescued by an untrusted prefix blob.
	for k := range header {
		if spec, ok := crypto.LookupMetaKey(k); ok && spec.Canonical == crypto.MetaEncryptedMetadata {
			header[k] = "invalid-header-blob"
		}
	}
	for _, interval := range []string{"", "bytes=2-7"} {
		req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/bucket/key", nil), map[string]string{"bucket": "bucket", "key": "key"})
		if interval != "" {
			req.Header.Set("Range", interval)
		}
		w := httptest.NewRecorder()
		h.handleGetObject(w, req)
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.NotContains(t, w.Body.String(), string(plain))
		require.Empty(t, w.Header().Get("x-amz-meta-extra"))
		require.NotEqual(t, "application/safe", w.Header().Get("Content-Type"))
	}
}

type fallbackCountingBody struct {
	reader       *bytes.Reader
	read, closes int
}

func (r *fallbackCountingBody) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}
func (r *fallbackCountingBody) Close() error { r.closes++; return nil }

type fallbackLongClient struct {
	*fallbackHeadStub
	body              *fallbackCountingBody
	rangeValue, match string
	calls             int
}

func (c *fallbackLongClient) GetObjectIfMatch(_ context.Context, _, _ string, _ *string, interval *string, match string, _ s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	c.calls++
	if interval != nil {
		c.rangeValue = *interval
	}
	c.match = match
	return c.body, c.get, nil
}

func TestGH353FallbackLongHeadBoundedRange(t *testing.T) {
	const max = crypto.MaxFallbackPrefixBytes
	total := max + 97
	for _, tc := range []struct {
		name         string
		bodyLength   int
		badRange, ok bool
		wantRead     int
	}{
		{"valid", max, false, true, max},
		{"overlong", total, false, false, max + 1},
		{"truncated", max - 1, false, false, max - 1},
		{"inconsistent range", max, true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := fallbackFixture()
			prefix := append([]byte(nil), fixture.data...)
			object := make([]byte, total)
			copy(object, prefix)
			// The parser consumes only framed JSON and leaves the chunk bytes untouched.
			prefixReader := bytes.NewReader(object[:max])
			parsed, err := crypto.ReadFallbackV2Prefix(t.Context(), prefixReader)
			require.NoError(t, err)
			require.Equal(t, "restored", parsed["x-amz-meta-extra"])
			require.Equal(t, max-len(prefix), prefixReader.Len())
			fixture.head["Content-Length"] = strconv.Itoa(total)
			fixture.get["Content-Length"] = strconv.Itoa(max)
			fixture.get["Content-Range"] = fmt.Sprintf("bytes 0-%d/%d", max-1, total)
			if tc.badRange {
				fixture.get["Content-Range"] = fmt.Sprintf("bytes 0-%d/%d", max-2, total)
			}
			body := &fallbackCountingBody{reader: bytes.NewReader(object[:tc.bodyLength])}
			client := &fallbackLongClient{fallbackHeadStub: fixture, body: body}
			e, err := crypto.NewEngineWithOpts([]byte("test-password-1234567890"), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
			require.NoError(t, err)
			t.Cleanup(func() { _ = e.(io.Closer).Close() })
			h := NewHandlerWithFeatures(client, e, logrus.New(), getTestMetrics(), nil, nil, nil, &config.Config{}, nil)
			req := mux.SetURLVars(httptest.NewRequest(http.MethodHead, "/bucket/key", nil), map[string]string{"bucket": "bucket", "key": "key"})
			w := httptest.NewRecorder()
			h.handleHeadObject(w, req)
			require.Equal(t, 1, client.calls)
			require.Equal(t, fmt.Sprintf("bytes=0-%d", max-1), client.rangeValue)
			require.Equal(t, `"cipher"`, client.match)
			require.Equal(t, tc.wantRead, body.read)
			require.LessOrEqual(t, body.read, max+1)
			require.Equal(t, 1, body.closes)
			if tc.ok {
				require.Equal(t, 200, w.Code)
				require.Equal(t, "restored", w.Header().Get("x-amz-meta-extra"))
			} else {
				require.Equal(t, 500, w.Code)
				require.Empty(t, w.Header().Get("x-amz-meta-extra"))
				require.Empty(t, w.Header().Get("ETag"))
			}
		})
	}
}
