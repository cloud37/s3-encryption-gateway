package api

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/sizecache"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

type gh353AdvancedPutClient struct {
	*mockS3Client
	options                  s3.ObjectPutOptions
	puts                     int
	tags                     string
	acl                      string
	plainLength              *int64
	putMetadata              map[string]string
	lastPutOptions           s3.ObjectPutOptions
	putError                 error
	readBody                 []byte
	responseHeaders          map[string]string
	responseETag             string
	customerKeyLiveAtBackend bool
	customerKeyBacking       []byte
	customerKeyAtBackend     []byte
	duringPut                func()
}

func (c *gh353AdvancedPutClient) PutObjectWithOptions(_ context.Context, bucket, key string, body io.Reader, metadata map[string]string, length *int64, tags string, lock *s3.ObjectLockInput, acl, full, read, readACP, writeACP string, options s3.ObjectPutOptions) (s3.PutObjectResult, error) {
	c.puts++
	c.options = options
	c.lastPutOptions = options
	c.tags, c.acl = tags, acl
	if length != nil {
		v := *length
		c.plainLength = &v
	} else {
		c.plainLength = nil
	}
	c.putMetadata = make(map[string]string, len(metadata))
	for name, value := range metadata {
		c.putMetadata[name] = value
	}
	if c.duringPut != nil {
		c.duringPut()
	}
	if options.SSE != nil && options.SSE.Customer != nil {
		c.customerKeyBacking = options.SSE.Customer.Key
		c.customerKeyAtBackend = append([]byte(nil), options.SSE.Customer.Key...)
		c.customerKeyLiveAtBackend = len(options.SSE.Customer.Key) == 32 && !bytes.Equal(options.SSE.Customer.Key, make([]byte, 32))
	}
	if c.putError != nil {
		return s3.PutObjectResult{}, c.putError
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return s3.PutObjectResult{}, err
	}
	c.readBody = append([]byte(nil), data...)
	etag, err := c.mockS3Client.PutObject(context.Background(), bucket, key, bytes.NewReader(data), metadata, length, tags, lock, acl, full, read, readACP, writeACP)
	headers := map[string]string{"x-amz-storage-class": options.StorageClass}
	for key, value := range c.responseHeaders {
		headers[key] = value
	}
	if c.responseETag != "" {
		etag = c.responseETag
	}
	return s3.PutObjectResult{ETag: etag, VersionID: "version-1", Headers: headers}, err
}

type gh353AuditWriter struct{ events []*audit.AuditEvent }

func (w *gh353AuditWriter) WriteEvent(event *audit.AuditEvent) error {
	w.events = append(w.events, event)
	return nil
}

type gh353AuditCallback struct {
	audit.Logger
	onEncrypt func()
}

type gh353AccountingAudit struct {
	audit.Logger
	calls int
}

func (a *gh353AccountingAudit) LogEncrypt(string, string, string, int, bool, error, time.Duration, map[string]interface{}) {
	a.calls++
}

func (a *gh353AuditCallback) LogEncrypt(bucket, key, algorithm string, keyVersion int, success bool, err error, duration time.Duration, metadata map[string]interface{}) {
	if a.onEncrypt != nil {
		a.onEncrypt()
	}
}

func (c *gh353AdvancedPutClient) GetObjectWithOptions(ctx context.Context, bucket, key string, versionID, rangeHeader *string, _ s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	return c.mockS3Client.GetObject(ctx, bucket, key, versionID, rangeHeader)
}
func (c *gh353AdvancedPutClient) HeadObjectWithOptions(ctx context.Context, bucket, key string, versionID *string, _ s3.ObjectReadOptions) (map[string]string, error) {
	return c.mockS3Client.HeadObject(ctx, bucket, key, versionID)
}

type gh353NoProfileEngine struct{ calls int }

func (e *gh353NoProfileEngine) Encrypt(_ context.Context, _ crypto.ObjectContext, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	e.calls++
	b, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}
	return bytes.NewReader(append([]byte("sealed:"), b...)), map[string]string{crypto.MetaEncrypted: "true", crypto.MetaObjectFormatVersion: "buffered-v2", crypto.MetaAlgorithm: "AES256-GCM", crypto.MetaOriginalSize: metadata["Content-Length"], crypto.MetaOriginalETag: metadata["ETag"]}, nil
}
func (e *gh353NoProfileEngine) Decrypt(context.Context, crypto.ObjectContext, io.Reader, map[string]string) (io.Reader, map[string]string, error) {
	return nil, nil, errors.New("unused")
}
func (e *gh353NoProfileEngine) DecryptRange(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error) {
	return nil, nil, errors.New("unused")
}
func (e *gh353NoProfileEngine) AuthenticateChunkedTrailer(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64) (crypto.ChunkedObjectInfo, error) {
	return crypto.ChunkedObjectInfo{}, errors.New("unused")
}
func (*gh353NoProfileEngine) IsEncrypted(metadata map[string]string) bool {
	return metadata[crypto.MetaEncrypted] == "true"
}
func (*gh353NoProfileEngine) PreferredAlgorithm() string { return "AES256-GCM" }

type gh353StreamingTestEngine struct{ calls int }

func (e *gh353StreamingTestEngine) Encrypt(_ context.Context, _ crypto.ObjectContext, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	e.calls++
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}
	return bytes.NewReader(append([]byte("chunked:"), data...)), map[string]string{crypto.MetaEncrypted: "true", crypto.MetaObjectFormatVersion: "chunked-v2", crypto.MetaChunkedFormat: "true", crypto.MetaAlgorithm: "AES256-GCM", crypto.MetaOriginalSize: metadata["Content-Length"], crypto.MetaOriginalETag: metadata["ETag"]}, nil
}
func (e *gh353StreamingTestEngine) Decrypt(context.Context, crypto.ObjectContext, io.Reader, map[string]string) (io.Reader, map[string]string, error) {
	return nil, nil, errors.New("unused")
}
func (e *gh353StreamingTestEngine) DecryptRange(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error) {
	return nil, nil, errors.New("unused")
}
func (e *gh353StreamingTestEngine) AuthenticateChunkedTrailer(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64) (crypto.ChunkedObjectInfo, error) {
	return crypto.ChunkedObjectInfo{}, errors.New("unused")
}
func (*gh353StreamingTestEngine) IsEncrypted(metadata map[string]string) bool {
	return metadata[crypto.MetaEncrypted] == "true"
}
func (*gh353StreamingTestEngine) PreferredAlgorithm() string { return "AES256-GCM" }
func (*gh353StreamingTestEngine) WriteProfile() crypto.EncryptionWriteProfile {
	return crypto.EncryptionWriteProfile{StreamsPlaintext: true}
}

type gh353FinalEOFReader struct{ data []byte }

func (r *gh353FinalEOFReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

type gh353LazyOutputEngine struct {
	crypto.EncryptionEngine
	output io.Reader
}

func (e *gh353LazyOutputEngine) Encrypt(context.Context, crypto.ObjectContext, io.Reader, map[string]string) (io.Reader, map[string]string, error) {
	return e.output, map[string]string{crypto.MetaEncrypted: "true", crypto.MetaObjectFormatVersion: "chunked-v2", crypto.MetaChunkedFormat: "true", crypto.MetaAlgorithm: "AES256-GCM", crypto.MetaOriginalSize: "8"}, nil
}
func (*gh353LazyOutputEngine) WriteProfile() crypto.EncryptionWriteProfile {
	return crypto.EncryptionWriteProfile{StreamsPlaintext: true}
}

type gh353OwnedReader struct {
	io.Reader
	closed bool
}

func (r *gh353OwnedReader) Close() error { r.closed = true; return nil }

type gh353CallbackReader struct {
	fn   func()
	done bool
}

type gh353DeleteCallbackCache struct {
	cache.Cache
	deletes int
	delete  func()
}

func (c *gh353DeleteCallbackCache) Delete(ctx context.Context, bucket, key string) error {
	c.deletes++
	if c.delete != nil {
		c.delete()
	}
	if c.Cache != nil {
		return c.Cache.Delete(ctx, bucket, key)
	}
	return nil
}

func (r *gh353CallbackReader) Read(p []byte) (int, error) {
	if !r.done {
		r.done = true
		r.fn()
	}
	return 0, io.EOF
}

type gh353SpyReader struct {
	reads    int
	data     []byte
	maxChunk int
}

type gh353MemorySizeCache struct {
	values map[string]int64
	sets   int
}

func (c *gh353MemorySizeCache) Set(_ context.Context, bucket, key string, value int64) error {
	c.sets++
	c.values[bucket+"/"+key] = value
	return nil
}
func (*gh353MemorySizeCache) SetBatch(context.Context, string, map[string]int64) error { return nil }
func (*gh353MemorySizeCache) GetBatch(context.Context, string, []string) (map[string]int64, error) {
	return nil, nil
}
func (c *gh353MemorySizeCache) Delete(_ context.Context, bucket, key string) error {
	delete(c.values, bucket+"/"+key)
	return nil
}
func (*gh353MemorySizeCache) DeleteBatch(context.Context, string, []string) error { return nil }
func (*gh353MemorySizeCache) Close() error                                        { return nil }

var _ sizecache.SizeCache = (*gh353MemorySizeCache)(nil)

func (r *gh353SpyReader) Read(p []byte) (int, error) {
	r.reads++
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if r.maxChunk > 0 && len(p) > r.maxChunk {
		p = p[:r.maxChunk]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func gh353TestInput(operation string, body io.Reader, length int64) objectWriteInput {
	return objectWriteInput{Bucket: "bucket", Key: "key", Operation: operation, Body: body, PlainLength: length, HaveLength: true, Metadata: writeMetadata{User: map[string]string{}, Standard: objectmeta.Standard{ContentType: "text/plain"}}}
}

func TestGH353PostOptions_RequiresAdvancedBackend(t *testing.T) {
	engine := &gh353NoProfileEngine{}
	backend := newMockS3Client()
	h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
	reader := &gh353SpyReader{data: []byte("data")}
	in := gh353TestInput("PostObject", reader, 4)
	in.Options.StorageClass = "STANDARD_IA"
	_, err := h.putObjectData(context.Background(), backend, in)
	if !errors.Is(err, ErrPostUnsupported) || reader.reads != 0 || engine.calls != 0 || backend.putObjectCallCount != 0 {
		t.Fatalf("err=%v reads=%d encrypt=%d puts=%d", err, reader.reads, engine.calls, backend.putObjectCallCount)
	}
	in.Options = s3.ObjectPutOptions{}
	in.Body = &gh353SpyReader{data: []byte("data")}
	if _, err := h.putObjectData(context.Background(), backend, in); err != nil {
		t.Fatalf("zero-option legacy fallback: %v", err)
	}
	if backend.putObjectCallCount != 1 {
		t.Fatalf("legacy puts=%d want=1", backend.putObjectCallCount)
	}

	advanced := &gh353AdvancedPutClient{mockS3Client: newMockS3Client()}
	in.Options.StorageClass = "STANDARD_IA"
	in.Body = &gh353SpyReader{data: []byte("data")}
	result, err := h.putObjectData(context.Background(), advanced, in)
	if err != nil || advanced.puts != 1 || advanced.options.StorageClass != "STANDARD_IA" || result.Backend.VersionID != "version-1" {
		t.Fatalf("result=%+v err=%v advanced=%+v", result, err, advanced)
	}
	advanced.putError = s3.ErrNotImplemented
	in.Body = &gh353SpyReader{data: []byte("data")}
	_, err = h.putObjectData(context.Background(), advanced, in)
	if !errors.Is(err, s3.ErrNotImplemented) {
		t.Fatalf("advanced backend error downgraded: %v", err)
	}
}

func TestGH353PostSpool_BufferedEngineBound(t *testing.T) {
	data := bytes.Repeat([]byte("p"), 96)
	for _, tc := range []struct {
		name       string
		engine     crypto.EncryptionEngine
		wantCalls  int
		wantError  error
		wantStored int
	}{
		{"missing profile rejects before encrypt", &gh353NoProfileEngine{}, 0, ErrPostEntityTooLarge, 0},
		{"profiled streaming above memory cap", &gh353StreamingTestEngine{}, 1, nil, len("chunked:") + len(data)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Server: config.ServerConfig{MaxPartBuffer: 32, MaxAggregateSpoolBytes: 4096, SpoolDirectory: t.TempDir()}}
			backend := newMockS3Client()
			h := NewHandler(backend, tc.engine, logrus.New(), getTestMetrics())
			h.config = cfg
			h.spoolManager = NewSpoolManager(4096, cfg.Server.SpoolDirectory)
			in := gh353TestInput("PostObject", bytes.NewReader(data), int64(len(data)))
			result, err := h.putObjectData(context.Background(), backend, in)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("err=%v want=%v", err, tc.wantError)
			}
			calls := 0
			switch engine := tc.engine.(type) {
			case *gh353NoProfileEngine:
				calls = engine.calls
			case *gh353StreamingTestEngine:
				calls = engine.calls
			}
			if calls != tc.wantCalls || backend.putObjectCallCount != tc.wantCalls {
				t.Fatalf("encrypt=%d puts=%d want=%d", calls, backend.putObjectCallCount, tc.wantCalls)
			}
			if err == nil {
				stored := backend.objects["bucket/key"]
				if len(stored) != tc.wantStored || result.PlainSize != int64(len(data)) {
					t.Fatalf("stored=%d result=%+v", len(stored), result)
				}
			}
			if current := h.spoolManager.(*spoolManager).CurrentBytes(); current != 0 {
				t.Fatalf("cipher spool quota leaked: %d", current)
			}
			if tc.name == "profiled streaming above memory cap" {
				entries, err := os.ReadDir(cfg.Server.SpoolDirectory)
				if err != nil || len(entries) != 0 {
					t.Fatalf("streaming ciphertext spool cleanup entries=%v err=%v", entries, err)
				}
			}
		})
	}
}

func TestGH353PostBufferedBoundaryAndSSECEtag(t *testing.T) {
	t.Run("inclusive buffer bound", func(t *testing.T) {
		cfg := &config.Config{Server: config.ServerConfig{MaxPartBuffer: 16, MaxAggregateSpoolBytes: 1024, SpoolDirectory: t.TempDir()}}
		engine := &gh353NoProfileEngine{}
		backend := newMockS3Client()
		h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
		h.config, h.spoolManager = cfg, NewSpoolManager(1024, cfg.Server.SpoolDirectory)
		in := gh353TestInput("PostObject", bytes.NewReader([]byte("sixteen-byte-data")), 17)
		// Confirm +1 is rejected; then use the inclusive exact maximum.
		_, err := h.putObjectData(context.Background(), backend, in)
		if !errors.Is(err, ErrPostEntityTooLarge) || engine.calls != 0 {
			t.Fatalf("err=%v encrypt=%d", err, engine.calls)
		}
		in = gh353TestInput("PostObject", bytes.NewReader([]byte("sixteen-byte!!")), 14)
		cfg.Server.MaxPartBuffer = 14
		_, err = h.putObjectData(context.Background(), backend, in)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("POST plaintext ETag, real fallback engine and passthrough", func(t *testing.T) {
		body := bytes.Repeat([]byte("data"), 128)
		digest := md5.Sum(body)
		plainETag := hex.EncodeToString(digest[:])
		for _, tc := range []struct {
			name      string
			engine    crypto.EncryptionEngine
			encrypted bool
		}{
			{"buffered", func() crypto.EncryptionEngine { e, _ := newAPIUnitEngine([]byte("post-etag-buffered")); return e }(), true},
			{"real chunked fallback", func() crypto.EncryptionEngine {
				enc, err := crypto.NewEngineWithChunkingAndProvider([]byte("post-etag-fallback"), "", nil, true, crypto.MinChunkSize, "aws", crypto.MinPBKDF2Iterations)
				if err != nil {
					t.Fatal(err)
				}
				return enc
			}(), true},
			{"passthrough", crypto.PassthroughEngine{}, false},
		} {
			t.Run(tc.name, func(t *testing.T) {
				backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client()}
				h := NewHandler(backend, tc.engine, logrus.New(), getTestMetrics())
				h.spoolManager = NewSpoolManager(1<<20, t.TempDir())
				in := gh353TestInput("PostObject", bytes.NewReader(body), int64(len(body)))
				in.PlainETag = plainETag
				if tc.name == "real chunked fallback" {
					in.Metadata.User["x-amz-meta-overflow"] = strings.Repeat("v", 10*1024)
				}
				result, err := h.putObjectData(context.Background(), backend, in)
				if err != nil {
					t.Fatal(err)
				}
				if tc.encrypted && result.ClientETag != quoteETag(plainETag) {
					t.Fatalf("etag=%q want=%q", result.ClientETag, quoteETag(plainETag))
				}
				if !tc.encrypted && result.ClientETag != result.Backend.ETag {
					t.Fatalf("passthrough etag=%q backend=%q", result.ClientETag, result.Backend.ETag)
				}
				if tc.name == "real chunked fallback" {
					meta := backend.mockS3Client.metadata["bucket/key"]
					expanded, err := crypto.ExpandMetadataForAPI(meta)
					if err != nil || expanded[crypto.MetaEncrypted] != "true" || expanded[crypto.MetaFallbackMode] != "true" || expanded[crypto.MetaFallbackVersion] != "2" || expanded[crypto.MetaObjectFormatVersion] != "chunked-v2" {
						t.Fatal("expected authentic compacted chunked metadata fallback")
					}
					reader, _, decryptErr := tc.engine.(crypto.EncryptionEngine).Decrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(backend.objects["bucket/key"]), meta)
					if decryptErr != nil {
						t.Fatal(decryptErr)
					}
					plaintext, readErr := io.ReadAll(reader)
					if readErr != nil || !bytes.Equal(plaintext, body) {
						t.Fatalf("fallback plaintext length=%d err=%v", len(plaintext), readErr)
					}
				}
			})
		}
	})
	t.Run("captured part limit beats changed config", func(t *testing.T) {
		cfg := &config.Config{Server: config.ServerConfig{MaxPartBuffer: 8, MaxAggregateSpoolBytes: 4096, SpoolDirectory: t.TempDir()}}
		engine := &gh353NoProfileEngine{}
		backend := newMockS3Client()
		h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
		h.config, h.spoolManager = cfg, NewSpoolManager(4096, cfg.Server.SpoolDirectory)
		h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { cfg.Server.MaxPartBuffer = 128; return engine, nil }
		requestCtx := context.WithValue(context.Background(), postUploadContextKey{}, &postUpload{limitSnapshot: SpoolLimits{Global: 4096, Part: 8}})
		in := gh353TestInput("PostObject", bytes.NewReader([]byte("123456789")), 9)
		if _, err := h.putObjectData(requestCtx, backend, in); !errors.Is(err, ErrPostEntityTooLarge) || engine.calls != 0 {
			t.Fatalf("err=%v encrypt=%d", err, engine.calls)
		}
		newCtx := context.WithValue(context.Background(), postUploadContextKey{}, &postUpload{limitSnapshot: SpoolLimits{Global: 4096, Part: 128}})
		in = gh353TestInput("PostObject", bytes.NewReader([]byte("123456789")), 9)
		if _, err := h.putObjectData(newCtx, backend, in); err != nil {
			t.Fatalf("subsequent request should use new snapshot: %v", err)
		}
	})

	t.Run("SSE-C keeps opaque backend ETag", func(t *testing.T) {
		engine, err := newAPIUnitEngine([]byte("ssec-etag-password"))
		if err != nil {
			t.Fatal(err)
		}
		backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client(), responseETag: `"opaque-backend"`, responseHeaders: map[string]string{"x-amz-server-side-encryption-customer-algorithm": "AES256"}}
		h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
		h.spoolManager = NewSpoolManager(2048, t.TempDir())
		customer := &s3.SSECustomerKey{Key: bytes.Repeat([]byte{0x22}, 32), MD5: "protocol-md5"}
		in := gh353TestInput("PostObject", bytes.NewReader([]byte("etag data")), int64(len("etag data")))
		in.PlainETag = "0123456789abcdef0123456789abcdef"
		in.Options = s3.ObjectPutOptions{SSE: &s3.SSEOptions{Customer: customer}}
		result, err := h.putObjectData(context.Background(), backend, in)
		if err != nil {
			t.Fatal(err)
		}
		if result.ClientETag != result.Backend.ETag || result.ClientETag == quoteETag(in.PlainETag) {
			t.Fatalf("result=%+v", result)
		}
		if !result.CustomerSSE || projectObjectWriteHeaders(result, nil).Get("Cache-Control") != "no-store" {
			t.Fatalf("SSE-C response projection=%v result=%+v", projectObjectWriteHeaders(result, nil), result)
		}
		if bytes.Equal(customer.Key, make([]byte, 32)) {
			t.Fatal("helper unexpectedly closed caller-owned SSE-C key")
		}
	})
	t.Run("POST records one successful encryption only after spool preparation", func(t *testing.T) {
		for _, failSpool := range []bool{false, true} {
			registry := prometheus.NewRegistry()
			metricSink := metrics.NewMetricsWithRegistry(registry)
			writer := &gh353AuditWriter{}
			logger := audit.NewLogger(10, writer)
			engine, err := newAPIUnitChunkedEngine([]byte("post-audit-password"), "AES256-GCM", []string{"AES256-GCM"}, true, crypto.MinChunkSize)
			if err != nil {
				t.Fatal(err)
			}
			backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client()}
			h := NewHandler(backend, engine, logrus.New(), metricSink)
			h.auditLogger = logger
			capacity := int64(1 << 20)
			if failSpool {
				capacity = 1
			}
			h.spoolManager = NewSpoolManager(capacity, t.TempDir())
			cacheStore := cache.NewMemoryCache(4096, 8, time.Minute)
			if err := cacheStore.Set(context.Background(), "bucket", "key", []byte("preexisting"), map[string]string{"sentinel": "metadata"}, time.Minute); err != nil {
				t.Fatal(err)
			}
			h.cache = cacheStore
			body := []byte("only one encryption accounting event")
			in := gh353TestInput("PostObject", bytes.NewReader(body), int64(len(body)))
			_, writeErr := h.putObjectData(context.Background(), backend, in)
			operationCount := metricSample(t, registry, "encryption_operations_total", `operation="encrypt"`)
			if failSpool {
				if !errors.Is(writeErr, ErrSpoolCapacity) || operationCount != 0 || len(writer.events) != 0 || backend.puts != 0 {
					t.Fatalf("err=%v operations=%v audit=%d puts=%d", writeErr, operationCount, len(writer.events), backend.puts)
				}
				entry, ok := cacheStore.Get(context.Background(), "bucket", "key")
				if !ok || string(entry.Data) != "preexisting" || entry.Metadata["sentinel"] != "metadata" {
					t.Fatalf("preexisting cache not preserved: entry=%+v ok=%v", entry, ok)
				}
			} else {
				if writeErr != nil || operationCount != 1 {
					t.Fatalf("err=%v operations=%v", writeErr, operationCount)
				}
				if got := metricSample(t, registry, "encryption_bytes_total", `operation="encrypt"`); got != float64(len(body)) {
					t.Fatalf("encryption bytes=%v want=%d", got, len(body))
				}
				if len(writer.events) != 1 || writer.events[0].Operation != "encrypt" || !writer.events[0].Success {
					t.Fatalf("audit events=%+v", writer.events)
				}
			}
		}
	})
	t.Run("ordinary PUT preserves backend ETag and sealed original metadata", func(t *testing.T) {
		body := []byte("ordinary PUT ETag")
		for _, customerMode := range []bool{false, true} {
			engine, err := newAPIUnitEngine([]byte("ordinary-put-etag-password"))
			if err != nil {
				t.Fatal(err)
			}
			backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client(), responseETag: `"opaque-put"`}
			if customerMode {
				backend.responseHeaders = map[string]string{sseCustomerAlg: "AES256"}
			}
			h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
			in := gh353TestInput("PutObject", bytes.NewReader(body), int64(len(body)))
			in.PlainETag = "0123456789abcdef0123456789abcdef"
			if customerMode {
				in.Options = s3.ObjectPutOptions{SSE: &s3.SSEOptions{Customer: &s3.SSECustomerKey{Key: bytes.Repeat([]byte{7}, 32), MD5: "request-md5"}}}
			}
			result, writeErr := h.putObjectData(context.Background(), backend, in)
			if writeErr != nil {
				t.Fatal(writeErr)
			}
			if result.ClientETag != result.Backend.ETag {
				t.Fatalf("result ETag=%q backend=%q", result.ClientETag, result.Backend.ETag)
			}
			wantDigest := md5.Sum(body)
			if got := backend.mockS3Client.metadata["bucket/key"][crypto.MetaOriginalETag]; got != hex.EncodeToString(wantDigest[:]) {
				t.Fatalf("PUT sealed ETag=%q want engine-computed %q", got, hex.EncodeToString(wantDigest[:]))
			}
		}
	})
}

func TestGH353Put_CharacterizationPreserved(t *testing.T) {
	for _, tc := range []struct {
		name   string
		engine func() crypto.EncryptionEngine
		body   []byte
	}{
		{"buffered", func() crypto.EncryptionEngine { e, _ := newAPIUnitEngine([]byte("put-refactor-password")); return e }, []byte("buffered payload")},
		{"chunked", func() crypto.EncryptionEngine {
			e, _ := newAPIUnitChunkedEngine([]byte("put-refactor-password"), "AES256-GCM", []string{"AES256-GCM"}, true, 8)
			return e
		}, []byte("chunked payload with multiple chunks")},
		{"passthrough", func() crypto.EncryptionEngine { return crypto.PassthroughEngine{} }, []byte("plain payload")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := newMockS3Client()
			h := NewHandler(backend, tc.engine(), logrus.New(), getTestMetrics())
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			req := httptest.NewRequest(http.MethodPut, "/bucket/refactor-key", bytes.NewReader(tc.body))
			req.Header.Set("Content-Length", strconv.Itoa(len(tc.body)))
			req.Header.Set("Content-Type", "application/x-gh353")
			req.Header.Set("Cache-Control", "no-cache")
			req.Header.Set("Content-Disposition", "inline")
			req.Header.Set("Content-Encoding", "gzip")
			req.Header.Set("Content-Language", "en")
			req.Header.Set("Expires", "Wed, 21 Oct 2037 07:28:00 GMT")
			req.Header.Set("X-Amz-Meta-ordinary", "value")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusOK || backend.putObjectCallCount != 1 {
				t.Fatalf("status=%d body=%s puts=%d", w.Code, w.Body.String(), backend.putObjectCallCount)
			}
			stored := backend.objects["bucket/refactor-key"]
			if len(stored) == 0 || backend.lastPutContentLength == nil || *backend.lastPutContentLength != int64(len(stored)) {
				t.Fatalf("stored=%d length=%v", len(stored), backend.lastPutContentLength)
			}
			if tc.name != "passthrough" {
				reader, _, err := tc.engine().Decrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "refactor-key"}, bytes.NewReader(stored), backend.metadata["bucket/refactor-key"])
				if err != nil {
					t.Fatal(err)
				}
				plain, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(plain, tc.body) {
					t.Fatalf("plaintext=%q err=%v", plain, err)
				}
			}
			meta := backend.metadata["bucket/refactor-key"]
			contentType := meta[crypto.MetaContentType]
			cacheControl := meta["x-amz-meta-encryption-cache-control"]
			if tc.name == "passthrough" {
				contentType, cacheControl = meta["Content-Type"], meta["Cache-Control"]
			}
			if contentType != "application/x-gh353" || cacheControl != "no-cache" || meta["x-amz-meta-ordinary"] != "value" {
				t.Fatalf("metadata=%v", backend.metadata["bucket/refactor-key"])
			}
			for _, header := range []string{"Content-Disposition", "Content-Encoding", "Content-Language", "Expires"} {
				want := map[string]string{"Content-Disposition": "inline", "Content-Encoding": "gzip", "Content-Language": "en", "Expires": "Wed, 21 Oct 2037 07:28:00 GMT"}[header]
				if tc.name == "passthrough" {
					if meta[header] != want {
						t.Errorf("%s=%q want %q metadata=%v", header, meta[header], want, meta)
					}
				} else {
					engine, _ := tc.engine().(interface {
						Decrypt(context.Context, crypto.ObjectContext, io.Reader, map[string]string) (io.Reader, map[string]string, error)
					})
					_, decrypted, decryptErr := engine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "refactor-key"}, bytes.NewReader(stored), meta)
					if decryptErr != nil || decrypted[header] != want {
						t.Errorf("decrypted %s=%q want %q err=%v", header, decrypted[header], want, decryptErr)
					}
				}
			}
		})
	}
}

func TestGH353PutRefactor_DeclaredZeroAndUnknownBackfill(t *testing.T) {
	t.Run("declared zero remains known", func(t *testing.T) {
		backend := newMockS3Client()
		engine, err := newAPIUnitChunkedEngine([]byte("put-zero-password"), "AES256-GCM", []string{"AES256-GCM"}, true, 8)
		if err != nil {
			t.Fatal(err)
		}
		h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
		in := gh353TestInput("PutObject", bytes.NewReader(nil), 0)
		result, err := h.putObjectData(context.Background(), backend, in)
		if err != nil {
			t.Fatal(err)
		}
		if backend.lastPutContentLength == nil || *backend.lastPutContentLength != int64(len(backend.objects["bucket/key"])) || result.PlainSize != 0 {
			t.Fatalf("result=%+v length=%v body=%d", result, backend.lastPutContentLength, len(backend.objects["bucket/key"]))
		}
		if _, exists := backend.metadata["bucket/key"][crypto.MetaOriginalSize]; exists {
			t.Fatalf("known-zero unexpectedly backfilled metadata: %v", backend.metadata["bucket/key"])
		}
	})

	t.Run("unknown stream backfills size", func(t *testing.T) {
		backend := newMockS3Client()
		engine, err := newAPIUnitChunkedEngine([]byte("put-unknown-password"), "AES256-GCM", []string{"AES256-GCM"}, true, 8)
		if err != nil {
			t.Fatal(err)
		}
		h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
		in := gh353TestInput("PutObject", bytes.NewReader([]byte("unknown length payload")), 0)
		in.HaveLength = false
		result, err := h.putObjectData(context.Background(), backend, in)
		if err != nil {
			t.Fatal(err)
		}
		if backend.metadata["bucket/key"][crypto.MetaOriginalSize] != strconv.Itoa(len("unknown length payload")) {
			t.Fatalf("metadata=%v", backend.metadata["bucket/key"])
		}
		if result.PlainSize != int64(len("unknown length payload")) {
			t.Fatalf("PlainSize=%d", result.PlainSize)
		}
	})
	t.Run("size cache updated once with inferred plaintext size", func(t *testing.T) {
		backend := newMockS3Client()
		engine, err := newAPIUnitChunkedEngine([]byte("put-size-cache-password"), "AES256-GCM", []string{"AES256-GCM"}, true, 8)
		if err != nil {
			t.Fatal(err)
		}
		h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
		cacheSpy := &gh353MemorySizeCache{values: map[string]int64{"bucket/key": 999}}
		h.sizeCache = cacheSpy
		body := []byte("unknown-length cache size")
		in := gh353TestInput("PutObject", bytes.NewReader(body), 0)
		in.HaveLength = false
		result, writeErr := h.putObjectData(context.Background(), backend, in)
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if result.PlainSize != int64(len(body)) || cacheSpy.sets != 1 || cacheSpy.values["bucket/key"] != int64(len(body)) {
			t.Fatalf("result=%+v cache=%+v", result, cacheSpy)
		}
	})
}

func TestGH353PostTypedWrite_RetryRewindsCiphertext(t *testing.T) {
	backend := &gh353RetryAdvancedClient{mockS3Client: newMockS3Client(), failFirst: true}
	engine := &gh353StreamingTestEngine{}
	h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
	h.spoolManager = NewSpoolManager(4096, t.TempDir())
	in := gh353TestInput("PostObject", bytes.NewReader([]byte("retry payload")), int64(len("retry payload")))
	result, err := h.putObjectData(context.Background(), backend, in)
	if err != nil || result.PlainSize != int64(len("retry payload")) || backend.puts != 2 || !bytes.Equal(backend.first, backend.second) {
		t.Fatalf("result=%+v err=%v puts=%d first=%q second=%q", result, err, backend.puts, backend.first, backend.second)
	}
	if h.spoolManager.(*spoolManager).CurrentBytes() != 0 {
		t.Fatal("ciphertext reservation leaked")
	}
}

type gh353RetryAdvancedClient struct {
	*mockS3Client
	puts          int
	failFirst     bool
	first, second []byte
}

func (c *gh353RetryAdvancedClient) PutObjectWithOptions(ctx context.Context, bucket, key string, body io.Reader, _ map[string]string, length *int64, tags string, lock *s3.ObjectLockInput, acl, full, read, readACP, writeACP string, _ s3.ObjectPutOptions) (s3.PutObjectResult, error) {
	seek, ok := body.(io.Seeker)
	if !ok {
		return s3.PutObjectResult{}, errors.New("retry body is not seekable")
	}
	first, err := io.ReadAll(body)
	if err != nil {
		return s3.PutObjectResult{}, err
	}
	c.first = append([]byte(nil), first...)
	c.puts = 1
	if c.failFirst {
		if _, err = seek.Seek(0, io.SeekStart); err != nil {
			return s3.PutObjectResult{}, err
		}
		c.puts = 2
	}
	second, err := io.ReadAll(body)
	if err != nil {
		return s3.PutObjectResult{}, err
	}
	c.second = append([]byte(nil), second...)
	etag, err := c.mockS3Client.PutObject(ctx, bucket, key, bytes.NewReader(second), nil, length, tags, lock, acl, full, read, readACP, writeACP)
	return s3.PutObjectResult{ETag: etag}, err
}
func (c *gh353RetryAdvancedClient) GetObjectWithOptions(ctx context.Context, bucket, key string, versionID, rangeHeader *string, _ s3.ObjectReadOptions) (io.ReadCloser, map[string]string, error) {
	return c.mockS3Client.GetObject(ctx, bucket, key, versionID, rangeHeader)
}
func (c *gh353RetryAdvancedClient) HeadObjectWithOptions(ctx context.Context, bucket, key string, versionID *string, _ s3.ObjectReadOptions) (map[string]string, error) {
	return c.mockS3Client.HeadObject(ctx, bucket, key, versionID)
}

func TestGH353PutOptions_ForwardedViaSharedWriter(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]string
		check  func(s3.ObjectPutOptions) bool
	}{
		{"storage", map[string]string{"x-amz-storage-class": "STANDARD_IA"}, func(o s3.ObjectPutOptions) bool { return o.StorageClass == "STANDARD_IA" }},
		{"website redirect", map[string]string{"x-amz-website-redirect-location": "/archive"}, func(o s3.ObjectPutOptions) bool { return o.WebsiteRedirectLocation == "/archive" }},
		{"SSE-S3", map[string]string{sseAlgorithmHeader: "AES256"}, func(o s3.ObjectPutOptions) bool { return o.SSE != nil && o.SSE.Algorithm == "AES256" }},
		{"SSE-KMS", map[string]string{sseAlgorithmHeader: "aws:kms", sseKMSKeyHeader: "kms-key", sseKMSContextHeader: "eyJwIjoiMSJ9", sseBucketKeyHeader: "true"}, func(o s3.ObjectPutOptions) bool {
			return o.SSE != nil && o.SSE.Algorithm == "aws:kms" && o.SSE.KMSKeyID == "kms-key" && o.SSE.KMSContext == "eyJwIjoiMSJ9" && o.SSE.BucketKeyEnabled != nil && *o.SSE.BucketKeyEnabled
		}},
		{"SSE-C", sseCustomerFields(), func(o s3.ObjectPutOptions) bool {
			return o.SSE != nil && o.SSE.Customer != nil && len(o.SSE.Customer.Key) == 0
		}},
		{"incomplete SSE-C denied", map[string]string{sseCustomerAlg: "AES256"}, func(s3.ObjectPutOptions) bool { return false }},
		{"unsigned SSE-C triplet denied", sseCustomerFields(), func(s3.ObjectPutOptions) bool { return false }},
		{"SSE-C without verified backend HTTPS denied", sseCustomerFields(), func(s3.ObjectPutOptions) bool { return false }},
		{"trusted immediate peer HTTPS", sseCustomerFields(), func(o s3.ObjectPutOptions) bool { return o.SSE != nil && o.SSE.Customer != nil }},
		{"plaintext ingress denied", sseCustomerFields(), func(s3.ObjectPutOptions) bool { return false }},
		{"untrusted peer denied", sseCustomerFields(), func(s3.ObjectPutOptions) bool { return false }},
		{"duplicate proxy alias denied", sseCustomerFields(), func(s3.ObjectPutOptions) bool { return false }},
		{"comma XFP denied", sseCustomerFields(), func(s3.ObjectPutOptions) bool { return false }},
		{"backend TLS verification disabled denied", sseCustomerFields(), func(s3.ObjectPutOptions) bool { return false }},
		{"mixed copy and SSE-C denied before read", sseCustomerFields(), func(s3.ObjectPutOptions) bool { return false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &gh353AdvancedPutClient{mockS3Client: newMockS3Client(), responseETag: `"opaque-backend"`}
			engine, err := newAPIUnitEngine([]byte("signed-put-options-password"))
			if err != nil {
				t.Fatal(err)
			}
			endpoint := "https://store.example"
			if tc.name == "SSE-C without verified backend HTTPS denied" || tc.name == "backend TLS verification disabled denied" {
				endpoint = "http://store.example"
			}
			tlsConfig := config.BackendTLSConfig{}
			if tc.name == "backend TLS verification disabled denied" {
				endpoint = "https://store.example"
				tlsConfig.InsecureSkipVerify = true
			}
			trustedProxies := []string(nil)
			if tc.name == "trusted immediate peer HTTPS" || tc.name == "duplicate proxy alias denied" || tc.name == "comma XFP denied" {
				trustedProxies = []string{"10.0.0.0/8"}
			}
			cfg := &config.Config{Server: config.ServerConfig{TrustedProxies: trustedProxies}, Backend: config.BackendConfig{Endpoint: endpoint, UseSSL: true, TLS: tlsConfig}}
			h := NewHandlerWithFeatures(client, engine, logrus.New(), getTestMetrics(), nil, nil, nil, cfg, nil)
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			bodyReader := &gh353SpyReader{data: []byte("body"), maxChunk: 1}
			request := httptest.NewRequest(http.MethodPut, "https://gateway.example/bucket/key", bodyReader)
			request.Host = "gateway.example"
			request.ContentLength = 4
			request.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
			unsignedSSEC := tc.name == "unsigned SSE-C triplet denied"
			for name, value := range tc.fields {
				if !unsignedSSEC {
					request.Header.Set(name, value)
				}
			}
			if tc.name == "mixed copy and SSE-C denied before read" {
				request.Header.Set("x-amz-copy-source", "/source/key")
			}
			switch tc.name {
			case "SSE-C", "SSE-C without verified backend HTTPS denied", "mixed copy and SSE-C denied before read", "unsigned SSE-C triplet denied":
				client.responseHeaders = map[string]string{sseCustomerAlg: "AES256", sseCustomerMD5: "non-secret-md5"}
			case "SSE-KMS":
				client.responseHeaders = map[string]string{"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "kms-key", "x-amz-server-side-encryption-bucket-key-enabled": "true"}
			case "storage":
				client.responseHeaders = map[string]string{"x-amz-storage-class": "STANDARD_IA"}
			case "website redirect":
				client.responseHeaders = map[string]string{"x-amz-website-redirect-location": "/archive"}
			default:
				client.responseHeaders = nil
			}
			if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}, request, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			if unsignedSSEC {
				for name, value := range tc.fields {
					request.Header.Set(name, value)
				}
			}
			if tc.name == "incomplete SSE-C denied" {
				request.Header.Set(sseCustomerAlg, "AES256")
			}
			request.TLS = nil
			if tc.name == "SSE-C" || tc.name == "plaintext ingress denied" {
				request.TLS = &tls.ConnectionState{}
			}
			switch tc.name {
			case "trusted immediate peer HTTPS":
				request.RemoteAddr = "10.1.2.3:1234"
				request.Header.Set("X-Forwarded-Proto", "HTTPS")
			case "plaintext ingress denied":
				request.TLS = nil
			case "untrusted peer denied":
				request.RemoteAddr = "198.51.100.8:1234"
				request.Header.Set("X-Forwarded-Proto", "https")
			case "duplicate proxy alias denied":
				request.RemoteAddr = "10.1.2.3:1234"
				request.Header.Set("X-Forwarded-Proto", "https")
				request.Header.Add("X-Forwarded-Proto", "https")
			case "comma XFP denied":
				request.RemoteAddr = "10.1.2.3:1234"
				request.Header.Set("X-Forwarded-Proto", "https, https")
			case "SSE-C without verified backend HTTPS denied", "backend TLS verification disabled denied":
				request.TLS = &tls.ConnectionState{}
			}
			response := httptest.NewRecorder()
			AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(AuthorizationMiddleware("", nil)(router)).ServeHTTP(response, request)
			if tc.name == "SSE-C without verified backend HTTPS denied" || tc.name == "incomplete SSE-C denied" || unsignedSSEC || tc.name == "mixed copy and SSE-C denied before read" || tc.name == "plaintext ingress denied" || tc.name == "untrusted peer denied" || tc.name == "duplicate proxy alias denied" || tc.name == "comma XFP denied" || tc.name == "backend TLS verification disabled denied" {
				if response.Code == http.StatusOK || client.puts != 0 || len(client.readBody) != 0 || bodyReader.reads != 0 {
					t.Fatalf("insecure SSE-C status=%d puts=%d", response.Code, client.puts)
				}
				if (unsignedSSEC || tc.name == "incomplete SSE-C denied") && (!strings.Contains(response.Body.String(), "<Code>InvalidArgument</Code>") || response.Code != http.StatusBadRequest) {
					t.Fatalf("invalid signed-option PUT status=%d body=%s", response.Code, response.Body.String())
				}
				if tc.name == "mixed copy and SSE-C denied before read" && (!strings.Contains(response.Body.String(), "<Code>NotImplemented</Code>") || response.Code != http.StatusNotImplemented) {
					t.Fatalf("mixed copy/SSE-C status=%d body=%s", response.Code, response.Body.String())
				}
				if (tc.name == "SSE-C without verified backend HTTPS denied" || tc.name == "plaintext ingress denied" || tc.name == "untrusted peer denied" || tc.name == "duplicate proxy alias denied" || tc.name == "comma XFP denied" || tc.name == "backend TLS verification disabled denied") && (!strings.Contains(response.Body.String(), "<Code>InvalidRequest</Code>") || response.Code != http.StatusBadRequest) {
					t.Fatalf("transport-option PUT status=%d body=%s", response.Code, response.Body.String())
				}
				return
			}
			if response.Code != http.StatusOK || client.puts != 1 || !tc.check(client.options) {
				t.Fatalf("status=%d puts=%d option match=%v", response.Code, client.puts, tc.check(client.options))
			}
			if bodyReader.reads <= 1 {
				t.Fatalf("signed option request did not exercise fragmented body reads: reads=%d", bodyReader.reads)
			}
			if response.Header().Get("ETag") != `"opaque-backend"` {
				t.Fatalf("ETag=%q", response.Header().Get("ETag"))
			}
			for _, header := range []string{sseCustomerKey, sseKMSContextHeader} {
				if response.Header().Get(header) != "" {
					t.Fatalf("secret option header %s projected", header)
				}
			}
			if tc.name == "SSE-KMS" && response.Header().Get("x-amz-server-side-encryption-aws-kms-key-id") != "kms-key" {
				t.Fatalf("KMS response header=%q", response.Header().Get("x-amz-server-side-encryption-aws-kms-key-id"))
			}
			if (tc.name == "SSE-C" || tc.name == "trusted immediate peer HTTPS") && response.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control=%q", response.Header().Get("Cache-Control"))
			}
			if tc.name != "SSE-C" && tc.name != "trusted immediate peer HTTPS" && response.Header().Get("Cache-Control") == "no-store" {
				t.Fatalf("ordinary PUT unexpectedly forced no-store: %v", response.Header())
			}
			if client.options.SSE != nil && client.options.SSE.Customer != nil && len(client.options.SSE.Customer.Key) != 0 {
				t.Fatal("request-owned SSE-C bytes survived handler completion")
			}
			if (tc.name == "SSE-C" || tc.name == "trusted immediate peer HTTPS") && (!client.customerKeyLiveAtBackend || !bytes.Equal(client.customerKeyBacking, make([]byte, 32))) {
				t.Fatal("SSE-C key was not live for backend call then zeroed")
			}
			if tc.name == "SSE-C" || tc.name == "trusted immediate peer HTTPS" {
				want, _ := base64.StdEncoding.DecodeString(sseCustomerFields()[sseCustomerKey])
				if !bytes.Equal(client.customerKeyAtBackend, want) {
					t.Fatal("backend did not receive the signed SSE-C key")
				}
			}
			if bytes.Contains(client.readBody, []byte("body")) {
				t.Fatal("backend received plaintext instead of ciphertext")
			}
		})
	}
}

func TestGH353PostPutTypedFailureClassification(t *testing.T) {
	if got := putObjectWriteS3Error(objectWriteFailure(objectWriteInvalid, ErrRequestExpired), "/b/k", "b", "k"); got.Code != "AccessDenied" || got.HTTPStatus != http.StatusForbidden {
		t.Fatalf("deadline classification=%+v", got)
	}
	if got := putObjectWriteS3Error(objectWriteFailure(objectWriteInvalid, ErrPostEntityTooLarge), "/b/k", "b", "k"); got.Code != "EntityTooLarge" || got.HTTPStatus != http.StatusRequestEntityTooLarge {
		t.Fatalf("size classification=%+v", got)
	}
	for _, tc := range []struct {
		err    error
		code   string
		status int
	}{
		{ErrSpoolCapacity, "SlowDown", http.StatusServiceUnavailable},
		{ErrSpoolRequestLimit, "EntityTooLarge", http.StatusRequestEntityTooLarge},
		{ErrStreamingCanceled, "IncompleteBody", http.StatusBadRequest},
	} {
		got := putObjectWriteS3Error(objectWriteFailure(objectWritePreparation, tc.err), "/b/k", "b", "k")
		if got.Code != tc.code || got.HTTPStatus != tc.status {
			t.Fatalf("error %v classified %+v want %s/%d", tc.err, got, tc.code, tc.status)
		}
	}
}

func TestGH353PostWriterNilDependenciesAndErrorStages(t *testing.T) {
	if upload, ok := postUploadFromContextRequestContext(nil); ok || upload != nil {
		t.Fatal("nil request context returned an upload")
	}
	if upload, ok := postUploadFromContextRequestContext(context.Background()); ok || upload != nil {
		t.Fatalf("context without POST snapshot returned upload=%v ok=%t", upload, ok)
	}
	if !nilWriteDependency(nil) {
		t.Fatal("nil interface dependency was considered present")
	}
	if _, err := (*Handler)(nil).putObjectData(context.Background(), newMockS3Client(), gh353TestInput("PutObject", strings.NewReader("x"), 1)); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("nil handler error=%v", err)
	}
	h := NewHandler(newMockS3Client(), nil, logrus.New(), nil)
	client := newMockS3Client()
	for _, input := range []objectWriteInput{
		gh353TestInput("unknown", strings.NewReader("x"), 1),
		func() objectWriteInput {
			in := gh353TestInput("PostObject", strings.NewReader("x"), 1)
			in.PlainETag = "bad"
			return in
		}(),
		func() objectWriteInput {
			in := gh353TestInput("PostObject", strings.NewReader("x"), 1)
			in.HaveLength = false
			return in
		}(),
	} {
		if _, err := h.putObjectData(context.Background(), client, input); err == nil {
			t.Fatalf("invalid writer input unexpectedly accepted: %+v", input)
		}
	}
	var nilBody *strings.Reader
	if _, err := h.putObjectData(context.Background(), client, gh353TestInput("PutObject", nilBody, 1)); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("typed-nil body error=%v", err)
	}
	var nilClient *mockS3Client
	if _, err := h.putObjectData(context.Background(), nilClient, gh353TestInput("PutObject", strings.NewReader("x"), 1)); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("typed-nil client error=%v", err)
	}
	if objectWriteFailure(objectWritePreparation, nil) != nil {
		t.Fatal("nil error wrapped into an object-write failure")
	}
	if got := putObjectWriteS3Error(errors.New("untyped backend diagnostic"), "/bucket/key", "bucket", "key"); got == nil || got.HTTPStatus == 0 {
		t.Fatalf("untyped error was not translated: %+v", got)
	}
	if got := putObjectWriteS3Error(objectWriteFailure(objectWritePreparation, errors.New("local spool preparation")), "/bucket/key", "bucket", "key"); got.Code != "InternalError" || got.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("generic preparation error=%+v", got)
	}
	if got := putObjectWriteS3Error(objectWriteFailure(objectWriteCrypto, errors.New("private crypto detail")), "/bucket/key", "bucket", "key"); got.Code != "InternalError" || strings.Contains(got.Message, "private crypto detail") {
		t.Fatalf("crypto error classification leaked detail: %+v", got)
	}
	if got := putObjectWriteS3Error(objectWriteFailure(objectWriteClassify, errors.New("classification")), "/bucket/key", "bucket", "key"); got.Code == "" {
		t.Fatalf("classification-stage error missing S3 code: %+v", got)
	}
	if got := putObjectWriteS3Error(objectWriteFailure(objectWriteBackend, s3.ErrNotImplemented), "/bucket/key", "bucket", "key"); got.Code != "NotImplemented" || got.HTTPStatus != http.StatusNotImplemented {
		t.Fatalf("backend unsupported classification=%+v", got)
	}
	if got := putObjectWriteS3Error(objectWriteFailure(objectWriteBackend, errors.New("backend failed")), "/bucket/key", "bucket", "key"); got.Code == "" {
		t.Fatalf("backend error classification missing code: %+v", got)
	}
}

func TestGH353PostWriter_PreparationFailurePreservesStateAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		name     string
		output   io.Reader
		deadline time.Duration
		want     error
	}{
		{"cipher read canceled", &gh353CallbackReader{fn: func() {}}, 0, ErrStreamingCanceled},
		{"deadline during preparation", &gh353CallbackReader{fn: func() { time.Sleep(20 * time.Millisecond) }}, 5 * time.Millisecond, ErrRequestExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if tc.want == ErrStreamingCanceled {
				tc.output.(*gh353CallbackReader).fn = cancel
			}
			engine, err := newAPIUnitChunkedEngine([]byte("prep-failure-password"), "AES256-GCM", []string{"AES256-GCM"}, true, crypto.MinChunkSize)
			if err != nil {
				t.Fatal(err)
			}
			backend := newMockS3Client()
			backend.objects["bucket/key"] = []byte("old-ciphertext")
			backend.metadata["bucket/key"] = map[string]string{"sentinel": "old-metadata"}
			registry := prometheus.NewRegistry()
			metricSink := metrics.NewMetricsWithRegistry(registry)
			writer := &gh353AuditWriter{}
			h := NewHandler(backend, &gh353LazyOutputEngine{EncryptionEngine: engine, output: tc.output}, logrus.New(), metricSink)
			h.auditLogger = audit.NewLogger(10, writer)
			h.spoolManager = NewSpoolManager(4096, t.TempDir())
			cacheStore := cache.NewMemoryCache(4096, 8, time.Minute)
			_ = cacheStore.Set(context.Background(), "bucket", "key", []byte("old-cache"), map[string]string{"sentinel": "cache"}, time.Minute)
			h.cache = cacheStore
			caller := &gh353OwnedReader{Reader: strings.NewReader("plaintext")}
			in := gh353TestInput("PostObject", caller, 8)
			if tc.deadline > 0 {
				in.Deadline = time.Now().Add(tc.deadline)
			}
			_, writeErr := h.putObjectData(ctx, backend, in)
			cancel()
			if !errors.Is(writeErr, tc.want) {
				t.Fatalf("err=%v want=%v", writeErr, tc.want)
			}
			if caller.closed {
				t.Fatal("writer closed caller-owned plaintext")
			}
			if backend.putObjectCallCount != 0 || string(backend.objects["bucket/key"]) != "old-ciphertext" || backend.metadata["bucket/key"]["sentinel"] != "old-metadata" {
				t.Fatalf("backend mutated: calls=%d object=%q metadata=%v", backend.putObjectCallCount, backend.objects["bucket/key"], backend.metadata["bucket/key"])
			}
			entry, ok := cacheStore.Get(context.Background(), "bucket", "key")
			if !ok || string(entry.Data) != "old-cache" || metricSample(t, registry, "encryption_operations_total", `operation="encrypt"`) != 0 || len(writer.events) != 0 {
				t.Fatalf("cache=%+v/%v metric/audit should remain untouched; audit=%+v", entry, ok, writer.events)
			}
			if got := h.spoolManager.(*spoolManager).CurrentBytes(); got != 0 {
				t.Fatalf("cipher quota leaked: %d", got)
			}
		})
	}
}

func TestGH353PostWriter_BackendFailureStageAndReservationOwnership(t *testing.T) {
	manager := NewSpoolManager(4096, t.TempDir())
	plainReservation, err := manager.Acquire(context.Background(), 7, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer plainReservation.Release()
	client := &gh353AdvancedPutClient{mockS3Client: newMockS3Client(), putError: errors.New("backend failure")}
	client.duringPut = func() {
		if got := manager.(*spoolManager).CurrentBytes(); got <= 7 {
			t.Errorf("backend invoked without ciphertext and plaintext reservations held: %d", got)
		}
	}
	engine, err := newAPIUnitChunkedEngine([]byte("backend-failure-password"), "AES256-GCM", []string{"AES256-GCM"}, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(client, engine, logrus.New(), getTestMetrics())
	h.spoolManager = manager
	caller := &gh353OwnedReader{Reader: strings.NewReader("plaintext")}
	in := gh353TestInput("PostObject", caller, 9)
	_, writeErr := h.putObjectData(context.Background(), client, in)
	var typed *objectWriteError
	if !errors.As(writeErr, &typed) || typed.stage != objectWriteBackend {
		t.Fatalf("failure=%v stage=%v", writeErr, typed)
	}
	if caller.closed {
		t.Fatal("writer closed caller-owned plaintext")
	}
	if got := manager.(*spoolManager).CurrentBytes(); got != 7 {
		t.Fatalf("cipher reservation not released or plaintext reservation released: %d", got)
	}
}

func TestGH353PostWriter_CipherSpoolFailuresPreserveDestinationAndPlainOwnership(t *testing.T) {
	for _, stage := range []string{"create", "chmod", "write", "short-write", "seek"} {
		t.Run(stage, func(t *testing.T) {
			directory := t.TempDir()
			manager := NewSpoolManager(4096, directory)
			plainReservation, err := manager.Acquire(context.Background(), 8, 8)
			if err != nil {
				t.Fatal(err)
			}
			plainFile, err := os.CreateTemp(directory, "caller-plain-*")
			if err != nil {
				t.Fatal(err)
			}
			plainPath := plainFile.Name()
			if _, err := plainFile.Write([]byte("plaintext")); err != nil {
				t.Fatal(err)
			}
			if _, err := plainFile.Seek(0, io.SeekStart); err != nil {
				t.Fatal(err)
			}
			caller := &verifiedAWSFile{File: plainFile, length: 9, path: plainPath, reservation: plainReservation}
			t.Cleanup(func() { _ = caller.Close() })

			original := streamingSpoolOps
			t.Cleanup(func() { streamingSpoolOps = original })
			streamingSpoolOps = original
			var cipherPath string
			streamingSpoolOps.createTemp = func(dir, pattern string) (*os.File, error) {
				if stage == "create" {
					return nil, errors.New("injected create")
				}
				f, createErr := original.createTemp(dir, pattern)
				if createErr == nil && strings.Contains(pattern, "cipher") {
					cipherPath = f.Name()
				}
				return f, createErr
			}
			switch stage {
			case "chmod":
				streamingSpoolOps.chmod = func(*os.File, os.FileMode) error { return errors.New("injected chmod") }
			case "write":
				streamingSpoolOps.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected write") }
			case "short-write":
				streamingSpoolOps.write = func(f *os.File, p []byte) (int, error) { n, writeErr := f.Write(p); return n - 1, writeErr }
			case "seek":
				streamingSpoolOps.seek = func(*os.File, int64, int) (int64, error) { return 0, errors.New("injected seek") }
			}

			engine := &gh353LazyOutputEngine{EncryptionEngine: crypto.PassthroughEngine{}, output: bytes.NewReader([]byte("sealed ciphertext"))}
			backend := newMockS3Client()
			backend.objects["bucket/key"] = []byte("old-ciphertext")
			backend.metadata["bucket/key"] = map[string]string{"sentinel": "old-metadata"}
			store := cache.NewMemoryCache(4096, 8, time.Minute)
			_ = store.Set(context.Background(), "bucket", "key", []byte("old-cache"), map[string]string{"sentinel": "cache"}, time.Minute)
			h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
			h.cache, h.spoolManager = store, manager
			in := gh353TestInput("PostObject", caller, 9)
			_, writeErr := h.putObjectData(context.Background(), backend, in)
			var typed *objectWriteError
			if !errors.As(writeErr, &typed) || typed.stage != objectWritePreparation {
				t.Fatalf("error=%v typed=%+v", writeErr, typed)
			}
			mapped := putObjectWriteS3Error(writeErr, "/bucket/key", "bucket", "key")
			if mapped.HTTPStatus != http.StatusInternalServerError || mapped.Code != "InternalError" || mapped.Message != "Failed to prepare object for upload" {
				t.Fatalf("preparation error mapping=%+v", mapped)
			}
			if backend.putObjectCallCount != 0 || string(backend.objects["bucket/key"]) != "old-ciphertext" || backend.metadata["bucket/key"]["sentinel"] != "old-metadata" {
				t.Fatalf("destination changed: calls=%d object=%q metadata=%v", backend.putObjectCallCount, backend.objects["bucket/key"], backend.metadata["bucket/key"])
			}
			if got := manager.(*spoolManager).CurrentBytes(); got != 8 {
				t.Fatalf("cipher reservation leaked or caller reservation released: %d", got)
			}
			if _, err := os.Stat(plainPath); err != nil {
				t.Fatalf("caller plaintext file removed: %v", err)
			}
			if cipherPath != "" {
				if _, err := os.Stat(cipherPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("ciphertext spool remains at %s: %v", cipherPath, err)
				}
			}
			entry, ok := store.Get(context.Background(), "bucket", "key")
			if !ok || string(entry.Data) != "old-cache" {
				t.Fatalf("cache altered before spool success: entry=%+v ok=%v", entry, ok)
			}
			if caller.closed {
				t.Fatal("shared writer closed caller-owned plaintext spool")
			}
		})
	}
}

func TestGH353PostWriter_RechecksCancellationAndDeadlineAfterCacheInvalidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(context.CancelFunc) objectWriteInput
		want error
	}{
		{"context canceled", func(cancel context.CancelFunc) objectWriteInput {
			return gh353TestInput("PostObject", bytes.NewReader([]byte("plain")), 5)
		}, ErrStreamingCanceled},
		{"request deadline elapsed", func(context.CancelFunc) objectWriteInput {
			in := gh353TestInput("PostObject", bytes.NewReader([]byte("plain")), 5)
			in.Deadline = time.Now().Add(time.Hour)
			return in
		}, ErrRequestExpired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client()}
			engine := &gh353StreamingTestEngine{}
			h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
			cacheSpy := &gh353DeleteCallbackCache{delete: func() {
				if tc.want == ErrStreamingCanceled {
					cancel()
				} else {
					time.Sleep(10 * time.Millisecond)
				}
			}}
			h.cache = cacheSpy
			in := tc.stop(cancel)
			if tc.want == ErrRequestExpired {
				in.Deadline = time.Now().Add(2 * time.Millisecond)
			}
			_, err := h.putObjectData(ctx, backend, in)
			if !errors.Is(err, tc.want) || cacheSpy.deletes != 1 || backend.puts != 0 || backend.mockS3Client.putObjectCallCount != 0 {
				t.Fatalf("err=%v want=%v deletes=%d advanced puts=%d legacy puts=%d", err, tc.want, cacheSpy.deletes, backend.puts, backend.mockS3Client.putObjectCallCount)
			}
		})
	}
}

func TestGH353PutRefactor_BackendAndBestEffortBackfillCompatibility(t *testing.T) {
	t.Run("backend put failure translates with no etag or size update", func(t *testing.T) {
		backend := newMockS3Client()
		backend.errors["bucket/key/put"] = errors.New("injected backend put failure")
		h := NewHandler(backend, crypto.PassthroughEngine{}, logrus.New(), getTestMetrics())
		cacheSpy := &gh353DeleteCallbackCache{Cache: cache.NewMemoryCache(1024, 4, time.Minute)}
		h.cache = cacheSpy
		sizeSpy := &gh353MemorySizeCache{values: map[string]int64{"bucket/key": 123}}
		h.sizeCache = sizeSpy
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("payload"))
		r.Header.Set("Content-Length", "7")
		r = mux.SetURLVars(r, map[string]string{"bucket": "bucket", "key": "key"})
		w := httptest.NewRecorder()
		h.handlePutObject(w, r)
		if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "<Code>InternalError</Code>") || !strings.Contains(w.Body.String(), "<Message>We encountered an internal error. Please try again.</Message>") || w.Header().Get("ETag") != "" {
			t.Fatalf("PUT failure response status=%d ETag=%q body=%s", w.Code, w.Header().Get("ETag"), w.Body.String())
		}
		if sizeSpy.sets != 0 || cacheSpy.deletes != 1 {
			t.Fatalf("size writes=%d cache invalidations=%d", sizeSpy.sets, cacheSpy.deletes)
		}
	})

	for _, copyFails := range []bool{false, true} {
		name := "successful size backfill"
		if copyFails {
			name = "best effort copy failure"
		}
		t.Run(name, func(t *testing.T) {
			base := newMockS3Client()
			backend := &gh353BackfillClient{mockS3Client: base, failCopy: copyFails}
			engine, err := newAPIUnitChunkedEngine([]byte("put-backfill-compatibility"), "AES256-GCM", []string{"AES256-GCM"}, true, 8)
			if err != nil {
				t.Fatal(err)
			}
			h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
			cacheSpy := &gh353DeleteCallbackCache{Cache: cache.NewMemoryCache(1024, 4, time.Minute)}
			h.cache = cacheSpy
			sizeSpy := &gh353MemorySizeCache{values: make(map[string]int64)}
			h.sizeCache = sizeSpy
			body := "unknown-length streaming body"
			r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader(body))
			r.ContentLength = -1
			r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
			r = mux.SetURLVars(r, map[string]string{"bucket": "bucket", "key": "key"})
			w := httptest.NewRecorder()
			h.handlePutObject(w, r)
			if w.Code != http.StatusOK || cacheSpy.deletes != 1 || backend.copyCalls != 1 {
				t.Fatalf("status=%d deletes=%d self-copy=%d body=%s", w.Code, cacheSpy.deletes, backend.copyCalls, w.Body.String())
			}
			got := sizeSpy.values["bucket/key"]
			if copyFails {
				if sizeSpy.sets != 0 || got != 0 || base.metadata["bucket/key"][crypto.MetaOriginalSize] != "" {
					t.Fatalf("failed best-effort backfill claimed exact size: writes=%d value=%d metadata=%v", sizeSpy.sets, got, base.metadata["bucket/key"])
				}
			} else if sizeSpy.sets != 1 || got != int64(len(body)) || base.metadata["bucket/key"][crypto.MetaOriginalSize] != strconv.Itoa(len(body)) {
				t.Fatalf("successful backfill size writes=%d value=%d metadata=%v", sizeSpy.sets, got, base.metadata["bucket/key"])
			}
		})
	}
}

type gh353BackfillClient struct {
	*mockS3Client
	failCopy  bool
	copyCalls int
}

func TestGH353PutRefactor_RealChunkedUnknownLengthAboveBufferCap(t *testing.T) {
	body := bytes.Repeat([]byte("real authenticated chunk "), 1+crypto.MinChunkSize/len("real authenticated chunk "))
	for _, tc := range []struct {
		name     string
		fallback bool
	}{{"streaming", false}, {"buffered fallback", true}} {
		t.Run(tc.name, func(t *testing.T) {
			for attempt := 0; attempt < 2; attempt++ {
				var engine crypto.EncryptionEngine
				var err error
				if tc.fallback {
					engine, err = crypto.NewEngineWithChunkingAndProvider([]byte("real-chunk-fallback"), "AES256-GCM", []string{"AES256-GCM"}, true, crypto.MinChunkSize, "aws", crypto.MinPBKDF2Iterations)
				} else {
					engine, err = newAPIUnitChunkedEngine([]byte("real-chunk-stream"), "AES256-GCM", []string{"AES256-GCM"}, true, crypto.MinChunkSize)
				}
				if err != nil {
					t.Fatal(err)
				}
				backend := newMockS3Client()
				h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
				h.encryptionEngine = engine
				h.config = &config.Config{Server: config.ServerConfig{MaxPartBuffer: 32}}
				sizeSpy := &gh353MemorySizeCache{values: make(map[string]int64)}
				h.sizeCache = sizeSpy
				in := gh353TestInput("PutObject", &gh353FinalEOFReader{data: append([]byte(nil), body...)}, 0)
				in.HaveLength = false
				if tc.fallback {
					in.Metadata.User["x-amz-meta-overflow"] = strings.Repeat("v", 10*1024)
				}
				result, writeErr := h.putObjectData(context.Background(), backend, in)
				if writeErr != nil {
					t.Fatalf("attempt %d: %v", attempt, writeErr)
				}
				ciphertext := backend.objects["bucket/key"]
				if len(ciphertext) <= 32 {
					t.Fatalf("attempt %d ciphertext=%d want above buffer cap", attempt, len(ciphertext))
				}
				if tc.fallback {
					if result.PlainSize != 0 || sizeSpy.sets != 0 {
						t.Fatalf("fallback without exact metadata claimed size=%d cache writes=%d", result.PlainSize, sizeSpy.sets)
					}
				} else if result.PlainSize != int64(len(body)) || sizeSpy.sets != 1 || sizeSpy.values["bucket/key"] != int64(len(body)) {
					t.Fatalf("streamed result/cache size=%d cache=%+v want=%d", result.PlainSize, sizeSpy, len(body))
				}
				reader, metadata, decryptErr := engine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "bucket", Key: "key"}, bytes.NewReader(ciphertext), backend.metadata["bucket/key"])
				if decryptErr != nil {
					t.Fatalf("attempt %d decrypt: %v", attempt, decryptErr)
				}
				plain, readErr := io.ReadAll(reader)
				if readErr != nil || !bytes.Equal(plain, body) {
					t.Fatalf("attempt %d plaintext length=%d err=%v", attempt, len(plain), readErr)
				}
				if tc.fallback && metadata[crypto.MetaFallbackMode] != "" {
					t.Fatalf("attempt %d expected legacy buffered object without streaming fallback metadata: %v", attempt, metadata)
				}
			}
		})
	}
}

func TestGH353PostWriter_RechecksAfterAuditCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client()}
	h := NewHandler(backend, &gh353StreamingTestEngine{}, logrus.New(), getTestMetrics())
	h.auditLogger = &gh353AuditCallback{onEncrypt: cancel}
	cacheSpy := &gh353DeleteCallbackCache{}
	h.cache = cacheSpy
	in := gh353TestInput("PostObject", bytes.NewReader([]byte("payload")), 7)
	_, err := h.putObjectData(ctx, backend, in)
	if !errors.Is(err, ErrStreamingCanceled) || cacheSpy.deletes != 0 || backend.puts != 0 {
		t.Fatalf("err=%v cache deletes=%d backend puts=%d", err, cacheSpy.deletes, backend.puts)
	}
}

func TestGH353PostWriter_SuccessAccountsOnceAndInvalidatesOnce(t *testing.T) {
	registry := prometheus.NewRegistry()
	metricSink := metrics.NewMetricsWithRegistry(registry)
	backend := &gh353AdvancedPutClient{mockS3Client: newMockS3Client()}
	engine := &gh353StreamingTestEngine{}
	h := NewHandler(backend, engine, logrus.New(), metricSink)
	auditSpy := &gh353AccountingAudit{}
	h.auditLogger = auditSpy
	cacheSpy := &gh353DeleteCallbackCache{}
	h.cache = cacheSpy
	known := gh353TestInput("PostObject", bytes.NewReader([]byte("known size")), int64(len("known size")))
	if _, err := h.putObjectData(context.Background(), backend, known); err != nil {
		t.Fatal(err)
	}
	if backend.puts != 1 || engine.calls != 1 || auditSpy.calls != 1 || cacheSpy.deletes != 1 || metricSample(t, registry, "encryption_operations_total", `operation="encrypt"`) != 1 {
		t.Fatalf("known write accounting puts=%d encryptions=%d audit=%d deletes=%d metric=%v", backend.puts, engine.calls, auditSpy.calls, cacheSpy.deletes, metricSample(t, registry, "encryption_operations_total", `operation="encrypt"`))
	}
	unknown := gh353TestInput("PutObject", bytes.NewReader([]byte("unknown size")), 0)
	unknown.HaveLength = false
	if _, err := h.putObjectData(context.Background(), backend, unknown); err != nil {
		t.Fatal(err)
	}
	if backend.puts != 2 || engine.calls != 2 || auditSpy.calls != 2 || cacheSpy.deletes != 2 || metricSample(t, registry, "encryption_operations_total", `operation="encrypt"`) != 2 {
		t.Fatalf("unknown write accounting puts=%d encryptions=%d audit=%d deletes=%d metric=%v", backend.puts, engine.calls, auditSpy.calls, cacheSpy.deletes, metricSample(t, registry, "encryption_operations_total", `operation="encrypt"`))
	}
}

func TestGH353PutRefactor_LegacyInlineOptionsAndMetadata(t *testing.T) {
	backend := newMockS3Client()
	engine := crypto.PassthroughEngine{}
	h := NewHandler(backend, engine, logrus.New(), getTestMetrics())
	r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("tagged body"))
	r.Header.Set("Content-Length", "11")
	r.Header.Set("Content-Type", "text/legacy")
	r.Header.Set("Cache-Control", "private")
	r.Header.Set("Content-Disposition", "attachment")
	r.Header.Set("Content-Encoding", "gzip")
	r.Header.Set("Content-Language", "en-GB")
	r.Header.Set("Expires", "Wed, 21 Oct 2037 07:28:00 GMT")
	r.Header.Set("x-amz-tagging", "team=storage")
	r.Header.Set("x-amz-acl", "public-read")
	r.Header.Set("x-amz-grant-full-control", "id=owner")
	r.Header.Set("x-amz-meta-user", "retained")
	r = mux.SetURLVars(r, map[string]string{"bucket": "bucket", "key": "key"})
	w := httptest.NewRecorder()
	h.handlePutObject(w, r)
	if w.Code != http.StatusOK || backend.putObjectCallCount != 1 {
		t.Fatalf("status=%d calls=%d body=%s", w.Code, backend.putObjectCallCount, w.Body.String())
	}
	meta := backend.metadata["bucket/key"]
	for key, want := range map[string]string{"Content-Type": "text/legacy", "Cache-Control": "private", "Content-Disposition": "attachment", "Content-Encoding": "gzip", "Content-Language": "en-GB", "Expires": "Wed, 21 Oct 2037 07:28:00 GMT", "x-amz-meta-user": "retained"} {
		if meta[key] != want {
			t.Errorf("backend metadata %s=%q want %q metadata=%v", key, meta[key], want, meta)
		}
	}
	backend.locksMu.Lock()
	acl, grant := backend.lastCannedACL, backend.lastGrantFullCtrl
	backend.locksMu.Unlock()
	if acl != "public-read" || grant != "id=owner" {
		t.Fatalf("ACL grants lost: canned=%q full=%q", acl, grant)
	}
	if backend.objects["bucket/key"] == nil {
		t.Fatal("object not persisted")
	}
}

func (c *gh353BackfillClient) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *s3.ObjectLockInput) (string, map[string]string, error) {
	c.copyCalls++
	if c.failCopy {
		return "", nil, errors.New("injected self-copy failure")
	}
	return c.mockS3Client.CopyObject(ctx, dstBucket, dstKey, srcBucket, srcKey, srcVersionID, metadata, lock)
}
