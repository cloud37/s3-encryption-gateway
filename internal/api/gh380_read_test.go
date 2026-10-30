package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/smithy-go"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func TestGH380EncryptedReadCompatibility(t *testing.T) {
	paths, err := filepath.Glob("testdata/objectformats/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("fixtures: %v", err)
	}
	for _, path := range paths {
		if filepath.Base(path) == "plaintext.json" {
			continue
		}
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture goldenBackendFixture
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			if err := runAuthenticObjectFormatGolden(t, fixture, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGH380ListPolicyNeutral(t *testing.T) {
	client := newMockS3Client()
	client.objects["test-bucket/plain"] = []byte("plaintext")
	client.metadata["test-bucket/plain"] = map[string]string{"Content-Length": "9"}
	h := gh380Handler(t, client)
	view, err := h.loadObjectView("test-bucket", "plain", nil, client.metadata["test-bucket/plain"])
	if err != nil {
		t.Fatal(err)
	}
	size, err := h.resolvePlaintextSize(context.Background(), client, view)
	if err != nil || !size.Exact || size.Size != 9 {
		t.Fatalf("size=%+v err=%v", size, err)
	}
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	list := httptest.NewRecorder()
	router.ServeHTTP(list, httptest.NewRequest("GET", "/test-bucket?list-type=2", nil))
	if list.Code != 200 || !strings.Contains(list.Body.String(), "<Size>9</Size>") {
		t.Fatalf("list: %d %s", list.Code, list.Body.String())
	}
	get := httptest.NewRecorder()
	router.ServeHTTP(get, httptest.NewRequest("GET", "/test-bucket/plain", nil))
	if get.Code != 403 {
		t.Fatalf("GET: %d", get.Code)
	}
}

func containsGH380Message(body string) bool {
	return strings.Contains(body, "<Code>AccessDenied</Code>") && strings.Contains(body, "Bucket policy requires gateway-encrypted objects; plaintext reads are forbidden.")
}

func TestGH380PlaintextReadRoutes(t *testing.T) {
	for _, body := range []string{"plaintext secret", ""} {
		client := newMockS3Client()
		client.objects["test-bucket/source"] = []byte(body)
		client.metadata["test-bucket/source"] = map[string]string{"x-amz-meta-user": "secret", "ETag": "etag"}
		h := gh380Handler(t, client)
		router := mux.NewRouter()
		h.RegisterRoutes(router)
		for _, tc := range []struct{ method, rangeValue string }{{"GET", ""}, {"GET", "bytes=0-1"}, {"GET", "bytes=1-"}, {"GET", "bytes=-2"}, {"GET", "invalid"}, {"HEAD", ""}} {
			req := httptest.NewRequest(tc.method, "/test-bucket/source?versionId=v1&response-content-type=text%2Fplain", nil)
			if tc.rangeValue != "" {
				req.Header.Set("Range", tc.rangeValue)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s %s status=%d body=%s", tc.method, tc.rangeValue, w.Code, w.Body.String())
			}
			if tc.method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD has body")
			}
			if tc.method == "GET" && !containsGH380Message(w.Body.String()) {
				t.Fatalf("wrong error: %s", w.Body.String())
			}
			for _, key := range []string{"ETag", "Content-Range", "x-amz-version-id", "x-amz-meta-user"} {
				if w.Header().Get(key) != "" {
					t.Fatalf("leaked %s", key)
				}
			}
		}
	}
}

type gh380SwapClient struct {
	*mockS3Client
	reads, closes             int
	headVersions, getVersions []string
	fetchedMetadata           map[string]string
}

type gh380Reader struct {
	io.ReadCloser
	owner *gh380SwapClient
}

func (r *gh380Reader) Read(p []byte) (int, error) { r.owner.reads++; return r.ReadCloser.Read(p) }
func (r *gh380Reader) Close() error               { r.owner.closes++; return r.ReadCloser.Close() }
func (c *gh380SwapClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	c.headVersions = append(c.headVersions, requestVersionID(versionID))
	return c.mockS3Client.HeadObject(ctx, bucket, key, versionID)
}
func (c *gh380SwapClient) GetObject(ctx context.Context, bucket, key string, versionID, byteRange *string) (io.ReadCloser, map[string]string, error) {
	c.getVersions = append(c.getVersions, requestVersionID(versionID))
	r, _, err := c.mockS3Client.GetObject(ctx, bucket, key, versionID, byteRange)
	if err != nil {
		return nil, nil, err
	}
	metadata := c.fetchedMetadata
	if metadata == nil {
		metadata = map[string]string{"Content-Length": "10"}
	}
	return &gh380Reader{ReadCloser: r, owner: c}, metadata, nil
}

func TestGH380FetchedReadMetadata(t *testing.T) {
	for _, rangeValue := range []string{"", "bytes=0-1"} {
		base := newMockS3Client()
		base.objects["test-bucket/source"] = []byte("0123456789")
		base.metadata["test-bucket/source"] = map[string]string{crypto.MetaEncrypted: "true", "Content-Length": "10"}
		client := &gh380SwapClient{mockS3Client: base}
		h := gh380Handler(t, base)
		h.clientAcquirer = func(*http.Request) (s3.Client, error) { return client, nil }
		router := mux.NewRouter()
		h.RegisterRoutes(router)
		req := httptest.NewRequest("GET", "/test-bucket/source", nil)
		if rangeValue != "" {
			req.Header.Set("Range", rangeValue)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != 403 || client.reads != 0 || client.closes != 1 {
			t.Fatalf("range=%q status=%d reads=%d closes=%d body=%s", rangeValue, w.Code, client.reads, client.closes, w.Body.String())
		}
	}
}

func TestGH380FetchedRangedMetadata(t *testing.T) {
	for _, mode := range []objectReadMode{objectReadOptimizedRange, objectReadMPURange} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			base := newMockS3Client()
			base.objects["test-bucket/source"] = []byte("0123456789")
			base.metadata["test-bucket/source"] = map[string]string{crypto.MetaEncrypted: "true", "Content-Length": "10"}
			client := &gh380SwapClient{mockS3Client: base}
			h := gh380Handler(t, base)
			rangeHeader := "bytes=0-1"
			plan := objectReadPlan{Bucket: "test-bucket", Key: "source", Mode: mode, BackendRange: &rangeHeader}
			if mode == objectReadMPURange {
				plan.MPUManifest = &loadedMPUManifest{Manifest: &crypto.MultipartManifest{}}
				plan.MPURange = &crypto.MPURangeResult{}
				plan.MPUDecrypt = func(crypto.ObjectContext, []byte, []byte, [32]byte, [12]byte, int32, int, int32) ([]byte, error) {
					t.Fatal("decrypt invoked")
					return nil, nil
				}
			}
			w := httptest.NewRecorder()
			h.servePlannedGetObject(w, httptest.NewRequest("GET", "/test-bucket/source", nil), client, h.encryptionEngine, nil, plan, time.Now())
			if w.Code != 403 || client.reads != 0 || client.closes != 1 || !containsGH380Message(w.Body.String()) {
				t.Fatalf("status=%d reads=%d closes=%d body=%s", w.Code, client.reads, client.closes, w.Body.String())
			}
		})
	}
}

type gh380GoldenSwap struct {
	s3.Client
	reads, closes, heads, dataGets int
	lastRange                      string
	headVersions, getVersions      []string
}

type gh380GoldenReader struct {
	io.ReadCloser
	owner *gh380GoldenSwap
}

func (r *gh380GoldenReader) Read(p []byte) (int, error) { r.owner.reads++; return r.ReadCloser.Read(p) }
func (r *gh380GoldenReader) Close() error               { r.owner.closes++; return r.ReadCloser.Close() }
func (c *gh380GoldenSwap) HeadObject(ctx context.Context, bucket, key string, version *string) (map[string]string, error) {
	if bucket == goldenBucket && key == goldenObject {
		c.heads++
		c.headVersions = append(c.headVersions, requestVersionID(version))
	}
	return c.Client.HeadObject(ctx, bucket, key, version)
}
func (c *gh380GoldenSwap) GetObject(ctx context.Context, bucket, key string, version, byteRange *string) (io.ReadCloser, map[string]string, error) {
	r, metadata, err := c.Client.GetObject(ctx, bucket, key, version, byteRange)
	if err != nil || bucket != goldenBucket || key != goldenObject {
		return r, metadata, err
	}
	c.dataGets++
	c.getVersions = append(c.getVersions, requestVersionID(version))
	if byteRange != nil {
		c.lastRange = *byteRange
	}
	return &gh380GoldenReader{ReadCloser: r, owner: c}, map[string]string{"Content-Length": "1"}, nil
}

func TestGH380RangedRouteFetchedMetadata(t *testing.T) {
	for _, format := range []string{"chunked-v1", "mpu-v2"} {
		t.Run(format, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata/objectformats", format+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var fixture goldenBackendFixture
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			body, err := base64.StdEncoding.DecodeString(fixture.Body)
			if err != nil {
				t.Fatal(err)
			}
			base := newMockS3Client()
			base.objects[goldenBucket+"/"+goldenObject] = body
			base.metadata[goldenBucket+"/"+goldenObject] = cloneStringMap(fixture.Metadata)
			if format == "chunked-v1" {
				base.metadata[goldenBucket+"/"+goldenObject][crypto.MetaChunkCount] = "1"
			}
			if fixture.ManifestBody != "" {
				manifest, err := base64.StdEncoding.DecodeString(fixture.ManifestBody)
				if err != nil {
					t.Fatal(err)
				}
				base.objects[goldenBucket+"/"+goldenObject+crypto.MPUManifestSuffix] = manifest
				base.metadata[goldenBucket+"/"+goldenObject+crypto.MPUManifestSuffix] = cloneStringMap(fixture.ManifestMetadata)
			}
			engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
			if err != nil {
				t.Fatal(err)
			}
			var km crypto.KeyManager
			if format == "mpu-v2" {
				km, err = crypto.NewInMemoryKeyManager(bytes.Repeat([]byte{0x55}, 32))
				if err != nil {
					t.Fatal(err)
				}
			}
			client := &gh380GoldenSwap{Client: base}
			h := NewHandlerWithFeatures(client, engine, logrus.New(), getTestMetrics(), km, nil, nil, &config.Config{}, gh380Policy(t, "id: strict\nbuckets: [golden-bucket]\nrequire_encryption: true\n"))
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { return engine, nil }
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			req := httptest.NewRequest("GET", "/"+goldenBucket+"/"+goldenObject+"?versionId=chosen", nil)
			req.Header.Set("Range", "bytes=1-8")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != 403 || !containsGH380Message(w.Body.String()) || !gh380AllVersions(client.headVersions, "chosen") || !gh380AllVersions(client.getVersions, "chosen") || client.dataGets != 1 || client.lastRange == "" || client.reads != 0 || client.closes != 1 {
				t.Fatalf("status=%d headVersions=%v getVersions=%v range=%q reads=%d closes=%d body=%s", w.Code, client.headVersions, client.getVersions, client.lastRange, client.reads, client.closes, w.Body.String())
			}
		})
	}
}

func TestGH380BackendAndAuthorizationErrors(t *testing.T) {
	client := newMockS3Client()
	client.objects["test-bucket/source"] = []byte("opaque")
	client.metadata["test-bucket/source"] = map[string]string{crypto.MetaMPUEncrypted: "unknown"}
	h := gh380Handler(t, client)
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/test-bucket/source", nil))
	if w.Code != 500 || !strings.Contains(w.Body.String(), "Unsupported encrypted object format") {
		t.Fatalf("malformed: %d %s", w.Code, w.Body.String())
	}
	client.errors["test-bucket/missing/get"] = &smithy.GenericAPIError{Code: "NoSuchKey", Message: "missing"}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/test-bucket/missing", nil))
	if w.Code != 404 || !strings.Contains(w.Body.String(), "NoSuchKey") {
		t.Fatalf("backend: %d %s", w.Code, w.Body.String())
	}
	spyHandler, acquisitions, spy := newCopySpyHandler(t)
	copySpyDenialModes(t, spyHandler, acquisitions, spy, Credential{Policy: AuthorizationPolicy{Permissions: config.ObjectPermissionReadWrite, Buckets: []string{"dest-bucket"}}}, "PUT", "/dest-bucket/key", "/source-bucket/key")
}

func TestGH380CachePolicyReload(t *testing.T) {
	client := newMockS3Client()
	client.objects["test-bucket/source"] = []byte("cached plaintext")
	client.metadata["test-bucket/source"] = map[string]string{"ETag": "stable", "Content-Length": "16"}
	h := gh380Handler(t, client)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	writePolicy := func(enabled bool) {
		t.Helper()
		value := "false"
		if enabled {
			value = "true"
		}
		if err := os.WriteFile(path, []byte("id: strict\nbuckets: [test-bucket]\nrequire_encryption: "+value+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := h.policyManager.ReloadPolicies([]string{path}); err != nil {
			t.Fatal(err)
		}
	}
	h.cache = cache.NewMemoryCache(4096, 10, time.Minute)
	h.config = &config.Config{Cache: config.CacheConfig{MaxSize: 1024}}
	h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { return h.encryptionEngine, nil }
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	get := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/test-bucket/source", nil))
		return w
	}
	writePolicy(false)
	if w := get(); w.Code != 200 || w.Body.String() != "cached plaintext" {
		t.Fatalf("warm: %d %s", w.Code, w.Body.String())
	}
	if _, ok := h.cache.Get(context.Background(), "test-bucket", "source"); !ok {
		t.Fatal("cache not warmed")
	}
	writePolicy(true)
	if w := get(); w.Code != 403 {
		t.Fatalf("reload: %d %s", w.Code, w.Body.String())
	}
	encReader, metadata, err := h.encryptionEngine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "encrypted"}, strings.NewReader("encrypted-cache"), nil)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatal(err)
	}
	metadata["ETag"] = "encrypted-etag"
	metadata["Content-Length"] = fmt.Sprint(len(enc))
	client.objects["test-bucket/encrypted"] = enc
	client.metadata["test-bucket/encrypted"] = metadata
	encryptedGet := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("GET", "/test-bucket/encrypted", nil))
		return w
	}
	if w := encryptedGet(); w.Code != 200 || w.Body.String() != "encrypted-cache" {
		t.Fatalf("encrypted warm: %d %s", w.Code, w.Body.String())
	}
	if _, ok := h.cache.Get(context.Background(), "test-bucket", "encrypted"); !ok {
		t.Fatal("encrypted cache not warmed")
	}
	gets := client.getObjectCallCount
	if w := encryptedGet(); w.Code != 200 || w.Body.String() != "encrypted-cache" || client.getObjectCallCount != gets {
		t.Fatalf("encrypted cache hit: %d %s", w.Code, w.Body.String())
	}
	if err := os.WriteFile(path, []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.policyManager.ReloadPolicies([]string{path}); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if w := get(); w.Code != 403 {
		t.Fatalf("failed reload: %d", w.Code)
	}
	if w := encryptedGet(); w.Code != 200 || w.Body.String() != "encrypted-cache" {
		t.Fatalf("encrypted after failed reload: %d", w.Code)
	}
}
