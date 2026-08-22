package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func putSEC37Object(t *testing.T, client *mockS3Client, engine crypto.EncryptionEngine, key string, plaintext []byte) {
	t.Helper()
	reader, metadata, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: key}, bytes.NewReader(plaintext), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := func() error {
		_, err := client.PutObject(context.Background(), "test-bucket", key, bytes.NewReader(ciphertext), metadata, nil, "", nil, "", "", "", "", "")
		return err
	}(); err != nil {
		t.Fatal(err)
	}
}

func compactSEC37V2Metadata(t *testing.T, metadata map[string]string) map[string]string {
	t.Helper()
	compacted, err := crypto.NewMetadataCompactor(crypto.ProviderAWS).CompactMetadata(metadata)
	if err != nil {
		t.Fatal(err)
	}
	return compacted
}

func truncateSEC37Object(client *mockS3Client, bucket, key string) {
	name := bucket + "/" + key
	client.objects[name] = client.objects[name][:len(client.objects[name])-crypto.ChunkedTerminalSize]
}

func newSEC37Router(t *testing.T, client s3.Client, engine crypto.EncryptionEngine) *mux.Router {
	t.Helper()
	handler := NewHandler(client, engine, logrus.New(), getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	return router
}

func TestSEC37_FullGET_PreflightRejectsTruncatedV2(t *testing.T) {
	client := newMockS3Client()
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client, engine, "truncated-full", []byte("full get"))
	client.objects["test-bucket/truncated-full"] = client.objects["test-bucket/truncated-full"][:len(client.objects["test-bucket/truncated-full"])-crypto.ChunkedTerminalSize]
	w := httptest.NewRecorder()
	newSEC37Router(t, client, engine).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test-bucket/truncated-full", nil))
	if w.Code == http.StatusOK {
		t.Fatal("truncated v2 full GET succeeded")
	}
}

func TestSEC37_RangeGET_PreflightRejectsTruncatedV2(t *testing.T) {
	client := newMockS3Client()
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client, engine, "truncated-range", []byte("range get"))
	client.objects["test-bucket/truncated-range"] = client.objects["test-bucket/truncated-range"][:len(client.objects["test-bucket/truncated-range"])-crypto.ChunkedTerminalSize]
	req := httptest.NewRequest(http.MethodGet, "/test-bucket/truncated-range", nil)
	req.Header.Set("Range", "bytes=0-2")
	w := httptest.NewRecorder()
	newSEC37Router(t, client, engine).ServeHTTP(w, req)
	if w.Code == http.StatusPartialContent || w.Code == http.StatusOK {
		t.Fatal("truncated v2 range GET succeeded")
	}
}

func TestSEC37_HEAD_PreflightRejectsTruncatedV2(t *testing.T) {
	client := newMockS3Client()
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client, engine, "truncated-head", []byte("head"))
	client.objects["test-bucket/truncated-head"] = client.objects["test-bucket/truncated-head"][:len(client.objects["test-bucket/truncated-head"])-crypto.ChunkedTerminalSize]
	w := httptest.NewRecorder()
	newSEC37Router(t, client, engine).ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/test-bucket/truncated-head", nil))
	if w.Code == http.StatusOK {
		t.Fatal("truncated v2 HEAD succeeded")
	}
}

func TestSEC37_APIUnknownVersion_ReturnsInternalError(t *testing.T) {
	for _, version := range []int{0, 3, 255} {
		t.Run(fmt.Sprintf("version-%d", version), func(t *testing.T) {
			client := newMockS3Client()
			engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
			if err != nil {
				t.Fatal(err)
			}
			putSEC37Object(t, client, engine, "unknown-version", []byte("blocked"))
			metadata := client.metadata["test-bucket/unknown-version"]
			var manifest map[string]any
			data, _ := base64.StdEncoding.DecodeString(metadata[crypto.MetaManifest])
			_ = json.Unmarshal(data, &manifest)
			manifest["v"] = float64(version)
			data, _ = json.Marshal(manifest)
			metadata[crypto.MetaManifest] = base64.StdEncoding.EncodeToString(data)
			tests := []struct {
				name   string
				method string
				path   string
				setup  func(*http.Request)
			}{
				{name: "GET", method: http.MethodGet, path: "/test-bucket/unknown-version"},
				{name: "range GET", method: http.MethodGet, path: "/test-bucket/unknown-version", setup: func(r *http.Request) { r.Header.Set("Range", "bytes=0-2") }},
				{name: "HEAD", method: http.MethodHead, path: "/test-bucket/unknown-version"},
				{name: "CopyObject", method: http.MethodPut, path: "/test-bucket/copy-destination", setup: func(r *http.Request) { r.Header.Set("x-amz-copy-source", "/test-bucket/unknown-version") }},
				{name: "UploadPartCopy", method: http.MethodPut, path: "/test-bucket/destination?partNumber=1&uploadId=plain-upload", setup: func(r *http.Request) { r.Header.Set("x-amz-copy-source", "/test-bucket/unknown-version") }},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					caseClient := newMockS3Client()
					caseClient.objects = client.objects
					caseClient.metadata = client.metadata
					caseClient.errors = client.errors
					w := httptest.NewRecorder()
					req := httptest.NewRequest(tt.method, tt.path, nil)
					if tt.setup != nil {
						tt.setup(req)
					}
					var apiClient s3.Client = caseClient
					var counting *sec37CountingS3Client
					if tt.name == "UploadPartCopy" {
						counting = &sec37CountingS3Client{mockS3Client: caseClient}
						apiClient = counting
					}
					newSEC37Router(t, apiClient, engine).ServeHTTP(w, req)
					if w.Code != http.StatusInternalServerError || (tt.name != "HEAD" && !bytes.Contains(w.Body.Bytes(), []byte("InternalError"))) {
						t.Fatalf("unknown version returned %d %s", w.Code, w.Body.String())
					}
					if tt.name == "HEAD" && w.Body.Len() != 0 {
						t.Fatal("HEAD returned a body")
					}
					if (tt.name == "GET" || tt.name == "range GET") && bytes.Contains(w.Body.Bytes(), []byte("blocked")) {
						t.Fatalf("returned plaintext: %q", w.Body.Bytes())
					}
					if tt.name == "CopyObject" {
						if _, ok := caseClient.objects["test-bucket/copy-destination"]; ok {
							t.Fatal("copy destination was written")
						}
					}
					if counting != nil && counting.uploadPartCalls != 0 {
						t.Fatalf("UploadPart calls = %d", counting.uploadPartCalls)
					}
				})
			}
		})
	}
}

type sec37CountingS3Client struct {
	*mockS3Client
	uploadPartCalls int
}

func (c *sec37CountingS3Client) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	c.uploadPartCalls++
	return c.mockS3Client.UploadPart(ctx, bucket, key, uploadID, partNumber, reader, contentLength)
}

type sec37CountingMPUClient struct {
	*mpuMockS3Client
	uploadPartCalls int
}

func (c *sec37CountingMPUClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	c.uploadPartCalls++
	return c.mpuMockS3Client.UploadPart(ctx, bucket, key, uploadID, partNumber, reader, contentLength)
}

type sec37CountingStateStore struct {
	mpu.StateStore
}

func unknownSEC37Manifest(t *testing.T, metadata map[string]string) {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(metadata[crypto.MetaManifest])
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["v"] = float64(255)
	data, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	metadata[crypto.MetaManifest] = base64.StdEncoding.EncodeToString(data)
}

func TestSEC37_FullGET_VerifiesAgainAfterPreflight(t *testing.T) {
	client := &sec37TOCTOUClient{mockS3Client: newMockS3Client()}
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client.mockS3Client, engine, "toctou", []byte("toctou"))
	client.trailer = append([]byte{}, client.objects["test-bucket/toctou"]...)
	truncateSEC37Object(client.mockS3Client, "test-bucket", "toctou")
	w := httptest.NewRecorder()
	newSEC37Router(t, client, engine).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/test-bucket/toctou", nil))
	if client.trailerGets != 1 || client.fullGets != 1 {
		t.Fatalf("preflight/full reads = %d/%d", client.trailerGets, client.fullGets)
	}
	if !client.fullReader.eof {
		t.Fatalf("full reader was not consumed to EOF")
	}
	if bytes.Contains(w.Body.Bytes(), []byte("toctou")) || (w.Code != http.StatusOK && w.Code != http.StatusInternalServerError) {
		t.Fatalf("changed full stream completed cleanly: status=%d body=%q", w.Code, w.Body.Bytes())
	}
	// Directly consume the same truncated full body through the crypto stream to
	// observe the post-preflight integrity error that HTTP cannot expose after
	// headers have been sent.
	full, metadata, err := client.mockS3Client.GetObject(context.Background(), "test-bucket", "toctou", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, _, err := engine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, full, metadata)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(decrypted)
	if !errors.Is(err, crypto.ErrChunkedObjectIncomplete) || len(plain) != 0 {
		t.Fatalf("stream plaintext=%q error=%v", plain, err)
	}
	if w.Code == http.StatusOK && w.Body.Len() != 0 {
		t.Fatalf("stream reported success with plaintext body: %q", w.Body.Bytes())
	}
}

type sec37TOCTOUClient struct {
	*mockS3Client
	trailer     []byte
	trailerGets int
	fullGets    int
	fullReader  *sec37TrackingReader
}

type sec37TrackingReader struct {
	io.Reader
	eof, sawError bool
}

func (r *sec37TrackingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		r.eof = true
	}
	if err != nil && err != io.EOF {
		r.sawError = true
	}
	return n, err
}

func (c *sec37TOCTOUClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if rangeHeader != nil {
		c.trailerGets++
		return io.NopCloser(bytes.NewReader(c.trailer[len(c.trailer)-crypto.ChunkedTerminalSize:])), c.metadata[bucket+"/"+key], nil
	}
	c.fullGets++
	r, metadata, err := c.mockS3Client.GetObject(ctx, bucket, key, versionID, rangeHeader)
	if err != nil {
		return nil, metadata, err
	}
	c.fullReader = &sec37TrackingReader{Reader: r}
	return structReadCloser{Reader: c.fullReader, closer: r}, metadata, nil
}

type structReadCloser struct {
	io.Reader
	closer io.Closer
}

func (r structReadCloser) Close() error { return r.closer.Close() }

func TestSEC37_CompactedV2Truncated_APIPreflight(t *testing.T) {
	methods := []struct {
		name, method, path string
		setup              func(*http.Request)
	}{
		{"GET", http.MethodGet, "/test-bucket/source", nil},
		{"range GET", http.MethodGet, "/test-bucket/source", func(r *http.Request) { r.Header.Set("Range", "bytes=0-2") }},
		{"HEAD", http.MethodHead, "/test-bucket/source", nil},
		{"CopyObject", http.MethodPut, "/test-bucket/dest", func(r *http.Request) { r.Header.Set("x-amz-copy-source", "/test-bucket/source") }},
		{"UploadPartCopy", http.MethodPut, "/test-bucket/dest?partNumber=1&uploadId=u", func(r *http.Request) { r.Header.Set("x-amz-copy-source", "/test-bucket/source") }},
	}
	for _, tc := range methods {
		t.Run(tc.name, func(t *testing.T) {
			client := newMockS3Client()
			engine, err := crypto.NewEngineWithOpts([]byte("sec37-password"), crypto.WithProvider("aws"), crypto.WithMetadataKey(bytes.Repeat([]byte{0x37}, 32)), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize))
			if err != nil {
				t.Fatal(err)
			}
			reader, metadata, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("compact")), nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			metadata = compactSEC37V2Metadata(t, metadata)
			_, err = client.PutObject(context.Background(), "test-bucket", "source", bytes.NewReader(body), metadata, nil, "", nil, "", "", "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			truncateSEC37Object(client, "test-bucket", "source")
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.setup != nil {
				tc.setup(r)
			}
			w := httptest.NewRecorder()
			newSEC37Router(t, client, engine).ServeHTTP(w, r)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d", w.Code)
			}
		})
	}
}

func TestSEC37_V1GETAndHEAD_RemainReadable(t *testing.T) {
	client := newMockS3Client()
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client, engine, "v1-compatible", []byte("legacy"))
	router := newSEC37Router(t, client, engine)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(method, "/test-bucket/v1-compatible", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("%s returned %d", method, w.Code)
		}
		if method == http.MethodHead && w.Body.Len() != 0 {
			t.Fatal("HEAD returned a body")
		}
	}
}

func TestSEC37_CopyObject_RejectsInvalidTrailerBeforeDestinationWrite(t *testing.T) {
	client := newMockS3Client()
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client, engine, "copy-source", []byte("copy"))
	client.objects["test-bucket/copy-source"] = client.objects["test-bucket/copy-source"][:len(client.objects["test-bucket/copy-source"])-crypto.ChunkedTerminalSize]
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/copy-destination", nil)
	req.Header.Set("x-amz-copy-source", "/test-bucket/copy-source")
	w := httptest.NewRecorder()
	newSEC37Router(t, client, engine).ServeHTTP(w, req)
	if _, exists := client.objects["test-bucket/copy-destination"]; exists {
		t.Fatal("destination was written before trailer verification")
	}
}

func TestSEC37_Preflight_PreservesSourceVersionID(t *testing.T) {
	client := &sec37VersionClient{mockS3Client: newMockS3Client()}
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client.mockS3Client, engine, "versioned", []byte("version"))
	versionID := "version-1"
	client.headVersions = nil
	client.getVersions = nil
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/versioned-destination", nil)
	req.Header.Set("x-amz-copy-source", "/test-bucket/versioned?versionId="+versionID)
	w := httptest.NewRecorder()
	newSEC37Router(t, client, engine).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("versioned GET status=%d", w.Code)
	}
	if len(client.headVersions) == 0 || len(client.getVersions) < 2 {
		t.Fatalf("calls HEAD=%d GET=%d", len(client.headVersions), len(client.getVersions))
	}
	if client.headVersions[0] == nil || *client.headVersions[0] != versionID {
		t.Fatal("source HEAD version mismatch")
	}
	for _, got := range client.getVersions {
		if got == nil || *got != versionID {
			t.Fatal("source GET version mismatch")
		}
	}
}

func TestSEC37_VersionedGET_PreservesSourceVersionIDAcrossReads(t *testing.T) {
	client := &sec37VersionClient{mockS3Client: newMockS3Client()}
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client.mockS3Client, engine, "versioned-endpoint", []byte("versioned"))
	versionID := "version-1"
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/versioned-destination", nil)
	req.Header.Set("x-amz-copy-source", "/test-bucket/versioned-endpoint?versionId="+versionID)
	w := httptest.NewRecorder()
	newSEC37Router(t, client, engine).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("CopyObject = %d %q", w.Code, w.Body.String())
	}
	if len(client.headVersions) == 0 || len(client.getVersions) < 2 {
		t.Fatalf("calls HEAD=%d GET=%d", len(client.headVersions), len(client.getVersions))
	}
	for _, got := range client.getVersions {
		if got == nil || *got != versionID {
			t.Fatalf("GET version = %v", got)
		}
	}
	// The source HEAD is the first recorded HEAD; destination bookkeeping may
	// legitimately use a nil version in this in-memory client.
	if client.headVersions[0] == nil || *client.headVersions[0] != versionID {
		t.Fatalf("source HEAD version = %v", client.headVersions[0])
	}
}

func TestSEC37_CompactedV2Truncated_EncryptedMPUDestination(t *testing.T) {
	handler, client, _ := newMPUTestHandler(t, "sec37-compact-mpu-bucket")
	engine, err := crypto.NewEngineWithOpts([]byte(mpuTestPassword), crypto.WithProvider("aws"), crypto.WithMetadataKey(bytes.Repeat([]byte{0x37}, 32)), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize))
	if err != nil {
		t.Fatal(err)
	}
	handler.encryptionEngine = engine
	reader, metadata, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("compact-mpu")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	metadata = compactSEC37V2Metadata(t, metadata)
	if _, err := client.PutObject(context.Background(), "sec37-compact-mpu-bucket", "source", bytes.NewReader(body), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	client.objects["sec37-compact-mpu-bucket/source"] = client.objects["sec37-compact-mpu-bucket/source"][:len(client.objects["sec37-compact-mpu-bucket/source"])-crypto.ChunkedTerminalSize]
	uploadID, err := client.CreateMultipartUpload(context.Background(), "sec37-compact-mpu-bucket", "dest", nil, "", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.mpuStateStore.Create(context.Background(), &mpu.UploadState{
		UploadID: uploadID, Bucket: "sec37-compact-mpu-bucket", Key: "dest",
		PolicySnapshot: mpu.PolicySnapshot{EncryptMultipartUploads: true},
	}); err != nil {
		t.Fatal(err)
	}
	stateStore := &sec37CountingStateStore{StateStore: handler.mpuStateStore}
	counting := &sec37CountingMPUClient{mpuMockS3Client: client}
	handler.s3Client, handler.mpuStateStore = counting, stateStore
	req := httptest.NewRequest(http.MethodPut, "/sec37-compact-mpu-bucket/dest?partNumber=1&uploadId="+uploadID, nil)
	req.Header.Set("x-amz-copy-source", "/sec37-compact-mpu-bucket/source")
	w := httptest.NewRecorder()
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || counting.uploadPartCalls != 0 {
		t.Fatalf("status=%d upload=%d", w.Code, counting.uploadPartCalls)
	}
}

func TestSEC37_PreflightHelper_ErrorAndCompatibilityBranches(t *testing.T) {
	client := newMockS3Client()
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(client, engine, logrus.New(), getTestMetrics())
	for _, tc := range []struct {
		name     string
		metadata map[string]string
		wantErr  bool
	}{
		{"missing manifest v1 compatibility", map[string]string{crypto.MetaChunkedFormat: "true", crypto.MetaOriginalSize: "3"}, false},
		{"empty manifest", map[string]string{crypto.MetaChunkedFormat: "true", crypto.MetaManifest: ""}, true},
		{"malformed manifest", map[string]string{crypto.MetaChunkedFormat: "true", crypto.MetaManifest: "%%%"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, gotErr := h.preflightChunkedCompletenessIfV2(context.Background(), client, "test-bucket", "missing", nil, tc.metadata)
			if (gotErr != nil) != tc.wantErr {
				t.Fatalf("error = %v, want error %v", gotErr, tc.wantErr)
			}
		})
	}
	lookupErr := NewHandler(newMockS3Client(), engine, logrus.New(), getTestMetrics())
	lookupErr.encryptionEngine = nil
	if _, err := lookupErr.expandMetadataForAPI("test-bucket", map[string]string{"Content-Length": "1"}); err != nil {
		t.Fatal(err)
	}
	// The API-only helper preserves malformed manifest strings for the engine;
	// the strict parser is exercised by preflight tests above.
}

func TestSEC37_PreflightChunkedCompleteness_BranchMatrix(t *testing.T) {
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "source"}, bytes.NewReader([]byte("preflight")), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	metadata["Content-Length"] = fmt.Sprintf("%d", len(body))
	client := newMockS3Client()
	if _, err := client.PutObject(context.Background(), "test-bucket", "source", bytes.NewReader(body), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	h := NewHandler(client, engine, logrus.New(), getTestMetrics())
	versionID := "v1"
	validV2 := func() map[string]string {
		cp := make(map[string]string, len(metadata))
		for k, v := range metadata {
			cp[k] = v
		}
		return cp
	}
	for _, tc := range []struct {
		name     string
		metadata func() map[string]string
		wantErr  bool
	}{
		{"v2 valid suffix", validV2, false},
		{"malformed length", func() map[string]string { m := validV2(); m["Content-Length"] = "bad"; return m }, true},
		{"short ciphertext", func() map[string]string { m := validV2(); m["Content-Length"] = "31"; return m }, true},
		{"v1 fallback", func() map[string]string {
			return map[string]string{crypto.MetaChunkedFormat: "true", crypto.MetaOriginalSize: "9"}
		}, false},
		{"v1 content length", func() map[string]string {
			m := map[string]string{crypto.MetaChunkedFormat: "true", crypto.MetaOriginalSize: "9", "Content-Length": "25", crypto.MetaChunkSize: fmt.Sprintf("%d", crypto.MinChunkSize)}
			return m
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, gotErr := h.preflightChunkedCompleteness(context.Background(), client, "test-bucket", "source", &versionID, tc.metadata())
			if (gotErr != nil) != tc.wantErr {
				t.Fatalf("error=%v want=%v", gotErr, tc.wantErr)
			}
		})
	}
	client.errors["test-bucket/source/get"] = fmt.Errorf("suffix failure")
	if _, err := h.preflightChunkedCompleteness(context.Background(), client, "test-bucket", "source", &versionID, validV2()); err == nil {
		t.Fatal("suffix failure accepted")
	}
	if _, err := (crypto.PassthroughEngine{}).AuthenticateChunkedTrailer(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, nil, nil, 0); err == nil {
		t.Fatal("passthrough trailer unexpectedly accepted")
	}
}

func TestSEC37_ExpandMetadataForAPIBranches(t *testing.T) {
	engine, err := crypto.NewEngineWithOpts([]byte("sec37-password"), crypto.WithMetadataKey(bytes.Repeat([]byte{0x44}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(newMockS3Client(), engine, logrus.New(), getTestMetrics())
	if _, err := h.expandMetadataForAPI("test-bucket", map[string]string{"Content-Length": "1"}); err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("protected")), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(reader)
	if _, err := h.expandMetadataForAPI("test-bucket", metadata); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{crypto.MetaEncrypted: "true", crypto.MetaEncryptedMetadata: "%%%"}
	if _, err := h.expandMetadataForAPI("test-bucket", bad); err == nil {
		t.Fatal("protected metadata failure accepted")
	}
	fallback := NewHandler(newMockS3Client(), crypto.PassthroughEngine{}, logrus.New(), getTestMetrics())
	if got, err := fallback.expandMetadataForAPI("test-bucket", map[string]string{"x-amz-meta-c": "true"}); err != nil || got[crypto.MetaChunkedFormat] != "true" {
		t.Fatalf("fallback expansion = %#v, error = %v", got, err)
	}
	if got, err := h.expandMetadataForAPI("test-bucket", map[string]string{"x-amz-meta-m": "%%%"}); err != nil || got == nil {
		t.Fatalf("alias-only expansion = %#v, error = %v", got, err)
	}
	for _, tc := range []struct {
		name    string
		engine  crypto.EncryptionEngine
		wantErr bool
	}{
		{"expander success", &sec37APIExpander{}, false},
		{"expander error", &sec37APIExpander{err: fmt.Errorf("expand failed")}, true},
		{"fallback", crypto.PassthroughEngine{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(newMockS3Client(), tc.engine, logrus.New(), getTestMetrics())
			got, err := h.expandMetadataForAPI("test-bucket", map[string]string{"x-amz-meta-c": "true"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v want=%v", err, tc.wantErr)
			}
			if !tc.wantErr && got == nil {
				t.Fatal("nil metadata")
			}
		})
	}
	forcedExpandErr := NewHandler(newMockS3Client(), engine, logrus.New(), getTestMetrics())
	forcedExpandErr.apiMetadataExpander = func(map[string]string) (map[string]string, error) { return nil, fmt.Errorf("forced expansion failure") }
	if _, err := forcedExpandErr.expandMetadataForAPI("test-bucket", map[string]string{}); err == nil {
		t.Fatal("forced expansion failure ignored")
	}
	forcedLoaderErr := NewHandler(newMockS3Client(), engine, logrus.New(), getTestMetrics())
	forcedLoaderErr.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { return nil, fmt.Errorf("forced loader failure") }
	if _, err := forcedLoaderErr.expandMetadataForAPI("test-bucket", map[string]string{}); err == nil {
		t.Fatal("forced loader failure ignored")
	}
}

type sec37APIExpander struct{ err error }

func (e *sec37APIExpander) Encrypt(ctx context.Context, object crypto.ObjectContext, r io.Reader, m map[string]string) (io.Reader, map[string]string, error) {
	return r, m, nil
}
func (e *sec37APIExpander) Decrypt(ctx context.Context, object crypto.ObjectContext, r io.Reader, m map[string]string) (io.Reader, map[string]string, error) {
	return r, m, nil
}
func (e *sec37APIExpander) DecryptRange(ctx context.Context, object crypto.ObjectContext, r io.Reader, m map[string]string, a, b int64) (io.Reader, map[string]string, error) {
	return r, m, nil
}
func (e *sec37APIExpander) AuthenticateChunkedTrailer(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64) (crypto.ChunkedObjectInfo, error) {
	return crypto.ChunkedObjectInfo{}, nil
}
func (e *sec37APIExpander) IsEncrypted(map[string]string) bool { return false }
func (e *sec37APIExpander) PreferredAlgorithm() string         { return crypto.AlgorithmAES256GCM }
func (e *sec37APIExpander) APIExpandedMetadata(map[string]string) (map[string]string, error) {
	if e.err != nil {
		return nil, e.err
	}
	return map[string]string{}, nil
}

func TestSEC37_Preflight_PassthroughAndMissingLengthBranches(t *testing.T) {
	h := NewHandler(newMockS3Client(), crypto.PassthroughEngine{}, logrus.New(), getTestMetrics())
	if _, err := h.preflightChunkedCompleteness(context.Background(), h.s3Client, "test-bucket", "missing", nil, map[string]string{crypto.MetaChunkedFormat: "true"}); err != nil {
		t.Fatal(err)
	}
}

type sec37VersionClient struct {
	*mockS3Client
	headVersions, getVersions []*string
}

func (c *sec37VersionClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	c.headVersions = append(c.headVersions, versionID)
	return c.mockS3Client.HeadObject(ctx, bucket, key, versionID)
}

func (c *sec37VersionClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	c.getVersions = append(c.getVersions, versionID)
	return c.mockS3Client.GetObject(ctx, bucket, key, versionID, rangeHeader)
}

func TestSEC37_UploadPartCopy_Chunked_RejectsInvalidTrailerBeforeUploadPart(t *testing.T) {
	client := &sec37CountingS3Client{mockS3Client: newMockS3Client()}
	engine, err := crypto.NewEngineWithChunking([]byte("sec37-password"), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	putSEC37Object(t, client.mockS3Client, engine, "copy-source", []byte("copy"))
	client.objects["test-bucket/copy-source"] = client.objects["test-bucket/copy-source"][:len(client.objects["test-bucket/copy-source"])-crypto.ChunkedTerminalSize]
	req := httptest.NewRequest(http.MethodPut, "/test-bucket/destination?partNumber=1&uploadId=plain-upload", nil)
	req.Header.Set("x-amz-copy-source", "/test-bucket/copy-source")
	w := httptest.NewRecorder()
	handler := NewHandler(client, engine, logrus.New(), getTestMetrics())
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || client.uploadPartCalls != 0 {
		t.Fatalf("preflight returned %d and made %d UploadPart calls", w.Code, client.uploadPartCalls)
	}
}

func TestSEC37_UploadPartCopy_ReencryptMPU_RejectsInvalidTrailerBeforeUploadPart(t *testing.T) {
	handler, client, _ := newMPUTestHandler(t, "sec37-mpu-bucket")
	chunkedEngine, err := crypto.NewEngineWithChunking([]byte(mpuTestPassword), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := chunkedEngine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("copy")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutObject(context.Background(), "sec37-mpu-bucket", "copy-source", bytes.NewReader(ciphertext), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	client.objects["sec37-mpu-bucket/copy-source"] = client.objects["sec37-mpu-bucket/copy-source"][:len(client.objects["sec37-mpu-bucket/copy-source"])-crypto.ChunkedTerminalSize]
	stateStore := &sec37CountingStateStore{StateStore: handler.mpuStateStore}
	clientCounter := &sec37CountingMPUClient{mpuMockS3Client: client}
	handler.s3Client = clientCounter
	handler.mpuStateStore = stateStore
	req := httptest.NewRequest(http.MethodPut, "/sec37-mpu-bucket/destination?partNumber=1&uploadId=encrypted-upload", nil)
	req.Header.Set("x-amz-copy-source", "/sec37-mpu-bucket/copy-source")
	w := httptest.NewRecorder()
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || clientCounter.uploadPartCalls != 0 {
		t.Fatalf("preflight returned %d, UploadPart=%d", w.Code, clientCounter.uploadPartCalls)
	}
}

func TestSEC37_UploadPartCopy_ReencryptMPU_RejectsUnknownManifestVersion(t *testing.T) {
	handler, client, _ := newMPUTestHandler(t, "sec37-unknown-mpu-bucket")
	engine, err := crypto.NewEngineWithChunking([]byte(mpuTestPassword), "", nil, true, crypto.MinChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	reader, metadata, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: "test-bucket", Key: "test-key"}, bytes.NewReader([]byte("copy")), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.PutObject(context.Background(), "sec37-unknown-mpu-bucket", "copy-source", bytes.NewReader(ciphertext), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatal(err)
	}
	unknownSEC37Manifest(t, client.metadata["sec37-unknown-mpu-bucket/copy-source"])
	clientCounter := &sec37CountingMPUClient{mpuMockS3Client: client}
	handler.s3Client = clientCounter
	router := mux.NewRouter()
	handler.RegisterRoutes(router)
	req := httptest.NewRequest(http.MethodPut, "/sec37-unknown-mpu-bucket/destination?partNumber=1&uploadId=encrypted-upload", nil)
	req.Header.Set("x-amz-copy-source", "/sec37-unknown-mpu-bucket/copy-source")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || clientCounter.uploadPartCalls != 0 {
		t.Fatalf("unknown manifest returned %d and made %d UploadPart calls", w.Code, clientCounter.uploadPartCalls)
	}
}
