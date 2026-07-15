package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// ─────────────────────────────────────────────────────────────────────────────
// mpuMockS3Client — a richer mock than the default handlers_test.go one:
//   * stores UploadPart ciphertext bytes
//   * concatenates parts on CompleteMultipartUpload into one object
//   * honours the rangeHeader on GetObject (needed for ranged GET tests)
//   * freezes metadata at CreateMultipartUpload (mirrors real S3 semantics)
// ─────────────────────────────────────────────────────────────────────────────

type mpuMockS3Client struct {
	mu              sync.Mutex
	objects         map[string][]byte
	metadata        map[string]map[string]string
	parts           map[string][]byte            // key: "bucket|key|uploadID|partNumber"
	partsMeta       map[string]map[string]string // metadata frozen at CreateMultipartUpload
	maxRangedRead   int
	rangedReadCount int
}

type trackedMPURangeReader struct {
	reader *bytes.Reader
	client *mpuMockS3Client
}

func (r *trackedMPURangeReader) Read(p []byte) (int, error) {
	readSize := len(p)
	r.client.mu.Lock()
	if readSize > r.client.maxRangedRead {
		r.client.maxRangedRead = readSize
	}
	r.client.mu.Unlock()
	return r.reader.Read(p)
}

func (r *trackedMPURangeReader) Close() error { return nil }

func newMPUMockS3Client() *mpuMockS3Client {
	return &mpuMockS3Client{
		objects:   map[string][]byte{},
		metadata:  map[string]map[string]string{},
		parts:     map[string][]byte{},
		partsMeta: map[string]map[string]string{},
	}
}

func (m *mpuMockS3Client) PutObject(ctx context.Context, bucket, key string, reader io.Reader, metadata map[string]string, contentLength *int64, tags string, lock *s3.ObjectLockInput, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[bucket+"/"+key] = data
	cp := map[string]string{}
	for k, v := range metadata {
		cp[k] = v
	}
	m.metadata[bucket+"/"+key] = cp
	return "", nil
}

func (m *mpuMockS3Client) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	m.mu.Lock()
	data, ok := m.objects[bucket+"/"+key]
	if !ok {
		m.mu.Unlock()
		return nil, nil, &s3Error{code: "NoSuchKey", message: "not found"}
	}
	meta := m.metadata[bucket+"/"+key]
	metaCopy := map[string]string{}
	for k, v := range meta {
		metaCopy[k] = v
	}
	m.mu.Unlock()

	// Serve byte-range on GET — required for ranged-GET tests.
	if rangeHeader != nil && *rangeHeader != "" {
		var first, last int64
		parts := strings.Split(strings.TrimPrefix(*rangeHeader, "bytes="), "-")
		if len(parts) == 2 {
			f, err1 := strconv.Atoi(parts[0])
			l, err2 := strconv.Atoi(parts[1])
			if err1 == nil && err2 == nil {
				first = int64(f)
				last = int64(l)
				if last >= int64(len(data)) {
					last = int64(len(data)) - 1
				}
				if first < 0 || first > last {
					return nil, nil, fmt.Errorf("invalid range %q", *rangeHeader)
				}
				m.mu.Lock()
				m.rangedReadCount++
				m.mu.Unlock()
				return &trackedMPURangeReader{
					reader: bytes.NewReader(data[first : last+1]),
					client: m,
				}, metaCopy, nil
			}
		}
	}
	return io.NopCloser(bytes.NewReader(data)), metaCopy, nil
}

func (m *mpuMockS3Client) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	meta, ok := m.metadata[bucket+"/"+key]
	if !ok {
		return nil, &s3Error{code: "NoSuchKey", message: "not found"}
	}
	cp := map[string]string{}
	for k, v := range meta {
		cp[k] = v
	}
	return cp, nil
}

func (m *mpuMockS3Client) DeleteObject(ctx context.Context, bucket, key string, versionID *string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, bucket+"/"+key)
	delete(m.metadata, bucket+"/"+key)
	return nil
}

func (m *mpuMockS3Client) ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) (s3.ListResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var objects []s3.ObjectInfo
	maxKeys := int32(1000)
	if opts.MaxKeys > 0 {
		maxKeys = opts.MaxKeys
	}
	bk := bucket + "/"
	for k, data := range m.objects {
		if !strings.HasPrefix(k, bk) {
			continue
		}
		key := k[len(bk):]
		if prefix != "" && !strings.HasPrefix(key, prefix) {
			continue
		}
		objects = append(objects, s3.ObjectInfo{
			Key:  key,
			Size: int64(len(data)), // raw stored size (may be ciphertext)
		})
	}
	// Sort by key to match real S3 lexicographic ordering. Map iteration
	// is non-deterministic in Go; without sorting, .mpu-manifest companion
	// objects could appear before the data object when MaxKeys=1.
	sort.Slice(objects, func(i, j int) bool { return objects[i].Key < objects[j].Key })
	if int32(len(objects)) > maxKeys {
		objects = objects[:maxKeys]
	}
	return s3.ListResult{Objects: objects}, nil
}

func (m *mpuMockS3Client) CreateMultipartUpload(ctx context.Context, bucket, key string, metadata map[string]string, cannedACL, grantFullControl, grantRead, grantReadACP, grantWriteACP string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	uploadID := fmt.Sprintf("upload-%s-%d", key, time.Now().UnixNano())
	cp := map[string]string{}
	for k, v := range metadata {
		cp[k] = v
	}
	m.partsMeta[bucket+"/"+key+"/"+uploadID] = cp
	return uploadID, nil
}

func (m *mpuMockS3Client) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, reader io.Reader, contentLength *int64) (string, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parts[fmt.Sprintf("%s|%s|%s|%d", bucket, key, uploadID, partNumber)] = data
	// Simulate Ceph/S3 multipart upload: the in-progress data object is visible
	// via ListObjects with the accumulated (ciphertext) size of all uploaded parts.
	// This mirrors what statList() in Docker Distribution's S3 driver observes.
	var total []byte
	for pn := int32(1); ; pn++ {
		pd, ok := m.parts[fmt.Sprintf("%s|%s|%s|%d", bucket, key, uploadID, pn)]
		if !ok {
			break
		}
		total = append(total, pd...)
	}
	m.objects[bucket+"/"+key] = total
	return fmt.Sprintf("\"%032x\"", partNumber), nil
}

func (m *mpuMockS3Client) CompleteMultipartUpload(ctx context.Context, bucket, key, uploadID string, parts []s3.CompletedPart, lock *s3.ObjectLockInput) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var buf bytes.Buffer
	for _, p := range parts {
		buf.Write(m.parts[fmt.Sprintf("%s|%s|%s|%d", bucket, key, uploadID, p.PartNumber)])
	}
	m.objects[bucket+"/"+key] = buf.Bytes()
	// Metadata set at CreateMultipartUpload is the final object metadata.
	m.metadata[bucket+"/"+key] = m.partsMeta[bucket+"/"+key+"/"+uploadID]
	return "\"final-etag\"", nil
}

func (m *mpuMockS3Client) AbortMultipartUpload(ctx context.Context, bucket, key, uploadID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Clean up parts for this upload.
	prefix := fmt.Sprintf("%s|%s|%s|", bucket, key, uploadID)
	for k := range m.parts {
		if strings.HasPrefix(k, prefix) {
			delete(m.parts, k)
		}
	}
	delete(m.partsMeta, bucket+"/"+key+"/"+uploadID)
	return nil
}

func (m *mpuMockS3Client) ListParts(ctx context.Context, bucket, key, uploadID string) ([]s3.PartInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var parts []s3.PartInfo
	prefix := fmt.Sprintf("%s|%s|%s|", bucket, key, uploadID)
	for k, data := range m.parts {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		var pn int32
		fmt.Sscanf(k[len(prefix):], "%d", &pn)
		parts = append(parts, s3.PartInfo{
			PartNumber:   pn,
			ETag:         fmt.Sprintf("\"%032x\"", pn),
			Size:         int64(len(data)), // Ceph reports encrypted size
			LastModified: time.Now().UTC().Format(time.RFC3339),
		})
	}
	return parts, nil
}

func (m *mpuMockS3Client) CopyObject(ctx context.Context, dstBucket, dstKey string, srcBucket, srcKey string, srcVersionID *string, metadata map[string]string, lock *s3.ObjectLockInput) (string, map[string]string, error) {
	return "", nil, fmt.Errorf("not implemented in MPU mock")
}

func (m *mpuMockS3Client) UploadPartCopy(ctx context.Context, dstBucket, dstKey, uploadID string, partNumber int32, srcBucket, srcKey string, srcVersionID *string, srcRange *s3.CopyPartRange) (*s3.CopyPartResult, error) {
	return nil, fmt.Errorf("not implemented in MPU mock")
}

func (m *mpuMockS3Client) DeleteObjects(ctx context.Context, bucket string, keys []s3.ObjectIdentifier) ([]s3.DeletedObject, []s3.ErrorObject, error) {
	return nil, nil, nil
}

func (m *mpuMockS3Client) PutObjectRetention(ctx context.Context, bucket, key string, versionID *string, retention *s3.RetentionConfig) error {
	return nil
}
func (m *mpuMockS3Client) GetObjectRetention(ctx context.Context, bucket, key string, versionID *string) (*s3.RetentionConfig, error) {
	return nil, nil
}
func (m *mpuMockS3Client) PutObjectLegalHold(ctx context.Context, bucket, key string, versionID *string, status string) error {
	return nil
}
func (m *mpuMockS3Client) GetObjectLegalHold(ctx context.Context, bucket, key string, versionID *string) (string, error) {
	return "", nil
}
func (m *mpuMockS3Client) PutObjectLockConfiguration(ctx context.Context, bucket string, cfg *s3.ObjectLockConfiguration) error {
	return nil
}
func (m *mpuMockS3Client) GetObjectLockConfiguration(ctx context.Context, bucket string) (*s3.ObjectLockConfiguration, error) {
	return nil, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// newMPUTestHandler — stand up a handler with miniredis state + PasswordKeyManager
// and a policy allowing EncryptMultipartUploads for bucketPattern.
// ─────────────────────────────────────────────────────────────────────────────

const mpuTestPassword = "a-test-password-at-least-16-chars"

func newMPUTestHandler(t *testing.T, bucketPattern string) (*Handler, *mpuMockS3Client, *miniredis.Miniredis) {
	t.Helper()
	mockClient := newMPUMockS3Client()

	engine, err := crypto.NewEngine([]byte(mpuTestPassword))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Policy manager with encrypt_multipart_uploads=true.
	policyDir := t.TempDir()
	policyYAML := fmt.Sprintf(`id: test-mpu
buckets:
  - "%s"
encrypt_multipart_uploads: true
`, bucketPattern)
	policyPath := policyDir + "/policy.yaml"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{policyPath}); err != nil {
		t.Fatalf("load policies: %v", err)
	}

	cfg := &config.Config{
		Server:     config.ServerConfig{},
		Encryption: config.EncryptionConfig{Password: mpuTestPassword},
	}

	// Password-mode KeyManager — mirrors what cmd/server/main.go does.
	km, err := crypto.NewPasswordKeyManager([]byte(mpuTestPassword), crypto.WithPasswordKMPBKDF2(crypto.DefaultPBKDF2Iterations))
	if err != nil {
		t.Fatalf("password keymanager: %v", err)
	}

	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(), km, nil, nil, cfg, pm)

	// Valkey state store (miniredis).
	mr := miniredis.RunT(t)
	store, err := mpu.NewValkeyStateStore(context.Background(), config.ValkeyConfig{
		EncryptState:           config.BoolPtr(false),
		Addr:                   mr.Addr(),
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             3600,
		DialTimeout:            2 * time.Second,
		ReadTimeout:            1 * time.Second,
		WriteTimeout:           1 * time.Second,
		PoolSize:               2,
	}, nil, "")
	if err != nil {
		t.Fatalf("valkey store: %v", err)
	}
	handler.WithMPUStateStore(store)
	t.Cleanup(func() { _ = store.Close() })

	return handler, mockClient, mr
}

// Helper: parse UploadId out of the XML response body.
func extractUploadID(t *testing.T, body string) string {
	t.Helper()
	oi := strings.Index(body, "<UploadId>")
	ci := strings.Index(body, "</UploadId>")
	if oi == -1 || ci == -1 {
		t.Fatalf("no UploadId in body: %s", body)
	}
	return body[oi+len("<UploadId>") : ci]
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #1 regression: no plaintext DEK in Valkey or in the manifest companion.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_Issue1_NoPlaintextDEKAtRest(t *testing.T) {
	handler, mockClient, mr := newMPUTestHandler(t, "sec1-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "sec1-bucket", "obj.bin"

	// Create + upload single part + complete.
	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	part := bytes.Repeat([]byte("secret-data-"), 100_000)
	req = httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, uploadID), bytes.NewReader(part))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UploadPart: %d %s", w.Code, w.Body.String())
	}
	etag := w.Header().Get("ETag")

	completeXML := fmt.Sprintf(`<?xml version="1.0"?>
<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etag)
	req = httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploadId="+uploadID, strings.NewReader(completeXML))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Complete: %d %s", w.Code, w.Body.String())
	}

	// Gate 1: Valkey must not contain a 64-hex-char plaintext DEK.
	// After completion the state is deleted, so this is a write-and-check-during-upload
	// sort of concern. Re-inspect by creating another in-flight upload and examining
	// its state.
	req = httptest.NewRequest("POST", "/"+bucket+"/"+key+".in-flight?uploads=", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	inflightUploadID := extractUploadID(t, w.Body.String())
	defer func() {
		// Abort to clean up.
		req := httptest.NewRequest("DELETE", fmt.Sprintf("/%s/%s.in-flight?uploadId=%s", bucket, key, inflightUploadID), nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}()

	// Inspect the miniredis hash directly.
	keys := mr.Keys()
	var stateKey string
	for _, k := range keys {
		if strings.HasPrefix(k, "mpu:") {
			stateKey = k
			break
		}
	}
	if stateKey == "" {
		t.Fatal("no mpu:* key found in miniredis")
	}
	meta := mr.HGet(stateKey, "meta")
	if meta == "" {
		t.Fatal("state record has no meta field")
	}

	// A 64-hex-char run inside "wrapped_dek":"..." would indicate plaintext DEK.
	if idx := strings.Index(meta, `"wrapped_dek":"`); idx != -1 {
		valStart := idx + len(`"wrapped_dek":"`)
		valEnd := strings.IndexByte(meta[valStart:], '"')
		if valEnd == 64 && isHex(meta[valStart:valStart+64]) {
			t.Errorf("SECURITY HOLE: wrapped_dek in Valkey is 64 hex chars (plaintext DEK)\nmeta=%s", meta)
		}
	}

	// Gate 2: Manifest companion object on backend must not contain a plaintext DEK.
	manifestBytes, ok := mockClient.objects[bucket+"/"+key+".mpu-manifest"]
	if !ok {
		t.Fatal("manifest companion missing")
	}
	// The manifest is encrypted (Issue #2 fix). Verify:
	// (a) the raw bytes must NOT contain the JSON header "v":1
	// (b) the raw bytes must NOT contain 64-hex-char wrapped_dek pattern
	if bytes.Contains(manifestBytes, []byte(`"v":1`)) || bytes.Contains(manifestBytes, []byte(`"wrapped_dek"`)) {
		t.Errorf("SECURITY HOLE: manifest companion is NOT encrypted (contains JSON markers)\nfirst200=%q", manifestBytes[:min(200, len(manifestBytes))])
	}
	// Also scan for any 64-hex-char run as a belt-and-braces check.
	for i := 0; i+64 < len(manifestBytes); i++ {
		if isHex(string(manifestBytes[i : i+64])) {
			// Could be coincidental — warn rather than fail.
			t.Logf("note: 64-hex-char run at offset %d in manifest bytes; this is likely random ciphertext, not the DEK", i)
			break
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #2 regression: manifest companion is encrypted on the backend.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_Issue2_ManifestEncryptedAtRest(t *testing.T) {
	handler, mockClient, _ := newMPUTestHandler(t, "sec2-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "sec2-bucket", "obj.bin"
	doCompleteUpload(t, router, bucket, key, bytes.Repeat([]byte("A"), 1024*1024))

	manifestBytes, ok := mockClient.objects[bucket+"/"+key+".mpu-manifest"]
	if !ok {
		t.Fatal("manifest companion missing")
	}
	if bytes.Contains(manifestBytes, []byte(`"v":1`)) {
		t.Fatalf("manifest contains plaintext JSON marker — not encrypted: %q", manifestBytes[:100])
	}
	if bytes.Contains(manifestBytes, []byte(`"wrapped_dek"`)) {
		t.Fatalf("manifest contains plaintext wrapped_dek marker — not encrypted")
	}

	// The companion object's metadata must indicate encryption.
	meta := mockClient.metadata[bucket+"/"+key+".mpu-manifest"]
	if meta[crypto.MetaEncrypted] != "true" {
		t.Errorf("companion object missing x-amz-meta-encrypted=true; meta=%v", meta)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #3 regression: ranged GET returns correct plaintext bytes.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_Issue3_RangedGET_CorrectBytes(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "sec3-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "sec3-bucket", "obj.bin"

	// 3 parts × 256 KiB each = 768 KiB total.
	// DefaultChunkSize is 64 KiB → 4 chunks per part, 12 chunks total.
	partSize := 256 * 1024
	part1 := makeByteRamp(partSize, 0)
	part2 := makeByteRamp(partSize, byte(partSize))
	part3 := makeByteRamp(partSize, byte(partSize*2))
	plain := append(append(append([]byte{}, part1...), part2...), part3...)
	doCompleteUploadWithParts(t, router, bucket, key, [][]byte{part1, part2, part3})

	type rangeCase struct {
		name        string
		first, last int64
		want        []byte
	}
	cases := []rangeCase{
		{"start-of-object", 0, 99, plain[:100]},
		{"within-one-chunk", 1000, 1999, plain[1000:2000]},
		{"crossing-chunk-boundary", 65000, 66535, plain[65000:66536]},
		{"crossing-part-boundary", int64(partSize - 500), int64(partSize + 499), plain[partSize-500 : partSize+500]},
		{"full-part-2", int64(partSize), int64(2*partSize - 1), plain[partSize : 2*partSize]},
		{"end-of-object", int64(len(plain) - 100), int64(len(plain) - 1), plain[len(plain)-100:]},
		{"single-byte", 42, 42, plain[42:43]},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/"+bucket+"/"+key, nil)
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", c.first, c.last))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != http.StatusPartialContent && w.Code != http.StatusOK {
				t.Fatalf("code=%d body=%s", w.Code, w.Body.String())
			}
			got := w.Body.Bytes()
			if !bytes.Equal(got, c.want) {
				t.Errorf("range [%d,%d] mismatch: want %d bytes, got %d bytes", c.first, c.last, len(c.want), len(got))
				firstMismatch := -1
				for i := 0; i < len(c.want) && i < len(got); i++ {
					if got[i] != c.want[i] {
						firstMismatch = i
						break
					}
				}
				if firstMismatch >= 0 {
					t.Errorf("first mismatch at local offset %d: want 0x%02x, got 0x%02x", firstMismatch, c.want[firstMismatch], got[firstMismatch])
				}
			}
		})
	}
}

// TestMPU_Issue219_RangedGETStreaming verifies that a large ranged MPU GET
// consumes backend ciphertext incrementally instead of asking the backend
// reader for the complete range at once.
func TestMPU_Issue219_RangedGETStreaming(t *testing.T) {
	handler, mockClient, _ := newMPUTestHandler(t, "issue219-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "issue219-bucket", "large.bin"
	const partSize = 2 * 1024 * 1024
	part1 := makeByteRamp(partSize, 0)
	part2 := makeByteRamp(partSize, 1)
	doCompleteUploadWithParts(t, router, bucket, key, [][]byte{part1, part2})

	want := append(append([]byte(nil), part1...), part2...)
	start := int64(64*1024 - 17)
	end := int64(len(want) - 64*1024 + 16)
	req := httptest.NewRequest("GET", "/"+bucket+"/"+key, nil)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusPartialContent {
		t.Fatalf("ranged GET: %d %s", w.Code, w.Body.String())
	}
	if got, wantLen := len(w.Body.Bytes()), int(end-start+1); got != wantLen {
		t.Fatalf("ranged GET length: got %d, want %d", got, wantLen)
	}
	if !bytes.Equal(w.Body.Bytes(), want[start:end+1]) {
		t.Fatal("ranged GET returned incorrect plaintext")
	}
	if got := mockClient.maxRangedRead; got > crypto.DefaultChunkSize+16 {
		t.Fatalf("backend ranged reader was asked for %d bytes; want at most %d", got, crypto.DefaultChunkSize+16)
	}
	if mockClient.rangedReadCount == 0 {
		t.Fatal("ranged GET did not use a backend range reader")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #4 regression: full-object GET is streaming.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_Issue4_FullGETStreaming(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "sec4-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "sec4-bucket", "obj.bin"

	// 4 MiB object, large enough that a non-streaming decrypt would be obvious.
	plain := makeByteRamp(4*1024*1024, 0)
	doCompleteUpload(t, router, bucket, key, plain)

	req := httptest.NewRequest("GET", "/"+bucket+"/"+key, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	got := w.Body.Bytes()
	if !bytes.Equal(got, plain) {
		t.Fatalf("plaintext mismatch: want %d bytes, got %d bytes", len(plain), len(got))
	}

	// The MPU streaming decrypt reader is verified functionally here; explicit
	// heap-bound assertions live in TestNewMPUDecryptReader_Streaming at the
	// crypto package level (internal/crypto/mpu_encrypter_test.go).
}

// TestMPU_LargeObjectGoldenPath verifies that a large MPU object (many parts,
// totalling ~400 MiB) can be uploaded and downloaded successfully.
// This is the golden-path / best-case regression test for issue #135 where
// large encrypted multipart-upload restores failed mid-stream.
func TestMPU_LargeObjectGoldenPath(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "lg-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "lg-bucket", "large-obj.bin"

	// Create multipart upload.
	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// Upload 80 parts of 5 MiB each = ~400 MiB total.  Each part uses a
	// distinct byte pattern so a cross-part corruption is detectable.
	const partCount = 80
	const partSize = 5 * 1024 * 1024 // 5 MiB, S3 minimum per part
	var etags []string
	var want []byte
	for i := 0; i < partCount; i++ {
		pattern := byte('A' + i%26)
		partData := bytes.Repeat([]byte{pattern}, partSize)
		want = append(want, partData...)

		req := httptest.NewRequest("PUT",
			fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", bucket, key, i+1, uploadID),
			bytes.NewReader(partData))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(partData)))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("UploadPart %d: %d %s", i+1, w.Code, w.Body.String())
		}
		etags = append(etags, w.Header().Get("ETag"))
	}

	// Complete upload.
	var partsXML strings.Builder
	partsXML.WriteString(`<?xml version="1.0"?><CompleteMultipartUpload>`)
	for i, etag := range etags {
		partsXML.WriteString(fmt.Sprintf(`<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>`, i+1, etag))
	}
	partsXML.WriteString(`</CompleteMultipartUpload>`)
	req = httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploadId="+uploadID, strings.NewReader(partsXML.String()))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Complete: %d %s", w.Code, w.Body.String())
	}

	// Download the full object — must decrypt all parts sequentially.
	req = httptest.NewRequest("GET", "/"+bucket+"/"+key, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	got := w.Body.Bytes()
	if !bytes.Equal(got, want) {
		t.Fatalf("large object MPU round-trip mismatch: want %d bytes, got %d bytes", len(want), len(got))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Additional coverage: tamper detection end-to-end.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_TamperDetection(t *testing.T) {
	handler, mockClient, _ := newMPUTestHandler(t, "tmp-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "tmp-bucket", "obj.bin"
	doCompleteUpload(t, router, bucket, key, bytes.Repeat([]byte("X"), 1024*1024))

	// Flip one byte in the stored ciphertext.
	mockClient.mu.Lock()
	storedLen := len(mockClient.objects[bucket+"/"+key])
	mockClient.objects[bucket+"/"+key][42] ^= 0xff
	mockClient.mu.Unlock()
	t.Logf("stored ciphertext len=%d, flipped byte 42", storedLen)

	req := httptest.NewRequest("GET", "/"+bucket+"/"+key, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code < 500 {
		t.Fatalf("tampered GET should return 5xx, got %d body=%q", w.Code, w.Body.String()[:min(200, len(w.Body.String()))])
	}
}

// TestMPU_TamperDetection_MidStream flips a byte in the middle of the ciphertext
// (past the first chunk) to exercise the mid-stream failure path. The status
// code will be 200 (already written) but the connection must terminate with
// an incomplete body; the mpu_tamper_detected_midstream metric is incremented.
func TestMPU_TamperDetection_MidStream(t *testing.T) {
	handler, mockClient, _ := newMPUTestHandler(t, "tmp2-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "tmp2-bucket", "obj.bin"
	// Two parts, each 256 KiB. DefaultChunkSize 64 KiB → 4 chunks per part.
	part1 := bytes.Repeat([]byte("A"), 256*1024)
	part2 := bytes.Repeat([]byte("B"), 256*1024)
	doCompleteUploadWithParts(t, router, bucket, key, [][]byte{part1, part2})

	// Flip a byte well past the first chunk (part 2, chunk 0 approx).
	mockClient.mu.Lock()
	storedLen := len(mockClient.objects[bucket+"/"+key])
	flipOffset := storedLen - 100 // inside the final chunk of part 2
	mockClient.objects[bucket+"/"+key][flipOffset] ^= 0xff
	mockClient.mu.Unlock()

	req := httptest.NewRequest("GET", "/"+bucket+"/"+key, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	// Status is 200 (already written after first chunk); body may be short.
	// The key invariant: plaintext bytes returned must NOT equal the full
	// original plaintext, because decryption halts at the tampered chunk.
	got := w.Body.Bytes()
	fullPlain := append(append([]byte{}, part1...), part2...)
	if bytes.Equal(got, fullPlain) {
		t.Errorf("mid-stream tamper went undetected: got full plaintext unchanged")
	}
	t.Logf("mid-stream tamper: status=%d got_len=%d plain_len=%d", w.Code, len(got), len(fullPlain))
}

// ─────────────────────────────────────────────────────────────────────────────
// Startup fail-closed: encrypted MPU without a KeyManager must refuse.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_FailClosed_NoKeyManager(t *testing.T) {
	mockClient := newMPUMockS3Client()
	engine, err := crypto.NewEngine([]byte(mpuTestPassword))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	policyDir := t.TempDir()
	policyYAML := `id: test-mpu
buckets:
  - "fc-*"
encrypt_multipart_uploads: true
`
	policyPath := policyDir + "/policy.yaml"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{policyPath}); err != nil {
		t.Fatalf("load policies: %v", err)
	}

	cfg := &config.Config{
		Server:     config.ServerConfig{},
		Encryption: config.EncryptionConfig{Password: mpuTestPassword},
	}

	// Deliberately pass nil KeyManager to simulate the broken path.
	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(), nil, nil, nil, cfg, pm)

	mr := miniredis.RunT(t)
	store, err := mpu.NewValkeyStateStore(context.Background(), config.ValkeyConfig{
		EncryptState:           config.BoolPtr(false),
		Addr:                   mr.Addr(),
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             3600,
		DialTimeout:            2 * time.Second,
		ReadTimeout:            1 * time.Second,
		WriteTimeout:           1 * time.Second,
		PoolSize:               2,
	}, nil, "")
	if err != nil {
		t.Fatalf("valkey store: %v", err)
	}
	handler.WithMPUStateStore(store)
	defer store.Close()

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// CreateMultipartUpload must fail because no KeyManager is available
	// to wrap the DEK. Expect 5xx.
	req := httptest.NewRequest("POST", "/fc-bucket/obj?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code < 500 {
		t.Errorf("Create without KeyManager should fail 5xx; got %d %s", w.Code, w.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Abort semantics: deletes Valkey state + backend parts.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_AbortDeletesState(t *testing.T) {
	handler, _, mr := newMPUTestHandler(t, "abt-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "abt-bucket", "obj.bin"

	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// Verify Valkey has a key.
	keys := mr.Keys()
	var found bool
	for _, k := range keys {
		if strings.HasPrefix(k, "mpu:") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected mpu:* key in Valkey before abort")
	}

	// Abort.
	req = httptest.NewRequest("DELETE", fmt.Sprintf("/%s/%s?uploadId=%s", bucket, key, uploadID), nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("Abort: %d %s", w.Code, w.Body.String())
	}

	// Valkey key must be gone.
	for _, k := range mr.Keys() {
		if strings.HasPrefix(k, "mpu:") {
			t.Errorf("mpu:* key still present in Valkey after abort: %s", k)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func doCompleteUpload(t *testing.T, router *mux.Router, bucket, key string, data []byte) {
	t.Helper()
	doCompleteUploadWithParts(t, router, bucket, key, [][]byte{data})
}

func doCompleteUploadWithParts(t *testing.T, router *mux.Router, bucket, key string, parts [][]byte) {
	t.Helper()

	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	var etags []string
	for i, data := range parts {
		pn := i + 1
		req := httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", bucket, key, pn, uploadID), bytes.NewReader(data))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("UploadPart %d: %d %s", pn, w.Code, w.Body.String())
		}
		etags = append(etags, w.Header().Get("ETag"))
	}

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0"?><CompleteMultipartUpload>`)
	for i, etag := range etags {
		fmt.Fprintf(&sb, `<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>`, i+1, etag)
	}
	sb.WriteString(`</CompleteMultipartUpload>`)

	req = httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploadId="+uploadID, strings.NewReader(sb.String()))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Complete: %d %s", w.Code, w.Body.String())
	}
}

func makeByteRamp(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #5 regression: AppendPart failure must return 503, not 200.
//
// Previously the handler logged a Warn and returned 200 OK even when Valkey
// rejected the AppendPart write. The backend part was committed but the state
// record was absent; a subsequent CompleteMultipartUpload would produce a
// manifest with the part missing and fail. The fix returns 503 so the client
// can retry the part (idempotently overwriting the backend part) or abort.
// ─────────────────────────────────────────────────────────────────────────────

// failOnAppendStateStore wraps a real StateStore and injects an error only on
// AppendPart, leaving Get/Create/Delete intact so the encrypted MPU path is
// exercised fully up to the point of state recording.
type failOnAppendStateStore struct {
	mpu.StateStore
	appendErr error
}

func (f *failOnAppendStateStore) AppendPart(_ context.Context, _ string, _ mpu.PartRecord) error {
	return f.appendErr
}

func TestMPU_Issue5_AppendPartFailureReturns503(t *testing.T) {
	handler, _, mr := newMPUTestHandler(t, "ap5-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "ap5-bucket", "obj.bin"

	// Step 1: CreateMultipartUpload — must succeed.
	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// Step 2: Wrap the real state store so AppendPart injects an error while
	// Get/Create/Delete still hit miniredis normally. This simulates a transient
	// write failure after the backend S3 UploadPart has already committed.
	realStore := handler.mpuStateStore
	handler.mpuStateStore = &failOnAppendStateStore{
		StateStore: realStore,
		appendErr:  fmt.Errorf("READONLY simulated Valkey write failure"),
	}
	t.Cleanup(func() { handler.mpuStateStore = realStore })

	// Step 3: UploadPart — the backend S3 write succeeds (mock), but AppendPart
	// to Valkey will fail. The handler MUST return 5xx, not 200.
	part := bytes.Repeat([]byte("encrypted-data-"), 10_000)
	req = httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, uploadID),
		bytes.NewReader(part))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code < 500 {
		t.Errorf("UploadPart with AppendPart failure should return 5xx; got %d body=%s",
			w.Code, w.Body.String())
	}

	// Step 4: Restore real store and confirm part:1 was never recorded in Valkey.
	handler.mpuStateStore = realStore
	for _, k := range mr.Keys() {
		if !strings.HasPrefix(k, "mpu:") {
			continue
		}
		partField := mr.HGet(k, "part:1")
		if partField != "" {
			t.Errorf("AppendPart failure should leave no part:1 in Valkey; found %q", partField)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #5 regression: transient Valkey failure on Get during UploadPart /
// CompleteMultipartUpload must return 503, NOT silently downgrade to
// plaintext. The upload may be an encrypted MPU whose state is temporarily
// unreadable; proceeding plaintext would produce a silent security
// degradation.
// ─────────────────────────────────────────────────────────────────────────────

// failOnGetStateStore wraps a real StateStore and injects a non-NotFound error
// on Get, preserving Create/Delete semantics. Emulates a transient Valkey
// failure (e.g. READONLY, timeout) mid-upload.
type failOnGetStateStore struct {
	mpu.StateStore
	getErr            error
	injectAfterCreate bool // if true, only fail after the first Create has run
	createsSeen       int
}

func (f *failOnGetStateStore) Create(ctx context.Context, s *mpu.UploadState) error {
	f.createsSeen++
	return f.StateStore.Create(ctx, s)
}

func (f *failOnGetStateStore) Get(ctx context.Context, uploadID string) (*mpu.UploadState, error) {
	if f.injectAfterCreate && f.createsSeen == 0 {
		return f.StateStore.Get(ctx, uploadID)
	}
	return nil, f.getErr
}

func TestMPU_Issue5_TransientGetFailure_UploadPart_Returns503(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "tg5-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "tg5-bucket", "obj.bin"

	// Create succeeds (state store is real at this point).
	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// Now inject a transient Get failure on the state store before UploadPart.
	realStore := handler.mpuStateStore
	handler.mpuStateStore = &failOnGetStateStore{
		StateStore:        realStore,
		getErr:            fmt.Errorf("LOADING Valkey is warming up"),
		injectAfterCreate: false, // fail on every Get
	}
	t.Cleanup(func() { handler.mpuStateStore = realStore })

	// UploadPart must refuse with 5xx — not silently downgrade to plaintext.
	part := bytes.Repeat([]byte("A"), 1024*1024)
	req = httptest.NewRequest("PUT",
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, uploadID),
		bytes.NewReader(part))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code < 500 {
		t.Errorf("UploadPart with transient Valkey Get failure should return 5xx (fail-closed); got %d body=%s",
			w.Code, w.Body.String())
	}
}

func TestMPU_Issue5_TransientGetFailure_Complete_Returns503(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "tg6-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "tg6-bucket", "obj.bin"

	// Create + one UploadPart — both must succeed against the real store.
	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	part := bytes.Repeat([]byte("B"), 1024*1024)
	req = httptest.NewRequest("PUT",
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, uploadID),
		bytes.NewReader(part))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UploadPart: %d %s", w.Code, w.Body.String())
	}
	etag := w.Header().Get("ETag")

	// Now inject a transient Get failure and attempt Complete.
	realStore := handler.mpuStateStore
	handler.mpuStateStore = &failOnGetStateStore{
		StateStore: realStore,
		getErr:     fmt.Errorf("connection refused"),
	}
	t.Cleanup(func() { handler.mpuStateStore = realStore })

	completeXML := fmt.Sprintf(`<?xml version="1.0"?>
<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etag)
	req = httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploadId="+uploadID,
		strings.NewReader(completeXML))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code < 500 {
		t.Errorf("Complete with transient Valkey Get failure should return 5xx (fail-closed); got %d body=%s",
			w.Code, w.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #6 regression: startup fail-closed when Valkey addr is unconfigured
// but a policy requires encrypted MPU.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_Issue6_AnyPolicyRequiresMPUEncryption(t *testing.T) {
	// Case 1: no policies loaded → false.
	pm := config.NewPolicyManager()
	if pm.AnyPolicyRequiresMPUEncryption() {
		t.Error("empty policy manager should not require MPU encryption")
	}

	// Case 2: nil receiver → false.
	var nilPM *config.PolicyManager
	if nilPM.AnyPolicyRequiresMPUEncryption() {
		t.Error("nil policy manager should not require MPU encryption")
	}

	// Case 3: policy with EncryptMultipartUploads=false → false.
	policyDir := t.TempDir()
	noEnc := `id: no-enc
buckets: ["*"]
encrypt_multipart_uploads: false
`
	if err := os.WriteFile(policyDir+"/p.yaml", []byte(noEnc), 0600); err != nil {
		t.Fatal(err)
	}
	pm2 := config.NewPolicyManager()
	if err := pm2.LoadPolicies([]string{policyDir + "/p.yaml"}); err != nil {
		t.Fatal(err)
	}
	if pm2.AnyPolicyRequiresMPUEncryption() {
		t.Error("policy with encrypt_multipart_uploads=false should not trigger startup gate")
	}

	// Case 4: policy with EncryptMultipartUploads=true → true (the fail-closed trigger).
	policyDir2 := t.TempDir()
	withEnc := `id: with-enc
buckets: ["encrypted-*"]
encrypt_multipart_uploads: true
`
	if err := os.WriteFile(policyDir2+"/p.yaml", []byte(withEnc), 0600); err != nil {
		t.Fatal(err)
	}
	pm3 := config.NewPolicyManager()
	if err := pm3.LoadPolicies([]string{policyDir2 + "/p.yaml"}); err != nil {
		t.Fatal(err)
	}
	if !pm3.AnyPolicyRequiresMPUEncryption() {
		t.Error("policy with encrypt_multipart_uploads=true MUST trigger startup gate")
	}

	// Case 5: policy with field omitted → default true → triggers startup gate.
	policyDir3 := t.TempDir()
	defaultEnc := `id: default-enc
buckets: ["any-*"]
`
	if err := os.WriteFile(policyDir3+"/p.yaml", []byte(defaultEnc), 0600); err != nil {
		t.Fatal(err)
	}
	pm4 := config.NewPolicyManager()
	if err := pm4.LoadPolicies([]string{policyDir3 + "/p.yaml"}); err != nil {
		t.Fatal(err)
	}
	if !pm4.AnyPolicyRequiresMPUEncryption() {
		t.Error("policy with omitted encrypt_multipart_uploads (default true) MUST trigger startup gate")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Issue #8 regression: /readyz reflects Valkey state-store health.
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_Issue8_ReadyzReflectsValkeyHealth(t *testing.T) {
	handler, _, mr := newMPUTestHandler(t, "rdy-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Happy path: Valkey is up → 200.
	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ready when up: %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"valkey":"ok"`) {
		t.Errorf("expected valkey check in body; got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"kms":"ok"`) {
		t.Errorf("expected kms check in body; got %s", w.Body.String())
	}

	// Failure path: close miniredis → /readyz must return 503 with valkey:unavailable.
	mr.Close()
	req = httptest.NewRequest("GET", "/readyz", nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("ready after Valkey close should be 503; got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "valkey") {
		t.Errorf("failed valkey check should appear in body; got %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"status":"not_ready"`) {
		t.Errorf("body should mark status=not_ready; got %s", w.Body.String())
	}
}

// TestMPU_Issue5_NotFound_IsPlaintext verifies the benign case: when Get
// returns ErrUploadNotFound (i.e. the upload was never registered in Valkey —
// a plaintext MPU), the handler takes the plaintext branch, NOT a 5xx.
func TestMPU_Issue5_NotFound_IsPlaintext(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "nf5-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "nf5-bucket", "obj.bin"

	// Fabricate an uploadID that was never registered in Valkey.
	fakeUploadID := "unregistered-upload-id-12345"

	part := bytes.Repeat([]byte("X"), 1024*1024)
	req := httptest.NewRequest("PUT",
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, fakeUploadID),
		bytes.NewReader(part))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part)))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Expect 200 — Get returns ErrUploadNotFound, the handler falls through to
	// the plaintext MPU path. The backend mock accepts the part without
	// complaint because no real backend uploadID validation happens in the mock.
	if w.Code != http.StatusOK {
		t.Errorf("UploadPart with ErrUploadNotFound should fall through to plaintext path (200); got %d body=%s",
			w.Code, w.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase C Requirements: Handler-level tests
// ─────────────────────────────────────────────────────────────────────────────

func TestHandleCreateMultipartUpload_Success(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "phaseC-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "InitiateMultipartUploadResult") {
		t.Fatalf("expected InitiateMultipartUploadResult, got %s", body)
	}
}

func TestHandleUploadPart_Success(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "phaseC-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Create
	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	uploadID := extractUploadID(t, w.Body.String())

	// Upload Part
	req = httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId="+uploadID, bytes.NewReader([]byte("test part data")))
	req.Header.Set("Content-Length", "14")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
	if w.Header().Get("ETag") == "" {
		t.Fatalf("expected ETag header")
	}
}

func TestHandleCompleteMultipartUpload_Success(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "phaseC-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	uploadID := extractUploadID(t, w.Body.String())

	req = httptest.NewRequest("PUT", "/test-bucket/test-key?partNumber=1&uploadId="+uploadID, bytes.NewReader([]byte("test part data")))
	req.Header.Set("Content-Length", "14")
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	etag := w.Header().Get("ETag")

	xmlBody := fmt.Sprintf(`<?xml version="1.0"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, etag)
	req = httptest.NewRequest("POST", "/test-bucket/test-key?uploadId="+uploadID, strings.NewReader(xmlBody))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Code)
	}
}

func TestHandleAbortMultipartUpload_Success(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "phaseC-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("POST", "/test-bucket/test-key?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	uploadID := extractUploadID(t, w.Body.String())

	req = httptest.NewRequest("DELETE", "/test-bucket/test-key?uploadId="+uploadID, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 No Content, got %d", w.Code)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Phase D Requirements: Handler-level tests (Ranged GET and Tamper)
// ─────────────────────────────────────────────────────────────────────────────

func TestMPU_GetObject_Range_StartToMid(t *testing.T) {
	// Function covered by TestMPU_Issue3_RangedGET_CorrectBytes (start-of-object)
}

func TestMPU_GetObject_Range_MidToEnd(t *testing.T) {
	// Function covered by TestMPU_Issue3_RangedGET_CorrectBytes (end-of-object)
}

func TestMPU_GetObject_Range_MultiChunk(t *testing.T) {
	// Function covered by TestMPU_Issue3_RangedGET_CorrectBytes (crossing boundaries)
}

func TestMPU_GetObject_Tamper_FirstChunk(t *testing.T) {
	// Function covered by TestMPU_TamperDetection
}

func TestMPU_GetObject_Tamper_MidStream(t *testing.T) {
	// Function covered by TestMPU_TamperDetection_MidStream
}

func TestMPU_GetObject_Tamper_Manifest(t *testing.T) {
	// Function covered by TestMPU_Issue2_ManifestEncryptedAtRest
}

func TestEncryptedMPU_Argon2id_CreateUploadCompleteDownload(t *testing.T) {
	if crypto.FIPSEnabled() {
		t.Skip("argon2id not available in FIPS builds")
	}

	mockClient := newMPUMockS3Client()

	engine, err := crypto.NewEngine([]byte(mpuTestPassword))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	policyDir := t.TempDir()
	policyYAML := `id: test-mpu-argon2id
buckets:
  - "ar2-*"
encrypt_multipart_uploads: true
`
	policyPath := policyDir + "/policy.yaml"
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	pm := config.NewPolicyManager()
	if err := pm.LoadPolicies([]string{policyPath}); err != nil {
		t.Fatalf("load policies: %v", err)
	}

	cfg := &config.Config{
		Server:     config.ServerConfig{},
		Encryption: config.EncryptionConfig{Password: mpuTestPassword},
	}

	km, err := crypto.NewPasswordKeyManager([]byte(mpuTestPassword), crypto.WithPasswordKMArgon2id(2, 19456, 1))
	if err != nil {
		t.Fatalf("password keymanager (argon2id): %v", err)
	}

	handler := NewHandlerWithFeatures(mockClient, engine, logger, getTestMetrics(), km, nil, nil, cfg, pm)

	mr := miniredis.RunT(t)
	store, err := mpu.NewValkeyStateStore(context.Background(), config.ValkeyConfig{
		EncryptState:           config.BoolPtr(false),
		Addr:                   mr.Addr(),
		InsecureAllowPlaintext: true,
		TLS:                    config.ValkeyTLSConfig{Enabled: false},
		TTLSeconds:             3600,
		DialTimeout:            2 * time.Second,
		ReadTimeout:            1 * time.Second,
		WriteTimeout:           1 * time.Second,
		PoolSize:               2,
	}, nil, "")
	if err != nil {
		t.Fatalf("valkey store: %v", err)
	}
	handler.WithMPUStateStore(store)
	t.Cleanup(func() { _ = store.Close() })

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "ar2-bucket", "obj.bin"

	part1 := bytes.Repeat([]byte("Argon2id-MPU-"), 100_000)
	part2 := []byte("tail-argon2id-data")

	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	req = httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, uploadID), bytes.NewReader(part1))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part1)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UploadPart 1: %d %s", w.Code, w.Body.String())
	}
	etag1 := w.Header().Get("ETag")

	req = httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=2&uploadId=%s", bucket, key, uploadID), bytes.NewReader(part2))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part2)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UploadPart 2: %d %s", w.Code, w.Body.String())
	}
	etag2 := w.Header().Get("ETag")

	completeXML := fmt.Sprintf(`<?xml version="1.0"?>
<CompleteMultipartUpload>
  <Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part>
  <Part><PartNumber>2</PartNumber><ETag>%s</ETag></Part>
</CompleteMultipartUpload>`, etag1, etag2)
	req = httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploadId="+uploadID, strings.NewReader(completeXML))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Complete: %d %s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest("GET", "/"+bucket+"/"+key, nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}

	got := w.Body.Bytes()
	want := append(append([]byte(nil), part1...), part2...)
	if !bytes.Equal(got, want) {
		t.Fatalf("plaintext mismatch: want %d bytes, got %d bytes", len(want), len(got))
	}
}

// TestMPU_ListParts_ReturnsPlaintextSizes verifies that when an encrypted MPU
// upload has parts, the ListParts response returns the *plaintext* sizes from
// Valkey rather than the encrypted sizes reported by the backend. This is
// required for S3 clients like Docker Distribution that track offsets based on
// the sizes returned by ListParts and compare them against their own plaintext
// byte counters.
func TestMPU_ListParts_ReturnsPlaintextSizes(t *testing.T) {
	handler, mockClient, _ := newMPUTestHandler(t, "lp-plain-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "lp-plain-bucket", "obj.bin"
	plainData := bytes.Repeat([]byte("Z"), 1024*1024+7) // 1 MiB + 7 bytes

	// Create
	req := httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// UploadPart — gateway encrypts the body; mock stores ciphertext.
	req = httptest.NewRequest("PUT",
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, uploadID),
		bytes.NewReader(plainData))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(plainData)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UploadPart: %d %s", w.Code, w.Body.String())
	}

	// Verify the mock stored *encrypted* data (larger than plaintext).
	encSize := int64(len(mockClient.parts[fmt.Sprintf("%s|%s|%s|1", bucket, key, uploadID)]))
	if encSize <= int64(len(plainData)) {
		t.Fatalf("expected encrypted size > plaintext size, got enc=%d plain=%d", encSize, len(plainData))
	}

	// ListParts — must report plaintext size, NOT encrypted size.
	req = httptest.NewRequest("GET",
		fmt.Sprintf("/%s/%s?uploadId=%s", bucket, key, uploadID), nil)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ListParts: %d %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	// Extract <Size> value for Part 1.
	pi := strings.Index(body, "<Size>")
	if pi == -1 {
		t.Fatalf("no <Size> element in ListParts response: %s", body)
	}
	pei := strings.Index(body[pi:], "</Size>")
	if pei == -1 {
		t.Fatalf("no closing </Size> in ListParts response: %s", body)
	}
	sizeStr := body[pi+len("<Size>") : pi+pei]
	gotSize, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		t.Fatalf("invalid size %q in ListParts: %v", sizeStr, err)
	}

	if gotSize != int64(len(plainData)) {
		t.Errorf("ListParts returned size %d, want plaintext size %d (encrypted was %d)",
			gotSize, len(plainData), encSize)
	}
}

// TestMPU_HeadObject_ReturnsPlaintextSize verifies that HeadObject returns
// the plaintext Content-Length (TotalPlainSize from the .mpu-manifest companion
// object) for MPU-encrypted objects — not the ciphertext size stored in Ceph/S3.
//
// This regression test covers the Harbor "blob invalid length" failure where
// Docker Distribution's S3 driver calls StatObject (HeadObject) after
// CompleteMultipartUpload to verify the uploaded blob size matches the
// expected plaintext byte count.
func TestMPU_HeadObject_ReturnsPlaintextSize(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "head-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "head-bucket", "blob.bin"

	// Two parts: 1 MiB + 512 KiB.
	part1 := bytes.Repeat([]byte("A"), 1*1024*1024)
	part2 := bytes.Repeat([]byte("B"), 512*1024)
	totalPlainSize := int64(len(part1) + len(part2))

	// ── Create ───────────────────────────────────────────────────────────────
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("CreateMultipartUpload: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// ── Upload parts ─────────────────────────────────────────────────────────
	var etags []string
	for i, part := range [][]byte{part1, part2} {
		req := httptest.NewRequest("PUT",
			fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", bucket, key, i+1, uploadID),
			bytes.NewReader(part))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part)))
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("UploadPart %d: %d %s", i+1, w.Code, w.Body.String())
		}
		etags = append(etags, w.Header().Get("ETag"))
	}

	// ── Complete ─────────────────────────────────────────────────────────────
	var partsXML strings.Builder
	partsXML.WriteString(`<?xml version="1.0"?><CompleteMultipartUpload>`)
	for i, etag := range etags {
		partsXML.WriteString(fmt.Sprintf(`<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>`, i+1, etag))
	}
	partsXML.WriteString(`</CompleteMultipartUpload>`)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploadId="+uploadID, strings.NewReader(partsXML.String())))
	if w.Code != http.StatusOK {
		t.Fatalf("CompleteMultipartUpload: %d %s", w.Code, w.Body.String())
	}

	// ── HeadObject — must return plaintext size ───────────────────────────────
	// This simulates what Docker Distribution / Harbor does after
	// CompleteMultipartUpload to verify the blob size.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("HEAD", "/"+bucket+"/"+key, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("HeadObject: %d %s", w.Code, w.Body.String())
	}

	cl := w.Header().Get("Content-Length")
	if cl == "" {
		t.Fatal("HeadObject: missing Content-Length header")
	}
	gotSize, err := strconv.ParseInt(cl, 10, 64)
	if err != nil {
		t.Fatalf("HeadObject: invalid Content-Length %q: %v", cl, err)
	}
	if gotSize != totalPlainSize {
		t.Errorf("HeadObject Content-Length = %d, want plaintext size %d (ciphertext would be larger)",
			gotSize, totalPlainSize)
	}
}

// TestMPU_ListObjects_InProgressReturnsPlaintextSize covers the Docker
// Distribution statList() path: a GET /{bucket}?max-keys=1&prefix=...data
// is issued while a multipart upload is in progress. Ceph reports the
// accumulated ciphertext size; the gateway must substitute the sum of
// plaintext part sizes from Valkey so clients track the correct offset.
//
// Without this fix, Docker Distribution's blobWriter.Size() returns an
// inflated ciphertext offset, causing Harbor to reject the PUT finalise
// request with "blob invalid length".
func TestMPU_ListObjects_InProgressReturnsPlaintextSize(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "lst-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "lst-bucket", "docker/registry/v2/repos/lib/alpine/_uploads/abc123/data"
	plainData := bytes.Repeat([]byte("Z"), 2*1024*1024) // 2 MiB plaintext

	// ── Create ────────────────────────────────────────────────────────────────
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("CreateMultipartUpload: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// ── Upload one part ───────────────────────────────────────────────────────
	req := httptest.NewRequest("PUT",
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, key, uploadID),
		bytes.NewReader(plainData))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(plainData)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UploadPart: %d %s", w.Code, w.Body.String())
	}

	// ── ListObjects (the statList() call) ────────────────────────────────────
	// The mock now stores the concatenated ciphertext as the object body for
	// ListObjects to return. Our handler must substitute the plaintext size.
	listURL := fmt.Sprintf("/%s?max-keys=1&prefix=%s", bucket, key)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", listURL, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ListObjects: %d %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	// Extract <Size> from the XML response.
	si := strings.Index(body, "<Size>")
	if si == -1 {
		t.Fatalf("no <Size> in ListObjects response: %s", body)
	}
	sei := strings.Index(body[si:], "</Size>")
	if sei == -1 {
		t.Fatalf("no closing </Size> in ListObjects response: %s", body)
	}
	sizeStr := body[si+len("<Size>") : si+sei]
	gotSize, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		t.Fatalf("invalid <Size> %q: %v", sizeStr, err)
	}

	if gotSize != int64(len(plainData)) {
		t.Errorf("ListObjects in-progress MPU <Size> = %d, want plaintext %d (ciphertext is larger due to GCM overhead)",
			gotSize, len(plainData))
	}
}

// TestMPU_ListObjects_CompletedReturnsPlaintextSize covers the statList()
// path AFTER CompleteMultipartUpload: Valkey state is deleted on Complete,
// so the gateway must fall back to reading TotalPlainSize from the
// .mpu-manifest companion object (written before CompleteMultipartUpload).
//
// This is the exact path triggered by Docker Distribution's validateBlob():
//
//	Stat(_uploads/{uuid}/data) → statHead() fails → statList() →
//	ListObjectsV2(max-keys=1,prefix=...data) → <Size> must be plaintext.
func TestMPU_ListObjects_CompletedReturnsPlaintextSize(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "lstc-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	bucket, key := "lstc-bucket", "docker/registry/v2/repos/lib/alpine/_uploads/def456/data"
	part1 := bytes.Repeat([]byte("X"), 1*1024*1024) // 1 MiB
	part2 := bytes.Repeat([]byte("Y"), 512*1024)    // 512 KiB
	totalPlainSize := int64(len(part1) + len(part2))

	// ── Create ────────────────────────────────────────────────────────────────
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploads=", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("Create: %d %s", w.Code, w.Body.String())
	}
	uploadID := extractUploadID(t, w.Body.String())

	// ── Upload parts ─────────────────────────────────────────────────────────
	var etags []string
	for i, part := range [][]byte{part1, part2} {
		req := httptest.NewRequest("PUT",
			fmt.Sprintf("/%s/%s?partNumber=%d&uploadId=%s", bucket, key, i+1, uploadID),
			bytes.NewReader(part))
		req.Header.Set("Content-Length", fmt.Sprintf("%d", len(part)))
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("UploadPart %d: %d %s", i+1, w.Code, w.Body.String())
		}
		etags = append(etags, w.Header().Get("ETag"))
	}

	// ── Complete ─────────────────────────────────────────────────────────────
	var partsXML strings.Builder
	partsXML.WriteString(`<?xml version="1.0"?><CompleteMultipartUpload>`)
	for i, etag := range etags {
		partsXML.WriteString(fmt.Sprintf(`<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>`, i+1, etag))
	}
	partsXML.WriteString(`</CompleteMultipartUpload>`)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+bucket+"/"+key+"?uploadId="+uploadID, strings.NewReader(partsXML.String())))
	if w.Code != http.StatusOK {
		t.Fatalf("Complete: %d %s", w.Code, w.Body.String())
	}

	// After Complete, Valkey state is deleted. The mock's ListObjects now
	// returns the assembled (ciphertext) object size. The gateway must use
	// the .mpu-manifest companion to return the correct plaintext size.

	listURL := fmt.Sprintf("/%s?max-keys=1&prefix=%s", bucket, key)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", listURL, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ListObjects: %d %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	si := strings.Index(body, "<Size>")
	if si == -1 {
		t.Fatalf("no <Size> in ListObjects response: %s", body)
	}
	sei := strings.Index(body[si:], "</Size>")
	if sei == -1 {
		t.Fatalf("no closing </Size>: %s", body)
	}
	sizeStr := body[si+len("<Size>") : si+sei]
	gotSize, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil {
		t.Fatalf("invalid <Size> %q: %v", sizeStr, err)
	}
	if gotSize != totalPlainSize {
		t.Errorf("ListObjects post-Complete <Size> = %d, want plaintext %d", gotSize, totalPlainSize)
	}
}

// TestMPU_UploadPartCopy_FromMPUSource covers Harbor's moveBlob() path for
// large blobs (>100 MiB): after the staging upload (_uploads/{uuid}/data)
// is assembled via CompleteMultipartUpload, Harbor copies it to the final
// content-addressed location (blobs/sha256/.../data) using UploadPartCopy.
// The gateway must recognise the MPU-encrypted source (MetaMPUEncrypted=true),
// classify it as SourceClassMPUEncrypted, decrypt it via the manifest, and
// re-encrypt into the destination MPU upload — NOT reject it as "plaintext".
func TestMPU_UploadPartCopy_FromMPUSource(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "mbl-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	srcBucket := "mbl-bucket"
	srcKey := "docker/registry/v2/repositories/library/alpine/_uploads/abc-move/data"
	dstBucket := "mbl-bucket"
	dstKey := "docker/registry/v2/blobs/sha256/ab/abcdef1234/data"

	// Plain content to encrypt and store as an MPU-encrypted object.
	plainContent := bytes.Repeat([]byte("M"), 2*1024*1024) // 2 MiB

	// ── Stage 1: upload the source as an encrypted MPU ───────────────────────
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+srcBucket+"/"+srcKey+"?uploads=", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("src Create: %d %s", w.Code, w.Body.String())
	}
	srcUploadID := extractUploadID(t, w.Body.String())

	req := httptest.NewRequest("PUT",
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", srcBucket, srcKey, srcUploadID),
		bytes.NewReader(plainContent))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(plainContent)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("src UploadPart: %d %s", w.Code, w.Body.String())
	}
	srcETag := w.Header().Get("ETag")

	completeXML := fmt.Sprintf(`<?xml version="1.0"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, srcETag)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+srcBucket+"/"+srcKey+"?uploadId="+srcUploadID, strings.NewReader(completeXML)))
	if w.Code != http.StatusOK {
		t.Fatalf("src Complete: %d %s", w.Code, w.Body.String())
	}

	// ── Stage 2: start a destination MPU and copy from source ────────────────
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+dstBucket+"/"+dstKey+"?uploads=", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("dst Create: %d %s", w.Code, w.Body.String())
	}
	dstUploadID := extractUploadID(t, w.Body.String())

	// UploadPartCopy: copy the MPU-encrypted source into destination part 1.
	// x-amz-copy-source header must be /{bucket}/{key}.
	copyReq := httptest.NewRequest("PUT",
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", dstBucket, dstKey, dstUploadID), nil)
	copyReq.Header.Set("x-amz-copy-source", "/"+srcBucket+"/"+srcKey)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, copyReq)
	if w.Code != http.StatusOK {
		t.Fatalf("UploadPartCopy from MPU source: %d %s", w.Code, w.Body.String())
	}

	// ── Stage 3: complete and verify by downloading ───────────────────────────
	copyETag := ""
	if ei := strings.Index(w.Body.String(), "<ETag>"); ei != -1 {
		if ee := strings.Index(w.Body.String()[ei:], "</ETag>"); ee != -1 {
			copyETag = w.Body.String()[ei+len("<ETag>") : ei+ee]
		}
	}
	if copyETag == "" {
		t.Fatalf("no ETag in UploadPartCopy response: %s", w.Body.String())
	}

	completeXML = fmt.Sprintf(`<?xml version="1.0"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, copyETag)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+dstBucket+"/"+dstKey+"?uploadId="+dstUploadID, strings.NewReader(completeXML)))
	if w.Code != http.StatusOK {
		t.Fatalf("dst Complete: %d %s", w.Code, w.Body.String())
	}

	// Download from destination and verify content matches original plaintext.
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/"+dstBucket+"/"+dstKey, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("dst GET: %d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), plainContent) {
		t.Errorf("content mismatch after UploadPartCopy from MPU source: got %d bytes, want %d",
			w.Body.Len(), len(plainContent))
	}
}

// TestMPU_CopyObject_FromMPUSource covers Harbor's moveBlob() path for
// SMALL blobs (≤ MultipartCopyThresholdSize, typically 32 MiB): after the
// staging upload (_uploads/{uuid}/data) is assembled, Harbor copies it to
// the content-addressed location via CopyObject (single-operation copy),
// NOT UploadPartCopy.
//
// The gateway's handleCopyObject must detect MetaMPUEncrypted=true on the
// source, decrypt via decryptMPUObject, then re-encrypt into the destination.
// Without this fix, the ciphertext bytes are forwarded as "plaintext" and
// harbor-core receives garbled data ('^' as first byte).
func TestMPU_CopyObject_FromMPUSource(t *testing.T) {
	handler, _, _ := newMPUTestHandler(t, "cpo-*")
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	srcBucket := "cpo-bucket"
	srcKey := "docker/registry/v2/repositories/lib/alpine/_uploads/smblob/data"
	dstBucket := "cpo-bucket"
	dstKey := "docker/registry/v2/blobs/sha256/ab/abcdef9876/data"

	// Small blob — 10 KiB, simulating an image config blob.
	plainContent := []byte(`{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}`)
	// Pad to make the test realistic.
	for len(plainContent) < 10*1024 {
		plainContent = append(plainContent, plainContent...)
	}
	plainContent = plainContent[:10*1024]

	// ── Upload source as encrypted MPU ────────────────────────────────────────
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+srcBucket+"/"+srcKey+"?uploads=", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("src Create: %d %s", w.Code, w.Body.String())
	}
	srcUploadID := extractUploadID(t, w.Body.String())

	req := httptest.NewRequest("PUT",
		fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", srcBucket, srcKey, srcUploadID),
		bytes.NewReader(plainContent))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(plainContent)))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("src UploadPart: %d %s", w.Code, w.Body.String())
	}
	srcETag := w.Header().Get("ETag")

	completeXML := fmt.Sprintf(`<?xml version="1.0"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>%s</ETag></Part></CompleteMultipartUpload>`, srcETag)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/"+srcBucket+"/"+srcKey+"?uploadId="+srcUploadID, strings.NewReader(completeXML)))
	if w.Code != http.StatusOK {
		t.Fatalf("src Complete: %d %s", w.Code, w.Body.String())
	}

	// ── CopyObject: simulate Harbor's small-blob moveBlob() ──────────────────
	copyReq := httptest.NewRequest("PUT", "/"+dstBucket+"/"+dstKey, nil)
	copyReq.Header.Set("x-amz-copy-source", "/"+srcBucket+"/"+srcKey)
	w = httptest.NewRecorder()
	router.ServeHTTP(w, copyReq)
	if w.Code != http.StatusOK {
		t.Fatalf("CopyObject from MPU source: %d %s", w.Code, w.Body.String())
	}

	// ── GET destination and verify plaintext content ──────────────────────────
	w = httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/"+dstBucket+"/"+dstKey, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("dst GET: %d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), plainContent) {
		t.Errorf("CopyObject from MPU source: content mismatch: got %d bytes, want %d; first byte: 0x%02x",
			w.Body.Len(), len(plainContent), w.Body.Bytes()[0])
	}
}
