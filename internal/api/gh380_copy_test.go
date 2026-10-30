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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
)

type gh380MPUSwap struct {
	*mpuMockS3Client
	sourceBucket, sourceKey              string
	reads, closes, uploads, nativeCopies int
	headVersions, getVersions            []string
	nativeVersion                        string
	allowNativeCopy                      bool
	beforeSourceGet                      func() error
	useRealMetadata                      bool
}

func gh380AllVersions(versions []string, want string) bool {
	if len(versions) == 0 {
		return false
	}
	for _, v := range versions {
		if v != want {
			return false
		}
	}
	return true
}

type gh380ReservationSpy struct {
	mpu.StateStore
	calls int
}

func (s *gh380ReservationSpy) ReservePart(ctx context.Context, uploadID string, part mpu.PartClaim) (mpu.Reservation, error) {
	s.calls++
	return s.StateStore.ReservePart(ctx, uploadID, part)
}

// Destination DEK unwrapping precedes both claim computation and encryption.
type gh380KeyManagerSpy struct {
	crypto.KeyManager
	destinationUnwraps int
}

func (s *gh380KeyManagerSpy) UnwrapKey(ctx context.Context, env *crypto.KeyEnvelope, metadata map[string]string) ([]byte, error) {
	if metadata["bucket"] == "destination-bucket" {
		s.destinationUnwraps++
	}
	return s.KeyManager.UnwrapKey(ctx, env, metadata)
}

type gh380MPUSwapReader struct {
	io.ReadCloser
	client *gh380MPUSwap
}

func (r *gh380MPUSwapReader) Read(p []byte) (int, error) {
	r.client.reads++
	return r.ReadCloser.Read(p)
}
func (r *gh380MPUSwapReader) Close() error { r.client.closes++; return r.ReadCloser.Close() }
func (c *gh380MPUSwap) HeadObject(ctx context.Context, bucket, key string, version *string) (map[string]string, error) {
	if bucket == c.sourceBucket && key == c.sourceKey {
		c.headVersions = append(c.headVersions, requestVersionID(version))
	}
	return c.mpuMockS3Client.HeadObject(ctx, bucket, key, version)
}
func (c *gh380MPUSwap) GetObject(ctx context.Context, bucket, key string, version, byteRange *string) (io.ReadCloser, map[string]string, error) {
	if bucket == c.sourceBucket && key == c.sourceKey && c.beforeSourceGet != nil {
		if err := c.beforeSourceGet(); err != nil {
			return nil, nil, err
		}
	}
	r, meta, err := c.mpuMockS3Client.GetObject(ctx, bucket, key, version, byteRange)
	if err != nil || bucket != c.sourceBucket || key != c.sourceKey {
		return r, meta, err
	}
	c.getVersions = append(c.getVersions, requestVersionID(version))
	if !c.useRealMetadata {
		meta = map[string]string{"Content-Length": "1"}
	}
	return &gh380MPUSwapReader{ReadCloser: r, client: c}, meta, nil
}

type gh380EncryptSpy struct {
	crypto.EncryptionEngine
	calls int
}

func (s *gh380EncryptSpy) Encrypt(ctx context.Context, object crypto.ObjectContext, reader io.Reader, metadata map[string]string) (io.Reader, map[string]string, error) {
	s.calls++
	return s.EncryptionEngine.Encrypt(ctx, object, reader, metadata)
}
func (c *gh380MPUSwap) UploadPart(ctx context.Context, bucket, key, uploadID string, number int32, reader io.Reader, length *int64) (string, error) {
	c.uploads++
	return c.mpuMockS3Client.UploadPart(ctx, bucket, key, uploadID, number, reader, length)
}
func (c *gh380MPUSwap) UploadPartCopy(ctx context.Context, bucket, key, uploadID string, number int32, sourceBucket, sourceKey string, version *string, partRange *s3.CopyPartRange) (*s3.CopyPartResult, error) {
	c.nativeCopies++
	c.nativeVersion = requestVersionID(version)
	if c.allowNativeCopy {
		c.mu.Lock()
		defer c.mu.Unlock()
		data, ok := c.objects[sourceBucket+"/"+sourceKey]
		if !ok {
			return nil, fmt.Errorf("source not found")
		}
		if partRange != nil {
			if partRange.First < 0 || partRange.Last < partRange.First || partRange.Last >= int64(len(data)) {
				return nil, fmt.Errorf("invalid range")
			}
			data = data[partRange.First : partRange.Last+1]
		}
		c.parts[fmt.Sprintf("%s|%s|%s|%d", bucket, key, uploadID, number)] = append([]byte(nil), data...)
		return &s3.CopyPartResult{ETag: "\"native-copy\"", LastModified: time.Now()}, nil
	}
	return c.mpuMockS3Client.UploadPartCopy(ctx, bucket, key, uploadID, number, sourceBucket, sourceKey, version, partRange)
}

func TestGH380CopyObjectSourcePolicy(t *testing.T) {
	for _, directive := range []string{"COPY", "REPLACE"} {
		client := newMockS3Client()
		client.objects["test-bucket/source"] = []byte("plaintext")
		client.metadata["test-bucket/source"] = map[string]string{"Content-Length": "9"}
		client.objects["test-bucket/destination"] = []byte("unchanged")
		client.metadata["test-bucket/destination"] = map[string]string{"Content-Length": "9"}
		h := gh380Handler(t, client)
		router := mux.NewRouter()
		h.RegisterRoutes(router)
		req := attachTestCredential(httptest.NewRequest("PUT", "/test-bucket/destination", nil))
		req.Header.Set("x-amz-copy-source", "/test-bucket/source?versionId=v1")
		req.Header.Set("x-amz-metadata-directive", directive)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != 403 || !containsGH380Message(w.Body.String()) {
			t.Fatalf("%s: %d %s", directive, w.Code, w.Body.String())
		}
		if string(client.objects["test-bucket/destination"]) != "unchanged" || client.putObjectCallCount != 0 || client.getObjectCallCount != 0 {
			t.Fatal("refused copy mutated destination or fetched source")
		}
	}
}

func TestGH380CopySourceDestinationMatrix(t *testing.T) {
	for _, sourceStrict := range []bool{false, true} {
		for _, destStrict := range []bool{false, true} {
			for _, directive := range []string{"COPY", "REPLACE"} {
				t.Run(fmt.Sprintf("source=%t/dest=%t/%s", sourceStrict, destStrict, directive), func(t *testing.T) {
					client := newMockS3Client()
					client.objects["source-bucket/a b"] = []byte("source-data")
					client.metadata["source-bucket/a b"] = map[string]string{"Content-Length": "11", "x-amz-meta-name": "source"}
					client.objects["dest-bucket/destination"] = []byte("unchanged")
					client.metadata["dest-bucket/destination"] = map[string]string{"Content-Length": "9", "x-amz-meta-name": "old"}
					original := cloneStringMap(client.metadata["dest-bucket/destination"])
					dir := t.TempDir()
					first := filepath.Join(dir, "1.yaml")
					second := filepath.Join(dir, "2.yaml")
					if err := os.WriteFile(first, []byte(fmt.Sprintf("id: source\nbuckets: [source-bucket]\nrequire_encryption: %t\n", sourceStrict)), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(second, []byte(fmt.Sprintf("id: destination\nbuckets: [dest-bucket]\nrequire_encryption: %t\n", destStrict)), 0600); err != nil {
						t.Fatal(err)
					}
					pm := config.NewPolicyManager()
					if err := pm.ReloadPolicies([]string{first, second}); err != nil {
						t.Fatal(err)
					}
					h := gh380Handler(t, client)
					h.policyManager = pm
					spy := &gh380EncryptSpy{EncryptionEngine: h.encryptionEngine}
					loads := 0
					h.encryptionEngineLoader = func(bucket string) (crypto.EncryptionEngine, error) {
						if bucket == "dest-bucket" {
							loads++
							return spy, nil
						}
						return h.encryptionEngine, nil
					}
					router := mux.NewRouter()
					h.RegisterRoutes(router)
					req := attachTestCredential(httptest.NewRequest("PUT", "/dest-bucket/destination", nil))
					req.Header.Set("x-amz-copy-source", "/source-bucket/a%20b?versionId=source-v1")
					req.Header.Set("x-amz-metadata-directive", directive)
					w := httptest.NewRecorder()
					router.ServeHTTP(w, req)
					if sourceStrict {
						if w.Code != 403 || client.getObjectCallCount != 0 || client.putObjectCallCount != 0 || loads != 0 || spy.calls != 0 || string(client.objects["dest-bucket/destination"]) != "unchanged" || !reflect.DeepEqual(original, client.metadata["dest-bucket/destination"]) {
							t.Fatalf("denial mutated source or destination: %d %s", w.Code, w.Body.String())
						}
					} else if w.Code != 200 || loads == 0 || spy.calls != 1 || !crypto.IsEncryptedMetadata(client.metadata["dest-bucket/destination"]) {
						t.Fatalf("import: %d %s", w.Code, w.Body.String())
					}
					if len(client.headVersionHistory) == 0 || requestVersionID(client.headVersionHistory[0].versionID) != "source-v1" {
						t.Fatal("source version not propagated")
					}
				})
			}
		}
	}
}

func TestGH380CopySameKeyDenied(t *testing.T) {
	client := newMockS3Client()
	client.objects["test-bucket/source"] = []byte("plaintext")
	client.metadata["test-bucket/source"] = map[string]string{"Content-Length": "9"}
	h := gh380Handler(t, client)
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	req := attachTestCredential(httptest.NewRequest("PUT", "/test-bucket/source", nil))
	req.Header.Set("x-amz-copy-source", "/test-bucket/source?versionId=v1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 403 || client.putObjectCallCount != 0 || string(client.objects["test-bucket/source"]) != "plaintext" {
		t.Fatalf("same-key status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestGH380CopyObjectUnprotectedSourceImport(t *testing.T) {
	client := newMockS3Client()
	client.objects["source-bucket/a b"] = []byte("import plaintext")
	client.metadata["source-bucket/a b"] = map[string]string{"Content-Length": "16"}
	h := gh380Handler(t, client)
	h.policyManager = gh380Policy(t, "id: strict\nbuckets: [dest-bucket]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	req := attachTestCredential(httptest.NewRequest("PUT", "/dest-bucket/destination", nil))
	req.Header.Set("x-amz-copy-source", "/source-bucket/a%20b?versionId=v1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("copy: %d %s", w.Code, w.Body.String())
	}
	metadata := client.metadata["dest-bucket/destination"]
	if len(metadata) == 0 || !crypto.IsEncryptedMetadata(metadata) {
		t.Fatal("destination not encrypted")
	}
	if string(client.objects["dest-bucket/destination"]) == "import plaintext" {
		t.Fatal("destination plaintext")
	}
}

func TestGH380UploadPartCopyFetchedMetadata(t *testing.T) {
	for _, strategy := range []string{"legacy", "chunked", "reencrypt-chunked", "reencrypt-plaintext", "reencrypt-legacy"} {
		t.Run(strategy, func(t *testing.T) {
			base := newMockS3Client()
			base.objects["test-bucket/source"] = []byte("0123456789")
			base.metadata["test-bucket/source"] = map[string]string{crypto.MetaEncrypted: "true", "Content-Length": "10"}
			if strings.Contains(strategy, "chunked") {
				base.metadata["test-bucket/source"][crypto.MetaChunkedFormat] = "true"
			}
			client := &gh380SwapClient{mockS3Client: base}
			h := gh380Handler(t, base)
			var err error
			if strategy == "chunked" {
				_, _, err = h.uploadPartCopyChunked(context.Background(), client, "test-bucket", "dest", "upload", 1, "test-bucket", "source", nil, nil, 1024, crypto.ChunkedObjectInfo{Authenticated: true, PlaintextSize: 10})
			} else if strategy == "legacy" {
				_, _, err = h.uploadPartCopyLegacy(context.Background(), client, "test-bucket", "dest", "upload", 1, "test-bucket", "source", nil, nil, 10, 1024)
			} else {
				class := SourceClassLegacy
				if strategy == "reencrypt-plaintext" {
					class = SourceClassPlaintext
				} else if strategy == "reencrypt-chunked" {
					class = SourceClassChunked
				}
				_, _, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "test-bucket", "dest", "upload", 1, "test-bucket", "source", nil, nil, &CopySourceMetadata{Class: class, ChunkedInfo: crypto.ChunkedObjectInfo{Authenticated: true, PlaintextSize: 10}}, 1024, 1024)
			}
			if !errors.Is(err, errPlaintextReadForbidden) || client.reads != 0 || client.closes != 1 {
				t.Fatalf("err=%v reads=%d closes=%d", err, client.reads, client.closes)
			}
		})
	}
}

func TestGH380UploadPartCopySourcePolicy(t *testing.T) {
	client := newMockS3Client()
	client.objects["test-bucket/source"] = []byte("plaintext")
	client.metadata["test-bucket/source"] = map[string]string{"Content-Length": "9"}
	h := gh380Handler(t, client)
	h.policyManager = gh380Policy(t, "id: strict\nbuckets: [test-bucket]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	req := attachTestCredential(httptest.NewRequest("PUT", "/test-bucket/destination?partNumber=1&uploadId=plain-upload", nil))
	req.Header.Set("x-amz-copy-source", "/test-bucket/source?versionId=v1")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 403 || !containsGH380Message(w.Body.String()) {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if client.getObjectCallCount != 0 {
		t.Fatal("source body fetched")
	}
}

func TestGH380DestinationOnlyMismatch(t *testing.T) {
	client := newMockS3Client()
	client.objects["source-bucket/source"] = []byte("plaintext")
	client.metadata["source-bucket/source"] = map[string]string{"Content-Length": "9"}
	h := gh380Handler(t, client)
	h.policyManager = gh380Policy(t, "id: destination\nbuckets: [dest-bucket]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	req := attachTestCredential(httptest.NewRequest("PUT", "/dest-bucket/dest?partNumber=1&uploadId=plain-upload", nil))
	req.Header.Set("x-amz-copy-source", "/source-bucket/source")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	if w.Code != 500 || !strings.Contains(w.Body.String(), "Destination bucket configuration requires encryption") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestGH380EncryptedMPUDestinationSourceDenial(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "gh380-*")
	h.policyManager = gh380Policy(t, "id: strict\nbuckets: ['gh380-*']\nrequire_encryption: true\nencrypt_multipart_uploads: true\n")
	const bucket, dst, src = "gh380-bucket", "destination", "source"
	backend.objects[bucket+"/"+src] = []byte("plaintext")
	backend.metadata[bucket+"/"+src] = map[string]string{"Content-Length": "9"}
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	created := httptest.NewRecorder()
	router.ServeHTTP(created, httptest.NewRequest("POST", "/"+bucket+"/"+dst+"?uploads=", nil))
	if created.Code != 200 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	id := extractUploadID(t, created.Body.String())
	part := httptest.NewRecorder()
	router.ServeHTTP(part, httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, dst, id), strings.NewReader("existing part")))
	if part.Code != 200 {
		t.Fatalf("part: %d %s", part.Code, part.Body.String())
	}
	partKey := fmt.Sprintf("%s|%s|%s|%d", bucket, dst, id, 1)
	beforePart := append([]byte(nil), backend.parts[partKey]...)
	beforeState, err := h.mpuStateStore.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	for _, rangeValue := range []string{"", "bytes=0-2"} {
		req := attachTestCredential(httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, dst, id), nil))
		req.Header.Set("x-amz-copy-source", "/"+bucket+"/"+src+"?versionId=v1")
		if rangeValue != "" {
			req.Header.Set("x-amz-copy-source-range", rangeValue)
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != 403 {
			t.Fatalf("range=%q status=%d %s", rangeValue, w.Code, w.Body.String())
		}
		afterState, err := h.mpuStateStore.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(beforePart, backend.parts[partKey]) || !reflect.DeepEqual(beforeState, afterState) {
			t.Fatal("part or state mutated on refusal")
		}
	}
}

func TestGH380UploadPartCopyRouteSubstitution(t *testing.T) {
	for _, encryptedDest := range []bool{false, true} {
		for _, format := range []string{"buffered-legacy", "chunked-v1", "mpu-v1", "mpu-v2"} {
			for _, rangeValue := range []string{"", "bytes=1-8"} {
				t.Run(fmt.Sprintf("encrypted=%t/%s/%s", encryptedDest, format, rangeValue), func(t *testing.T) {
					h, backend, _ := newMPUTestHandler(t, "destination-*")
					dir := t.TempDir()
					srcPolicy := filepath.Join(dir, "1.yaml")
					dstPolicy := filepath.Join(dir, "2.yaml")
					if err := os.WriteFile(srcPolicy, []byte("id: source\nbuckets: [golden-bucket]\nrequire_encryption: true\nencrypt_multipart_uploads: false\n"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(dstPolicy, []byte(fmt.Sprintf("id: destination\nbuckets: [destination-bucket]\nencrypt_multipart_uploads: %t\n", encryptedDest)), 0600); err != nil {
						t.Fatal(err)
					}
					pm := config.NewPolicyManager()
					if err := pm.ReloadPolicies([]string{srcPolicy, dstPolicy}); err != nil {
						t.Fatal(err)
					}
					h.policyManager = pm
					engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
					if err != nil {
						t.Fatal(err)
					}
					if format == "mpu-v1" || format == "mpu-v2" {
						h.encryptionEngineLoader = func(bucket string) (crypto.EncryptionEngine, error) {
							if bucket == goldenBucket {
								return engine, nil
							}
							return h.encryptionEngine, nil
						}
					}
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
					backend.objects[goldenBucket+"/"+goldenObject] = body
					backend.metadata[goldenBucket+"/"+goldenObject] = cloneStringMap(fixture.Metadata)
					if fixture.ManifestBody != "" {
						m, err := base64.StdEncoding.DecodeString(fixture.ManifestBody)
						if err != nil {
							t.Fatal(err)
						}
						backend.objects[goldenBucket+"/"+goldenObject+crypto.MPUManifestSuffix] = m
						backend.metadata[goldenBucket+"/"+goldenObject+crypto.MPUManifestSuffix] = cloneStringMap(fixture.ManifestMetadata)
					}
					client := &gh380MPUSwap{mpuMockS3Client: backend, sourceBucket: goldenBucket, sourceKey: goldenObject}
					h.s3Client = client
					h.SetAllowUntrackedPlaintextUploads(true)
					router := mux.NewRouter()
					h.RegisterRoutes(router)
					const bucket, destination = "destination-bucket", "dest"
					id := "plaintext-upload"
					if encryptedDest {
						w := httptest.NewRecorder()
						router.ServeHTTP(w, httptest.NewRequest("POST", "/"+bucket+"/"+destination+"?uploads=", nil))
						if w.Code != 200 {
							t.Fatalf("create: %d %s", w.Code, w.Body.String())
						}
						id = extractUploadID(t, w.Body.String())
					}
					w := httptest.NewRecorder()
					router.ServeHTTP(w, httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, destination, id), strings.NewReader("existing part")))
					if w.Code != 200 {
						t.Fatalf("part: %d %s", w.Code, w.Body.String())
					}
					partKey := fmt.Sprintf("%s|%s|%s|1", bucket, destination, id)
					existing := append([]byte(nil), backend.parts[partKey]...)
					var stateBefore any
					if encryptedDest {
						stateBefore, err = h.mpuStateStore.Get(context.Background(), id)
						if err != nil {
							t.Fatal(err)
						}
					}
					client.uploads, client.nativeCopies = 0, 0
					storeSpy := &gh380ReservationSpy{StateStore: h.mpuStateStore}
					h.mpuStateStore = storeSpy
					keySpy := &gh380KeyManagerSpy{KeyManager: h.keyManager}
					h.keyManager = keySpy
					encryptions := 0
					h.destinationEncryptionConstructed = func() { encryptions++ }
					req := attachTestCredential(httptest.NewRequest("PUT", fmt.Sprintf("/%s/%s?partNumber=1&uploadId=%s", bucket, destination, id), nil))
					req.Header.Set("x-amz-copy-source", "/"+goldenBucket+"/"+goldenObject+"?versionId=chosen")
					if rangeValue != "" {
						req.Header.Set("x-amz-copy-source-range", rangeValue)
					}
					w = httptest.NewRecorder()
					router.ServeHTTP(w, req)
					if w.Code != http.StatusForbidden || client.reads != 0 || client.closes != 1 || client.uploads != 0 || client.nativeCopies != 0 || !gh380AllVersions(client.headVersions, "chosen") || !gh380AllVersions(client.getVersions, "chosen") || storeSpy.calls != 0 || keySpy.destinationUnwraps != 0 || encryptions != 0 || !bytes.Equal(existing, backend.parts[partKey]) {
						t.Fatalf("status=%d reads=%d closes=%d uploads=%d native=%d head=%v get=%v reservations=%d destinationUnwraps=%d encryptions=%d body=%s", w.Code, client.reads, client.closes, client.uploads, client.nativeCopies, client.headVersions, client.getVersions, storeSpy.calls, keySpy.destinationUnwraps, encryptions, w.Body.String())
					}
					if encryptedDest {
						stateAfter, err := h.mpuStateStore.Get(context.Background(), id)
						if err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(stateBefore, stateAfter) {
							t.Fatal("destination state/claim changed")
						}
					}
				})
			}
		}
	}
}

func TestGH380UploadPartCopyRoutePolicyMatrix(t *testing.T) {
	for _, encryptedDest := range []bool{false, true} {
		for _, sourceStrict := range []bool{false, true} {
			for _, rangeValue := range []string{"", "bytes=0-2"} {
				t.Run(fmt.Sprintf("encrypted=%t/strict=%t/range=%q", encryptedDest, sourceStrict, rangeValue), func(t *testing.T) {
					h, backend, _ := newMPUTestHandler(t, "destination-*")
					dir := t.TempDir()
					srcPolicy, dstPolicy := filepath.Join(dir, "1.yaml"), filepath.Join(dir, "2.yaml")
					if err := os.WriteFile(srcPolicy, []byte(fmt.Sprintf("id: source\nbuckets: [source-bucket]\nrequire_encryption: %t\nencrypt_multipart_uploads: false\n", sourceStrict)), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(dstPolicy, []byte(fmt.Sprintf("id: destination\nbuckets: [destination-bucket]\nencrypt_multipart_uploads: %t\n", encryptedDest)), 0600); err != nil {
						t.Fatal(err)
					}
					pm := config.NewPolicyManager()
					if err := pm.ReloadPolicies([]string{srcPolicy, dstPolicy}); err != nil {
						t.Fatal(err)
					}
					h.policyManager = pm
					backend.objects["source-bucket/source"] = []byte("plaintext source")
					backend.metadata["source-bucket/source"] = map[string]string{"Content-Length": "16"}
					client := &gh380MPUSwap{mpuMockS3Client: backend, sourceBucket: "source-bucket", sourceKey: "source", allowNativeCopy: true}
					// Unprotected encrypted-destination reads must use the real metadata.
					if !sourceStrict && encryptedDest {
						h.s3Client = backend
					} else {
						h.s3Client = client
					}
					h.SetAllowUntrackedPlaintextUploads(true)
					router := mux.NewRouter()
					h.RegisterRoutes(router)
					id := "plain-upload"
					if encryptedDest {
						w := httptest.NewRecorder()
						router.ServeHTTP(w, httptest.NewRequest("POST", "/destination-bucket/dest?uploads=", nil))
						if w.Code != 200 {
							t.Fatalf("create: %d %s", w.Code, w.Body.String())
						}
						id = extractUploadID(t, w.Body.String())
					}
					if sourceStrict {
						w := httptest.NewRecorder()
						router.ServeHTTP(w, httptest.NewRequest("PUT", "/destination-bucket/dest?partNumber=1&uploadId="+id, strings.NewReader("existing part")))
						if w.Code != 200 {
							t.Fatalf("seed part: %d %s", w.Code, w.Body.String())
						}
					}
					partKey := "destination-bucket|dest|" + id + "|1"
					prior := append([]byte(nil), backend.parts[partKey]...)
					var oldState any
					if encryptedDest {
						var err error
						oldState, err = h.mpuStateStore.Get(context.Background(), id)
						if err != nil {
							t.Fatal(err)
						}
					}
					client.uploads, client.nativeCopies = 0, 0
					req := attachTestCredential(httptest.NewRequest("PUT", "/destination-bucket/dest?partNumber=1&uploadId="+id, nil))
					req.Header.Set("x-amz-copy-source", "/source-bucket/source?versionId=chosen")
					if rangeValue != "" {
						req.Header.Set("x-amz-copy-source-range", rangeValue)
					}
					w := httptest.NewRecorder()
					router.ServeHTTP(w, req)
					if sourceStrict {
						if w.Code != 403 || client.reads != 0 || client.uploads != 0 || client.nativeCopies != 0 || !gh380AllVersions(client.headVersions, "chosen") || !bytes.Equal(prior, backend.parts[partKey]) {
							t.Fatalf("denied status=%d reads=%d uploads=%d native=%d head=%v body=%s", w.Code, client.reads, client.uploads, client.nativeCopies, client.headVersions, w.Body.String())
						}
						if encryptedDest {
							state, err := h.mpuStateStore.Get(context.Background(), id)
							if err != nil {
								t.Fatal(err)
							}
							if !reflect.DeepEqual(oldState, state) {
								t.Fatal("state changed")
							}
						}
					} else if encryptedDest {
						if w.Code != 200 || bytes.Equal(backend.parts[partKey], backend.objects["source-bucket/source"]) {
							t.Fatalf("encrypted import: %d %s", w.Code, w.Body.String())
						}
					} else {
						want := backend.objects["source-bucket/source"]
						if rangeValue != "" {
							want = want[:3]
						}
						if client.nativeCopies != 1 || w.Code != 200 || client.nativeVersion != "chosen" || !gh380AllVersions(client.headVersions, "chosen") || !bytes.Equal(backend.parts[partKey], want) {
							t.Fatalf("plaintext copy: %d native=%d head=%v version=%q part=%q want=%q body=%s", w.Code, client.nativeCopies, client.headVersions, client.nativeVersion, backend.parts[partKey], want, w.Body.String())
						}
					}
				})
			}
		}
	}
}

func TestGH380CopyObjectFetchedMetadata(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata map[string]string
		status   int
		message  string
	}{
		{"plaintext", map[string]string{"Content-Length": "10"}, 403, "Bucket policy requires gateway-encrypted objects"},
		{"unsupported-encrypted-marker", map[string]string{crypto.MetaMPUEncrypted: "unknown"}, 500, "Unsupported encrypted object format"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newMockS3Client()
			base.objects["test-bucket/source"] = []byte("0123456789")
			base.metadata["test-bucket/source"] = map[string]string{crypto.MetaEncrypted: "true", "Content-Length": "10"}
			base.objects["dest-bucket/destination"] = []byte("unchanged")
			base.metadata["dest-bucket/destination"] = map[string]string{"Content-Length": "9", "x-amz-meta-original": "value"}
			beforeMeta := cloneStringMap(base.metadata["dest-bucket/destination"])
			client := &gh380SwapClient{mockS3Client: base, fetchedMetadata: tc.metadata}
			h := gh380Handler(t, base)
			h.s3Client = client
			spy := &gh380EncryptSpy{EncryptionEngine: h.encryptionEngine}
			loads := 0
			h.encryptionEngineLoader = func(bucket string) (crypto.EncryptionEngine, error) {
				if bucket == "dest-bucket" {
					loads++
					return spy, nil
				}
				return h.encryptionEngine, nil
			}
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			req := attachTestCredential(httptest.NewRequest("PUT", "/dest-bucket/destination", nil))
			req.Header.Set("x-amz-copy-source", "/test-bucket/source?versionId=chosen")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.message) || client.reads != 0 || client.closes != 1 || base.putObjectCallCount != 0 || loads != 0 || spy.calls != 0 || !gh380AllVersions(client.headVersions, "chosen") || !gh380AllVersions(client.getVersions, "chosen") || string(base.objects["dest-bucket/destination"]) != "unchanged" || !reflect.DeepEqual(beforeMeta, base.metadata["dest-bucket/destination"]) {
				t.Fatalf("status=%d reads=%d closes=%d puts=%d loads=%d encrypt=%d head=%v get=%v body=%s", w.Code, client.reads, client.closes, base.putObjectCallCount, loads, spy.calls, client.headVersions, client.getVersions, w.Body.String())
			}
		})
	}
}

func TestGH380UploadPartCopyLivePolicyReload(t *testing.T) {
	for _, rangeValue := range []string{"", "bytes=0-2"} {
		t.Run(fmt.Sprintf("range=%q", rangeValue), func(t *testing.T) {
			h, backend, _ := newMPUTestHandler(t, "destination-*")
			dir := t.TempDir()
			srcPolicy, dstPolicy := filepath.Join(dir, "1.yaml"), filepath.Join(dir, "2.yaml")
			writeSource := func(strict bool) {
				t.Helper()
				if err := os.WriteFile(srcPolicy, []byte(fmt.Sprintf("id: source\nbuckets: [source-bucket]\nrequire_encryption: %t\n", strict)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeSource(false)
			if err := os.WriteFile(dstPolicy, []byte("id: destination\nbuckets: [destination-bucket]\nencrypt_multipart_uploads: true\n"), 0600); err != nil {
				t.Fatal(err)
			}
			pm := config.NewPolicyManager()
			if err := pm.ReloadPolicies([]string{srcPolicy, dstPolicy}); err != nil {
				t.Fatal(err)
			}
			h.policyManager = pm
			backend.objects["source-bucket/source"] = []byte("plaintext source")
			backend.metadata["source-bucket/source"] = map[string]string{"Content-Length": "16"}
			client := &gh380MPUSwap{mpuMockS3Client: backend, sourceBucket: "source-bucket", sourceKey: "source", useRealMetadata: true}
			h.s3Client = client
			router := mux.NewRouter()
			h.RegisterRoutes(router)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("POST", "/destination-bucket/dest?uploads=", nil))
			if w.Code != 200 {
				t.Fatalf("create: %d %s", w.Code, w.Body.String())
			}
			id := extractUploadID(t, w.Body.String())
			partKey := "destination-bucket|dest|" + id + "|1"
			w = httptest.NewRecorder()
			router.ServeHTTP(w, httptest.NewRequest("PUT", "/destination-bucket/dest?partNumber=1&uploadId="+id, strings.NewReader("existing part")))
			if w.Code != 200 {
				t.Fatalf("seed part: %d %s", w.Code, w.Body.String())
			}
			before := append([]byte(nil), backend.parts[partKey]...)
			state, err := h.mpuStateStore.Get(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			client.uploads = 0
			storeSpy := &gh380ReservationSpy{StateStore: h.mpuStateStore}
			h.mpuStateStore = storeSpy
			keySpy := &gh380KeyManagerSpy{KeyManager: h.keyManager}
			h.keyManager = keySpy
			encryptions, reloads := 0, 0
			h.destinationEncryptionConstructed = func() { encryptions++ }
			client.beforeSourceGet = func() error { reloads++; writeSource(true); return pm.ReloadPolicies([]string{srcPolicy, dstPolicy}) }
			req := attachTestCredential(httptest.NewRequest("PUT", "/destination-bucket/dest?partNumber=1&uploadId="+id, nil))
			req.Header.Set("x-amz-copy-source", "/source-bucket/source?versionId=chosen")
			if rangeValue != "" {
				req.Header.Set("x-amz-copy-source-range", rangeValue)
			}
			w = httptest.NewRecorder()
			router.ServeHTTP(w, req)
			after, err := h.mpuStateStore.Get(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if w.Code != 403 || !containsGH380Message(w.Body.String()) || reloads != 1 || client.reads != 0 || client.closes != 1 || client.uploads != 0 || client.nativeCopies != 0 || storeSpy.calls != 0 || keySpy.destinationUnwraps != 0 || encryptions != 0 || !gh380AllVersions(client.headVersions, "chosen") || !gh380AllVersions(client.getVersions, "chosen") || !bytes.Equal(before, backend.parts[partKey]) || !reflect.DeepEqual(state, after) {
				t.Fatalf("status=%d reloads=%d reads=%d closes=%d uploads=%d native=%d reservations=%d unwraps=%d encryptions=%d head=%v get=%v body=%s", w.Code, reloads, client.reads, client.closes, client.uploads, client.nativeCopies, storeSpy.calls, keySpy.destinationUnwraps, encryptions, client.headVersions, client.getVersions, w.Body.String())
			}
		})
	}
}
