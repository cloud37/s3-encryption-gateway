package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

func sec42Router(t *testing.T, h *Handler) *mux.Router {
	t.Helper()
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	return r
}

func TestCopyObject_InvalidSourceAndMissingSourceFailClosed(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-copy-errors-*")
	r := sec42Router(t, h)

	for _, tc := range []struct {
		name   string
		source string
		want   int
	}{
		{"malformed source", "not-a-valid-source", http.StatusBadRequest},
		{"missing source", "/sec42-copy-errors-bucket/missing", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/sec42-copy-errors-bucket/destination", nil)
			req.Header.Set("x-amz-copy-source", tc.source)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			require.Equal(t, tc.want, w.Code, w.Body.String())
		})
	}
	_, err := backend.HeadObject(context.Background(), "sec42-copy-errors-bucket", "missing", nil)
	require.Error(t, err)
}

func TestCopyObject_InvalidTaggingRejectedBeforeDataPlane(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-copy-tags-*")
	r := sec42Router(t, h)
	bucket := "sec42-copy-tags-bucket"
	backend.objects[bucket+"/source"] = []byte("source")
	backend.metadata[bucket+"/source"] = map[string]string{}
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/destination", nil)
	req.Header.Set("x-amz-copy-source", "/"+bucket+"/source")
	req.Header.Set("x-amz-tagging", "invalid%tagging%value")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	_, err := backend.HeadObject(context.Background(), bucket, "destination", nil)
	require.Error(t, err, "rejected copy must not create destination")
}

func TestCopyObject_MetadataExpansionFailureDoesNotWriteDestination(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-copy-metadata-error-*")
	r := sec42Router(t, h)
	bucket := "sec42-copy-metadata-error-bucket"
	backend.objects[bucket+"/source"] = []byte("source")
	backend.metadata[bucket+"/source"] = map[string]string{}
	h.apiMetadataExpander = func(map[string]string) (map[string]string, error) {
		return nil, errors.New("malformed protected metadata")
	}
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/destination", nil)
	req.Header.Set("x-amz-copy-source", "/"+bucket+"/source")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	_, err := backend.HeadObject(context.Background(), bucket, "destination", nil)
	require.Error(t, err, "metadata failure must prevent destination creation")
}

func TestMPUV2_NormalGetCorruptManifestFailsClosed(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-manifest-corrupt-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-manifest-corrupt-bucket", "object"
	plain := bytes.Repeat([]byte("M"), sec42MPUPlainSize)
	doCompleteUpload(t, r, bucket, key, plain)
	manifestKey := bucket + "/" + key + ".mpu-manifest"
	backend.objects[manifestKey][len(backend.objects[manifestKey])-1] ^= 1
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil))
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), string(plain), "corrupt manifest must not expose plaintext")
}

func TestMPUV2_NormalGetRejectsManifestMetadataAndBindingFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*mpuMockS3Client, string, string)
	}{
		{"invalid companion marker", func(b *mpuMockS3Client, bucket, key string) {
			b.metadata[bucket+"/"+key+".mpu-manifest"][crypto.MetaMPUManifestVersion] = "1"
		}},
		{"invalid main binding", func(b *mpuMockS3Client, bucket, key string) {
			b.metadata[bucket+"/"+key][crypto.MetaObjectBindingID] = "bad"
		}},
		{"short main binding", func(b *mpuMockS3Client, bucket, key string) {
			b.metadata[bucket+"/"+key][crypto.MetaObjectBindingID] = base64.RawURLEncoding.EncodeToString([]byte{1})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, backend, _ := newMPUTestHandler(t, "sec42-manifest-meta-*")
			r := sec42Router(t, h)
			bucket, key := "sec42-manifest-meta-bucket", "object"
			doCompleteUpload(t, r, bucket, key, bytes.Repeat([]byte("M"), sec42MPUPlainSize))
			tc.mutate(backend, bucket, key)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil))
			require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
			require.NotContains(t, w.Body.String(), "MMMM")
		})
	}
}

func TestMPUV2_RangeRejectsCorruptCiphertextWithoutPlaintext(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-range-tamper-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-range-tamper-bucket", "object"
	plain := bytes.Repeat([]byte("T"), sec42MPUPlainSize)
	doCompleteUpload(t, r, bucket, key, plain)
	backend.objects[bucket+"/"+key][0] ^= 1
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	req.Header.Set("Range", "bytes=0-10")
	r.ServeHTTP(w, req)
	require.NotEqual(t, http.StatusPartialContent, w.Code)
	require.NotContains(t, w.Body.String(), "TTTT")
}

func TestMPUV2_RangeManifestValidationFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*mpuMockS3Client, string, string)
	}{
		{"invalid companion marker", func(b *mpuMockS3Client, bucket, key string) {
			b.metadata[bucket+"/"+key+".mpu-manifest"][crypto.MetaMPUManifestVersion] = "1"
		}},
		{"invalid main binding", func(b *mpuMockS3Client, bucket, key string) {
			b.metadata[bucket+"/"+key][crypto.MetaObjectBindingID] = "bad"
		}},
		{"corrupt manifest", func(b *mpuMockS3Client, bucket, key string) {
			manifest := b.objects[bucket+"/"+key+".mpu-manifest"]
			manifest[len(manifest)-1] ^= 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, backend, _ := newMPUTestHandler(t, "sec42-range-manifest-errors-*")
			r := sec42Router(t, h)
			bucket, key := "sec42-range-manifest-errors-bucket", "object"
			plain := bytes.Repeat([]byte("R"), sec42MPUPlainSize)
			doCompleteUpload(t, r, bucket, key, plain)
			tc.mutate(backend, bucket, key)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
			req.Header.Set("Range", "bytes=0-10")
			r.ServeHTTP(w, req)
			require.NotEqual(t, http.StatusPartialContent, w.Code, w.Body.String())
			require.NotContains(t, w.Body.String(), "RRRR")
		})
	}
}

func TestMPUV2_RangeManifestSecurityFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*mpuMockS3Client, string, string)
	}{
		{"companion marker", func(b *mpuMockS3Client, bucket, key string) {
			b.metadata[bucket+"/"+key+".mpu-manifest"][crypto.MetaMPUManifestVersion] = "1"
		}},
		{"main binding", func(b *mpuMockS3Client, bucket, key string) {
			b.metadata[bucket+"/"+key][crypto.MetaObjectBindingID] = "bad"
		}},
		{"manifest parse", func(b *mpuMockS3Client, bucket, key string) {
			b.objects[bucket+"/"+key+".mpu-manifest"] = []byte("corrupt")
		}},
		{"relationship", func(b *mpuMockS3Client, bucket, key string) {
			b.metadata[bucket+"/"+key+".mpu-manifest"][crypto.MetaObjectBindingID] = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{91}, 16))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, backend, _ := newMPUTestHandler(t, "sec42-range-security-*")
			r := sec42Router(t, h)
			bucket, key := "sec42-range-security-bucket", "object"
			plain := bytes.Repeat([]byte("S"), sec42MPUPlainSize)
			doCompleteUpload(t, r, bucket, key, plain)
			tc.mutate(backend, bucket, key)
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
			req.Header.Set("Range", "bytes=0-10")
			r.ServeHTTP(w, req)
			require.NotEqual(t, http.StatusPartialContent, w.Code, w.Body.String())
			require.NotContains(t, w.Body.String(), "SSSS")
		})
	}
}

func TestMPUV2_ManifestHelpersRejectMalformedSecurityState(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-helper-errors-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-helper-errors-bucket", "object"
	doCompleteUpload(t, r, bucket, key, bytes.Repeat([]byte("H"), sec42MPUPlainSize))
	mainMeta := backend.metadata[bucket+"/"+key]
	manifestKey := bucket + "/" + key + ".mpu-manifest"
	for _, tc := range []struct {
		name   string
		mutate func()
	}{
		{"invalid main binding", func() { mainMeta[crypto.MetaObjectBindingID] = "bad" }},
		{"invalid companion marker", func() { backend.metadata[manifestKey][crypto.MetaMPUManifestVersion] = "1" }},
		{"invalid manifest JSON", func() { backend.objects[manifestKey] = []byte("corrupt") }},
		{"manifest relationship", func() {
			manifestMeta := backend.metadata[manifestKey]
			badBinding := bytes.Repeat([]byte{77}, 16)
			manifestMeta[crypto.MetaObjectBindingID] = base64.RawURLEncoding.EncodeToString(badBinding)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Recreate the fixture so each mutation starts from authenticated state.
			h, backend, _ = newMPUTestHandler(t, "sec42-helper-errors-*")
			r = sec42Router(t, h)
			doCompleteUpload(t, r, bucket, key, bytes.Repeat([]byte("H"), sec42MPUPlainSize))
			mainMeta = backend.metadata[bucket+"/"+key]
			manifestKey = bucket + "/" + key + ".mpu-manifest"
			tc.mutate()
			reader, meta, err := backend.GetObject(context.Background(), bucket, key, nil, nil)
			require.NoError(t, err)
			_, err = h.decryptMPUObject(context.Background(), bucket, key, meta, reader, backend)
			require.Error(t, err, "malformed MPU security state accepted")
			if tc.name == "invalid companion marker" || tc.name == "invalid manifest JSON" || tc.name == "manifest relationship" {
				_, err = h.readMPUManifestTotalPlainSize(context.Background(), bucket, key, manifestKey, mainMeta, backend)
				require.Error(t, err)
			}
		})
	}
}

func TestCopyObject_CorruptMPUSourceDoesNotWriteDestination(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-copy-corrupt-mpu-*")
	r := sec42Router(t, h)
	bucket, source, destination := "sec42-copy-corrupt-mpu-bucket", "source", "destination"
	doCompleteUpload(t, r, bucket, source, bytes.Repeat([]byte("C"), sec42MPUPlainSize))
	manifestKey := bucket + "/" + source + ".mpu-manifest"
	backend.objects[manifestKey][len(backend.objects[manifestKey])-1] ^= 1
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+destination, nil)
	req.Header.Set("x-amz-copy-source", "/"+bucket+"/"+source)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	_, err := backend.HeadObject(context.Background(), bucket, destination, nil)
	require.Error(t, err, "corrupt MPU source must not create destination")
}

func TestMPUCopyRangeManifestFailuresFailClosed(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-copy-range-errors-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-copy-range-errors-bucket", "source"
	doCompleteUpload(t, r, bucket, key, bytes.Repeat([]byte("Q"), sec42MPUPlainSize))
	validRange := &s3.CopyPartRange{First: 0, Last: 10}
	if _, err := h.readMPUPlaintextRange(context.Background(), backend, bucket, key, nil, validRange); err != nil {
		t.Fatalf("valid MPU source range failed: %v", err)
	}
	manifestKey := bucket + "/" + key + ".mpu-manifest"
	for _, tc := range []struct {
		name   string
		mutate func()
	}{
		{"invalid binding", func() { backend.metadata[bucket+"/"+key][crypto.MetaObjectBindingID] = "bad" }},
		{"invalid marker", func() { backend.metadata[manifestKey][crypto.MetaMPUManifestVersion] = "1" }},
		{"corrupt manifest", func() { backend.objects[manifestKey] = []byte("corrupt") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, backend, _ = newMPUTestHandler(t, "sec42-copy-range-errors-*")
			r = sec42Router(t, h)
			doCompleteUpload(t, r, bucket, key, bytes.Repeat([]byte("Q"), sec42MPUPlainSize))
			manifestKey = bucket + "/" + key + ".mpu-manifest"
			tc.mutate()
			if _, err := h.readMPUPlaintextRange(context.Background(), backend, bucket, key, nil, validRange); err == nil {
				t.Fatal("malformed MPU source range accepted")
			}
		})
	}
}

type sec42ManifestReadFailureClient struct{ *mpuMockS3Client }

type sec42ManifestReadFailure struct{}

func (sec42ManifestReadFailure) Read([]byte) (int, error) {
	return 0, errors.New("manifest read failure")
}
func (sec42ManifestReadFailure) Close() error { return nil }

func (c *sec42ManifestReadFailureClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if strings.HasSuffix(key, ".mpu-manifest") {
		return sec42ManifestReadFailure{}, map[string]string{}, nil
	}
	return c.mpuMockS3Client.GetObject(ctx, bucket, key, versionID, rangeHeader)
}

func TestMPUV2_RangedGetManifestReadFailureReturnsNoPlaintext(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-ranged-read-error-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-ranged-read-error-bucket", "object"
	plain := bytes.Repeat([]byte("E"), sec42MPUPlainSize)
	doCompleteUpload(t, r, bucket, key, plain)
	h.s3Client = &sec42ManifestReadFailureClient{mpuMockS3Client: backend}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	req.Header.Set("Range", "bytes=0-10")
	r.ServeHTTP(w, req)
	require.NotEqual(t, http.StatusPartialContent, w.Code)
	require.NotContains(t, w.Body.String(), "EEEE")
}

func TestMPUCopyRangeLegacyManifestAndReadFailures(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-copy-legacy-manifest-*")
	bucket, key, uploadID := "sec42-copy-legacy-manifest-bucket", "source", "legacy-source"
	object := crypto.ObjectContext{Bucket: bucket, Key: key}
	dek := bytes.Repeat([]byte{9}, 32)
	uploadHash := crypto.UploadIDHash(uploadID)
	var iv [12]byte
	_, err := rand.Read(iv[:])
	require.NoError(t, err)
	envelope, err := h.keyManager.WrapKey(context.Background(), dek, map[string]string{"bucket": bucket, "key": key, "uploadId": uploadID})
	require.NoError(t, err)
	envelopeJSON, err := json.Marshal(envelope)
	require.NoError(t, err)
	plain := []byte("legacy source")
	partReader, partLen, err := crypto.NewMPUPartEncryptReaderV1(context.Background(), object, bytes.NewReader(plain), dek, uploadHash, iv, 1, crypto.DefaultChunkSize, int64(len(plain)), crypto.AlgorithmAES256GCM)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(partReader)
	require.NoError(t, err)
	manifest := &crypto.MultipartManifest{Version: 1, Algorithm: crypto.AlgorithmAES256GCM, ChunkSize: crypto.DefaultChunkSize, IVPrefix: hex.EncodeToString(iv[:]), UploadIDHash: mpu.UploadIDHashB64(uploadID), WrappedDEK: string(envelopeJSON), TotalPlainSize: int64(len(plain)), Parts: []crypto.MPUPartRecord{{PartNumber: 1, PlainLen: int64(len(plain)), EncLen: partLen, ChunkCount: 1}}}
	manifestJSON, err := manifest.Marshal()
	require.NoError(t, err)
	engine, err := h.getEncryptionEngine(bucket)
	require.NoError(t, err)
	manifestReader, manifestMeta, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: bucket, Key: key + ".mpu-manifest"}, bytes.NewReader(manifestJSON), nil)
	require.NoError(t, err)
	manifestCiphertext, err := io.ReadAll(manifestReader)
	require.NoError(t, err)
	// A v1 MPU has no v2 marker or binding. Setting MetaMPUEncrypted to
	// "v2" would intentionally require MetaObjectBindingID and is not a
	// valid legacy fixture.
	_, err = backend.PutObject(context.Background(), bucket, key, bytes.NewReader(ciphertext), map[string]string{crypto.MetaFallbackPointer: key + ".mpu-manifest", "Content-Length": fmt.Sprint(len(ciphertext))}, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)
	_, err = backend.PutObject(context.Background(), bucket, key+".mpu-manifest", bytes.NewReader(manifestCiphertext), manifestMeta, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)
	legacyReader, legacyMeta, err := backend.GetObject(context.Background(), bucket, key, nil, nil)
	require.NoError(t, err)
	backend.objects[bucket+"/"+key+".mpu-manifest"] = []byte("not-json")
	_, err = h.decryptMPUObject(context.Background(), bucket, key, legacyMeta, legacyReader, backend)
	require.Error(t, err)
	backend.objects[bucket+"/"+key+".mpu-manifest"] = []byte("not-json")
	badReader, badMeta, err := backend.GetObject(context.Background(), bucket, key, nil, nil)
	require.NoError(t, err)
	_, err = h.decryptMPUObject(context.Background(), bucket, key, badMeta, badReader, backend)
	require.Error(t, err)

	failingClient := &sec42ManifestReadFailureClient{mpuMockS3Client: backend}
	_, err = h.readMPUPlaintextRange(context.Background(), failingClient, bucket, key, nil, &s3.CopyPartRange{First: 0, Last: 5})
	require.Error(t, err)
}

func TestSEC42_LegacyMPUCopyRangeDecryptsExactSubrange(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-copy-legacy-range-*")
	bucket, key, uploadID := "sec42-copy-legacy-range-bucket", "source", "legacy-range"
	object := crypto.ObjectContext{Bucket: bucket, Key: key}
	dek := bytes.Repeat([]byte{9}, 32)
	uploadHash := crypto.UploadIDHash(uploadID)
	var iv [12]byte
	_, err := rand.Read(iv[:])
	require.NoError(t, err)
	envelope, err := h.keyManager.WrapKey(context.Background(), dek, map[string]string{"bucket": bucket, "key": key, "uploadId": uploadID})
	require.NoError(t, err)
	envelopeJSON, err := json.Marshal(envelope)
	require.NoError(t, err)
	plain := []byte("legacy ranged source")
	partReader, partLen, err := crypto.NewMPUPartEncryptReaderV1(context.Background(), object, bytes.NewReader(plain), dek, uploadHash, iv, 1, crypto.DefaultChunkSize, int64(len(plain)), crypto.AlgorithmAES256GCM)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(partReader)
	require.NoError(t, err)
	manifest := &crypto.MultipartManifest{Version: 1, Algorithm: crypto.AlgorithmAES256GCM, ChunkSize: crypto.DefaultChunkSize, IVPrefix: hex.EncodeToString(iv[:]), UploadIDHash: mpu.UploadIDHashB64(uploadID), WrappedDEK: string(envelopeJSON), TotalPlainSize: int64(len(plain)), Parts: []crypto.MPUPartRecord{{PartNumber: 1, PlainLen: int64(len(plain)), EncLen: partLen, ChunkCount: 1}}}
	manifestJSON, err := manifest.Marshal()
	require.NoError(t, err)
	engine, err := h.getEncryptionEngine(bucket)
	require.NoError(t, err)
	manifestReader, manifestMeta, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: bucket, Key: key + ".mpu-manifest"}, bytes.NewReader(manifestJSON), nil)
	require.NoError(t, err)
	manifestCiphertext, err := io.ReadAll(manifestReader)
	require.NoError(t, err)
	_, err = backend.PutObject(context.Background(), bucket, key, bytes.NewReader(ciphertext), map[string]string{crypto.MetaFallbackPointer: key + ".mpu-manifest", "Content-Length": fmt.Sprint(len(ciphertext))}, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)
	_, err = backend.PutObject(context.Background(), bucket, key+".mpu-manifest", bytes.NewReader(manifestCiphertext), manifestMeta, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)
	got, err := h.readMPUPlaintextRange(context.Background(), backend, bucket, key, nil, &s3.CopyPartRange{First: 7, Last: 12})
	require.NoError(t, err)
	require.Equal(t, plain[7:13], got)
}

func tamperSEC42MPUState(t *testing.T, mr *miniredis.Miniredis, mutate func(map[string]interface{})) {
	t.Helper()
	for _, key := range mr.Keys() {
		if !strings.HasPrefix(key, "mpu:") || key == "mpu:writer-version" {
			continue
		}
		var fields map[string]interface{}
		require.NoError(t, json.Unmarshal([]byte(mr.HGet(key, "meta")), &fields))
		mutate(fields)
		encoded, err := json.Marshal(fields)
		require.NoError(t, err)
		mr.HSet(key, "meta", string(encoded))
		return
	}
	t.Fatal("MPU state key not found")
}

func TestSEC42_MPUUploadPartRouteMismatchHasNoMutation(t *testing.T) {
	h, backend, mr := newMPUTestHandler(t, "sec42-state-upload-part-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-state-upload-part-bucket", "object"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploads=", nil))
	uploadID := extractUploadID(t, w.Body.String())
	tamperSEC42MPUState(t, mr, func(fields map[string]interface{}) { fields["bucket"] = "wrong-bucket" })
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+key+"?partNumber=1&uploadId="+uploadID, bytes.NewReader([]byte("part"))))
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Empty(t, backend.parts)
}

func TestSEC42_MPUUploadPartCopyRouteMismatchHasNoMutation(t *testing.T) {
	h, backend, mr := newMPUTestHandler(t, "sec42-state-copy-*")
	r := sec42Router(t, h)
	bucket := "sec42-state-copy-bucket"
	doCompleteUpload(t, r, bucket, "source", []byte("source"))
	beforeParts := len(backend.parts)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/destination?uploads=", nil))
	uploadID := extractUploadID(t, w.Body.String())
	tamperSEC42MPUState(t, mr, func(fields map[string]interface{}) { fields["key"] = "wrong-key" })
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/destination?partNumber=1&uploadId="+uploadID, nil)
	req.Header.Set("x-amz-copy-source", "/"+bucket+"/source")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusNotFound, w.Code)
	require.Len(t, backend.parts, beforeParts)
}

func TestSEC42_MPUCompleteRouteMismatchHasNoMutation(t *testing.T) {
	h, backend, mr := newMPUTestHandler(t, "sec42-state-complete-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-state-complete-bucket", "object"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploads=", nil))
	uploadID := extractUploadID(t, w.Body.String())
	partReq := httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+key+"?partNumber=1&uploadId="+uploadID, strings.NewReader("part"))
	partW := httptest.NewRecorder()
	r.ServeHTTP(partW, partReq)
	require.Equal(t, http.StatusOK, partW.Code)
	etag := partW.Header().Get("ETag")
	tamperSEC42MPUState(t, mr, func(fields map[string]interface{}) { fields["bucket"] = "wrong-bucket" })
	body := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + etag + `</ETag></Part></CompleteMultipartUpload>`
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploadId="+uploadID, strings.NewReader(body)))
	require.Equal(t, http.StatusNotFound, w.Code)
	_, err := backend.HeadObject(context.Background(), bucket, key, nil)
	require.Error(t, err)
}

func TestLegacyMPUManifestDecryptAndParseFailures(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-legacy-manifest-path-*")
	h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) {
		return &mockEngine{}, nil
	}
	bucket, key := "sec42-legacy-manifest-path-bucket", "source"
	backend.objects[bucket+"/"+key] = []byte("ciphertext")
	backend.metadata[bucket+"/"+key] = map[string]string{crypto.MetaMPUEncrypted: "true", crypto.MetaFallbackPointer: key + ".mpu-manifest"}
	backend.objects[bucket+"/"+key+".mpu-manifest"] = []byte("not-json")
	backend.metadata[bucket+"/"+key+".mpu-manifest"] = map[string]string{}

	r, meta, err := backend.GetObject(context.Background(), bucket, key, nil, nil)
	require.NoError(t, err)
	_, err = h.decryptMPUObject(context.Background(), bucket, key, meta, r, backend)
	require.Error(t, err)
	_, err = h.readMPUPlaintextRange(context.Background(), backend, bucket, key, nil, &s3.CopyPartRange{First: 0, Last: 1})
	require.Error(t, err)
}

func TestMPUManifestReaderSetupFailureIsFailClosed(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-reader-setup-*")
	bucket, key := "sec42-reader-setup-bucket", "source"
	backend.objects[bucket+"/"+key] = []byte("ciphertext")
	backend.metadata[bucket+"/"+key] = map[string]string{crypto.MetaMPUEncrypted: "v2", crypto.MetaObjectBindingID: "bad", crypto.MetaFallbackPointer: key + ".mpu-manifest"}
	backend.objects[bucket+"/"+key+".mpu-manifest"] = []byte("manifest")
	backend.metadata[bucket+"/"+key+".mpu-manifest"] = map[string]string{crypto.MetaMPUManifestVersion: "2"}
	reader, meta, err := backend.GetObject(context.Background(), bucket, key, nil, nil)
	require.NoError(t, err)
	_, err = h.decryptMPUObject(context.Background(), bucket, key, meta, reader, backend)
	require.Error(t, err)
}

func TestMPUManifestHelperFailureContracts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		engine crypto.EncryptionEngine
		body   []byte
	}{
		{"decrypt failure", &sec39ErrorEngine{err: errors.New("manifest decrypt failure")}, []byte("ciphertext")},
		{"parse failure", &mockEngine{}, []byte("not-json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, backend, _ := newMPUTestHandler(t, "sec42-manifest-helper-*")
			h.encryptionEngineLoader = func(string) (crypto.EncryptionEngine, error) { return tc.engine, nil }
			bucket, key := "sec42-manifest-helper-bucket", "source"
			manifestKey := key + ".mpu-manifest"
			backend.objects[bucket+"/"+manifestKey] = tc.body
			backend.metadata[bucket+"/"+manifestKey] = map[string]string{}
			backend.objects[bucket+"/"+key] = []byte("ciphertext")
			backend.metadata[bucket+"/"+key] = map[string]string{crypto.MetaMPUEncrypted: "true", crypto.MetaFallbackPointer: manifestKey}

			reader, meta, err := backend.GetObject(context.Background(), bucket, key, nil, nil)
			require.NoError(t, err)
			_, err = h.decryptMPUObject(context.Background(), bucket, key, meta, reader, backend)
			require.Error(t, err)

			_, err = h.readMPUManifestTotalPlainSize(context.Background(), bucket, key, manifestKey, backend.metadata[bucket+"/"+key], backend)
			require.Error(t, err)
		})
	}
}

func sec42Put(t *testing.T, r *mux.Router, bucket, key string, data []byte) {
	t.Helper()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+key, bytes.NewReader(data))
	req.Header.Set("Content-Length", "100")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}

func sec42Get(t *testing.T, r *mux.Router, bucket, key string) []byte {
	t.Helper()
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	return w.Body.Bytes()
}

func TestPutGet_BoundObjectRoundTrip(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-bound-*")
	r := sec42Router(t, h)
	plain := []byte("route-derived object context")
	sec42Put(t, r, "sec42-bound-bucket", "a", plain)
	require.Equal(t, plain, sec42Get(t, r, "sec42-bound-bucket", "a"))
	require.NotEmpty(t, backend.metadata["sec42-bound-bucket/a"][crypto.MetaObjectBindingID])
}

func TestBackendMove_BoundObjectFailsClosed(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-move-*")
	r := sec42Router(t, h)
	plain := []byte("must not survive backend relocation")
	sec42Put(t, r, "sec42-move-bucket", "a", plain)
	backend.objects["sec42-move-bucket/b"] = append([]byte(nil), backend.objects["sec42-move-bucket/a"]...)
	backend.metadata["sec42-move-bucket/b"] = map[string]string{}
	for k, v := range backend.metadata["sec42-move-bucket/a"] {
		backend.metadata["sec42-move-bucket/b"][k] = v
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sec42-move-bucket/b", nil))
	require.NotEqual(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), string(plain))
}

func TestCopyObject_RebindsDestination(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-copy-*")
	r := sec42Router(t, h)
	plain := []byte("copy gets a new destination binding")
	sec42Put(t, r, "sec42-copy-bucket", "a", plain)
	srcID := backend.metadata["sec42-copy-bucket/a"][crypto.MetaObjectBindingID]
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sec42-copy-bucket/b", nil)
	req.Header.Set("x-amz-copy-source", "/sec42-copy-bucket/a")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, plain, sec42Get(t, r, "sec42-copy-bucket", "b"))
	dstID := backend.metadata["sec42-copy-bucket/b"][crypto.MetaObjectBindingID]
	require.NotEmpty(t, srcID)
	require.NotEmpty(t, dstID)
	require.NotEqual(t, srcID, dstID)
	engine, err := h.getEncryptionEngine("sec42-copy-bucket")
	require.NoError(t, err)
	reader, _, err := engine.Decrypt(context.Background(), crypto.ObjectContext{Bucket: "sec42-copy-bucket", Key: "a"}, bytes.NewReader(backend.objects["sec42-copy-bucket/b"]), backend.metadata["sec42-copy-bucket/b"])
	if err == nil {
		_, err = io.ReadAll(reader)
	}
	require.Error(t, err)
}

func TestCopyObject_SameKeyRefreshesBindingID(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-same-*")
	r := sec42Router(t, h)
	plain := []byte("same key copy")
	sec42Put(t, r, "sec42-same-bucket", "a", plain)
	oldID := backend.metadata["sec42-same-bucket/a"][crypto.MetaObjectBindingID]
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/sec42-same-bucket/a", nil)
	req.Header.Set("x-amz-copy-source", "/sec42-same-bucket/a")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotEqual(t, oldID, backend.metadata["sec42-same-bucket/a"][crypto.MetaObjectBindingID])
	require.Equal(t, plain, sec42Get(t, r, "sec42-same-bucket", "a"))
}

func TestMPUCompleteV2_BindsDataManifestAndCompanion(t *testing.T) {
	h, backend, mr := newMPUTestHandler(t, "sec42-complete-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-complete-bucket", "a"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploads=", nil))
	require.Equal(t, http.StatusOK, w.Code)
	uploadID := extractUploadID(t, w.Body.String())
	mainMeta := backend.partsMeta[bucket+"/"+key+"/"+uploadID]
	state, err := h.mpuStateStore.Get(context.Background(), uploadID)
	require.NoError(t, err)
	require.Equal(t, mainMeta[crypto.MetaObjectBindingID], state.BindingID)
	data := []byte("v2 complete")
	var etag string
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/"+key+"?partNumber=1&uploadId="+uploadID, bytes.NewReader(data))
	req.Header.Set("Content-Length", "11")
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	etag = w.Header().Get("ETag")
	w = httptest.NewRecorder()
	complete := "<?xml version=\"1.0\"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" + etag + "</ETag></Part></CompleteMultipartUpload>"
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploadId="+uploadID, bytes.NewBufferString(complete)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, data, sec42Get(t, r, bucket, key))
	manifestMeta := backend.metadata[bucket+"/"+key+".mpu-manifest"]
	require.Equal(t, "2", manifestMeta[crypto.MetaMPUManifestVersion])
	require.Equal(t, mainMeta[crypto.MetaObjectBindingID], manifestMeta[crypto.MetaObjectBindingID])
	require.NotNil(t, mr)
}

func TestMPUManifestSwap_FailsClosed(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-swap-*")
	r := sec42Router(t, h)
	bucket := "sec42-swap-bucket"
	doCompleteUpload(t, r, bucket, "a", []byte("parent a"))
	// Reuse the authenticated companion rather than completing a second MPU.
	// The copied manifest still declares a.mpu-manifest as its companion, so
	// pointing a at b.mpu-manifest exercises the same relationship mismatch
	// without paying for another FIPS PBKDF setup.
	backend.objects[bucket+"/b.mpu-manifest"] = append([]byte(nil), backend.objects[bucket+"/a.mpu-manifest"]...)
	backend.metadata[bucket+"/b.mpu-manifest"] = make(map[string]string)
	for k, v := range backend.metadata[bucket+"/a.mpu-manifest"] {
		backend.metadata[bucket+"/b.mpu-manifest"][k] = v
	}
	backend.metadata[bucket+"/a"][crypto.MetaFallbackPointer] = "b.mpu-manifest"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+bucket+"/a", nil))
	require.NotEqual(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), "parent b")
}

func TestMPURangeV2_KeyMismatchFails(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-range-*")
	r := sec42Router(t, h)
	plain := bytes.Repeat([]byte("r"), sec42MPUPlainSize)
	doCompleteUpload(t, r, "sec42-range-bucket", "a", plain)
	backend.objects["sec42-range-bucket/b"] = append([]byte(nil), backend.objects["sec42-range-bucket/a"]...)
	backend.metadata["sec42-range-bucket/b"] = map[string]string{}
	for k, v := range backend.metadata["sec42-range-bucket/a"] {
		backend.metadata["sec42-range-bucket/b"][k] = v
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sec42-range-bucket/b", nil)
	req.Header.Set("Range", "bytes=0-99")
	r.ServeHTTP(w, req)
	require.NotEqual(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), string(plain[:100]))
}

func TestMPUUploadPartCopy_RebindsDestination(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-upcopy-*")
	r := sec42Router(t, h)
	bucket := "sec42-upcopy-bucket"
	sourcePlain := bytes.Repeat([]byte("S"), sec42MPUPlainSize)
	doCompleteUpload(t, r, bucket, "source", sourcePlain)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/dest?uploads=", nil))
	require.Equal(t, http.StatusOK, w.Code)
	uploadID := extractUploadID(t, w.Body.String())
	srcID := backend.metadata[bucket+"/source"][crypto.MetaObjectBindingID]
	req := httptest.NewRequest(http.MethodPut, "/"+bucket+"/dest?partNumber=1&uploadId="+uploadID, nil)
	req.Header.Set("x-amz-copy-source", "/"+bucket+"/source")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	state, err := h.mpuStateStore.Get(context.Background(), uploadID)
	require.NoError(t, err)
	require.NotEqual(t, srcID, state.BindingID)
	require.NotEqual(t, [16]byte{}, func() [16]byte {
		b, _ := base64.RawURLEncoding.DecodeString(state.BindingID)
		var id [16]byte
		copy(id[:], b)
		return id
	}())
	// Complete the destination MPU through the production completion path.
	var copyResult CopyPartResultXML
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), &copyResult))
	etag := copyResult.ETag
	complete := "<?xml version=\"1.0\"?><CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" + etag + "</ETag></Part></CompleteMultipartUpload>"
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/dest?uploadId="+uploadID, bytes.NewBufferString(complete)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, sourcePlain, sec42Get(t, r, bucket, "dest"))
	engine, err := h.getEncryptionEngine(bucket)
	require.NoError(t, err)
	// The source MPU companion is authentic at its source location, but cannot
	// be paired with the destination binding/context after re-encryption.
	var dstBinding [16]byte
	dstRaw, err := base64.RawURLEncoding.DecodeString(backend.metadata[bucket+"/dest"][crypto.MetaObjectBindingID])
	require.NoError(t, err)
	copy(dstBinding[:], dstRaw)
	srcManifest := backend.objects[bucket+"/source.mpu-manifest"]
	srcManifestMeta := backend.metadata[bucket+"/source.mpu-manifest"]
	_, err = crypto.DecryptMPUManifest(context.Background(), engine, crypto.ObjectContext{Bucket: bucket, Key: "dest.mpu-manifest"}, dstBinding, srcManifest, srcManifestMeta)
	require.Error(t, err, "source MPU manifest authenticated at destination context")
}

func TestMPUV2_NewUploadGetsFreshBinding(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-fresh-*")
	r := sec42Router(t, h)
	ids := make([]string, 2)
	bindings := make([]string, 2)
	for i := range ids {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/sec42-fresh-bucket/object?uploads=", nil))
		require.Equal(t, http.StatusOK, w.Code)
		ids[i] = extractUploadID(t, w.Body.String())
		meta := backend.partsMeta["sec42-fresh-bucket/object/"+ids[i]]
		bindings[i] = meta[crypto.MetaObjectBindingID]
		decoded, err := base64.RawURLEncoding.DecodeString(meta[crypto.MetaObjectBindingID])
		require.NoError(t, err)
		require.Len(t, decoded, 16)
		require.NotEqual(t, make([]byte, 16), decoded)
	}
	require.NotEqual(t, ids[0], ids[1])
	require.NotEqual(t, bindings[0], bindings[1])
}

func TestMPUV2_RangeAcrossPartBoundary(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-range-boundary-*")
	r := sec42Router(t, h)
	parts := [][]byte{bytes.Repeat([]byte("A"), sec42MPUPlainSize), bytes.Repeat([]byte("B"), sec42MPUPlainSize)}
	doCompleteUploadWithParts(t, r, "sec42-range-boundary-bucket", "object", parts)
	start, end := int64(len(parts[0])-11), int64(len(parts[0])+10)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/sec42-range-boundary-bucket/object", nil)
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusPartialContent, w.Code, w.Body.String())
	require.Equal(t, append(bytes.Repeat([]byte("A"), 11), bytes.Repeat([]byte("B"), 11)...), w.Body.Bytes())
	backend.objects["sec42-range-boundary-bucket/moved"] = append([]byte(nil), backend.objects["sec42-range-boundary-bucket/object"]...)
	backend.metadata["sec42-range-boundary-bucket/moved"] = cloneMetadata(backend.metadata["sec42-range-boundary-bucket/object"])
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/sec42-range-boundary-bucket/moved", nil)
	req.Header.Set("Range", "bytes=0-20")
	r.ServeHTTP(w, req)
	require.NotEqual(t, http.StatusPartialContent, w.Code)
	require.NotContains(t, w.Body.String(), "A")
}

func TestMPUV2_RangeRejectsInvalidHeadersAndManifestRead(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-range-errors-*")
	r := sec42Router(t, h)
	bucket, key := "sec42-range-errors-bucket", "object"
	doCompleteUpload(t, r, bucket, key, bytes.Repeat([]byte("R"), sec42MPUPlainSize))
	for _, header := range []string{"bytes=bad", "bytes=999999-1000000", "bytes=10-1"} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
		req.Header.Set("Range", header)
		r.ServeHTTP(w, req)
		require.NotEqual(t, http.StatusOK, w.Code)
	}
	backend.metadata[bucket+"/"+key][crypto.MetaFallbackPointer] = "missing.mpu-manifest"
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	req.Header.Set("Range", "bytes=0-10")
	r.ServeHTTP(w, req)
	require.NotEqual(t, http.StatusPartialContent, w.Code)
}

func TestMigrationRewrite_LegacyToBoundV2(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-migration-*")
	r := sec42Router(t, h)
	// A legacy/plain object is read through the gateway, then rewritten through
	// the actual PUT route, which is the supported migration operation.
	legacy := []byte("legacy migration payload")
	backend.objects["sec42-migration-bucket/legacy"] = legacy
	backend.metadata["sec42-migration-bucket/legacy"] = map[string]string{}
	got := sec42Get(t, r, "sec42-migration-bucket", "legacy")
	sec42Put(t, r, "sec42-migration-bucket", "legacy", got)
	require.Equal(t, "chunked-v2", backend.metadata["sec42-migration-bucket/legacy"][crypto.MetaObjectFormatVersion])
}

func TestMigrationRewrite_MovedDestinationRebinds(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-migration-move-*")
	r := sec42Router(t, h)
	plain := []byte("moved legacy payload")
	backend.objects["sec42-migration-move-bucket/source"] = plain
	backend.metadata["sec42-migration-move-bucket/source"] = map[string]string{}
	sec42Put(t, r, "sec42-migration-move-bucket", "destination", sec42Get(t, r, "sec42-migration-move-bucket", "source"))
	require.Equal(t, plain, sec42Get(t, r, "sec42-migration-move-bucket", "destination"))
	require.Equal(t, "chunked-v2", backend.metadata["sec42-migration-move-bucket/destination"][crypto.MetaObjectFormatVersion])
}

func TestMigrationRewrite_MPUV1ToCurrentFormats(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-migration-mpu-*")
	r := sec42Router(t, h)
	plain := []byte("legacy MPU migration payload")
	bucket, key, uploadID := "sec42-migration-mpu-bucket", "source", "legacy-mpu-migration"
	dek := bytes.Repeat([]byte{7}, 32)
	uploadHash := crypto.UploadIDHash(uploadID)
	var iv [12]byte
	_, err := rand.Read(iv[:])
	require.NoError(t, err)
	envelope, err := h.keyManager.WrapKey(context.Background(), dek, map[string]string{"bucket": bucket, "key": key, "uploadId": uploadID})
	require.NoError(t, err)
	env, err := json.Marshal(envelope)
	require.NoError(t, err)
	partReader, partLen, err := crypto.NewMPUPartEncryptReaderV1(context.Background(), crypto.ObjectContext{Bucket: bucket, Key: key}, bytes.NewReader(plain), dek, uploadHash, iv, 1, crypto.DefaultChunkSize, int64(len(plain)), crypto.AlgorithmAES256GCM)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(partReader)
	require.NoError(t, err)
	manifest := &crypto.MultipartManifest{Version: 1, Algorithm: crypto.AlgorithmAES256GCM, ChunkSize: crypto.DefaultChunkSize, IVPrefix: hex.EncodeToString(iv[:]), UploadIDHash: mpu.UploadIDHashB64(uploadID), WrappedDEK: string(env), TotalPlainSize: int64(len(plain)), Parts: []crypto.MPUPartRecord{{PartNumber: 1, PlainLen: int64(len(plain)), EncLen: partLen, ChunkCount: 1}}}
	manifestJSON, err := manifest.Marshal()
	require.NoError(t, err)
	engine, err := h.getEncryptionEngine(bucket)
	require.NoError(t, err)
	manifestReader, manifestMeta, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: bucket, Key: key + ".mpu-manifest"}, bytes.NewReader(manifestJSON), map[string]string{crypto.MetaEncrypted: "true"})
	require.NoError(t, err)
	manifestCiphertext, err := io.ReadAll(manifestReader)
	require.NoError(t, err)
	_, err = backend.PutObject(context.Background(), bucket, key, bytes.NewReader(ciphertext), map[string]string{crypto.MetaMPUEncrypted: "true", crypto.MetaFallbackPointer: key + ".mpu-manifest", "Content-Length": fmt.Sprint(len(ciphertext))}, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)
	_, err = backend.PutObject(context.Background(), bucket, key+".mpu-manifest", bytes.NewReader(manifestCiphertext), manifestMeta, nil, "", nil, "", "", "", "", "")
	require.NoError(t, err)
	got := sec42Get(t, r, bucket, key)
	sec42Put(t, r, bucket, "destination", got)
	require.Equal(t, plain, sec42Get(t, r, "sec42-migration-mpu-bucket", "destination"))
	require.Equal(t, "chunked-v2", backend.metadata[bucket+"/destination"][crypto.MetaObjectFormatVersion])
	require.NotEmpty(t, backend.metadata[bucket+"/destination"][crypto.MetaObjectBindingID])
	backend.objects[bucket+"/moved"] = append([]byte(nil), backend.objects[bucket+"/destination"]...)
	backend.metadata[bucket+"/moved"] = cloneMetadata(backend.metadata[bucket+"/destination"])
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+bucket+"/moved", nil))
	require.NotEqual(t, http.StatusOK, w.Code)
}

func cloneMetadata(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
