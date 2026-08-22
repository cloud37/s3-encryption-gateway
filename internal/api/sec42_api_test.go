package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

const sec42MPUPlainSize = crypto.DefaultChunkSize + 1

func TestSEC42_MPUCreate_PersistsMatchingBinding(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-create-*")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "sec42-create-bucket", "object"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/"+bucket+"/"+key+"?uploads=", nil))
	require.Equal(t, http.StatusOK, w.Code)
	uploadID := extractUploadID(t, w.Body.String())

	meta := backend.partsMeta[bucket+"/"+key+"/"+uploadID]
	require.Equal(t, "v2", meta[crypto.MetaMPUEncrypted])
	b, err := base64.RawURLEncoding.DecodeString(meta[crypto.MetaObjectBindingID])
	require.NoError(t, err)
	require.Len(t, b, 16)
	require.NotEqual(t, make([]byte, 16), b)
	state, err := h.mpuStateStore.Get(context.Background(), uploadID)
	require.NoError(t, err)
	require.Equal(t, meta[crypto.MetaObjectBindingID], state.BindingID)
}

func TestSEC42_MPUV2_ManifestBindingMismatchFailsClosed(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-mismatch-*")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "sec42-mismatch-bucket", "object"
	plain := bytes.Repeat([]byte("x"), sec42MPUPlainSize)
	doCompleteUpload(t, router, bucket, key, plain)
	meta := backend.metadata[bucket+"/"+key]
	var wrong [16]byte
	_, err := rand.Read(wrong[:])
	require.NoError(t, err)
	meta[crypto.MetaObjectBindingID] = base64.RawURLEncoding.EncodeToString(wrong[:])

	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil))
	require.NotEqual(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), string(plain))
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil)
	req.Header.Set("Range", "bytes=0-99")
	router.ServeHTTP(w, req)
	require.NotEqual(t, http.StatusOK, w.Code)
	require.NotContains(t, w.Body.String(), string(plain))
}

func TestSEC42_MPUV2_HeadRejectsSwappedCompanion(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-head-*")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket := "sec42-head-bucket"
	doCompleteUpload(t, router, bucket, "a", bytes.Repeat([]byte("a"), 4096))
	doCompleteUpload(t, router, bucket, "b", bytes.Repeat([]byte("b"), 8192))
	mainMeta := backend.metadata[bucket+"/a"]
	mainMeta[crypto.MetaFallbackPointer] = "b.mpu-manifest"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/"+bucket+"/a", nil))
	require.Equal(t, http.StatusOK, w.Code)
	contentLength := w.Header().Get("Content-Length")
	require.NotEqual(t, "8192", contentLength)
}

func TestSEC42_MPUV1_LegacyReadStillWorks(t *testing.T) {
	h, backend, _ := newMPUTestHandler(t, "sec42-legacy-*")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	bucket, key := "sec42-legacy-bucket", "object"
	plain := []byte("legacy multipart plaintext")
	uploadID := "legacy-upload"
	dek := bytes.Repeat([]byte{7}, 32)
	uploadIDHash := crypto.UploadIDHash(uploadID)
	var iv [12]byte
	_, err := rand.Read(iv[:])
	require.NoError(t, err)
	envelope, err := h.keyManager.WrapKey(context.Background(), dek, map[string]string{"bucket": bucket, "key": key, "uploadId": uploadID})
	require.NoError(t, err)
	env, err := json.Marshal(envelope)
	require.NoError(t, err)
	partReader, partLen, err := crypto.NewMPUPartEncryptReaderV1(context.Background(), crypto.ObjectContext{Bucket: bucket, Key: key}, bytes.NewReader(plain), dek, uploadIDHash, iv, 1, crypto.DefaultChunkSize, int64(len(plain)), crypto.AlgorithmAES256GCM)
	require.NoError(t, err)
	ciphertext, err := io.ReadAll(partReader)
	require.NoError(t, err)
	manifest := (&crypto.MultipartManifest{Version: 1, Algorithm: crypto.AlgorithmAES256GCM, ChunkSize: crypto.DefaultChunkSize, IVPrefix: hex.EncodeToString(iv[:]), UploadIDHash: mpu.UploadIDHashB64(uploadID), WrappedDEK: string(env), TotalPlainSize: int64(len(plain)), Parts: []crypto.MPUPartRecord{{PartNumber: 1, PlainLen: int64(len(plain)), EncLen: partLen, ChunkCount: 1}}})
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
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+bucket+"/"+key, nil))
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, plain, w.Body.Bytes())
}
