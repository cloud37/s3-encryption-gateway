package api

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/pbkdf2"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/hkdf"
)

const (
	goldenPassword = "object-format-golden-password"
	goldenBucket   = "golden-bucket"
	goldenObject   = "golden-object"
	goldenPlain    = "authentic golden plaintext payload"
)

var goldenStandardHeaders = map[string]string{
	"Content-Type":        "application/x-golden",
	"Cache-Control":       "private, max-age=37",
	"Content-Disposition": `attachment; filename="golden.txt"`,
	"Content-Encoding":    "identity",
	"Content-Language":    "en-CA",
	"Expires":             "Tue, 15 Nov 2033 08:12:31 GMT",
}

type goldenBackendFixture struct {
	objectFormatFixture
	Ciphertext       string            `json:"ciphertext_base64"`
	Body             string            `json:"body_base64"`
	ManifestBody     string            `json:"manifest_body_base64,omitempty"`
	ManifestMetadata map[string]string `json:"manifest_metadata,omitempty"`
	Profile          string            `json:"crypto_profile,omitempty"`
	MetadataKey      bool              `json:"metadata_key,omitempty"`
	ExpectedBody     string            `json:"plaintext_base64"`
	TamperFirstChunk bool              `json:"-"`
}

type repeatReader byte

func (r repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r) + byte(i%31)
	}
	return len(p), nil
}

func TestGenerateObjectFormatFixtures(t *testing.T) {
	if os.Getenv("UPDATE_OBJECTFORMAT_GOLDENS") != "1" {
		t.Skip("set UPDATE_OBJECTFORMAT_GOLDENS=1 to regenerate deterministic encrypted object fixtures")
	}
	formats := []string{
		"buffered-legacy", "buffered-v2", "fallback-v1", "fallback-v2", "fallback-v3",
		"chunked-v1", "chunked-v2", "compacted", "metadata-blob-buffered", "metadata-blob-chunked",
		"mpu-v1", "mpu-v2", "plaintext",
	}
	dir := filepath.Join("testdata", "objectformats")
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			oldReader := crand.Reader
			crand.Reader = repeatReader(byte(0x31 + len(format)))
			t.Cleanup(func() { crand.Reader = oldReader })
			fixture, err := generateAuthenticObjectFixture(format)
			if err != nil {
				t.Fatal(err)
			}
			fixture.Metadata = sortedJSONMap(fixture.Metadata)
			fixture.Headers = sortedJSONMap(fixture.Headers)
			fixture.ManifestMetadata = sortedJSONMap(fixture.ManifestMetadata)
			data, err := json.MarshalIndent(fixture, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, '\n')
			if err := os.WriteFile(filepath.Join(dir, format+".json"), data, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func generateAuthenticObjectFixture(format string) (goldenBackendFixture, error) {
	ctx := context.Background()
	plain := []byte(goldenPlain)
	obj := crypto.ObjectContext{Bucket: goldenBucket, Key: goldenObject}
	f := goldenBackendFixture{objectFormatFixture: objectFormatFixture{Format: format, Size: int64(len(plain))}, ExpectedBody: base64.StdEncoding.EncodeToString(plain)}
	metadata := map[string]string{}
	for k, v := range goldenStandardHeaders {
		metadata[k] = v
	}
	metadata["x-amz-meta-user-a"] = "golden-user-value"
	metadata["ETag"] = "backend-cipher-etag"
	if format != "plaintext" {
		metadata[crypto.MetaWrappedKeyCiphertext] = "internal-must-not-leak"
	}

	if format == "plaintext" {
		f.Body = base64.StdEncoding.EncodeToString(plain)
		f.Ciphertext = f.Body
		metadata["Content-Length"] = strconv.Itoa(len(plain))
		metadata["ETag"] = `"plaintext-golden-etag"`
		f.Metadata = metadata
		f.Headers = goldenExpectedHeaders(metadata["ETag"], int64(len(plain)), goldenStandardHeaders)
		f.Ciphertext = f.Body
		return f, nil
	}

	if format == "mpu-v1" || format == "mpu-v2" {
		return generateGoldenMPU(format, f, plain, metadata)
	}

	var opts []crypto.Option
	if format == "chunked-v1" || format == "chunked-v2" || format == "metadata-blob-chunked" || format == "fallback-v2" {
		opts = append(opts, crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize))
	}
	if format == "metadata-blob-buffered" || format == "metadata-blob-chunked" {
		opts = append(opts, crypto.WithMetadataKey(bytes.Repeat([]byte{0x42}, 32)))
		f.MetadataKey = true
	}
	if format == "compacted" {
		opts = append(opts, crypto.WithProvider("aws"))
		f.Profile = "aws"
	}
	if format == "fallback-v1" {
		opts = append(opts, crypto.WithAllowUnmarkedNoAADFallback(true))
	}
	engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), append(opts, crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))...)
	if err != nil {
		return f, err
	}
	defer func() {
		if closer, ok := engine.(io.Closer); ok {
			_ = closer.Close()
		}
	}()

	if format == "buffered-legacy" || format == "chunked-v1" || format == "fallback-v1" {
		var body []byte
		var meta map[string]string
		switch format {
		case "buffered-legacy":
			body, meta, err = makeLegacyBufferedFixture(plain, metadata)
		case "chunked-v1":
			body, meta, err = makeLegacyChunkedFixture(plain, metadata)
		case "fallback-v1":
			body, meta, err = makeLegacyFallbackFixture(plain, metadata)
		}
		if err != nil {
			return f, err
		}
		f.Body, f.Metadata = base64.StdEncoding.EncodeToString(body), meta
		f.Metadata[crypto.MetaWrappedKeyCiphertext] = "internal-must-not-leak"
	} else {
		encInput := cloneStringMap(metadata)
		encInput["Content-Length"] = strconv.Itoa(len(plain))
		encInput["ETag"] = "golden-plaintext-etag"
		if format == "fallback-v2" || format == "fallback-v3" {
			// Trigger the engine's real metadata fallback branch without external I/O.
			encInput["x-amz-meta-golden-padding"] = strings.Repeat("p", 9000)
		}
		reader, encMeta, encErr := engine.Encrypt(ctx, obj, bytes.NewReader(plain), encInput)
		if encErr != nil {
			return f, encErr
		}
		body, readErr := io.ReadAll(reader)
		if readErr != nil {
			return f, readErr
		}
		if format == "fallback-v3" && encMeta[crypto.MetaFallbackVersion] != "3" {
			return f, fmt.Errorf("buffered fallback fixture produced version %q", encMeta[crypto.MetaFallbackVersion])
		}
		f.Body, f.Metadata = base64.StdEncoding.EncodeToString(body), mergeMaps(encMeta, backendObjectHeaders(metadata, body, "backend-cipher-etag"))
		if format == "fallback-v2" || format == "fallback-v3" {
			f.Metadata[crypto.MetaOriginalSize] = strconv.Itoa(len(plain))
			f.Metadata[crypto.MetaOriginalETag] = "golden-plaintext-etag"
		}
		f.Metadata[crypto.MetaWrappedKeyCiphertext] = "internal-must-not-leak"
		if format == "compacted" {
			f.Profile = "aws"
		}
	}
	if f.Metadata == nil {
		return f, fmt.Errorf("format %s generated no backend metadata", format)
	}
	f.Metadata["Content-Length"] = strconv.Itoa(len(mustDecodeBase64(f.Body)))
	if f.Metadata["ETag"] == "" {
		f.Metadata["ETag"] = "backend-cipher-etag"
	}
	if f.Format == "fallback-v1" || f.Format == "fallback-v2" || f.Format == "fallback-v3" {
		// These compatibility fallback generations embed the authenticated client
		// metadata inside ciphertext; no user metadata is exposed in HEAD.
		if f.Format != "fallback-v1" {
			f.Metadata["x-amz-meta-user-a"] = "golden-user-value"
		}
	}
	plainETag := f.Metadata[crypto.MetaOriginalETag]
	if plainETag == "" {
		digest := md5.Sum(plain)
		plainETag = hex.EncodeToString(digest[:])
		f.Metadata[crypto.MetaOriginalETag] = plainETag
	}
	f.Headers = goldenExpectedHeaders(quoteETag(plainETag), int64(len(plain)), goldenStandardHeaders)
	if format == "metadata-blob-chunked" {
		f.Headers["ETag"] = `"golden-plaintext-etag"`
	}
	f.Ciphertext = f.Body
	return f, nil
}

func makeLegacyBufferedFixture(plain []byte, standard map[string]string) ([]byte, map[string]string, error) {
	salt := bytes.Repeat([]byte{0x19}, 32)
	iv := bytes.Repeat([]byte{0x27}, 12)
	params := crypto.DefaultKDFParams(crypto.MinPBKDF2Iterations)
	key, err := pbkdf2.Key(sha256.New, goldenPassword, salt, params.Iterations, 32)
	if err != nil {
		return nil, nil, err
	}
	defer zeroFixtureBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	md5sum := md5.Sum(plain)
	meta := map[string]string{
		crypto.MetaEncrypted: "true", crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKeySalt: base64.StdEncoding.EncodeToString(salt), crypto.MetaIV: base64.StdEncoding.EncodeToString(iv),
		crypto.MetaOriginalSize: strconv.Itoa(len(plain)), crypto.MetaOriginalETag: hex.EncodeToString(md5sum[:]),
		crypto.MetaKDFParams: crypto.FormatKDFParams(params),
	}
	for _, spec := range crypto.ProtectedStandardKeys() {
		meta[spec.Canonical] = standard[spec.Header]
	}
	ct := aead.Seal(nil, iv, plain, legacyGoldenAAD(crypto.AlgorithmAES256GCM, salt, iv, standard["Content-Type"], len(plain)))
	meta["Content-Length"] = strconv.Itoa(len(ct))
	meta["ETag"] = "backend-cipher-etag"
	meta["x-amz-meta-user-a"] = "golden-user-value"
	meta[crypto.MetaWrappedKeyCiphertext] = "internal-must-not-leak"
	return ct, meta, nil
}

func makeLegacyFallbackFixture(plain []byte, standard map[string]string) ([]byte, map[string]string, error) {
	ct, meta, err := makeLegacyBufferedFixture(plain, standard)
	if err != nil {
		return nil, nil, err
	}
	// The v1 fallback body wraps serialized full metadata and the payload in the same legacy AEAD.
	salt, _ := base64.StdEncoding.DecodeString(meta[crypto.MetaKeySalt])
	iv, _ := base64.StdEncoding.DecodeString(meta[crypto.MetaIV])
	params, _ := crypto.ParseKDFParams(meta[crypto.MetaKDFParams])
	key, err := pbkdf2.Key(sha256.New, goldenPassword, salt, params.Iterations, 32)
	if err != nil {
		return nil, nil, err
	}
	defer zeroFixtureBytes(key)
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	full := cloneStringMap(meta)
	delete(full, "Content-Length")
	delete(full, "ETag")
	serialized, err := json.Marshal(full)
	if err != nil {
		return nil, nil, err
	}
	inner := make([]byte, 4+len(serialized)+len(plain))
	binary.BigEndian.PutUint32(inner[:4], uint32(len(serialized)))
	copy(inner[4:], serialized)
	copy(inner[4+len(serialized):], plain)
	ct = aead.Seal(nil, iv, inner, legacyGoldenAAD(crypto.AlgorithmAES256GCM, salt, iv, standard["Content-Type"], len(plain)))
	meta[crypto.MetaFallbackMode] = "true"
	delete(meta, crypto.MetaFallbackVersion)
	delete(meta, crypto.MetaObjectFormatVersion)
	meta["Content-Length"] = strconv.Itoa(len(ct))
	return ct, meta, nil
}

func makeLegacyChunkedFixture(plain []byte, standard map[string]string) ([]byte, map[string]string, error) {
	salt, baseIV := bytes.Repeat([]byte{0x19}, 32), bytes.Repeat([]byte{0x27}, 12)
	params := crypto.DefaultKDFParams(crypto.MinPBKDF2Iterations)
	key, err := pbkdf2.Key(sha256.New, goldenPassword, salt, params.Iterations, 32)
	if err != nil {
		return nil, nil, err
	}
	defer zeroFixtureBytes(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	const chunkSize = crypto.MinChunkSize
	var body bytes.Buffer
	var count uint64
	for start := 0; start < len(plain); start += chunkSize {
		end := min(start+chunkSize, len(plain))
		nonce, err := legacyChunkNonce(baseIV, count)
		if err != nil {
			return nil, nil, err
		}
		body.Write(aead.Seal(nil, nonce, plain[start:end], nil))
		count++
	}
	manifest, err := json.Marshal(map[string]any{"v": 1, "cs": chunkSize, "cc": count, "iv": base64.StdEncoding.EncodeToString(baseIV), "ivd": "hkdf-sha256"})
	if err != nil {
		return nil, nil, err
	}
	meta := map[string]string{
		crypto.MetaEncrypted: "true", crypto.MetaAlgorithm: crypto.AlgorithmAES256GCM,
		crypto.MetaKeySalt: base64.StdEncoding.EncodeToString(salt), crypto.MetaIV: base64.StdEncoding.EncodeToString(baseIV),
		crypto.MetaKDFParams: crypto.FormatKDFParams(params), crypto.MetaChunkedFormat: "true",
		crypto.MetaChunkSize: strconv.Itoa(chunkSize), crypto.MetaManifest: base64.StdEncoding.EncodeToString(manifest),
		crypto.MetaOriginalSize: strconv.Itoa(len(plain)), crypto.MetaOriginalETag: "legacy-chunk-etag",
		"Content-Length": strconv.Itoa(body.Len()), "ETag": "backend-cipher-etag", "x-amz-meta-user-a": "golden-user-value",
		crypto.MetaWrappedKeyCiphertext: "internal-must-not-leak",
	}
	for _, spec := range crypto.ProtectedStandardKeys() {
		meta[spec.Canonical] = standard[spec.Header]
	}
	return body.Bytes(), meta, nil
}

func legacyChunkNonce(base []byte, index uint64) ([]byte, error) {
	info := make([]byte, 12)
	copy(info, "chunk-iv")
	binary.BigEndian.PutUint32(info[8:], uint32(index))
	reader := hkdf.Expand(sha256.New, base, info)
	nonce := make([]byte, 12)
	_, err := io.ReadFull(reader, nonce)
	return nonce, err
}

func legacyGoldenAAD(algorithm string, salt, iv []byte, contentType string, size int) []byte {
	var out bytes.Buffer
	for _, item := range [][]byte{[]byte(algorithm), salt, iv, nil, []byte(contentType), []byte(strconv.Itoa(size))} {
		_ = binary.Write(&out, binary.BigEndian, uint32(len(item)))
		out.Write(item)
	}
	return out.Bytes()
}

func generateGoldenMPU(format string, f goldenBackendFixture, plain []byte, metadata map[string]string) (goldenBackendFixture, error) {
	ctx := context.Background()
	engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	if err != nil {
		return f, err
	}
	defer func() {
		if c, ok := engine.(io.Closer); ok {
			_ = c.Close()
		}
	}()
	km, err := crypto.NewInMemoryKeyManager(bytes.Repeat([]byte{0x55}, 32))
	if err != nil {
		return f, err
	}
	dek := bytes.Repeat([]byte{0x66}, 32)
	wrapped, err := km.WrapKey(ctx, dek, nil)
	if err != nil {
		return f, err
	}
	wrapped.CreatedAt = time.Time{}
	wrappedJSON, err := json.Marshal(wrapped)
	if err != nil {
		return f, err
	}
	uploadID := "golden-upload"
	uploadHash := crypto.UploadIDHash(uploadID)
	ivPrefix := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	bindingBytes := bytes.Repeat([]byte{0x77}, 16)
	var binding [16]byte
	copy(binding[:], bindingBytes)
	chunkSize := crypto.MinChunkSize
	var partReader io.Reader
	var encLen int64
	if format == "mpu-v2" {
		partReader, encLen, err = crypto.NewMPUPartEncryptReader(ctx, crypto.ObjectContext{Bucket: goldenBucket, Key: goldenObject}, binding, bytes.NewReader(plain), dek, uploadHash, ivPrefix, 1, chunkSize, int64(len(plain)), crypto.AlgorithmAES256GCM)
	} else {
		partReader, encLen, err = crypto.NewMPUPartEncryptReaderV1(ctx, crypto.ObjectContext{Bucket: goldenBucket, Key: goldenObject}, bytes.NewReader(plain), dek, uploadHash, ivPrefix, 1, chunkSize, int64(len(plain)), crypto.AlgorithmAES256GCM)
	}
	if err != nil {
		return f, err
	}
	body, err := io.ReadAll(partReader)
	if err != nil {
		return f, err
	}
	manifest := &crypto.MultipartManifest{Version: 1, Algorithm: crypto.AlgorithmAES256GCM, ChunkSize: chunkSize, IVPrefix: hex.EncodeToString(ivPrefix[:]), UploadIDHash: base64.URLEncoding.EncodeToString(uploadHash[:]), WrappedDEK: string(wrappedJSON), Parts: []crypto.MPUPartRecord{{PartNumber: 1, ETag: "part-etag", PlainLen: int64(len(plain)), EncLen: encLen, ChunkCount: 1}}, OriginalETag: "golden-mpu-etag", TotalPlainSize: int64(len(plain))}
	companionKey := goldenObject + crypto.MPUManifestSuffix
	var manifestBody []byte
	var manifestMeta map[string]string
	if format == "mpu-v2" {
		manifest.Version = 2
		manifest.ParentBucket, manifest.ParentKey = goldenBucket, goldenObject
		manifest.CompanionBucket, manifest.CompanionKey = goldenBucket, companionKey
		manifest.BindingID = base64.RawURLEncoding.EncodeToString(binding[:])
		manifestBody, manifestMeta, err = crypto.EncryptMPUManifest(ctx, engine, crypto.ObjectContext{Bucket: goldenBucket, Key: companionKey}, binding, mustMarshalManifest(manifest))
		if err != nil {
			return f, err
		}
		manifestMeta[crypto.MetaMPUManifestVersion] = "2"
		metadata[crypto.MetaMPUEncrypted] = "v2"
		metadata[crypto.MetaObjectBindingID] = manifest.BindingID
	} else {
		manifestBodyReader, encMeta, encErr := engine.Encrypt(ctx, crypto.ObjectContext{Bucket: goldenBucket, Key: companionKey}, bytes.NewReader(mustMarshalManifest(manifest)), map[string]string{"Content-Length": strconv.Itoa(len(mustMarshalManifest(manifest))), "ETag": "manifest-etag"})
		if encErr != nil {
			return f, encErr
		}
		manifestBody, err = io.ReadAll(manifestBodyReader)
		if err != nil {
			return f, err
		}
		manifestMeta = encMeta
		metadata[crypto.MetaMPUEncrypted] = "true"
	}
	metadata[crypto.MetaFallbackPointer] = companionKey
	metadata["Content-Length"] = strconv.Itoa(len(body))
	metadata["ETag"] = "backend-mpu-etag"
	metadata["x-amz-meta-user-a"] = "golden-user-value"
	metadata[crypto.MetaWrappedKeyCiphertext] = "internal-must-not-leak"
	f.Body = base64.StdEncoding.EncodeToString(body)
	f.Metadata = metadata
	f.ManifestBody = base64.StdEncoding.EncodeToString(manifestBody)
	f.ManifestMetadata = manifestMeta
	f.Headers = goldenExpectedHeaders("backend-mpu-etag", int64(len(plain)), goldenStandardHeaders)
	if format == "mpu-v1" {
		f.Headers["ETag"] = "backend-mpu-etag"
	}
	f.Ciphertext = f.Body
	return f, nil
}

func mustMarshalManifest(m *crypto.MultipartManifest) []byte { b, _ := m.Marshal(); return b }

func runAuthenticObjectFormatGolden(t *testing.T, fixture goldenBackendFixture) error {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(fixture.Body)
	if err != nil {
		return fmt.Errorf("decode body: %w", err)
	}
	if fixture.TamperFirstChunk {
		if len(body) == 0 {
			return fmt.Errorf("cannot tamper empty object body")
		}
		body[len(body)-1] ^= 0x80
	}
	wantBody, err := base64.StdEncoding.DecodeString(fixture.ExpectedBody)
	if err != nil {
		return fmt.Errorf("decode expected plaintext: %w", err)
	}
	client := newMockS3Client()
	client.objects[goldenBucket+"/"+goldenObject] = body
	client.metadata[goldenBucket+"/"+goldenObject] = cloneStringMap(fixture.Metadata)
	if fixture.ManifestBody != "" {
		manifestBody, decodeErr := base64.StdEncoding.DecodeString(fixture.ManifestBody)
		if decodeErr != nil {
			return fmt.Errorf("decode manifest body: %w", decodeErr)
		}
		manifestKey := goldenObject + crypto.MPUManifestSuffix
		client.objects[goldenBucket+"/"+manifestKey] = manifestBody
		client.metadata[goldenBucket+"/"+manifestKey] = cloneStringMap(fixture.ManifestMetadata)
	}
	var opts []crypto.Option
	if fixture.Format == "chunked-v2" || fixture.Format == "chunked-v1" || fixture.Format == "metadata-blob-chunked" || fixture.Format == "fallback-v2" {
		opts = append(opts, crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize))
	}
	if fixture.MetadataKey {
		opts = append(opts, crypto.WithMetadataKey(bytes.Repeat([]byte{0x42}, 32)))
	}
	if fixture.Profile != "" {
		opts = append(opts, crypto.WithProvider(fixture.Profile))
	}
	if fixture.Format == "fallback-v1" {
		opts = append(opts, crypto.WithAllowUnmarkedNoAADFallback(true))
	}
	engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), append(opts, crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))...)
	if err != nil {
		return err
	}
	defer func() {
		if closer, ok := engine.(io.Closer); ok {
			_ = closer.Close()
		}
	}()
	var km crypto.KeyManager
	if strings.HasPrefix(fixture.Format, "mpu-") {
		km, err = crypto.NewInMemoryKeyManager(bytes.Repeat([]byte{0x55}, 32))
		if err != nil {
			return err
		}
	}
	h := NewHandlerWithFeatures(client, engine, logrus.New(), getTestMetrics(), km, nil, nil, &config.Config{}, nil)
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	for _, tc := range []struct {
		method, rangeHeader string
		status              int
		start, end          int
	}{
		{http.MethodHead, "", http.StatusOK, 0, 0},
		{http.MethodGet, "", http.StatusOK, 0, len(wantBody)},
		{http.MethodGet, "bytes=1-8", http.StatusPartialContent, 1, 9},
	} {
		requestURL := "/" + goldenBucket + "/" + goldenObject + "?versionId=golden-version"
		if tc.method == http.MethodGet {
			requestURL += "&response-content-type=application%2Fx-override&response-cache-control=private%2C%20max-age%3D99"
		}
		req := httptest.NewRequest(tc.method, requestURL, nil)
		if tc.rangeHeader != "" {
			req.Header.Set("Range", tc.rangeHeader)
		}
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		if fixture.TamperFirstChunk {
			if tc.method != http.MethodGet || tc.rangeHeader != "" {
				continue
			}
			if resp.Code < http.StatusInternalServerError || resp.Code > 599 {
				return fmt.Errorf("tampered first chunk returned status %d, want 5xx", resp.Code)
			}
			continue
		}
		responseHeaders := resp.Result().Header
		if got := responseHeaders.Get("x-amz-version-id"); got != "golden-version" {
			return fmt.Errorf("%s %q version ID=%q want golden-version", tc.method, tc.rangeHeader, got)
		}
		client.locksMu.Lock()
		var primaryHeadCalls, primaryGetCalls int
		for _, got := range client.headVersionHistory {
			if got.key != goldenBucket+"/"+goldenObject {
				continue
			}
			primaryHeadCalls++
			if got.versionID == nil || *got.versionID != "golden-version" {
				client.locksMu.Unlock()
				return fmt.Errorf("%s %q HEAD backend version ID=%v want golden-version", tc.method, tc.rangeHeader, got.versionID)
			}
		}
		for _, got := range client.getVersionHistory {
			if got.key != goldenBucket+"/"+goldenObject {
				continue
			}
			primaryGetCalls++
			if got.versionID == nil || *got.versionID != "golden-version" {
				client.locksMu.Unlock()
				return fmt.Errorf("%s %q GET backend version ID=%v want golden-version", tc.method, tc.rangeHeader, got.versionID)
			}
		}
		if primaryHeadCalls == 0 || (tc.method == http.MethodGet && primaryGetCalls == 0) {
			client.locksMu.Unlock()
			return fmt.Errorf("%s %q did not make expected versioned backend calls (HEAD=%d GET=%d)", tc.method, tc.rangeHeader, primaryHeadCalls, primaryGetCalls)
		}
		client.locksMu.Unlock()
		if resp.Code != tc.status {
			return fmt.Errorf("%s %q status=%d body=%s; want %d", tc.method, tc.rangeHeader, resp.Code, resp.Body.String(), tc.status)
		}
		if tc.method == http.MethodHead {
			if resp.Body.Len() != 0 {
				return fmt.Errorf("HEAD body length=%d", resp.Body.Len())
			}
		} else {
			want := wantBody[tc.start:tc.end]
			if !bytes.Equal(resp.Body.Bytes(), want) {
				return fmt.Errorf("%s %q body=%q want %q", tc.method, tc.rangeHeader, resp.Body.Bytes(), want)
			}
		}
		wantLen := len(wantBody)
		if tc.rangeHeader != "" {
			wantLen = tc.end - tc.start
		}
		if responseHeaders.Get("Content-Length") != strconv.Itoa(wantLen) {
			got := responseHeaders.Get("Content-Length")
			return fmt.Errorf("%s %q Content-Length=%q want %d", tc.method, tc.rangeHeader, got, wantLen)
		}
		if tc.method != http.MethodHead && resp.Body.Len() != wantLen {
			return fmt.Errorf("%s %q plaintext body length=%d want %d", tc.method, tc.rangeHeader, resp.Body.Len(), wantLen)
		}
		if tc.rangeHeader != "" {
			wantRange := fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end-1, len(wantBody))
			if got := responseHeaders.Get("Content-Range"); got != wantRange {
				return fmt.Errorf("Content-Range=%q want %q", got, wantRange)
			}
		} else if got := responseHeaders.Get("Content-Range"); got != "" {
			return fmt.Errorf("unexpected Content-Range %q", got)
		}
		for key, want := range fixture.Headers {
			if key == "Content-Length" || key == "Content-Range" {
				continue
			}
			if tc.method == http.MethodGet {
				switch key {
				case "Content-Type":
					want = "application/x-override"
				case "Cache-Control":
					want = "private, max-age=99"
				}
			}
			if got := responseHeaders.Get(key); got != want {
				return fmt.Errorf("%s %q header %s=%q want %q", tc.method, tc.rangeHeader, key, got, want)
			}
		}
		if got := responseHeaders.Get("x-amz-meta-user-a"); got != "golden-user-value" {
			return fmt.Errorf("user metadata=%q", got)
		}
		for key := range responseHeaders {
			if crypto.IsGatewayReservedKey(key) {
				return fmt.Errorf("reserved metadata leaked in %s: %s", tc.method, key)
			}
		}
	}
	return nil
}

func goldenExpectedHeaders(etag string, size int64, standard map[string]string) map[string]string {
	out := cloneStringMap(standard)
	out["ETag"], out["Content-Length"], out["Accept-Ranges"] = etag, strconv.FormatInt(size, 10), "bytes"
	return out
}

func backendObjectHeaders(standard map[string]string, body []byte, etag string) map[string]string {
	out := cloneStringMap(standard)
	out["Content-Length"], out["ETag"] = strconv.Itoa(len(body)), etag
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func sortedJSONMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out[key] = in[key]
	}
	return out
}

func mergeMaps(a, b map[string]string) map[string]string {
	out := cloneStringMap(a)
	for key, value := range b {
		out[key] = value
	}
	return out
}

func mustDecodeBase64(value string) []byte { b, _ := base64.StdEncoding.DecodeString(value); return b }
func zeroFixtureBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
