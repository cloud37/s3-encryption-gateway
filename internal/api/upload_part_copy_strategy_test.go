package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type strategyClient struct {
	*mockS3Client
	uploadErr error
	uploads   int
	data      []byte
}

type strategyErrorReader struct{}

func (strategyErrorReader) Read([]byte) (int, error) { return 0, errors.New("reader failure") }
func (strategyErrorReader) Close() error             { return nil }

type strategyReadErrorClient struct{ *mockS3Client }

func (c *strategyReadErrorClient) GetObject(context.Context, string, string, *string, *string) (io.ReadCloser, map[string]string, error) {
	return strategyErrorReader{}, map[string]string{}, nil
}

type strategyClaimStore struct {
	mpu.ClaimStateStore
	getErr     error
	reserveErr error
	commitErr  error
	state      *mpu.UploadState
	releases   int
}

func (s *strategyClaimStore) Get(ctx context.Context, id string) (*mpu.UploadState, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	if s.state != nil {
		return s.state, nil
	}
	return s.ClaimStateStore.Get(ctx, id)
}

func (s *strategyClaimStore) ReservePart(context.Context, string, mpu.PartClaim) (mpu.Reservation, error) {
	if s.reserveErr != nil {
		return mpu.Reservation{}, s.reserveErr
	}
	return mpu.Reservation{}, nil
}

func (s *strategyClaimStore) CommitPart(context.Context, string, mpu.PartClaim) error {
	return s.commitErr
}

func (s *strategyClaimStore) ReleasePart(ctx context.Context, id string, pn int32, token string) error {
	s.releases++
	return s.ClaimStateStore.ReleasePart(ctx, id, pn, token)
}

func (c *strategyClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, r io.Reader, n *int64) (string, error) {
	c.uploads++
	if c.uploadErr != nil {
		return "", c.uploadErr
	}
	c.data, _ = io.ReadAll(r)
	return "etag-strategy", nil
}

func (c *strategyClient) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	if err := c.errors[bucket+"/"+key+"/get"]; err != nil {
		return nil, nil, err
	}
	return c.mockS3Client.GetObject(ctx, bucket, key, versionID, rangeHeader)
}

func (c *strategyClient) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	if err := c.errors[bucket+"/"+key+"/head"]; err != nil {
		return nil, err
	}
	return c.mockS3Client.HeadObject(ctx, bucket, key, versionID)
}

func strategyHandler(client s3.Client, engine crypto.EncryptionEngine) *Handler {
	return &Handler{encryptionEngine: engine, logger: logrus.New(), metrics: getTestMetrics()}
}

type strategyRangeEngine struct{ mockEngine }

func (e *strategyRangeEngine) DecryptRange(_ context.Context, r io.Reader, _ map[string]string, start, end int64) (io.Reader, map[string]string, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	if start < 0 || end >= int64(len(b)) {
		end = int64(len(b)) - 1
	}
	return bytes.NewReader(b[start : end+1]), nil, nil
}

type strategySourceEngine struct {
	crypto.EncryptionEngine
	plain []byte
}

func (e *strategySourceEngine) DecryptRange(context.Context, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error) {
	return bytes.NewReader(e.plain), nil, nil
}

func (e *strategySourceEngine) Decrypt(context.Context, io.Reader, map[string]string) (io.Reader, map[string]string, error) {
	return bytes.NewReader(e.plain), nil, nil
}

func TestSEC37_Copy_Strategy_ChunkedDirect(t *testing.T) {
	plain := []byte("0123456789")
	for _, tc := range []struct {
		name string
		r    *s3.CopyPartRange
		info crypto.ChunkedObjectInfo
		size string
		want []byte
		err  error
	}{
		{"range", &s3.CopyPartRange{First: 2, Last: 5}, crypto.ChunkedObjectInfo{}, "10", plain[2:6], nil},
		{"full", nil, crypto.ChunkedObjectInfo{}, "10", plain, nil},
		{"authenticated", nil, crypto.ChunkedObjectInfo{Authenticated: true, PlaintextSize: 4}, "10", plain[:4], nil},
		{"clamp", &s3.CopyPartRange{First: 7, Last: 99}, crypto.ChunkedObjectInfo{}, "10", plain[7:], nil},
		{"416", &s3.CopyPartRange{First: 10, Last: 11}, crypto.ChunkedObjectInfo{}, "10", nil, errRangeNotSatisfiable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newMockS3Client()
			base.objects["src/key"] = plain
			base.metadata["src/key"] = map[string]string{crypto.MetaOriginalSize: tc.size}
			client := &strategyClient{mockS3Client: base}
			got, n, err := strategyHandler(client, &strategyRangeEngine{}).uploadPartCopyChunked(context.Background(), client, "dst", "key", "u", 1, "src", "key", nil, tc.r, 100, tc.info)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, int64(len(tc.want)), n)
			require.Equal(t, tc.want, client.data)
			require.Equal(t, "etag-strategy", got.ETag)
		})
	}
}

func TestSEC37_Copy_Strategy_ChunkedDirectErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(*mockS3Client)
		engine crypto.EncryptionEngine
		want   string
	}{
		{"head", func(c *mockS3Client) { c.errors["src/key/head"] = errors.New("head") }, &mockEngine{}, "head"},
		{"get", func(c *mockS3Client) { c.errors["src/key/get"] = errors.New("get") }, &mockEngine{}, "get"},
		{"decrypt", nil, &strategyDecryptError{err: errors.New("decrypt")}, "decrypt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newMockS3Client()
			c.objects["src/key"] = []byte("data")
			c.metadata["src/key"] = map[string]string{crypto.MetaOriginalSize: "4"}
			if tc.setup != nil {
				tc.setup(c)
			}
			_, _, err := strategyHandler(c, tc.engine).uploadPartCopyChunked(context.Background(), c, "d", "k", "u", 1, "src", "key", nil, nil, 100, crypto.ChunkedObjectInfo{})
			require.ErrorContains(t, err, tc.want)
		})
	}
	c := newMockS3Client()
	c.metadata["src/key"] = map[string]string{}
	c.objects["src/key"] = []byte("data")
	_, _, err := strategyHandler(c, &mockEngine{}).uploadPartCopyChunked(context.Background(), c, "d", "k", "u", 1, "src", "key", nil, nil, 100, crypto.ChunkedObjectInfo{})
	require.ErrorContains(t, err, "cannot determine plaintext size")
	client := &strategyClient{mockS3Client: c, uploadErr: errors.New("upload")}
	c.metadata["src/key"][crypto.MetaOriginalSize] = "4"
	_, _, err = strategyHandler(client, &mockEngine{}).uploadPartCopyChunked(context.Background(), client, "d", "k", "u", 1, "src", "key", nil, nil, 100, crypto.ChunkedObjectInfo{})
	require.ErrorContains(t, err, "upload")
}

type strategyDecryptError struct{ err error }

func (e *strategyDecryptError) Encrypt(context.Context, io.Reader, map[string]string) (io.Reader, map[string]string, error) {
	return nil, nil, nil
}
func (e *strategyDecryptError) Decrypt(context.Context, io.Reader, map[string]string) (io.Reader, map[string]string, error) {
	return nil, nil, e.err
}
func (e *strategyDecryptError) DecryptRange(context.Context, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error) {
	return nil, nil, e.err
}
func (e *strategyDecryptError) AuthenticateChunkedTrailer(context.Context, io.Reader, map[string]string, int64) (crypto.ChunkedObjectInfo, error) {
	return crypto.ChunkedObjectInfo{}, nil
}
func (e *strategyDecryptError) IsEncrypted(map[string]string) bool { return true }
func (e *strategyDecryptError) PreferredAlgorithm() string         { return crypto.AlgorithmAES256GCM }
func (e *strategyDecryptError) Close() error                       { return nil }

func TestSEC37_Copy_Strategy_ReencryptMPU_Plaintext(t *testing.T) {
	h, client, uploadID := setupStrategyMPU(t)
	client.objects["src/key"] = []byte("plain")
	client.metadata["src/key"] = map[string]string{}
	result, n, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dst-bucket", "d", uploadID, 1, "src", "key", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 100, 100)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Positive(t, n)
	result, n, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "dst-bucket", "d", uploadID, 2, "src", "key", nil, &s3.CopyPartRange{First: 1, Last: 99}, &CopySourceMetadata{Class: SourceClassPlaintext}, 100, 100)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, int64(4), n)
}

func setupStrategyMPU(t *testing.T) (*Handler, *mpuMockS3Client, string) {
	t.Helper()
	h, client, _ := newMPUTestHandler(t, "dst-bucket")
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/dst-bucket/d?uploads=", nil))
	require.Equal(t, 200, w.Code, w.Body.String())
	return h, client, extractUploadID(t, w.Body.String())
}

type countingMPUClient struct {
	*mpuMockS3Client
	uploads   int
	uploadErr error
}

func (c *countingMPUClient) UploadPart(ctx context.Context, bucket, key, uploadID string, partNumber int32, r io.Reader, n *int64) (string, error) {
	c.uploads++
	if c.uploadErr != nil {
		return "", c.uploadErr
	}
	return c.mpuMockS3Client.UploadPart(ctx, bucket, key, uploadID, partNumber, r, n)
}

func setupStrategySource(t *testing.T, client *mpuMockS3Client) (string, string, crypto.EncryptionEngine) {
	t.Helper()
	engine, err := crypto.NewEngineWithChunking([]byte(mpuTestPassword), "", nil, true, crypto.MinChunkSize)
	require.NoError(t, err)
	tmp := newMockS3Client()
	putSEC37Object(t, tmp, engine, "chunked", []byte("chunked strategy source"))
	client.objects["src/chunked"] = tmp.objects["test-bucket/chunked"]
	client.metadata["src/chunked"] = tmp.metadata["test-bucket/chunked"]
	legacy, err := crypto.NewEngine([]byte(mpuTestPassword))
	require.NoError(t, err)
	legacyReader, legacyMetadata, err := legacy.Encrypt(context.Background(), bytes.NewReader([]byte("legacy strategy source")), nil)
	require.NoError(t, err)
	legacyCiphertext, err := io.ReadAll(legacyReader)
	require.NoError(t, err)
	client.objects["src/legacy"] = legacyCiphertext
	client.metadata["src/legacy"] = legacyMetadata
	return "chunked", "legacy", engine
}

func TestSEC37_Copy_Strategy_ReencryptMPU_ChunkedAndLegacy(t *testing.T) {
	h, client, uploadID := setupStrategyMPU(t)
	chunkedKey, legacyKey, sourceEngine := setupStrategySource(t, client)
	h.encryptionEngine = &strategySourceEngine{EncryptionEngine: sourceEngine, plain: []byte("chunked strategy source")}
	chunked := &CopySourceMetadata{Class: SourceClassChunked, IsChunked: true, IsEncrypted: true, Size: 23, ChunkedInfo: crypto.ChunkedObjectInfo{Authenticated: true, PlaintextSize: 23}}
	legacy := &CopySourceMetadata{Class: SourceClassLegacy, IsEncrypted: true, Size: 23}

	result, n, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 1, "src", chunkedKey, nil, nil, chunked, 1024, 1024)
	require.NoError(t, err)
	require.NotEmpty(t, result.ETag)
	require.Positive(t, n)
	result, n, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 2, "src", chunkedKey, nil, &s3.CopyPartRange{First: 0, Last: 999}, chunked, 1024, 1024)
	require.NoError(t, err)
	require.NotEmpty(t, result.ETag)
	require.Positive(t, n)
	result, n, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 3, "src", legacyKey, nil, nil, legacy, 1024, 1024)
	require.NoError(t, err)
	require.NotEmpty(t, result.ETag)
	require.Positive(t, n)
	result, n, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 4, "src", legacyKey, nil, &s3.CopyPartRange{First: 2, Last: 999}, legacy, 1024, 1024)
	require.NoError(t, err)
	require.NotEmpty(t, result.ETag)
	require.Positive(t, n)
}

func TestSEC37_Copy_Strategy_ReencryptMPU_ClaimBranches(t *testing.T) {
	h, base, uploadID := setupStrategyMPU(t)
	_, _, sourceEngine := setupStrategySource(t, base)
	h.encryptionEngine = &strategySourceEngine{EncryptionEngine: sourceEngine, plain: []byte("plain source")}
	client := &countingMPUClient{mpuMockS3Client: base}
	source := &CopySourceMetadata{Class: SourceClassPlaintext}
	base.objects["src/plain"] = []byte("claim source")
	base.metadata["src/plain"] = map[string]string{}

	client.uploadErr = errors.New("upload failure")
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 5, "src", "plain", nil, nil, source, 1024, 1024)
	require.ErrorContains(t, err, "upload re-encrypted part")
	state, stateErr := h.mpuStateStore.Get(context.Background(), uploadID)
	require.NoError(t, stateErr)
	var reservedPart *mpu.PartRecord
	for _, part := range state.Parts {
		if part.PartNumber == 5 {
			reservedPart = &part
		}
	}
	require.NotNil(t, reservedPart, "uncertain backend outcome must retain reservation")

	client.uploadErr = nil
	result, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 6, "src", "plain", nil, nil, source, 1024, 1024)
	require.NoError(t, err)
	calls := client.uploads
	result2, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 6, "src", "plain", nil, nil, source, 1024, 1024)
	require.NoError(t, err)
	require.Equal(t, result.ETag, result2.ETag)
	require.Equal(t, calls, client.uploads)
}

func TestSEC38_Copy_ReleasesReservationBeforeUploadOnEncryptionFailure(t *testing.T) {
	h, client, uploadID := setupStrategyMPU(t)
	client.objects["src/plain"] = []byte("claim source")
	client.metadata["src/plain"] = map[string]string{}
	store := &strategyClaimStore{ClaimStateStore: h.mpuStateStore}
	h.mpuStateStore = store
	h.destinationEncryptionReader = func(io.Reader, int64) (io.Reader, int64, error) {
		return nil, 0, errors.New("encrypt construction failed")
	}
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 9, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.ErrorContains(t, err, "re-encrypt")
	require.Equal(t, 1, store.releases)
	require.Len(t, client.parts, 0)
	h.destinationEncryptionReader = nil
	_, _, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 9, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.NoError(t, err)
}

func TestSEC38_Copy_ReleasesReservationOnEncryptedReadFailure(t *testing.T) {
	h, client, uploadID := setupStrategyMPU(t)
	client.objects["src/plain"] = []byte("claim source")
	client.metadata["src/plain"] = map[string]string{}
	store := &strategyClaimStore{ClaimStateStore: h.mpuStateStore}
	h.mpuStateStore = store
	h.destinationEncryptionReader = func(io.Reader, int64) (io.Reader, int64, error) {
		return strategyErrorReader{}, 42, nil
	}
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 10, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.ErrorContains(t, err, "read re-encrypted part")
	require.Equal(t, 1, store.releases)
	require.Len(t, client.parts, 0)
	h.destinationEncryptionReader = nil
	_, _, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 10, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.NoError(t, err)
}

func TestSEC37_Copy_Strategy_ReencryptMPU_LegacyStateBranches(t *testing.T) {
	h, client, uploadID := setupStrategyMPU(t)
	client.objects["src/plain"] = []byte("legacy state source")
	client.metadata["src/plain"] = map[string]string{}
	realStore := h.mpuStateStore
	legacyStore := &failOnCommitStateStore{StateStore: realStore, commitErr: errors.New("commit failed")}
	h.mpuStateStore = legacyStore
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 7, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.ErrorIs(t, err, errMPUStateUnavailable)

	h.mpuStateStore = &countingCommitStateStore{StateStore: realStore}
	result, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 8, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestUploadPartCopy_EncryptedMPU_IdenticalRetry(t *testing.T) {
	h, base, uploadID := setupStrategyMPU(t)
	base.objects["src/plain"], base.metadata["src/plain"] = []byte("same source"), map[string]string{}
	client := &countingMPUClient{mpuMockS3Client: base}
	first, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.NoError(t, err)
	calls := client.uploads
	second, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.NoError(t, err)
	require.Equal(t, first.ETag, second.ETag)
	require.Equal(t, calls, client.uploads)
}

func TestUploadPartCopy_EncryptedMPU_ChangedSourceRejected(t *testing.T) {
	h, base, uploadID := setupStrategyMPU(t)
	base.objects["src/plain"], base.metadata["src/plain"] = []byte("first source"), map[string]string{}
	client := &countingMPUClient{mpuMockS3Client: base}
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.NoError(t, err)
	calls := client.uploads
	base.objects["src/plain"] = []byte("changed source")
	_, _, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.ErrorIs(t, err, mpu.ErrPartContentMismatch)
	require.Equal(t, calls, client.uploads)
}

func TestUploadPartCopy_EncryptedMPU_ConcurrentReservation(t *testing.T) {
	h, base, uploadID := setupStrategyMPU(t)
	base.objects["src/plain"], base.metadata["src/plain"] = []byte("source"), map[string]string{}
	client := &countingMPUClient{mpuMockS3Client: base}
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
			errs <- err
		}()
	}
	var success int
	for i := 0; i < 2; i++ {
		if err := <-errs; err == nil {
			success++
		}
	}
	require.Equal(t, 1, success)
}

func TestUploadPartCopy_EncryptedMPU_LegacyStateRejected(t *testing.T) {
	h, base, uploadID := setupStrategyMPU(t)
	base.objects["src/plain"], base.metadata["src/plain"] = []byte("source"), map[string]string{}
	legacy := &failOnCommitStateStore{StateStore: h.mpuStateStore, commitErr: errors.New("legacy state")}
	h.mpuStateStore = legacy
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), base, "dest-bucket", "dest", uploadID, 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 1024, 1024)
	require.ErrorIs(t, err, errMPUStateUnavailable)
}

func TestUploadPartCopy_EncryptedMPU_DestinationUploadFailureReleases(t *testing.T) {
	h, base, uploadID := setupStrategyMPU(t)
	base.objects["src/plain"], base.metadata["src/plain"] = []byte("source"), map[string]string{}
	client := &countingMPUClient{mpuMockS3Client: base, uploadErr: errors.New("destination unavailable")}
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 100, 100)
	require.Error(t, err)
	state, getErr := h.mpuStateStore.Get(context.Background(), uploadID)
	require.NoError(t, getErr)
	var reserved *mpu.PartRecord
	for _, p := range state.Parts {
		if p.PartNumber == 1 {
			reserved = &p
		}
	}
	require.NotNil(t, reserved, "uncertain backend outcome must retain reservation")
}

func TestSEC37_Copy_Strategy_ReencryptMPU_Bounds(t *testing.T) {
	base := newMockS3Client()
	base.objects["src/plain"] = []byte("too large")
	base.metadata["src/plain"] = map[string]string{}
	client := &strategyClient{mockS3Client: base}
	h := strategyHandler(client, &mockEngine{})
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "d", "k", "u", 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 4, 100)
	require.ErrorIs(t, err, errLegacySourceTooLarge)

	base.objects["src/chunked"] = []byte("ciphertext")
	base.metadata["src/chunked"] = map[string]string{crypto.MetaOriginalSize: "9"}
	oversized := &oversizedDecryptEngine{EncryptionEngine: &mockEngine{}, returnBytes: 5}
	h.encryptionEngine = oversized
	_, _, err = h.uploadPartCopyReencryptMPU(context.Background(), client, "d", "k", "u", 1, "src", "chunked", nil, nil, &CopySourceMetadata{Class: SourceClassChunked, IsChunked: true, ChunkedInfo: crypto.ChunkedObjectInfo{Authenticated: true, PlaintextSize: 9}}, 100, 4)
	require.ErrorContains(t, err, "exceeds maximum copy-part size")
}

func TestSEC37_Copy_Strategy_ReencryptMPU_EncryptError(t *testing.T) {
	h, client, uploadID := setupStrategyMPU(t)
	client.objects["src/plain"] = []byte("source")
	client.metadata["src/plain"] = map[string]string{}
	h.mpuStateStore = &failOnGetStateStore{StateStore: h.mpuStateStore, getErr: errors.New("state unavailable")}
	_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dst-bucket", "dest", uploadID, 1, "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 100, 100)
	require.ErrorContains(t, err, "re-encrypt")
}

func TestSEC37_Copy_Strategy_ReencryptMPU_SourceErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		class  SourceClass
		setup  func(*mockS3Client)
		engine crypto.EncryptionEngine
		want   string
	}{
		{"plaintext get", SourceClassPlaintext, func(c *mockS3Client) { c.errors["src/key/get"] = errors.New("get plaintext") }, &mockEngine{}, "get plaintext source"},
		{"chunked head", SourceClassChunked, func(c *mockS3Client) { c.errors["src/key/head"] = errors.New("head chunked") }, &mockEngine{}, "head chunked"},
		{"chunked get", SourceClassChunked, func(c *mockS3Client) { c.errors["src/key/get"] = errors.New("get chunked") }, &mockEngine{}, "get chunked source"},
		{"chunked decrypt", SourceClassChunked, nil, &strategyDecryptError{err: errors.New("decrypt chunked")}, "decrypt chunked source"},
		{"legacy get", SourceClassLegacy, func(c *mockS3Client) { c.errors["src/key/get"] = errors.New("get legacy") }, &mockEngine{}, "get legacy"},
		{"legacy decrypt", SourceClassLegacy, nil, &strategyDecryptError{err: errors.New("decrypt legacy")}, "decrypt legacy source"},
		{"mpu manifest", SourceClassMPUEncrypted, nil, &mockEngine{}, "read mpu source range"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newMockS3Client()
			client.objects["src/key"] = []byte("source")
			client.metadata["src/key"] = map[string]string{crypto.MetaOriginalSize: "6"}
			if tc.setup != nil {
				tc.setup(client)
			}
			_, _, err := strategyHandler(client, tc.engine).uploadPartCopyReencryptMPU(context.Background(), client, "d", "k", "u", 1, "src", "key", nil, nil, &CopySourceMetadata{Class: tc.class, IsChunked: tc.class == SourceClassChunked}, 100, 100)
			require.ErrorContains(t, err, tc.want)
		})
	}
	client := &strategyReadErrorClient{mockS3Client: newMockS3Client()}
	_, _, err := strategyHandler(client, &mockEngine{}).uploadPartCopyReencryptMPU(context.Background(), client, "d", "k", "u", 1, "src", "key", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 100, 100)
	require.ErrorContains(t, err, "read plaintext source")

	client2 := newMockS3Client()
	client2.objects["src/key"] = []byte("source")
	client2.metadata["src/key"] = map[string]string{}
	h := strategyHandler(client2, &mockEngine{})
	_, _, err = h.uploadPartCopyReencryptMPU(context.Background(), client2, "d", "k", "u", 1, "src", "key", nil, nil, &CopySourceMetadata{Class: SourceClassChunked, IsChunked: true}, 100, 100)
	require.ErrorContains(t, err, "cannot determine plaintext size")
}

func TestSEC37_Copy_Strategy_ReencryptMPU_ClaimErrors(t *testing.T) {
	h, client, uploadID := setupStrategyMPU(t)
	client.objects["src/plain"] = []byte("claim source")
	client.metadata["src/plain"] = map[string]string{}
	realStore := h.mpuStateStore
	for _, tc := range []struct {
		name  string
		store *strategyClaimStore
		want  string
	}{
		{"get", &strategyClaimStore{ClaimStateStore: realStore, getErr: errors.New("claim get")}, "get destination state"},
		{"unwrap", &strategyClaimStore{ClaimStateStore: realStore, state: &mpu.UploadState{WrappedDEK: "bad"}}, "unwrap destination DEK"},
		{"reserve", &strategyClaimStore{ClaimStateStore: realStore, reserveErr: errors.New("reserve")}, "reserve"},
		{"commit", &strategyClaimStore{ClaimStateStore: realStore, commitErr: errors.New("commit")}, "mpu state store unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h.mpuStateStore = tc.store
			_, _, err := h.uploadPartCopyReencryptMPU(context.Background(), client, "dest-bucket", "dest", uploadID, int32(20+len(tc.name)), "src", "plain", nil, nil, &CopySourceMetadata{Class: SourceClassPlaintext}, 100, 100)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

type countingCommitStateStore struct {
	mpu.StateStore
	commits int
}

func (s *countingCommitStateStore) CommitPart(ctx context.Context, id string, part mpu.PartClaim) error {
	s.commits++
	return s.StateStore.CommitPart(ctx, id, part)
}
