package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

// objectReadPlan combines backend-read decisions with the projected successful
// response. Classification, size/range selection, and integrity preflight are
// completed before it is handed to serveObjectBody.
type objectReadPlan struct {
	Bucket                           string
	Key                              string
	Status                           int
	ResponseStatus                   int
	ResponseRange                    *byteRange
	Headers                          http.Header
	Body                             io.Reader
	Class                            crypto.ObjectClass
	Size                             plaintextSize
	BackendRange                     *string
	RangeStart, RangeEnd, RangeTotal int64
	View                             *objectView
	Source                           objectResponseSource
	MPUManifest                      *loadedMPUManifest
	MPURange                         *crypto.MPURangeResult
	MPURangeError                    error
	MPUDecrypt                       func(crypto.ObjectContext, []byte, []byte, [32]byte, [12]byte, int32, int, int32) ([]byte, error)
	PreflightBody                    bool
	PreflightLimit                   int64
	Started                          time.Time
	ResponseStarted                  bool
	OperationStarted                 time.Time
	SkipRequestMetric                bool
	Mode                             objectReadMode
	RangeHeader                      *string
	DecryptSuccess                   *objectDecryptSuccess
	CacheEligible                    bool
}

type objectReadMode uint8

const (
	objectReadFull objectReadMode = iota
	objectReadMPUFull
	objectReadPassthroughRange
	objectReadBufferedRange
	objectReadOptimizedRange
	objectReadMPURange
)

type objectDecryptSuccess struct {
	Algorithm     string
	KeyVersion    int
	Duration      time.Duration
	PlainSize     int64
	AuditMetadata map[string]interface{}
	RotatedFrom   int
	RotatedTo     int
}

// planObjectRead is the owner of object classification, plaintext-size and
// range decisions. It also performs the format-specific preflight through the
// shared size resolver before allowing the caller to issue a successful GET.
func (h *Handler) planObjectRead(ctx context.Context, client s3.Client, bucket, key string, versionID *string, rawMetadata map[string]string, rangeHeader *string) (objectReadPlan, error) {
	if bucket == "" || key == "" {
		return objectReadPlan{}, fmt.Errorf("object read plan requires bucket and key")
	}
	plan := objectReadPlan{Bucket: bucket, Key: key, RangeTotal: -1, ResponseStatus: http.StatusOK}
	view, err := h.loadObjectView(bucket, key, versionID, rawMetadata)
	if err != nil {
		return objectReadPlan{}, err
	}
	plan.Class = view.Class
	plan.View = view
	plan.Source = objectResponseSource{Class: view.Class, Meta: view.Expanded, BackendETag: view.Expanded["ETag"]}
	plan.RangeHeader = rangeHeader
	plan.PreflightBody = rangeHeader == nil && view.Class.Encrypted
	if view.Class.Format == crypto.FormatMPUV1 || view.Class.Format == crypto.FormatMPUV2 {
		if rangeHeader == nil {
			plan.Mode = objectReadMPUFull
			headMetadata, headErr := client.HeadObject(ctx, bucket, key, versionID)
			if headErr != nil {
				return objectReadPlan{}, headErr
			}
			headView, viewErr := h.loadObjectView(bucket, key, versionID, headMetadata)
			if viewErr != nil {
				return objectReadPlan{}, viewErr
			}
			if headView.Class.Format != view.Class.Format || (rawMetadata["ETag"] != "" && headMetadata["ETag"] != "" && rawMetadata["ETag"] != headMetadata["ETag"]) {
				return objectReadPlan{}, fmt.Errorf("MPU HEAD metadata does not match object metadata")
			}
			plan.Source = objectResponseSource{Class: headView.Class, Meta: headView.Expanded, BackendETag: headMetadata["ETag"]}
			view = headView
			plan.View, plan.Class = view, view.Class
		}
		loaded, loadErr := h.loadMPUManifest(ctx, client, bucket, key, view.Class)
		if loadErr != nil {
			return objectReadPlan{}, loadErr
		}
		plan.MPUManifest = loaded
		plan.Size = plaintextSize{Size: loaded.Manifest.TotalPlainSize, Exact: true, Source: "mpu-manifest"}
		plan.Source.PlainSize = plan.Size.Size
		if rangeHeader != nil {
			plan.Mode = objectReadMPURange
			plan.MPUDecrypt = mpuChunkDecryptor(loaded)
			plan.Source.Decrypted = crypto.PlaintextMetadataView(view.Expanded, -1, "")
			start, end, rangeErr := parseObjectRange(*rangeHeader, loaded.Manifest.TotalPlainSize)
			if rangeErr != nil {
				plan.MPURangeError = rangeErr
				plan.ResponseStatus = http.StatusRequestedRangeNotSatisfiable
				plan.Status = http.StatusRequestedRangeNotSatisfiable
			} else {
				plan.RangeStart, plan.RangeEnd, plan.RangeTotal = start, end, loaded.Manifest.TotalPlainSize
				plan.ResponseStatus = http.StatusPartialContent
				plan.ResponseRange = &byteRange{Start: start, End: end}
				plannedRange, rangeErr := loaded.Manifest.EncRangeForPlaintextRange(start, end)
				if rangeErr != nil {
					return objectReadPlan{}, rangeErr
				}
				plan.MPURange = &plannedRange
				plan.BackendRange = cryptoRangeHeader(plannedRange)
			}
		}
		return plan, nil
	}
	if rangeHeader != nil && view.Class.Format == crypto.FormatChunkedV1 {
		missingOriginalSize := rawMetadataValue(rawMetadata, crypto.MetaOriginalSize) == "" || rawMetadataValue(rawMetadata, crypto.MetaChunkCount) == ""
		if missingOriginalSize {
			plan.Size = plaintextSize{Size: -1}
			plan.BackendRange = nil
			plan.Mode = objectReadBufferedRange
			return plan, nil
		}
	}
	size, err := h.resolvePlaintextSize(ctx, client, view)
	if err != nil {
		return objectReadPlan{}, err
	}
	plan.Size = size
	plan.Source.PlainSize = size.Size
	if rangeHeader == nil {
		return plan, nil
	}
	plan.Mode = objectReadBufferedRange
	if !size.Exact && size.Size >= 0 {
		size.Exact = true
		plan.Size = size
	}
	if !size.Exact && size.Size >= 0 {
		plan.Size.Exact = true
	}
	plan.BackendRange = rangeHeader
	if size.Exact {
		if start, end, rangeErr := parseObjectRange(*rangeHeader, size.Size); rangeErr == nil {
			plan.RangeStart, plan.RangeEnd, plan.RangeTotal = start, end, size.Size
			plan.ResponseStatus = http.StatusPartialContent
			plan.ResponseRange = &byteRange{Start: start, End: end}
		}
	}
	if !view.Class.Encrypted {
		if size.Exact && size.Size > 0 {
			if plan.RangeTotal >= 0 {
				plan.Mode = objectReadPassthroughRange
				plan.ResponseStatus = http.StatusPartialContent
				plan.ResponseRange = &byteRange{Start: plan.RangeStart, End: plan.RangeEnd}
			}
		}
		if plan.Mode != objectReadPassthroughRange {
			plan.Mode = objectReadBufferedRange
		}
		return plan, nil
	}
	if plan.RangeTotal < 0 && size.Size >= 0 {
		start, end, rangeErr := parseObjectRange(*rangeHeader, size.Size)
		if rangeErr == nil {
			plan.RangeStart, plan.RangeEnd, plan.RangeTotal = start, end, size.Size
		}
	}
	if view.Class.Format != crypto.FormatChunkedV1 && view.Class.Format != crypto.FormatChunkedV2 {
		plan.BackendRange = nil
		plan.Mode = objectReadBufferedRange
		return plan, nil
	}
	missingOriginalSize := rawMetadataValue(rawMetadata, crypto.MetaOriginalSize) == "" || rawMetadataValue(rawMetadata, crypto.MetaChunkCount) == ""
	if missingOriginalSize || view.Expanded[crypto.MetaManifest] == "" || strings.TrimSpace(*rangeHeader) == "bytes=0-" || !size.Exact {
		plan.BackendRange = nil
		plan.Mode = objectReadBufferedRange
		return plan, nil
	}
	if plan.RangeTotal < 0 || (plan.RangeStart == 0 && plan.RangeEnd == size.Size-1) {
		plan.BackendRange = nil
		plan.Mode = objectReadBufferedRange
		return plan, nil
	}
	encryptedStart, encryptedEnd, err := crypto.CalculateEncryptedRangeForPlaintextRange(view.Expanded, plan.RangeStart, plan.RangeEnd)
	if err == nil {
		encryptedEnd, err = clampEncryptedRangeEnd(encryptedStart, encryptedEnd, rawMetadata["Content-Length"])
	}
	if err != nil {
		plan.Mode = objectReadBufferedRange
		return plan, nil
	}
	backendRange := fmt.Sprintf("bytes=%d-%d", encryptedStart, encryptedEnd)
	plan.BackendRange = &backendRange
	plan.Mode = objectReadOptimizedRange
	plan.ResponseStatus = http.StatusPartialContent
	plan.ResponseRange = &byteRange{Start: plan.RangeStart, End: plan.RangeEnd}
	// Optimized encrypted ranges still authenticate their first requested
	// plaintext chunk before committing 206 headers. MPU ranges use their own
	// per-chunk write path and never enter this mode, avoiding a second read of
	// their already range-limited backend stream.
	plan.PreflightBody = true
	return plan, nil
}

func mpuChunkDecryptor(loaded *loadedMPUManifest) func(crypto.ObjectContext, []byte, []byte, [32]byte, [12]byte, int32, int, int32) ([]byte, error) {
	if loaded == nil {
		return nil
	}
	if loaded.IsV2 {
		return func(object crypto.ObjectContext, ciphertext, dek []byte, uploadIDHash [32]byte, ivPrefix [12]byte, partNumber int32, chunkSize int, chunkIndex int32) ([]byte, error) {
			return crypto.DecryptMPUPartRange(object, loaded.BindingID, ciphertext, dek, uploadIDHash, ivPrefix, partNumber, chunkSize, chunkIndex, loaded.Manifest.Algorithm)
		}
	}
	return func(object crypto.ObjectContext, ciphertext, dek []byte, uploadIDHash [32]byte, ivPrefix [12]byte, partNumber int32, chunkSize int, chunkIndex int32) ([]byte, error) {
		return crypto.DecryptMPUPartRangeV1(object, ciphertext, dek, uploadIDHash, ivPrefix, partNumber, chunkSize, chunkIndex, loaded.Manifest.Algorithm)
	}
}

func (h *Handler) planGetObjectRead(ctx context.Context, client s3.Client, bucket, key string, versionID, rangeHeader *string, optimizedDecryptAvailable bool, r *http.Request) (objectReadPlan, error) {
	if rangeHeader == nil {
		plan := objectReadPlan{Bucket: bucket, Key: key, Mode: objectReadFull, CacheEligible: versionID == nil, ResponseStatus: http.StatusOK}
		plan.Source.Method = r.Method
		plan.Source.Overrides = parseResponseOverrides(r)
		plan.Source.VersionID = r.URL.Query().Get("versionId")
		return plan, nil
	}
	plan, err := h.planGetObjectRange(ctx, client, bucket, key, versionID, rangeHeader, optimizedDecryptAvailable)
	plan.Source.Method = r.Method
	plan.Source.Overrides = parseResponseOverrides(r)
	plan.Source.VersionID = r.URL.Query().Get("versionId")
	return plan, err
}

func cryptoRangeHeader(r crypto.MPURangeResult) *string {
	value := fmt.Sprintf("bytes=%d-%d", r.EncStart, r.EncEnd)
	return &value
}

func (h *Handler) planGetObjectRange(ctx context.Context, client s3.Client, bucket, key string, versionID, rangeHeader *string, optimizedDecryptAvailable bool) (objectReadPlan, error) {
	metadata, err := client.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		return objectReadPlan{}, err
	}
	plan, err := h.planObjectRead(ctx, client, bucket, key, versionID, metadata, rangeHeader)
	plan.Source.VersionID = requestVersionID(versionID)
	if err == nil && plan.usesOptimizedRange() && !optimizedDecryptAvailable {
		plan.Mode = objectReadBufferedRange
		plan.BackendRange = nil
	}
	return plan, err
}

func (h *Handler) completeGetObjectRead(ctx context.Context, client s3.Client, bucket, key string, versionID *string, plan objectReadPlan, metadata map[string]string) (objectReadPlan, error) {
	if !plan.isFull() {
		return plan, nil
	}
	completed, err := h.planObjectRead(ctx, client, bucket, key, versionID, metadata, nil)
	completed.CacheEligible = plan.CacheEligible
	completed.Source.Method = plan.Source.Method
	completed.Source.VersionID = plan.Source.VersionID
	completed.Source.Overrides = plan.Source.Overrides
	completed.PreflightBody = true
	return completed, err
}

func requestVersionID(versionID *string) string {
	if versionID == nil {
		return ""
	}
	return *versionID
}

func (h *Handler) planCachedObjectRead(ctx context.Context, client s3.Client, bucket, key string) (objectReadPlan, error) {
	metadata, err := client.HeadObject(ctx, bucket, key, nil)
	if err != nil {
		return objectReadPlan{}, err
	}
	plan, err := h.planObjectRead(ctx, client, bucket, key, nil, metadata, nil)
	plan.CacheEligible = true
	return plan, err
}

func (h *Handler) prepareGetObjectRead(ctx context.Context, client s3.Client, bucket, key string, versionID, rangeHeader *string, optimizedDecryptAvailable bool, r *http.Request) (objectReadPlan, error) {
	return h.planGetObjectRead(ctx, client, bucket, key, versionID, rangeHeader, optimizedDecryptAvailable, r)
}

func objectCacheRequestEligible(rangeHeader, versionID *string) bool {
	return rangeHeader == nil && versionID == nil
}

func (h *Handler) decryptPlannedObject(ctx context.Context, engine crypto.EncryptionEngine, optimizedDecryptor interface {
	DecryptRangeOptimized(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error)
}, plan objectReadPlan, reader io.Reader, metadata map[string]string, bucket, key string) (io.Reader, map[string]string, error) {
	if !plan.Class.Encrypted {
		return reader, metadata, nil
	}
	if plan.usesOptimizedRange() {
		return optimizedDecryptor.DecryptRangeOptimized(ctx, crypto.ObjectContext{Bucket: bucket, Key: key}, reader, metadata, plan.RangeStart, plan.RangeEnd)
	}
	return engine.Decrypt(ctx, crypto.ObjectContext{Bucket: bucket, Key: key}, reader, metadata)
}

// planFullObjectRead is the shared full-GET variant, including HEAD-backed
// metadata consistency for MPU objects whose GET adapter may omit user keys.
func (h *Handler) planFullObjectRead(ctx context.Context, client s3.Client, bucket, key string, versionID *string, rawMetadata map[string]string) (objectReadPlan, error) {
	return h.planObjectRead(ctx, client, bucket, key, versionID, rawMetadata, nil)
}

func (h *Handler) objectResponsePlan(src objectResponseSource, shape responseShape, status int, body io.Reader, bucket, key string) (objectReadPlan, error) {
	plan, err := makeObjectResponsePlan(src, shape, status, body, bucket, key)
	if err != nil {
		return objectReadPlan{}, err
	}
	plan.Bucket, plan.Key = bucket, key
	plan.Source, plan.ResponseRange, plan.ResponseStatus = src, shape.Range, status
	plan.Body = body
	return plan, nil
}

func (h *Handler) cachedObjectResponsePlan(readPlan objectReadPlan, cachedSource objectResponseSource, data []byte, r *http.Request) objectReadPlan {
	readPlan.Source.Decrypted = cachedSource.Decrypted
	readPlan.Source.PlainSize = cachedSource.PlainSize
	readPlan.Source.BackendETag = cachedSource.BackendETag
	readPlan.Source.Method = r.Method
	readPlan.Source.Overrides = parseResponseOverrides(r)
	readPlan.Source.VersionID = r.URL.Query().Get("versionId")
	readPlan.Body = bytes.NewReader(data)
	return readPlan
}

func rawMetadataValue(metadata map[string]string, canonical string) string {
	if value := metadata[canonical]; value != "" {
		return value
	}
	spec, ok := crypto.LookupMetaKey(canonical)
	if !ok || spec.Compact == "" {
		return ""
	}
	return metadata[spec.Compact]
}

// resolveReadRange is the single range-normalization owner for reads whose
// plaintext size becomes authoritative only after decryption.
func resolveReadRange(plan objectReadPlan, rangeHeader string, actualPlainSize int64) objectReadPlan {
	if plan.RangeTotal >= 0 {
		return plan
	}
	start, end, err := parseObjectRange(rangeHeader, actualPlainSize)
	if err != nil {
		return plan
	}
	plan.RangeStart, plan.RangeEnd, plan.RangeTotal = start, end, actualPlainSize
	return plan
}

func (plan objectReadPlan) withDecryptedMetadata(metadata map[string]string, plainSize int64, backendETag string) objectReadPlan {
	plan.Source.Decrypted = metadata
	plan.Source.PlainSize = plainSize
	plan.Source.BackendETag = backendETag
	return plan
}

func (plan objectReadPlan) withExecutionResponse(r *http.Request, decrypted map[string]string, plainSize int64, backendETag string, body io.Reader) objectReadPlan {
	if plan.View != nil {
		plan.Source.Meta = plan.View.Expanded
	}
	plan.Source.Decrypted = decrypted
	plan.Source.PlainSize = plainSize
	plan.Source.BackendETag = backendETag
	if plan.Source.Method == "" {
		plan.Source.Method = r.Method
		plan.Source.VersionID = r.URL.Query().Get("versionId")
		plan.Source.Overrides = parseResponseOverrides(r)
	}
	plan.Body = body
	return plan
}

func (plan objectReadPlan) responseShape(r *http.Request, requestedRange *byteRange) responseShape {
	return responseShape{Method: plan.Source.Method, Range: requestedRange, VersionID: plan.Source.VersionID, Overrides: plan.Source.Overrides}
}

func (plan objectReadPlan) withDecryptedRange(actualPlainSize int64) objectReadPlan {
	if plan.RangeHeader == nil {
		return plan
	}
	plan = resolveReadRange(plan, *plan.RangeHeader, actualPlainSize)
	plan.ResponseRange = &byteRange{Start: plan.RangeStart, End: plan.RangeEnd}
	plan.ResponseStatus = http.StatusPartialContent
	return plan
}

func (plan objectReadPlan) finalizeBufferedRange(data []byte, backendETag string) (objectReadPlan, error) {
	if plan.RangeHeader == nil {
		return plan, fmt.Errorf("buffered range plan is missing the client range")
	}
	output, err := applyRangeRequest(data, *plan.RangeHeader)
	if err != nil {
		return plan, err
	}
	plan = plan.withDecryptedRange(int64(len(data)))
	plan.Source.PlainSize = int64(len(data))
	plan.Source.BackendETag = backendETag
	plan.Body = bytes.NewReader(output)
	return plan, nil
}

func (plan objectReadPlan) validMPURange() bool {
	return plan.isMPURange() && plan.MPUManifest != nil && plan.MPUDecrypt != nil && (plan.MPURange != nil || plan.MPURangeError != nil)
}

func (plan objectReadPlan) isMPURange() bool { return plan.Mode == objectReadMPURange }

func (plan objectReadPlan) isMPUFull() bool { return plan.Mode == objectReadMPUFull }

func (plan objectReadPlan) isPassthroughRange() bool {
	return plan.Mode == objectReadPassthroughRange
}

func (plan objectReadPlan) isFull() bool { return plan.Mode == objectReadFull }

func (plan objectReadPlan) usesOptimizedRange() bool {
	return plan.Mode == objectReadOptimizedRange
}

func (plan objectReadPlan) isBufferedRange() bool { return plan.Mode == objectReadBufferedRange }

func (plan objectReadPlan) isEncryptedBufferedRange() bool {
	return plan.isBufferedRange() && plan.Class.Encrypted
}

func makeObjectResponsePlan(src objectResponseSource, shape responseShape, status int, body io.Reader, bucket, key string) (objectReadPlan, error) {
	if bucket == "" || key == "" {
		return objectReadPlan{}, fmt.Errorf("object response plan requires bucket and key")
	}
	headers, err := projectObjectHeaders(src, shape)
	if err != nil {
		return objectReadPlan{}, err
	}
	if body == nil {
		body = bytes.NewReader(nil)
	}
	return objectReadPlan{Bucket: bucket, Key: key, Status: status, Headers: headers, Body: body, Class: src.Class, Size: plaintextSize{Size: src.PlainSize, Exact: src.PlainSize >= 0}}, nil
}

type boundedCacheCapture struct {
	bytes.Buffer
	limit    int64
	overflow bool
}

func newBoundedCacheCapture(limit int64) *boundedCacheCapture {
	return &boundedCacheCapture{limit: limit}
}

func (c *boundedCacheCapture) Write(p []byte) (int, error) {
	if c.overflow || int64(c.Len())+int64(len(p)) > c.limit {
		c.overflow = true
		return len(p), nil
	}
	if len(p) == 0 {
		return 0, nil
	}
	return c.Buffer.Write(p)
}

func (c *boundedCacheCapture) Overflowed() bool { return c.overflow }

func cacheCaptureEligibility(plainSize, limit int64) bool {
	return plainSize >= 0 && limit > 0 && plainSize <= limit
}

func (h *Handler) streamObjectBody(w http.ResponseWriter, r *http.Request, bucket, key string, body io.Reader) (int64, error) {
	var timeout time.Duration
	if h.config != nil {
		timeout = h.config.Server.WriteTimeout
	}
	n, err := copyWithDeadlineRefresh(responseErrorWriter{ResponseWriter: w}, body, timeout)
	if err != nil {
		h.recordObjectStreamFailure(r, bucket, key, err)
	}
	return n, err
}

// mpuPlaintextRangeReader authenticates and exposes one intersecting MPU
// plaintext chunk at a time. Its memory use is bounded by a single chunk and
// range clipping happens before bytes are returned to the response owner.
type mpuPlaintextRangeReader struct {
	ciphertext  io.Reader
	manifest    *crypto.MultipartManifest
	rangeResult crypto.MPURangeResult
	rangeStart  int64
	rangeEnd    int64
	plainOffset int64
	partIndex   int
	chunkIndex  int32
	object      crypto.ObjectContext
	dek         []byte
	uploadHash  [32]byte
	ivPrefix    [12]byte
	decrypt     func(crypto.ObjectContext, []byte, []byte, [32]byte, [12]byte, int32, int, int32) ([]byte, error)
	pending     []byte
	done        bool
}

func (r *mpuPlaintextRangeReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		if r.done {
			return 0, io.EOF
		}
		if r.partIndex > r.rangeResult.PartEndIdx {
			r.done = true
			return 0, io.EOF
		}

		part := r.manifest.Parts[r.partIndex]
		chunkPlainLen := int64(r.manifest.ChunkSize)
		if r.chunkIndex == part.ChunkCount-1 {
			chunkPlainLen = part.PlainLen - int64(r.chunkIndex)*int64(r.manifest.ChunkSize)
		}
		ciphertext := make([]byte, int(chunkPlainLen)+16)
		if _, err := io.ReadFull(r.ciphertext, ciphertext); err != nil {
			return 0, err
		}
		plain, err := r.decrypt(r.object, ciphertext, r.dek, r.uploadHash, r.ivPrefix, part.PartNumber, r.manifest.ChunkSize, r.chunkIndex)
		if err != nil {
			return 0, err
		}

		chunkStart := r.plainOffset
		chunkEnd := chunkStart + int64(len(plain)) - 1
		writeStart := r.rangeStart
		if writeStart < chunkStart {
			writeStart = chunkStart
		}
		writeEnd := r.rangeEnd
		if writeEnd > chunkEnd {
			writeEnd = chunkEnd
		}
		r.plainOffset += chunkPlainLen
		if r.chunkIndex == r.rangeResult.ChunkEnd && r.partIndex == r.rangeResult.PartEndIdx {
			r.done = true
		} else if r.chunkIndex == part.ChunkCount-1 {
			r.partIndex++
			if r.partIndex <= r.rangeResult.PartEndIdx {
				r.chunkIndex = 0
			}
		} else {
			r.chunkIndex++
		}

		if writeStart <= writeEnd {
			from, to := writeStart-chunkStart, writeEnd-chunkStart+1
			r.pending = plain[from:to]
		}
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// responseWriteError marks failures returned by the downstream HTTP writer.
// These are client-stream failures even when the error text resembles an AEAD
// or decrypt failure; they did not originate from the object reader.
type responseWriteError struct{ err error }

func (e responseWriteError) Error() string { return e.err.Error() }
func (e responseWriteError) Unwrap() error { return e.err }

type responseErrorWriter struct{ http.ResponseWriter }

func (w responseErrorWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if err != nil {
		return n, responseWriteError{err: err}
	}
	return n, nil
}

// recordObjectStreamFailure is the shared post-header error accounting path for
// failures discovered while reading/decrypting a stream or writing it to the
// client. Network aborts are S3 client-stream failures; other uncanceled
// failures are integrity failures and produce one tamper metric/audit event.
func (h *Handler) recordObjectStreamFailure(r *http.Request, bucket, key string, err error) {
	if err == nil {
		return
	}
	var writeErr responseWriteError
	if errors.As(err, &writeErr) || isNetworkError(err) {
		if h.metrics != nil {
			h.metrics.RecordS3Error(r.Context(), "GetObject", bucket, "client_stream")
		}
		return
	}
	if r.Context().Err() == nil {
		h.recordObjectIntegrityFailure(r, bucket, key, err)
	}
}

func (h *Handler) finishObjectStream(r *http.Request, status int, start time.Time, bytesWritten int64) {
	h.writeObjectResponseMetric(r, status, start, bytesWritten)
}

// finishObjectStreamFailure accounts for a failure after success headers were
// committed. Callers set failureRecorded when streamObjectBody already handled
// the read/write failure; this keeps tamper, network and request metrics
// exactly-once across chunked response writers.
func (h *Handler) finishObjectStreamFailure(r *http.Request, bucket, key string, err error, failureRecorded bool, status int, start time.Time, bytesWritten int64) {
	if !failureRecorded {
		h.recordObjectStreamFailure(r, bucket, key, err)
	}
	if err != nil {
		h.writeObjectResponseMetric(r, http.StatusInternalServerError, start, bytesWritten)
		return
	}
	h.finishObjectStream(r, status, start, bytesWritten)
}

func (h *Handler) serveObjectBody(w http.ResponseWriter, r *http.Request, plan objectReadPlan) (int64, error) {
	if plan.Body == nil {
		plan.Body = bytes.NewReader(nil)
	}
	if plan.OperationStarted.IsZero() {
		plan.OperationStarted = time.Now()
	}
	if plan.isBufferedRange() && plan.RangeHeader != nil {
		decrypted, err := io.ReadAll(plan.Body)
		if err != nil {
			h.writeObjectDecryptError(w, r, "GetObject", plan.Bucket, plan.Key, err, plan.Started)
			return 0, err
		}
		if plan.Class.Encrypted {
			output, rangeErr := applyRangeRequest(decrypted, *plan.RangeHeader)
			if rangeErr != nil {
				s3Err := &S3Error{Code: "InvalidRange", Message: fmt.Sprintf("Invalid range request: %v", rangeErr), Resource: r.URL.Path, HTTPStatus: http.StatusRequestedRangeNotSatisfiable}
				h.writeObjectError(w, r, "GetObject", s3Err, plan.Started)
				return 0, rangeErr
			}
			plan = plan.withDecryptedRange(int64(len(decrypted)))
			plan.Source.PlainSize = int64(len(decrypted))
			plan = plan.withExecutionResponse(r, plan.Source.Decrypted, int64(len(decrypted)), plan.Source.BackendETag, bytes.NewReader(output))
		} else {
			plan = plan.withExecutionResponse(r, plan.Source.Decrypted, int64(len(decrypted)), plan.Source.BackendETag, bytes.NewReader(decrypted))
		}
	}
	if plan.Headers == nil {
		shape := plan.responseShape(r, plan.ResponseRange)
		if plan.Source.Method == "" {
			plan.Source.Method = r.Method
		}
		shape.Method = plan.Source.Method
		if plan.ResponseStatus == http.StatusRequestedRangeNotSatisfiable {
			shape.Range = nil
			shape.HasUnsatisfiedRange = true
			shape.UnsatisfiedRangeTotal = plan.Size.Size
		}
		headers, err := projectObjectHeaders(plan.Source, shape)
		if err != nil {
			return 0, err
		}
		plan.Headers = headers
		if plan.ResponseStatus != 0 {
			plan.Status = plan.ResponseStatus
		}
	}
	if plan.PreflightBody {
		preflightSize := int64(crypto.DefaultChunkSize)
		if plan.PreflightLimit > 0 {
			preflightSize = plan.PreflightLimit
		}
		first := make([]byte, int(preflightSize))
		n, err := io.ReadFull(plan.Body, first)
		if plan.PreflightLimit > 0 && (errors.Is(err, io.ErrUnexpectedEOF) || int64(n) < plan.PreflightLimit) {
			integrityErr := err
			if integrityErr == nil {
				integrityErr = io.ErrUnexpectedEOF
			}
			h.writeObjectIntegrityError(w, r, "GetObject", plan.Bucket, plan.Key, integrityErr, plan.Started)
			return 0, io.ErrUnexpectedEOF
		}
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			h.writeObjectIntegrityError(w, r, "GetObject", plan.Bucket, plan.Key, err, plan.Started)
			return 0, err
		}
		plan.Body = io.MultiReader(bytes.NewReader(first[:n]), plan.Body)
		if errors.Is(err, io.EOF) {
			plan.Body = bytes.NewReader(first[:n])
		}
	}
	if !plan.ResponseStarted {
		startObjectBody(w, plan)
	}
	if plan.PreflightBody && plan.DecryptSuccess != nil {
		plan.DecryptSuccess.Duration = time.Since(plan.OperationStarted)
	}
	n, err := h.streamObjectBody(w, r, plan.Bucket, plan.Key, plan.Body)
	if err == nil && plan.DecryptSuccess != nil && plan.Class.Encrypted {
		success := plan.DecryptSuccess
		h.recordObjectDecryptSuccess(r, plan.Bucket, plan.Key, success.Algorithm, success.KeyVersion, success.Duration, success.PlainSize, success.AuditMetadata)
		if success.RotatedFrom > 0 && success.RotatedTo > 0 && h.metrics != nil {
			h.metrics.RecordRotatedRead(r.Context(), success.RotatedFrom, success.RotatedTo)
		}
	}
	if err == nil && plan.Status >= 200 && plan.Status < 300 && !plan.SkipRequestMetric && !plan.ResponseStarted {
		h.finishObjectStream(r, plan.Status, plan.OperationStarted, n)
	}
	if err == nil && plan.Status == http.StatusRequestedRangeNotSatisfiable {
		h.finishObjectStream(r, plan.Status, plan.OperationStarted, 0)
	}
	if err != nil && !plan.SkipRequestMetric && !plan.ResponseStarted {
		h.finishObjectStreamFailure(r, plan.Bucket, plan.Key, err, true, plan.Status, plan.OperationStarted, n)
	}
	return n, err
}

// startObjectBody is the only writer of successful object-response headers and
// status. serveObjectBody invokes it after its preflight read succeeds.
func startObjectBody(w http.ResponseWriter, plan objectReadPlan) {
	writeObjectHeaders(w, plan.Headers)
	w.WriteHeader(plan.Status)
}

func (h *Handler) serveUnsatisfiedObjectRange(w http.ResponseWriter, r *http.Request, plan objectReadPlan, start time.Time) bool {
	if plan.ResponseStatus != http.StatusRequestedRangeNotSatisfiable {
		return false
	}
	plan.Body = nil
	plan = plan.withExecutionResponse(r, plan.Source.Decrypted, plan.Size.Size, plan.Source.BackendETag, nil)
	plan.Started = start
	_, _ = h.serveObjectBody(w, r, plan)
	return true
}

func objectReadSupportsOptimizedDecrypt(engine crypto.EncryptionEngine) bool {
	_, ok := engine.(interface {
		DecryptRangeOptimized(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error)
	})
	return ok
}

// servePlannedGetObject executes a fully selected read plan. Backend range
// acquisition, decrypt dispatch, first-chunk integrity setup and successful
// response projection stay with the object-read owner rather than the route.
func (h *Handler) servePlannedGetObject(w http.ResponseWriter, r *http.Request, s3Client s3.Client, engine crypto.EncryptionEngine, versionID *string, objectRead objectReadPlan, start time.Time) {
	ctx := r.Context()
	bucket, key := objectRead.Bucket, objectRead.Key
	if objectRead.isMPURange() {
		h.serveMPURangedGetPlanned(w, r, bucket, key, versionID, objectRead, s3Client, start)
		return
	}
	reader, metadata, err := s3Client.GetObject(ctx, bucket, key, versionID, objectRead.BackendRange)
	if err != nil {
		s3Err := TranslateError(err, bucket, key)
		h.writeObjectError(w, r, "GetObject", s3Err, start)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to get object")
		return
	}
	defer func() { _ = reader.Close() }()

	// Authenticate the v2 terminal before any success headers or plaintext are
	// exposed. Ranged GETs already performed this check during HEAD planning.
	if objectRead.isFull() {
		objectRead, err = h.completeGetObjectRead(ctx, s3Client, bucket, key, versionID, objectRead, metadata)
		if err != nil {
			h.writeObjectDecryptError(w, r, "GET", bucket, key, err, start)
			return
		}
	}

	if objectRead.isPassthroughRange() {
		objectRead = objectRead.withExecutionResponse(r, nil, objectRead.RangeTotal, metadata["ETag"], reader)
		_, copyErr := h.serveObjectBody(w, r, objectRead)
		if copyErr != nil {
			h.logger.WithError(copyErr).WithFields(logrus.Fields{"bucket": bucket, "key": key}).Warn("Failed to write passthrough range response")
		}
		return
	}

	// For MPU-encrypted objects, delegate to the MPU decrypt path.
	if objectRead.isMPUFull() {
		decryptStart := time.Now()
		decryptedReader, err := h.decryptMPUObjectWithManifest(ctx, bucket, key, reader, objectRead.MPUManifest)
		decryptDuration := time.Since(decryptStart)
		if err != nil {
			h.logger.WithError(err).WithFields(logrus.Fields{
				"bucket": bucket,
				"key":    key,
			}).Error("Failed to decrypt MPU object")
			h.writeObjectDecryptError(w, r, "GET", bucket, key, err, start)
			return
		}
		mpuPlainSize := objectRead.Size.Size
		objectRead = objectRead.withExecutionResponse(r, objectRead.Source.Decrypted, mpuPlainSize, objectRead.Source.BackendETag, decryptedReader)
		objectRead.PreflightBody = true
		objectRead.Started = start
		objectRead.DecryptSuccess = &objectDecryptSuccess{Algorithm: crypto.AlgorithmAES256GCM, Duration: decryptDuration, PlainSize: mpuPlainSize}
		_, copyErr := h.serveObjectBody(w, r, objectRead)
		if copyErr != nil {
			if isNetworkError(copyErr) {
				h.logger.WithError(copyErr).WithFields(logrus.Fields{"bucket": bucket, "key": key}).Warn("MPU stream aborted by network error after 200 OK")
			} else {
				h.logger.WithError(copyErr).WithFields(logrus.Fields{"bucket": bucket, "key": key}).Error("MPU decrypt failed mid-stream after 200 OK")
			}
		}
		return
	}

	// Decrypt if encrypted
	decryptStart := time.Now()
	var decryptedReader io.Reader
	var decMetadata map[string]string
	var fullGetSize plaintextSize
	if objectRead.isFull() {
		fullGetSize = objectRead.Size
	}

	optimizedDecryptor, _ := engine.(interface {
		DecryptRangeOptimized(context.Context, crypto.ObjectContext, io.Reader, map[string]string, int64, int64) (io.Reader, map[string]string, error)
	})
	decryptedReader, decMetadata, err = h.decryptPlannedObject(r.Context(), engine, optimizedDecryptor, objectRead, reader, metadata, bucket, key)
	decryptDuration := time.Since(decryptStart)
	if err != nil {
		h.logger.WithError(err).WithFields(logrus.Fields{
			"bucket": bucket,
			"key":    key,
		}).Error("Failed to decrypt object")
		h.writeObjectDecryptError(w, r, "GET", bucket, key, err, start)
		return
	}
	if objectRead.isFull() || objectRead.isMPUFull() {
		if fullGetSize.Exact {
			decMetadata["Content-Length"] = strconv.FormatInt(fullGetSize.Size, 10)
		}
	}
	if decMetadata["ETag"] != "" {
		decMetadata["ETag"] = quoteETag(decMetadata["ETag"])
	}

	// For range optimization, we already have the exact range in decryptedReader
	// For non-optimized ranges, we need to buffer and apply range
	var decryptedData []byte
	var decryptedSize int64
	if objectRead.isEncryptedBufferedRange() {
		// Buffer for range processing (only if not using optimization)
		dd, err := io.ReadAll(decryptedReader)
		if err != nil {
			h.logger.WithError(err).Error("Failed to read decrypted data")
			h.writeObjectDecryptError(w, r, "GetObject", bucket, key, err, start)
			return
		}
		decryptedData = dd
		decryptedSize = int64(len(decryptedData))
	} else if objectRead.usesOptimizedRange() {
		// For optimized range, the reader already contains only the range
		// But we still need to read it to send it
		decryptedSize = objectRead.RangeEnd - objectRead.RangeStart + 1
	} else {
		// Full-object decrypt (no range request): use the shared size policy.
		if fullGetSize.Exact && fullGetSize.Size > 0 {
			decryptedSize = fullGetSize.Size
		}
	}
	// Get algorithm and key version from metadata for audit logging
	algorithm := metadata[crypto.MetaAlgorithm]
	if algorithm == "" {
		algorithm = crypto.AlgorithmAES256GCM
	}

	// Extract actual key version used for decryption from metadata
	keyVersionUsed := 0
	// Use the normalized metadata view produced by the shared object planner.
	// Backend providers may compact gateway metadata (for example to
	// x-amz-meta-kv), so the raw S3 response is not a reliable source for the
	// canonical key-version field.
	keyMetadata := metadata
	if objectRead.View != nil {
		keyMetadata = objectRead.View.Expanded
	}
	if kvStr, ok := keyMetadata[crypto.MetaKeyVersion]; ok && kvStr != "" {
		if kv, err := strconv.Atoi(kvStr); err == nil {
			keyVersionUsed = kv
		}
	}

	// Get active key version and check for rotated read
	activeKeyVersion := 0
	if h.keyManager != nil {
		activeKeyVersion = h.currentKeyVersion(r.Context())
	}

	// Use keyVersionUsed for audit logging (actual version used, not active)
	keyVersion := keyVersionUsed
	if keyVersion == 0 && h.keyManager != nil {
		// Fallback to active version if metadata doesn't have version
		keyVersion = activeKeyVersion
	}

	// Audit logging with metadata indicating rotated read if applicable
	auditMetadata := make(map[string]interface{})
	if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
		auditMetadata["rotated_read"] = true
		auditMetadata["key_version_used"] = keyVersionUsed
		auditMetadata["active_key_version"] = activeKeyVersion
	}
	decryptSuccess := &objectDecryptSuccess{Algorithm: algorithm, KeyVersion: keyVersion, Duration: decryptDuration, PlainSize: decryptedSize, AuditMetadata: auditMetadata}
	if keyVersionUsed > 0 && activeKeyVersion > 0 && keyVersionUsed != activeKeyVersion {
		decryptSuccess.RotatedFrom, decryptSuccess.RotatedTo = keyVersionUsed, activeKeyVersion
	}

	// Apply range request if present (after decryption) and set headers BEFORE WriteHeader
	if objectRead.usesOptimizedRange() || objectRead.isEncryptedBufferedRange() {
		if objectRead.usesOptimizedRange() {
			// V0.6-PERF-1 Phase B: Optimized range — stream directly to the
			// response writer without buffering the entire range into memory.
			// Content-Length is known from the plaintext range (already computed
			// above at decryptedSize). This eliminates one full-range allocation.

			// Get total size for Content-Range header
			totalSize := int64(-1)
			if objectRead.Size.Exact {
				totalSize = objectRead.Size.Size
			}
			if totalSize == 0 {
				// Fallback to approximate from decryptedData if available
				totalSize = int64(len(decryptedData))
			}

			// Set decrypted metadata headers
			objectRead = objectRead.withExecutionResponse(r, decMetadata, totalSize, metadata["ETag"], decryptedReader)
			objectRead.DecryptSuccess = decryptSuccess
			objectRead.Started = start
			h.logger.WithFields(logrus.Fields{
				"bucket":         bucket,
				"key":            key,
				"content_range":  fmt.Sprintf("bytes %d-%d/%d", objectRead.RangeStart, objectRead.RangeEnd, totalSize),
				"content_length": decryptedSize,
				"client_range":   objectRead.RangeHeader,
			}).Info("serving range-optimized response")
			// Content headers were projected before the optimized stream started.
			// Stream range bytes directly — no intermediate buffer.
			n64, copyErr := h.serveObjectBody(w, r, objectRead)
			if copyErr != nil {
				h.logger.WithError(copyErr).Error("Failed to write optimized range data")
				// Headers already sent; log only.
			}
			if n64 != decryptedSize {
				h.logger.WithFields(logrus.Fields{
					"bucket":          bucket,
					"key":             key,
					"promised_bytes":  decryptedSize,
					"written_bytes":   n64,
					"plaintext_range": fmt.Sprintf("%d-%d", objectRead.RangeStart, objectRead.RangeEnd),
				}).Error("BYTES MISMATCH: Content-Length promised != bytes actually written")
			}
			return
		} else {
			objectRead = objectRead.withExecutionResponse(r, decMetadata, int64(len(decryptedData)), metadata["ETag"], bytes.NewReader(decryptedData))
			objectRead.DecryptSuccess = decryptSuccess
			objectRead.Started = start
			if _, serveErr := h.serveObjectBody(w, r, objectRead); serveErr != nil {
				h.logger.WithError(serveErr).Warn("Failed to write buffered range response")
				return
			}
			return
		}
	} else {
		// Project headers through the shared response owner before streaming.
		// The backend Content-Length is ciphertext length, so only the
		// decrypted metadata may provide the plaintext length here.
		plainSize := int64(-1)
		if fullGetSize.Exact {
			plainSize = fullGetSize.Size
		}
		canCapture := h.cache != nil && objectRead.CacheEligible && h.config != nil && cacheCaptureEligibility(plainSize, h.config.Cache.MaxSize)
		var capture *boundedCacheCapture
		body := decryptedReader
		if canCapture {
			capture = newBoundedCacheCapture(h.config.Cache.MaxSize)
			body = io.TeeReader(decryptedReader, capture)
		}
		// Read the first plaintext chunk before committing success headers. This
		// surfaces chunk authentication and terminal failures for short/full-first-
		// chunk objects while preserving streaming for the remainder.
		objectRead = objectRead.withExecutionResponse(r, decMetadata, plainSize, metadata["ETag"], body)
		objectRead.Started = start
		objectRead.DecryptSuccess = decryptSuccess
		n64, err := h.serveObjectBody(w, r, objectRead)
		if err != nil {
			if isNetworkError(err) {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    key,
				}).Warn("Object stream aborted by network error after 200 OK")
			} else {
				h.logger.WithError(err).WithFields(logrus.Fields{
					"bucket": bucket,
					"key":    key,
				}).Error("Failed to write response")
			}
			// Can't change status code after WriteHeader; still record the bytes sent.
			return
		}
		if capture != nil && !capture.Overflowed() && n64 == plainSize && int64(capture.Len()) == plainSize && metadata["ETag"] != "" {
			if entryWriter, ok := h.cache.(cache.EntryWriter); ok {
				cachedSource := objectRead.Source
				cachedSource.Decrypted = decMetadata
				cachedSource.PlainSize = plainSize
				cachedSource.BackendETag = metadata["ETag"]
				if sourceBytes, marshalErr := json.Marshal(cachedSource); marshalErr == nil {
					entry := &cache.CacheEntry{Data: capture.Bytes(), Metadata: decMetadata, BackendETag: metadata["ETag"], Source: sourceBytes}
					if cacheErr := entryWriter.SetEntry(ctx, bucket, key, entry, 0); cacheErr != nil {
						h.logger.WithError(cacheErr).WithFields(logrus.Fields{"bucket": bucket, "key": key}).Warn("Failed to cache object")
					}
				}
			}
		}
		return
	}

}
