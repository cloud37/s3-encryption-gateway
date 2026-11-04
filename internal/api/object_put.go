package api

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// objectWriteInput is the validated, request-independent description of one
// object write. The caller owns Body and any request-scoped SSE key.
type objectWriteInput struct {
	Bucket, Key, Operation string
	Body                   io.Reader
	PlainLength            int64
	HaveLength             bool
	Metadata               writeMetadata
	PlainETag              string
	Tags, ACL              string
	GrantFullControl       string
	GrantRead              string
	GrantReadACP           string
	GrantWriteACP          string
	Lock                   *s3.ObjectLockInput
	Options                s3.ObjectPutOptions
	Deadline               time.Time
}

type objectWriteResult struct {
	Backend    s3.PutObjectResult
	ClientETag string
	PlainSize  int64
	// CustomerSSE carries the request-side no-store requirement when an
	// advanced backend does not echo its SSE-C response header. The projector
	// also independently detects backend-declared SSE-C for direct callers.
	CustomerSSE bool
}

type objectWriteStage uint8

const (
	objectWriteInvalid objectWriteStage = iota + 1
	objectWriteCrypto
	objectWriteClassify
	objectWritePreparation
	objectWriteBackend
)

type objectWriteError struct {
	stage objectWriteStage
	err   error
}

func (e *objectWriteError) Error() string { return e.err.Error() }
func (e *objectWriteError) Unwrap() error { return e.err }

func objectWriteFailure(stage objectWriteStage, err error) error {
	if err == nil {
		return nil
	}
	return &objectWriteError{stage: stage, err: err}
}

// putObjectData owns encryption and backend persistence for both ordinary PUT
// and the future validated POST caller. It does not retain or close in.Body,
// write HTTP responses, or accept an HTTP request as a hidden input channel.
func (h *Handler) putObjectData(ctx context.Context, client s3.Client, in objectWriteInput) (objectWriteResult, error) {
	if h == nil || ctx == nil || nilWriteDependency(client) || in.Body == nil || nilWriteDependency(in.Body) || in.Bucket == "" || in.Key == "" {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrPostFormMalformed)
	}
	if in.Operation != "PutObject" && in.Operation != "PostObject" {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrPostFormMalformed)
	}
	if in.HaveLength && in.PlainLength < 0 || in.Operation == "PostObject" && (!in.HaveLength || in.PlainLength < 0) {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrPostFormMalformed)
	}
	if in.Operation == "PostObject" && in.PlainETag != "" {
		if len(in.PlainETag) != 32 {
			return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrPostFormMalformed)
		}
		if _, err := hex.DecodeString(in.PlainETag); err != nil {
			return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrPostFormMalformed)
		}
	}
	if err := ctx.Err(); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrStreamingCanceled)
	}
	if err := objectWriteDeadline(in); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, err)
	}
	maxBuffer := effectiveMaxPartBuffer(h.config)
	var postPartLimit int64
	if upload, ok := postUploadFromContextRequestContext(ctx); ok && upload.limitSnapshot.Part > 0 {
		postPartLimit = upload.limitSnapshot.Part
	} else {
		postPartLimit = maxBuffer
	}
	advanced, advancedOK := client.(s3.AdvancedObjectClient)
	if advancedOK && nilWriteDependency(advanced) {
		advancedOK = false
	}
	if objectPutOptionsNonzero(in.Options) && !advancedOK {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrPostUnsupported)
	}
	engine, err := h.getEncryptionEngine(in.Bucket)
	if err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteCrypto, err)
	}
	if engine == nil || nilWriteDependency(engine) {
		return objectWriteResult{}, objectWriteFailure(objectWriteCrypto, errors.New("encryption engine unavailable"))
	}
	var writeProfile crypto.EncryptionWriteProfile
	profile, hasProfile := engine.(crypto.EncryptionWriteProfiler)
	if hasProfile {
		writeProfile = profile.WriteProfile()
	}
	if in.Operation == "PostObject" {
		if (!hasProfile || !writeProfile.StreamsPlaintext) && in.PlainLength > postPartLimit {
			return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrPostEntityTooLarge)
		}
	}

	engineMetadata := in.Metadata.engineInput(in.PlainLength, in.HaveLength)
	if in.Operation == "PostObject" && in.PlainETag != "" && !hasCustomerSSE(in.Options) {
		engineMetadata["ETag"] = in.PlainETag
	}
	encryptStart := time.Now()
	encryptedReader, encryptedMetadata, encryptErr := engine.Encrypt(ctx, crypto.ObjectContext{Bucket: in.Bucket, Key: in.Key}, in.Body, engineMetadata)
	encryptDuration := time.Since(encryptStart)
	algorithm := encryptedMetadata[crypto.MetaAlgorithm]
	if algorithm == "" {
		algorithm = crypto.AlgorithmAES256GCM
	}
	keyVersion := 0
	if h.keyManager != nil {
		keyVersion = h.currentKeyVersion(ctx)
	}
	if encryptErr != nil {
		if h.metrics != nil {
			h.metrics.RecordEncryptionError(ctx, "encrypt", "encryption_failed")
		}
		if h.auditLogger != nil {
			h.auditLogger.LogEncrypt(in.Bucket, in.Key, algorithm, keyVersion, false, encryptErr, encryptDuration, nil)
		}
		return objectWriteResult{}, objectWriteFailure(objectWriteCrypto, encryptErr)
	}
	if encryptedMetadata == nil {
		return objectWriteResult{}, objectWriteFailure(objectWritePreparation, errors.New("encryption returned no object metadata"))
	}
	if encryptedReader == nil || nilWriteDependency(encryptedReader) {
		prepErr := errors.New("encryption returned no object body")
		return objectWriteResult{}, objectWriteFailure(objectWritePreparation, prepErr)
	}
	expandedMetadata, err := crypto.ExpandMetadataForAPI(encryptedMetadata)
	if err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteClassify, err)
	}
	class, err := crypto.ClassifyObject(in.Key, expandedMetadata)
	if err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteClassify, err)
	}
	if h.auditLogger != nil && in.Operation != "PostObject" {
		h.auditLogger.LogEncrypt(in.Bucket, in.Key, algorithm, keyVersion, true, nil, encryptDuration, nil)
	}
	if h.metrics != nil && in.Operation != "PostObject" {
		h.metrics.RecordEncryptionOperation(ctx, "encrypt", encryptDuration, in.PlainLength)
	}
	if class.Format == crypto.FormatPlaintext {
		in.Metadata.Standard.ApplyTo(encryptedMetadata)
	}

	filterKeys := []string(nil)
	if h.config != nil {
		filterKeys = h.config.Backend.FilterMetadataKeys
	}
	persist := buildPersistPlan(encryptedMetadata, class, filterKeys)
	backendMetadata := persist.Metadata
	persist.Native.ApplyTo(backendMetadata)
	if in.Operation == "PostObject" && class.Format == crypto.FormatPlaintext {
		provider, mode := "", ""
		if h.config != nil {
			provider = h.config.Backend.Provider
			mode = h.config.Backend.MetadataProfile
		}
		profile, err := crypto.ResolveMetadataProfile(provider, mode)
		if err != nil {
			return objectWriteResult{}, objectWriteFailure(objectWritePreparation, err)
		}
		envelope := make(map[string]string, len(backendMetadata))
		for key, value := range backendMetadata {
			if !strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") && !objectmeta.IsStandard(key) {
				key = "x-amz-meta-" + key
			}
			envelope[key] = value
		}
		if err := profile.ValidateMetadataSize(envelope); err != nil {
			return objectWriteResult{}, objectWriteFailure(objectWritePreparation, err)
		}
	}

	var ciphertextCounter *countingReader
	if in.Operation == "PutObject" && !in.HaveLength && expandedMetadata[crypto.MetaChunkedFormat] == "true" {
		ciphertextCounter = newCountingReader(encryptedReader)
		encryptedReader = ciphertextCounter
	}

	var contentLength *int64
	if in.Operation == "PostObject" {
		manager := h.spoolManager
		if manager == nil {
			manager = DefaultSpoolManager()
		}
		ciphertext, spoolErr := spoolPostCiphertext(ctx, encryptedReader, manager)
		if spoolErr != nil {
			return objectWriteResult{}, objectWriteFailure(objectWritePreparation, spoolErr)
		}
		defer ciphertext.Close()
		encryptedReader = ciphertext
		exact := ciphertext.DecodedLength()
		contentLength = &exact
	} else {
		if in.HaveLength && class.Format == crypto.FormatPlaintext {
			exact := in.PlainLength
			contentLength = &exact
		} else if (class.Format == crypto.FormatChunkedV1 || class.Format == crypto.FormatChunkedV2) && in.HaveLength {
			if exact, sizeErr := crypto.CiphertextSizeForPlaintext(expandedMetadata, in.PlainLength); sizeErr == nil {
				contentLength = &exact
			}
		}
		if seeker, ok := encryptedReader.(io.Seeker); ok {
			if current, seekErr := seeker.Seek(0, io.SeekCurrent); seekErr == nil {
				if end, endErr := seeker.Seek(0, io.SeekEnd); endErr == nil {
					if _, restoreErr := seeker.Seek(current, io.SeekStart); restoreErr == nil && end >= current {
						exact := end - current
						contentLength = &exact
					}
				}
			}
		}
	}

	if err := ctx.Err(); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrStreamingCanceled)
	}
	if err := objectWriteDeadline(in); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, err)
	}
	if in.Operation == "PutObject" && contentLength != nil && *contentLength <= maxBuffer {
		if _, seekable := encryptedReader.(io.Seeker); !seekable {
			seekableBody, bufferErr := s3.NewSeekableBody(encryptedReader, maxBuffer)
			if bufferErr != nil {
				return objectWriteResult{}, objectWriteFailure(objectWritePreparation, bufferErr)
			}
			encryptedReader = seekableBody
			exact := seekableBody.Len
			contentLength = &exact
		}
	}
	if err := ctx.Err(); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrStreamingCanceled)
	}
	if err := objectWriteDeadline(in); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, err)
	}
	if in.Operation == "PostObject" {
		if h.auditLogger != nil {
			h.auditLogger.LogEncrypt(in.Bucket, in.Key, algorithm, keyVersion, class.Format != crypto.FormatPlaintext, nil, encryptDuration, nil)
		}
		if h.metrics != nil && class.Format != crypto.FormatPlaintext {
			h.metrics.RecordEncryptionOperation(ctx, "encrypt", encryptDuration, in.PlainLength)
		}
	}
	if err := ctx.Err(); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrStreamingCanceled)
	}
	if err := objectWriteDeadline(in); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, err)
	}
	if h.cache != nil {
		h.cache.Delete(ctx, in.Bucket, in.Key)
	}
	// Cache invalidation is an external seam and can itself block. Recheck
	// immediately before persistence so a canceled/expired request cannot
	// begin a backend write after that delay.
	if err := ctx.Err(); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, ErrStreamingCanceled)
	}
	if err := objectWriteDeadline(in); err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteInvalid, err)
	}

	var backendResult s3.PutObjectResult
	if advancedOK {
		backendResult, err = advanced.PutObjectWithOptions(ctx, in.Bucket, in.Key, encryptedReader, backendMetadata, contentLength, in.Tags, in.Lock, in.ACL, in.GrantFullControl, in.GrantRead, in.GrantReadACP, in.GrantWriteACP, in.Options)
	} else {
		backendResult.ETag, err = client.PutObject(ctx, in.Bucket, in.Key, encryptedReader, backendMetadata, contentLength, in.Tags, in.Lock, in.ACL, in.GrantFullControl, in.GrantRead, in.GrantReadACP, in.GrantWriteACP)
	}
	if err != nil {
		return objectWriteResult{}, objectWriteFailure(objectWriteBackend, err)
	}

	resultPlainSize := in.PlainLength
	exactPlainSize := in.HaveLength && in.PlainLength >= 0
	if !in.HaveLength {
		if metadataSize, parseErr := strconv.ParseInt(expandedMetadata[crypto.MetaOriginalSize], 10, 64); parseErr == nil && metadataSize >= 0 {
			resultPlainSize = metadataSize
			exactPlainSize = true
		}
	}
	if ciphertextCounter != nil && ciphertextCounter.n > 0 && expandedMetadata[crypto.MetaFallbackMode] != "true" {
		plainSize, _, sizeErr := crypto.PlaintextSizeForCiphertext(expandedMetadata, ciphertextCounter.n)
		if sizeErr != nil || plainSize <= 0 {
			// Preserve the legacy best-effort behavior for formats whose ciphertext
			// size cannot be inverted: the object write succeeds, but the helper
			// does not claim an inferred exact plaintext size or update size cache.
			return objectWriteResult{Backend: backendResult, ClientETag: backendResult.ETag, PlainSize: in.PlainLength}, nil
		}
		resultPlainSize = plainSize
		exactPlainSize = false
		backfill := make(map[string]string, len(encryptedMetadata)+1)
		for k, v := range encryptedMetadata {
			backfill[k] = v
		}
		backfill[crypto.MetaOriginalSize] = strconv.FormatInt(plainSize, 10)
		plan := buildPersistPlan(backfill, class, filterKeys)
		plan.Native.ApplyTo(plan.Metadata)
		if _, _, copyErr := client.CopyObject(ctx, in.Bucket, in.Key, in.Bucket, in.Key, nil, plan.Metadata, nil); copyErr != nil {
			if h.logger != nil {
				h.logger.WithError(copyErr).WithFields(map[string]interface{}{"bucket": in.Bucket, "key": in.Key, "plain_size": plainSize}).Warn("failed to update original plaintext size after streaming PUT")
			}
		} else {
			encryptedMetadata[crypto.MetaOriginalSize] = strconv.FormatInt(plainSize, 10)
			expandedMetadata[crypto.MetaOriginalSize] = strconv.FormatInt(plainSize, 10)
			exactPlainSize = true
		}
	}

	if plainSize, parseErr := strconv.ParseInt(expandedMetadata[crypto.MetaOriginalSize], 10, 64); exactPlainSize && parseErr == nil && plainSize >= 0 {
		h.recordPlaintextSize(ctx, in.Bucket, in.Key, plaintextSize{Size: plainSize, Exact: true, Source: "original-size"})
	}
	customerSSE := hasCustomerSSE(in.Options) || isSSECustomerBackendObject(backendResult.Headers)
	if in.Operation == "PostObject" && class.Encrypted && !customerSSE && in.PlainETag != "" {
		return objectWriteResult{Backend: backendResult, ClientETag: quoteETag(in.PlainETag), PlainSize: resultPlainSize, CustomerSSE: customerSSE}, nil
	}
	return objectWriteResult{Backend: backendResult, ClientETag: backendResult.ETag, PlainSize: resultPlainSize, CustomerSSE: customerSSE}, nil
}

// postUploadFromContextRequestContext extracts only the authenticated request's
// private immutable POST snapshot. Direct helper callers without that auth
// context use the single fallback limit captured at writer entry.
func postUploadFromContextRequestContext(ctx context.Context) (*postUpload, bool) {
	if ctx == nil {
		return nil, false
	}
	upload, ok := ctx.Value(postUploadContextKey{}).(*postUpload)
	return upload, ok && upload != nil
}

func objectWriteDeadline(in objectWriteInput) error {
	if in.Operation == "PostObject" && !in.Deadline.IsZero() && !time.Now().Before(in.Deadline) {
		return ErrRequestExpired
	}
	return nil
}

func objectPutOptionsNonzero(options s3.ObjectPutOptions) bool {
	return options.StorageClass != "" || options.WebsiteRedirectLocation != "" || options.SSE != nil
}

func hasCustomerSSE(options s3.ObjectPutOptions) bool {
	return options.SSE != nil && options.SSE.Customer != nil
}

func nilWriteDependency(value interface{}) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

func putObjectWriteS3Error(err error, resource, bucket, key string) *S3Error {
	if err == nil {
		return nil
	}
	var failure *objectWriteError
	if !errors.As(err, &failure) {
		return TranslateError(err, bucket, key)
	}
	switch failure.stage {
	case objectWriteBackend:
		if errors.Is(failure.err, s3.ErrNotImplemented) {
			return classifyPostError(failure.err, resource)
		}
		return TranslateError(failure.err, bucket, key)
	case objectWriteInvalid:
		return classifyPostError(failure.err, resource)
	case objectWritePreparation:
		if errors.Is(failure.err, ErrPostEntityTooLarge) || errors.Is(failure.err, ErrSpoolCapacity) || errors.Is(failure.err, ErrSpoolRequestLimit) || errors.Is(failure.err, ErrRequestExpired) || errors.Is(failure.err, ErrStreamingCanceled) {
			return classifyPostError(failure.err, resource)
		}
		return &S3Error{Code: "InternalError", Message: "Failed to prepare object for upload", Resource: resource, HTTPStatus: http.StatusInternalServerError}
	case objectWriteCrypto:
		return &S3Error{Code: "InternalError", Message: "Failed to encrypt object", Resource: resource, HTTPStatus: http.StatusInternalServerError}
	case objectWriteClassify:
		return decryptFailure(failure.err, resource)
	default:
		return &S3Error{Code: "InternalError", Message: "Failed to prepare object for upload", Resource: resource, HTTPStatus: http.StatusInternalServerError}
	}
}
