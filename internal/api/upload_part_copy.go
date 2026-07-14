package api

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/mpu"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// SourceClass defines the type of encryption (if any) on the source object
// of an UploadPartCopy request. Each class maps to a distinct strategy in
// handleUploadPartCopy; see docs/adr/0006-upload-part-copy.md §Decision #3.
type SourceClass int

const (
	SourceClassPlaintext SourceClass = iota
	SourceClassChunked
	SourceClassLegacy
	// SourceClassMPUEncrypted is an object that was assembled via the gateway's
	// encrypted multipart upload path (MetaMPUEncrypted = "true"). Its bytes are
	// a concatenation of independently AEAD-encrypted chunks whose DEK + manifest
	// live in the companion .mpu-manifest object. It must be decrypted via
	// decryptMPUObject before being re-encrypted into the destination upload.
	SourceClassMPUEncrypted
)

// String returns the short metric-safe label for a SourceClass.
func (c SourceClass) String() string {
	switch c {
	case SourceClassChunked:
		return "chunked"
	case SourceClassLegacy:
		return "legacy"
	case SourceClassMPUEncrypted:
		return "mpu_encrypted"
	default:
		return "plaintext"
	}
}

// CopySourceMetadata holds classification info for the source object.
type CopySourceMetadata struct {
	Class       SourceClass
	Size        int64
	IsChunked   bool
	IsEncrypted bool
}

// CopyPartResultXML is the XML response body for UploadPartCopy.
// See https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html
type CopyPartResultXML struct {
	XMLName      xml.Name `xml:"CopyPartResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// S3 per-part limits per
// https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html
const (
	// maxCopySourceSizeBytes is the S3-enforced upper bound on a single
	// UploadPartCopy source when no range is provided (5 GiB).
	maxCopySourceSizeBytes int64 = 5 * 1024 * 1024 * 1024
	// maxCopyPartRangeBytes is the maximum span of a single
	// x-amz-copy-source-range (5 GiB).
	maxCopyPartRangeBytes int64 = 5 * 1024 * 1024 * 1024
)

// handleUploadPartCopy handles UploadPartCopy requests (PUT with
// x-amz-copy-source header on a multipart part URL).
//
// Invariants preserved by this handler (see ADR 0006):
//  1. Destination parts are plaintext (ADR 0002). No per-part encryption.
//  2. Source-bucket READ authorisation is enforced implicitly because the
//     same caller-derived S3 client (from h.getS3Client(r)) performs the
//     HeadObject/GetObject. A caller without read access on the source
//     surfaces AccessDenied from the backend, which TranslateError maps to
//     HTTP 403.
//  3. If the destination bucket policy sets RequireEncryption=true and the
//     classified source is plaintext, the handler hard-refuses with 500
//     InternalError (destination-policy / source-mode mismatch) and emits
//     an audit event. This prevents silent security degradation from
//     config drift; see ADR 0006 §"Config Mismatch Detection".
//  4. The legacy fallback path is bounded by Server.MaxLegacyCopySourceBytes
//     (default 256 MiB, opt-out safety posture).
func (h *Handler) handleUploadPartCopy(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	bucket := vars["bucket"]
	key := vars["key"]
	uploadID := vars["uploadId"]
	partNumberStr := vars["partNumber"]

	// These should already be validated in handleUploadPart, but double-check.
	if bucket == "" || key == "" || uploadID == "" || partNumberStr == "" {
		s3Err := ErrInvalidRequest
		s3Err.Resource = r.URL.Path
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Check if multipart uploads are disabled.
	if h.config != nil && h.config.Server.DisableMultipartUploads {
		s3Err := &S3Error{
			Code:       "NotImplemented",
			Message:    "Multipart uploads are disabled",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusNotImplemented,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Fail closed if policy requires encrypted MPU but infra is missing.
	if h.mpuGuardMisconfig(w, r, bucket, "PUT", start) {
		return
	}

	partNumber, err := strconv.ParseInt(partNumberStr, 10, 32)
	if err != nil || partNumber < 1 {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Invalid part number",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	ctx := r.Context()

	// Get S3 client. The caller's credentials are already validated by
	// AuthMiddleware before reaching this handler; source-bucket read
	// authorisation is enforced by the backend using the gateway's
	// configured backend credentials.
	s3Client, err := h.getS3Client(r)
	if err != nil {
		h.logger.WithError(err).Error("Failed to get S3 client")
		h.writeS3ClientError(w, r, err, "PUT", start)
		return
	}

	// Parse x-amz-copy-source header.
	copySource := r.Header.Get("x-amz-copy-source")
	if copySource == "" {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Missing x-amz-copy-source header",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	srcBucket, srcKey, srcVersionID, err := parseCopySource(copySource)
	if err != nil {
		s3Err := &S3Error{
			Code:       "InvalidArgument",
			Message:    "Invalid x-amz-copy-source header",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Parse optional x-amz-copy-source-range header.
	var srcRange *s3.CopyPartRange
	rangeHeader := r.Header.Get("x-amz-copy-source-range")
	if rangeHeader != "" {
		start64, end64, perr := crypto.ParseHTTPRangeHeader(rangeHeader, -1)
		if perr != nil {
			s3Err := &S3Error{
				Code:       "InvalidArgument",
				Message:    "Invalid x-amz-copy-source-range header",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadRequest,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		if end64-start64+1 > maxCopyPartRangeBytes {
			s3Err := &S3Error{
				Code:       "InvalidRequest",
				Message:    "The specified copy-source-range exceeds the maximum allowable size (5 GiB)",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadRequest,
			}
			s3Err.WriteXML(w)
			h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
			return
		}
		srcRange = &s3.CopyPartRange{
			First: start64,
			Last:  end64,
		}
	}

	// Classify the source object. This issues a single HeadObject using the
	// caller's credentials, so an unauthorised caller gets AccessDenied
	// (HTTP 403) from the backend — this is the source-bucket READ
	// authorisation gate.
	sourceClass, err := h.classifyCopySource(ctx, s3Client, srcBucket, srcKey, srcVersionID)
	if err != nil {
		s3Err := TranslateError(err, srcBucket, srcKey)
		s3Err.WriteXML(w)
		h.logger.WithError(err).WithFields(logrus.Fields{
			"src_bucket": srcBucket,
			"src_key":    srcKey,
		}).Error("Failed to classify copy source")
		// Source-scoped error: record with the source bucket label for
		// debuggability.
		h.metrics.RecordS3Error(r.Context(), "UploadPartCopy", srcBucket, s3Err.Code)
		h.metrics.RecordUploadPartCopy("unknown", "error", 0, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Enforce 5 GiB cap on source size when no range is provided.
	// S3 requires UploadPartCopy with source > 5 GiB to specify a range.
	if srcRange == nil && sourceClass.Size > 0 && sourceClass.Size > maxCopySourceSizeBytes {
		s3Err := &S3Error{
			Code:       "InvalidRequest",
			Message:    "The specified copy source is larger than the maximum allowable size for a copy source: 5368709120. Specify x-amz-copy-source-range.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusBadRequest,
		}
		s3Err.WriteXML(w)
		h.metrics.RecordUploadPartCopy(sourceClass.Class.String(), "error", 0, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Destination-policy / source-mode mismatch hard-refusal:
	// if the destination bucket policy mandates encryption but the source
	// is classified as plaintext, refuse. The plaintext fast path would
	// otherwise silently upload unencrypted bytes into a bucket policy says
	// must be encrypted. Per ADR 0006 §"Config Mismatch Detection" and
	// Real-World Cryptography (Wong, 2021) Ch. 16.
	if sourceClass.Class == SourceClassPlaintext && h.policyManager != nil && h.policyManager.BucketRequiresEncryption(bucket) {
		msg := "Destination bucket requires encryption but copy source is plaintext"
		h.logger.WithFields(logrus.Fields{
			"src_bucket": srcBucket,
			"src_key":    srcKey,
			"dst_bucket": bucket,
			"dst_key":    key,
		}).Error(msg)
		s3Err := &S3Error{
			Code:       "InternalError",
			Message:    "Destination bucket configuration requires encryption but the copy source is not encrypted.",
			Resource:   r.URL.Path,
			HTTPStatus: http.StatusInternalServerError,
		}
		s3Err.WriteXML(w)
		// Audit the refusal so operators see config-drift incidents.
		if h.auditLogger != nil {
			h.auditLogger.LogAccessWithMetadata(
				"copy_part_refused", bucket, key,
				getClientIP(r), r.UserAgent(), getRequestID(r),
				false, fmt.Errorf("%s", msg), time.Since(start),
				map[string]interface{}{
					"src_bucket":  srcBucket,
					"src_key":     srcKey,
					"src_version": versionIDValue(srcVersionID),
					"src_mode":    "plaintext",
					"upload_id":   uploadID,
					"part_number": partNumber,
					"reason":      "destination_requires_encryption",
				},
			)
		}
		h.metrics.RecordS3Error(r.Context(), "UploadPartCopy", bucket, s3Err.Code)
		h.metrics.RecordUploadPartCopy("plaintext", "error", 0, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Execute the appropriate strategy based on source class.
	var (
		copyResult   *s3.CopyPartResult
		strategyErr  error
		bytesCopied  int64
		sourceMode   = sourceClass.Class.String()
		maxLegacyCap = effectiveMaxLegacyCopySourceBytes(h.config)
	)

	// When the destination is an encrypted MPU, the backend-native UploadPartCopy
	// fast path is disabled. All source classes are decrypted and re-encrypted
	// through the destination's per-upload DEK schedule (ADR 0009 §Consequences).
	if h.bucketEncryptsMPU(bucket) {
		copyResult, bytesCopied, strategyErr = h.uploadPartCopyReencryptMPU(ctx, s3Client, bucket, key, uploadID,
			int32(partNumber), srcBucket, srcKey, srcVersionID, srcRange, sourceClass, maxLegacyCap, maxCopyPartRangeBytes)
	} else {
		switch sourceClass.Class {
		case SourceClassPlaintext:
			copyResult, strategyErr = s3Client.UploadPartCopy(ctx, bucket, key, uploadID, int32(partNumber),
				srcBucket, srcKey, srcVersionID, srcRange)
			if strategyErr == nil {
				bytesCopied = plaintextCopiedBytes(srcRange, sourceClass.Size)
			}

		case SourceClassChunked:
			copyResult, bytesCopied, strategyErr = h.uploadPartCopyChunked(ctx, s3Client, bucket, key, uploadID, int32(partNumber),
				srcBucket, srcKey, srcVersionID, srcRange, maxCopyPartRangeBytes)

		case SourceClassLegacy:
			copyResult, bytesCopied, strategyErr = h.uploadPartCopyLegacy(ctx, s3Client, bucket, key, uploadID, int32(partNumber),
				srcBucket, srcKey, srcVersionID, srcRange, sourceClass.Size, maxLegacyCap)

		case SourceClassMPUEncrypted:
			// Copy an MPU-encrypted source into a non-encrypted-MPU destination.
			// Decrypt the source via its manifest and forward the plaintext part.
			copyResult, bytesCopied, strategyErr = h.uploadPartCopyFromMPUSource(ctx, s3Client, bucket, key, uploadID, int32(partNumber),
				srcBucket, srcKey, srcVersionID, srcRange, maxLegacyCap)
		}
	}

	if strategyErr != nil {
		s3Err := TranslateError(strategyErr, bucket, key)
		// Promote sentinel errors to specific S3 codes.
		if isLegacySourceTooLarge(strategyErr) {
			s3Err = &S3Error{
				Code: "InvalidRequest",
				Message: fmt.Sprintf(
					"Legacy-encrypted copy source exceeds the gateway's in-memory cap (%d bytes). "+
						"Migrate the source to chunked encryption, or raise Server.MaxLegacyCopySourceBytes with adequate pod memory.",
					maxLegacyCap),
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusBadRequest,
			}
		} else if isRangeNotSatisfiable(strategyErr) {
			s3Err = &S3Error{
				Code:       "InvalidRange",
				Message:    "The requested range is not satisfiable",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusRequestedRangeNotSatisfiable,
			}
		} else if errors.Is(strategyErr, errMPUStateUnavailable) {
			// Audit/metrics already recorded in uploadPartCopyReencryptMPU.
			s3Err = &S3Error{
				Code:       "ServiceUnavailable",
				Message:    "Multipart encryption state store unavailable; retry the part upload",
				Resource:   r.URL.Path,
				HTTPStatus: http.StatusServiceUnavailable,
			}
		}
		s3Err.WriteXML(w)
		h.logger.WithError(strategyErr).WithFields(logrus.Fields{
			"bucket":      bucket,
			"key":         key,
			"uploadID":    uploadID,
			"partNumber":  partNumber,
			"srcBucket":   srcBucket,
			"srcKey":      srcKey,
			"source_mode": sourceMode,
			"duration_ms": time.Since(start).Milliseconds(),
		}).Error("UploadPartCopy strategy failed")
		h.metrics.RecordS3Error(r.Context(), "UploadPartCopy", bucket, s3Err.Code)
		h.metrics.RecordUploadPartCopy(sourceMode, "error", 0, time.Since(start))
		h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, s3Err.HTTPStatus, time.Since(start), 0)
		return
	}

	// Log successful copy with structured fields.
	h.logger.WithFields(logrus.Fields{
		"src_bucket":   srcBucket,
		"src_key":      srcKey,
		"src_version":  versionIDValue(srcVersionID),
		"src_range":    formatRangeForLog(srcRange),
		"src_mode":     sourceMode,
		"dst_bucket":   bucket,
		"dst_key":      key,
		"upload_id":    uploadID,
		"part_number":  partNumber,
		"dst_etag":     copyResult.ETag,
		"bytes_copied": bytesCopied,
		"duration_ms":  time.Since(start).Milliseconds(),
	}).Info("UploadPartCopy completed")

	// Record metrics.
	h.metrics.RecordS3Operation(r.Context(), "UploadPartCopy", bucket, time.Since(start))
	h.metrics.RecordUploadPartCopy(sourceMode, "ok", bytesCopied, time.Since(start))

	// Audit the successful copy with full metadata.
	if h.auditLogger != nil {
		auditMetadata := map[string]interface{}{
			"src_bucket":   srcBucket,
			"src_key":      srcKey,
			"src_version":  versionIDValue(srcVersionID),
			"src_mode":     sourceMode,
			"upload_id":    uploadID,
			"part_number":  partNumber,
			"dst_etag":     copyResult.ETag,
			"bytes_copied": bytesCopied,
		}
		if srcRange != nil {
			auditMetadata["src_range"] = map[string]int64{"first": srcRange.First, "last": srcRange.Last}
		}
		h.auditLogger.LogAccessWithMetadata(
			"copy_part", bucket, key,
			getClientIP(r), r.UserAgent(), getRequestID(r),
			true, nil, time.Since(start), auditMetadata,
		)
	}

	// Return CopyPartResult XML.
	result := CopyPartResultXML{
		ETag:         copyResult.ETag,
		LastModified: copyResult.LastModified.UTC().Format("2006-01-02T15:04:05.000Z"),
	}

	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_ = xml.NewEncoder(w).Encode(result)

	h.metrics.RecordHTTPRequest(r.Context(), "PUT", r.URL.Path, http.StatusOK, time.Since(start), 0)
}

// classifyCopySource determines the encryption class of the source object
// using a single HeadObject call. The HeadObject is issued with the
// caller's credentials (via the provided s3Client), so unauthorised callers
// surface AccessDenied here and short-circuit the copy.
func (h *Handler) classifyCopySource(ctx context.Context, s3Client s3.Client, bucket, key string, versionID *string) (*CopySourceMetadata, error) {
	metadata, err := s3Client.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		return nil, err
	}

	sourceClass := &CopySourceMetadata{
		Class: SourceClassPlaintext,
	}

	// Check MPU before the generic encrypted marker. MPU objects may carry
	// MetaEncrypted as well as MetaMPUEncrypted, but they are not legacy
	// single-AEAD objects and must use the manifest-backed MPU path.
	if metadata[crypto.MetaMPUEncrypted] == "true" {
		// Object was assembled via the gateway's encrypted multipart upload
		// path. Its ciphertext is a concatenation of AEAD-encrypted chunks;
		// the plaintext DEK and manifest live in a companion .mpu-manifest
		// object. Must not be treated as plaintext or legacy ciphertext.
		sourceClass.Class = SourceClassMPUEncrypted
		sourceClass.IsEncrypted = true
	} else if metadata[crypto.MetaChunkedFormat] == "true" {
		sourceClass.Class = SourceClassChunked
		sourceClass.IsChunked = true
		sourceClass.IsEncrypted = true
	} else if metadata[crypto.MetaEncrypted] == "true" {
		sourceClass.Class = SourceClassLegacy
		sourceClass.IsEncrypted = true
	}

	// Object size is available from Content-Length or OriginalSize (chunked)
	// depending on the source format.
	if sizeStr, ok := metadata["Content-Length"]; ok {
		if size, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
			sourceClass.Size = size
		}
	}
	if sourceClass.Size == 0 {
		if origSize, ok := metadata[crypto.MetaOriginalSize]; ok {
			if size, err := strconv.ParseInt(origSize, 10, 64); err == nil {
				sourceClass.Size = size
			}
		}
	}

	return sourceClass, nil
}

// uploadPartCopyChunked handles UploadPartCopy for chunked-encrypted sources.
// DecryptRange is invoked with absolute plaintext offsets; it seeks within
// the encrypted stream using the manifest carried in metadata. Bounded
// memory: one chunk + transfer buffer (chunk size ≤ 1 MiB per chunked.go).
func (h *Handler) uploadPartCopyChunked(ctx context.Context, s3Client s3.Client,
	dstBucket, dstKey, uploadID string, partNumber int32,
	srcBucket, srcKey string, srcVersionID *string, srcRange *s3.CopyPartRange,
	maxChunkedCap int64,
) (*s3.CopyPartResult, int64, error) {

	srcEngine, err := h.getEncryptionEngine(srcBucket)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get source encryption engine: %w", err)
	}

	srcMetadata, err := s3Client.HeadObject(ctx, srcBucket, srcKey, srcVersionID)
	if err != nil {
		return nil, 0, err
	}

	// Determine plaintext range. When no source range is specified, copy
	// the full object (bounded by plaintext size from metadata).
	plaintextSize, _ := crypto.GetPlaintextSizeFromMetadata(srcMetadata)
	var plaintextStart, plaintextEnd int64
	if srcRange != nil {
		plaintextStart = srcRange.First
		plaintextEnd = srcRange.Last
		// Explicit 416 for out-of-range source-range against chunked sources.
		if plaintextSize > 0 && plaintextStart >= plaintextSize {
			return nil, 0, errRangeNotSatisfiable
		}
		// Clamp end to last valid byte (AWS behaviour).
		if plaintextSize > 0 && plaintextEnd >= plaintextSize {
			plaintextEnd = plaintextSize - 1
		}
	} else {
		if plaintextSize <= 0 {
			return nil, 0, fmt.Errorf("cannot determine plaintext size for chunked source")
		}
		plaintextStart = 0
		plaintextEnd = plaintextSize - 1
	}

	// DecryptRange assumes the source reader contains the FULL encrypted
	// object (see range_decrypt.go: it skips startChunk*encryptedChunkSize
	// bytes from the source before decoding). We therefore fetch the full
	// object, not a pre-ranged slice. The memory cost is bounded by the
	// server's MaxLegacyCopySourceBytes cap; chunked streaming keeps peak
	// heap well below the full ciphertext size.
	srcReader, _, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get source object: %w", err)
	}
	defer srcReader.Close()

	// DecryptRange uses the manifest in metadata to seek within the encrypted
	// stream and emits plaintext for the requested absolute range.
	decryptedReader, _, err := srcEngine.DecryptRange(ctx, srcReader, srcMetadata, plaintextStart, plaintextEnd)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt range: %w", err)
	}

	// Buffer into a seekable reader. Required because the backend SDK's SigV4
	// signer must seek the body to compute the payload hash over plaintext HTTP.
	// V1.0-SEC-29: bound the read to maxCopyPartRangeBytes (5 GiB, the S3 per-part
	// maximum). DecryptRange already clips the output to the requested plaintext
	// slice, so a well-formed request will never hit this limit; the guard
	// prevents a crafted or corrupt source from exhausting heap memory.
	decryptedBytes, err := io.ReadAll(io.LimitReader(decryptedReader, maxChunkedCap+1))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read decrypted range: %w", err)
	}
	if int64(len(decryptedBytes)) > maxChunkedCap {
		return nil, 0, fmt.Errorf("decrypted range exceeds maximum copy-part size (%d bytes)", maxChunkedCap)
	}
	bytesCopied := int64(len(decryptedBytes))
	etag, err := s3Client.UploadPart(ctx, dstBucket, dstKey, uploadID, partNumber, bytes.NewReader(decryptedBytes), &bytesCopied)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to upload part: %w", err)
	}

	return &s3.CopyPartResult{
		ETag:         etag,
		LastModified: time.Now(),
	}, bytesCopied, nil
}

// uploadPartCopyLegacy handles UploadPartCopy for legacy (non-chunked)
// encrypted sources. Must buffer the full object in memory because legacy
// format is a single AEAD stream that cannot be range-decrypted. Bounded
// by Server.MaxLegacyCopySourceBytes (default 256 MiB, opt-out safety
// posture — see ADR 0006 §"Why Legacy Fallback Has a Configurable Cap").
func (h *Handler) uploadPartCopyLegacy(ctx context.Context, s3Client s3.Client,
	dstBucket, dstKey, uploadID string, partNumber int32,
	srcBucket, srcKey string, srcVersionID *string, srcRange *s3.CopyPartRange,
	srcSizeHint int64, maxLegacyCap int64,
) (*s3.CopyPartResult, int64, error) {

	// Pre-flight cap check using the Content-Length from classification if
	// available. Avoids starting a large download we will refuse.
	if srcSizeHint > 0 && srcSizeHint > maxLegacyCap {
		return nil, 0, errLegacySourceTooLarge
	}

	srcEngine, err := h.getEncryptionEngine(srcBucket)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get source encryption engine: %w", err)
	}

	srcReader, srcMetadata, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		return nil, 0, err
	}
	defer srcReader.Close()

	decryptedReader, _, err := srcEngine.Decrypt(ctx, srcReader, srcMetadata)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to decrypt source object: %w", err)
	}

	// V0.6-PERF-1 / V1.0-SEC-29: intentionally buffered — legacy AEAD is a
	// single-nonce envelope that cannot be authenticated before reading the
	// whole ciphertext (RFC 5116 / *Serious Cryptography, 2nd Ed.* §8.4
	// commit-before-release rule). Streaming is non-trivially incorrect here.
	// The LimitReader caps the allocation at maxLegacyCap+1
	// (Server.MaxLegacyCopySourceBytes, default 256 MiB); reading one byte
	// past the cap lets us distinguish "exactly at limit" from "over limit".
	limited := io.LimitReader(decryptedReader, maxLegacyCap+1)
	plaintextData, err := io.ReadAll(limited)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read decrypted source: %w", err)
	}
	if int64(len(plaintextData)) > maxLegacyCap {
		return nil, 0, errLegacySourceTooLarge
	}

	if h.logger != nil {
		h.logger.WithFields(logrus.Fields{
			"src_bucket":        srcBucket,
			"src_key":           srcKey,
			"object_size_bytes": len(plaintextData),
			"max_cap_bytes":     maxLegacyCap,
		}).Warn("UploadPartCopy using legacy (non-chunked) source; full-object decryption required (slow path)")
	}

	// Slice the requested range if provided.
	var partData []byte
	if srcRange != nil {
		if srcRange.First >= int64(len(plaintextData)) {
			return nil, 0, errRangeNotSatisfiable
		}
		end := srcRange.Last + 1
		if end > int64(len(plaintextData)) {
			end = int64(len(plaintextData))
		}
		partData = plaintextData[srcRange.First:end]
	} else {
		partData = plaintextData
	}

	partLen := int64(len(partData))
	etag, err := s3Client.UploadPart(ctx, dstBucket, dstKey, uploadID, partNumber, bytes.NewReader(partData), &partLen)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to upload part: %w", err)
	}

	return &s3.CopyPartResult{
		ETag:         etag,
		LastModified: time.Now(),
	}, int64(len(partData)), nil
}

// --- sentinel errors & helpers ---

var (
	errLegacySourceTooLarge = fmt.Errorf("legacy copy source exceeds gateway cap")
	errRangeNotSatisfiable  = fmt.Errorf("range not satisfiable")
	errMPUStateUnavailable  = fmt.Errorf("mpu state store unavailable")
)

func isLegacySourceTooLarge(err error) bool {
	return err != nil && errors.Is(err, errLegacySourceTooLarge)
}

func isMPUStateUnavailable(err error) bool {
	return err != nil && errors.Is(err, errMPUStateUnavailable)
}

func isRangeNotSatisfiable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errRangeNotSatisfiable) {
		return true
	}
	// Also catch the string emitted by engine.DecryptRange for out-of-range
	// source-range against chunked sources.
	return strings.Contains(err.Error(), "range not satisfiable")
}

// effectiveMaxLegacyCopySourceBytes returns the configured cap, falling back
// to the conservative default (256 MiB) if unconfigured or ≤ 0.
func effectiveMaxLegacyCopySourceBytes(cfg *config.Config) int64 {
	if cfg != nil && cfg.Server.MaxLegacyCopySourceBytes > 0 {
		return cfg.Server.MaxLegacyCopySourceBytes
	}
	return config.DefaultMaxLegacyCopySourceBytes
}

// plaintextCopiedBytes returns the number of plaintext bytes a plaintext-
// fast-path copy transferred. Used for the bytes_total metric. When the
// backend performed the copy and we don't have authoritative sizing, we
// approximate from the range or Content-Length.
func plaintextCopiedBytes(srcRange *s3.CopyPartRange, srcSize int64) int64 {
	if srcRange != nil {
		return srcRange.Last - srcRange.First + 1
	}
	if srcSize > 0 {
		return srcSize
	}
	return 0
}

// formatRangeForLog formats a CopyPartRange for structured logging.
func formatRangeForLog(r *s3.CopyPartRange) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf("bytes=%d-%d", r.First, r.Last)
}

// versionIDValue dereferences an optional version ID for log/audit output.
func versionIDValue(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

// uploadPartCopyReencryptMPU handles UploadPartCopy when the destination bucket
// has EncryptMultipartUploads=true. It decrypts the source (using the per-class
// strategy) and re-encrypts through the destination's per-upload DEK schedule.
// The backend-native UploadPartCopy fast path is intentionally disabled here
// because it would write unencrypted bytes to an encrypted MPU destination.
func (h *Handler) uploadPartCopyReencryptMPU(
	ctx context.Context,
	s3Client s3.Client,
	dstBucket, dstKey, uploadID string,
	partNumber int32,
	srcBucket, srcKey string,
	srcVersionID *string,
	srcRange *s3.CopyPartRange,
	sourceClass *CopySourceMetadata,
	maxLegacyCap int64,
	maxChunkedCap int64,
) (*s3.CopyPartResult, int64, error) {
	// Step 1: Obtain the plaintext bytes from the source using the per-class decrypt strategy.
	var plaintextData []byte
	var err error

	switch sourceClass.Class {
	case SourceClassPlaintext:
		var rangeHdr *string
		if srcRange != nil {
			rh := fmt.Sprintf("bytes=%d-%d", srcRange.First, srcRange.Last)
			rangeHdr = &rh
		}
		r, _, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, rangeHdr)
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: get plaintext source: %w", err)
		}
		defer r.Close()
		// V1.0-SEC-29: LimitReader caps at maxLegacyCap+1 so we can detect over-limit
		// objects and return errLegacySourceTooLarge rather than exhausting heap.
		plaintextData, err = io.ReadAll(io.LimitReader(r, maxLegacyCap+1))
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: read plaintext source: %w", err)
		}
		if int64(len(plaintextData)) > maxLegacyCap {
			return nil, 0, errLegacySourceTooLarge
		}

	case SourceClassChunked:
		srcEngine, err := h.getEncryptionEngine(srcBucket)
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: get src engine: %w", err)
		}
		srcMeta, err := s3Client.HeadObject(ctx, srcBucket, srcKey, srcVersionID)
		if err != nil {
			return nil, 0, err
		}
		plaintextSize, _ := crypto.GetPlaintextSizeFromMetadata(srcMeta)
		var pStart, pEnd int64
		if srcRange != nil {
			pStart, pEnd = srcRange.First, srcRange.Last
			if plaintextSize > 0 && pEnd >= plaintextSize {
				pEnd = plaintextSize - 1
			}
		} else {
			if plaintextSize <= 0 {
				return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: cannot determine plaintext size")
			}
			pEnd = plaintextSize - 1
		}
		// DecryptRange expects the source reader to contain the FULL encrypted
		// object — see uploadPartCopyChunked for rationale.
		r, _, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: get chunked source: %w", err)
		}
		defer r.Close()
		decR, _, err := srcEngine.DecryptRange(ctx, r, srcMeta, pStart, pEnd)
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: decrypt chunked source: %w", err)
		}
		// V1.0-SEC-29: bound to maxCopyPartRangeBytes (5 GiB). DecryptRange already
		// clips output to the requested plaintext slice; this guard prevents a
		// crafted/corrupt source from exhausting heap memory.
		plaintextData, err = io.ReadAll(io.LimitReader(decR, maxChunkedCap+1))
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: read decrypted chunked source: %w", err)
		}
		if int64(len(plaintextData)) > maxChunkedCap {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: decrypted chunked range exceeds maximum copy-part size (%d bytes)", maxChunkedCap)
		}

	case SourceClassMPUEncrypted:
		// Harbor supplies a plaintext source range for each destination part.
		// Decrypt only that range. Reading the entire staging blob here caused
		// every copy-part request to hit the legacy 256 MiB cap, even though the
		// source itself was an encrypted MPU and each destination part was only
		// 10 MiB.
		plaintextData, err = h.readMPUPlaintextRange(ctx, s3Client, srcBucket, srcKey, srcVersionID, srcRange)
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: read mpu source range: %w", err)
		}

	case SourceClassLegacy:
		srcEngine, err := h.getEncryptionEngine(srcBucket)
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: get src engine: %w", err)
		}
		r, srcMeta, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
		if err != nil {
			return nil, 0, err
		}
		defer r.Close()
		decR, _, err := srcEngine.Decrypt(ctx, r, srcMeta)
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: decrypt legacy source: %w", err)
		}
		// V1.0-SEC-29: same rationale as SourceClassPlaintext above — LimitReader
		// ensures the legacy buffering cap is enforced even after decryption.
		plaintextData, err = io.ReadAll(io.LimitReader(decR, maxLegacyCap+1))
		if err != nil {
			return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: read decrypted legacy: %w", err)
		}
		if int64(len(plaintextData)) > maxLegacyCap {
			return nil, 0, errLegacySourceTooLarge
		}
		if srcRange != nil {
			start, end := srcRange.First, srcRange.Last
			if end >= int64(len(plaintextData)) {
				end = int64(len(plaintextData)) - 1
			}
			plaintextData = plaintextData[start : end+1]
		}
	}

	// Step 2: Re-encrypt via the destination MPU DEK schedule.
	encReader, encLen, err := h.encryptMPUPart(ctx, dstBucket, uploadID, partNumber, bytes.NewReader(plaintextData), int64(len(plaintextData)))
	if err != nil {
		return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: re-encrypt: %w", err)
	}

	// V0.6-PERF-1: intentionally buffered — the backend SDK requires a seekable
	// body for SigV4 payload hashing over plaintext-HTTP (see Phase D of the
	// PERF-1 plan). encReader is now a streaming mpuEncryptReader (Phase G);
	// buffering it here to obtain a *bytes.Reader is unavoidable without
	// backend streaming-checksum support (D-1, deferred). The allocation is
	// bounded by encLen (≤ MaxPartBuffer; enforced upstream in the handler).
	encBytes, err := io.ReadAll(encReader)
	if err != nil {
		return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: read re-encrypted part: %w", err)
	}
	if int64(len(encBytes)) != encLen {
		return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: encrypted length mismatch: got %d, expected %d", len(encBytes), encLen)
	}
	etag, err := s3Client.UploadPart(ctx, dstBucket, dstKey, uploadID, partNumber, bytes.NewReader(encBytes), &encLen)
	if err != nil {
		return nil, 0, fmt.Errorf("uploadPartCopyReencryptMPU: upload re-encrypted part: %w", err)
	}

	// Persist the part record. Fail-closed: a state-store hiccup here must
	// return 503 so the client retries, matching handlers.go:2730-2757.
	chunkCount := int32((int64(len(plaintextData)) + int64(crypto.DefaultChunkSize) - 1) / int64(crypto.DefaultChunkSize)) // #nosec G115 — max ~82k for 5 GiB parts, fits int32
	if appendErr := h.mpuStateStore.AppendPart(ctx, uploadID, mpu.PartRecord{
		PartNumber: partNumber,
		ETag:       etag,
		PlainLen:   int64(len(plaintextData)),
		EncLen:     encLen,
		ChunkCount: chunkCount,
	}); appendErr != nil {
		h.logger.WithError(appendErr).WithFields(logrus.Fields{
			"bucket":     dstBucket,
			"key":        dstKey,
			"uploadID":   uploadID,
			"partNumber": partNumber,
		}).Error("mpu.append_part.failure: backend part written but state not recorded; returning 503 so client retries")
		h.metrics.RecordS3Error(ctx, "AppendMPUPartState", dstBucket, "StateUnavailable")
		if h.auditLogger != nil {
			h.auditLogger.Log(&audit.AuditEvent{
				EventType: audit.EventTypeMPUValkeyUnavail,
				Timestamp: time.Now().UTC(),
				Bucket:    dstBucket,
				Key:       dstKey,
				Success:   false,
				Metadata:  map[string]interface{}{"upload_id": uploadID},
			})
		}
		return nil, 0, errMPUStateUnavailable
	}

	return &s3.CopyPartResult{
		ETag:         etag,
		LastModified: time.Now(),
	}, int64(len(plaintextData)), nil
}

// readMPUPlaintextRange decrypts only the requested plaintext range from an
// encrypted MPU source. The manifest maps the range to the minimum complete
// ciphertext chunk span, so memory use is proportional to one copy part.
func (h *Handler) readMPUPlaintextRange(
	ctx context.Context,
	s3Client s3.Client,
	bucket, key string,
	versionID *string,
	srcRange *s3.CopyPartRange,
) ([]byte, error) {
	meta, err := s3Client.HeadObject(ctx, bucket, key, versionID)
	if err != nil {
		return nil, fmt.Errorf("head source: %w", err)
	}
	manifestKey := meta[crypto.MetaFallbackPointer]
	if manifestKey == "" {
		manifestKey = key + ".mpu-manifest"
	}
	manifestReader, manifestMeta, err := s3Client.GetObject(ctx, bucket, manifestKey, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("get manifest: %w", err)
	}
	defer manifestReader.Close()
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		return nil, err
	}
	plainManifest, _, err := engine.Decrypt(ctx, manifestReader, manifestMeta)
	if err != nil {
		return nil, fmt.Errorf("decrypt manifest: %w", err)
	}
	manifestJSON, err := io.ReadAll(plainManifest)
	if err != nil {
		return nil, err
	}
	manifest, err := crypto.UnmarshalMultipartManifest(manifestJSON)
	if err != nil {
		return nil, err
	}
	if srcRange == nil {
		srcRange = &s3.CopyPartRange{First: 0, Last: manifest.TotalPlainSize - 1}
	}
	pStart, pEnd, err := crypto.ParseHTTPRangeHeader(
		fmt.Sprintf("bytes=%d-%d", srcRange.First, srcRange.Last), manifest.TotalPlainSize)
	if err != nil {
		return nil, err
	}
	encRange, err := manifest.EncRangeForPlaintextRange(pStart, pEnd)
	if err != nil {
		return nil, err
	}
	backendRange := fmt.Sprintf("bytes=%d-%d", encRange.EncStart, encRange.EncEnd)
	r, _, err := s3Client.GetObject(ctx, bucket, key, versionID, &backendRange)
	if err != nil {
		return nil, fmt.Errorf("get ciphertext range: %w", err)
	}
	defer r.Close()
	ciphertext, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	dek, err := h.unwrapMPUDEKFromManifest(ctx, manifest, bucket, key)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dek)
	ivPrefix, err := hexToIVPrefix(manifest.IVPrefix)
	if err != nil {
		return nil, err
	}
	uploadIDHash, err := decodeBase64ToFixed32(manifest.UploadIDHash)
	if err != nil {
		return nil, err
	}
	const encTagSize = 16
	encChunkSize := manifest.ChunkSize + encTagSize
	var plaintext []byte
	consumed := 0
	for pi := encRange.PartStartIdx; pi <= encRange.PartEndIdx; pi++ {
		part := manifest.Parts[pi]
		first := int32(0)
		if pi == encRange.PartStartIdx {
			first = encRange.ChunkStart
		}
		last := part.ChunkCount - 1
		if pi == encRange.PartEndIdx {
			last = encRange.ChunkEnd
		}
		partLen := int(part.EncLen) - int(first)*encChunkSize
		if pi != encRange.PartEndIdx || last != part.ChunkCount-1 {
			partLen = int(last-first+1) * encChunkSize
		}
		if consumed+partLen > len(ciphertext) {
			partLen = len(ciphertext) - consumed
		}
		plain, err := crypto.DecryptMPUPartRange(ciphertext[consumed:consumed+partLen], dek, uploadIDHash, ivPrefix, part.PartNumber, manifest.ChunkSize, first, manifest.Algorithm)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, plain...)
		consumed += partLen
	}
	base := int64(0)
	for i := 0; i < encRange.PartStartIdx; i++ {
		base += manifest.Parts[i].PlainLen
	}
	base += int64(encRange.ChunkStart) * int64(manifest.ChunkSize)
	start := pStart - base
	end := pEnd - base
	if start < 0 || end >= int64(len(plaintext)) || start > end {
		return nil, fmt.Errorf("decrypted range slice %d-%d outside %d bytes", start, end, len(plaintext))
	}
	return plaintext[start : end+1], nil
}

// uploadPartCopyFromMPUSource handles UploadPartCopy when the source is an
// MPU-encrypted object (SourceClassMPUEncrypted) and the destination is NOT
// an encrypted-MPU bucket. It decrypts the source via its companion manifest
// and uploads the plaintext as a raw UploadPart to the destination.
func (h *Handler) uploadPartCopyFromMPUSource(
	ctx context.Context,
	s3Client s3.Client,
	dstBucket, dstKey, uploadID string,
	partNumber int32,
	srcBucket, srcKey string,
	srcVersionID *string,
	srcRange *s3.CopyPartRange,
	maxCap int64,
) (*s3.CopyPartResult, int64, error) {
	srcMeta, err := s3Client.HeadObject(ctx, srcBucket, srcKey, srcVersionID)
	if err != nil {
		return nil, 0, fmt.Errorf("uploadPartCopyFromMPUSource: head: %w", err)
	}
	r, _, err := s3Client.GetObject(ctx, srcBucket, srcKey, srcVersionID, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("uploadPartCopyFromMPUSource: get: %w", err)
	}
	defer r.Close()

	decR, err := h.decryptMPUObject(ctx, srcBucket, srcKey, srcMeta, r, s3Client)
	if err != nil {
		return nil, 0, fmt.Errorf("uploadPartCopyFromMPUSource: decrypt: %w", err)
	}
	plainData, err := io.ReadAll(io.LimitReader(decR, maxCap+1))
	if err != nil {
		return nil, 0, fmt.Errorf("uploadPartCopyFromMPUSource: read: %w", err)
	}
	if int64(len(plainData)) > maxCap {
		return nil, 0, errLegacySourceTooLarge
	}
	if srcRange != nil {
		start, end := srcRange.First, srcRange.Last
		if end >= int64(len(plainData)) {
			end = int64(len(plainData)) - 1
		}
		plainData = plainData[start : end+1]
	}
	bytesCopied := int64(len(plainData))
	etag, err := s3Client.UploadPart(ctx, dstBucket, dstKey, uploadID, partNumber,
		bytes.NewReader(plainData), &bytesCopied)
	if err != nil {
		return nil, 0, fmt.Errorf("uploadPartCopyFromMPUSource: upload: %w", err)
	}
	return &s3.CopyPartResult{ETag: etag}, bytesCopied, nil
}
