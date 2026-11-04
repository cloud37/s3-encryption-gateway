package api

import (
	"errors"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
	"github.com/gorilla/mux"
)

// handlePostObject consumes only the authenticated POST snapshot. It validates
// every scalar option and response input before reading the file, then waits for
// complete MIME/file/checksum validation before acquiring the backend client.
func (h *Handler) handlePostObject(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	if h == nil || w == nil || r == nil {
		return
	}
	upload, ok := postUploadFromContext(r)
	credential, hasCredential := CredentialFromContext(r)
	if r.URL == nil {
		writePostError(w, r, h, ErrPostFormMalformed, started)
		return
	}
	routeBucket := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if !isPostObjectRequest(r) || !ok || !hasCredential || upload.authenticatedAccessKey == "" || upload.authenticatedAccessKey != credential.AccessKey || !credential.CanWrite() || !credential.AllowsBucket(upload.bucket) || upload.bucket == "" || upload.bucket != routeBucket || upload.fields == nil || upload.file == nil || upload.fileRead == nil {
		writeAuthorizationDenied(w, r, h.auditLogger, "unknown_operation")
		return
	}
	if !upload.deadline.IsZero() && !time.Now().Before(upload.deadline) {
		writePostError(w, r, h, ErrRequestExpired, started)
		return
	}
	if h.proxiedBucket != "" && h.proxiedBucket != upload.bucket {
		writeAuthorizationDenied(w, r, h.auditLogger, "bucket_scope")
		return
	}
	formKey, hasKey := postFormField(upload.fields, "key", "")
	if !hasKey || formKey != upload.key {
		writeAuthorizationDenied(w, r, h.auditLogger, "unknown_operation")
		return
	}
	if err := (crypto.ObjectContext{Bucket: upload.bucket, Key: upload.key}).Validate(); err != nil {
		writePostError(w, r, h, ErrPostPolicyDenied, started)
		return
	}

	responseStatus, redirect, err := parsePostSuccess(upload.fields)
	if err != nil {
		writePostError(w, r, h, err, started)
		return
	}
	upload.successStatus, upload.redirect = responseStatus, redirect
	secure := r.TLS != nil || h.trustedIPExtractor != nil && !h.trustedIPExtractorInvalid && h.trustedIPExtractor.IsHTTPSRequest(r)
	if _, err := postObjectLocation(r, upload.bucket, upload.key, secure); err != nil {
		writePostError(w, r, h, ErrPostInvalidOption, started)
		return
	}
	if redirect != nil && !validPostRedirectURL(redirect) {
		// Parsed URLs are immutable request state; defend direct/misconstructed
		// contexts before file consumption and treat invalid redirects as absent.
		upload.redirect = nil
	}

	options, tags, acl, err := parsePostOptions(upload.fields)
	if err != nil {
		writePostError(w, r, h, err, started)
		return
	}
	// AuthMiddleware owns upload.Close for the full downstream lifetime. Publish
	// the request-scoped SSE key there before any later validation can fail.
	upload.options = options
	if h.config != nil && h.config.Backend.PostInlineTagging == "unsupported" {
		for name := range upload.fields {
			if asciiPostFold(name) == "tagging" {
				writePostError(w, r, h, ErrPostUnsupported, started)
				return
			}
		}
	}
	upload.checksum, err = parsePostChecksum(upload.fields)
	if err != nil {
		writePostError(w, r, h, err, started)
		return
	}
	if hasCustomerSSE(options) {
		if err := h.validateSSECustomerTransport(r); err != nil {
			writePostError(w, r, h, err, started)
			return
		}
	}
	metadataHeader := make(http.Header)
	for name, value := range upload.fields {
		folded := asciiPostFold(name)
		for _, standard := range objectmeta.Names {
			if folded == asciiPostFold(standard) {
				metadataHeader.Set(standard, value)
				break
			}
		}
		if strings.HasPrefix(folded, "x-amz-meta-") {
			metadataHeader[textproto.CanonicalMIMEHeaderKey(name)] = []string{value}
		}
	}
	metadata, metadataErr := parseWriteMetadata(metadataHeader)
	if metadataErr != nil {
		writePostError(w, r, h, ErrPostInvalidOption, started)
		return
	}
	if metadata.Standard.ContentType == "" {
		metadata.Standard.ContentType = "application/octet-stream"
	}
	globalLimit := upload.limitSnapshot.Global
	if globalLimit <= 0 {
		globalLimit = postDefaultFileLimit
	}
	manager := h.spoolManager
	if manager == nil {
		manager = DefaultSpoolManager()
	}
	validated, err := spoolPostFile(r.Context(), upload, manager, globalLimit)
	if err != nil {
		writePostError(w, r, h, err, started)
		return
	}
	if err := r.Context().Err(); err != nil {
		writePostError(w, r, h, ErrStreamingCanceled, started)
		return
	}
	if !upload.deadline.IsZero() && !time.Now().Before(upload.deadline) {
		writePostError(w, r, h, ErrRequestExpired, started)
		return
	}
	client, err := h.getS3Client(r)
	if err != nil {
		writePostClientAcquisitionError(w, r, h, upload, err, started)
		return
	}
	input := objectWriteInput{
		Bucket: upload.bucket, Key: upload.key, Operation: "PostObject", Body: validated.body,
		PlainLength: validated.length, HaveLength: true, Metadata: metadata, PlainETag: validated.md5Hex,
		Tags: tags, ACL: acl, Options: upload.options, Deadline: upload.deadline,
	}
	result, writeErr := h.putObjectData(r.Context(), client, input)
	if writeErr != nil {
		writePostError(w, r, h, writeErr, started)
		return
	}
	if h.metrics != nil {
		h.metrics.RecordS3Operation(r.Context(), "PostObject", upload.bucket, time.Since(started))
	}
	if err := h.writePostSuccess(w, r, upload, result, validated.responseChecksums); err != nil {
		// The response may already be committed. Never attempt a second S3 error
		// response; the deferred authenticated upload owner cleans up plaintext
		// and the request-scoped customer key.
		if h.logger != nil {
			h.logger.WithField("operation", "PostObject").Warn("POST response write failed")
		}
	}
}

func writePostError(w http.ResponseWriter, r *http.Request, h *Handler, err error, started time.Time) {
	if h == nil || r == nil || w == nil {
		return
	}
	var writeFailure *objectWriteError
	resource := ""
	if r.URL != nil {
		resource = r.URL.Path
	}
	s3Err := classifyPostError(err, resource)
	if errors.As(err, &writeFailure) {
		bucket, key := postErrorObjectIdentity(r)
		if errors.Is(err, crypto.ErrMetadataTooLarge) {
			s3Err = &S3Error{Code: "MetadataTooLarge", Message: "The object metadata exceeds the permitted size.", Resource: resource, HTTPStatus: http.StatusBadRequest}
		} else {
			s3Err = putObjectWriteS3Error(err, resource, bucket, key)
		}
		if h.logger != nil && s3Err != nil && s3Err.HTTPStatus >= http.StatusInternalServerError {
			h.logger.WithFields(map[string]interface{}{
				"operation": "PostObject",
				"stage":     postObjectWriteStageName(writeFailure.stage),
			}).Error("PostObject request failed")
		}
	} else if h.logger != nil && s3Err != nil && s3Err.HTTPStatus >= http.StatusInternalServerError {
		h.logger.WithFields(map[string]interface{}{
			"operation": "PostObject",
			"stage":     "unknown",
		}).Error("PostObject request failed")
	}
	bucket, _ := postErrorObjectIdentity(r)
	h.writeObjectErrorForBucket(w, r, "PostObject", bucket, s3Err, started)
}

func postObjectWriteStageName(stage objectWriteStage) string {
	switch stage {
	case objectWriteInvalid:
		return "validation"
	case objectWriteCrypto:
		return "encryption"
	case objectWriteClassify:
		return "classification"
	case objectWritePreparation:
		return "preparation"
	case objectWriteBackend:
		return "backend"
	default:
		return "unknown"
	}
}

func writePostClientAcquisitionError(w http.ResponseWriter, r *http.Request, h *Handler, upload *postUpload, err error, started time.Time) {
	if h == nil || r == nil || w == nil {
		return
	}
	resource := ""
	if r.URL != nil {
		resource = r.URL.Path
	}
	if upload == nil {
		upload, _ = postUploadFromContext(r)
	}
	bucket, key := postErrorObjectIdentity(r)
	if upload != nil {
		bucket, key = upload.bucket, upload.key
	}
	if h.logger != nil && err != nil {
		h.logger.WithFields(map[string]interface{}{
			"operation": "PostObject",
			"stage":     "backend_acquisition",
		}).Error("Failed to acquire backend client")
	}
	var translated *S3Error
	switch {
	case errors.Is(err, ErrInvalidToken), errors.Is(err, ErrExpiredToken), errors.Is(err, ErrSpoolRequestLimit), errors.Is(err, ErrSpoolCapacity), errors.Is(err, ErrRequestTimeTooSkewed), errors.Is(err, ErrRequestExpired), errors.Is(err, ErrInvalidPresignedExpiry), errors.Is(err, ErrSignatureMismatch), errors.Is(err, ErrUnknownAccessKey), errors.Is(err, ErrMissingCredentials):
		translated = classifyAuthError(err, resource)
	default:
		translated = TranslateError(err, bucket, key)
	}
	if translated == nil {
		translated = classifyAuthError(err, resource)
	}
	h.writeObjectErrorForBucket(w, r, "PostObject", bucket, translated, started)
}

func postErrorObjectIdentity(r *http.Request) (string, string) {
	if r == nil {
		return "", ""
	}
	if upload, ok := postUploadFromContext(r); ok {
		return upload.bucket, upload.key
	}
	if vars := mux.Vars(r); vars != nil && (vars["bucket"] != "" || vars["key"] != "") {
		return vars["bucket"], vars["key"]
	}
	if r.URL == nil {
		return "", ""
	}
	bucket := strings.Trim(strings.TrimPrefix(r.URL.Path, "/"), "/")
	return bucket, ""
}
