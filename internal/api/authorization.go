package api

import (
	"net/http"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

type authorizationOperation int

const (
	authorizationUnknown authorizationOperation = iota
	authorizationRead
	authorizationWrite
	authorizationCreateBucket
	authorizationDeleteBucket
	authorizationListBuckets
)

// AuthorizationMiddleware enforces the authenticated credential's policy before
// routing can acquire a backend client. proxiedBucket is an additional global
// restriction and can only narrow a credential's scope.
func AuthorizationMiddleware(proxiedBucket string, auditLog audit.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isSystemEndpoint(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			credential, ok := CredentialFromContext(r)
			if !ok {
				writeAuthorizationDenied(w, r, auditLog, "unknown_operation")
				return
			}
			op, bucket := classifyAuthorizationOperation(r)
			if op == authorizationUnknown {
				writeAuthorizationDenied(w, r, auditLog, "unknown_operation")
				return
			}
			if op == authorizationListBuckets {
				if credential.Policy.Permissions != config.ObjectPermissionReadOnly && credential.Policy.Permissions != config.ObjectPermissionReadWrite {
					writeAuthorizationDenied(w, r, auditLog, "read_only")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if bucket == "" || !credential.AllowsBucket(bucket) || (proxiedBucket != "" && bucket != proxiedBucket) {
				writeAuthorizationDenied(w, r, auditLog, "bucket_scope")
				return
			}
			switch op {
			case authorizationRead:
			case authorizationWrite:
				if !credential.CanWrite() {
					writeAuthorizationDenied(w, r, auditLog, "read_only")
					return
				}
			case authorizationCreateBucket:
				if !credential.HasBucketPermission(config.BucketPermissionCreate) {
					writeAuthorizationDenied(w, r, auditLog, "bucket_create")
					return
				}
			case authorizationDeleteBucket:
				if !credential.HasBucketPermission(config.BucketPermissionDelete) {
					writeAuthorizationDenied(w, r, auditLog, "bucket_delete")
					return
				}
			}
			if op == authorizationWrite && isCopyAuthorizationRoute(r) {
				if copySource := r.Header.Get("x-amz-copy-source"); copySource != "" {
					sourceBucket, _, _, err := ParseCopySource(copySource)
					if err != nil || !copyBucketsAuthorized(credential, bucket, sourceBucket, proxiedBucket) {
						writeAuthorizationDenied(w, r, auditLog, "bucket_scope")
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isCopyAuthorizationRoute mirrors the PUT object routes that can dispatch to
// CopyObject or UploadPartCopy. Subresource PUTs must ignore this header; their
// handlers do not interpret it as a copy request.
func isCopyAuthorizationRoute(r *http.Request) bool {
	if r.Method != http.MethodPut {
		return false
	}
	query := operationQuery(r)
	if len(query) == 0 {
		return true // CopyObject / PutObject route
	}
	_, hasUploadID := query["uploadId"]
	_, hasPartNumber := query["partNumber"]
	return hasUploadID && (len(query) == 1 || (len(query) == 2 && hasPartNumber))
}

// The query keys below mirror the exact route/query groups registered in
// Handler.RegisterRoutes (handlers.go). The classifier validates complete
// parameter groups instead of broad key allowlists so that a query shape the
// mux cannot route to its intended handler can never authorize a fallback
// handler — in particular the generic CreateBucket/DeleteBucket routes.
var (
	// listObjectsParams are the optional ListObjects (GET /{bucket})
	// pagination parameters accepted by handleListObjects.
	listObjectsParams = map[string]bool{"list-type": true, "prefix": true, "marker": true, "delimiter": true, "max-keys": true, "continuation-token": true, "start-after": true, "encoding-type": true, "fetch-owner": true}
	// listMultipartUploadsParams are the optional ListMultipartUploads
	// (GET /{bucket}?uploads) parameters.
	listMultipartUploadsParams = map[string]bool{"uploads": true, "prefix": true, "delimiter": true, "encoding-type": true, "key-marker": true, "upload-id-marker": true, "max-uploads": true}
	// listPartsParams are the optional ListParts (GET /{bucket}/{key}?uploadId=)
	// parameters.
	listPartsParams = map[string]bool{"uploadId": true, "max-parts": true, "part-number-marker": true}
	// bucketReadSelectors are bucket-level GET/HEAD subresource selectors.
	// Every registered route uses Queries(key, "") so a non-empty value can
	// never select the subresource handler.
	bucketReadSelectors = map[string]bool{"acl": true, "analytics": true, "cors": true, "encryption": true, "inventory": true, "lifecycle": true, "location": true, "logging": true, "notification": true, "object-lock": true, "policy": true, "replication": true, "requestPayment": true, "uploads": true, "versioning": true, "website": true}
	// bucketPutSelectors are bucket-level PUT subresource selectors.
	bucketPutSelectors = map[string]bool{"acl": true, "cors": true, "encryption": true, "intelligent-tiering": true, "inventory": true, "lifecycle": true, "logging": true, "notification": true, "object-lock": true, "policy": true, "replication": true, "requestPayment": true, "versioning": true, "website": true}
	// bucketDeleteSelectors are bucket-level DELETE subresource selectors.
	// These keys have registered DELETE subresource routes; any other key on a
	// bucket DELETE would fall through to the generic DeleteBucket route.
	bucketDeleteSelectors = map[string]bool{"lifecycle": true, "policy": true, "cors": true, "encryption": true, "replication": true, "website": true, "inventory": true}
	// inventoryIDSelectors may pair with the non-selector "id" parameter.
	// PutBucketInventoryConfiguration, GetBucketInventoryConfiguration,
	// DeleteBucketInventoryConfiguration, GetBucketAnalyticsConfiguration and
	// PutBucketIntelligentTieringConfiguration all address a configuration by
	// id. The mux route matches on the empty-value selector alone, so the id
	// parameter does not affect routing.
	inventoryIDSelectors = map[string]bool{"inventory": true, "analytics": true, "intelligent-tiering": true}
)

// queryHasAllKeys reports whether every query key is present in allowed.
func queryHasAllKeys(query map[string][]string, allowed map[string]bool) bool {
	for key := range query {
		if !allowed[key] {
			return false
		}
	}
	return true
}

// classifyBucketSelectorQuery validates a bucket subresource query against an
// exact selector group. Exactly one selector key must be present with an
// empty value (matching Queries(key, "")); "id" is a non-selector parameter
// allowed only beside a selector listed in idSelectors. Non-empty selector
// values, missing selectors, and mixed selectors all fail closed because
// gorilla/mux would skip the subresource route and reach the generic
// CreateBucket/DeleteBucket handlers.
func classifyBucketSelectorQuery(query map[string][]string, selectors, idSelectors map[string]bool, base authorizationOperation) authorizationOperation {
	selector := ""
	for key, vals := range query {
		if selectors[key] {
			if selector != "" {
				return authorizationUnknown // mixed selectors are ambiguous
			}
			selector = key
			if len(vals) > 0 && vals[0] != "" {
				return authorizationUnknown // non-empty value misses Queries(key, "")
			}
			continue
		}
		if key != "id" {
			return authorizationUnknown
		}
	}
	if selector == "" {
		return authorizationUnknown
	}
	if _, hasID := query["id"]; hasID && !idSelectors[selector] {
		return authorizationUnknown // id without its parent selector
	}
	return base
}

// queryValueNonEmpty reports whether the first value of key is non-empty.
func queryValueNonEmpty(query map[string][]string, key string) bool {
	vals, ok := query[key]
	return ok && len(vals) > 0 && vals[0] != ""
}

func classifyAuthorizationOperation(r *http.Request) (authorizationOperation, string) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if path == "" {
		if r.Method == http.MethodGet && len(operationQuery(r)) == 0 {
			return authorizationListBuckets, ""
		}
		return authorizationUnknown, ""
	}
	bucket := parts[0]
	object := len(parts) > 1 && strings.Join(parts[1:], "/") != ""
	if object {
		return classifyObjectAuthorizationOperation(r, bucket)
	}
	if r.Method == http.MethodOptions {
		return authorizationRead, bucket
	}

	query := operationQuery(r)
	if len(query) == 0 {
		switch r.Method {
		case http.MethodGet:
			return authorizationRead, bucket // ListObjects
		case http.MethodHead:
			return authorizationRead, bucket
		case http.MethodPut:
			return authorizationCreateBucket, bucket
		case http.MethodDelete:
			return authorizationDeleteBucket, bucket
		}
		return authorizationUnknown, bucket
	}

	// Bucket subresources are all route-defined. Their DELETE variants are
	// ordinary mutations, not DeleteBucket lifecycle operations.
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if queryHasAllKeys(query, listObjectsParams) {
			return authorizationRead, bucket // ListObjects pagination
		}
		if _, hasUploads := query["uploads"]; hasUploads && queryHasAllKeys(query, listMultipartUploadsParams) {
			return authorizationRead, bucket // ListMultipartUploads parameter group
		}
		if _, hasUploads := query["uploads"]; !hasUploads && queryHasAllKeys(query, listMultipartUploadsParams) {
			return authorizationUnknown, bucket // pagination keys without uploads
		}
		return classifyBucketSelectorQuery(query, bucketReadSelectors, inventoryIDSelectors, authorizationRead), bucket
	case http.MethodPut:
		return classifyBucketSelectorQuery(query, bucketPutSelectors, inventoryIDSelectors, authorizationWrite), bucket
	case http.MethodDelete:
		return classifyBucketSelectorQuery(query, bucketDeleteSelectors, inventoryIDSelectors, authorizationWrite), bucket
	case http.MethodPost:
		if len(query) != 1 {
			return authorizationUnknown, bucket
		}
		if _, ok := query["delete"]; !ok || queryValueNonEmpty(query, "delete") {
			return authorizationUnknown, bucket
		}
		return authorizationWrite, bucket
	}
	return authorizationUnknown, bucket
}

func classifyObjectAuthorizationOperation(r *http.Request, bucket string) (authorizationOperation, string) {
	if r.Method == http.MethodOptions {
		return authorizationRead, bucket
	}
	query := operationQuery(r)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if _, hasUploadID := query["uploadId"]; hasUploadID {
			// ListParts parameter group: uploadId plus optional pagination.
			if !queryHasAllKeys(query, listPartsParams) {
				return authorizationUnknown, bucket // mixed selector with uploadId
			}
			if !queryValueNonEmpty(query, "uploadId") {
				return authorizationUnknown, bucket // Queries("uploadId", "{uploadId}") requires a value
			}
			return authorizationRead, bucket
		}
		for key := range query {
			switch key {
			case "acl", "retention", "legal-hold", "tagging":
				if queryValueNonEmpty(query, key) {
					return authorizationUnknown, bucket // Queries(key, "") requires empty
				}
			case "versionId", "partNumber":
				// value-carrying parameters handled by handleGetObject
			case "max-parts", "part-number-marker":
				return authorizationUnknown, bucket // ListParts pagination without uploadId
			default:
				return authorizationUnknown, bucket
			}
		}
		return authorizationRead, bucket
	case http.MethodPut:
		_, hasPartNumber := query["partNumber"]
		_, hasUploadID := query["uploadId"]
		if hasPartNumber && !hasUploadID {
			return authorizationUnknown, bucket
		}
		if hasUploadID {
			// UploadPart/UploadPartCopy group: only partNumber may accompany
			// uploadId; any other key is an ambiguous combination.
			if !queryValueNonEmpty(query, "uploadId") {
				return authorizationUnknown, bucket
			}
			for key := range query {
				if key != "uploadId" && key != "partNumber" {
					return authorizationUnknown, bucket
				}
			}
		}
		for key := range query {
			switch key {
			case "acl", "retention", "legal-hold", "tagging":
				if queryValueNonEmpty(query, key) {
					return authorizationUnknown, bucket // Queries(key, "") requires empty
				}
			case "versionId", "partNumber", "uploadId":
				// value-carrying parameters
			default:
				return authorizationUnknown, bucket
			}
		}
		return authorizationWrite, bucket
	case http.MethodDelete:
		if _, hasUploadID := query["uploadId"]; hasUploadID {
			// AbortMultipartUpload group: uploadId alone.
			if len(query) != 1 || !queryValueNonEmpty(query, "uploadId") {
				return authorizationUnknown, bucket
			}
			return authorizationWrite, bucket
		}
		for key := range query {
			switch key {
			case "tagging":
				if queryValueNonEmpty(query, key) {
					return authorizationUnknown, bucket
				}
			case "versionId":
				// value-carrying parameter handled by handleDeleteObject
			default:
				return authorizationUnknown, bucket
			}
		}
		return authorizationWrite, bucket
	case http.MethodPost:
		if len(query) == 0 {
			return authorizationUnknown, bucket
		}
		_, hasSelect := query["select"]
		_, hasSelectType := query["select-type"]
		_, hasUploads := query["uploads"]
		_, hasUploadID := query["uploadId"]
		_, hasRestore := query["restore"]
		switch {
		case hasSelect || hasSelectType:
			// SelectObjectContent: select with empty value or select-type
			// equal to the registered route value "2". Any mutation key
			// alongside select keys keeps the request classified as a write.
			for key := range query {
				if key != "select" && key != "select-type" {
					if _, isMutation := map[string]bool{"uploads": true, "uploadId": true, "restore": true}[key]; isMutation {
						return authorizationWrite, bucket
					}
					return authorizationUnknown, bucket
				}
			}
			if hasSelectType && (len(query["select-type"]) == 0 || query["select-type"][0] != "2") {
				return authorizationUnknown, bucket // Queries("select-type", "2") requires the exact value
			}
			if hasSelect && queryValueNonEmpty(query, "select") {
				return authorizationUnknown, bucket // Queries("select", "") requires empty
			}
			return authorizationRead, bucket
		case hasUploads:
			// CreateMultipartUpload group: uploads with empty value alone.
			if len(query) != 1 || queryValueNonEmpty(query, "uploads") {
				return authorizationUnknown, bucket
			}
			return authorizationWrite, bucket
		case hasUploadID:
			// CompleteMultipartUpload group: uploadId with a value alone.
			if len(query) != 1 || !queryValueNonEmpty(query, "uploadId") {
				return authorizationUnknown, bucket
			}
			return authorizationWrite, bucket
		case hasRestore:
			// RestoreObject group: restore with empty value alone.
			if len(query) != 1 || queryValueNonEmpty(query, "restore") {
				return authorizationUnknown, bucket
			}
			return authorizationWrite, bucket
		}
		return authorizationUnknown, bucket
	}
	return authorizationUnknown, bucket
}

// operationQuery excludes signature transport parameters so presigned SigV4
// and query-style SigV2 requests classify according to the S3 operation.
// x-id is an AWS-internal pass-through key: it may accompany a valid
// operation but never identifies one itself, so it is excluded from
// classification entirely.
func operationQuery(r *http.Request) map[string][]string {
	query := r.URL.Query()
	for key := range query {
		lower := strings.ToLower(key)
		if key == "AWSAccessKeyId" || key == "Signature" || key == "Expires" || key == "x-id" || strings.HasPrefix(lower, "x-amz-") {
			delete(query, key)
		}
	}
	return query
}

func writeAuthorizationDenied(w http.ResponseWriter, r *http.Request, auditLog audit.Logger, reason string) {
	if auditLog != nil {
		auditLog.LogAccessWithMetadata(string(audit.EventTypeAuthorizationDenied), "", "", r.RemoteAddr, r.UserAgent(), r.Header.Get("X-Request-Id"), false, ErrAccessDenied, 0, map[string]interface{}{"reason": reason, "method": r.Method, "path": r.URL.Path})
	}
	WriteAccessDenied(w, r.URL.Path)
}

// copyBucketsAuthorized reports whether the credential scope and the
// deployment-level PROXIED_BUCKET restriction permit reading the copy source
// and writing the copy destination. PROXIED_BUCKET only narrows scope.
func copyBucketsAuthorized(credential Credential, dstBucket, srcBucket, proxiedBucket string) bool {
	if !credential.AllowsBucket(dstBucket) || !credential.AllowsBucket(srcBucket) {
		return false
	}
	return proxiedBucket == "" || (dstBucket == proxiedBucket && srcBucket == proxiedBucket)
}

// authorizeCopyOperation enforces the caller's scope for the destination and
// source buckets of a CopyObject/UploadPartCopy request before any backend
// client is acquired. It mirrors the AuthorizationMiddleware check as
// handler-level defense-in-depth so copy authorization never depends on
// middleware ordering. It returns ErrAccessDenied when the caller lacks
// scope, and the ParseCopySource error for malformed headers.
func (h *Handler) authorizeCopyOperation(r *http.Request, dstBucket, copySource string) error {
	credential, ok := CredentialFromContext(r)
	if !ok {
		return ErrAccessDenied
	}
	if !credential.CanWrite() {
		return ErrAccessDenied
	}
	srcBucket, _, _, err := ParseCopySource(copySource)
	if err != nil {
		return err
	}
	proxiedBucket := ""
	if h.config != nil {
		proxiedBucket = h.config.ProxiedBucket
	}
	if !copyBucketsAuthorized(credential, dstBucket, srcBucket, proxiedBucket) {
		return ErrAccessDenied
	}
	return nil
}
