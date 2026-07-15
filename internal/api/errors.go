package api

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/smithy-go"
)

// ErrMissingMPUManifest identifies an encrypted multipart object whose
// gateway-owned manifest is unavailable.
var ErrMissingMPUManifest = errors.New("encrypted multipart object manifest is missing")

// S3Error represents an S3 API error response.
type S3Error struct {
	Code       string
	Message    string
	Resource   string
	RequestID  string
	HTTPStatus int
}

// Error implements the error interface.
func (e *S3Error) Error() string {
	return fmt.Sprintf("S3 Error: %s - %s", e.Code, e.Message)
}

// WriteXML writes the S3 error response in XML format.
func (e *S3Error) WriteXML(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(e.HTTPStatus)

	// S3 Error Response structure
	type ErrorResponse struct {
		XMLName   xml.Name `xml:"Error"`
		Code      string   `xml:"Code"`
		Message   string   `xml:"Message"`
		Resource  string   `xml:"Resource,omitempty"`
		RequestID string   `xml:"RequestId,omitempty"`
	}

	response := ErrorResponse{
		Code:      e.Code,
		Message:   e.Message,
		Resource:  e.Resource,
		RequestID: e.RequestID,
	}

	xmlData, err := xml.MarshalIndent(response, "", "  ")
	if err != nil {
		// Fallback to plain text if XML marshaling fails
		http.Error(w, e.Message, e.HTTPStatus)
		return
	}

	w.Write([]byte(xml.Header))
	w.Write(xmlData)
}

// TranslateError translates AWS SDK and other errors to S3 errors.
func TranslateError(err error, bucket, key string) *S3Error {
	if err == nil {
		return nil
	}

	// Extract request ID if available
	requestID := ""
	var opErr *smithy.OperationError
	if errors.As(err, &opErr) {
		if reqID := extractRequestID(opErr); reqID != "" {
			requestID = reqID
		}
	}

	resource := ""
	if bucket != "" {
		if key != "" {
			resource = fmt.Sprintf("/%s/%s", bucket, key)
		} else {
			resource = fmt.Sprintf("/%s", bucket)
		}
	}

	// Check for API errors first (smithy.APIError interface)
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchBucket":
			return &S3Error{
				Code:       "NoSuchBucket",
				Message:    fmt.Sprintf("The specified bucket does not exist: %s", bucket),
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusNotFound,
			}
		case "NoSuchKey", "NotFound":
			return &S3Error{
				Code:       "NoSuchKey",
				Message:    fmt.Sprintf("The specified key does not exist: %s", key),
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusNotFound,
			}
		case "AccessDenied":
			return &S3Error{
				Code:       "AccessDenied",
				Message:    "Access Denied",
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusForbidden,
			}
		case "InvalidBucketName":
			return &S3Error{
				Code:       "InvalidBucketName",
				Message:    "The specified bucket is not valid.",
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusBadRequest,
			}
		case "InvalidArgument":
			// SECURITY: Deliberately do NOT include apiErr.ErrorMessage() in
			// the response. The ErrorMessage comes from the backend and is
			// attacker-influenceable (compromised/malicious backend, or
			// non-AWS implementations with different conventions). The
			// structured Code is the stable contract for clients; the
			// underlying detail is logged by callers via WithError.
			return &S3Error{
				Code:       "InvalidArgument",
				Message:    "The request contains an invalid argument.",
				Resource:   resource,
				RequestID:  requestID,
				HTTPStatus: http.StatusBadRequest,
			}
		}
	}

	// Default to internal error.
	//
	// SECURITY: Do NOT embed err.Error() or %v-formatted err into the Message.
	// Upstream errors may contain:
	//   - internal endpoint URLs / hostnames (from SDK transport errors)
	//   - bucket paths and keys beyond what the caller requested
	//   - credential metadata in transport-level errors
	//   - wrapped diagnostic detail from other layers (e.g. computed HMAC
	//     signatures — see the history of ValidateSignatureV4)
	// Callers are expected to log err themselves via logger.WithError(err);
	// all 14 production call sites in handlers.go do so. The client-facing
	// Message is the canonical AWS S3 InternalError string.
	return &S3Error{
		Code:       "InternalError",
		Message:    "We encountered an internal error. Please try again.",
		Resource:   resource,
		RequestID:  requestID,
		HTTPStatus: http.StatusInternalServerError,
	}
}

// isS3NotFoundError reports whether err represents an S3 "not found" condition
// (NoSuchKey or NotFound). This is used to treat missing companion objects
// (e.g. MPU manifests) as no-ops during cleanup.
func isS3NotFoundError(err error) bool {
	if err == nil {
		return false
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code := apiErr.ErrorCode()
		return code == "NoSuchKey" || code == "NotFound"
	}
	// Some S3-compatible backends wrap the code in a plain error string.
	// Check for common patterns as a fallback.
	msg := err.Error()
	return strings.Contains(msg, "NoSuchKey") || strings.Contains(msg, "NotFound")
}

// extractRequestID attempts to extract request ID from error.
func extractRequestID(err error) string {
	// Request ID extraction from AWS SDK errors would go here
	// For now, return empty string
	return ""
}

// Predefined S3 errors
var (
	ErrInvalidRequest = &S3Error{
		Code:       "InvalidRequest",
		Message:    "Invalid Request",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrInvalidBucketName = &S3Error{
		Code:       "InvalidBucketName",
		Message:    "The specified bucket is not valid.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrInvalidKeyName = &S3Error{
		Code:       "InvalidArgument",
		Message:    "The specified key is not valid.",
		HTTPStatus: http.StatusBadRequest,
	}

	ErrAccessDenied = &S3Error{
		Code:       "AccessDenied",
		Message:    "Access Denied",
		HTTPStatus: http.StatusForbidden,
	}

	ErrNoSuchBucket = &S3Error{
		Code:       "NoSuchBucket",
		Message:    "The specified bucket does not exist.",
		HTTPStatus: http.StatusNotFound,
	}

	ErrNoSuchKey = &S3Error{
		Code:       "NoSuchKey",
		Message:    "The specified key does not exist.",
		HTTPStatus: http.StatusNotFound,
	}

	ErrMethodNotAllowed = &S3Error{
		Code:       "MethodNotAllowed",
		Message:    "The specified method is not allowed against this resource.",
		HTTPStatus: http.StatusMethodNotAllowed,
	}
)
