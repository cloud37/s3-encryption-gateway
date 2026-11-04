package api

import (
	"errors"
	"net/http"

	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// SSE option errors use the same fixed, non-secret classification as POST
// option validation. This file is the minimal Phase C1 prerequisite for Phase B.
var (
	ErrPostPolicyMalformed        = errors.New("malformed POST policy")
	ErrPostPolicyDenied           = errors.New("POST policy denied")
	ErrPostFormMalformed          = errors.New("malformed POST form")
	ErrPostEntityTooSmall         = errors.New("POST file below policy minimum")
	ErrPostBadDigest              = errors.New("POST checksum mismatch")
	ErrPostUnsupported            = errors.New("unsupported POST option")
	ErrPostIncompleteBody         = errors.New("incomplete POST body")
	ErrPostEntityTooLarge         = errors.New("POST body exceeds permitted size")
	ErrPostInvalidOption          = errors.New("invalid object option")
	ErrPostChecksumInvalidRequest = errors.New("invalid POST checksum selection")
	ErrPostMalformedXML           = errors.New("malformed XML")
	ErrPostInvalidTag             = errors.New("invalid tag")
	ErrSSEInsecureTransport       = errors.New("SSE-C requires a secure transport")
)

// classifyPostError maps POST/auth/parser failures to fixed S3 errors. It never
// includes the underlying error text, which may contain submitted fields or
// cryptographic material. Authentication errors retain the gateway's existing
// classifications and sentinels.
func classifyPostError(err error, resource string) *S3Error {
	if err == nil {
		return &S3Error{Code: "InternalError", Message: "We encountered an internal error. Please try again.", Resource: resource, HTTPStatus: http.StatusInternalServerError}
	}
	makeError := func(code, message string, status int) *S3Error {
		return &S3Error{Code: code, Message: message, Resource: resource, HTTPStatus: status}
	}
	switch {
	case errors.Is(err, ErrUnknownAccessKey):
		return classifyAuthError(err, resource)
	case errors.Is(err, ErrMissingCredentials):
		return &S3Error{Code: "AccessDenied", Message: "Missing or invalid credentials in request.", Resource: resource, HTTPStatus: http.StatusForbidden}
	case errors.Is(err, ErrPostPolicyDenied):
		return makeError("AccessDenied", "The request does not satisfy the POST policy.", http.StatusForbidden)
	case errors.Is(err, ErrSignatureMismatch):
		return classifyAuthError(err, resource)
	case errors.Is(err, ErrRequestTimeTooSkewed):
		return makeError("RequestTimeTooSkewed", "The difference between the request time and the server's time is too large.", http.StatusForbidden)
	case errors.Is(err, ErrRequestExpired):
		return makeError("AccessDenied", "Request has expired.", http.StatusForbidden)
	case errors.Is(err, ErrExpiredToken):
		return makeError("ExpiredToken", "The provided token has expired.", http.StatusForbidden)
	case errors.Is(err, ErrInvalidToken):
		return makeError("InvalidToken", "The provided token is invalid.", http.StatusForbidden)
	case errors.Is(err, ErrInvalidPresignedExpiry), errors.Is(err, ErrPostPolicyMalformed):
		return makeError("InvalidArgument", "Invalid POST policy.", http.StatusBadRequest)
	case errors.Is(err, ErrPostInvalidOption):
		return makeError("InvalidArgument", "The specified POST option is invalid.", http.StatusBadRequest)
	case errors.Is(err, ErrPostFormMalformed):
		return makeError("InvalidRequest", "Invalid POST form.", http.StatusBadRequest)
	case errors.Is(err, ErrPostChecksumInvalidRequest):
		return makeError("InvalidRequest", "Invalid POST checksum selection.", http.StatusBadRequest)
	case errors.Is(err, ErrPostIncompleteBody), errors.Is(err, ErrIncompleteBody), errors.Is(err, ErrStreamingCanceled):
		return makeError("IncompleteBody", "The request body is incomplete.", http.StatusBadRequest)
	case errors.Is(err, ErrPostEntityTooLarge), errors.Is(err, ErrSpoolRequestLimit):
		return makeError("EntityTooLarge", "The request exceeds the permitted payload size.", http.StatusRequestEntityTooLarge)
	case errors.Is(err, ErrPostEntityTooSmall):
		return makeError("EntityTooSmall", "The uploaded object is smaller than the permitted size.", http.StatusBadRequest)
	case errors.Is(err, ErrPostBadDigest):
		return makeError("BadDigest", "The provided checksum does not match the uploaded object.", http.StatusBadRequest)
	case errors.Is(err, ErrPostMalformedXML):
		return makeError("MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema.", http.StatusBadRequest)
	case errors.Is(err, ErrPostInvalidTag):
		return makeError("InvalidTag", "The tag provided was not valid.", http.StatusBadRequest)
	case errors.Is(err, ErrPostUnsupported), errors.Is(err, s3.ErrNotImplemented):
		return makeError("NotImplemented", "The requested POST option is not supported.", http.StatusNotImplemented)
	case errors.Is(err, ErrSSEInsecureTransport):
		return makeError("InvalidRequest", "SSE-C requires a secure transport.", http.StatusBadRequest)
	case errors.Is(err, ErrSpoolCapacity):
		return makeError("SlowDown", "Please reduce your request rate.", http.StatusServiceUnavailable)
	case errors.Is(err, ErrStreamingSpool):
		return makeError("InternalError", "We encountered an internal error. Please try again.", http.StatusInternalServerError)
	default:
		return makeError("InternalError", "We encountered an internal error. Please try again.", http.StatusInternalServerError)
	}
}

// classifySSEOptionError keeps option errors opaque and maps unsupported modes
// (including backends without the required advanced capability) consistently.
func classifySSEOptionError(err error) (code, message string, status int) {
	if errors.Is(err, ErrSSEInsecureTransport) {
		return "InvalidRequest", "SSE-C requires a secure transport.", http.StatusBadRequest
	}
	if errors.Is(err, ErrPostUnsupported) || errors.Is(err, s3.ErrNotImplemented) {
		return "NotImplemented", "The requested object option is not supported.", http.StatusNotImplemented
	}
	return "InvalidArgument", "The specified encryption option is invalid.", http.StatusBadRequest
}
