package api

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
)

func TestTranslateError_BackendAvailability(t *testing.T) {
	for _, code := range []string{"SlowDown", "ServiceUnavailable"} {
		t.Run(code, func(t *testing.T) {
			err := fmt.Errorf("backend: %w", &smithy.OperationError{ServiceID: "S3", OperationName: "GetObject", Err: &smithy.GenericAPIError{Code: code, Message: "private diagnostic"}})
			got := TranslateError(err, "bucket", "key")
			if got.Code != code || got.HTTPStatus != http.StatusServiceUnavailable || got.Resource != "/bucket/key" || strings.Contains(got.Message, "private diagnostic") {
				t.Fatalf("translation=%+v", got)
			}
		})
	}
}

// TestS3Error_Error verifies the error message format.
func TestS3Error_Error(t *testing.T) {
	e := &S3Error{
		Code:    "NoSuchKey",
		Message: "The specified key does not exist.",
	}
	got := e.Error()
	if !strings.Contains(got, "NoSuchKey") {
		t.Errorf("S3Error.Error() missing Code: %q", got)
	}
	if !strings.Contains(got, "The specified key does not exist.") {
		t.Errorf("S3Error.Error() missing Message: %q", got)
	}
}

// TestS3Error_WriteXML_StatusCode verifies that WriteXML sets the correct HTTP
// status code for each error.
func TestS3Error_WriteXML_StatusCode(t *testing.T) {
	tests := []struct {
		name       string
		err        *S3Error
		wantStatus int
	}{
		{"404", &S3Error{Code: "NoSuchKey", Message: "not found", HTTPStatus: http.StatusNotFound}, http.StatusNotFound},
		{"403", &S3Error{Code: "AccessDenied", Message: "denied", HTTPStatus: http.StatusForbidden}, http.StatusForbidden},
		{"400", &S3Error{Code: "InvalidBucketName", Message: "bad name", HTTPStatus: http.StatusBadRequest}, http.StatusBadRequest},
		{"405", &S3Error{Code: "MethodNotAllowed", Message: "not allowed", HTTPStatus: http.StatusMethodNotAllowed}, http.StatusMethodNotAllowed},
		{"500", &S3Error{Code: "InternalError", Message: "internal", HTTPStatus: http.StatusInternalServerError}, http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			tc.err.WriteXML(w)

			if w.Code != tc.wantStatus {
				t.Errorf("WriteXML() status = %d, want %d", w.Code, tc.wantStatus)
			}
		})
	}
}

// TestS3Error_WriteXML_ContentType verifies that WriteXML sets application/xml.
func TestS3Error_WriteXML_ContentType(t *testing.T) {
	e := &S3Error{
		Code:       "TestCode",
		Message:    "test message",
		HTTPStatus: http.StatusBadRequest,
	}
	w := httptest.NewRecorder()
	e.WriteXML(w)

	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/xml") {
		t.Errorf("WriteXML() Content-Type = %q, want application/xml", ct)
	}
}

// TestS3Error_WriteXML_Body verifies the XML body structure.
func TestS3Error_WriteXML_Body(t *testing.T) {
	e := &S3Error{
		Code:       "NoSuchBucket",
		Message:    "The specified bucket does not exist.",
		Resource:   "/my-bucket",
		RequestID:  "req-123",
		HTTPStatus: http.StatusNotFound,
	}
	w := httptest.NewRecorder()
	e.WriteXML(w)

	body := w.Body.String()

	// Check XML structure
	if !strings.Contains(body, "<Error>") && !strings.Contains(body, "<Error ") {
		t.Errorf("WriteXML() body missing <Error> element: %s", body)
	}
	if !strings.Contains(body, "<Code>NoSuchBucket</Code>") {
		t.Errorf("WriteXML() body missing Code: %s", body)
	}
	if !strings.Contains(body, "<Message>The specified bucket does not exist.</Message>") {
		t.Errorf("WriteXML() body missing Message: %s", body)
	}
	if !strings.Contains(body, "<Resource>/my-bucket</Resource>") {
		t.Errorf("WriteXML() body missing Resource: %s", body)
	}
	if !strings.Contains(body, "<RequestId>req-123</RequestId>") {
		t.Errorf("WriteXML() body missing RequestId: %s", body)
	}
}

// TestS3Error_WriteXML_ValidXML verifies the output is well-formed XML.
func TestS3Error_WriteXML_ValidXML(t *testing.T) {
	e := &S3Error{
		Code:       "InvalidArgument",
		Message:    "Invalid argument.",
		HTTPStatus: http.StatusBadRequest,
	}
	w := httptest.NewRecorder()
	e.WriteXML(w)

	body := w.Body.String()

	// Strip XML declaration if present (xml.Header)
	body = strings.TrimPrefix(body, xml.Header)

	// Attempt to parse as XML
	var parsed struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if err := xml.Unmarshal([]byte(body), &parsed); err != nil {
		t.Errorf("WriteXML() produced invalid XML: %v\nbody: %s", err, body)
	}
	if parsed.Code != e.Code {
		t.Errorf("parsed Code = %q, want %q", parsed.Code, e.Code)
	}
}

// TestTranslateError_Nil verifies that TranslateError(nil, ...) returns nil.
func TestTranslateError_Nil(t *testing.T) {
	result := TranslateError(nil, "bucket", "key")
	if result != nil {
		t.Errorf("TranslateError(nil, ...) = %v, want nil", result)
	}
}

// TestTranslateError_ResourceField verifies that the Resource field is set
// correctly based on bucket and key arguments.
func TestTranslateError_ResourceField(t *testing.T) {
	tests := []struct {
		bucket       string
		key          string
		wantResource string
	}{
		{"my-bucket", "my-key", "/my-bucket/my-key"},
		{"my-bucket", "", "/my-bucket"},
		{"", "", ""},
	}

	for _, tc := range tests {
		err := fmt.Errorf("some error")
		s3err := TranslateError(err, tc.bucket, tc.key)
		if s3err == nil {
			t.Fatalf("TranslateError() returned nil for non-nil error")
		}
		if s3err.Resource != tc.wantResource {
			t.Errorf("TranslateError() Resource = %q, want %q", s3err.Resource, tc.wantResource)
		}
	}
}

// TestTranslateError_InternalError verifies that an unknown error maps to
// InternalError with status 500 and that err.Error() is NOT embedded in the
// message (security requirement: no error details leak).
func TestTranslateError_InternalError(t *testing.T) {
	sensitiveDetail := "sensitive internal endpoint details"
	err := fmt.Errorf("something failed: %s", sensitiveDetail)

	s3err := TranslateError(err, "", "")
	if s3err == nil {
		t.Fatal("TranslateError() returned nil for non-nil error")
	}
	if s3err.Code != "InternalError" {
		t.Errorf("TranslateError() Code = %q, want InternalError", s3err.Code)
	}
	if s3err.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("TranslateError() HTTPStatus = %d, want 500", s3err.HTTPStatus)
	}
	// SECURITY: The message must NOT contain the error detail
	if strings.Contains(s3err.Message, sensitiveDetail) {
		t.Errorf("TranslateError() Message leaks error detail: %q", s3err.Message)
	}
}

// TestPredefinedErrors_Shape verifies that predefined S3 error vars have the
// expected code, message, and HTTP status.
func TestPredefinedErrors_Shape(t *testing.T) {
	tests := []struct {
		name       string
		err        *S3Error
		wantCode   string
		wantStatus int
	}{
		{"ErrInvalidRequest", ErrInvalidRequest, "InvalidRequest", http.StatusBadRequest},
		{"ErrInvalidBucketName", ErrInvalidBucketName, "InvalidBucketName", http.StatusBadRequest},
		{"ErrInvalidKeyName", ErrInvalidKeyName, "InvalidArgument", http.StatusBadRequest},
		{"ErrAccessDenied", ErrAccessDenied, "AccessDenied", http.StatusForbidden},
		{"ErrNoSuchBucket", ErrNoSuchBucket, "NoSuchBucket", http.StatusNotFound},
		{"ErrNoSuchKey", ErrNoSuchKey, "NoSuchKey", http.StatusNotFound},
		{"ErrMethodNotAllowed", ErrMethodNotAllowed, "MethodNotAllowed", http.StatusMethodNotAllowed},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Code != tc.wantCode {
				t.Errorf("%s.Code = %q, want %q", tc.name, tc.err.Code, tc.wantCode)
			}
			if tc.err.HTTPStatus != tc.wantStatus {
				t.Errorf("%s.HTTPStatus = %d, want %d", tc.name, tc.err.HTTPStatus, tc.wantStatus)
			}
			if tc.err.Message == "" {
				t.Errorf("%s.Message is empty", tc.name)
			}
		})
	}
}

// TestS3Error_WriteXML_EmptyResource verifies that an empty Resource field
// is not included in the XML output (the omitempty tag).
func TestS3Error_WriteXML_EmptyResource(t *testing.T) {
	e := &S3Error{
		Code:       "InternalError",
		Message:    "internal",
		Resource:   "", // empty
		HTTPStatus: http.StatusInternalServerError,
	}
	w := httptest.NewRecorder()
	e.WriteXML(w)

	body := w.Body.String()
	if strings.Contains(body, "<Resource>") {
		t.Errorf("WriteXML() included empty <Resource> element: %s", body)
	}
}
