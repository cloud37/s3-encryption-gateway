package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
	"github.com/kenchrcum/s3-encryption-gateway/internal/crypto"
	"github.com/sirupsen/logrus"
)

// secretShaped is the kind of string that historically leaked into response
// bodies via err.Error() concatenation. We use it as a canary: if any of these
// substrings appears in a response body, the hardening has regressed.
const (
	secretShapedSig      = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
	secretShapedInternal = "internal diagnostic do not leak"
)

func TestClassifyAuthError_Table(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantCode   string
		wantStatus int
	}{
		{
			name:       "signature mismatch",
			err:        fmt.Errorf("%w: computed %s expected %s", ErrSignatureMismatch, secretShapedSig, secretShapedSig),
			wantCode:   "SignatureDoesNotMatch",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unknown access key",
			err:        ErrUnknownAccessKey,
			wantCode:   "InvalidAccessKeyId",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "missing credentials",
			err:        fmt.Errorf("%w: %v", ErrMissingCredentials, errors.New(secretShapedInternal)),
			wantCode:   "AccessDenied",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unknown error falls through to 500",
			err:        errors.New(secretShapedInternal),
			wantCode:   "InternalError",
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "nil error also produces 500 (should never happen, but total function)",
			err:        nil,
			wantCode:   "InternalError",
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyAuthError(tc.err, "/bucket/key")
			if got.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", got.Code, tc.wantCode)
			}
			if got.HTTPStatus != tc.wantStatus {
				t.Errorf("HTTPStatus = %d, want %d", got.HTTPStatus, tc.wantStatus)
			}
			if got.Resource != "/bucket/key" {
				t.Errorf("Resource = %q, want %q", got.Resource, "/bucket/key")
			}
			// CRITICAL: the classifier must never copy err.Error() into
			// the Message. Check that none of our canary strings appear.
			if strings.Contains(got.Message, secretShapedSig) {
				t.Errorf("Message leaked signature-shaped substring: %q", got.Message)
			}
			if strings.Contains(got.Message, secretShapedInternal) {
				t.Errorf("Message leaked internal diagnostic: %q", got.Message)
			}
		})
	}
}

// TestWriteS3ClientError_NoLeakRegression is the end-to-end regression test for
// the vulnerability where ValidateSignatureV4 put the computed HMAC signature
// into the error string, which writeS3ClientError then embedded verbatim into
// the XML response body.
//
// It exercises the public writer path and asserts the response body contains
// neither the secret-shaped value we embed in the wrapped error nor any
// substring of err.Error().
func TestWriteS3ClientError_NoLeakRegression(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)

	mockEngine, _ := crypto.NewEngine([]byte("test-password-123456"))

	cases := []struct {
		name string
		cfg  *config.Config
		err  error
	}{
		{
			name: "sig mismatch with leaked detail",
			cfg:  &config.Config{Backend: config.BackendConfig{}},
			err:  fmt.Errorf("%w: computed %s expected %s", ErrSignatureMismatch, secretShapedSig, secretShapedSig),
		},
		{
			name: "generic unclassified error",
			cfg:  &config.Config{Backend: config.BackendConfig{}},
			err:  errors.New(secretShapedInternal),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandlerWithFeatures(nil, mockEngine, logger, getTestMetrics(), nil, nil, nil, tc.cfg, nil)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest("GET", "/bucket/key", nil)

			h.writeS3ClientError(rec, req, tc.err, "GET", time.Now())

			body := rec.Body.String()
			if strings.Contains(body, secretShapedSig) {
				t.Errorf("response body leaked signature-shaped value\nbody: %s", body)
			}
			if strings.Contains(body, secretShapedInternal) {
				t.Errorf("response body leaked internal diagnostic\nbody: %s", body)
			}
			// Also assert we never just dump err.Error() verbatim.
			if strings.Contains(body, tc.err.Error()) {
				t.Errorf("response body contains err.Error() verbatim\nerr: %s\nbody: %s", tc.err.Error(), body)
			}
		})
	}
}
