package api

import (
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/sirupsen/logrus"
)

const presignedTestSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

// Use an independent SDK signer, not the gateway's canonicalization helpers.
// Backdating the signature reproduces GH-345 immediately, without sleeps.
func presignedTimeRequest(t *testing.T, at time.Time, expires []string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	q := req.URL.Query()
	if expires != nil {
		q["X-Amz-Expires"] = expires
	}
	req.URL.RawQuery = q.Encode()
	rawURL, _, err := v4.NewSigner().PresignHTTP(t.Context(), aws.Credentials{
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: presignedTestSecret,
	}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", at)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodGet, rawURL, nil)
}

func presignedTimeHeaderRequest(t *testing.T, at time.Time) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://localhost/bucket/key", nil)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	if err := v4.NewSigner().SignHTTP(t.Context(), aws.Credentials{
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: presignedTestSecret,
	}, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", at); err != nil {
		t.Fatal(err)
	}
	return req
}

func TestPresignedTime_ValidatorAndMiddleware(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name    string
		age     time.Duration
		expires []string
		header  bool
		skew    time.Duration
		code    string
		status  int
	}{
		{name: "recent", age: 2 * time.Minute, expires: []string{"900"}, status: 200},
		{name: "15m_link_after_6m", age: 6 * time.Minute, expires: []string{"900"}, status: 200},
		{name: "30m_link_after_20m", age: 20 * time.Minute, expires: []string{"1800"}, status: 200},
		{name: "60m_link_after_59m", age: 59 * time.Minute, expires: []string{"3600"}, status: 200},
		{name: "7day_link_after_6days", age: 6 * 24 * time.Hour, expires: []string{"604800"}, status: 200},
		{name: "custom_skew_does_not_cap_lifetime", age: 2 * time.Minute, expires: []string{"900"}, skew: time.Minute, status: 200},
		{name: "zero_skew_uses_default", age: 6 * time.Minute, expires: []string{"900"}, status: 200},
		{name: "negative_skew_uses_default", age: 6 * time.Minute, expires: []string{"900"}, skew: -time.Minute, status: 200},
		{name: "future_inside_skew", age: -2 * time.Minute, expires: []string{"900"}, status: 200},
		{name: "future_outside_skew", age: -6 * time.Minute, expires: []string{"900"}, code: "RequestTimeTooSkewed", status: 403},
		{name: "future_outside_custom_skew", age: -2 * time.Minute, expires: []string{"900"}, skew: time.Minute, code: "RequestTimeTooSkewed", status: 403},
		{name: "expired_inside_skew", age: 3 * time.Minute, expires: []string{"60"}, code: "AccessDenied", status: 403},
		{name: "expired_outside_skew", age: 16 * time.Minute, expires: []string{"900"}, code: "AccessDenied", status: 403},
		{name: "expiry_not_extended_by_skew", age: 16 * time.Minute, expires: []string{"900"}, skew: time.Hour, code: "AccessDenied", status: 403},
		{name: "missing_expiry", expires: nil, code: "InvalidArgument", status: 400},
		{name: "empty_expiry", expires: []string{""}, code: "InvalidArgument", status: 400},
		{name: "zero_expiry_future", age: -2 * time.Minute, expires: []string{"0"}, code: "InvalidArgument", status: 400},
		{name: "negative_expiry_future", age: -2 * time.Minute, expires: []string{"-1"}, code: "InvalidArgument", status: 400},
		{name: "malformed_expiry", expires: []string{"900x"}, code: "InvalidArgument", status: 400},
		{name: "decimal_expiry", expires: []string{"1.5"}, code: "InvalidArgument", status: 400},
		{name: "signed_expiry", expires: []string{"+900"}, code: "InvalidArgument", status: 400},
		{name: "whitespace_expiry", expires: []string{" 900"}, code: "InvalidArgument", status: 400},
		{name: "above_maximum", expires: []string{"604801"}, code: "InvalidArgument", status: 400},
		{name: "integer_overflow", expires: []string{"18446744073709551616"}, code: "InvalidArgument", status: 400},
		{name: "duration_overflow", expires: []string{"9223372036854775807"}, code: "InvalidArgument", status: 400},
		{name: "duplicate_expiry", expires: []string{"900", "900"}, code: "InvalidArgument", status: 400},
		{name: "conflicting_expiry", expires: []string{"900", "60"}, code: "InvalidArgument", status: 400},
		{name: "header_inside_skew", header: true, age: 2 * time.Minute, status: 200},
		{name: "header_old", header: true, age: 6 * time.Minute, code: "RequestTimeTooSkewed", status: 403},
		{name: "header_future", header: true, age: -6 * time.Minute, code: "RequestTimeTooSkewed", status: 403},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := presignedTimeRequest(t, now.Add(-tc.age), tc.expires)
			if tc.header {
				req = presignedTimeHeaderRequest(t, now.Add(-tc.age))
			}
			skew := tc.skew
			if skew == 0 && tc.name != "zero_skew_uses_default" {
				skew = 5 * time.Minute
			}
			ctx, err := ValidateSignatureV4(req, presignedTestSecret, skew)
			if ctx != nil {
				ctx.Close()
			}
			if tc.status == 200 && err != nil {
				t.Errorf("valid SDK signature rejected: %v", err)
			}
			if tc.status != 200 && (err == nil || ctx != nil) {
				t.Errorf("invalid request returned context=%v error=%v", ctx, err)
			}

			logger := logrus.New()
			logger.SetOutput(io.Discard)
			auditLog := audit.NewLogger(10, nil)
			called := false
			handler := AuthMiddleware(testCredentialStore(), skew, logger, auditLog, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status || called != (tc.status == 200) {
				t.Errorf("status=%d next=%v, want status=%d next=%v; body=%s", rec.Code, called, tc.status, tc.status == 200, rec.Body.String())
			}
			if tc.status == 200 {
				if events := auditLog.GetEvents(); len(events) != 0 {
					t.Errorf("successful auth emitted failure events: %v", events)
				}
				return
			}
			var response struct{ Code, Message, Resource string }
			if err := xml.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response.Code != tc.code || response.Resource != "/bucket/key" {
				t.Errorf("XML=%+v, want code=%s resource=/bucket/key", response, tc.code)
			}
			if tc.code == "AccessDenied" && response.Message != "Request has expired." {
				t.Errorf("expired message=%q", response.Message)
			}
			if tc.code == "RequestTimeTooSkewed" && response.Message != "The difference between the request time and the server's time is too large." {
				t.Errorf("skew message=%q", response.Message)
			}
			if strings.Contains(rec.Body.String(), presignedTestSecret) || strings.Contains(rec.Body.String(), req.URL.Query().Get("X-Amz-Signature")) && !tc.header {
				t.Error("response leaked signing material")
			}
			events := auditLog.GetEvents()
			if len(events) != 1 || events[0].EventType != audit.EventTypeAuthFailure || events[0].Success {
				t.Errorf("want exactly one failed-auth event, got %v", events)
			}
		})
	}
}

func TestPresignedTime_SignatureStillRequired(t *testing.T) {
	for _, mutation := range []string{"signature", "expiry", "scope_date"} {
		t.Run(mutation, func(t *testing.T) {
			req := presignedTimeRequest(t, time.Now().UTC().Add(-6*time.Minute), []string{"900"})
			q := req.URL.Query()
			switch mutation {
			case "signature":
				q.Set("X-Amz-Signature", strings.Repeat("0", 64))
			case "expiry":
				q.Set("X-Amz-Expires", "1800")
			case "scope_date":
				parts := strings.Split(q.Get("X-Amz-Credential"), "/")
				parts[1] = "20000101"
				q.Set("X-Amz-Credential", strings.Join(parts, "/"))
			}
			req.URL.RawQuery = q.Encode()
			ctx, err := ValidateSignatureV4(req, presignedTestSecret, 5*time.Minute)
			if ctx != nil {
				ctx.Close()
			}
			if err == nil || ctx != nil {
				t.Fatalf("tampered request accepted: context=%v error=%v", ctx, err)
			}
			logger := logrus.New()
			logger.SetOutput(io.Discard)
			rec := httptest.NewRecorder()
			AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, false)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("tampered request reached next")
			})).ServeHTTP(rec, req)
			if rec.Code != 403 || !strings.Contains(rec.Body.String(), "SignatureDoesNotMatch") {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}
