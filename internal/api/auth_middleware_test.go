package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/audit"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

func testCredentialStore() CredentialStore {
	store, _ := NewStaticCredentialStore([]config.GatewayCredential{
		{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Label: "test"},
	})
	return store
}

func signedPostPolicyRequest(t *testing.T, policyText string, fields map[string]string, filePayload string, boundary string) *http.Request {
	return signedPostPolicyRequestWithCredentials(t, policyText, fields, filePayload, boundary, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1")
}

func signedPostPolicyRequestWithCredentials(t *testing.T, policyText string, fields map[string]string, filePayload string, boundary, secret, region string) *http.Request {
	t.Helper()
	if boundary == "" {
		boundary = "auth-post-boundary"
	}
	date := fields["x-amz-date"]
	if len(date) < 8 {
		t.Fatal("signed POST fixture requires a valid x-amz-date")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(policyText))
	fields["policy"] = encoded
	fields["x-amz-signature"] = signPostPolicy(secret, date[:8], region, encoded)
	var body strings.Builder
	for name, value := range fields {
		fmt.Fprintf(&body, "--%s\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n", boundary, name, value)
	}
	fmt.Fprintf(&body, "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.jpg\"\r\n\r\n%s\r\n--%s--\r\n", boundary, filePayload, boundary)
	r := httptest.NewRequest(http.MethodPost, "/bucket", strings.NewReader(body.String()))
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	r.ContentLength = int64(body.Len())
	return r
}

func validSignedPostPolicyRequest(t *testing.T, expiration string) *http.Request {
	return validSignedPostPolicyRequestFor(t, expiration, "/bucket", "bucket", "test.jpg", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "")
}

func validSignedPostPolicyRequestFor(t *testing.T, expiration, target, bucket, key, accessKey, secret, region, filename string) *http.Request {
	t.Helper()
	date := time.Now().UTC().Format("20060102T150405Z")
	dateDay := date[:8]
	scope := accessKey + "/" + dateDay + "/" + region + "/s3/aws4_request"
	policyText := fmt.Sprintf(`{"expiration":%q,"conditions":[{"bucket":%q,"key":%q,"x-amz-algorithm":"AWS4-HMAC-SHA256","x-amz-credential":%q,"x-amz-date":%q}]}`, expiration, bucket, key, scope, date)
	fields := map[string]string{"bucket": bucket, "key": key, "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date}
	return buildSignedPostForm(t, target, policyText, fields, strings.Repeat("x", 64*1024), "auth-post-boundary", secret, region, filename)
}

func buildSignedPostForm(t *testing.T, target, policyText string, fields map[string]string, filePayload, boundary, secret, region, filename string) *http.Request {
	t.Helper()
	r := signedPostPolicyRequestWithCredentials(t, policyText, fields, filePayload, boundary, secret, region)
	r.URL.Path = target
	if filename != "" {
		body, _ := io.ReadAll(r.Body)
		text := strings.Replace(string(body), `filename="test.jpg"`, fmt.Sprintf("filename=%q", filename), 1)
		r.Body = io.NopCloser(strings.NewReader(text))
		r.ContentLength = int64(len(text))
	}
	return r
}

func validSignedSessionPostRequest(t *testing.T, expiration time.Time, token string) *http.Request {
	t.Helper()
	date := time.Now().UTC().Format("20060102T150405Z")
	day := date[:8]
	policyText := fmt.Sprintf(`{"expiration":%q,"conditions":[{"bucket":"bucket","key":"test.jpg","x-amz-algorithm":"AWS4-HMAC-SHA256","x-amz-credential":"AKIAIOSFODNN7EXAMPLE/%s/us-east-1/s3/aws4_request","x-amz-date":%q,"x-amz-security-token":%q}]}`, expiration.Format(time.RFC3339), day, date, token)
	fields := map[string]string{"bucket": "bucket", "key": "test.jpg", "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": "AKIAIOSFODNN7EXAMPLE/" + day + "/us-east-1/s3/aws4_request", "x-amz-date": date, "x-amz-security-token": token}
	return buildSignedPostForm(t, "/bucket", policyText, fields, strings.Repeat("s", 64*1024), "auth-session-boundary", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "")
}

func validSignedSessionPostRequestWithTimes(t *testing.T, policyExpiration, signedAt time.Time, token string) *http.Request {
	t.Helper()
	date := signedAt.UTC().Format("20060102T150405Z")
	day := date[:8]
	scope := "AKIAIOSFODNN7EXAMPLE/" + day + "/us-east-1/s3/aws4_request"
	policyText := fmt.Sprintf(`{"expiration":%q,"conditions":[{"bucket":"bucket","key":"test.jpg","x-amz-algorithm":"AWS4-HMAC-SHA256","x-amz-credential":%q,"x-amz-date":%q`, policyExpiration.UTC().Format(time.RFC3339Nano), scope, date)
	fields := map[string]string{"bucket": "bucket", "key": "test.jpg", "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date}
	if token != "" {
		policyText += fmt.Sprintf(`,"x-amz-security-token":%q`, token)
		fields["x-amz-security-token"] = token
	}
	policyText += `}]}`
	return buildSignedPostForm(t, "/bucket", policyText, fields, strings.Repeat("s", 64*1024), "auth-session-boundary", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "")
}

func validSignedStaticTokenPostRequest(t *testing.T, token string) *http.Request {
	t.Helper()
	date := time.Now().UTC().Format("20060102T150405Z")
	day := date[:8]
	scope := "AKIAIOSFODNN7EXAMPLE/" + day + "/us-east-1/s3/aws4_request"
	policyText := fmt.Sprintf(`{"expiration":%q,"conditions":[{"bucket":"bucket","key":"test.jpg","x-amz-algorithm":"AWS4-HMAC-SHA256","x-amz-credential":%q,"x-amz-date":%q,"x-amz-security-token":%q}]}`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), scope, date, token)
	fields := map[string]string{"bucket": "bucket", "key": "test.jpg", "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date, "x-amz-security-token": token}
	return buildSignedPostForm(t, "/bucket", policyText, fields, strings.Repeat("x", 64*1024), "auth-static-token-boundary", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "")
}

func buildSignedPostRequest(t *testing.T, target, bucket, formKey, policyKey, filename, accessKey, secret, region, token string, policyExpiration, signedAt time.Time) *http.Request {
	t.Helper()
	date := signedAt.UTC().Format("20060102T150405Z")
	day := date[:8]
	scope := accessKey + "/" + day + "/" + region + "/s3/aws4_request"
	policyText := fmt.Sprintf(`{"expiration":%q,"conditions":[{"bucket":%q},{"key":%q},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":%q},{"x-amz-date":%q}`, policyExpiration.UTC().Format(time.RFC3339Nano), bucket, policyKey, scope, date)
	fields := map[string]string{"bucket": bucket, "key": formKey, "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date}
	if token != "" {
		policyText += fmt.Sprintf(`,{"x-amz-security-token":%q}`, token)
		fields["x-amz-security-token"] = token
	}
	policyText += `]}`
	r := signedPostPolicyRequestWithCredentials(t, policyText, fields, strings.Repeat("p", 64*1024), "auth-post-boundary", secret, region)
	if filename != "" {
		data, _ := io.ReadAll(r.Body)
		text := strings.Replace(string(data), `filename="test.jpg"`, fmt.Sprintf("filename=%q", filename), 1)
		r.Body = io.NopCloser(strings.NewReader(text))
		r.ContentLength = int64(len(text))
	}
	r.URL.Path = target
	return r
}

func replaceRequestBody(t *testing.T, target *http.Request, source *http.Request) {
	t.Helper()
	target.Body = source.Body
	target.ContentLength = source.ContentLength
}

type observedRequestBody struct {
	io.Reader
	read int64
}

type chunkedBody struct {
	reader io.Reader
	max    int
}

func (r *chunkedBody) Read(p []byte) (int, error) {
	if len(p) > r.max {
		p = p[:r.max]
	}
	return r.reader.Read(p)
}

func (r *observedRequestBody) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.read += int64(n)
	return n, err
}

func (r *observedRequestBody) Close() error { return nil }

type postSpoolSpy struct{ acquired int }

func (s *postSpoolSpy) Acquire(context.Context, int64, int64) (SpoolReservation, error) {
	s.acquired++
	return nil, errors.New("unexpected spool reservation")
}

func TestGH353PostAuth_DeniedBeforeFileSpool(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	store, err := NewStaticCredentialStore([]config.GatewayCredential{{
		AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Label: "post-test",
		Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite),
	}})
	if err != nil {
		t.Fatal(err)
	}
	limits := NewSpoolLimitSource(SpoolLimits{Global: 256 * 1024, Part: 32 * 1024})
	tests := []struct {
		name       string
		mutate     func(*http.Request)
		wantCode   string
		wantStatus int
	}{
		{"bad signature", func(r *http.Request) { r.Body = tamperPostSignatureBody(r) }, "SignatureDoesNotMatch", http.StatusForbidden},
		{"malformed policy", func(r *http.Request) {
			r.Body = mutatePostScalarBody(r, "policy", base64.StdEncoding.EncodeToString([]byte("{")))
		}, "InvalidArgument", http.StatusBadRequest},
		{"missing form credential", func(r *http.Request) { r.Body = removePostScalarBody(r, "x-amz-credential") }, "AccessDenied", http.StatusForbidden},
		{"missing required signing date", func(r *http.Request) { r.Body = removePostScalarBody(r, "x-amz-date") }, "AccessDenied", http.StatusForbidden},
		{"duplicate credential", func(r *http.Request) { r.Body = duplicatePostScalarBody(r, "x-amz-date", "20300101T000000Z") }, "InvalidRequest", http.StatusBadRequest},
		{"mixed auth", func(r *http.Request) { r.Header.Set("Authorization", "AWS4-HMAC-SHA256 invalid") }, "InvalidRequest", http.StatusBadRequest},
		{"duplicate authorization", func(r *http.Request) { r.Header.Add("Authorization", "AWS4-HMAC-SHA256 second") }, "InvalidRequest", http.StatusBadRequest},
		{"lowercase authorization map alias", func(r *http.Request) { r.Header["authorization"] = []string{"AWS4-HMAC-SHA256 conflict"} }, "InvalidRequest", http.StatusBadRequest},
		{"mixed-case authorization map alias", func(r *http.Request) { r.Header["aUtHoRiZaTiOn"] = []string{"AWS4-HMAC-SHA256 conflict"} }, "InvalidRequest", http.StatusBadRequest},
		{"explicit empty authorization header", func(r *http.Request) { r.Header["Authorization"] = []string{""} }, "InvalidRequest", http.StatusBadRequest},
		{"unknown form access key", func(r *http.Request) {
			replaceRequestBody(t, r, buildSignedPostRequest(t, "/bucket", "bucket", "test.jpg", "test.jpg", "", "ASIAUNKNOWNKEY", "unknown-key-secret", "us-east-1", "", time.Now().UTC().Add(time.Hour), time.Now().UTC()))
		}, "InvalidAccessKeyId", http.StatusForbidden},
		{"future signing date", func(r *http.Request) {
			replaceRequestBody(t, r, buildSignedPostRequest(t, "/bucket", "bucket", "test.jpg", "test.jpg", "", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "", time.Now().UTC().Add(time.Hour), time.Now().UTC().Add(2*time.Hour)))
		}, "RequestTimeTooSkewed", http.StatusForbidden},
		{"uncovered signed field", func(r *http.Request) {
			r.Body = mutatePostScalarBody(r, "key", "test.jpg\r\n--auth-post-boundary\r\nContent-Disposition: form-data; name=\"acl\"\r\n\r\npublic-read")
		}, "AccessDenied", http.StatusForbidden},
		{"mismatched URL bucket", func(r *http.Request) { r.URL.Path = "/different" }, "AccessDenied", http.StatusForbidden},
		{"malformed multipart form", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("--auth-post-boundary\r\nbroken")) }, "InvalidRequest", http.StatusBadRequest},
		{"partial query auth stays ordinary auth", func(r *http.Request) { r.URL.RawQuery = "X-Amz-Signature=partial" }, "AccessDenied", http.StatusForbidden},
		{"raw query", func(r *http.Request) { r.URL.RawQuery = "x=1" }, "AccessDenied", http.StatusForbidden},
		{"missing content type", func(r *http.Request) { r.Header.Del("Content-Type") }, "AccessDenied", http.StatusForbidden},
		{"object selector", func(r *http.Request) { r.URL.Path = "/bucket/key" }, "AccessDenied", http.StatusForbidden},
		{"missing key maps to missing credentials", func(r *http.Request) {
			r.Body = removePostScalarBody(r, "key")
		}, "AccessDenied", http.StatusForbidden},
	}
	spoolSpy := &postSpoolSpy{}
	postAudit := audit.NewLogger(100, nil)
	staticStore, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, extraToken := range []string{"unexpected", ""} {
		staticTokenReq := validSignedStaticTokenPostRequest(t, extraToken)
		staticTokenReq.Header.Set("X-Test-Secret-Sentinel", "policy-secret-sentinel")
		observed := &observedRequestBody{Reader: &chunkedBody{reader: staticTokenReq.Body, max: 7}}
		staticTokenReq.Body = observed
		staticTokenCalled := false
		staticTokenRecorder := httptest.NewRecorder()
		AuthMiddleware(staticStore, time.Minute, logger, postAudit, true, limits, spoolSpy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { staticTokenCalled = true })).ServeHTTP(staticTokenRecorder, staticTokenReq)
		if staticTokenCalled || staticTokenRecorder.Code != http.StatusForbidden || !strings.Contains(staticTokenRecorder.Body.String(), "<Code>InvalidToken</Code>") || observed.read > postBeforeFileLimit+1 || spoolSpy.acquired != 0 {
			t.Fatalf("static extra token=%q called=%v status=%d bytes=%d quota=%d body=%s", extraToken, staticTokenCalled, staticTokenRecorder.Code, observed.read, spoolSpy.acquired, staticTokenRecorder.Body.String())
		}
	}
	sessionExpiry := time.Now().UTC().Add(time.Minute)
	sessionStore, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", SessionToken: "session-token", ExpiresAt: &sessionExpiry, Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}})
	if err != nil {
		t.Fatal(err)
	}
	sessionRequest := validSignedSessionPostRequest(t, time.Now().UTC().Add(time.Hour), "session-token")
	sessionCalled := false
	sessionRecorder := httptest.NewRecorder()
	AuthMiddleware(sessionStore, time.Minute, logger, nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upload, _ := postUploadFromContext(r)
		sessionCalled = upload != nil && upload.deadline.Equal(sessionExpiry)
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(sessionRecorder, sessionRequest)
	if !sessionCalled || sessionRecorder.Code != http.StatusNoContent {
		t.Fatalf("valid session POST called=%v status=%d body=%s", sessionCalled, sessionRecorder.Code, sessionRecorder.Body.String())
	}
	exclusiveExpiry := time.Now().UTC().Add(-time.Second)
	exclusiveStore, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", SessionToken: "session-token", ExpiresAt: &exclusiveExpiry, Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}})
	if err != nil {
		t.Fatal(err)
	}
	exclusiveRequest := validSignedSessionPostRequestWithTimes(t, time.Now().UTC().Add(time.Hour), time.Now().UTC(), "session-token")
	exclusiveCalled := false
	exclusiveRecorder := httptest.NewRecorder()
	AuthMiddleware(exclusiveStore, time.Minute, logger, nil, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { exclusiveCalled = true })).ServeHTTP(exclusiveRecorder, exclusiveRequest)
	if exclusiveCalled || exclusiveRecorder.Code != http.StatusForbidden || !strings.Contains(exclusiveRecorder.Body.String(), "<Code>ExpiredToken</Code>") {
		t.Fatalf("exclusive session deadline called=%v status=%d body=%s", exclusiveCalled, exclusiveRecorder.Code, exclusiveRecorder.Body.String())
	}
	expiredPolicyStore, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}})
	if err != nil {
		t.Fatal(err)
	}
	expiredPolicyRequest := buildSignedPostRequest(t, "/bucket", "bucket", "test.jpg", "test.jpg", "", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "", time.Now().UTC().Add(-time.Second), time.Now().UTC())
	expiredPolicyObserved := &observedRequestBody{Reader: &chunkedBody{reader: expiredPolicyRequest.Body, max: 1}}
	expiredPolicyRequest.Body = expiredPolicyObserved
	expiredPolicyCalled := false
	expiredPolicyRecorder := httptest.NewRecorder()
	AuthMiddleware(expiredPolicyStore, time.Minute, logger, postAudit, true, limits, spoolSpy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { expiredPolicyCalled = true })).ServeHTTP(expiredPolicyRecorder, expiredPolicyRequest)
	if expiredPolicyCalled || expiredPolicyRecorder.Code != http.StatusForbidden || !strings.Contains(expiredPolicyRecorder.Body.String(), "Request has expired.") || expiredPolicyObserved.read > postBeforeFileLimit+1 || spoolSpy.acquired != 0 {
		t.Fatalf("expired policy called=%v status=%d bytes=%d quota=%d body=%s", expiredPolicyCalled, expiredPolicyRecorder.Code, expiredPolicyObserved.read, spoolSpy.acquired, expiredPolicyRecorder.Body.String())
	}
	expiredAt := time.Now().UTC().Add(-time.Second)
	expiredStore, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", SessionToken: "session-token", ExpiresAt: &expiredAt, Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}})
	if err != nil {
		t.Fatal(err)
	}
	expiredRequest := validSignedSessionPostRequestWithTimes(t, time.Now().UTC().Add(time.Hour), time.Now().UTC(), "session-token")
	expiredObserved := &observedRequestBody{Reader: &chunkedBody{reader: expiredRequest.Body, max: 1}}
	expiredRequest.Body = expiredObserved
	expiredCalled := false
	expiredRecorder := httptest.NewRecorder()
	AuthMiddleware(expiredStore, time.Minute, logger, nil, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { expiredCalled = true })).ServeHTTP(expiredRecorder, expiredRequest)
	if expiredCalled || expiredRecorder.Code != http.StatusForbidden || !strings.Contains(expiredRecorder.Body.String(), "<Code>ExpiredToken</Code>") || expiredObserved.read > postBeforeFileLimit+1 || spoolSpy.acquired != 0 {
		t.Fatalf("expired session POST called=%v status=%d bytes=%d quota=%d body=%s", expiredCalled, expiredRecorder.Code, expiredObserved.read, spoolSpy.acquired, expiredRecorder.Body.String())
	}
	for _, denied := range []struct {
		name  string
		token string
	}{
		{"missing session token", ""}, {"wrong session token", "other-token"},
	} {
		t.Run(denied.name, func(t *testing.T) {
			req := validSignedSessionPostRequestWithTimes(t, time.Now().UTC().Add(time.Hour), time.Now().UTC(), denied.token)
			observed := &observedRequestBody{Reader: &chunkedBody{reader: req.Body, max: 7}}
			req.Body = observed
			called := false
			rec := httptest.NewRecorder()
			AuthMiddleware(sessionStore, time.Minute, logger, nil, true, limits, spoolSpy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)
			if called || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "<Code>InvalidToken</Code>") || observed.read > postBeforeFileLimit+1 || spoolSpy.acquired != 0 {
				t.Fatalf("called=%v status=%d bytes=%d quota=%d body=%s", called, rec.Code, observed.read, spoolSpy.acquired, rec.Body.String())
			}
		})
	}
	for _, tc := range []struct {
		name     string
		token    string
		wantCode string
	}{
		{"missing required session token", "", "InvalidToken"},
		{"wrong session token", "wrong-token", "InvalidToken"},
	} {
		t.Run("session-case/"+tc.name, func(t *testing.T) {
			req := validSignedSessionPostRequestWithTimes(t, time.Now().UTC().Add(time.Hour), time.Now().UTC(), tc.token)
			observed := &observedRequestBody{Reader: &chunkedBody{reader: req.Body, max: 7}}
			req.Body = observed
			called := false
			rec := httptest.NewRecorder()
			AuthMiddleware(sessionStore, time.Minute, logger, postAudit, true, limits, spoolSpy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)
			if called || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "<Code>"+tc.wantCode+"</Code>") || observed.read > postBeforeFileLimit+1 || spoolSpy.acquired != 0 {
				t.Fatalf("called=%v status=%d bytes=%d quota=%d body=%s", called, rec.Code, observed.read, spoolSpy.acquired, rec.Body.String())
			}
		})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := validSignedPostPolicyRequest(t, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
			if tc.mutate != nil {
				tc.mutate(req)
			}
			observed := &observedRequestBody{Reader: req.Body}
			if tc.name == "bad signature" || strings.Contains(tc.name, "auth") || tc.name == "future signing date" || tc.name == "unknown form access key" {
				observed.Reader = &chunkedBody{reader: observed.Reader, max: 7}
			}
			req.Body = observed
			nextCalled := false
			h := AuthMiddleware(store, time.Minute, logger, postAudit, true, limits, spoolSpy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true }))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if nextCalled || rec.Code != tc.wantStatus || !strings.Contains(rec.Body.String(), "<Code>"+tc.wantCode+"</Code>") {
				t.Fatalf("next=%v status=%d want=%d body=%s", nextCalled, rec.Code, tc.wantStatus, rec.Body.String())
			}
			if (tc.name == "bad signature" || strings.Contains(tc.name, "auth") || tc.name == "future signing date" || tc.name == "unknown form access key") && observed.read > postBeforeFileLimit+1 {
				t.Fatalf("rejected auth consumed %d bytes before authorization", observed.read)
			}
			if spoolSpy.acquired != 0 {
				t.Fatalf("auth failure acquired %d spool reservations", spoolSpy.acquired)
			}
			if strings.Contains(rec.Body.String(), "unknown-key-secret") || strings.Contains(rec.Body.String(), "test-secret") {
				t.Fatal("auth response leaked signing material")
			}
			for _, event := range postAudit.GetEvents() {
				encoded := fmt.Sprintf("%+v", event)
				for _, secret := range []string{"unknown-key-secret", "session-token", "policy-secret-sentinel", "x-amz-signature", "eyJleHBpcmF0aW9u"} {
					if strings.Contains(encoded, secret) {
						t.Fatalf("POST auth audit leaked sensitive value %q", secret)
					}
				}
			}
		})
	}
	for _, tc := range []struct {
		name       string
		credential config.GatewayCredential
		proxied    string
	}{
		{"read only", config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadOnly)}, ""},
		{"scope", config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"other"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}, ""},
		{"global bucket", config.GatewayCredential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}, "other"},
	} {
		t.Run("authorization/"+tc.name, func(t *testing.T) {
			denialStore, err := NewStaticCredentialStore([]config.GatewayCredential{tc.credential})
			if err != nil {
				t.Fatal(err)
			}
			req := validSignedPostPolicyRequest(t, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
			observed := &observedRequestBody{Reader: req.Body}
			observed.Reader = &chunkedBody{reader: observed.Reader, max: 7}
			req.Body = observed
			nextCalled := false
			chain := AuthMiddleware(denialStore, time.Minute, logger, postAudit, true, limits, spoolSpy)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upload, ok := postUploadFromContext(r)
				if !ok || upload.fileCounter == nil || upload.fileCounter.wire == nil || upload.fileCounter.wire.fileBytes != 0 {
					t.Errorf("authorization began after file consumption: upload=%+v", upload)
				}
				AuthorizationMiddleware(tc.proxied, postAudit)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })).ServeHTTP(w, r)
			}))
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, req)
			if nextCalled || rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "<Code>AccessDenied</Code>") {
				t.Fatalf("authorization next=%v status=%d body=%s", nextCalled, rec.Code, rec.Body.String())
			}
			if observed.read > postBeforeFileLimit+1 {
				t.Fatalf("authorization denied after reading %d bytes", observed.read)
			}
			if spoolSpy.acquired != 0 {
				t.Fatalf("authorization denial acquired %d spool reservations", spoolSpy.acquired)
			}
			for _, event := range postAudit.GetEvents() {
				encoded := fmt.Sprintf("%+v", event)
				for _, secret := range []string{"session-token", "test-secret", "x-amz-signature", "eyJleHBpcmF0aW9u"} {
					if strings.Contains(encoded, secret) {
						t.Fatalf("POST authorization audit leaked sensitive value %q", secret)
					}
				}
			}
		})
	}

	req := validSignedPostPolicyRequest(t, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	observed := &observedRequestBody{Reader: &chunkedBody{reader: req.Body, max: 1}}
	req.Body = observed
	var called bool
	var capturedUpload *postUpload
	var capturedCredential Credential
	auth := AuthMiddleware(store, time.Minute, logger, postAudit, true, limits, spoolSpy)
	h := auth(AuthorizationMiddleware("", postAudit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if CredentialLabelFromContext(r) != "post-test" {
			t.Errorf("credential label missing")
		}
		credential, ok := CredentialFromContext(r)
		capturedCredential = credential
		if !ok || credential.AccessKey != "AKIAIOSFODNN7EXAMPLE" {
			t.Errorf("principal missing: %+v %t", credential, ok)
		}
		if credential.SecretKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" || credential.Label != "post-test" {
			t.Errorf("authorization received wrong principal snapshot: %+v", credential)
		}
		upload, ok := postUploadFromContext(r)
		capturedUpload = upload
		if !ok || upload.bucket != "bucket" || upload.key != "test.jpg" || upload.limitSnapshot != (SpoolLimits{Global: 256 * 1024, Part: 32 * 1024}) {
			t.Errorf("POST context=%+v ok=%t", upload, ok)
		}
		if upload.fileCounter == nil || upload.fileCounter.wire == nil || upload.fileCounter.wire.fileBytes != 0 {
			t.Errorf("positive request consumed file bytes before downstream entry: %+v", upload.fileCounter)
		}
		limits.Set(SpoolLimits{Global: 128 * 1024, Part: 16 * 1024})
		if err := store.Replace([]config.GatewayCredential{{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "rotated-secret", Label: "rotated", Buckets: []string{"new-bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadOnly)}}); err != nil {
			t.Errorf("rotate credentials during request: %v", err)
		}
		if credential.SecretKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" || credential.Label != "post-test" || credential.Policy.Permissions != config.ObjectPermissionReadWrite || !credential.AllowsBucket("bucket") {
			t.Errorf("captured authenticated snapshot changed during replacement: %+v", credential)
		}
		if upload.limitSnapshot.Global != 256*1024 || upload.limitSnapshot.Part != 32*1024 {
			t.Errorf("request limits changed under request: %+v", upload.limitSnapshot)
		}
		read, err := io.Copy(io.Discard, upload.fileRead)
		if err != nil || read != 64*1024 {
			t.Errorf("file read=%d err=%v", read, err)
		}
		if err := upload.Finish(); err != nil {
			t.Errorf("Finish: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusNoContent || observed.read < 64*1024 {
		t.Fatalf("called=%v status=%d body-read=%d", called, rec.Code, observed.read)
	}
	if capturedUpload == nil || capturedUpload.file != nil || capturedUpload.fields != nil || capturedUpload.fileRead != nil {
		t.Fatalf("request cleanup did not clear upload: %+v", capturedUpload)
	}
	if spoolSpy.acquired != 0 {
		t.Fatalf("auth chain unexpectedly acquired %d spool reservations", spoolSpy.acquired)
	}
	if capturedCredential.SecretKey != "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" || capturedCredential.Label != "post-test" || !capturedCredential.AllowsBucket("bucket") {
		t.Fatalf("in-flight credential snapshot mutated after next returned: %+v", capturedCredential)
	}
	nextRequest := validSignedPostPolicyRequest(t, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	nextSawLimits := false
	nextLabel := ""
	nextHandler := auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upload, _ := postUploadFromContext(r)
		nextSawLimits = upload != nil && upload.limitSnapshot == (SpoolLimits{Global: 128 * 1024, Part: 16 * 1024})
		credential, _ := CredentialFromContext(r)
		nextLabel = CredentialLabelFromContext(r)
		if credential.SecretKey != "rotated-secret" || credential.Policy.Permissions != config.ObjectPermissionReadOnly || !credential.AllowsBucket("new-bucket") {
			t.Errorf("next request did not observe new snapshot: %+v", credential)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	nextRequest = buildSignedPostRequest(t, "/new-bucket", "new-bucket", "test.jpg", "test.jpg", "", "AKIAIOSFODNN7EXAMPLE", "rotated-secret", "us-east-1", "", time.Now().UTC().Add(time.Hour), time.Now().UTC())
	nextRecorder := httptest.NewRecorder()
	nextHandler.ServeHTTP(nextRecorder, nextRequest)
	if !nextSawLimits || nextRecorder.Code != http.StatusNoContent || nextLabel != "rotated" {
		t.Fatalf("next request snapshot: limitsSeen=%v label=%q status=%d body=%s", nextSawLimits, nextLabel, nextRecorder.Code, nextRecorder.Body.String())
	}
	oldSecretRequest := validSignedPostPolicyRequest(t, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	oldBodyCounter := &observedRequestBody{Reader: &chunkedBody{reader: oldSecretRequest.Body, max: 1}}
	oldSecretRequest.Body = oldBodyCounter
	oldSecretCalled := false
	oldSecretRecorder := httptest.NewRecorder()
	AuthMiddleware(store, time.Minute, logger, postAudit, true, limits, spoolSpy)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { oldSecretCalled = true })).ServeHTTP(oldSecretRecorder, oldSecretRequest)
	if oldSecretCalled || oldSecretRecorder.Code != http.StatusForbidden || !strings.Contains(oldSecretRecorder.Body.String(), "<Code>SignatureDoesNotMatch</Code>") || oldBodyCounter.read > postBeforeFileLimit+1 || spoolSpy.acquired != 0 {
		t.Fatalf("old secret request called=%v status=%d bytes=%d quota=%d", oldSecretCalled, oldSecretRecorder.Code, oldBodyCounter.read, spoolSpy.acquired)
	}
	for _, filename := range []string{"plain + plus.txt", "dir/sub.dot/../literal.txt", "雪だるま.txt"} {
		key := "prefix/${filename}/tail/"
		base := filename
		if slash := strings.LastIndexAny(base, "/\\"); slash >= 0 {
			base = base[slash+1:]
		}
		effectiveKey := strings.ReplaceAll(key, "${filename}", base)
		date := time.Now().UTC().Format("20060102T150405Z")
		scope := "AKIAIOSFODNN7EXAMPLE/" + date[:8] + "/us-east-1/s3/aws4_request"
		policy := fmt.Sprintf(`{"expiration":%q,"conditions":[{"bucket":"bucket"},{"key":%q},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":%q},{"x-amz-date":%q}]}`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), effectiveKey, scope, date)
		fields := map[string]string{"bucket": "bucket", "key": key, "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date}
		req := buildSignedPostForm(t, "/bucket", policy, fields, "positive", "auth-post-boundary", "rotated-secret", "us-east-1", filename)
		rotatedStore, err := NewStaticCredentialStore([]config.GatewayCredential{{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "rotated-secret", Label: "rotated", Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite)}})
		if err != nil {
			t.Fatal(err)
		}
		called := false
		rec := httptest.NewRecorder()
		AuthMiddleware(rotatedStore, time.Minute, logger, postAudit, true, limits)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upload, ok := postUploadFromContext(r)
			wantKey := effectiveKey
			if !ok || upload.key != wantKey || upload.fileCounter.wire.fileBytes != 0 {
				t.Errorf("filename %q upload=%+v want key=%q", filename, upload, wantKey)
			}
			called = true
			if _, err := io.Copy(io.Discard, upload.fileRead); err != nil {
				t.Errorf("filename %q read: %v", filename, err)
			}
			if err := upload.Finish(); err != nil {
				t.Errorf("filename %q Finish: %v", filename, err)
			}
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(rec, req)
		if !called || rec.Code != http.StatusNoContent {
			t.Fatalf("filename %q called=%v status=%d body=%s", filename, called, rec.Code, rec.Body.String())
		}
	}
}

func permissionPtr(p config.ObjectPermission) *config.ObjectPermission { return &p }

func tamperPostSignatureBody(r *http.Request) io.ReadCloser {
	data, _ := io.ReadAll(r.Body)
	text := string(data)
	const signature = "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"
	if strings.Contains(text, signature) {
		text = strings.Replace(text, signature, "0"+signature[1:], 1)
	} else {
		// The generated signature is dynamic, so alter the value in its named
		// scalar part while preserving the rest of the multipart wire.
		if index := strings.Index(text, "name=\"x-amz-signature\""); index >= 0 {
			if start := strings.Index(text[index:], "\r\n\r\n"); start >= 0 {
				value := index + start + 4
				if value < len(text) {
					replacement := byte('0')
					if text[value] == replacement {
						replacement = '1'
					}
					text = text[:value] + string(replacement) + text[value+1:]
				}
			}
		}
	}
	return io.NopCloser(strings.NewReader(text))
}

func mutatePostScalarBody(r *http.Request, field, value string) io.ReadCloser {
	data, _ := io.ReadAll(r.Body)
	text := string(data)
	marker := "name=\"" + field + "\""
	if index := strings.Index(text, marker); index >= 0 {
		if start := strings.Index(text[index:], "\r\n\r\n"); start >= 0 {
			valueStart := index + start + 4
			valueEnd := strings.Index(text[valueStart:], "\r\n")
			if valueEnd >= 0 {
				text = text[:valueStart] + value + text[valueStart+valueEnd:]
			}
		}
	}
	return io.NopCloser(strings.NewReader(text))
}

func removePostScalarBody(r *http.Request, field string) io.ReadCloser {
	data, _ := io.ReadAll(r.Body)
	text := string(data)
	name := "name=\"" + field + "\""
	if index := strings.Index(text, name); index >= 0 {
		start := strings.LastIndex(text[:index], "--")
		end := strings.Index(text[index:], "\r\n--")
		if start >= 0 && end >= 0 {
			text = text[:start] + text[index+end+2:]
		}
	}
	return io.NopCloser(strings.NewReader(text))
}

func duplicatePostScalarBody(r *http.Request, field, value string) io.ReadCloser {
	data, _ := io.ReadAll(r.Body)
	text := string(data)
	marker := "name=\"" + field + "\""
	if index := strings.Index(text, marker); index >= 0 {
		end := strings.Index(text[index:], "\r\n")
		if end >= 0 {
			partStart := strings.LastIndex(text[:index], "--")
			partEnd := strings.Index(text[index+end:], "\r\n--")
			if partStart >= 0 && partEnd >= 0 {
				partEnd = index + end + partEnd
				part := text[partStart:partEnd]
				text = text[:partEnd] + part + "\r\n" + value + text[partEnd:]
			}
		}
	}
	return io.NopCloser(strings.NewReader(text))
}

func TestAuthMiddleware_NoCredentials(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "AccessDenied") {
		t.Errorf("body = %q, want AccessDenied", body)
	}
}

func TestIsUnauthenticatedCORSPreflight(t *testing.T) {
	tests := []struct {
		name            string
		method          string
		path            string
		origin          string
		requestedMethod string
		authorization   string
		want            bool
	}{
		{name: "bucket preflight", method: http.MethodOptions, path: "/bucket", origin: "https://example.com", requestedMethod: http.MethodPut, want: true},
		{name: "object preflight", method: http.MethodOptions, path: "/bucket/object", origin: "https://example.com", requestedMethod: http.MethodPut, want: true},
		{name: "missing origin", method: http.MethodOptions, path: "/bucket/object", requestedMethod: http.MethodPut},
		{name: "missing requested method", method: http.MethodOptions, path: "/bucket/object", origin: "https://example.com"},
		{name: "non-options", method: http.MethodPut, path: "/bucket/object", origin: "https://example.com", requestedMethod: http.MethodPut},
		{name: "root path", method: http.MethodOptions, path: "/", origin: "https://example.com", requestedMethod: http.MethodPut},
		{name: "signed authorization", method: http.MethodOptions, path: "/bucket/object", origin: "https://example.com", requestedMethod: http.MethodPut, authorization: "AWS4-HMAC-SHA256 Credential=key/date/region/s3/aws4_request"},
		{name: "presigned credentials", method: http.MethodOptions, path: "/bucket/object?X-Amz-Credential=key/date/region/s3/aws4_request", origin: "https://example.com", requestedMethod: http.MethodPut},
		{name: "partial presigned signature", method: http.MethodOptions, path: "/bucket/object?X-Amz-Signature=signature", origin: "https://example.com", requestedMethod: http.MethodPut},
		{name: "partial sigv2 credentials", method: http.MethodOptions, path: "/bucket/object?Expires=123", origin: "https://example.com", requestedMethod: http.MethodPut},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", tt.requestedMethod)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			if got := isUnauthenticatedCORSPreflight(req); got != tt.want {
				t.Fatalf("isUnauthenticatedCORSPreflight() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthMiddleware_CORSPreflightBypassReachesNext(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	h := AuthMiddleware(testCredentialStore(), time.Minute, logger, nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/bucket/object", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodPut)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestAuthMiddleware_IncompleteCORSPreflightStillRequiresCredentials(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	h := AuthMiddleware(testCredentialStore(), time.Minute, logger, nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next called for incomplete CORS preflight")
	}))

	req := httptest.NewRequest(http.MethodOptions, "/bucket/object", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestAuthMiddleware_UnknownAccessKey(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/bucket/key?AWSAccessKeyId=UNKNOWN&Signature=xyz&AWSSecretAccessKey=dummy", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestAuthMiddleware_SigV2_Valid(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use a dynamic expires 1 hour from now — within the 7-day upper bound.
	expires := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)

	q := url.Values{}
	q.Set("AWSAccessKeyId", "AKIAIOSFODNN7EXAMPLE")
	q.Set("Expires", expires)
	q.Set("AWSSecretAccessKey", "dummy")

	stringToSign := "GET\n\n\n" + expires + "\n/bucket/key"
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), []byte(stringToSign)))
	q.Set("Signature", sig)

	req := httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAuthMiddleware_SigV2_SubresourceSubstitutionRejected(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	called := false
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) }))
	date := time.Now().UTC().Format(time.RFC1123)
	req := httptest.NewRequest("GET", "/bucket/key?acl", nil)
	req.Header.Set("Date", date)
	// The signature covers the literal /bucket/key?acl canonical resource.
	stringToSign := "GET\n\n\n" + date + "\n/bucket/key?acl"
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secret), []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+sig)
	req.URL.RawQuery = "versioning"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || called || !strings.Contains(rec.Body.String(), "SignatureDoesNotMatch") {
		t.Fatalf("status=%d called=%v, want forbidden and no downstream call", rec.Code, called)
	}
}

func TestAuthMiddleware_SigV2_MultipartUploadIDMutationRejected(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	called := false
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	date := time.Now().UTC().Format(time.RFC1123)
	req := httptest.NewRequest("POST", "/bucket/key?uploadId=one", nil)
	req.Header.Set("Date", date)
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secret), []byte("POST\n\n\n"+date+"\n/bucket/key?uploadId=one")))
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+sig)
	req.URL.RawQuery = "uploadId=two"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || called || !strings.Contains(rec.Body.String(), "SignatureDoesNotMatch") {
		t.Fatalf("status=%d called=%v", rec.Code, called)
	}
}

func TestAuthMiddleware_SigV2_ValidSignedSubresourceAccepted(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	called := false
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusOK) }))
	date := time.Now().UTC().Format(time.RFC1123)
	req := httptest.NewRequest("GET", "/bucket/key?acl", nil)
	req.Header.Set("Date", date)
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secret), []byte("GET\n\n\n"+date+"\n/bucket/key?acl")))
	req.Header.Set("Authorization", "AWS AKIAIOSFODNN7EXAMPLE:"+sig)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("status=%d called=%v", rec.Code, called)
	}
}

func TestAuthMiddleware_SigV2_BadSignature(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/bucket/key?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=bad-signature&Expires=1893456000&AWSSecretAccessKey=dummy", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestAuthMiddleware_SigV2_Expired(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Expires 1 hour ago — should be rejected
	expires := strconv.FormatInt(time.Now().Add(-1*time.Hour).Unix(), 10)
	q := url.Values{}
	q.Set("AWSAccessKeyId", "AKIAIOSFODNN7EXAMPLE")
	q.Set("Expires", expires)
	q.Set("AWSSecretAccessKey", "dummy")
	q.Set("Signature", "badsignature")

	req := httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestAuthMiddleware_SigV2_ExpiryExceedsMaxDuration verifies that SigV2 presigned URLs
// a SigV2 presigned URL with Expires more than 7 days in the future is rejected.
func TestAuthMiddleware_SigV2_ExpiryExceedsMaxDuration(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Expires 8 days from now — exceeds the 7-day cap (604800 s).
	expires := strconv.FormatInt(time.Now().Add(8*24*time.Hour).Unix(), 10)
	q := url.Values{}
	q.Set("AWSAccessKeyId", "AKIAIOSFODNN7EXAMPLE")
	q.Set("Expires", expires)
	q.Set("AWSSecretAccessKey", "dummy")
	q.Set("Signature", "irrelevant") // rejected before signature check

	req := httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// TestAuthMiddleware_SigV2_DisabledByPolicy verifies that
// when allowSigV2=false, SigV2 requests are rejected with SignatureDoesNotMatch.
func TestAuthMiddleware_SigV2_DisabledByPolicy(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	// allowSigV2=false enforces V4-only policy
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, false)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	expires := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	q := url.Values{}
	q.Set("AWSAccessKeyId", "AKIAIOSFODNN7EXAMPLE")
	q.Set("Expires", expires)
	q.Set("AWSSecretAccessKey", "dummy")

	stringToSign := "GET\n\n\n" + expires + "\n/bucket/key"
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), []byte(stringToSign)))
	q.Set("Signature", sig)

	req := httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "SignatureDoesNotMatch") {
		t.Errorf("body = %q, want SignatureDoesNotMatch", body)
	}
}

func TestAuthMiddleware_PresignedV4_Expired(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	oldDate := "20000101T000000Z"
	req := httptest.NewRequest("GET", "/bucket/key?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20000101/us-east-1/s3/aws4_request&X-Amz-Date="+oldDate+"&X-Amz-Expires=1&X-Amz-SignedHeaders=host&X-Amz-Signature=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestAuthMiddleware_ContextLabel(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	var capturedLabel string
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedLabel = CredentialLabelFromContext(r)
		w.WriteHeader(http.StatusOK)
	}))

	// Use a dynamic expires 1 hour from now — within the 7-day upper bound.
	expires := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)

	q := url.Values{}
	q.Set("AWSAccessKeyId", "AKIAIOSFODNN7EXAMPLE")
	q.Set("Expires", expires)
	q.Set("AWSSecretAccessKey", "dummy")

	stringToSign := "GET\n\n\n" + expires + "\n/bucket/key"
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), []byte(stringToSign)))
	q.Set("Signature", sig)

	req := httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if capturedLabel != "test" {
		t.Errorf("context label = %q, want %q", capturedLabel, "test")
	}
}

func TestAuthMiddleware_SigV4_Valid(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	region := "us-east-1"
	service := "s3"
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Host = "localhost"
	req.Header.Set("X-Amz-Date", timestamp)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	signedHdrs := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalReq, err := createCanonicalRequest(req, false, signedHdrs)
	if err != nil {
		t.Fatalf("createCanonicalRequest() error: %v", err)
	}

	stringToSign := createStringToSign(timestamp, credScope, canonicalReq)
	signingKey := getSignatureKey(secretKey, date, region, service)
	sig := hex.EncodeToString(sign(signingKey, []byte(stringToSign)))

	signedHdrsStr := strings.Join(signedHdrs, ";")
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/%s, SignedHeaders=%s, Signature=%s",
		credScope, signedHdrsStr, sig)
	req.Header.Set("Authorization", authHeader)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAuthMiddleware_SigV4ConcretePayloadHash_ValidBodyReplayedToNext(t *testing.T) {
	cases := []struct {
		name string
		body []byte
	}{
		{name: "text", body: []byte("middleware verified body")},
		{name: "binary", body: []byte{0x00, 0xff, 0xfe, 'a', 0x00, 0x80}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := signedConcreteRequest(t, tc.body)
			var got []byte
			h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got, _ = io.ReadAll(r.Body)
				if r.ContentLength != int64(len(tc.body)) || r.Header.Get("Content-Length") != fmt.Sprint(len(tc.body)) {
					t.Errorf("length fields not normalized")
				}
				w.WriteHeader(http.StatusOK)
			}))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK || !bytes.Equal(got, tc.body) {
				t.Fatalf("status %d body %v", rec.Code, got)
			}
		})
	}
}

func TestAuthMiddleware_SigV4ConcretePayloadHash_TamperedBodyRejectedBeforeNext(t *testing.T) {
	req := signedConcreteRequest(t, []byte("original"))
	req.Body = io.NopCloser(strings.NewReader("tampered"))
	next := false
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "SignatureDoesNotMatch") || next {
		t.Fatalf("code=%d next=%v body=%s", rec.Code, next, rec.Body.String())
	}
}

func TestAuthMiddleware_OperationalLookupError(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	nextCalled := false
	h := AuthMiddleware(sec41LookupErrorStore{}, time.Minute, logger, nil, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	}))
	req := httptest.NewRequest("GET", "/bucket/key?AWSAccessKeyId=key&Signature=x&Expires=1893456000", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || nextCalled || !strings.Contains(rec.Body.String(), "InvalidAccessKeyId") {
		t.Fatalf("lookup failure: status=%d next=%v body=%s", rec.Code, nextCalled, rec.Body.String())
	}
}

func TestAuthMiddleware_UnsupportedStreamingModeAudited(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	auditLogger := audit.NewLogger(10, nil)
	h := AuthMiddleware(testCredentialStore(), time.Minute, logger, auditLogger, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next called for unsupported streaming mode")
	}))
	req := sec41AuthRequestBody(http.MethodPut, "/bucket/streaming", "STREAMING-UNKNOWN", "", 0, "")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "InvalidRequest") {
		t.Fatalf("streaming failure: status=%d body=%s", rec.Code, rec.Body.String())
	}
	if len(auditLogger.GetEvents()) != 1 {
		t.Fatalf("audit events=%d, want 1", len(auditLogger.GetEvents()))
	}
}

func TestAuthMiddleware_ValidV2AttachesLabel(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	var gotLabel string
	h := AuthMiddleware(testCredentialStore(), time.Minute, logger, nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLabel = CredentialLabelFromContext(r)
		w.WriteHeader(http.StatusOK)
	}))
	expires := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	q := url.Values{"AWSAccessKeyId": {"AKIAIOSFODNN7EXAMPLE"}, "Expires": {expires}, "AWSSecretAccessKey": {"dummy"}}
	stringToSign := "GET\n\n\n" + expires + "\n/bucket/key"
	q.Set("Signature", base64.StdEncoding.EncodeToString(hmacSHA1([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), []byte(stringToSign))))
	req := httptest.NewRequest(http.MethodGet, "/bucket/key?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || gotLabel != "test" {
		t.Fatalf("v2 request: status=%d label=%q body=%s", rec.Code, gotLabel, rec.Body.String())
	}
}

func TestAuthMiddleware_SigV4UnsignedPayload_DoesNotPreReadBody(t *testing.T) {
	req := signedConcreteRequest(t, nil)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	resignV4Request(t, req, "UNSIGNED-PAYLOAD")
	read := false
	body := []byte("unsigned body")
	req.Body = trackingBody{Reader: bytes.NewReader(body), read: &read}
	entered := false
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered = true
		if read {
			t.Fatal("body was read before next")
		}
		got, err := io.ReadAll(r.Body)
		if err != nil || !bytes.Equal(got, body) {
			t.Fatalf("body=%q err=%v", got, err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !entered || !read {
		t.Fatalf("code=%d entered=%v read=%v", rec.Code, entered, read)
	}
}

func resignV4Request(t *testing.T, req *http.Request, payloadHash string) {
	t.Helper()
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	timestamp := req.Header.Get("X-Amz-Date")
	date := timestamp[:8]
	scope := date + "/us-east-1/s3/aws4_request"
	signed := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonical, err := createCanonicalRequest(req, false, signed)
	if err != nil {
		t.Fatal(err)
	}
	key := getSignatureKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", date, "us-east-1", "s3")
	sig := hex.EncodeToString(sign(key, []byte(createStringToSign(timestamp, scope, canonical))))
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/%s, SignedHeaders=%s, Signature=%s", scope, strings.Join(signed, ";"), sig))
}

type trackingBody struct {
	io.Reader
	read *bool
}

func (b trackingBody) Close() error { return nil }

func (b trackingBody) Read(p []byte) (int, error) { *b.read = true; return b.Reader.Read(p) }

func TestAuthMiddleware_SigV4ConcretePayloadHash_EmptyBody(t *testing.T) {
	req := signedConcreteRequest(t, nil)
	called := false
	h := AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		data, _ := io.ReadAll(r.Body)
		if len(data) != 0 {
			t.Fatal("non-empty body")
		}
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("code=%d called=%v", rec.Code, called)
	}
}

func TestAuthMiddleware_SigV4ConcretePayloadHash_SpoolFailureReturnsInternalError(t *testing.T) {
	original := streamingSpoolOps
	t.Cleanup(func() { streamingSpoolOps = original })
	streamingSpoolOps.createTemp = func(string, string) (*os.File, error) { return nil, errors.New("create") }
	auditLogger := audit.NewLogger(10, nil)
	rec := httptest.NewRecorder()
	AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), auditLogger, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next called") })).ServeHTTP(rec, signedConcreteRequest(t, []byte("body")))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "InternalError") {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	events := auditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("audit events=%d, want one %q event", len(events), ErrStreamingSpool)
	}
	if events[0].Error != ErrStreamingSpool.Error() {
		t.Fatalf("audit error=%q, want %q", events[0].Error, ErrStreamingSpool)
	}
}

func TestAuthMiddleware_SigV4ConcretePayloadHash_CanceledRequestReturnsIncompleteBody(t *testing.T) {
	req := signedConcreteRequest(t, []byte("body"))
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	auditLogger := audit.NewLogger(10, nil)
	AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), auditLogger, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("next called") })).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "IncompleteBody") {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	events := auditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("audit events=%d, want one %q event", len(events), ErrStreamingCanceled)
	}
	if events[0].Error != ErrStreamingCanceled.Error() {
		t.Fatalf("audit error=%q, want %q", events[0].Error, ErrStreamingCanceled)
	}
}

func TestAuthMiddleware_SigV4ConcretePayloadHash_SpoolRemovedAfterNext(t *testing.T) {
	var path string
	original := streamingSpoolOps
	t.Cleanup(func() { streamingSpoolOps = original })
	streamingSpoolOps.createTemp = func(d, p string) (*os.File, error) {
		f, err := original.createTemp(d, p)
		if err == nil {
			path = f.Name()
		}
		return f, err
	}
	rec := httptest.NewRecorder()
	AuthMiddleware(testCredentialStore(), time.Minute, logrus.New(), nil, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, signedConcreteRequest(t, []byte("body")))
	if rec.Code != http.StatusOK || path == "" {
		t.Fatalf("code=%d path=%q", rec.Code, path)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("spool remains: %v", err)
	}
}

func TestAuthMiddleware_SigV4ConcretePayloadHash_NoDigestLeak(t *testing.T) {
	originalBody := []byte("body")
	tamperedBody := []byte("tamper")
	expectedDigest := fmt.Sprintf("%x", sha256.Sum256(originalBody))
	receivedDigest := fmt.Sprintf("%x", sha256.Sum256(tamperedBody))
	req := signedConcreteRequest(t, originalBody)
	// Replace only the received body after creating the valid signed request.
	req.Body = io.NopCloser(bytes.NewReader(tamperedBody))
	logger := logrus.New()
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	auditLogger := audit.NewLogger(10, nil)
	reg := prometheus.NewRegistry()
	testMetrics := metrics.NewMetricsWithRegistry(reg)
	testMetrics.RecordS3Error(context.Background(), "PutObject", "bucket", "403")
	rec := httptest.NewRecorder()
	AuthMiddleware(testCredentialStore(), time.Minute, logger, auditLogger, true)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next called for tampered body")
	})).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "SignatureDoesNotMatch") {
		t.Fatalf("status=%d body=%s, want 403 SignatureDoesNotMatch", rec.Code, rec.Body.String())
	}
	metricText := httptest.NewRecorder()
	promhttp.HandlerFor(reg, promhttp.HandlerOpts{}).ServeHTTP(metricText, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, captured := range []struct {
		name string
		data string
	}{
		{name: "response", data: rec.Body.String()},
		{name: "logs", data: logs.String()},
		{name: "metrics", data: metricText.Body.String()},
	} {
		if strings.Contains(captured.data, expectedDigest) || strings.Contains(captured.data, receivedDigest) {
			t.Fatalf("%s leaked a payload digest", captured.name)
		}
	}
	events := auditLogger.GetEvents()
	if len(events) != 1 {
		t.Fatalf("audit events=%d, want 1", len(events))
	}
	event := events[0]
	if event.EventType != audit.EventTypeAuthFailure || event.Success {
		t.Fatalf("audit event type=%q success=%v, want auth failure", event.EventType, event.Success)
	}
	if got := event.Metadata["access_key"]; got != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("audit access key=%v, want request access key", got)
	}
	if event.Error != ErrSignatureMismatch.Error() {
		t.Fatalf("audit error=%q, want %q", event.Error, ErrSignatureMismatch)
	}
	metadata := fmt.Sprint(event.Metadata)
	if strings.Contains(event.Error, expectedDigest) || strings.Contains(event.Error, receivedDigest) {
		t.Fatal("audit error leaked a payload digest")
	}
	if strings.Contains(metadata, expectedDigest) || strings.Contains(metadata, receivedDigest) {
		t.Fatal("audit metadata leaked a payload digest")
	}
}

func TestAuthMiddleware_SigV4_BadSignature(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/%s/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb",
		now.Format("20060102"))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Host = "localhost"
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Amz-Date", timestamp)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

// --- V1.0-SEC-30: Auth bypass tests ---

// TestAuthMiddleware_MetricsPrefixBypass_Rejected verifies that a request to
// /metrics-<anything> without credentials is rejected (exact-match only).
func TestAuthMiddleware_MetricsPrefixBypass_Rejected(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("PUT", "/metrics-attackerbucket/key", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "AccessDenied") {
		t.Errorf("body = %q, want AccessDenied", body)
	}
}

// TestAuthMiddleware_MetricsExact_Allowed verifies that GET /metrics with no
// credentials reaches the inner handler.
func TestAuthMiddleware_MetricsExact_Allowed(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	var reached bool
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !reached {
		t.Error("inner handler was not reached")
	}
}

// TestAuthMiddleware_HealthReadyLive_Allowed verifies that canonical and
// S3-compatible health routes all pass through without authentication.
func TestAuthMiddleware_HealthReadyLive_Allowed(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	for _, path := range []string{
		"/health", "/ready", "/live",
		"/minio/health/live", "/minio/health/ready",
		"/health/live", "/health/ready",
	} {
		t.Run(path, func(t *testing.T) {
			var reached bool
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("GET", path, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if !reached {
				t.Error("inner handler was not reached")
			}
		})
	}
}

// TestAuthMiddleware_HealthAliasNearMatchesRejected proves compatible health
// aliases retain exact-match authentication bypass semantics (V1.0-SEC-30).
func TestAuthMiddleware_HealthAliasNearMatchesRejected(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("near-match health alias reached unauthenticated handler")
	}))

	for _, path := range []string{
		"/minio/health/live-extra",
		"/minio/health/ready/anything",
		"/health/live-extra",
		"/health/ready/anything",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
		})
	}
}

// TestAuthMiddleware_MetricsPrefixBypass_WithCredentials_Rejected verifies
// that a request to /metrics-<anything> with a valid SigV4 signature for a
// different bucket still goes through auth (the prefix bypass is gone).
func TestAuthMiddleware_MetricsPrefixBypass_WithCredentials_Rejected(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Use a valid SigV2 signature for a different bucket (/real-bucket/key).
	expires := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	q := url.Values{}
	q.Set("AWSAccessKeyId", "AKIAIOSFODNN7EXAMPLE")
	q.Set("Expires", expires)
	q.Set("AWSSecretAccessKey", "dummy")

	// Sign for /real-bucket/key, but request goes to /metrics-attackerbucket/key.
	stringToSign := "PUT\n\n\n" + expires + "\n/real-bucket/key"
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"), []byte(stringToSign)))
	q.Set("Signature", sig)

	req := httptest.NewRequest("PUT", "/metrics-attackerbucket/key?"+q.Encode(), nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// The request is NOT skipped by the auth bypass (exact-match only), so auth
	// runs. The signature is for /real-bucket/key but the path is
	// /metrics-attackerbucket/key, so signature validation catches the mismatch.
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

func TestAuthMiddleware_PresignedV4_Valid(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	region := "us-east-1"
	service := "s3"
	accessKey := "AKIAIOSFODNN7EXAMPLE"
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)

	q := url.Values{}
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+credScope)
	q.Set("X-Amz-Date", timestamp)
	q.Set("X-Amz-Expires", "86400")
	q.Set("X-Amz-SignedHeaders", "host")

	reqURL := "/bucket/key?" + q.Encode()
	req := httptest.NewRequest("GET", reqURL, nil)
	req.Host = "localhost"

	canonicalReq, err := createCanonicalRequest(req, true, []string{"host"})
	if err != nil {
		t.Fatalf("createCanonicalRequest() error: %v", err)
	}

	stringToSign := createStringToSign(timestamp, credScope, canonicalReq)
	signingKey := getSignatureKey(secretKey, date, region, service)
	sig := hex.EncodeToString(sign(signingKey, []byte(stringToSign)))

	q.Set("X-Amz-Signature", sig)
	reqURL = "/bucket/key?" + q.Encode()
	req = httptest.NewRequest("GET", reqURL, nil)
	req.Host = "localhost"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}
