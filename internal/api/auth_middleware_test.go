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

// TestAuthMiddleware_HealthReadyLive_Allowed verifies that /health, /ready,
// and /live all pass through without authentication.
func TestAuthMiddleware_HealthReadyLive_Allowed(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	middleware := AuthMiddleware(testCredentialStore(), 5*time.Minute, logger, nil, true)

	for _, path := range []string{"/health", "/ready", "/live"} {
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
