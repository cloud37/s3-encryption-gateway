package api

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kenchrcum/s3-encryption-gateway/internal/config"
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
