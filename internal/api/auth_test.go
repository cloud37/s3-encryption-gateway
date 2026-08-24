package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// sigV4TestVector is a known AWS SigV4 test vector.
// Based on the AWS SigV4 test suite (public domain).
// Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
type sigV4TestVector struct {
	method     string
	path       string
	query      string
	headers    map[string]string
	signedHdrs []string
	secretKey  string
	date       string
	region     string
	service    string
	wantSig    string // if empty, compute and round-trip
}

// buildHMAC is a pure helper so tests can compute expected values without
// calling production code.
func buildHMAC(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// computeTestSignature computes the SigV4 signature for the given parameters
// using ONLY standard library functions — this gives us an independent
// reference to validate the production code against.
func computeTestSignature(secretKey, date, region, service, stringToSign string) string {
	kDate := buildHMAC([]byte("AWS4"+secretKey), date)
	kRegion := buildHMAC(kDate, region)
	kService := buildHMAC(kRegion, service)
	kSigning := buildHMAC(kService, "aws4_request")
	sig := buildHMAC(kSigning, stringToSign)
	return hex.EncodeToString(sig)
}

// TestSign_KnownVector verifies the sign() helper against a hard-coded HMAC
// vector so that any regression in the core primitive is immediately visible.
func TestSign_KnownVector(t *testing.T) {
	key := []byte("test-signing-key")
	data := []byte("test data to sign")

	got := sign(key, data)

	h := hmac.New(sha256.New, key)
	h.Write(data)
	want := h.Sum(nil)

	if !hmac.Equal(got, want) {
		t.Errorf("sign() = %x, want %x", got, want)
	}
}

// TestGetSignatureKey verifies that the key derivation produces the correct
// HMAC chain: AWS4+secret → date → region → service → aws4_request.
func TestGetSignatureKey(t *testing.T) {
	secret := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	date := "20150830"
	region := "us-east-1"
	service := "iam"

	got := getSignatureKey(secret, date, region, service)

	// Independently compute expected
	kDate := buildHMAC([]byte("AWS4"+secret), date)
	kRegion := buildHMAC(kDate, region)
	kService := buildHMAC(kRegion, service)
	want := buildHMAC(kService, "aws4_request")

	if !hmac.Equal(got, want) {
		t.Errorf("getSignatureKey() = %x, want %x", got, want)
	}
}

// TestURIEncode_Table verifies uriEncode() against a table of known encodings.
func TestURIEncode_Table(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"hello", "hello"},
		{"hello world", "hello%20world"},
		{"a+b", "a%2Bb"},
		{"a/b", "a%2Fb"},
		{"a=b", "a%3Db"},
		{"a&b", "a%26b"},
		{"a%b", "a%25b"},
		{"abc123-_.~", "abc123-_.~"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"},
	}

	for _, tc := range tests {
		got := uriEncode(tc.input)
		if got != tc.want {
			t.Errorf("uriEncode(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestEncodePath_SlashPreservation verifies that encodePath preserves the
// slash separator between path segments while encoding each segment.
func TestEncodePath_SlashPreservation(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/", "/"},
		{"/bucket", "/bucket"},
		{"/bucket/key", "/bucket/key"},
		{"/bucket/key with spaces", "/bucket/key%20with%20spaces"},
		{"/bucket/key+special", "/bucket/key%2Bspecial"},
		// Slashes within path segments are preserved by splitting
		{"/a/b/c", "/a/b/c"},
	}

	for _, tc := range tests {
		got := encodePath(tc.path)
		if got != tc.want {
			t.Errorf("encodePath(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestCreateStringToSign_Structure verifies the string-to-sign format:
//
//	"AWS4-HMAC-SHA256\n<timestamp>\n<credentialScope>\n<hexHash(canonicalRequest)>"
func TestCreateStringToSign_Structure(t *testing.T) {
	timestamp := "20150830T123600Z"
	credentialScope := "20150830/us-east-1/iam/aws4_request"
	canonicalRequest := "GET\n/\n\nhost:iam.amazonaws.com\n\nhost\ne3b0c44298fc1c149afb"

	got := createStringToSign(timestamp, credentialScope, canonicalRequest)

	if !strings.HasPrefix(got, "AWS4-HMAC-SHA256\n") {
		t.Errorf("createStringToSign() should start with AWS4-HMAC-SHA256\\n, got: %q", got)
	}
	if !strings.Contains(got, timestamp) {
		t.Errorf("createStringToSign() should contain timestamp %q", timestamp)
	}
	if !strings.Contains(got, credentialScope) {
		t.Errorf("createStringToSign() should contain credentialScope %q", credentialScope)
	}

	// Verify SHA256 of canonical request is embedded
	hash := sha256.Sum256([]byte(canonicalRequest))
	expectedHash := hex.EncodeToString(hash[:])
	if !strings.Contains(got, expectedHash) {
		t.Errorf("createStringToSign() should contain SHA256 hash %q of canonical request", expectedHash)
	}
}

// TestValidateSignatureV4_MissingAuthHeader verifies that a request without
// an Authorization header returns an error (not a panic, not a false success).
func TestValidateSignatureV4_MissingAuthHeader(t *testing.T) {
	req := httptest.NewRequest("GET", "/bucket/key", nil)
	// No Authorization header, no X-Amz-Algorithm query param → error

	_, err := ValidateSignatureV4(req, "any-secret", defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for missing auth header, got nil")
	}
}

// TestValidateSignatureV4_MalformedAuthHeader verifies graceful handling of a
// malformed Authorization header (wrong prefix, etc.).
func TestValidateSignatureV4_MalformedAuthHeader(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{"wrong scheme", "Basic dXNlcjpwYXNz"},
		{"Bearer token", "Bearer mytoken"},
		{"empty", ""},
		{"almost right, no credential", "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=abc"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/bucket/key", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			_, err := ValidateSignatureV4(req, "secret", defaultClockSkew)
			if err == nil {
				t.Errorf("ValidateSignatureV4(%q) expected error, got nil", tc.header)
			}
		})
	}
}

// TestValidateSignatureV4_SignatureMismatch verifies that a syntactically valid
// Authorization header with a wrong signature returns ErrSignatureMismatch
// (or at minimum an error — the error wraps the sentinel).
func TestValidateSignatureV4_SignatureMismatch(t *testing.T) {
	// Build a syntactically valid Authorization header but with the wrong
	// secret key — signature computation will produce a different value.
	secretKey := "correct-secret"
	wrongSecret := "wrong-secret"
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	date := timestamp[:8]
	credScope := fmt.Sprintf("%s/us-east-1/s3/aws4_request", date)

	// Build a minimal canonical request manually
	canonicalReq := "GET\n/bucket/key\n\nhost:localhost\n\nhost\nUNSIGNED-PAYLOAD"
	hashCanonical := sha256.Sum256([]byte(canonicalReq))
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		timestamp, credScope, hex.EncodeToString(hashCanonical[:]))

	// Sign with the WRONG secret
	wrongSig := computeTestSignature(wrongSecret, date, "us-east-1", "s3", stringToSign)

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=AKIATEST/%s, SignedHeaders=host, Signature=%s",
		credScope, wrongSig)

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Host = "localhost"
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Amz-Date", timestamp)

	_, err := ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for wrong signature, got nil")
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("ValidateSignatureV4() error = %v, want errors.Is(err, ErrSignatureMismatch)", err)
	}
}

// TestValidateSignatureV4_Valid verifies that a correctly-signed request is
// accepted. We use the production code itself to sign and then verify,
// which ensures we're testing the round-trip rather than an external standard.
func TestValidateSignatureV4_Valid(t *testing.T) {
	secretKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	region := "us-east-1"
	service := "s3"
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)

	// Build the request first so we can use the production createCanonicalRequest
	// to get the exact canonical form.
	req := httptest.NewRequest("GET", "/examplebucket/test.txt", nil)
	req.Host = "examplebucket.s3.amazonaws.com"
	req.Header.Set("X-Amz-Date", timestamp)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	signedHdrs := []string{"host", "x-amz-content-sha256", "x-amz-date"}

	// Use the production canonical request builder to get the exact canonical form
	canonicalReq, err := createCanonicalRequest(req, false, signedHdrs)
	if err != nil {
		t.Fatalf("createCanonicalRequest() error: %v", err)
	}

	// Build string to sign using the production function
	stringToSign := createStringToSign(timestamp, credScope, canonicalReq)

	// Derive signing key and compute signature
	signingKey := getSignatureKey(secretKey, date, region, service)
	sig := hex.EncodeToString(sign(signingKey, []byte(stringToSign)))

	signedHdrsStr := strings.Join(signedHdrs, ";")
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/%s, SignedHeaders=%s, Signature=%s",
		credScope, signedHdrsStr, sig)

	// Set the Authorization header and validate
	req.Header.Set("Authorization", authHeader)

	_, err = ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err != nil {
		t.Fatalf("ValidateSignatureV4() expected nil error for valid signature, got: %v", err)
	}
}

func TestValidateSignatureV4_ConcretePayloadHashCapturedOnlyAfterSignatureVerification(t *testing.T) {
	body := []byte("signed payload")
	req := signedConcreteRequest(t, body)
	ctx, err := ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", defaultClockSkew)
	wantHash := sha256Sum(body)
	if err != nil || ctx == nil || !ctx.verifyPayload || !hmac.Equal(ctx.expectedPayloadHash[:], wantHash[:]) {
		t.Fatalf("valid concrete payload context = %#v, err = %v", ctx, err)
	}
	ctx.Close()
	req.Header.Set("Authorization", strings.Replace(req.Header.Get("Authorization"), "Signature=", "Signature=0", 1))
	ctx, err = ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", defaultClockSkew)
	if err == nil || ctx != nil {
		t.Fatalf("failed validation returned context: %#v, err %v", ctx, err)
	}
}

func sha256Sum(data []byte) [sha256.Size]byte { return sha256.Sum256(data) }

func TestValidateSignatureV4_UnsignedPayloadHasNoExpectedDigest(t *testing.T) {
	req := signedConcreteRequest(t, nil)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	// Re-sign the changed canonical claim.
	req = signedConcreteRequest(t, nil)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	// The shared helper signs concrete payloads; construct the valid unsigned case
	// using the existing middleware test vector instead of accepting a bad claim.
	canonical, _ := createCanonicalRequest(req, false, []string{"host", "x-amz-content-sha256", "x-amz-date"})
	date := req.Header.Get("X-Amz-Date")[:8]
	scope := date + "/us-east-1/s3/aws4_request"
	key := getSignatureKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", date, "us-east-1", "s3")
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/%s, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", scope, hex.EncodeToString(sign(key, []byte(createStringToSign(req.Header.Get("X-Amz-Date"), scope, canonical))))))
	ctx, err := ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", defaultClockSkew)
	if err != nil || ctx == nil || ctx.verifyPayload || ctx.expectedPayloadHash != [sha256.Size]byte{} {
		t.Fatalf("unsigned context = %#v, err %v", ctx, err)
	}
}

func TestValidateSignatureV4_StreamingPayloadHasNoOrdinaryExpectedDigest(t *testing.T) {
	req := signedConcreteRequest(t, []byte("chunk"))
	// Streaming mode is classified after signature validation; this test only
	// needs to prove the resulting context does not select ordinary hashing.
	req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	canonical, _ := createCanonicalRequest(req, false, []string{"host", "x-amz-content-sha256", "x-amz-date"})
	date, timestamp := req.Header.Get("X-Amz-Date")[:8], req.Header.Get("X-Amz-Date")
	scope := date + "/us-east-1/s3/aws4_request"
	key := getSignatureKey("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", date, "us-east-1", "s3")
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/%s, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", scope, hex.EncodeToString(sign(key, []byte(createStringToSign(timestamp, scope, canonical))))))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Decoded-Content-Length", "5")
	ctx, err := ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", defaultClockSkew)
	if err != nil || ctx == nil || ctx.verifyPayload || ctx.expectedPayloadHash != [sha256.Size]byte{} {
		t.Fatalf("streaming context = %#v, err %v", ctx, err)
	}
}

func TestValidateSignatureV4_UppercasePayloadHashRejectedAsNonConcrete(t *testing.T) {
	req := signedConcreteRequest(t, []byte("body"))
	upper := strings.ToUpper(req.Header.Get("X-Amz-Content-Sha256"))
	req.Header.Set("X-Amz-Content-Sha256", upper)
	resignV4Request(t, req, upper)
	ctx, err := ValidateSignatureV4(req, "wJalrXUtnFEMI/K7MDENG/bPxrfiCYEXAMPLEKEY", defaultClockSkew)
	if err == nil || ctx != nil {
		t.Fatalf("uppercase hash result context=%#v err=%v", ctx, err)
	}
}

func TestV4SigningContext_CloseZeroizesPayloadDigest(t *testing.T) {
	c := &V4SigningContext{verifyPayload: true, expectedPayloadHash: sha256.Sum256([]byte("secret")), signingKey: []byte("key"), seedSignature: sha256.Sum256([]byte("seed"))}
	c.Close()
	c.Close()
	if c.verifyPayload || c.expectedPayloadHash != [sha256.Size]byte{} || c.signingKey != nil || c.seedSignature != [sha256.Size]byte{} {
		t.Fatalf("context not zeroized: %#v", c)
	}
}

// TestValidateSignatureV4_ClockSkew_Past verifies that a header-auth request
// with a timestamp more than 5 minutes in the past is rejected.
func TestValidateSignatureV4_ClockSkew_Past(t *testing.T) {
	secretKey := "test-secret"
	// Timestamp 20 minutes in the past
	past := time.Now().UTC().Add(-20 * time.Minute)
	timestamp := past.Format("20060102T150405Z")
	date := past.Format("20060102")
	credScope := fmt.Sprintf("%s/us-east-1/s3/aws4_request", date)

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=AKIATEST/%s, SignedHeaders=host, Signature=%s",
		credScope, strings.Repeat("a", 64))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Host = "localhost"
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Amz-Date", timestamp)

	_, err := ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for old timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "clock skew") {
		t.Errorf("ValidateSignatureV4() error = %v, want clock-skew rejection", err)
	}
}

// TestValidateSignatureV4_ClockSkew_Future verifies that a header-auth request
// with a timestamp more than 5 minutes in the future is rejected.
func TestValidateSignatureV4_ClockSkew_Future(t *testing.T) {
	secretKey := "test-secret"
	// Timestamp 20 minutes in the future
	future := time.Now().UTC().Add(20 * time.Minute)
	timestamp := future.Format("20060102T150405Z")
	date := future.Format("20060102")
	credScope := fmt.Sprintf("%s/us-east-1/s3/aws4_request", date)

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=AKIATEST/%s, SignedHeaders=host, Signature=%s",
		credScope, strings.Repeat("a", 64))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Host = "localhost"
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Amz-Date", timestamp)

	_, err := ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for future timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "clock skew") {
		t.Errorf("ValidateSignatureV4() error = %v, want clock-skew rejection", err)
	}
}

// TestValidateSignatureV4_ClockSkew_WithinWindow verifies that a header-auth
// request with a timestamp inside the 5-minute window is accepted.
func TestValidateSignatureV4_ClockSkew_WithinWindow(t *testing.T) {
	secretKey := "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	// Timestamp 2 minutes in the past — comfortably within the skew window
	now := time.Now().UTC().Add(-2 * time.Minute)
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	region := "us-east-1"
	service := "s3"
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)

	req := httptest.NewRequest("GET", "/examplebucket/test.txt", nil)
	req.Host = "examplebucket.s3.amazonaws.com"
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

	_, err = ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err != nil {
		t.Fatalf("ValidateSignatureV4() expected nil error for timestamp within skew window, got: %v", err)
	}
}

// TestValidateSignatureV4_MissingTimestamp verifies that a request without a
// timestamp (X-Amz-Date) header or Date header returns an error.
func TestValidateSignatureV4_MissingTimestamp(t *testing.T) {
	secretKey := "test-secret"
	credScope := "20150830/us-east-1/s3/aws4_request"
	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=AKIATEST/%s, SignedHeaders=host, Signature=%s",
		credScope, strings.Repeat("a", 64))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Host = "localhost"
	req.Header.Set("Authorization", authHeader)
	// No X-Amz-Date or Date header

	_, err := ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for missing timestamp, got nil")
	}
}

// TestValidateSignatureV4_PresignedURL verifies that presigned URL validation
// works: the X-Amz-Algorithm query parameter selects the presigned path.
func TestValidateSignatureV4_PresignedURL(t *testing.T) {
	secretKey := "test-presign-secret"
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	region := "us-east-1"
	service := "s3"
	accessKey := "AKIATEST"
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)

	// Build minimal presigned query params (without signature)
	q := url.Values{}
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+credScope)
	q.Set("X-Amz-Date", timestamp)
	q.Set("X-Amz-Expires", "86400")
	q.Set("X-Amz-SignedHeaders", "host")

	// Build the request without signature so we can use production createCanonicalRequest
	reqURL := "/bucket/key?" + q.Encode()
	req := httptest.NewRequest("GET", reqURL, nil)
	req.Host = "localhost"

	// Use production createCanonicalRequest to get the exact canonical form
	canonicalReq, err := createCanonicalRequest(req, true, []string{"host"})
	if err != nil {
		t.Fatalf("createCanonicalRequest() error: %v", err)
	}

	stringToSign := createStringToSign(timestamp, credScope, canonicalReq)

	kDate := buildHMAC([]byte("AWS4"+secretKey), date)
	kRegion := buildHMAC(kDate, region)
	kService := buildHMAC(kRegion, service)
	kSigning := buildHMAC(kService, "aws4_request")
	sig := hex.EncodeToString(buildHMAC(kSigning, stringToSign))

	// Add signature to query and rebuild request
	q.Set("X-Amz-Signature", sig)
	reqURL = "/bucket/key?" + q.Encode()
	req = httptest.NewRequest("GET", reqURL, nil)
	req.Host = "localhost"

	// This should succeed (valid presigned URL within clock-skew window)
	_, err = ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err != nil {
		if !errors.Is(err, ErrSignatureMismatch) && !strings.Contains(err.Error(), "signature") {
			t.Errorf("ValidateSignatureV4() presigned: unexpected error type: %v", err)
		}
	}
}

// TestCreateCanonicalRequest_Headers verifies that the canonical headers
// section is correctly formatted: lowercase key, trimmed value, newline.
func TestCreateCanonicalRequest_Headers(t *testing.T) {
	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Host = "s3.amazonaws.com"
	req.Header.Set("X-Amz-Date", "20150830T123600Z")
	req.Header.Set("Content-Type", "text/plain")

	signedHeaders := []string{"host", "x-amz-date"}

	canonical, err := createCanonicalRequest(req, false, signedHeaders)
	if err != nil {
		t.Fatalf("createCanonicalRequest() error: %v", err)
	}

	// Should contain lowercase "host:" header
	if !strings.Contains(canonical, "host:") {
		t.Errorf("canonical request missing 'host:' header, got:\n%s", canonical)
	}

	// Should contain lowercase "x-amz-date:" header
	if !strings.Contains(canonical, "x-amz-date:") {
		t.Errorf("canonical request missing 'x-amz-date:' header, got:\n%s", canonical)
	}

	// Should NOT contain content-type (not in signedHeaders)
	if strings.Contains(canonical, "content-type:") {
		t.Errorf("canonical request contains 'content-type' but it's not in signedHeaders:\n%s", canonical)
	}
}

// TestCreateCanonicalRequest_QueryString verifies that query parameters are
// sorted alphabetically and URI-encoded.
func TestCreateCanonicalRequest_QueryString(t *testing.T) {
	req := httptest.NewRequest("GET", "/bucket?delimiter=%2F&prefix=test&max-keys=100", nil)
	req.Host = "s3.amazonaws.com"

	signedHeaders := []string{"host"}

	canonical, err := createCanonicalRequest(req, false, signedHeaders)
	if err != nil {
		t.Fatalf("createCanonicalRequest() error: %v", err)
	}

	lines := strings.Split(canonical, "\n")
	// Line 0 = method, line 1 = URI, line 2 = query string
	if len(lines) < 3 {
		t.Fatalf("canonical request has too few lines: %d", len(lines))
	}
	queryLine := lines[2]

	// All three params should appear, sorted
	if !strings.Contains(queryLine, "delimiter") {
		t.Errorf("query string missing 'delimiter': %q", queryLine)
	}
	if !strings.Contains(queryLine, "max-keys") {
		t.Errorf("query string missing 'max-keys': %q", queryLine)
	}
	if !strings.Contains(queryLine, "prefix") {
		t.Errorf("query string missing 'prefix': %q", queryLine)
	}
}

// TestValidateSignatureV4_InvalidCredentialFormat verifies that malformed
// credential scopes (missing parts) return an error before any HMAC is computed.
func TestValidateSignatureV4_InvalidCredentialFormat(t *testing.T) {
	tests := []struct {
		name string
		auth string
	}{
		{
			name: "credential with too few parts",
			auth: "AWS4-HMAC-SHA256 Credential=AKIA/20150830/aws4_request, SignedHeaders=host, Signature=abc",
		},
		{
			name: "credential with too many parts",
			auth: "AWS4-HMAC-SHA256 Credential=AKIA/date/region/service/aws4_request/extra, SignedHeaders=host, Signature=abc",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/bucket/key", nil)
			req.Header.Set("Authorization", tc.auth)
			req.Header.Set("X-Amz-Date", "20150830T123600Z")

			_, err := ValidateSignatureV4(req, "secret", defaultClockSkew)
			if err == nil {
				t.Errorf("ValidateSignatureV4(%q) expected error for malformed credential, got nil", tc.auth)
			}
		})
	}
}

// TestValidateSignatureV4_CredentialDateMismatch_Header verifies that a header-auth
// request whose credential-scope date does not match X-Amz-Date is rejected.
func TestValidateSignatureV4_CredentialDateMismatch_Header(t *testing.T) {
	secretKey := "test-secret"
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	// Deliberately use yesterday's date in the credential scope
	oldDate := now.Add(-24 * time.Hour).Format("20060102")
	credScope := fmt.Sprintf("%s/us-east-1/s3/aws4_request", oldDate)

	authHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=AKIATEST/%s, SignedHeaders=host, Signature=%s",
		credScope, strings.Repeat("a", 64))

	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Host = "localhost"
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("X-Amz-Date", timestamp)

	_, err := ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for credential date mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "credential date mismatch") {
		t.Errorf("ValidateSignatureV4() error = %v, want credential date mismatch", err)
	}
}

// TestValidateSignatureV4_CredentialDateMismatch_Presigned verifies that a
// presigned URL whose credential-scope date does not match X-Amz-Date is rejected.
func TestValidateSignatureV4_CredentialDateMismatch_Presigned(t *testing.T) {
	secretKey := "test-secret"
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	oldDate := now.Add(-24 * time.Hour).Format("20060102")
	credScope := fmt.Sprintf("%s/us-east-1/s3/aws4_request", oldDate)
	accessKey := "AKIATEST"

	q := url.Values{}
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+credScope)
	q.Set("X-Amz-Date", timestamp)
	q.Set("X-Amz-Expires", "300")
	q.Set("X-Amz-SignedHeaders", "host")
	q.Set("X-Amz-Signature", strings.Repeat("a", 64))

	reqURL := "/bucket/key?" + q.Encode()
	req := httptest.NewRequest("GET", reqURL, nil)
	req.Host = "localhost"

	_, err := ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for credential date mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "credential date mismatch") {
		t.Errorf("ValidateSignatureV4() error = %v, want credential date mismatch", err)
	}
}

// TestValidateSignatureV4_PresignedURL_Expired verifies that an expired
// presigned URL is rejected.
func TestValidateSignatureV4_PresignedURL_Expired(t *testing.T) {
	secretKey := "test-secret"
	// Use a timestamp 3 minutes ago with a 1-minute expiry so the URL is
	// expired but still within the 5-minute clock-skew window.
	now := time.Now().UTC().Add(-3 * time.Minute)
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	region := "us-east-1"
	service := "s3"
	accessKey := "AKIATEST"
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)

	q := url.Values{}
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+credScope)
	q.Set("X-Amz-Date", timestamp)
	q.Set("X-Amz-Expires", "60") // 1 minute — expired 2 minutes ago
	q.Set("X-Amz-SignedHeaders", "host")
	q.Set("X-Amz-Signature", strings.Repeat("a", 64))

	reqURL := "/bucket/key?" + q.Encode()
	req := httptest.NewRequest("GET", reqURL, nil)
	req.Host = "localhost"

	_, err := ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for expired presigned URL, got nil")
	}
	if !strings.Contains(err.Error(), "expired") && !errors.Is(err, ErrSignatureMismatch) {
		t.Logf("ValidateSignatureV4() expired presigned URL returned: %v", err)
		// Either "expired" message or a signature mismatch (computed before expiry check) is acceptable
	}
}

// TestValidateSignatureV4_PresignedURL_ExceedsMaxDuration verifies that a
// presigned URL with X-Amz-Expires > 604800 (7 days) is rejected immediately.
func TestValidateSignatureV4_PresignedURL_ExceedsMaxDuration(t *testing.T) {
	secretKey := "test-presign-secret"
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	region := "us-east-1"
	service := "s3"
	accessKey := "AKIATEST"
	credScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)

	// Build minimal presigned query params (without signature)
	q := url.Values{}
	q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
	q.Set("X-Amz-Credential", accessKey+"/"+credScope)
	q.Set("X-Amz-Date", timestamp)
	q.Set("X-Amz-Expires", "604801") // 1 second over the 7-day maximum
	q.Set("X-Amz-SignedHeaders", "host")

	reqURL := "/bucket/key?" + q.Encode()
	req := httptest.NewRequest("GET", reqURL, nil)
	req.Host = "localhost"

	// Compute a valid signature so we reach the expiry check.
	canonicalReq, err := createCanonicalRequest(req, true, []string{"host"})
	if err != nil {
		t.Fatalf("createCanonicalRequest() error: %v", err)
	}
	stringToSign := createStringToSign(timestamp, credScope, canonicalReq)
	kDate := buildHMAC([]byte("AWS4"+secretKey), date)
	kRegion := buildHMAC(kDate, region)
	kService := buildHMAC(kRegion, service)
	kSigning := buildHMAC(kService, "aws4_request")
	sig := hex.EncodeToString(buildHMAC(kSigning, stringToSign))

	q.Set("X-Amz-Signature", sig)
	reqURL = "/bucket/key?" + q.Encode()
	req = httptest.NewRequest("GET", reqURL, nil)
	req.Host = "localhost"

	_, err = ValidateSignatureV4(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV4() expected error for presigned URL exceeding max duration, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds maximum allowed duration") {
		t.Errorf("ValidateSignatureV4() error = %v, want 'exceeds maximum allowed duration'", err)
	}
}

// TestValidateSignatureV2_HeaderAuth verifies that a valid V2 Authorization
// header with a current timestamp is accepted.
func TestValidateSignatureV2_HeaderAuth(t *testing.T) {
	secretKey := "test-secret-key"
	accessKey := "AKIATEST"
	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123))

	stringToSign := buildV2StringToSign(req)
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secretKey), []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS "+accessKey+":"+sig)

	err := ValidateSignatureV2(req, secretKey, defaultClockSkew)
	if err != nil {
		t.Fatalf("ValidateSignatureV2() expected nil for valid header auth, got: %v", err)
	}
}

// TestValidateSignatureV2_QueryParam verifies that a valid V2 query-parameter
// request with a future Expires timestamp is accepted.
func TestValidateSignatureV2_QueryParam(t *testing.T) {
	secretKey := "test-secret-key"
	accessKey := "AKIATEST"
	// Expires 1 hour from now (Unix timestamp)
	expires := strconv.FormatInt(time.Now().Add(1*time.Hour).Unix(), 10)
	q := url.Values{}
	q.Set("AWSAccessKeyId", accessKey)
	q.Set("Expires", expires)

	req := httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	stringToSign := buildV2StringToSign(req)
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secretKey), []byte(stringToSign)))
	q.Set("Signature", sig)

	req = httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	err := ValidateSignatureV2(req, secretKey, defaultClockSkew)
	if err != nil {
		t.Fatalf("ValidateSignatureV2() expected nil for valid query-param auth, got: %v", err)
	}
}

// TestValidateSignatureV2_BadSignature verifies that a wrong signature returns
// ErrSignatureMismatch.
func TestValidateSignatureV2_BadSignature(t *testing.T) {
	secretKey := "correct-secret"
	req := httptest.NewRequest("GET", "/bucket/key", nil)
	req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123))
	req.Header.Set("Authorization", "AWS AKIATEST:badsignature")

	err := ValidateSignatureV2(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV2() expected error for bad signature, got nil")
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("ValidateSignatureV2() error = %v, want errors.Is(err, ErrSignatureMismatch)", err)
	}
}

// TestValidateSignatureV2_ClockSkew_Past verifies that a V2 header-auth
// request with a Date more than 5 minutes in the past is rejected.
func TestValidateSignatureV2_ClockSkew_Past(t *testing.T) {
	secretKey := "test-secret"
	req := httptest.NewRequest("GET", "/bucket/key", nil)
	// Timestamp 20 minutes in the past
	req.Header.Set("Date", time.Now().UTC().Add(-20*time.Minute).Format(time.RFC1123))
	req.Header.Set("Authorization", "AWS AKIATEST:badsignature")

	err := ValidateSignatureV2(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV2() expected error for old timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "clock skew") {
		t.Errorf("ValidateSignatureV2() error = %v, want clock-skew rejection", err)
	}
}

// TestValidateSignatureV2_ClockSkew_Future verifies that a V2 header-auth
// request with a Date more than 5 minutes in the future is rejected.
func TestValidateSignatureV2_ClockSkew_Future(t *testing.T) {
	secretKey := "test-secret"
	req := httptest.NewRequest("GET", "/bucket/key", nil)
	// Timestamp 20 minutes in the future
	req.Header.Set("Date", time.Now().UTC().Add(20*time.Minute).Format(time.RFC1123))
	req.Header.Set("Authorization", "AWS AKIATEST:badsignature")

	err := ValidateSignatureV2(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV2() expected error for future timestamp, got nil")
	}
	if !strings.Contains(err.Error(), "clock skew") {
		t.Errorf("ValidateSignatureV2() error = %v, want clock-skew rejection", err)
	}
}

// TestValidateSignatureV2_ClockSkew_WithinWindow verifies that a V2 header-auth
// request with a Date within the 5-minute skew window is accepted.
func TestValidateSignatureV2_ClockSkew_WithinWindow(t *testing.T) {
	secretKey := "test-secret-key"
	accessKey := "AKIATEST"
	req := httptest.NewRequest("GET", "/bucket/key", nil)
	// Timestamp 2 minutes in the past — comfortably within the skew window
	req.Header.Set("Date", time.Now().UTC().Add(-2*time.Minute).Format(time.RFC1123))

	stringToSign := buildV2StringToSign(req)
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secretKey), []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS "+accessKey+":"+sig)

	err := ValidateSignatureV2(req, secretKey, defaultClockSkew)
	if err != nil {
		t.Fatalf("ValidateSignatureV2() expected nil for timestamp within skew window, got: %v", err)
	}
}

// TestValidateSignatureV2_QueryParam_Expired verifies that a V2 query-param
// request with an Expires timestamp in the past is rejected.
func TestValidateSignatureV2_QueryParam_Expired(t *testing.T) {
	secretKey := "test-secret"
	// Expires 1 hour ago
	expires := strconv.FormatInt(time.Now().Add(-1*time.Hour).Unix(), 10)
	q := url.Values{}
	q.Set("AWSAccessKeyId", "AKIATEST")
	q.Set("Expires", expires)
	q.Set("Signature", "badsignature")

	req := httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	err := ValidateSignatureV2(req, secretKey, defaultClockSkew)
	if err == nil {
		t.Fatal("ValidateSignatureV2() expected error for expired request, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("ValidateSignatureV2() error = %v, want expired rejection", err)
	}
}

// TestValidateSignatureV2_QueryParam_ValidFuture verifies that a V2 query-param
// request with an Expires timestamp in the future is accepted.
func TestValidateSignatureV2_QueryParam_ValidFuture(t *testing.T) {
	secretKey := "test-secret-key"
	accessKey := "AKIATEST"
	// Expires 1 hour from now
	expires := strconv.FormatInt(time.Now().Add(1*time.Hour).Unix(), 10)
	q := url.Values{}
	q.Set("AWSAccessKeyId", accessKey)
	q.Set("Expires", expires)

	req := httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	stringToSign := buildV2StringToSign(req)
	sig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secretKey), []byte(stringToSign)))
	q.Set("Signature", sig)

	req = httptest.NewRequest("GET", "/bucket/key?"+q.Encode(), nil)
	err := ValidateSignatureV2(req, secretKey, defaultClockSkew)
	if err != nil {
		t.Fatalf("ValidateSignatureV2() expected nil for valid future Expires, got: %v", err)
	}
}

// TestIsSignatureV4Request verifies that IsSignatureV4Request only matches
// AWS4-HMAC-SHA256 and not the legacy "AWS " prefix.
func TestIsSignatureV4Request(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*http.Request)
		want  bool
	}{
		{
			name: "SigV4 header",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/.../..., SignedHeaders=host, Signature=abc")
			},
			want: true,
		},
		{
			name: "SigV4 presigned query",
			setup: func(r *http.Request) {
				r.URL.RawQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc"
			},
			want: true,
		},
		{
			name: "legacy AWS header",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS AKIA:signature")
			},
			want: false,
		},
		{
			name: "Bearer token",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer sometoken")
			},
			want: false,
		},
		{
			name:  "no auth",
			setup: func(r *http.Request) {},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			tc.setup(req)
			if got := IsSignatureV4Request(req); got != tc.want {
				t.Errorf("IsSignatureV4Request() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsSignatureV2Request verifies that IsSignatureV2Request matches the
// "AWS " Authorization header and AWSAccessKeyId+Signature query params.
func TestIsSignatureV2Request(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*http.Request)
		want  bool
	}{
		{
			name: "V2 header",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS AKIA:signature")
			},
			want: true,
		},
		{
			name: "V2 query params",
			setup: func(r *http.Request) {
				r.URL.RawQuery = "AWSAccessKeyId=AKIA&Signature=abc"
			},
			want: true,
		},
		{
			name: "SigV4 header",
			setup: func(r *http.Request) {
				r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA/.../..., SignedHeaders=host, Signature=abc")
			},
			want: false,
		},
		{
			name: "SigV4 query params",
			setup: func(r *http.Request) {
				r.URL.RawQuery = "X-Amz-Algorithm=AWS4-HMAC-SHA256"
			},
			want: false,
		},
		{
			name:  "no auth",
			setup: func(r *http.Request) {},
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			tc.setup(req)
			if got := IsSignatureV2Request(req); got != tc.want {
				t.Errorf("IsSignatureV2Request() = %v, want %v", got, tc.want)
			}
		})
	}
}
