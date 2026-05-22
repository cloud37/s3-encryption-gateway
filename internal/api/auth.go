package api

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Sentinel authentication errors.
//
// These are used to classify failures in a way that does not rely on string
// matching of wrapped error messages. Call sites wrap these with %w so that
// response writers can use errors.Is to select the appropriate client-facing
// response without ever reading err.Error() (which may contain sensitive
// diagnostic detail intended only for logs).
//
// classifyAuthError maps these three sentinels to three
// distinct S3 error codes (SignatureDoesNotMatch, InvalidAccessKeyId,
// AccessDenied). This is intentional S3 specification compliance — AWS S3
// itself returns these same distinct codes, and many AWS SDK clients use the
// code to distinguish misconfigured credentials (InvalidAccessKeyId) from a
// signing error (SignatureDoesNotMatch). Collapsing all auth failures into a
// single opaque error would break legitimate SDK retry/diagnostic behaviour.
// The mitigation against enumeration is that err.Error() (which may contain
// computed HMAC signatures or internal detail) is NEVER included in the
// response body; only the fixed per-class message string is returned. This is
// enforced and regression-tested in auth_error_test.go.
var (
	// ErrSignatureMismatch indicates SigV4 validation failed (bad signature).
	ErrSignatureMismatch = errors.New("signature validation failed")

	// ErrUnknownAccessKey indicates the request's access key is not recognised.
	ErrUnknownAccessKey = errors.New("unknown access key")

	// ErrMissingCredentials indicates credentials could not be extracted or
	// were incomplete (missing access key or secret key).
	ErrMissingCredentials = errors.New("missing or incomplete credentials")

)

const defaultClockSkew = 5 * time.Minute

// ValidateSignatureV4 validates the AWS Signature V4 in the request.
// It supports both Authorization header and Presigned URL (query param).
// secretKey is the shared secret used to sign the request.
// clockSkew is the maximum acceptable difference between the request
// timestamp and server time; zero or negative values fall back to
// defaultClockSkew (5 minutes).
func ValidateSignatureV4(r *http.Request, secretKey string, clockSkew time.Duration) error {
	if clockSkew <= 0 {
		clockSkew = defaultClockSkew
	}
	// Determine if it's a Presigned URL or Header Auth
	query := r.URL.Query()
	isPresigned := query.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"

	var signature string
	var signedHeaders []string
	var credentialScope string
	var timestamp string

	if isPresigned {
		signature = query.Get("X-Amz-Signature")
		signedHeaders = strings.Split(query.Get("X-Amz-SignedHeaders"), ";")
		credential := query.Get("X-Amz-Credential")
		// Credential format: AccessKey/Date/Region/Service/aws4_request
		parts := strings.Split(credential, "/")
		if len(parts) != 5 {
			return fmt.Errorf("invalid credential format")
		}
		credentialScope = strings.Join(parts[1:], "/")
		timestamp = query.Get("X-Amz-Date")
	} else {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
			return fmt.Errorf("missing or invalid Authorization header")
		}
		// Parse Authorization header
		// AWS4-HMAC-SHA256 Credential=..., SignedHeaders=..., Signature=...
		parts := strings.Split(authHeader[17:], ",")
		params := make(map[string]string)
		for _, p := range parts {
			kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
			if len(kv) == 2 {
				params[kv[0]] = kv[1]
			}
		}
		signature = params["Signature"]
		signedHeaders = strings.Split(params["SignedHeaders"], ";")
		credential := params["Credential"]
		credParts := strings.Split(credential, "/")
		if len(credParts) != 5 {
			return fmt.Errorf("invalid credential format in header")
		}
		credentialScope = strings.Join(credParts[1:], "/")
		timestamp = r.Header.Get("X-Amz-Date")
		if timestamp == "" {
			timestamp = r.Header.Get("Date")
		}
	}

	if signature == "" {
		return fmt.Errorf("missing signature")
	}
	if timestamp == "" {
		return fmt.Errorf("missing timestamp")
	}

	// Clock-skew validation: reject requests whose timestamp is outside the
	// configured skew window. This applies to both header-auth and presigned
	// requests and prevents indefinite replay of captured signatures.
	t, err := time.Parse("20060102T150405Z", timestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp format")
	}
	now := time.Now().UTC()
	skew := now.Sub(t).Abs()
	if skew > clockSkew {
		return fmt.Errorf("request timestamp outside clock skew window")
	}

	// Cross-validate credential-scope date against X-Amz-Date.
	// The signing key is derived from the credential-scope date; if it does not
	// match the request timestamp an attacker can replay old credentials within
	// the clock-skew window.
	scopeParts := strings.Split(credentialScope, "/")
	if len(scopeParts) != 4 {
		return fmt.Errorf("invalid credential scope")
	}
	credDate := scopeParts[0]
	if credDate != t.Format("20060102") {
		return fmt.Errorf("credential date mismatch")
	}

	// 1. Create Canonical Request
	canonicalRequest, err := createCanonicalRequest(r, isPresigned, signedHeaders)
	if err != nil {
		return fmt.Errorf("failed to create canonical request: %w", err)
	}

	// 2. Create String to Sign
	stringToSign := createStringToSign(timestamp, credentialScope, canonicalRequest)

	// 3. Calculate Signature (scopeParts already validated above)
	date := scopeParts[0]
	region := scopeParts[1]
	service := scopeParts[2]

	signingKey := getSignatureKey(secretKey, date, region, service)
	calculatedSignature := hex.EncodeToString(sign(signingKey, []byte(stringToSign)))

	// 4. Compare using constant-time comparison to avoid timing side channels.
	// Do NOT include the computed or expected signatures in the error: the error
	// message propagates into HTTP response bodies (see writeS3ClientError),
	// and leaking the computed signature would turn this endpoint into a
	// signing oracle for the shared secret.
	if !hmac.Equal([]byte(calculatedSignature), []byte(signature)) {
		return ErrSignatureMismatch
	}

	// Check Expiry for Presigned URLs
	if isPresigned {
		expiresStr := query.Get("X-Amz-Expires")
		if expiresStr != "" {
			expires, err := strconv.Atoi(expiresStr)
			if err != nil {
				return fmt.Errorf("invalid expires format")
			}
			if expires > 604800 {
				return fmt.Errorf("presigned url expiry exceeds maximum allowed duration")
			}
			if now.After(t.Add(time.Duration(expires) * time.Second)) {
				return fmt.Errorf("presigned url expired")
			}
		}
	}

	return nil
}

// ValidateSignatureV2 validates an AWS Signature Version 2 request.
// It supports both the Authorization header and query-parameter styles.
// secretKey is the stored secret for the access key identified in the request.
// clockSkew is the maximum acceptable difference between the request
// timestamp and server time for header-style auth; zero or negative values
// fall back to defaultClockSkew (5 minutes). For query-parameter style with
// Expires, the expiry is checked against the current time directly.
func ValidateSignatureV2(r *http.Request, secretKey string, clockSkew time.Duration) error {
	if clockSkew <= 0 {
		clockSkew = defaultClockSkew
	}

	// Query-parameter style
	q := r.URL.Query()
	if q.Get("AWSAccessKeyId") != "" && q.Get("Signature") != "" {
		signature := q.Get("Signature")
		expiresStr := q.Get("Expires")
		if expiresStr != "" {
			// Expires is a Unix timestamp — reject if the request has expired.
			expires, err := strconv.ParseInt(expiresStr, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid Expires format")
			}
			// Enforce the same 7-day upper bound as SigV4. A
			// presigned URL with Expires far in the future (e.g. year 2286)
			// could otherwise remain valid indefinitely.
			if expires-time.Now().Unix() > 604800 {
				return fmt.Errorf("presigned url expiry exceeds maximum allowed duration")
			}
			if time.Now().Unix() > expires {
				return fmt.Errorf("request has expired")
			}
		} else {
			// Fallback to Date query parameter (RFC 1123 format) — check clock skew.
			dateStr := q.Get("Date")
			if dateStr == "" {
				return fmt.Errorf("missing Date/Expires parameter")
			}
			t, err := time.Parse(time.RFC1123, dateStr)
			if err != nil {
				return fmt.Errorf("invalid date format")
			}
			now := time.Now().UTC()
			skew := now.Sub(t).Abs()
			if skew > clockSkew {
				return fmt.Errorf("request timestamp outside clock skew window")
			}
		}
		// Build string-to-sign
		stringToSign := buildV2StringToSign(r)
		expectedSig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secretKey), []byte(stringToSign)))
		if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
			return ErrSignatureMismatch
		}
		return nil
	}

	// Authorization header style: "AWS ACCESS_KEY:SIGNATURE"
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "AWS ") {
		parts := strings.SplitN(authHeader[4:], ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid V2 authorization header format")
		}
		signature := parts[1]
		date := r.Header.Get("Date")
		if date == "" {
			date = r.Header.Get("X-Amz-Date")
		}
		if date == "" {
			return fmt.Errorf("missing Date header")
		}
		// Validate timestamp is within clock skew window to prevent replay.
		t, err := time.Parse(time.RFC1123, date)
		if err != nil {
			return fmt.Errorf("invalid date format")
		}
		now := time.Now().UTC()
		skew := now.Sub(t).Abs()
		if skew > clockSkew {
			return fmt.Errorf("request timestamp outside clock skew window")
		}
		stringToSign := buildV2StringToSign(r)
		expectedSig := base64.StdEncoding.EncodeToString(hmacSHA1([]byte(secretKey), []byte(stringToSign)))
		if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
			return ErrSignatureMismatch
		}
		return nil
	}

	return fmt.Errorf("no V2 signature found")
}

// buildV2StringToSign builds the AWS SigV2 string-to-sign.
func buildV2StringToSign(r *http.Request) string {
	var buf strings.Builder
	buf.WriteString(r.Method)
	buf.WriteByte('\n')
	// Content-MD5 (empty if not present)
	if md5 := r.Header.Get("Content-MD5"); md5 != "" {
		buf.WriteString(md5)
	}
	buf.WriteByte('\n')
	// Content-Type (empty if not present)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		buf.WriteString(ct)
	}
	buf.WriteByte('\n')
	// Date
	date := r.Header.Get("Date")
	if date == "" {
		date = r.Header.Get("X-Amz-Date")
	}
	if date == "" {
		date = r.URL.Query().Get("Expires")
	}
	buf.WriteString(date)
	buf.WriteByte('\n')
	// CanonicalizedAmzHeaders (V2 only includes x-amz-* headers)
	amzHeaders := make([]string, 0)
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") {
			val := strings.Join(v, ",")
			amzHeaders = append(amzHeaders, lk+":"+strings.TrimSpace(val))
		}
	}
	sort.Strings(amzHeaders)
	for _, h := range amzHeaders {
		buf.WriteString(h)
		buf.WriteByte('\n')
	}
	// CanonicalizedResource
	resource := r.URL.Path
	if resource == "" {
		resource = "/"
	}
	buf.WriteString(resource)
	return buf.String()
}

// hmacSHA1 computes HMAC-SHA1.
func hmacSHA1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func createCanonicalRequest(r *http.Request, isPresigned bool, signedHeaders []string) (string, error) {
	var buf strings.Builder

	// HTTP Method
	buf.WriteString(r.Method)
	buf.WriteByte('\n')

	// Canonical URI
	// Note: This should be normalized path. For simple proxying, r.URL.Path is usually sufficient,
	// but AWS requires strict encoding.
	uri := r.URL.Path
	if uri == "" {
		uri = "/"
	}
	// Encode path segments according to S3 rules
	encodedURI := encodePath(uri)
	buf.WriteString(encodedURI)
	buf.WriteByte('\n')

	// Canonical Query String
	query := r.URL.Query()
	// Filter out X-Amz-Signature for presigned
	var keys []string
	for k := range query {
		if k != "X-Amz-Signature" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	var queryBuf strings.Builder
	for i, k := range keys {
		if i > 0 {
			queryBuf.WriteByte('&')
		}
		// Encode key and value
		// Note: AWS expects strict URI encoding
		vals := query[k]
		// AWS spec says sorted by key, then if multiple values, sort by value?
		// Go's url.Values maps to []string. We should sort values if multiple.
		sort.Strings(vals)
		for j, v := range vals {
			if j > 0 {
				queryBuf.WriteByte('&') // This is incorrect for duplicate keys, AWS expects key=val&key=val2
				// Actually, key=val1&key=val2 is handled by flattening
			}
			// But wait, standard flattening: key=val1&key=val2
			// If we iterate keys, we need to handle multiple values manually
			// Re-do loop properly
			_ = v // unused in this scope, fix below
		}
	}

	// Correct query string construction
	var encodedQueryItems []string
	for _, k := range keys {
		vals := query[k]
		sort.Strings(vals)
		for _, v := range vals {
			// UriEncode(Key) + "=" + UriEncode(Value)
			item := uriEncode(k) + "=" + uriEncode(v)
			encodedQueryItems = append(encodedQueryItems, item)
		}
	}
	buf.WriteString(strings.Join(encodedQueryItems, "&"))
	buf.WriteByte('\n')

	// Canonical Headers
	// Must use the signed headers list
	headerMap := make(map[string][]string)
	for k, v := range r.Header {
		headerMap[strings.ToLower(k)] = v
	}
	// Host header is special: if not in r.Header, use r.Host
	if _, ok := headerMap["host"]; !ok && r.Host != "" {
		headerMap["host"] = []string{r.Host}
	}

	sort.Strings(signedHeaders)
	for _, h := range signedHeaders {
		lk := strings.ToLower(h)
		vals, ok := headerMap[lk]
		if ok {
			// Join values with comma, trim spaces
			var trimmedVals []string
			for _, v := range vals {
				trimmedVals = append(trimmedVals, strings.TrimSpace(v))
			}
			buf.WriteString(lk)
			buf.WriteByte(':')
			buf.WriteString(strings.Join(trimmedVals, ","))
			buf.WriteByte('\n')
		} else {
			// Should header mismatch be error? AWS says yes.
			// But for now let's assume it exists if it was signed.
		}
	}
	buf.WriteByte('\n')

	// Signed Headers
	buf.WriteString(strings.Join(signedHeaders, ";"))
	buf.WriteByte('\n')

	// Payload Hash
	// For Presigned URLs, usually "UNSIGNED-PAYLOAD"
	// For Header Auth, extracted from X-Amz-Content-Sha256
	payloadHash := "UNSIGNED-PAYLOAD"
	if !isPresigned {
		ph := r.Header.Get("X-Amz-Content-Sha256")
		if ph != "" {
			payloadHash = ph
		}
	} else {
		// For presigned, it's strictly "UNSIGNED-PAYLOAD" for GET
		// For PUT, it might be signed? usually UNSIGNED-PAYLOAD too for browser compatibility
		// We'll assume UNSIGNED-PAYLOAD for presigned unless header is present (which is rare)
		// Actually, "UNSIGNED-PAYLOAD" is the literal string used in signature calculation
	}
	buf.WriteString(payloadHash)

	return buf.String(), nil
}

func createStringToSign(timestamp, credentialScope, canonicalRequest string) string {
	hash := sha256.Sum256([]byte(canonicalRequest))
	canonicalRequestHash := hex.EncodeToString(hash[:])

	return strings.Join([]string{
		"AWS4-HMAC-SHA256",
		timestamp,
		credentialScope,
		canonicalRequestHash,
	}, "\n")
}

func sign(key []byte, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func getSignatureKey(secret, date, region, service string) []byte {
	kDate := sign([]byte("AWS4"+secret), []byte(date))
	kRegion := sign(kDate, []byte(region))
	kService := sign(kRegion, []byte(service))
	kSigning := sign(kService, []byte("aws4_request"))
	return kSigning
}

// uriEncode encodes strings for AWS Signature V4 (RFC 3986)
// This is different from url.QueryEscape
func uriEncode(s string) string {
	// url.QueryEscape encodes spaces as +, but AWS requires %20
	encoded := url.QueryEscape(s)
	return strings.ReplaceAll(encoded, "+", "%20")
}

// encodePath encodes the path for S3 canonical URI
func encodePath(path string) string {
	// S3 requires encoding of all characters except unreserved and slash
	// We split by slash, encode each segment, and join back
	segments := strings.Split(path, "/")
	var encodedSegments []string
	for _, s := range segments {
		encodedSegments = append(encodedSegments, uriEncode(s))
	}
	// If the path started with /, split will give empty string as first element
	// which uriEncode will return as empty string. Join will restore the slash.
	// However, if path ended with /, last element is empty, join will restore.
	// This matches S3 expectations.
	return strings.Join(encodedSegments, "/")
}
