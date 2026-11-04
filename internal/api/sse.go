package api

import (
	"bytes"
	"crypto/md5" // S3 SSE-C protocol checksum, not authentication.
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/aws/smithy-go"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/util"
)

const (
	sseAlgorithmHeader  = "x-amz-server-side-encryption"
	sseKMSKeyHeader     = "x-amz-server-side-encryption-aws-kms-key-id"
	sseKMSContextHeader = "x-amz-server-side-encryption-context"
	sseBucketKeyHeader  = "x-amz-server-side-encryption-bucket-key-enabled"
	sseCustomerAlg      = "x-amz-server-side-encryption-customer-algorithm"
	sseCustomerKey      = "x-amz-server-side-encryption-customer-key"
	sseCustomerMD5      = "x-amz-server-side-encryption-customer-key-md5"
)

type sseFieldSet map[string]string

func parseSSEOptions(fields map[string]string) (*s3.SSEOptions, error) {
	values := make(sseFieldSet, len(fields))
	for name, value := range fields {
		name = strings.ToLower(name)
		if _, exists := values[name]; exists {
			return nil, ErrPostInvalidOption
		}
		values[name] = value
	}
	return parseSSEFieldSet(values)
}

func parseSSEFieldSet(fields sseFieldSet) (*s3.SSEOptions, error) {
	present := func(key string) bool { _, ok := fields[key]; return ok }
	value := func(key string) string { return fields[key] }
	keys := []string{sseAlgorithmHeader, sseKMSKeyHeader, sseKMSContextHeader, sseBucketKeyHeader, sseCustomerAlg, sseCustomerKey, sseCustomerMD5}
	any := false
	for _, key := range keys {
		any = any || present(key)
	}
	if !any {
		return nil, nil
	}
	algorithm := value(sseAlgorithmHeader)
	if present(sseAlgorithmHeader) && algorithm == "" {
		return nil, ErrPostInvalidOption
	}
	customerFields := present(sseCustomerAlg) || present(sseCustomerKey) || present(sseCustomerMD5)
	kmsFields := present(sseKMSKeyHeader) || present(sseKMSContextHeader) || present(sseBucketKeyHeader)
	if customerFields {
		if present(sseAlgorithmHeader) || kmsFields || !present(sseCustomerAlg) || !present(sseCustomerKey) || !present(sseCustomerMD5) || value(sseCustomerAlg) != "AES256" {
			return nil, ErrPostInvalidOption
		}
		key, err := base64.StdEncoding.Strict().DecodeString(value(sseCustomerKey))
		if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != value(sseCustomerKey) {
			clear(key)
			return nil, ErrPostInvalidOption
		}
		md5Bytes, err := base64.StdEncoding.Strict().DecodeString(value(sseCustomerMD5))
		want := md5.Sum(key)
		if err != nil || len(md5Bytes) != md5.Size || base64.StdEncoding.EncodeToString(md5Bytes) != value(sseCustomerMD5) || subtle.ConstantTimeCompare(md5Bytes, want[:]) != 1 {
			clear(key)
			clear(md5Bytes)
			return nil, ErrPostInvalidOption
		}
		clear(md5Bytes)
		return &s3.SSEOptions{Customer: &s3.SSECustomerKey{Key: key, MD5: value(sseCustomerMD5)}}, nil
	}
	result := &s3.SSEOptions{Algorithm: algorithm}
	switch algorithm {
	case "AES256":
		if kmsFields {
			return nil, ErrPostInvalidOption
		}
	case "aws:kms":
		if present(sseKMSKeyHeader) {
			if value(sseKMSKeyHeader) == "" {
				return nil, ErrPostInvalidOption
			}
			result.KMSKeyID = value(sseKMSKeyHeader)
		}
		if present(sseKMSContextHeader) {
			if value(sseKMSContextHeader) == "" || !validKMSContext(value(sseKMSContextHeader)) {
				return nil, ErrPostInvalidOption
			}
			result.KMSContext = value(sseKMSContextHeader)
		}
		if present(sseBucketKeyHeader) {
			var enabled bool
			switch value(sseBucketKeyHeader) {
			case "true":
				enabled = true
			case "false":
			default:
				return nil, ErrPostInvalidOption
			}
			result.BucketKeyEnabled = &enabled
		}
	case "aws:kms:dsse":
		return nil, ErrPostUnsupported
	case "":
		return nil, ErrPostInvalidOption
	default:
		return nil, ErrPostUnsupported
	}
	if algorithm != "aws:kms" && kmsFields {
		return nil, ErrPostInvalidOption
	}
	return result, nil
}

func validKMSContext(encoded string) bool {
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded || !utf8.Valid(decoded) {
		return false
	}
	defer clear(decoded)
	if !validJSONSurrogates(decoded) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(decoded))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return false
		}
		key, ok := keyToken.(string)
		if !ok || seen[key] {
			return false
		}
		seen[key] = true
		valueToken, err := dec.Token()
		if err != nil {
			return false
		}
		if _, ok := valueToken.(string); !ok {
			return false
		}
	}
	if _, err := dec.Token(); err != nil {
		return false
	}
	var extra any
	return errors.Is(dec.Decode(&extra), io.EOF)
}

// validJSONSurrogates rejects unpaired UTF-16 surrogate escapes. encoding/json
// otherwise replaces them with U+FFFD, which would accept malformed context
// strings despite valid UTF-8 bytes in the base64 payload.
func validJSONSurrogates(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '"' {
			continue
		}
		for i++; i < len(data); i++ {
			switch data[i] {
			case '\\':
				i++
				if i >= len(data) {
					return false
				}
				if data[i] != 'u' {
					continue
				}
				if i+4 >= len(data) {
					return false
				}
				code, ok := parseHex4(data[i+1 : i+5])
				if !ok {
					return false
				}
				i += 4
				if code >= 0xDC00 && code <= 0xDFFF {
					return false
				}
				if code >= 0xD800 && code <= 0xDBFF {
					if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
						return false
					}
					low, ok := parseHex4(data[i+3 : i+7])
					if !ok || low < 0xDC00 || low > 0xDFFF {
						return false
					}
					i += 6
				}
			case '"':
				goto nextString
			}
		}
		return false
	nextString:
	}
	return true
}

func parseHex4(data []byte) (uint16, bool) {
	if len(data) != 4 {
		return 0, false
	}
	var n uint16
	for _, b := range data {
		n <<= 4
		switch {
		case b >= '0' && b <= '9':
			n |= uint16(b - '0')
		case b >= 'a' && b <= 'f':
			n |= uint16(b-'a') + 10
		case b >= 'A' && b <= 'F':
			n |= uint16(b-'A') + 10
		default:
			return 0, false
		}
	}
	return n, true
}

func parseSSECustomerHeaders(h http.Header) (*s3.SSECustomerKey, error) {
	fields := make(sseFieldSet)
	for _, name := range []string{sseCustomerAlg, sseCustomerKey, sseCustomerMD5} {
		var values []string
		count := 0
		for key, entries := range h {
			if strings.EqualFold(key, name) {
				count++
				values = append(values, entries...)
			}
		}
		if count > 1 || len(values) > 1 {
			return nil, ErrPostInvalidOption
		}
		if len(values) == 1 {
			fields[name] = values[0]
		}
	}
	if len(fields) == 0 {
		return nil, nil
	}
	parsed, err := parseSSEFieldSet(fields)
	if err != nil {
		return nil, err
	}
	if parsed == nil || parsed.Customer == nil {
		return nil, ErrPostInvalidOption
	}
	return parsed.Customer, nil
}

func parsePutObjectOptions(r *http.Request) (s3.ObjectPutOptions, error) {
	var options s3.ObjectPutOptions
	if r == nil {
		return options, ErrPostInvalidOption
	}
	fields := make(sseFieldSet)
	for _, name := range []string{sseAlgorithmHeader, sseKMSKeyHeader, sseKMSContextHeader, sseBucketKeyHeader, sseCustomerAlg, sseCustomerKey, sseCustomerMD5} {
		values, count := headerValues(r.Header, name)
		if count > 1 || len(values) > 1 {
			return options, ErrPostInvalidOption
		}
		if len(values) == 1 {
			fields[name] = values[0]
		}
	}
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	if queryErr != nil {
		return options, ErrPostInvalidOption
	}
	queryCustomer := make(sseFieldSet)
	canonicalQuery := map[string]string{sseCustomerAlg: "X-Amz-Server-Side-Encryption-Customer-Algorithm", sseCustomerKey: "X-Amz-Server-Side-Encryption-Customer-Key", sseCustomerMD5: "X-Amz-Server-Side-Encryption-Customer-Key-MD5"}
	for lower, canonical := range canonicalQuery {
		if values, ok := query[canonical]; ok {
			if len(values) != 1 || values[0] == "" {
				return options, ErrPostInvalidOption
			}
			queryCustomer[lower] = values[0]
		}
		for name := range query {
			if strings.EqualFold(name, canonical) && name != canonical {
				return options, ErrPostInvalidOption
			}
		}
	}
	if len(queryCustomer) > 0 {
		if len(fields) > 0 || query.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || r.Header.Get("Authorization") != "" {
			return options, ErrPostInvalidOption
		}
		fields = queryCustomer
	}
	sse, err := parseSSEFieldSet(fields)
	if err != nil {
		return options, err
	}
	options.SSE = sse
	return validateParsedPutObjectOptions(r, options)
}

func hasSSECustomerHeaders(headers http.Header) bool {
	for _, name := range []string{sseCustomerAlg, sseCustomerKey, sseCustomerMD5} {
		if values, count := headerValues(headers, name); count > 0 || len(values) > 0 {
			return true
		}
	}
	return false
}

// validateParsedPutObjectOptions owns a parsed customer key until successful
// return. Every validation failure after key decoding wipes its mutable bytes.
func validateParsedPutObjectOptions(r *http.Request, options s3.ObjectPutOptions) (result s3.ObjectPutOptions, err error) {
	result = options
	var customer *s3.SSECustomerKey
	if options.SSE != nil {
		customer = options.SSE.Customer
	}
	defer func() {
		if err != nil && customer != nil {
			customer.Close()
		}
	}()
	if value, ok := singleHeader(r.Header, "x-amz-storage-class"); ok {
		switch value {
		case "STANDARD":
		case "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR":
			result.StorageClass = value
		case "EXPRESS_ONEZONE":
			return s3.ObjectPutOptions{}, ErrPostUnsupported
		default:
			return s3.ObjectPutOptions{}, ErrPostInvalidOption
		}
	}
	if values, count := headerValues(r.Header, "x-amz-storage-class"); count > 1 || len(values) > 1 {
		return s3.ObjectPutOptions{}, ErrPostInvalidOption
	}
	if value, ok := singleHeader(r.Header, "x-amz-website-redirect-location"); ok {
		if !validWebsiteRedirect(value) {
			return s3.ObjectPutOptions{}, ErrPostInvalidOption
		}
		result.WebsiteRedirectLocation = value
	}
	if values, count := headerValues(r.Header, "x-amz-website-redirect-location"); count > 1 || len(values) > 1 {
		return s3.ObjectPutOptions{}, ErrPostInvalidOption
	}
	if result.SSE != nil && result.SSE.Customer != nil {
		query, queryErr := url.ParseQuery(r.URL.RawQuery)
		queryCustomer := queryErr == nil && hasSSECustomerQuery(query)
		if !queryCustomer {
			if err := requireSignedCustomerHeaders(r); err != nil {
				return s3.ObjectPutOptions{}, err
			}
		}
	}
	return result, nil
}

func validWebsiteRedirect(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return true
	}
	u, err := url.Parse(value)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.Hostname() == "" || u.User != nil {
		return false
	}
	if port := u.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 {
			return false
		}
	}
	return true
}

func hasSSECustomerQuery(query url.Values) bool {
	for name := range query {
		if strings.EqualFold(name, "X-Amz-Server-Side-Encryption-Customer-Algorithm") || strings.EqualFold(name, "X-Amz-Server-Side-Encryption-Customer-Key") || strings.EqualFold(name, "X-Amz-Server-Side-Encryption-Customer-Key-MD5") {
			return true
		}
	}
	return false
}

func headerValues(h http.Header, name string) ([]string, int) {
	var values []string
	count := 0
	for key, entries := range h {
		if strings.EqualFold(key, name) {
			count++
			values = append(values, entries...)
		}
	}
	return values, count
}

func singleHeader(h http.Header, name string) (string, bool) {
	values, count := headerValues(h, name)
	if count != 1 || len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func requireSignedCustomerHeaders(r *http.Request) error {
	if r.Header.Get("Authorization") == "" {
		return ErrPostInvalidOption
	}
	authorization := r.Header.Get("Authorization")
	for _, required := range []string{sseCustomerAlg, sseCustomerKey, sseCustomerMD5} {
		if !authorizationSignsHeader(authorization, required) {
			return ErrPostInvalidOption
		}
	}
	return nil
}

func authorizationSignsHeader(authorization, header string) bool {
	if !strings.HasPrefix(authorization, "AWS4-HMAC-SHA256 ") {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(authorization, "AWS4-HMAC-SHA256 "), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && key == "SignedHeaders" {
			for _, name := range strings.Split(value, ";") {
				if name == header {
					return true
				}
			}
		}
	}
	return false
}

func (h *Handler) objectReadClient(r *http.Request, client s3.Client, bucket, key string) (s3.Client, func(), error) {
	cleanup := func() {}
	if r == nil || client == nil {
		return nil, cleanup, ErrPostInvalidOption
	}
	queryFields := make(sseFieldSet)
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, cleanup, ErrPostInvalidOption
	}
	for name, values := range query {
		lower := strings.ToLower(name)
		switch lower {
		case sseCustomerAlg, sseCustomerKey, sseCustomerMD5:
			canonical := map[string]string{sseCustomerAlg: "X-Amz-Server-Side-Encryption-Customer-Algorithm", sseCustomerKey: "X-Amz-Server-Side-Encryption-Customer-Key", sseCustomerMD5: "X-Amz-Server-Side-Encryption-Customer-Key-MD5"}[lower]
			if name != canonical || len(values) != 1 {
				return nil, cleanup, ErrPostInvalidOption
			}
			queryFields[lower] = values[0]
		case sseAlgorithmHeader, sseKMSKeyHeader, sseKMSContextHeader, sseBucketKeyHeader:
			return nil, cleanup, ErrPostInvalidOption
		}
	}
	for name := range query {
		lower := strings.ToLower(name)
		if (lower == sseCustomerAlg || lower == sseCustomerKey || lower == sseCustomerMD5) && queryFields[lower] == "" {
			return nil, cleanup, ErrPostInvalidOption
		}
	}
	for _, name := range []string{sseAlgorithmHeader, sseKMSKeyHeader, sseKMSContextHeader, sseBucketKeyHeader} {
		if values, count := headerValues(r.Header, name); count > 0 || len(values) > 0 {
			return nil, cleanup, ErrPostInvalidOption
		}
	}
	headerFields := make(sseFieldSet)
	for _, name := range []string{sseCustomerAlg, sseCustomerKey, sseCustomerMD5} {
		values, count := headerValues(r.Header, name)
		if count > 1 || len(values) > 1 {
			return nil, cleanup, ErrPostInvalidOption
		}
		if len(values) == 1 {
			headerFields[name] = values[0]
		}
	}
	if len(queryFields) > 0 && len(headerFields) > 0 {
		return nil, cleanup, ErrPostInvalidOption
	}
	fields := headerFields
	presigned := false
	if len(queryFields) > 0 {
		fields = queryFields
		presigned = query.Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256"
		if !presigned || r.Header.Get("Authorization") != "" {
			return nil, cleanup, ErrPostInvalidOption
		}
	}
	if len(fields) == 0 {
		return client, cleanup, nil
	}
	if !presigned {
		if err := requireSignedCustomerHeaders(r); err != nil {
			return nil, cleanup, err
		}
	}
	parsed, err := parseSSEFieldSet(fields)
	if err != nil {
		return nil, cleanup, err
	}
	if parsed == nil || parsed.Customer == nil {
		return nil, cleanup, ErrPostInvalidOption
	}
	customer := parsed.Customer
	if err := h.validateSSECustomerTransport(r); err != nil {
		customer.Close()
		return nil, cleanup, err
	}
	decorated, err := s3.WithSSECustomerReadClient(client, bucket, key, customer)
	if err != nil {
		customer.Close()
		return nil, cleanup, err
	}
	return decorated, customer.Close, nil
}

// translateSSECustomerReadError is used only by object GET/HEAD backend read
// failures. Compatible services report missing-key reads as InvalidRequest on
// GET or BadRequest on HEAD; the SDK exposes a bodyless HEAD 403 as Forbidden.
// Each translation is gated by its backend method, finite code, and HTTP status.
func translateSSECustomerReadError(err error, bucket, key string, method string, backendStatus int) *S3Error {
	var apiErr smithy.APIError
	apiCode := ""
	if errors.As(err, &apiErr) {
		apiCode = apiErr.ErrorCode()
	}
	if (method == http.MethodGet && apiCode == "InvalidRequest" || method == http.MethodHead && apiCode == "BadRequest") && backendStatus == http.StatusBadRequest {
		resource := ""
		if bucket != "" {
			resource = "/" + bucket
			if key != "" {
				resource += "/" + key
			}
		}
		return &S3Error{Code: "InvalidArgument", Message: "The request contains an invalid argument.", Resource: resource, HTTPStatus: http.StatusBadRequest}
	}
	if method == http.MethodHead && apiCode == "Forbidden" && backendStatus == http.StatusForbidden {
		resource := ""
		if bucket != "" {
			resource = "/" + bucket
			if key != "" {
				resource += "/" + key
			}
		}
		return &S3Error{Code: "AccessDenied", Message: "Access Denied", Resource: resource, HTTPStatus: http.StatusForbidden}
	}
	return TranslateError(err, bucket, key)
}

func requestHasSSECustomerInput(r *http.Request) bool {
	if r == nil {
		return false
	}
	for _, name := range []string{sseCustomerAlg, sseCustomerKey, sseCustomerMD5} {
		if values, count := headerValues(r.Header, name); count > 0 || len(values) > 0 {
			return true
		}
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false
	}
	for name := range query {
		if strings.EqualFold(name, sseCustomerAlg) || strings.EqualFold(name, sseCustomerKey) || strings.EqualFold(name, sseCustomerMD5) {
			return true
		}
	}
	return false
}

func objectReadCacheCaptureAllowed(cacheEnabled, requestEligible bool, metadata map[string]string, plainSize, limit int64) bool {
	return cacheEnabled && requestEligible && !isSSECustomerBackendObject(metadata) && cacheCaptureEligibility(plainSize, limit)
}

func (h *Handler) validateSSECustomerTransport(r *http.Request) error {
	if h == nil || h.trustedIPExtractor == nil || h.trustedIPExtractorInvalid || !h.trustedIPExtractor.IsHTTPSRequest(r) {
		return ErrSSEInsecureTransport
	}
	if h.backendEndpointError != nil || h.backendEndpointScheme != "https" || h.backendTLS.InsecureSkipVerify {
		return ErrSSEInsecureTransport
	}
	return nil
}

func rejectSSECustomerCopyOrMPU(r *http.Request) error {
	if r == nil || r.URL == nil {
		return nil
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err == nil {
		for name := range query {
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "x-amz-copy-source-server-side-encryption-customer-") || strings.HasPrefix(lower, "x-amz-server-side-encryption-customer-") {
				return ErrPostUnsupported
			}
		}
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-copy-source-server-side-encryption-customer-") || strings.HasPrefix(lower, "x-amz-server-side-encryption-customer-") {
			return ErrPostUnsupported
		}
	}
	return nil
}

func isCopyOrMPURequest(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	if r.Header.Get("x-amz-copy-source") != "" {
		return true
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return false
	}
	_, uploads := query["uploads"]
	_, uploadID := query["uploadId"]
	_, partNumber := query["partNumber"]
	return uploads || uploadID || partNumber
}

func cloneSSEMetadata(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (h *Handler) writeSSEOptionError(w http.ResponseWriter, r *http.Request, op string, err error, start time.Time) {
	code, message, status := classifySSEOptionError(err)
	h.writeObjectError(w, r, op, &S3Error{Code: code, Message: message, Resource: r.URL.Path, HTTPStatus: status}, start)
}

func newTrustedIPExtractor(cfg *config.Config) (*util.IPExtractor, bool) {
	if cfg == nil {
		extractor, _ := util.NewIPExtractor(nil)
		return extractor, false
	}
	extractor, err := util.NewIPExtractor(append([]string(nil), cfg.Server.TrustedProxies...))
	if err != nil {
		return nil, true
	}
	return extractor, false
}

func validateBackendSSETransport(endpoint string, useSSL bool, tls config.BackendTLSConfig) (scheme string, err error) {
	u, err := s3.ResolveEndpoint(endpoint, useSSL)
	if err != nil {
		return "", fmt.Errorf("backend endpoint: %w", err)
	}
	return u.Scheme, nil
}
