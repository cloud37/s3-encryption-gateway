//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/md5" // S3 SSE-C protocol checksum, not authentication.
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	internalS3 "github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

const (
	postGatewayAccess = "GH353GATEWAYACCESS"
	postGatewaySecret = "gateway-post-only-secret-not-backend"
	postSessionToken  = "gateway-post-session-token-only"
)

type postFormCase struct {
	fields               map[string]string
	afterFileFields      map[string]string
	conditionOverrides   map[string]string
	startsWithConditions map[string]string
	omitConditions       map[string]bool
	contentLengthRange   *[2]int64
	file                 []byte
	fileName             string
	tokenOverride        *string
	omitSessionToken     bool
	unknownLength        bool
	date                 time.Time
	expiration           time.Time
	corruptSignature     bool
	truncateBody         bool
}

func postCredential(token string, expires *time.Time) config.GatewayCredential {
	return config.GatewayCredential{
		AccessKey: postGatewayAccess, SecretKey: postGatewaySecret,
		SessionToken: token, ExpiresAt: expires,
		Buckets: []string{"*"}, Permissions: postPermission(config.ObjectPermissionReadWrite),
	}
}

func postPermission(value config.ObjectPermission) *config.ObjectPermission { return &value }

func postGateway(t *testing.T, inst provider.Instance, credential config.GatewayCredential, opts ...harness.Option) *harness.Gateway {
	t.Helper()
	options := []harness.Option{harness.WithAuth(credential), harness.WithConfigMutator(func(cfg *config.Config) {
		cfg.Backend.MetadataProfile = inst.GH353MetadataProfile
		cfg.Backend.PostInlineTagging = provider.GH353PostInlineTagging(inst)
	})}
	options = append(options, opts...)
	return harness.StartGateway(t, inst, options...)
}

func postProtectedGateway(t *testing.T, inst provider.Instance, credential config.GatewayCredential, opts ...harness.Option) *harness.Gateway {
	t.Helper()
	inst.GH353MetadataProfile = "compact"
	return postGateway(t, inst, credential, opts...)
}

func postFormURL(gw *harness.Gateway, bucket string) string {
	return strings.TrimRight(gw.URL, "/") + "/" + postEncodePathSegment(bucket)
}

// makePostRequest independently constructs and signs the original policy bytes.
// The file part is always the last MIME part, matching the signed POST contract.
func makePostRequest(t *testing.T, endpoint, bucket, key string, credential config.GatewayCredential, tc postFormCase) *http.Request {
	t.Helper()
	if tc.date.IsZero() {
		tc.date = time.Now().UTC()
	}
	if tc.expiration.IsZero() {
		tc.expiration = tc.date.Add(15 * time.Minute)
	}
	date := tc.date.UTC().Format("20060102T150405Z")
	day := date[:8]
	scope := credential.AccessKey + "/" + day + "/" + testRegion + "/s3/aws4_request"
	fields := map[string]string{
		"bucket": bucket, "key": key,
		"x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": scope, "x-amz-date": date,
	}
	if credential.SessionToken != "" && !tc.omitSessionToken {
		fields["x-amz-security-token"] = credential.SessionToken
	}
	if tc.tokenOverride != nil {
		fields["x-amz-security-token"] = *tc.tokenOverride
	}
	for name, value := range tc.fields {
		fields[name] = value
	}
	for name, value := range tc.afterFileFields {
		fields[name] = value
	}
	conditionFields := make(map[string]string, len(fields))
	for name, value := range fields {
		// x-ignore-* fields are explicitly exempt from POST policy coverage and
		// are discarded by the gateway. Keep an after-file framing probe out of
		// the signed field set so authentication succeeds before Finish rejects
		// the non-final file part.
		if _, afterFile := tc.afterFileFields[name]; afterFile && strings.HasPrefix(strings.ToLower(name), "x-ignore-") {
			continue
		}
		conditionFields[name] = value
	}
	for name, value := range tc.conditionOverrides {
		conditionFields[name] = value
	}
	fieldNames := make([]string, 0, len(conditionFields))
	for name := range conditionFields {
		fieldNames = append(fieldNames, name)
	}
	sort.Strings(fieldNames)
	conditions := make([]any, 0, len(fieldNames)+1)
	for _, name := range fieldNames {
		if tc.omitConditions[name] {
			continue
		}
		if _, startsWith := tc.startsWithConditions[name]; startsWith {
			continue
		}
		conditions = append(conditions, map[string]string{name: conditionFields[name]})
	}
	conditionNames := make([]string, 0, len(tc.startsWithConditions))
	for name := range tc.startsWithConditions {
		conditionNames = append(conditionNames, name)
	}
	sort.Strings(conditionNames)
	for _, name := range conditionNames {
		conditions = append(conditions, []any{"starts-with", "$" + name, tc.startsWithConditions[name]})
	}
	if tc.contentLengthRange != nil {
		conditions = append(conditions, []any{"content-length-range", tc.contentLengthRange[0], tc.contentLengthRange[1]})
	}
	policy, err := json.Marshal(struct {
		Expiration string `json:"expiration"`
		Conditions []any  `json:"conditions"`
	}{tc.expiration.UTC().Format(time.RFC3339), conditions})
	if err != nil {
		t.Fatal("construct signed POST policy")
	}
	encodedPolicy := base64.StdEncoding.EncodeToString(policy)
	fields["policy"] = encodedPolicy
	fields["x-amz-signature"] = postPolicySignature(credential.SecretKey, day, testRegion, encodedPolicy)
	if tc.corruptSignature {
		fields["x-amz-signature"] = strings.Repeat("0", 64)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, name := range fieldNames {
		if _, afterFile := tc.afterFileFields[name]; afterFile {
			continue
		}
		part, createErr := writer.CreateFormField(name)
		if createErr != nil {
			t.Fatal("construct signed POST fields")
		}
		if _, writeErr := io.WriteString(part, fields[name]); writeErr != nil {
			t.Fatal("write signed POST field")
		}
	}
	for _, name := range []string{"policy", "x-amz-signature"} {
		part, createErr := writer.CreateFormField(name)
		if createErr != nil {
			t.Fatal("construct signed POST authentication fields")
		}
		if _, writeErr := io.WriteString(part, fields[name]); writeErr != nil {
			t.Fatal("write signed POST authentication field")
		}
	}
	fileName := tc.fileName
	if fileName == "" {
		fileName = "upload.bin"
	}
	filePart, err := writer.CreateFormFile("file", fileName)
	if err != nil {
		t.Fatal("construct signed POST file part")
	}
	if _, err := filePart.Write(tc.file); err != nil {
		t.Fatal("write signed POST file")
	}
	afterFileNames := make([]string, 0, len(tc.afterFileFields))
	for name := range tc.afterFileFields {
		afterFileNames = append(afterFileNames, name)
	}
	sort.Strings(afterFileNames)
	for _, name := range afterFileNames {
		part, createErr := writer.CreateFormField(name)
		if createErr != nil {
			t.Fatal("construct post-file form field")
		}
		if _, writeErr := io.WriteString(part, tc.afterFileFields[name]); writeErr != nil {
			t.Fatal("write post-file form field")
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal("finish signed POST form")
	}
	if tc.truncateBody && body.Len() > 12 {
		body.Truncate(body.Len() - 12)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body.Bytes()))
	if err != nil {
		t.Fatal("construct signed POST request")
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if tc.unknownLength {
		req.ContentLength = -1
	} else {
		req.ContentLength = int64(body.Len())
	}
	return req
}

func postPolicySignature(secret, day, region, policy string) string {
	hmac256 := func(key, value []byte) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write(value)
		return h.Sum(nil)
	}
	dateKey := hmac256([]byte("AWS4"+secret), []byte(day))
	regionKey := hmac256(dateKey, []byte(region))
	serviceKey := hmac256(regionKey, []byte("s3"))
	signingKey := hmac256(serviceKey, []byte("aws4_request"))
	defer clear(dateKey)
	defer clear(regionKey)
	defer clear(serviceKey)
	defer clear(signingKey)
	signature := hmac256(signingKey, []byte(policy))
	defer clear(signature)
	return hex.EncodeToString(signature)
}

func TestGH353PostObjectAfterFileIgnoreFieldIsEmittedButNotSigned(t *testing.T) {
	credential := postCredential("", nil)
	request := makePostRequest(t, "http://gateway.example/bucket", "bucket", "object.bin", credential, postFormCase{
		afterFileFields: map[string]string{"x-ignore-after-file": "framing-probe"},
		file:            []byte("payload"),
	})
	defer request.Body.Close()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal("read generated POST fixture")
	}
	text := string(body)
	fileEnd := strings.Index(text, `name="file"`)
	afterFile := strings.Index(text, `name="x-ignore-after-file"`)
	if fileEnd < 0 || afterFile <= fileEnd || !strings.Contains(text, "framing-probe") {
		t.Fatal("x-ignore framing probe was not emitted after the file part")
	}
	policyPart := strings.SplitN(text, `name="policy"`, 2)
	if len(policyPart) != 2 {
		t.Fatal("generated policy part missing")
	}
	policyEnd := strings.Index(policyPart[1], "\r\n")
	if policyEnd < 0 {
		t.Fatal("generated policy value terminator missing")
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(policyPart[1][:policyEnd]))
	if decodeErr != nil {
		t.Fatal("decode generated POST policy")
	}
	if bytes.Contains(decoded, []byte("x-ignore-after-file")) {
		t.Fatal("exempt x-ignore field was incorrectly covered by the signature")
	}
}

func postHTTP(t *testing.T, gw *harness.Gateway, credential config.GatewayCredential, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	client := gw.HTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("signed PostObject request transport failed")
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("signed PostObject response could not be read")
	}
	return resp, body
}

func postErrorCode(t *testing.T, body []byte) string {
	t.Helper()
	var response struct {
		Code string `xml:"Code"`
	}
	if err := xml.Unmarshal(body, &response); err != nil {
		t.Fatalf("PostObject error response was not S3 XML")
	}
	return response.Code
}

func postSafeErrorCode(body []byte) string {
	var response struct {
		Code string `xml:"Code"`
	}
	if xml.Unmarshal(body, &response) != nil {
		return "unavailable"
	}
	switch response.Code {
	case "AccessDenied", "BadDigest", "EntityTooLarge", "EntityTooSmall", "ExpiredToken", "IncompleteBody", "InternalError", "InvalidArgument", "InvalidRequest", "InvalidToken", "MalformedPOSTRequest", "MalformedXML", "MetadataTooLarge", "NotImplemented", "RequestExpired", "RequestTimeTooSkewed", "SignatureDoesNotMatch", "SlowDown":
		return response.Code
	default:
		return "unavailable"
	}
}

func postSafeErrorCodeWithStatus(status int, body []byte) string {
	if status == http.StatusBadRequest || status == http.StatusForbidden || status == http.StatusRequestEntityTooLarge || status == http.StatusNotImplemented || status == http.StatusInternalServerError {
		return postSafeErrorCode(body)
	}
	return "unavailable"
}

func postSafeSDKError(err error) (int, string) {
	status, code := 0, "unavailable"
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) {
		status = response.HTTPStatusCode()
	}
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		if allowed := postAllowlistedBackendErrorHeader(apiError.ErrorCode()); allowed != "" {
			code = allowed
		}
	}
	return status, code
}

func postSafeErrorDetails(body []byte) (string, string) {
	var response struct {
		Code string `xml:"Code"`
	}
	if xml.Unmarshal(body, &response) != nil {
		return "unavailable", ""
	}
	code := postSafeErrorCodeWithStatus(http.StatusBadRequest, body)
	switch code {
	case "EntityTooSmall":
		return code, "The uploaded object is smaller than the permitted size."
	case "EntityTooLarge":
		return code, "The request exceeds the permitted payload size."
	case "IncompleteBody":
		return code, "The request body is incomplete."
	case "InvalidArgument", "InvalidRequest":
		return code, "Invalid POST form."
	case "NotImplemented":
		return code, "The requested POST option is not supported."
	default:
		return code, ""
	}
}

func signedGatewayRequest(t *testing.T, method, rawURL string, body []byte, token string, customerHeaders http.Header) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, bytes.NewReader(body))
	if err != nil {
		t.Fatal("construct signed gateway request")
	}
	if customerHeaders != nil {
		req.Header = customerHeaders.Clone()
	}
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if req.Host == "" {
		req.Host = req.URL.Host
	}
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	day := timestamp[:8]
	req.Header.Set("X-Amz-Date", timestamp)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	if token != "" {
		req.Header.Set("X-Amz-Security-Token", token)
	}
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if token != "" {
		signedHeaders = append(signedHeaders, "x-amz-security-token")
	}
	for header := range req.Header {
		lower := strings.ToLower(header)
		if strings.HasPrefix(lower, "x-amz-server-side-encryption-customer-") {
			signedHeaders = append(signedHeaders, lower)
		}
	}
	sort.Strings(signedHeaders)
	canonical := postCanonicalRequest(req, signedHeaders)
	scope := day + "/" + testRegion + "/s3/aws4_request"
	stringToSign := buildStringToSign(timestamp, scope, canonical)
	key := getSignatureKey(postGatewaySecret, day, testRegion, "s3")
	sig := hex.EncodeToString(hmacSHA256(key, []byte(stringToSign)))
	clear(key)
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s", postGatewayAccess, scope, strings.Join(signedHeaders, ";"), sig))
	return req
}

func postCanonicalRequest(req *http.Request, signedHeaders []string) string {
	var canonical strings.Builder
	canonical.WriteString(req.Method)
	canonical.WriteByte('\n')
	canonical.WriteString(postCanonicalURI(req.URL.EscapedPath()))
	canonical.WriteByte('\n')
	query := req.URL.Query()
	queryKeys := make([]string, 0, len(query))
	for name := range query {
		queryKeys = append(queryKeys, name)
	}
	sort.Strings(queryKeys)
	queryParts := make([]string, 0)
	for _, name := range queryKeys {
		values := append([]string(nil), query[name]...)
		sort.Strings(values)
		for _, value := range values {
			queryParts = append(queryParts, uriEncodeV4(name)+"="+uriEncodeV4(value))
		}
	}
	canonical.WriteString(strings.Join(queryParts, "&"))
	canonical.WriteByte('\n')
	for _, name := range signedHeaders {
		value := req.Header.Get(name)
		if strings.EqualFold(name, "host") {
			value = req.Host
		}
		canonical.WriteString(strings.ToLower(name))
		canonical.WriteByte(':')
		canonical.WriteString(strings.TrimSpace(value))
		canonical.WriteByte('\n')
	}
	canonical.WriteByte('\n')
	canonical.WriteString(strings.Join(signedHeaders, ";"))
	canonical.WriteByte('\n')
	canonical.WriteString(req.Header.Get("X-Amz-Content-Sha256"))
	return canonical.String()
}

func postCanonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	parts := strings.Split(path, "/")
	for index := range parts {
		decoded, err := url.PathUnescape(parts[index])
		if err != nil {
			return ""
		}
		// Match the gateway's SigV4 canonicalizer: encode the decoded URL.Path
		// segment with query escaping (spaces become %20), preserving literal
		// dots. postEncodePathSegment is for emitted object URLs/Location values
		// and intentionally escapes dots, so it is not suitable for signing.
		parts[index] = uriEncodeV4(decoded)
	}
	return strings.Join(parts, "/")
}

func postGatewayGet(t *testing.T, gw *harness.Gateway, bucket, key, token string, headers http.Header) (*http.Response, []byte) {
	t.Helper()
	request := signedGatewayRequest(t, http.MethodGet, postObjectURL(gw, bucket, key), nil, token, headers)
	resp, err := gw.HTTPClient().Do(request)
	if err != nil {
		t.Fatalf("signed gateway GET transport failed")
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatalf("signed gateway GET body read failed")
	}
	return resp, body
}

func postGatewayHead(t *testing.T, gw *harness.Gateway, bucket, key, token string, headers http.Header) *http.Response {
	t.Helper()
	request := signedGatewayRequest(t, http.MethodHead, postObjectURL(gw, bucket, key), nil, token, headers)
	resp, err := gw.HTTPClient().Do(request)
	if err != nil {
		t.Fatalf("signed gateway HEAD transport failed")
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func postObjectURL(gw *harness.Gateway, bucket, key string) string {
	parts := encodePostKeySegments(key)
	return strings.TrimRight(gw.URL, "/") + "/" + postEncodePathSegment(bucket) + "/" + strings.Join(parts, "/")
}

func postStageDelta(gw *harness.Gateway, start int) ([]string, bool) {
	if gw == nil {
		return nil, false
	}
	return gw.PostObjectFailureStagesSince(start)
}

func postGatewayLocation(gw *harness.Gateway, bucket, key string) string {
	parsed, err := url.Parse(gw.URL)
	if err != nil {
		return ""
	}
	parsed.Path = "/" + bucket + "/" + key
	parsed.RawPath = "/" + postEncodePathSegment(bucket) + "/" + strings.Join(encodePostKeySegments(key), "/")
	return parsed.String()
}

func encodePostKeySegments(key string) []string {
	parts := strings.Split(key, "/")
	for i, part := range parts {
		parts[i] = postEncodePathSegment(part)
	}
	return parts
}

func postEncodePathSegment(segment string) string {
	const hexDigits = "0123456789ABCDEF"
	var encoded strings.Builder
	for _, value := range []byte(segment) {
		if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || strings.ContainsRune("-_~", rune(value)) {
			encoded.WriteByte(value)
			continue
		}
		encoded.WriteByte('%')
		encoded.WriteByte(hexDigits[value>>4])
		encoded.WriteByte(hexDigits[value&15])
	}
	return encoded.String()
}

func verifyPostReadback(t *testing.T, gw *harness.Gateway, bucket, key string, want []byte, token string, recorders ...*postWriteRecorder) {
	t.Helper()
	resp, body := postGatewayGet(t, gw, bucket, key, token, nil)
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, want) {
		backend := "unavailable"
		if len(recorders) == 1 {
			backend = recorders[0].safeReadSummary()
		}
		t.Fatalf("PostObject readback status=%d bytes_match=%t length_match=%t client_uncompressed=%t client_length_match=%t backend={%s}", resp.StatusCode, bytes.Equal(body, want), len(body) == len(want), resp.Uncompressed, resp.ContentLength == int64(len(want)), backend)
	}
	head := postGatewayHead(t, gw, bucket, key, token, nil)
	if head.StatusCode != http.StatusOK || head.ContentLength != int64(len(want)) {
		t.Fatalf("PostObject HEAD status=%d length=%d", head.StatusCode, head.ContentLength)
	}
	if resp.Header.Get("ETag") != head.Header.Get("ETag") {
		t.Fatal("PostObject GET and HEAD ETag projection differed")
	}
	end := min(int64(len(want))-1, 31)
	if end >= 0 {
		request, err := http.NewRequest(http.MethodGet, postObjectURL(gw, bucket, key), nil)
		if err != nil {
			t.Fatal("construct PostObject range read")
		}
		rangeHeaders := http.Header{"Range": []string{fmt.Sprintf("bytes=0-%d", end)}}
		signed := signedGatewayRequest(t, http.MethodGet, request.URL.String(), nil, token, rangeHeaders)
		rangeResp, err := gw.HTTPClient().Do(signed)
		if err != nil {
			t.Fatal("PostObject range read transport failed")
		}
		rangeBody, readErr := io.ReadAll(rangeResp.Body)
		rangeResp.Body.Close()
		if readErr != nil || rangeResp.StatusCode != http.StatusPartialContent || !bytes.Equal(rangeBody, want[:end+1]) {
			t.Fatalf("PostObject range read status=%d or bytes differ", rangeResp.StatusCode)
		}
	}
}

func directPostBackend(t *testing.T, inst provider.Instance) internalS3.Client {
	t.Helper()
	return newS3Client(t, inst)
}

func providerCapabilitiesFor(inst provider.Instance) (provider.Capabilities, bool) {
	return provider.CapabilitiesForInstance(inst)
}

func providerCleanupPolicyFor(inst provider.Instance) (provider.CleanupPolicy, bool) {
	return provider.CleanupPolicyForInstance(inst)
}

func canCleanupPostObject(inst provider.Instance) bool {
	cleanup, available := providerCleanupPolicyFor(inst)
	return available && cleanup == provider.CleanupPolicyDelete
}

func cleanupPostObject(t *testing.T, inst provider.Instance, key string) {
	t.Helper()
	if !canCleanupPostObject(inst) {
		return
	}
	{
		backend := newS3CompatClient(t, inst)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		head, headErr := backend.HeadObject(ctx, &awss3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
		if headErr != nil {
			var apiErr smithy.APIError
			if errors.As(headErr, &apiErr) && (apiErr.ErrorCode() == "NoSuchKey" || apiErr.ErrorCode() == "NotFound") {
				return
			}
			t.Error("cleanup could not identify owned PostObject")
			return
		}
		if head == nil {
			t.Error("cleanup returned no HEAD metadata for owned PostObject")
			return
		}
		deleteInput := &awss3.DeleteObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)}
		if versionID := aws.ToString(head.VersionId); versionID != "" {
			deleteInput.VersionId = aws.String(versionID)
		}
		if _, err := backend.DeleteObject(ctx, deleteInput); err != nil {
			t.Error("cleanup of owned PostObject failed")
		}
	}
}

func testPostObjectRoundTrip(t *testing.T, inst provider.Instance) {
	for _, tc := range []struct {
		name, engine string
		unknown      bool
		bypass       bool
		filename     string
		key          string
		bounds       *[2]int64
		zeroBytes    bool
		overflowMeta bool
	}{
		{name: "buffered-known-form-length", engine: "buffered"},
		{name: "chunked-unknown-form-length", engine: "chunked", unknown: true},
		{name: "chunked-metadata-overflow-streaming-prefix-fallback", engine: "chunked", unknown: true, overflowMeta: true},
		{name: "policy-bypass-from-encrypting-default", engine: "buffered", bypass: true},
		{name: "filename-unix-basename-literal-key", engine: "chunked", filename: "dir/sub/name.bin", key: "literal/../plus+percent%25/"},
		{name: "filename-windows-basename", engine: "buffered", filename: `C:\browser\windows.bin`},
		{name: "literal-dot-plus-percent-unicode-trailing-slash", engine: "chunked", key: "literal/dot..segment/plus+percent%25/雪/"},
		{name: "zero-byte-inclusive-policy-bound", engine: "buffered", bounds: &[2]int64{0, 0}, zeroBytes: true},
		{name: "exact-inclusive-policy-bounds", engine: "chunked", bounds: &[2]int64{20 * 1024, 20 * 1024}},
	} {
		runPostCase(t, tc.name, func(t *testing.T) {
			if tc.name == "filename-unix-basename-literal-key" {
				if expectation, restricted := provider.LiteralPostRejectionForInstance(inst); restricted {
					t.Run("native-rejection-neighbor-preserved", func(t *testing.T) { testLiteralNativeRejection(t, inst, expectation) })
					return
				}
			}
			payload := bytes.Repeat([]byte("GH353-post-record-☃-"), 1024)
			if tc.zeroBytes {
				payload = nil
			} else if tc.bounds != nil {
				payload = bytes.Repeat([]byte("b"), int(tc.bounds[0]))
			}
			runPostObjectRoundTripDetailedWithOverflow(t, inst, tc.engine, tc.unknown, tc.bypass, tc.filename, tc.key, tc.bounds, payload, tc.overflowMeta)
		})
	}
	runPostCase(t, "protected-metadata-round-trip", func(t *testing.T) { runPostObjectProtectedMetadata(t, inst) })
}

func TestGH353PostObjectPathEncodingAndLocation(t *testing.T) {
	gw := &harness.Gateway{URL: "https://gateway.example:8443"}
	bucket := "bucket"
	key := "literal/dot..segment/plus+percent%25/雪/"
	wantPath := "/bucket/literal/dot..segment/plus%2Bpercent%2525/%E9%9B%AA/"
	if got := postCanonicalURI(postObjectURL(gw, bucket, key)[len(gw.URL):]); got != wantPath {
		t.Fatalf("canonical URI %q want %q", got, wantPath)
	}
	wantLocation := gw.URL + "/bucket/literal/dot%2E%2Esegment/plus%2Bpercent%2525/%E9%9B%AA/"
	if got, want := postGatewayLocation(gw, bucket, key), wantLocation; got != want {
		t.Fatalf("PostResponse Location %q want %q", got, want)
	}
}

func TestGH353PostObjectCanonicalSignerMatchesGatewayForDots(t *testing.T) {
	gw := &harness.Gateway{URL: "https://gateway.example:8443"}
	request := signedGatewayRequest(t, http.MethodGet, postObjectURL(gw, "bucket", "records..bin"), nil, "", nil)
	if _, err := api.ValidateSignatureV4(request, postGatewaySecret, time.Minute); err != nil {
		t.Fatalf("helper-signed request did not verify with gateway canonicalization: %v", err)
	}
}

func runPostObjectRoundTrip(t *testing.T, inst provider.Instance, engine string, unknownLength bool) {
	runPostObjectRoundTripCase(t, inst, engine, unknownLength, false, "", "")
}

func runPostObjectRoundTripCase(t *testing.T, inst provider.Instance, engine string, unknownLength, bypass bool, filename, literalKey string) {
	runPostObjectRoundTripDetailed(t, inst, engine, unknownLength, bypass, filename, literalKey, nil, bytes.Repeat([]byte("GH353-post-record-☃-"), 1024))
}

func runPostObjectRoundTripDetailed(t *testing.T, inst provider.Instance, engine string, unknownLength, bypass bool, filename, literalKey string, bounds *[2]int64, want []byte) {
	runPostObjectRoundTripDetailedWithOverflow(t, inst, engine, unknownLength, bypass, filename, literalKey, bounds, want, false)
}

func runPostObjectRoundTripDetailedWithOverflow(t *testing.T, inst provider.Instance, engine string, unknownLength, bypass bool, filename, literalKey string, bounds *[2]int64, want []byte, overflowMeta bool) {
	t.Helper()
	key := literalKey
	if key == "" {
		key = uniqueKey(t) + "/plus+percent%25.dots..雪/records.bin"
	} else if _, external := os.LookupEnv(externalSelectionEnv); external {
		// Literal path segments stay unchanged, but external fixtures must never
		// write a fixed shared key or delete an object from a previous run.
		key = uniqueKey(t) + "/" + key
	}
	requestKey := key
	if overflowMeta {
		requestKey = strings.TrimSuffix(key, "records.bin") + "${filename}"
	}
	if filename != "" {
		base := filename[strings.LastIndexAny(filename, "/\\")+1:]
		requestKey = strings.TrimSuffix(key, "/") + "/${filename}"
		key = strings.TrimSuffix(key, "/") + "/" + base
	}
	t.Cleanup(func() { cleanupPostObject(t, inst, key) })
	credential := postCredential("", nil)
	recorder := &postWriteRecorder{base: http.DefaultTransport, diagnosticLength: int64(len(want)), diagnosticLanguage: "en", diagnosticTarget: "/" + inst.Bucket + "/" + key, diagnosticEnabled: true}
	backendTransport := http.RoundTripper(recorder)
	options := []harness.Option{harness.WithChunking(engine == "chunked"), harness.WithBackendTransport(backendTransport)}
	if bypass {
		bypassManager := newBypassPolicyManager(t, inst.Bucket)
		if !bypassManager.BucketDisablesEncryption(inst.Bucket) {
			t.Fatal("bypass fixture did not disable encryption for the destination bucket")
		}
		options = append(options, harness.WithPolicyManager(bypassManager))
	}
	gw := postGateway(t, inst, credential, options...)
	stageStart := gw.PostObjectFailureStageCount()
	backendStart := recorder.putEvidenceCount()
	fields := map[string]string{
		"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
		"Content-Disposition": "inline", "Cache-Control": "no-cache",
		"Content-Language": "en", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
	}
	fields["x-amz-meta-owner"], fields["x-amz-meta-purpose"] = "browser-post", "conformance"
	if overflowMeta {
		fields["x-amz-meta-overflow"] = strings.Repeat("v", 7900)
		fields["key"] = requestKey
	} else {
		fields["key"] = requestKey
	}
	requestFilename := filename
	if requestFilename == "" {
		requestFilename = "records.bin"
	}
	startsWithConditions := map[string]string{}
	if strings.Contains(fields["key"], "${filename}") {
		startsWithConditions["key"] = strings.TrimSuffix(fields["key"], "${filename}")
	}
	if overflowMeta {
		startsWithConditions["x-amz-meta-overflow"] = ""
	}
	req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, requestKey, credential, postFormCase{
		fields: fields, file: want, fileName: requestFilename, unknownLength: unknownLength, contentLengthRange: bounds,
		startsWithConditions: startsWithConditions,
	})
	resp, body := postHTTP(t, gw, credential, req)
	if overflowMeta {
		logPostHeaderMeasurements(t, recorder, backendStart)
	}
	responseStages, stagesOK := postStageDelta(gw, stageStart)
	if resp.StatusCode != http.StatusNoContent || len(body) != 0 {
		backendSummary, backendSnapshotOK := recorder.putEvidenceSummarySince(backendStart)
		t.Fatalf("PostObject response status=%d code=%s backend={%s} backend_snapshot_valid=%t safe_failure_stages=%v stage_snapshot_valid=%t", resp.StatusCode, postSafeErrorCode(body), backendSummary, backendSnapshotOK, responseStages, stagesOK)
	}
	if recorder != nil {
		if identity, ok := recorder.identity.Load().(string); !ok || identity == "" || strings.Contains(identity, postGatewayAccess) || recorder.tokenSeen.Load() {
			t.Fatal("gateway POST credential identity or token was forwarded to the backend")
		}
		identity, _ := recorder.identity.Load().(string)
		if provider.RequiresBackendCredentialIdentity(inst) && !strings.Contains(identity, "Credential="+inst.AccessKey+"/") {
			t.Fatal("local provider backend request was not signed with the configured backend identity")
		}
	}
	if unknownLength && req.ContentLength != -1 {
		t.Fatal("unknown-length POST fixture unexpectedly set ContentLength")
	}
	if overflowMeta {
		if engine != "chunked" || !unknownLength {
			t.Fatal("metadata-overflow fallback case must use unknown-length chunked streaming")
		}
		if req.ContentLength != -1 {
			t.Fatal("metadata-overflow fallback request unexpectedly had a known length")
		}
	}
	wantETag := `"` + hex.EncodeToString(md5Sum(want)) + `"`
	if !bypass && resp.Header.Get("ETag") != wantETag {
		t.Fatalf("PostObject returned an unexpected plaintext ETag")
	}
	verifyPostReadback(t, gw, inst.Bucket, key, want, "", recorder)
	readResponse, _ := postGatewayGet(t, gw, inst.Bucket, key, "", nil)
	readHead := postGatewayHead(t, gw, inst.Bucket, key, "", nil)
	wantMetadata := map[string]string{
		"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
		"Content-Disposition": "inline", "Cache-Control": "no-cache",
		"Content-Language": "en", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
	}
	wantMetadata["X-Amz-Meta-Owner"], wantMetadata["X-Amz-Meta-Purpose"] = "browser-post", "conformance"
	if overflowMeta {
		wantMetadata["X-Amz-Meta-Overflow"] = strings.Repeat("v", 7900)
	}
	if !bypass {
		wantMetadata["ETag"] = wantETag
	}
	for header, expected := range wantMetadata {
		if readResponse.Header.Get(header) != expected || readHead.Header.Get(header) != expected {
			t.Fatalf("PostObject metadata %s did not round-trip get_match=%t head_match=%t backend={%s}", header, readResponse.Header.Get(header) == expected, readHead.Header.Get(header) == expected, recorder.safeReadSummary())
		}
	}
	if len(want) > 0 {
		end := min(len(want)-1, 31)
		rangeRequest := signedGatewayRequest(t, http.MethodGet, postObjectURL(gw, inst.Bucket, key), nil, "", http.Header{"Range": {fmt.Sprintf("bytes=0-%d", end)}})
		rangeResponse, err := gw.HTTPClient().Do(rangeRequest)
		if err != nil {
			t.Fatal("metadata range transport failed")
		}
		rangeBody, readErr := io.ReadAll(rangeResponse.Body)
		closeErr := rangeResponse.Body.Close()
		if readErr != nil || closeErr != nil || rangeResponse.StatusCode != http.StatusPartialContent || !bytes.Equal(rangeBody, want[:end+1]) || !metadataResponseValuesMatch(rangeResponse.Header, wantMetadata) {
			t.Fatal("POST range did not restore complete metadata")
		}
	}
	backend := directPostBackend(t, inst)
	ciphertext, metadata, err := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
	if err != nil {
		t.Fatalf("read PostObject backend ciphertext")
	}
	stored, readErr := io.ReadAll(ciphertext)
	closeErr := ciphertext.Close()
	if readErr != nil || closeErr != nil || !bypass && (bytes.Equal(stored, want) || metadata[crypto.MetaEncrypted] != "true") || bypass && (!bytes.Equal(stored, want) || metadata[crypto.MetaEncrypted] != "") {
		clear(stored)
		t.Fatalf("PostObject backend payload encryption/bypass contract mismatch")
	}
	clear(stored)
	if bypass && (metadata[crypto.MetaAlgorithm] != "" || metadata[crypto.MetaObjectFormatVersion] != "" || metadata[crypto.MetaEncryptedMetadata] != "" || metadata[crypto.MetaEncryptedMetadataCompact] != "") {
		t.Fatal("policy bypass persisted gateway encryption metadata")
	}
	if bypass {
		for name, expected := range map[string]string{
			"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
			"Content-Disposition": "inline", "Cache-Control": "no-cache",
			"Content-Language": "en", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
			"x-amz-meta-owner": "browser-post", "x-amz-meta-purpose": "conformance",
		} {
			if metadata[name] != expected {
				t.Fatalf("bypass backend metadata %s=%q want %q", name, metadata[name], expected)
			}
		}
	}
	backendMetadata, err := backend.HeadObject(t.Context(), inst.Bucket, key, nil)
	if err != nil {
		t.Fatalf("PostObject backend HEAD failed")
	}
	if overflowMeta {
		expanded, expandErr := crypto.ExpandMetadataForAPI(backendMetadata)
		if expandErr != nil {
			t.Fatalf("expand persisted fallback metadata: %v", expandErr)
		}
		if expanded[crypto.MetaChunkedFormat] != "true" || expanded[crypto.MetaFallbackMode] != "true" || expanded[crypto.MetaFallbackVersion] != "2" {
			t.Fatal("backend did not persist the real chunked fallback-v2 markers")
		}
		if expanded[crypto.MetaEncrypted] != "true" {
			t.Fatal("fallback backend metadata did not retain the encrypted marker")
		}
		for name, protectedKey := range map[string]string{
			"Content-Type": crypto.MetaContentType, "Content-Encoding": crypto.MetaContentEncoding,
			"Content-Disposition": crypto.MetaContentDisposition, "Cache-Control": crypto.MetaCacheControl,
			"Content-Language": crypto.MetaContentLanguage, "Expires": crypto.MetaExpires,
		} {
			if expanded[protectedKey] != fields[name] {
				t.Fatalf("fallback encrypted backend protected metadata for %s was not persisted", name)
			}
		}
		for name, expected := range map[string]string{"x-amz-meta-owner": "browser-post", "x-amz-meta-purpose": "conformance"} {
			if expanded[name] != expected {
				t.Fatalf("fallback encrypted backend user metadata %s was not persisted", name)
			}
		}
		if expanded["x-amz-meta-overflow"] != "" {
			t.Fatal("overflow metadata must not be duplicated in backend headers")
		}
		fallbackObject, _, getErr := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
		if getErr != nil {
			t.Fatal("read persisted fallback object")
		}
		fallbackEngine, engineErr := crypto.NewEngineWithOpts([]byte("test-encryption-password-123456"), crypto.WithChunking(true))
		if engineErr != nil {
			fallbackObject.Close()
			t.Fatal("construct matching chunked fallback reader")
		}
		decryptedReader, decryptedMetadata, decryptErr := fallbackEngine.Decrypt(t.Context(), crypto.ObjectContext{Bucket: inst.Bucket, Key: key}, fallbackObject, expanded)
		if decryptErr != nil {
			fallbackObject.Close()
			t.Fatalf("decrypt actual persisted fallback object: %v", decryptErr)
		}
		decryptedFallback, readErr := io.ReadAll(decryptedReader)
		closeErr := fallbackObject.Close()
		if readErr != nil || closeErr != nil || !bytes.Equal(decryptedFallback, want) || decryptedMetadata["x-amz-meta-overflow"] != strings.Repeat("v", 7900) {
			clear(decryptedFallback)
			t.Fatal("persisted fallback body/decrypted metadata did not match overflow upload")
		}
		for header, value := range map[string]string{
			"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
			"Content-Disposition": "inline", "Cache-Control": "no-cache",
			"Content-Language": "en", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
			"x-amz-meta-owner": "browser-post", "x-amz-meta-purpose": "conformance",
		} {
			if decryptedMetadata[header] != value {
				clear(decryptedFallback)
				t.Fatalf("fallback decrypted metadata %s=%q want %q", header, decryptedMetadata[header], value)
			}
		}
		clear(decryptedFallback)
	}
	if bypass {
		backendETag, ok := recorder.lastETag.Load().(string)
		if !ok || backendETag == "" || !postETagProvenanceMatches(backendETag, resp.Header.Get("ETag"), readResponse.Header.Get("ETag"), readHead.Header.Get("ETag")) {
			t.Fatalf("bypass response ETag did not preserve backend ETag %q", backendETag)
		}
		for header, expected := range map[string]string{
			"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
			"Content-Disposition": "inline", "Cache-Control": "no-cache",
			"Content-Language": "en", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
			"x-amz-meta-owner": "browser-post", "x-amz-meta-purpose": "conformance",
		} {
			if backendMetadata[header] != expected {
				t.Fatalf("bypass backend metadata %s did not round-trip", header)
			}
		}
	} else if !overflowMeta {
		expanded, expandErr := crypto.ExpandMetadataForAPI(backendMetadata)
		if expandErr != nil {
			t.Fatal("expand encrypted backend metadata")
		}
		if expanded[crypto.MetaEncrypted] != "true" {
			t.Fatal("encrypted backend metadata lacks the clear encryption marker")
		}
		for header, protectedKey := range map[string]string{
			"Content-Type": crypto.MetaContentType, "Content-Encoding": crypto.MetaContentEncoding,
			"Content-Disposition": crypto.MetaContentDisposition, "Cache-Control": crypto.MetaCacheControl,
			"Content-Language": crypto.MetaContentLanguage, "Expires": crypto.MetaExpires,
		} {
			if expanded[protectedKey] != fields[header] {
				t.Fatalf("encrypted backend protected metadata for %s was not persisted", header)
			}
		}
		for name, expected := range map[string]string{"x-amz-meta-owner": "browser-post", "x-amz-meta-purpose": "conformance"} {
			if expanded[name] != expected {
				t.Fatalf("encrypted backend user metadata %s was not persisted", name)
			}
		}
	}
}

func postETagProvenanceMatches(backend, post, get, head string) bool {
	return backend != "" && post == backend && get == backend && head == backend
}

func metadataResponseValuesMatch(headers http.Header, expected map[string]string) bool {
	for name, value := range expected {
		if headers.Get(name) != value {
			return false
		}
	}
	return true
}

func TestGH353PostObjectETagProvenanceAcceptsMD5AndOpaque(t *testing.T) {
	payload := []byte("backend-owned-etag")
	plaintextMD5 := `"` + hex.EncodeToString(md5Sum(payload)) + `"`
	for _, tc := range []struct {
		name        string
		backendETag string
	}{
		{name: "backend md5 equals plaintext md5", backendETag: plaintextMD5},
		{name: "opaque backend etag", backendETag: `"opaque-provider-tag-2-part"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				etag := `"later-read-must-not-replace-put"`
				if req.Method == http.MethodPut {
					etag = tc.backendETag
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Etag": {etag}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			})
			recorder := &postWriteRecorder{base: base}
			for _, method := range []string{http.MethodPut, http.MethodGet, http.MethodHead} {
				request, err := http.NewRequest(method, "https://backend.example/object", nil)
				if err != nil {
					t.Fatal("construct fixture request")
				}
				response, err := recorder.RoundTrip(request)
				if err != nil {
					t.Fatal("record fixture response")
				}
				response.Body.Close()
			}
			captured, ok := recorder.lastETag.Load().(string)
			if !ok || captured != tc.backendETag {
				t.Fatalf("recorder ETag=%q want backend PUT ETag %q", captured, tc.backendETag)
			}
			if !postETagProvenanceMatches(captured, tc.backendETag, tc.backendETag, tc.backendETag) {
				t.Fatal("backend ETag provenance assertion rejected equal-MD5 or opaque backend ETag")
			}
			if tc.backendETag != plaintextMD5 && captured != tc.backendETag {
				t.Fatal("opaque backend ETag was recomputed instead of retained")
			}
		})
	}
}

func runPostObjectProtectedMetadata(t *testing.T, inst provider.Instance) {
	t.Helper()
	key := uniqueKey(t)
	credential := postCredential("", nil)
	metaKey := bytes.Repeat([]byte{0x42}, 32)
	t.Cleanup(func() { clear(metaKey) })
	t.Cleanup(func() { cleanupPostObject(t, inst, key) })
	backendRecorder := &postWriteRecorder{base: http.DefaultTransport}
	gw := postProtectedGateway(t, inst, credential, harness.WithChunking(true), harness.WithMetadataEncryptionKey(metaKey), harness.WithBackendTransport(backendRecorder))
	stageStart := gw.PostObjectFailureStageCount()
	boundaryStart := gw.PostObjectBoundaries()
	want := bytes.Repeat([]byte("protected-post-record/"), 128)
	fields := map[string]string{
		"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
		"Content-Disposition": "attachment", "Cache-Control": "private",
		"Content-Language": "en-GB", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
		"x-amz-meta-owner": "protected-post", "x-amz-meta-purpose": "round-trip",
	}
	backendStart := backendRecorder.putEvidenceCount()
	request := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{fields: fields, file: want})
	response, body := postHTTP(t, gw, credential, request)
	logPostHeaderMeasurements(t, backendRecorder, backendStart)
	if response.StatusCode != http.StatusNoContent || len(body) != 0 {
		stages, stagesOK := postStageDelta(gw, stageStart)
		backendSummary, backendSnapshotOK := backendRecorder.putEvidenceSummarySince(backendStart)
		boundaries := gw.PostObjectBoundaries()
		t.Fatalf("protected-metadata PostObject response status=%d code=%s backend={%s} backend_snapshot_valid=%t safe_failure_stages=%v stage_snapshot_valid=%t boundary_outer=%t boundary_authenticated=%t boundary_routed=%t", response.StatusCode, postSafeErrorCode(body), backendSummary, backendSnapshotOK, stages, stagesOK, boundaries[0] > boundaryStart[0], boundaries[1] > boundaryStart[1], boundaries[2] > boundaryStart[2])
	}
	expected := map[string]string{
		"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
		"Content-Disposition": "attachment", "Cache-Control": "private",
		"Content-Language": "en-GB", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
		"X-Amz-Meta-Owner": "protected-post", "X-Amz-Meta-Purpose": "round-trip",
	}
	getResponse, getBody := postGatewayGet(t, gw, inst.Bucket, key, "", nil)
	readbackOK := getResponse.StatusCode == http.StatusOK && bytes.Equal(getBody, want) && metadataResponseValuesMatch(getResponse.Header, expected)
	clear(getBody)
	if !readbackOK {
		t.Fatal("protected metadata GET did not return the uploaded plaintext")
	}
	assertProtectedPostMetadata(t, getResponse.Header, expected)
	headResponse := postGatewayHead(t, gw, inst.Bucket, key, "", nil)
	if headResponse.StatusCode != http.StatusOK || headResponse.ContentLength != int64(len(want)) || !metadataResponseValuesMatch(headResponse.Header, expected) {
		t.Fatal("protected metadata HEAD did not return the uploaded object")
	}
	assertProtectedPostMetadata(t, headResponse.Header, expected)
	rangeHeaders := http.Header{"Range": {"bytes=0-17"}}
	rangeRequest := signedGatewayRequest(t, http.MethodGet, postObjectURL(gw, inst.Bucket, key), nil, "", rangeHeaders)
	rangeResponse, err := gw.HTTPClient().Do(rangeRequest)
	if err != nil {
		t.Fatal("protected metadata range transport failed")
	}
	rangeBody, readErr := io.ReadAll(rangeResponse.Body)
	closeErr := rangeResponse.Body.Close()
	if readErr != nil || closeErr != nil || rangeResponse.StatusCode != http.StatusPartialContent || !bytes.Equal(rangeBody, want[:18]) || !metadataResponseValuesMatch(rangeResponse.Header, expected) {
		t.Fatal("protected metadata range did not return the requested plaintext")
	}
	assertProtectedPostMetadata(t, rangeResponse.Header, expected)
	backend := directPostBackend(t, inst)
	backendMetadata, err := backend.HeadObject(t.Context(), inst.Bucket, key, nil)
	if err != nil {
		t.Fatal("protected metadata backend HEAD failed")
	}
	expandedMetadata, err := crypto.ExpandMetadataForAPI(backendMetadata)
	if err != nil {
		t.Fatal("expand protected metadata backend headers")
	}
	if expandedMetadata[crypto.MetaEncrypted] != "true" || expandedMetadata[crypto.MetaEncryptedMetadata] == "" && expandedMetadata[crypto.MetaEncryptedMetadataCompact] == "" {
		t.Fatal("backend did not store encrypted metadata marker/blob")
	}
	backendObject, _, err := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
	if err != nil {
		t.Fatal("protected metadata backend GET failed")
	}
	metadataReader, err := crypto.NewEngineWithOpts([]byte("test-encryption-password-123456"), crypto.WithChunking(true))
	if err != nil {
		backendObject.Close()
		t.Fatal("construct metadata-protected object reader")
	}
	crypto.SetMetadataKey(metadataReader, metaKey)
	decryptedReader, decryptedMetadata, err := metadataReader.Decrypt(t.Context(), crypto.ObjectContext{Bucket: inst.Bucket, Key: key}, backendObject, expandedMetadata)
	if err != nil {
		backendObject.Close()
		t.Fatal("decrypt actual protected-metadata backend object")
	}
	decryptedBytes, readErr := io.ReadAll(decryptedReader)
	closeErr = backendObject.Close()
	if readErr != nil || closeErr != nil || !bytes.Equal(decryptedBytes, want) {
		clear(decryptedBytes)
		t.Fatal("protected metadata backend decrypt did not restore uploaded bytes")
	}
	clear(decryptedBytes)
	for name, value := range map[string]string{
		"Content-Type": "application/octet-stream", "Content-Encoding": "identity",
		"Content-Disposition": "attachment", "Cache-Control": "private",
		"Content-Language": "en-GB", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
		"x-amz-meta-owner": "protected-post", "x-amz-meta-purpose": "round-trip",
	} {
		if decryptedMetadata[name] != value {
			t.Fatalf("decrypted stored metadata %s=%q want %q", name, decryptedMetadata[name], value)
		}
	}
	for _, responseHeaders := range []http.Header{getResponse.Header, headResponse.Header, rangeResponse.Header} {
		for name := range responseHeaders {
			if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-enc-") || strings.EqualFold(name, "x-amz-meta-e") || strings.EqualFold(name, "x-amz-meta-em") {
				t.Fatalf("gateway exposed reserved metadata %s", name)
			}
		}
	}
}

func assertProtectedPostMetadata(t *testing.T, headers http.Header, expected map[string]string) {
	t.Helper()
	for name, want := range expected {
		if got := headers.Get(name); got != want {
			t.Errorf("protected PostObject metadata %s=%q want %q", name, got, want)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type postWriteRecorder struct {
	base               http.RoundTripper
	writes             atomic.Int64
	identity           atomic.Value
	tokenSeen          atomic.Bool
	lastETag           atomic.Value
	putEvidenceMu      sync.Mutex
	putEvidence        []*postBackendResponseEvidence
	putHeaders         []postBackendHeaderMeasurement
	evidenceTruncated  bool
	readEvidenceMu     sync.Mutex
	readEvidence       []*postBackendReadEvidence
	readEvidenceLost   bool
	diagnosticEnabled  bool
	diagnosticLength   int64
	diagnosticLanguage string
	diagnosticTarget   string
	diagnosticMu       sync.Mutex
	diagnosticReads    []postSafeRead
}

type postSafeRead struct {
	method                                                                      string
	status                                                                      int
	uncompressed, lengthMatch, languageMatch, languagePresent, encodingIdentity bool
	targetMatch, markerPresent, expandedMarker                                  bool
}

func (r *postWriteRecorder) safeReadSummary() string {
	if r == nil || !r.diagnosticEnabled {
		return "unavailable"
	}
	r.diagnosticMu.Lock()
	defer r.diagnosticMu.Unlock()
	if len(r.diagnosticReads) == 0 {
		return "none_observed"
	}
	parts := make([]string, 0, len(r.diagnosticReads))
	for _, v := range r.diagnosticReads {
		parts = append(parts, fmt.Sprintf("method=%s status=%d uncompressed=%t length_match=%t language_match=%t language_present=%t encoding_identity=%t target_match=%t marker_present=%t expanded_marker=%t", v.method, v.status, v.uncompressed, v.lengthMatch, v.languageMatch, v.languagePresent, v.encodingIdentity, v.targetMatch, v.markerPresent, v.expandedMarker))
	}
	return strings.Join(parts, ",")
}

func (r *postWriteRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	if identity := req.Header.Get("Authorization"); identity != "" {
		r.identity.Store(identity)
	}
	if req.Header.Get("X-Amz-Security-Token") != "" {
		r.tokenSeen.Store(true)
	}
	if req.Method == http.MethodPut || req.Method == http.MethodPost || req.Method == http.MethodDelete {
		r.writes.Add(1)
	}
	response, err := r.base.RoundTrip(req)
	if r.diagnosticEnabled && err == nil && response != nil && (req.Method == http.MethodPut || req.Method == http.MethodGet || req.Method == http.MethodHead) && req.Header.Get("Range") == "" {
		metadata := response.Header
		if req.Method == http.MethodPut {
			metadata = req.Header
		}
		raw := make(map[string]string)
		for name, values := range metadata {
			if len(values) > 0 && strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
				raw[strings.ToLower(name)] = values[0]
			}
		}
		spec, _ := crypto.LookupMetaKey(crypto.MetaEncrypted)
		markerPresent := raw[spec.Canonical] != "" || raw[spec.Compact] != ""
		expanded, expandErr := crypto.ExpandMetadataForAPI(raw)
		r.diagnosticMu.Lock()
		if len(r.diagnosticReads) < 8 {
			r.diagnosticReads = append(r.diagnosticReads, postSafeRead{method: req.Method, status: response.StatusCode, uncompressed: response.Uncompressed, lengthMatch: response.ContentLength == r.diagnosticLength, languageMatch: response.Header.Get("Content-Language") == r.diagnosticLanguage, languagePresent: response.Header.Get("Content-Language") != "", encodingIdentity: response.Header.Get("Content-Encoding") == "identity", targetMatch: r.diagnosticTarget != "" && req.URL.Path == r.diagnosticTarget, markerPresent: markerPresent, expandedMarker: expandErr == nil && expanded[crypto.MetaEncrypted] == "true"})
		}
		r.diagnosticMu.Unlock()
	}
	if (req.Method == http.MethodGet || req.Method == http.MethodHead) && err == nil && response != nil && response.StatusCode >= http.StatusBadRequest {
		evidence := &postBackendReadEvidence{method: req.Method, status: response.StatusCode}
		if code := postAllowlistedBackendErrorHeader(response.Header.Get("x-amz-error-code")); code != "" {
			evidence.errorCode = code
		}
		if response.Body != nil && req.Method != http.MethodHead {
			body, ok := response.Body.(*postReadEvidenceBody)
			if !ok {
				body = &postReadEvidenceBody{body: response.Body, code: func(code, parseClass string) {
					r.readEvidenceMu.Lock()
					evidence.errorCode, evidence.parseClass = code, parseClass
					r.readEvidenceMu.Unlock()
				}}
			}
			response.Body = body
		}
		r.readEvidenceMu.Lock()
		if len(r.readEvidence) < postBackendResponseEvidenceLimit {
			r.readEvidence = append(r.readEvidence, evidence)
		} else {
			r.readEvidenceLost = true
		}
		r.readEvidenceMu.Unlock()
	}
	if req.Method == http.MethodPut {
		measurement := measurePostBackendHeaders(req.Header)
		evidence := &postBackendResponseEvidence{method: http.MethodPut, headers: measurement}
		if err != nil {
			evidence.transportClass = postTransportFailureClass(err)
		} else if response != nil {
			evidence.status = response.StatusCode
			if response.StatusCode >= http.StatusBadRequest {
				if response.Body != nil {
					body, ok := response.Body.(*postResponseEvidenceBody)
					if !ok {
						body = &postResponseEvidenceBody{
							body: response.Body, expectedLength: response.ContentLength,
							expectedKnown: response.ContentLength >= 0,
							tooLarge:      response.ContentLength > postBackendErrorBodyCaptureLimit,
							code: func(code, parseClass string) {
								evidence.mu.Lock()
								evidence.errorCode = code
								evidence.parseClass = parseClass
								evidence.mu.Unlock()
							},
						}
					}
					response.Body = body
				}
			}
		}
		r.putEvidenceMu.Lock()
		if len(r.putEvidence) < postBackendResponseEvidenceLimit {
			r.putEvidence = append(r.putEvidence, evidence)
			r.putHeaders = append(r.putHeaders, measurement)
		} else {
			r.evidenceTruncated = true
		}
		r.putEvidenceMu.Unlock()
	}
	if err == nil && response != nil && req.Method == http.MethodPut {
		if etag := response.Header.Get("ETag"); etag != "" {
			r.lastETag.Store(etag)
		}
	}
	return response, err
}

type postBackendReadEvidence struct {
	method, errorCode, parseClass string
	status                        int
}

func (r *postWriteRecorder) readEvidenceCount() int {
	r.readEvidenceMu.Lock()
	defer r.readEvidenceMu.Unlock()
	return len(r.readEvidence)
}

func (r *postWriteRecorder) readEvidenceSummarySince(start int) string {
	r.readEvidenceMu.Lock()
	defer r.readEvidenceMu.Unlock()
	if start < 0 || start > len(r.readEvidence) || r.readEvidenceLost {
		return "backend_read_evidence=unavailable"
	}
	if start == len(r.readEvidence) {
		return "backend_read_errors=none_observed"
	}
	parts := make([]string, 0, len(r.readEvidence)-start)
	for _, evidence := range r.readEvidence[start:] {
		method := evidence.method
		if method != http.MethodGet && method != http.MethodHead {
			method = "unavailable"
		}
		if evidence.errorCode != "" {
			parts = append(parts, fmt.Sprintf("method=%s status=%d code=%s", method, evidence.status, evidence.errorCode))
		} else if parseClass := postBackendErrorParseClass(evidence.parseClass); parseClass != "" {
			parts = append(parts, fmt.Sprintf("method=%s status=%d code=unavailable parse=%s", method, evidence.status, parseClass))
		} else {
			parts = append(parts, fmt.Sprintf("method=%s status=%d code=unavailable", method, evidence.status))
		}
	}
	return strings.Join(parts, ",")
}

func postAllowlistedBackendErrorHeader(value string) string {
	switch value {
	case "AccessDenied", "InvalidArgument", "InvalidRequest", "BadRequest", "InternalError", "NoSuchKey", "NoSuchBucket", "NotImplemented", "SlowDown":
		return value
	default:
		return ""
	}
}

type postReadEvidenceBody struct {
	body      io.ReadCloser
	mu        sync.Mutex
	observed  []byte
	tooLarge  bool
	finalized bool
	code      func(string, string)
}

func (b *postReadEvidenceBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.body.Read(p)
	if !b.finalized && n > 0 {
		if len(b.observed)+n > postBackendErrorBodyCaptureLimit {
			b.tooLarge = true
			clear(b.observed)
			b.observed = nil
		} else if !b.tooLarge {
			b.observed = append(b.observed, p[:n]...)
		}
	}
	if err == io.EOF {
		b.finalizeLocked()
	}
	return n, err
}

func (b *postReadEvidenceBody) Close() error {
	b.mu.Lock()
	b.finalizeLocked()
	err := b.body.Close()
	b.mu.Unlock()
	return err
}

func (b *postReadEvidenceBody) finalizeLocked() {
	if b.finalized {
		return
	}
	b.finalized = true
	code, parseClass := "", ""
	if b.tooLarge {
		parseClass = "oversized"
	} else {
		code, parseClass = postAllowlistedBackendErrorCode(b.observed)
	}
	b.code(code, parseClass)
	clear(b.observed)
	b.observed = nil
}

func TestPostBackendReadErrorEvidenceIsBoundedAndRedacted(t *testing.T) {
	const canary = "backend-secret-message-canary"
	for _, tc := range []struct {
		name, body, wantCode, wantClass string
	}{
		{name: "finite InvalidRequest", body: `<Error><Code>InvalidRequest</Code><Message>` + canary + `</Message></Error>`, wantCode: "InvalidRequest"},
		{name: "unallowlisted code", body: `<Error><Code>` + canary + `</Code></Error>`, wantClass: "unallowlisted"},
		{name: "oversized response", body: `<Error><Code>InvalidRequest</Code><Message>` + strings.Repeat("x", postBackendErrorBodyCaptureLimit) + `</Message></Error>`, wantClass: "oversized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotCode, gotClass string
			observed := &postReadEvidenceBody{body: io.NopCloser(strings.NewReader(tc.body)), code: func(code, class string) { gotCode, gotClass = code, class }}
			got, err := io.ReadAll(observed)
			if err != nil || string(got) != tc.body {
				t.Fatal("read evidence wrapper changed backend response")
			}
			if err := observed.Close(); err != nil {
				t.Fatal("close evidence wrapper")
			}
			if gotCode != tc.wantCode || gotClass != tc.wantClass {
				t.Fatalf("safe backend read evidence code=%q class=%q", gotCode, gotClass)
			}
			if strings.Contains(fmt.Sprintf("%s %s", gotCode, gotClass), canary) {
				t.Fatal("read evidence summary exposed backend message/code content")
			}
		})
	}
	if got := postAllowlistedBackendErrorHeader("InvalidRequest"); got != "InvalidRequest" {
		t.Fatal("finite error header classification rejected")
	}
	if got := postAllowlistedBackendErrorHeader(canary); got != "" {
		t.Fatal("unallowlisted error header was retained")
	}
}

const postBackendErrorBodyCaptureLimit = 8 << 10
const postBackendResponseEvidenceLimit = 16

type postBackendResponseEvidence struct {
	mu             sync.Mutex
	method         string
	status         int
	headers        postBackendHeaderMeasurement
	errorCode      string
	parseClass     string
	transportClass string
}

// postBackendHeaderMeasurement contains bounded numeric aggregates only. It
// intentionally does not retain header names or values, which can include
// credentials, customer keys, object metadata, and request-specific material.
type postBackendHeaderMeasurement struct {
	totalBytes              int
	userMetadataBytes       int
	userMetadataCount       int
	protectedCiphertextLen  int
	largestValueLen         int
	compactMarkerPresent    bool
	storageClassPresent     bool
	storageClassHeaderCount int
	storageClassValueCount  int
	storageClassValuesMatch bool
}

const postBackendHeaderMeasurementCeiling = 1 << 20

func measurePostBackendHeaders(headers http.Header) postBackendHeaderMeasurement {
	const metadataPrefix = "x-amz-meta-"
	var measurement postBackendHeaderMeasurement
	for name, values := range headers {
		if len(values) == 0 {
			continue
		}
		nameLower := strings.ToLower(name)
		value := values[0]
		valueLen := len(value)
		if valueLen > postBackendHeaderMeasurementCeiling {
			valueLen = postBackendHeaderMeasurementCeiling
		}
		measurement.totalBytes = boundedPostHeaderAdd(measurement.totalBytes, len(name), valueLen)
		if valueLen > measurement.largestValueLen {
			measurement.largestValueLen = valueLen
		}
		if strings.HasPrefix(nameLower, metadataPrefix) {
			if measurement.userMetadataCount < 1024 {
				measurement.userMetadataCount++
			}
			measurement.userMetadataBytes = boundedPostHeaderAdd(measurement.userMetadataBytes, len(name), valueLen)
		}
		switch nameLower {
		case crypto.MetaEncryptedMetadata, crypto.MetaEncryptedMetadataCompact:
			measurement.protectedCiphertextLen = valueLen
		}
		if nameLower == crypto.MetaEncryptedMetadataCompact {
			measurement.compactMarkerPresent = value != ""
		}
	}
	for name, values := range headers {
		if !strings.EqualFold(name, "x-amz-storage-class") {
			continue
		}
		measurement.storageClassPresent = measurement.storageClassPresent || len(values) > 0
		if measurement.storageClassHeaderCount < 1024 {
			measurement.storageClassHeaderCount++
		}
		for _, value := range values {
			if measurement.storageClassValueCount < 1024 {
				measurement.storageClassValueCount++
			}
			if measurement.storageClassHeaderCount == 1 && measurement.storageClassValueCount == 1 {
				measurement.storageClassValuesMatch = value == "STANDARD"
			} else {
				measurement.storageClassValuesMatch = false
			}
		}
	}
	return measurement
}

func boundedPostHeaderAdd(current, nameLen, valueLen int) int {
	if current >= postBackendHeaderMeasurementCeiling || nameLen >= postBackendHeaderMeasurementCeiling-current {
		return postBackendHeaderMeasurementCeiling
	}
	current += nameLen
	if valueLen >= postBackendHeaderMeasurementCeiling-current {
		return postBackendHeaderMeasurementCeiling
	}
	return current + valueLen
}

func (m postBackendHeaderMeasurement) summary() string {
	return fmt.Sprintf("total_bytes=%d user_metadata_bytes=%d protected_ciphertext_len=%d compact_marker_present=%t user_metadata_count=%d largest_value_len=%d storage_class_present=%t standard_storage_class=%t",
		m.totalBytes, m.userMetadataBytes, m.protectedCiphertextLen, m.compactMarkerPresent, m.userMetadataCount, m.largestValueLen, m.storageClassPresent, postStorageClassMeasurementMatches(m, "STANDARD", true))
}

func logPostHeaderMeasurements(t *testing.T, recorder *postWriteRecorder, start int) {
	t.Helper()
	measurements, ok := recorder.putHeaderMeasurementsSince(start)
	if !ok || len(measurements) == 0 {
		t.Log("safe backend PUT header measurements: unavailable")
		return
	}
	for _, measurement := range measurements {
		t.Logf("safe backend PUT header measurements: %s", measurement.summary())
	}
}

func TestGH353PostBackendHeaderMeasurementsAreNumericAndBounded(t *testing.T) {
	secret := "secret"
	measurement := measurePostBackendHeaders(http.Header{
		"Content-Type":                 {"application/octet-stream"},
		"X-Amz-Meta-Owner":             {secret},
		"X-Amz-Meta-Em":                {"ciphertext-canary"},
		"X-Amz-Storage-Class":          {"STANDARD"},
		"X-Amz-Server-Side-Encryption": {"AES256"},
	})
	if measurement.totalBytes == 0 || measurement.userMetadataBytes == 0 || measurement.userMetadataCount != 2 || measurement.protectedCiphertextLen != len("ciphertext-canary") || !measurement.compactMarkerPresent || !postStorageClassMeasurementMatches(measurement, "STANDARD", false) || measurement.largestValueLen != len("application/octet-stream") {
		t.Fatal("backend header measurement did not capture the bounded numeric contract")
	}
	summary := measurement.summary()
	for _, forbidden := range []string{secret, "ciphertext-canary", "Content-Type", "X-Amz-Meta", "STANDARD", "AES256"} {
		if strings.Contains(summary, forbidden) {
			t.Fatal("backend header measurement summary exposed header content")
		}
	}
	missingStorageClass := measurePostBackendHeaders(http.Header{"Content-Type": {"application/octet-stream"}})
	if missingStorageClass.storageClassPresent || !postStorageClassMeasurementMatches(missingStorageClass, "STANDARD", true) || postStorageClassMeasurementMatches(missingStorageClass, "STANDARD", false) {
		t.Fatal("storage-class measurement reported a header that was absent")
	}
	for _, tc := range []struct {
		name    string
		headers http.Header
	}{
		{name: "different value", headers: http.Header{"X-Amz-Storage-Class": {"STANDARD_IA"}}},
		{name: "duplicate case variants", headers: http.Header{"X-Amz-Storage-Class": {"STANDARD"}, "x-amz-storage-class": {"STANDARD"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if postStorageClassMeasurementMatches(measurePostBackendHeaders(tc.headers), "STANDARD", true) {
				t.Fatal("storage-class measurement accepted a different or duplicate class")
			}
		})
	}
	oversized := measurePostBackendHeaders(http.Header{
		"X-Amz-Meta-Large": {strings.Repeat("x", postBackendHeaderMeasurementCeiling+1)},
	})
	if oversized.totalBytes != postBackendHeaderMeasurementCeiling || oversized.userMetadataBytes != postBackendHeaderMeasurementCeiling || oversized.largestValueLen != postBackendHeaderMeasurementCeiling {
		t.Fatal("backend header measurement exceeded its numeric ceiling")
	}
}

func TestGH353PostStorageClassResponseOracle(t *testing.T) {
	for _, tc := range []struct {
		name        string
		header      http.Header
		allowAbsent bool
		wantPresent bool
		wantMatches bool
	}{
		{name: "standard present", header: http.Header{"X-Amz-Storage-Class": {"STANDARD"}}, wantPresent: true, wantMatches: true},
		{name: "standard omitted when optional", header: make(http.Header), allowAbsent: true, wantMatches: true},
		{name: "standard omitted when required", header: make(http.Header)},
		{name: "different class rejected", header: http.Header{"X-Amz-Storage-Class": {"STANDARD_IA"}}, allowAbsent: true, wantPresent: true},
		{name: "duplicate class rejected", header: http.Header{"X-Amz-Storage-Class": {"STANDARD", "STANDARD"}}, allowAbsent: true, wantPresent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			present, matches := postStorageClassHeaderMatches(tc.header, "STANDARD", tc.allowAbsent)
			if present != tc.wantPresent || matches != tc.wantMatches {
				t.Fatalf("storage-class response oracle flags present=%t matches=%t, want present=%t matches=%t", present, matches, tc.wantPresent, tc.wantMatches)
			}
		})
	}
	if !postStorageClassValueMatches("", "STANDARD", true) ||
		!postStorageClassValueMatches("STANDARD", "STANDARD", true) ||
		postStorageClassValueMatches("STANDARD_IA", "STANDARD", true) ||
		postStorageClassValueMatches("", "STANDARD", false) {
		t.Fatal("backend HEAD storage-class oracle did not distinguish documented STANDARD omission from mismatches")
	}
	for _, values := range [][]string{{"STANDARD"}, {"STANDARD_IA"}, {"STANDARD", "STANDARD"}} {
		if postStorageClassValueListMatches(values, "STANDARD", true) != (len(values) == 1 && values[0] == "STANDARD") {
			t.Fatal("backend HEAD storage-class oracle accepted a different or duplicate class")
		}
	}
}

// postStorageClassHeaderMatches accepts omission only when the protocol permits
// it; duplicate or different values are never treated as a match.
func postStorageClassHeaderMatches(headers http.Header, expected string, allowAbsent bool) (bool, bool) {
	var values []string
	for name, current := range headers {
		if strings.EqualFold(name, "x-amz-storage-class") {
			values = append(values, current...)
		}
	}
	if len(values) == 0 {
		return false, allowAbsent
	}
	return true, len(values) == 1 && values[0] == expected
}

func postStorageClassMeasurementMatches(measurement postBackendHeaderMeasurement, expected string, allowAbsent bool) bool {
	if measurement.storageClassValueCount == 0 {
		return allowAbsent && measurement.storageClassHeaderCount == 0
	}
	return measurement.storageClassHeaderCount == 1 && measurement.storageClassValueCount == 1 && measurement.storageClassValuesMatch && expected == "STANDARD"
}

func postStorageClassValueMatches(actual, expected string, allowAbsent bool) bool {
	if actual == "" {
		return allowAbsent
	}
	return actual == expected
}

func postStorageClassValueListMatches(values []string, expected string, allowAbsent bool) bool {
	if len(values) == 0 {
		return allowAbsent
	}
	return len(values) == 1 && values[0] == expected
}

type postResponseEvidenceBody struct {
	body           io.ReadCloser
	mu             sync.Mutex
	observed       []byte
	observedBytes  int64
	expectedLength int64
	expectedKnown  bool
	tooLarge       bool
	finalized      bool
	code           func(string, string)
}

func (b *postResponseEvidenceBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.body.Read(p)
	if !b.finalized {
		b.observedBytes += int64(n)
	}
	if !b.finalized && !b.tooLarge && n > 0 {
		remaining := postBackendErrorBodyCaptureLimit - len(b.observed)
		if n > remaining {
			b.tooLarge = true
			clear(b.observed)
			b.observed = nil
		} else {
			b.observed = append(b.observed, p[:n]...)
		}
	}
	if err == io.EOF {
		b.finalizeLocked()
	}
	return n, err
}

func (b *postResponseEvidenceBody) Close() error {
	b.mu.Lock()
	b.finalizeLocked()
	err := b.body.Close()
	b.mu.Unlock()
	return err
}

// finalizeLocked reports evidence once, while the body mutex serializes EOF,
// Close, and concurrent readers. It does not read ahead from the SDK body.
func (b *postResponseEvidenceBody) finalizeLocked() {
	if b.finalized {
		return
	}
	b.finalized = true
	code, parseClass := "", ""
	if b.tooLarge {
		parseClass = "oversized"
	} else if b.expectedKnown && b.observedBytes != b.expectedLength {
		parseClass = "incomplete_or_malformed"
	} else if !b.expectedKnown && b.observedBytes == postBackendErrorBodyCaptureLimit {
		// At the capture ceiling without EOF, Close cannot establish whether
		// bytes remain. Treat the prefix as incomplete rather than parsing it.
		parseClass = "incomplete_or_malformed"
	} else {
		code, parseClass = postAllowlistedBackendErrorCode(b.observed)
	}
	b.code(code, parseClass)
	clear(b.observed)
	b.observed = nil
}

func postTransportFailureClass(err error) string {
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "network"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return "network"
	}
	return "transport_other"
}

func postAllowlistedBackendErrorCode(body []byte) (string, string) {
	var response struct {
		Code string `xml:"Code"`
	}
	if len(body) == 0 {
		return "", "empty"
	}
	if xml.Unmarshal(body, &response) != nil {
		return "", "incomplete_or_malformed"
	}
	if response.Code == "" {
		return "", "empty"
	}
	// Keep this finite observer allowlist limited to S3 API response literals
	// from MinIO's pinned API error map plus InvalidTag from the pinned minio-go
	// tag parser. This is diagnostic evidence only; it does not change gateway
	// error mapping or treat backend failures as success.
	// Sources:
	// https://raw.githubusercontent.com/minio/minio/7aac2a2c5b7c882e68c1ce017d8256be2feea27f/cmd/api-errors.go
	// https://raw.githubusercontent.com/minio/minio-go/v7.0.91/pkg/tags/tags.go
	switch response.Code {
	case "AccessDenied", "AuthorizationHeaderMalformed", "BadDigest", "BadRequest", "BucketAlreadyExists", "BucketNotEmpty", "EntityTooLarge", "ExcessData", "IncompleteBody", "InternalError", "InvalidArgument", "InvalidDigest", "InvalidRequest", "InvalidStorageClass", "InvalidTag", "KMS.NotFoundException", "KeyTooLongError", "MetadataTooLarge", "MissingContentMD5", "MissingSecurityHeader", "NoSuchBucket", "NoSuchKey", "NotImplemented", "NotSupported", "PreconditionFailed", "RequestTimeTooSkewed", "SignatureDoesNotMatch", "SlowDown", "XAmzContentChecksumMismatch", "XAmzContentSHA256Mismatch", "XMinioInvalidObjectName", "XMinioInvalidResourceName", "XMinioObjectExistsAsDirectory", "XMinioRequestBodyParse", "XMinioInvalidDecompressedSize":
		return response.Code, ""
	default:
		return "", "unallowlisted"
	}
}

func postEvidenceSummary(method string, status int, errorCode, parseClass, transportClass string) string {
	if method != http.MethodPut {
		method = "unavailable"
	}
	if status == 0 {
		if transportClass != "" {
			return "method=" + method + " transport=" + transportClass
		}
		return "method=" + method + " status=unavailable"
	}
	if errorCode != "" {
		return fmt.Sprintf("method=%s status=%d code=%s", method, status, errorCode)
	}
	if parseClass = postBackendErrorParseClass(parseClass); parseClass != "" {
		return fmt.Sprintf("method=%s status=%d code=unavailable parse=%s", method, status, parseClass)
	}
	return fmt.Sprintf("method=%s status=%d code=unavailable", method, status)
}

func postBackendErrorParseClass(value string) string {
	if value == "" {
		return ""
	}
	switch value {
	case "empty", "incomplete_or_malformed", "oversized", "unallowlisted":
		return value
	default:
		return "incomplete_or_malformed"
	}
}

func postEvidencePointerSummary(evidence *postBackendResponseEvidence) string {
	if evidence == nil {
		return "method=PUT status=unavailable"
	}
	evidence.mu.Lock()
	defer evidence.mu.Unlock()
	return postEvidenceSummary(evidence.method, evidence.status, evidence.errorCode, evidence.parseClass, evidence.transportClass)
}

func (r *postWriteRecorder) latestPutEvidence() *postBackendResponseEvidence {
	r.putEvidenceMu.Lock()
	defer r.putEvidenceMu.Unlock()
	if len(r.putEvidence) == 0 {
		return nil
	}
	return r.putEvidence[len(r.putEvidence)-1]
}

func (r *postWriteRecorder) putEvidenceCount() int {
	r.putEvidenceMu.Lock()
	defer r.putEvidenceMu.Unlock()
	return len(r.putEvidence)
}

func (r *postWriteRecorder) resetPutEvidence() {
	r.putEvidenceMu.Lock()
	r.putEvidence = nil
	r.putHeaders = nil
	r.evidenceTruncated = false
	r.putEvidenceMu.Unlock()
}

func (r *postWriteRecorder) putHeaderMeasurementsSince(start int) ([]postBackendHeaderMeasurement, bool) {
	r.putEvidenceMu.Lock()
	defer r.putEvidenceMu.Unlock()
	if start < 0 || start > len(r.putHeaders) || r.evidenceTruncated {
		return nil, false
	}
	return append([]postBackendHeaderMeasurement(nil), r.putHeaders[start:]...), true
}

func (r *postWriteRecorder) putEvidenceSummarySince(start int) (string, bool) {
	r.putEvidenceMu.Lock()
	if start < 0 || start > len(r.putEvidence) || r.evidenceTruncated {
		r.putEvidenceMu.Unlock()
		return "method=PUT status=unavailable", false
	}
	evidence := append([]*postBackendResponseEvidence(nil), r.putEvidence[start:]...)
	r.putEvidenceMu.Unlock()
	if len(evidence) == 0 {
		return "method=PUT request=not_observed status=unavailable", true
	}
	parts := make([]string, 0, len(evidence))
	for _, item := range evidence {
		parts = append(parts, "{"+postEvidencePointerSummary(item)+"}")
	}
	return strings.Join(parts, ","), true
}

type closeCountingBody struct {
	*strings.Reader
	closed atomic.Int64
}

func (b *closeCountingBody) Close() error {
	b.closed.Add(1)
	return nil
}

func TestGH353PostBackendErrorEvidenceReplayBoundedAndRedacted(t *testing.T) {
	const canary = "backend-secret-error-message-canary"
	for _, tc := range []struct {
		name  string
		body  string
		code  string
		parse string
	}{
		{name: "allowlisted code and secret message", body: `<Error><Code>InvalidRequest</Code><Message>` + canary + `</Message></Error>`, code: "InvalidRequest"},
		{name: "malformed response", body: `<Error><Code>InvalidRequest</Code><Message>` + canary, parse: "incomplete_or_malformed"},
		{name: "empty code", body: `<Error><Message>` + canary + `</Message></Error>`, parse: "empty"},
		{name: "unknown code is not published", body: `<Error><Code>` + canary + `</Code></Error>`, parse: "unallowlisted"},
		{name: "oversized response", body: `<Error><Message>` + strings.Repeat("x", postBackendErrorBodyCaptureLimit) + `</Message><Code>InvalidRequest</Code></Error>`, parse: "oversized"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &closeCountingBody{Reader: strings.NewReader(tc.body)}
			var code, parse string
			evidenceBody := &postResponseEvidenceBody{body: original, expectedLength: int64(len(tc.body)), expectedKnown: true, tooLarge: len(tc.body) > postBackendErrorBodyCaptureLimit, code: func(value, category string) { code, parse = value, category }}
			got, err := io.ReadAll(evidenceBody)
			if err != nil || string(got) != tc.body {
				t.Fatal("backend response body changed while collecting bounded evidence")
			}
			if code != tc.code || parse != tc.parse {
				t.Fatalf("safe error evidence code=%q parse=%q want code=%q parse=%q", code, parse, tc.code, tc.parse)
			}
			evidenceBody.mu.Lock()
			retained := len(evidenceBody.observed)
			evidenceBody.mu.Unlock()
			if retained != 0 {
				t.Fatal("parsed backend error body prefix remained retained")
			}
			if closeErr := evidenceBody.Close(); closeErr != nil || original.closed.Load() != 1 {
				t.Fatal("backend response close ownership changed")
			}
			summary := postEvidenceSummary(http.MethodPut, http.StatusInternalServerError, code, parse, "")
			if strings.Contains(summary, canary) || strings.Contains(summary, "<Error>") || strings.Contains(summary, "Message") || strings.Contains(summary, tc.body) {
				t.Fatal("backend response evidence exposed untrusted body text")
			}
		})
	}
}

func TestGH353PostBackendErrorEvidencePinnedMinIOPutCodes(t *testing.T) {
	const unknownCanary = "unknown-backend-code-secret-canary"
	const secretMessage = "backend-response-message-secret-canary"
	codes := []string{
		"InvalidStorageClass", "IncompleteBody", "ExcessData", "InvalidDigest",
		"MissingContentMD5", "MissingSecurityHeader", "AuthorizationHeaderMalformed",
		"BadRequest", "KeyTooLongError", "MetadataTooLarge",
		"XAmzContentSHA256Mismatch", "XAmzContentChecksumMismatch",
		"XMinioRequestBodyParse", "XMinioObjectExistsAsDirectory",
		"XMinioInvalidResourceName", "XMinioInvalidDecompressedSize",
		"InvalidTag",
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			body := `<Error><Code>` + code + `</Code><Message>` + secretMessage + `</Message></Error>`
			got, category := postAllowlistedBackendErrorCode([]byte(body))
			if got != code || category != "" {
				t.Fatal("pinned MinIO PUT code was not safely recognized")
			}
			summary := postEvidenceSummary(http.MethodPut, http.StatusBadRequest, got, category, "")
			if summary != "method=PUT status=400 code="+code || strings.Contains(summary, secretMessage) || strings.Contains(summary, "<Error>") {
				t.Fatal("recognized backend evidence exposed more than the allowlisted code")
			}
		})
	}
	unknownXML := `<Error><Code>` + unknownCanary + `</Code><Message>` + secretMessage + `</Message></Error>`
	got, category := postAllowlistedBackendErrorCode([]byte(unknownXML))
	if got != "" || category != "unallowlisted" {
		t.Fatal("unknown backend code was not kept unavailable")
	}
	summary := postEvidenceSummary(http.MethodPut, http.StatusBadRequest, got, category, "")
	if strings.Contains(summary, unknownCanary) || strings.Contains(summary, secretMessage) || strings.Contains(summary, unknownXML) {
		t.Fatal("unknown backend code or response message was exposed")
	}
}

func TestGH353PostBackendErrorEvidenceFinalizesOnCloseAndOnlyOnce(t *testing.T) {
	const secret = "close-without-eof-secret-canary"
	validXML := `<Error><Code>InvalidRequest</Code><Message>` + secret + `</Message></Error>`
	for _, tc := range []struct {
		name      string
		body      string
		readAll   bool
		readEOF   bool
		wantCode  string
		wantParse string
	}{
		{name: "SDK consumes complete XML then closes without EOF", body: validXML, readAll: true, wantCode: "InvalidRequest"},
		{name: "partial XML closed", body: validXML, wantParse: "incomplete_or_malformed"},
		{name: "oversized prefix closed", body: strings.Repeat("s", postBackendErrorBodyCaptureLimit+1), readAll: true, wantParse: "oversized"},
		{name: "EOF then Close retains final evidence", body: validXML, readAll: true, readEOF: true, wantCode: "InvalidRequest"},
		{name: "exact capture boundary without EOF is incomplete", body: strings.Repeat(" ", postBackendErrorBodyCaptureLimit), readAll: true, wantParse: "incomplete_or_malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := &closeCountingBody{Reader: strings.NewReader(tc.body)}
			var resultMu sync.Mutex
			var code, parse string
			callbacks := atomic.Int64{}
			observed := &postResponseEvidenceBody{body: original, expectedLength: int64(len(tc.body)), expectedKnown: true, code: func(value, category string) {
				resultMu.Lock()
				code, parse = value, category
				resultMu.Unlock()
				callbacks.Add(1)
			}}
			if tc.name == "partial XML closed" {
				buffer := make([]byte, len(tc.body)/2)
				if _, err := io.ReadFull(observed, buffer); err != nil {
					t.Fatal("partial SDK-like body read failed")
				}
			} else if tc.readAll {
				buffer := make([]byte, len(tc.body))
				if _, err := io.ReadFull(observed, buffer); err != nil || string(buffer) != tc.body {
					t.Fatal("SDK-like exact body read changed response bytes")
				}
			} else {
				buffer := make([]byte, len(tc.body)/2)
				if _, err := observed.Read(buffer); err != nil {
					t.Fatal("partial SDK-like body read failed")
				}
			}
			if tc.readEOF {
				if _, err := observed.Read(make([]byte, 1)); err != io.EOF {
					t.Fatal("expected EOF after fully consumed response")
				}
			}
			if err := observed.Close(); err != nil {
				t.Fatal("close observed backend response")
			}
			if err := observed.Close(); err != nil {
				t.Fatal("repeated close changed backend response ownership")
			}
			resultMu.Lock()
			gotCode, gotParse := code, parse
			resultMu.Unlock()
			if gotCode != tc.wantCode || gotParse != tc.wantParse || callbacks.Load() != 1 {
				t.Fatalf("finalized safe evidence code=%q parse=%q callbacks=%d", gotCode, gotParse, callbacks.Load())
			}
			observed.mu.Lock()
			retained := len(observed.observed)
			observed.mu.Unlock()
			if retained != 0 || original.closed.Load() != 2 {
				t.Fatal("evidence finalization retained body bytes or changed Close forwarding")
			}
			summary := postEvidenceSummary(http.MethodPut, http.StatusBadRequest, gotCode, gotParse, "")
			if strings.Contains(summary, secret) || strings.Contains(summary, tc.body) {
				t.Fatal("close-time evidence exposed backend response material")
			}
		})
	}
}

func TestGH353PostBackendErrorEvidenceConcurrentReads(t *testing.T) {
	const secret = "concurrent-backend-secret-canary"
	body := &closeCountingBody{Reader: strings.NewReader(`<Error><Code>InternalError</Code><Message>` + secret + `</Message></Error>`)}
	evidence := &postBackendResponseEvidence{method: http.MethodPut, status: http.StatusInternalServerError}
	var callbacks atomic.Int64
	observed := &postResponseEvidenceBody{body: body, expectedLength: int64(len(`<Error><Code>InternalError</Code><Message>` + secret + `</Message></Error>`)), expectedKnown: true, code: func(code, parseClass string) {
		callbacks.Add(1)
		evidence.mu.Lock()
		evidence.errorCode = code
		evidence.parseClass = parseClass
		evidence.mu.Unlock()
	}}
	var reads sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		reads.Add(1)
		go func() {
			defer reads.Done()
			<-start
			buffer := make([]byte, 7)
			for {
				_, err := observed.Read(buffer)
				if err != nil {
					return
				}
			}
		}()
	}
	closeDone := make(chan error, 1)
	go func() {
		<-start
		closeDone <- observed.Close()
	}()
	close(start)
	reads.Wait()
	if err := <-closeDone; err != nil || body.closed.Load() != 1 {
		t.Fatal("concurrent observation changed response close ownership")
	}
	observed.mu.Lock()
	retained := len(observed.observed)
	observed.mu.Unlock()
	if retained != 0 {
		t.Fatal("concurrent backend error body prefix remained retained")
	}
	summary := postEvidencePointerSummary(evidence)
	if !strings.Contains(summary, "code=InternalError") && !strings.Contains(summary, "code=unavailable parse=incomplete_or_malformed") || strings.Contains(summary, secret) || callbacks.Load() != 1 {
		t.Fatalf("concurrent response observation produced unexpected safe evidence: %s", summary)
	}
}

func TestGH353PostBackendTransportEvidenceUsesFixedClasses(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{name: "network category", err: &url.Error{Op: "Put", URL: "https://secret.example/object?token=secret", Err: errors.New("secret transport diagnostic")}, want: "network"},
		{name: "other category", err: errors.New("secret transport diagnostic"), want: "transport_other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := postTransportFailureClass(tc.err)
			if got != tc.want {
				t.Fatalf("transport class=%q want %q", got, tc.want)
			}
			if strings.Contains(got, "secret") || strings.Contains(got, "token") {
				t.Fatal("transport evidence exposed untrusted diagnostic text")
			}
		})
	}
}

func TestGH353PostBackendEvidenceCaptureIntegration(t *testing.T) {
	const secret = "backend-secret-error-message-canary"
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{name: "bounded allowlisted code", body: `<Error><Code>InvalidRequest</Code><Message>` + secret + `</Message></Error>`, want: `method=PUT status=500 code=InvalidRequest`},
		{name: "oversized body does not expose code beyond cap", body: `<Error><Message>` + strings.Repeat("x", postBackendErrorBodyCaptureLimit) + `</Message><Code>InvalidRequest</Code></Error>`, want: `method=PUT status=500 code=unavailable parse=oversized`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(tc.body)), Request: req}, nil
			})
			recorder := &postWriteRecorder{base: base}
			request := httptest.NewRequest(http.MethodPut, "http://backend.local/opaque", nil)
			response, err := recorder.RoundTrip(request)
			if err != nil || response.StatusCode != http.StatusInternalServerError {
				t.Fatal("recorder altered backend error response")
			}
			response.ContentLength = int64(len(tc.body))
			wrapped, ok := response.Body.(*postResponseEvidenceBody)
			if !ok {
				t.Fatal("backend error body evidence wrapper was not installed")
			}
			wrapped.expectedLength = int64(len(tc.body))
			wrapped.expectedKnown = true
			wrapped.tooLarge = len(tc.body) > postBackendErrorBodyCaptureLimit
			raw := recorder.latestPutEvidence()
			if raw == nil {
				t.Fatal("backend response evidence was not retained")
			}
			body, readErr := io.ReadAll(response.Body)
			if readErr != nil || string(body) != tc.body {
				t.Fatal("SDK-facing backend response was not replayed byte-for-byte")
			}
			summary := postEvidencePointerSummary(raw)
			if summary != tc.want || strings.Contains(summary, secret) || strings.Contains(summary, "backend.local") || strings.Contains(summary, "<Error>") {
				t.Fatalf("unsafe or unexpected backend evidence: %q", summary)
			}
			if closeErr := response.Body.Close(); closeErr != nil {
				t.Fatal("close captured backend error response")
			}
		})
	}

	// Ensure the allowlisted-code parser accepts valid bounded S3 XML without
	// depending on any test logger or formatted response text.
	if got, category := postAllowlistedBackendErrorCode([]byte(`<Error><Code>InvalidRequest</Code></Error>`)); got != "InvalidRequest" || category != "" {
		t.Fatalf("allowlisted XML error code=%q", got)
	}
}

func TestGH353PostTrustedRecorderRetainsRootVerification(t *testing.T) {
	root := x509.NewCertPool()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate fixture CA key")
	}
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "GH353 test CA"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("create fixture CA certificate")
	}
	if !root.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})) {
		t.Fatal("append fixture CA")
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate fixture server key")
	}
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caTemplate, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal("create fixture server certificate")
	}
	serverCertificate := tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	trustedTransport := http.DefaultTransport.(*http.Transport).Clone()
	trustedTransport.TLSClientConfig = &tls.Config{RootCAs: root, MinVersion: tls.VersionTLS12}
	defer trustedTransport.CloseIdleConnections()
	trustedRecorder := &postWriteRecorder{base: trustedTransport}
	request, _ := http.NewRequest(http.MethodPut, server.URL, nil)
	trustedResponse, err := trustedRecorder.RoundTrip(request)
	if err != nil {
		t.Fatalf("trusted CA request through recorder failed: %v", err)
	}
	if trustedResponse != nil && trustedResponse.Body != nil {
		if closeErr := trustedResponse.Body.Close(); closeErr != nil {
			t.Fatal("close trusted recorder response body")
		}
	}
	unknownTransport := http.DefaultTransport.(*http.Transport).Clone()
	unknownTransport.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	defer unknownTransport.CloseIdleConnections()
	unknownRecorder := &postWriteRecorder{base: unknownTransport}
	unknownResponse, unknownErr := unknownRecorder.RoundTrip(request)
	if unknownResponse != nil && unknownResponse.Body != nil {
		if closeErr := unknownResponse.Body.Close(); closeErr != nil {
			t.Fatal("close untrusted recorder response body")
		}
	}
	if unknownErr == nil {
		t.Fatal("untrusted server certificate succeeded through backend recorder")
	}
}

func TestGH353PostObjectCleanupUsesDefaultSDKEndpointResolver(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	var storageEvidence []struct {
		present    bool
		standard   bool
		standardIA bool
		valueCount int
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.EscapedPath())
		if r.Method == http.MethodPut {
			values := r.Header.Values("X-Amz-Storage-Class")
			storageEvidence = append(storageEvidence, struct {
				present    bool
				standard   bool
				standardIA bool
				valueCount int
			}{
				present:    len(values) > 0,
				standard:   len(values) == 1 && values[0] == "STANDARD",
				standardIA: len(values) == 1 && values[0] == "STANDARD_IA",
				valueCount: len(values),
			})
		}
		mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("ETag", `"fixture-etag"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodHead:
			w.Header().Set("Content-Length", "17")
			w.Header().Set("ETag", `"fixture-etag"`)
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	root := x509.NewCertPool()
	root.AddCert(server.Certificate())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: root, MinVersion: tls.VersionTLS12}
	defer transport.CloseIdleConnections()
	trustedClient := &http.Client{Transport: transport, Timeout: time.Minute}

	config, err := awsconfig.LoadDefaultConfig(t.Context(), awsconfig.WithRegion(testRegion), awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("fixture-access", "fixture-secret", "")))
	if err != nil {
		t.Fatal("load cleanup wire-fixture AWS config")
	}
	direct := awss3.NewFromConfig(config, func(options *awss3.Options) {
		options.BaseEndpoint = aws.String(server.URL)
		options.UsePathStyle = true
		options.HTTPClient = trustedClient
	})
	if direct.Options().EndpointResolverV2 == nil {
		t.Fatal("AWS SDK did not install its default endpoint resolver")
	}
	for _, tc := range []struct {
		key          string
		storageClass types.StorageClass
	}{
		{key: "default-class"},
		{key: "nondefault-class", storageClass: types.StorageClassStandardIa},
	} {
		_, putErr := direct.PutObject(t.Context(), &awss3.PutObjectInput{
			Bucket: aws.String("fixture-bucket"), Key: aws.String(tc.key), Body: strings.NewReader("wire-fixture"), StorageClass: tc.storageClass,
		})
		if putErr != nil {
			t.Fatalf("real AWS SDK PUT wire fixture failed: %v", putErr)
		}
	}

	err = cleanupPostObjectWithIdentity(t.Context(), "fixture-bucket", "owned-object", "", "", "", "",
		func(ctx context.Context, input *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) {
			return direct.HeadObject(ctx, input)
		},
		func(ctx context.Context, input *awss3.DeleteObjectInput) error {
			_, deleteErr := direct.DeleteObject(ctx, input)
			return deleteErr
		}, nil)
	if err != nil {
		t.Fatalf("real AWS SDK cleanup callbacks failed through trusted BaseEndpoint: %v", err)
	}
	mu.Lock()
	gotCalls := append([]string(nil), calls...)
	gotStorageEvidence := append([]struct {
		present    bool
		standard   bool
		standardIA bool
		valueCount int
	}(nil), storageEvidence...)
	mu.Unlock()
	wantCalls := []string{"PUT /fixture-bucket/default-class", "PUT /fixture-bucket/nondefault-class", "HEAD /fixture-bucket/owned-object", "DELETE /fixture-bucket/owned-object"}
	if !reflect.DeepEqual(gotCalls, wantCalls) {
		t.Fatalf("AWS SDK cleanup wire calls=%v want %v", gotCalls, wantCalls)
	}
	if len(gotStorageEvidence) != 2 || gotStorageEvidence[0].present || gotStorageEvidence[0].valueCount != 0 || gotStorageEvidence[1].valueCount != 1 || !gotStorageEvidence[1].present || gotStorageEvidence[1].standard || !gotStorageEvidence[1].standardIA {
		t.Fatal("AWS SDK storage-class wire oracle did not distinguish normalized STANDARD default from projected non-default class")
	}
}

func testPostObjectRejectPreservesExisting(t *testing.T, inst provider.Instance) {
	key := uniqueKey(t)
	t.Cleanup(func() { cleanupPostObject(t, inst, key) })
	original := bytes.Repeat([]byte("original-encrypted-existing-value-"), 1024)
	seedCredential := postCredential("", nil)
	seedGateway := postGateway(t, inst, seedCredential)
	seedRequest := makePostRequest(t, postFormURL(seedGateway, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{file: original})
	seedResponse, _ := postHTTP(t, seedGateway, seedCredential, seedRequest)
	if seedResponse.StatusCode != http.StatusNoContent {
		t.Fatal("could not seed existing encrypted PostObject")
	}
	backend := directPostBackend(t, inst)
	originalCiphertext, originalMetadata, err := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
	if err != nil {
		t.Fatal("could not capture existing backend object")
	}
	originalWire, err := io.ReadAll(originalCiphertext)
	originalCiphertext.Close()
	if err != nil {
		t.Fatal("could not read existing backend object")
	}
	originalHead, err := backend.HeadObject(t.Context(), inst.Bucket, key, nil)
	if err != nil {
		t.Fatal("could not capture existing object version metadata")
	}
	recorder := &postWriteRecorder{base: http.DefaultTransport}
	gw := postGateway(t, inst, seedCredential, harness.WithBackendTransport(recorder))
	assertUnchanged := func() {
		t.Helper()
		current, metadata, getErr := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
		if getErr != nil {
			t.Fatal("existing backend object disappeared after rejected POST")
		}
		currentWire, readErr := io.ReadAll(current)
		closeErr := current.Close()
		currentHead, headErr := backend.HeadObject(t.Context(), inst.Bucket, key, nil)
		unchanged := readErr == nil && closeErr == nil && headErr == nil && bytes.Equal(currentWire, originalWire) && equalPostMetadata(metadata, originalMetadata) && currentHead["ETag"] == originalHead["ETag"] && currentHead["x-amz-version-id"] == originalHead["x-amz-version-id"]
		clear(currentWire)
		if !unchanged {
			t.Fatal("rejected PostObject changed the existing backend object, metadata, or version")
		}
		verifyPostReadback(t, gw, inst.Bucket, key, original, "")
	}
	verifyPostReadback(t, gw, inst.Bucket, key, original, "")
	wrongSignature := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{file: []byte("replacement"), corruptSignature: true})
	resp, body := postHTTP(t, gw, seedCredential, wrongSignature)
	if resp.StatusCode != http.StatusForbidden || postErrorCode(t, body) != "SignatureDoesNotMatch" {
		t.Fatal("invalid PostObject signature did not return fixed signature error")
	}
	assertUnchanged()
	wrongPolicy := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{
		file: []byte("replacement"), conditionOverrides: map[string]string{"key": key + "-other"},
	})
	resp, body = postHTTP(t, gw, seedCredential, wrongPolicy)
	if resp.StatusCode != http.StatusForbidden || postErrorCode(t, body) != "AccessDenied" {
		t.Fatal("unsatisfied PostObject policy did not return fixed access-denied error")
	}
	assertUnchanged()
	badChecksum := md5.Sum([]byte("not-the-upload"))
	checksumFields := map[string]string{"Content-MD5": base64.StdEncoding.EncodeToString(badChecksum[:])}
	badDigest := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{fields: checksumFields, file: []byte("replacement")})
	resp, body = postHTTP(t, gw, seedCredential, badDigest)
	if resp.StatusCode != http.StatusBadRequest || postErrorCode(t, body) != "BadDigest" {
		t.Fatal("signed PostObject checksum mismatch did not return BadDigest")
	}
	assertUnchanged()
	minRange := [2]int64{20, 64}
	tooSmall := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{contentLengthRange: &minRange, file: []byte("small"), unknownLength: true})
	resp, body = postHTTP(t, gw, seedCredential, tooSmall)
	code, message := postSafeErrorDetails(body)
	if resp.StatusCode != http.StatusBadRequest || code != "EntityTooSmall" || message != "The uploaded object is smaller than the permitted size." {
		t.Fatalf("minimum-size response status=%d code=%s", resp.StatusCode, code)
	}
	assertUnchanged()
	maxRange := [2]int64{0, 4}
	tooLarge := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{contentLengthRange: &maxRange, file: []byte("five-"), unknownLength: true})
	resp, body = postHTTP(t, gw, seedCredential, tooLarge)
	code, message = postSafeErrorDetails(body)
	if resp.StatusCode != http.StatusRequestEntityTooLarge || code != "EntityTooLarge" || message != "The request exceeds the permitted payload size." {
		t.Fatalf("maximum-size response status=%d code=%s", resp.StatusCode, code)
	}
	assertUnchanged()
	expiredPolicy := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{file: []byte("replacement"), expiration: time.Now().UTC().Add(-time.Minute)})
	resp, body = postHTTP(t, gw, seedCredential, expiredPolicy)
	if resp.StatusCode != http.StatusForbidden || postErrorCode(t, body) != "AccessDenied" {
		t.Fatal("expired signed PostObject policy did not return fixed access-denied error")
	}
	assertUnchanged()
	truncated := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{file: []byte("replacement"), truncateBody: true})
	resp, body = postHTTP(t, gw, seedCredential, truncated)
	code, message = postSafeErrorDetails(body)
	if resp.StatusCode != http.StatusBadRequest || code != "IncompleteBody" || message != "The request body is incomplete." {
		t.Fatalf("truncated form response status=%d code=%s", resp.StatusCode, code)
	}
	assertUnchanged()
	unsupportedFields := map[string]string{"x-amz-storage-class": "EXPRESS_ONEZONE"}
	unsupported := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{fields: unsupportedFields, file: []byte("replacement")})
	resp, body = postHTTP(t, gw, seedCredential, unsupported)
	code, message = postSafeErrorDetails(body)
	if resp.StatusCode != http.StatusNotImplemented || code != "NotImplemented" || message != "The requested POST option is not supported." {
		t.Fatalf("unsupported option response status=%d code=%s", resp.StatusCode, code)
	}
	assertUnchanged()
	postFileField := map[string]string{"x-ignore-after-file": "framing-probe"}
	fileNotLast := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, seedCredential, postFormCase{afterFileFields: postFileField, file: []byte("replacement")})
	resp, body = postHTTP(t, gw, seedCredential, fileNotLast)
	code, message = postSafeErrorDetails(body)
	if resp.StatusCode != http.StatusBadRequest || code != "InvalidRequest" || message != "Invalid POST form." {
		t.Fatalf("non-final file part response status=%d code=%s", resp.StatusCode, code)
	}
	assertUnchanged()
	if recorder.writes.Load() != 0 {
		t.Fatalf("invalid PostObject requests caused %d backend mutation requests", recorder.writes.Load())
	}
	clear(originalWire)
}

func equalPostMetadata(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func testPostObjectSessionAndExpiry(t *testing.T, inst provider.Instance) {
	key := uniqueKey(t)
	t.Cleanup(func() { cleanupPostObject(t, inst, key) })
	want := bytes.Repeat([]byte("session-post-data-"), 2048)
	expires := time.Now().UTC().Add(15 * time.Minute).Truncate(time.Second)
	credential := postCredential(postSessionToken, &expires)
	recorder := &postWriteRecorder{base: http.DefaultTransport}
	gw := postGateway(t, inst, credential, harness.WithBackendTransport(recorder))
	req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{file: want})
	resp, _ := postHTTP(t, gw, credential, req)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal("configured session credential could not upload a signed POST")
	}
	if identity, ok := recorder.identity.Load().(string); !ok || identity == "" || strings.Contains(identity, postGatewayAccess) || strings.Contains(identity, postSessionToken) || recorder.tokenSeen.Load() {
		t.Fatal("gateway session identity or token was forwarded to the backend")
	}
	verifyPostReadback(t, gw, inst.Bucket, key, want, postSessionToken)
	missingToken := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{file: []byte("must-not-overwrite"), omitSessionToken: true})
	missingResp, missingBody := postHTTP(t, gw, credential, missingToken)
	if missingResp.StatusCode != http.StatusForbidden || postErrorCode(t, missingBody) != "InvalidToken" {
		t.Fatal("session POST without its token was not rejected")
	}
	wrongToken := "not-the-session-token"
	wrongTokenReq := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{file: []byte("must-not-overwrite"), tokenOverride: &wrongToken})
	wrongTokenResp, wrongTokenBody := postHTTP(t, gw, credential, wrongTokenReq)
	if wrongTokenResp.StatusCode != http.StatusForbidden || postErrorCode(t, wrongTokenBody) != "InvalidToken" {
		t.Fatal("session POST with a wrong token was not rejected")
	}
	uncoveredToken := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{file: []byte("must-not-overwrite"), omitConditions: map[string]bool{"x-amz-security-token": true}})
	uncoveredResp, uncoveredBody := postHTTP(t, gw, credential, uncoveredToken)
	if uncoveredResp.StatusCode != http.StatusForbidden || postErrorCode(t, uncoveredBody) != "AccessDenied" {
		t.Fatal("session POST whose policy omitted the token condition was not rejected")
	}
	for _, tc := range []struct {
		name, token string
	}{
		{name: "missing token"},
		{name: "wrong token", token: "not-the-session-token"},
	} {
		runPostCase(t, tc.name, func(t *testing.T) {
			read, _ := postGatewayGet(t, gw, inst.Bucket, key, tc.token, nil)
			if read.StatusCode != http.StatusForbidden {
				t.Fatalf("session GET with %s was not rejected", tc.name)
			}
		})
	}
	backend := directPostBackend(t, inst)
	before, beforeMetadata, err := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
	if err != nil {
		t.Fatal("could not capture session destination")
	}
	beforeBytes, err := io.ReadAll(before)
	before.Close()
	if err != nil {
		t.Fatal("could not read session destination")
	}
	expired := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	expiredCredential := postCredential(postSessionToken, &expired)
	expiredGateway := postGateway(t, inst, expiredCredential)
	expiredReq := makePostRequest(t, postFormURL(expiredGateway, inst.Bucket), inst.Bucket, key, expiredCredential, postFormCase{file: []byte("must-not-overwrite")})
	expiredResp, expiredBody := postHTTP(t, expiredGateway, expiredCredential, expiredReq)
	if expiredResp.StatusCode != http.StatusForbidden || postErrorCode(t, expiredBody) != "ExpiredToken" {
		t.Fatal("expired configured session credential was not rejected as ExpiredToken")
	}
	after, afterMetadata, err := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
	if err != nil {
		t.Fatal("session destination disappeared after expired attempt")
	}
	afterBytes, readErr := io.ReadAll(after)
	after.Close()
	if readErr != nil || !bytes.Equal(beforeBytes, afterBytes) || !equalPostMetadata(beforeMetadata, afterMetadata) {
		clear(beforeBytes)
		clear(afterBytes)
		t.Fatal("expired session attempt changed the backend destination")
	}
	clear(beforeBytes)
	clear(afterBytes)
}

func testPostObjectResponses(t *testing.T, inst provider.Instance) {
	credential := postCredential("", nil)
	gw := postGateway(t, inst, credential)
	for _, status := range []string{"200", "201", "204", "invalid"} {
		runPostCase(t, "status-"+status, func(t *testing.T) {
			key := uniqueKey(t)
			t.Cleanup(func() { cleanupPostObject(t, inst, key) })
			fields := map[string]string{"success_action_status": status}
			req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{fields: fields, file: []byte("response-body")})
			resp, body := postHTTP(t, gw, credential, req)
			want := http.StatusNoContent
			if status == "200" {
				want = http.StatusOK
			} else if status == "201" {
				want = http.StatusCreated
			}
			if resp.StatusCode != want {
				t.Fatalf("PostObject response status=%d want=%d", resp.StatusCode, want)
			}
			if want == http.StatusCreated {
				var response struct {
					XMLName  xml.Name `xml:"PostResponse"`
					XMLNS    string   `xml:"xmlns,attr"`
					Bucket   string   `xml:"Bucket"`
					Key      string   `xml:"Key"`
					ETag     string   `xml:"ETag"`
					Location string   `xml:"Location"`
				}
				wantLocation := postGatewayLocation(gw, inst.Bucket, key)
				if err := xml.Unmarshal(body, &response); err != nil || response.XMLNS != "http://s3.amazonaws.com/doc/2006-03-01/" || response.Bucket != inst.Bucket || response.Key != key || response.ETag != `"`+hex.EncodeToString(md5Sum([]byte("response-body")))+`"` || response.Location != wantLocation {
					t.Fatal("PostObject 201 XML contract mismatch")
				}
			} else if len(body) != 0 {
				t.Fatal("PostObject empty-status response unexpectedly had a body")
			}
		})
	}
	key := uniqueKey(t)
	t.Cleanup(func() { cleanupPostObject(t, inst, key) })
	redirect := "https://redirect.example/path?keep=yes#done"
	redirectFields := map[string]string{"success_action_redirect": redirect}
	redirectReq := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{fields: redirectFields, file: []byte("redirect")})
	client := gw.HTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	redirectResp, redirectBody := postHTTPWithClient(t, client, redirectReq)
	if redirectResp.StatusCode != http.StatusSeeOther || len(redirectBody) != 0 {
		t.Fatal("valid PostObject redirect did not return a non-followed 303")
	}
	location, err := url.Parse(redirectResp.Header.Get("Location"))
	wantRedirectETag := `"` + hex.EncodeToString(md5Sum([]byte("redirect"))) + `"`
	if err != nil || location.Host != "redirect.example" || location.Query().Get("keep") != "yes" || location.Query().Get("bucket") != inst.Bucket || location.Query().Get("key") != key || location.Query().Get("etag") != wantRedirectETag || redirectResp.Header.Get("ETag") != wantRedirectETag || location.Fragment != "done" {
		t.Fatal("PostObject redirect Location lost target or object selectors")
	}
	invalidKey := uniqueKey(t)
	t.Cleanup(func() { cleanupPostObject(t, inst, invalidKey) })
	invalidReq := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, invalidKey, credential, postFormCase{
		fields: map[string]string{"success_action_redirect": "javascript:alert(1)"}, file: []byte("invalid-redirect"),
	})
	invalidResp, invalidBody := postHTTP(t, gw, credential, invalidReq)
	if invalidResp.StatusCode != http.StatusNoContent || len(invalidBody) != 0 || invalidResp.Header.Get("Location") != "" {
		t.Fatal("invalid PostObject redirect did not fall back to default response")
	}
	verifyPostReadback(t, gw, inst.Bucket, invalidKey, []byte("invalid-redirect"), "")
}

func TestGH353PostObjectFormBuilderSessionAndFraming(t *testing.T) {
	timestamp := time.Date(2026, time.October, 21, 12, 0, 0, 0, time.UTC)
	request := makePostRequest(t, "http://127.0.0.1/bucket", "bucket", "key", postCredential("", nil), postFormCase{
		file: []byte("bounded form bytes"), date: timestamp, unknownLength: true,
	})
	if request.ContentLength != -1 || len(request.TransferEncoding) != 0 || request.Header.Get("Content-Type") == "" {
		t.Fatal("multipart form builder did not produce the requested unknown-length HTTP body")
	}
	expiresAt := timestamp.Add(time.Hour)
	credential := postCredential("session-fixture-token", &expiresAt)
	request = makePostRequest(t, "http://127.0.0.1/bucket", "bucket", "key", credential, postFormCase{file: []byte("session form"), date: timestamp, expiration: expiresAt})
	reader := multipart.NewReader(request.Body, strings.TrimPrefix(request.Header.Get("Content-Type"), "multipart/form-data; boundary="))
	values := make(map[string]string)
	var partOrder []string
	for {
		part, partErr := reader.NextPart()
		if partErr == io.EOF {
			break
		}
		if partErr != nil {
			t.Fatalf("read generated POST part: %v", partErr)
		}
		name := part.FormName()
		partOrder = append(partOrder, name)
		data, readErr := io.ReadAll(part)
		closeErr := part.Close()
		if readErr != nil || closeErr != nil {
			t.Fatal("read generated POST part body")
		}
		values[name] = string(data)
	}
	if len(partOrder) == 0 || partOrder[len(partOrder)-1] != "file" {
		t.Fatalf("generated multipart fields did not put file last: %v", partOrder)
	}
	policy, err := base64.StdEncoding.DecodeString(values["policy"])
	if err != nil {
		t.Fatal("decode generated POST policy")
	}
	var decoded struct {
		Conditions []json.RawMessage `json:"conditions"`
	}
	if err := json.Unmarshal(policy, &decoded); err != nil {
		t.Fatal("decode generated POST policy conditions")
	}
	coveredToken := false
	for _, condition := range decoded.Conditions {
		var values map[string]string
		if json.Unmarshal(condition, &values) == nil && values["x-amz-security-token"] == credential.SessionToken {
			coveredToken = true
		}
	}
	if !coveredToken || values["x-amz-security-token"] != credential.SessionToken {
		t.Fatal("generated session form policy did not cover the session token")
	}
	if values["x-amz-date"] != "20261021T120000Z" || values["x-amz-credential"] != "GH353GATEWAYACCESS/20261021/us-east-1/s3/aws4_request" {
		t.Fatalf("session form did not retain fixed timestamp/scope: date=%q scope=%q", values["x-amz-date"], values["x-amz-credential"])
	}
	const expectedSessionPolicy = "eyJleHBpcmF0aW9uIjoiMjAyNi0xMC0yMVQxMzowMDowMFoiLCJjb25kaXRpb25zIjpbeyJidWNrZXQiOiJidWNrZXQifSx7ImtleSI6ImtleSJ9LHsieC1hbXotYWxnb3JpdGhtIjoiQVdTNC1ITUFDLVNIQTI1NiJ9LHsieC1hbXotY3JlZGVudGlhbCI6IkdIMzUzR0FURVdBWUFDQ0VTUy8yMDI2MTAyMS91cy1lYXN0LTEvczMvYXdzNF9yZXF1ZXN0In0seyJ4LWFtei1kYXRlIjoiMjAyNjEwMjFUMTIwMDAwWiJ9LHsieC1hbXotc2VjdXJpdHktdG9rZW4iOiJzZXNzaW9uLWZpeHR1cmUtdG9rZW4ifV19"
	const expectedSignature = "1ac48adc981026e9bae30c5d15bb452c3f317be0baadda26d98c706c01eb64cb"
	if values["policy"] != expectedSessionPolicy || values["x-amz-signature"] != expectedSignature {
		t.Fatalf("generated session form changed fixed policy/signature vector: policy=%q signature=%q", values["policy"], values["x-amz-signature"])
	}
	mutatedPolicy := append([]byte(nil), policy...)
	mutatedPolicy[0] ^= 1
	mutatedEncoding := base64.StdEncoding.EncodeToString(mutatedPolicy)
	if postPolicySignature(credential.SecretKey, "20261021", testRegion, mutatedEncoding) == values["x-amz-signature"] {
		t.Fatal("altered original policy bytes retained the generated signature")
	}
}

func TestGH353PostObjectOverflowFixtureFramingAndMetadataPolicy(t *testing.T) {
	credential := postCredential("", nil)
	metadataValue := strings.Repeat("v", 7900)
	fixture := func(startsWith map[string]string) (*http.Request, []byte, int, int, int, string) {
		request := makePostRequest(t, "http://127.0.0.1/bucket", "bucket", "prefix/${filename}", credential, postFormCase{
			fields: map[string]string{
				"x-amz-meta-overflow": metadataValue,
				"Content-Type":        "application/octet-stream", "Content-Encoding": "identity",
				"Content-Disposition": "inline", "Cache-Control": "no-cache",
				"Content-Language": "en", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT",
				"x-amz-meta-owner": "browser-post", "x-amz-meta-purpose": "conformance",
			}, startsWithConditions: startsWith,
			file: []byte("small fixture payload"), fileName: "records.bin", unknownLength: true,
			date: time.Date(2026, time.October, 26, 12, 0, 0, 0, time.UTC),
		})
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal("read deterministic overflow multipart fixture")
		}
		boundary := strings.TrimPrefix(request.Header.Get("Content-Type"), "multipart/form-data; boundary=")
		reader := multipart.NewReader(bytes.NewReader(body), boundary)
		var scalarCount, scalarValueBytes, fileBytes int
		var encodedPolicy, signature string
		for {
			part, nextErr := reader.NextPart()
			if nextErr == io.EOF {
				break
			}
			if nextErr != nil {
				t.Fatal("parse deterministic overflow multipart fixture")
			}
			name := part.FormName()
			partBytes, readErr := io.ReadAll(part)
			closeErr := part.Close()
			if readErr != nil || closeErr != nil {
				t.Fatal("read deterministic overflow multipart part")
			}
			if name == "file" {
				fileBytes += len(partBytes)
				continue
			}
			scalarCount++
			scalarValueBytes += len(partBytes)
			switch name {
			case "policy":
				encodedPolicy = string(partBytes)
			case "x-amz-signature":
				signature = string(partBytes)
			}
		}
		return request, body, scalarCount, scalarValueBytes, fileBytes, encodedPolicy + "\x00" + signature
	}
	request, body, scalarCount, scalarValueBytes, fileBytes, authenticationFields := fixture(map[string]string{"key": "prefix/", "x-amz-meta-overflow": ""})
	encodedPolicy, signature, found := strings.Cut(authenticationFields, "\x00")
	if !found {
		t.Fatal("overflow fixture omitted policy authentication fields")
	}
	policyBytes, decodeErr := base64.StdEncoding.Strict().DecodeString(encodedPolicy)
	if decodeErr != nil {
		t.Fatal("decode deterministic overflow policy")
	}
	var policy struct {
		Conditions []json.RawMessage `json:"conditions"`
	}
	if json.Unmarshal(policyBytes, &policy) != nil {
		t.Fatal("parse deterministic overflow policy")
	}
	keyStartsWith, metadataStartsWith, metadataEquality := false, false, false
	for _, rawCondition := range policy.Conditions {
		var eq map[string]string
		if json.Unmarshal(rawCondition, &eq) == nil {
			if _, exists := eq["x-amz-meta-overflow"]; exists {
				metadataEquality = true
			}
			continue
		}
		var startsWith []string
		if json.Unmarshal(rawCondition, &startsWith) == nil && len(startsWith) == 3 && startsWith[0] == "starts-with" {
			if startsWith[1] == "$key" && startsWith[2] == "prefix/" {
				keyStartsWith = true
			}
			if startsWith[1] == "$x-amz-meta-overflow" && startsWith[2] == "" {
				metadataStartsWith = true
			}
		}
	}
	framingBytes := len(body) - fileBytes
	if !keyStartsWith || !metadataStartsWith || metadataEquality || len(metadataValue) != 7900 || scalarCount > 128 || scalarValueBytes > 20*1024 || framingBytes > 20*1024 || signature != postPolicySignature(credential.SecretKey, "20261026", testRegion, encodedPolicy) {
		t.Fatalf("overflow fixture framing/policy invalid: framing_bytes=%d encoded_policy_bytes=%d policy_bytes=%d scalar_count=%d scalar_value_bytes=%d metadata_bytes=%d", framingBytes, len(encodedPolicy), len(policyBytes), scalarCount, scalarValueBytes, len(metadataValue))
	}
	if len(encodedPolicy) <= 0 || fileBytes != len("small fixture payload") || request.ContentLength != -1 {
		t.Fatalf("overflow fixture measurements invalid: framing_bytes=%d encoded_policy_bytes=%d policy_bytes=%d scalar_count=%d scalar_value_bytes=%d metadata_bytes=%d", framingBytes, len(encodedPolicy), len(policyBytes), scalarCount, scalarValueBytes, len(metadataValue))
	}
	_, equalityBody, _, _, equalityFileBytes, equalityAuthFields := fixture(map[string]string{"key": "prefix/"})
	equalityEncoded, _, _ := strings.Cut(equalityAuthFields, "\x00")
	equalityFramingBytes := len(equalityBody) - equalityFileBytes
	if equalityFramingBytes <= 20*1024 || equalityEncoded == "" {
		t.Fatalf("equality-policy baseline did not independently exceed existing framing cap: framing_bytes=%d encoded_policy_bytes=%d", equalityFramingBytes, len(equalityEncoded))
	}
	t.Logf("overflow fixture measurements: framing_bytes=%d equality_baseline_framing_bytes=%d encoded_policy_bytes=%d equality_baseline_encoded_policy_bytes=%d policy_bytes=%d scalar_count=%d scalar_value_bytes=%d metadata_bytes=%d framing_limit_bytes=%d scalar_count_limit=%d", framingBytes, equalityFramingBytes, len(encodedPolicy), len(equalityEncoded), len(policyBytes), scalarCount, scalarValueBytes, len(metadataValue), 20*1024, 128)
}

func postHTTPWithClient(t *testing.T, client *http.Client, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal("PostObject response transport failed")
	}
	body, readErr := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("PostObject response body read failed")
	}
	return resp, body
}

func md5Sum(value []byte) []byte {
	sum := md5.Sum(value)
	return sum[:]
}

func testPostObjectTaggingACLVersion(t *testing.T, inst provider.Instance) {
	credential := postCredential("", nil)
	caps, known := providerCapabilitiesFor(inst)
	if !known {
		t.Skip("provider registration unavailable for optional PostObject capability checks")
	}
	backend := newS3CompatClient(t, inst)
	if provider.GH353PostInlineTagging(inst) == "unsupported" {
		requiredCase(t, "Tagging", func(t *testing.T) { testPostUnsupportedTaggingPreservesExisting(t, inst) })
	} else {
		t.Run("Tagging", func(t *testing.T) {
			if caps&provider.CapInlinePutTagging == 0 {
				t.Skip("provider does not advertise inline PutObject tagging")
			}
			key := uniqueKey(t)
			t.Cleanup(func() { cleanupPostObject(t, inst, key) })
			recorder := &postWriteRecorder{base: http.DefaultTransport}
			gw := postGateway(t, inst, credential, harness.WithBackendTransport(recorder))
			stageStart := gw.PostObjectFailureStageCount()
			backendStart := recorder.putEvidenceCount()
			fields := map[string]string{"tagging": `<Tagging><TagSet><Tag><Key>cafe</Key><Value>browser upload</Value></Tag></TagSet></Tagging>`}
			request := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{fields: fields, file: []byte("tagged-versioned-post")})
			response, body := postHTTP(t, gw, credential, request)
			if response.StatusCode != http.StatusNoContent {
				stages, stagesOK := postStageDelta(gw, stageStart)
				backendSummary, backendSnapshotOK := recorder.putEvidenceSummarySince(backendStart)
				t.Fatalf("inline tagging PostObject failed: status=%d code=%s backend={%s} backend_snapshot_valid=%t safe_failure_stages=%v stage_snapshot_valid=%t", response.StatusCode, postSafeErrorCode(body), backendSummary, backendSnapshotOK, stages, stagesOK)
			}
			got, tagErr := backend.GetObjectTagging(t.Context(), &awss3.GetObjectTaggingInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
			if tagErr != nil || got == nil || len(got.TagSet) != 1 || aws.ToString(got.TagSet[0].Key) != "cafe" || aws.ToString(got.TagSet[0].Value) != "browser upload" {
				status, code := postSafeSDKError(tagErr)
				backendSummary, ok := recorder.putEvidenceSummarySince(backendStart)
				t.Fatalf("inline PostObject tagging did not round-trip read_status=%d read_code=%s put={%s} snapshot_valid=%t", status, code, backendSummary, ok)
			}
		})
	}
	t.Run("PrivateACL", func(t *testing.T) {
		if caps&provider.CapObjectACL == 0 {
			t.Skip("provider does not advertise object ACL support")
		}
		key := uniqueKey(t)
		t.Cleanup(func() { cleanupPostObject(t, inst, key) })
		gw := postGateway(t, inst, credential)
		request := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{fields: map[string]string{"acl": "private"}, file: []byte("private-acl-post")})
		response, body := postHTTP(t, gw, credential, request)
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("private-ACL PostObject failed: status=%d code=%s", response.StatusCode, postSafeErrorCode(body))
		}
		acl, aclErr := backend.GetObjectAcl(t.Context(), &awss3.GetObjectAclInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
		if aclErr != nil || acl.Owner == nil || acl.Owner.ID == nil || len(acl.Grants) != 1 || acl.Grants[0].Grantee == nil || acl.Grants[0].Grantee.ID == nil || aws.ToString(acl.Grants[0].Grantee.ID) != aws.ToString(acl.Owner.ID) || acl.Grants[0].Permission != types.PermissionFullControl {
			t.Fatal("PostObject private ACL did not contain only owner FULL_CONTROL grant")
		}
	})
	t.Run("VersionedReads", func(t *testing.T) {
		if _, external := os.LookupEnv(externalSelectionEnv); external {
			t.Skip("focused external mode does not create versioned buckets")
		}
		if caps&provider.CapVersioning == 0 {
			t.Skip("provider does not advertise object versioning")
		}
		if !provider.ShouldCreateDisposableVersionedBucket(inst) {
			t.Skip("provider cleanup policy forbids creating a disposable versioning bucket")
		}
		bucket := createPostVersionedBucket(t, inst, backend)
		recorder := &postWriteRecorder{base: http.DefaultTransport}
		gw := postGateway(t, inst, credential, harness.WithBackendTransport(recorder))
		key := uniqueKey(t)
		versions := make([]string, 0, 2)
		wantOld, wantCurrent := []byte("old-version-plaintext"), []byte("current-version-plaintext")
		cleanupOwnedVersions := func() {
			if len(versions) == 0 {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for _, versionID := range versions {
				if _, deleteErr := backend.DeleteObject(ctx, &awss3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(versionID)}); deleteErr != nil {
					t.Errorf("delete owned PostObject version %q: %v", versionID, deleteErr)
				}
			}
		}
		t.Cleanup(cleanupOwnedVersions)
		for _, want := range [][]byte{wantOld, wantCurrent} {
			start := recorder.putEvidenceCount()
			stageStart := gw.PostObjectFailureStageCount()
			boundaries := gw.PostObjectBoundaries()
			request := makePostRequest(t, postFormURL(gw, bucket), bucket, key, credential, postFormCase{file: want})
			response, body := postHTTP(t, gw, credential, request)
			versionID := response.Header.Get("x-amz-version-id")
			if response.StatusCode != http.StatusNoContent || versionID == "" {
				summary, valid := recorder.putEvidenceSummarySince(start)
				stages, stagesOK := postStageDelta(gw, stageStart)
				after := gw.PostObjectBoundaries()
				t.Fatalf("versioned PostObject response status=%d version_present=%t code=%s backend={%s} snapshot_valid=%t stages=%v stages_valid=%t boundary_outer=%t boundary_authenticated=%t boundary_routed=%t", response.StatusCode, versionID != "", postSafeErrorCode(body), summary, valid, stages, stagesOK, after[0] > boundaries[0], after[1] > boundaries[1], after[2] > boundaries[2])
			}
			versions = append(versions, versionID)
		}
		if versions[0] == versions[1] {
			t.Fatal("successive PostObject writes returned the same version identity")
		}
		for index, want := range [][]byte{wantOld, wantCurrent} {
			versionURL := postObjectURL(gw, bucket, key) + "?versionId=" + url.QueryEscape(versions[index])
			getRequest := signedGatewayRequest(t, http.MethodGet, versionURL, nil, "", nil)
			getResponse, getErr := gw.HTTPClient().Do(getRequest)
			if getErr != nil {
				t.Fatal("signed versioned gateway GET transport failed")
			}
			got, readErr := io.ReadAll(getResponse.Body)
			closeErr := getResponse.Body.Close()
			if readErr != nil || closeErr != nil || getResponse.StatusCode != http.StatusOK || !bytes.Equal(got, want) || getResponse.Header.Get("x-amz-version-id") != versions[index] {
				t.Fatalf("signed gateway version %q did not return expected plaintext", versions[index])
			}
			headReq := signedGatewayRequest(t, http.MethodHead, versionURL, nil, "", nil)
			headResponse, headErr := gw.HTTPClient().Do(headReq)
			if headErr != nil {
				t.Fatal("signed versioned gateway HEAD transport failed")
			}
			headResponse.Body.Close()
			if headResponse.StatusCode != http.StatusOK || headResponse.ContentLength != int64(len(want)) || headResponse.Header.Get("x-amz-version-id") != versions[index] {
				t.Fatalf("signed gateway versioned HEAD status=%d length=%d", headResponse.StatusCode, headResponse.ContentLength)
			}
			rangeURL := versionURL
			rangeHeaders := http.Header{"Range": {"bytes=0-4"}}
			rangeRequest := signedGatewayRequest(t, http.MethodGet, rangeURL, nil, "", rangeHeaders)
			rangeResponse, rangeErr := gw.HTTPClient().Do(rangeRequest)
			if rangeErr != nil {
				t.Fatalf("signed range for version %q transport failed", versions[index])
			}
			rangeBody, rangeReadErr := io.ReadAll(rangeResponse.Body)
			rangeCloseErr := rangeResponse.Body.Close()
			if rangeReadErr != nil || rangeCloseErr != nil || rangeResponse.StatusCode != http.StatusPartialContent || !bytes.Equal(rangeBody, want[:5]) || rangeResponse.Header.Get("x-amz-version-id") != versions[index] {
				t.Fatalf("signed range for version %q did not preserve plaintext/version identity", versions[index])
			}
			backendHead, headErr := backend.HeadObject(t.Context(), &awss3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: aws.String(versions[index])})
			if headErr != nil || backendHead == nil || aws.ToString(backendHead.VersionId) != versions[index] {
				t.Fatalf("backend version identity mismatch for returned version %q", versions[index])
			}
		}
		latestURL := postObjectURL(gw, bucket, key)
		latest, latestBody := postGatewayGet(t, gw, bucket, key, "", nil)
		if latest.StatusCode != http.StatusOK || !bytes.Equal(latestBody, wantCurrent) {
			t.Fatal("latest version read did not return the second plaintext generation")
		}
		latestHeadRequest := signedGatewayRequest(t, http.MethodHead, latestURL, nil, "", nil)
		latestHead, latestHeadErr := gw.HTTPClient().Do(latestHeadRequest)
		if latestHeadErr != nil {
			t.Fatal("signed latest-version HEAD transport failed")
		}
		latestHead.Body.Close()
		if latestHead.StatusCode != http.StatusOK || latestHead.Header.Get("x-amz-version-id") != versions[1] {
			t.Fatalf("latest HEAD version=%q status=%d want version=%q", latestHead.Header.Get("x-amz-version-id"), latestHead.StatusCode, versions[1])
		}
		latestRangeHeaders := http.Header{"Range": {"bytes=0-4"}}
		latestRangeRequest := signedGatewayRequest(t, http.MethodGet, latestURL, nil, "", latestRangeHeaders)
		latestRange, latestRangeErr := gw.HTTPClient().Do(latestRangeRequest)
		if latestRangeErr != nil {
			t.Fatal("signed latest-version range transport failed")
		}
		latestRangeBody, latestRangeReadErr := io.ReadAll(latestRange.Body)
		latestRangeCloseErr := latestRange.Body.Close()
		if latestRangeReadErr != nil || latestRangeCloseErr != nil || latestRange.StatusCode != http.StatusPartialContent || !bytes.Equal(latestRangeBody, wantCurrent[:5]) {
			t.Fatal("latest version range did not return the current plaintext prefix")
		}
		cleanupOwnedVersions()
		versions = nil
		request := signedGatewayRequest(t, http.MethodGet, postObjectURL(gw, bucket, key), nil, "", nil)
		response, err := gw.HTTPClient().Do(request)
		if err != nil {
			t.Fatal("verify disposable version cleanup transport failed")
		}
		_, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusNotFound {
			t.Fatalf("owned version cleanup left a visible latest object: status=%d", response.StatusCode)
		}
	})
}

type postRejectionCache struct {
	cache.Cache
	deletes atomic.Int64
	sets    atomic.Int64
}

// The local Garage proof is mandatory even if a test filter omits suite rows.
func TestConformancePostUnsupportedTaggingProof(t *testing.T) {
	if externalOnlyMode() {
		t.Skip("local-only mandatory POST tagging proof; not external evidence")
	}
	providers := provider.GH353UnsupportedTaggingProofProviders()
	if len(providers) != 1 {
		t.Fatal("mandatory unsupported POST tagging fixture missing or ambiguous")
	}
	p := providers[0]
	requiredCase(t, p.Name(), func(t *testing.T) {
		inst := p.Start(context.Background(), t)
		if inst.ProviderName != p.Name() || inst.Endpoint == "" || inst.Bucket == "" || inst.AccessKey == "" || inst.SecretKey == "" || provider.GH353PostInlineTagging(inst) != "unsupported" {
			t.Fatal("mandatory unsupported tagging fixture incomplete")
		}
		testPostUnsupportedTaggingPreservesExisting(t, inst)
	})
}

func (c *postRejectionCache) Delete(ctx context.Context, bucket, key string) error {
	c.deletes.Add(1)
	return c.Cache.Delete(ctx, bucket, key)
}
func (c *postRejectionCache) Set(ctx context.Context, bucket, key string, data []byte, metadata map[string]string, ttl time.Duration) error {
	c.sets.Add(1)
	return c.Cache.Set(ctx, bucket, key, data, metadata, ttl)
}

func testPostUnsupportedTaggingPreservesExisting(t *testing.T, inst provider.Instance) {
	t.Helper()
	key := uniqueKey(t)
	t.Cleanup(func() { cleanupPostObject(t, inst, key) })
	credential := postCredential("", nil)
	recorder := &postWriteRecorder{base: http.DefaultTransport}
	var acquisitions atomic.Int64
	cacheSpy := &postRejectionCache{Cache: cache.NewMemoryCache(1<<20, 16, time.Minute)}
	gw := postGateway(t, inst, credential, harness.WithBackendTransport(recorder), harness.WithBackendAcquisitionObserver(func() { acquisitions.Add(1) }), harness.WithCacheOverride(cacheSpy), harness.WithConfigMutator(func(cfg *config.Config) {
		cfg.Cache.Enabled = true
		cfg.Cache.MaxSize = 1 << 20
		cfg.Cache.MaxItems = 16
		cfg.Cache.DefaultTTL = time.Minute
	}))
	want := []byte("owned tagging rejection sentinel")
	seed := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{file: want})
	resp, _ := postHTTP(t, gw, credential, seed)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatal("could not seed unsupported-tagging fixture")
	}
	verifyPostReadback(t, gw, inst.Bucket, key, want, "")
	backend := directPostBackend(t, inst)
	before, metadata, err := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
	if err != nil {
		t.Fatal("could not capture destination")
	}
	wire, err := io.ReadAll(before)
	before.Close()
	if err != nil {
		t.Fatal("could not read destination")
	}
	if err := cacheSpy.Cache.Set(t.Context(), inst.Bucket, key, []byte("cache sentinel"), map[string]string{"owner": "cache"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	writes := recorder.writes.Load()
	for _, tags := range []string{`<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`, `<Tagging><TagSet></TagSet></Tagging>`} {
		beforeAcquisitions, beforeDeletes, beforeSets := acquisitions.Load(), cacheSpy.deletes.Load(), cacheSpy.sets.Load()
		req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, key, credential, postFormCase{fields: map[string]string{"tagging": tags}, file: []byte("replacement")})
		response, body := postHTTP(t, gw, credential, req)
		entry, ok := cacheSpy.Cache.Get(t.Context(), inst.Bucket, key)
		if response.StatusCode != http.StatusNotImplemented || postSafeErrorCode(body) != "NotImplemented" || !bytes.Contains(body, []byte("The requested POST option is not supported.")) || recorder.writes.Load() != writes || acquisitions.Load() != beforeAcquisitions || cacheSpy.deletes.Load() != beforeDeletes || cacheSpy.sets.Load() != beforeSets || !ok || string(entry.Data) != "cache sentinel" || entry.Metadata["owner"] != "cache" {
			t.Fatal("unsupported tagging did not fail before backend mutation")
		}
	}
	cacheSpy.Cache.Delete(t.Context(), inst.Bucket, key)
	verifyPostReadback(t, gw, inst.Bucket, key, want, "")
	after, current, err := backend.GetObject(t.Context(), inst.Bucket, key, nil, nil)
	if err != nil {
		t.Fatal("destination missing after rejection")
	}
	afterWire, err := io.ReadAll(after)
	after.Close()
	if err != nil || !bytes.Equal(wire, afterWire) || !equalPostMetadata(metadata, current) {
		t.Fatal("unsupported tagging changed owned destination")
	}
}

func testPostObjectSSE(t *testing.T, inst provider.Instance) {
	if inst.ObjectSSE == nil {
		if provider.RequiresObjectSSEFixture(inst) || inst.MinIOObjectSSEAttempted || inst.ObjectSSEError != "" {
			t.Fatalf("mandatory MinIO ObjectSSE fixture is unavailable: %s", inst.ObjectSSEError)
		}
		t.Skip("provider has no verified ObjectSSE HTTPS fixture")
	}
	if provider.RequiresObjectSSEFixture(inst) || inst.MinIOObjectSSEAttempted || inst.ObjectSSEError != "" {
		if err := provider.ValidateMinIOObjectSSEFixture(inst); err != nil {
			t.Fatalf("mandatory MinIO ObjectSSE fixture validation failed: %v", err)
		}
	} else if inst.ObjectSSE.Backend.Endpoint == "" || inst.ObjectSSE.Backend.CAFile == "" || inst.ObjectSSE.Backend.Bucket == "" || inst.ObjectSSE.Backend.AccessKey == "" || inst.ObjectSSE.Backend.SecretKey == "" || inst.ObjectSSE.KMSKeyID == "" {
		t.Fatalf("ObjectSSE fixture is missing trusted backend configuration")
	}
	fixture := inst.ObjectSSE
	tlsInst := inst
	tlsInst.Endpoint = fixture.Backend.Endpoint
	tlsInst.Bucket = fixture.Backend.Bucket
	tlsInst.AccessKey = fixture.Backend.AccessKey
	tlsInst.SecretKey = fixture.Backend.SecretKey
	tlsInst.BackendTLS = &fixture.Backend
	credential := postCredential("", nil)
	trustedBackendClient := postTrustedHTTPClient(t, fixture.Backend.CAFile)
	backendRecorder := &postWriteRecorder{base: trustedBackendClient.Transport}
	gw := postGateway(t, tlsInst, credential, harness.WithTLS(true), harness.WithBackendTransport(backendRecorder), harness.WithConfigMutator(func(cfg *config.Config) {
		cfg.Backend.Endpoint = fixture.Backend.Endpoint
		cfg.Backend.UseSSL = true
		cfg.Backend.TLS.CAFile = fixture.Backend.CAFile
		cfg.Backend.TLS.InsecureSkipVerify = false
		cfg.Server.TrustedProxies = []string{"127.0.0.0/8", "::1/128"}
		cfg.Cache.Enabled = true
		cfg.Cache.MaxSize = 8 << 20
		cfg.Cache.MaxItems = 64
		cfg.Cache.DefaultTTL = 5 * time.Minute
	}))
	client, err := awsconfig.LoadDefaultConfig(t.Context(), awsconfig.WithRegion(tlsInst.Region), awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(tlsInst.AccessKey, tlsInst.SecretKey, "")))
	if err != nil {
		t.Fatal("load ObjectSSE direct SDK client")
	}
	direct := awss3.NewFromConfig(client, func(options *awss3.Options) {
		options.BaseEndpoint = aws.String(fixture.Backend.Endpoint)
		options.UsePathStyle = true
		options.HTTPClient = postTrustedHTTPClient(t, fixture.Backend.CAFile)
	})
	for _, mode := range []string{"AES256", "aws:kms", "SSE-C"} {
		t.Run(mode, func(t *testing.T) {
			stageStart := gw.PostObjectFailureStageCount()
			backendRecorder.resetPutEvidence()
			backendStart := backendRecorder.putEvidenceCount()
			key := uniqueKey(t)
			var createdVersion string
			var createdObject bool
			var customerKeyBase64, customerMD5 string
			var customerHeaders http.Header
			var customerKey []byte
			var sensitiveFields map[string]string
			releaseCustomerKey := func() {
				customerKeyBase64, customerMD5 = "", ""
				for header := range customerHeaders {
					customerHeaders[header] = nil
				}
				if sensitiveFields != nil {
					for _, name := range []string{"x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-MD5"} {
						sensitiveFields[name] = ""
					}
				}
				clear(customerKey)
			}
			t.Cleanup(func() {
				defer releaseCustomerKey()
				cleanup, available := providerCleanupPolicyFor(inst)
				if available && cleanup != provider.CleanupPolicySkipDelete {
					if !createdObject {
						return
					}
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					algorithm := ""
					if mode == "SSE-C" {
						algorithm = "AES256"
					}
					cleanupErr := cleanupPostObjectWithIdentity(ctx, tlsInst.Bucket, key, createdVersion, algorithm, customerKeyBase64, customerMD5,
						func(ctx context.Context, input *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) {
							return direct.HeadObject(ctx, input)
						},
						func(ctx context.Context, input *awss3.DeleteObjectInput) error {
							_, err := direct.DeleteObject(ctx, input)
							return err
						}, nil)
					if cleanupErr != nil {
						t.Errorf("cleanup of owned ObjectSSE PostObject object failed: %s", cleanupErr)
					}
				}
			})
			plain := bytes.Repeat([]byte("gateway-and-backend-SSE-record-"), 512)
			fields := map[string]string{}
			sensitiveFields = fields
			switch mode {
			case "AES256":
				fields["x-amz-server-side-encryption"] = "AES256"
			case "aws:kms":
				fields["x-amz-server-side-encryption"] = "aws:kms"
				fields["x-amz-server-side-encryption-aws-kms-key-id"] = fixture.KMSKeyID
			case "SSE-C":
				customerKey = make([]byte, 32)
				if _, err := rand.Read(customerKey); err != nil {
					t.Fatal("generate SSE-C conformance key")
				}
				keyEncoding := make([]byte, base64.StdEncoding.EncodedLen(len(customerKey)))
				base64.StdEncoding.Encode(keyEncoding, customerKey)
				customerKeyBase64 = string(keyEncoding)
				defer clear(keyEncoding)
				checksum := md5.Sum(customerKey)
				md5Encoding := make([]byte, base64.StdEncoding.EncodedLen(len(checksum)))
				base64.StdEncoding.Encode(md5Encoding, checksum[:])
				customerMD5 = string(md5Encoding)
				defer clear(md5Encoding)
				clear(checksum[:])
				fields["x-amz-server-side-encryption-customer-algorithm"] = "AES256"
				fields["x-amz-server-side-encryption-customer-key"] = customerKeyBase64
				fields["x-amz-server-side-encryption-customer-key-MD5"] = customerMD5
				customerHeaders = make(http.Header)
				customerHeaders.Set("X-Amz-Server-Side-Encryption-Customer-Algorithm", "AES256")
				customerHeaders.Set("X-Amz-Server-Side-Encryption-Customer-Key", customerKeyBase64)
				customerHeaders.Set("X-Amz-Server-Side-Encryption-Customer-Key-MD5", customerMD5)
			}
			storageClass := provider.ObjectSSEStorageClass(inst, fixture)
			if storageClass != "" {
				fields["x-amz-storage-class"] = storageClass
			}
			request := makePostRequest(t, postFormURL(gw, tlsInst.Bucket), tlsInst.Bucket, key, credential, postFormCase{fields: fields, file: plain})
			response, body := postHTTP(t, gw, credential, request)
			if response.StatusCode != http.StatusNoContent {
				stages, stagesOK := postStageDelta(gw, stageStart)
				backendSummary, backendSnapshotOK := backendRecorder.putEvidenceSummarySince(backendStart)
				t.Fatalf("verified ObjectSSE %s POST failed: status=%d code=%s backend={%s} backend_snapshot_valid=%t safe_failure_stages=%v stage_snapshot_valid=%t", mode, response.StatusCode, postSafeErrorCode(body), backendSummary, backendSnapshotOK, stages, stagesOK)
			}
			createdObject = true
			createdVersion = response.Header.Get("x-amz-version-id")
			postETag := response.Header.Get("ETag")
			plainETag := `"` + hex.EncodeToString(md5Sum(plain)) + `"`
			if len(body) != 0 || response.Header.Get("Location") != "" || postETag == "" || mode != "SSE-C" && postETag != plainETag || mode == "SSE-C" && postETag == plainETag {
				t.Fatal("ObjectSSE 204 POST response violated empty-body, no-Location, or mode-specific ETag contract")
			}
			if storageClass != "" {
				present, matches := postStorageClassHeaderMatches(response.Header, storageClass, true)
				if !matches {
					t.Fatalf("ObjectSSE POST storage-class response header violated optional projection contract (present=%t)", present)
				}
			}
			measurements, measurementsOK := backendRecorder.putHeaderMeasurementsSince(backendStart)
			if !measurementsOK || len(measurements) != 1 || storageClass != "" && !postStorageClassMeasurementMatches(measurements[0], storageClass, true) {
				t.Fatal("ObjectSSE backend PUT storage-class projection did not match provider policy")
			}
			identity, _ := backendRecorder.identity.Load().(string)
			if !strings.Contains(identity, "Credential="+tlsInst.AccessKey+"/") || strings.Contains(identity, postGatewayAccess) || backendRecorder.tokenSeen.Load() {
				t.Fatal("ObjectSSE backend request did not use fixture credentials independently")
			}
			readHeaders := make(http.Header)
			if mode == "SSE-C" {
				readHeaders = customerHeaders.Clone()
			}
			getResp, got := postGatewayGet(t, gw, tlsInst.Bucket, key, "", readHeaders)
			if getResp.StatusCode != http.StatusOK || !bytes.Equal(got, plain) || getResp.Header.Get("x-amz-server-side-encryption-customer-key") != "" {
				t.Fatalf("verified ObjectSSE %s gateway GET did not return plaintext securely", mode)
			}
			assertPostSSEResponseHeaders(t, mode, getResp.Header, customerMD5, true)
			if mode == "SSE-C" && getResp.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("SSE-C plaintext read was not explicitly marked no-store")
			}
			headResp := postGatewayHead(t, gw, tlsInst.Bucket, key, "", readHeaders)
			if headResp.StatusCode != http.StatusOK || headResp.ContentLength != int64(len(plain)) {
				t.Fatalf("verified ObjectSSE %s gateway HEAD failed", mode)
			}
			assertPostSSEResponseHeaders(t, mode, headResp.Header, customerMD5, false)
			// Range must be part of the canonical signature.
			rangeHeaders := mergePostHeaders(readHeaders, http.Header{"Range": []string{"bytes=0-31"}})
			rangeReq := signedGatewayRequest(t, http.MethodGet, postObjectURL(gw, tlsInst.Bucket, key), nil, "", rangeHeaders)
			rangeResp, err := gw.HTTPClient().Do(rangeReq)
			if err != nil {
				t.Fatal("verified ObjectSSE range read transport failed")
			}
			rangeBody, rangeErr := io.ReadAll(rangeResp.Body)
			rangeResp.Body.Close()
			if rangeErr != nil || rangeResp.StatusCode != http.StatusPartialContent || !bytes.Equal(rangeBody, plain[:32]) {
				t.Fatalf("verified ObjectSSE %s ranged GET did not return plaintext range", mode)
			}
			assertPostSSEResponseHeaders(t, mode, rangeResp.Header, customerMD5, true)
			backendHeadInput := &awss3.HeadObjectInput{Bucket: aws.String(tlsInst.Bucket), Key: aws.String(key)}
			if mode == "SSE-C" {
				backendHeadInput.SSECustomerAlgorithm = aws.String("AES256")
				backendHeadInput.SSECustomerKey = aws.String(customerKeyBase64)
				backendHeadInput.SSECustomerKeyMD5 = aws.String(customerMD5)
			}
			backendHead, err := direct.HeadObject(t.Context(), backendHeadInput)
			if err != nil {
				t.Fatalf("verified ObjectSSE %s backend HEAD metadata mismatch", mode)
			}
			if (mode == "AES256" && string(backendHead.ServerSideEncryption) != "AES256") ||
				(mode == "aws:kms" && (string(backendHead.ServerSideEncryption) != "aws:kms" || !provider.ObjectSSEKMSIdentityMatches(inst, fixture.KMSKeyID, aws.ToString(backendHead.SSEKMSKeyId)))) ||
				(mode == "SSE-C" && (aws.ToString(backendHead.SSECustomerAlgorithm) != "AES256" || aws.ToString(backendHead.SSECustomerKeyMD5) != customerMD5)) {
				t.Fatalf("verified ObjectSSE %s backend SSE headers did not match the selected mode", mode)
			}
			if storageClass != "" && !postStorageClassValueMatches(string(backendHead.StorageClass), storageClass, true) {
				t.Fatal("provider-owned disposable ObjectSSE fixture did not store the object in its expected class")
			}
			backendGetInput := &awss3.GetObjectInput{Bucket: aws.String(tlsInst.Bucket), Key: aws.String(key)}
			if mode == "SSE-C" {
				backendGetInput.SSECustomerAlgorithm = aws.String("AES256")
				backendGetInput.SSECustomerKey = aws.String(customerKeyBase64)
				backendGetInput.SSECustomerKeyMD5 = aws.String(customerMD5)
			}
			backendGet, err := direct.GetObject(t.Context(), backendGetInput)
			if err != nil {
				t.Fatalf("verified ObjectSSE %s direct ciphertext GET failed", mode)
			}
			ciphertext, readErr := io.ReadAll(backendGet.Body)
			closeErr := backendGet.Body.Close()
			if readErr != nil || closeErr != nil || bytes.Equal(ciphertext, plain) || int64(len(ciphertext)) != aws.ToInt64(backendHead.ContentLength) {
				clear(ciphertext)
				t.Fatalf("verified ObjectSSE %s direct backend bytes were not encrypted gateway payload", mode)
			}
			clear(ciphertext)
			if mode == "SSE-C" {
				assertKeyedRead := func(phase string) {
					getResponse, getBody := postGatewayGet(t, gw, tlsInst.Bucket, key, "", readHeaders)
					if getResponse.StatusCode != http.StatusOK || !bytes.Equal(getBody, plain) {
						t.Fatalf("valid SSE-C key failed GET %s denied-read probe", phase)
					}
					headResponse := postGatewayHead(t, gw, tlsInst.Bucket, key, "", readHeaders)
					if headResponse.StatusCode != http.StatusOK || headResponse.ContentLength != int64(len(plain)) {
						t.Fatalf("valid SSE-C key failed HEAD %s denied-read probe", phase)
					}
				}
				for _, probe := range []struct {
					name    string
					headers http.Header
				}{
					{name: "missing key"},
					{name: "wrong key", headers: wrongSSECustomerHeaders(t)},
				} {
					assertKeyedRead("before")
					for _, method := range []string{http.MethodGet, http.MethodHead} {
						backendEvidenceStart := backendRecorder.readEvidenceCount()
						denied, deniedBody := postSSEDeniedRead(t, gw, tlsInst.Bucket, key, probe.headers, method, "", "")
						if !postSSECustomerKeyDenied(denied, deniedBody, method) || bytes.Contains(deniedBody, plain) || postSSEDeniedSuccessMetadata(denied.Header) {
							status, class := postSSEDenialDiagnostic(denied, deniedBody, method)
							t.Fatalf("%s %s denial rejected: status=%d diagnostic=%s backend=%s", probe.name, method, status, class, backendRecorder.readEvidenceSummarySince(backendEvidenceStart))
						}
					}
					backendEvidenceStart := backendRecorder.readEvidenceCount()
					denied, deniedBody := postSSEDeniedRead(t, gw, tlsInst.Bucket, key, probe.headers, http.MethodGet, "", "bytes=0-31")
					if !postSSECustomerKeyDenied(denied, deniedBody, http.MethodGet) || bytes.Contains(deniedBody, plain[:32]) || postSSEDeniedSuccessMetadata(denied.Header) {
						status, class := postSSEDenialDiagnostic(denied, deniedBody, http.MethodGet)
						t.Fatalf("%s ranged GET denial rejected: status=%d diagnostic=%s backend=%s", probe.name, status, class, backendRecorder.readEvidenceSummarySince(backendEvidenceStart))
					}
					assertKeyedRead("after")
				}
			}
		})
	}
}

func postTrustedHTTPClient(t *testing.T, caFile string) *http.Client {
	t.Helper()
	data, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal("read trusted ObjectSSE CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		t.Fatal("invalid trusted ObjectSSE CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: time.Minute}
}

func createPostVersionedBucket(t *testing.T, inst provider.Instance, backend *awss3.Client) string {
	t.Helper()
	bucket := "gh353-versioned-" + strings.ReplaceAll(uniqueSuffix(t), "_", "-")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	createInput := &awss3.CreateBucketInput{Bucket: aws.String(bucket)}
	if inst.Region != "" && inst.Region != "us-east-1" {
		createInput.CreateBucketConfiguration = &types.CreateBucketConfiguration{LocationConstraint: types.BucketLocationConstraint(inst.Region)}
	}
	if _, err := backend.CreateBucket(ctx, createInput); err != nil {
		t.Skipf("provider cannot create a disposable versioning bucket: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		versions, listErr := backend.ListObjectVersions(cleanupCtx, &awss3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		if listErr != nil {
			t.Errorf("list disposable PostObject versions: %v", listErr)
			return
		}
		if versions.IsTruncated != nil && *versions.IsTruncated {
			t.Errorf("disposable PostObject version bucket needs pagination; refusing incomplete cleanup")
			return
		}
		for _, version := range versions.Versions {
			if _, err := backend.DeleteObject(cleanupCtx, &awss3.DeleteObjectInput{Bucket: aws.String(bucket), Key: version.Key, VersionId: version.VersionId}); err != nil {
				t.Errorf("delete disposable PostObject version: %v", err)
			}
		}
		for _, marker := range versions.DeleteMarkers {
			if _, err := backend.DeleteObject(cleanupCtx, &awss3.DeleteObjectInput{Bucket: aws.String(bucket), Key: marker.Key, VersionId: marker.VersionId}); err != nil {
				t.Errorf("delete disposable PostObject delete marker: %v", err)
			}
		}
		if _, err := backend.DeleteBucket(cleanupCtx, &awss3.DeleteBucketInput{Bucket: aws.String(bucket)}); err != nil {
			t.Errorf("delete disposable PostObject bucket: %v", err)
		}
	})
	if _, err := backend.PutBucketVersioning(ctx, &awss3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); err != nil {
		t.Skipf("provider cannot enable versioning on disposable bucket: %v", err)
	}
	versioning, err := backend.GetBucketVersioning(ctx, &awss3.GetBucketVersioningInput{Bucket: aws.String(bucket)})
	if err != nil || versioning == nil || versioning.Status != types.BucketVersioningStatusEnabled {
		var status types.BucketVersioningStatus
		if versioning != nil {
			status = versioning.Status
		}
		t.Skipf("disposable bucket versioning not enabled: status=%v error=%v", status, err)
	}
	return bucket
}

func mergePostHeaders(a, b http.Header) http.Header {
	out := a.Clone()
	for key, values := range b {
		out[key] = append([]string(nil), values...)
	}
	return out
}

func wrongSSECustomerHeaders(t *testing.T) http.Header {
	t.Helper()
	wrong := make([]byte, 32)
	if _, err := rand.Read(wrong); err != nil {
		t.Fatal("generate wrong SSE-C probe key")
	}
	defer clear(wrong)
	checksum := md5.Sum(wrong)
	defer clear(checksum[:])
	keyB64 := base64.StdEncoding.EncodeToString(wrong)
	md5B64 := base64.StdEncoding.EncodeToString(checksum[:])
	return http.Header{
		"X-Amz-Server-Side-Encryption-Customer-Algorithm": {"AES256"},
		"X-Amz-Server-Side-Encryption-Customer-Key":       {keyB64},
		"X-Amz-Server-Side-Encryption-Customer-Key-Md5":   {md5B64},
	}
}

func postSSEDeniedRead(t *testing.T, gw *harness.Gateway, bucket, key string, headers http.Header, method, versionID, byteRange string) (*http.Response, []byte) {
	t.Helper()
	rawURL := postObjectURL(gw, bucket, key)
	if versionID != "" {
		rawURL += "?versionId=" + url.QueryEscape(versionID)
	}
	requestHeaders := headers.Clone()
	if requestHeaders == nil {
		requestHeaders = make(http.Header)
	}
	if byteRange != "" {
		requestHeaders.Set("Range", byteRange)
	}
	request := signedGatewayRequest(t, method, rawURL, nil, "", requestHeaders)
	response, err := gw.HTTPClient().Do(request)
	if err != nil {
		t.Fatalf("SSE-C denied %s transport failed", method)
	}
	body, readErr := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatalf("SSE-C denied %s response read/close failed", method)
	}
	return response, body
}

func postSSECustomerKeyDenied(response *http.Response, body []byte, method string) bool {
	if response == nil {
		return false
	}
	if method == http.MethodHead {
		return (response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusForbidden) && len(body) == 0
	}
	if method != http.MethodGet {
		return false
	}
	var responseError struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
	}
	if xml.Unmarshal(body, &responseError) != nil || responseError.XMLName.Local != "Error" {
		return false
	}
	if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusForbidden {
		return false
	}
	return response.StatusCode == http.StatusBadRequest && responseError.Code == "InvalidArgument" || response.StatusCode == http.StatusForbidden && responseError.Code == "AccessDenied"
}

func postSSEDeniedSuccessMetadata(headers http.Header) bool {
	if headers.Get("ETag") != "" || headers.Get("Last-Modified") != "" || headers.Get("Content-Encoding") != "" || headers.Get("Content-Disposition") != "" || headers.Get("Cache-Control") != "" || headers.Get("Content-Language") != "" || headers.Get("Expires") != "" {
		return true
	}
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "x-amz-meta-") {
			return true
		}
	}
	return false
}

func postSSEDenialDiagnostic(response *http.Response, body []byte, method string) (int, string) {
	if response == nil {
		return 0, "no_response"
	}
	if method == http.MethodHead {
		if len(body) == 0 {
			return response.StatusCode, "empty_body"
		}
		return response.StatusCode, "unexpected_body"
	}
	if len(body) == 0 {
		return response.StatusCode, "empty_error_body"
	}
	var responseError struct {
		Code string `xml:"Code"`
	}
	if err := xml.Unmarshal(body, &responseError); err != nil {
		return response.StatusCode, "malformed_error_xml"
	}
	switch responseError.Code {
	case "AccessDenied", "InvalidArgument":
		return response.StatusCode, responseError.Code
	default:
		return response.StatusCode, "unavailable_error_code"
	}
}

func TestGH353PostSSECustomerKeyDeniedRealHTTPWire(t *testing.T) {
	t.Run("HEAD accepts only 400 or 403 with wire-empty body", func(t *testing.T) {
		for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError, http.StatusOK} {
			t.Run(fmt.Sprint(status), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodHead {
						t.Errorf("wire request method=%s, want HEAD", r.Method)
					}
					w.Header().Set("Content-Type", "application/xml")
					if status == http.StatusOK {
						w.Header().Set("ETag", `"plaintext-success"`)
					}
					w.WriteHeader(status)
					_, _ = io.WriteString(w, `<Error><Code>InvalidArgument</Code></Error>`)
				}))
				defer server.Close()
				request, err := http.NewRequest(http.MethodHead, server.URL, nil)
				if err != nil {
					t.Fatal("construct real HTTP HEAD")
				}
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal("real HTTP HEAD transport")
				}
				body, readErr := io.ReadAll(response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal("read/close real HTTP HEAD response")
				}
				accepted := status == http.StatusBadRequest || status == http.StatusForbidden
				if got := postSSECustomerKeyDenied(response, body, http.MethodHead); got != accepted {
					status, class := postSSEDenialDiagnostic(response, body, http.MethodHead)
					t.Fatalf("HEAD predicate=%v want %v: status=%d diagnostic=%s", got, accepted, status, class)
				}
				if len(body) != 0 {
					t.Fatalf("HTTP HEAD unexpectedly exposed body bytes: %d", len(body))
				}
				if accepted && postSSEDeniedSuccessMetadata(response.Header) {
					t.Fatal("denied HEAD retained success/plaintext metadata")
				}
				_, diagnostic := postSSEDenialDiagnostic(response, body, http.MethodHead)
				if strings.Contains(diagnostic, "Code") || strings.Contains(diagnostic, "XML") {
					t.Fatalf("HEAD diagnostic attempted to parse absent XML: %q", diagnostic)
				}
			})
		}
	})
	t.Run("GET requires exact translated key-error XML", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			status int
			body   string
			accept bool
		}{
			{name: "400 InvalidArgument", status: http.StatusBadRequest, body: `<Error><Code>InvalidArgument</Code></Error>`, accept: true},
			{name: "403 AccessDenied", status: http.StatusForbidden, body: `<Error><Code>AccessDenied</Code></Error>`, accept: true},
			{name: "empty", status: http.StatusBadRequest},
			{name: "malformed", status: http.StatusBadRequest, body: `<Error><Code>InvalidArgument`},
			{name: "non-key 400", status: http.StatusBadRequest, body: `<Error><Code>InvalidRequest</Code></Error>`},
			{name: "404", status: http.StatusNotFound, body: `<Error><Code>NoSuchKey</Code></Error>`},
			{name: "500", status: http.StatusInternalServerError, body: `<Error><Code>InternalError</Code></Error>`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Errorf("wire request method=%s, want GET", r.Method)
					}
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
				}))
				defer server.Close()
				request, err := http.NewRequest(http.MethodGet, server.URL, nil)
				if err != nil {
					t.Fatal("construct real HTTP GET")
				}
				response, err := server.Client().Do(request)
				if err != nil {
					t.Fatal("real HTTP GET transport")
				}
				body, readErr := io.ReadAll(response.Body)
				closeErr := response.Body.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal("read/close real HTTP GET response")
				}
				if got := postSSECustomerKeyDenied(response, body, http.MethodGet); got != tc.accept {
					status, class := postSSEDenialDiagnostic(response, body, http.MethodGet)
					t.Fatalf("GET predicate=%v want %v: status=%d diagnostic=%s", got, tc.accept, status, class)
				}
			})
		}
	})
}

type postObjectHeadFunc func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error)
type postObjectDeleteFunc func(context.Context, *awss3.DeleteObjectInput) error

// cleanupPostObject identifies the exact owned object/version before deletion.
// It never exposes provider errors and always releases the request-owned key
// after any required keyed HEAD and the single delete attempt have completed.
func cleanupPostObjectWithIdentity(ctx context.Context, bucket, key, versionID, customerAlgorithm, customerKey, customerMD5 string, head postObjectHeadFunc, delete postObjectDeleteFunc, release func()) error {
	if release != nil {
		defer release()
	}
	if ctx == nil || bucket == "" || key == "" || head == nil || delete == nil {
		return errors.New("invalid owned-object cleanup configuration")
	}
	deleteInput := &awss3.DeleteObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
	if versionID != "" {
		deleteInput.VersionId = aws.String(versionID)
	} else {
		headInput := &awss3.HeadObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)}
		if customerAlgorithm != "" {
			if customerAlgorithm != "AES256" || customerKey == "" || customerMD5 == "" {
				return errors.New("owned SSE-C cleanup identity is incomplete")
			}
			headInput.SSECustomerAlgorithm = aws.String(customerAlgorithm)
			headInput.SSECustomerKey = aws.String(customerKey)
			headInput.SSECustomerKeyMD5 = aws.String(customerMD5)
		}
		identified, err := head(ctx, headInput)
		if err != nil || identified == nil {
			return errors.New("could not identify owned object for cleanup")
		}
		if identified.VersionId != nil && *identified.VersionId != "" {
			deleteInput.VersionId = identified.VersionId
		}
	}
	if err := delete(ctx, deleteInput); err != nil {
		return errors.New("could not delete owned object")
	}
	return nil
}

func TestGH353PostObjectCleanupSSECustomerKeyLifetime(t *testing.T) {
	t.Run("nonversioned uses keyed HEAD then one delete then releases key", func(t *testing.T) {
		keyBytes := bytes.Repeat([]byte{0x5a}, 32)
		keyB64 := base64.StdEncoding.EncodeToString(keyBytes)
		checksum := md5.Sum(keyBytes)
		md5B64 := base64.StdEncoding.EncodeToString(checksum[:])
		clear(keyBytes)
		clear(checksum[:])
		heads, deletes := 0, 0
		cleanupErr := cleanupPostObjectWithIdentity(context.Background(), "bucket", "owned-key", "", "AES256", keyB64, md5B64,
			func(_ context.Context, input *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) {
				heads++
				if input.SSECustomerAlgorithm == nil || *input.SSECustomerAlgorithm != "AES256" || aws.ToString(input.SSECustomerKey) != keyB64 || aws.ToString(input.SSECustomerKeyMD5) != md5B64 {
					t.Fatal("nonversioned cleanup HEAD did not use the correct SSE-C triplet")
				}
				return &awss3.HeadObjectOutput{}, nil
			},
			func(_ context.Context, input *awss3.DeleteObjectInput) error {
				deletes++
				if aws.ToString(input.Bucket) != "bucket" || aws.ToString(input.Key) != "owned-key" || input.VersionId != nil {
					t.Fatal("cleanup delete did not target only the identified nonversioned object")
				}
				return nil
			}, func() {
				if heads != 1 || deletes != 1 {
					t.Fatalf("customer key released before exactly one HEAD/delete: heads=%d deletes=%d", heads, deletes)
				}
				keyB64, md5B64 = "", ""
			})
		if cleanupErr != nil || heads != 1 || deletes != 1 || keyB64 != "" || md5B64 != "" {
			t.Fatalf("nonversioned cleanup failed or did not release key: heads=%d deletes=%d err=%v", heads, deletes, cleanupErr)
		}
	})
	t.Run("known version skips HEAD and deletes only that version", func(t *testing.T) {
		calls := 0
		cleanupErr := cleanupPostObjectWithIdentity(context.Background(), "bucket", "owned-key", "version-1", "AES256", "key", "md5",
			func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) {
				t.Fatal("known-version cleanup performed unnecessary HEAD")
				return nil, nil
			},
			func(_ context.Context, input *awss3.DeleteObjectInput) error {
				calls++
				if aws.ToString(input.Key) != "owned-key" || aws.ToString(input.VersionId) != "version-1" {
					t.Fatal("known-version cleanup did not preserve captured identity")
				}
				return nil
			}, nil)
		if cleanupErr != nil || calls != 1 {
			t.Fatalf("known-version cleanup calls=%d err=%v", calls, cleanupErr)
		}
	})
	t.Run("provider callback errors are sanitized and still release key", func(t *testing.T) {
		released := false
		secretDetail := "raw-provider-error-with-customer-key"
		cleanupErr := cleanupPostObjectWithIdentity(context.Background(), "bucket", "owned-key", "", "AES256", "key", "md5",
			func(context.Context, *awss3.HeadObjectInput) (*awss3.HeadObjectOutput, error) {
				return nil, errors.New(secretDetail)
			},
			func(context.Context, *awss3.DeleteObjectInput) error {
				t.Fatal("delete must not follow failed identification")
				return nil
			},
			func() { released = true })
		if cleanupErr == nil || strings.Contains(cleanupErr.Error(), secretDetail) || !released {
			t.Fatal("cleanup failure leaked provider detail or retained key material")
		}
	})
}

func assertPostSSEResponseHeaders(t *testing.T, mode string, headers http.Header, customerMD5 string, hasBody bool) {
	t.Helper()
	wantMode := mode
	if mode == "SSE-C" {
		wantMode = ""
	}
	if headers.Get("x-amz-server-side-encryption") != wantMode {
		t.Fatalf("%s response exposed SSE mode %q, want %q", mode, headers.Get("x-amz-server-side-encryption"), wantMode)
	}
	if mode == "SSE-C" {
		if headers.Get("x-amz-server-side-encryption-customer-algorithm") != "AES256" || headers.Get("x-amz-server-side-encryption-customer-key-md5") != customerMD5 || headers.Get("x-amz-server-side-encryption-customer-key") != "" || headers.Get("Cache-Control") != "no-store" {
			t.Fatalf("SSE-C response headers exposed key material or lost opaque SSE metadata")
		}
		if headers.Get("ETag") == "" || !strings.HasPrefix(headers.Get("ETag"), "\"") || strings.Contains(headers.Get("ETag"), hex.EncodeToString(md5Sum(bytes.Repeat([]byte("gateway-and-backend-SSE-record-"), 512)))) {
			t.Fatal("SSE-C response did not retain an opaque backend ETag")
		}
	} else if mode == "aws:kms" && headers.Get("x-amz-server-side-encryption-aws-kms-key-id") == "" {
		t.Fatal("SSE-KMS response omitted the configured key identifier")
	}
	if !hasBody && headers.Get("Content-Length") == "" {
		t.Fatalf("%s HEAD response omitted content length", mode)
	}
}
