package middleware_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/middleware"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

const (
	postSecretsAccessKey = "AKIAIOSFODNN7EXAMPLE"
	postSecretsSecret    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	postSecretsToken     = "session-token-canary-raw"
)

func TestGH353PostSecrets_LogsAndTracingNeverLeak(t *testing.T) {
	for _, format := range []string{"default", "json", "clf"} {
		for _, customRedactions := range [][]string{nil, {"X-Benign-Secret"}} {
			customName := "empty-configured-redactions"
			if len(customRedactions) != 0 {
				customName = "additional-configured-redaction"
			}
			for _, traceRedaction := range []bool{false, true} {
				for _, scenario := range []string{"signed-get", "accepted-post", "rejected-post", "header-signed-rejected"} {
					t.Run(fmt.Sprintf("%s/%s/tracing-%t/%s", format, customName, traceRedaction, scenario), func(t *testing.T) {
						secrets, request, expectedStatus, handlerCalls := postSecretsRequest(t, scenario)
						var output bytes.Buffer
						logger := logrus.New()
						logger.SetOutput(&output)
						logger.SetLevel(logrus.InfoLevel)
						logger.SetFormatter(&logrus.JSONFormatter{})

						store, err := api.NewStaticCredentialStore([]config.GatewayCredential{{
							AccessKey: postSecretsAccessKey, SecretKey: postSecretsSecret,
							SessionToken: postSecretsToken, ExpiresAt: timePtr(time.Now().UTC().Add(time.Hour)),
							Buckets: []string{"bucket"}, Permissions: permissionPtr(config.ObjectPermissionReadWrite), BucketPermissions: []config.BucketPermission{config.BucketPermissionManage, config.BucketPermissionCreate, config.BucketPermissionDelete},
						}})
						if err != nil {
							t.Fatal(err)
						}
						oldProvider := otel.GetTracerProvider()
						recorder := tracetest.NewSpanRecorder()
						provider := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithSpanProcessor(recorder))
						otel.SetTracerProvider(provider)
						defer func() { otel.SetTracerProvider(oldProvider); _ = provider.Shutdown(context.Background()) }()
						var gotHandlerCalls int
						endpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							gotHandlerCalls++
							if _, ok := api.CredentialFromContext(r); !ok {
								t.Error("real authentication chain did not attach its credential")
							}
							w.WriteHeader(expectedStatus)
						})
						router := mux.NewRouter()
						router.Use(api.AuthMiddleware(store, time.Minute, logger, nil, false))
						router.Handle("/{bucket}/{key}", endpoint).Methods(http.MethodGet).Name("GetObject")
						router.Handle("/{bucket}", endpoint).Methods(http.MethodPost).Name("PostObject")
						chain := middleware.LoggingMiddleware(logger, &config.LoggingConfig{AccessLogFormat: format, RedactHeaders: customRedactions})(
							middleware.TracingMiddleware(traceRedaction, nil)(router),
						)
						originalQuery := request.URL.RawQuery
						originalAuthorization := request.Header.Get("Authorization")
						originalHeaders := request.Header.Clone()
						response := httptest.NewRecorder()
						chain.ServeHTTP(response, request)
						if err := provider.ForceFlush(context.Background()); err != nil {
							t.Fatalf("flush span exporter: %v", err)
						}
						if response.Code != expectedStatus || gotHandlerCalls != handlerCalls {
							t.Fatalf("status=%d want=%d downstream calls=%d want=%d body=%s", response.Code, expectedStatus, gotHandlerCalls, handlerCalls, response.Body.String())
						}
						if request.URL.RawQuery != originalQuery || request.Header.Get("Authorization") != originalAuthorization {
							t.Fatalf("telemetry/auth changed the signed request: query=%q authorization preserved=%t", request.URL.RawQuery, request.Header.Get("Authorization") == originalAuthorization)
						}
						for name, values := range originalHeaders {
							if !equalStrings(request.Header[name], values) {
								t.Fatalf("signed request header %q changed: %v -> %v", name, values, request.Header[name])
							}
						}

						logged := output.String()
						for _, secret := range secrets {
							if secret != "" && strings.Contains(logged, secret) {
								t.Fatalf("secret leaked to %s access log: %q", format, secret)
							}
						}
						if scenario == "signed-get" && !strings.Contains(logged, "benign-version-visible") {
							t.Fatalf("benign request telemetry disappeared: %s", logged)
						}
						if (format == "default" || format == "json") && !strings.Contains(logged, "benign-agent-visible") {
							t.Fatalf("benign User-Agent missing from structured log: %s", logged)
						}
						if format == "json" && customName == "additional-configured-redaction" && strings.Contains(logged, "benign-header-secret-canary") {
							t.Fatalf("operator-configured additional redaction was ignored: %s", logged)
						}
						if strings.Contains(logged, "multipart-body-canary") {
							t.Fatal("serialized multipart request body appeared in access logs")
						}
						if format == "json" {
							for _, header := range []string{"authorization", "x-amz-security-token", "x-amz-server-side-encryption-customer-algorithm", "x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-md5", "x-amz-signature", "policy"} {
								if len(headerValuesFold(request.Header, header)) > 0 && !strings.Contains(logged, `\"`+header+`\":\"[REDACTED]\"`) {
									t.Errorf("JSON headers omit mandatory redaction for %q: %s", header, logged)
								}
							}
							if !strings.Contains(logged, "benign-agent-visible") || !strings.Contains(logged, "x-benign-secret") {
								t.Errorf("benign headers were not retained in JSON log: %s", logged)
							}
						}
						assertSafeSpan(t, recorder.Ended(), secrets, traceRedaction, request.Header)
					})
				}
			}
		}
	}
}

func postSecretsRequest(t *testing.T, scenario string) ([]string, *http.Request, int, int) {
	t.Helper()
	key := []byte("SSEC-key-canary-raw-32-bytes!!!!")
	if len(key) != 32 {
		t.Fatalf("test customer key length=%d", len(key))
	}
	encodedKey := base64.StdEncoding.EncodeToString(key)
	keyMD5 := md5.Sum(key)
	encodedMD5 := base64.StdEncoding.EncodeToString(keyMD5[:])
	secrets := []string{
		postSecretsToken, string(key), encodedKey, encodedMD5, "signature-query-canary",
		"policy-query-canary", "credential-query-canary", "sse-algorithm-query-canary", "sigv4-query-canary",
		"multipart-body-canary", "second-customer-key-canary", "signature-duplicate-canary", "policy-duplicate-canary",
	}
	if scenario == "signed-get" {
		query := "versionId=benign-version-visible&X-Amz-Expires=300&signature=signature-query-canary&Signature=signature-query-duplicate-canary&policy=policy-query-canary&Policy=policy-duplicate-canary&x-amz-server-side-encryption-customer-key=" + url.QueryEscape(encodedKey) + "&benign=benign-query-visible"
		req := httptest.NewRequest(http.MethodGet, "https://gateway.example/bucket/object?"+query, nil)
		req.Header.Set("User-Agent", "benign-agent-visible")
		req.Header.Set("X-Benign-Secret", "benign-header-secret-canary")
		credentials := aws.Credentials{
			AccessKeyID: postSecretsAccessKey, SecretAccessKey: postSecretsSecret, SessionToken: postSecretsToken,
		}
		signedURI, _, err := v4.NewSigner().PresignHTTP(context.Background(), credentials, req, "UNSIGNED-PAYLOAD", "s3", "us-east-1", time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		req.URL, err = url.Parse(signedURI)
		if err != nil {
			t.Fatal(err)
		}
		secrets = append(secrets, req.URL.Query().Get("X-Amz-Credential"), req.URL.Query().Get("X-Amz-Signature"), postSecretsToken)
		secrets = append(secrets, "signature-query-duplicate-canary", "credential-query-canary")
		return secrets, req, http.StatusOK, 1
	}

	date := time.Now().UTC().Format("20060102T150405Z")
	scope := postSecretsAccessKey + "/" + date[:8] + "/us-east-1/s3/aws4_request"
	fields := map[string]string{
		"bucket": "bucket", "key": "object", "x-amz-algorithm": "AWS4-HMAC-SHA256",
		"x-amz-credential": scope, "x-amz-date": date, "x-amz-security-token": postSecretsToken,
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       encodedKey,
		"x-amz-server-side-encryption-customer-key-MD5":   encodedMD5,
	}
	conditions := []string{
		`{"bucket":"bucket"}`, `{"key":"object"}`, `{"x-amz-algorithm":"AWS4-HMAC-SHA256"}`,
		fmt.Sprintf(`{"x-amz-credential":%q}`, scope), fmt.Sprintf(`{"x-amz-date":%q}`, date),
		fmt.Sprintf(`{"x-amz-security-token":%q}`, postSecretsToken),
		`{"x-amz-server-side-encryption-customer-algorithm":"AES256"}`,
		fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key":%q}`, encodedKey),
		fmt.Sprintf(`{"x-amz-server-side-encryption-customer-key-MD5":%q}`, encodedMD5),
	}
	expires := time.Now().UTC().Add(20 * time.Minute).Format(time.RFC3339Nano)
	policyText := fmt.Sprintf(`{"expiration":%q,"conditions":[%s]}`, expires, strings.Join(conditions, ","))
	policy := base64.StdEncoding.EncodeToString([]byte(policyText))
	signature := signPostSecretsPolicy(policy, date[:8])
	fields["policy"], fields["x-amz-signature"] = policy, signature
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range fields {
		part, err := writer.CreateFormField(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormFile("file", "object")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, "multipart-body-canary"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "http://gateway.example/bucket", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("User-Agent", "benign-agent-visible")
	req.Header.Set("X-Benign-Secret", "benign-header-secret-canary")
	if scenario != "signed-get" {
		req.Header.Set("X-Amz-Signature", "signature-header-canary")
		req.Header.Set("Policy", "policy-header-canary")
		req.Header.Set("X-Amz-Server-Side-Encryption-Customer-Key", encodedKey)
		req.Header.Set("X-Amz-Server-Side-Encryption-Customer-Algorithm", "AES256")
		req.Header.Set("X-Amz-Server-Side-Encryption-Customer-Key-MD5", encodedMD5)
	}
	// Include mixed-case raw map spellings and repeated values. These bypass
	// Header.Set canonicalization and exercise the actual telemetry redaction path.
	if scenario != "signed-get" && scenario != "accepted-post" && scenario != "rejected-post" {
		req.Header["aUtHoRiZaTiOn"] = []string{"authorization-alias-canary", "authorization-alias-duplicate-canary"}
	}
	if scenario != "signed-get" {
		req.Header["x-AmZ-SeCuRiTy-ToKeN"] = []string{"token-header-alias-canary", "token-header-duplicate-canary"}
		req.Header["x-AmZ-SeRvEr-SiDe-EnCrYpTiOn-CuStOmEr-KeY"] = []string{encodedKey, "second-customer-key-canary"}
		req.Header["X-Amz-Server-Side-Encryption-Customer-Key-Md5"] = []string{encodedMD5, "customer-md5-duplicate-canary"}
		req.Header["x-amz-signature"] = []string{"signature-alias-canary", "signature-duplicate-canary"}
		req.Header["pOlIcY"] = []string{"policy-alias-canary", "policy-duplicate-canary"}
	}
	if scenario == "header-signed-rejected" {
		req.Header["aUtHoRiZaTiOn"] = []string{"AWS4-HMAC-SHA256 Credential=denied/invalid, SignedHeaders=host, Signature=header-signature-canary"}
	}
	status, calls := http.StatusNoContent, 1
	if scenario == "rejected-post" {
		status, calls = http.StatusForbidden, 1
	} else if scenario == "header-signed-rejected" {
		status, calls = http.StatusBadRequest, 0
		secrets = append(secrets, "header-signature-canary")
	}
	secrets = append(secrets, signature, policy, "signature-header-canary", "policy-header-canary", "second-customer-key-canary", "authorization-alias-canary", "authorization-alias-duplicate-canary", "token-header-alias-canary", "token-header-duplicate-canary", "customer-md5-duplicate-canary", "signature-alias-canary", "policy-alias-canary", "policy-duplicate-canary")
	return secrets, req, status, calls
}

func appendMultipartScalar(t *testing.T, original []byte, name, value string) *bytes.Buffer {
	t.Helper()
	reader := multipart.NewReader(bytes.NewReader(original), multipartBoundary(original))
	var rewritten bytes.Buffer
	writer := multipart.NewWriter(&rewritten)
	if err := writer.SetBoundary(multipartBoundary(original)); err != nil {
		t.Fatal(err)
	}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		var out io.Writer
		if part.FileName() != "" {
			out, err = writer.CreateFormFile(part.FormName(), part.FileName())
		} else {
			out, err = writer.CreateFormField(part.FormName())
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	part, err := writer.CreateFormField(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(part, value); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &rewritten
}

func rewriteMultipartFormValue(t *testing.T, original []byte, name, value string) *bytes.Buffer {
	t.Helper()
	reader := multipart.NewReader(bytes.NewReader(original), multipartBoundary(original))
	var rewritten bytes.Buffer
	writer := multipart.NewWriter(&rewritten)
	if err := writer.SetBoundary(multipartBoundary(original)); err != nil {
		t.Fatal(err)
	}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		if part.FormName() == name {
			data = []byte(value)
		}
		var out io.Writer
		if part.FileName() != "" {
			out, err = writer.CreateFormFile(part.FormName(), part.FileName())
		} else {
			out, err = writer.CreateFormField(part.FormName())
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &rewritten
}

func multipartBoundary(body []byte) string {
	line := strings.SplitN(string(body), "\r\n", 2)[0]
	return strings.TrimPrefix(line, "--")
}

func signPostSecretsPolicy(policy, date string) string {
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = io.WriteString(h, value)
		return h.Sum(nil)
	}
	dateKey := mac([]byte("AWS4"+postSecretsSecret), date)
	regionKey := mac(dateKey, "us-east-1")
	serviceKey := mac(regionKey, "s3")
	signingKey := mac(serviceKey, "aws4_request")
	return hex.EncodeToString(mac(signingKey, policy))
}

func assertSafeSpan(t *testing.T, spans []sdktrace.ReadOnlySpan, secrets []string, redactSensitive bool, requestHeaders http.Header) {
	t.Helper()
	if len(spans) != 1 {
		t.Fatalf("expected one completed server span, got %d", len(spans))
	}
	var rendered []string
	var attributes []attribute.KeyValue
	for _, span := range spans {
		for _, attr := range span.Attributes() {
			attributes = append(attributes, attr)
			rendered = append(rendered, string(attr.Key)+"="+attr.Value.AsString())
		}
	}
	joined := strings.Join(rendered, "\n")
	for _, secret := range secrets {
		if secret != "" && strings.Contains(joined, secret) {
			t.Fatalf("secret leaked to span: %q in %s", secret, joined)
		}
	}
	for _, header := range []string{"authorization", "x-amz-security-token", "x-amz-server-side-encryption-customer-algorithm", "x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-md5", "x-amz-signature", "policy"} {
		if len(headerValuesFold(requestHeaders, header)) == 0 {
			continue
		}
		foundRedacted := false
		for _, attr := range attributes {
			if string(attr.Key) == "http.request.header."+header && attr.Value.AsString() == "[REDACTED]" {
				foundRedacted = true
			}
		}
		if !foundRedacted {
			t.Errorf("span lacks mandatory [REDACTED] value for header %q: %s", header, joined)
		}
	}
	if strings.Contains(joined, "http.query=") && !strings.Contains(joined, "benign-version-visible") && redactSensitive == false {
		t.Fatalf("benign span query attribute was lost: %s", joined)
	}
	if !strings.Contains(joined, "http.user_agent=benign-agent-visible") {
		t.Fatalf("benign User-Agent span attribute missing: %s", joined)
	}
	if strings.Contains(joined, "multipart-body-canary") {
		t.Fatal("multipart body value appeared in span attributes")
	}
	for _, attr := range attributes {
		if strings.Contains(strings.ToLower(string(attr.Key)), "post.field") || strings.Contains(strings.ToLower(string(attr.Key)), "form") || strings.Contains(strings.ToLower(string(attr.Key)), "body") {
			t.Fatalf("POST form/body attribute was emitted: %s", attr.Key)
		}
	}
	_ = redactSensitive // Both settings are covered; mandatory fields stay redacted in either mode.
}

func headerValuesFold(headers http.Header, name string) []string {
	var values []string
	for candidate, candidates := range headers {
		if strings.EqualFold(candidate, name) {
			values = append(values, candidates...)
		}
	}
	return values
}

func permissionPtr(value config.ObjectPermission) *config.ObjectPermission { return &value }
func timePtr(value time.Time) *time.Time                                   { return &value }
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
