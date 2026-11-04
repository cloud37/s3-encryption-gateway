package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

func TestGH353MinioObjectSSEFailureGateIsolatedFromOrdinaryFixture(t *testing.T) {
	plain := Instance{Endpoint: "http://ordinary-minio", MinIOObjectSSEAttempted: false}
	if err := ValidateMinIOObjectSSEFixture(plain); err == nil || !strings.Contains(err.Error(), "not attempted") {
		t.Fatalf("expected isolated-fixture diagnostic, got %v", err)
	}
	plain.MinIOObjectSSEAttempted = true
	plain.ObjectSSEError = minioStaticKMSError("SDK verification", errors.New("unsupported"))
	if err := ValidateMinIOObjectSSEFixture(plain); err == nil || !strings.Contains(err.Error(), "static-key support") {
		t.Fatalf("expected failed-verification diagnostic, got %v", err)
	}
}

func TestGH353MinioStaticKMSFixtureSecretShape(t *testing.T) {
	secret, key, err := newMinioStaticKMSSecret()
	if err != nil {
		t.Fatal("generate test fixture KMS key")
	}
	defer clear(key)
	if !strings.HasPrefix(secret, "gh353-test:") {
		t.Fatalf("fixture KMS key has unexpected identifier prefix")
	}
	encoded := strings.TrimPrefix(secret, "gh353-test:")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		clear(decoded)
		t.Fatalf("fixture KMS key must be base64 of exactly 32 random bytes: decode error=%v bytes=%d", err, len(decoded))
	}
	clear(decoded)
	if secret == "" || len(key) != 32 {
		t.Fatal("fixture helper returned missing or incorrectly sized backing key")
	}
	second, secondKey, err := newMinioStaticKMSSecret()
	if err != nil {
		t.Fatal("generate independent KMS key")
	}
	defer clear(secondKey)
	defer func() { second = "" }()
	firstDigest, secondDigest := sha256.Sum256(key), sha256.Sum256(secondKey)
	if firstDigest == secondDigest || secret == second {
		t.Fatal("static-KMS fixture keys were unexpectedly repeated")
	}
}

func TestGH353MinioObjectSSEDoesNotReplaceOrdinaryEndpoint(t *testing.T) {
	inst := Instance{
		Endpoint: "http://ordinary-minio:9000", Region: "us-east-1", ProviderName: "minio",
		ObjectSSE: &SSEFixture{Backend: TLSFixture{Endpoint: "https://sse-minio:9000", CAFile: "/tmp/fixture-ca.pem"}, KMSKeyID: "gh353-test"},
	}
	backend := (&minioProvider{}).BackendConfig(inst)
	if backend.Endpoint != inst.Endpoint || backend.UseSSL {
		t.Fatalf("ObjectSSE fixture changed normal provider backend selection: endpoint=%q useSSL=%t", backend.Endpoint, backend.UseSSL)
	}
}

func TestGH353MinioObjectSSEGateRequiresCompletedSDKFixture(t *testing.T) {
	inst := Instance{MinIOObjectSSEAttempted: true, ObjectSSE: &SSEFixture{Backend: TLSFixture{Endpoint: "https://minio", CAFile: "ca.pem", Bucket: "fixture", AccessKey: "access", SecretKey: "secret"}, KMSKeyID: "gh353-test"}}
	if err := ValidateMinIOObjectSSEFixture(inst); err != nil {
		t.Fatalf("complete verified-fixture shape rejected: %v", err)
	}
	inst.ObjectSSE = nil
	if err := ValidateMinIOObjectSSEFixture(inst); err == nil || !strings.Contains(err.Error(), "not published") {
		t.Fatalf("fixture gate accepted missing SDK result: %v", err)
	}
}

func TestGH353MinioFailureDiagnosticDoesNotPersistRawContainerError(t *testing.T) {
	diagnostic := minioStaticKMSError("container startup", errors.New("create container failed, details redacted"))
	if strings.Contains(diagnostic, "details redacted") || strings.Contains(diagnostic, "MINIO_KMS_SECRET_KEY") {
		t.Fatalf("fixture diagnostic retained raw container details: %q", diagnostic)
	}
	if !strings.Contains(diagnostic, "category: runtime") || !strings.Contains(diagnostic, "container startup") {
		t.Fatalf("fixture diagnostic lost non-secret stage/category: %q", diagnostic)
	}
}

func TestGH353MinioSSEProbeDiagnosticIsStageSpecificAndRedacted(t *testing.T) {
	response := &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
		Err:      &smithy.GenericAPIError{Code: "InvalidRequest", Message: "sensitive request details"},
	}
	err := minioSSEOperationError("SSE-KMS", "PUT", response)
	diagnostic := minioStaticKMSError("SDK capability verification", err)
	for _, want := range []string{"SSE-KMS PUT", "HTTP status 400", "AWS error code InvalidRequest"} {
		if !strings.Contains(diagnostic, want) {
			t.Errorf("safe diagnostic %q missing %q", diagnostic, want)
		}
	}
	for _, forbidden := range []string{"sensitive request details", "https://", "?token="} {
		if strings.Contains(diagnostic, forbidden) {
			t.Errorf("diagnostic leaked %q: %q", forbidden, diagnostic)
		}
	}
	privateResponse := &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &http.Response{StatusCode: http.StatusBadRequest}},
		Err:      &smithy.GenericAPIError{Code: "private-code", Message: "private details"},
	}
	unknown := minioStaticKMSError("SDK capability verification", minioSSEOperationError("SSE-S3", "GET", privateResponse))
	if strings.Contains(unknown, "private-code") || strings.Contains(unknown, "private details") || !strings.Contains(unknown, "AWS error code unclassified") {
		t.Fatalf("unallowlisted error leaked or was not classified: %q", unknown)
	}
}

func TestGH353MinioSSESuccessfulKMSResponseMismatchHasDistinctSafeProvenance(t *testing.T) {
	const configuredKey = "gh353-test"
	for _, tc := range []struct {
		name   string
		mode   string
		output *s3.PutObjectOutput
		want   []string
	}{
		{name: "empty identity", mode: "sse-kms", output: &s3.PutObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms}, want: []string{"successful response failed assertion (kms-identity-mismatch)", "identity_matches=false", "returned_identity=empty"}},
		{name: "different opaque identity", mode: "sse-kms", output: &s3.PutObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String("private-kms-key-id")}, want: []string{"kms-identity-mismatch", "configured_is_arn=false", "returned_is_arn=false"}},
		{name: "exact configured identity", mode: "sse-kms", output: &s3.PutObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(configuredKey)}},
		{name: "wrong algorithm", mode: "sse-kms", output: &s3.PutObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAes256, SSEKMSKeyId: aws.String(configuredKey)}, want: []string{"sse-algorithm-mismatch", "algorithm_matches=false"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMinioSSEPutResponse(tc.mode, tc.output, configuredKey)
			if len(tc.want) == 0 {
				if err != nil {
					t.Fatalf("exact configured identity rejected: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("mismatching successful SDK response accepted")
			}
			diagnostic := minioStaticKMSError("SDK capability verification", err)
			for _, fragment := range tc.want {
				if !strings.Contains(diagnostic, fragment) {
					t.Errorf("diagnostic %q missing %q", diagnostic, fragment)
				}
			}
			if strings.Contains(diagnostic, "private-kms-key-id") || strings.Contains(diagnostic, configuredKey) || strings.Contains(diagnostic, "HTTP status") || strings.Contains(diagnostic, "AWS error code") {
				t.Errorf("successful response mismatch diagnostic leaked values or impersonated API failure: %q", diagnostic)
			}
		})
	}
}

func TestGH353MinioKMSResponseValidatorsUseCanonicalIdentityBinding(t *testing.T) {
	const configured = "gh353-test"
	const returned = "arn:aws:kms:" + configured
	put := &s3.PutObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(returned)}
	get := &s3.GetObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(returned)}
	head := &s3.HeadObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(returned)}
	if err := validateMinioSSEPutResponse("sse-kms", put, configured); err != nil {
		t.Errorf("PUT rejected documented MinIO canonical identity: %v", err)
	}
	if err := validateMinioSSEGetResponse("sse-kms", get, configured); err != nil {
		t.Errorf("GET rejected documented MinIO canonical identity: %v", err)
	}
	if err := validateMinioSSEHeadResponse("sse-kms", head, configured); err != nil {
		t.Errorf("HEAD rejected documented MinIO canonical identity: %v", err)
	}
	for _, err := range []error{
		validateMinioSSEPutResponse("sse-kms", &s3.PutObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String("arn:aws:kms:other-key")}, configured),
		validateMinioSSEGetResponse("sse-kms", &s3.GetObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String("arn:aws:kms:other-key")}, configured),
		validateMinioSSEHeadResponse("sse-kms", &s3.HeadObjectOutput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String("arn:aws:kms:other-key")}, configured),
	} {
		if err == nil || !strings.Contains(err.Error(), "kms-identity-mismatch") || strings.Contains(err.Error(), "other-key") {
			t.Errorf("wrong KMS identity not safely rejected: %v", err)
		}
	}
}

func TestGH353MinioSSECanonicalKMSWireMismatchDiagnosticIsSafe(t *testing.T) {
	const configured = "gh353-test"
	const returned = "arn:aws:kms:private-identity"
	client := s3.New(s3.Options{
		Region: "us-east-1",
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, nil
		}),
		BaseEndpoint: aws.String("https://minio.example"),
		UsePathStyle: true,
		HTTPClient: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{
				"X-Amz-Server-Side-Encryption":                []string{"aws:kms"},
				"X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id": []string{returned},
			}, Body: http.NoBody, Request: req}, nil
		}),
		Retryer: aws.NopRetryer{},
	})
	output, requestErr := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: aws.String("fixture"), Key: aws.String("object"), Body: strings.NewReader("payload"),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(configured),
	})
	if requestErr != nil {
		t.Fatalf("wire response should be a successful SDK response: %v", requestErr)
	}
	err := validateMinioSSEPutResponse("sse-kms", output, configured)
	if err == nil {
		t.Fatal("wrong prefixed identity accepted")
	}
	diagnostic := minioStaticKMSError("SDK capability verification", err)
	for _, forbidden := range []string{configured, returned, "HTTP status", "AWS error code"} {
		if strings.Contains(diagnostic, forbidden) {
			t.Errorf("safe identity assertion diagnostic leaked %q: %s", forbidden, diagnostic)
		}
	}
	if !strings.Contains(diagnostic, "kms-identity-mismatch") || !strings.Contains(diagnostic, "identity_matches=false") {
		t.Fatalf("identity mismatch provenance missing: %s", diagnostic)
	}
}

func TestGH353MinioKMSCanonicalIdentityBinding(t *testing.T) {
	minio := Instance{ProviderName: (&minioProvider{}).Name()}
	other := Instance{ProviderName: "not-registered-minio"}
	const configured = "gh353-test"
	const canonical = "arn:aws:kms:" + configured
	for _, tc := range []struct {
		name       string
		inst       Instance
		configured string
		returned   string
		want       bool
	}{
		{name: "minio exact raw equality", inst: minio, configured: configured, returned: configured, want: true},
		{name: "minio exact canonical prefix", inst: minio, configured: configured, returned: canonical, want: true},
		{name: "minio canonical configured equality", inst: minio, configured: canonical, returned: canonical, want: true},
		{name: "minio wrong key with canonical prefix", inst: minio, configured: configured, returned: "arn:aws:kms:other-key"},
		{name: "minio matching suffix other region and account", inst: minio, configured: configured, returned: "arn:aws:kms:us-west-2:123456789012:key/gh353-test"},
		{name: "minio wrong prefix", inst: minio, configured: configured, returned: "arn:aws:other:" + configured},
		{name: "minio prefix case mismatch", inst: minio, configured: configured, returned: "ARN:AWS:KMS:" + configured},
		{name: "minio empty configured", inst: minio, returned: canonical},
		{name: "minio empty returned", inst: minio, configured: configured},
		{name: "minio doubled canonical prefix", inst: minio, configured: canonical, returned: "arn:aws:kms:" + canonical},
		{name: "minio canonical configured different identity", inst: minio, configured: canonical, returned: "arn:aws:kms:other-key"},
		{name: "minio canonical configured raw response", inst: minio, configured: canonical, returned: configured},
		{name: "other provider remains exact", inst: other, configured: configured, returned: canonical},
		{name: "other provider exact equality", inst: other, configured: configured, returned: configured, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ObjectSSEKMSIdentityMatches(tc.inst, tc.configured, tc.returned); got != tc.want {
				t.Fatalf("identity policy result=%t, want %t", got, tc.want)
			}
		})
	}
}

func TestGH353MinioSSETransportFailureDiffersFromSuccessfulResponseAssertion(t *testing.T) {
	transportFailure := minioSSEOperationError("sse-kms", "PUT", io.EOF)
	transportDiagnostic := minioStaticKMSError("SDK capability verification", transportFailure)
	responseMismatch := minioSSEAssertionFailure("sse-kms", "PUT", "kms-identity-mismatch", "identity_matches=false returned_identity=empty")
	assertionDiagnostic := minioStaticKMSError("SDK capability verification", responseMismatch)
	if !strings.Contains(transportDiagnostic, "failure_kind=transport") || !strings.Contains(transportDiagnostic, "category=eof") {
		t.Fatalf("transport failure provenance=%q", transportDiagnostic)
	}
	if !strings.Contains(assertionDiagnostic, "successful response failed assertion") || strings.Contains(assertionDiagnostic, "category=") || strings.Contains(assertionDiagnostic, "HTTP status") {
		t.Fatalf("successful-response mismatch provenance=%q", assertionDiagnostic)
	}
}

func TestGH353MinioSSESDKWireSeparatesSuccessfulMismatchFromAPIAndTransportFailures(t *testing.T) {
	const configuredKey = "gh353-test"
	const returnedKey = "private-kms-key-id"
	for _, tc := range []struct {
		name      string
		response  func(*http.Request) (*http.Response, error)
		want      []string
		forbidden []string
	}{
		{
			name: "successful KMS identity mismatch",
			response: func(req *http.Request) (*http.Response, error) {
				header := http.Header{
					"X-Amz-Server-Side-Encryption":                []string{"aws:kms"},
					"X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id": []string{returnedKey},
				}
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: http.NoBody, Request: req}, nil
			},
			want:      []string{"successful response failed assertion (kms-identity-mismatch)", "identity_matches=false"},
			forbidden: []string{returnedKey, configuredKey, "HTTP status", "AWS error code"},
		},
		{
			name: "API failure",
			response: func(req *http.Request) (*http.Response, error) {
				body := io.NopCloser(strings.NewReader(`<Error><Code>InvalidRequest</Code><Message>private API detail</Message></Error>`))
				return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Content-Type": []string{"application/xml"}}, Body: body, Request: req}, nil
			},
			want:      []string{"failure_kind=API response", "HTTP status 400", "AWS error code InvalidRequest"},
			forbidden: []string{"private API detail", returnedKey, configuredKey},
		},
		{
			name: "transport failure",
			response: func(*http.Request) (*http.Response, error) {
				return nil, errors.New("private transport detail ?token=secret")
			},
			want:      []string{"failure_kind=transport", "category=runtime"},
			forbidden: []string{"private transport detail", "token=secret", returnedKey, configuredKey},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := s3.New(s3.Options{
				Region: "us-east-1",
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, nil
				}),
				BaseEndpoint: aws.String("https://minio.example"),
				UsePathStyle: true,
				HTTPClient:   roundTripFunc(tc.response),
				Retryer:      aws.NopRetryer{},
			})
			output, requestErr := client.PutObject(context.Background(), &s3.PutObjectInput{
				Bucket: aws.String("fixture"), Key: aws.String("object"), Body: strings.NewReader("payload"),
				ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(configuredKey),
			})
			var err error
			if requestErr != nil {
				err = minioSSEOperationError("sse-kms", "PUT", requestErr)
			} else {
				err = validateMinioSSEPutResponse("sse-kms", output, configuredKey)
			}
			if err == nil {
				t.Fatal("mismatch/failure was accepted")
			}
			diagnostic := minioStaticKMSError("SDK capability verification", err)
			for _, fragment := range tc.want {
				if !strings.Contains(diagnostic, fragment) {
					t.Errorf("diagnostic %q missing %q", diagnostic, fragment)
				}
			}
			for _, fragment := range tc.forbidden {
				if strings.Contains(diagnostic, fragment) {
					t.Errorf("diagnostic leaked or misclassified %q: %q", fragment, diagnostic)
				}
			}
		})
	}
}

func TestGH353MinioHeadResultErrorsAreSafeForNilOutput(t *testing.T) {
	tests := []struct {
		name           string
		result         *s3.HeadObjectOutput
		err            error
		expectedLength int64
		want           string
	}{
		{name: "error with nil result", err: errors.New("private SDK detail"), expectedLength: 7, want: "request failed"},
		{name: "nil result", expectedLength: 7, want: "response was empty"},
		{name: "wrong length", result: &s3.HeadObjectOutput{ContentLength: int64ptr(6)}, expectedLength: 7, want: "content length"},
		{name: "valid result", result: &s3.HeadObjectOutput{ContentLength: int64ptr(7)}, expectedLength: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMinioHeadResult(tt.result, tt.err, tt.expectedLength)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("valid HEAD result rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) || strings.Contains(err.Error(), "private SDK detail") {
				t.Fatalf("expected safe %q diagnostic, got %v", tt.want, err)
			}
		})
	}
}

func TestGH353MinioSSECustomerKeyFailureSDKWireClassification(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		code    string
		message string
		want    bool
	}{
		{name: "wrong key access denied", status: http.StatusForbidden, code: "AccessDenied", message: "Access Denied", want: true},
		{name: "key validation bad request", status: http.StatusBadRequest, code: "InvalidRequest", message: "The SSE-C customer key is invalid", want: true},
		{name: "unrelated bad request", status: http.StatusBadRequest, code: "InvalidRequest", message: "Invalid bucket name"},
		{name: "not found is not proof", status: http.StatusNotFound, code: "NoSuchKey"},
		{name: "unrelated auth denial", status: http.StatusForbidden, code: "InvalidAccessKeyId"},
		{name: "unrelated client error", status: http.StatusBadRequest, code: "InvalidArgument"},
		{name: "network error", status: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.status != 0 {
				err = &smithyhttp.ResponseError{
					Response: &smithyhttp.Response{Response: &http.Response{StatusCode: tc.status}},
					Err:      &smithy.GenericAPIError{Code: tc.code, Message: tc.message},
				}
			} else {
				err = errors.New("connection reset")
			}
			if got := isMinIOSSECustomerKeyFailure(err); got != tc.want {
				t.Fatalf("isMinIOSSECustomerKeyFailure()=%t, want %t", got, tc.want)
			}
		})
	}
}

func TestGH353MinioSSECustomerHeadDenialSDKWireFixtures(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body        bool
		errorCode   string
		transport   bool
		wantDenied  bool
		wantSuccess bool
	}{
		{name: "bodyless bad request", status: http.StatusBadRequest, wantDenied: true},
		{name: "bodyless forbidden", status: http.StatusForbidden, wantDenied: true},
		{name: "bodyless not found", status: http.StatusNotFound},
		{name: "bodyless server failure", status: http.StatusInternalServerError},
		{name: "unexpected success", status: http.StatusOK, wantSuccess: true},
		{name: "unrelated explicit credential code", status: http.StatusForbidden, errorCode: "InvalidAccessKeyId"},
		{name: "unrelated explicit signature code", status: http.StatusForbidden, errorCode: "SignatureDoesNotMatch"},
		{name: "unrelated explicit missing object code", status: http.StatusBadRequest, errorCode: "NoSuchKey"},
		{name: "transport failure", transport: true},
		{name: "nil error", wantDenied: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if tc.name != "nil error" {
				client := s3.New(s3.Options{
					Region: "us-east-1",
					Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
						return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, nil
					}),
					BaseEndpoint: aws.String("https://minio.example"),
					UsePathStyle: true,
					Retryer:      aws.NopRetryer{},
					HTTPClient: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						if tc.transport {
							return nil, errors.New("private transport details")
						}
						header := make(http.Header)
						var body io.ReadCloser = http.NoBody
						if tc.body {
							body = io.NopCloser(strings.NewReader("must not be inspected"))
						}
						if tc.errorCode != "" {
							header.Set("Content-Type", "application/xml")
							body = io.NopCloser(strings.NewReader(fmt.Sprintf(`<Error><Code>%s</Code><Message>irrelevant</Message></Error>`, tc.errorCode)))
						}
						return &http.Response{StatusCode: tc.status, Header: header, Body: body, Request: req}, nil
					}),
				})
				_, err = client.HeadObject(context.Background(), &s3.HeadObjectInput{Bucket: aws.String("fixture"), Key: aws.String("known-object")})
				if err == nil && !tc.wantSuccess {
					t.Fatalf("HEAD response unexpectedly succeeded; status=%d", tc.status)
				}
			}
			if got := isMinIOSSECustomerHeadDenial(err); got != tc.wantDenied {
				var responseErr *smithyhttp.ResponseError
				responseFound := errors.As(err, &responseErr)
				status := 0
				if responseFound {
					status = responseErr.HTTPStatusCode()
				}
				var apiErr smithy.APIError
				apiFound := errors.As(err, &apiErr)
				apiCode := ""
				if apiFound {
					apiCode = apiErr.ErrorCode()
				}
				t.Fatalf("HEAD denial classifier=%t, want %t; SDK error type=%T response_found=%t status=%d api_found=%t api_code=%q", got, tc.wantDenied, err, responseFound, status, apiFound, apiCode)
			}
		})
	}
}

func TestGH353MinioSSECustomerGETDenialRemainsStrict(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		code    string
		message string
		want    bool
	}{
		{name: "recognized key denial", status: http.StatusForbidden, code: "AccessDenied", message: "Access Denied", want: true},
		{name: "recognized key validation", status: http.StatusBadRequest, code: "InvalidRequest", message: "SSE-C customer key invalid", want: true},
		{name: "bodyless generic bad request", status: http.StatusBadRequest},
		{name: "unrelated explicit code", status: http.StatusBadRequest, code: "InvalidAccessKeyId", message: "Invalid access key"},
		{name: "unrelated invalid request", status: http.StatusBadRequest, code: "InvalidRequest", message: "Invalid bucket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := s3.New(s3.Options{
				Region: "us-east-1",
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, nil
				}),
				BaseEndpoint: aws.String("https://minio.example"), UsePathStyle: true,
				Retryer: aws.NopRetryer{},
				HTTPClient: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					if tc.code == "" {
						return &http.Response{StatusCode: tc.status, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
					}
					body := fmt.Sprintf(`<Error><Code>%s</Code><Message>%s</Message></Error>`, tc.code, tc.message)
					return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
				}),
			})
			_, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String("fixture"), Key: aws.String("known-object")})
			if err == nil {
				t.Fatal("GET error response unexpectedly succeeded")
			}
			if got := isMinIOSSECustomerKeyFailure(err); got != tc.want {
				t.Fatalf("strict GET classifier=%t, want %t", got, tc.want)
			}
		})
	}
}

func TestGH353MinioSSECustomerReadSDKWireHeaders(t *testing.T) {
	const customerKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	const customerMD5 = "1B2M2Y8AsgTpgAmY7PhCfg=="
	client := s3.New(s3.Options{
		Region: "us-east-1",
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, nil
		}),
		BaseEndpoint: aws.String("https://minio.example"),
		UsePathStyle: true,
		HTTPClient: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			if req.Header.Get("X-Amz-Server-Side-Encryption-Customer-Algorithm") != "AES256" || req.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key") != customerKey || req.Header.Get("X-Amz-Server-Side-Encryption-Customer-Key-Md5") != customerMD5 {
				t.Errorf("SDK request omitted SSE-C headers: %#v", req.Header)
			}
			header := http.Header{"Content-Length": []string{"5"}, "X-Amz-Server-Side-Encryption-Customer-Algorithm": []string{"AES256"}, "X-Amz-Server-Side-Encryption-Customer-Key-Md5": []string{customerMD5}}
			if req.Method == http.MethodHead {
				return &http.Response{StatusCode: http.StatusOK, Header: header, Body: http.NoBody, Request: req}, nil
			}
			if req.Header.Get("Range") != "bytes=1-5" {
				t.Errorf("SDK request omitted range header: %q", req.Header.Get("Range"))
			}
			return &http.Response{StatusCode: http.StatusPartialContent, Header: header, Body: io.NopCloser(strings.NewReader("bcdef")), Request: req}, nil
		}),
	})
	result, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket: aws.String("fixture"), Key: aws.String("object"), Range: aws.String("bytes=1-5"),
		SSECustomerAlgorithm: aws.String("AES256"), SSECustomerKey: aws.String(customerKey), SSECustomerKeyMD5: aws.String(customerMD5),
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(result.Body)
	closeErr := result.Body.Close()
	if err != nil || closeErr != nil || string(body) != "bcdef" {
		t.Fatalf("wire-fixture response body=%q err=%v close=%v", body, err, closeErr)
	}
	head, err := client.HeadObject(context.Background(), &s3.HeadObjectInput{
		Bucket: aws.String("fixture"), Key: aws.String("object"),
		SSECustomerAlgorithm: aws.String("AES256"), SSECustomerKey: aws.String(customerKey), SSECustomerKeyMD5: aws.String(customerMD5),
	})
	if err != nil || aws.ToInt64(head.ContentLength) != 5 || aws.ToString(head.SSECustomerAlgorithm) != "AES256" || aws.ToString(head.SSECustomerKeyMD5) != customerMD5 {
		t.Fatalf("SDK HEAD wire fixture result=%+v error=%v", head, err)
	}
}

func TestGH353MinioSSECustomerFailureSDKWireFixtures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		code    string
		message string
		want    bool
	}{
		{name: "key denial", status: http.StatusForbidden, code: "AccessDenied", message: "Access Denied", want: true},
		{name: "missing object", status: http.StatusNotFound, code: "NoSuchKey", message: "The specified key does not exist"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := s3.New(s3.Options{
				Region: "us-east-1",
				Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
					return aws.Credentials{AccessKeyID: "access", SecretAccessKey: "secret"}, nil
				}),
				BaseEndpoint: aws.String("https://minio.example"),
				UsePathStyle: true,
				HTTPClient: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					body := fmt.Sprintf("<Error><Code>%s</Code><Message>%s</Message></Error>", tc.code, tc.message)
					return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
				}),
			})
			_, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: aws.String("fixture"), Key: aws.String("object")})
			if err == nil {
				t.Fatal("expected SDK to return the fixture error response")
			}
			if got := isMinIOSSECustomerKeyFailure(err); got != tc.want {
				t.Fatalf("SDK response classified as key failure=%t, want %t (err=%v)", got, tc.want, err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) Do(req *http.Request) (*http.Response, error) { return f(req) }

func int64ptr(n int64) *int64 { return &n }
