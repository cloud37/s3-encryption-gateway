package provider

import (
	"context"
	"crypto/md5" // S3 SSE-C protocol checksum, not authentication.
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func init() {
	if os.Getenv("GATEWAY_TEST_SKIP_MINIO") == "" {
		Register(&minioProvider{})
	}
}

type minioProvider struct{ tlsReady bool }

// ObjectSSEStorageClass selects a class accepted by the pinned MinIO fixture.
// Other providers retain their own defaults and storage-class semantics.
func (p *minioProvider) ObjectSSEStorageClass(fixture *SSEFixture) string {
	if fixture == nil || fixture.KMSKeyID != "gh353-test" {
		return ""
	}
	return "STANDARD"
}

// renovate: datasource=docker depName=chainguard/minio versioning=docker
const minioImage = "chainguard/minio@sha256:de89cccd6cb19f505bf85c8a36f099414dc7a372c0e16abd2170ebaada9cc99f"

func (p *minioProvider) Name() string { return "minio" }
func (*minioProvider) LiteralPostRejection() LiteralPostRejection {
	return LiteralPostRejection{400, "XMinioInvalidResourceName", 500, "InternalError"}
}

func (*minioProvider) RequiresGH353LiteralRejectionProof() bool { return true }

func (p *minioProvider) Capabilities() Capabilities {
	// MinIO supports bucket policy and lifecycle round trips used by SEC47.
	caps := CapMultipartUpload |
		CapBucketManagement |
		CapBucketPolicy |
		CapBucketLifecycle |
		CapMultipartCopy |
		CapObjectTagging |
		CapInlinePutTagging |
		CapPresignedURL |
		CapConditionalWrites |
		CapBatchDelete |
		CapSizeTranslation |
		CapEncryptedMPU |
		CapKMSIntegration |
		CapOpenBaoKMS |
		CapLoadTest |
		CapSDKAWSGoV2 |
		CapSDKBoto3 |
		CapCLIAWSCLI |
		CapCLIS5cmd |
		CapCLIRclone |
		CapSDKMinIOPy |
		CapCLIRestic
	if p.tlsReady {
		caps |= CapBackendTLSFixture
	}
	return caps
}

func (p *minioProvider) CleanupPolicy() CleanupPolicy            { return CleanupPolicyDelete }
func (p *minioProvider) RequiresObjectSSEFixture() bool          { return true }
func (p *minioProvider) RequiresBackendCredentialIdentity() bool { return true }
func (p *minioProvider) IsDisposableLocalFixture() bool          { return true }
func (p *minioProvider) MatchesObjectSSEKMSIdentity(configured, returned string) bool {
	if configured == "" || returned == "" {
		return false
	}
	if configured == returned {
		return true
	}
	const canonicalPrefix = "arn:aws:kms:"
	return !strings.HasPrefix(configured, canonicalPrefix) && returned == canonicalPrefix+configured
}

func (p *minioProvider) BackendConfig(inst Instance) config.BackendConfig {
	cfg := config.BackendConfig{
		Endpoint:     inst.Endpoint,
		Region:       inst.Region,
		AccessKey:    inst.AccessKey,
		SecretKey:    inst.SecretKey,
		Provider:     "minio",
		UseSSL:       false,
		UsePathStyle: true,
	}
	if inst.BackendTLS != nil {
		cfg.Endpoint = inst.BackendTLS.Endpoint
		cfg.UseSSL = true
		cfg.TLS = config.BackendTLSConfig{CAFile: inst.BackendTLS.CAFile}
	}
	return cfg
}

func minioTLSMaterial(host string) (string, string, string, error) {
	now := time.Now()
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway test CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	server := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		server.IPAddresses = []net.IP{ip, net.ParseIP("127.0.0.1")}
	} else {
		server.DNSNames = append(server.DNSNames, host)
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(serverKey)
	if err != nil {
		return "", "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return string(caPEM), string(certPEM), string(keyPEM), nil
}

func (p *minioProvider) Start(ctx context.Context, t *testing.T) Instance {
	t.Helper()
	p.tlsReady = false
	// Keep the ordinary provider fixture plaintext for the existing conformance
	// matrix. The TLS fixture below is deliberately independent.
	plain, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image: minioImage, ExposedPorts: []string{"9000/tcp"},
			Cmd:        []string{"server", "/data"},
			WaitingFor: wait.ForHTTP("/minio/health/ready").WithPort("9000/tcp"),
			Env:        map[string]string{"MINIO_ROOT_USER": "minioadmin", "MINIO_ROOT_PASSWORD": "minioadmin"},
		}, Started: true,
	})
	if err != nil {
		t.Skipf("minio provider: failed to start HTTP fixture (Docker unavailable?): %v", err)
		return Instance{}
	}
	t.Cleanup(func() { _ = plain.Terminate(context.Background()) })
	plainHost, err := plain.Host(ctx)
	if err != nil {
		t.Skipf("minio provider: resolve HTTP host: %v", err)
		return Instance{}
	}
	plainPort, err := plain.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Skipf("minio provider: resolve HTTP port: %v", err)
		return Instance{}
	}
	plainInst := Instance{Endpoint: fmt.Sprintf("http://%s:%s", plainHost, plainPort.Port()), Region: "us-east-1", AccessKey: "minioadmin", SecretKey: "minioadmin", Bucket: fmt.Sprintf("conf-%s-%d", p.Name(), time.Now().UnixNano()), ProviderName: p.Name()}
	createBucketS3(ctx, t, plainInst)

	dockerProvider, err := tc.NewDockerProvider()
	if err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("Docker provider discovery", err)
		return plainInst
	}
	defer dockerProvider.Close()
	host, err := dockerProvider.DaemonHost(ctx)
	if err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("Docker host discovery", err)
		return plainInst
	}
	caPEM, certPEM, keyPEM, err := minioTLSMaterial(host)
	if err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("TLS certificate generation", err)
		return plainInst
	}
	keyPEMBuffer := []byte(keyPEM)
	defer func() {
		clear(keyPEMBuffer)
		keyPEM = ""
	}()
	certPEMBuffer := []byte(certPEM)
	defer clear(certPEMBuffer)
	staticKMSSecret, staticKMSBytes, err := newMinioStaticKMSSecret()
	if err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("disposable KMS secret generation", err)
		return plainInst
	}
	plainInst.MinIOObjectSSEAttempted = true
	clear(staticKMSBytes)
	kmsSecretBuffer := []byte(staticKMSSecret)
	defer func() {
		clear(kmsSecretBuffer)
		staticKMSSecret = ""
	}()
	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image: minioImage, ExposedPorts: []string{"9000/tcp"},
			// Chainguard's distroless image runs as nonroot, so the legacy
			// /root/.minio/certs location cannot hold this test-only fixture.
			Cmd:        []string{"--certs-dir", "/tmp/minio-certs", "server", "/data"},
			WaitingFor: wait.ForHTTP("/minio/health/ready").WithPort("9000/tcp").WithTLS(true, &tls.Config{InsecureSkipVerify: true}),                                                                                                                      // #nosec G402 -- test-only health probe for the generated self-signed fixture
			Files:      []tc.ContainerFile{{Reader: strings.NewReader(certPEM), ContainerFilePath: "/tmp/minio-certs/public.crt", FileMode: 0644}, {Reader: strings.NewReader(keyPEM), ContainerFilePath: "/tmp/minio-certs/private.key", FileMode: 0644}}, // #nosec G306 -- disposable container-only certificate/private key must be readable by its nonroot user; isolated fixture, never production key permissions
			Env: map[string]string{
				"MINIO_ROOT_USER":      "minioadmin",
				"MINIO_ROOT_PASSWORD":  "minioadmin",
				"MINIO_KMS_SECRET_KEY": string(kmsSecretBuffer),
			},
		}, Started: true,
	})
	if err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("container startup", err)
		staticKMSSecret = ""
		return plainInst
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	port, err := c.MappedPort(ctx, "9000/tcp")
	if err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("container mapped-port discovery", err)
		staticKMSSecret = ""
		return plainInst
	}
	// Keep the provider's normal endpoint plaintext so existing conformance
	// cases do not accidentally opt into the TLS fixture. The optional fixture
	// carries the HTTPS endpoint separately.
	tlsEndpoint := (&url.URL{Scheme: "https", Host: net.JoinHostPort(host, port.Port())}).String()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte(caPEM), 0600); err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("trusted CA file setup", err)
		staticKMSSecret = ""
		return plainInst
	}
	t.Cleanup(func() { _ = os.Remove(caFile) })

	tlsInst := Instance{
		Endpoint:     tlsEndpoint,
		Region:       "us-east-1",
		AccessKey:    "minioadmin",
		SecretKey:    "minioadmin",
		Bucket:       fmt.Sprintf("conf-%s-tls-%d", p.Name(), time.Now().UnixNano()),
		ProviderName: p.Name(),
		BackendTLS:   &TLSFixture{Endpoint: tlsEndpoint, CAFile: caFile},
	}
	// Only advertise the capability after the trusted TLS data path and bucket
	// initialization have succeeded. Starting a container alone is insufficient.
	if err := createBucketS3TLS(ctx, tlsInst); err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("trusted SDK TLS bucket initialization", err)
		staticKMSSecret = ""
		return plainInst
	}
	p.tlsReady = true
	tlsInst.BackendTLS.Bucket = tlsInst.Bucket
	tlsInst.BackendTLS.AccessKey = tlsInst.AccessKey
	tlsInst.BackendTLS.SecretKey = tlsInst.SecretKey
	plainInst.BackendTLS = tlsInst.BackendTLS
	objectSSE := &SSEFixture{Backend: *tlsInst.BackendTLS, KMSKeyID: "gh353-test"}
	if err := verifyMinioObjectSSE(ctx, tlsInst, objectSSE.KMSKeyID); err != nil {
		plainInst.ObjectSSEError = minioStaticKMSError("SDK capability verification", err)
		staticKMSSecret = ""
		return plainInst
	}
	objectSSE.Backend.Bucket = tlsInst.Bucket
	objectSSE.Backend.AccessKey = tlsInst.AccessKey
	objectSSE.Backend.SecretKey = tlsInst.SecretKey
	plainInst.ObjectSSE = objectSSE
	staticKMSSecret = ""
	return plainInst
}

func minioStaticKMSError(stage string, err error) string {
	// Provider diagnostics are deliberately concise and stage-oriented. Docker
	// errors can serialize the complete create request, including fixture secrets.
	detail := minioSafeSSEFailure(err)
	return fmt.Sprintf("MinIO static KMS fixture %s failed (static-key support or configuration may be unavailable): %s", stage, detail)
}

func minioSafeSSEFailure(err error) string {
	if err == nil {
		return "underlying operation failed (category: unknown)"
	}
	var probeFailure *minioSSEProbeFailure
	if errors.As(err, &probeFailure) {
		return probeFailure.Error()
	}
	var responseErr *smithyhttp.ResponseError
	if errors.As(err, &responseErr) {
		code := ""
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			code = minioAllowlistedSSEErrorCode(apiErr.ErrorCode())
		}
		if code == "" {
			return fmt.Sprintf("SDK request failed (failure_kind=API response; HTTP status %d; AWS error code unclassified)", responseErr.HTTPStatusCode())
		}
		return fmt.Sprintf("SDK request failed (failure_kind=API response; HTTP status %d; AWS error code %s)", responseErr.HTTPStatusCode(), code)
	}
	return fmt.Sprintf("underlying operation failed (category: %s)", minioStaticKMSErrorCategory(err))
}

func minioStaticKMSErrorCategory(err error) string {
	if err == nil {
		return "unknown"
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "permission"), strings.Contains(message, "denied"):
		return "permission"
	case strings.Contains(message, "timeout"), strings.Contains(message, "deadline"):
		return "timeout"
	case strings.Contains(message, "connection refused"), strings.Contains(message, "no such host"), strings.Contains(message, "unreachable"):
		return "connectivity"
	case strings.Contains(message, "not found"), strings.Contains(message, "no such container"):
		return "not-found"
	default:
		return "runtime"
	}
}

func newMinioStaticKMSSecret() (string, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		clear(key)
		return "", nil, err
	}
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(key)))
	base64.StdEncoding.Encode(encoded, key)
	secret := "gh353-test:" + string(encoded)
	clear(encoded)
	return secret, key, nil
}

// createBucketS3 creates the bucket named in inst.Bucket using the AWS SDK v2.
// It is a shared helper used by all provider implementations that need to
// pre-create their test bucket.
func createBucketS3(ctx context.Context, t *testing.T, inst Instance) {
	t.Helper()
	if err := createBucketS3TLS(ctx, inst); err != nil {
		t.Fatalf("createBucketS3: %v", err)
	}
}

func createBucketS3TLS(ctx context.Context, inst Instance) error {
	var transport *http.Transport
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(inst.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, "")),
	}
	if inst.BackendTLS != nil {
		roots := x509.NewCertPool()
		data, err := os.ReadFile(inst.BackendTLS.CAFile)
		if err != nil {
			return fmt.Errorf("read CA: %w", err)
		}
		if !roots.AppendCertsFromPEM(data) {
			return fmt.Errorf("invalid CA")
		}
		transport = http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		loadOpts = append(loadOpts, awsconfig.WithHTTPClient(&http.Client{Transport: transport}))
	}
	if transport != nil {
		defer transport.CloseIdleConnections()
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	svc := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(inst.Endpoint)
		o.UsePathStyle = true
	})

	_, err = svc.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: aws.String(inst.Bucket),
	})
	if err != nil {
		return fmt.Errorf("create bucket %q: %w", inst.Bucket, err)
	}
	return nil
}

// verifyMinioObjectSSE uses AWS SDK requests over the trusted generated CA.
// No fixture is published until every mode, response header, data read, and
// customer-key rejection has been observed against the live MinIO container.
func verifyMinioObjectSSE(ctx context.Context, inst Instance, kmsKeyID string) (resultErr error) {
	stage := "trusted SDK configuration"
	defer func() {
		if resultErr == nil {
			return
		}
		var probeFailure *minioSSEProbeFailure
		if errors.As(resultErr, &probeFailure) {
			return
		}
		resultErr = minioSSELocalError(stage, resultErr)
	}()
	if inst.BackendTLS == nil || kmsKeyID == "" {
		stage = "fixture precondition"
		return fmt.Errorf("trusted HTTPS backend and KMS key identifier are required")
	}
	roots := x509.NewCertPool()
	stage = "trusted CA read"
	ca, err := os.ReadFile(inst.BackendTLS.CAFile)
	if err != nil {
		return fmt.Errorf("read generated CA: %w", err)
	}
	if !roots.AppendCertsFromPEM(ca) {
		stage = "trusted CA validation"
		return fmt.Errorf("generated CA is invalid")
	}
	stage = "trusted SDK configuration"
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	defer transport.CloseIdleConnections()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(inst.Region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, "")),
		awsconfig.WithHTTPClient(&http.Client{Transport: transport}),
	)
	if err != nil {
		return fmt.Errorf("load trusted SDK configuration: %w", err)
	}
	svc := s3.NewFromConfig(awsCfg, func(options *s3.Options) {
		options.BaseEndpoint = aws.String(inst.BackendTLS.Endpoint)
		options.UsePathStyle = true
	})

	type testObject struct {
		name, data string
		put        *s3.PutObjectInput
		get        *s3.GetObjectInput
	}
	plainText := "gh353 verified SSE provider bytes"
	objects := []testObject{
		{name: "sse-s3", data: plainText, put: &s3.PutObjectInput{ServerSideEncryption: types.ServerSideEncryptionAes256}},
		{name: "sse-kms", data: plainText, put: &s3.PutObjectInput{ServerSideEncryption: types.ServerSideEncryptionAwsKms, SSEKMSKeyId: aws.String(kmsKeyID)}},
	}
	customerKey := make([]byte, 32)
	stage = "SSE-C key generation"
	if _, err := rand.Read(customerKey); err != nil {
		return err
	}
	defer clear(customerKey)
	keyBase64Buffer := make([]byte, base64.StdEncoding.EncodedLen(len(customerKey)))
	base64.StdEncoding.Encode(keyBase64Buffer, customerKey)
	keyBase64 := string(keyBase64Buffer)
	defer clear(keyBase64Buffer)
	keyMD5 := md5.Sum(customerKey)
	keyMD5Buffer := make([]byte, base64.StdEncoding.EncodedLen(len(keyMD5)))
	base64.StdEncoding.Encode(keyMD5Buffer, keyMD5[:])
	keyMD5Base64 := string(keyMD5Buffer)
	defer clear(keyMD5Buffer)
	defer clear(keyMD5[:])
	customerPut := &s3.PutObjectInput{
		SSECustomerAlgorithm: aws.String("AES256"),
		SSECustomerKey:       aws.String(keyBase64),
		SSECustomerKeyMD5:    aws.String(keyMD5Base64),
	}
	customerGet := &s3.GetObjectInput{
		SSECustomerAlgorithm: aws.String("AES256"), SSECustomerKey: aws.String(keyBase64), SSECustomerKeyMD5: aws.String(keyMD5Base64),
	}
	defer func() {
		keyBase64 = ""
		keyMD5Base64 = ""
		customerPut.SSECustomerKey = nil
		customerPut.SSECustomerKeyMD5 = nil
		customerGet.SSECustomerKey = nil
		customerGet.SSECustomerKeyMD5 = nil
	}()
	objects = append(objects, testObject{name: "sse-c", data: plainText, put: customerPut, get: customerGet})
	for _, object := range objects {
		stage = object.name + " PUT"
		key := fmt.Sprintf("gh353-provider-sse/%s-%d", object.name, time.Now().UnixNano())
		defer func(key string) {
			_, _ = svc.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
		}(key)
		input := *object.put
		input.Bucket, input.Key, input.Body = aws.String(inst.Bucket), aws.String(key), strings.NewReader(object.data)
		putResult, err := svc.PutObject(ctx, &input)
		if err != nil {
			return minioSSEOperationError(object.name, "PUT", err)
		}
		if err := validateMinioSSEPutResponse(object.name, putResult, kmsKeyID); err != nil {
			return err
		}
		if object.name == "sse-c" && !minioSSECustomerResponseMatches(aws.ToString(putResult.SSECustomerAlgorithm), aws.ToString(putResult.SSECustomerKeyMD5), keyMD5Base64) {
			return minioSSEAssertionFailure(object.name, "PUT", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_matches=false")
		}
		stage = object.name + " GET"
		getInput := &s3.GetObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)}
		if object.get != nil {
			getInput.SSECustomerAlgorithm = object.get.SSECustomerAlgorithm
			getInput.SSECustomerKey = object.get.SSECustomerKey
			getInput.SSECustomerKeyMD5 = object.get.SSECustomerKeyMD5
		}
		getResult, err := svc.GetObject(ctx, getInput)
		if err != nil {
			return minioSSEOperationError(object.name, "GET", err)
		}
		if getResult == nil || getResult.Body == nil {
			return minioSSEAssertionFailure(object.name, "GET", "missing-response-body")
		}
		actual, readErr := io.ReadAll(getResult.Body)
		closeErr := getResult.Body.Close()
		if readErr != nil || closeErr != nil {
			clear(actual)
			return minioSSEBodyTransportFailure(object.name, "GET", readErr, closeErr)
		}
		dataMatches := subtle.ConstantTimeCompare(actual, []byte(object.data)) == 1
		clear(actual)
		if !dataMatches {
			return minioSSEAssertionFailure(object.name, "GET", "body-content-mismatch")
		}
		if err := validateMinioSSEGetResponse(object.name, getResult, kmsKeyID); err != nil {
			return err
		}
		if object.name == "sse-c" && !minioSSECustomerResponseMatches(aws.ToString(getResult.SSECustomerAlgorithm), aws.ToString(getResult.SSECustomerKeyMD5), keyMD5Base64) {
			return minioSSEAssertionFailure(object.name, "GET", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_matches=false")
		}
		stage = object.name + " ranged GET"
		rangeInput := *getInput
		rangeInput.Range = aws.String("bytes=1-5")
		ranged, err := svc.GetObject(ctx, &rangeInput)
		if err != nil {
			return minioSSEOperationError(object.name, "ranged GET", err)
		}
		if ranged == nil || ranged.Body == nil {
			return minioSSEAssertionFailure(object.name, "ranged GET", "missing-response-body")
		}
		rangeBytes, rangeReadErr := io.ReadAll(ranged.Body)
		rangeCloseErr := ranged.Body.Close()
		if rangeReadErr != nil || rangeCloseErr != nil {
			clear(rangeBytes)
			return minioSSEBodyTransportFailure(object.name, "ranged GET", rangeReadErr, rangeCloseErr)
		}
		if string(rangeBytes) != object.data[1:6] {
			clear(rangeBytes)
			return minioSSEAssertionFailure(object.name, "ranged GET", "range-content-mismatch", "range_bytes_match=false")
		}
		clear(rangeBytes)
		if err := validateMinioSSEGetResponse(object.name, ranged, kmsKeyID); err != nil {
			return err
		}
		if object.name == "sse-c" && !minioSSECustomerResponseMatches(aws.ToString(ranged.SSECustomerAlgorithm), aws.ToString(ranged.SSECustomerKeyMD5), keyMD5Base64) {
			return minioSSEAssertionFailure(object.name, "ranged GET", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_matches=false")
		}
		stage = object.name + " HEAD"
		headInput := &s3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)}
		if object.get != nil {
			headInput.SSECustomerAlgorithm = object.get.SSECustomerAlgorithm
			headInput.SSECustomerKey = object.get.SSECustomerKey
			headInput.SSECustomerKeyMD5 = object.get.SSECustomerKeyMD5
		}
		headResult, err := svc.HeadObject(ctx, headInput)
		if err != nil {
			return minioSSEOperationError(object.name, "HEAD", err)
		}
		if headResult == nil {
			return minioSSEAssertionFailure(object.name, "HEAD", "missing-success-response")
		}
		if aws.ToInt64(headResult.ContentLength) != int64(len(object.data)) {
			return minioSSEAssertionFailure(object.name, "HEAD", "content-length-mismatch", "content_length_matches=false")
		}
		if err := validateMinioSSEHeadResponse(object.name, headResult, kmsKeyID); err != nil {
			return err
		}
		if object.name == "sse-c" && !minioSSECustomerResponseMatches(aws.ToString(headResult.SSECustomerAlgorithm), aws.ToString(headResult.SSECustomerKeyMD5), keyMD5Base64) {
			return minioSSEAssertionFailure(object.name, "HEAD", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_matches=false")
		}
		if object.name == "sse-c" {
			stage = "SSE-C GET without customer key"
			missingGet, missingGetErr := svc.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
			if missingGetErr == nil {
				if missingGet != nil && missingGet.Body != nil {
					_ = missingGet.Body.Close()
				}
				return minioSSEAssertionFailure("SSE-C", "GET without customer key", "unexpected-success")
			}
			if !isMinIOSSECustomerKeyFailure(missingGetErr) {
				return minioSSEOperationError("SSE-C", "GET without customer key", missingGetErr)
			}
			wrong := make([]byte, 32)
			stage = "SSE-C wrong-key generation"
			if _, err := rand.Read(wrong); err != nil {
				return err
			}
			defer clear(wrong)
			wrongMD5 := md5.Sum(wrong)
			wrongBase64Buffer := make([]byte, base64.StdEncoding.EncodedLen(len(wrong)))
			base64.StdEncoding.Encode(wrongBase64Buffer, wrong)
			wrongBase64 := string(wrongBase64Buffer)
			wrongMD5Buffer := make([]byte, base64.StdEncoding.EncodedLen(len(wrongMD5)))
			base64.StdEncoding.Encode(wrongMD5Buffer, wrongMD5[:])
			wrongMD5Base64 := string(wrongMD5Buffer)
			wrongBase64Copy := []byte(wrongBase64)
			wrongMD5Base64Copy := []byte(wrongMD5Base64)
			stage = "SSE-C GET with wrong customer key"
			wrongGet, wrongErr := svc.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key), SSECustomerAlgorithm: aws.String("AES256"), SSECustomerKey: aws.String(wrongBase64), SSECustomerKeyMD5: aws.String(wrongMD5Base64)})
			clear(wrong)
			clear(wrongMD5[:])
			wrongBase64 = ""
			wrongMD5Base64 = ""
			clear(wrongBase64Buffer)
			clear(wrongMD5Buffer)
			clear(wrongBase64Copy)
			clear(wrongMD5Base64Copy)
			if wrongErr == nil {
				if wrongGet != nil && wrongGet.Body != nil {
					_ = wrongGet.Body.Close()
				}
				return minioSSEAssertionFailure("SSE-C", "GET with wrong customer key", "unexpected-success")
			}
			if !isMinIOSSECustomerKeyFailure(wrongErr) {
				return minioSSEOperationError("SSE-C", "GET with wrong customer key", wrongErr)
			}
			stage = "SSE-C HEAD without customer key"
			_, missingHeadErr := svc.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key)})
			if !isMinIOSSECustomerHeadDenial(missingHeadErr) {
				if missingHeadErr == nil {
					return minioSSEAssertionFailure("SSE-C", "HEAD without customer key", "unexpected-success")
				}
				return minioSSEOperationError("SSE-C", "HEAD without customer key", missingHeadErr)
			}
			wrongHead := make([]byte, 32)
			stage = "SSE-C wrong-key HEAD generation"
			if _, err := rand.Read(wrongHead); err != nil {
				return err
			}
			defer clear(wrongHead)
			wrongHeadMD5 := md5.Sum(wrongHead)
			wrongHeadBase64Buffer := make([]byte, base64.StdEncoding.EncodedLen(len(wrongHead)))
			base64.StdEncoding.Encode(wrongHeadBase64Buffer, wrongHead)
			wrongHeadBase64 := string(wrongHeadBase64Buffer)
			wrongHeadMD5Buffer := make([]byte, base64.StdEncoding.EncodedLen(len(wrongHeadMD5)))
			base64.StdEncoding.Encode(wrongHeadMD5Buffer, wrongHeadMD5[:])
			wrongHeadMD5Base64 := string(wrongHeadMD5Buffer)
			wrongHeadBase64Copy := []byte(wrongHeadBase64)
			wrongHeadMD5Base64Copy := []byte(wrongHeadMD5Base64)
			stage = "SSE-C HEAD with wrong customer key"
			_, wrongHeadErr := svc.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(key), SSECustomerAlgorithm: aws.String("AES256"), SSECustomerKey: aws.String(wrongHeadBase64), SSECustomerKeyMD5: aws.String(wrongHeadMD5Base64)})
			clear(wrongHead)
			clear(wrongHeadMD5[:])
			wrongHeadBase64 = ""
			wrongHeadMD5Base64 = ""
			clear(wrongHeadBase64Buffer)
			clear(wrongHeadMD5Buffer)
			clear(wrongHeadBase64Copy)
			clear(wrongHeadMD5Base64Copy)
			if !isMinIOSSECustomerHeadDenial(wrongHeadErr) {
				if wrongHeadErr == nil {
					return minioSSEAssertionFailure("SSE-C", "HEAD with wrong customer key", "unexpected-success")
				}
				return minioSSEOperationError("SSE-C", "HEAD with wrong customer key", wrongHeadErr)
			}
			stage = "SSE-C correct-key GET after rejection checks"
			readAfterDenials, readAfterDenialsErr := svc.GetObject(ctx, getInput)
			if readAfterDenialsErr != nil {
				return minioSSEOperationError("SSE-C", "GET after rejection checks", readAfterDenialsErr)
			}
			if readAfterDenials == nil || readAfterDenials.Body == nil {
				return minioSSEAssertionFailure("SSE-C", "GET after rejection checks", "missing-response-body")
			}
			readAfterDenialsBytes, readAfterDenialsReadErr := io.ReadAll(readAfterDenials.Body)
			readAfterDenialsCloseErr := readAfterDenials.Body.Close()
			readAfterDenialsMatch := subtle.ConstantTimeCompare(readAfterDenialsBytes, []byte(object.data)) == 1
			clear(readAfterDenialsBytes)
			if readAfterDenialsReadErr != nil || readAfterDenialsCloseErr != nil || !readAfterDenialsMatch {
				if readAfterDenialsReadErr != nil || readAfterDenialsCloseErr != nil {
					return minioSSEBodyTransportFailure("SSE-C", "GET after rejection checks", readAfterDenialsReadErr, readAfterDenialsCloseErr)
				}
				return minioSSEAssertionFailure("SSE-C", "GET after rejection checks", "body-read-or-content-mismatch", "read_category="+minioSafeTransportCategory(readAfterDenialsReadErr), "close_category="+minioSafeTransportCategory(readAfterDenialsCloseErr), fmt.Sprintf("body_matches=%t", readAfterDenialsMatch))
			}
			if err := validateMinioSSEGetResponse("SSE-C", readAfterDenials, kmsKeyID); err != nil {
				return err
			}
			if !minioSSECustomerResponseMatches(aws.ToString(readAfterDenials.SSECustomerAlgorithm), aws.ToString(readAfterDenials.SSECustomerKeyMD5), keyMD5Base64) {
				return minioSSEAssertionFailure("SSE-C", "GET after rejection checks", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_matches=false")
			}
			stage = "SSE-C correct-key HEAD after rejection checks"
			headAfterDenials, headAfterDenialsErr := svc.HeadObject(ctx, headInput)
			if headAfterDenialsErr != nil {
				return minioSSEOperationError("SSE-C", "HEAD after rejection checks", headAfterDenialsErr)
			}
			if headAfterDenials == nil || aws.ToInt64(headAfterDenials.ContentLength) != int64(len(object.data)) {
				return minioSSEAssertionFailure("SSE-C", "HEAD after rejection checks", "content-length-mismatch", "content_length_matches=false")
			}
			if err := validateMinioSSEHeadResponse("SSE-C", headAfterDenials, kmsKeyID); err != nil {
				return err
			}
			if !minioSSECustomerResponseMatches(aws.ToString(headAfterDenials.SSECustomerAlgorithm), aws.ToString(headAfterDenials.SSECustomerKeyMD5), keyMD5Base64) {
				return minioSSEAssertionFailure("SSE-C", "HEAD after rejection checks", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_matches=false")
			}
		}
	}
	return nil
}

func validateMinioSSEPutResponse(mode string, result *s3.PutObjectOutput, configuredKMSKey string) error {
	if result == nil {
		return minioSSEAssertionFailure(mode, "PUT", "missing-success-response")
	}
	switch mode {
	case "sse-s3":
		if result.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return minioSSEAssertionFailure(mode, "PUT", "sse-algorithm-mismatch", "returned_algorithm="+minioSafeSSEAlgorithm(string(result.ServerSideEncryption)))
		}
	case "sse-kms":
		algorithmMatches := result.ServerSideEncryption == types.ServerSideEncryptionAwsKms
		identity := minioKMSIdentityRelation(configuredKMSKey, aws.ToString(result.SSEKMSKeyId))
		if !algorithmMatches {
			return minioSSEAssertionFailure(mode, "PUT", "sse-algorithm-mismatch", fmt.Sprintf("algorithm_matches=%t", algorithmMatches), identity)
		}
		if !minioKMSIdentityMatches(configuredKMSKey, aws.ToString(result.SSEKMSKeyId)) {
			return minioSSEAssertionFailure(mode, "PUT", "kms-identity-mismatch", identity)
		}
	case "sse-c":
		if !minioSSECustomerResponseMatches(aws.ToString(result.SSECustomerAlgorithm), aws.ToString(result.SSECustomerKeyMD5), "") {
			return minioSSEAssertionFailure(mode, "PUT", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_present=false")
		}
	}
	return nil
}

func validateMinioSSEGetResponse(mode string, result *s3.GetObjectOutput, configuredKMSKey string) error {
	if result == nil {
		return minioSSEAssertionFailure(mode, "GET", "missing-success-response")
	}
	switch mode {
	case "sse-s3":
		if result.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return minioSSEAssertionFailure(mode, "GET", "sse-algorithm-mismatch", "returned_algorithm="+minioSafeSSEAlgorithm(string(result.ServerSideEncryption)))
		}
	case "sse-kms":
		algorithmMatches := result.ServerSideEncryption == types.ServerSideEncryptionAwsKms
		identity := minioKMSIdentityRelation(configuredKMSKey, aws.ToString(result.SSEKMSKeyId))
		if !algorithmMatches {
			return minioSSEAssertionFailure(mode, "GET", "sse-algorithm-mismatch", fmt.Sprintf("algorithm_matches=%t", algorithmMatches), identity)
		}
		if !minioKMSIdentityMatches(configuredKMSKey, aws.ToString(result.SSEKMSKeyId)) {
			return minioSSEAssertionFailure(mode, "GET", "kms-identity-mismatch", identity)
		}
	case "sse-c":
		if !minioSSECustomerResponseMatches(aws.ToString(result.SSECustomerAlgorithm), aws.ToString(result.SSECustomerKeyMD5), "") {
			return minioSSEAssertionFailure(mode, "GET", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_present=false")
		}
	}
	return nil
}

func validateMinioSSEHeadResponse(mode string, result *s3.HeadObjectOutput, configuredKMSKey string) error {
	if result == nil {
		return minioSSEAssertionFailure(mode, "HEAD", "missing-success-response")
	}
	switch mode {
	case "sse-s3":
		if result.ServerSideEncryption != types.ServerSideEncryptionAes256 {
			return minioSSEAssertionFailure(mode, "HEAD", "sse-algorithm-mismatch", "returned_algorithm="+minioSafeSSEAlgorithm(string(result.ServerSideEncryption)))
		}
	case "sse-kms":
		algorithmMatches := result.ServerSideEncryption == types.ServerSideEncryptionAwsKms
		identity := minioKMSIdentityRelation(configuredKMSKey, aws.ToString(result.SSEKMSKeyId))
		if !algorithmMatches {
			return minioSSEAssertionFailure(mode, "HEAD", "sse-algorithm-mismatch", fmt.Sprintf("algorithm_matches=%t", algorithmMatches), identity)
		}
		if !minioKMSIdentityMatches(configuredKMSKey, aws.ToString(result.SSEKMSKeyId)) {
			return minioSSEAssertionFailure(mode, "HEAD", "kms-identity-mismatch", identity)
		}
	case "sse-c":
		if !minioSSECustomerResponseMatches(aws.ToString(result.SSECustomerAlgorithm), aws.ToString(result.SSECustomerKeyMD5), "") {
			return minioSSEAssertionFailure(mode, "HEAD", "sse-c-response-mismatch", "algorithm_matches=false", "key_checksum_present=false")
		}
	}
	return nil
}

func minioSSECustomerResponseMatches(algorithm, checksum, expectedChecksum string) bool {
	return algorithm == "AES256" && checksum != "" && (expectedChecksum == "" || checksum == expectedChecksum)
}

func minioKMSIdentityRelation(configured, returned string) string {
	if returned == "" {
		return "identity_matches=false returned_identity=empty"
	}
	configuredARN := strings.HasPrefix(configured, "arn:")
	returnedARN := strings.HasPrefix(returned, "arn:")
	if configured == returned {
		return fmt.Sprintf("identity_matches=true configured_is_arn=%t returned_is_arn=%t", configuredARN, returnedARN)
	}
	return fmt.Sprintf("identity_matches=false configured_is_arn=%t returned_is_arn=%t", configuredARN, returnedARN)
}

func minioKMSIdentityMatches(configured, returned string) bool {
	inst := Instance{ProviderName: (&minioProvider{}).Name()}
	return ObjectSSEKMSIdentityMatches(inst, configured, returned)
}

func minioSafeSSEAlgorithm(value string) string {
	switch value {
	case "AES256", "aws:kms", "aws:kms:dsse":
		return value
	case "":
		return "empty"
	default:
		return "other"
	}
}

func minioSSEAssertionFailure(mode, operation, assertion string, flags ...string) error {
	message := fmt.Sprintf("%s %s successful response failed assertion (%s)", mode, operation, assertion)
	for _, flag := range flags {
		message += "; " + flag
	}
	return &minioSSEProbeFailure{mode: mode, operation: operation, assertion: message}
}

func minioSafeTransportCategory(err error) string {
	if err == nil {
		return "none"
	}
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return minioSafeTransportCategory(urlErr.Err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "timeout"
		}
		return "network"
	}
	var certErr x509.UnknownAuthorityError
	if errors.As(err, &certErr) {
		return "tls-unknown-authority"
	}
	var invalidCertErr x509.CertificateInvalidError
	if errors.As(err, &invalidCertErr) {
		return "tls-certificate-invalid"
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return "tls-hostname"
	}
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) {
		return "tls-record"
	}
	var hostErr *net.DNSError
	if errors.As(err, &hostErr) {
		return "dns"
	}
	return "runtime"
}

func minioSSEOperationError(mode, operation string, err error) error {
	if err == nil {
		return &minioSSEProbeFailure{mode: mode, operation: operation, category: "unknown", failureKind: "SDK request"}
	}
	status := 0
	var responseErr *smithyhttp.ResponseError
	if errors.As(err, &responseErr) {
		status = responseErr.HTTPStatusCode()
	}
	code := ""
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		code = minioAllowlistedSSEErrorCode(apiErr.ErrorCode())
	}
	if responseErr != nil && status > 0 {
		return &minioSSEProbeFailure{mode: mode, operation: operation, status: status, code: code, category: "api", failureKind: "API response"}
	}
	return &minioSSEProbeFailure{mode: mode, operation: operation, status: status, code: code, category: minioSafeTransportCategory(err), failureKind: "transport"}
}

func minioSSELocalError(stage string, err error) error {
	return &minioSSEProbeFailure{mode: "fixture", operation: stage, category: minioSafeTransportCategory(err), failureKind: "local setup"}
}

func minioSSEBodyTransportFailure(mode, operation string, readErr, closeErr error) error {
	category := "none"
	if readErr != nil {
		category = minioSafeTransportCategory(readErr)
	}
	if closeErr != nil {
		closeCategory := minioSafeTransportCategory(closeErr)
		if category == "none" {
			category = closeCategory
		} else {
			category += "+" + closeCategory
		}
	}
	return &minioSSEProbeFailure{mode: mode, operation: operation + " body", category: category, failureKind: "transport"}
}

type minioSSEProbeFailure struct {
	mode, operation string
	status          int
	code            string
	category        string
	assertion       string
	failureKind     string
}

func (e *minioSSEProbeFailure) Error() string {
	if e == nil {
		return "ObjectSSE probe failed (category: unknown)"
	}
	if e.assertion != "" {
		return e.assertion
	}
	kind := e.failureKind
	if kind == "" {
		kind = "transport"
	}
	if e.status != 0 || e.code != "" {
		if e.status == 0 {
			return fmt.Sprintf("%s %s failed (failure_kind=%s; AWS error code %s)", e.mode, e.operation, kind, e.code)
		}
		if e.code == "" {
			return fmt.Sprintf("%s %s failed (failure_kind=%s; HTTP status %d; AWS error code unclassified)", e.mode, e.operation, kind, e.status)
		}
		return fmt.Sprintf("%s %s failed (failure_kind=%s; HTTP status %d; AWS error code %s)", e.mode, e.operation, kind, e.status, e.code)
	}
	category := e.category
	if category == "" {
		category = "unknown"
	}
	return fmt.Sprintf("%s %s failed (failure_kind=%s; category=%s)", e.mode, e.operation, kind, category)
}

func minioAllowlistedSSEErrorCode(code string) string {
	switch code {
	case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "InvalidRequest", "NotImplemented", "NotSupported", "NoSuchBucket", "NoSuchKey", "InvalidArgument", "InternalError", "SlowDown", "RequestTimeout", "XMinioKMSNotConfigured", "KMSNotConfigured", "KMSConfigNotFound", "InvalidEncryptionAlgorithmError":
		return code
	default:
		return ""
	}
}

func validateMinioHeadResult(result *s3.HeadObjectOutput, err error, expectedLength int64) error {
	if err != nil {
		return fmt.Errorf("request failed")
	}
	if result == nil {
		return fmt.Errorf("response was empty")
	}
	if aws.ToInt64(result.ContentLength) != expectedLength {
		return fmt.Errorf("content length did not match")
	}
	return nil
}

func isMinIOSSECustomerKeyFailure(err error) bool {
	if err == nil {
		return false
	}
	var response *smithyhttp.ResponseError
	if !errors.As(err, &response) || response.Response == nil || response.Response.Response == nil {
		return false
	}
	if status := response.HTTPStatusCode(); status != http.StatusBadRequest && status != http.StatusForbidden {
		return false
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "AccessDenied":
		return response.HTTPStatusCode() == http.StatusForbidden
	case "InvalidRequest":
		if response.HTTPStatusCode() != http.StatusBadRequest {
			return false
		}
		message := strings.ToLower(apiErr.ErrorMessage())
		return strings.Contains(message, "sse-c") || strings.Contains(message, "customer") || strings.Contains(message, "server side encryption")
	default:
		return false
	}
}

// isMinIOSSECustomerHeadDenial is deliberately scoped to the isolated fixture's
// already-verified object and credential/TLS path. S3 HEAD errors have no
// response body, so unlike GET they can expose only generic 400/403 status
// evidence (https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html).
// The caller proves the object first with correct-key HEAD and again with
// correct-key GET/HEAD after both denials; explicit unrelated AWS codes remain
// disqualifying, while no arbitrary body or raw error detail is inspected.
func isMinIOSSECustomerHeadDenial(err error) bool {
	if err == nil {
		return false
	}
	var response *smithyhttp.ResponseError
	if !errors.As(err, &response) || response.Response == nil || response.Response.Response == nil {
		return false
	}
	status := response.HTTPStatusCode()
	if status != http.StatusBadRequest && status != http.StatusForbidden {
		return false
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return true
	}
	switch apiErr.ErrorCode() {
	case "", "BadRequest":
		return status == http.StatusBadRequest
	case "AccessDenied", "Forbidden":
		return status == http.StatusForbidden
	case "InvalidRequest":
		return status == http.StatusBadRequest
	case "InvalidAccessKeyId", "SignatureDoesNotMatch", "NoSuchBucket", "NoSuchKey", "InvalidArgument", "NotImplemented", "NotSupported", "InternalError", "SlowDown", "RequestTimeout":
		return false
	default:
		// Unknown codes are not interpreted as proof; status plus the surrounding
		// correct-key object checks are the only evidence available on HEAD.
		return false
	}
}
