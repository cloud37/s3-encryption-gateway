package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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

// renovate: datasource=docker depName=minio/minio versioning=docker
const minioImage = "minio/minio:RELEASE.2024-11-07T00-52-20Z"

func (p *minioProvider) Name() string { return "minio" }

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

func (p *minioProvider) CleanupPolicy() CleanupPolicy { return CleanupPolicyDelete }

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
		t.Skipf("minio backend TLS fixture: resolve Docker host: %v", err)
		return Instance{}
	}
	defer dockerProvider.Close()
	host, err := dockerProvider.DaemonHost(ctx)
	if err != nil {
		t.Skipf("minio backend TLS fixture: resolve Docker host: %v", err)
		return Instance{}
	}
	caPEM, certPEM, keyPEM, err := minioTLSMaterial(host)
	if err != nil {
		t.Skipf("minio backend TLS fixture: generate certificate: %v", err)
		return Instance{}
	}
	c, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image: minioImage, ExposedPorts: []string{"9000/tcp"},
			Cmd:        []string{"server", "/data"},
			WaitingFor: wait.ForHTTP("/minio/health/ready").WithPort("9000/tcp").WithTLS(true, &tls.Config{InsecureSkipVerify: true}), // #nosec G402 -- test-only health probe for the generated self-signed fixture
			Files:      []tc.ContainerFile{{Reader: strings.NewReader(certPEM), ContainerFilePath: "/root/.minio/certs/public.crt", FileMode: 0600}, {Reader: strings.NewReader(keyPEM), ContainerFilePath: "/root/.minio/certs/private.key", FileMode: 0600}},
			Env: map[string]string{
				"MINIO_ROOT_USER":     "minioadmin",
				"MINIO_ROOT_PASSWORD": "minioadmin",
			},
		}, Started: true,
	})
	if err != nil {
		t.Skipf("minio provider: failed to start container (Docker unavailable?): %v", err)
		return Instance{}
	}
	t.Cleanup(func() { _ = c.Terminate(context.Background()) })

	port, err := c.MappedPort(ctx, "9000/tcp")
	if err != nil {
		t.Skipf("minio backend TLS fixture: resolve mapped port: %v", err)
		return Instance{}
	}
	// Keep the provider's normal endpoint plaintext so existing conformance
	// cases do not accidentally opt into the TLS fixture. The optional fixture
	// carries the HTTPS endpoint separately.
	address := fmt.Sprintf("%s:%s", host, port.Port())
	tlsEndpoint := "https://" + address
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, []byte(caPEM), 0600); err != nil {
		t.Skipf("minio backend TLS fixture: write CA: %v", err)
		return Instance{}
	}

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
		t.Skipf("minio backend TLS fixture: initialize bucket through trusted TLS client: %v", err)
		return Instance{}
	}
	p.tlsReady = true
	tlsInst.BackendTLS.Bucket = tlsInst.Bucket
	tlsInst.BackendTLS.AccessKey = tlsInst.AccessKey
	tlsInst.BackendTLS.SecretKey = tlsInst.SecretKey
	plainInst.BackendTLS = tlsInst.BackendTLS
	return plainInst
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
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		loadOpts = append(loadOpts, awsconfig.WithHTTPClient(&http.Client{Transport: tr}))
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
