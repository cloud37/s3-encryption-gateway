//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func testCompatAWSCLIListBucketsPermissions(t *testing.T, inst provider.Instance) {
	t.Helper()
	u, err := url.Parse(inst.Endpoint)
	if err != nil || u.Scheme != "http" {
		t.Skipf("provider fixture lacks HTTP endpoint required for scheme-less forwarding: %q", inst.Endpoint)
	}
	for _, credential := range []config.GatewayCredential{
		{AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Permissions: compatPermissionPtr(config.ObjectPermissionReadWrite)},
		{AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate}},
		{AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, BucketPermissions: []config.BucketPermission{config.BucketPermissionDelete}},
		{AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Permissions: compatPermissionPtr(config.ObjectPermissionReadWrite), BucketPermissions: []config.BucketPermission{config.BucketPermissionCreate, config.BucketPermissionDelete}},
	} {
		gw := harness.StartGateway(t, inst, harness.WithBucketManagementCredentials(credential), harness.WithConfigMutator(func(cfg *config.Config) { cfg.Backend.Endpoint = u.Host; cfg.Backend.UseSSL = false }))
		env := sdkTestEnv{Endpoint: gw.URL, Region: inst.Region, AccessKey: inst.AccessKey, SecretKey: inst.SecretKey, Bucket: inst.Bucket, Key: compatUniqueKey(t)}
		if err := runToolContainer(context.Background(), t, &awscliListBucketsRunner{}, env); err != nil {
			t.Fatal(err)
		}
	}
}

func compatPermissionPtr(permission config.ObjectPermission) *config.ObjectPermission {
	return &permission
}

// newCompatS3Client creates an AWS SDK Go v2 S3 client routed through the
// gateway at the given URL.
func newCompatS3Client(t *testing.T, gw *harness.Gateway, inst provider.Instance) *s3.Client {
	t.Helper()
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(inst.Region),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(inst.AccessKey, inst.SecretKey, ""),
		),
	)
	if err != nil {
		t.Fatalf("newCompatS3Client: %v", err)
	}
	return s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String(gw.URL)
	})
}

// testCompatSmoke_AWSGoV2 exercises the full smoke-test baseline using the
// AWS SDK Go v2 in-process. This covers all 7 operations from §1.3.
func testCompatSmoke_AWSGoV2(t *testing.T, inst provider.Instance) {
	t.Helper()
	// External providers can leave an upstream response open when a request is
	// rejected or eventually consistent. Bound the whole compatibility probe so
	// one backend response cannot consume the suite's ten-minute timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	gw, env := newUniqueTestEnv(t, inst)
	client := newCompatS3Client(t, gw, inst)

	// PutObject (single, ≤ 5 MiB)
	payload := []byte("compat-test-data")
	_, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
		Body:   bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: PutObject: %v", err)
	}

	// HeadObject
	head, err := client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: HeadObject: %v", err)
	}
	if head.ContentLength == nil || *head.ContentLength != int64(len(payload)) {
		t.Errorf("AWSGoV2: HeadObject ContentLength = %v, want %d", head.ContentLength, len(payload))
	}

	// GetObject (full read)
	get, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: GetObject: %v", err)
	}
	gotBody, err := io.ReadAll(get.Body)
	get.Body.Close()
	if err != nil {
		t.Fatalf("AWSGoV2: GetObject read body: %v", err)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Fatalf("AWSGoV2: GetObject body mismatch: got %q, want %q", string(gotBody), string(payload))
	}

	// ListObjectsV2
	list, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(env.Bucket),
		Prefix: aws.String(env.Key),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: ListObjectsV2: %v", err)
	}
	found := false
	for _, obj := range list.Contents {
		if obj.Key != nil && *obj.Key == env.Key {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AWSGoV2: ListObjectsV2: key %q not found", env.Key)
	}

	// DeleteObject
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: DeleteObject: %v", err)
	}

	// Multipart (all providers with CapSDKAWSGoV2 also have CapMultipartUpload).
	mpKey := env.Key + "-mp"
	createResp, err := client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(mpKey),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: CreateMultipartUpload: %v", err)
	}
	uploadID := *createResp.UploadId

	// Upload 3 parts (each exactly 5 MiB to satisfy S3 minimum part size).
	partSize := int64(5 * 1024 * 1024)
	partData := bytes.Repeat([]byte("A"), int(3*partSize))
	var completedParts []s3types.CompletedPart
	for i := int64(0); i < 3; i++ {
		partNum := int32(i + 1)
		partResp, err := client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket:     aws.String(env.Bucket),
			Key:        aws.String(mpKey),
			PartNumber: aws.Int32(partNum),
			UploadId:   aws.String(uploadID),
			Body:       bytes.NewReader(partData[i*partSize : (i+1)*partSize]),
		})
		if err != nil {
			client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
				Bucket:   aws.String(env.Bucket),
				Key:      aws.String(mpKey),
				UploadId: aws.String(uploadID),
			})
			t.Fatalf("AWSGoV2: UploadPart %d: %v", partNum, err)
		}
		completedParts = append(completedParts, s3types.CompletedPart{
			PartNumber: aws.Int32(partNum),
			ETag:       partResp.ETag,
		})
	}

	_, err = client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(env.Bucket),
		Key:      aws.String(mpKey),
		UploadId: aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		t.Fatalf("AWSGoV2: CompleteMultipartUpload: %v", err)
	}

	// Verify round-trip on MPU object.
	mpGet, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(mpKey),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: MPU GetObject: %v", err)
	}
	mpBody, err := io.ReadAll(mpGet.Body)
	mpGet.Body.Close()
	if err != nil {
		t.Fatalf("AWSGoV2: MPU read body: %v", err)
	}
	expectedMP := partData[:3*partSize]
	if !bytes.Equal(mpBody, expectedMP) {
		t.Fatalf("AWSGoV2: MPU body mismatch: len(got)=%d, len(want)=%d", len(mpBody), len(expectedMP))
	}

	// Cleanup MPU object.
	client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(mpKey),
	})

	// CopyObject (all providers with CapSDKAWSGoV2 also have CapMultipartCopy).
	copyKey := env.Key + "-copy"
	// Re-upload source since we deleted it.
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
		Body:   bytes.NewReader(payload),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: PutObject for copy source: %v", err)
	}

	_, err = client.CopyObject(ctx, &s3.CopyObjectInput{
		Bucket:     aws.String(env.Bucket),
		Key:        aws.String(copyKey),
		CopySource: aws.String(fmt.Sprintf("%s/%s", env.Bucket, env.Key)),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: CopyObject: %v", err)
	}

	copyGet, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(copyKey),
	})
	if err != nil {
		t.Fatalf("AWSGoV2: CopyObject GetObject: %v", err)
	}
	copyBody, err := io.ReadAll(copyGet.Body)
	copyGet.Body.Close()
	if err != nil {
		t.Fatalf("AWSGoV2: CopyObject read body: %v", err)
	}
	if !bytes.Equal(copyBody, payload) {
		t.Fatalf("AWSGoV2: CopyObject body mismatch")
	}

	// Cleanup copy and source.
	client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(copyKey),
	})
	client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(env.Bucket),
		Key:    aws.String(env.Key),
	})
}

// testCompatSmoke_Boto3 exercises the smoke-test baseline using boto3 (Python).
func testCompatSmoke_Boto3(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &boto3Runner{}, env); err != nil {
		t.Fatalf("boto3: %v", err)
	}
	_ = gw // gw is used indirectly via env.Endpoint
}

func testCompatBoto3PresignedPost(t *testing.T, inst provider.Instance) {
	t.Helper()
	testCompatPresignedPostSDK(t, inst, "boto3", false)
	testCompatPresignedPostSDK(t, inst, "boto3", true)
}

func testCompatAWSJSPresignedPost(t *testing.T, inst provider.Instance) {
	t.Helper()
	testCompatPresignedPostSDK(t, inst, "aws-js", false)
	testCompatPresignedPostSDK(t, inst, "aws-js", true)
}

func testCompatBrowserPost(t *testing.T, inst provider.Instance) {
	t.Helper()
	testCompatBrowserPostMode(t, inst, false)
	testCompatBrowserPostMode(t, inst, true)
}

func testCompatBrowserPostMode(t *testing.T, inst provider.Instance, session bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	vk := provider.StartValkey(ctx, t)
	if vk.Addr == "" {
		t.Fatal("browser POST requires the real shared Valkey fixture")
	}
	if inst.AccessKey == postGatewayAccess || inst.SecretKey == postGatewaySecret {
		t.Fatal("browser POST gateway identity must be independent from backend credentials")
	}
	var expires *time.Time
	token := ""
	if session {
		deadline := time.Now().UTC().Add(2 * time.Hour)
		expires = &deadline
		token = "compat-browser-session-token-fixture"
	}
	credential := postCredential(token, expires)
	manager := config.GatewayCredential{
		AccessKey: postGatewayAccess + "CORS", SecretKey: postGatewaySecret + "-cors-manager",
		Buckets: []string{inst.Bucket}, Permissions: compatPermissionPtr(config.ObjectPermissionReadWrite),
		BucketPermissions: []config.BucketPermission{config.BucketPermissionManage},
	}
	if manager.AccessKey == credential.AccessKey || manager.SecretKey == credential.SecretKey ||
		manager.AccessKey == inst.AccessKey || manager.SecretKey == inst.SecretKey {
		t.Fatal("browser CORS management identity must be separate from both upload and backend credentials")
	}
	var stageMu sync.Mutex
	var currentStage string
	var stageLedger []browserLedgerEntry
	bucketPath := "/" + postEncodePathSegment(inst.Bucket)
	gw := postGateway(t, inst, credential, harness.WithAuth(manager), harness.WithValkeyAddr(vk.Addr), harness.WithCORSMode("gateway"), harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations), harness.WithRequestObserver(func(observation harness.RequestObservation) {
		if observation.Method == http.MethodOptions || observation.Method == http.MethodPost {
			stageMu.Lock()
			if observation.Path == bucketPath {
				stageLedger = append(stageLedger, browserLedgerEntry{Stage: currentStage, Request: observation})
			}
			stageMu.Unlock()
		}
	}))
	prefix := compatUniqueKey(t)
	keys := []string{prefix + "-browser-default", prefix + "-browser-created", prefix + "-browser-preflight", prefix + "-browser-denied-header", prefix + "-browser-denied-origin"}
	if token != "" {
		keys = append(keys, prefix+"-browser-session")
	}
	for _, key := range keys {
		owned := key
		t.Cleanup(func() { cleanupPostObject(t, inst, owned) })
	}

	pageOrigin, closePage := startBrowserOrigin(t, "allowed", &stageMu, &currentStage, &stageLedger)
	t.Cleanup(closePage)
	deniedOrigin, closeDenied := startBrowserOrigin(t, "denied", nil, nil, nil)
	t.Cleanup(closeDenied)

	corsXML := browserCORSConfiguration(pageOrigin)
	corsURL := strings.TrimRight(gw.URL, "/") + "/" + postEncodePathSegment(inst.Bucket) + "?cors"
	readCORS, err := http.NewRequestWithContext(ctx, http.MethodGet, corsURL, nil)
	if err != nil {
		t.Fatal("construct signed gateway CORS snapshot request")
	}
	signV4Headers(t, readCORS, manager.AccessKey, manager.SecretKey, nil)
	oldResponse, err := gw.HTTPClient().Do(readCORS)
	if err != nil {
		t.Fatal("gateway CORS snapshot request failed")
	}
	oldXML, err := io.ReadAll(oldResponse.Body)
	oldResponse.Body.Close()
	if err != nil {
		t.Fatal("read gateway CORS snapshot")
	}
	if oldResponse.StatusCode != http.StatusOK && oldResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("gateway CORS snapshot returned HTTP %d", oldResponse.StatusCode)
	}
	previousPolicyExists := oldResponse.StatusCode == http.StatusOK
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		method, body := http.MethodDelete, ""
		if previousPolicyExists {
			method, body = http.MethodPut, string(oldXML)
		}
		request, requestErr := http.NewRequestWithContext(cleanupCtx, method, corsURL, strings.NewReader(body))
		if requestErr != nil {
			t.Errorf("construct gateway CORS cleanup request")
			return
		}
		var signedBody []byte
		if method == http.MethodPut {
			signedBody = oldXML
		}
		signV4Headers(t, request, manager.AccessKey, manager.SecretKey, signedBody)
		response, doErr := gw.HTTPClient().Do(request)
		if doErr != nil {
			t.Errorf("gateway CORS cleanup failed")
			return
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		wantStatus := http.StatusNoContent
		if method == http.MethodPut {
			wantStatus = http.StatusOK
		}
		if response.StatusCode != wantStatus {
			t.Errorf("gateway CORS cleanup returned HTTP %d", response.StatusCode)
		}
	})
	management, err := http.NewRequestWithContext(ctx, http.MethodPut, corsURL, strings.NewReader(corsXML))
	if err != nil {
		t.Fatal("construct signed gateway CORS management request")
	}
	signV4Headers(t, management, manager.AccessKey, manager.SecretKey, []byte(corsXML))
	managedResponse, err := gw.HTTPClient().Do(management)
	if err != nil {
		t.Fatal("gateway CORS management request failed")
	}
	io.Copy(io.Discard, managedResponse.Body)
	managedResponse.Body.Close()
	if managedResponse.StatusCode != http.StatusOK {
		t.Fatalf("gateway CORS management returned HTTP %d", managedResponse.StatusCode)
	}

	env := sdkTestEnv{Endpoint: gw.URL, Region: inst.Region, AccessKey: credential.AccessKey, SecretKey: credential.SecretKey, SessionToken: token, Bucket: inst.Bucket, Key: prefix}
	env.BrowserPageURL = pageOrigin
	env.BrowserDeniedPageURL = deniedOrigin
	env.BrowserStageURL = pageOrigin + "/stage"
	runner := &browserPostRunner{sessionExpected: session}
	if err := runToolContainer(ctx, t, runner, env); err != nil {
		t.Fatalf("browser POST conformance failed: %v", err)
	}
	payload := make([]byte, 32768)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	encryptedKeys := []string{prefix + "-browser-default", prefix + "-browser-created", prefix + "-browser-preflight", prefix + "-browser-denied-origin"}
	if token != "" {
		encryptedKeys = append(encryptedKeys, prefix+"-browser-session")
	}
	backend := directPostBackend(t, inst)
	for _, key := range encryptedKeys {
		ciphertext, metadata, getErr := backend.GetObject(ctx, inst.Bucket, key, nil, nil)
		if getErr != nil {
			t.Fatalf("read gateway-written browser object from backend")
		}
		wire, readErr := io.ReadAll(ciphertext)
		closeErr := ciphertext.Close()
		if readErr != nil || closeErr != nil || metadata[crypto.MetaEncrypted] != "true" || bytes.Equal(wire, payload) || len(wire) <= len(payload) {
			clear(wire)
			t.Fatalf("browser POST backend marker/ciphertext contract mismatch")
		}
		clear(wire)
	}
	stageMu.Lock()
	stageSnapshot := append([]browserLedgerEntry(nil), stageLedger...)
	stageMu.Unlock()
	assertBrowserLedger(t, stageSnapshot, session, bucketPath, pageOrigin, deniedOrigin)
}

func testCompatPresignedPostSDK(t *testing.T, inst provider.Instance, sdk string, session bool) {
	t.Helper()
	if inst.AccessKey == postGatewayAccess || inst.SecretKey == postGatewaySecret {
		t.Fatal("SDK POST gateway identity must be independent from backend credentials")
	}
	var expires *time.Time
	token := ""
	if session {
		deadline := time.Now().UTC().Add(2 * time.Hour)
		expires = &deadline
		token = "compat-post-session-token-fixture"
	}
	credential := postCredential(token, expires)
	if credential.AccessKey == inst.AccessKey || credential.SecretKey == inst.SecretKey {
		t.Fatal("presigned POST runner requires gateway credentials distinct from backend credentials")
	}
	gw := postGateway(t, inst, credential, harness.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	prefix := compatUniqueKey(t)
	env := sdkTestEnv{
		Endpoint: gw.URL, Region: inst.Region, AccessKey: credential.AccessKey,
		SecretKey: credential.SecretKey, SessionToken: credential.SessionToken,
		Bucket: inst.Bucket, Key: prefix,
	}
	flowName := sdk
	if flowName == "aws-js" {
		flowName = "awsjs"
	}
	suffixes := []string{"-" + flowName + "-default", "-" + flowName + "-created"}
	if session {
		suffixes = append(suffixes, "-"+flowName+"-session")
	}
	for _, suffix := range suffixes {
		key := prefix + suffix
		ownedKey := key
		t.Cleanup(func() { cleanupPostObject(t, inst, ownedKey) })
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Minute)
	defer cancel()
	if session {
		if env.SessionToken == "" || credential.ExpiresAt == nil || time.Until(*credential.ExpiresAt) < 15*time.Minute {
			t.Fatal("SDK session fixture must have a live token and at least fifteen minutes before expiry")
		}
	} else if env.SessionToken != "" {
		t.Fatal("static SDK fixture unexpectedly has a session token")
	}
	var runner sdkToolRunner
	switch sdk {
	case "boto3":
		runner = &boto3PresignedPostRunner{sessionExpected: session}
	case "aws-js":
		runner = &awsJSPresignedPostRunner{sessionExpected: session}
	default:
		t.Fatal("unknown presigned POST SDK selection")
	}
	if err := runToolContainer(ctx, t, runner, env); err != nil {
		t.Fatalf("%s SDK POST: %v", runner.Name(), err)
	}
	backend := newS3CompatClient(t, inst)
	for _, suffix := range suffixes {
		stored, err := backend.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(prefix + suffix)})
		if err != nil || stored == nil {
			t.Fatalf("direct backend HEAD for SDK-created object failed")
		}
		if !sdkBackendEncryptedMarker(stored.Metadata) {
			t.Fatal("direct backend SDK POST object lacks the gateway encrypted marker")
		}
		object, err := backend.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(inst.Bucket), Key: aws.String(prefix + suffix)})
		if err != nil || object == nil || object.Body == nil {
			t.Fatal("direct backend GET for SDK-created ciphertext failed")
		}
		ciphertext, readErr := io.ReadAll(object.Body)
		closeErr := object.Body.Close()
		wantPlaintext := make([]byte, 32*1024)
		for i := range wantPlaintext {
			wantPlaintext[i] = byte(i % 251)
		}
		if readErr != nil || closeErr != nil || len(ciphertext) == 0 || bytes.Equal(ciphertext, wantPlaintext) {
			t.Fatal("direct backend ciphertext was empty or unreadable")
		}
		clear(ciphertext)
		clear(wantPlaintext)
	}
}

// testCompatSmoke_AWSCLI exercises the smoke-test baseline using awscli.
func testCompatSmoke_AWSCLI(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &awscliRunner{}, env); err != nil {
		t.Fatalf("awscli: %v", err)
	}
	_ = gw
}

// testCompat_HTTPSUnsignedTrailer ensures the CI conformance matrix covers the
// authenticated HTTPS aws-chunked mode selected by current AWS CLI v2 and
// boto3. Its single-part and multipart uploads exercise PutObject and
// UploadPart, respectively (issue #329).
func testCompat_HTTPSUnsignedTrailer(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	credential := config.GatewayCredential{AccessKey: inst.AccessKey, SecretKey: inst.SecretKey}
	gw := harness.StartGateway(t, inst, harness.WithTLS(true), harness.WithAuth(credential))
	env := sdkTestEnv{
		Endpoint: gw.URL, Region: inst.Region, AccessKey: inst.AccessKey, SecretKey: inst.SecretKey,
		Bucket: inst.Bucket, Key: compatUniqueKey(t),
	}
	if err := runToolContainer(ctx, t, &awscliUnsignedTrailerRunner{}, env); err != nil {
		t.Fatalf("awscli HTTPS unsigned trailer: %v", err)
	}
	if err := runToolContainer(ctx, t, &boto3UnsignedTrailerRunner{}, env); err != nil {
		t.Fatalf("boto3 HTTPS unsigned trailer: %v", err)
	}
}

// testCompatSmoke_S5cmd exercises the smoke-test baseline using s5cmd.
func testCompatSmoke_S5cmd(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &s5cmdRunner{}, env); err != nil {
		t.Fatalf("s5cmd: %v", err)
	}
	_ = gw
}

// testCompatSmoke_Rclone exercises the smoke-test baseline using rclone.
func testCompatSmoke_Rclone(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &rcloneRunner{}, env); err != nil {
		t.Fatalf("rclone: %v", err)
	}
	_ = gw
}

// testCompatSmoke_MinIOPy exercises the smoke-test baseline using minio-py.
func testCompatSmoke_MinIOPy(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()
	gw, env := newUniqueTestEnv(t, inst)
	if err := runToolContainer(ctx, t, &minioPyRunner{}, env); err != nil {
		t.Fatalf("minio-py: %v", err)
	}
	_ = gw
}

// testRcloneSyncCheck_SizeCache verifies the warm-cache path for issues #204
// and #207: objects uploaded through the gateway populate the Valkey size cache
// automatically, so rclone check --size-only sees correct plaintext sizes.
//
// This covers the steady-state case: deploy gateway with Valkey, upload via
// gateway, rclone check passes immediately.
func testRcloneSyncCheck_SizeCache(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	// Start a real Valkey container so the gateway size cache is active.
	vk := provider.StartValkey(ctx, t)

	// Start the gateway with the size cache wired via the shared Valkey pool.
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
	)

	// Use a unique prefix so parallel tests never collide in the same bucket.
	prefix := compatUniqueKey(t)

	env := sdkTestEnv{
		Endpoint:  gw.URL,
		Region:    inst.Region,
		AccessKey: inst.AccessKey,
		SecretKey: inst.SecretKey,
		Bucket:    inst.Bucket,
		Key:       prefix, // repurposed as the remote path prefix
	}

	if err := runToolContainer(ctx, t, &rcloneSyncCheckRunner{}, env); err != nil {
		t.Fatalf("rclone-sync-check: %v", err)
	}
}

// testRcloneSyncCheck_FallbackHead is the regression test for the specific
// failure reported in issue #207 comment: the user upgraded to 0.11.1, set
// LIST_SIZE_TRANSLATE_ENABLED=true and LIST_SIZE_TRANSLATE_FALLBACK_HEAD_ENABLED=true,
// but rclone check still reported "sizes differ".
//
// Root cause: loadFromEnv() never read the LIST_SIZE_TRANSLATE_* env vars —
// the env: struct tags were declared but not wired. The env vars were silently
// ignored, the fallback HEAD path never fired, and pre-existing objects
// (uploaded before 0.11.1 with a cold cache) always returned ciphertext sizes.
//
// This test reproduces that scenario:
//  1. Upload 15 objects directly to the backend (bypassing the gateway) so the
//     Valkey cache starts cold — simulating objects that existed before upgrade.
//  2. Start the gateway with Valkey + fallback HEAD enabled.
//  3. rclone sync downloads the objects and then rclone check --size-only
//     compares local sizes against the gateway listing. Without the fix the
//     env var is ignored, the fallback never fires, and check exits 1.
//     With the fix the env var is respected, the fallback HEAD resolves
//     plaintext sizes, and check exits 0.
func testRcloneSyncCheck_FallbackHead(t *testing.T, inst provider.Instance) {
	t.Helper()
	ctx := context.Background()

	// Start Valkey — cache starts empty (cold).
	vk := provider.StartValkey(ctx, t)

	// Start the gateway with Valkey + fallback HEAD enabled.
	// WithConfigMutator simulates the operator setting
	// LIST_SIZE_TRANSLATE_FALLBACK_HEAD_ENABLED=true after upgrade.
	gw := harness.StartGateway(t, inst,
		harness.WithValkeyAddr(vk.Addr),
		harness.WithConfigMutator(func(cfg *config.Config) {
			cfg.ListSizeTranslate.FallbackHeadEnabled = true
			cfg.ListSizeTranslate.FallbackHeadConcurrency = 10
			cfg.ListSizeTranslate.FallbackHeadTimeout = 30 * time.Second
		}),
	)

	// Write the 15 files directly to the backend, bypassing the gateway.
	// This means the Valkey cache has no entries for them — exactly the
	// situation for objects that existed before the 0.11.1 upgrade.
	prefix := compatUniqueKey(t)
	directClient := newS3Client(t, inst)
	eng, err := crypto.NewEngine([]byte("test-encryption-password-123456"))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	type fileSpec struct {
		name string
		size int
	}
	files := []fileSpec{
		{"file-00.bin", 100}, {"file-01.bin", 1100}, {"file-02.bin", 2100},
		{"file-03.bin", 3100}, {"file-04.bin", 4100}, {"file-05.bin", 5100},
		{"file-06.bin", 6100}, {"file-07.bin", 7100}, {"file-08.bin", 8100},
		{"file-09.bin", 9100}, {"file-10.bin", 65536}, {"file-11.bin", 65537},
		{"file-12.bin", 131072}, {"file-13.bin", 131073}, {"file-14.txt", 18},
	}

	for _, f := range files {
		plaintext := make([]byte, f.size)
		for i := range plaintext {
			plaintext[i] = byte('a' + (i % 26))
		}
		key := prefix + "/" + f.name
		putEncryptedObject(t, directClient, eng, inst.Bucket, key, plaintext, nil)
	}

	// Run rclone sync (download from gateway) then rclone check --size-only.
	// The sync downloads the objects; check compares the local sizes against
	// what ListObjects returns. The fallback HEAD must fire for each cache-miss
	// to resolve the plaintext size — otherwise check sees ciphertext sizes.
	env := sdkTestEnv{
		Endpoint:  gw.URL,
		Region:    inst.Region,
		AccessKey: inst.AccessKey,
		SecretKey: inst.SecretKey,
		Bucket:    inst.Bucket,
		Key:       prefix,
	}

	if err := runToolContainer(ctx, t, &rcloneSyncCheckFallbackRunner{}, env); err != nil {
		t.Fatalf("rclone-sync-check-fallback: %v", err)
	}
}
