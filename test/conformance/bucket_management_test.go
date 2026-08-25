//go:build conformance

package conformance

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func bucketManagementCredential(bucket string, grants ...config.BucketPermission) config.GatewayCredential {
	return config.GatewayCredential{AccessKey: "S3MANAGEMENT", SecretKey: "s3-management-secret", Label: "bucket-management", Buckets: []string{bucket}, BucketPermissions: grants}
}

func bucketManagementRequest(t *testing.T, gw *harness.Gateway, method, bucket string, body []byte, c config.GatewayCredential) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, gw.URL+"/"+bucket, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, c.AccessKey, c.SecretKey, body)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, data
}

func testBucketManagementCreateBucketEnabledAuthorized(t *testing.T, inst provider.Instance) {
	t.Helper()
	if inst.Bucket == "" {
		t.Skip("provider has no managed bucket fixture")
	}
	name := "s3mgmt-create-" + uniqueSuffix(t)
	c := bucketManagementCredential(name, config.BucketPermissionCreate, config.BucketPermissionDelete)
	gw := harness.StartGateway(t, inst, harness.WithBucketCreation(true), harness.WithBucketManagementCredentials(c))
	resp, body := bucketManagementRequest(t, gw, http.MethodPut, name, nil, c)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("CreateBucket status=%d body=%s", resp.StatusCode, body)
	}
	t.Cleanup(func() { _, _ = bucketManagementRequest(t, gw, http.MethodDelete, name, nil, c) })
}

func testBucketManagementCreateBucketDefaultDisabled(t *testing.T, inst provider.Instance) {
	name := "s3mgmt-disabled-" + uniqueSuffix(t)
	c := bucketManagementCredential(name, config.BucketPermissionCreate)
	gw := harness.StartGateway(t, inst, harness.WithBucketManagementCredentials(c))
	resp, body := bucketManagementRequest(t, gw, http.MethodPut, name, nil, c)
	if resp.StatusCode != http.StatusNotImplemented || !strings.Contains(string(body), "<Code>NotImplemented</Code>") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

func testBucketManagementCreateBucketOutOfScope(t *testing.T, inst provider.Instance) {
	name := "s3mgmt-outside-" + uniqueSuffix(t)
	c := bucketManagementCredential("outside-*", config.BucketPermissionCreate)
	gw := harness.StartGateway(t, inst, harness.WithBucketCreation(true), harness.WithBucketManagementCredentials(c))
	resp, body := bucketManagementRequest(t, gw, http.MethodPut, name, nil, c)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "<Code>AccessDenied</Code>") {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
}

func testBucketManagementCreateBucketLocationConstraint(t *testing.T, inst provider.Instance) {
	t.Helper()
	name := "s3mgmt-location-" + uniqueSuffix(t)
	c := bucketManagementCredential(name, config.BucketPermissionCreate, config.BucketPermissionDelete)
	gw := harness.StartGateway(t, inst, harness.WithBucketCreation(true), harness.WithBucketManagementCredentials(c))
	body := []byte("<CreateBucketConfiguration><LocationConstraint>" + inst.Region + "</LocationConstraint></CreateBucketConfiguration>")
	resp, responseBody := bucketManagementRequest(t, gw, http.MethodPut, name, body, c)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("CreateBucket location status=%d body=%s", resp.StatusCode, responseBody)
	}
	t.Cleanup(func() { _, _ = bucketManagementRequest(t, gw, http.MethodDelete, name, nil, c) })
}

func testBucketManagementDeleteBucketAuthorized(t *testing.T, inst provider.Instance) {
	if inst.Bucket == "" {
		t.Skip("provider has no managed bucket fixture")
	}
	// The provider fixture is intentionally not deleted; use a disposable bucket
	// created through the gateway by the same explicitly authorized credential.
	name := "s3mgmt-delete-" + uniqueSuffix(t)
	create := bucketManagementCredential(name, config.BucketPermissionCreate, config.BucketPermissionDelete)
	gw := harness.StartGateway(t, inst, harness.WithBucketCreation(true), harness.WithBucketManagementCredentials(create))
	resp, body := bucketManagementRequest(t, gw, http.MethodPut, name, nil, create)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Skipf("provider cannot create management fixture: %s", body)
	}
	resp, body = bucketManagementRequest(t, gw, http.MethodDelete, name, nil, create)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("DeleteBucket status=%d body=%s", resp.StatusCode, body)
	}
}
