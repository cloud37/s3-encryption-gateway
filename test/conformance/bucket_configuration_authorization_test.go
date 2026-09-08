//go:build conformance

package conformance

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

// testSEC47_BucketConfigurationAuthorization proves that object write access
// does not confer bucket administration, while a scoped manage grant permits
// the supported policy and lifecycle configuration round trips.
func testSEC47_BucketConfigurationAuthorization(t *testing.T, inst provider.Instance) {
	t.Helper()
	readWrite := config.ObjectPermissionReadWrite
	denied := config.GatewayCredential{
		AccessKey: "SEC47RW", SecretKey: "sec47-rw-secret", Buckets: []string{inst.Bucket},
		Permissions: &readWrite,
	}
	manage := denied
	manage.AccessKey = "SEC47MANAGE"
	manage.SecretKey = "sec47-manage-secret"
	manage.BucketPermissions = []config.BucketPermission{config.BucketPermissionManage}

	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::%s/*"}]}`, inst.Bucket)
	lifecycle := `<LifecycleConfiguration><Rule><ID>sec47-expire</ID><Status>Enabled</Status><Filter><Prefix>sec47/</Prefix></Filter><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>`

	deniedGateway := harness.StartGateway(t, inst, harness.WithAuth(denied))
	assertSignedOperationAccessDenied(t, deniedGateway, http.MethodPut, "/"+inst.Bucket+"?policy", []byte(policy), denied)
	assertSignedOperationAccessDenied(t, deniedGateway, http.MethodPut, "/"+inst.Bucket+"?lifecycle", []byte(lifecycle), denied)

	managedGateway := harness.StartGateway(t, inst, harness.WithAuth(manage))
	putAndGetBucketConfiguration(t, managedGateway, inst.Bucket, "policy", []byte(policy), manage)
	putAndGetBucketConfiguration(t, managedGateway, inst.Bucket, "lifecycle", []byte(lifecycle), manage)

	assertSignedOperationStatus(t, managedGateway, http.MethodDelete, "/"+inst.Bucket+"?policy", nil, manage, http.StatusNoContent)
	assertSignedOperationStatus(t, managedGateway, http.MethodDelete, "/"+inst.Bucket+"?lifecycle", nil, manage, http.StatusNoContent)
}

func putAndGetBucketConfiguration(t *testing.T, gw *harness.Gateway, bucket, selector string, body []byte, credential config.GatewayCredential) {
	t.Helper()
	path := "/" + bucket + "?" + selector
	resp, responseBody := signedOperation(t, gw, http.MethodPut, path, body, credential)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= 300 {
		t.Fatalf("PUT %s: status %d: %s", path, resp.StatusCode, responseBody)
	}
	resp, responseBody = signedOperation(t, gw, http.MethodGet, path, nil, credential)
	if resp.StatusCode != http.StatusOK || len(responseBody) == 0 {
		t.Fatalf("GET %s: status %d: %s", path, resp.StatusCode, responseBody)
	}
}

func assertSignedOperationStatus(t *testing.T, gw *harness.Gateway, method, path string, body []byte, credential config.GatewayCredential, want int) {
	t.Helper()
	resp, responseBody := signedOperation(t, gw, method, path, body, credential)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, responseBody)
	}
}
