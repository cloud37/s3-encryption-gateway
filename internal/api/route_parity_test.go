package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

func TestRouteClassificationParity(t *testing.T) {
	queries := map[string][]string{
		"CreateMultipartUpload": {"uploads"}, "CompleteMultipartUpload": {"uploadId=u"}, "AbortMultipartUpload": {"uploadId=u"},
		"ListParts": {"uploadId=u"}, "UploadPart": {"partNumber=1&uploadId=u"}, "UploadPartCopy": {"partNumber=1&uploadId=u"},
		"GetObjectRetention": {"retention"}, "PutObjectRetention": {"retention"}, "GetObjectLegalHold": {"legal-hold"},
		"PutObjectLegalHold": {"legal-hold"}, "GetObjectTagging": {"tagging"}, "PutObjectTagging": {"tagging"},
		"DeleteObjectTagging": {"tagging"}, "GetObjectACL": {"acl"}, "PutObjectACL": {"acl"}, "RestoreObject": {"restore"},
		"SelectObjectContent": {"select", "select-type=2"}, "GetObjectLockConfiguration": {"object-lock"},
		"PutObjectLockConfiguration": {"object-lock"}, "GetBucketLifecycle": {"lifecycle"}, "PutBucketLifecycle": {"lifecycle"},
		"DeleteBucketLifecycle": {"lifecycle"}, "GetBucketPolicy": {"policy"}, "PutBucketPolicy": {"policy"},
		"DeleteBucketPolicy": {"policy"}, "GetBucketCors": {"cors"}, "PutBucketCors": {"cors"}, "DeleteBucketCors": {"cors"},
		"GetBucketVersioning": {"versioning"}, "PutBucketVersioning": {"versioning"}, "GetBucketEncryption": {"encryption"},
		"PutBucketEncryption": {"encryption"}, "DeleteBucketEncryption": {"encryption"}, "GetBucketACL": {"acl"},
		"PutBucketACL": {"acl"}, "GetBucketLocation": {"location"}, "ListMultipartUploads": {"uploads"},
		"GetBucketNotification": {"notification"}, "PutBucketNotification": {"notification"},
		"GetBucketReplication": {"replication"}, "PutBucketReplication": {"replication"}, "DeleteBucketReplication": {"replication"},
		"GetBucketLogging": {"logging"}, "PutBucketLogging": {"logging"}, "GetBucketRequestPayment": {"requestPayment"},
		"PutBucketRequestPayment": {"requestPayment"}, "GetBucketWebsite": {"website"}, "PutBucketWebsite": {"website"},
		"DeleteBucketWebsite": {"website"}, "GetBucketInventory": {"inventory&id=abc", "inventory"},
		"PutBucketInventory": {"inventory&id=abc", "inventory"}, "DeleteBucketInventory": {"inventory&id=abc", "inventory"},
		"GetBucketAnalytics": {"analytics&id=abc", "analytics"}, "PutBucketIntelligentTiering": {"intelligent-tiering&id=abc", "intelligent-tiering"},
		"DeleteObjects": {"delete"},
	}
	queries["CORSPreflight"] = []string{""}
	methods := map[string]string{
		"ListBuckets": http.MethodGet, "CreateBucket": http.MethodPut, "DeleteBucket": http.MethodDelete,
		"HeadBucket": http.MethodHead, "ListObjects": http.MethodGet, "GetObject": http.MethodGet,
		"HeadObject": http.MethodHead, "PutObject": http.MethodPut, "CopyObject": http.MethodPut,
		"DeleteObject": http.MethodDelete, "DeleteObjects": http.MethodPost,
		"CreateMultipartUpload": http.MethodPost, "CompleteMultipartUpload": http.MethodPost,
		"AbortMultipartUpload": http.MethodDelete, "ListParts": http.MethodGet,
		"UploadPart": http.MethodPut, "UploadPartCopy": http.MethodPut,
		"ListMultipartUploads": http.MethodGet,
		"GetObjectRetention":   http.MethodGet, "PutObjectRetention": http.MethodPut,
		"GetObjectLegalHold": http.MethodGet, "PutObjectLegalHold": http.MethodPut,
		"GetObjectTagging": http.MethodGet, "PutObjectTagging": http.MethodPut, "DeleteObjectTagging": http.MethodDelete,
		"GetObjectACL": http.MethodGet, "PutObjectACL": http.MethodPut, "RestoreObject": http.MethodPost,
		"SelectObjectContent": http.MethodPost, "GetObjectLockConfiguration": http.MethodGet,
		"PutObjectLockConfiguration": http.MethodPut, "GetBucketLifecycle": http.MethodGet,
		"PutBucketLifecycle": http.MethodPut, "DeleteBucketLifecycle": http.MethodDelete,
		"GetBucketPolicy": http.MethodGet, "PutBucketPolicy": http.MethodPut, "DeleteBucketPolicy": http.MethodDelete,
		"GetBucketCors": http.MethodGet, "PutBucketCors": http.MethodPut, "DeleteBucketCors": http.MethodDelete,
		"GetBucketVersioning": http.MethodGet, "PutBucketVersioning": http.MethodPut,
		"GetBucketEncryption": http.MethodGet, "PutBucketEncryption": http.MethodPut, "DeleteBucketEncryption": http.MethodDelete,
		"GetBucketACL": http.MethodGet, "PutBucketACL": http.MethodPut, "GetBucketLocation": http.MethodGet,
		"GetBucketNotification": http.MethodGet, "PutBucketNotification": http.MethodPut,
		"GetBucketReplication": http.MethodGet, "PutBucketReplication": http.MethodPut, "DeleteBucketReplication": http.MethodDelete,
		"GetBucketLogging": http.MethodGet, "PutBucketLogging": http.MethodPut, "GetBucketRequestPayment": http.MethodGet,
		"PutBucketRequestPayment": http.MethodPut, "GetBucketWebsite": http.MethodGet, "PutBucketWebsite": http.MethodPut,
		"DeleteBucketWebsite": http.MethodDelete, "GetBucketInventory": http.MethodGet, "PutBucketInventory": http.MethodPut,
		"DeleteBucketInventory": http.MethodDelete, "GetBucketAnalytics": http.MethodGet,
		"PutBucketIntelligentTiering": http.MethodPut,
		"CORSPreflight":               http.MethodOptions,
	}
	router := mux.NewRouter()
	handler := &Handler{}
	handler.RegisterRoutes(router)

	type candidate struct{ method, target, expected string }
	var cases []candidate
	for route, wantPermission := range independentRoutePermissions() {
		if got, ok := operationPermission[route]; !ok || got != wantPermission {
			t.Fatalf("production permission for %q=%v present=%t want independent oracle %v", route, got, ok, wantPermission)
		}
		method, ok := methods[route]
		if !ok {
			t.Fatalf("permission table route %q lacks method case", route)
		}
		base := "/bucket/key"
		if route == "CORSPreflight" {
			base = "/bucket/key"
		}
		if route == "ListBuckets" {
			base = "/"
		} else if strings.HasPrefix(route, "GetObjectLock") || strings.HasPrefix(route, "PutObjectLock") {
			base = "/bucket"
		} else if strings.HasPrefix(route, "GetBucket") || strings.HasPrefix(route, "PutBucket") || strings.HasPrefix(route, "DeleteBucket") || route == "CreateBucket" || route == "HeadBucket" || route == "ListObjects" || route == "DeleteObjects" || route == "ListMultipartUploads" {
			base = "/bucket"
		}
		qs := queries[route]
		if len(qs) == 0 {
			qs = []string{""}
		}
		for _, query := range qs {
			target := base
			if query != "" {
				target += "?" + query
			}
			cases = append(cases, candidate{method: method, target: target, expected: route})
		}
	}
	for _, route := range []candidate{
		{http.MethodPut, "/bucket/key", "CopyObject"},
		{http.MethodPut, "/bucket/key?partNumber=2&uploadId=u", "UploadPartCopy"},
		{http.MethodGet, "/bucket/key?response-content-type=text%2Fplain&versionId=v1", "GetObject"},
		{http.MethodGet, "/bucket/key/?tagging", "GetObjectTagging"},
		{http.MethodPost, "/bucket/key?select-type=2", "SelectObjectContent"},
	} {
		cases = append(cases, route)
	}
	for _, target := range []string{
		"/bucket/key?versionId=v1", "/bucket/key?versionId=v2", "/bucket/key?response-content-type=text%2Fplain",
		"/bucket/key?response-cache-control=no-cache", "/bucket/key?response-content-language=en", "/bucket/key?response-expires=tomorrow",
		"/bucket/key?response-content-encoding=gzip", "/bucket/key?response-content-disposition=attachment",
		"/bucket/key?x-id=GetObject", "/bucket/key?versionId=v1&x-id=GetObject", "/bucket/key?partNumber=1&uploadId=u&x-id=UploadPart",
		"/bucket/key/?response-content-type=text%2Fplain", "/bucket/key/?response-content-disposition=attachment",
		"/bucket/key?select-type=2", "/bucket/key?select", "/bucket/key?uploadId=u", "/bucket/key?partNumber=1&uploadId=u",
	} {
		expected := "GetObject"
		method := http.MethodGet
		if strings.Contains(target, "select") {
			expected = "SelectObjectContent"
			method = http.MethodPost
		} else if strings.Contains(target, "partNumber=") {
			expected = "UploadPart"
			method = http.MethodPut
		} else if strings.Contains(target, "uploadId=") {
			expected = "ListParts"
		}
		cases = append(cases, candidate{method: method, target: target, expected: expected})
	}
	if len(cases) < 85 {
		t.Fatalf("route parity table has %d cases; want about 90", len(cases))
	}

	for i, tc := range cases {
		t.Run(fmt.Sprintf("%02d_%s_%s", i, tc.method, strings.ReplaceAll(tc.target, "/", "_")), func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, nil)
			if tc.expected == "CopyObject" || tc.expected == "UploadPartCopy" {
				r.Header.Set("x-amz-copy-source", "/source/object")
			}
			var match mux.RouteMatch
			if !router.Match(r, &match) || match.Route == nil {
				t.Fatalf("router did not match %s %s", tc.method, tc.target)
			}
			routerWant := tc.expected
			if tc.expected == "CopyObject" {
				routerWant = "PutObject"
			}
			if tc.expected == "UploadPartCopy" {
				routerWant = "UploadPart"
			}
			if got := match.Route.GetName(); got != routerWant {
				t.Fatalf("router route=%q want=%q", got, routerWant)
			}
			// CopyObject is a semantic operation layered on the PUT route family;
			// UploadPartCopy similarly shares UploadPart's method/query router
			// family. Keep this translation explicit rather than coupling the
			// independent permission oracle to instrumentation naming.
			r = mux.SetURLVars(r, match.Vars)
			if got := s3OperationName(r); got != tc.expected {
				t.Fatalf("instrumentation=%q want=%q", got, tc.expected)
			}
			got, _ := classifyAuthorizationOperation(r)
			wantPermission, ok := independentRoutePermissions()[routerWant]
			if !ok || got != wantPermission {
				t.Fatalf("authorization=%v want=%v for %s", got, wantPermission, tc.expected)
			}
			if wantPermission != got {
				t.Fatalf("independent route permission=%v does not equal authorization=%v", wantPermission, got)
			}
		})
	}
}

func TestRouteClassificationParity_CopyNamingContract(t *testing.T) {
	router := mux.NewRouter()
	(&Handler{}).RegisterRoutes(router)
	for _, tc := range []struct {
		method, target, routeName, semantic string
	}{
		{http.MethodPut, "/bucket/key", "PutObject", "CopyObject"},
		{http.MethodPut, "/bucket/key?partNumber=1&uploadId=u", "UploadPart", "UploadPartCopy"},
	} {
		r := httptest.NewRequest(tc.method, tc.target, nil)
		r.Header.Set("x-amz-copy-source", "/source/key")
		var match mux.RouteMatch
		if !router.Match(r, &match) {
			t.Fatalf("router did not match %s", tc.target)
		}
		if got := match.Route.GetName(); got != tc.routeName {
			t.Fatalf("route name=%s want=%s", got, tc.routeName)
		}
		r = mux.SetURLVars(r, match.Vars)
		if got := s3OperationName(r); got != tc.semantic {
			t.Fatalf("semantic operation=%s want=%s", got, tc.semantic)
		}
	}
}

func TestRouteClassificationParity_RouteTablePermissionOracle(t *testing.T) {
	for route, want := range independentRoutePermissions() {
		if got, ok := operationPermission[route]; !ok || got != want {
			t.Errorf("production operationPermission[%q]=%v present=%t want independent oracle %v", route, got, ok, want)
		}
	}
}

// independentRoutePermissions is deliberately a test-owned oracle rather than
// an iteration over operationPermission, so missing or incorrect production
// table entries cannot make parity pass tautologically. Route-level CopyObject
// and UploadPartCopy intentionally map to the router's PutObject and UploadPart
// method/query family names; semantic instrumentation retains the copy names.
func independentRoutePermissions() map[string]authorizationOperation {
	return map[string]authorizationOperation{
		"ListBuckets": authorizationListBuckets, "CreateBucket": authorizationCreateBucket,
		"DeleteBucket": authorizationDeleteBucket, "HeadBucket": authorizationRead, "ListObjects": authorizationRead,
		"GetObject": authorizationRead, "HeadObject": authorizationRead, "PutObject": authorizationWrite,
		"DeleteObject": authorizationWrite, "DeleteObjects": authorizationWrite,
		"CreateMultipartUpload": authorizationWrite, "CompleteMultipartUpload": authorizationWrite,
		"AbortMultipartUpload": authorizationWrite, "ListParts": authorizationRead, "UploadPart": authorizationWrite,
		"ListMultipartUploads": authorizationRead,
		"GetObjectRetention":   authorizationRead, "PutObjectRetention": authorizationWrite,
		"GetObjectLegalHold": authorizationRead, "PutObjectLegalHold": authorizationWrite,
		"GetObjectTagging": authorizationRead, "PutObjectTagging": authorizationWrite,
		"DeleteObjectTagging": authorizationWrite, "GetObjectACL": authorizationRead,
		"PutObjectACL": authorizationWrite, "RestoreObject": authorizationWrite,
		"SelectObjectContent": authorizationRead, "CORSPreflight": authorizationRead,
		"GetObjectLockConfiguration": authorizationRead, "PutObjectLockConfiguration": authorizationManageBucket,
		"GetBucketLifecycle": authorizationRead, "PutBucketLifecycle": authorizationManageBucket,
		"DeleteBucketLifecycle": authorizationManageBucket, "GetBucketPolicy": authorizationRead,
		"PutBucketPolicy": authorizationManageBucket, "DeleteBucketPolicy": authorizationManageBucket,
		"GetBucketCors": authorizationRead, "PutBucketCors": authorizationManageBucket,
		"DeleteBucketCors": authorizationManageBucket, "GetBucketVersioning": authorizationRead,
		"PutBucketVersioning": authorizationManageBucket, "GetBucketEncryption": authorizationRead,
		"PutBucketEncryption": authorizationManageBucket, "DeleteBucketEncryption": authorizationManageBucket,
		"GetBucketACL": authorizationRead, "PutBucketACL": authorizationManageBucket,
		"GetBucketLocation": authorizationRead, "GetBucketNotification": authorizationRead,
		"PutBucketNotification": authorizationManageBucket, "GetBucketReplication": authorizationRead,
		"PutBucketReplication": authorizationManageBucket, "DeleteBucketReplication": authorizationManageBucket,
		"GetBucketLogging": authorizationRead, "PutBucketLogging": authorizationManageBucket,
		"GetBucketRequestPayment": authorizationRead, "PutBucketRequestPayment": authorizationManageBucket,
		"GetBucketWebsite": authorizationRead, "PutBucketWebsite": authorizationManageBucket,
		"DeleteBucketWebsite": authorizationManageBucket, "GetBucketInventory": authorizationRead,
		"PutBucketInventory": authorizationManageBucket, "DeleteBucketInventory": authorizationManageBucket,
		"GetBucketAnalytics": authorizationRead, "PutBucketIntelligentTiering": authorizationManageBucket,
	}
}
