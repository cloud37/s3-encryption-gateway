package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestGH353LiteralRouting_ClassifierParity(t *testing.T) {
	router := mux.NewRouter().SkipClean(true)
	(&Handler{}).RegisterRoutes(router)
	for _, tc := range []struct {
		target, route string
		permission    authorizationOperation
	}{
		{"/bucket/literal/%2E%2E/plus%2Bpercent%2525/name%2Ebin", "GetObject", authorizationRead},
		{"/bucket/a//b", "GetObject", authorizationRead},
		{"/bucket//leading", "GetObject", authorizationRead},
		{"/bucket/a/%252F", "GetObject", authorizationRead},
		{"/bucket/a//b?tagging", "GetObjectTagging", authorizationRead},
		{"/bucket/a//b?uploadId=selected", "ListParts", authorizationRead},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.target, nil)
		var match mux.RouteMatch
		if !router.Match(req, &match) || match.Route == nil || match.Route.GetName() != tc.route {
			t.Fatal("literal route mismatch")
		}
		op, bucket := classifyAuthorizationOperation(req)
		if op != tc.permission || bucket != "bucket" || match.Vars["bucket"] != bucket {
			t.Fatal("route/classifier permission mismatch")
		}
	}
}
