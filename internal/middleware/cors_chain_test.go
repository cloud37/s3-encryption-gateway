package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/api"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/middleware"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestCORSMiddleware_ProductionTrailingSlashRouterChain(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := api.NewValkeyCORSStore(client)
	cfg := &api.CORSConfiguration{Rules: []api.CORSRule{{AllowedOrigins: []string{"https://app.example.com"}, AllowedMethods: []string{"GET"}, ExposeHeaders: []string{"ETag"}}}}
	require.NoError(t, store.Put(context.Background(), "bucket", cfg))
	router := mux.NewRouter()
	var routeHit bool
	router.HandleFunc("/{bucket}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.WriteHeader(http.StatusNoContent)
	})
	router.HandleFunc("/{bucket}/{key:.+}", func(w http.ResponseWriter, r *http.Request) {
		routeHit = true
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.WriteHeader(http.StatusNoContent)
	})
	chain := api.CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(middleware.StripBucketTrailingSlash(router))
	for _, tc := range []struct {
		path, origin, want string
		status             int
	}{
		{"/bucket/", "https://app.example.com", "https://app.example.com", http.StatusNoContent},
		{"/bucket/", "https://evil.example", "", http.StatusNoContent},
		{"/bucket/", "", "", http.StatusNoContent},
		{"/missing/", "https://app.example.com", "", http.StatusNoContent},
		{"/bucket/dir/", "https://app.example.com", "https://app.example.com", http.StatusNoContent},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, r)
		require.Equal(t, tc.status, w.Code, tc.path)
		require.Equal(t, tc.want, w.Header().Get("Access-Control-Allow-Origin"), tc.path)
	}
	// Gorilla mux's default cleaning redirects repeated slash paths before
	// matching; those requests still remain in CORS S3 scope at the outer edge.
	repeated := httptest.NewRequest(http.MethodGet, "/bucket/dir//item", nil)
	repeated.Header.Set("Origin", "https://evil.example")
	repeatedRec := httptest.NewRecorder()
	chain.ServeHTTP(repeatedRec, repeated)
	require.Equal(t, "/bucket/dir/item", repeatedRec.Header().Get("Location"))
	require.Empty(t, repeatedRec.Header().Get("Access-Control-Allow-Origin"))
	// The registered object route is confirmed independently with the router's
	// normalized path; this is the path mux dispatches after its clean redirect.
	clean := httptest.NewRequest(http.MethodGet, "/bucket/dir/item", nil)
	clean.Header.Set("Origin", "https://app.example.com")
	cleanRec := httptest.NewRecorder()
	chain.ServeHTTP(cleanRec, clean)
	require.Equal(t, http.StatusNoContent, cleanRec.Code)
	require.True(t, routeHit)
	require.Equal(t, "https://app.example.com", cleanRec.Header().Get("Access-Control-Allow-Origin"))
}
