package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func middlewareCORSStore(t *testing.T) CORSStore {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	store := NewValkeyCORSStore(client)
	cfg, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><ID>web</ID><AllowedOrigin>https://app.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod><AllowedMethod>PUT</AllowedMethod><AllowedMethod>DELETE</AllowedMethod><AllowedHeader>content-type</AllowedHeader><ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>3600</MaxAgeSeconds></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "bucket", cfg))
	return store
}

func TestCORSMiddleware_EncryptedAndProxyHeaders(t *testing.T) {
	store := middlewareCORSStore(t)
	request := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("ciphertext"))
	request.Header.Set("Origin", "https://app.example.com")
	handler := CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		require.Equal(t, "ciphertext", string(body))
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.Header().Set("Access-Control-Expose-Headers", "X-Backend")
		w.Header().Set("ETag", `"part-etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "ETag", w.Header().Get("Access-Control-Expose-Headers"))
	require.Equal(t, `"part-etag"`, w.Header().Get("ETag"))
	require.NotContains(t, w.Header().Get("Access-Control-Allow-Methods"), "PUT")
	require.Contains(t, w.Header().Get("Vary"), "Origin")
}

func TestCORSMiddleware_UnmatchedOriginStripsUpstream(t *testing.T) {
	store := middlewareCORSStore(t)
	request := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	request.Header.Set("Origin", "https://evil.example")
	handler := CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	require.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORSMiddleware_ErrorAndHEADResponses(t *testing.T) {
	store := middlewareCORSStore(t)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := httptest.NewRequest(method, "/bucket/key", nil)
		r.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://evil.example")
			w.WriteHeader(http.StatusInternalServerError)
		})).ServeHTTP(w, r)
		require.Equal(t, http.StatusInternalServerError, w.Code)
		require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_MatchedGETAndHEADResponses(t *testing.T) {
	store := middlewareCORSStore(t)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		r := httptest.NewRequest(method, "/bucket/key", nil)
		r.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, r)
		require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_InvalidOriginSuppressesPolicy(t *testing.T) {
	store := middlewareCORSStore(t)
	for _, origin := range []string{"*", "null", "https://", "https://app.example.com:99999", "https://app.example.com/path", "https://app.example.com\rX-Evil", "https://app.example.com,https://other.example"} {
		for _, method := range []string{http.MethodGet, http.MethodOptions} {
			r := httptest.NewRequest(method, "/bucket/key", nil)
			r.Header.Add("Origin", origin)
			if method == http.MethodOptions {
				r.Header.Set("Access-Control-Request-Method", "PUT")
			}
			w := httptest.NewRecorder()
			CORSMiddleware(config.CORSConfig{Mode: "gateway", AllowCredentials: true}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Access-Control-Allow-Origin", "unsafe")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.WriteHeader(http.StatusOK)
			})).ServeHTTP(w, r)
			require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"), "%s %s", method, origin)
			require.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"), "%s %s", method, origin)
		}
	}
}

func TestCORSMiddleware_InformationalAndImplicitHeaderOnlyCommit(t *testing.T) {
	store := middlewareCORSStore(t)
	server := httptest.NewServer(CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bucket/info" {
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Set("X-After-103", "visible")
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
	})))
	defer server.Close()
	for _, path := range []string{"/bucket/info", "/bucket/headers"} {
		req, err := http.NewRequest(http.MethodGet, server.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Origin", "https://app.example.com")
		resp, err := server.Client().Do(req)
		require.NoError(t, err)
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, "https://app.example.com", resp.Header.Get("Access-Control-Allow-Origin"))
		require.NotContains(t, resp.Header.Get("Access-Control-Allow-Origin"), "backend")
		if path == "/bucket/info" {
			require.Equal(t, "visible", resp.Header.Get("X-After-103"))
		}
	}
}

func TestCORSMiddleware_InformationalResponsesReconcileUpstreamCORS(t *testing.T) {
	store := middlewareCORSStore(t)
	server := httptest.NewServer(CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "DELETE")
		w.Header().Set("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("X-Final-Header", "present")
		status := http.StatusOK
		if r.URL.Path == "/bucket/early-error" {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
	})))
	defer server.Close()

	for _, tc := range []struct {
		name, path, origin, wantOrigin string
		wantFinal                      int
	}{
		{"matched", "/bucket/matched", "https://app.example.com", "https://app.example.com", http.StatusOK},
		{"unmatched", "/bucket/unmatched", "https://evil.example", "", http.StatusOK},
		{"absent origin", "/bucket/absent", "", "", http.StatusOK},
		{"malformed origin", "/bucket/malformed", "https://host]", "", http.StatusOK},
		{"matched early error", "/bucket/early-error", "https://app.example.com", "https://app.example.com", http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, server.URL+tc.path, nil)
			require.NoError(t, err)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			var infoHeaders http.Header
			req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
				Got1xxResponse: func(code int, header textproto.MIMEHeader) error {
					require.Equal(t, http.StatusEarlyHints, code)
					infoHeaders = http.Header(header).Clone()
					return nil
				},
			}))
			resp, err := server.Client().Do(req)
			require.NoError(t, err)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			require.Equal(t, tc.wantFinal, resp.StatusCode)
			require.NotNil(t, infoHeaders, "server must deliver the 103 block")
			require.Equal(t, tc.wantOrigin, infoHeaders.Get("Access-Control-Allow-Origin"))
			require.Empty(t, infoHeaders.Get("Access-Control-Allow-Credentials"), "upstream credentials grants must never escape")
			require.Empty(t, infoHeaders.Get("Access-Control-Allow-Methods"), "upstream method grants must never escape")
			require.Contains(t, infoHeaders.Get("Vary"), "Accept-Encoding")
			require.Equal(t, "present", resp.Header.Get("X-Final-Header"), "final response headers must remain writable after 103")
			require.Equal(t, tc.wantOrigin, resp.Header.Get("Access-Control-Allow-Origin"))
			require.Empty(t, resp.Header.Get("Access-Control-Allow-Credentials"))
		})
	}
}

func TestCORSMiddleware_WriteErrorAndDeleteResponses(t *testing.T) {
	store := middlewareCORSStore(t)
	for _, method := range []string{http.MethodPut, http.MethodDelete} {
		r := httptest.NewRequest(method, "/bucket/key", nil)
		r.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "https://upstream.example")
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
		require.Equal(t, http.StatusNoContent, w.Code)
		require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_CredentialsWildcardEchoAndVary(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer client.Close()
	store := NewValkeyCORSStore(client)
	cfg, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><ExposeHeader>ETag</ExposeHeader></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	require.NoError(t, store.Put(context.Background(), "bucket", cfg))
	configValue := config.CORSConfig{Mode: "gateway", AllowCredentials: true}
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	r.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	CORSMiddleware(configValue, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	require.Contains(t, w.Header().Get("Vary"), "Accept-Encoding")
	require.Contains(t, w.Header().Get("Vary"), "Origin")
	require.NotEqual(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_StreamingOptionalInterfaces(t *testing.T) {
	store := middlewareCORSStore(t)
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	r.Header.Set("Origin", "https://app.example.com")
	base := httptest.NewRecorder()
	var wrapped http.ResponseWriter
	CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		wrapped = w
		if _, ok := w.(http.Flusher); !ok {
			t.Error("Flusher not preserved")
		}
		if _, ok := w.(io.ReaderFrom); !ok {
			t.Error("ReaderFrom not preserved")
		}
		if _, ok := w.(http.Hijacker); !ok {
			t.Error("Hijacker not preserved")
		}
		if _, ok := w.(http.Pusher); !ok {
			t.Error("Pusher not preserved")
		}
		if _, ok := w.(interface{ Unwrap() http.ResponseWriter }); !ok {
			t.Error("Unwrap not preserved")
		}
		if _, err := io.Copy(w, strings.NewReader("stream")); err != nil {
			t.Error(err)
		}
	})).ServeHTTP(base, r)
	require.NotNil(t, wrapped)
	require.Equal(t, "stream", base.Body.String())
	require.Equal(t, "https://app.example.com", base.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_StoreDownNeverFallsBack(t *testing.T) {
	client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer client.Close()
	cfg := config.CORSConfig{Mode: "gateway", Fallback: config.CORSFallbackConfig{AllowedOrigins: []string{"*"}, AllowedMethods: []string{"GET"}}}
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	r.Header.Set("Origin", "https://app.example.com")
	w := httptest.NewRecorder()
	CORSMiddleware(cfg, NewValkeyCORSStore(client), logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_NoOriginStripsBackendCORS(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	w := httptest.NewRecorder()
	CORSMiddleware(config.CORSConfig{Mode: "gateway"}, nil, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Expose-Headers", "ETag")
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	require.Empty(t, w.Header().Get("Access-Control-Expose-Headers"))
}

func TestCORSMiddleware_BucketPathOnlyAndVaryPreserved(t *testing.T) {
	calls := 0
	middleware := CORSMiddleware(config.CORSConfig{Mode: "gateway"}, nil, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	for _, path := range []string{"/health", "/ready", "/metrics", "/", "/admin/health", "/bucket/key"} {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Header.Set("Origin", "https://app.example.com")
		w := httptest.NewRecorder()
		middleware.ServeHTTP(w, r)
		if path == "/admin/health" {
			require.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"), "unrelated paths are untouched")
		} else if path == "/bucket/key" {
			require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
			require.Contains(t, w.Header().Get("Vary"), "Origin")
		} else {
			require.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"), path)
		}
	}
	require.Equal(t, 6, calls)
}

func TestCORSMiddleware_ProductionTrailingSlashNormalizationScope(t *testing.T) {
	store := middlewareCORSStore(t)
	router := mux.NewRouter()
	router.HandleFunc("/{bucket}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.WriteHeader(http.StatusNoContent)
	})
	chain := CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = mux.SetURLVars(r, map[string]string{"bucket": "bucket"})
		if corsBucketTrailingSlash(r.URL.Path) {
			u := *r.URL
			u.Path = strings.TrimSuffix(u.Path, "/")
			r.URL = &u
		}
		router.ServeHTTP(w, r)
	}))
	for _, tc := range []struct {
		path, origin, want string
		status             int
	}{
		{"/bucket/", "https://app.example.com", "https://app.example.com", http.StatusNoContent},
		{"/bucket/", "https://evil.example", "", http.StatusNoContent},
		{"/bucket/", "", "", http.StatusNoContent},
		{"/other/", "https://app.example.com", "", http.StatusNoContent},
		{"/bucket/key/", "https://app.example.com", "", http.StatusNotFound},
	} {
		r := httptest.NewRequest(http.MethodGet, tc.path, nil)
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, r)
		require.Equal(t, tc.status, w.Code)
		if tc.path == "/bucket/" {
			require.Equal(t, tc.want, w.Header().Get("Access-Control-Allow-Origin"))
		} else if tc.path == "/bucket/key/" {
			// Object-key trailing slash is not normalized as a bucket path.
			// This router has no object route, so gorilla/mux returns 404 and
			// never mutates the signed request URL.
			require.Equal(t, tc.path, r.URL.Path)
		}
	}
	keyPath := httptest.NewRequest(http.MethodGet, "/bucket/a//b", nil)
	require.True(t, isCORSPath(keyPath), "repeated object-key slashes remain eligible for gateway CORS")
	require.Equal(t, "/bucket/a//b", keyPath.URL.Path)
}

func TestCORSMiddleware_RepeatedSlashPathStripsBackendCORS(t *testing.T) {
	store := middlewareCORSStore(t)
	r := httptest.NewRequest(http.MethodGet, "/bucket/a//b", nil)
	r.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/bucket/a//b", r.URL.Path, "middleware does not mutate signed path")
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_RepeatedSlashObjectKeyRemainsEligible(t *testing.T) {
	store := middlewareCORSStore(t)
	r := httptest.NewRequest(http.MethodGet, "/bucket/a//b", nil)
	r.Header.Set("Origin", "https://app.example.com")
	require.True(t, isCORSPath(r), "the object route accepts non-empty key text containing repeated slash bytes")
	w := httptest.NewRecorder()
	CORSMiddleware(config.CORSConfig{Mode: "gateway"}, store, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/bucket/a//b", r.URL.Path)
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORSMiddleware_UnmatchedBucketTrailingSlashAndBackendPolicyStripped(t *testing.T) {
	chain := CORSMiddleware(config.CORSConfig{Mode: "gateway"}, middlewareCORSStore(t), logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://backend.example")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusNotFound)
	}))
	for _, origin := range []string{"https://evil.example", ""} {
		r := httptest.NewRequest(http.MethodGet, "/bucket/", nil)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		chain.ServeHTTP(w, r)
		require.Equal(t, http.StatusNotFound, w.Code)
		require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
		require.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	}
}

func TestCORSMiddleware_PreflightAuthFailureStripsHeaders(t *testing.T) {
	r := httptest.NewRequest(http.MethodOptions, "/bucket", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "PUT")
	w := httptest.NewRecorder()
	CORSMiddleware(config.CORSConfig{Mode: "gateway"}, nil, logrus.New())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusForbidden)
	})).ServeHTTP(w, r)
	require.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, w.Header().Get("Vary"), "Access-Control-Request-Headers")
}
