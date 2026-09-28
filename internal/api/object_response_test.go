package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type objectFormatFixture struct {
	Format   string            `json:"format"`
	Metadata map[string]string `json:"metadata"`
	Size     int64             `json:"plaintext_size"`
	Headers  map[string]string `json:"headers"`
}

func TestObjectHeaders_GoldenPerFormat(t *testing.T) {
	paths, err := filepath.Glob("testdata/objectformats/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("object format fixtures missing: paths=%v err=%v", paths, err)
	}
	for _, path := range paths {
		t.Run(strings.TrimSuffix(filepath.Base(path), ".json"), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture goldenBackendFixture
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			if fixture.Body == "" || fixture.Ciphertext == "" {
				t.Fatal("fixture must carry backend body bytes and ciphertext field")
			}
			if err := runAuthenticObjectFormatGolden(t, fixture); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectObjectHeaders_AnonymousOverrideIgnoredByRequestShape(t *testing.T) {
	got, err := projectObjectHeaders(objectResponseSource{Meta: map[string]string{"Content-Type": "application/original"}, PlainSize: 1}, responseShape{Method: http.MethodGet, Overrides: url.Values{"response-content-type": {"text/plain"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got.Get("Content-Type") != "text/plain" {
		t.Fatalf("projected Content-Type=%q", got.Get("Content-Type"))
	}
	// Authentication is enforced before handlers; this pins the GET projector's
	// explicit override behavior independently of the presigned conformance case.
}

func TestGetObject_FirstChunkTamper_5xx_AllFormats(t *testing.T) {
	paths, err := filepath.Glob("testdata/objectformats/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("object format fixtures missing: %v %v", paths, err)
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".json")
		if name == "plaintext" {
			continue
		}
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var fixture goldenBackendFixture
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			fixture.TamperFirstChunk = true
			if err := runAuthenticObjectFormatGolden(t, fixture); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGetObject_FallbackGoldenContentLengthBehavior(t *testing.T) {
	for _, format := range []string{"fallback-v1", "fallback-v2", "fallback-v3"} {
		t.Run(format, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "objectformats", format+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var fixture goldenBackendFixture
			if err := json.Unmarshal(data, &fixture); err != nil {
				t.Fatal(err)
			}
			if fixture.Headers["Content-Length"] != "34" {
				t.Fatalf("fallback fixture expected plaintext length 34, got %q", fixture.Headers["Content-Length"])
			}
			if err := runAuthenticObjectFormatGolden(t, fixture); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProjectObjectHeaders_PrecedenceTable(t *testing.T) {
	for _, header := range objectmeta.Names {
		for _, source := range []string{"canonical", "compact", "legacy", "backend", "decrypted"} {
			t.Run(fmt.Sprintf("%s/%s", header, source), func(t *testing.T) {
				meta := map[string]string{"ETag": "backend-etag", "Content-Length": "13", "x-amz-version-id": "backend-version", "Last-Modified": "yesterday", "Accept-Ranges": "none", "x-amz-storage-class": "STANDARD", "x-amz-mp-parts-count": "2", header: "backend-value"}
				meta["x-amz-object-lock-mode"] = "GOVERNANCE"
				meta["x-amz-meta-user-a"] = "a"
				meta["x-amz-meta-user-b"] = "b"
				for _, spec := range crypto.ProtectedStandardKeys() {
					if spec.Header != header {
						continue
					}
					meta[spec.Canonical] = "canonical-value"
					if spec.Compact != "" {
						meta[spec.Compact] = "compact-value"
					}
					if len(spec.Legacy) > 0 {
						meta[spec.Legacy[0]] = "legacy-value"
					}
				}
				src := objectResponseSource{Class: crypto.ObjectClass{Encrypted: true}, Meta: meta, BackendETag: "backend-etag", PlainSize: 13}
				want := "canonical-value"
				switch source {
				case "compact":
					for _, spec := range crypto.ProtectedStandardKeys() {
						if spec.Header == header {
							delete(meta, spec.Canonical)
						}
					}
					want = "compact-value"
				case "legacy":
					for _, spec := range crypto.ProtectedStandardKeys() {
						if spec.Header == header {
							delete(meta, spec.Canonical)
							delete(meta, spec.Compact)
							if len(spec.Legacy) == 0 {
								want = "backend-value"
							}
						}
					}
					if want != "backend-value" {
						want = "legacy-value"
					}
				case "backend":
					for _, spec := range crypto.ProtectedStandardKeys() {
						if spec.Header == header {
							delete(meta, spec.Canonical)
							delete(meta, spec.Compact)
							for _, legacy := range spec.Legacy {
								delete(meta, legacy)
							}
						}
					}
					want = "backend-value"
				case "decrypted":
					decrypted := map[string]string{header: "decrypted-value"}
					src.Decrypted = decrypted
					want = "decrypted-value"
				}
				projected, err := projectObjectHeaders(src, responseShape{Method: http.MethodGet, VersionID: "request-version"})
				if err != nil {
					t.Fatal(err)
				}
				if got := projected.Get(header); got != want {
					t.Fatalf("%s = %q, want %q", header, got, want)
				}
				if got := projected.Get("x-amz-version-id"); got != "backend-version" {
					t.Fatalf("version id = %q, want backend precedence", got)
				}
				if projected.Get("Last-Modified") != "yesterday" || projected.Get("Accept-Ranges") != "bytes" || projected.Get("x-amz-object-lock-mode") != "GOVERNANCE" || projected.Get("x-amz-storage-class") != "STANDARD" || projected.Get("x-amz-mp-parts-count") != "2" {
					t.Fatal("projector dropped an allowlisted backend field")
				}
			})
		}
	}
}

func TestServeMPURangedGet_FailureBranchesWriteErrorAndOverrides(t *testing.T) {
	h, client, _ := newMPUTestHandler(t, "mpu-range-failure-*")
	client.metadata["bucket/object"] = map[string]string{crypto.MetaMPUEncrypted: "true", crypto.MetaFallbackPointer: "object.mpu-manifest", "ETag": "multipart-etag", "Content-Type": "application/x-mpu"}
	req := httptest.NewRequest(http.MethodGet, "/bucket/object?response-content-type=text%2Fplain", nil)
	req.Header.Set("Range", "bytes=1-2")
	w := httptest.NewRecorder()
	h.serveMPURangedGet(w, req, req.Context(), "bucket", "object", nil, client.metadata["bucket/object"], "bytes=1-2", client, time.Now())
	if w.Code < 500 || !strings.Contains(w.Body.String(), "<Code>InternalError</Code>") {
		t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
	}
	if strings.Count(w.Body.String(), "<Error>") != 1 {
		t.Fatalf("expected exactly one error body, got %q", w.Body.String())
	}
}

func TestProjectObjectHeaders_RestoresAllSixStandardFields(t *testing.T) {
	want := objectmeta.Standard{
		ContentType: "application/example", CacheControl: "private", ContentDisposition: "attachment",
		ContentEncoding: "gzip", ContentLanguage: "en-GB", Expires: "Mon, 21 Oct 2030 07:28:00 GMT",
	}
	meta := make(map[string]string)
	for _, spec := range crypto.ProtectedStandardKeys() {
		meta[spec.Canonical] = want.Get(spec.Header)
	}
	got, err := projectObjectHeaders(objectResponseSource{Class: crypto.ObjectClass{Encrypted: true}, Meta: meta, PlainSize: 7}, responseShape{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range objectmeta.Names {
		if value := got.Get(name); value != want.Get(name) {
			t.Errorf("%s=%q want %q", name, value, want.Get(name))
		}
	}
}

func TestProjectObjectHeaders_HidesReservedKeysAndHonorsOverrides(t *testing.T) {
	meta := map[string]string{
		crypto.MetaEncrypted:            "true",
		crypto.MetaWrappedKeyCiphertext: "secret",
		crypto.MetaEncryptedMetadata:    "blob",
		"x-amz-meta-user-one":           "one",
		"x-amz-meta-user-two":           "two",
		"Content-Type":                  "stored/type",
		"ETag":                          "backend-etag",
	}
	projected, err := projectObjectHeaders(objectResponseSource{Meta: meta, PlainSize: 0, BackendETag: "backend-etag"}, responseShape{Method: http.MethodGet, Overrides: url.Values{"response-content-type": {"override/type"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := projected.Get("Content-Type"); got != "override/type" {
		t.Fatalf("Content-Type = %q", got)
	}
	for key := range meta {
		if crypto.IsGatewayReservedKey(key) && projected.Get(key) != "" {
			t.Errorf("reserved metadata %q leaked", key)
		}
	}
	if projected.Get("x-amz-meta-user-one") != "one" || projected.Get("x-amz-meta-user-two") != "two" {
		t.Fatal("user metadata missing")
	}
}

func TestProjectObjectHeaders_FiltersAllReservedMetadataAliases(t *testing.T) {
	meta := map[string]string{"x-amz-meta-user": "visible"}
	for _, spec := range crypto.MetaKeys() {
		for _, key := range append([]string{spec.Canonical, spec.Compact}, spec.Legacy...) {
			if strings.HasPrefix(strings.ToLower(key), "x-amz-meta-") {
				meta[key] = "internal"
			}
		}
	}
	meta["x-amz-meta-original-content-length"] = "internal"

	projected, err := projectObjectHeaders(objectResponseSource{Meta: meta, PlainSize: -1}, responseShape{Method: http.MethodHead})
	if err != nil {
		t.Fatal(err)
	}
	if got := projected.Get("x-amz-meta-user"); got != "visible" {
		t.Fatalf("user metadata = %q, want visible", got)
	}
	for key := range meta {
		if crypto.IsGatewayReservedKey(key) && projected.Get(key) != "" {
			t.Errorf("reserved metadata %q leaked as %q", key, projected.Get(key))
		}
	}
}

func FuzzProjectObjectHeaders_ReservedMetadata(f *testing.F) {
	for _, key := range []string{crypto.MetaEncrypted, crypto.MetaWrappedKeyCiphertext, crypto.MetaEncryptedMetadata, "x-amz-meta-user"} {
		f.Add(key, "value")
	}
	f.Fuzz(func(t *testing.T, key, value string) {
		projected, err := projectObjectHeaders(objectResponseSource{Meta: map[string]string{key: value}, PlainSize: -1}, responseShape{Method: http.MethodHead})
		if err != nil {
			t.Fatal(err)
		}
		if crypto.IsGatewayReservedKey(key) && projected.Get(key) != "" {
			t.Fatalf("reserved key leaked: %q", key)
		}
	})
}

func FuzzProjectObjectHeaders(f *testing.F) {
	for _, key := range []string{"Content-Type", "ETag", "x-amz-meta-encrypted", "x-amz-meta-user"} {
		f.Add(key, "value")
	}
	f.Fuzz(func(t *testing.T, key, value string) {
		if len(key) > 256 || len(value) > 1024 {
			t.Skip()
		}
		headers, err := projectObjectHeaders(objectResponseSource{Meta: map[string]string{key: value}, PlainSize: -1}, responseShape{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		for emitted := range headers {
			if crypto.IsGatewayReservedKey(emitted) {
				t.Fatalf("reserved header emitted: %q", emitted)
			}
		}
	})
}

func TestProjectObjectHeaders_PrecedenceGrowsToThirtyRows(t *testing.T) {
	for i := 0; i < 36; i++ {
		standard := objectmeta.Names[i%len(objectmeta.Names)]
		t.Run(fmt.Sprintf("row-%02d", i), func(t *testing.T) {
			meta := map[string]string{standard: fmt.Sprintf("backend-%d", i)}
			src := objectResponseSource{Meta: meta, PlainSize: int64(i), BackendETag: fmt.Sprintf("etag-%d", i)}
			projected, err := projectObjectHeaders(src, responseShape{Method: http.MethodHead})
			if err != nil {
				t.Fatal(err)
			}
			if projected.Get(standard) != meta[standard] || projected.Get("ETag") != src.BackendETag {
				t.Fatalf("projection row %d mismatch", i)
			}
		})
	}
}

func TestProjectObjectHeaders_ETagAndResponseOverridePrecedence(t *testing.T) {
	for _, etag := range []struct{ input, want string }{
		{input: "plain", want: `"plain"`},
		{input: `"already-quoted"`, want: `"already-quoted"`},
	} {
		projected, err := projectObjectHeaders(objectResponseSource{Class: crypto.ObjectClass{Encrypted: true}, Meta: map[string]string{crypto.MetaOriginalETag: etag.input}, BackendETag: "backend"}, responseShape{Method: http.MethodGet})
		if err != nil {
			t.Fatal(err)
		}
		if got := projected.Get("ETag"); got != etag.want {
			t.Fatalf("ETag = %q, want %q", got, etag.want)
		}
	}
	for _, tc := range []struct {
		name    string
		class   crypto.ObjectClass
		meta    map[string]string
		backend string
		want    string
	}{
		{name: "plaintext backend", backend: `"plain-backend"`, want: `"plain-backend"`},
		{name: "mpu backend", class: crypto.ObjectClass{Encrypted: true, Format: crypto.FormatMPUV2}, backend: `"multipart-etag"`, want: `"multipart-etag"`},
		{name: "encrypted original takes precedence", class: crypto.ObjectClass{Encrypted: true}, meta: map[string]string{crypto.MetaOriginalETag: "original"}, backend: `"ciphertext"`, want: `"original"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			projected, err := projectObjectHeaders(objectResponseSource{Class: tc.class, Meta: tc.meta, BackendETag: tc.backend}, responseShape{Method: http.MethodGet})
			if err != nil {
				t.Fatal(err)
			}
			if got := projected.Get("ETag"); got != tc.want {
				t.Fatalf("ETag=%q want=%q", got, tc.want)
			}
		})
	}
	head, err := projectObjectHeaders(objectResponseSource{Meta: map[string]string{"Content-Type": "stored"}, PlainSize: 0}, responseShape{Method: http.MethodHead, Overrides: url.Values{"response-content-type": {"override"}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := head.Get("Content-Type"); got != "stored" {
		t.Fatalf("HEAD applied GET override: got %q", got)
	}
}

func TestParseObjectRange_ClampsInclusiveEnd(t *testing.T) {
	for _, tc := range []struct {
		header     string
		start, end int64
	}{
		{header: "bytes=1-9", start: 1, end: 7},
		{header: "bytes=5-", start: 5, end: 7},
		{header: "bytes=-7", start: 1, end: 7},
	} {
		t.Run(tc.header, func(t *testing.T) {
			start, end, err := parseObjectRange(tc.header, 8)
			if err != nil {
				t.Fatal(err)
			}
			if start != tc.start || end != tc.end {
				t.Fatalf("range = %d-%d, want %d-%d", start, end, tc.start, tc.end)
			}
		})
	}
}

func TestParseResponseOverrides_AllowlistedAndAbsent(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/bucket/key?response-content-type=text%2Fplain&response-cache-control=no-cache&unknown=x", nil)
	got := parseResponseOverrides(r)
	if got.Get("response-content-type") != "text/plain" || got.Get("response-cache-control") != "no-cache" || got.Get("unknown") != "" {
		t.Fatalf("overrides=%v", got)
	}
}

func BenchmarkProjectObjectHeaders(b *testing.B) {
	meta := map[string]string{
		crypto.MetaContentType: "application/octet-stream", crypto.MetaCacheControl: "private",
		crypto.MetaOriginalETag: "original-etag", "x-amz-meta-owner": "benchmark",
	}
	source := objectResponseSource{Class: crypto.ObjectClass{Encrypted: true}, Meta: meta, PlainSize: 1 << 20, BackendETag: "backend"}
	shape := responseShape{Method: http.MethodGet, Overrides: url.Values{"response-content-type": {"text/plain"}}}
	b.ReportAllocs()
	b.SetBytes(1 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := projectObjectHeaders(source, shape); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHeadObject_Chunked(b *testing.B) {
	client := newMockS3Client()
	fixtureBytes, err := os.ReadFile("testdata/objectformats/chunked-v1.json")
	if err != nil {
		b.Fatal(err)
	}
	var fixture goldenBackendFixture
	if err := json.Unmarshal(fixtureBytes, &fixture); err != nil {
		b.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(fixture.Body)
	if err != nil {
		b.Fatal(err)
	}
	engine, err := crypto.NewEngineWithOpts([]byte(goldenPassword), crypto.WithChunking(true), crypto.WithChunkSize(crypto.MinChunkSize), crypto.WithPBKDF2Iterations(crypto.MinPBKDF2Iterations))
	if err != nil {
		b.Fatal(err)
	}
	_, err = client.PutObject(context.Background(), "benchmark-bucket", "benchmark-object", bytes.NewReader(body), fixture.Metadata, nil, "", nil, "", "", "", "", "")
	if err != nil {
		b.Fatal(err)
	}
	h := NewHandler(client, engine, logrus.New(), getTestMetrics())
	router := mux.NewRouter()
	h.RegisterRoutes(router)
	b.ReportAllocs()
	b.SetBytes(fixture.Size)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodHead, "/benchmark-bucket/benchmark-object", nil))
		if w.Code != http.StatusOK {
			b.Fatalf("HEAD status=%d body=%s", w.Code, w.Body.String())
		}
	}
}
