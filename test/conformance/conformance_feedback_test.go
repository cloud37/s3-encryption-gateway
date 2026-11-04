//go:build conformance

package conformance

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/cloud37/s3-encryption-gateway/internal/cache"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func TestGH353ConformanceFeedbackHarnessBoundaries(t *testing.T) {
	for _, candidate := range provider.GH353FeedbackProviders() {
		providerName := candidate.Name()
		t.Run(providerName, func(t *testing.T) {
			var mu sync.Mutex
			puts := 0
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				mu.Lock()
				puts++
				mu.Unlock()
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("ETag", `"opaque"`)
				w.Header().Set("x-amz-version-id", "fixture-version")
			}))
			defer backend.Close()
			inst := provider.Instance{ProviderName: providerName, Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
			recorder := &postWriteRecorder{base: http.DefaultTransport}
			credential := postCredential("", nil)
			gw := postGateway(t, inst, credential, harness.WithChunking(true), harness.WithMetadataEncryptionKey(bytes.Repeat([]byte{0x42}, 32)), harness.WithBackendTransport(recorder))
			fields := map[string]string{"Content-Type": "application/octet-stream", "Content-Encoding": "identity", "Content-Disposition": "attachment", "Cache-Control": "private", "Content-Language": "en-GB", "Expires": "Mon, 21 Oct 2030 07:28:00 GMT", "x-amz-meta-owner": "protected-post", "x-amz-meta-purpose": "round-trip"}
			for _, overflow := range []bool{false, true} {
				if overflow {
					fields["x-amz-meta-overflow"] = strings.Repeat("v", 7900)
				}
				before := gw.PostObjectBoundaries()
				starts := map[string]string{}
				if overflow {
					starts["x-amz-meta-overflow"] = ""
				}
				req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, "fixture-key", credential, postFormCase{fields: fields, file: bytes.Repeat([]byte("protected-post-record/"), 128), startsWithConditions: starts})
				resp, body := postHTTP(t, gw, credential, req)
				after := gw.PostObjectBoundaries()
				if after != [3]int{before[0] + 1, before[1] + 1, before[2] + 1} {
					t.Fatalf("harness fixture overflow=%t status=%d code=%s boundaries=%v", overflow, resp.StatusCode, postSafeErrorCode(body), after)
				}
				if providerName == provider.GH353FeedbackCompactingProvider().Name() {
					if resp.StatusCode != http.StatusNoContent || len(body) != 0 || resp.Header.Get("x-amz-version-id") != "fixture-version" {
						t.Fatal("compacting fixture did not reach the versioned backend")
					}
				} else if resp.StatusCode != http.StatusBadRequest || postSafeErrorCode(body) != "MetadataTooLarge" {
					t.Fatalf("default profile fixture status=%d code=%s", resp.StatusCode, postSafeErrorCode(body))
				}
			}
			mu.Lock()
			got := puts
			mu.Unlock()
			wantPuts := 0
			if providerName == provider.GH353FeedbackCompactingProvider().Name() {
				wantPuts = 2
			}
			if got != wantPuts {
				t.Fatalf("backend PUT count=%d", got)
			}
		})
	}
}

func TestGH353ConformanceFeedbackSafeSDKError(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotImplemented)
		fmt.Fprint(w, "<Error><Code>NotImplemented</Code><Message>private-canary</Message></Error>")
	}))
	defer backend.Close()
	inst := provider.Instance{Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
	_, err := newS3CompatClient(t, inst).GetObjectTagging(t.Context(), &awss3.GetObjectTaggingInput{Bucket: aws.String("bucket"), Key: aws.String("key")})
	status, code := postSafeSDKError(err)
	if err == nil || status != 501 || code != "NotImplemented" {
		t.Fatalf("safe SDK error status=%d code=%s", status, code)
	}
}

func TestGH353ConformanceFeedbackBoundaryRejection(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("rejected request reached backend")
		w.WriteHeader(500)
	}))
	defer backend.Close()
	inst := provider.Instance{ProviderName: provider.GH353FeedbackCompactingProvider().Name(), Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
	credential := postCredential("", nil)
	gw := postGateway(t, inst, credential)
	before := gw.PostObjectBoundaries()
	req := makePostRequest(t, postFormURL(gw, "bucket"), "bucket", "key", credential, postFormCase{file: []byte("data"), corruptSignature: true})
	resp, _ := postHTTP(t, gw, credential, req)
	after := gw.PostObjectBoundaries()
	if resp.StatusCode != http.StatusForbidden || after != [3]int{before[0] + 1, before[1], before[2]} {
		t.Fatalf("signature rejection status=%d boundaries=%v", resp.StatusCode, after)
	}
}

func TestGH353ConformanceFeedbackTagAndVersionProjection(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("backend_failure=", fail), func(t *testing.T) {
			var mu sync.Mutex
			var tagged bool
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPut {
					w.WriteHeader(404)
					return
				}
				tags, err := url.ParseQuery(r.Header.Get("x-amz-tagging"))
				mu.Lock()
				tagged = err == nil && tags.Get("cafe") == "browser upload"
				mu.Unlock()
				_, _ = io.Copy(io.Discard, r.Body)
				if fail {
					w.Header().Set("Content-Type", "application/xml")
					w.WriteHeader(500)
					fmt.Fprint(w, `<Error><Code>InternalError</Code><Message>private-canary</Message></Error>`)
					return
				}
				w.Header().Set("ETag", `"fixture"`)
				w.Header().Set("x-amz-version-id", "fixture-version")
			}))
			defer backend.Close()
			inst := provider.Instance{ProviderName: provider.GH353FeedbackCompactingProvider().Name(), Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
			recorder := &postWriteRecorder{base: http.DefaultTransport}
			credential := postCredential("", nil)
			gw := postGateway(t, inst, credential, harness.WithBackendTransport(recorder))
			fields := map[string]string{"tagging": `<Tagging><TagSet><Tag><Key>cafe</Key><Value>browser upload</Value></Tag></TagSet></Tagging>`}
			req := makePostRequest(t, postFormURL(gw, inst.Bucket), inst.Bucket, "key", credential, postFormCase{fields: fields, file: []byte("tagged-versioned-post")})
			resp, body := postHTTP(t, gw, credential, req)
			mu.Lock()
			observed := tagged
			mu.Unlock()
			if !observed {
				t.Fatal("gateway did not forward exact inline tags")
			}
			if fail {
				if resp.StatusCode != 500 || postSafeErrorCode(body) != "InternalError" || resp.Header.Get("x-amz-version-id") != "" || bytes.Contains(body, []byte("private-canary")) {
					t.Fatal("unsafe backend error projection")
				}
			} else if resp.StatusCode != 204 || resp.Header.Get("x-amz-version-id") != "fixture-version" {
				t.Fatal("version projection failed")
			}
		})
	}
}

func TestGH353GarageTaggingLocalWirePrevalidation(t *testing.T) {
	providers := provider.GH353UnsupportedTaggingProofProviders()
	if len(providers) != 1 {
		t.Fatal("mandatory tagging fixture missing")
	}
	var writes, acquisitions atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer backend.Close()
	inst := provider.Instance{ProviderName: providers[0].Name(), Endpoint: backend.URL, Region: testRegion, Bucket: "bucket", AccessKey: "backend-access", SecretKey: "backend-secret"}
	store := &postRejectionCache{Cache: cache.NewMemoryCache(1<<20, 16, time.Minute)}
	if err := store.Cache.Set(t.Context(), "bucket", "key", []byte("cached sentinel"), map[string]string{"owner": "cache"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	cred := postCredential("", nil)
	gw := postGateway(t, inst, cred, harness.WithCacheOverride(store), harness.WithBackendAcquisitionObserver(func() { acquisitions.Add(1) }))
	for _, tags := range []string{`<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>`, `<Tagging><TagSet></TagSet></Tagging>`} {
		response, body := postHTTP(t, gw, cred, makePostRequest(t, postFormURL(gw, "bucket"), "bucket", "key", cred, postFormCase{fields: map[string]string{"tagging": tags}, file: []byte("replacement")}))
		entry, ok := store.Cache.Get(t.Context(), "bucket", "key")
		if response.StatusCode != http.StatusNotImplemented || postSafeErrorCode(body) != "NotImplemented" || acquisitions.Load() != 0 || writes.Load() != 0 || store.deletes.Load() != 0 || store.sets.Load() != 0 || !ok || string(entry.Data) != "cached sentinel" {
			t.Fatal("local tagging prevalidation changed backend or cache")
		}
	}
}
