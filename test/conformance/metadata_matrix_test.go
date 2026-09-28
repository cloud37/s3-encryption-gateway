//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func testMetadataMatrix_Put(t *testing.T, inst provider.Instance) {
	runMetadataMatrix(t, inst, func(t *testing.T, gw *harness.Gateway, bucket, key string) {
		req, _ := http.NewRequest(http.MethodPut, objectURL(gw, bucket, key), bytes.NewReader([]byte("metadata")))
		setMetadataHeaders(req)
		resp, err := gw.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("PUT status=%d", resp.StatusCode)
		}
	}, harness.WithKeyManager(makeAESKEKManager(t)))
}

type metadataWriter func(*testing.T, *harness.Gateway, string, string)

func setMetadataHeaders(req *http.Request) {
	for name, value := range metadataValues() {
		req.Header.Set(name, value)
	}
	req.Header.Set("X-Amz-Meta-Owner", "team")
	req.Header.Set("X-Amz-Meta-Project", "gateway")
}

func runMetadataMatrix(t *testing.T, inst provider.Instance, writer metadataWriter, extra ...harness.Option) {
	t.Helper()
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%t", chunked), func(t *testing.T) {
			opts := append([]harness.Option{}, extra...)
			if chunked {
				opts = append(opts, harness.WithChunking(true))
			} else {
				opts = append(opts, harness.WithChunking(false))
			}
			gw := harness.StartGateway(t, inst, opts...)
			key := uniqueKey(t)
			writer(t, gw, inst.Bucket, key)
			wantBody := []byte("metadata")
			head, err := gw.HTTPClient().Head(objectURL(gw, inst.Bucket, key))
			if err != nil {
				t.Fatal(err)
			}
			head.Body.Close()
			if head.StatusCode != http.StatusOK || head.Header.Get("Content-Length") != fmt.Sprint(len(wantBody)) || head.Header.Get("ETag") == "" {
				t.Fatalf("HEAD status=%d Content-Length=%q ETag=%q", head.StatusCode, head.Header.Get("Content-Length"), head.Header.Get("ETag"))
			}
			headETag := head.Header.Get("ETag")
			assertNoReservedMetadata(t, head.Header)
			for _, tc := range []struct {
				name, rangeHeader, wantBody, wantRange string
			}{{"full", "", "metadata", ""}, {"first", "bytes=1-9", "etadata", "bytes 1-7/8"}, {"open", "bytes=5-", "ata", "bytes 5-7/8"}, {"suffix", "bytes=-7", "etadata", "bytes 1-7/8"}} {
				t.Run(tc.name, func(t *testing.T) {
					req, _ := http.NewRequest(http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
					if tc.rangeHeader != "" {
						req.Header.Set("Range", tc.rangeHeader)
					}
					resp, err := gw.HTTPClient().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					body, err := io.ReadAll(resp.Body)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(body, []byte(tc.wantBody)) {
						t.Fatalf("body=%q want=%q", body, tc.wantBody)
					}
					wantStatus := http.StatusOK
					if tc.rangeHeader != "" {
						wantStatus = http.StatusPartialContent
					}
					if resp.StatusCode != wantStatus {
						t.Errorf("GET status=%d want=%d", resp.StatusCode, wantStatus)
					}
					if got := resp.Header.Get("Content-Range"); got != tc.wantRange {
						t.Errorf("Content-Range=%q want=%q", got, tc.wantRange)
					}
					if got := resp.Header.Get("Content-Length"); got != fmt.Sprint(len(tc.wantBody)) {
						t.Errorf("Content-Length=%q want=%d", got, len(tc.wantBody))
					}
					if got := resp.Header.Get("ETag"); got == "" {
						t.Error("GET ETag missing")
					} else if got != headETag {
						t.Errorf("GET ETag=%q want HEAD/backend ETag %q", got, headETag)
					}
					assertNoReservedMetadata(t, resp.Header)
					if resp.Header.Get("X-Amz-Meta-Owner") != "team" || resp.Header.Get("X-Amz-Meta-Project") != "gateway" {
						t.Fatal("user metadata missing")
					}
					for i, name := range objectmeta.Names {
						want := fmt.Sprintf("metadata-%d", i)
						if name == "Expires" {
							want = "Mon, 21 Oct 2030 07:28:00 GMT"
						}
						if got := resp.Header.Get(name); got != want {
							t.Errorf("%s=%q", name, got)
						}
					}
				})
			}
			if head.Header.Get("X-Amz-Meta-Owner") != "team" || head.Header.Get("X-Amz-Meta-Project") != "gateway" {
				t.Fatal("HEAD user metadata missing")
			}
			for i, name := range objectmeta.Names {
				want := fmt.Sprintf("metadata-%d", i)
				if name == "Expires" {
					want = "Mon, 21 Oct 2030 07:28:00 GMT"
				}
				if got := head.Header.Get(name); got != want {
					t.Errorf("HEAD %s=%q", name, got)
				}
			}
		})
	}
}

func testMetadataMatrix_CopyDefault(t *testing.T, inst provider.Instance) {
	runMetadataMatrix(t, inst, func(t *testing.T, gw *harness.Gateway, bucket, key string) {
		src := uniqueKey(t)
		putReq, _ := http.NewRequest(http.MethodPut, objectURL(gw, bucket, src), bytes.NewReader([]byte("metadata")))
		setMetadataHeaders(putReq)
		resp, err := gw.HTTPClient().Do(putReq)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		req, _ := http.NewRequest(http.MethodPut, objectURL(gw, bucket, key), nil)
		req.Header.Set("x-amz-copy-source", "/"+bucket+"/"+src)
		resp, err = gw.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("COPY status=%d", resp.StatusCode)
		}
	}, harness.WithKeyManager(makeAESKEKManager(t)))
}

func testMetadataMatrix_CopyReplace(t *testing.T, inst provider.Instance) {
	runMetadataMatrix(t, inst, func(t *testing.T, gw *harness.Gateway, bucket, key string) {
		src := uniqueKey(t)
		put(t, gw, bucket, src, []byte("metadata"))
		req, _ := http.NewRequest(http.MethodPut, objectURL(gw, bucket, key), nil)
		req.Header.Set("x-amz-copy-source", "/"+bucket+"/"+src)
		req.Header.Set("x-amz-metadata-directive", "REPLACE")
		setMetadataHeaders(req)
		resp, err := gw.HTTPClient().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("COPY REPLACE status=%d", resp.StatusCode)
		}
	}, harness.WithKeyManager(makeAESKEKManager(t)))
}

func testMetadataMatrix_EncryptedMPU(t *testing.T, inst provider.Instance) {
	vk := provider.StartValkey(context.Background(), t)
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%t", chunked), func(t *testing.T) {
			gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket), harness.WithChunking(chunked), harness.WithKeyManager(makeAESKEKManager(t)))
			key := uniqueKey(t)
			values := metadataValues()
			uploadID := initiateMultipartUploadWithMetadata(t, gw, inst.Bucket, key, values)
			t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })
			part := bytes.Repeat([]byte("M"), 5*1024*1024)
			etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part)
			etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part)
			completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{{1, etag1}, {2, etag2}})
			assertMetadataMatrixReads(t, gw, inst.Bucket, key, bytes.Repeat(part, 2), values)
		})
	}
}

func testMetadataMatrix_UploadPartCopy(t *testing.T, inst provider.Instance) {
	vk := provider.StartValkey(context.Background(), t)
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprintf("chunked=%t", chunked), func(t *testing.T) {
			gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket), harness.WithChunking(chunked), harness.WithKeyManager(makeAESKEKManager(t)))
			source, destination := uniqueKey(t), uniqueKey(t)
			values := metadataValues()
			sourceBody := bytes.Repeat([]byte("C"), 5*1024*1024)
			putReq, _ := http.NewRequest(http.MethodPut, objectURL(gw, inst.Bucket, source), bytes.NewReader(sourceBody))
			for name, value := range values {
				putReq.Header.Set(name, value)
			}
			putReq.Header.Set("X-Amz-Meta-Owner", "team")
			putReq.Header.Set("X-Amz-Meta-Project", "gateway")
			resp, err := gw.HTTPClient().Do(putReq)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("source PUT status=%d", resp.StatusCode)
			}
			uploadID := initiateMultipartUploadWithMetadata(t, gw, inst.Bucket, destination, values)
			t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, destination, uploadID) })
			etag := doUploadPartCopy(t, gw, inst.Bucket, destination, uploadID, 1, inst.Bucket, source, "")
			completeMultipartUpload(t, gw, inst.Bucket, destination, uploadID, []mpuPart{{1, etag}})
			assertMetadataMatrixReads(t, gw, inst.Bucket, destination, sourceBody, values)
		})
	}
}

func initiateMultipartUploadWithMetadata(t *testing.T, gw *harness.Gateway, bucket, key string, values map[string]string) string {
	t.Helper()
	ctx, cancel := conformanceMPUContext()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/%s/%s?uploads", gw.URL, bucket, key), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range values {
		req.Header.Set(name, value)
	}
	req.Header.Set("X-Amz-Meta-Owner", "team")
	req.Header.Set("X-Amz-Meta-Project", "gateway")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CreateMultipartUpload status=%d body=%s", resp.StatusCode, body)
	}
	var result struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.UploadID == "" {
		t.Fatal("CreateMultipartUpload returned empty upload ID")
	}
	return result.UploadID
}

func metadataValues() map[string]string {
	values := make(map[string]string, len(objectmeta.Names))
	for i, name := range objectmeta.Names {
		values[name] = fmt.Sprintf("metadata-%d", i)
	}
	values["Expires"] = "Mon, 21 Oct 2030 07:28:00 GMT"
	return values
}

func assertMetadataMatrixReads(t *testing.T, gw *harness.Gateway, bucket, key string, wantBody []byte, values map[string]string) {
	t.Helper()
	head, err := gw.HTTPClient().Head(objectURL(gw, bucket, key))
	if err != nil {
		t.Fatal(err)
	}
	defer head.Body.Close()
	if head.StatusCode != http.StatusOK || head.Header.Get("ETag") == "" || head.Header.Get("Content-Length") != fmt.Sprint(len(wantBody)) {
		t.Fatalf("HEAD status=%d Content-Length=%q ETag=%q", head.StatusCode, head.Header.Get("Content-Length"), head.Header.Get("ETag"))
	}
	headETag := head.Header.Get("ETag")
	assertNoReservedMetadata(t, head.Header)
	last := int64(len(wantBody) - 1)
	for _, tc := range []struct {
		name, rangeHeader string
		start, end        int64
	}{{name: "full", start: 0, end: last}, {name: "fixed", rangeHeader: "bytes=1-9", start: 1, end: min(int64(9), last)}, {name: "open", rangeHeader: "bytes=5-", start: 5, end: last}, {name: "suffix", rangeHeader: "bytes=-7", start: max(int64(0), int64(len(wantBody))-7), end: last}} {
		t.Run("GET/"+tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, objectURL(gw, bucket, key), nil)
			if tc.rangeHeader != "" {
				req.Header.Set("Range", tc.rangeHeader)
			}
			resp, err := gw.HTTPClient().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			wantStatus := http.StatusOK
			if tc.rangeHeader != "" {
				wantStatus = http.StatusPartialContent
			}
			want := wantBody[tc.start : tc.end+1]
			if resp.StatusCode != wantStatus || !bytes.Equal(body, want) {
				t.Fatalf("GET status=%d body length=%d want status=%d body length=%d", resp.StatusCode, len(body), wantStatus, len(want))
			}
			if got := resp.Header.Get("Content-Length"); got != fmt.Sprint(len(want)) {
				t.Errorf("Content-Length=%q want=%d", got, len(want))
			}
			wantRange := ""
			if tc.rangeHeader != "" {
				wantRange = fmt.Sprintf("bytes %d-%d/%d", tc.start, tc.end, len(wantBody))
			}
			if got := resp.Header.Get("Content-Range"); got != wantRange {
				t.Errorf("Content-Range=%q want=%q", got, wantRange)
			}
			if got := resp.Header.Get("ETag"); got == "" {
				t.Error("ETag missing")
			} else if got != headETag {
				t.Errorf("GET ETag=%q want HEAD/backend ETag %q", got, headETag)
			}
			assertNoReservedMetadata(t, resp.Header)
			checkAllStandardHeaders(t, resp.Header, values)
			if resp.Header.Get("X-Amz-Meta-Owner") != "team" || resp.Header.Get("X-Amz-Meta-Project") != "gateway" {
				t.Error("user metadata missing")
			}
		})
	}
	if head.StatusCode != http.StatusOK || head.Header.Get("Content-Length") != fmt.Sprint(len(wantBody)) || head.Header.Get("ETag") == "" {
		t.Fatalf("HEAD status=%d Content-Length=%q ETag=%q", head.StatusCode, head.Header.Get("Content-Length"), head.Header.Get("ETag"))
	}
	checkAllStandardHeaders(t, head.Header, values)
	if head.Header.Get("X-Amz-Meta-Owner") != "team" || head.Header.Get("X-Amz-Meta-Project") != "gateway" {
		t.Fatal("HEAD user metadata missing")
	}
	assertNoReservedMetadata(t, head.Header)
}

func assertNoReservedMetadata(t *testing.T, headers http.Header) {
	t.Helper()
	for name := range headers {
		if crypto.IsGatewayReservedKey(name) {
			t.Errorf("reserved gateway metadata exposed in response: %s", name)
		}
	}
}

func checkAllStandardHeaders(t *testing.T, got http.Header, values map[string]string) {
	t.Helper()
	for _, name := range objectmeta.Names {
		if value := got.Get(name); value != values[name] {
			t.Errorf("%s=%q want %q", name, value, values[name])
		}
	}
}

func testMetadata_ResponseOverrides_Presigned(t *testing.T, inst provider.Instance) {
	gw := harness.StartGateway(t, inst, harness.WithAuth(config.GatewayCredential{AccessKey: testAccessKey, SecretKey: testSecretKey}))
	key := uniqueKey(t)
	putSigned(t, gw, inst.Bucket, key, []byte("presigned metadata"), testAccessKey, testSecretKey)
	headReq, err := http.NewRequest(http.MethodHead, objectURL(gw, inst.Bucket, key), nil)
	if err != nil {
		t.Fatal(err)
	}
	headReq.Host = headReq.URL.Host
	signV4Headers(t, headReq, testAccessKey, testSecretKey, nil)
	head, err := gw.HTTPClient().Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	headETag := head.Header.Get("ETag")
	head.Body.Close()
	if head.StatusCode != http.StatusOK || headETag == "" {
		t.Fatalf("baseline HEAD status=%d ETag=%q", head.StatusCode, headETag)
	}
	query := url.Values{
		"response-content-type":        {"application/x-presigned-override"},
		"response-content-language":    {"fr"},
		"response-expires":             {"Wed, 21 Oct 2030 07:28:00 GMT"},
		"response-cache-control":       {"no-store"},
		"response-content-disposition": {"attachment; filename=override.txt"},
		"response-content-encoding":    {"br"},
	}
	signed := presignV4GETWithQuery(t, gw, inst.Bucket, key, testAccessKey, testSecretKey, time.Hour, query)
	req, err := http.NewRequest(http.MethodGet, signed, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || string(body) != "presigned metadata" {
		t.Fatalf("presigned GET status=%d body=%q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("ETag"); got == "" || got != headETag {
		t.Errorf("presigned GET ETag=%q want baseline HEAD ETag %q", got, headETag)
	}
	if got := resp.Header.Get("Content-Length"); got != fmt.Sprint(len(body)) {
		t.Errorf("presigned Content-Length=%q want=%d", got, len(body))
	}
	if got := resp.Header.Get("Content-Type"); got != "application/x-presigned-override" {
		t.Fatalf("presigned Content-Type override=%q", got)
	}
	for name, want := range map[string]string{
		"Content-Language": "fr", "Expires": "Wed, 21 Oct 2030 07:28:00 GMT",
		"Cache-Control": "no-store", "Content-Disposition": "attachment; filename=override.txt", "Content-Encoding": "br",
	} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("presigned %s=%q want %q", name, got, want)
		}
	}
}

func testMetadata_BypassBucketStandardHeaders(t *testing.T, inst provider.Instance) {
	pm := newBypassPolicyManager(t, inst.Bucket)
	gw := harness.StartGateway(t, inst, harness.WithPolicyManager(pm))
	key := uniqueKey(t)
	req, _ := http.NewRequest(http.MethodPut, objectURL(gw, inst.Bucket, key), bytes.NewReader([]byte("bypass")))
	req.Header.Set("Content-Type", "text/csv")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status=%d", resp.StatusCode)
	}
	head, err := gw.HTTPClient().Head(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatal(err)
	}
	defer head.Body.Close()
	if head.Header.Get("Content-Type") != "text/csv" || head.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("bypass standard metadata not preserved")
	}
}

func testMetadata_ReservedKeyRejected(t *testing.T, inst provider.Instance) {
	gw := harness.StartGateway(t, inst)
	req, _ := http.NewRequest(http.MethodPut, objectURL(gw, inst.Bucket, uniqueKey(t)), bytes.NewReader([]byte("reserved")))
	req.Header.Set("x-amz-meta-encrypted", "true")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func testMetadata_CopyDirectiveInvalid(t *testing.T, inst provider.Instance) {
	gw := harness.StartGateway(t, inst)
	src, dst := uniqueKey(t), uniqueKey(t)
	put(t, gw, inst.Bucket, src, []byte("directive"))
	req, _ := http.NewRequest(http.MethodPut, objectURL(gw, inst.Bucket, dst), nil)
	req.Header.Set("x-amz-copy-source", "/"+inst.Bucket+"/"+src)
	req.Header.Set("x-amz-metadata-directive", "INVALID")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func testMetadata_CacheHitServesBody(t *testing.T, inst provider.Instance) {
	backendGets := &countBackendGets{base: http.DefaultTransport}
	gw := harness.StartGateway(t, inst, harness.WithBackendTransport(backendGets), harness.WithConfigMutator(func(cfg *config.Config) {
		cfg.Cache.Enabled = true
		cfg.Cache.MaxSize = 1024 * 1024
		cfg.Cache.MaxItems = 10
		cfg.Cache.DefaultTTL = time.Minute
	}))
	key := uniqueKey(t)
	want := []byte("cache body")
	put(t, gw, inst.Bucket, key, want)
	if got := get(t, gw, inst.Bucket, key); !bytes.Equal(got, want) {
		t.Fatalf("first body mismatch")
	}
	if got := get(t, gw, inst.Bucket, key); !bytes.Equal(got, want) {
		t.Fatalf("cache body mismatch")
	}
	getsAfterFill := backendGets.gets.Load()
	if getsAfterFill == 0 {
		t.Fatal("initial GET did not reach the backend")
	}
	if got := get(t, gw, inst.Bucket, key); !bytes.Equal(got, want) {
		t.Fatalf("second cache body mismatch")
	}
	if got := backendGets.gets.Load(); got != getsAfterFill {
		t.Fatalf("second full GET reached backend: GET requests %d -> %d; response was not a cache hit", getsAfterFill, got)
	}
	backend := newS3Client(t, inst)
	updated := []byte("fresh backend body")
	engine, err := crypto.NewEngine([]byte("test-encryption-password-123456"))
	if err != nil {
		t.Fatal(err)
	}
	encReader, metadata, err := engine.Encrypt(context.Background(), crypto.ObjectContext{Bucket: inst.Bucket, Key: key}, bytes.NewReader(updated), nil)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatal(err)
	}
	metadata["ETag"] = `"direct-backend-v2"`
	if _, err := backend.PutObject(context.Background(), inst.Bucket, key, bytes.NewReader(ciphertext), metadata, nil, "", nil, "", "", "", "", ""); err != nil {
		t.Fatalf("replace backend object: %v", err)
	}
	if got := get(t, gw, inst.Bucket, key); !bytes.Equal(got, updated) {
		t.Fatalf("ETag mismatch did not refresh object: got %q want %q", got, updated)
	}
}

type countBackendGets struct {
	base http.RoundTripper
	gets atomic.Int64
}

func (c *countBackendGets) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet && !strings.Contains(req.URL.RawQuery, "uploadId=") {
		c.gets.Add(1)
	}
	return c.base.RoundTrip(req)
}

func testListObjects_EncryptedMPUv2_PlaintextSize(t *testing.T, inst provider.Instance) {
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket), harness.WithKeyManager(makeAESKEKManager(t)))
	key := uniqueKey(t)
	data := bytes.Repeat([]byte("L"), 5*1024*1024)
	uploadID := initiateMultipartUploadWithMetadata(t, gw, inst.Bucket, key, metadataValues())
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })
	etag := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, data)
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{{1, etag}})
	resp, err := gw.HTTPClient().Get(fmt.Sprintf("%s/%s?prefix=%s", gw.URL, inst.Bucket, key))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("ListObjects status=%d err=%v body=%s", resp.StatusCode, err, body)
	}
	var result struct {
		Contents []struct {
			Key  string `xml:"Key"`
			Size int64  `xml:"Size"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("parse ListObjects XML: %v body=%s", err, body)
	}
	if len(result.Contents) != 1 || result.Contents[0].Key != key || result.Contents[0].Size != int64(len(data)) {
		t.Fatalf("listed contents=%+v, want key=%q plaintext size=%d", result.Contents, key, len(data))
	}
}
func testDeleteObjects_EncryptedMPUv2_RemovesManifest(t *testing.T, inst provider.Instance) {
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket))
	key := uniqueKey(t)
	data := bytes.Repeat([]byte("D"), 5*1024*1024)
	uploadID := initiateMultipartUploadWithMetadata(t, gw, inst.Bucket, key, metadataValues())
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })
	etag := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, data)
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{{1, etag}})
	backend := newS3Client(t, inst)
	if _, err := backend.HeadObject(ctx, inst.Bucket, key+".mpu-manifest", nil); err != nil {
		t.Fatalf("manifest missing before gateway DeleteObject: %v", err)
	}
	body := fmt.Sprintf(`<Delete><Object><Key>%s</Key></Object></Delete>`, key)
	deleteReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/%s?delete", gw.URL, inst.Bucket), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	digest := md5.Sum([]byte(body))
	deleteReq.Header.Set("Content-Type", "application/xml")
	deleteReq.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(digest[:]))
	batchResp, err := gw.HTTPClient().Do(deleteReq)
	if err != nil {
		t.Fatal(err)
	}
	batchBody, _ := io.ReadAll(batchResp.Body)
	batchResp.Body.Close()
	if batchResp.StatusCode != http.StatusOK || bytes.Contains(batchBody, []byte("<Error>")) {
		t.Fatalf("gateway DeleteObjects status=%d body=%s", batchResp.StatusCode, batchBody)
	}
	if _, err := backend.HeadObject(ctx, inst.Bucket, key, nil); err == nil {
		t.Fatal("primary object still exists after gateway DeleteObjects")
	}
	if _, err := backend.HeadObject(ctx, inst.Bucket, key+".mpu-manifest", nil); err == nil {
		t.Fatal("companion manifest still exists after gateway DeleteObjects")
	}
}

func testDeleteObject_EncryptedMPUv2_RemovesManifest(t *testing.T, inst provider.Instance) {
	ctx := context.Background()
	vk := provider.StartValkey(ctx, t)
	gw := harness.StartGateway(t, inst, harness.WithValkeyAddr(vk.Addr), harness.WithEncryptedMPUForBucket(inst.Bucket), harness.WithKeyManager(makeAESKEKManager(t)))
	key := uniqueKey(t)
	data := bytes.Repeat([]byte("D"), 5*1024*1024)
	uploadID := initiateMultipartUploadWithMetadata(t, gw, inst.Bucket, key, metadataValues())
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })
	etag := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, data)
	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{{1, etag}})
	backend := newS3Client(t, inst)
	if _, err := backend.HeadObject(ctx, inst.Bucket, key+crypto.MPUManifestSuffix, nil); err != nil {
		t.Fatalf("manifest missing before gateway DeleteObject: %v", err)
	}
	req, err := http.NewRequest(http.MethodDelete, objectURL(gw, inst.Bucket, key), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		t.Fatalf("gateway DeleteObject status=%d body=%s", resp.StatusCode, body)
	}
	if _, err := backend.HeadObject(ctx, inst.Bucket, key+crypto.MPUManifestSuffix, nil); err == nil {
		t.Fatal("companion manifest still exists after gateway DeleteObject")
	}
	if _, err := backend.HeadObject(ctx, inst.Bucket, key, nil); err == nil {
		t.Fatal("primary object still exists after gateway DeleteObject")
	}
}
