//go:build conformance

package conformance

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

const sec41Access = "SEC41ACCESS"
const sec41Secret = "sec41-independent-secret"

func sec41HMAC(key, data []byte) [32]byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func sec41Key(secret, date, region string) []byte {
	d := sec41HMAC([]byte("AWS4"+secret), []byte(date))
	r := sec41HMAC(d[:], []byte(region))
	s := sec41HMAC(r[:], []byte("s3"))
	k := sec41HMAC(s[:], []byte("aws4_request"))
	return k[:]
}
func sec41Chunk(key []byte, timestamp, scope string, previous [32]byte, data []byte) [32]byte {
	d := sha256.Sum256(data)
	e := sha256.Sum256(nil)
	return sec41HMAC(key, []byte("AWS4-HMAC-SHA256-PAYLOAD\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(previous[:])+"\n"+hex.EncodeToString(e[:])+"\n"+hex.EncodeToString(d[:])))
}

func sec41Body(data []byte, key []byte, timestamp, scope string, seed [32]byte, trailer bool) []byte {
	var b strings.Builder
	previous := seed
	for _, part := range [][]byte{data[:len(data)/2], data[len(data)/2:]} {
		sig := sec41Chunk(key, timestamp, scope, previous, part)
		fmt.Fprintf(&b, "%x;chunk-signature=%s\r\n", len(part), hex.EncodeToString(sig[:]))
		b.Write(part)
		b.WriteString("\r\n")
		previous = sig
	}
	zero := sec41Chunk(key, timestamp, scope, previous, nil)
	fmt.Fprintf(&b, "0;chunk-signature=%s\r\n", hex.EncodeToString(zero[:]))
	if trailer {
		digest := sha256.Sum256(data)
		value := base64.StdEncoding.EncodeToString(digest[:])
		canonical := "x-amz-checksum-sha256:" + value + "\n"
		canonicalDigest := sha256.Sum256([]byte(canonical))
		input := "AWS4-HMAC-SHA256-TRAILER\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(zero[:]) + "\n" + hex.EncodeToString(canonicalDigest[:])
		signature := sec41HMAC(key, []byte(input))
		fmt.Fprintf(&b, "x-amz-checksum-sha256: %s\r\nx-amz-trailer-signature: %s\r\n\r\n", value, hex.EncodeToString(signature[:]))
	}
	return []byte(b.String())
}

func sec41Request(t *testing.T, gw *harness.Gateway, bucket, keyName string, payload []byte, mode string, mutate bool) (*http.Response, []byte) {
	t.Helper()
	now := time.Now().UTC()
	timestamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	scope := date + "/" + "us-east-1" + "/s3/aws4_request"
	signingKey := sec41Key(sec41Secret, date, "us-east-1")
	target := gw.URL + "/" + bucket + "/" + keyName
	req, err := http.NewRequest(http.MethodPut, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Amz-Date", timestamp)
	req.Header.Set("X-Amz-Content-Sha256", mode)
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("X-Amz-Decoded-Content-Length", fmt.Sprint(len(payload)))
	if mode == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" {
		req.Header.Set("X-Amz-Trailer", "x-amz-checksum-sha256")
	}
	req.Host = req.URL.Host
	canonicalHeaders := "host:" + req.Host + "\n" + "x-amz-content-sha256:" + mode + "\n" + "x-amz-date:" + timestamp + "\n"
	canonical := "PUT\n" + sec41EncodePath(req.URL.Path) + "\n" + sec41CanonicalQuery(req.URL.Query()) + "\n" + canonicalHeaders + "\n" + "host;x-amz-content-sha256;x-amz-date\n" + mode
	canonicalDigest := sha256.Sum256([]byte(canonical))
	stringToSign := "AWS4-HMAC-SHA256\n" + timestamp + "\n" + scope + "\n" + hex.EncodeToString(canonicalDigest[:])
	seed := sec41HMAC(signingKey, []byte(stringToSign))
	wire := sec41Body(payload, signingKey, timestamp, scope, seed, mode == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
	if mutate {
		// Keep the framing syntactically valid so the gateway reaches the
		// signed-chain check rather than rejecting malformed wire bytes.
		firstData := bytes.Index(wire, []byte("\r\n")) + 2
		wire[firstData] ^= 1
	}
	req.Body = io.NopCloser(bytes.NewReader(wire))
	req.ContentLength = int64(len(wire))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+sec41Access+"/"+scope+", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+hex.EncodeToString(seed[:]))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, got
}

func sec41AuthRequest(t *testing.T, gw *harness.Gateway, method, target string, body []byte) (*http.Response, []byte) {
	t.Helper()
	now := time.Now().UTC()
	timestamp, date := now.Format("20060102T150405Z"), now.Format("20060102")
	scope := date + "/us-east-1/s3/aws4_request"
	key := sec41Key(sec41Secret, date, "us-east-1")
	req, err := http.NewRequest(method, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	req.Header.Set("X-Amz-Date", timestamp)
	payloadHash := sha256.Sum256(body)
	req.Header.Set("X-Amz-Content-Sha256", hex.EncodeToString(payloadHash[:]))
	canonical := method + "\n" + sec41EncodePath(req.URL.Path) + "\n" + sec41CanonicalQuery(req.URL.Query()) + "\n" + "host:" + req.Host + "\n" + "x-amz-content-sha256:" + hex.EncodeToString(payloadHash[:]) + "\n" + "x-amz-date:" + timestamp + "\n\n" + "host;x-amz-content-sha256;x-amz-date\n" + hex.EncodeToString(payloadHash[:])
	canonicalHash := sha256.Sum256([]byte(canonical))
	seed := sec41HMAC(key, []byte("AWS4-HMAC-SHA256\n"+timestamp+"\n"+scope+"\n"+hex.EncodeToString(canonicalHash[:])))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+sec41Access+"/"+scope+", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature="+hex.EncodeToString(seed[:]))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp, got
}

func sec41AbortMultipartUpload(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string) {
	t.Helper()
	_, _ = sec41AuthRequest(t, gw, http.MethodDelete,
		fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, url.QueryEscape(uploadID)), nil)
}

func sec41Encode(value string) string { return strings.ReplaceAll(url.QueryEscape(value), "+", "%20") }

func sec41EncodePath(path string) string {
	parts := strings.Split(path, "/")
	for i := range parts {
		parts[i] = sec41Encode(parts[i])
	}
	return strings.Join(parts, "/")
}

func sec41CanonicalQuery(values url.Values) string {
	items := make([]string, 0)
	for key, vals := range values {
		for _, value := range vals {
			items = append(items, sec41Encode(key)+"="+sec41Encode(value))
		}
	}
	sort.Strings(items)
	return strings.Join(items, "&")
}

func sec41Gateway(t *testing.T, inst provider.Instance) *harness.Gateway {
	return harness.StartGateway(t, inst, harness.WithAuth(config.GatewayCredential{AccessKey: sec41Access, SecretKey: sec41Secret}))
}

func testSEC41_SigV4Streaming_PutObjectRoundTrip(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	data := []byte("SEC-41 multi-chunk object payload")
	resp, body := sec41Request(t, gw, inst.Bucket, key, data, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("put status %d body=%s", resp.StatusCode, body)
	}
	getResp, got := sec41AuthRequest(t, gw, http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
	if getResp.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("roundtrip %q", got)
	}
}
func testSEC41_SigV4Streaming_TamperedPutObjectRejectedWithoutObject(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	resp, _ := sec41Request(t, gw, inst.Bucket, key, []byte("tampered"), "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", true)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status %d", resp.StatusCode)
	}
	getResp, _ := sec41AuthRequest(t, gw, http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
	if getResp.StatusCode == http.StatusOK {
		t.Fatal("tampered object exists")
	}
}
func testSEC41_SigV4Streaming_UploadPartRoundTrip(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	resp, body := sec41AuthRequest(t, gw, http.MethodPost, fmt.Sprintf("%s/%s/%s?uploads", gw.URL, inst.Bucket, key), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initiate status %d body=%s", resp.StatusCode, body)
	}
	var initResult struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(body, &initResult); err != nil {
		t.Fatal(err)
	}
	uploadID := initResult.UploadID
	defer sec41AbortMultipartUpload(t, gw, inst.Bucket, key, uploadID)
	data := []byte("SEC-41 signed multipart part")
	resp, _ = sec41Request(t, gw, inst.Bucket, key+"?partNumber=1&uploadId="+url.QueryEscape(uploadID), data, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("part status %d", resp.StatusCode)
	}
	listResp, listBody := sec41AuthRequest(t, gw, http.MethodGet, fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, inst.Bucket, key, url.QueryEscape(uploadID)), nil)
	if listResp.StatusCode != http.StatusOK || !bytes.Contains(listBody, []byte("<PartNumber>1</PartNumber>")) {
		t.Fatalf("ListParts status %d body=%s", listResp.StatusCode, listBody)
	}
}
func testSEC41_SigV4Streaming_TamperedUploadPartRejected(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	resp, body := sec41AuthRequest(t, gw, http.MethodPost, fmt.Sprintf("%s/%s/%s?uploads", gw.URL, inst.Bucket, key), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initiate status %d body=%s", resp.StatusCode, body)
	}
	var initResult struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(body, &initResult); err != nil {
		t.Fatal(err)
	}
	uploadID := initResult.UploadID
	defer sec41AbortMultipartUpload(t, gw, inst.Bucket, key, uploadID)
	resp, body = sec41Request(t, gw, inst.Bucket, key+"?partNumber=1&uploadId="+url.QueryEscape(uploadID), []byte("bad part"), "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", true)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("part status %d body=%s", resp.StatusCode, body)
	}
	listResp, listBody := sec41AuthRequest(t, gw, http.MethodGet,
		fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, inst.Bucket, key, url.QueryEscape(uploadID)), nil)
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("ListParts status %d body=%s", listResp.StatusCode, listBody)
	}
	if bytes.Contains(listBody, []byte("<PartNumber>1</PartNumber>")) {
		t.Fatalf("rejected part appears in ListParts: %s", listBody)
	}
}
func testSEC41_SigV4Streaming_SignedTrailerPutRoundTrip(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	data := []byte("signed trailer payload")
	resp, _ := sec41Request(t, gw, inst.Bucket, key, data, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("trailer status %d", resp.StatusCode)
	}
	getResp, got := sec41AuthRequest(t, gw, http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
	if getResp.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("trailer roundtrip %q", got)
	}
}
