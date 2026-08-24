//go:build conformance

package conformance

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func sec43SignedRequest(t *testing.T, gw *harness.Gateway, method, target string, signed, sent []byte) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, target, bytes.NewReader(sent))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = req.URL.Host
	signV4Headers(t, req, sec41Access, sec41Secret, signed)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func testSEC43_SigV4ConcretePayload_PutObjectRoundTrip(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key, data := uniqueKey(t), []byte("SEC-43 concrete payload")
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, sec41Access, sec41Secret) })
	resp := sec43SignedRequest(t, gw, http.MethodPut, objectURL(gw, inst.Bucket, key), data, data)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT status %d: %s", resp.StatusCode, body)
	}
	getResp, got := sec41AuthRequest(t, gw, http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
	if getResp.StatusCode != http.StatusOK || !bytes.Equal(got, data) {
		t.Fatalf("roundtrip status %d body %q", getResp.StatusCode, got)
	}
}

func testSEC43_SigV4ConcretePayload_TamperedPutRejectedWithoutObject(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key, original := uniqueKey(t), []byte("original")
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, sec41Access, sec41Secret) })
	resp := sec43SignedRequest(t, gw, http.MethodPut, objectURL(gw, inst.Bucket, key), original, []byte("tampered"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("SignatureDoesNotMatch")) {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	getResp, _ := sec41AuthRequest(t, gw, http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
	getResp.Body.Close()
	if getResp.StatusCode == http.StatusOK {
		t.Fatal("tampered PUT created an object")
	}
}

func testSEC43_SigV4ConcretePayload_TamperedUploadPartRejected(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	// Cleanup is registered immediately so failed assertions cannot leak the MPU.
	resp, body := sec41AuthRequest(t, gw, http.MethodPost, objectURL(gw, inst.Bucket, key)+"?uploads", nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initiate status %d: %s", resp.StatusCode, body)
	}
	var result struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sec41AbortMultipartUpload(t, gw, inst.Bucket, key, result.UploadID) })
	target := objectURL(gw, inst.Bucket, key) + "?partNumber=1&uploadId=" + url.QueryEscape(result.UploadID)
	part := []byte("original part")
	resp = sec43SignedRequest(t, gw, http.MethodPut, target, part, []byte("tampered part"))
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("SignatureDoesNotMatch")) {
		t.Fatalf("part status %d body %s", resp.StatusCode, body)
	}
	listResp, listBody := sec41AuthRequest(t, gw, http.MethodGet, objectURL(gw, inst.Bucket, key)+"?uploadId="+url.QueryEscape(result.UploadID), nil)
	listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK || bytes.Contains(listBody, []byte("<PartNumber>1</PartNumber>")) {
		t.Fatalf("part persisted: status=%d body=%s", listResp.StatusCode, listBody)
	}
}

func testSEC43_SigV4ConcretePayload_TamperedDeleteObjectsRejectedWithoutDeletion(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	putSigned(t, gw, inst.Bucket, key, []byte("keep"), sec41Access, sec41Secret)
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, sec41Access, sec41Secret) })
	xmlBody := []byte("<Delete><Object><Key>" + key + "</Key></Object></Delete>")
	target := objectURL(gw, inst.Bucket, key) + "?delete"
	resp := sec43SignedRequest(t, gw, http.MethodPost, target, xmlBody, []byte("<Delete><Object><Key>other</Key></Object></Delete>"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("SignatureDoesNotMatch")) {
		t.Fatalf("delete status %d body %s", resp.StatusCode, body)
	}
	getResp, _ := sec41AuthRequest(t, gw, http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatal("object was deleted")
	}
}

func testSEC43_SigV4ConcretePayload_TamperedTaggingRejectedWithoutMutation(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	putSigned(t, gw, inst.Bucket, key, []byte("tagged"), sec41Access, sec41Secret)
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, sec41Access, sec41Secret) })
	original := []byte("<Tagging><TagSet><Tag><Key>old</Key><Value>one</Value></Tag></TagSet></Tagging>")
	seed := sec43SignedRequest(t, gw, http.MethodPut, objectURL(gw, inst.Bucket, key)+"?tagging", original, original)
	seed.Body.Close()
	if seed.StatusCode != http.StatusOK {
		t.Fatalf("seed tags status %d", seed.StatusCode)
	}
	target := objectURL(gw, inst.Bucket, key) + "?tagging"
	resp := sec43SignedRequest(t, gw, http.MethodPut, target, original, []byte("<Tagging><TagSet><Tag><Key>new</Key><Value>two</Value></Tag></TagSet></Tagging>"))
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !bytes.Contains(body, []byte("SignatureDoesNotMatch")) {
		t.Fatalf("tagging status %d body %s", resp.StatusCode, body)
	}
	getResp, tags := sec41AuthRequest(t, gw, http.MethodGet, target, nil)
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK || !bytes.Contains(tags, []byte("old")) || !bytes.Contains(tags, []byte("one")) {
		t.Fatalf("tags mutated: status=%d body=%s", getResp.StatusCode, tags)
	}
}
