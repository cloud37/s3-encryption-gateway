//go:build conformance

package conformance

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

func sec49InitiateSignedMultipart(t *testing.T, gw *harness.Gateway, bucket, key string) string {
	t.Helper()
	target := fmt.Sprintf("%s/%s/%s?uploads", gw.URL, bucket, key)
	resp := sec43SignedRequest(t, gw, http.MethodPost, target, nil, nil)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed multipart init status=%d body=%s", resp.StatusCode, body)
	}
	var result struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		UploadID string   `xml:"UploadId"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.UploadID == "" {
		t.Fatal("signed multipart init returned empty UploadId")
	}
	return result.UploadID
}

func testSEC49_ValidBoundedSignedPayloads(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key, data := uniqueKey(t), []byte("SEC-49 bounded payload")
	t.Cleanup(func() { deleteSigned(t, gw, inst.Bucket, key, sec41Access, sec41Secret) })
	resp := sec43SignedRequest(t, gw, http.MethodPut, objectURL(gw, inst.Bucket, key), data, data)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("bounded PUT status=%d body=%s", resp.StatusCode, body)
	}

	partKey := uniqueKey(t)
	uploadID := sec49InitiateSignedMultipart(t, gw, inst.Bucket, partKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, partKey, uploadID) })
	target := fmt.Sprintf("%s/%s/%s?partNumber=1&uploadId=%s", gw.URL, inst.Bucket, partKey, uploadID)
	part := []byte("bounded signed part")
	partResp := sec43SignedRequest(t, gw, http.MethodPut, target, part, part)
	defer partResp.Body.Close()
	if partResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(partResp.Body)
		t.Fatalf("bounded UploadPart status=%d body=%s", partResp.StatusCode, body)
	}
}

func testSEC49_OversizeSignedPayloadNoMutation(t *testing.T, inst provider.Instance) {
	gw := sec41Gateway(t, inst)
	key := uniqueKey(t)
	req, err := http.NewRequest(http.MethodPut, objectURL(gw, inst.Bucket, key), bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = 6 << 30
	req.Host = req.URL.Host
	signV4Headers(t, req, sec41Access, sec41Secret, []byte("x"))
	resp := sec49DoDeceptiveRequest(t, req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize PUT status=%d body=%s", resp.StatusCode, body)
	}
	get, _ := sec41AuthRequest(t, gw, http.MethodGet, objectURL(gw, inst.Bucket, key), nil)
	get.Body.Close()
	if get.StatusCode == http.StatusOK {
		t.Fatal("oversize request mutated object")
	}

	partKey := uniqueKey(t)
	uploadID := sec49InitiateSignedMultipart(t, gw, inst.Bucket, partKey)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, partKey, uploadID) })
	partReq, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/%s/%s?partNumber=1&uploadId=%s", gw.URL, inst.Bucket, partKey, uploadID), bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	partReq.ContentLength = 6 << 30
	partReq.Host = partReq.URL.Host
	signV4Headers(t, partReq, sec41Access, sec41Secret, []byte("x"))
	partResp := sec49DoDeceptiveRequest(t, partReq)
	partBody, _ := io.ReadAll(partResp.Body)
	partResp.Body.Close()
	if partResp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize UploadPart status=%d body=%s", partResp.StatusCode, partBody)
	}
	listReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, inst.Bucket, partKey, uploadID), nil)
	listResp, err := gw.HTTPClient().Do(listReq)
	if err != nil {
		t.Fatal(err)
	}
	listBody, _ := io.ReadAll(listResp.Body)
	listResp.Body.Close()
	if bytes.Contains(listBody, []byte("<PartNumber>1</PartNumber>")) {
		t.Fatal("oversize UploadPart mutated MPU")
	}
}
