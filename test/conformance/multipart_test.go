//go:build conformance

package conformance

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/kenchrcum/s3-encryption-gateway/test/harness"
	"github.com/kenchrcum/s3-encryption-gateway/test/provider"
)

// initiateMultipartUpload starts a multipart upload and returns the uploadId.
func initiateMultipartUpload(t *testing.T, gw *harness.Gateway, bucket, key string) string {
	t.Helper()
	u := fmt.Sprintf("%s/%s/%s?uploads", gw.URL, bucket, key)
	resp, err := gw.HTTPClient().Post(u, "application/xml", nil)
	if err != nil {
		t.Fatalf("InitiateMultipartUpload %q: %v", key, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("InitiateMultipartUpload %q: status %d: %s", key, resp.StatusCode, string(body))
	}
	var result struct {
		XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
		UploadID string   `xml:"UploadId"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("InitiateMultipartUpload: decode: %v", err)
	}
	if result.UploadID == "" {
		t.Fatal("InitiateMultipartUpload: empty UploadId")
	}
	return result.UploadID
}

// uploadPart uploads one part and returns its ETag.
func uploadPart(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string, partNum int, data []byte) string {
	t.Helper()
	u := fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s",
		gw.URL, bucket, key, partNum, uploadID)
	req, _ := http.NewRequest("PUT", u, bytes.NewReader(data))
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("UploadPart #%d: %v", partNum, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("UploadPart #%d: status %d: %s", partNum, resp.StatusCode, string(body))
	}
	return resp.Header.Get("ETag")
}

// mpuPart holds part number and ETag for CompleteMultipartUpload.
type mpuPart struct {
	Number int
	ETag   string
}

// completeMultipartUpload finishes a multipart upload.
func completeMultipartUpload(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string, parts []mpuPart) {
	t.Helper()
	var xmlParts strings.Builder
	xmlParts.WriteString("<CompleteMultipartUpload>")
	for _, p := range parts {
		xmlParts.WriteString(fmt.Sprintf("<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
			p.Number, p.ETag))
	}
	xmlParts.WriteString("</CompleteMultipartUpload>")

	u := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, uploadID)
	req, _ := http.NewRequest("POST", u, strings.NewReader(xmlParts.String()))
	req.Header.Set("Content-Type", "application/xml")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CompleteMultipartUpload: status %d: %s", resp.StatusCode, string(body))
	}
}

// abortMultipartUpload aborts a multipart upload.
func abortMultipartUpload(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string) {
	t.Helper()
	u := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, uploadID)
	req, _ := http.NewRequest("DELETE", u, nil)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Logf("AbortMultipartUpload: %v (non-fatal)", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

// testMultipartBasic verifies a basic 2-part multipart upload round-trip.
func testMultipartBasic(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	// S3 requires a minimum 5 MiB for all parts except the last.
	part1 := bytes.Repeat([]byte("p1"), 5*1024*1024/2) // 5 MiB
	part2 := []byte("final-part-data")

	etag1 := uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1)
	etag2 := uploadPart(t, gw, inst.Bucket, key, uploadID, 2, part2)

	completeMultipartUpload(t, gw, inst.Bucket, key, uploadID, []mpuPart{
		{1, etag1},
		{2, etag2},
	})

	got := get(t, gw, inst.Bucket, key)
	want := append(part1, part2...)
	if !bytes.Equal(got, want) {
		t.Errorf("multipart basic: round-trip mismatch (%d bytes vs %d expected)",
			len(got), len(want))
	}
}

// testMultipartAbort verifies that an aborted multipart upload leaves no
// object at the key.
func testMultipartAbort(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)

	part1 := bytes.Repeat([]byte("a"), 5*1024*1024)
	uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1)

	abortMultipartUpload(t, gw, inst.Bucket, key, uploadID)

	// The object must not exist after abort.
	resp, err := gw.HTTPClient().Get(objectURL(gw, inst.Bucket, key))
	if err != nil {
		t.Fatalf("GET after abort: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("GET after abort: status %d, want 404", resp.StatusCode)
	}
}

// testMultipartListParts verifies that ListParts returns the uploaded parts.
func testMultipartListParts(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)

	key := uniqueKey(t)
	uploadID := initiateMultipartUpload(t, gw, inst.Bucket, key)
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, uploadID) })

	part1 := bytes.Repeat([]byte("L"), 5*1024*1024)
	uploadPart(t, gw, inst.Bucket, key, uploadID, 1, part1)

	u := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, inst.Bucket, key, uploadID)
	resp, err := gw.HTTPClient().Get(u)
	if err != nil {
		t.Fatalf("ListParts: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListParts: status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		XMLName xml.Name `xml:"ListPartsResult"`
		Parts   []struct {
			PartNumber int    `xml:"PartNumber"`
			ETag       string `xml:"ETag"`
			Size       int64  `xml:"Size"`
		} `xml:"Part"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatalf("ListParts: decode: %v", err)
	}
	if len(result.Parts) != 1 {
		t.Errorf("ListParts: got %d parts, want 1", len(result.Parts))
	}
}
