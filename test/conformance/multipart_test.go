//go:build conformance

package conformance

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cloud37/s3-encryption-gateway/test/harness"
	"github.com/cloud37/s3-encryption-gateway/test/provider"
)

const conformanceMPURequestTimeout = 90 * time.Second

func conformanceMPUContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), conformanceMPURequestTimeout)
}

// initiateMultipartUpload starts a multipart upload and returns the uploadId.
func initiateMultipartUpload(t *testing.T, gw *harness.Gateway, bucket, key string) string {
	t.Helper()
	u := fmt.Sprintf("%s/%s/%s?uploads", gw.URL, bucket, key)
	ctx, cancel := conformanceMPUContext()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		t.Fatalf("InitiateMultipartUpload %q: create request: %v", key, err)
	}
	req.Header.Set("Content-Type", "application/xml")
	resp, err := gw.HTTPClient().Do(req)
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
	ctx, cancel := conformanceMPUContext()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UploadPart #%d: create request: %v", partNum, err)
	}
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

func uploadPartStatus(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string, partNum int, data []byte) (int, string) {
	status, body, _ := uploadPartNegative(t, gw, bucket, key, uploadID, partNum, data)
	return status, body
}

// uploadPartNegative is a nonfatal negative-request helper. It returns the
// status, XML body, and ETag without aborting the conformance test.
func uploadPartNegative(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string, partNum int, data []byte) (int, string, string) {
	t.Helper()
	u := fmt.Sprintf("%s/%s/%s?partNumber=%d&uploadId=%s", gw.URL, bucket, key, partNum, uploadID)
	ctx, cancel := conformanceMPUContext()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("UploadPart #%d: create request: %v", partNum, err)
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("UploadPart #%d: %v", partNum, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header.Get("ETag")
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
	ctx, cancel := conformanceMPUContext()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(xmlParts.String()))
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: create request: %v", err)
	}
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

func completeMultipartUploadStatus(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string, parts []mpuPart) int {
	status, _, _ := completeMultipartUploadNegative(t, gw, bucket, key, uploadID, parts)
	return status
}

func completeMultipartUploadNegative(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string, parts []mpuPart) (int, string, string) {
	t.Helper()
	var xmlParts strings.Builder
	xmlParts.WriteString("<CompleteMultipartUpload>")
	for _, p := range parts {
		fmt.Fprintf(&xmlParts, "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>", p.Number, p.ETag)
	}
	xmlParts.WriteString("</CompleteMultipartUpload>")
	u := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, uploadID)
	ctx, cancel := conformanceMPUContext()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(xmlParts.String()))
	if err != nil {
		t.Fatalf("completion request: %v", err)
	}
	req.Header.Set("Content-Type", "application/xml")
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("completion: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header.Get("ETag")
}

// abortMultipartUpload aborts a multipart upload.
func abortMultipartUpload(t *testing.T, gw *harness.Gateway, bucket, key, uploadID string) {
	t.Helper()
	u := fmt.Sprintf("%s/%s/%s?uploadId=%s", gw.URL, bucket, key, uploadID)
	ctx, cancel := conformanceMPUContext()
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		t.Logf("AbortMultipartUpload: create request: %v (non-fatal)", err)
		return
	}
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

func testMultipartStandardMetadata(t *testing.T, inst provider.Instance) {
	t.Helper()
	gw := harness.StartGateway(t, inst)
	key := uniqueKey(t)
	u := fmt.Sprintf("%s/%s/%s?uploads", gw.URL, inst.Bucket, key)
	req, _ := http.NewRequest("POST", u, nil)
	req.Header.Set("Content-Type", "image/png")
	req.Header.Set("Cache-Control", "max-age=300")
	req.Header.Set("Content-Disposition", `inline; filename="multipart.png"`)
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		t.Fatalf("initiate MPU: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initiate MPU: %d: %s", resp.StatusCode, body)
	}
	var result struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { abortMultipartUpload(t, gw, inst.Bucket, key, result.UploadID) })
	etag := uploadPart(t, gw, inst.Bucket, key, result.UploadID, 1, []byte("multipart metadata"))
	completeMultipartUpload(t, gw, inst.Bucket, key, result.UploadID, []mpuPart{{1, etag}})

	headReq, _ := http.NewRequest("HEAD", objectURL(gw, inst.Bucket, key), nil)
	head, err := gw.HTTPClient().Do(headReq)
	if err != nil {
		t.Fatal(err)
	}
	defer head.Body.Close()
	for header, want := range map[string]string{
		"Content-Type": "image/png", "Cache-Control": "max-age=300",
		"Content-Disposition": `inline; filename="multipart.png"`,
	} {
		if got := head.Header.Get(header); got != want {
			t.Errorf("HEAD %s = %q, want %q", header, got, want)
		}
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
