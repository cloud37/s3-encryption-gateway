package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func postRequest(body string, contentType string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://gateway/bucket", strings.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	return r
}

func postMultipart(fields map[string]string, fileHeader, file string) (string, string) {
	const boundary = "gh353-boundary"
	var body strings.Builder
	for name, value := range fields {
		fmt.Fprintf(&body, "--%s\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n", boundary, name, value)
	}
	if fileHeader == "" {
		fileHeader = `Content-Disposition: form-data; name="file"; filename="test.bin"`
	}
	fmt.Fprintf(&body, "--%s\r\n%s\r\n\r\n%s\r\n--%s--\r\n", boundary, fileHeader, file, boundary)
	return body.String(), "multipart/form-data; boundary=" + boundary
}

func TestGH353PostForm_RoutePredicate(t *testing.T) {
	valid := postRequest("", "multipart/form-data; boundary=b")
	for _, path := range []string{"/bucket", "/bucket/"} {
		valid.URL.Path = path
		if !isPostObjectRequest(valid) {
			t.Errorf("valid path rejected: %q", path)
		}
	}
	cases := []struct {
		method, target, contentType string
	}{
		{"PUT", "/bucket", "multipart/form-data; boundary=b"},
		{"POST", "/bucket/key", "multipart/form-data; boundary=b"},
		{"POST", "/bucket?uploads", "multipart/form-data; boundary=b"},
		{"POST", "/bucket?", "multipart/form-data; boundary=b"},
		{"POST", "/bucket", "application/json"},
		{"POST", "/bucket", "multipart/form-data"},
		{"POST", "/bucket", "multipart/form-data; boundary=" + strings.Repeat("x", 71)},
		{"POST", "/bucket", `multipart/form-data; boundary="a "`},
		{"POST", "/bucket", `multipart/form-data; boundary="["`},
		{"POST", "/bucket", `multipart/form-data; boundary="a]"`},
		{"POST", "/bucket//", "multipart/form-data; boundary=b"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(tc.method, "http://gateway"+tc.target, nil)
		r.Header.Set("Content-Type", tc.contentType)
		if isPostObjectRequest(r) {
			t.Errorf("accepted %s %s %q", tc.method, tc.target, tc.contentType)
		}
	}
	duplicateCT := postRequest("", "multipart/form-data; boundary=b")
	duplicateCT.Header["content-type"] = []string{"multipart/form-data; boundary=b"}
	if isPostObjectRequest(duplicateCT) {
		t.Fatal("case-variant duplicate Content-Type accepted")
	}
}

func TestGH353PostForm_FieldAndFilenameSemantics(t *testing.T) {
	fields := map[string]string{"key": "literal%2F/${filename}/../name", "x-amz-meta-note": "${filename}"}
	filePart := `Content-Disposition: form-data; name="file"; filename="C:\\dir\\photo.png"`
	body, contentType := postMultipart(fields, filePart, "\x00\xffbinary")
	upload, err := parsePostUpload(postRequest(body, contentType), 1024)
	if err != nil {
		t.Fatal(err)
	}
	defer upload.Close()
	if upload.filename != "photo.png" || upload.key != "literal%2F/photo.png/../name" || upload.fields["x-amz-meta-note"] != "photo.png" {
		t.Fatalf("filename/key/field = %q %q %q", upload.filename, upload.key, upload.fields["x-amz-meta-note"])
	}
	if err := upload.bindDestination("bucket"); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(upload.fileRead); err != nil || !bytes.Equal(got, []byte{0, 0xff, 'b', 'i', 'n', 'a', 'r', 'y'}) {
		t.Fatalf("file bytes = %x, err=%v", got, err)
	}
	if err := upload.Finish(); err != nil {
		t.Fatalf("raw wire finish: %v", err)
	}
	body, contentType = postMultipart(map[string]string{"key": "x"}, `Content-Disposition: form-data; name="file"`, "text is valid")
	upload, err = parsePostUpload(postRequest(body, contentType), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if upload.filename != "" {
		t.Fatalf("absent filename became %q", upload.filename)
	}
	_ = upload.Close()
	if _, _, err := expandPostFilename(map[string]string{"x-amz-credential": "a/${filename}"}, "x"); err == nil {
		t.Fatal("authentication field interpolation accepted")
	}
}

func TestGH353PostForm_DestinationBindingAndNilLifecycle(t *testing.T) {
	if err := (*postUpload)(nil).Close(); err != nil {
		t.Fatalf("nil upload close=%v", err)
	}
	if err := (*postUpload)(nil).bindDestination("bucket"); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("nil upload destination error=%v", err)
	}
	upload := &postUpload{key: "path/object", fields: map[string]string{}}
	if err := upload.bindDestination(""); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("empty destination error=%v", err)
	}
	if err := upload.bindDestination("bucket"); err != nil || upload.bucket != "bucket" {
		t.Fatalf("valid destination bucket=%q err=%v", upload.bucket, err)
	}
	upload.fields["bucket"] = "other"
	if err := upload.bindDestination("bucket"); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("conflicting signed bucket error=%v", err)
	}
	if err := upload.Finish(); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("incomplete upload Finish error=%v", err)
	}
}

type postFormCloseBody struct {
	io.Reader
	closeErr error
	closes   int
}

type trackingPostBody struct {
	io.Reader
	reads int
}

func (b *trackingPostBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

func (b *trackingPostBody) Close() error { return nil }

func (b *postFormCloseBody) Close() error {
	b.closes++
	return b.closeErr
}

func TestGH353PostForm_FinishBodyOwnershipAndLengthClasses(t *testing.T) {
	validBody, contentType := postMultipart(map[string]string{"key": "bound-key"}, `Content-Disposition: form-data; name="file"; filename="x"`, "body")
	for _, tc := range []struct {
		name          string
		body          string
		contentLength int64
		closeErr      error
		want          error
	}{
		{name: "successful close and exact length", body: validBody, contentLength: int64(len(validBody))},
		{name: "declared length truncation", body: validBody, contentLength: int64(len(validBody) + 1), want: ErrPostIncompleteBody},
		{name: "request close failure", body: validBody, contentLength: int64(len(validBody)), closeErr: errors.New("close transport detail"), want: ErrPostIncompleteBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := &postFormCloseBody{Reader: strings.NewReader(tc.body), closeErr: tc.closeErr}
			r := postRequest("", contentType)
			r.Body = body
			r.ContentLength = tc.contentLength
			upload, err := parsePostUpload(r, 1024)
			if err != nil {
				t.Fatalf("parse upload: %v", err)
			}
			if _, err := io.Copy(io.Discard, upload.fileRead); err != nil {
				t.Fatalf("consume file: %v", err)
			}
			finishErr := upload.Finish()
			if tc.want != nil && !errors.Is(finishErr, tc.want) {
				t.Fatalf("Finish error=%v, want %v", finishErr, tc.want)
			}
			if tc.want == nil && finishErr != nil {
				t.Fatalf("Finish: %v", finishErr)
			}
			wantCloses := 1
			if tc.name == "declared length truncation" {
				wantCloses = 0
			}
			if body.closes != wantCloses {
				t.Fatalf("request body close count=%d, want %d", body.closes, wantCloses)
			}
			if finishErr == nil && upload.requestBody != nil {
				t.Fatal("successful Finish retained request body ownership")
			}
			if finishErr != nil && upload.requestBody == nil {
				t.Fatal("failed Finish released request body ownership before cleanup")
			}
			if closeErr := upload.Close(); closeErr != nil {
				t.Fatalf("upload Close: %v", closeErr)
			}
			if body.closes != wantCloses {
				t.Fatalf("upload Close drained or reclosed request body: %d", body.closes)
			}
		})
	}
}

func TestGH353PostForm_WireReaderErrorClassesAndObserverStates(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want error
	}{
		{name: "EOF with no bytes", err: io.EOF, want: io.EOF},
		{name: "unexpected EOF", err: io.ErrUnexpectedEOF, want: ErrPostIncompleteBody},
		{name: "entity limit", err: ErrPostEntityTooLarge, want: ErrPostEntityTooLarge},
		{name: "cancel", err: context.Canceled, want: ErrStreamingCanceled},
		{name: "deadline", err: context.DeadlineExceeded, want: ErrStreamingCanceled},
		{name: "other read error", err: errors.New("private reader error"), want: ErrPostIncompleteBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := newPostWireReader(errorPostReader{err: tc.err}, "b", 16)
			buf := make([]byte, 8)
			_, got := wire.Read(buf)
			if !errors.Is(got, tc.want) {
				t.Fatalf("wire read error=%v, want %v", got, tc.want)
			}
		})
	}
	if _, err := newPostWireReader(nil, "b", 16).Read(make([]byte, 1)); !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("nil raw reader error=%v", err)
	}
	if err := (*postWireReader)(nil).Finish(); !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("nil observer Finish error=%v", err)
	}
	wire := newPostWireReader(nil, "b", 16)
	if err := wire.Finish(); !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("observer with nil source Finish error=%v", err)
	}
	wire = newPostWireReader(strings.NewReader(""), "b", 16)
	if err := wire.recognizeFile(); err != nil {
		t.Fatal(err)
	}
	if err := wire.Finish(); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("missing opening delimiter error=%v", err)
	}
	wire = newPostWireReader(strings.NewReader("--b\r\n"), "b", 16)
	if err := wire.recognizeFile(); err != nil {
		t.Fatal(err)
	}
	if err := wire.Finish(); !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("missing closing delimiter error=%v", err)
	}
	wire = newPostWireReader(strings.NewReader(strings.Repeat(" \t\r\n", int(postFormOverheadLimit/4+1))+"--b\r\n"), "b", 16)
	if err := wire.recognizeFile(); err != nil {
		t.Fatal(err)
	}
	if err := wire.Finish(); !errors.Is(err, ErrPostEntityTooLarge) {
		t.Fatalf("oversized preamble error=%v", err)
	}
	if err := (*postWireReader)(nil).addFileBytes(1); !errors.Is(err, ErrPostEntityTooLarge) {
		t.Fatalf("nil observer file accounting error=%v", err)
	}
	wire = newPostWireReader(strings.NewReader(""), "b", int64(^uint64(0)>>1))
	for _, n := range []int64{-1, 1} {
		if err := wire.addFileBytes(n); !errors.Is(err, ErrPostEntityTooLarge) {
			t.Errorf("unrecognized/invalid file accounting n=%d error=%v", n, err)
		}
	}
	if err := wire.recognizeFile(); !errors.Is(err, ErrPostEntityTooLarge) {
		t.Fatalf("file limit overflow error=%v", err)
	}
	wire = newPostWireReader(strings.NewReader("xx"), "b", 0)
	wire.limit = 0
	if n, err := wire.Read(make([]byte, 1)); n != 1 || !errors.Is(err, ErrPostEntityTooLarge) {
		t.Fatalf("wire limit read n=%d err=%v", n, err)
	}
	if _, err := wire.Read(make([]byte, 1)); !errors.Is(err, ErrPostEntityTooLarge) {
		t.Fatalf("sticky wire limit error=%v", err)
	}
}

type errorPostReader struct{ err error }

func (r errorPostReader) Read([]byte) (int, error) { return 0, r.err }

type emptyPostReader struct{}

func (emptyPostReader) Read([]byte) (int, error) { return 0, nil }

func TestGH353PostForm_ZeroProgressAndNilBodyGuards(t *testing.T) {
	if n, err := newPostWireReader(emptyPostReader{}, "b", 16).Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("zero-progress wire read n=%d err=%v", n, err)
	}
	if n, err := (*postWireReader)(nil).Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("nil wire read n=%d err=%v", n, err)
	}
	if n, err := (*postWireReader)(nil).Read(nil); n != 0 || err != nil {
		t.Fatalf("nil zero-length wire read n=%d err=%v", n, err)
	}
	if n, err := (*postFileReader)(nil).Read(make([]byte, 1)); n != 0 || !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("nil file reader error=%v", err)
	}
	if n, err := (*postFileReader)(nil).Read(nil); n != 0 || err != nil {
		t.Fatalf("nil zero-length file read n=%d err=%v", n, err)
	}
	r := postRequest("", "multipart/form-data; boundary=b")
	r.Body = nil
	if _, err := parsePostUpload(r, 1024); !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("nil request body parse error=%v", err)
	}
	if _, err := parsePostUpload(nil, 1024); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("nil request parse error=%v", err)
	}
}

func TestGH353PostForm_ScalarValidationAndIgnoredFieldBounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		fields map[string]string
		want   error
	}{
		{name: "unsupported scalar", fields: map[string]string{"key": "k", "unknown": "v"}, want: ErrPostUnsupported},
		{name: "unsupported policy range field", fields: map[string]string{"key": "k", "content-length-range": "0,10"}, want: ErrPostUnsupported},
		{name: "ignored scalar rejects control bytes", fields: map[string]string{"key": "k", "x-ignore-note": "bad\x00value"}, want: ErrPostFormMalformed},
		{name: "ignored scalar is bounded", fields: map[string]string{"key": "k", "x-ignore-note": strings.Repeat("x", int(postFormOverheadLimit)+1)}, want: ErrPostEntityTooLarge},
		{name: "ordinary scalar rejects line breaks", fields: map[string]string{"key": "k\nvalue"}, want: ErrPostFormMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, contentType := postMultipart(tc.fields, `Content-Disposition: form-data; name="file"; filename="x"`, "payload")
			_, err := parsePostUpload(postRequest(body, contentType), 1024)
			if !errors.Is(err, tc.want) {
				t.Fatalf("parse error=%v, want %v", err, tc.want)
			}
		})
	}

	var body strings.Builder
	for i := 0; i <= postScalarCountLimit; i++ {
		fmt.Fprintf(&body, "--b\r\nContent-Disposition: form-data; name=\"x-amz-meta-k%d\"\r\n\r\nv\r\n", i)
	}
	body.WriteString("--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n\r\npayload\r\n--b--\r\n")
	if _, err := parsePostUpload(postRequest(body.String(), "multipart/form-data; boundary=b"), 1024); !errors.Is(err, ErrPostEntityTooLarge) {
		t.Fatalf("scalar count limit error=%v, want %v", err, ErrPostEntityTooLarge)
	}

	bodyText, contentType := postMultipart(map[string]string{"key": "k", "x-ignore-note": "discarded"}, `Content-Disposition: form-data; name="file"; filename="x"`, "payload")
	upload, err := parsePostUpload(postRequest(bodyText, contentType), 0)
	if err != nil {
		t.Fatalf("valid ignored scalar form: %v", err)
	}
	defer upload.Close()
	if _, exists := upload.fields["x-ignore-note"]; exists || upload.scalarBytes != int64(len("k")+len("discarded")) {
		t.Fatalf("ignored field retained/accounting wrong: fields=%v scalarBytes=%d", upload.fields, upload.scalarBytes)
	}
	if upload.wire.fileLimit != postDefaultFileLimit {
		t.Fatalf("default file limit=%d, want %d", upload.wire.fileLimit, postDefaultFileLimit)
	}
	if _, err := io.Copy(io.Discard, upload.fileRead); err != nil {
		t.Fatal(err)
	}
	if err := upload.Finish(); err != nil {
		t.Fatalf("Finish ignored-field form: %v", err)
	}
}

func TestGH353PostForm_RouteAndContentTypeValidationBeforeBodyRead(t *testing.T) {
	for _, tc := range []struct {
		name        string
		path        string
		contentType []string
	}{
		{name: "root route", path: "/", contentType: []string{"multipart/form-data; boundary=b"}},
		{name: "nested object route", path: "/bucket/key", contentType: []string{"multipart/form-data; boundary=b"}},
		{name: "missing content type", path: "/bucket"},
		{name: "duplicate content type", path: "/bucket", contentType: []string{"multipart/form-data; boundary=b", "multipart/form-data; boundary=b"}},
		{name: "malformed media type", path: "/bucket", contentType: []string{"multipart/form-data; boundary=\"unterminated"}},
		{name: "wrong media type", path: "/bucket", contentType: []string{"application/octet-stream; boundary=b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://gateway"+tc.path, nil)
			body := &trackingPostBody{Reader: strings.NewReader("must remain unread")}
			request.Body = body
			if tc.contentType != nil {
				request.Header["Content-Type"] = append([]string(nil), tc.contentType...)
			}
			_, err := parsePostUpload(request, 1024)
			if !errors.Is(err, ErrPostFormMalformed) {
				t.Fatalf("parse error=%v, want %v", err, ErrPostFormMalformed)
			}
			if body.reads != 0 {
				t.Fatalf("rejected request body was read %d times before route/MIME validation", body.reads)
			}
		})
	}

	caseVariantDuplicate := httptest.NewRequest(http.MethodPost, "http://gateway/bucket", nil)
	caseVariantDuplicate.Header.Set("Content-Type", "multipart/form-data; boundary=b")
	caseVariantDuplicate.Header["content-type"] = []string{"multipart/form-data; boundary=b"}
	if _, err := parsePostUpload(caseVariantDuplicate, 1024); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("case-variant duplicate Content-Type error=%v", err)
	}
}

func TestGH353PostForm_RawObserverMalformedPreambleAndDelimiterClasses(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "non-whitespace preamble line",
			body: "untrusted preamble\r\n--b\r\n",
		},
		{
			name: "bare line feed resembles an interior delimiter",
			body: "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\npayload\n--b\r\n--b--\r\n",
		},
		{
			name: "carriage return not followed by line feed",
			body: "preamble\rX\r\n--b\r\n",
		},
		{
			name: "bare line feed creates invalid interior delimiter",
			body: "--b\r\nfile\n--b\r\n--b--\r\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := newPostWireReader(strings.NewReader(tc.body), "b", 1024)
			if err := wire.recognizeFile(); err != nil {
				t.Fatal(err)
			}
			if err := wire.Finish(); !errors.Is(err, ErrPostFormMalformed) {
				t.Fatalf("raw observer error=%v, want %v (state=%+v)", err, ErrPostFormMalformed, wire)
			}
		})
	}
}

func TestGH353PostForm_DuplicatesFramingAndUTF8(t *testing.T) {
	for _, tc := range []struct {
		name, body string
	}{
		{"duplicate case", "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"KEY\"\r\n\r\ny\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nz\r\n--b--\r\n"},
		{"invalid utf8", "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n\xff\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nz\r\n--b--\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := postRequest(tc.body, "multipart/form-data; boundary=b")
			if _, err := parsePostUpload(r, 1024); err == nil {
				t.Fatal("malformed form accepted")
			}
		})
	}
	for _, tc := range []struct{ name, body string }{
		{"LF only", "--b\nContent-Disposition: form-data; name=\"key\"\n\nx\n--b\nContent-Disposition: form-data; name=\"file\"\n\nz\n--b--\n"},
		{"extra after close", "--b\r\npart\r\n--b--\r\nnot-ws\r\n"},
		{"bad epilogue", "--b\r\n--b--\r\nnot-ws"},
		{"LF closing delimiter", "--b\r\npart\n--b--\r\n"},
	} {
		t.Run(tc.name+" observer", func(t *testing.T) {
			wire := newPostWireReader(strings.NewReader(tc.body), "b", 1024)
			_ = wire.recognizeFile()
			_, _ = io.Copy(io.Discard, wire)
			if err := wire.Finish(); err == nil {
				t.Fatal("raw observer accepted malformed delimiter sequence")
			}
		})
	}
	for _, malformed := range []string{
		"--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n" + strings.Repeat("f", 64*1024),
		"--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Transfer-Encoding: binary\r\n\r\n" + strings.Repeat("f", 64*1024),
		"--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Type: multipart/mixed\r\n\r\n" + strings.Repeat("f", 64*1024),
		"--b\r\nContent-Disposition: form-data; name=\"unknown\"; filename=\"x\"\r\n\r\n" + strings.Repeat("f", 64*1024),
		"--b\r\nContent-Disposition: form-data; name=\"unknown\"\r\n\r\n" + strings.Repeat("f", 64*1024),
		"--b\r\nContent-Disposition: form-data; name=\"key\"\r\nX-Unicode: \xff\r\n\r\nx",
		"--b\r\nContent-Disposition: form-data; name=\"x-ignore-\xff\"\r\n\r\nx\r\n--b--\r\n",
		"--b\r\nContent-Disposition: form-data; name=\"x-ignore-a\"\r\n\r\nx\x00\r\n--b--\r\n",
		"--b\r\nContent-Disposition: form-data; name=\"x-ignore-a\"; filename=\"x\"\r\n\r\nx\r\n--b--\r\n",
	} {
		counter := &limitedPostReader{r: strings.NewReader(malformed), max: 3}
		r := postRequest("", "multipart/form-data; boundary=b")
		r.Body = io.NopCloser(counter)
		if _, err := parsePostUpload(r, 1<<20); err == nil {
			t.Errorf("malformed form accepted: %q", malformed[:min(80, len(malformed))])
		}
		if counter.read > postBeforeFileLimit+1 {
			t.Errorf("malformed form drained %d bytes", counter.read)
		}
	}
	missingFile := "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--b--\r\n"
	if _, err := parsePostUpload(postRequest(missingFile, "multipart/form-data; boundary=b"), 1024); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("missing file = %v", err)
	}
	duplicateHeader := "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nz\r\n--b--\r\n"
	if _, err := parsePostUpload(postRequest(duplicateHeader, "multipart/form-data; boundary=b"), 1024); err == nil {
		t.Fatal("duplicate critical MIME header accepted")
	}
	truncated := "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nz"
	truncatedUpload, err := parsePostUpload(postRequest(truncated, "multipart/form-data; boundary=b"), 1024)
	if err != nil {
		t.Fatalf("parser should leave file unread until authorization: %v", err)
	}
	_, err = io.Copy(io.Discard, truncatedUpload.fileRead)
	if err != nil && !errors.Is(err, ErrPostIncompleteBody) {
		t.Fatalf("truncated read class: %v", err)
	}
	if err := truncatedUpload.Finish(); err == nil {
		t.Fatal("truncated file without closing delimiter finished successfully")
	}
	_ = truncatedUpload.Close()
}

type limitedPostReader struct {
	r    io.Reader
	max  int
	read int64
}

func (r *limitedPostReader) Read(p []byte) (int, error) {
	if len(p) > r.max {
		p = p[:r.max]
	}
	n, err := r.r.Read(p)
	r.read += int64(n)
	return n, err
}

func TestGH353PostForm_LargeKnownAndUnknownLengthDefersFileConsumption(t *testing.T) {
	for _, size := range []int{64 * 1024, 128 * 1024} {
		for _, chunk := range []int{1, 7, 8192} {
			for _, known := range []bool{true, false} {
				t.Run(strconv.Itoa(size)+"/"+strconv.Itoa(chunk)+"/known="+strconv.FormatBool(known), func(t *testing.T) {
					payload := strings.Repeat("z", size)
					body, ct := postMultipart(map[string]string{"key": "k"}, `Content-Disposition: form-data; name="file"; filename="x"`, payload)
					counter := &limitedPostReader{r: strings.NewReader(body), max: chunk}
					r := postRequest("", ct)
					r.Body = io.NopCloser(counter)
					if known {
						r.ContentLength = int64(len(body))
					} else {
						r.ContentLength = -1
					}
					u, err := parsePostUpload(r, 1<<20)
					if err != nil {
						t.Fatalf("parse: %v", err)
					}
					if counter.read > postBeforeFileLimit+1 {
						t.Fatalf("pre-auth read %d > bounded allowance", counter.read)
					}
					if counter.read >= int64(len(body)) {
						t.Fatalf("parser consumed file before auth: %d/%d", counter.read, len(body))
					}
					_, err = io.Copy(io.Discard, u.fileRead)
					if err != nil {
						t.Fatalf("consume: %v", err)
					}
					if u.wire.fileBytes != int64(size) {
						t.Fatalf("file bytes = %d want %d", u.wire.fileBytes, size)
					}
					if err := u.Finish(); err != nil {
						t.Fatalf("finish: %v", err)
					}
					_ = u.Close()
				})
			}
		}
	}
}

func TestGH353PostForm_FileCounterAndFramingCandidates(t *testing.T) {
	body, ct := postMultipart(map[string]string{"key": "k"}, `Content-Disposition: form-data; name="file"`, strings.Repeat("x", 64*1024))
	u, err := parsePostUpload(postRequest(body, ct), 128*1024)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	for {
		_, e := u.fileRead.Read(buf)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	if u.wire.fileBytes != 64*1024 {
		t.Fatalf("cumulative count=%d", u.wire.fileBytes)
	}
	if err := u.Finish(); err != nil {
		t.Fatal(err)
	}
	_ = u.Close()

	for _, suffix := range []string{"Xbinary", "-x", "--X", "\rX"} {
		payload := "binary\r\n--b--" + suffix + "tail"
		framed := "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n" + payload + "\r\n--b--\r\n"
		wire := newPostWireReader(&limitedPostReader{r: strings.NewReader(framed), max: 1}, "b", 4096)
		if err := wire.recognizeFile(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, wire); err != nil {
			t.Fatal(err)
		}
		if err := wire.Finish(); err != nil {
			t.Errorf("valid near-boundary payload %q rejected: %v", suffix, err)
		}
		if len(wire.scan) > len(wire.boundary)+8 || cap(wire.scan) > len(wire.boundary)+8 {
			t.Errorf("scan bounds len/cap=%d/%d", len(wire.scan), cap(wire.scan))
		}
	}
	for _, chunk := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16} {
		framed := "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nf\r\n--b-- \t\r\n \t\r\n"
		wire := newPostWireReader(&limitedPostReader{r: strings.NewReader(framed), max: chunk}, "b", 4096)
		if err := wire.recognizeFile(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, wire); err != nil {
			t.Fatal(err)
		}
		if err := wire.Finish(); err != nil {
			t.Errorf("split/padded close chunk=%d: %v", chunk, err)
		}
	}
	for _, ending := range []string{"--b--", "--b-- \t\r\n"} {
		framed := "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nx\r\n" + ending
		wire := newPostWireReader(&limitedPostReader{r: strings.NewReader(framed), max: 2}, "b", 4096)
		_ = wire.recognizeFile()
		_, _ = io.Copy(io.Discard, wire)
		if err := wire.Finish(); err != nil {
			t.Errorf("exact close ending %q: %v", ending, err)
		}
	}
	for _, chunk := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16} {
		framed := "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nx\r\n--b-- \t"
		wire := newPostWireReader(&limitedPostReader{r: strings.NewReader(framed), max: chunk}, "b", 4096)
		_ = wire.recognizeFile()
		_, _ = io.Copy(io.Discard, wire)
		if err := wire.Finish(); err != nil {
			t.Errorf("EOF-padded close chunk=%d: %v", chunk, err)
		}
	}
	for _, payload := range []string{"near\r\n--b--\r Xtail", "near\r\n--b-- \tXtail"} {
		body, ct := postMultipart(map[string]string{"key": "k"}, `Content-Disposition: form-data; name="file"`, payload)
		for _, chunk := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32} {
			r := postRequest("", ct)
			r.Body = io.NopCloser(&limitedPostReader{r: strings.NewReader(body), max: chunk})
			r.ContentLength = int64(len(body))
			u, parseErr := parsePostUpload(r, 4096)
			if parseErr != nil {
				t.Errorf("MIME rejects binary candidate %q chunk=%d: %v", payload, chunk, parseErr)
				continue
			}
			got, readErr := io.ReadAll(u.fileRead)
			if readErr != nil || string(got) != payload {
				t.Errorf("candidate file chunk=%d got=%q err=%v", chunk, got, readErr)
			}
			if err := u.Finish(); err != nil {
				t.Errorf("candidate Finish chunk=%d: %v", chunk, err)
			}
			_ = u.Close()
		}
	}
	for _, ending := range []string{"--b--\r\nnot-ws", "--b--\r\n--b--\r\n", "--b--\r\nnot-ws\r\n--b--\r\n"} {
		framed := "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nx\r\n" + ending
		wire := newPostWireReader(strings.NewReader(framed), "b", 4096)
		_ = wire.recognizeFile()
		_, _ = io.Copy(io.Discard, wire)
		if err := wire.Finish(); err == nil {
			t.Errorf("invalid post-close bytes accepted: %q", ending)
		}
	}
	bareLF := "--b\r\npart\n--b--\n"
	wire := newPostWireReader(&limitedPostReader{r: strings.NewReader(bareLF), max: 1}, "b", 128)
	_ = wire.recognizeFile()
	_, _ = io.Copy(io.Discard, wire)
	if err := wire.Finish(); err == nil {
		t.Fatal("LF-only close accepted")
	}
}

type finalBytesEOFReader struct{ data []byte }

func (r *finalBytesEOFReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

func TestGH353PostForm_FinalBytesWithEOFAndPaddedClosingLine(t *testing.T) {
	for _, suffix := range []string{"", " \t"} {
		body, ct := postMultipart(map[string]string{"key": "k"}, `Content-Disposition: form-data; name="file"`, "payload")
		body = strings.TrimSuffix(body, "--gh353-boundary--\r\n") + "--gh353-boundary--" + suffix
		for _, chunk := range []int{1, 2, 7, 8192} {
			wire := newPostWireReader(&limitedPostReader{r: &finalBytesEOFReader{data: []byte(body)}, max: chunk}, "gh353-boundary", 4096)
			if err := wire.recognizeFile(); err != nil {
				t.Fatal(err)
			}
			if err := wire.Finish(); err != nil {
				t.Errorf("raw observer suffix=%q chunk=%d: %v", suffix, chunk, err)
			}
			if wire.read != int64(len(body)) {
				t.Errorf("raw observer read=%d want=%d", wire.read, len(body))
			}
		}
		for _, prefetched := range []bool{false, true} {
			for _, chunk := range []int{1, 2, 7, 8192} {
				t.Run(fmt.Sprintf("suffix=%q/prefetched=%t/chunk=%d", suffix, prefetched, chunk), func(t *testing.T) {
					data := []byte(body)
					if prefetched {
						// Force the multipart buffered reader to prefetch the EOF-bearing
						// final delimiter while parsing the file part.
						chunk = len(data)
					}
					r := postRequest("", ct)
					r.Body = io.NopCloser(&limitedPostReader{r: &finalBytesEOFReader{data: data}, max: chunk})
					r.ContentLength = int64(len(data))
					u, err := parsePostUpload(r, 4096)
					if err != nil {
						t.Fatalf("parse: %v", err)
					}
					got, err := io.ReadAll(u.fileRead)
					if err != nil || string(got) != "payload" {
						t.Fatalf("file read=%q err=%v", got, err)
					}
					if err := u.Finish(); err != nil {
						t.Fatalf("Finish: %v", err)
					}
					if u.wire.read != int64(len(data)) || u.wire.fileBytes != int64(len("payload")) {
						t.Fatalf("wire/file counts=%d/%d want=%d/%d", u.wire.read, u.wire.fileBytes, len(data), len("payload"))
					}
					if err := u.Close(); err != nil || u.file != nil {
						t.Fatalf("Close err=%v file=%v", err, u.file)
					}
				})
			}
		}
	}
}

func TestGH353PostForm_FileAccountingBoundsAndPostFilePart(t *testing.T) {
	for _, tc := range []struct {
		name string
		adds []int64
		want int64
		fail bool
	}{{"zero", []int64{0}, 0, false}, {"minimum", []int64{1}, 1, false}, {"maximum", []int64{3, 4}, 7, false}, {"one-over", []int64{7, 1}, 7, true}} {
		t.Run(tc.name, func(t *testing.T) {
			wire := newPostWireReader(strings.NewReader(""), "b", 7)
			if err := wire.recognizeFile(); err != nil {
				t.Fatal(err)
			}
			for i, n := range tc.adds {
				err := wire.addFileBytes(n)
				shouldFail := tc.fail && i > 0
				if shouldFail && err != nil {
					break
				}
				if (err != nil) != shouldFail {
					t.Fatalf("add %d err=%v fail=%t", n, err, shouldFail)
				}
			}
			if wire.fileBytes != tc.want {
				t.Fatalf("fileBytes=%d want=%d", wire.fileBytes, tc.want)
			}
		})
	}
	extra := "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--b--\r\n"
	u, err := parsePostUpload(postRequest(extra, "multipart/form-data; boundary=b"), 32)
	if err != nil {
		t.Fatalf("parse file before extra part: %v", err)
	}
	if _, err := io.Copy(io.Discard, u.fileRead); err != nil {
		t.Fatal(err)
	}
	if err := u.Finish(); !errors.Is(err, ErrPostFormMalformed) {
		t.Fatalf("post-file part Finish=%v", err)
	}
	_ = u.Close()
}

func TestGH353PostForm_PrefetchedFileDoesNotCountAsScalarOverhead(t *testing.T) {
	for _, chunk := range []int{4096, 16 * 1024, 24 * 1024} {
		payload := strings.Repeat("p", 28*1024)
		body, ct := postMultipart(map[string]string{"key": "k"}, `Content-Disposition: form-data; name="file"; filename="x"`, payload)
		counter := &limitedPostReader{r: strings.NewReader(body), max: chunk}
		r := postRequest("", ct)
		r.Body = io.NopCloser(counter)
		r.ContentLength = int64(len(body))
		u, err := parsePostUpload(r, 64*1024)
		if err != nil {
			t.Fatalf("chunk %d parse: %v", chunk, err)
		}
		_, err = io.Copy(io.Discard, u.fileRead)
		if err != nil {
			t.Fatal(err)
		}
		if u.wire.fileBytes != int64(len(payload)) {
			t.Errorf("chunk %d file count=%d", chunk, u.wire.fileBytes)
		}
		if err := u.Finish(); err != nil {
			t.Errorf("chunk %d Finish: %v", chunk, err)
		}
		_ = u.Close()
	}
}

func TestGH353PostForm_BoundaryGrammarAndPreamble(t *testing.T) {
	for _, boundary := range []string{"a ", "[", "a]", "a\\", "a\""} {
		r := postRequest("", `multipart/form-data; boundary="`+boundary+`"`)
		if isPostObjectRequest(r) {
			t.Errorf("invalid boundary accepted: %q", boundary)
		}
	}
	valid := postRequest("", `multipart/form-data; boundary="a:b"`)
	if !isPostObjectRequest(valid) {
		t.Fatal("valid quoted MIME boundary rejected")
	}
	preamble := strings.Repeat(" \t\r\n", 1000) + "--b\r\n\r\n--b--\r\n"
	wire := newPostWireReader(strings.NewReader(preamble), "b", 100)
	if _, err := io.Copy(io.Discard, wire); err != nil {
		t.Fatal(err)
	}
	if err := wire.Finish(); err != nil {
		t.Fatalf("bounded whitespace preamble rejected: %v state=%+v", err, wire)
	}
	if len(wire.scan) > len(wire.boundary)+8 || cap(wire.scan) > len(wire.boundary)+8 {
		t.Fatalf("scan window len/cap=%d/%d", len(wire.scan), cap(wire.scan))
	}
}

func TestGH353PostForm_OverheadAndLookaheadBound(t *testing.T) {
	largeHeader := "--b\r\nContent-Disposition: form-data; name=\"key\"\r\nX-Pad: " + strings.Repeat("x", 60*1024) + "\r\n\r\nx\r\n--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nz\r\n--b--\r\n"
	reader := &countingPostReader{r: strings.NewReader(largeHeader)}
	r := postRequest("", "multipart/form-data; boundary=b")
	r.Body = io.NopCloser(reader)
	if _, err := parsePostUpload(r, 1024); err == nil {
		t.Fatal("oversized header accepted")
	}
	if reader.read > postBeforeFileLimit+1 {
		t.Fatalf("consumed %d bytes before rejecting oversized header", reader.read)
	}
	wire := newPostWireReader(strings.NewReader(""), "b", 4)
	if err := wire.recognizeFile(); err != nil {
		t.Fatal(err)
	}
	if n, err := wire.Read(nil); n != 0 || err != nil {
		t.Fatalf("zero read = %d,%v", n, err)
	}
	if err := wire.addFileBytes(5); err == nil {
		t.Fatal("file limit sentinel accepted")
	}
}

type countingPostReader struct {
	r    io.Reader
	read int64
}

func (r *countingPostReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.read += int64(n)
	return n, err
}

func FuzzPostForm(f *testing.F) {
	body, contentType := postMultipart(map[string]string{"key": "key"}, "", "file")
	f.Add(body, contentType)
	f.Add("--b\nnot a form", "multipart/form-data; boundary=b")
	f.Fuzz(func(t *testing.T, body, contentType string) {
		if len(body) > 128*1024 || len(contentType) > 512 {
			t.Skip()
		}
		bodyBytes := []byte(body)
		counter := &countingPostReader{r: bytes.NewReader(bodyBytes)}
		r := postRequest("", contentType)
		r.Body = io.NopCloser(counter)
		upload, err := parsePostUpload(r, 1024)
		if err == nil {
			var independentlyRead int64
			var fileReadErr error
			if upload.fileRead != nil {
				independentlyRead, fileReadErr = io.Copy(io.Discard, upload.fileRead)
			}
			finishErr := upload.Finish()
			if finishErr == nil {
				if fileReadErr != nil || !upload.fileCounter.eof {
					t.Fatalf("successful Finish without clean file EOF: readErr=%v eof=%t", fileReadErr, upload.fileCounter.eof)
				}
				if upload.wire.fileBytes != independentlyRead || upload.wire.fileBytes > 1024 || upload.wire.read-upload.wire.fileBytes > postFormOverheadLimit {
					t.Fatalf("accounting invariant: wire/file=%d/%d independently-read=%d", upload.wire.read, upload.wire.fileBytes, independentlyRead)
				}
				if counter.read > int64(len(bodyBytes)) || counter.read > postBeforeFileLimit+1+1024+postFormOverheadLimit {
					t.Fatalf("unbounded reader consumption: %d/%d", counter.read, len(bodyBytes))
				}
				if len(upload.wire.scan) > len(upload.wire.boundary)+8 || cap(upload.wire.scan) > len(upload.wire.boundary)+8 {
					t.Fatalf("unbounded scan len/cap=%d/%d", len(upload.wire.scan), cap(upload.wire.scan))
				}
			}
			if err := upload.Close(); err != nil {
				t.Fatal(err)
			}
			if err := upload.Close(); err != nil {
				t.Fatalf("idempotent Close: %v", err)
			}
		}
	})
}
