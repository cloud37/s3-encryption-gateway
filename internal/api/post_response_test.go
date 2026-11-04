package api

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
	"github.com/sirupsen/logrus"
)

func TestGH353PostResponse_StatusXMLAndRedirect(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fields     map[string]string
		wantStatus int
		wantErr    bool
	}{
		{"default absent", nil, http.StatusNoContent, false},
		{"default invalid", map[string]string{"success_action_status": "202"}, http.StatusNoContent, false},
		{"200", map[string]string{"success_action_status": "200"}, http.StatusOK, false},
		{"201", map[string]string{"success_action_status": "201"}, http.StatusCreated, false},
		{"204", map[string]string{"success_action_status": "204"}, http.StatusNoContent, false},
		{"redirect alias", map[string]string{"success_action_redirect": "https://upload.example/ok"}, http.StatusNoContent, false},
		{"legacy alias", map[string]string{"redirect": "http://upload.example/ok"}, http.StatusNoContent, false},
		{"both aliases including empty", map[string]string{"success_action_redirect": "", "redirect": "https://upload.example/ok"}, 0, true},
		{"invalid redirect falls back", map[string]string{"success_action_status": "201", "redirect": "ftp://upload.example/"}, http.StatusCreated, false},
		{"2048 byte redirect", map[string]string{"redirect": "https://a.test/" + strings.Repeat("x", 2033)}, http.StatusNoContent, false},
		{"2049 byte redirect", map[string]string{"redirect": "https://a.test/" + strings.Repeat("x", 2034)}, http.StatusNoContent, false},
		{"control redirect", map[string]string{"redirect": "https://a.test/\npath"}, http.StatusNoContent, false},
		{"userinfo redirect", map[string]string{"redirect": "https://user@a.test/"}, http.StatusNoContent, false},
		{"IPv6 authority", map[string]string{"redirect": "https://[2001:db8::1]:8443/path"}, http.StatusNoContent, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, target, err := parsePostSuccess(tc.fields)
			if tc.wantErr {
				if !errors.Is(err, ErrPostInvalidOption) {
					t.Fatalf("err=%v want ErrPostInvalidOption", err)
				}
				return
			}
			if err != nil || status != tc.wantStatus {
				t.Fatalf("status=%d redirect=%v err=%v want status=%d", status, target, err, tc.wantStatus)
			}
			if tc.name == "IPv6 authority" && (target == nil || target.Host != "[2001:db8::1]:8443") {
				t.Fatalf("IPv6 target=%v", target)
			}
			if tc.name == "2048 byte redirect" && target == nil {
				t.Fatal("exact redirect size rejected")
			}
			if tc.name == "2049 byte redirect" && target != nil {
				t.Fatal("overlong redirect accepted")
			}
		})
	}
}

func TestGH353PostResponse_LocationAndEscaping(t *testing.T) {
	key := `literal%2F+./../雪 &<>"/tail`
	r := httptest.NewRequest(http.MethodPost, "http://ignored.example/bucket", nil)
	r.Host = "gateway.example:8443"
	location, err := postObjectLocation(r, "bucket", key, true)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Scheme != "https" || parsed.Host != "gateway.example:8443" || parsed.Path != "/bucket/"+key || parsed.RawQuery != "" {
		t.Fatalf("location %q parsed=%+v want literal key path", location, parsed)
	}
	for _, value := range []string{"gateway.example/" + key, "", "bucket"} {
		_ = value
	}
	for _, host := range []string{"", "bad host", "user@gateway.example", "gateway.example/path", "bad_host", "gateway.example:0", "2001:db8::1"} {
		r.Host = host
		if _, err := postObjectLocation(r, "bucket", key, false); err == nil {
			t.Errorf("invalid authority %q accepted", host)
		}
	}
	r.Host = "[2001:db8::1]:443"
	if got, err := postObjectLocation(r, "bucket", key, false); err != nil || !strings.HasPrefix(got, "http://[2001:db8::1]:443/") {
		t.Fatalf("IPv6 authority location=%q err=%v", got, err)
	}
	for _, invalid := range []struct{ bucket, key string }{{"", "key"}, {"bucket", ""}, {"bucket", strings.Repeat("x", 1025)}} {
		if _, err := postObjectLocation(r, invalid.bucket, invalid.key, false); err == nil {
			t.Errorf("invalid object identity bucket=%q key bytes=%d accepted", invalid.bucket, len(invalid.key))
		}
	}
}

func TestGH353PostResponse_RedirectCloneQueryReplacementAndImmutability(t *testing.T) {
	fields := map[string]string{"redirect": "https://upload.example/path?existing=keep&bucket=old#frag"}
	status, parsed, err := parsePostSuccess(fields)
	if err != nil || status != http.StatusNoContent || parsed == nil {
		t.Fatalf("status=%d target=%v err=%v", status, parsed, err)
	}
	parsedBefore := parsed.String()
	fields["redirect"] = "https://mutated.invalid/"
	got := postRedirectLocation(parsed, "new bucket", "a+/雪", `"tag&<>`)
	redirect, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	query := redirect.Query()
	if query.Get("existing") != "keep" || query.Get("bucket") != "new bucket" || query.Get("key") != "a+/雪" || query.Get("etag") != `"tag&<>` || redirect.Fragment != "frag" {
		t.Fatalf("redirect=%q query=%v fragment=%q", got, query, redirect.Fragment)
	}
	if got := parsed.String(); got != parsedBefore {
		t.Fatalf("redirect target mutated: before=%q after=%q", parsedBefore, got)
	}
	if strings.Count(redirect.RawQuery, "bucket=") != 1 || strings.Count(redirect.RawQuery, "key=") != 1 || strings.Count(redirect.RawQuery, "etag=") != 1 {
		t.Fatalf("selector query duplicates: %q", redirect.RawQuery)
	}
	malicious := &url.URL{Scheme: "https", Host: "safe.example", RawQuery: "x=1&bad=%ZZ"}
	if postRedirectLocation(malicious, "b", "k", "e") != "" {
		t.Fatal("malformed unrelated query was normalized into success")
	}
}

func FuzzPostRedirect(f *testing.F) {
	for _, seed := range []struct {
		target string
		both   bool
	}{
		{"https://upload.example/a/../%E9%9B%AA?bucket=old&bucket=older&key=old&etag=old&keep=a%2Bb&keep=%E9%9B%AA#frag", false},
		{"http://upload.example/path?keep=dot.%25%2B#section", false},
		{"https://upload.example/?bad=%ZZ", false},
		{"/relative/path", false},
		{"ftp://upload.example/path", false},
		{"https://user@upload.example/path", false},
		{"https://upload.example/\npath", false},
		{"https://upload.example/" + strings.Repeat("x", 2049), false},
		{"https://a.test/" + strings.Repeat("x", 2033), false},
		{"https://upload.example/", true},
		{"", true},
	} {
		f.Add(seed.target, "bucket+%雪", "a/../雪%2F+ .", `"tag&+%雪"`, seed.both)
	}
	f.Fuzz(func(t *testing.T, raw, bucket, key, etag string, both bool) {
		if len(raw) > 4096 || len(bucket) > 1024 || len(key) > 1024 || len(etag) > 1024 {
			t.Skip()
		}
		fields := map[string]string{"success_action_status": "201", "success_action_redirect": raw}
		if both {
			fields["redirect"] = raw
		}
		status, target, err := parsePostSuccess(fields)
		if both {
			if status != 0 || target != nil || !errors.Is(err, ErrPostInvalidOption) {
				t.Fatal("redirect alias conflict did not return invalid option")
			}
			return
		}
		if err != nil || status != http.StatusCreated {
			t.Fatalf("invalid redirect must use status path: status=%d err=%v", status, err)
		}
		// Both names have the same semantics when used independently.
		legacyStatus, legacy, legacyErr := parsePostSuccess(map[string]string{"success_action_status": "201", "redirect": raw})
		if legacyErr != nil || legacyStatus != status || !reflect.DeepEqual(legacy, target) {
			t.Fatal("redirect aliases differ")
		}
		parsed, parseErr := url.Parse(raw)
		invalid := raw == "" || len(raw) > 2048 || !utf8.ValidString(raw) || hasURLControl(raw) || parseErr != nil
		if !invalid {
			_, queryErr := url.ParseQuery(parsed.RawQuery)
			invalid = parsed.Opaque != "" || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || queryErr != nil
			if queryErr != nil {
				before := *parsed
				if postRedirectLocation(parsed, bucket, key, etag) != "" || !reflect.DeepEqual(*parsed, before) {
					t.Fatal("malformed query produced a location or mutated target")
				}
			}
			if !invalid {
				_, authorityErr := parsePostAuthority(parsed.Host)
				invalid = authorityErr != nil
			}
		}
		if invalid != (target == nil) {
			t.Fatal("redirect acceptance does not match target validity")
		}
		if target == nil {
			if postRedirectLocation(target, bucket, key, etag) != "" {
				t.Fatal("absent redirect produced a location")
			}
			return
		}
		if invalid || !target.IsAbs() || target.User != nil || target.Opaque != "" || hasURLControl(target.String()) {
			t.Fatal("accepted target violates redirect safety")
		}
		before := *target
		originalQuery, err := url.ParseQuery(target.RawQuery)
		if err != nil {
			t.Fatal("accepted malformed query")
		}
		location := postRedirectLocation(target, bucket, key, etag)
		if !reflect.DeepEqual(*target, before) {
			t.Fatal("redirect target was mutated")
		}
		projected, err := url.Parse(location)
		if err != nil || projected == nil {
			t.Fatal("redirect location is invalid")
		}
		query, err := url.ParseQuery(projected.RawQuery)
		if err != nil {
			t.Fatal("redirect location query is invalid")
		}
		for name, want := range map[string]string{"bucket": bucket, "key": key, "etag": etag} {
			if values := query[name]; len(values) != 1 || values[0] != want {
				t.Fatalf("selector %s did not round-trip exactly", name)
			}
			delete(query, name)
			delete(originalQuery, name)
		}
		if !reflect.DeepEqual(query, originalQuery) {
			t.Fatal("unrelated redirect query changed")
		}
		projected.RawQuery = before.RawQuery
		if !reflect.DeepEqual(*projected, before) {
			t.Fatal("redirect target path, authority, or fragment changed")
		}
	})
}

func TestGH353PostResponse_EscapingVersionSSEAndChecksums(t *testing.T) {
	result := objectWriteResult{ClientETag: `"client-etag"`, PlainSize: 0, Backend: s3.PutObjectResult{ETag: `"backend-etag"`, VersionID: "version-7", Headers: map[string]string{
		"x-amz-expiration": "expiry", "x-amz-storage-class": "STANDARD_IA", "x-amz-website-redirect-location": "/new",
		"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": "kms-id", "x-amz-server-side-encryption-bucket-key-enabled": "true", "x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key-md5": "customer-md5", sseCustomerKey: "customer-key-secret", sseKMSContextHeader: "kms-context-secret",
	}}, CustomerSSE: true}
	checksums := map[string]string{"x-amz-checksum-crc32": "crc32", "x-amz-checksum-crc32c": "crc32c", "x-amz-checksum-sha1": "sha1", "x-amz-checksum-sha256": "sha256", "x-amz-checksum-crc64nvme": "no", "x-amz-checksum-unknown": "no"}
	upload := &postUpload{bucket: "bucket", key: `literal%2F+../雪&<>`, successStatus: http.StatusCreated}
	r := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/bucket", nil)
	r.Host = "public.example"
	w := httptest.NewRecorder()
	h := NewHandler(newMockS3Client(), crypto.PassthroughEngine{}, logrus.New(), nil)
	if err := h.writePostSuccess(w, r, upload, result, checksums); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusCreated || w.Header().Get("Content-Type") != "application/xml" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
	}
	if w.Header().Get("Content-Length") != "" {
		t.Fatalf("object Content-Length leaked: %q", w.Header().Get("Content-Length"))
	}
	for name, want := range map[string]string{"ETag": `"backend-etag"`, "x-amz-version-id": "version-7", "x-amz-expiration": "expiry", "x-amz-storage-class": "STANDARD_IA", "x-amz-website-redirect-location": "/new", "x-amz-checksum-crc32": "crc32", "x-amz-checksum-crc32c": "crc32c", "x-amz-checksum-sha1": "sha1", "x-amz-checksum-sha256": "sha256"} {
		if w.Header().Get(name) != want {
			t.Errorf("header %s=%q want %q", name, w.Header().Get(name), want)
		}
	}
	for _, name := range []string{"x-amz-checksum-crc64nvme", "x-amz-checksum-unknown", sseCustomerKey, sseKMSContextHeader} {
		if w.Header().Get(name) != "" || strings.Contains(w.Body.String(), name+"-secret") {
			t.Errorf("secret/unsupported field %q leaked", name)
		}
	}
	var response postResponse
	if err := xml.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.XMLName.Local != "PostResponse" || response.XMLName.Space != postResponseNamespace || response.XMLNS != postResponseNamespace || response.ETag != `"backend-etag"` || response.Key != upload.key || !strings.HasPrefix(response.Location, "http://public.example/") {
		t.Fatalf("XML result=%+v", response)
	}
	location, err := url.Parse(response.Location)
	if err != nil || location.Path != "/bucket/"+upload.key {
		t.Fatalf("XML Location=%q parsed=%v err=%v", response.Location, location, err)
	}
	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		upload.successStatus = status
		w = httptest.NewRecorder()
		if err := h.writePostSuccess(w, r, upload, result, nil); err != nil || w.Code != status || w.Body.Len() != 0 {
			t.Fatalf("status=%d actual=%d error=%v body=%q", status, w.Code, err, w.Body.String())
		}
	}
	upload.successStatus = http.StatusCreated
	upload.redirect, _ = url.Parse("https://redirect.example/landing?key=old#section")
	w = httptest.NewRecorder()
	if err := h.writePostSuccess(w, r, upload, result, nil); err != nil || w.Code != http.StatusSeeOther || w.Body.Len() != 0 {
		t.Fatalf("redirect status=%d err=%v body=%q", w.Code, err, w.Body.String())
	}
	redirectURL, err := url.Parse(w.Header().Get("Location"))
	if err != nil || redirectURL.Query().Get("etag") != `"backend-etag"` || w.Header().Get("ETag") != `"backend-etag"` || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("redirect/header precedence location=%q headers=%v err=%v", w.Header().Get("Location"), w.Header(), err)
	}
}

func TestGH353PostResponse_NoRedirectFetchOrHostSpoof(t *testing.T) {
	for _, tc := range []struct {
		name, host, xfp, remote string
		tls                     bool
		trusted                 bool
		wantScheme              string
	}{
		{"direct TLS", "gateway.example", "http", "198.51.100.1:443", true, false, "https"},
		{"trusted proxy", "gateway.example", "HTTPS", "10.0.0.4:443", false, true, "https"},
		{"spoofed host and scheme", "gateway.example", "https", "198.51.100.1:443", false, false, "http"},
		{"duplicate XFP", "gateway.example", "https", "10.0.0.4:443", false, true, "http"},
		{"comma XFP", "gateway.example", "https,https", "10.0.0.4:443", false, true, "http"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{Server: config.ServerConfig{TrustedProxies: []string{"10.0.0.0/8"}}}
			h := NewHandlerWithFeatures(newMockS3Client(), crypto.PassthroughEngine{}, logrus.New(), nil, nil, nil, nil, cfg, nil)
			upload := &postUpload{bucket: "bucket", key: "key", successStatus: http.StatusCreated}
			r := httptest.NewRequest(http.MethodPost, "http://gateway.invalid/bucket", nil)
			r.Host = tc.host
			r.RemoteAddr = tc.remote
			if tc.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", tc.xfp)
			}
			if tc.name == "duplicate XFP" {
				r.Header.Add("X-Forwarded-Proto", "https")
			}
			if tc.tls {
				r.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			if err := h.writePostSuccess(w, r, upload, objectWriteResult{ClientETag: `"etag"`}, nil); err != nil {
				t.Fatal(err)
			}
			var response postResponse
			if err := xml.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(response.Location, tc.wantScheme+"://gateway.example/") {
				t.Fatalf("Location=%q want scheme=%s and request Host", response.Location, tc.wantScheme)
			}
		})
	}
	// The helper only serializes the redirect and must never request it.
	target, _ := url.Parse("http://127.0.0.1:1/never-fetch")
	h := NewHandler(newMockS3Client(), crypto.PassthroughEngine{}, logrus.New(), nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "http://gateway/bucket", nil)
	upload := &postUpload{bucket: "bucket", key: "key", successStatus: http.StatusNoContent, redirect: target}
	if err := h.writePostSuccess(w, r, upload, objectWriteResult{}, nil); err != nil || w.Code != http.StatusSeeOther {
		t.Fatalf("redirect serialization err=%v status=%d", err, w.Code)
	}
}

type postResponseWriter struct {
	header http.Header
	writes int
	short  bool
	err    error
}

func (w *postResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (w *postResponseWriter) WriteHeader(int) { w.writes++ }
func (w *postResponseWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.short {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func TestGH353PostResponse_InvalidBeforeWriteAndWriterFailures(t *testing.T) {
	h := NewHandler(newMockS3Client(), crypto.PassthroughEngine{}, logrus.New(), nil)
	upload := &postUpload{bucket: "bucket", key: "key", successStatus: http.StatusCreated}
	r := httptest.NewRequest(http.MethodPost, "http://gateway/bucket", nil)
	for _, host := range []string{"", "bad host", "user@gateway", "bad_host"} {
		r.Host = host
		w := &postResponseWriter{}
		if err := h.writePostSuccess(w, r, upload, objectWriteResult{}, nil); err == nil || w.writes != 0 || len(w.header) != 0 {
			t.Errorf("host %q err=%v writes=%d headers=%v", host, err, w.writes, w.header)
		}
	}
	r.Host = "gateway.example"
	upload.redirect, _ = url.Parse("https://target.example/path?bad=%ZZ")
	w := &postResponseWriter{}
	if err := h.writePostSuccess(w, r, upload, objectWriteResult{}, nil); err == nil || w.writes != 0 || len(w.header) != 0 {
		t.Fatalf("malformed redirect err=%v writes=%d headers=%v", err, w.writes, w.header)
	}
	upload.redirect = nil
	for _, tc := range []struct {
		name  string
		short bool
		err   error
	}{{"short", true, nil}, {"write error", false, io.ErrClosedPipe}} {
		t.Run(tc.name, func(t *testing.T) {
			w := &postResponseWriter{short: tc.short, err: tc.err}
			err := h.writePostSuccess(w, r, upload, objectWriteResult{ClientETag: `"etag"`}, nil)
			if tc.short && !errors.Is(err, io.ErrShortWrite) || tc.err != nil && !errors.Is(err, tc.err) || w.writes != 1 {
				t.Fatalf("err=%v writes=%d", err, w.writes)
			}
		})
	}
}

func TestGH353PostResponse_NilAndInvalidTypedValuesDoNotWrite(t *testing.T) {
	h := NewHandler(newMockS3Client(), crypto.PassthroughEngine{}, logrus.New(), nil)
	r := httptest.NewRequest(http.MethodPost, "http://gateway/bucket", nil)
	for _, tc := range []struct {
		name string
		u    *postUpload
	}{
		{"nil upload", nil},
		{"invalid status", &postUpload{bucket: "bucket", key: "key", successStatus: 202}},
		{"invalid redirect", &postUpload{bucket: "bucket", key: "key", successStatus: http.StatusNoContent, redirect: &url.URL{Scheme: "ftp", Host: "target.example"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &postResponseWriter{}
			if err := h.writePostSuccess(w, r, tc.u, objectWriteResult{}, nil); err == nil || w.writes != 0 || len(w.header) != 0 {
				t.Fatalf("err=%v writes=%d headers=%v", err, w.writes, w.header)
			}
		})
	}
	if err := (*Handler)(nil).writePostSuccess(&postResponseWriter{}, r, &postUpload{}, objectWriteResult{}, nil); err == nil {
		t.Fatal("nil handler accepted")
	}
	if err := h.writePostSuccess(nil, r, &postUpload{}, objectWriteResult{}, nil); err == nil {
		t.Fatal("nil response writer accepted")
	}
}
