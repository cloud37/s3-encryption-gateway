package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func TestParseWriteMetadata_RejectsReservedKey(t *testing.T) {
	h := make(http.Header)
	h.Set("X-Amz-Meta-Encrypted", "false")
	if _, err := parseWriteMetadata(h); err == nil || err.Code != "InvalidArgument" {
		t.Fatalf("parseWriteMetadata error = %#v, want InvalidArgument", err)
	}
}

func TestParseWriteMetadata_AllStandardAndUserFields(t *testing.T) {
	h := make(http.Header)
	for i, name := range objectmeta.Names {
		h.Set(name, "standard-"+string(rune('a'+i)))
	}
	h.Set("X-Amz-Meta-Owner", "team")
	h.Set("X-Amz-Meta-Project", "gateway")
	got, s3Err := parseWriteMetadata(h)
	if s3Err != nil {
		t.Fatal(s3Err)
	}
	for i, name := range objectmeta.Names {
		want := "standard-" + string(rune('a'+i))
		if value := got.Standard.Get(name); value != want {
			t.Errorf("%s = %q, want %q", name, value, want)
		}
	}
	if got.User["x-amz-meta-owner"] != "team" || got.User["x-amz-meta-project"] != "gateway" {
		t.Fatalf("user metadata = %#v", got.User)
	}
}

func TestResolveCopyWriteMetadata_CopyVsReplace(t *testing.T) {
	sourceMeta := map[string]string{"x-amz-meta-owner": "source"}
	standard := objectmeta.Standard{
		ContentType: "source/type", CacheControl: "source-cache", ContentDisposition: "source-disposition",
		ContentEncoding: "gzip", ContentLanguage: "en-GB", Expires: "Mon, 21 Oct 2030 07:28:00 GMT",
	}
	standard.ApplyTo(sourceMeta)
	source := objectResponseSource{Meta: sourceMeta}
	for _, directive := range []string{"", "COPY"} {
		h := make(http.Header)
		h.Set("Content-Type", "ignored/type")
		h.Set("X-Amz-Meta-Owner", "ignored")
		h.Set("x-amz-metadata-directive", directive)
		got, err := resolveCopyWriteMetadata(h, source)
		if err != nil {
			t.Fatal(err)
		}
		if got.Standard != standard || got.User["x-amz-meta-owner"] != "source" {
			t.Fatalf("COPY metadata = %#v", got)
		}
	}
	h := make(http.Header)
	h.Set("x-amz-metadata-directive", "REPLACE")
	h.Set("Content-Type", "replacement/type")
	h.Set("X-Amz-Meta-Owner", "replacement")
	got, err := resolveCopyWriteMetadata(h, source)
	if err != nil {
		t.Fatal(err)
	}
	if got.Standard.ContentType != "replacement/type" || got.Standard.ContentEncoding != "" || got.Standard.ContentLanguage != "" || got.Standard.Expires != "" || got.User["x-amz-meta-owner"] != "replacement" {
		t.Fatalf("REPLACE metadata = %#v", got)
	}
	replace := make(http.Header)
	replace.Set("x-amz-metadata-directive", "REPLACE")
	replace.Set("Content-Encoding", "br")
	replace.Set("Content-Language", "fr")
	replace.Set("Expires", "Wed, 22 Oct 2031 07:28:00 GMT")
	replaced, err := resolveCopyWriteMetadata(replace, source)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Standard.ContentType != "application/octet-stream" || replaced.Standard.ContentEncoding != "br" || replaced.Standard.ContentLanguage != "fr" || replaced.Standard.Expires != "Wed, 22 Oct 2031 07:28:00 GMT" {
		t.Fatalf("REPLACE all-six metadata = %#v", replaced.Standard)
	}
}

func TestCreateMultipartUpload_ParsesAllStandardHeadersAndRejectsReservedBeforeBackend(t *testing.T) {
	client := newMockS3Client()
	handler := &Handler{s3Client: client, logger: logrus.New(), metrics: getTestMetrics(), encryptionEngine: &mockEngine{}, config: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploads", nil)
	for _, name := range objectmeta.Names {
		req.Header.Set(name, "value-"+name)
	}
	req.Header.Set("X-Amz-Meta-Owner", "team")
	req.Header.Set("X-Amz-Meta-Project", "gateway")
	w := httptest.NewRecorder()
	handler.handleCreateMultipartUpload(w, mux.SetURLVars(req, map[string]string{"bucket": "bucket", "key": "key"}))
	if w.Code != http.StatusOK {
		t.Fatalf("CreateMultipartUpload status=%d body=%s", w.Code, w.Body.String())
	}
	for _, name := range objectmeta.Names {
		if got := client.lastMPUMetadata[name]; got != "value-"+name {
			t.Errorf("MPU %s=%q", name, got)
		}
	}
	if client.lastMPUMetadata["x-amz-meta-owner"] != "team" || client.lastMPUMetadata["x-amz-meta-project"] != "gateway" {
		t.Fatalf("MPU user metadata = %#v", client.lastMPUMetadata)
	}
	beforeUploads := len(client.objects)
	req = httptest.NewRequest(http.MethodPost, "/bucket/key?uploads", nil)
	req.Header.Set("X-Amz-Meta-Encrypted", "forged")
	w = httptest.NewRecorder()
	handler.handleCreateMultipartUpload(w, mux.SetURLVars(req, map[string]string{"bucket": "bucket", "key": "key"}))
	if w.Code != http.StatusBadRequest || len(client.objects) != beforeUploads {
		t.Fatalf("reserved CreateMPU metadata: status=%d backend changed=%t", w.Code, len(client.objects) != beforeUploads)
	}
}

func TestCreateMultipartUpload_UsesPersistPlanForNativeStandardHeaders(t *testing.T) {
	client := newMockS3Client()
	handler := &Handler{s3Client: client, logger: logrus.New(), metrics: getTestMetrics(), encryptionEngine: &mockEngine{}, config: &config.Config{}}
	req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploads", nil)
	for _, name := range objectmeta.Names {
		req.Header.Set(name, "native-"+name)
	}
	req.Header.Set("X-Amz-Meta-Owner", "team")
	w := httptest.NewRecorder()
	handler.handleCreateMultipartUpload(w, mux.SetURLVars(req, map[string]string{"bucket": "bucket", "key": "key"}))
	if w.Code != http.StatusOK {
		t.Fatalf("CreateMultipartUpload status=%d body=%s", w.Code, w.Body.String())
	}
	for _, name := range objectmeta.Names {
		if got := client.lastMPUMetadata[name]; got != "native-"+name {
			t.Errorf("planned MPU field %s=%q", name, got)
		}
	}
	if got := client.lastMPUMetadata["x-amz-meta-owner"]; got != "team" {
		t.Fatalf("user metadata=%q, want team", got)
	}
}

func TestResolveCopyWriteMetadata_UnknownDirectiveDoesNotReadSource(t *testing.T) {
	h := make(http.Header)
	h.Set("x-amz-metadata-directive", "merge")
	if _, err := resolveCopyWriteMetadata(h, objectResponseSource{}); err == nil || err.Code != "InvalidArgument" {
		t.Fatalf("resolveCopyWriteMetadata error = %#v, want InvalidArgument", err)
	}
}

func TestBuildPersistPlan_PassthroughSplitsStandardHeaders(t *testing.T) {
	plan := buildPersistPlan(map[string]string{"Content-Type": "text/plain", "x-amz-meta-owner": "a"}, crypto.ObjectClass{}, nil)
	if plan.Native.ContentType != "text/plain" || plan.Metadata["Content-Type"] != "" || plan.Metadata["x-amz-meta-owner"] != "a" {
		t.Fatalf("unexpected persist plan: %#v", plan)
	}
}
