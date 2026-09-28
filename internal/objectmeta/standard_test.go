package objectmeta

import (
	"net/http"
	"testing"
)

func TestStandard_FromHeader_AllSixFields(t *testing.T) {
	h := http.Header{"content-type": {"text/plain"}, "CACHE-CONTROL": {"no-cache"}, "Content-Disposition": {"inline"}, "Content-Encoding": {"gzip"}, "Content-Language": {"en"}, "Expires": {"tomorrow"}}
	s := FromHeader(h)
	for _, tc := range []struct{ n, v string }{{"Content-Type", "text/plain"}, {"Cache-Control", "no-cache"}, {"Content-Disposition", "inline"}, {"Content-Encoding", "gzip"}, {"Content-Language", "en"}, {"Expires", "tomorrow"}} {
		if got := s.Get(tc.n); got != tc.v {
			t.Errorf("%s: got %q", tc.n, got)
		}
	}
}

func TestStandard_ApplyOverlayAndUnknownNames(t *testing.T) {
	base := Standard{ContentType: "text/plain", CacheControl: "private"}
	if base.Get("Content-Type") != "text/plain" || base.Get("not-a-header") != "" {
		t.Fatal("Get returned unexpected standard header")
	}
	merged := base.Overlay(Standard{ContentType: "application/json", Expires: "tomorrow"})
	if merged.ContentType != "application/json" || merged.CacheControl != "private" || merged.Expires != "tomorrow" {
		t.Fatalf("Overlay=%+v", merged)
	}
	if IsStandard("content-language") != true || IsStandard("ETag") {
		t.Fatal("IsStandard classification mismatch")
	}
	meta := make(map[string]string)
	merged.ApplyTo(meta)
	if len(meta) != 3 || meta["Content-Type"] != "application/json" || meta["Expires"] != "tomorrow" {
		t.Fatalf("ApplyTo metadata=%v", meta)
	}
}

func TestSplit_CaseInsensitive_RemainderPreserved(t *testing.T) {
	s, rest := Split(map[string]string{"CONTENT-TYPE": "text/plain", "X-Amz-Meta-Foo": "bar"})
	if s.ContentType != "text/plain" || rest["X-Amz-Meta-Foo"] != "bar" {
		t.Fatalf("unexpected split: %#v %#v", s, rest)
	}
}

func TestNormalizeBackendKeys_Table(t *testing.T) {
	got := NormalizeBackendKeys(map[string]string{"content-length": "1", "X-Amz-Meta-Foo": "bar", "ETag": "e"})
	if got["Content-Length"] != "1" || got["x-amz-meta-foo"] != "bar" || got["ETag"] != "e" {
		t.Fatalf("unexpected keys: %#v", got)
	}
}
