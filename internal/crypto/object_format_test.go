package crypto

import (
	"errors"
	"testing"
)

func TestClassifyObject_AllFormats(t *testing.T) {
	manifest, _ := encodeManifest(&ChunkManifest{Version: int(ChunkedFormatV1), ChunkSize: DefaultChunkSize})
	for _, tc := range []struct {
		name string
		meta map[string]string
		want ObjectFormat
	}{
		{"plain", nil, FormatPlaintext}, {"legacy", map[string]string{MetaEncrypted: "true"}, FormatBufferedLegacy}, {"v2", map[string]string{MetaEncrypted: "true", MetaObjectFormatVersion: "buffered-v2"}, FormatBufferedV2}, {"fallback", map[string]string{MetaFallbackMode: "v1"}, FormatBufferedFallback}, {"chunked", map[string]string{MetaChunkedFormat: "true", MetaManifest: manifest}, FormatChunkedV1}, {"mpu", map[string]string{MetaMPUEncrypted: "true"}, FormatMPUV1},
	} {
		got, err := ClassifyObject("key", tc.meta)
		if err != nil || got.Format != tc.want {
			t.Errorf("%s: %#v %v", tc.name, got, err)
		}
	}
}

func TestClassifyObject_UnknownMPUMarker_FailsClosed(t *testing.T) {
	_, err := ClassifyObject("k", map[string]string{MetaMPUEncrypted: "v3"})
	if !errors.Is(err, ErrUnsupportedObjectFormat) {
		t.Fatal(err)
	}
}
func TestClassifyObject_ManifestPointerMismatch_FailsClosed(t *testing.T) {
	_, err := ClassifyObject("k", map[string]string{MetaMPUEncrypted: "v2", MetaFallbackPointer: "other"})
	if !errors.Is(err, ErrUnsupportedObjectFormat) {
		t.Fatal(err)
	}
}

func TestClassifyObject_MarkerValidationTable(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]string
		want ObjectFormat
		bad  bool
	}{
		{"buffered v2", map[string]string{MetaEncrypted: "true", MetaObjectFormatVersion: "buffered-v2"}, FormatBufferedV2, false},
		{"bad buffered version", map[string]string{MetaEncrypted: "true", MetaObjectFormatVersion: "future"}, 0, true},
		{"fallback v3", map[string]string{MetaFallbackMode: "v3"}, FormatBufferedFallback, false},
		{"bad fallback", map[string]string{MetaFallbackMode: "future"}, 0, true},
		{"chunked v2", map[string]string{MetaChunkedFormat: "true", MetaManifest: encodeBase64URL([]byte(`{"v":2,"cs":16384}`)), MetaObjectFormatVersion: "chunked-v2", MetaObjectBindingID: "AAECAwQFBgcICQoLDA0ODw"}, FormatChunkedV2, false},
		{"bad chunked version", map[string]string{MetaChunkedFormat: "true", MetaManifest: "{}"}, 0, true},
		{"mpu v2 missing binding", map[string]string{MetaMPUEncrypted: "v2"}, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ClassifyObject("key", tc.meta)
			if tc.bad {
				if err == nil {
					t.Fatalf("ClassifyObject unexpectedly succeeded: %#v", got)
				}
				return
			}
			if err != nil || got.Format != tc.want {
				t.Fatalf("ClassifyObject=%#v err=%v want=%v", got, err, tc.want)
			}
		})
	}
}

func TestClassifyObject_ChunkSizeBounds(t *testing.T) {
	for _, value := range []string{"", "bad", "1", "999999999999999999999999999999"} {
		got := parseChunkSize(map[string]string{MetaChunkSize: value})
		if value == "1" {
			if got != 1 {
				t.Errorf("parseChunkSize(%q)=%d want 1", value, got)
			}
		} else if got != DefaultChunkSize {
			t.Errorf("parseChunkSize(%q)=%d want default %d", value, got, DefaultChunkSize)
		}
	}
	if got := parseChunkSize(nil); got != DefaultChunkSize {
		t.Fatalf("parseChunkSize(nil)=%d want default %d", got, DefaultChunkSize)
	}
}

func TestClassifyObject_LegacyPointerOnlyMPU(t *testing.T) {
	class, err := ClassifyObject("legacy", map[string]string{MetaFallbackPointer: "legacy" + MPUManifestSuffix})
	if err != nil || class.Format != FormatMPUV1 || class.ManifestKey != "legacy"+MPUManifestSuffix {
		t.Fatalf("legacy pointer-only MPU class=%+v err=%v", class, err)
	}
}

func FuzzClassifyObject(f *testing.F) {
	for _, marker := range []string{"true", "v2", "v3", "", "unknown"} {
		f.Add(marker, "object")
	}
	f.Fuzz(func(t *testing.T, marker, key string) {
		if len(marker) > 64 || len(key) > 256 {
			t.Skip()
		}
		_, err := ClassifyObject(key, map[string]string{MetaMPUEncrypted: marker})
		if marker != "" && marker != "true" && marker != "v2" && err == nil {
			t.Fatalf("unsupported marker %q classified without error", marker)
		}
	})
}
