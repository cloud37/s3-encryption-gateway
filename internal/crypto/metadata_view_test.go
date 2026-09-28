package crypto

import "testing"

func TestMetadataView_PublicAndReservedHelpers(t *testing.T) {
	meta := map[string]string{MetaEncrypted: "true", MetaContentType: "text/plain", "x-amz-meta-user": "value"}
	dropGatewayReserved(meta)
	if _, ok := meta[MetaEncrypted]; ok {
		t.Fatal("reserved marker not dropped")
	}
	view := PlaintextMetadataView(map[string]string{MetaContentType: "application/json", "x-amz-meta-user": "value"}, 7, "etag")
	if view["Content-Type"] != "application/json" || view["Content-Length"] != "7" || view["ETag"] != "etag" {
		t.Fatalf("public plaintext metadata view=%v", view)
	}
	if !isEncryptionCleanupMetadata(MetaEncrypted) {
		t.Fatal("clear encryption marker not classified for cleanup")
	}
}

func TestPlaintextMetadataView_PrecedenceAndReservedFiltering(t *testing.T) {
	view := plaintextMetadataView(map[string]string{
		MetaEncrypted: "true", MetaContentType: "canonical", "x-amz-meta-ct": "compact",
		"encryption-content-type": "legacy", "Content-Type": "native", "x-amz-meta-user": "ok",
	}, -1, "")
	if view["Content-Type"] != "canonical" || view["x-amz-meta-user"] != "ok" {
		t.Fatalf("view=%v", view)
	}
	for key := range view {
		if IsGatewayReservedKey(key) {
			t.Fatalf("reserved field %q leaked", key)
		}
	}
}

func TestPlaintextMetadataView_PublicSizeAndETagBranches(t *testing.T) {
	withoutLength := PlaintextMetadataView(map[string]string{}, -1, "")
	if _, ok := withoutLength["Content-Length"]; ok {
		t.Fatalf("unknown size emitted Content-Length: %v", withoutLength)
	}
	withoutETag := PlaintextMetadataView(map[string]string{}, 0, "")
	if _, ok := withoutETag["ETag"]; ok {
		t.Fatalf("empty ETag emitted: %v", withoutETag)
	}
}

func TestPlaintextMetadataView_EmptyOriginalValues(t *testing.T) {
	view := plaintextMetadataView(map[string]string{MetaContentType: "", MetaCacheControl: ""}, -1, "")
	if _, ok := view["Content-Type"]; ok {
		t.Fatalf("empty protected field emitted: %v", view)
	}
}

func TestPlaintextMetadataView_MetadataKeyFormsAndNilMap(t *testing.T) {
	if got := PlaintextMetadataView(nil, 3, ""); got["Content-Length"] != "3" {
		t.Fatalf("nil metadata view=%v", got)
	}
	for _, key := range []string{"Content-Type", "content-type"} {
		if value := metadataValueFold(map[string]string{key: "found"}, "content-type"); value != "found" {
			t.Errorf("metadataValueFold(%q)=%q", key, value)
		}
	}
}

func TestMetadataValueFold_AbsentValue(t *testing.T) {
	if got := metadataValueFold(nil, "content-type"); got != "" {
		t.Fatalf("absent value=%q", got)
	}
}
