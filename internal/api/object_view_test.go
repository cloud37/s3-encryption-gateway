package api

import (
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
)

func TestLoadObjectView_ClassifiesMPU(t *testing.T) {
	h := &Handler{}
	view, err := h.loadObjectView("bucket", "key", nil, map[string]string{crypto.MetaMPUEncrypted: "true"})
	if err != nil {
		t.Fatal(err)
	}
	if view.Class.Format != crypto.FormatMPUV1 || view.Class.ManifestKey != "key"+crypto.MPUManifestSuffix {
		t.Fatalf("unexpected view: %#v", view)
	}
}

func TestSetEncryptedMPUMarker_Table(t *testing.T) {
	for _, marker := range []string{"true", "v2"} {
		metadata := map[string]string{}
		setEncryptedMPUMarker(metadata, marker)
		if got := metadata[crypto.MetaMPUEncrypted]; got != marker {
			t.Fatalf("marker=%q want %q", got, marker)
		}
	}
}
