package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

func TestNewRangeDecryptReaderRejectsUnknownManifestVersions(t *testing.T) {
	for _, version := range []int{0, 3, 255} {
		t.Run(fmt.Sprintf("version-%d", version), func(t *testing.T) {
			_, err := newRangeDecryptReader(
				bytes.NewReader(nil),
				nil,
				&ChunkManifest{Version: version, ChunkSize: 1, ChunkCount: 1},
				nil,
				0,
				0,
				nil,
				false,
			)
			if err == nil {
				t.Fatalf("expected version %d to be rejected", version)
			}
		})
	}
}
