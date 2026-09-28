package crypto

import (
	"errors"
	"fmt"
)

type ObjectFormat uint8

const (
	FormatPlaintext ObjectFormat = iota
	FormatBufferedLegacy
	FormatBufferedV2
	FormatBufferedFallback
	FormatChunkedV1
	FormatChunkedV2
	FormatMPUV1
	FormatMPUV2
)

type ObjectClass struct {
	Format      ObjectFormat
	Encrypted   bool
	ChunkSize   int
	BindingID   [16]byte
	ManifestKey string
}

const MPUManifestSuffix = ".mpu-manifest"

var ErrUnsupportedObjectFormat = errors.New("crypto: unsupported object format marker")

func ClassifyObject(parentKey string, expanded map[string]string) (ObjectClass, error) {
	if marker := expanded[MetaMPUEncrypted]; marker != "" {
		var f ObjectFormat
		switch marker {
		case "true":
			f = FormatMPUV1
		case "v2":
			f = FormatMPUV2
		default:
			return ObjectClass{}, fmt.Errorf("%w: mpu marker %q", ErrUnsupportedObjectFormat, marker)
		}
		manifest := parentKey + MPUManifestSuffix
		if p := expanded[MetaFallbackPointer]; p != "" && p != manifest {
			return ObjectClass{}, fmt.Errorf("%w: manifest pointer mismatch", ErrUnsupportedObjectFormat)
		}
		var binding [16]byte
		if f == FormatMPUV2 {
			b, err := parseObjectBindingID(expanded[MetaObjectBindingID])
			if err != nil {
				return ObjectClass{}, fmt.Errorf("%w: binding: %v", ErrUnsupportedObjectFormat, err)
			}
			copy(binding[:], b)
		}
		return ObjectClass{Format: f, Encrypted: true, BindingID: binding, ManifestKey: manifest}, nil
	}
	if p := expanded[MetaFallbackPointer]; p != "" {
		manifest := parentKey + MPUManifestSuffix
		if p != manifest {
			return ObjectClass{}, fmt.Errorf("%w: manifest pointer mismatch", ErrUnsupportedObjectFormat)
		}
		return ObjectClass{Format: FormatMPUV1, Encrypted: true, ManifestKey: manifest}, nil
	}
	if mode := expanded[MetaFallbackMode]; mode != "" {
		if mode != "true" && mode != "v1" && mode != "v2" && mode != "v3" {
			return ObjectClass{}, fmt.Errorf("%w: fallback marker %q", ErrUnsupportedObjectFormat, mode)
		}
		return ObjectClass{Format: FormatBufferedFallback, Encrypted: true}, nil
	}
	if expanded[MetaChunkedFormat] != "" {
		if declared := parseChunkSize(expanded); declared <= 0 || declared > MaxChunkSize {
			return ObjectClass{}, fmt.Errorf("%w: invalid chunk size", ErrChunkedObjectIncomplete)
		}
		v, err := chunkedVersionForMetadata(expanded)
		if err != nil {
			return ObjectClass{}, fmt.Errorf("%w: %v", ErrUnsupportedObjectFormat, err)
		}
		f := FormatChunkedV1
		if v == ChunkedFormatV2 {
			f = FormatChunkedV2
		}
		return ObjectClass{Format: f, Encrypted: true, ChunkSize: parseChunkSize(expanded)}, nil
	}
	if expanded[MetaEncrypted] != "" {
		f := FormatBufferedLegacy
		if v := expanded[MetaObjectFormatVersion]; v != "" {
			if v != "buffered-v2" {
				return ObjectClass{}, fmt.Errorf("%w: format marker %q", ErrUnsupportedObjectFormat, v)
			}
			f = FormatBufferedV2
		}
		return ObjectClass{Format: f, Encrypted: true}, nil
	}
	return ObjectClass{Format: FormatPlaintext}, nil
}

func parseChunkSize(meta map[string]string) int {
	n := DefaultChunkSize
	if v := meta[MetaChunkSize]; v != "" {
		var parsed int
		if _, e := fmt.Sscanf(v, "%d", &parsed); e == nil && parsed > 0 {
			n = parsed
		}
	}
	return n
}
