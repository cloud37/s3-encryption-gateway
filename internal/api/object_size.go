package api

import (
	"context"
	"fmt"
	"strconv"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// plaintextSize is the result of the gateway's single plaintext-size policy.
type plaintextSize struct {
	Size   int64
	Exact  bool
	Source string
}

// resolvePlaintextSize derives the client-visible size from normalized object
// metadata.  The backend content length is used only for plaintext objects;
// encrypted formats use their authenticated/original-size metadata or the
// format-specific ciphertext formula.
func (h *Handler) resolvePlaintextSize(ctx context.Context, c s3.Client, view *objectView) (plaintextSize, error) {
	if view == nil {
		return plaintextSize{Size: -1}, fmt.Errorf("nil object view")
	}
	meta := view.Expanded
	if !view.Class.Encrypted {
		return metadataSize(meta, "backend")
	}
	if view.Class.Format == crypto.FormatMPUV1 || view.Class.Format == crypto.FormatMPUV2 {
		loaded, err := h.loadMPUManifest(ctx, c, view.Bucket, view.Key, view.Class)
		if err != nil {
			return plaintextSize{Size: -1}, err
		}
		return plaintextSize{Size: loaded.Manifest.TotalPlainSize, Exact: true, Source: "mpu-manifest"}, nil
	}
	if view.Class.Format == crypto.FormatBufferedFallback {
		// The fallback-v2 object body embeds its authenticated metadata prefix;
		// its header original-size value was emitted by the encryptor and is exact.
		if value := meta[crypto.MetaOriginalSize]; value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return plaintextSize{Size: -1}, fmt.Errorf("invalid fallback original plaintext size")
			}
			return plaintextSize{Size: n, Exact: true, Source: "original-size"}, nil
		}
		return plaintextSize{Size: -1}, nil
	}
	if view.Class.Format == crypto.FormatChunkedV1 || view.Class.Format == crypto.FormatChunkedV2 {
		// Chunked-v1 metadata in deployed legacy objects may omit a manifest;
		// the classifier has already selected the v1 compatibility format.
		if view.Class.Format == crypto.FormatChunkedV2 {
			info, err := h.preflightChunkedCompleteness(ctx, c, view.Bucket, view.Key, view.VersionID, view.Raw)
			if err != nil {
				return plaintextSize{Size: -1}, err
			}
			if info.PlaintextSize <= uint64(^uint64(0)>>1) {
				return plaintextSize{Size: int64(info.PlaintextSize), Exact: true, Source: "chunked-terminal"}, nil
			}
		}
		if value := view.Raw["Content-Length"]; value != "" {
			n, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr != nil || n < 0 {
				return plaintextSize{Size: -1}, fmt.Errorf("invalid chunked ciphertext size")
			}
			plain, _, err := crypto.PlaintextSizeForCiphertext(meta, n)
			if err != nil {
				return plaintextSize{Size: -1}, err
			}
			return plaintextSize{Size: plain, Exact: true, Source: "chunked-formula"}, nil
		}
		if view.Class.Format == crypto.FormatChunkedV1 {
			return plaintextSize{Size: -1}, nil
		}
		if value := meta[crypto.MetaOriginalSize]; value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil || n < 0 {
				return plaintextSize{Size: -1}, fmt.Errorf("invalid original plaintext size")
			}
			return plaintextSize{Size: n, Exact: true, Source: "original-size"}, nil
		}
		return plaintextSize{Size: -1}, nil
	}
	if value := meta[crypto.MetaOriginalSize]; value != "" {
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil || n < 0 {
			return plaintextSize{Size: -1}, fmt.Errorf("invalid original plaintext size")
		}
		return plaintextSize{Size: n, Exact: true, Source: "original-size"}, nil
	}
	if value := meta["Content-Length"]; value != "" {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			if overhead, overheadErr := crypto.AEADOverheadForAlgorithm(meta[crypto.MetaAlgorithm]); overheadErr == nil && n >= int64(overhead) {
				return plaintextSize{Size: n - int64(overhead), Exact: true, Source: "legacy-aead"}, nil
			}
		}
	}
	return plaintextSize{Size: -1}, nil
}

func metadataSize(meta map[string]string, source string) (plaintextSize, error) {
	n, err := strconv.ParseInt(meta["Content-Length"], 10, 64)
	if err != nil || n < 0 {
		return plaintextSize{Size: -1}, nil
	}
	return plaintextSize{Size: n, Exact: true, Source: source}, nil
}
