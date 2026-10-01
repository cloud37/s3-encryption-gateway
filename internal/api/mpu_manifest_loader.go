package api

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

type loadedMPUManifest struct {
	Manifest  *crypto.MultipartManifest
	BindingID [16]byte
	IsV2      bool
}

// loadMPUManifest is the single authenticated companion-object loader used by
// all completed-MPU read paths.
func (h *Handler) loadMPUManifest(ctx context.Context, c s3.Client, bucket, parentKey string, class crypto.ObjectClass) (*loadedMPUManifest, error) {
	if class.Format != crypto.FormatMPUV1 && class.Format != crypto.FormatMPUV2 {
		return nil, fmt.Errorf("not an MPU object")
	}
	manifestKey := class.ManifestKey
	r, meta, err := c.GetObject(ctx, bucket, manifestKey, nil, nil)
	if err != nil {
		if isS3NotFoundError(err) {
			return nil, fmt.Errorf("%w: %s", ErrMissingMPUManifest, manifestKey)
		}
		return nil, fmt.Errorf("fetch manifest: %w", backendObjectError(bucket, manifestKey, err))
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", backendObjectError(bucket, manifestKey, err))
	}
	engine, err := h.getEncryptionEngine(bucket)
	if err != nil {
		return nil, fmt.Errorf("get engine: %w", err)
	}
	loaded := &loadedMPUManifest{IsV2: class.Format == crypto.FormatMPUV2}
	if loaded.IsV2 {
		if meta[crypto.MetaMPUManifestVersion] != "2" {
			return nil, fmt.Errorf("invalid companion marker")
		}
		// ClassifyObject has already validated the binding; use its bytes directly.
		loaded.BindingID = class.BindingID
		plain, err := crypto.DecryptMPUManifest(ctx, engine, crypto.ObjectContext{Bucket: bucket, Key: manifestKey}, loaded.BindingID, raw, meta)
		if err != nil {
			return nil, fmt.Errorf("decrypt manifest: %w", err)
		}
		raw = plain
	} else {
		plainReader, _, err := engine.Decrypt(ctx, crypto.ObjectContext{Bucket: bucket, Key: manifestKey}, bytes.NewReader(raw), meta)
		if err != nil {
			return nil, fmt.Errorf("decrypt manifest: %w", err)
		}
		raw, err = io.ReadAll(plainReader)
		if err != nil {
			return nil, fmt.Errorf("read manifest plaintext: %w", err)
		}
	}
	manifest, err := crypto.UnmarshalMultipartManifest(raw)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if loaded.IsV2 {
		if err := manifest.ValidateFor(crypto.ObjectContext{Bucket: bucket, Key: parentKey}, crypto.ObjectContext{Bucket: bucket, Key: manifestKey}, loaded.BindingID); err != nil {
			return nil, err
		}
	}
	loaded.Manifest = manifest
	return loaded, nil
}

func (h *Handler) loadMPUManifestSize(ctx context.Context, c s3.Client, bucket, parentKey string, raw map[string]string) (int64, error) {
	view, err := h.loadObjectView(bucket, parentKey, nil, raw)
	if err != nil {
		return 0, err
	}
	loaded, err := h.loadMPUManifest(ctx, c, bucket, parentKey, view.Class)
	if err != nil {
		return 0, err
	}
	return loaded.Manifest.TotalPlainSize, nil
}
