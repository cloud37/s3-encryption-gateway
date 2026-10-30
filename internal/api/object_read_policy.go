package api

import (
	"context"
	"errors"
	"io"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

var errPlaintextReadForbidden = errors.New("plaintext object read forbidden by bucket encryption policy")

func (h *Handler) enforceObjectReadPolicy(bucket string, class crypto.ObjectClass) error {
	if !class.Encrypted && h.policyManager.BucketRequiresEncryption(bucket) {
		return errPlaintextReadForbidden
	}
	return nil
}

// readableParentClient validates fetched parent metadata for targeted reads.
// Companion objects are not subject to the parent policy check.
type readableParentClient struct {
	s3.Client
	h           *Handler
	bucket, key string
}

func (c readableParentClient) GetObject(ctx context.Context, bucket, key string, versionID, byteRange *string) (io.ReadCloser, map[string]string, error) {
	r, metadata, err := c.Client.GetObject(ctx, bucket, key, versionID, byteRange)
	if err != nil || bucket != c.bucket || key != c.key {
		return r, metadata, err
	}
	if _, err := c.h.loadReadableObjectView(bucket, key, versionID, metadata); err != nil {
		_ = r.Close()
		return nil, nil, err
	}
	return r, metadata, nil
}

func (h *Handler) loadReadableObjectView(bucket, key string, versionID *string, raw map[string]string) (*objectView, error) {
	view, err := h.loadObjectView(bucket, key, versionID, raw)
	if err != nil {
		return nil, err
	}
	if err := h.enforceObjectReadPolicy(bucket, view.Class); err != nil {
		return nil, err
	}
	return view, nil
}
