package api

import "context"

// recordPlaintextSize is the sole API size-cache writer. Unknown or
// estimated sizes are intentionally never persisted.
func (h *Handler) recordPlaintextSize(ctx context.Context, bucket, key string, size plaintextSize) {
	if h.sizeCache == nil || !size.Exact || size.Size < 0 {
		return
	}
	if err := h.sizeCache.Set(ctx, bucket, key, size.Size); err != nil && h.logger != nil {
		h.logger.WithError(err).WithField("bucket", bucket).WithField("key", key).
			Warn("failed to record plaintext size")
	}
}
