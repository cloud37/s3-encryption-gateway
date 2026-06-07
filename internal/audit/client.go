package audit

import (
	"context"
	"io"

	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// AuditClient is the read-only backend access surface for s3eg-cli.
// Invariants:
//   - Implementations MUST NOT mutate backend state.
//   - ctx is honoured for cancellation on every call.
type AuditClient interface {
	HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error)
	GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error)
	ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) (s3.ListResult, error)
}
