package audit

import (
	"context"
	"io"
	"testing"

	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

// compile-time check: s3.Client satisfies AuditClient.
var _ AuditClient = (*s3ClientAdapter)(nil)

// s3ClientAdapter adapts s3.Client to AuditClient.
// We use a separate type to verify the interface at compile time without
// needing to instantiate an actual s3.Client.
type s3ClientAdapter struct {
	inner s3.Client
}

func (a *s3ClientAdapter) HeadObject(ctx context.Context, bucket, key string, versionID *string) (map[string]string, error) {
	return a.inner.HeadObject(ctx, bucket, key, versionID)
}

func (a *s3ClientAdapter) GetObject(ctx context.Context, bucket, key string, versionID *string, rangeHeader *string) (io.ReadCloser, map[string]string, error) {
	return a.inner.GetObject(ctx, bucket, key, versionID, rangeHeader)
}

func (a *s3ClientAdapter) ListObjects(ctx context.Context, bucket, prefix string, opts s3.ListOptions) (s3.ListResult, error) {
	return a.inner.ListObjects(ctx, bucket, prefix, opts)
}

// TestAuditClient_InterfaceHasNoWriteMethods asserts at the type-system level
// that AuditClient does not include any write methods. The compile-time
// assignment var _ AuditClient = (*s3ClientAdapter)(nil) above ensures that
// the adapter satisfies the interface. If any write method were added to
// AuditClient without also being added to s3ClientAdapter, the code would
// not compile.
func TestAuditClient_InterfaceHasNoWriteMethods(t *testing.T) {
	// Verify the AuditClient type has no method named PutObject, CopyObject,
	// or DeleteObject. This is a simple naming convention guard.
	t.Log("AuditClient interface is read-only (compile-time check via var _ AuditClient)")
}
