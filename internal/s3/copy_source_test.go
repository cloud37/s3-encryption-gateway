package s3

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type copySourceBackend interface {
	CopyObject(context.Context, string, string, string, string, *string, map[string]string, *ObjectLockInput) (string, map[string]string, error)
	UploadPartCopy(context.Context, string, string, string, int32, string, string, *string, *CopyPartRange) (*CopyPartResult, error)
}

func TestCopySource_BackendHeaderEncoding(t *testing.T) {
	for _, tc := range []struct{ key, version, wire string }{
		{"plain", "", "src-bucket/plain"},
		{"dir/with space.txt", "", "src-bucket/dir%2Fwith%20space.txt"},
		{"dir/umlaut-ä.txt", "", "src-bucket/dir%2Fumlaut-%C3%A4.txt"},
		{"dir/a+b&c.txt", "", "src-bucket/dir%2Fa%2Bb%26c.txt"},
		{"literal%2F", "", "src-bucket/literal%252F"},
		{"name?versionId=literal#hash", "v+/=%", "src-bucket/name%3FversionId%3Dliteral%23hash?versionId=v%2B%2F%3D%25"},
		{"/leading//key", "", "src-bucket/%2Fleading%2F%2Fkey"},
	} {
		for _, proxy := range []bool{false, true} {
			for _, part := range []bool{false, true} {
				t.Run(fmt.Sprintf("proxy=%t/part=%t/%s", proxy, part, tc.key), func(t *testing.T) {
					backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						assert.Equal(t, tc.wire, r.Header.Get("x-amz-copy-source"))
						if part {
							assert.Equal(t, "bytes=2-9", r.Header.Get("x-amz-copy-source-range"))
							assert.Equal(t, "u", r.URL.Query().Get("uploadId"))
							assert.Equal(t, "1", r.URL.Query().Get("partNumber"))
						}
						root := "CopyObjectResult"
						if part {
							root = "CopyPartResult"
						}
						w.Header().Set("Content-Type", "application/xml")
						_, _ = fmt.Fprintf(w, `<%s><ETag>"copied"</ETag><LastModified>2024-01-15T10:30:00.000Z</LastModified></%s>`, root, root)
					})
					var client copySourceBackend
					if proxy {
						server := httptest.NewServer(backend)
						t.Cleanup(server.Close)
						client = newTestProxyClient(t, server.URL)
					} else {
						client = buildTestS3Client(t, &fakeS3Transport{handler: backend})
					}
					var version *string
					if tc.version != "" {
						version = &tc.version
					}
					if part {
						_, err := client.UploadPartCopy(context.Background(), "dst-bucket", "dst", "u", 1, "src-bucket", tc.key, version, &CopyPartRange{First: 2, Last: 9})
						require.NoError(t, err)
					} else {
						_, _, err := client.CopyObject(context.Background(), "dst-bucket", "dst", "src-bucket", tc.key, version, nil, nil)
						require.NoError(t, err)
					}
				})
			}
		}
	}
}
