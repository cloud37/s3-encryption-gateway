package s3

import (
	"net/url"
	"strings"
)

// copySourceHeader encodes decoded backend identities at the wire boundary.
// The SDK's CopySource field is already a header value: it does not escape it.
// Escape each component independently so a key's ?versionId= remains data and
// a literal percent sequence cannot be interpreted as a second decoding layer.
func copySourceHeader(bucket, key string, versionID *string) string {
	escape := func(value string) string {
		return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
	}
	header := escape(bucket) + "/" + escape(key)
	if versionID != nil && *versionID != "" {
		header += "?versionId=" + escape(*versionID)
	}
	return header
}
