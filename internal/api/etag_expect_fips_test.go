//go:build fips

package api

import (
	"crypto/sha256"
	"encoding/hex"
)

func expectedOriginalETagForBuild(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
