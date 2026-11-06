//go:build !fips

package api

import (
	"crypto/md5"
	"encoding/hex"
)

func expectedOriginalETagForBuild(data []byte) string {
	digest := md5.Sum(data)
	return hex.EncodeToString(digest[:])
}
