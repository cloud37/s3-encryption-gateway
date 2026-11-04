package api

import (
	"crypto/md5"  // S3 Content-MD5 interoperability, not authentication.
	"crypto/sha1" // S3 checksum interoperability, not authentication.
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"hash/crc32"
	"strings"
)

type postChecksum struct {
	algorithm, value, md5 string
}

type postValidatedFile struct {
	body              verifiedAWSBody
	length            int64
	md5Hex            string
	responseChecksums map[string]string
}

type postChecksumSet struct {
	md5        hash.Hash
	checksum   hash.Hash
	algorithm  string
	encoded    string
	encodedMD5 string
}

func parsePostChecksum(fields map[string]string) (postChecksum, error) {
	if fields == nil {
		return postChecksum{}, nil
	}
	seen := make(map[string]struct{}, len(fields))
	for name := range fields {
		canonical := asciiPostFold(name)
		if canonical == "content-md5" || canonical == "x-amz-checksum-algorithm" || strings.HasPrefix(canonical, "x-amz-checksum-") {
			if _, duplicate := seen[canonical]; duplicate {
				return postChecksum{}, ErrPostChecksumInvalidRequest
			}
			seen[canonical] = struct{}{}
		}
	}
	contentMD5, md5Present := postFieldValue(fields, "content-md5")
	selected, algorithmPresent := postFieldValue(fields, "x-amz-checksum-algorithm")
	var selectedName, selectedValue string
	count := 0
	for name, value := range fields {
		folded := asciiPostFold(name)
		if folded == "x-amz-checksum-crc64nvme" {
			return postChecksum{}, ErrPostUnsupported
		}
		if strings.HasPrefix(folded, "x-amz-checksum-") && folded != "x-amz-checksum-algorithm" && postDigestSize(folded) == 0 {
			return postChecksum{}, ErrPostUnsupported
		}
		switch folded {
		case "x-amz-checksum-crc32", "x-amz-checksum-crc32c", "x-amz-checksum-sha1", "x-amz-checksum-sha256":
			count++
			selectedName, selectedValue = folded, value
			if !canonicalDigest(value, postDigestSize(folded)) {
				return postChecksum{}, ErrPostInvalidOption
			}
		}
	}
	if md5Present && !canonicalDigest(contentMD5, md5.Size) {
		return postChecksum{}, ErrPostInvalidOption
	}
	if count > 1 {
		return postChecksum{}, ErrPostChecksumInvalidRequest
	}
	if count == 0 {
		if algorithmPresent {
			if selected == "" {
				return postChecksum{}, ErrPostChecksumInvalidRequest
			}
			if unsupportedPostChecksum(selected) {
				return postChecksum{}, ErrPostUnsupported
			}
			return postChecksum{}, ErrPostChecksumInvalidRequest
		}
		return postChecksum{md5: contentMD5}, nil
	}
	algorithm := postAlgorithmForField(selectedName)
	if algorithmPresent {
		if selected == "" {
			return postChecksum{}, ErrPostChecksumInvalidRequest
		}
		if selected != algorithm {
			if unsupportedPostChecksum(selected) {
				return postChecksum{}, ErrPostUnsupported
			}
			return postChecksum{}, ErrPostChecksumInvalidRequest
		}
	}
	return postChecksum{algorithm: algorithm, value: selectedValue, md5: contentMD5}, nil
}

func postFieldValue(fields map[string]string, name string) (string, bool) {
	var value string
	count := 0
	for key, candidate := range fields {
		if asciiPostFold(key) == name {
			count++
			value = candidate
		}
	}
	return value, count == 1
}

func postDigestSize(name string) int {
	switch name {
	case "x-amz-checksum-crc32", "x-amz-checksum-crc32c":
		return 4
	case "x-amz-checksum-sha1":
		return sha1.Size
	case "x-amz-checksum-sha256":
		return sha256.Size
	default:
		return 0
	}
}

func postAlgorithmForField(name string) string {
	switch name {
	case "x-amz-checksum-crc32":
		return "CRC32"
	case "x-amz-checksum-crc32c":
		return "CRC32C"
	case "x-amz-checksum-sha1":
		return "SHA1"
	case "x-amz-checksum-sha256":
		return "SHA256"
	default:
		return ""
	}
}

func unsupportedPostChecksum(value string) bool {
	switch value {
	case "CRC32", "CRC32C", "SHA1", "SHA256":
		return false
	default:
		return true
	}
}

func canonicalDigest(value string, size int) bool {
	if value == "" || size == 0 {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size || base64.StdEncoding.EncodeToString(decoded) != value {
		clear(decoded)
		return false
	}
	clear(decoded)
	return true
}

func (c postChecksum) newSet() (*postChecksumSet, error) {
	set := &postChecksumSet{md5: md5.New(), algorithm: c.algorithm, encoded: c.value, encodedMD5: c.md5}
	if c.md5 != "" && !canonicalDigest(c.md5, md5.Size) {
		return nil, ErrPostInvalidOption
	}
	if c.value != "" {
		if !canonicalDigest(c.value, postDigestSize(postChecksumField(c.algorithm))) {
			return nil, ErrPostInvalidOption
		}
		switch c.algorithm {
		case "CRC32":
			set.checksum = crc32.NewIEEE()
		case "CRC32C":
			set.checksum = crc32.New(crc32.MakeTable(crc32.Castagnoli))
		case "SHA1":
			set.checksum = sha1.New()
		case "SHA256":
			set.checksum = sha256.New()
		default:
			return nil, ErrPostUnsupported
		}
	}
	return set, nil
}

func postChecksumField(algorithm string) string {
	switch algorithm {
	case "CRC32":
		return "x-amz-checksum-crc32"
	case "CRC32C":
		return "x-amz-checksum-crc32c"
	case "SHA1":
		return "x-amz-checksum-sha1"
	case "SHA256":
		return "x-amz-checksum-sha256"
	default:
		return ""
	}
}

func (c *postChecksumSet) Write(p []byte) (int, error) {
	if c == nil || c.md5 == nil {
		return 0, errors.New("invalid POST checksum state")
	}
	n, err := c.md5.Write(p)
	if err == nil && c.checksum != nil {
		_, err = c.checksum.Write(p)
	}
	return n, err
}

func (c *postChecksumSet) validate() (string, map[string]string, error) {
	if c == nil || c.md5 == nil {
		return "", nil, ErrPostFormMalformed
	}
	md5sum := c.md5.Sum(nil)
	if c.encodedMD5 != "" {
		want, _ := base64.StdEncoding.Strict().DecodeString(c.encodedMD5)
		match := subtle.ConstantTimeCompare(md5sum, want) == 1
		clear(want)
		if !match {
			return "", nil, ErrPostBadDigest
		}
	}
	response := make(map[string]string)
	if c.checksum != nil {
		want, _ := base64.StdEncoding.Strict().DecodeString(c.encoded)
		got := c.checksum.Sum(nil)
		match := subtle.ConstantTimeCompare(got, want) == 1
		clear(want)
		if !match {
			clear(got)
			return "", nil, ErrPostBadDigest
		}
		response["x-amz-checksum-"+strings.ToLower(c.algorithm)] = base64.StdEncoding.EncodeToString(got)
		clear(got)
	}
	return hex.EncodeToString(md5sum), response, nil
}
