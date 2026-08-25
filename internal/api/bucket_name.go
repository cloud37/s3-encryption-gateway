package api

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

// ValidateBucketName validates the provider-neutral S3 bucket naming subset.
func ValidateBucketName(name string) error {
	if len(name) < 3 || len(name) > 63 {
		return fmt.Errorf("bucket name must be between 3 and 63 characters")
	}
	if net.ParseIP(name) != nil {
		return fmt.Errorf("bucket name must not be an IP address")
	}
	parts := strings.Split(name, ".")
	if len(parts) == 4 {
		allNumeric := true
		for _, part := range parts {
			if part == "" {
				allNumeric = false
				break
			}
			for _, c := range part {
				if c < '0' || c > '9' {
					allNumeric = false
					break
				}
			}
		}
		if allNumeric {
			return fmt.Errorf("bucket name must not be an IP address")
		}
	}
	isAlphaNum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }
	if !isAlphaNum(name[0]) || !isAlphaNum(name[len(name)-1]) {
		return fmt.Errorf("bucket name must begin and end with a lowercase letter or digit")
	}
	for i, r := range name {
		if r > unicode.MaxASCII || !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return fmt.Errorf("bucket name contains invalid characters")
		}
		if i > 0 && name[i-1] == '.' && r == '.' {
			return fmt.Errorf("bucket name must not contain adjacent dots")
		}
		if i > 0 && ((name[i-1] == '.' && r == '-') || (name[i-1] == '-' && r == '.')) {
			return fmt.Errorf("bucket name must not contain dot-hyphen sequences")
		}
	}
	return nil
}
