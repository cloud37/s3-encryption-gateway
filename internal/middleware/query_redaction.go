package middleware

import (
	"net/url"
	"strings"
)

var sensitiveQueryParams = []string{
	"awssecretaccesskey", "awsaccesskeyid", "x-amz-security-token", "x-amz-signature",
	"x-amz-credential", "x-amz-tagging", "signature", "policy",
	"x-amz-server-side-encryption-customer-algorithm",
	"x-amz-server-side-encryption-customer-key",
	"x-amz-server-side-encryption-customer-key-md5",
}

// RedactSensitiveQuery returns a telemetry-safe encoding of rawQuery.
func RedactSensitiveQuery(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "[REDACTED]"
	}
	for key := range values {
		for _, sensitive := range sensitiveQueryParams {
			if strings.EqualFold(key, sensitive) {
				values[key] = []string{"[REDACTED]"}
				break
			}
		}
	}
	return values.Encode()
}
