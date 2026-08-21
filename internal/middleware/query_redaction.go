package middleware

import (
	"net/url"
	"strings"
)

var sensitiveQueryParams = []string{
	"awssecretaccesskey", "x-amz-security-token", "x-amz-signature",
	"x-amz-tagging", "signature",
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
