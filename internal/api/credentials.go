package api

import (
	"fmt"
	"net/http"
	"strings"
)

// ClientCredentials holds credentials extracted from a client request.
type ClientCredentials struct {
	AccessKey string
	// SecretKey is NOT extracted from client requests. The gateway resolves
	// the secret via CredentialStore.Lookup() using the access key.
}

// ExtractCredentials extracts the AWS access key identifier from an HTTP request.
// It tries multiple methods in order:
// 1. Query parameters (X-Amz-Credential) - Signature V4 presigned URL
// 2. Query parameters (AWSAccessKeyId) - SigV2 query-param style (access key only)
// 3. Authorization header (Signature V4 or legacy SigV2)
// 4. Returns error if no credentials found
//
// The secret key is never extracted from the request; it is resolved by the
// caller via CredentialStore.Lookup() using the access key. This prevents
// credential exposure through URL query parameters (CWE-598).
func ExtractCredentials(r *http.Request) (*ClientCredentials, error) {
	accessKey := ""

	// Method 1: Presigned URL (Signature V4)
	// Format: X-Amz-Credential=ACCESS_KEY/YYYYMMDD/REGION/SERVICE/aws4_request
	if credential := r.URL.Query().Get("X-Amz-Credential"); credential != "" {
		parts := strings.Split(credential, "/")
		if len(parts) > 0 && parts[0] != "" {
			accessKey = parts[0]
		}
	}

	// Method 2: SigV2 query-param style
	// Format: ?AWSAccessKeyId=...&Signature=...&Expires=...
	// Only the access key identifier is extracted; the secret key is NOT read
	// from query parameters (would expose it to proxy logs, CDNs, browser history).
	if accessKey == "" {
		if ak := r.URL.Query().Get("AWSAccessKeyId"); ak != "" {
			accessKey = ak
		}
	}

	// Method 3: Authorization header
	// Format: AWS4-HMAC-SHA256 Credential=ACCESS_KEY/YYYYMMDD/REGION/s3/aws4_request, ...
	// or: AWS ACCESS_KEY:SIGNATURE (legacy SigV2)
	if accessKey == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256") || strings.HasPrefix(authHeader, "AWS ") {
				credentialStart := strings.Index(authHeader, "Credential=")
				if credentialStart != -1 {
					credentialPart := authHeader[credentialStart+11:]
					endIdx := strings.IndexAny(credentialPart, ", ")
					if endIdx == -1 {
						endIdx = len(credentialPart)
					}
					credential := credentialPart[:endIdx]
					parts := strings.Split(credential, "/")
					if len(parts) > 0 && parts[0] != "" {
						accessKey = parts[0]
					}
				} else {
					// Legacy AWS signature format: "AWS ACCESS_KEY:SIGNATURE"
					parts := strings.Fields(authHeader)
					if len(parts) >= 2 && strings.HasPrefix(parts[0], "AWS") {
						credParts := strings.Split(parts[1], ":")
						if len(credParts) > 0 {
							accessKey = credParts[0]
						}
					}
				}
			}
		}
	}

	if accessKey == "" {
		return nil, fmt.Errorf("no credentials found in request")
	}

	return &ClientCredentials{
		AccessKey: accessKey,
	}, nil
}

// HasCredentials checks if the request contains credentials.
func HasCredentials(r *http.Request) bool {
	if r.URL.Query().Get("X-Amz-Credential") != "" {
		return true
	}
	if r.URL.Query().Get("AWSAccessKeyId") != "" {
		return true
	}
	if r.Header.Get("Authorization") != "" {
		return true
	}
	return false
}

// IsSignatureV4Request reports whether the request carries a SigV4
// Authorization header ("AWS4-HMAC-SHA256 ...") or SigV4 query parameters
// (X-Amz-Algorithm=AWS4-HMAC-SHA256).
func IsSignatureV4Request(r *http.Request) bool {
	if r.URL.Query().Get("X-Amz-Algorithm") == "AWS4-HMAC-SHA256" {
		return true
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false
	}
	return strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256")
}

// IsSignatureV2Request reports whether the request carries a SigV2
// Authorization header ("AWS ACCESS_KEY:SIG") or V2 query parameters
// (AWSAccessKeyId + Signature).
func IsSignatureV2Request(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "AWS ") {
		return true
	}
	q := r.URL.Query()
	return q.Get("AWSAccessKeyId") != "" && q.Get("Signature") != ""
}
