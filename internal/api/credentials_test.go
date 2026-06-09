package api

import (
	"net/http"
	"net/url"
	"testing"
)

func TestExtractCredentials_PresignedURL(t *testing.T) {
	tests := []struct {
		name          string
		queryParams   map[string]string
		wantAccessKey string
		wantErr       bool
	}{
		{
			name:          "valid presigned URL",
			queryParams:   map[string]string{"X-Amz-Credential": "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"},
			wantAccessKey: "AKIAIOSFODNN7EXAMPLE",
			wantErr:       false,
		},
		{
			name:        "empty query parameters",
			queryParams: map[string]string{},
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{
					RawQuery: buildQueryString(tt.queryParams),
				},
			}

			creds, err := ExtractCredentials(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if creds == nil {
					t.Fatal("ExtractCredentials() returned nil credentials without error")
				}
				if creds.AccessKey != tt.wantAccessKey {
					t.Errorf("ExtractCredentials() AccessKey = %v, want %v", creds.AccessKey, tt.wantAccessKey)
				}
			}
		})
	}
}

func TestExtractCredentials_AuthorizationHeader(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		wantAccessKey string
		wantErr       bool
	}{
		{
			name:          "AWS Signature V4",
			authHeader:    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=...",
			wantAccessKey: "AKIAIOSFODNN7EXAMPLE",
			wantErr:       false,
		},
		{
			name:          "Legacy AWS signature",
			authHeader:    "AWS AKIAIOSFODNN7EXAMPLE:signature",
			wantAccessKey: "AKIAIOSFODNN7EXAMPLE",
			wantErr:       false,
		},
		{
			name:       "invalid authorization header",
			authHeader: "Bearer token",
			wantErr:    true,
		},
		{
			name:       "empty authorization header",
			authHeader: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL:    &url.URL{},
				Header: make(http.Header),
			}
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			creds, err := ExtractCredentials(req)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if creds == nil {
					t.Fatal("ExtractCredentials() returned nil credentials without error")
				}
				if creds.AccessKey != tt.wantAccessKey {
					t.Errorf("ExtractCredentials() AccessKey = %v, want %v", creds.AccessKey, tt.wantAccessKey)
				}
			}
		})
	}
}

func TestHasCredentials(t *testing.T) {
	tests := []struct {
		name string
		req  *http.Request
		want bool
	}{
		{
			name: "has AWSAccessKeyId query param",
			req: &http.Request{
				URL: &url.URL{
					RawQuery: "AWSAccessKeyId=AKIA",
				},
			},
			want: true,
		},
		{
			name: "has presigned URL",
			req: &http.Request{
				URL: &url.URL{
					RawQuery: "X-Amz-Credential=AKIA/20130524/us-east-1/s3/aws4_request",
				},
			},
			want: true,
		},
		{
			name: "has authorization header",
			req: &http.Request{
				URL: &url.URL{},
				Header: http.Header{
					"Authorization": []string{"AWS4-HMAC-SHA256 Credential=AKIA/.../..."},
				},
			},
			want: true,
		},
		{
			name: "no credentials",
			req: &http.Request{
				URL:    &url.URL{},
				Header: make(http.Header),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := HasCredentials(tt.req)
			if got != tt.want {
				t.Errorf("HasCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func buildQueryString(params map[string]string) string {
	var parts []string
	for k, v := range params {
		parts = append(parts, k+"="+v)
	}
	return buildRawQuery(parts)
}

func buildRawQuery(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += "&" + parts[i]
	}
	return result
}
