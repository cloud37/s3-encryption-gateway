package middleware

import "testing"

func TestRedactSensitiveQuery(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"empty", "", ""},
		{"benign duplicates", "versionId=one&versionId=two", "versionId=one&versionId=two"},
		{"sigv2", "Signature=sigv2", "Signature=%5BREDACTED%5D"},
		{"sigv4", "X-Amz-Signature=sigv4", "X-Amz-Signature=%5BREDACTED%5D"},
		{"case variant", "sIgNaTuRe=secret", "sIgNaTuRe=%5BREDACTED%5D"},
		{"encoded key", "%53ignature=secret", "Signature=%5BREDACTED%5D"},
		{"duplicates", "Signature=one&signature=two", "Signature=%5BREDACTED%5D&signature=%5BREDACTED%5D"},
		{"same key duplicates", "Signature=one&Signature=two", "Signature=%5BREDACTED%5D"},
		{"both families", "Signature=v2&X-Amz-Signature=v4&versionId=7", "Signature=%5BREDACTED%5D&X-Amz-Signature=%5BREDACTED%5D&versionId=7"},
		{"sensitive and benign", "Signature=secret&versionId=benign", "Signature=%5BREDACTED%5D&versionId=benign"},
		{"malformed", "prefix=%ZZ", "[REDACTED]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactSensitiveQuery(tt.input); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactSensitiveQuery_DoesNotMutateRawQuery(t *testing.T) {
	raw := "Signature=secret&versionId=7"
	RedactSensitiveQuery(raw)
	if raw != "Signature=secret&versionId=7" {
		t.Fatal("raw query changed")
	}
}
