package api

import (
	"strings"
	"testing"
)

func TestValidateBucketName_Valid(t *testing.T) {
	for _, name := range []string{"abc", "a-b.c", "bucket-123", strings.Repeat("a", 63)} {
		if err := ValidateBucketName(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestValidateBucketName_TooShort(t *testing.T) {
	if ValidateBucketName("ab") == nil {
		t.Fatal("accepted short name")
	}
}
func TestValidateBucketName_TooLong(t *testing.T) {
	if ValidateBucketName(strings.Repeat("a", 64)) == nil {
		t.Fatal("accepted long name")
	}
}
func TestValidateBucketName_UppercaseRejected(t *testing.T) {
	if ValidateBucketName("Abc") == nil {
		t.Fatal("accepted uppercase")
	}
}
func TestValidateBucketName_InvalidCharactersRejected(t *testing.T) {
	for _, name := range []string{"a_b", "a..b", "a.-b", "a-.b", "-abc", "abc-", "ab c", "abé"} {
		if ValidateBucketName(name) == nil {
			t.Errorf("accepted %q", name)
		}
	}
}
func TestValidateBucketName_IPAddressRejected(t *testing.T) {
	for _, name := range []string{"192.168.1.1", "001.002.003.004"} {
		if ValidateBucketName(name) == nil {
			t.Errorf("accepted IP %q", name)
		}
	}
}
