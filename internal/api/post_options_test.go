package api

import (
	"bytes"
	"crypto/md5" // SSE-C protocol checksum, not authentication.
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
)

func TestGH353PostOptions_ClosedFieldMatrix(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	keyMD5Bytes := md5.Sum(key)
	validValues := map[string]string{
		"key": "${filename}", "bucket": "bucket", "file": "ignored", "policy": "cG9saWN5", "x-amz-algorithm": "AWS4-HMAC-SHA256",
		"x-amz-credential": "AKIA/20260101/us-east-1/s3/aws4_request", "x-amz-date": "20260101T000000Z", "x-amz-signature": strings.Repeat("a", 64), "x-amz-security-token": "token",
		"acl": "private", "success_action_status": "201", "success_action_redirect": "https://example.test/ok", "redirect": "https://example.test/ok", "tagging": "<Tagging><TagSet/></Tagging>",
		"x-amz-storage-class": "STANDARD_IA", "x-amz-website-redirect-location": "/redirect",
		"Content-MD5": "kAFQmDzST7DWlj99KOF/cg==", "x-amz-checksum-algorithm": "CRC32", "x-amz-checksum-crc32": "NSRBwg==",
		"x-amz-checksum-crc32c": "Nks/tw==", "x-amz-checksum-sha1": "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=", "x-amz-checksum-sha256": "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=",
		"x-amz-server-side-encryption": "AES256", "x-amz-server-side-encryption-aws-kms-key-id": "key-id", "x-amz-server-side-encryption-context": base64.StdEncoding.EncodeToString([]byte(`{"purpose":"test"}`)),
		"x-amz-server-side-encryption-bucket-key-enabled": "true", "x-amz-server-side-encryption-customer-algorithm": "AES256", "x-amz-server-side-encryption-customer-key": base64.StdEncoding.EncodeToString(key), "x-amz-server-side-encryption-customer-key-MD5": base64.StdEncoding.EncodeToString(keyMD5Bytes[:]),
		"x-amz-meta-note": "value", "x-ignore-trace": "trace",
	}
	for _, name := range objectmeta.Names {
		validValues[name] = "value"
	}
	for name, value := range validValues {
		fields := map[string]string{name: value}
		switch name {
		case "x-amz-checksum-algorithm":
			fields["x-amz-checksum-crc32"] = validValues["x-amz-checksum-crc32"]
		case "x-amz-checksum-crc32", "x-amz-checksum-crc32c", "x-amz-checksum-sha1", "x-amz-checksum-sha256":
			fields["x-amz-checksum-algorithm"] = map[string]string{"x-amz-checksum-crc32": "CRC32", "x-amz-checksum-crc32c": "CRC32C", "x-amz-checksum-sha1": "SHA1", "x-amz-checksum-sha256": "SHA256"}[name]
		case "x-amz-server-side-encryption-customer-algorithm", "x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-MD5":
			for _, customerName := range []string{"x-amz-server-side-encryption-customer-algorithm", "x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-MD5"} {
				fields[customerName] = validValues[customerName]
			}
		case "x-amz-server-side-encryption-aws-kms-key-id", "x-amz-server-side-encryption-context", "x-amz-server-side-encryption-bucket-key-enabled":
			fields["x-amz-server-side-encryption"] = "aws:kms"
			for _, kmsName := range []string{"x-amz-server-side-encryption-aws-kms-key-id", "x-amz-server-side-encryption-context", "x-amz-server-side-encryption-bucket-key-enabled"} {
				if name != kmsName {
					fields[kmsName] = validValues[kmsName]
				}
			}
		}
		if _, _, _, err := parsePostOptions(fields); err != nil {
			t.Errorf("valid accepted field %q rejected: %v", name, err)
		}
	}
	for _, name := range []string{"x-amz-server-side-encryption-aws-kms-key-id", "x-amz-server-side-encryption-context", "x-amz-server-side-encryption-bucket-key-enabled"} {
		fields := map[string]string{"x-amz-server-side-encryption": "aws:kms", name: validValues[name]}
		for _, other := range []string{"x-amz-server-side-encryption-aws-kms-key-id", "x-amz-server-side-encryption-context", "x-amz-server-side-encryption-bucket-key-enabled"} {
			if name != other {
				fields[other] = validValues[other]
			}
		}
		if _, _, _, err := parsePostOptions(fields); err != nil {
			t.Errorf("valid KMS field %q rejected: %v", name, err)
		}
	}
	for _, tc := range []struct {
		name string
		want error
	}{
		{"x-amz-checksum-crc64nvme", ErrPostUnsupported},
		{"x-amz-storage-class", ErrPostInvalidOption},
		{"x-amz-unknown", ErrPostUnsupported}, {"ETag", ErrPostUnsupported}, {"Content-Length", ErrPostUnsupported},
		{"x-amz-grant-read", ErrPostUnsupported}, {"x-amz-object-lock-mode", ErrPostUnsupported}, {"x-amz-copy-source", ErrPostUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := validValues[tc.name]
			if tc.name == "x-amz-storage-class" {
				value = "unexpected"
			}
			_, _, _, err := parsePostOptions(map[string]string{tc.name: value})
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want %v", err, tc.want)
			}
		})
	}
	if _, _, _, err := parsePostOptions(map[string]string{"x-amz-meta-original-content-length": "secret"}); !errors.Is(err, ErrPostInvalidOption) {
		t.Fatalf("reserved metadata error=%v", err)
	}
	if _, _, _, err := parsePostOptions(map[string]string{"Content-Type": "text/plain", "content-type": "text/plain"}); !errors.Is(err, ErrPostInvalidOption) {
		t.Fatalf("case alias duplicate error=%v", err)
	}
	for _, name := range []string{"x-amz-meta-", "x-ignore-"} {
		if _, _, _, err := parsePostOptions(map[string]string{name: "x"}); !errors.Is(err, ErrPostUnsupported) {
			t.Errorf("empty suffix %q error=%v", name, err)
		}
	}
	if _, _, _, err := parsePostOptions(map[string]string{"x-amz-checksum-algorithm": "CRC32", "x-amz-checksum-crc32": "NSRBwg=="}); err != nil {
		t.Fatalf("valid checksum field rejected: %v", err)
	}
	if _, _, _, err := parsePostOptions(map[string]string{"x-amz-checksum-crc64nvme": "AAAAAA=="}); !errors.Is(err, ErrPostUnsupported) {
		t.Fatalf("unsupported checksum classification=%v", err)
	}
}

func TestGH353PostTagging_StrictXMLAndUnicode(t *testing.T) {
	valid := `<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>雪 + key</Key><Value>café @</Value></Tag><Tag><Key>zero</Key><Value></Value></Tag></TagSet></Tagging>`
	got, err := parsePostTagging(valid)
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(got)
	if err != nil || values.Get("雪 + key") != "café @" || values.Get("zero") != "" {
		t.Fatalf("encoded tags=%q parsed=%v err=%v", got, values, err)
	}
	for _, tc := range []struct {
		input string
		want  error
	}{
		{`<!DOCTYPE Tagging [<!ENTITY x "y">]><Tagging><TagSet/></Tagging>`, ErrPostMalformedXML},
		{`<Tagging><TagSet><Tag><Key>a</Key><Key>b</Key><Value>v</Value></Tag></TagSet></Tagging>`, ErrPostMalformedXML},
		{`<Tagging><TagSet><Tag><Key>a</Key><Value>v</Value><Other>x</Other></Tag></TagSet></Tagging>`, ErrPostMalformedXML},
		{`<Tagging><TagSet><Tag><Key>a</Key><Value>v</Value></Tag></TagSet></Tagging>trailing`, ErrPostMalformedXML},
		{`<Tagging><TagSet><Tag><Key>aws:reserved</Key><Value>v</Value></Tag></TagSet></Tagging>`, ErrPostInvalidTag},
		{`<Tagging><TagSet><Tag><Key>bad?</Key><Value>v</Value></Tag></TagSet></Tagging>`, ErrPostInvalidTag},
		{`<Tagging><TagSet><Tag><Key>a</Key><Value>v</Value></Tag><Tag><Key>a</Key><Value>w</Value></Tag></TagSet></Tagging>`, ErrPostInvalidTag},
		{`<Tagging><TagSet><Tag><Key>a</Key><Value>v</Value></Tag></TagSet></Tagging>`, nil},
		{`<Tagging><TagSet><Tag><Key>a</Key><Value>v</Value></Tag></TagSet></Tagging>`, nil},
	} {
		if _, err := parsePostTagging(tc.input); !errors.Is(err, tc.want) {
			t.Errorf("input %q error=%v want=%v", tc.input, err, tc.want)
		}
	}
	if _, err := parsePostTagging(strings.Repeat("x", postTaggingXMLLimit+1)); !errors.Is(err, ErrPostMalformedXML) {
		t.Fatalf("oversize XML error=%v", err)
	}
	var ten strings.Builder
	ten.WriteString(`<Tagging><TagSet>`)
	for i := 0; i < 10; i++ {
		ten.WriteString(`<Tag><Key>k` + string(rune('0'+i)) + `</Key><Value>v</Value></Tag>`)
	}
	ten.WriteString(`</TagSet></Tagging>`)
	if _, err := parsePostTagging(ten.String()); err != nil {
		t.Fatalf("ten tags rejected: %v", err)
	}
	if _, err := parsePostTagging(strings.Replace(ten.String(), `</TagSet>`, `<Tag><Key>k10</Key><Value>v</Value></Tag></TagSet>`, 1)); !errors.Is(err, ErrPostInvalidTag) {
		t.Fatalf("eleven tags error=%v", err)
	}
	for _, tc := range []struct {
		name, text string
		want       error
	}{
		{"key min", "", ErrPostInvalidTag}, {"key max", strings.Repeat("雪", 128), nil}, {"key above", strings.Repeat("雪", 129), ErrPostInvalidTag},
		{"value max", strings.Repeat("語", 256), nil}, {"value above", strings.Repeat("語", 257), ErrPostInvalidTag},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := `<Tagging><TagSet><Tag><Key>` + tc.text + `</Key><Value>v</Value></Tag></TagSet></Tagging>`
			if strings.HasPrefix(tc.name, "value") {
				input = `<Tagging><TagSet><Tag><Key>k</Key><Value>` + tc.text + `</Value></Tag></TagSet></Tagging>`
			}
			_, err := parsePostTagging(input)
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
		})
	}
	invalidBoundary := `<Tagging><TagSet><Tag><Key>` + strings.Repeat("雪", 128) + `</Key><Value>` + strings.Repeat("語", 256) + `</Value></Tag></TagSet></Tagging>`
	if _, err := parsePostTagging(invalidBoundary); err != nil {
		t.Fatalf("valid codepoint boundaries rejected: %v", err)
	}
	if _, err := parsePostTagging(`<Tagging><TagSet xmlns="wrong"/></Tagging>`); !errors.Is(err, ErrPostMalformedXML) {
		t.Fatalf("wrong namespace=%v", err)
	}
	if _, err := parsePostTagging(`<Tagging x="y"><TagSet/></Tagging>`); !errors.Is(err, ErrPostMalformedXML) {
		t.Fatalf("attribute=%v", err)
	}
	if _, err := parsePostTagging(`<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><TagSet><Tag><Key>a</Key><Value>v</Value></Tag></TagSet></Tagging>`); err != nil {
		t.Fatalf("accepted default S3 namespace rejected: %v", err)
	}
	if _, err := parsePostTagging(`<s:Tagging xmlns:s="http://s3.amazonaws.com/doc/2006-03-01/"><s:TagSet><s:Tag><s:Key>a</s:Key><s:Value>v</s:Value></s:Tag></s:TagSet></s:Tagging>`); err != nil {
		t.Fatalf("accepted prefixed S3 namespace rejected: %v", err)
	}
	if _, err := parsePostTagging("<Tagging><TagSet><Tag><Key>\xff</Key><Value>x</Value></Tag></TagSet></Tagging>"); !errors.Is(err, ErrPostMalformedXML) {
		t.Fatalf("invalid UTF-8=%v", err)
	}
}

func TestGH353PostOptions_StorageACLAndWebsite(t *testing.T) {
	for _, tc := range []struct {
		storage, acl, website string
		wantStorage, wantACL  string
		wantErr               error
	}{
		{"", "", "", "", "", nil}, {"STANDARD", "private", "/x", "", "private", nil},
		{"STANDARD_IA", "aws-exec-read", "https://example.test/a", "STANDARD_IA", "aws-exec-read", nil},
		{"EXPRESS_ONEZONE", "", "", "", "", ErrPostUnsupported},
		{"unexpected", "", "", "", "", ErrPostInvalidOption},
		{"", "log-delivery-write", "", "", "", ErrPostInvalidOption},
		{"", "", "ftp://example.test", "", "", ErrPostInvalidOption},
		{"", "", "https://user@example.test", "", "", ErrPostInvalidOption},
	} {
		fields := map[string]string{}
		if tc.storage != "" {
			fields["x-amz-storage-class"] = tc.storage
		}
		if tc.acl != "" {
			fields["acl"] = tc.acl
		}
		if tc.website != "" {
			fields["x-amz-website-redirect-location"] = tc.website
		}
		options, _, acl, err := parsePostOptions(fields)
		if !errors.Is(err, tc.wantErr) || options.StorageClass != tc.wantStorage || acl != tc.wantACL {
			t.Fatalf("storage=%q acl=%q redirect=%q err=%v wantStorage=%q wantACL=%q err=%v", options.StorageClass, acl, options.WebsiteRedirectLocation, err, tc.wantStorage, tc.wantACL, tc.wantErr)
		}
		if err == nil && options.WebsiteRedirectLocation != tc.website {
			t.Fatalf("website redirect=%q want=%q", options.WebsiteRedirectLocation, tc.website)
		}
	}
	for _, value := range []string{"private", "public-read", "public-read-write", "authenticated-read", "aws-exec-read", "bucket-owner-read", "bucket-owner-full-control"} {
		_, _, acl, err := parsePostOptions(map[string]string{"acl": value})
		if err != nil || acl != value {
			t.Errorf("accepted ACL %q -> %q, %v", value, acl, err)
		}
	}
	for _, value := range []string{"STANDARD", "REDUCED_REDUNDANCY", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING", "GLACIER", "DEEP_ARCHIVE", "GLACIER_IR"} {
		options, _, _, err := parsePostOptions(map[string]string{"x-amz-storage-class": value})
		want := value
		if value == "STANDARD" {
			want = ""
		}
		if err != nil || options.StorageClass != want {
			t.Errorf("accepted storage %q -> %q, %v", value, options.StorageClass, err)
		}
	}
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{"", false}, {"/", true}, {"https://example.test/" + strings.Repeat("x", 1900), true}, {"https://example.test/" + strings.Repeat("x", 2030), false},
		{"https://user@example.test/", false}, {"https://example.test/\n", false}, {"/雪", true},
	} {
		_, _, _, err := parsePostOptions(map[string]string{"x-amz-website-redirect-location": tc.value})
		if (err == nil) != tc.valid {
			t.Errorf("website len=%d valid=%v error=%v", len(tc.value), tc.valid, err)
		}
	}
	prefix := "https://example.test/"
	for _, tc := range []struct {
		value string
		valid bool
	}{
		{prefix + strings.Repeat("x", 2048-len(prefix)), true},
		{prefix + strings.Repeat("x", 2049-len(prefix)), false},
	} {
		_, _, _, err := parsePostOptions(map[string]string{"x-amz-website-redirect-location": tc.value})
		if (err == nil) != tc.valid {
			t.Errorf("website boundary len=%d valid=%v err=%v", len(tc.value), tc.valid, err)
		}
	}
	if _, _, _, err := parsePostOptions(map[string]string{}); err != nil {
		t.Fatalf("absent optional fields: %v", err)
	}
	if _, _, _, err := parsePostOptions(map[string]string{"x-amz-website-redirect-location": ""}); !errors.Is(err, ErrPostInvalidOption) {
		t.Fatalf("explicit empty website=%v", err)
	}
}

func TestGH353PostOptions_SSEAndNoKeyPersistence(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	keyMD5Bytes := md5.Sum(key)
	keyMD5 := base64.StdEncoding.EncodeToString(keyMD5Bytes[:])
	encodedKey := base64.StdEncoding.EncodeToString(key)
	options, tags, acl, err := parsePostOptions(map[string]string{
		"x-amz-server-side-encryption-customer-algorithm": "AES256",
		"x-amz-server-side-encryption-customer-key":       encodedKey,
		"x-amz-server-side-encryption-customer-key-MD5":   keyMD5,
	})
	if err != nil || options.SSE == nil || options.SSE.Customer == nil || string(options.SSE.Customer.Key) != string(key) || tags != "" || acl != "" {
		t.Fatalf("valid SSE-C parse failed (details redacted), err=%v", err)
	}
	keyBacking := options.SSE.Customer.Key
	options.SSE.Customer.Close()
	if !bytesAreZero(keyBacking) {
		t.Fatal("SSE-C raw key backing array was not zeroized on Close")
	}
	options, _, _, err = parsePostOptions(map[string]string{"x-amz-server-side-encryption": "aws:kms"})
	if err != nil || options.SSE == nil || options.SSE.Algorithm != "aws:kms" {
		t.Fatalf("SSE-KMS parse failed err=%v", err)
	}
	for _, fields := range []map[string]string{
		{"x-amz-server-side-encryption": ""}, {"x-amz-server-side-encryption": "AES256", "x-amz-server-side-encryption-aws-kms-key-id": "key"},
		{"x-amz-server-side-encryption": "aws:kms", "x-amz-server-side-encryption-aws-kms-key-id": ""},
		{"x-amz-server-side-encryption-customer-algorithm": "AES256"},
		{"x-amz-server-side-encryption-customer-algorithm": "AES256", "x-amz-server-side-encryption-customer-key": encodedKey, "x-amz-server-side-encryption-customer-key-MD5": "AAAA"},
	} {
		_, _, _, err := parsePostOptions(fields)
		if !errors.Is(err, ErrPostInvalidOption) {
			t.Errorf("invalid SSE mix result=%v", err)
		}
	}
}

func bytesAreZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func FuzzPostTagging(f *testing.F) {
	for _, seed := range []string{
		`<Tagging><TagSet/></Tagging>`,
		`<Tagging><TagSet><Tag><Key>a</Key><Value>b</Value></Tag></TagSet></Tagging>`,
		`<Tagging><TagSet><Tag><Key>aws:system</Key><Value>x</Value></Tag></TagSet></Tagging>`,
		`<!DOCTYPE x><Tagging/>`, "\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > postTaggingXMLLimit+1 {
			t.Skip()
		}
		encoded, err := parsePostTagging(input)
		if err == nil {
			parsed, parseErr := url.ParseQuery(encoded)
			if parseErr != nil || len(parsed) > 10 {
				t.Fatalf("accepted invalid normalized tags %q: %v", encoded, parseErr)
			}
			for key, entries := range parsed {
				if strings.HasPrefix(key, "aws:") || !validPostTagKey(key) || len(entries) != 1 || !validPostTagValue(entries[0]) || !utf8.ValidString(key) || !utf8.ValidString(entries[0]) {
					t.Fatalf("accepted invalid normalized tag %q=%q", key, entries)
				}
			}
			var normalizedXML bytes.Buffer
			normalizedXML.WriteString(`<Tagging><TagSet>`)
			for key, entries := range parsed {
				for _, value := range entries {
					normalizedXML.WriteString(`<Tag><Key>`)
					_ = xml.EscapeText(&normalizedXML, []byte(key))
					normalizedXML.WriteString(`</Key><Value>`)
					_ = xml.EscapeText(&normalizedXML, []byte(value))
					normalizedXML.WriteString(`</Value></Tag>`)
				}
			}
			normalizedXML.WriteString(`</TagSet></Tagging>`)
			if roundTrip, roundErr := parsePostTagging(normalizedXML.String()); roundErr != nil || roundTrip != encoded {
				t.Fatalf("normalized roundtrip=%q err=%v want=%q", roundTrip, roundErr, encoded)
			}
		}
	})
}
