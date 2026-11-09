package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const gh353AWSPolicy = "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9"

func policyEncoded(t *testing.T, object string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString([]byte(object))
}

func signPostPolicy(secret, date, region, encoded string) string {
	key := deriveSignatureKey(secret, date, region, "s3")
	defer clearAuthBytes(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	return hex.EncodeToString(mac.Sum(nil))
}

func validPostPolicyFixture(t *testing.T, expiration string, nowDate string) (*postUpload, Credential, time.Time) {
	t.Helper()
	const secret = "test-secret"
	date := nowDate
	jsonPolicy := fmt.Sprintf(`{"expiration":%q,"conditions":[{"bucket":"b","key":"k","x-amz-algorithm":"AWS4-HMAC-SHA256","x-amz-credential":"ak/%s/us-east-1/s3/aws4_request","x-amz-date":"%s"}]}`, expiration, date[:8], date)
	encoded := policyEncoded(t, jsonPolicy)
	fields := map[string]string{
		"policy": encoded, "bucket": "b", "key": "k", "x-amz-algorithm": "AWS4-HMAC-SHA256",
		"x-amz-credential": "ak/" + date[:8] + "/us-east-1/s3/aws4_request", "x-amz-date": date,
	}
	fields["x-amz-signature"] = signPostPolicy(secret, date[:8], "us-east-1", encoded)
	u := &postUpload{fields: fields, bucket: "b", key: "k"}
	credential := Credential{AccessKey: "ak", SecretKey: secret}
	signedAt, err := time.Parse("20060102T150405Z", date)
	if err != nil {
		t.Fatal(err)
	}
	return u, credential, signedAt
}

func TestGH353PostPolicy_AWSSignatureVector(t *testing.T) {
	policy, err := parsePostPolicy(gh353AWSPolicy)
	if err != nil {
		t.Fatal(err)
	}
	if got := signPostPolicy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "20151229", "us-east-1", policy.encoded); got != "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e" {
		t.Fatalf("signature = %s", got)
	}
	fields := map[string]string{
		"policy": gh353AWSPolicy, "bucket": "sigv4examplebucket", "key": "user/user1/test.jpg", "acl": "public-read",
		"success_action_redirect": "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html", "Content-Type": "image/jpeg",
		"x-amz-meta-uuid": "14365123651274", "x-amz-server-side-encryption": "AES256", "x-amz-meta-tag": "",
		"x-amz-credential": "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request", "x-amz-algorithm": "AWS4-HMAC-SHA256",
		"x-amz-date": "20151229T000000Z", "x-amz-signature": "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e",
	}
	upload := &postUpload{fields: fields, bucket: fields["bucket"], key: fields["key"]}
	credential := Credential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	frozen := time.Date(2015, 12, 29, 0, 0, 0, 0, time.UTC)
	if err := validatePostPolicyAt(upload, credential, time.Minute, frozen); err != nil {
		t.Fatalf("complete AWS policy validation: %v", err)
	}
	if want := time.Date(2015, 12, 30, 12, 0, 0, 0, time.UTC); !upload.deadline.Equal(want) {
		t.Fatalf("exclusive policy deadline = %s want %s", upload.deadline, want)
	}
	decoded, err := base64.StdEncoding.DecodeString(policy.encoded)
	if err != nil {
		t.Fatal(err)
	}
	decoded = append(decoded, []byte("\r\n ")...)
	mutatedEncoded := base64.StdEncoding.EncodeToString(decoded)
	if _, err := parsePostPolicy(mutatedEncoded); err != nil {
		t.Fatalf("mutated whitespace policy should parse: %v", err)
	}
	mutatedPolicy, err := parsePostPolicy(mutatedEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(mutatedPolicy.conditions) == 0 {
		t.Fatal("mutated policy lost conditions")
	}
	fields["policy"] = mutatedEncoded
	if err := validatePostPolicyAt(upload, credential, time.Minute, frozen); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("mutated policy old signature = %v", err)
	}
}

func TestGH353PostPolicy_StrictJSONAndScope(t *testing.T) {
	valid := `{"expiration":"2030-01-02T03:04:05Z","conditions":[{"bucket":"b","key":"k"},["starts-with","$x-amz-meta-note",""]]}`
	policy, err := parsePostPolicy(policyEncoded(t, valid))
	if err != nil || len(policy.conditions) != 3 {
		t.Fatalf("multi-field exact policy: %+v, %v", policy, err)
	}
	bad := []string{
		`{"expiration":"2030-01-02T03:04:05Z","expiration":"2030-01-02T03:04:05Z","conditions":[]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[{"bucket":"b","Bucket":"b"}]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[],"extra":1}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[["starts-with","$acl",""]]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[["content-length-range",-1,2]]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[["content-length-range",1.0,2]]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[]} {}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[{"bucket":"b","bucket":"b"}]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[["starts-with","$x-amz-website-redirect-location","/"]]}`,
	}
	for i, document := range bad {
		if _, err := parsePostPolicy(policyEncoded(t, document)); !errors.Is(err, ErrPostPolicyMalformed) {
			t.Errorf("case %d err = %v", i, err)
		}
	}
	for _, document := range []string{
		`{"expiration":"2030-01-02T03:04:05Z","conditions":null}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[null]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[true]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[{"bucket":null}]}`,
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[["eq","$key",null]]}`,
		"{\"expiration\":\"2030-01-02T03:04:05Z\",\"conditions\":[],\"nested\":{\"x\":1,\"x\":2}}",
		`{"expiration":"2030-01-02T03:04:05Z","conditions":[["eq","$key","\ud800"]]}`,
	} {
		if _, err := parsePostPolicy(policyEncoded(t, document)); !errors.Is(err, ErrPostPolicyMalformed) {
			t.Errorf("strict JSON document %q err=%v", document, err)
		}
	}
	invalidUTF8 := []byte(`{"expiration":"2030-01-02T03:04:05Z","conditions":[]}`)
	invalidUTF8 = append(invalidUTF8, 0xff)
	if _, err := parsePostPolicy(base64.StdEncoding.EncodeToString(invalidUTF8)); !errors.Is(err, ErrPostPolicyMalformed) {
		t.Errorf("invalid UTF-8 policy err=%v", err)
	}
	for _, encoded := range []string{"", "eyJ4IjoxfQ", "eyJ4IjoxfQ===", "eyJ4IjoxfR==", base64.RawStdEncoding.EncodeToString([]byte(`{"expiration":"2030-01-02T03:04:05Z","conditions":[]}`))} {
		if _, err := parsePostPolicy(encoded); !errors.Is(err, ErrPostPolicyMalformed) {
			t.Errorf("noncanonical base64 %q err=%v", encoded, err)
		}
	}
	for _, count := range []int{256, 257} {
		conditions := strings.Repeat(`{"bucket":"b"},`, count)
		conditions = strings.TrimSuffix(conditions, ",")
		document := `{"expiration":"2030-01-02T03:04:05Z","conditions":[` + conditions + `]}`
		_, err := parsePostPolicy(policyEncoded(t, document))
		if count == 256 && err != nil {
			t.Errorf("exactly 256 conditions rejected: %v", err)
		}
		if count == 257 && !errors.Is(err, ErrPostPolicyMalformed) {
			t.Errorf("257 conditions err=%v", err)
		}
	}
	if _, err := parsePostPolicy(policyEncoded(t, `{"expiration":"2030-01-02T03:04:05Z","conditions":[{"key":"k"},["content-length-range",0,10]]}`)); err != nil {
		t.Fatalf("policy range should be accepted: %v", err)
	}
	if _, err := parsePostPolicy("eyJ4IjoxfQ"); !errors.Is(err, ErrPostPolicyMalformed) {
		t.Fatalf("unpadded base64 err = %v", err)
	}
	for _, scope := range []string{"ak/20300102/us-east-1/s3/aws4_request/x", "ak/20300102//s3/aws4_request", "ak/20300102/us-east-1/ec2/aws4_request", "ak/20300102/us-east-1/s3/nope", "ak/20300102/us-east-1/s3/aws4_request/", "ak/20300103/us-east-1/s3/aws4_request"} {
		upload, credential, now := validPostPolicyFixture(t, "2030-01-02T04:00:00Z", "20300102T030000Z")
		upload.fields["x-amz-credential"] = scope
		if len(strings.Split(scope, "/")) == 5 {
			upload.fields["x-amz-signature"] = signPostPolicy(credential.SecretKey, "20300102", "us-east-1", upload.fields["policy"])
		}
		if err := validatePostPolicyAt(upload, credential, time.Minute, now); !errors.Is(err, ErrSignatureMismatch) {
			t.Errorf("scope %q err = %v", scope, err)
		}
	}
	for _, algorithm := range []string{"AWS4-HMAC-SHA1", "AWS4-HMAC-SHA256 "} {
		u, credential, now := validPostPolicyFixture(t, "2030-01-02T04:00:00Z", "20300102T030000Z")
		u.fields["x-amz-algorithm"] = algorithm
		if err := validatePostPolicyAt(u, credential, time.Minute, now); !errors.Is(err, ErrSignatureMismatch) {
			t.Errorf("algorithm %q: %v", algorithm, err)
		}
	}
}

func TestGH353PostPolicy_AllConditionsAndFieldCoverage(t *testing.T) {
	policy := postPolicy{conditions: []postCondition{
		{op: "eq", field: "bucket", value: "b"}, {op: "eq", field: "x-amz-algorithm", value: "AWS4-HMAC-SHA256"},
		{op: "eq", field: "x-amz-credential", value: "ak/20300102/r/s3/aws4_request"}, {op: "eq", field: "x-amz-date", value: "20300102T000000Z"},
		{op: "starts-with", field: "key", value: "prefix"}, {op: "starts-with", field: "x-amz-meta-name", value: ""},
		{op: "content-length-range", min: 12, max: 500}, {op: "content-length-range", min: 20, max: 300},
	}}
	fields := map[string]string{"bucket": "b", "key": "prefix/../literal%2F", "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": "ak/20300102/r/s3/aws4_request", "x-amz-date": "20300102T000000Z", "x-amz-meta-name": "n"}
	min, max, err := matchPostConditions(policy, fields, "b")
	if err != nil || min != 20 || max != 300 {
		t.Fatalf("intersection = %d..%d, err=%v", min, max, err)
	}
	fields["acl"] = "private"
	if _, _, err := matchPostConditions(policy, fields, "b"); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("uncovered field err = %v", err)
	}
	delete(fields, "acl")
	fields["bucket"] = "other"
	if _, _, err := matchPostConditions(policy, fields, "b"); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("bucket mismatch = %v", err)
	}
	fields["bucket"] = "b"
	policy.conditions = append(policy.conditions, postCondition{op: "starts-with", field: "key", value: "different"})
	if _, _, err := matchPostConditions(policy, fields, "b"); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("incompatible key conditions err = %v", err)
	}
}

func TestGH353PostPolicy_ExactAndPrefixKeyConditionsAreANDed(t *testing.T) {
	policy := postPolicy{conditions: []postCondition{
		{op: "eq", field: "bucket", value: "b"}, {op: "eq", field: "key", value: "prefix/key"},
		{op: "starts-with", field: "key", value: "prefix/"}, {op: "eq", field: "x-amz-algorithm", value: "a"},
		{op: "eq", field: "x-amz-credential", value: "c"}, {op: "eq", field: "x-amz-date", value: "d"},
	}}
	fields := map[string]string{"bucket": "b", "key": "prefix/key", "x-amz-algorithm": "a", "x-amz-credential": "c", "x-amz-date": "d"}
	if _, _, err := matchPostConditions(policy, fields, "b"); err != nil {
		t.Fatalf("compatible exact+prefix conditions: %v", err)
	}
	fields["key"] = "prefix/other"
	if _, _, err := matchPostConditions(policy, fields, "b"); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("conflicting exact+prefix conditions: %v", err)
	}
}

func TestGH353PostPolicy_RequiredAuthConditionsAndFields(t *testing.T) {
	required := []string{"bucket", "key", "x-amz-algorithm", "x-amz-credential", "x-amz-date"}
	conditions := []postCondition{{op: "eq", field: "bucket", value: "b"}, {op: "eq", field: "key", value: "k"}, {op: "eq", field: "x-amz-algorithm", value: "a"}, {op: "eq", field: "x-amz-credential", value: "c"}, {op: "eq", field: "x-amz-date", value: "d"}}
	fields := map[string]string{"bucket": "b", "key": "k", "x-amz-algorithm": "a", "x-amz-credential": "c", "x-amz-date": "d"}
	for _, missing := range required {
		withoutCondition := make([]postCondition, 0, len(conditions)-1)
		for _, condition := range conditions {
			if condition.field != missing {
				withoutCondition = append(withoutCondition, condition)
			}
		}
		if _, _, err := matchPostConditions(postPolicy{conditions: withoutCondition}, fields, "b"); !errors.Is(err, ErrPostPolicyDenied) {
			t.Errorf("missing mandatory condition %s err=%v", missing, err)
		}
		withoutField := make(map[string]string, len(fields)-1)
		for name, value := range fields {
			if name != missing {
				withoutField[name] = value
			}
		}
		if missing == "bucket" {
			if _, _, err := matchPostConditions(postPolicy{conditions: conditions}, withoutField, "b"); err != nil {
				t.Errorf("omitted optional bucket should bind destination: %v", err)
			}
		} else if _, _, err := matchPostConditions(postPolicy{conditions: conditions}, withoutField, "b"); !errors.Is(err, ErrPostPolicyDenied) {
			t.Errorf("missing mandatory field %s err=%v", missing, err)
		}
	}
}

func TestGH353PostPolicy_ContentTypeCommaSemantics(t *testing.T) {
	base := []postCondition{{op: "eq", field: "bucket", value: "b"}, {op: "eq", field: "key", value: "k"}, {op: "eq", field: "x-amz-algorithm", value: "a"}, {op: "eq", field: "x-amz-credential", value: "c"}, {op: "eq", field: "x-amz-date", value: "d"}}
	fields := map[string]string{"bucket": "b", "key": "k", "x-amz-algorithm": "a", "x-amz-credential": "c", "x-amz-date": "d", "Content-Type": "image/png,text/plain"}
	policy := postPolicy{conditions: append(append([]postCondition(nil), base...), postCondition{op: "starts-with", field: "content-type", value: "image/"})}
	if _, _, err := matchPostConditions(policy, fields, "b"); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("comma list should check every type, err=%v", err)
	}
	fields["Content-Type"] = "image/png,image/jpeg"
	if _, _, err := matchPostConditions(policy, fields, "b"); err != nil {
		t.Fatalf("valid comma list err=%v", err)
	}
	policy.conditions[len(policy.conditions)-1].field = "x-amz-meta-note"
	delete(fields, "Content-Type")
	fields["x-amz-meta-note"] = "prefix,literal"
	policy.conditions[len(policy.conditions)-1].value = "prefix,"
	if _, _, err := matchPostConditions(policy, fields, "b"); err != nil {
		t.Fatalf("non-content-type comma must be literal: %v", err)
	}
}

func TestGH353PostPolicy_ExpirationAndFutureSkew(t *testing.T) {
	const encoded = `{"expiration":"2030-01-02T03:04:05Z","conditions":[{"bucket":"b","key":"k","x-amz-algorithm":"AWS4-HMAC-SHA256","x-amz-credential":"ak/20300102/us-east-1/s3/aws4_request","x-amz-date":"20300102T030000Z"}]}`
	fields := map[string]string{"policy": policyEncoded(t, encoded), "bucket": "b", "key": "k", "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-credential": "ak/20300102/us-east-1/s3/aws4_request", "x-amz-date": "20300102T030000Z"}
	fields["x-amz-signature"] = signPostPolicy("secret", "20300102", "us-east-1", fields["policy"])
	upload := &postUpload{fields: fields, bucket: "b", key: "k"}
	credential := Credential{AccessKey: "ak", SecretKey: "secret"}
	now := time.Date(2030, 1, 2, 3, 0, 0, 0, time.UTC)
	if err := validatePostPolicyAt(upload, credential, time.Minute, now); err != nil {
		t.Fatalf("valid signing instant err=%v", err)
	}
	fields["x-amz-date"] = "20300102T030200Z"
	fields["x-amz-credential"] = "ak/20300102/us-east-1/s3/aws4_request"
	fields["x-amz-signature"] = signPostPolicy("secret", "20300102", "us-east-1", fields["policy"])
	if err := validatePostPolicyAt(upload, credential, time.Minute, now); !errors.Is(err, ErrRequestTimeTooSkewed) {
		t.Fatalf("future skew err=%v", err)
	}
	fields["x-amz-date"] = "20300102T030000Z"
	fields["x-amz-signature"] = signPostPolicy("secret", "20300102", "us-east-1", fields["policy"])
	if err := validatePostPolicyAt(upload, credential, time.Minute, time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("exclusive policy deadline err=%v", err)
	}
	credential.SessionToken, credential.ExpiresAt = "token", ptrTime(time.Date(2030, 1, 2, 3, 1, 0, 0, time.UTC))
	fields["x-amz-security-token"] = "token"
	if err := validatePostPolicyAt(upload, credential, time.Minute, now); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("uncovered session token err=%v", err)
	}
}

func TestGH353PostPolicy_OriginalAWSPolicyAndLiteralBinding(t *testing.T) {
	const date = "20151229T000000Z"
	encoded := gh353AWSPolicy
	fields := map[string]string{
		"policy": encoded, "bucket": "sigv4examplebucket", "key": "user/user1/photo.jpg", "acl": "public-read",
		"success_action_redirect": "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html", "Content-Type": "image/jpeg",
		"x-amz-meta-uuid": "14365123651274", "x-amz-server-side-encryption": "AES256", "x-amz-meta-tag": "",
		"x-amz-credential": "AKIAIOSFODNN7EXAMPLE/20151229/us-east-1/s3/aws4_request", "x-amz-algorithm": "AWS4-HMAC-SHA256", "x-amz-date": date,
	}
	u := &postUpload{fields: fields, bucket: fields["bucket"], key: fields["key"]}
	cred := Credential{AccessKey: "AKIAIOSFODNN7EXAMPLE", SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	now := time.Date(2015, 12, 29, 0, 0, 0, 0, time.UTC)
	fields["x-amz-signature"] = "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"
	if err := validatePostPolicyAt(u, cred, time.Minute, now); err != nil {
		t.Fatalf("AWS policy vector rejected: %v", err)
	}
	if err := validatePostPolicyAt(u, cred, time.Minute, now); err != nil {
		t.Fatalf("cached original policy validation: %v", err)
	}
	if !u.deadline.Equal(time.Date(2015, 12, 30, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("deadline = %s", u.deadline)
	}
	for name, value := range map[string]string{"bucket": "sigv4examplebucket", "key": "user/user1/photo.jpg", "acl": "public-read", "success_action_redirect": "http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html", "Content-Type": "image/jpeg", "x-amz-meta-uuid": "14365123651274", "x-amz-server-side-encryption": "AES256", "x-amz-meta-tag": ""} {
		fields[name] = value
	}
	if err := validatePostPolicyAt(u, cred, time.Minute, now); err != nil {
		t.Fatalf("complete AWS signed policy validation: %v", err)
	}
	mutated, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	mutated = append(mutated, []byte("\r\n ")...)
	fields["policy"] = base64.StdEncoding.EncodeToString(mutated)
	if err := validatePostPolicyAt(u, cred, time.Minute, now); !errors.Is(err, ErrSignatureMismatch) {
		t.Fatalf("mutated policy with old signature = %v", err)
	}
}

func TestGH353PostPolicy_SignatureScopeTimeAndCoverage(t *testing.T) {
	base, cred, now := validPostPolicyFixture(t, "2030-01-02T04:00:00Z", "20300102T030000Z")
	if err := validatePostPolicyAt(base, cred, time.Minute, now); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	if err := validatePostPolicyAt(base, cred, time.Minute, now.Add(10*time.Minute)); err != nil {
		t.Fatalf("signature older than ordinary auth window: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*postUpload)
		at     time.Time
		want   error
	}{
		{"future", func(u *postUpload) {
			u.fields["x-amz-date"] = "20300102T030200Z"
			u.fields["x-amz-credential"] = "ak/20300102/us-east-1/s3/aws4_request"
			u.fields["x-amz-signature"] = signPostPolicy(cred.SecretKey, "20300102", "us-east-1", u.fields["policy"])
		}, now, ErrRequestTimeTooSkewed},
		{"bad service", func(u *postUpload) { u.fields["x-amz-credential"] = "ak/20300102/us-east-1/ec2/aws4_request" }, now, ErrSignatureMismatch},
		{"bad algorithm", func(u *postUpload) { u.fields["x-amz-algorithm"] = "AWS4-HMAC-SHA1" }, now, ErrSignatureMismatch},
		{"exact expiry", func(u *postUpload) {}, time.Date(2030, 1, 2, 4, 0, 0, 0, time.UTC), ErrRequestExpired},
		{"missing required auth field", func(u *postUpload) { delete(u.fields, "x-amz-date") }, now, ErrMissingCredentials},
		{"missing empty-prefix metadata", func(u *postUpload) {
			policyText := `{"expiration":"2030-01-02T04:00:00Z","conditions":[{"bucket":"b"},{"key":"k"},{"x-amz-algorithm":"AWS4-HMAC-SHA256"},{"x-amz-credential":"ak/20300102/us-east-1/s3/aws4_request"},{"x-amz-date":"20300102T030000Z"},["starts-with","$x-amz-meta-note",""]]}`
			u.fields["policy"] = policyEncoded(t, policyText)
			u.fields["x-amz-signature"] = signPostPolicy(cred.SecretKey, "20300102", "us-east-1", u.fields["policy"])
			u.policy = postPolicy{}
		}, now, ErrPostPolicyDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &postUpload{
				bucket: base.bucket,
				key:    base.key,
				fields: make(map[string]string, len(base.fields)),
				policy: base.policy,
			}
			for k, v := range base.fields {
				u.fields[k] = v
			}
			tc.mutate(u)
			if err := validatePostPolicyAt(u, cred, time.Minute, tc.at); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	for _, deadline := range []time.Time{now.Add(time.Hour), now.Add(30 * time.Minute), now} {
		u, credential, at := validPostPolicyFixture(t, "2030-01-02T04:00:00Z", "20300102T030000Z")
		credential.SessionToken, credential.ExpiresAt = "token", &deadline
		policyText := `{"expiration":"2030-01-02T04:00:00Z","conditions":[{"bucket":"b","key":"k","x-amz-algorithm":"AWS4-HMAC-SHA256","x-amz-credential":"ak/20300102/us-east-1/s3/aws4_request","x-amz-date":"20300102T030000Z","x-amz-security-token":"token"}]}`
		u.fields["x-amz-security-token"] = "token"
		u.fields["policy"] = policyEncoded(t, policyText)
		u.fields["x-amz-signature"] = signPostPolicy(credential.SecretKey, "20300102", "us-east-1", u.fields["policy"])
		wantDeadline := deadline
		if deadline.Before(time.Date(2030, 1, 2, 4, 0, 0, 0, time.UTC)) {
			wantDeadline = deadline
		} else {
			wantDeadline = time.Date(2030, 1, 2, 4, 0, 0, 0, time.UTC)
		}
		if deadline.Equal(at) || !deadline.After(at) {
			if err := validatePostPolicyAt(u, credential, time.Minute, at); !errors.Is(err, ErrExpiredToken) {
				t.Fatalf("expired session deadline %s err=%v", deadline, err)
			}
			continue
		}
		if err := validatePostPolicyAt(u, credential, time.Minute, at); err != nil {
			t.Fatalf("live session deadline: %v", err)
		}
		if !u.deadline.Equal(wantDeadline) {
			t.Fatalf("deadline = %s want min=%s", u.deadline, wantDeadline)
		}
	}
	boundary, boundaryCred, boundaryNow := validPostPolicyFixture(t, "2030-01-02T04:00:00Z", "20300102T030000Z")
	if err := validatePostPolicyAt(boundary, boundaryCred, time.Minute, boundaryNow); err != nil {
		t.Fatalf("future skew exact boundary: %v", err)
	}
	futureBoundary, futureCred, futureBase := validPostPolicyFixture(t, "2030-01-02T04:00:00Z", "20300102T030200Z")
	futureBoundary.fields["x-amz-signature"] = signPostPolicy(futureCred.SecretKey, "20300102", "us-east-1", futureBoundary.fields["policy"])
	if err := validatePostPolicyAt(futureBoundary, futureCred, time.Minute, futureBase.Add(-time.Minute)); err != nil {
		t.Fatalf("future skew exact boundary: %v", err)
	}
	if err := validatePostPolicyAt(futureBoundary, futureCred, time.Minute, futureBase.Add(-time.Minute-time.Nanosecond)); !errors.Is(err, ErrRequestTimeTooSkewed) {
		t.Fatalf("future skew beyond boundary: %v", err)
	}
	expiry, expiryCred, _ := validPostPolicyFixture(t, "2030-01-02T03:00:00.000000001Z", "20300102T020000Z")
	if err := validatePostPolicyAt(expiry, expiryCred, time.Minute, time.Date(2030, 1, 2, 3, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("nanosecond before expiry: %v", err)
	}
	if err := validatePostPolicyAt(expiry, expiryCred, time.Minute, time.Date(2030, 1, 2, 3, 0, 0, 1, time.UTC)); !errors.Is(err, ErrRequestExpired) {
		t.Fatalf("nanosecond expiry boundary: %v", err)
	}
}

func TestGH353PostPolicy_SessionTokenBindingAndStaticToken(t *testing.T) {
	for _, tc := range []struct {
		name              string
		session, supplied string
		present           bool
		want              error
	}{
		{"static omitted", "", "", false, nil},
		{"static explicit empty", "", "", true, ErrInvalidToken},
		{"static unexpected", "", "other", true, ErrInvalidToken},
		{"session missing", "token", "", false, ErrInvalidToken},
		{"session wrong", "token", "other", true, ErrInvalidToken},
		{"session valid", "token", "token", true, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, cred, now := validPostPolicyFixture(t, "2030-01-02T04:00:00Z", "20300102T030000Z")
			if tc.session != "" {
				deadline := now.Add(time.Hour)
				cred.SessionToken, cred.ExpiresAt = tc.session, &deadline
			}
			if tc.present {
				u.fields["x-amz-security-token"] = tc.supplied
			}
			if tc.present && tc.session != "" {
				policyText := fmt.Sprintf(`{"expiration":"2030-01-02T04:00:00Z","conditions":[{"bucket":"b","key":"k","x-amz-algorithm":"AWS4-HMAC-SHA256","x-amz-credential":"ak/20300102/us-east-1/s3/aws4_request","x-amz-date":"20300102T030000Z","x-amz-security-token":%q}]}`, tc.supplied)
				u.fields["policy"] = policyEncoded(t, policyText)
				u.policy = postPolicy{}
				u.fields["x-amz-signature"] = signPostPolicy(cred.SecretKey, "20300102", "us-east-1", u.fields["policy"])
			}
			err := validatePostPolicyAt(u, cred, time.Minute, now)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestGH353PostPolicy_WebsiteRedirectConditionTypes(t *testing.T) {
	for _, tc := range []struct {
		op      string
		allowed bool
	}{{"eq", true}, {"starts-with", false}} {
		_, err := parsePostPolicy(policyEncoded(t, fmt.Sprintf(`{"expiration":"2030-01-02T03:04:05Z","conditions":[[ %q, "$x-amz-website-redirect-location", "/x"]]}`, tc.op)))
		if (err == nil) != tc.allowed {
			t.Errorf("op %s: err=%v", tc.op, err)
		}
	}
	if validPostFormField("content-length-range") {
		t.Fatal("policy operator accepted as form field")
	}
	fields := map[string]string{"bucket": "b", "key": "k", "x-amz-algorithm": "a", "x-amz-credential": "c", "x-amz-date": "d", "x-amz-website-redirect-location": "/target"}
	policy, err := parsePostPolicy(policyEncoded(t, `{"expiration":"2030-01-02T03:04:05Z","conditions":[{"bucket":"b"},{"key":"k"},{"x-amz-algorithm":"a"},{"x-amz-credential":"c"},{"x-amz-date":"d"},{"x-amz-website-redirect-location":"/target"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := matchPostConditions(policy, fields, "b"); err != nil {
		t.Fatalf("exact website redirect condition: %v", err)
	}
	fields["content-length-range"] = "1,10"
	if _, _, err := matchPostConditions(policy, fields, "b"); !errors.Is(err, ErrPostUnsupported) {
		t.Fatalf("submitted operator field: %v", err)
	}
	rangePolicy, err := parsePostPolicy(policyEncoded(t, `{"expiration":"2030-01-02T03:04:05Z","conditions":[{"bucket":"b"},{"key":"k"},{"x-amz-algorithm":"a"},{"x-amz-credential":"c"},{"x-amz-date":"d"},{"x-amz-website-redirect-location":"/target"},["content-length-range",0,10]]}`))
	if err != nil {
		t.Fatal(err)
	}
	delete(fields, "content-length-range")
	if _, _, err := matchPostConditions(rangePolicy, fields, "b"); err != nil {
		t.Fatalf("valid policy range rejected: %v", err)
	}
	fields["content-length-range"] = "1,10"
	if _, _, err := matchPostConditions(rangePolicy, fields, "b"); !errors.Is(err, ErrPostUnsupported) {
		t.Fatalf("submitted operator covered by policy: %v", err)
	}
}

func TestGH353PostPolicy_BindDestinationAndBoundaries(t *testing.T) {
	upload := &postUpload{fields: map[string]string{"key": "literal/../%2F", "bucket": "target"}, key: "literal/../%2F"}
	if err := upload.bindDestination("target"); err != nil || upload.key != "literal/../%2F" {
		t.Fatalf("destination binding: upload=%+v err=%v", upload, err)
	}
	if err := upload.bindDestination("other"); !errors.Is(err, ErrPostPolicyDenied) {
		t.Fatalf("wrong destination err=%v", err)
	}
	tooDeep := `{"expiration":"2030-01-02T03:04:05Z","conditions":[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}`
	if _, err := parsePostPolicy(policyEncoded(t, tooDeep)); !errors.Is(err, ErrPostPolicyMalformed) {
		t.Fatalf("deep JSON err=%v", err)
	}
	for _, value := range []string{"00", "-0", "+1", "1.0", "1e2", "9223372036854775808"} {
		if _, err := parsePostInteger(value); !errors.Is(err, ErrPostPolicyMalformed) {
			t.Errorf("integer %q err=%v", value, err)
		}
	}
}

func TestGH353PostPolicy_RequiredBucketUsesDestination(t *testing.T) {
	policy := postPolicy{conditions: []postCondition{{op: "eq", field: "bucket", value: "b"}, {op: "eq", field: "key", value: "k"}, {op: "eq", field: "x-amz-algorithm", value: "a"}, {op: "eq", field: "x-amz-credential", value: "c"}, {op: "eq", field: "x-amz-date", value: "d"}}}
	fields := map[string]string{"key": "k", "x-amz-algorithm": "a", "x-amz-credential": "c", "x-amz-date": "d"}
	if _, _, err := matchPostConditions(policy, fields, "b"); err != nil {
		t.Fatalf("omitted bucket field should bind route bucket: %v", err)
	}
	fields["x-ignore-test"] = "ignored"
	if _, _, err := matchPostConditions(policy, fields, "b"); err != nil {
		t.Fatalf("ignore field should not require coverage: %v", err)
	}
}

func TestClassifyPostError_FixedMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
	}{{ErrPostPolicyDenied, "AccessDenied", 403}, {ErrPostPolicyMalformed, "InvalidArgument", 400}, {ErrPostFormMalformed, "InvalidRequest", 400}, {ErrPostUnsupported, "NotImplemented", 501}, {ErrPostEntityTooLarge, "EntityTooLarge", 413}, {ErrPostIncompleteBody, "IncompleteBody", 400}, {ErrPostBadDigest, "BadDigest", 400}, {ErrExpiredToken, "ExpiredToken", 403}, {ErrInvalidToken, "InvalidToken", 403}, {ErrRequestExpired, "AccessDenied", 403}, {ErrRequestTimeTooSkewed, "RequestTimeTooSkewed", 403}, {ErrInvalidPresignedExpiry, "InvalidArgument", 400}} {
		got := classifyPostError(fmt.Errorf("%w: secret", tc.err), "/b/k")
		if got.Code != tc.code || got.HTTPStatus != tc.status || got.Resource != "/b/k" {
			t.Errorf("%v => %+v", tc.err, got)
		}
		if got.Message == "secret" || got.Message == tc.err.Error() {
			t.Errorf("error leaked in message %q", got.Message)
		}
	}
	if got := classifyPostError(nil, ""); got.Code != "InternalError" || got.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("nil mapping = %+v", got)
	}
}

func ptrTime(value time.Time) *time.Time { return &value }

func FuzzPostPolicy(f *testing.F) {
	f.Add(gh353AWSPolicy)
	f.Add(base64.StdEncoding.EncodeToString([]byte(`{"expiration":"2030-01-02T03:04:05Z","conditions":[]}`)))
	f.Add("eyJ4IjoxfQ==")
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > 100*1024 {
			t.Skip()
		}
		policy, err := parsePostPolicy(encoded)
		if err == nil {
			if len(policy.encoded) == 0 || len(policy.encoded) != len(encoded) || len(policy.conditions) > 256 || policy.expiration.IsZero() {
				t.Fatalf("accepted policy violates canonical bounds: %+v", policy)
			}
			for _, condition := range policy.conditions {
				switch condition.op {
				case "eq", "starts-with":
					if condition.field == "" || condition.field == "content-length-range" {
						t.Fatalf("accepted invalid condition: %+v", condition)
					}
				case "content-length-range":
					if condition.min < 0 || condition.max < condition.min {
						t.Fatalf("accepted invalid range: %+v", condition)
					}
				default:
					t.Fatalf("accepted unknown operation: %+v", condition)
				}
			}
		}
	})
}
