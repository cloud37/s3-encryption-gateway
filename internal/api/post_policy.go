package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
)

const maxPostPolicyBytes = 64 * 1024

var postCredentialDate = regexp.MustCompile(`^[0-9]{8}$`)
var postTimestamp = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z$`)

type postCondition struct {
	op, field, value string
	min, max         int64
}

type postPolicy struct {
	expiration time.Time
	conditions []postCondition
	encoded    string
}

// parsePostPolicy validates the canonical padded base64 and strict JSON policy.
// The literal encoded value is retained for SigV4; it is never reserialized.
func parsePostPolicy(encoded string) (postPolicy, error) {
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(maxPostPolicyBytes) {
		return postPolicy{}, ErrPostPolicyMalformed
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded || len(raw) > maxPostPolicyBytes || !utf8.Valid(raw) || !validJSONSurrogates(raw) {
		clearAuthBytes(raw)
		return postPolicy{}, ErrPostPolicyMalformed
	}
	defer clearAuthBytes(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := decodePostJSONValue(dec, 0)
	if err != nil {
		return postPolicy{}, ErrPostPolicyMalformed
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return postPolicy{}, ErrPostPolicyMalformed
	}
	root, ok := value.(map[string]any)
	if !ok || len(root) != 2 {
		return postPolicy{}, ErrPostPolicyMalformed
	}
	for key := range root {
		if key != "expiration" && key != "conditions" {
			return postPolicy{}, ErrPostPolicyMalformed
		}
	}
	expirationText, ok := root["expiration"].(string)
	if !ok || !strings.HasSuffix(expirationText, "Z") {
		return postPolicy{}, ErrPostPolicyMalformed
	}
	expiration, err := time.Parse(time.RFC3339Nano, expirationText)
	if err != nil || expiration.Location() != time.UTC || !strings.HasSuffix(expirationText, "Z") {
		return postPolicy{}, ErrPostPolicyMalformed
	}
	conditionValues, ok := root["conditions"].([]any)
	if !ok || len(conditionValues) > 256 {
		return postPolicy{}, ErrPostPolicyMalformed
	}
	policy := postPolicy{expiration: expiration, conditions: make([]postCondition, 0, len(conditionValues)), encoded: encoded}
	for _, value := range conditionValues {
		conditions, err := parsePostCondition(value)
		if err != nil {
			return postPolicy{}, err
		}
		if len(policy.conditions)+len(conditions) > 256 {
			return postPolicy{}, ErrPostPolicyMalformed
		}
		policy.conditions = append(policy.conditions, conditions...)
	}
	return policy, nil
}

func decodePostJSONValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, ErrPostPolicyMalformed
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := make(map[string]any)
			for dec.More() {
				keyToken, keyErr := dec.Token()
				if keyErr != nil {
					return nil, keyErr
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, ErrPostPolicyMalformed
				}
				if _, exists := object[key]; exists {
					return nil, ErrPostPolicyMalformed
				}
				value, valueErr := decodePostJSONValue(dec, depth+1)
				if valueErr != nil {
					return nil, valueErr
				}
				object[key] = value
			}
			end, endErr := dec.Token()
			if endErr != nil || end != json.Delim('}') {
				return nil, ErrPostPolicyMalformed
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for dec.More() {
				value, valueErr := decodePostJSONValue(dec, depth+1)
				if valueErr != nil {
					return nil, valueErr
				}
				array = append(array, value)
			}
			end, endErr := dec.Token()
			if endErr != nil || end != json.Delim(']') {
				return nil, ErrPostPolicyMalformed
			}
			return array, nil
		default:
			return nil, ErrPostPolicyMalformed
		}
	case string, json.Number, bool, nil:
		return token, nil
	default:
		return nil, ErrPostPolicyMalformed
	}
}

func parsePostCondition(value any) ([]postCondition, error) {
	switch condition := value.(type) {
	case map[string]any:
		if len(condition) == 0 {
			return nil, ErrPostPolicyMalformed
		}
		var result []postCondition
		seen := make(map[string]struct{}, len(condition))
		for name, raw := range condition {
			field, ok := canonicalPostField(name)
			text, stringOK := raw.(string)
			if !ok || !stringOK {
				return nil, ErrPostPolicyMalformed
			}
			if field == "file" || field == "policy" || field == "x-amz-signature" || strings.HasPrefix(field, "x-ignore-") {
				return nil, ErrPostPolicyMalformed
			}
			if !postConditionTypeAllowed("eq", field) {
				return nil, ErrPostPolicyMalformed
			}
			if _, exists := seen[field]; exists {
				return nil, ErrPostPolicyMalformed
			}
			seen[field] = struct{}{}
			result = append(result, postCondition{op: "eq", field: field, value: text})
		}
		return result, nil
	case []any:
		if len(condition) == 0 {
			return nil, ErrPostPolicyMalformed
		}
		op, ok := condition[0].(string)
		if !ok {
			return nil, ErrPostPolicyMalformed
		}
		switch op {
		case "eq", "starts-with":
			if len(condition) != 3 {
				return nil, ErrPostPolicyMalformed
			}
			fieldExpr, fieldOK := condition[1].(string)
			value, valueOK := condition[2].(string)
			if !fieldOK || !valueOK || !strings.HasPrefix(fieldExpr, "$") || len(fieldExpr) == 1 {
				return nil, ErrPostPolicyMalformed
			}
			field, ok := canonicalPostField(fieldExpr[1:])
			if !ok || field == "file" || field == "policy" || field == "x-amz-signature" || strings.HasPrefix(field, "x-ignore-") || !postConditionTypeAllowed(op, field) {
				return nil, ErrPostPolicyMalformed
			}
			return []postCondition{{op: op, field: field, value: value}}, nil
		case "content-length-range":
			if len(condition) != 3 {
				return nil, ErrPostPolicyMalformed
			}
			min, minOK := condition[1].(json.Number)
			max, maxOK := condition[2].(json.Number)
			if !minOK || !maxOK {
				return nil, ErrPostPolicyMalformed
			}
			minInt, errMin := parsePostInteger(string(min))
			maxInt, errMax := parsePostInteger(string(max))
			if errMin != nil || errMax != nil || minInt > maxInt {
				return nil, ErrPostPolicyMalformed
			}
			return []postCondition{{op: op, field: "content-length-range", min: minInt, max: maxInt}}, nil
		default:
			return nil, ErrPostPolicyMalformed
		}
	default:
		return nil, ErrPostPolicyMalformed
	}
}

func parsePostInteger(value string) (int64, error) {
	if value == "" {
		return 0, ErrPostPolicyMalformed
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, ErrPostPolicyMalformed
		}
	}
	if len(value) > 1 && value[0] == '0' {
		return 0, ErrPostPolicyMalformed
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, ErrPostPolicyMalformed
	}
	return parsed, nil
}

func asciiPostFold(value string) string {
	bytes := []byte(value)
	for i, b := range bytes {
		if b >= 'A' && b <= 'Z' {
			bytes[i] = b + ('a' - 'A')
		}
	}
	return string(bytes)
}

func canonicalPostField(value string) (string, bool) {
	folded := asciiPostFold(value)
	if folded == "file" || folded == "policy" || folded == "x-amz-signature" {
		return folded, true
	}
	known := map[string]struct{}{
		"bucket": {}, "key": {}, "x-amz-algorithm": {}, "x-amz-credential": {}, "x-amz-date": {}, "x-amz-security-token": {},
		"acl": {}, "success_action_status": {}, "success_action_redirect": {}, "redirect": {}, "tagging": {}, "x-amz-storage-class": {},
		"x-amz-website-redirect-location": {}, "content-md5": {}, "x-amz-checksum-algorithm": {}, "x-amz-checksum-crc32": {},
		"x-amz-checksum-crc32c": {}, "x-amz-checksum-sha1": {}, "x-amz-checksum-sha256": {}, "x-amz-checksum-crc64nvme": {},
		"x-amz-server-side-encryption": {}, "x-amz-server-side-encryption-aws-kms-key-id": {}, "x-amz-server-side-encryption-context": {},
		"x-amz-server-side-encryption-bucket-key-enabled": {}, "x-amz-server-side-encryption-customer-algorithm": {},
		"x-amz-server-side-encryption-customer-key": {}, "x-amz-server-side-encryption-customer-key-md5": {},
	}
	for _, name := range objectmeta.Names {
		known[asciiPostFold(name)] = struct{}{}
	}
	if _, ok := known[folded]; ok {
		return folded, true
	}
	if strings.HasPrefix(folded, "x-amz-meta-") && len(folded) > len("x-amz-meta-") {
		return folded, true
	}
	if strings.HasPrefix(folded, "x-ignore-") && len(folded) > len("x-ignore-") {
		return folded, true
	}
	return "", false
}

func postConditionTypeAllowed(op, field string) bool {
	if op == "content-length-range" {
		return field == "content-length-range"
	}
	if field == "content-length-range" {
		return false
	}
	if op == "eq" {
		return field != "content-length-range"
	}
	if op != "starts-with" {
		return false
	}
	if field == "x-amz-website-redirect-location" {
		return false
	}
	switch field {
	case "key", "success_action_redirect", "redirect", "content-type", "cache-control", "content-disposition", "content-encoding", "content-language", "expires":
		return true
	default:
		return strings.HasPrefix(field, "x-amz-meta-")
	}
}

func postFormField(fields map[string]string, name, bucket string) (string, bool) {
	if name == "bucket" {
		for field, value := range fields {
			if asciiPostFold(field) == "bucket" {
				return value, true
			}
		}
		return bucket, bucket != ""
	}
	for field, value := range fields {
		if asciiPostFold(field) == name {
			return value, true
		}
	}
	return "", false
}

func postConditionCovered(policy postPolicy, field string) bool {
	for _, condition := range policy.conditions {
		if condition.field == field && (condition.op == "eq" || condition.op == "starts-with") {
			return true
		}
	}
	return false
}

func validPostFormField(value string) bool {
	folded := asciiPostFold(value)
	if folded == "file" || folded == "policy" || folded == "x-amz-signature" {
		return true
	}
	_, ok := canonicalPostField(value)
	return ok
}

func matchPostConditions(policy postPolicy, fields map[string]string, bucket string) (int64, int64, error) {
	minimum, maximum := int64(0), int64(math.MaxInt64)
	if submittedBucket, present := postFormField(fields, "bucket", ""); present && submittedBucket != bucket {
		return 0, 0, ErrPostPolicyDenied
	}
	covered := make(map[string]bool)
	for _, condition := range policy.conditions {
		if condition.op == "content-length-range" {
			if condition.min > minimum {
				minimum = condition.min
			}
			if condition.max < maximum {
				maximum = condition.max
			}
			if minimum > maximum {
				return 0, 0, ErrPostPolicyDenied
			}
			continue
		}
		actual, present := postFormField(fields, condition.field, bucket)
		if !present {
			return 0, 0, ErrPostPolicyDenied
		}
		covered[condition.field] = true
		switch condition.op {
		case "eq":
			if actual != condition.value {
				return 0, 0, ErrPostPolicyDenied
			}
		case "starts-with":
			values := []string{actual}
			if condition.field == "content-type" {
				values = strings.Split(actual, ",")
			}
			for _, value := range values {
				if !strings.HasPrefix(value, condition.value) {
					return 0, 0, ErrPostPolicyDenied
				}
			}
		default:
			return 0, 0, ErrPostPolicyMalformed
		}
	}
	for _, required := range []string{"bucket", "key", "x-amz-algorithm", "x-amz-credential", "x-amz-date"} {
		if !covered[required] {
			return 0, 0, ErrPostPolicyDenied
		}
	}
	if _, hasToken := postFormField(fields, "x-amz-security-token", ""); hasToken && !covered["x-amz-security-token"] {
		return 0, 0, ErrPostPolicyDenied
	}
	if !covered["bucket"] {
		return 0, 0, ErrPostPolicyDenied
	}
	for name := range fields {
		field, known := canonicalPostField(name)
		if !known || !validPostFormField(name) {
			return 0, 0, ErrPostUnsupported
		}
		if field == "policy" || field == "file" || field == "x-amz-signature" || strings.HasPrefix(field, "x-ignore-") {
			continue
		}
		if field == "content-length-range" {
			return 0, 0, ErrPostUnsupported
		}
		if !covered[field] {
			return 0, 0, ErrPostPolicyDenied
		}
	}
	return minimum, maximum, nil
}

func validatePostPolicyAt(upload *postUpload, credential Credential, skew time.Duration, now time.Time) error {
	if upload == nil || upload.fields == nil {
		return ErrPostPolicyDenied
	}
	fields := upload.fields
	fieldKey, hasKey := postFormField(fields, "key", "")
	if upload.bucket == "" || upload.key == "" || !hasKey || fieldKey != upload.key {
		return ErrPostPolicyDenied
	}
	if err := (crypto.ObjectContext{Bucket: upload.bucket, Key: upload.key}).Validate(); err != nil {
		return ErrPostPolicyDenied
	}
	if submitted, present := postFormField(fields, "bucket", ""); present && submitted != upload.bucket {
		return ErrPostPolicyDenied
	}
	for _, required := range []string{"policy", "x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-signature", "key"} {
		if _, ok := postFormField(fields, required, ""); !ok {
			return ErrMissingCredentials
		}
	}
	lookup := make(map[string]string, len(fields))
	for name, value := range fields {
		if asciiPostFold(name) == "content-length-range" {
			return ErrPostUnsupported
		}
		canonical, ok := canonicalPostField(name)
		if !ok {
			return ErrPostUnsupported
		}
		if canonical == "file" || strings.HasPrefix(canonical, "x-ignore-") {
			continue
		}
		if value != "" && strings.Contains(value, "${filename}") && (canonical == "x-amz-algorithm" || canonical == "x-amz-credential" || canonical == "x-amz-date" || canonical == "x-amz-security-token") {
			return ErrPostFormMalformed
		}
		if _, exists := lookup[canonical]; exists {
			return ErrPostFormMalformed
		}
		lookup[canonical] = value
	}
	if strings.Contains(fields["key"], "${filename}") {
		return ErrPostFormMalformed
	}
	policy := upload.policy
	if policy.encoded == "" {
		var err error
		policy, err = parsePostPolicy(lookup["policy"])
		if err != nil {
			return err
		}
	}
	if policy.encoded != lookup["policy"] {
		return ErrSignatureMismatch
	}
	upload.policy = policy
	for _, field := range []string{"bucket", "key", "x-amz-algorithm", "x-amz-credential", "x-amz-date"} {
		if !postConditionCovered(policy, field) {
			return ErrPostPolicyDenied
		}
	}
	algorithm, credentialScope := lookup["x-amz-algorithm"], lookup["x-amz-credential"]
	date, signature := lookup["x-amz-date"], lookup["x-amz-signature"]
	if algorithm != "AWS4-HMAC-SHA256" || !postTimestamp.MatchString(date) || len(signature) != sha256.Size*2 {
		return ErrSignatureMismatch
	}
	parts := strings.Split(credentialScope, "/")
	if len(parts) != 5 || parts[0] == "" || parts[1] == "" || parts[2] == "" || parts[3] != "s3" || parts[4] != "aws4_request" || !postCredentialDate.MatchString(parts[1]) || parts[1] != date[:8] || parts[0] != credential.AccessKey {
		return ErrSignatureMismatch
	}
	if _, err := time.Parse("20060102", parts[1]); err != nil {
		return ErrSignatureMismatch
	}
	if strings.ContainsAny(credentialScope, "\r\n\x00") || strings.ContainsAny(parts[2], "\r\n\x00") {
		return ErrSignatureMismatch
	}
	signedAt, err := time.Parse("20060102T150405Z", date)
	if err != nil {
		return ErrSignatureMismatch
	}
	if skew <= 0 {
		skew = defaultClockSkew
	}
	if signedAt.After(now) && signedAt.Sub(now) > skew {
		return ErrRequestTimeTooSkewed
	}
	if !now.Before(policy.expiration) {
		return ErrRequestExpired
	}
	if credential.ExpiresAt != nil && !now.Before(*credential.ExpiresAt) {
		return ErrExpiredToken
	}
	token := lookup["x-amz-security-token"]
	_, tokenPresent := lookup["x-amz-security-token"]
	if credential.SessionToken == "" && tokenPresent {
		return ErrInvalidToken
	}
	if err := validateSessionCredentialAt(credential, token, now); err != nil {
		return err
	}
	if tokenPresent && !postConditionCovered(policy, "x-amz-security-token") {
		return ErrPostPolicyDenied
	}
	provided, err := hex.DecodeString(signature)
	if err != nil || len(provided) != sha256.Size || len(signature) != sha256.Size*2 {
		clearAuthBytes(provided)
		return ErrSignatureMismatch
	}
	defer clearAuthBytes(provided)
	key := deriveSignatureKey(credential.SecretKey, parts[1], parts[2], parts[3])
	defer clearAuthBytes(key)
	mac := hmac.New(sha256.New, key)
	policyBytes := []byte(policy.encoded)
	_, _ = mac.Write(policyBytes)
	clearAuthBytes(policyBytes)
	want := mac.Sum(nil)
	defer clearAuthBytes(want)
	if !hmac.Equal(want, provided) {
		return ErrSignatureMismatch
	}
	minimum, maximum, err := matchPostConditions(policy, lookup, upload.bucket)
	if err != nil {
		return err
	}
	if minimum < 0 || maximum < minimum {
		return ErrPostPolicyMalformed
	}
	upload.minimumFileSize, upload.maximumFileSize = minimum, maximum
	if err := (crypto.ObjectContext{Bucket: upload.bucket, Key: upload.key}).Validate(); err != nil {
		return ErrPostPolicyDenied
	}
	deadline := policy.expiration
	if credential.ExpiresAt != nil && credential.ExpiresAt.Before(deadline) {
		deadline = *credential.ExpiresAt
	}
	upload.deadline = deadline
	return nil
}

func expandPostFilename(fields map[string]string, rawFilename string) (map[string]string, string, error) {
	if !utf8.ValidString(rawFilename) || strings.ContainsAny(rawFilename, "\x00\r\n") {
		return nil, "", ErrPostFormMalformed
	}
	filename := rawFilename
	if index := strings.LastIndexAny(filename, "/\\"); index >= 0 {
		filename = filename[index+1:]
	}
	expanded := make(map[string]string, len(fields))
	for name, value := range fields {
		canonical, known := canonicalPostField(name)
		if !known {
			return nil, "", ErrPostUnsupported
		}
		if canonical == "policy" || canonical == "x-amz-signature" {
			expanded[name] = value
			continue
		}
		if strings.Contains(value, "${filename}") {
			if strings.HasPrefix(canonical, "x-amz-algorithm") || canonical == "x-amz-credential" || canonical == "x-amz-date" || canonical == "x-amz-security-token" {
				return nil, "", ErrPostFormMalformed
			}
			value = strings.ReplaceAll(value, "${filename}", filename)
		}
		expanded[name] = value
	}
	return expanded, filename, nil
}
