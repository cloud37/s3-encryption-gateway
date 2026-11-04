package api

import (
	"bytes"
	"encoding/xml"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/cloud37/s3-encryption-gateway/internal/crypto"
	"github.com/cloud37/s3-encryption-gateway/internal/objectmeta"
	"github.com/cloud37/s3-encryption-gateway/internal/s3"
)

const postTaggingXMLLimit = 20 * 1024

const s3TaggingNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"

var postCannedACLs = map[string]struct{}{
	"private": {}, "public-read": {}, "public-read-write": {}, "authenticated-read": {},
	"aws-exec-read": {}, "bucket-owner-read": {}, "bucket-owner-full-control": {},
}

var postStorageClasses = map[string]struct{}{
	"REDUCED_REDUNDANCY": {}, "STANDARD_IA": {}, "ONEZONE_IA": {}, "INTELLIGENT_TIERING": {},
	"GLACIER": {}, "DEEP_ARCHIVE": {}, "GLACIER_IR": {},
}

func parsePostOptions(fields map[string]string) (options s3.ObjectPutOptions, tags, acl string, err error) {
	fail := func(parseErr error) (s3.ObjectPutOptions, string, string, error) {
		if options.SSE != nil && options.SSE.Customer != nil {
			options.SSE.Customer.Close()
		}
		return s3.ObjectPutOptions{}, "", "", parseErr
	}
	if fields == nil {
		return options, "", "", nil
	}
	seen := make(map[string]struct{}, len(fields))
	for name := range fields {
		if !postOptionFieldAccepted(name) {
			return fail(ErrPostUnsupported)
		}
		if strings.HasPrefix(asciiPostFold(name), "x-amz-meta-") && crypto.IsGatewayReservedKey(name) {
			return fail(ErrPostInvalidOption)
		}
		canonical := asciiPostFold(name)
		if _, duplicate := seen[canonical]; duplicate {
			return fail(ErrPostInvalidOption)
		}
		seen[canonical] = struct{}{}
	}
	for name, value := range fields {
		if strings.HasPrefix(asciiPostFold(name), "x-amz-meta-") {
			if crypto.IsGatewayReservedKey(name) {
				return fail(ErrPostInvalidOption)
			}
			_ = value // Metadata conversion remains owned by the common write path.
		}
	}
	if checksum, checksumErr := parsePostChecksum(fields); checksumErr != nil {
		return fail(checksumErr)
	} else {
		_ = checksum
	}
	if value, present := postFieldValue(fields, "acl"); present {
		if value != "" {
			if _, ok := postCannedACLs[value]; !ok {
				return fail(ErrPostInvalidOption)
			}
			acl = value
		}
	}
	if value, present := postFieldValue(fields, "x-amz-storage-class"); present {
		switch value {
		case "STANDARD":
			// Zero is the backend default; still validate explicit STANDARD.
		case "EXPRESS_ONEZONE":
			return fail(ErrPostUnsupported)
		default:
			if _, ok := postStorageClasses[value]; !ok {
				return fail(ErrPostInvalidOption)
			}
			options.StorageClass = value
		}
	}
	if value, present := postFieldValue(fields, "x-amz-website-redirect-location"); present {
		if !validPostWebsiteRedirect(value) {
			return fail(ErrPostInvalidOption)
		}
		options.WebsiteRedirectLocation = value
	}
	if value, present := postFieldValue(fields, "tagging"); present {
		tags, err = parsePostTagging(value)
		if err != nil {
			return fail(err)
		}
	}
	options.SSE, err = parseSSEOptions(fields)
	if err != nil {
		return fail(err)
	}
	return options, tags, acl, nil
}

func postOptionFieldAccepted(name string) bool {
	folded := asciiPostFold(name)
	switch folded {
	case "key", "bucket", "file", "policy", "x-amz-algorithm", "x-amz-credential", "x-amz-date", "x-amz-signature", "x-amz-security-token",
		"acl", "success_action_status", "success_action_redirect", "redirect", "tagging", "x-amz-storage-class", "x-amz-website-redirect-location",
		"content-md5", "x-amz-checksum-algorithm", "x-amz-checksum-crc32", "x-amz-checksum-crc32c", "x-amz-checksum-sha1", "x-amz-checksum-sha256", "x-amz-checksum-crc64nvme",
		"x-amz-server-side-encryption", "x-amz-server-side-encryption-aws-kms-key-id", "x-amz-server-side-encryption-context", "x-amz-server-side-encryption-bucket-key-enabled",
		"x-amz-server-side-encryption-customer-algorithm", "x-amz-server-side-encryption-customer-key", "x-amz-server-side-encryption-customer-key-md5":
		return true
	}
	for _, standard := range objectmeta.Names {
		if folded == asciiPostFold(standard) {
			return true
		}
	}
	return strings.HasPrefix(folded, "x-amz-meta-") && len(folded) > len("x-amz-meta-") ||
		strings.HasPrefix(folded, "x-ignore-") && len(folded) > len("x-ignore-")
}

func validPostWebsiteRedirect(value string) bool {
	if value == "" || len(value) > 2048 || !utf8.ValidString(value) || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	if strings.HasPrefix(value, "/") {
		return true
	}
	u, err := url.Parse(value)
	return err == nil && (strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")) && u.Host != "" && u.User == nil
}

func parsePostTagging(value string) (string, error) {
	if len(value) > postTaggingXMLLimit || !utf8.ValidString(value) {
		return "", ErrPostMalformedXML
	}
	if strings.Contains(value, "<!") {
		return "", ErrPostMalformedXML
	}
	decoder := xml.NewDecoder(bytes.NewReader([]byte(value)))
	decoder.Strict = true
	root, err := nextPostXMLStart(decoder)
	if err != nil || !postXMLName(root, "Tagging") || !postXMLAttrsAllowed(root) {
		return "", ErrPostMalformedXML
	}
	rootNS, err := postXMLNamespace(root)
	if err != nil {
		return "", ErrPostMalformedXML
	}
	tagSet, err := nextPostXMLStart(decoder)
	if err != nil || !postXMLNameNS(tagSet.Name, "TagSet", rootNS) || !postXMLAttrsAllowed(tagSet) {
		return "", ErrPostMalformedXML
	}
	values := make(url.Values)
	seen := make(map[string]struct{})
	for {
		tok, tokenErr := nextPostXMLContent(decoder)
		if tokenErr != nil {
			return "", ErrPostMalformedXML
		}
		end, done := tok.(xml.EndElement)
		if done {
			if !postXMLNameNS(end.Name, "TagSet", rootNS) {
				return "", ErrPostMalformedXML
			}
			break
		}
		start, ok := tok.(xml.StartElement)
		if !ok || !postXMLNameNS(start.Name, "Tag", rootNS) || !postXMLAttrsAllowed(start) {
			return "", ErrPostMalformedXML
		}
		if len(values) == 10 {
			return "", ErrPostInvalidTag
		}
		key, keyErr := readPostXMLValue(decoder, rootNS, "Key")
		if keyErr != nil {
			return "", ErrPostMalformedXML
		}
		valueText, valueErr := readPostXMLValue(decoder, rootNS, "Value")
		if valueErr != nil {
			return "", ErrPostMalformedXML
		}
		if endTag, endErr := nextPostXMLContent(decoder); endErr != nil {
			return "", ErrPostMalformedXML
		} else if end, ok := endTag.(xml.EndElement); !ok || !postXMLNameNS(end.Name, "Tag", rootNS) {
			return "", ErrPostMalformedXML
		}
		if !validPostTagKey(key) || !validPostTagValue(valueText) || strings.HasPrefix(key, "aws:") {
			return "", ErrPostInvalidTag
		}
		if _, duplicate := seen[key]; duplicate {
			return "", ErrPostInvalidTag
		}
		seen[key] = struct{}{}
		values.Add(key, valueText)
	}
	endRoot, err := nextPostXMLContent(decoder)
	if err != nil {
		return "", ErrPostMalformedXML
	}
	end, ok := endRoot.(xml.EndElement)
	if !ok || !postXMLNameNS(end.Name, "Tagging", rootNS) {
		return "", ErrPostMalformedXML
	}
	if tok, err := nextPostXMLContent(decoder); err != io.EOF || tok != nil {
		return "", ErrPostMalformedXML
	}
	return values.Encode(), nil
}

func nextPostXMLStart(decoder *xml.Decoder) (xml.StartElement, error) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			return xml.StartElement{}, err
		}
		switch value := tok.(type) {
		case xml.CharData:
			if strings.TrimSpace(string(value)) != "" {
				return xml.StartElement{}, ErrPostMalformedXML
			}
		case xml.StartElement:
			return value, nil
		default:
			return xml.StartElement{}, ErrPostMalformedXML
		}
	}
}

func nextPostXMLContent(decoder *xml.Decoder) (xml.Token, error) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if data, ok := tok.(xml.CharData); ok && strings.TrimSpace(string(data)) == "" {
			continue
		}
		return tok, nil
	}
}

func postXMLNamespace(start xml.StartElement) (string, error) {
	if start.Name.Space != "" && start.Name.Space != s3TaggingNamespace {
		return "", ErrPostMalformedXML
	}
	return start.Name.Space, nil
}

func postXMLName(start xml.StartElement, local string) bool {
	return start.Name.Local == local && (start.Name.Space == "" || start.Name.Space == s3TaggingNamespace)
}

func postXMLNameNS(name xml.Name, local, namespace string) bool {
	return name.Local == local && name.Space == namespace
}

func postXMLAttrsAllowed(start xml.StartElement) bool {
	for _, attr := range start.Attr {
		if attr.Name.Space == "xmlns" || attr.Name.Space == "" && attr.Name.Local == "xmlns" {
			if attr.Value != s3TaggingNamespace {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func readPostXMLValue(decoder *xml.Decoder, namespace, local string) (string, error) {
	start, err := nextPostXMLStart(decoder)
	if err != nil || !postXMLNameNS(start.Name, local, namespace) || !postXMLAttrsAllowed(start) {
		return "", ErrPostMalformedXML
	}
	var text strings.Builder
	for {
		tok, tokenErr := decoder.Token()
		if tokenErr != nil {
			return "", tokenErr
		}
		switch value := tok.(type) {
		case xml.CharData:
			if text.Len()+len(value) > postTaggingXMLLimit {
				return "", ErrPostMalformedXML
			}
			text.Write(value)
		case xml.EndElement:
			if !postXMLNameNS(value.Name, local, namespace) {
				return "", ErrPostMalformedXML
			}
			return text.String(), nil
		default:
			return "", ErrPostMalformedXML
		}
	}
}

func validPostTagKey(value string) bool {
	n := utf8.RuneCountInString(value)
	return n >= 1 && n <= 128 && validPostTagCharacters(value)
}

func validPostTagValue(value string) bool {
	return utf8.RuneCountInString(value) <= 256 && validPostTagCharacters(value)
}

func validPostTagCharacters(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) || strings.ContainsRune("+-=._:/@", r) {
			continue
		}
		return false
	}
	return true
}
