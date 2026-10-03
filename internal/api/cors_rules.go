package api

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/cloud37/s3-encryption-gateway/internal/config"
)

const (
	corsXMLNamespace = "http://s3.amazonaws.com/doc/2006-03-01/"
	maxCORSXMLBytes  = 64 << 10
	maxCORSRules     = 100
)

var (
	ErrCORSInvalidXML = errors.New("invalid CORS configuration XML")
	ErrCORSTooLarge   = errors.New("CORS configuration XML exceeds 64 KiB")
	xmlDeclarationRE  = regexp.MustCompile(`^version[ \t\r\n]*=[ \t\r\n]*(?:"1\.0"|'1\.0')(?:[ \t\r\n]+encoding[ \t\r\n]*=[ \t\r\n]*(?:"[A-Za-z][A-Za-z0-9._-]*"|'[A-Za-z][A-Za-z0-9._-]*'))?(?:[ \t\r\n]+standalone[ \t\r\n]*=[ \t\r\n]*(?:"(?:yes|no)"|'(?:yes|no)'))?[ \t\r\n]*$`)
)

type CORSConfiguration struct {
	XMLName xml.Name   `xml:"CORSConfiguration"`
	Rules   []CORSRule `xml:"CORSRule"`
}

type CORSRule struct {
	ID             string   `xml:"ID,omitempty"`
	AllowedOrigins []string `xml:"AllowedOrigin"`
	AllowedMethods []string `xml:"AllowedMethod"`
	AllowedHeaders []string `xml:"AllowedHeader,omitempty"`
	ExposeHeaders  []string `xml:"ExposeHeader,omitempty"`
	MaxAgeSeconds  *int     `xml:"MaxAgeSeconds,omitempty"`
}

type corsXMLNode struct {
	name     xml.Name
	attrs    []xml.Attr
	text     strings.Builder
	children []*corsXMLNode
}

func parseCORSXML(body []byte) (*CORSConfiguration, error) {
	if len(body) > maxCORSXMLBytes {
		return nil, ErrCORSTooLarge
	}
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = true
	declarationAllowed := false
	trimmedBody := bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf})
	if len(trimmedBody) >= len("<?xml") && bytes.HasPrefix(trimmedBody, []byte("<?xml")) {
		declarationAllowed = true
	}
	var root *corsXMLNode
	stack := make([]*corsXMLNode, 0, 4)
	seenRoot := false
	seenXMLDeclaration := false
	seenToken := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCORSInvalidXML, err)
		}
		switch v := tok.(type) {
		case xml.ProcInst:
			if seenRoot || seenToken || seenXMLDeclaration || !declarationAllowed || v.Target != "xml" || !xmlDeclarationRE.Match(v.Inst) {
				return nil, fmt.Errorf("%w: processing instructions are not allowed", ErrCORSInvalidXML)
			}
			seenXMLDeclaration = true
		case xml.Directive:
			return nil, fmt.Errorf("%w: directives are not allowed", ErrCORSInvalidXML)
		case xml.Comment:
			// Comments are intentionally discarded by canonical serialization.
			seenToken = true
		case xml.StartElement:
			seenToken = true
			node := &corsXMLNode{name: v.Name, attrs: append([]xml.Attr(nil), v.Attr...)}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("%w: multiple root elements", ErrCORSInvalidXML)
				}
				root = node
				seenRoot = true
			} else {
				stack[len(stack)-1].children = append(stack[len(stack)-1].children, node)
			}
			stack = append(stack, node)
		case xml.EndElement:
			seenToken = true
			if len(stack) == 0 || stack[len(stack)-1].name != v.Name {
				return nil, fmt.Errorf("%w: mismatched element", ErrCORSInvalidXML)
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(v) > 0 {
				seenToken = true
			}
			if len(stack) == 0 {
				if strings.TrimSpace(string(v)) != "" {
					return nil, fmt.Errorf("%w: unexpected text outside root", ErrCORSInvalidXML)
				}
			} else {
				stack[len(stack)-1].text.Write(v)
			}
		}
	}
	if root == nil || len(stack) != 0 || root.name.Local != "CORSConfiguration" || (root.name.Space != "" && root.name.Space != corsXMLNamespace) {
		return nil, fmt.Errorf("%w: invalid root element or namespace", ErrCORSInvalidXML)
	}
	for _, attr := range root.attrs {
		if !(attr.Name.Local == "xmlns" && attr.Value == corsXMLNamespace) {
			return nil, fmt.Errorf("%w: unexpected root attribute", ErrCORSInvalidXML)
		}
	}
	if strings.TrimSpace(root.text.String()) != "" {
		return nil, fmt.Errorf("%w: unexpected root text", ErrCORSInvalidXML)
	}
	if len(root.children) == 0 || len(root.children) > maxCORSRules {
		return nil, fmt.Errorf("%w: configuration must contain 1 to 100 rules", ErrCORSInvalidXML)
	}
	cfg := &CORSConfiguration{XMLName: xml.Name{Local: "CORSConfiguration"}, Rules: make([]CORSRule, 0, len(root.children))}
	for _, node := range root.children {
		if node.name.Local != "CORSRule" || node.name.Space != root.name.Space || len(node.attrs) != 0 || strings.TrimSpace(node.text.String()) != "" {
			return nil, fmt.Errorf("%w: unexpected rule element or text", ErrCORSInvalidXML)
		}
		rule, err := parseCORSRule(node)
		if err != nil {
			return nil, err
		}
		cfg.Rules = append(cfg.Rules, rule)
	}
	return cfg, nil
}

func parseCORSRule(node *corsXMLNode) (CORSRule, error) {
	var rule CORSRule
	seen := map[string]bool{}
	for _, child := range node.children {
		name := child.name.Local
		if child.name.Space != node.name.Space {
			return rule, fmt.Errorf("%w: unexpected namespace", ErrCORSInvalidXML)
		}
		switch name {
		case "ID", "AllowedOrigin", "AllowedMethod", "AllowedHeader", "ExposeHeader", "MaxAgeSeconds":
		default:
			return rule, fmt.Errorf("%w: unknown element %q", ErrCORSInvalidXML, name)
		}
		if len(child.attrs) != 0 || len(child.children) != 0 {
			return rule, fmt.Errorf("%w: nested elements or attributes are not allowed", ErrCORSInvalidXML)
		}
		rawValue := child.text.String()
		if hasCORSControl(rawValue) {
			return rule, fmt.Errorf("%w: raw control character in %s", ErrCORSInvalidXML, name)
		}
		value := strings.TrimSpace(rawValue)
		if name == "ID" && value == "" && !seen[name] {
			seen[name] = true
			continue
		}
		if value == "" {
			return rule, fmt.Errorf("%w: empty or invalid %s", ErrCORSInvalidXML, name)
		}
		switch name {
		case "ID":
			if seen[name] {
				return rule, fmt.Errorf("%w: duplicate ID", ErrCORSInvalidXML)
			}
			seen[name], rule.ID = true, value
		case "AllowedOrigin":
			if err := config.ValidateCORSOriginPattern(value); err != nil {
				return rule, fmt.Errorf("%w: %v", ErrCORSInvalidXML, err)
			}
			rule.AllowedOrigins = append(rule.AllowedOrigins, value)
		case "AllowedMethod":
			if !validCORSMethod(value) {
				return rule, fmt.Errorf("%w: unsupported method %q", ErrCORSInvalidXML, value)
			}
			rule.AllowedMethods = append(rule.AllowedMethods, value)
		case "AllowedHeader":
			if err := config.ValidateCORSHeaderPattern(value); err != nil {
				return rule, fmt.Errorf("%w: %v", ErrCORSInvalidXML, err)
			}
			rule.AllowedHeaders = append(rule.AllowedHeaders, value)
		case "ExposeHeader":
			if err := config.ValidateCORSFieldName(value); err != nil {
				return rule, fmt.Errorf("%w: %v", ErrCORSInvalidXML, err)
			}
			rule.ExposeHeaders = append(rule.ExposeHeaders, value)
		case "MaxAgeSeconds":
			if seen[name] {
				return rule, fmt.Errorf("%w: duplicate MaxAgeSeconds", ErrCORSInvalidXML)
			}
			age, err := parseNonnegativeDecimal(value)
			if err != nil {
				return rule, fmt.Errorf("%w: invalid MaxAgeSeconds", ErrCORSInvalidXML)
			}
			seen[name], rule.MaxAgeSeconds = true, &age
		default:
			return rule, fmt.Errorf("%w: unknown element %q", ErrCORSInvalidXML, name)
		}
	}
	if len(rule.AllowedOrigins) == 0 || len(rule.AllowedMethods) == 0 {
		return rule, fmt.Errorf("%w: each rule requires an origin and method", ErrCORSInvalidXML)
	}
	if len(rule.AllowedOrigins) > 100 || len(rule.AllowedMethods) > 6 || len(rule.AllowedHeaders) > 100 || len(rule.ExposeHeaders) > 100 {
		return rule, fmt.Errorf("%w: rule list limit exceeded", ErrCORSInvalidXML)
	}
	return rule, nil
}

func hasCORSControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func parseNonnegativeDecimal(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty integer")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not decimal")
		}
	}
	var n int64
	for _, c := range s {
		digit := int64(c - '0')
		if n > (int64(^uint(0)>>1)-digit)/10 {
			return 0, errors.New("overflow")
		}
		n = n*10 + digit
	}
	if strconv.IntSize == 32 && n > int64(^uint32(0)>>1) {
		return 0, errors.New("overflow")
	}
	return int(n), nil
}

func marshalCORSXML(cfg *CORSConfiguration) ([]byte, error) {
	if cfg == nil {
		return nil, fmt.Errorf("%w: nil configuration", ErrCORSInvalidXML)
	}
	// Round-trip through the same strict validator to avoid persisting invalid
	// caller-owned structs and to detach the stored value from the caller.
	if len(cfg.Rules) == 0 || len(cfg.Rules) > maxCORSRules {
		return nil, ErrCORSInvalidXML
	}
	for _, rule := range cfg.Rules {
		if len(rule.AllowedOrigins) == 0 || len(rule.AllowedMethods) == 0 {
			return nil, ErrCORSInvalidXML
		}
		if len(rule.AllowedOrigins) > 100 || len(rule.AllowedMethods) > 6 || len(rule.AllowedHeaders) > 100 || len(rule.ExposeHeaders) > 100 {
			return nil, ErrCORSInvalidXML
		}
		for _, origin := range rule.AllowedOrigins {
			if err := config.ValidateCORSOriginPattern(origin); err != nil {
				return nil, err
			}
		}
		for _, method := range rule.AllowedMethods {
			if !validCORSMethod(method) {
				return nil, fmt.Errorf("invalid method %q", method)
			}
		}
		for _, header := range rule.AllowedHeaders {
			if err := config.ValidateCORSHeaderPattern(header); err != nil {
				return nil, err
			}
		}
		for _, header := range rule.ExposeHeaders {
			if err := config.ValidateCORSFieldName(header); err != nil {
				return nil, err
			}
		}
		if rule.MaxAgeSeconds != nil && *rule.MaxAgeSeconds < 0 {
			return nil, ErrCORSInvalidXML
		}
		if len(rule.ID) > 255 || strings.ContainsAny(rule.ID, "\r\n\x00") {
			return nil, ErrCORSInvalidXML
		}
	}
	wireCfg := struct {
		XMLName xml.Name   `xml:"CORSConfiguration"`
		XMLNS   string     `xml:"xmlns,attr"`
		Rules   []CORSRule `xml:"CORSRule"`
	}{XMLName: xml.Name{Local: "CORSConfiguration"}, XMLNS: corsXMLNamespace, Rules: cloneCORSConfiguration(cfg).Rules}
	wire, err := xml.Marshal(wireCfg)
	if err != nil {
		return nil, fmt.Errorf("marshal CORS XML: %w", err)
	}
	if len(wire) > maxCORSXMLBytes {
		return nil, ErrCORSTooLarge
	}
	return wire, nil
}

func writeCORSXML(w http.ResponseWriter, cfg *CORSConfiguration) error {
	wire, err := marshalCORSXML(cfg)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(wire)
	return err
}

func matchCORSRule(cfg *CORSConfiguration, origin, method string, requestedHeaders []string) (*CORSRule, bool) {
	if cfg == nil || !validOriginHeader(origin) || !validRequestedMethod(method) {
		return nil, false
	}
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		if !stringListMatchesOrigin(rule.AllowedOrigins, origin) || !containsExact(rule.AllowedMethods, method) {
			continue
		}
		matched := true
		for _, requested := range requestedHeaders {
			if config.ValidateCORSFieldName(requested) != nil || !matchesAnyHeader(rule.AllowedHeaders, requested) {
				matched = false
				break
			}
		}
		if matched {
			return rule, true
		}
	}
	return nil, false
}

func validCORSMethod(method string) bool {
	return method == "GET" || method == "PUT" || method == "POST" || method == "DELETE" || method == "HEAD"
}
func validRequestedMethod(method string) bool {
	return method != "" && !strings.ContainsAny(method, "\r\n,") && validCORSMethod(method)
}

func validOriginHeader(origin string) bool {
	if origin == "" || strings.ContainsAny(origin, ",*\r\n\t\x00") {
		return false
	}
	for _, r := range origin {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return validateConcreteCORSOrigin(origin) == nil
}

func validateConcreteCORSOrigin(origin string) error {
	if origin == "" || origin == "null" || strings.ContainsAny(origin, "*?#\\") {
		return fmt.Errorf("invalid concrete CORS origin")
	}
	u, err := url.Parse(origin)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil || u.Host == "" || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid concrete CORS origin")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("invalid concrete CORS origin")
	}
	hostname := u.Hostname()
	authority := strings.TrimPrefix(origin, u.Scheme+"://")
	if strings.ContainsAny(authority, "\"'<>@%") || strings.ContainsAny(hostname, "\"'<>@%[]") {
		return fmt.Errorf("invalid concrete CORS origin authority")
	}
	if strings.HasPrefix(authority, "[") {
		closeBracket := strings.IndexByte(authority, ']')
		if closeBracket < 0 || (closeBracket+1 < len(authority) && authority[closeBracket+1] != ':') {
			return fmt.Errorf("invalid concrete CORS origin authority")
		}
		ip := net.ParseIP(hostname)
		if ip == nil || !strings.Contains(hostname, ":") {
			return fmt.Errorf("invalid concrete CORS origin IP literal")
		}
	} else {
		if strings.ContainsAny(authority, "[]") || strings.Contains(hostname, ":") || !validCORSOriginDNSName(hostname) {
			return fmt.Errorf("invalid concrete CORS origin hostname")
		}
		if strings.ContainsAny(hostname, ".") && strings.Trim(hostname, "0123456789.") == "" && net.ParseIP(hostname) == nil {
			return fmt.Errorf("invalid concrete CORS origin IPv4 literal")
		}
	}
	port := ""
	portPresent := false
	if strings.HasPrefix(authority, "[") {
		closeBracket := strings.IndexByte(authority, ']')
		if closeBracket+1 < len(authority) {
			portPresent = true
			port = authority[closeBracket+2:]
		}
	} else if colon := strings.LastIndexByte(authority, ':'); colon >= 0 {
		portPresent = true
		port = authority[colon+1:]
	}
	if portPresent {
		if port == "" {
			return fmt.Errorf("invalid concrete CORS origin port")
		}
		for _, digit := range port {
			if digit < '0' || digit > '9' {
				return fmt.Errorf("invalid concrete CORS origin port")
			}
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return fmt.Errorf("invalid concrete CORS origin port")
		}
	}
	return nil
}

func validCORSOriginDNSName(hostname string) bool {
	if hostname == "" || len(hostname) > 254 {
		return false
	}
	name := strings.TrimSuffix(hostname, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || !isASCIIAlphaNumeric(label[0]) || !isASCIIAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 1; i < len(label)-1; i++ {
			if !isASCIIAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func stringListMatchesOrigin(patterns []string, origin string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		if corsOriginEqual(pattern, origin) {
			return true
		}
	}
	return false
}

func corsOriginEqual(pattern, origin string) bool {
	patternScheme, patternHost, ok := splitCORSOrigin(pattern)
	if !ok {
		return false
	}
	originScheme, originHost, ok := splitCORSOrigin(origin)
	if !ok || patternScheme != originScheme {
		return false
	}
	if !strings.Contains(patternHost, "*") {
		return patternHost == originHost
	}
	quoted := regexp.QuoteMeta(patternHost)
	quoted = strings.ReplaceAll(quoted, `\*`, `[^:/]*`)
	matched, _ := regexp.MatchString("^"+quoted+"$", originHost)
	return matched
}

func splitCORSOrigin(origin string) (scheme, host string, ok bool) {
	if origin == "*" {
		return "*", "*", true
	}
	parts := strings.SplitN(origin, "://", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	host = strings.ToLower(parts[1])
	if !strings.Contains(host, "*") {
		u, err := url.Parse(origin)
		if err == nil && u != nil {
			host = strings.ToLower(u.Host)
		}
	}
	return strings.ToLower(parts[0]), host, true
}

func containsExact(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func matchesAnyHeader(patterns []string, name string) bool {
	for _, pattern := range patterns {
		if pattern == "*" {
			return true
		}
		re := "^" + strings.ReplaceAll(regexp.QuoteMeta(strings.ToLower(pattern)), `\*`, ".*") + "$"
		matched, _ := regexp.MatchString(re, strings.ToLower(name))
		if matched {
			return true
		}
	}
	return false
}

func cloneCORSConfiguration(cfg *CORSConfiguration) *CORSConfiguration {
	if cfg == nil {
		return nil
	}
	clone := &CORSConfiguration{XMLName: cfg.XMLName, Rules: make([]CORSRule, len(cfg.Rules))}
	for i, rule := range cfg.Rules {
		clone.Rules[i] = rule
		clone.Rules[i].AllowedOrigins = append([]string(nil), rule.AllowedOrigins...)
		clone.Rules[i].AllowedMethods = append([]string(nil), rule.AllowedMethods...)
		clone.Rules[i].AllowedHeaders = append([]string(nil), rule.AllowedHeaders...)
		clone.Rules[i].ExposeHeaders = append([]string(nil), rule.ExposeHeaders...)
		if rule.MaxAgeSeconds != nil {
			age := *rule.MaxAgeSeconds
			clone.Rules[i].MaxAgeSeconds = &age
		}
	}
	return clone
}
