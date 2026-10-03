package api

import (
	"net/http"
	"strings"
)

// corsOwnedResponseHeaderNames is the complete set of policy headers the
// gateway may author. Upstream Access-Control-* fields are still stripped,
// but cannot be copied into an allow decision unless explicitly listed here.
var corsOwnedResponseHeaderNames = [...]string{
	"Access-Control-Allow-Origin",
	"Access-Control-Allow-Methods",
	"Access-Control-Allow-Headers",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Access-Control-Allow-Credentials",
}

func isOwnedCORSResponseHeader(name string) bool {
	for _, owned := range corsOwnedResponseHeaderNames {
		if name == owned {
			return true
		}
	}
	return false
}

// setCORSResponseHeader is the sole authoring boundary for gateway-owned CORS
// policy response headers. Keep its name switch synchronized with the drift
// guard's explicit registry assertion.
func setCORSResponseHeader(headers http.Header, name, value string) {
	switch name {
	case "Access-Control-Allow-Origin":
		headers.Set("Access-Control-Allow-Origin", value)
	case "Access-Control-Allow-Methods":
		headers.Set("Access-Control-Allow-Methods", value)
	case "Access-Control-Allow-Headers":
		headers.Set("Access-Control-Allow-Headers", value)
	case "Access-Control-Expose-Headers":
		headers.Set("Access-Control-Expose-Headers", value)
	case "Access-Control-Max-Age":
		headers.Set("Access-Control-Max-Age", value)
	case "Access-Control-Allow-Credentials":
		headers.Set("Access-Control-Allow-Credentials", value)
	default:
		panic("unregistered gateway CORS response header: " + name)
	}
}

func addCORSResponseHeader(headers http.Header, name, value string) {
	switch name {
	case "Access-Control-Allow-Origin":
		headers.Add("Access-Control-Allow-Origin", value)
	case "Access-Control-Allow-Methods":
		headers.Add("Access-Control-Allow-Methods", value)
	case "Access-Control-Allow-Headers":
		headers.Add("Access-Control-Allow-Headers", value)
	case "Access-Control-Expose-Headers":
		headers.Add("Access-Control-Expose-Headers", value)
	case "Access-Control-Max-Age":
		headers.Add("Access-Control-Max-Age", value)
	case "Access-Control-Allow-Credentials":
		headers.Add("Access-Control-Allow-Credentials", value)
	default:
		panic("unregistered gateway CORS response header: " + name)
	}
}

func deleteCORSResponseHeader(headers http.Header, name string) {
	switch name {
	case "Access-Control-Allow-Origin":
		headers.Del("Access-Control-Allow-Origin")
	case "Access-Control-Allow-Methods":
		headers.Del("Access-Control-Allow-Methods")
	case "Access-Control-Allow-Headers":
		headers.Del("Access-Control-Allow-Headers")
	case "Access-Control-Expose-Headers":
		headers.Del("Access-Control-Expose-Headers")
	case "Access-Control-Max-Age":
		headers.Del("Access-Control-Max-Age")
	case "Access-Control-Allow-Credentials":
		headers.Del("Access-Control-Allow-Credentials")
	default:
		panic("unregistered gateway CORS response header: " + name)
	}
}

func copyCORSResponseHeaders(source http.Header) http.Header {
	result := make(http.Header)
	for _, name := range corsOwnedResponseHeaderNames {
		for _, value := range source.Values(name) {
			switch name {
			case "Access-Control-Allow-Origin":
				addCORSResponseHeader(result, "Access-Control-Allow-Origin", value)
			case "Access-Control-Allow-Methods":
				addCORSResponseHeader(result, "Access-Control-Allow-Methods", value)
			case "Access-Control-Allow-Headers":
				addCORSResponseHeader(result, "Access-Control-Allow-Headers", value)
			case "Access-Control-Expose-Headers":
				addCORSResponseHeader(result, "Access-Control-Expose-Headers", value)
			case "Access-Control-Max-Age":
				addCORSResponseHeader(result, "Access-Control-Max-Age", value)
			case "Access-Control-Allow-Credentials":
				addCORSResponseHeader(result, "Access-Control-Allow-Credentials", value)
			}
		}
	}
	return result
}

func replaceCORSResponseHeaders(destination, source http.Header) {
	deleteCORSResponseHeader(destination, "Access-Control-Allow-Origin")
	deleteCORSResponseHeader(destination, "Access-Control-Allow-Methods")
	deleteCORSResponseHeader(destination, "Access-Control-Allow-Headers")
	deleteCORSResponseHeader(destination, "Access-Control-Expose-Headers")
	deleteCORSResponseHeader(destination, "Access-Control-Max-Age")
	deleteCORSResponseHeader(destination, "Access-Control-Allow-Credentials")
	copyCORSResponseHeaderValues(destination, source, "Access-Control-Allow-Origin")
	copyCORSResponseHeaderValues(destination, source, "Access-Control-Allow-Methods")
	copyCORSResponseHeaderValues(destination, source, "Access-Control-Allow-Headers")
	copyCORSResponseHeaderValues(destination, source, "Access-Control-Expose-Headers")
	copyCORSResponseHeaderValues(destination, source, "Access-Control-Max-Age")
	copyCORSResponseHeaderValues(destination, source, "Access-Control-Allow-Credentials")
}

func copyCORSResponseHeaderValues(destination, source http.Header, name string) {
	for _, value := range source.Values(name) {
		switch name {
		case "Access-Control-Allow-Origin":
			addCORSResponseHeader(destination, "Access-Control-Allow-Origin", value)
		case "Access-Control-Allow-Methods":
			addCORSResponseHeader(destination, "Access-Control-Allow-Methods", value)
		case "Access-Control-Allow-Headers":
			addCORSResponseHeader(destination, "Access-Control-Allow-Headers", value)
		case "Access-Control-Expose-Headers":
			addCORSResponseHeader(destination, "Access-Control-Expose-Headers", value)
		case "Access-Control-Max-Age":
			addCORSResponseHeader(destination, "Access-Control-Max-Age", value)
		case "Access-Control-Allow-Credentials":
			addCORSResponseHeader(destination, "Access-Control-Allow-Credentials", value)
		}
	}
}

// stripCORSResponseHeaders removes every upstream Access-Control-* field,
// including fields that the gateway does not recognize or author itself.
func stripCORSResponseHeaders(headers http.Header) {
	for name := range headers {
		if strings.HasPrefix(strings.ToLower(name), "access-control-") {
			delete(headers, name)
		}
	}
}
