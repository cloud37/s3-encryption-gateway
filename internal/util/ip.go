package util

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// IPExtractor provides trusted proxy-aware client IP extraction.
type IPExtractor struct {
	trustedProxies []*net.IPNet
}

// NewIPExtractor creates a new IPExtractor with the given trusted proxy CIDRs.
// If trustedProxies is empty, all X-Forwarded-For headers are ignored (fail-safe).
func NewIPExtractor(trustedProxyCIDRs []string) (*IPExtractor, error) {
	extractor := &IPExtractor{
		trustedProxies: make([]*net.IPNet, 0, len(trustedProxyCIDRs)),
	}

	for _, cidr := range trustedProxyCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", cidr, err)
		}
		extractor.trustedProxies = append(extractor.trustedProxies, ipNet)
	}

	return extractor, nil
}

// IsTrustedPeer considers only the immediate network peer, never XFF/client IP.
func (e *IPExtractor) IsTrustedPeer(r *http.Request) bool {
	if e == nil || r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	return e.isIPInNets(host)
}

// IsHTTPSRequest accepts direct TLS or one exact trusted-peer XFP indication.
// Forwarded, X-Forwarded-SSL, XFF and ForceHTTPS are not transport authority.
func (e *IPExtractor) IsHTTPSRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if !e.IsTrustedPeer(r) {
		return false
	}
	var values []string
	fields := 0
	for name, v := range r.Header {
		if strings.EqualFold(name, "X-Forwarded-Proto") {
			fields++
			values = append(values, v...)
		}
	}
	return fields == 1 && len(values) == 1 && strings.EqualFold(values[0], "https")
}

// GetClientIP extracts the client IP address from the request.
// If the request comes from a trusted proxy, it uses X-Forwarded-For or X-Real-IP headers.
// Otherwise, it uses RemoteAddr directly (fail-safe default).
func (e *IPExtractor) GetClientIP(r *http.Request) string {
	remoteIP := ExtractIP(r.RemoteAddr)

	// If no trusted proxies configured, always use RemoteAddr (fail-safe)
	if len(e.trustedProxies) == 0 {
		return remoteIP
	}

	// If remote IP is not a trusted proxy, use RemoteAddr
	if !e.isIPInNets(remoteIP) {
		return remoteIP
	}

	// Request comes from trusted proxy, check X-Forwarded-For
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		// Walk from rightmost to leftmost to find the rightmost non-trusted IP.
		// The X-Forwarded-For chain is: client, proxy1, proxy2, ..., immediate_peer
		// Our immediate peer (remoteIP) is already verified as trusted.
		// The rightmost IP in XFF is the one closest to our trusted peer.
		// We skip any IPs that are also trusted proxies, looking for the first
		// untrusted IP (the actual client or an untrusted proxy).
		for i := len(ips) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(ips[i])
			if ip == "" {
				continue
			}
			// If this IP is not a trusted proxy, it's the client (or an untrusted proxy)
			if !e.isIPInNets(ip) {
				return ip
			}
			// If it IS a trusted proxy, continue to the next (more original) IP to the left
		}
		// All IPs in the chain are trusted proxies, return the leftmost (most original)
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to RemoteAddr
	return remoteIP
}

// isIPInNets checks if the given IP address is in any of the trusted proxy networks.
func (e *IPExtractor) isIPInNets(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, ipNet := range e.trustedProxies {
		if ipNet.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// ExtractIP extracts the IP address from a host:port string.
// If there's no port, returns the input unchanged.
func ExtractIP(hostPort string) string {
	if hostPort == "" {
		return ""
	}

	// Handle IPv6 addresses with ports [host]:port
	if strings.HasPrefix(hostPort, "[") {
		if idx := strings.LastIndex(hostPort, "]"); idx != -1 {
			if idx+1 < len(hostPort) && hostPort[idx+1] == ':' {
				// Has port
				return hostPort[1:idx]
			}
			// No port
			return hostPort[1:idx]
		}
	}

	// Handle IPv4 addresses with ports host:port
	if colonIdx := strings.LastIndex(hostPort, ":"); colonIdx != -1 {
		// Check if this is an IPv6 address without brackets (shouldn't happen with RemoteAddr)
		if strings.Contains(hostPort[:colonIdx], ":") {
			// IPv6 without brackets, no port
			return hostPort
		}
		return hostPort[:colonIdx]
	}

	// No port present
	return hostPort
}

// isPrivateIP reports whether the given IP address is a private/reserved address.
// This includes RFC 1918 (10/8, 172.16/12, 192.168/16), loopback, link-local, etc.
func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check for loopback
	if parsedIP.IsLoopback() {
		return true
	}

	// Check for link-local
	if parsedIP.IsLinkLocalUnicast() || parsedIP.IsLinkLocalMulticast() {
		return true
	}

	// Check for private RFC 1918 ranges
	privateRanges := []string{
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // Link-local (APIPA)
		"127.0.0.0/8",    // Loopback
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local
	}

	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(parsedIP) {
			return true
		}
	}

	return false
}
