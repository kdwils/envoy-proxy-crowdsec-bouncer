package ip

import "net/netip"

// Type returns the CrowdSec metrics label value for the address family of addr.
// IPv4-mapped IPv6 addresses are unmapped before classification.
// Invalid addresses return an empty string.
func Type(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return "ipv4"
	}
	return "ipv6"
}

// TypeFromPrefix returns the CrowdSec metrics label value for the address
// family of prefix. IPv4-mapped IPv6 prefixes are unmapped before classification.
func TypeFromPrefix(prefix netip.Prefix) string {
	if !prefix.IsValid() {
		return ""
	}
	return Type(prefix.Addr().Unmap())
}
