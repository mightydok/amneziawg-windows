/* SPDX-License-Identifier: MIT
 *
 * Office split-tunnel: the ExcludeRoutes and SplitDNS configuration keys. They let a
 * full-tunnel VPN coexist with corporate resources reachable only on the local network:
 * ExcludeRoutes keeps chosen prefixes off the tunnel and permitted through the
 * kill-switch, SplitDNS resolves chosen domain suffixes on corporate DNS servers. Both
 * work independently of GeoSplit.
 */

package conf

import (
	"net"
	"net/netip"
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/l18n"
)

// SplitDNSRule maps a DNS domain suffix to the servers that must resolve it while the
// tunnel is up. Everything outside the configured suffixes keeps using the tunnel DNS.
type SplitDNSRule struct {
	Domain  string
	Servers []net.IP
}

// parseExcludeRoutes parses a comma-separated list of prefixes or bare addresses into
// masked prefixes. A bare address becomes a host route (/32 or /128).
func parseExcludeRoutes(s string) ([]netip.Prefix, error) {
	items, err := splitList(s)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		p, err := parseOnePrefix(item)
		if err != nil {
			return nil, &ParseError{l18n.Sprintf("Invalid excluded route"), item}
		}
		out = append(out, p)
	}
	return out, nil
}

func parseOnePrefix(item string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(item); err == nil {
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(item)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// parseSplitDNS parses one "domain > server[, server...]" rule.
func parseSplitDNS(s string) (SplitDNSRule, error) {
	domain, serversPart, ok := strings.Cut(s, ">")
	if !ok {
		return SplitDNSRule{}, &ParseError{l18n.Sprintf("Split DNS rule must be \"domain > server[, server]\""), s}
	}
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	if domain == "" {
		return SplitDNSRule{}, &ParseError{l18n.Sprintf("Split DNS rule has no domain"), s}
	}
	items, err := splitList(serversPart)
	if err != nil {
		return SplitDNSRule{}, err
	}
	var servers []net.IP
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		ip := net.ParseIP(item)
		if ip == nil {
			return SplitDNSRule{}, &ParseError{l18n.Sprintf("Invalid split DNS server address"), item}
		}
		servers = append(servers, ip)
	}
	if len(servers) == 0 {
		return SplitDNSRule{}, &ParseError{l18n.Sprintf("Split DNS rule has no server"), s}
	}
	return SplitDNSRule{Domain: domain, Servers: servers}, nil
}
