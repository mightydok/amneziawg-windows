/* SPDX-License-Identifier: MIT
 *
 * Geo-split routing: policy applied to a country prefix list.
 */

package geolist

import (
	"fmt"
	"net/netip"
)

const (
	// IPv6Direct routes the country's IPv6 prefixes directly, like IPv4.
	IPv6Direct = "direct"
	// IPv6Tunnel sends all IPv6 through the tunnel and installs no IPv6 exception routes.
	IPv6Tunnel = "tunnel"
)

// Policy describes how the raw country list is turned into direct routes.
type Policy struct {
	// MinPrefixV4 keeps only IPv4 blocks whose prefix length is at most MinPrefixV4,
	// that is blocks at least that large. Smaller blocks go through the tunnel.
	// Zero keeps every block.
	MinPrefixV4 int
	// IPv6Mode is IPv6Direct or IPv6Tunnel.
	IPv6Mode string
	// AlwaysDirect prefixes are routed directly regardless of the list.
	AlwaysDirect []netip.Prefix
	// AlwaysTunnel prefixes are removed from the direct set regardless of the list.
	AlwaysTunnel []netip.Prefix
}

// Validate checks the policy values.
func (p Policy) Validate() error {
	if p.MinPrefixV4 < 0 || p.MinPrefixV4 > 32 {
		return fmt.Errorf("min prefix must be between 0 and 32, got %d", p.MinPrefixV4)
	}
	if p.IPv6Mode != IPv6Direct && p.IPv6Mode != IPv6Tunnel {
		return fmt.Errorf("unknown IPv6 mode %q", p.IPv6Mode)
	}
	return nil
}

// Stats summarizes what Apply produced.
type Stats struct {
	SourceV4        int
	SourceV6        int
	RoutesV4        int
	RoutesV6        int
	DroppedBlocksV4 int
	DroppedAddrsV4  uint64
	DirectAddrsV4   uint64
}

// Result is the direct set for both families plus statistics.
type Result struct {
	Direct4 []netip.Prefix
	Direct6 []netip.Prefix
	Stats   Stats
}

// Apply builds the direct route sets from the country lists and the policy.
func Apply(list4, list6 []netip.Prefix, p Policy) Result {
	var r Result
	r.Stats.SourceV4 = len(list4)
	r.Stats.SourceV6 = len(list6)

	d4 := make([]netip.Prefix, 0, len(list4))
	for _, pfx := range list4 {
		if p.MinPrefixV4 > 0 && pfx.Bits() > p.MinPrefixV4 {
			r.Stats.DroppedBlocksV4++
			r.Stats.DroppedAddrsV4 += AddrCount4(pfx)
			continue
		}
		d4 = append(d4, pfx)
	}
	var d6 []netip.Prefix
	if p.IPv6Mode != IPv6Tunnel {
		d6 = append(d6, list6...)
	}
	for _, pfx := range p.AlwaysDirect {
		if pfx.Addr().Is4() {
			d4 = append(d4, pfx)
		} else {
			d6 = append(d6, pfx)
		}
	}
	d4 = Subtract(MergeSiblings(Normalize(d4)), p.AlwaysTunnel)
	d6 = Subtract(MergeSiblings(Normalize(d6)), p.AlwaysTunnel)

	r.Direct4, r.Direct6 = d4, d6
	r.Stats.RoutesV4 = len(d4)
	r.Stats.RoutesV6 = len(d6)
	for _, pfx := range d4 {
		r.Stats.DirectAddrsV4 += AddrCount4(pfx)
	}
	return r
}
