/* SPDX-License-Identifier: MIT
 *
 * Geo-split routing: exception routes for one country's prefixes.
 *
 * The tunnel keeps its 0.0.0.0/0 and ::/0 routes. For every prefix of the direct set
 * a more specific route is installed on the interface that currently owns the
 * physical default route, using that route's next hop. Whenever the default route
 * moves (roaming) the routes are re-pointed. While they are absent, traffic to those
 * prefixes goes through the tunnel, never outside of it.
 */

package tunnel

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
	"github.com/amnezia-vpn/amneziawg-windows/v3/geolist"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/firewall"
	"github.com/amnezia-vpn/amneziawg-windows/v3/tunnel/winipcfg"
)

// geoRouteProtocol marks the exception routes so that leftovers of a crashed instance
// can be found. NL_ROUTE_PROTOCOL is informational for locally created routes and
// RouteProtocolBbn is not used by Windows itself.
const geoRouteProtocol = winipcfg.RouteProtocolBbn

type geoInstalled struct {
	luid    winipcfg.LUID
	nextHop net.IP
	count   int
}

type geoSplit struct {
	country       string
	direct4       []netip.Prefix
	direct6       []netip.Prefix
	permitPrivate bool
	stats         geolist.Stats

	mu        sync.Mutex
	installed map[winipcfg.AddressFamily]*geoInstalled
}

// loadGeoSplit prepares the direct sets for the configuration. It returns nil when the
// configuration does not enable geo-split.
func loadGeoSplit(config *conf.Config) (*geoSplit, error) {
	country := config.Interface.GeoSplit
	if country == "" {
		return nil, nil
	}
	settings, err := geolist.LoadSettings()
	if err != nil {
		log.Printf("Geo-split: settings are unreadable, using defaults: %v", err)
	}
	policy, err := settings.Policy()
	if err != nil {
		return nil, fmt.Errorf("geo-split policy: %w", err)
	}
	list4, list6, src, err := geolist.Load(country)
	if err != nil {
		return nil, fmt.Errorf("geo-split list: %w", err)
	}
	result := geolist.Apply(list4, list6, policy)
	g := &geoSplit{
		country:       country,
		direct4:       result.Direct4,
		direct6:       result.Direct6,
		permitPrivate: settings.PermitPrivate,
		stats:         result.Stats,
		installed:     make(map[winipcfg.AddressFamily]*geoInstalled),
	}
	age := "embedded snapshot"
	if src.Kind == geolist.SourceCache {
		if src.FetchedAt.IsZero() {
			age = "cached list, fetch time unknown"
		} else {
			age = fmt.Sprintf("cached list fetched %s ago", time.Since(src.FetchedAt).Round(time.Minute))
		}
	}
	log.Printf("Geo-split %s: %d IPv4 and %d IPv6 direct routes (%s); %d IPv4 blocks smaller than /%d (%d addresses) go through the tunnel",
		strings.ToUpper(country), len(g.direct4), len(g.direct6), age, result.Stats.DroppedBlocksV4, policy.MinPrefixV4, result.Stats.DroppedAddrsV4)
	return g, nil
}

// exceptions returns the kill-switch exceptions; nil for a nil receiver.
func (g *geoSplit) exceptions() *firewall.Exceptions {
	if g == nil {
		return nil
	}
	return &firewall.Exceptions{
		Prefixes4:     g.direct4,
		Prefixes6:     g.direct6,
		PermitPrivate: g.permitPrivate,
	}
}

func (g *geoSplit) prefixes(family winipcfg.AddressFamily) []netip.Prefix {
	switch family {
	case windows.AF_INET:
		return g.direct4
	case windows.AF_INET6:
		return g.direct6
	}
	return nil
}

// onDefaultRoute installs the exception routes on the interface that owns the physical
// default route, replacing routes installed for a previous interface or next hop. A zero
// luid means there is no default route and only removes existing routes.
func (g *geoSplit) onDefaultRoute(family winipcfg.AddressFamily, luid winipcfg.LUID, nextHop net.IP) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if cur := g.installed[family]; cur != nil {
		if cur.luid == luid && cur.nextHop.Equal(nextHop) {
			return
		}
		g.removeLocked(family)
	}
	if luid == 0 {
		return
	}
	prefixes := g.prefixes(family)
	if len(prefixes) == 0 {
		return
	}
	if nextHop == nil {
		// An on-link default route (PPP, cellular) has no gateway; mirror that.
		if family == windows.AF_INET6 {
			nextHop = net.IPv6zero
		} else {
			nextHop = net.IPv4zero
		}
	}

	start := time.Now()
	added, failed := 0, 0
	var firstErr error
	for _, p := range prefixes {
		err := createGeoRoute(luid, p, nextHop)
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		added++
	}
	g.installed[family] = &geoInstalled{luid: luid, nextHop: nextHop, count: added}
	msg := fmt.Sprintf("Geo-split: installed %d %s direct routes via %s on interface LUID %d in %v", added, familyName(family), nextHopString(nextHop), luid, time.Since(start).Round(time.Millisecond))
	if failed > 0 {
		msg += fmt.Sprintf(" (%d failed, first error: %v)", failed, firstErr)
	}
	log.Println(msg)
}

func createGeoRoute(luid winipcfg.LUID, p netip.Prefix, nextHop net.IP) error {
	row := winipcfg.MibIPforwardRow2{}
	row.Init()
	row.InterfaceLUID = luid
	if err := row.DestinationPrefix.SetIPNet(prefixToIPNet(p)); err != nil {
		return err
	}
	if err := row.NextHop.SetIP(nextHop, 0); err != nil {
		return err
	}
	row.Metric = 0
	row.Protocol = geoRouteProtocol
	err := row.Create()
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		return nil
	}
	return err
}

// removeLocked deletes the routes recorded for the family. Routes are matched by
// interface and destination, so this works even if the marker protocol was rejected.
func (g *geoSplit) removeLocked(family winipcfg.AddressFamily) {
	cur := g.installed[family]
	if cur == nil {
		return
	}
	delete(g.installed, family)
	start := time.Now()
	set := make(map[netip.Prefix]struct{}, len(g.prefixes(family)))
	for _, p := range g.prefixes(family) {
		set[p] = struct{}{}
	}
	removed := deleteRoutes(family, func(row *winipcfg.MibIPforwardRow2) bool {
		if row.InterfaceLUID != cur.luid {
			return false
		}
		p, ok := rowPrefix(row)
		if !ok {
			return false
		}
		_, ours := set[p]
		return ours
	})
	log.Printf("Geo-split: removed %d %s direct routes from interface LUID %d in %v", removed, familyName(family), cur.luid, time.Since(start).Round(time.Millisecond))
}

// removeAll deletes the exception routes of both families.
func (g *geoSplit) removeAll() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		g.removeLocked(family)
	}
}

// sweepStaleGeoRoutes removes marker routes left behind by an instance that did not
// shut down cleanly. It is called before any new routes are installed.
func sweepStaleGeoRoutes() {
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		n := deleteRoutes(family, func(row *winipcfg.MibIPforwardRow2) bool {
			return row.Protocol == geoRouteProtocol
		})
		if n > 0 {
			log.Printf("Geo-split: removed %d stale %s routes from a previous instance", n, familyName(family))
		}
	}
}

func deleteRoutes(family winipcfg.AddressFamily, match func(*winipcfg.MibIPforwardRow2) bool) int {
	table, err := winipcfg.GetIPForwardTable2(family)
	if err != nil {
		log.Printf("Geo-split: unable to read the %s routing table: %v", familyName(family), err)
		return 0
	}
	n := 0
	for i := range table {
		if !match(&table[i]) {
			continue
		}
		if err := table[i].Delete(); err == nil {
			n++
		}
	}
	return n
}

func rowPrefix(row *winipcfg.MibIPforwardRow2) (netip.Prefix, bool) {
	ipnet := row.DestinationPrefix.IPNet()
	addr, ok := netip.AddrFromSlice(ipnet.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, int(row.DestinationPrefix.PrefixLength)).Masked(), true
}

func prefixToIPNet(p netip.Prefix) net.IPNet {
	return net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

func familyName(family winipcfg.AddressFamily) string {
	if family == windows.AF_INET6 {
		return "IPv6"
	}
	return "IPv4"
}

func nextHopString(nextHop net.IP) string {
	if nextHop == nil || nextHop.IsUnspecified() {
		return "on-link"
	}
	return nextHop.String()
}
