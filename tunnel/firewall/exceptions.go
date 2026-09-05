/* SPDX-License-Identifier: MIT
 *
 * Geo-split routing: kill-switch exceptions for destinations reached outside the tunnel.
 */

package firewall

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Exceptions lists remote destinations that stay reachable on non-tunnel interfaces
// while the kill-switch is active.
type Exceptions struct {
	// Prefixes4 and Prefixes6 are permitted for outbound connections at the same
	// weight as the tunnel interface itself.
	Prefixes4 []netip.Prefix
	Prefixes6 []netip.Prefix
	// PermitPrivate permits outbound connections to private, link-local, CGNAT and
	// multicast ranges above the DNS restriction, so LAN devices and other VPN
	// adapters (with their DNS servers) keep working.
	PermitPrivate bool
	// InterfaceLUIDs are adapters of other VPN clients; outbound connections on
	// them are permitted above the DNS restriction, so routes those clients push
	// to public addresses keep working through their tunnels.
	InterfaceLUIDs []uint64
}

// IsEmpty reports whether the exceptions would add no filters.
func (e *Exceptions) IsEmpty() bool {
	return e == nil || (len(e.Prefixes4) == 0 && len(e.Prefixes6) == 0 && !e.PermitPrivate && len(e.InterfaceLUIDs) == 0)
}

// permitInterfaceOutbound permits outbound IPv4 and IPv6 connections on one interface.
func permitInterfaceOutbound(session uintptr, baseObjects *baseObjects, weight uint8, ifLUID uint64) error {
	ifaceCondition := wtFwpmFilterCondition0{
		fieldKey:  cFWPM_CONDITION_IP_LOCAL_INTERFACE,
		matchType: cFWP_MATCH_EQUAL,
		conditionValue: wtFwpConditionValue0{
			_type: cFWP_UINT64,
			value: (uintptr)(unsafe.Pointer(&ifLUID)),
		},
	}
	filter := wtFwpmFilter0{
		providerKey:         &baseObjects.provider,
		subLayerKey:         baseObjects.filters,
		weight:              filterWeight(weight),
		numFilterConditions: 1,
		filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&ifaceCondition)),
		action: wtFwpmAction0{
			_type: cFWP_ACTION_PERMIT,
		},
	}
	for _, layer := range []struct {
		key  windows.GUID
		name string
	}{
		{cFWPM_LAYER_ALE_AUTH_CONNECT_V4, "Permit outbound IPv4 traffic on other VPN adapter"},
		{cFWPM_LAYER_ALE_AUTH_CONNECT_V6, "Permit outbound IPv6 traffic on other VPN adapter"},
	} {
		displayData, err := createWtFwpmDisplayData0(layer.name, "")
		if err != nil {
			return wrapErr(err)
		}
		filter.displayData = *displayData
		filter.layerKey = layer.key
		filterID := uint64(0)
		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		runtime.KeepAlive(ifLUID)
		if err != nil {
			return wrapErr(err)
		}
	}
	return nil
}

func permitInterfaces(session uintptr, baseObjects *baseObjects, weight uint8, luids []uint64) error {
	for _, luid := range luids {
		if err := permitInterfaceOutbound(session, baseObjects, weight, luid); err != nil {
			return err
		}
	}
	return nil
}

// PermitInterface adds the other-VPN-adapter permit for an adapter that appeared
// after the firewall was enabled. It is a no-op while the firewall is off.
func PermitInterface(luid uint64) error {
	if wfpSession == 0 || wfpBaseObjects == nil || !wfpRestricting {
		return nil
	}
	return runTransaction(wfpSession, func(session uintptr) error {
		return permitInterfaceOutbound(session, wfpBaseObjects, 15, luid)
	})
}

// prefixesPerFilter bounds the number of OR-ed conditions in one WFP filter.
const prefixesPerFilter = 256

var privatePrefixes4 = mustPrefixes(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"255.255.255.255/32",
)

var privatePrefixes6 = mustPrefixes(
	"fe80::/10",
	"fc00::/7",
	"ff00::/8",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s))
	for _, x := range s {
		out = append(out, netip.MustParsePrefix(x))
	}
	return out
}

func permitPrivateOutbound(session uintptr, baseObjects *baseObjects, weight uint8) error {
	return permitRemotePrefixes(session, baseObjects, weight, "private networks", privatePrefixes4, privatePrefixes6)
}

// permitRemotePrefixes permits outbound connections to the given prefixes on any
// interface, in batches of prefixesPerFilter conditions per filter. Conditions on the
// same field within a filter are OR-ed by WFP.
func permitRemotePrefixes(session uintptr, baseObjects *baseObjects, weight uint8, name string, prefixes4, prefixes6 []netip.Prefix) error {
	if err := permitRemotePrefixesFamily(session, baseObjects, weight, name, prefixes4, false); err != nil {
		return err
	}
	return permitRemotePrefixesFamily(session, baseObjects, weight, name, prefixes6, true)
}

func permitRemotePrefixesFamily(session uintptr, baseObjects *baseObjects, weight uint8, name string, prefixes []netip.Prefix, v6 bool) error {
	layer := cFWPM_LAYER_ALE_AUTH_CONNECT_V4
	family := "IPv4"
	if v6 {
		layer = cFWPM_LAYER_ALE_AUTH_CONNECT_V6
		family = "IPv6"
	}
	for batch := 0; batch*prefixesPerFilter < len(prefixes); batch++ {
		end := (batch + 1) * prefixesPerFilter
		if end > len(prefixes) {
			end = len(prefixes)
		}
		chunk := prefixes[batch*prefixesPerFilter : end]

		// The condition values point into these slices; they are allocated with the
		// final capacity so the pointers stay valid until fwpmFilterAdd0 returns.
		conditions := make([]wtFwpmFilterCondition0, 0, len(chunk))
		masks4 := make([]wtFwpV4AddrAndMask, 0, len(chunk))
		masks6 := make([]wtFwpV6AddrAndMask, 0, len(chunk))
		for _, p := range chunk {
			if v6 != p.Addr().Is6() {
				return fmt.Errorf("prefix %s does not match the %s filter family", p, family)
			}
			if v6 {
				var m wtFwpV6AddrAndMask
				copy(m.addr[:], p.Addr().AsSlice())
				m.prefixLength = uint8(p.Bits())
				masks6 = append(masks6, m)
				conditions = append(conditions, wtFwpmFilterCondition0{
					fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
					matchType: cFWP_MATCH_EQUAL,
					conditionValue: wtFwpConditionValue0{
						_type: cFWP_V6_ADDR_MASK,
						value: uintptr(unsafe.Pointer(&masks6[len(masks6)-1])),
					},
				})
			} else {
				a := p.Addr().As4()
				mask := uint32(0xffffffff) << uint(32-p.Bits())
				masks4 = append(masks4, wtFwpV4AddrAndMask{
					addr: binary.BigEndian.Uint32(a[:]) & mask,
					mask: mask,
				})
				conditions = append(conditions, wtFwpmFilterCondition0{
					fieldKey:  cFWPM_CONDITION_IP_REMOTE_ADDRESS,
					matchType: cFWP_MATCH_EQUAL,
					conditionValue: wtFwpConditionValue0{
						_type: cFWP_V4_ADDR_MASK,
						value: uintptr(unsafe.Pointer(&masks4[len(masks4)-1])),
					},
				})
			}
		}

		displayData, err := createWtFwpmDisplayData0(fmt.Sprintf("Permit %s outbound (%s) #%d", name, family, batch+1), "")
		if err != nil {
			return wrapErr(err)
		}
		filter := wtFwpmFilter0{
			displayData:         *displayData,
			providerKey:         &baseObjects.provider,
			layerKey:            layer,
			subLayerKey:         baseObjects.filters,
			weight:              filterWeight(weight),
			numFilterConditions: uint32(len(conditions)),
			filterCondition:     (*wtFwpmFilterCondition0)(unsafe.Pointer(&conditions[0])),
			action: wtFwpmAction0{
				_type: cFWP_ACTION_PERMIT,
			},
		}
		filterID := uint64(0)
		err = fwpmFilterAdd0(session, &filter, 0, &filterID)
		runtime.KeepAlive(masks4)
		runtime.KeepAlive(masks6)
		runtime.KeepAlive(conditions)
		if err != nil {
			return wrapErr(err)
		}
	}
	return nil
}
