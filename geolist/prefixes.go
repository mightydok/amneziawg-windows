/* SPDX-License-Identifier: MIT
 *
 * Geo-split routing: prefix list parsing and set arithmetic.
 */

// Package geolist loads country IP prefix lists, applies the geo-split policy and
// keeps the on-disk cache used by the tunnel service and the manager.
package geolist

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// Family selects the address family of a prefix list.
type Family int

const (
	IPv4 Family = 4
	IPv6 Family = 6
)

func (f Family) String() string {
	if f == IPv4 {
		return "IPv4"
	}
	return "IPv6"
}

// Bits returns the address length of the family.
func (f Family) Bits() int {
	if f == IPv4 {
		return 32
	}
	return 128
}

// Matches reports whether p belongs to the family. Callers are expected to Unmap
// IPv4-mapped IPv6 addresses before calling; ParsePrefix does that.
func (f Family) Matches(p netip.Prefix) bool {
	if f == IPv4 {
		return p.Addr().Is4()
	}
	return p.Addr().Is6()
}

var errEmptyList = errors.New("prefix list is empty")

// Parse reads a text list with one CIDR (or a bare address) per line. Blank lines and
// comments starting with a hash sign are ignored. Lines of the other address family
// are skipped so mixed lists are accepted; any other malformed line is an error.
// The result is normalized.
func Parse(data []byte, family Family) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		p, err := ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if !family.Matches(p) {
			continue
		}
		out = append(out, p)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errEmptyList
	}
	return Normalize(out), nil
}

// ParsePrefix parses "a.b.c.d/n", "a.b.c.d" (as /32) and their IPv6 counterparts.
// IPv4-mapped IPv6 addresses are unmapped so that "::ffff:1.2.3.4" is IPv4.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.IndexByte(s, '/') >= 0 {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %s is shorter than /96", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// ParseAll parses a comma, semicolon, space or newline separated list of prefixes of
// any family. An empty string yields an empty list.
func ParseAll(s string) ([]netip.Prefix, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	out := make([]netip.Prefix, 0, len(fields))
	for _, f := range fields {
		p, err := ParsePrefix(f)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", f, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// Format renders prefixes as a comma separated list.
func Format(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ", ")
}

func less(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return a.Addr().Is4()
	}
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c < 0
	}
	return a.Bits() < b.Bits()
}

// Normalize masks, sorts and deduplicates prefixes and removes prefixes that are
// contained in another prefix of the list. IPv4 sorts before IPv6.
func Normalize(ps []netip.Prefix) []netip.Prefix {
	if len(ps) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if !p.IsValid() {
			continue
		}
		out = append(out, p.Masked())
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	kept := out[:0]
	for _, p := range out {
		if len(kept) > 0 {
			last := kept[len(kept)-1]
			// Sorted by address and then by shortest prefix, so if they overlap the
			// previously kept prefix already covers p.
			if last.Addr().Is4() == p.Addr().Is4() && last.Overlaps(p) {
				continue
			}
		}
		kept = append(kept, p)
	}
	return kept
}

// MergeSiblings joins adjacent sibling prefixes (the two halves of one parent) into the
// parent, repeatedly, without changing the covered address set. The input must be
// normalized.
func MergeSiblings(ps []netip.Prefix) []netip.Prefix {
	for {
		merged := false
		out := make([]netip.Prefix, 0, len(ps))
		for i := 0; i < len(ps); i++ {
			if i+1 < len(ps) {
				if parent, ok := siblingParent(ps[i], ps[i+1]); ok {
					out = append(out, parent)
					i++
					merged = true
					continue
				}
			}
			out = append(out, ps[i])
		}
		ps = out
		if !merged {
			return ps
		}
	}
}

func siblingParent(a, b netip.Prefix) (netip.Prefix, bool) {
	if a.Bits() == 0 || a.Bits() != b.Bits() || a.Addr().Is4() != b.Addr().Is4() {
		return netip.Prefix{}, false
	}
	parent := netip.PrefixFrom(a.Addr(), a.Bits()-1).Masked()
	if parent.Addr() != a.Addr() {
		// a is the upper half, so a and b cannot be lower/upper siblings in this order
		return netip.Prefix{}, false
	}
	upper := netip.PrefixFrom(flipBit(a.Addr(), a.Bits()-1), a.Bits()).Masked()
	if b != upper {
		return netip.Prefix{}, false
	}
	return parent, true
}

// Subtract removes every address of excl from set, splitting prefixes as needed.
// Both inputs may be unnormalized; the result is normalized.
func Subtract(set, excl []netip.Prefix) []netip.Prefix {
	set = Normalize(set)
	excl = Normalize(excl)
	if len(excl) == 0 {
		return set
	}
	var out []netip.Prefix
	for _, s := range set {
		pieces := []netip.Prefix{s}
		for _, e := range excl {
			if e.Addr().Is4() != s.Addr().Is4() || !e.Overlaps(s) {
				continue
			}
			var next []netip.Prefix
			for _, piece := range pieces {
				next = append(next, splitOut(piece, e)...)
			}
			pieces = next
			if len(pieces) == 0 {
				break
			}
		}
		out = append(out, pieces...)
	}
	return Normalize(out)
}

// splitOut returns the prefixes covering s minus e.
func splitOut(s, e netip.Prefix) []netip.Prefix {
	if !s.Overlaps(e) {
		return []netip.Prefix{s}
	}
	if e.Bits() <= s.Bits() {
		// e covers all of s
		return nil
	}
	var out []netip.Prefix
	cur := s
	for cur.Bits() < e.Bits() {
		bits := cur.Bits() + 1
		lower := netip.PrefixFrom(cur.Addr(), bits).Masked()
		upper := netip.PrefixFrom(flipBit(cur.Addr(), bits-1), bits).Masked()
		if lower.Contains(e.Addr()) {
			out = append(out, upper)
			cur = lower
		} else {
			out = append(out, lower)
			cur = upper
		}
	}
	return out
}

// flipBit returns addr with bit i (0 = most significant) set to one.
func flipBit(addr netip.Addr, i int) netip.Addr {
	b := addr.AsSlice()
	b[i/8] |= 0x80 >> uint(i%8)
	a, _ := netip.AddrFromSlice(b)
	return a
}

// AddrCount4 returns the number of addresses covered by an IPv4 prefix.
func AddrCount4(p netip.Prefix) uint64 {
	if !p.Addr().Is4() {
		return 0
	}
	return uint64(1) << uint(32-p.Bits())
}

// Contains reports whether any prefix of the normalized set contains addr.
func Contains(set []netip.Prefix, addr netip.Addr) bool {
	for _, p := range set {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
