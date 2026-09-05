/* SPDX-License-Identifier: MIT */

package geolist

import (
	"math/big"
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, s ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(s))
	for _, x := range s {
		p, err := ParsePrefix(x)
		if err != nil {
			t.Fatalf("parse %q: %v", x, err)
		}
		out = append(out, p)
	}
	return out
}

func equalPrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// addrCount returns the total number of addresses covered by a normalized set.
func addrCount(ps []netip.Prefix) *big.Int {
	total := new(big.Int)
	for _, p := range ps {
		size := new(big.Int).Lsh(big.NewInt(1), uint(p.Addr().BitLen()-p.Bits()))
		total.Add(total, size)
	}
	return total
}

func TestParseMixedListWithComments(t *testing.T) {
	data := []byte("# Country: RU\n\n5.8.0.0/19 # trailing\n2a00:1450::/32\n 77.88.8.8\n5.8.0.0/24\n")
	v4, err := Parse(data, IPv4)
	if err != nil {
		t.Fatal(err)
	}
	want := mustPrefixes(t, "5.8.0.0/19", "77.88.8.8/32")
	if !equalPrefixes(v4, want) {
		t.Fatalf("v4 = %v, want %v", v4, want)
	}
	v6, err := Parse(data, IPv6)
	if err != nil {
		t.Fatal(err)
	}
	if !equalPrefixes(v6, mustPrefixes(t, "2a00:1450::/32")) {
		t.Fatalf("v6 = %v", v6)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	if _, err := Parse([]byte("5.8.0.0/19\nnot-a-prefix\n"), IPv4); err == nil {
		t.Fatal("expected error for malformed line")
	}
	if _, err := Parse([]byte("# only comments\n"), IPv4); err == nil {
		t.Fatal("expected error for empty list")
	}
}

func TestParsePrefixUnmapsIPv4In6(t *testing.T) {
	p, err := ParsePrefix("::ffff:10.0.0.0/104")
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != "10.0.0.0/8" {
		t.Fatalf("got %s", p)
	}
	if _, err := ParsePrefix("::ffff:10.0.0.0/64"); err == nil {
		t.Fatal("expected error for mapped prefix shorter than /96")
	}
}

func TestNormalizeRemovesNestedAndDuplicates(t *testing.T) {
	in := mustPrefixes(t, "10.0.1.0/24", "10.0.0.0/16", "10.0.0.0/16", "10.0.0.0/8", "192.168.0.0/24", "2001:db8::/32", "2001:db8:1::/48")
	got := Normalize(in)
	want := mustPrefixes(t, "10.0.0.0/8", "192.168.0.0/24", "2001:db8::/32")
	if !equalPrefixes(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestMergeSiblings(t *testing.T) {
	in := Normalize(mustPrefixes(t, "10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24", "10.0.5.0/24", "10.0.6.0/24"))
	got := MergeSiblings(in)
	want := mustPrefixes(t, "10.0.0.0/22", "10.0.5.0/24", "10.0.6.0/24")
	if !equalPrefixes(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if addrCount(got).Cmp(addrCount(in)) != 0 {
		t.Fatal("merge changed the covered address count")
	}
}

func TestSubtract(t *testing.T) {
	cases := []struct {
		set, excl, want []string
	}{
		{[]string{"10.0.0.0/8"}, []string{"10.1.0.0/16"}, []string{"10.0.0.0/16", "10.2.0.0/15", "10.4.0.0/14", "10.8.0.0/13", "10.16.0.0/12", "10.32.0.0/11", "10.64.0.0/10", "10.128.0.0/9"}},
		{[]string{"10.0.0.0/24"}, []string{"10.0.0.0/8"}, nil},
		{[]string{"10.0.0.0/24", "10.1.0.0/24"}, []string{"192.168.0.0/16"}, []string{"10.0.0.0/24", "10.1.0.0/24"}},
		{[]string{"10.0.0.0/24"}, []string{"10.0.0.255/32"}, []string{"10.0.0.0/25", "10.0.0.128/26", "10.0.0.192/27", "10.0.0.224/28", "10.0.0.240/29", "10.0.0.248/30", "10.0.0.252/31", "10.0.0.254/32"}},
		{[]string{"2001:db8::/32"}, []string{"2001:db8:8000::/33"}, []string{"2001:db8::/33"}},
	}
	for _, c := range cases {
		got := Subtract(mustPrefixes(t, c.set...), mustPrefixes(t, c.excl...))
		want := Normalize(mustPrefixes(t, c.want...))
		if !equalPrefixes(got, want) {
			t.Errorf("Subtract(%v, %v) = %v, want %v", c.set, c.excl, got, want)
		}
		for _, e := range mustPrefixes(t, c.excl...) {
			if Contains(got, e.Addr()) {
				t.Errorf("Subtract(%v, %v) still contains %v", c.set, c.excl, e.Addr())
			}
		}
	}
}

func TestParseAll(t *testing.T) {
	got, err := ParseAll("10.0.0.0/8, 192.168.1.1;2001:db8::/32\n172.16.0.0/12")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d prefixes: %v", len(got), got)
	}
	if _, err := ParseAll("10.0.0.0/8, nope"); err == nil {
		t.Fatal("expected error")
	}
	if got, err := ParseAll("  "); err != nil || len(got) != 0 {
		t.Fatalf("empty input: %v %v", got, err)
	}
}

func TestEmbeddedSnapshotParses(t *testing.T) {
	for _, fam := range []Family{IPv4, IPv6} {
		raw, ok := embeddedList(DefaultCountry, fam)
		if !ok {
			t.Fatalf("no embedded %s list", fam)
		}
		list, err := Validate(raw, fam, 0)
		if err != nil {
			t.Fatalf("embedded %s: %v", fam, err)
		}
		t.Logf("embedded %s: %d prefixes", fam, len(list))
	}
}
