/* SPDX-License-Identifier: MIT */

package geolist

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestApplyMinPrefixAndExceptions(t *testing.T) {
	list4 := Normalize(mustPrefixes(t, "5.8.0.0/19", "5.8.32.0/24", "77.88.0.0/18", "95.163.0.0/17"))
	list6 := Normalize(mustPrefixes(t, "2a02:6b8::/32"))
	p := Policy{
		MinPrefixV4:  22,
		IPv6Mode:     IPv6Direct,
		AlwaysDirect: mustPrefixes(t, "5.8.32.0/24", "2001:db8::/32"),
		AlwaysTunnel: mustPrefixes(t, "95.163.128.0/18"),
	}
	r := Apply(list4, list6, p)
	if r.Stats.DroppedBlocksV4 != 1 || r.Stats.DroppedAddrsV4 != 256 {
		t.Fatalf("dropped = %d blocks / %d addrs", r.Stats.DroppedBlocksV4, r.Stats.DroppedAddrsV4)
	}
	// 5.8.32.0/24 was dropped by the threshold but re-added by AlwaysDirect.
	if !Contains(r.Direct4, mustPrefixes(t, "5.8.32.1")[0].Addr()) {
		t.Fatalf("always-direct prefix missing: %v", r.Direct4)
	}
	// 95.163.128.0/18 removed from 95.163.0.0/17 leaves 95.163.0.0/18.
	if Contains(r.Direct4, mustPrefixes(t, "95.163.200.1")[0].Addr()) {
		t.Fatalf("always-tunnel prefix still direct: %v", r.Direct4)
	}
	if !Contains(r.Direct4, mustPrefixes(t, "95.163.10.1")[0].Addr()) {
		t.Fatalf("remaining half of split block missing: %v", r.Direct4)
	}
	if len(r.Direct6) != 2 {
		t.Fatalf("v6 = %v", r.Direct6)
	}
	if r.Stats.RoutesV4 != len(r.Direct4) || r.Stats.RoutesV6 != len(r.Direct6) {
		t.Fatal("stats do not match result")
	}

	p.IPv6Mode = IPv6Tunnel
	r = Apply(list4, list6, p)
	if len(r.Direct6) != 1 || r.Direct6[0].String() != "2001:db8::/32" {
		t.Fatalf("IPv6 tunnel mode should keep only always-direct: %v", r.Direct6)
	}
}

func TestApplyEmbeddedRUAtDefaultThreshold(t *testing.T) {
	raw4, _ := embeddedList(DefaultCountry, IPv4)
	raw6, _ := embeddedList(DefaultCountry, IPv6)
	l4, err := Parse(raw4, IPv4)
	if err != nil {
		t.Fatal(err)
	}
	l6, err := Parse(raw6, IPv6)
	if err != nil {
		t.Fatal(err)
	}
	s := DefaultSettings()
	p, err := s.Policy()
	if err != nil {
		t.Fatal(err)
	}
	r := Apply(l4, l6, p)
	t.Logf("RU /%d: %d v4 routes (%d blocks / %d addrs via tunnel), %d v6 routes", p.MinPrefixV4, r.Stats.RoutesV4, r.Stats.DroppedBlocksV4, r.Stats.DroppedAddrsV4, r.Stats.RoutesV6)
	if r.Stats.RoutesV4 < 3000 || r.Stats.RoutesV4 > 9000 {
		t.Fatalf("unexpected v4 route count %d", r.Stats.RoutesV4)
	}
	if r.Stats.RoutesV4 >= r.Stats.SourceV4 {
		t.Fatalf("threshold did not reduce routes: %d >= %d", r.Stats.RoutesV4, r.Stats.SourceV4)
	}
	for _, pfx := range r.Direct4 {
		if pfx.Bits() > p.MinPrefixV4 {
			t.Fatalf("block %v smaller than /%d survived", pfx, p.MinPrefixV4)
		}
	}
}

func TestSettingsRoundTripAndDefaults(t *testing.T) {
	dir := t.TempDir()
	s, err := loadSettingsFrom(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d := DefaultSettings(); s.MinPrefixV4 != d.MinPrefixV4 || s.StaleHours != d.StaleHours || s.IPv6Mode != d.IPv6Mode ||
		s.UpdateOnStart != d.UpdateOnStart || s.PermitPrivate != d.PermitPrivate || s.SourceV4 != d.SourceV4 || s.SourceV6 != d.SourceV6 ||
		len(s.AlwaysDirect) != 0 || len(s.AlwaysTunnel) != 0 {
		t.Fatalf("defaults differ: %+v", s)
	}
	s.MinPrefixV4 = 21
	s.AlwaysTunnel = []string{"5.8.0.0/24"}
	if err := s.saveTo(dir); err != nil {
		t.Fatal(err)
	}
	// A partial file keeps defaults for missing fields.
	if err := os.WriteFile(filepath.Join(dir, settingsFile), []byte(`{"min_prefix_v4": 20}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := loadSettingsFrom(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.MinPrefixV4 != 20 || s2.StaleHours != DefaultStaleHours || !s2.UpdateOnStart {
		t.Fatalf("partial settings: %+v", s2)
	}
	bad := DefaultSettings()
	bad.AlwaysDirect = []string{"garbage"}
	if err := bad.Validate(); err == nil {
		t.Fatal("expected validation error")
	}
	bad = DefaultSettings()
	bad.MinPrefixV4 = 40
	if err := bad.Validate(); err == nil {
		t.Fatal("expected validation error for min prefix")
	}
}

func TestStoreValidatesAndLoads(t *testing.T) {
	dir := t.TempDir()
	raw4, _ := embeddedList(DefaultCountry, IPv4)
	raw6, _ := embeddedList(DefaultCountry, IPv6)

	if _, _, err := storeTo(dir, "ru", IPv4, []byte("10.0.0.0/8\n"), 0); err == nil {
		t.Fatal("expected too-small list to be rejected")
	}
	count4, sha4, err := storeTo(dir, "ru", IPv4, raw4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if sha4 != SHA256Hex(raw4) || count4 < MinCountV4 {
		t.Fatalf("count=%d sha=%s", count4, sha4)
	}
	if _, _, err := storeTo(dir, "ru", IPv4, raw4[:len(raw4)/4], count4); err == nil {
		t.Fatal("expected drift check to reject a much shorter list")
	}
	count6, _, err := storeTo(dir, "ru", IPv6, raw6, 0)
	if err != nil {
		t.Fatal(err)
	}
	m := Meta{Country: "ru", FetchedAt: time.Now().Add(-2 * time.Hour), CountV4: count4, CountV6: count6}
	if err := m.saveTo(dir); err != nil {
		t.Fatal(err)
	}
	if m.IsStale(24, time.Now()) {
		t.Fatal("2h old cache must not be stale at 24h")
	}
	if !m.IsStale(1, time.Now()) {
		t.Fatal("2h old cache must be stale at 1h")
	}
	l4, l6, src, err := loadFrom(dir, "ru")
	if err != nil {
		t.Fatal(err)
	}
	if src.Kind != SourceCache || len(l4) != count4 || len(l6) != count6 || src.FetchedAt.IsZero() {
		t.Fatalf("loadFrom: kind=%s l4=%d l6=%d fetched=%v", src.Kind, len(l4), len(l6), src.FetchedAt)
	}
	if _, err := os.Stat(filepath.Join(dir, "ru-v4.list.tmp")); !os.IsNotExist(err) {
		t.Fatal("temp file left behind")
	}
}
