/* SPDX-License-Identifier: MIT */

package conf

import (
	"strings"
	"testing"
)

const geoSplitInput = `
[Interface]
PrivateKey = 6KpEbHkZ6KgAAB8DFKaJ7kHYc6wa+BIYtaf5bGsESVs=
Address = 10.0.0.2/32
DNS = 1.1.1.1
GeoSplit = RU

[Peer]
PublicKey = NkK6hwLJb/K1hM2/qs+cX7yh6mQ4Fh6VvHAfr9qZjCk=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.1:51820
`

func TestGeoSplitKeyRoundTrip(t *testing.T) {
	c, err := FromWgQuick(geoSplitInput, "test")
	if err != nil {
		t.Fatal(err)
	}
	if c.Interface.GeoSplit != "ru" {
		t.Fatalf("GeoSplit = %q, want ru", c.Interface.GeoSplit)
	}
	out := c.ToWgQuick()
	if !strings.Contains(out, "GeoSplit = ru\n") {
		t.Fatalf("ToWgQuick lost the key:\n%s", out)
	}
	if strings.Contains(out, "geosplit") {
		t.Fatal("UAPI-style key leaked into wg-quick output")
	}
	uapi, err := c.ToUAPI()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(uapi), "geosplit") {
		t.Fatalf("GeoSplit must not appear in UAPI:\n%s", uapi)
	}

	c2, err := FromWgQuick(strings.Replace(geoSplitInput, "GeoSplit = RU", "GeoSplit = off", 1), "test")
	if err != nil {
		t.Fatal(err)
	}
	if c2.Interface.GeoSplit != "" {
		t.Fatalf("GeoSplit off = %q", c2.Interface.GeoSplit)
	}
	if strings.Contains(c2.ToWgQuick(), "GeoSplit") {
		t.Fatal("disabled GeoSplit must not be written")
	}

	if _, err := FromWgQuick(strings.Replace(geoSplitInput, "GeoSplit = RU", "GeoSplit = russia", 1), "test"); err == nil {
		t.Fatal("expected error for invalid country code")
	}
}
