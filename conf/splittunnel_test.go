/* SPDX-License-Identifier: MIT */

package conf

import (
	"strings"
	"testing"
)

func TestSplitTunnelParseAndRoundTrip(t *testing.T) {
	const input = `[Interface]
PrivateKey = TFlmmEUC7V7VtiDYLKsbP5rySTKLIZq1yn8lMqK83wo=
Address = 172.16.254.10/32
DNS = 1.1.1.1
ExcludeRoutes = 10.0.0.0/8, 192.168.5.10
SplitDNS = corp.mvideo.ru > 10.95.0.8, 10.95.0.9
SplitDNS = .intra.mvideo.ru > 10.170.18.8

[Peer]
PublicKey = vBN7qyUTb5lJtWYJ8LhbPio1Z4RcyBPGnqFBGn6O6Qg=
AllowedIPs = 0.0.0.0/0
Endpoint = 192.0.2.1:51820
`
	cfg, err := FromWgQuick(input, "office")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	if got := len(cfg.Interface.ExcludeRoutes); got != 2 {
		t.Fatalf("ExcludeRoutes count = %d, want 2", got)
	}
	if cfg.Interface.ExcludeRoutes[0].String() != "10.0.0.0/8" {
		t.Errorf("ExcludeRoutes[0] = %s, want 10.0.0.0/8", cfg.Interface.ExcludeRoutes[0])
	}
	if cfg.Interface.ExcludeRoutes[1].String() != "192.168.5.10/32" {
		t.Errorf("bare IP must become a host route, got %s", cfg.Interface.ExcludeRoutes[1])
	}

	if got := len(cfg.Interface.SplitDNS); got != 2 {
		t.Fatalf("SplitDNS count = %d, want 2", got)
	}
	r0 := cfg.Interface.SplitDNS[0]
	if r0.Domain != "corp.mvideo.ru" || len(r0.Servers) != 2 {
		t.Errorf("SplitDNS[0] = %+v, want corp.mvideo.ru with 2 servers", r0)
	}
	if cfg.Interface.SplitDNS[1].Domain != "intra.mvideo.ru" {
		t.Errorf("leading dot must be stripped, got %q", cfg.Interface.SplitDNS[1].Domain)
	}

	// Round trip through the writer and back.
	out := cfg.ToWgQuick()
	if !strings.Contains(out, "ExcludeRoutes = 10.0.0.0/8, 192.168.5.10/32") {
		t.Errorf("writer output missing ExcludeRoutes line:\n%s", out)
	}
	if !strings.Contains(out, "SplitDNS = corp.mvideo.ru > 10.95.0.8, 10.95.0.9") {
		t.Errorf("writer output missing SplitDNS line:\n%s", out)
	}
	cfg2, err := FromWgQuick(out, "office")
	if err != nil {
		t.Fatalf("re-parse failed: %v", err)
	}
	if len(cfg2.Interface.ExcludeRoutes) != 2 || len(cfg2.Interface.SplitDNS) != 2 {
		t.Errorf("round trip lost fields: %d routes, %d dns rules", len(cfg2.Interface.ExcludeRoutes), len(cfg2.Interface.SplitDNS))
	}
}

func TestSplitTunnelRejectsBadInput(t *testing.T) {
	bad := []string{
		"ExcludeRoutes = not-an-ip",
		"SplitDNS = corp.example.com",             // no server
		"SplitDNS = corp.example.com > not-an-ip", // bad server
		"SplitDNS = > 10.0.0.1",                   // no domain
	}
	for _, line := range bad {
		input := "[Interface]\nPrivateKey = TFlmmEUC7V7VtiDYLKsbP5rySTKLIZq1yn8lMqK83wo=\n" + line + "\n"
		if _, err := FromWgQuick(input, "x"); err == nil {
			t.Errorf("expected error for %q", line)
		}
	}
}
