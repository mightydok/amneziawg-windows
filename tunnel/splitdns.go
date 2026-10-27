/* SPDX-License-Identifier: MIT
 *
 * Office split-tunnel: split DNS through the Name Resolution Policy Table (NRPT).
 *
 * While the tunnel is up, the configured domain suffixes are resolved on the corporate
 * DNS servers instead of the tunnel's DNS. This writes the same local NRPT store that
 * Add-DnsClientNrptRule and other VPN clients use, under the Dnscache service parameters;
 * the DNS client watches that key and applies changes without a restart. The rules are
 * removed when the tunnel goes down, and stale rules from a crashed instance are swept on
 * the next bring-up.
 */

package tunnel

import (
	"fmt"
	"log"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	nrptBasePath   = `SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig`
	nrptKeyPrefix  = "AmneziaWG-SplitDNS-"
	nrptConfigOpts = 8 // use GenericDNSServers for the namespace
	nrptVersion    = 2
)

// nrptRulePrefix is the registry key name prefix for one tunnel's split-DNS rules.
func nrptRulePrefix(tunnelName string) string {
	return nrptKeyPrefix + strings.NewReplacer(`\`, "_", "/", "_").Replace(tunnelName) + "-"
}

// registerSplitDNS installs one NRPT rule per SplitDNS entry for the tunnel. Any previous
// rules for the same tunnel are removed first, so a re-bring-up is clean.
func registerSplitDNS(tunnelName string, rules []conf.SplitDNSRule) error {
	if len(rules) == 0 {
		return nil
	}
	removeSplitDNS(tunnelName)

	base, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBasePath, registry.CREATE_SUB_KEY)
	if err != nil {
		return fmt.Errorf("split DNS: opening NRPT store: %w", err)
	}
	defer base.Close()

	prefix := nrptRulePrefix(tunnelName)
	for i, rule := range rules {
		servers := make([]string, len(rule.Servers))
		for j, s := range rule.Servers {
			servers[j] = s.String()
		}
		name := fmt.Sprintf("%s%d", prefix, i)
		key, _, err := registry.CreateKey(base, name, registry.SET_VALUE)
		if err != nil {
			removeSplitDNS(tunnelName)
			return fmt.Errorf("split DNS: creating rule %q: %w", name, err)
		}
		err = writeNrptRule(key, "."+rule.Domain, servers)
		key.Close()
		if err != nil {
			removeSplitDNS(tunnelName)
			return fmt.Errorf("split DNS: writing rule for %q: %w", rule.Domain, err)
		}
		log.Printf("Split DNS: %s resolved on %s", rule.Domain, strings.Join(servers, ", "))
	}
	flushDNSResolverCache()
	return nil
}

func writeNrptRule(key registry.Key, namespace string, servers []string) error {
	if err := key.SetDWordValue("Version", nrptVersion); err != nil {
		return err
	}
	if err := key.SetDWordValue("ConfigOptions", nrptConfigOpts); err != nil {
		return err
	}
	if err := key.SetStringsValue("Name", []string{namespace}); err != nil {
		return err
	}
	return key.SetStringValue("GenericDNSServers", strings.Join(servers, ";"))
}

// removeSplitDNS deletes every NRPT rule this client created for the tunnel.
func removeSplitDNS(tunnelName string) {
	base, err := registry.OpenKey(registry.LOCAL_MACHINE, nrptBasePath, registry.ENUMERATE_SUB_KEYS|registry.SET_VALUE)
	if err != nil {
		return
	}
	defer base.Close()
	names, err := base.ReadSubKeyNames(-1)
	if err != nil {
		return
	}
	prefix := nrptRulePrefix(tunnelName)
	removed := false
	for _, name := range names {
		if strings.HasPrefix(name, prefix) {
			if err := registry.DeleteKey(base, name); err != nil {
				log.Printf("Split DNS: unable to remove rule %q: %v", name, err)
			} else {
				removed = true
			}
		}
	}
	if removed {
		flushDNSResolverCache()
	}
}

var dnsapiFlush = windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache")

// flushDNSResolverCache clears negatively cached internal names so new NRPT rules take
// effect immediately. Best effort: the export is undocumented but stable, and failure is
// harmless because the resolver consults the NRPT per query anyway.
func flushDNSResolverCache() {
	if err := dnsapiFlush.Find(); err != nil {
		return
	}
	dnsapiFlush.Call()
}
