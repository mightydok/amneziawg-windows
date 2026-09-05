/* SPDX-License-Identifier: MIT
 *
 * Geo-split routing: the GeoSplit configuration key.
 */

package conf

import (
	"strings"

	"github.com/amnezia-vpn/amneziawg-windows/v3/l18n"
)

// parseGeoSplit accepts a two-letter country code, or "off" / empty to disable.
func parseGeoSplit(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "off" {
		return "", nil
	}
	if len(s) != 2 || s[0] < 'a' || s[0] > 'z' || s[1] < 'a' || s[1] > 'z' {
		return "", &ParseError{l18n.Sprintf("Invalid geo-split country code"), s}
	}
	return s, nil
}
