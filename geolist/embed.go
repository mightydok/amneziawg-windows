/* SPDX-License-Identifier: MIT
 *
 * Geo-split routing: snapshot lists compiled into the binary.
 */

package geolist

import (
	"embed"
	"fmt"
)

// Snapshot lists are refreshed before a release with `go generate ./geolist` and are
// used when no downloaded list exists yet or the cache cannot be read.
//
//go:generate go run ./internal/fetchsnapshot ru
//go:embed data/*.txt
var embedded embed.FS

func embeddedList(country string, fam Family) ([]byte, bool) {
	name := fmt.Sprintf("data/%s-v%d.txt", country, int(fam))
	data, err := embedded.ReadFile(name)
	if err != nil {
		return nil, false
	}
	return data, true
}
