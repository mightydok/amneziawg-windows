// Command fetchsnapshot downloads the default ipverse lists for a country into
// geolist/data so they can be embedded. Run via `go generate ./geolist`.
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: fetchsnapshot <country-code>")
		os.Exit(2)
	}
	country := os.Args[1]
	for _, fam := range []int{4, 6} {
		url := fmt.Sprintf("https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/%s/ipv%d-aggregated.txt", country, fam)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "%s: status %d err %v\n", url, resp.StatusCode, err)
			os.Exit(1)
		}
		out := filepath.Join("data", fmt.Sprintf("%s-v%d.txt", country, fam))
		if err := os.WriteFile(out, data, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (%d bytes)\n", out, len(data))
	}
}
