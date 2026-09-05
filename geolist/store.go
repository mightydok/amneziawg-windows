/* SPDX-License-Identifier: MIT
 *
 * Geo-split routing: settings, metadata and the on-disk list cache.
 */

package geolist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-windows/v3/conf"
)

const (
	dirName      = "geo"
	settingsFile = "settings.json"
	metaFile     = "meta.json"

	// DefaultCountry is the only country with an embedded snapshot.
	DefaultCountry = "ru"

	// Default list sources. A "%s" is replaced with the country code.
	DefaultSourceV4 = "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/%s/ipv4-aggregated.txt"
	DefaultSourceV6 = "https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/%s/ipv6-aggregated.txt"

	DefaultStaleHours  = 24
	DefaultMinPrefixV4 = 22

	// Sanity limits for downloaded lists.
	MinCountV4    = 2000
	MinCountV6    = 200
	MaxListBytes  = 4 << 20
	MaxCountDrift = 0.5
)

var countryRe = regexp.MustCompile(`^[a-z]{2}$`)

// ValidCountry reports whether s is a lowercase two-letter country code.
func ValidCountry(s string) bool {
	return countryRe.MatchString(s)
}

// Settings are the global geo-split settings written by the manager service.
type Settings struct {
	UpdateOnStart bool     `json:"update_on_start"`
	StaleHours    int      `json:"stale_hours"`
	MinPrefixV4   int      `json:"min_prefix_v4"`
	IPv6Mode      string   `json:"ipv6_mode"`
	PermitPrivate bool     `json:"permit_private"`
	AlwaysDirect  []string `json:"always_direct"`
	AlwaysTunnel  []string `json:"always_tunnel"`
	SourceV4      string   `json:"source_v4"`
	SourceV6      string   `json:"source_v6"`
}

// DefaultSettings returns the settings used when no file exists.
func DefaultSettings() Settings {
	return Settings{
		UpdateOnStart: true,
		StaleHours:    DefaultStaleHours,
		MinPrefixV4:   DefaultMinPrefixV4,
		IPv6Mode:      IPv6Direct,
		PermitPrivate: true,
		SourceV4:      DefaultSourceV4,
		SourceV6:      DefaultSourceV6,
	}
}

// Validate checks the settings.
func (s Settings) Validate() error {
	if s.StaleHours < 1 || s.StaleHours > 24*30 {
		return fmt.Errorf("stale hours must be between 1 and %d", 24*30)
	}
	if _, err := s.Policy(); err != nil {
		return err
	}
	for _, src := range []string{s.SourceV4, s.SourceV6} {
		if strings.TrimSpace(src) == "" {
			return errors.New("list source must not be empty")
		}
	}
	return nil
}

// Policy converts the settings into a Policy.
func (s Settings) Policy() (Policy, error) {
	direct, err := ParseAll(strings.Join(s.AlwaysDirect, ","))
	if err != nil {
		return Policy{}, fmt.Errorf("always direct: %w", err)
	}
	tunnel, err := ParseAll(strings.Join(s.AlwaysTunnel, ","))
	if err != nil {
		return Policy{}, fmt.Errorf("always tunnel: %w", err)
	}
	p := Policy{
		MinPrefixV4:  s.MinPrefixV4,
		IPv6Mode:     s.IPv6Mode,
		AlwaysDirect: direct,
		AlwaysTunnel: tunnel,
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// Source returns the list source for the family with the country substituted.
func (s Settings) Source(fam Family, country string) string {
	src := s.SourceV4
	if fam == IPv6 {
		src = s.SourceV6
	}
	if strings.Contains(src, "%s") {
		return fmt.Sprintf(src, country)
	}
	return src
}

// Meta describes the cached lists.
type Meta struct {
	Country     string    `json:"country"`
	SourceV4    string    `json:"source_v4"`
	SourceV6    string    `json:"source_v6"`
	FetchedAt   time.Time `json:"fetched_at"`
	SHA256V4    string    `json:"sha256_v4"`
	SHA256V6    string    `json:"sha256_v6"`
	CountV4     int       `json:"count_v4"`
	CountV6     int       `json:"count_v6"`
	LastAttempt time.Time `json:"last_attempt"`
	LastError   string    `json:"last_error"`
}

// IsStale reports whether the cache is older than staleHours or has never been fetched.
func (m Meta) IsStale(staleHours int, now time.Time) bool {
	if m.FetchedAt.IsZero() {
		return true
	}
	return now.Sub(m.FetchedAt) > time.Duration(staleHours)*time.Hour
}

// SourceKind says where Load got its lists from.
type SourceKind string

const (
	SourceCache    SourceKind = "cache"
	SourceEmbedded SourceKind = "embedded"
)

// Source describes the origin of loaded lists.
type Source struct {
	Kind      SourceKind
	FetchedAt time.Time
}

// Dir returns the geo cache directory under the protected Data directory, creating it.
func Dir() (string, error) {
	root, err := conf.RootDirectory(true)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, dirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

func listPath(dir, country string, fam Family) string {
	return filepath.Join(dir, fmt.Sprintf("%s-v%d.list", country, int(fam)))
}

// LoadSettings reads settings.json, filling missing fields with defaults.
func LoadSettings() (Settings, error) {
	dir, err := Dir()
	if err != nil {
		return DefaultSettings(), err
	}
	return loadSettingsFrom(dir)
}

func loadSettingsFrom(dir string) (Settings, error) {
	s := DefaultSettings()
	data, err := os.ReadFile(filepath.Join(dir, settingsFile))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return DefaultSettings(), fmt.Errorf("settings.json: %w", err)
	}
	if err := s.Validate(); err != nil {
		return DefaultSettings(), fmt.Errorf("settings.json: %w", err)
	}
	return s, nil
}

// Save validates and writes the settings atomically.
func (s Settings) Save() error {
	if err := s.Validate(); err != nil {
		return err
	}
	dir, err := Dir()
	if err != nil {
		return err
	}
	return s.saveTo(dir)
}

func (s Settings) saveTo(dir string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, settingsFile), data)
}

// LoadMeta reads meta.json; a missing file yields a zero Meta.
func LoadMeta() (Meta, error) {
	dir, err := Dir()
	if err != nil {
		return Meta{}, err
	}
	return loadMetaFrom(dir)
}

func loadMetaFrom(dir string) (Meta, error) {
	var m Meta
	data, err := os.ReadFile(filepath.Join(dir, metaFile))
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return Meta{}, fmt.Errorf("meta.json: %w", err)
	}
	return m, nil
}

// Save writes the metadata atomically.
func (m Meta) Save() error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	return m.saveTo(dir)
}

func (m Meta) saveTo(dir string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, metaFile), data)
}

// Load returns the parsed lists for the country. The cache is preferred; if either list
// is missing or unreadable the embedded snapshot is used.
func Load(country string) (list4, list6 []netip.Prefix, src Source, err error) {
	if !ValidCountry(country) {
		return nil, nil, Source{}, fmt.Errorf("invalid country code %q", country)
	}
	dir, dirErr := Dir()
	if dirErr == nil {
		list4, list6, src, err = loadFrom(dir, country)
		if err == nil {
			return list4, list6, src, nil
		}
	}
	e4, ok4 := embeddedList(country, IPv4)
	e6, ok6 := embeddedList(country, IPv6)
	if !ok4 || !ok6 {
		if dirErr != nil {
			return nil, nil, Source{}, fmt.Errorf("no cached list for %s (%v) and no embedded snapshot", country, dirErr)
		}
		return nil, nil, Source{}, fmt.Errorf("no cached list for %s (%v) and no embedded snapshot", country, err)
	}
	list4, err = Parse(e4, IPv4)
	if err != nil {
		return nil, nil, Source{}, fmt.Errorf("embedded %s IPv4 list: %w", country, err)
	}
	list6, err = Parse(e6, IPv6)
	if err != nil {
		return nil, nil, Source{}, fmt.Errorf("embedded %s IPv6 list: %w", country, err)
	}
	return list4, list6, Source{Kind: SourceEmbedded}, nil
}

func loadFrom(dir, country string) (list4, list6 []netip.Prefix, src Source, err error) {
	raw4, err := os.ReadFile(listPath(dir, country, IPv4))
	if err != nil {
		return nil, nil, Source{}, err
	}
	raw6, err := os.ReadFile(listPath(dir, country, IPv6))
	if err != nil {
		return nil, nil, Source{}, err
	}
	list4, err = Parse(raw4, IPv4)
	if err != nil {
		return nil, nil, Source{}, fmt.Errorf("cached IPv4 list: %w", err)
	}
	list6, err = Parse(raw6, IPv6)
	if err != nil {
		return nil, nil, Source{}, fmt.Errorf("cached IPv6 list: %w", err)
	}
	meta, _ := loadMetaFrom(dir)
	return list4, list6, Source{Kind: SourceCache, FetchedAt: meta.FetchedAt}, nil
}

// Validate parses a downloaded list and applies the sanity rules. previousCount is the
// count of the list being replaced; zero disables the drift check.
func Validate(raw []byte, fam Family, previousCount int) ([]netip.Prefix, error) {
	if len(raw) > MaxListBytes {
		return nil, fmt.Errorf("%s list is too large (%d bytes)", fam, len(raw))
	}
	list, err := Parse(raw, fam)
	if err != nil {
		return nil, fmt.Errorf("%s list: %w", fam, err)
	}
	minCount := MinCountV4
	if fam == IPv6 {
		minCount = MinCountV6
	}
	if len(list) < minCount {
		return nil, fmt.Errorf("%s list has only %d prefixes, expected at least %d", fam, len(list), minCount)
	}
	if previousCount > 0 {
		drift := float64(len(list)-previousCount) / float64(previousCount)
		if drift > MaxCountDrift || drift < -MaxCountDrift {
			return nil, fmt.Errorf("%s list changed from %d to %d prefixes, refusing to apply", fam, previousCount, len(list))
		}
	}
	return list, nil
}

// Store validates raw and writes it to the cache atomically. It returns the prefix
// count and the SHA-256 of the stored bytes.
func Store(country string, fam Family, raw []byte, previousCount int) (count int, sha string, err error) {
	dir, err := Dir()
	if err != nil {
		return 0, "", err
	}
	return storeTo(dir, country, fam, raw, previousCount)
}

func storeTo(dir, country string, fam Family, raw []byte, previousCount int) (count int, sha string, err error) {
	if !ValidCountry(country) {
		return 0, "", fmt.Errorf("invalid country code %q", country)
	}
	list, err := Validate(raw, fam, previousCount)
	if err != nil {
		return 0, "", err
	}
	if err := writeAtomic(listPath(dir, country, fam), raw); err != nil {
		return 0, "", err
	}
	sum := sha256.Sum256(raw)
	return len(list), hex.EncodeToString(sum[:]), nil
}

// SHA256Hex returns the hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
