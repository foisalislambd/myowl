// Package geo resolves IP addresses to locations using a DB-IP / MaxMind
// compatible mmdb file (DB-IP "IP to City Lite" is free, CC-BY 4.0).
package geo

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"

	"github.com/myowl/myowl/agent/internal/model"
)

type record struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Resolver looks up IPs with an LRU-ish cache.
type Resolver struct {
	mu    sync.RWMutex
	db    *maxminddb.Reader
	path  string
	cache map[string]model.Geo
	// Fake is used in demo mode to fabricate locations.
	Fake func(ip string) model.Geo
}

// New opens path if it exists. A missing database is not an error.
func New(path string) *Resolver {
	r := &Resolver{path: path, cache: map[string]model.Geo{}}
	r.open()
	return r
}

func (r *Resolver) open() {
	if r.path == "" {
		return
	}
	db, err := maxminddb.Open(r.path)
	if err != nil {
		return
	}
	r.mu.Lock()
	if r.db != nil {
		r.db.Close()
	}
	r.db = db
	r.cache = map[string]model.Geo{}
	r.mu.Unlock()
}

// Available reports whether a database is loaded.
func (r *Resolver) Available() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.db != nil || r.Fake != nil
}

// Status returns a human readable status.
func (r *Resolver) Status() (string, string) {
	if r.Fake != nil {
		return "ok", "demo locations"
	}
	if r.Available() {
		return "ok", "using " + r.path
	}
	return "off", "no GeoIP database found at " + r.path + " (the world map needs it; it is downloaded automatically when internet access is available)"
}

var privateNets []*net.IPNet

func init() {
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
		"100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10", "0.0.0.0/8"} {
		_, n, _ := net.ParseCIDR(c)
		privateNets = append(privateNets, n)
	}
}

// IsPrivate reports whether ip is not publicly routable.
func IsPrivate(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return ip.IsUnspecified() || ip.IsMulticast()
}

// Lookup resolves an IP. Unknown IPs return a zero Geo.
func (r *Resolver) Lookup(ipStr string) model.Geo {
	if ipStr == "" {
		return model.Geo{}
	}
	r.mu.RLock()
	g, ok := r.cache[ipStr]
	db := r.db
	r.mu.RUnlock()
	if ok {
		return g
	}
	ip := net.ParseIP(ipStr)
	if IsPrivate(ip) {
		g = model.Geo{Private: true, Country: "Private network"}
	} else if r.Fake != nil {
		g = r.Fake(ipStr)
	} else if db != nil {
		var rec record
		if err := db.Lookup(ip, &rec); err == nil {
			g = model.Geo{CC: rec.Country.ISOCode, Country: rec.Country.Names["en"], City: rec.City.Names["en"],
				Lat: rec.Location.Latitude, Lon: rec.Location.Longitude}
		}
	}
	r.mu.Lock()
	if len(r.cache) > 50000 {
		r.cache = map[string]model.Geo{}
	}
	r.cache[ipStr] = g
	r.mu.Unlock()
	return g
}

// Label returns "City, Country" for explanations.
func (r *Resolver) Label(ip string) string {
	g := r.Lookup(ip)
	if g.Private {
		return "your private network"
	}
	switch {
	case g.City != "" && g.Country != "":
		return g.City + ", " + g.Country
	case g.Country != "":
		return g.Country
	}
	return ""
}

// AutoDownload fetches the free DB-IP City Lite database if missing.
func (r *Resolver) AutoDownload() {
	if r.path == "" || r.Available() {
		return
	}
	if err := Download(r.path); err != nil {
		log.Printf("geoip: download failed: %v", err)
		return
	}
	log.Printf("geoip: downloaded %s", r.path)
	r.open()
}

// Download fetches the current (or previous) month's DB-IP City Lite file.
func Download(dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	now := time.Now().UTC()
	var lastErr error
	for i := 0; i < 3; i++ {
		t := now.AddDate(0, -i, 0)
		url := fmt.Sprintf("https://download.db-ip.com/free/dbip-city-lite-%d-%02d.mmdb.gz", t.Year(), int(t.Month()))
		if err := fetch(url, dst); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return lastErr
}

func fetch(url, dst string) error {
	c := &http.Client{Timeout: 10 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, gz); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	if _, err := maxminddb.Open(tmp); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("downloaded file is not a valid mmdb: %w", err)
	}
	return os.Rename(tmp, dst)
}
