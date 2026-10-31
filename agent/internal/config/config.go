// Package config loads the YAML configuration file.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// AccessLog is one web-server access log to tail.
type AccessLog struct {
	Path   string `yaml:"path" json:"path"`
	Format string `yaml:"format" json:"format"` // auto | combined | common | json
	Name   string `yaml:"name" json:"name"`
}

// Config is the full configuration.
type Config struct {
	Listen       string `yaml:"listen"`
	DataDir      string `yaml:"data_dir"`
	CookieSecure bool   `yaml:"cookie_secure"`
	TrustProxy   bool   `yaml:"trust_proxy"`
	TLS          struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
	Retention struct {
		Days        int `yaml:"days"`
		MaxRequests int `yaml:"max_requests"`
	} `yaml:"retention"`
	Intervals struct {
		SystemSec   int `yaml:"system_sec"`
		NetworkSec  int `yaml:"network_sec"`
		SessionsSec int `yaml:"sessions_sec"`
	} `yaml:"intervals"`
	AccessLogs []AccessLog `yaml:"access_logs"`
	AuthLogs   []string    `yaml:"auth_logs"`
	KernelLogs []string    `yaml:"kernel_logs"`
	Journald   string      `yaml:"journald"` // auto | on | off
	Backfill   int         `yaml:"backfill_lines"`
	GeoIP      struct {
		Path         string `yaml:"path"`
		AutoDownload bool   `yaml:"auto_download"`
	} `yaml:"geoip"`
	ServerLocation struct {
		Lat  float64 `yaml:"lat"`
		Lon  float64 `yaml:"lon"`
		City string  `yaml:"city"`
	} `yaml:"server_location"`
	Capture struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"capture"`
	Firewall struct {
		Enabled      bool     `yaml:"enabled"`
		Backend      string   `yaml:"backend"` // auto | ufw | nftables | iptables
		Whitelist    []string `yaml:"whitelist"`
		AllowPrivate bool     `yaml:"allow_private"`
	} `yaml:"firewall"`
	Detection struct {
		SSHFailThreshold  int      `yaml:"ssh_fail_threshold"`
		SSHWindowMin      int      `yaml:"ssh_window_min"`
		ReqRatePerMin     int      `yaml:"request_rate_per_min"`
		NotFoundThreshold int      `yaml:"not_found_threshold"`
		PortScanPorts     int      `yaml:"port_scan_ports"`
		PortScanWindowSec int      `yaml:"port_scan_window_sec"`
		IgnorePaths       []string `yaml:"ignore_paths"`
		IgnoreIPs         []string `yaml:"ignore_ips"`
	} `yaml:"detection"`
	Notify struct {
		Webhook struct {
			URL     string            `yaml:"url"`
			Headers map[string]string `yaml:"headers"`
		} `yaml:"webhook"`
		Telegram struct {
			BotToken string `yaml:"bot_token"`
			ChatID   string `yaml:"chat_id"`
		} `yaml:"telegram"`
		SMTP struct {
			Host     string   `yaml:"host"`
			Port     int      `yaml:"port"`
			Username string   `yaml:"username"`
			Password string   `yaml:"password"`
			From     string   `yaml:"from"`
			To       []string `yaml:"to"`
		} `yaml:"smtp"`
	} `yaml:"notify"`

	// Runtime only.
	Demo bool   `yaml:"-"`
	Path string `yaml:"-"`
}

// Default returns a configuration with sane defaults.
func Default() *Config {
	c := &Config{}
	c.Listen = "0.0.0.0:8787"
	c.DataDir = "/var/lib/myowl"
	c.Retention.Days = 14
	c.Retention.MaxRequests = 500000
	c.Intervals.SystemSec = 2
	c.Intervals.NetworkSec = 2
	c.Intervals.SessionsSec = 10
	c.AccessLogs = []AccessLog{
		{Path: "/var/log/nginx/access.log", Format: "auto", Name: "nginx"},
		{Path: "/var/log/apache2/access.log", Format: "auto", Name: "apache"},
		{Path: "/var/log/httpd/access_log", Format: "auto", Name: "apache"},
		{Path: "/var/log/caddy/access.log", Format: "json", Name: "caddy"},
	}
	c.AuthLogs = []string{"/var/log/auth.log", "/var/log/secure"}
	c.KernelLogs = []string{"/var/log/ufw.log", "/var/log/kern.log"}
	c.Journald = "auto"
	c.Backfill = 500
	c.GeoIP.Path = "/var/lib/myowl/dbip-city-lite.mmdb"
	c.GeoIP.AutoDownload = true
	c.Capture.Enabled = true
	c.Firewall.Enabled = true
	c.Firewall.Backend = "auto"
	c.Detection.SSHFailThreshold = 5
	c.Detection.SSHWindowMin = 10
	c.Detection.ReqRatePerMin = 300
	c.Detection.NotFoundThreshold = 30
	c.Detection.PortScanPorts = 12
	c.Detection.PortScanWindowSec = 60
	c.Notify.SMTP.Port = 587
	return c
}

// Load reads a YAML file on top of the defaults. A missing file is not an
// error: defaults are returned and missing=true.
func Load(path string) (c *Config, missing bool, err error) {
	c = Default()
	c.Path = path
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, true, nil
		}
		return nil, false, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	c.Path = path
	c.fill()
	return c, false, nil
}

func (c *Config) fill() {
	d := Default()
	if c.Listen == "" {
		c.Listen = d.Listen
	}
	if c.DataDir == "" {
		c.DataDir = d.DataDir
	}
	if c.Retention.Days <= 0 {
		c.Retention.Days = d.Retention.Days
	}
	if c.Retention.MaxRequests <= 0 {
		c.Retention.MaxRequests = d.Retention.MaxRequests
	}
	if c.Intervals.SystemSec <= 0 {
		c.Intervals.SystemSec = d.Intervals.SystemSec
	}
	if c.Intervals.NetworkSec <= 0 {
		c.Intervals.NetworkSec = d.Intervals.NetworkSec
	}
	if c.Intervals.SessionsSec <= 0 {
		c.Intervals.SessionsSec = d.Intervals.SessionsSec
	}
	if c.Journald == "" {
		c.Journald = "auto"
	}
	if c.Firewall.Backend == "" {
		c.Firewall.Backend = "auto"
	}
	det := &c.Detection
	if det.SSHFailThreshold <= 0 {
		det.SSHFailThreshold = d.Detection.SSHFailThreshold
	}
	if det.SSHWindowMin <= 0 {
		det.SSHWindowMin = d.Detection.SSHWindowMin
	}
	if det.ReqRatePerMin <= 0 {
		det.ReqRatePerMin = d.Detection.ReqRatePerMin
	}
	if det.NotFoundThreshold <= 0 {
		det.NotFoundThreshold = d.Detection.NotFoundThreshold
	}
	if det.PortScanPorts <= 0 {
		det.PortScanPorts = d.Detection.PortScanPorts
	}
	if det.PortScanWindowSec <= 0 {
		det.PortScanWindowSec = d.Detection.PortScanWindowSec
	}
	if c.Notify.SMTP.Port == 0 {
		c.Notify.SMTP.Port = 587
	}
	for i := range c.AccessLogs {
		if c.AccessLogs[i].Format == "" {
			c.AccessLogs[i].Format = "auto"
		}
	}
}

// TLSEnabled reports whether built-in TLS is configured.
func (c *Config) TLSEnabled() bool { return c.TLS.Cert != "" && c.TLS.Key != "" }
