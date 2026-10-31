// Package model contains the data types shared between collectors, the
// engine, storage and the HTTP API.
package model

// CPU usage summary.
type CPU struct {
	Usage   float64   `json:"usage"`
	PerCore []float64 `json:"per_core"`
	Cores   int       `json:"cores"`
	Model   string    `json:"model"`
	IOWait  float64   `json:"iowait"`
	Steal   float64   `json:"steal"`
}

// Memory usage summary (bytes).
type Memory struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Available   uint64  `json:"available"`
	Cached      uint64  `json:"cached"`
	Buffers     uint64  `json:"buffers"`
	Percent     float64 `json:"percent"`
	SwapTotal   uint64  `json:"swap_total"`
	SwapUsed    uint64  `json:"swap_used"`
	SwapPercent float64 `json:"swap_percent"`
}

// Disk is one mounted filesystem.
type Disk struct {
	Mount         string  `json:"mount"`
	Device        string  `json:"device"`
	FSType        string  `json:"fstype"`
	Total         uint64  `json:"total"`
	Used          uint64  `json:"used"`
	Free          uint64  `json:"free"`
	Percent       float64 `json:"percent"`
	InodesPercent float64 `json:"inodes_percent"`
}

// DiskIO throughput in bytes/sec.
type DiskIO struct {
	ReadBps  float64 `json:"read_bps"`
	WriteBps float64 `json:"write_bps"`
}

// Process is a running process.
type Process struct {
	PID        int     `json:"pid"`
	Name       string  `json:"name"`
	User       string  `json:"user"`
	Cmd        string  `json:"cmd"`
	CPU        float64 `json:"cpu"`
	MemRSS     uint64  `json:"mem_rss"`
	MemPercent float64 `json:"mem_percent"`
	State      string  `json:"state"`
	Threads    int     `json:"threads"`
	Started    int64   `json:"started"`
}

// Service is a systemd unit.
type Service struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Load        string `json:"load"`
	Active      string `json:"active"`
	Sub         string `json:"sub"`
}

// HealthMsg is a plain-language health statement.
type HealthMsg struct {
	Level string `json:"level"` // good | warn | bad
	Area  string `json:"area"`
	Text  string `json:"text"`
}

// Health is an overall plain-language verdict.
type Health struct {
	Score    int         `json:"score"`
	Level    string      `json:"level"`
	Summary  string      `json:"summary"`
	Messages []HealthMsg `json:"messages"`
}

// SystemSnapshot is the full system view at a point in time.
type SystemSnapshot struct {
	TS                int64      `json:"ts"`
	Hostname          string     `json:"hostname"`
	OS                string     `json:"os"`
	Kernel            string     `json:"kernel"`
	Arch              string     `json:"arch"`
	Uptime            int64      `json:"uptime"`
	BootTime          int64      `json:"boot_time"`
	CPU               CPU        `json:"cpu"`
	Memory            Memory     `json:"memory"`
	Load              [3]float64 `json:"load"`
	Disks             []Disk     `json:"disks"`
	DiskIO            DiskIO     `json:"disk_io"`
	Processes         []Process  `json:"processes"`
	ProcCount         int        `json:"proc_count"`
	Services          []Service  `json:"services"`
	ServicesAvailable bool       `json:"services_available"`
	ServicesMessage   string     `json:"services_message,omitempty"`
}

// Interface is a network interface with its throughput.
type Interface struct {
	Name      string   `json:"name"`
	RxBps     float64  `json:"rx_bps"`
	TxBps     float64  `json:"tx_bps"`
	RxBytes   uint64   `json:"rx_bytes"`
	TxBytes   uint64   `json:"tx_bytes"`
	RxPackets uint64   `json:"rx_packets"`
	TxPackets uint64   `json:"tx_packets"`
	RxErrors  uint64   `json:"rx_errors"`
	TxErrors  uint64   `json:"tx_errors"`
	Up        bool     `json:"up"`
	Addrs     []string `json:"addrs"`
	MAC       string   `json:"mac"`
}

// Geo describes where an IP address is.
type Geo struct {
	Country string  `json:"country,omitempty"`
	CC      string  `json:"cc,omitempty"`
	City    string  `json:"city,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lon     float64 `json:"lon,omitempty"`
	Private bool    `json:"private,omitempty"`
}

// Conn is a single socket.
type Conn struct {
	Proto      string  `json:"proto"`
	State      string  `json:"state"`
	LocalIP    string  `json:"local_ip"`
	LocalPort  int     `json:"local_port"`
	RemoteIP   string  `json:"remote_ip"`
	RemotePort int     `json:"remote_port"`
	PID        int     `json:"pid"`
	Process    string  `json:"process"`
	User       string  `json:"user"`
	BytesSent  uint64  `json:"bytes_sent"`
	BytesRecv  uint64  `json:"bytes_recv"`
	RTTms      float64 `json:"rtt_ms"`
	Direction  string  `json:"direction"` // in | out | local
	Inode      uint64  `json:"-"`
	Geo        Geo     `json:"geo"`
}

// Listener is an open (listening) port.
type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid"`
	Process string `json:"process"`
	User    string `json:"user"`
	Public  bool   `json:"public"`
	Service string `json:"service"`
	Conns   int    `json:"conns"`
	Risk    string `json:"risk,omitempty"`
}

// Talker is a remote IP aggregated across connections.
type Talker struct {
	IP        string   `json:"ip"`
	Conns     int      `json:"conns"`
	BytesIn   uint64   `json:"bytes_in"`
	BytesOut  uint64   `json:"bytes_out"`
	RateIn    float64  `json:"rate_in"`
	RateOut   float64  `json:"rate_out"`
	Processes []string `json:"processes"`
	Ports     []int    `json:"ports"`
	Direction string   `json:"direction"`
	Geo       Geo      `json:"geo"`
	Threat    bool     `json:"threat"`
	Blocked   bool     `json:"blocked"`
}

// GeoPoint aggregates traffic per location for the world map.
type GeoPoint struct {
	Lat     float64  `json:"lat"`
	Lon     float64  `json:"lon"`
	Country string   `json:"country"`
	CC      string   `json:"cc"`
	City    string   `json:"city"`
	IPs     []string `json:"ips"`
	Conns   int      `json:"conns"`
	Rate    float64  `json:"rate"`
	Threat  bool     `json:"threat"`
}

// CountryStat aggregates per country.
type CountryStat struct {
	CC      string  `json:"cc"`
	Country string  `json:"country"`
	IPs     int     `json:"ips"`
	Conns   int     `json:"conns"`
	Rate    float64 `json:"rate"`
}

// NetworkSnapshot is the full network view.
type NetworkSnapshot struct {
	TS          int64          `json:"ts"`
	Interfaces  []Interface    `json:"interfaces"`
	TotalRxBps  float64        `json:"total_rx_bps"`
	TotalTxBps  float64        `json:"total_tx_bps"`
	Connections []Conn         `json:"connections"`
	Listeners   []Listener     `json:"listeners"`
	Talkers     []Talker       `json:"talkers"`
	Geo         []GeoPoint     `json:"geo"`
	Countries   []CountryStat  `json:"countries"`
	ConnCount   int            `json:"conn_count"`
	StateCounts map[string]int `json:"state_counts"`
	Server      *Geo           `json:"server,omitempty"`
	Source      string         `json:"source"` // netlink | procfs | demo
	Capture     string         `json:"capture"`
}

// HTTPRequest is one parsed access-log line.
type HTTPRequest struct {
	ID        int64    `json:"id"`
	TS        int64    `json:"ts"`
	IP        string   `json:"ip"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Query     string   `json:"query"`
	Proto     string   `json:"proto"`
	Status    int      `json:"status"`
	Bytes     int64    `json:"bytes"`
	UA        string   `json:"ua"`
	Referer   string   `json:"referer"`
	Host      string   `json:"host"`
	LatencyMs float64  `json:"latency_ms"` // -1 when unknown
	Source    string   `json:"source"`
	Flags     []string `json:"flags"`
	User      string   `json:"user"`
	Raw       string   `json:"raw"`
	Geo       Geo      `json:"geo"`
}

// Severity levels.
const (
	SevInfo     = "info"
	SevLow      = "low"
	SevMedium   = "medium"
	SevHigh     = "high"
	SevCritical = "critical"
)

// SeverityRank orders severities.
func SeverityRank(s string) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}

// Threat is a detected security event.
type Threat struct {
	ID          int64          `json:"id"`
	TS          int64          `json:"ts"`
	LastSeen    int64          `json:"last_seen"`
	IP          string         `json:"ip"`
	Type        string         `json:"type"`
	Severity    string         `json:"severity"`
	Title       string         `json:"title"`
	Explanation string         `json:"explanation"`
	Advice      string         `json:"advice"`
	Count       int            `json:"count"`
	Details     map[string]any `json:"details"`
	Acked       bool           `json:"acked"`
	Blocked     bool           `json:"blocked"`
	Geo         Geo            `json:"geo"`
}

// AuthEvent kinds.
const (
	AuthSSHFailed   = "ssh_failed"
	AuthSSHInvalid  = "ssh_invalid_user"
	AuthSSHAccepted = "ssh_accepted"
	AuthSudo        = "sudo"
	AuthSudoFailed  = "sudo_failed"
	AuthSu          = "su"
)

// AuthEvent is a parsed authentication log line.
type AuthEvent struct {
	ID      int64  `json:"id"`
	TS      int64  `json:"ts"`
	Kind    string `json:"kind"`
	User    string `json:"user"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	Method  string `json:"method"`
	TTY     string `json:"tty"`
	Command string `json:"command"`
	RunAs   string `json:"run_as"`
	Raw     string `json:"raw"`
	Geo     Geo    `json:"geo"`
}

// FirewallEvent is a packet logged by the kernel firewall (e.g. UFW BLOCK).
type FirewallEvent struct {
	TS    int64  `json:"ts"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Proto string `json:"proto"`
	DPort int    `json:"dport"`
	SYN   bool   `json:"syn"`
}

// LoginSession is a currently logged-in user.
type LoginSession struct {
	User      string `json:"user"`
	TTY       string `json:"tty"`
	Host      string `json:"host"`
	LoginTime int64  `json:"login_time"`
	PID       int    `json:"pid"`
	Geo       Geo    `json:"geo"`
}

// LoginRecord is a historic login.
type LoginRecord struct {
	User   string `json:"user"`
	TTY    string `json:"tty"`
	Host   string `json:"host"`
	Login  int64  `json:"login"`
	Logout int64  `json:"logout"` // 0 = still logged in, -1 = unknown/crash
	Kind   string `json:"kind"`   // user | reboot
	Geo    Geo    `json:"geo"`
}

// SessionsSnapshot is the sessions page data.
type SessionsSnapshot struct {
	TS      int64          `json:"ts"`
	Current []LoginSession `json:"current"`
	History []LoginRecord  `json:"history"`
	Source  string         `json:"source"`
	Message string         `json:"message,omitempty"`
}

// AlertRule is a configurable alert condition.
type AlertRule struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"` // metric | threat | login | service
	Metric    string   `json:"metric"`
	Op        string   `json:"op"`
	Threshold float64  `json:"threshold"`
	Duration  int      `json:"duration"` // seconds condition must hold
	Severity  string   `json:"severity"` // minimum threat severity / alert severity
	Channels  []string `json:"channels"`
	Cooldown  int      `json:"cooldown"` // minutes
	Enabled   bool     `json:"enabled"`
}

// AlertEvent is a fired alert.
type AlertEvent struct {
	ID        int64  `json:"id"`
	TS        int64  `json:"ts"`
	RuleID    int64  `json:"rule_id"`
	RuleName  string `json:"rule_name"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	Delivered string `json:"delivered"`
}

// BlockedIP is an IP blocked through the firewall integration.
type BlockedIP struct {
	IP      string `json:"ip"`
	TS      int64  `json:"ts"`
	Reason  string `json:"reason"`
	Backend string `json:"backend"`
	Geo     Geo    `json:"geo"`
}

// CollectorStatus describes whether a data source works.
type CollectorStatus struct {
	Name    string `json:"name"`
	Label   string `json:"label"`
	State   string `json:"state"` // ok | degraded | off
	Message string `json:"message"`
}

// MetricPoint is one stored history sample.
type MetricPoint struct {
	TS    int64   `json:"ts"`
	CPU   float64 `json:"cpu"`
	Mem   float64 `json:"mem"`
	Swap  float64 `json:"swap"`
	Disk  float64 `json:"disk"`
	Load1 float64 `json:"load1"`
	Rx    float64 `json:"rx"`
	Tx    float64 `json:"tx"`
	Conns float64 `json:"conns"`
	Reqs  float64 `json:"reqs"`
}
