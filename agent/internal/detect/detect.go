package detect

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/myowl/myowl/agent/internal/model"
)

// Config holds detector thresholds.
type Config struct {
	SSHFailThreshold  int
	SSHWindow         time.Duration
	ReqRatePerMin     int
	NotFoundThreshold int
	PortScanPorts     int
	PortScanWindow    time.Duration
	IgnorePaths       []string
	IgnoreIPs         []string
}

// DefaultConfig returns default thresholds.
func DefaultConfig() Config {
	return Config{SSHFailThreshold: 5, SSHWindow: 10 * time.Minute, ReqRatePerMin: 300,
		NotFoundThreshold: 30, PortScanPorts: 12, PortScanWindow: time.Minute}
}

// Finding is a threat produced by a detector. Key groups repeated findings
// into a single threat (e.g. "ssh_bruteforce|1.2.3.4").
type Finding struct {
	Key    string
	Threat model.Threat
	// Update means "refresh counters of an existing threat" and should not
	// trigger a new alert on its own.
	Update bool
}

type window struct {
	times []int64
	extra map[string]int
	last  int64
	level int // last emitted threshold index
}

func (w *window) add(ts int64, span int64) {
	w.times = append(w.times, ts)
	w.prune(ts, span)
	w.last = ts
}

func (w *window) prune(now, span int64) {
	cut := 0
	for cut < len(w.times) && w.times[cut] < now-span {
		cut++
	}
	if cut > 0 {
		w.times = append(w.times[:0], w.times[cut:]...)
	}
}

// Detector holds sliding-window state for all detectors.
type Detector struct {
	mu  sync.Mutex
	cfg Config
	// GeoName optionally returns a "City, Country" label for an IP.
	GeoName func(ip string) string

	sshFails   map[string]*window
	sshHistory map[string]int64 // ip -> last failure ts (for success-after-failure)
	knownLogin map[string]bool  // user|ip seen before
	reqFlags   map[string]*window
	reqRate    map[string]*window
	notFound   map[string]*window
	portScan   map[string]*window
	synRecv    map[string]*window
	ignoreNets []*net.IPNet

	minuteStart int64
	minuteCount int
	baseline    float64
	spikeLast   int64
}

// New creates a detector.
func New(cfg Config) *Detector {
	d := &Detector{cfg: cfg,
		sshFails: map[string]*window{}, sshHistory: map[string]int64{}, knownLogin: map[string]bool{},
		reqFlags: map[string]*window{}, reqRate: map[string]*window{}, notFound: map[string]*window{},
		portScan: map[string]*window{}, synRecv: map[string]*window{}}
	for _, s := range cfg.IgnoreIPs {
		if !strings.Contains(s, "/") {
			if strings.Contains(s, ":") {
				s += "/128"
			} else {
				s += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			d.ignoreNets = append(d.ignoreNets, n)
		}
	}
	return d
}

func (d *Detector) ignored(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range d.ignoreNets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

func (d *Detector) where(ip string) string {
	if d.GeoName != nil {
		if g := d.GeoName(ip); g != "" {
			return ip + " (" + g + ")"
		}
	}
	return ip
}

func get(m map[string]*window, k string) *window {
	w := m[k]
	if w == nil {
		w = &window{extra: map[string]int{}}
		m[k] = w
	}
	return w
}

func humanDur(d time.Duration) string {
	m := int(d.Minutes())
	switch {
	case m <= 1:
		return "1 minute"
	case m < 60:
		return fmt.Sprintf("%d minutes", m)
	case m == 60:
		return "1 hour"
	}
	return fmt.Sprintf("%d hours", m/60)
}

func topKeys(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	sort.Slice(arr, func(i, j int) bool {
		if arr[i].v == arr[j].v {
			return arr[i].k < arr[j].k
		}
		return arr[i].v > arr[j].v
	})
	var out []string
	for i := 0; i < len(arr) && i < n; i++ {
		out = append(out, arr[i].k)
	}
	return out
}

// levelFor returns index of the highest threshold reached (-1 if none).
func levelFor(n int, thresholds []int) int {
	lvl := -1
	for i, t := range thresholds {
		if n >= t {
			lvl = i
		}
	}
	return lvl
}

// OnAuth analyses an authentication event.
func (d *Detector) OnAuth(ev *model.AuthEvent) []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	if ev.IP != "" && d.ignored(ev.IP) {
		return nil
	}
	var out []Finding
	span := d.cfg.SSHWindow.Milliseconds()
	switch ev.Kind {
	case model.AuthSSHFailed, model.AuthSSHInvalid:
		if ev.IP == "" || ev.Method == "probe" {
			// "Invalid user" probe lines precede the actual failure line.
			if ev.IP != "" && ev.Method == "probe" {
				w := get(d.sshFails, ev.IP)
				w.extra[ev.User]++
			}
			return nil
		}
		w := get(d.sshFails, ev.IP)
		w.add(ev.TS, span)
		w.extra[ev.User]++
		d.sshHistory[ev.IP] = ev.TS
		n := len(w.times)
		th := []int{d.cfg.SSHFailThreshold, d.cfg.SSHFailThreshold * 4, d.cfg.SSHFailThreshold * 20, d.cfg.SSHFailThreshold * 100}
		sev := []string{model.SevLow, model.SevMedium, model.SevHigh, model.SevCritical}
		lvl := levelFor(n, th)
		if lvl >= 0 && lvl+1 > w.level {
			w.level = lvl + 1
			users := topKeys(w.extra, 4)
			out = append(out, Finding{Key: "ssh_bruteforce|" + ev.IP, Threat: model.Threat{
				TS: ev.TS, LastSeen: ev.TS, IP: ev.IP, Type: "ssh_bruteforce", Severity: sev[lvl],
				Title: "SSH password guessing (brute force)",
				Explanation: fmt.Sprintf("Someone from %s tried %d wrong SSH passwords in %s, using usernames like %s.",
					d.where(ev.IP), n, humanDur(d.cfg.SSHWindow), strings.Join(users, ", ")),
				Advice:  "This is an automated attack trying to guess your login. Use SSH keys instead of passwords, disable root login, and block this IP (or install fail2ban).",
				Count:   n,
				Details: map[string]any{"usernames": users, "window_minutes": int(d.cfg.SSHWindow.Minutes()), "last_port": ev.Port},
			}})
		} else if lvl >= 0 {
			// keep counters fresh on the existing threat
			out = append(out, Finding{Key: "ssh_bruteforce|" + ev.IP, Threat: model.Threat{
				TS: ev.TS, LastSeen: ev.TS, IP: ev.IP, Type: "ssh_bruteforce", Severity: sev[w.level-1],
				Title: "SSH password guessing (brute force)",
				Explanation: fmt.Sprintf("Someone from %s tried %d wrong SSH passwords in %s, using usernames like %s.",
					d.where(ev.IP), n, humanDur(d.cfg.SSHWindow), strings.Join(topKeys(w.extra, 4), ", ")),
				Advice: "This is an automated attack trying to guess your login. Use SSH keys instead of passwords, disable root login, and block this IP (or install fail2ban).",
				Count:  n, Details: map[string]any{"usernames": topKeys(w.extra, 4), "window_minutes": int(d.cfg.SSHWindow.Minutes()), "last_port": ev.Port},
			}, Update: true})
		}
	case model.AuthSSHAccepted:
		key := ev.User + "|" + ev.IP
		if lastFail, ok := d.sshHistory[ev.IP]; ok && ev.TS-lastFail < time.Hour.Milliseconds() {
			fails := 0
			if w := d.sshFails[ev.IP]; w != nil {
				fails = len(w.times)
			}
			if fails >= d.cfg.SSHFailThreshold {
				out = append(out, Finding{Key: "ssh_success_after_fail|" + ev.IP + "|" + ev.User, Threat: model.Threat{
					TS: ev.TS, LastSeen: ev.TS, IP: ev.IP, Type: "ssh_success_after_fail", Severity: model.SevCritical,
					Title: "Successful login after many failed attempts",
					Explanation: fmt.Sprintf("%s logged in as \"%s\" over SSH right after %d failed password attempts from the same address. This could mean a password was guessed.",
						d.where(ev.IP), ev.User, fails),
					Advice: "If this was not you or a teammate, change the password immediately, check running processes and logged-in sessions, and block the IP.",
					Count:  1, Details: map[string]any{"user": ev.User, "method": ev.Method, "previous_failures": fails},
				}})
			}
		}
		if !d.knownLogin[key] {
			d.knownLogin[key] = true
			sev := model.SevInfo
			if ev.User == "root" {
				sev = model.SevLow
			}
			out = append(out, Finding{Key: "ssh_login|" + key, Threat: model.Threat{
				TS: ev.TS, LastSeen: ev.TS, IP: ev.IP, Type: "ssh_login", Severity: sev,
				Title:       "SSH login from a new address",
				Explanation: fmt.Sprintf("User \"%s\" logged in over SSH from %s using %s. This address has not been seen for this user since monitoring started.", ev.User, d.where(ev.IP), ev.Method),
				Advice:      "If you recognise this login, no action is needed.",
				Count:       1, Details: map[string]any{"user": ev.User, "method": ev.Method},
			}})
		}
	case model.AuthSudoFailed:
		out = append(out, Finding{Key: "sudo_failed|" + ev.User, Threat: model.Threat{
			TS: ev.TS, LastSeen: ev.TS, Type: "sudo_failed", Severity: model.SevMedium,
			Title:       "Failed attempt to gain admin rights (sudo)",
			Explanation: fmt.Sprintf("User \"%s\" tried to run \"%s\" as %s but was refused (%s).", ev.User, ev.Command, ev.RunAs, ev.Method),
			Advice:      "Usually a mistyped password. If this user should not be using sudo, investigate.",
			Count:       1, Details: map[string]any{"user": ev.User, "command": ev.Command, "tty": ev.TTY},
		}})
	}
	return out
}

// OnRequest classifies a request (filling r.Flags) and runs request detectors.
func (d *Detector) OnRequest(r *model.HTTPRequest) []Finding {
	for _, p := range d.cfg.IgnorePaths {
		if strings.HasPrefix(r.Path, p) {
			return nil
		}
	}
	r.Flags = ClassifyRequest(r)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ignored(r.IP) {
		r.Flags = nil
		return nil
	}
	var out []Finding
	sample := r.Method + " " + r.Path
	if r.Query != "" {
		sample += "?" + r.Query
	}
	if len(sample) > 200 {
		sample = sample[:200] + "…"
	}
	for _, f := range r.Flags {
		info := Flags[f]
		w := get(d.reqFlags, f+"|"+r.IP)
		w.add(r.TS, (30 * time.Minute).Milliseconds())
		w.extra[r.Path]++
		if r.Status >= 200 && r.Status < 300 {
			w.extra["__ok"]++
		}
		n := len(w.times)
		sev := info.Severity
		if f == FlagScanner && len(withoutOK(w.extra)) > 20 {
			sev = model.SevMedium
		}
		if n >= 50 && model.SeverityRank(sev) < 3 {
			sev = bump(sev)
		}
		expl := fmt.Sprintf("Someone from %s %s. Example: %s", d.where(r.IP), fmt.Sprintf(info.Explain, n), sample)
		if ok := w.extra["__ok"]; ok > 0 && f != FlagScanner {
			expl += fmt.Sprintf(" — %d of these got a successful (2xx) response, so check those pages.", ok)
			if model.SeverityRank(sev) < 3 {
				sev = model.SevHigh
			}
		}
		out = append(out, Finding{Key: "http_" + f + "|" + r.IP, Threat: model.Threat{
			TS: r.TS, LastSeen: r.TS, IP: r.IP, Type: "http_" + f, Severity: sev, Title: info.Title,
			Explanation: expl, Advice: info.Advice, Count: n,
			Details: map[string]any{"example": sample, "status": r.Status, "user_agent": r.UA, "paths": topKeys(withoutOK(w.extra), 8)},
		}})
	}
	// Per-IP request rate.
	rw := get(d.reqRate, r.IP)
	rw.add(r.TS, time.Minute.Milliseconds())
	if n := len(rw.times); n >= d.cfg.ReqRatePerMin {
		lvl := levelFor(n, []int{d.cfg.ReqRatePerMin, d.cfg.ReqRatePerMin * 3, d.cfg.ReqRatePerMin * 10})
		if lvl+1 > rw.level || int(r.TS/1000)-rw.extra["__emit"] >= 60 {
			rw.level = lvl + 1
			rw.extra["__emit"] = int(r.TS / 1000)
			sev := []string{model.SevMedium, model.SevHigh, model.SevCritical}[lvl]
			out = append(out, Finding{Key: "http_flood|" + r.IP, Threat: model.Threat{
				TS: r.TS, LastSeen: r.TS, IP: r.IP, Type: "http_flood", Severity: sev,
				Title:       "Request flood from one address",
				Explanation: fmt.Sprintf("%s sent %d requests in the last minute — far more than a normal visitor. This could be an aggressive bot, a scraper or a denial-of-service attempt.", d.where(r.IP), n),
				Advice:      "If this is not a known service (uptime monitor, your own API client), consider blocking or rate-limiting it in your web server.",
				Count:       n, Details: map[string]any{"requests_per_minute": n, "user_agent": r.UA},
			}})
		}
	}
	// 404 probing.
	if r.Status == 404 {
		nw := get(d.notFound, r.IP)
		nw.add(r.TS, (5 * time.Minute).Milliseconds())
		nw.extra[r.Path]++
		n := len(nw.times)
		lvl := levelFor(n, []int{d.cfg.NotFoundThreshold, d.cfg.NotFoundThreshold * 5})
		if lvl >= 0 && lvl+1 > nw.level {
			nw.level = lvl + 1
			out = append(out, Finding{Key: "http_probing|" + r.IP, Threat: model.Threat{
				TS: r.TS, LastSeen: r.TS, IP: r.IP, Type: "http_probing", Severity: []string{model.SevLow, model.SevMedium}[lvl],
				Title:       "Probing for hidden pages",
				Explanation: fmt.Sprintf("%s requested %d pages that do not exist (404) within 5 minutes — typical of a bot searching for hidden files or admin panels.", d.where(r.IP), n),
				Advice:      "Usually harmless background noise; block the IP if it keeps going.",
				Count:       n, Details: map[string]any{"paths": topKeys(nw.extra, 10)},
			}})
		}
	}
	// Global traffic spike (per-minute buckets vs moving baseline).
	minute := r.TS / 60000
	if minute != d.minuteStart {
		if d.minuteStart != 0 && minute == d.minuteStart+1 {
			c := float64(d.minuteCount)
			if d.baseline == 0 {
				d.baseline = c
			} else {
				if c > 3*d.baseline && c > 120 && d.minuteStart*60000-d.spikeLast > 10*60000 {
					d.spikeLast = d.minuteStart * 60000
					out = append(out, Finding{Key: fmt.Sprintf("traffic_spike|%d", d.minuteStart), Threat: model.Threat{
						TS: r.TS, LastSeen: r.TS, Type: "traffic_spike", Severity: model.SevMedium,
						Title:       "Sudden traffic spike",
						Explanation: fmt.Sprintf("Your website received %d requests in one minute, about %.0fx more than usual (%.0f/min). This may be a viral link, a bot, or the start of an attack.", d.minuteCount, c/maxf(d.baseline, 1), d.baseline),
						Advice:      "Check the Top IPs on the Requests page to see who is causing it.",
						Count:       d.minuteCount, Details: map[string]any{"requests": d.minuteCount, "baseline_per_min": int(d.baseline)},
					}})
				}
				d.baseline = d.baseline*0.9 + c*0.1
			}
		}
		d.minuteStart = minute
		d.minuteCount = 0
	}
	d.minuteCount++
	return out
}

func bump(s string) string {
	switch s {
	case model.SevInfo:
		return model.SevLow
	case model.SevLow:
		return model.SevMedium
	case model.SevMedium:
		return model.SevHigh
	}
	return model.SevCritical
}

func maxf(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func withoutOK(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		if !strings.HasPrefix(k, "__") {
			out[k] = v
		}
	}
	return out
}

// OnProbe records an inbound connection attempt (SYN) from src to dport,
// from packet capture or kernel firewall logs.
func (d *Detector) OnProbe(src string, dport int, ts int64, source string) []Finding {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ignored(src) {
		return nil
	}
	w := get(d.portScan, src)
	span := d.cfg.PortScanWindow.Milliseconds()
	w.add(ts, span)
	w.extra[fmt.Sprint(dport)] = int(ts / 1000)
	// distinct ports seen within window
	cut := int(ts/1000) - int(span/1000)
	ports := 0
	for k, v := range w.extra {
		if v < cut {
			delete(w.extra, k)
			continue
		}
		ports++
	}
	lvl := levelFor(ports, []int{d.cfg.PortScanPorts, d.cfg.PortScanPorts * 5, d.cfg.PortScanPorts * 50})
	if lvl >= 0 && lvl+1 > w.level {
		w.level = lvl + 1
		plist := topKeys(w.extra, 15)
		return []Finding{{Key: "port_scan|" + src, Threat: model.Threat{
			TS: ts, LastSeen: ts, IP: src, Type: "port_scan", Severity: []string{model.SevMedium, model.SevHigh, model.SevHigh}[lvl],
			Title:       "Port scan",
			Explanation: fmt.Sprintf("%s knocked on %d different ports of your server within %s, looking for services to attack.", d.where(src), ports, humanDur(d.cfg.PortScanWindow)),
			Advice:      "Port scans are common. Make sure only the ports you need are open (see Network → Open ports) and that a firewall is enabled. Blocking the IP is safe.",
			Count:       ports, Details: map[string]any{"ports_sample": plist, "source": source},
		}}}
	}
	return nil
}

// OnConnections inspects a connection table snapshot for SYN floods and
// connection-based scans.
func (d *Detector) OnConnections(conns []model.Conn, ts int64) []Finding {
	perIP := map[string]int{}
	ports := map[string]map[int]bool{}
	for _, c := range conns {
		if c.Direction != "in" || c.RemoteIP == "" {
			continue
		}
		if c.State == "SYN_RECV" {
			perIP[c.RemoteIP]++
		}
		if ports[c.RemoteIP] == nil {
			ports[c.RemoteIP] = map[int]bool{}
		}
		ports[c.RemoteIP][c.LocalPort] = true
	}
	var out []Finding
	for ip, ps := range ports {
		for p := range ps {
			out = append(out, d.OnProbe(ip, p, ts, "connections")...)
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for ip, n := range perIP {
		if n < 50 || d.ignored(ip) {
			continue
		}
		w := get(d.synRecv, ip)
		if ts-w.last < 10*60000 {
			continue
		}
		w.last = ts
		out = append(out, Finding{Key: "syn_flood|" + ip, Threat: model.Threat{
			TS: ts, LastSeen: ts, IP: ip, Type: "syn_flood", Severity: model.SevHigh,
			Title:       "Connection flood (SYN flood)",
			Explanation: fmt.Sprintf("%s has %d half-open connections to your server right now. This is a common denial-of-service technique.", d.where(ip), n),
			Advice:      "Block the IP. If it comes from many addresses, ask your hosting provider about DDoS protection.",
			Count:       n, Details: map[string]any{"half_open": n},
		}})
	}
	return out
}

// GC drops idle state older than an hour.
func (d *Detector) GC(now int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	cut := now - time.Hour.Milliseconds()
	for _, m := range []map[string]*window{d.sshFails, d.reqFlags, d.reqRate, d.notFound, d.portScan, d.synRecv} {
		for k, w := range m {
			if w.last < cut {
				delete(m, k)
			}
		}
	}
	for k, v := range d.sshHistory {
		if v < cut {
			delete(d.sshHistory, k)
		}
	}
	if len(d.knownLogin) > 10000 {
		d.knownLogin = map[string]bool{}
	}
}
