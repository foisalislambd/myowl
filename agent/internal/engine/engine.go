// Package engine wires collectors, log tailers, detectors, storage, alerts
// and the real-time hub together.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/myowl/myowl/agent/internal/alerts"
	"github.com/myowl/myowl/agent/internal/collect"
	"github.com/myowl/myowl/agent/internal/config"
	"github.com/myowl/myowl/agent/internal/detect"
	"github.com/myowl/myowl/agent/internal/firewall"
	"github.com/myowl/myowl/agent/internal/geo"
	"github.com/myowl/myowl/agent/internal/hub"
	"github.com/myowl/myowl/agent/internal/logs"
	"github.com/myowl/myowl/agent/internal/model"
	"github.com/myowl/myowl/agent/internal/store"
)

// Engine is the central runtime.
type Engine struct {
	Cfg    *config.Config
	St     *store.Store
	Hub    *hub.Hub
	Geo    *geo.Resolver
	Det    *detect.Detector
	FW     *firewall.Firewall
	Alerts *alerts.Manager

	sys *collect.SystemCollector
	net *collect.NetCollector
	cap *collect.Capture

	// Overrides used by demo mode.
	SysFn  func() *model.SystemSnapshot
	NetFn  func() *model.NetworkSnapshot
	SessFn func() *model.SessionsSnapshot

	mu        sync.RWMutex
	lastSys   *model.SystemSnapshot
	lastNet   *model.NetworkSnapshot
	lastSess  *model.SessionsSnapshot
	statuses  map[string]model.CollectorStatus
	blocked   map[string]model.BlockedIP
	threatIPs map[string]bool
	prevSvc   map[string]string
	serverGeo *model.Geo

	reqMu       sync.Mutex
	reqBuf      []*model.HTTPRequest
	reqSinceMet int

	threatMu    sync.Mutex
	threatCache map[string]*cachedThreat

	journalCursor string
	started       time.Time
}

type cachedThreat struct {
	t       *model.Threat
	written int64
	dirty   bool
}

// New builds an engine.
func New(cfg *config.Config, st *store.Store) *Engine {
	e := &Engine{Cfg: cfg, St: st, Hub: hub.New(), statuses: map[string]model.CollectorStatus{},
		blocked: map[string]model.BlockedIP{}, threatIPs: map[string]bool{}, prevSvc: map[string]string{},
		threatCache: map[string]*cachedThreat{}, started: time.Now()}
	e.Geo = geo.New(cfg.GeoIP.Path)
	dc := detect.DefaultConfig()
	d := cfg.Detection
	dc.SSHFailThreshold, dc.ReqRatePerMin, dc.NotFoundThreshold, dc.PortScanPorts = d.SSHFailThreshold, d.ReqRatePerMin, d.NotFoundThreshold, d.PortScanPorts
	dc.SSHWindow = time.Duration(d.SSHWindowMin) * time.Minute
	dc.PortScanWindow = time.Duration(d.PortScanWindowSec) * time.Second
	dc.IgnorePaths, dc.IgnoreIPs = d.IgnorePaths, d.IgnoreIPs
	e.Det = detect.New(dc)
	e.Det.GeoName = func(ip string) string {
		if !e.Geo.Available() {
			return ""
		}
		return e.Geo.Label(ip)
	}
	e.FW = firewall.New(firewall.Options{Enabled: cfg.Firewall.Enabled, Backend: cfg.Firewall.Backend, Whitelist: cfg.Firewall.Whitelist,
		AllowPrivate: cfg.Firewall.AllowPrivate, Demo: cfg.Demo})
	n := alerts.NewNotifier(cfg)
	n.Demo = cfg.Demo
	e.Alerts = alerts.NewManager(st, n)
	e.Alerts.OnEvent = func(ev model.AlertEvent) { e.Hub.Publish("alert", ev) }
	e.sys = collect.NewSystemCollector()
	e.net = collect.NewNetCollector()
	if bl, err := st.Blocked(); err == nil {
		for _, b := range bl {
			e.blocked[b.IP] = b
		}
	}
	return e
}

// SetStatus records a collector status and pushes it to clients.
func (e *Engine) SetStatus(name, label, state, msg string) {
	e.mu.Lock()
	old, ok := e.statuses[name]
	s := model.CollectorStatus{Name: name, Label: label, State: state, Message: msg}
	e.statuses[name] = s
	e.mu.Unlock()
	if !ok || old != s {
		if state != "ok" && (!ok || old.State != state) {
			log.Printf("[%s] %s: %s", name, state, msg)
		}
		e.Hub.Publish("status", s)
	}
}

// Statuses returns all collector statuses sorted by name.
func (e *Engine) Statuses() []model.CollectorStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]model.CollectorStatus, 0, len(e.statuses))
	for _, s := range e.statuses {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// System returns the latest system snapshot.
func (e *Engine) System() *model.SystemSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastSys
}

// Network returns the latest network snapshot.
func (e *Engine) Network() *model.NetworkSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastNet
}

// Sessions returns the latest sessions snapshot.
func (e *Engine) Sessions() *model.SessionsSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastSess
}

// IsBlocked reports whether ip is blocked by us.
func (e *Engine) IsBlocked(ip string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.blocked[ip]
	return ok
}

// BlockedList returns blocked IPs with geo.
func (e *Engine) BlockedList() []model.BlockedIP {
	e.mu.RLock()
	out := make([]model.BlockedIP, 0, len(e.blocked))
	for _, b := range e.blocked {
		out = append(out, b)
	}
	e.mu.RUnlock()
	for i := range out {
		out[i].Geo = e.Geo.Lookup(out[i].IP)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS > out[j].TS })
	return out
}

// Block blocks ip via the firewall.
func (e *Engine) Block(ip, reason, requester string) (string, error) {
	canon, err := e.FW.Validate(ip, requester)
	if err != nil {
		return "", err
	}
	if err := e.FW.Block(canon); err != nil {
		return "", err
	}
	b := model.BlockedIP{IP: canon, TS: time.Now().UnixMilli(), Reason: reason, Backend: e.FW.Status().Backend}
	if err := e.St.AddBlocked(b); err != nil {
		return "", err
	}
	e.mu.Lock()
	e.blocked[canon] = b
	e.mu.Unlock()
	log.Printf("firewall: blocked %s (%s)", canon, reason)
	e.Hub.Publish("blocked", e.BlockedList())
	return canon, nil
}

// Unblock removes a block.
func (e *Engine) Unblock(ip string) error {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return fmt.Errorf("not a valid IP address")
	}
	canon := p.String()
	if err := e.FW.Unblock(canon); err != nil {
		log.Printf("firewall: unblock %s: %v", canon, err)
		if !strings.Contains(err.Error(), "No such file") && !strings.Contains(err.Error(), "does not exist") && !strings.Contains(err.Error(), "Bad rule") {
			return err
		}
	}
	_ = e.St.RemoveBlocked(canon)
	e.mu.Lock()
	delete(e.blocked, canon)
	e.mu.Unlock()
	log.Printf("firewall: unblocked %s", canon)
	e.Hub.Publish("blocked", e.BlockedList())
	return nil
}

// ---------------- ingest ----------------

// IngestRequest processes one HTTP request.
func (e *Engine) IngestRequest(r *model.HTTPRequest, backfill bool) {
	r.Geo = e.Geo.Lookup(r.IP)
	fs := e.Det.OnRequest(r)
	if r.Flags == nil {
		r.Flags = []string{}
	}
	e.handleFindings(fs, backfill)
	e.reqMu.Lock()
	e.reqBuf = append(e.reqBuf, r)
	if !backfill {
		e.reqSinceMet++
	}
	full := len(e.reqBuf) >= 5000
	e.reqMu.Unlock()
	if full {
		e.flushRequests()
	}
}

func (e *Engine) flushRequests() {
	e.reqMu.Lock()
	buf := e.reqBuf
	e.reqBuf = nil
	e.reqMu.Unlock()
	if len(buf) == 0 {
		return
	}
	if err := e.St.InsertRequests(buf); err != nil {
		log.Printf("store requests: %v", err)
		return
	}
	cut := time.Now().Add(-2 * time.Minute).UnixMilli()
	live := make([]*model.HTTPRequest, 0, len(buf))
	for _, r := range buf {
		if r.TS >= cut {
			live = append(live, r)
		}
	}
	if len(live) > 200 {
		live = live[len(live)-200:]
	}
	if len(live) > 0 {
		e.Hub.Publish("requests", live)
	}
}

// IngestAuth processes one auth event.
func (e *Engine) IngestAuth(ev *model.AuthEvent, backfill bool) {
	if ev.IP != "" {
		ev.Geo = e.Geo.Lookup(ev.IP)
	}
	if err := e.St.InsertAuth(ev); err != nil {
		log.Printf("store auth: %v", err)
	}
	fs := e.Det.OnAuth(ev)
	e.handleFindings(fs, backfill)
	recent := time.Now().UnixMilli()-ev.TS < 10*60000
	if ev.Kind == model.AuthSSHAccepted && !backfill && recent {
		e.Alerts.OnLogin(ev, e.Geo.Label(ev.IP))
	}
	if recent {
		e.Hub.Publish("auth", ev)
	}
}

// IngestProbe records an inbound connection attempt.
func (e *Engine) IngestProbe(src string, port int, ts int64, source string) {
	if e.isLocal(src) {
		return
	}
	e.handleFindings(e.Det.OnProbe(src, port, ts, source), false)
}

func (e *Engine) isLocal(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil || p.IsLoopback() {
		return true
	}
	if e.net != nil {
		if l := e.net.LocalIPs(); l != nil && l[ip] {
			return true
		}
	}
	return false
}

// handleFindings upserts threats and fires alerts for new/escalated ones.
func (e *Engine) handleFindings(fs []detect.Finding, backfill bool) {
	if len(fs) == 0 {
		return
	}
	now := time.Now().UnixMilli()
	for _, f := range fs {
		t := f.Threat
		if t.IP != "" {
			t.Geo = e.Geo.Lookup(t.IP)
		}
		if t.Details == nil {
			t.Details = map[string]any{}
		}
		e.threatMu.Lock()
		c := e.threatCache[f.Key]
		if c == nil || t.TS-c.t.LastSeen > 30*60000 {
			c = nil
			if ex, err := e.St.FindThreatByKey(f.Key, t.TS-30*60000); err == nil {
				c = &cachedThreat{t: ex, written: now}
				e.threatCache[f.Key] = c
			}
		}
		isNew, escalated := false, false
		var out *model.Threat
		if c == nil {
			tt := t
			if err := e.St.InsertThreat(f.Key, &tt); err != nil {
				e.threatMu.Unlock()
				log.Printf("store threat: %v", err)
				continue
			}
			c = &cachedThreat{t: &tt, written: now}
			e.threatCache[f.Key] = c
			isNew = true
			out = &tt
		} else {
			ex := c.t
			if model.SeverityRank(t.Severity) > model.SeverityRank(ex.Severity) {
				ex.Severity = t.Severity
				escalated = true
			}
			if t.LastSeen > ex.LastSeen {
				ex.LastSeen = t.LastSeen
			}
			if t.Count >= ex.Count {
				ex.Count = t.Count
			} else {
				ex.Count++
			}
			ex.Explanation = t.Explanation
			for k, v := range t.Details {
				ex.Details[k] = v
			}
			c.dirty = true
			if escalated || now-c.written > 3000 {
				_ = e.St.UpdateThreat(ex)
				c.written = now
				c.dirty = false
			}
			cp := *ex
			out = &cp
		}
		if len(e.threatCache) > 5000 {
			e.flushThreatsLocked(true)
		}
		e.threatMu.Unlock()
		if out.IP != "" {
			e.mu.Lock()
			e.threatIPs[out.IP] = true
			e.mu.Unlock()
		}
		recent := now-out.LastSeen < 10*60000
		if recent {
			e.Hub.Publish("threat", e.decorateThreat(out))
		}
		if (isNew || escalated) && !backfill && recent && !f.Update {
			e.Alerts.OnThreat(out)
		}
	}
}

func (e *Engine) flushThreatsLocked(evict bool) {
	cut := time.Now().UnixMilli() - 30*60000
	for k, c := range e.threatCache {
		if c.dirty {
			_ = e.St.UpdateThreat(c.t)
			c.dirty = false
			c.written = time.Now().UnixMilli()
		}
		if evict && c.t.LastSeen < cut {
			delete(e.threatCache, k)
		}
	}
}

func (e *Engine) decorateThreat(t *model.Threat) *model.Threat {
	cp := *t
	cp.Blocked = cp.IP != "" && e.IsBlocked(cp.IP)
	return &cp
}

// DecorateThreats sets Blocked flags.
func (e *Engine) DecorateThreats(ts []*model.Threat) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, t := range ts {
		_, t.Blocked = e.blocked[t.IP]
	}
}

// ---------------- run loops ----------------

// Start launches all background workers.
func (e *Engine) Start(ctx context.Context) {
	host, _ := os.Hostname()
	e.Alerts.SetHost(host)
	if !e.Cfg.Demo {
		var ips []string
		for ip := range e.blocked {
			ips = append(ips, ip)
		}
		e.FW.Reapply(ips)
		e.startGeo(ctx)
		e.startCapture(ctx)
		e.startLogs(ctx)
	}
	fs := e.FW.Status()
	if fs.CanBlock {
		e.SetStatus("firewall", "Firewall blocking", "ok", fs.Message)
	} else {
		e.SetStatus("firewall", "Firewall blocking", "off", fs.Message)
	}
	e.refreshThreatIPs()
	go e.loop(ctx, time.Duration(e.Cfg.Intervals.SystemSec)*time.Second, e.tickSystem)
	go e.loop(ctx, time.Duration(e.Cfg.Intervals.NetworkSec)*time.Second, e.tickNetwork)
	go e.loop(ctx, time.Duration(e.Cfg.Intervals.SessionsSec)*time.Second, e.tickSessions)
	go e.loop(ctx, time.Second, e.flushRequests)
	go e.loop(ctx, 10*time.Second, e.tickMetrics)
	go e.loop(ctx, 30*time.Second, e.refreshThreatIPs)
	go e.loop(ctx, time.Minute, func() {
		e.Det.GC(time.Now().UnixMilli())
		e.threatMu.Lock()
		e.flushThreatsLocked(true)
		e.threatMu.Unlock()
		if e.journalCursor != "" {
			_ = e.St.Set("journal_cursor", e.journalCursor)
		}
	})
	go e.loop(ctx, time.Hour, func() { e.St.Prune(e.Cfg.Retention.Days, e.Cfg.Retention.MaxRequests) })
	go func() {
		<-ctx.Done()
		e.flushRequests()
		e.threatMu.Lock()
		e.flushThreatsLocked(false)
		e.threatMu.Unlock()
	}()
}

func (e *Engine) loop(ctx context.Context, every time.Duration, fn func()) {
	if every <= 0 {
		every = 2 * time.Second
	}
	fn()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("worker panic: %v", r)
					}
				}()
				fn()
			}()
		}
	}
}

func (e *Engine) refreshThreatIPs() {
	ips := e.St.ThreatIPsSince(time.Now().Add(-24 * time.Hour).UnixMilli())
	e.mu.Lock()
	e.threatIPs = ips
	e.mu.Unlock()
}

func (e *Engine) startGeo(ctx context.Context) {
	if e.Geo.Available() {
		e.SetStatus("geoip", "GeoIP (world map)", "ok", "DB-IP City Lite database loaded")
		return
	}
	if !e.Cfg.GeoIP.AutoDownload {
		_, msg := e.Geo.Status()
		e.SetStatus("geoip", "GeoIP (world map)", "off", msg)
		return
	}
	e.SetStatus("geoip", "GeoIP (world map)", "degraded", "downloading the free DB-IP City Lite database…")
	go func() {
		e.Geo.AutoDownload()
		if e.Geo.Available() {
			e.SetStatus("geoip", "GeoIP (world map)", "ok", "DB-IP City Lite database loaded")
		} else {
			_, msg := e.Geo.Status()
			e.SetStatus("geoip", "GeoIP (world map)", "off", msg)
		}
	}()
}

func (e *Engine) startCapture(ctx context.Context) {
	if !e.Cfg.Capture.Enabled {
		e.SetStatus("capture", "Packet capture", "off", "disabled in config (capture.enabled: false)")
		return
	}
	e.cap = collect.NewCapture(e.isLocal)
	e.cap.OnSYN = func(src string, dport int, ts int64) { e.IngestProbe(src, dport, ts, "packet capture") }
	if err := e.cap.Start(); err != nil {
		_, msg := e.cap.Status()
		e.SetStatus("capture", "Packet capture", "off", msg)
		e.cap = nil
		return
	}
	e.net.Capture = e.cap
	e.SetStatus("capture", "Packet capture", "ok", "passive capture via AF_PACKET")
	go func() {
		<-ctx.Done()
		e.cap.Stop()
	}()
}

func (e *Engine) tickSystem() {
	var s *model.SystemSnapshot
	if e.SysFn != nil {
		s = e.SysFn()
	} else {
		s = e.sys.Collect()
		if s.ServicesAvailable {
			e.SetStatus("services", "systemd services", "ok", fmt.Sprintf("%d services", len(s.Services)))
		} else {
			e.SetStatus("services", "systemd services", "off", s.ServicesMessage)
		}
		e.SetStatus("system", "System metrics (/proc)", "ok", "reading /proc")
	}
	e.mu.Lock()
	e.lastSys = s
	prev := e.prevSvc
	cur := map[string]string{}
	for _, svc := range s.Services {
		cur[svc.Name] = svc.Active
	}
	e.prevSvc = cur
	nw := e.lastNet
	e.mu.Unlock()
	e.Alerts.EvalMetrics(s, nw, prev)
	e.Hub.Publish("system", s)
}

func (e *Engine) tickNetwork() {
	var n *model.NetworkSnapshot
	if e.NetFn != nil {
		n = e.NetFn()
	} else {
		n = e.net.Collect()
		src, msg := e.net.Source()
		state := "ok"
		if src != "netlink" {
			state = "degraded"
		}
		if os.Geteuid() != 0 {
			state = "degraded"
			msg += "; not root, so process names are only shown for your own processes"
		}
		e.SetStatus("connections", "Connections", state, msg)
		if e.cap != nil {
			st, m := e.cap.Status()
			e.SetStatus("capture", "Packet capture", st, m)
			n.Capture = "active"
		} else {
			n.Capture = "off"
		}
		for _, f := range e.Det.OnConnections(n.Connections, n.TS) {
			e.handleFindings([]detect.Finding{f}, false)
		}
	}
	e.enrichNetwork(n)
	e.mu.Lock()
	e.lastNet = n
	e.mu.Unlock()
	e.Hub.Publish("network", n)
}

func (e *Engine) enrichNetwork(n *model.NetworkSnapshot) {
	e.mu.RLock()
	threats := make(map[string]bool, len(e.threatIPs))
	for k, v := range e.threatIPs {
		threats[k] = v
	}
	blocked := make(map[string]model.BlockedIP, len(e.blocked))
	for k, v := range e.blocked {
		blocked[k] = v
	}
	e.mu.RUnlock()
	for i := range n.Connections {
		c := &n.Connections[i]
		if c.Geo == (model.Geo{}) {
			c.Geo = e.Geo.Lookup(c.RemoteIP)
		}
	}
	type gk struct{ lat, lon float64 }
	points := map[gk]*model.GeoPoint{}
	countries := map[string]*model.CountryStat{}
	for i := range n.Talkers {
		t := &n.Talkers[i]
		if t.Geo == (model.Geo{}) {
			t.Geo = e.Geo.Lookup(t.IP)
		}
		t.Threat = threats[t.IP]
		_, t.Blocked = blocked[t.IP]
		if t.Geo.Private || (t.Geo.Lat == 0 && t.Geo.Lon == 0) {
			continue
		}
		k := gk{math.Round(t.Geo.Lat*10) / 10, math.Round(t.Geo.Lon*10) / 10}
		p := points[k]
		if p == nil {
			p = &model.GeoPoint{Lat: t.Geo.Lat, Lon: t.Geo.Lon, Country: t.Geo.Country, CC: t.Geo.CC, City: t.Geo.City}
			points[k] = p
		}
		if len(p.IPs) < 20 {
			p.IPs = append(p.IPs, t.IP)
		}
		p.Conns += t.Conns
		p.Rate += t.RateIn + t.RateOut
		p.Threat = p.Threat || t.Threat
		cc := t.Geo.CC
		cs := countries[cc]
		if cs == nil {
			cs = &model.CountryStat{CC: cc, Country: t.Geo.Country}
			countries[cc] = cs
		}
		cs.IPs++
		cs.Conns += t.Conns
		cs.Rate += t.RateIn + t.RateOut
	}
	n.Geo = make([]model.GeoPoint, 0, len(points))
	for _, p := range points {
		n.Geo = append(n.Geo, *p)
	}
	sort.Slice(n.Geo, func(i, j int) bool { return n.Geo[i].Conns > n.Geo[j].Conns })
	n.Countries = make([]model.CountryStat, 0, len(countries))
	for _, c := range countries {
		n.Countries = append(n.Countries, *c)
	}
	sort.Slice(n.Countries, func(i, j int) bool { return n.Countries[i].Conns > n.Countries[j].Conns })
	if n.Server == nil {
		n.Server = e.serverLocation(n)
	}
	if n.Talkers == nil {
		n.Talkers = []model.Talker{}
	}
	if n.Connections == nil {
		n.Connections = []model.Conn{}
	}
	if n.Listeners == nil {
		n.Listeners = []model.Listener{}
	}
}

func (e *Engine) serverLocation(n *model.NetworkSnapshot) *model.Geo {
	sl := e.Cfg.ServerLocation
	if sl.Lat != 0 || sl.Lon != 0 {
		return &model.Geo{Lat: sl.Lat, Lon: sl.Lon, City: sl.City}
	}
	e.mu.RLock()
	sg := e.serverGeo
	e.mu.RUnlock()
	if sg != nil {
		return sg
	}
	for _, i := range n.Interfaces {
		for _, a := range i.Addrs {
			ip, _, err := net.ParseCIDR(a)
			if err != nil || geo.IsPrivate(ip) || ip.IsLinkLocalUnicast() {
				continue
			}
			g := e.Geo.Lookup(ip.String())
			if g.Lat != 0 || g.Lon != 0 {
				e.mu.Lock()
				e.serverGeo = &g
				e.mu.Unlock()
				return &g
			}
		}
	}
	return nil
}

func (e *Engine) tickSessions() {
	var s *model.SessionsSnapshot
	if e.SessFn != nil {
		s = e.SessFn()
	} else {
		s = &model.SessionsSnapshot{TS: time.Now().UnixMilli()}
		var src, msg string
		s.Current, src, msg = collect.CurrentSessions()
		var hsrc string
		s.History, hsrc = collect.LoginHistory(200)
		s.Source = src + " + " + hsrc
		s.Message = msg
		if hsrc == "none" {
			if s.Message != "" {
				s.Message += "; "
			}
			s.Message += "no login history file (/var/log/wtmp or wtmpdb) is readable"
		}
		state := "ok"
		if src == "none" || hsrc == "none" {
			state = "degraded"
		}
		e.SetStatus("sessions", "Login sessions", state, strings.TrimPrefix(s.Source+" "+s.Message, " "))
	}
	for i := range s.Current {
		if ip := net.ParseIP(s.Current[i].Host); ip != nil {
			s.Current[i].Geo = e.Geo.Lookup(s.Current[i].Host)
		}
	}
	for i := range s.History {
		if ip := net.ParseIP(s.History[i].Host); ip != nil {
			s.History[i].Geo = e.Geo.Lookup(s.History[i].Host)
		}
	}
	e.mu.Lock()
	e.lastSess = s
	e.mu.Unlock()
	e.Hub.Publish("sessions", s)
}

func (e *Engine) tickMetrics() {
	s, n := e.System(), e.Network()
	if s == nil {
		return
	}
	p := model.MetricPoint{TS: time.Now().UnixMilli(), CPU: s.CPU.Usage, Mem: s.Memory.Percent, Swap: s.Memory.SwapPercent, Load1: s.Load[0]}
	for _, d := range s.Disks {
		if d.Percent > p.Disk {
			p.Disk = d.Percent
		}
	}
	if n != nil {
		p.Rx, p.Tx, p.Conns = n.TotalRxBps, n.TotalTxBps, float64(n.ConnCount)
	}
	e.reqMu.Lock()
	p.Reqs = float64(e.reqSinceMet) * 6 // per minute
	e.reqSinceMet = 0
	e.reqMu.Unlock()
	if err := e.St.InsertMetric(p); err != nil {
		log.Printf("store metric: %v", err)
	}
	e.Hub.Publish("metric", p)
}

// ---------------- log sources ----------------

func (e *Engine) loadPos(path string) logs.Position {
	var p logs.Position
	if v := e.St.Get("offset:" + path); v != "" {
		_ = json.Unmarshal([]byte(v), &p)
	}
	return p
}

func (e *Engine) savePos(path string) func(logs.Position) {
	return func(p logs.Position) {
		b, _ := json.Marshal(p)
		_ = e.St.Set("offset:"+path, string(b))
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func (e *Engine) startLogs(ctx context.Context) {
	// access logs
	var accessFound []string
	for _, al := range e.Cfg.AccessLogs {
		al := al
		if !fileExists(al.Path) && !explicitLog(al.Path) {
			continue
		}
		accessFound = append(accessFound, al.Path)
		name := "access:" + al.Path
		label := "Web log " + al.Path
		src := al.Name
		if src == "" {
			src = "web"
		}
		go logs.Tail(ctx, al.Path, logs.TailOptions{
			Start: e.loadPos(al.Path), BackfillLines: e.Cfg.Backfill, OnPos: e.savePos(al.Path),
			OnStatus: func(state, msg string) { e.SetStatus(name, label, mapState(state), msg) },
			OnLine: func(line string, backfill bool) {
				r, err := logs.ParseAccessLine(line, al.Format)
				if err != nil {
					return
				}
				r.Source = src
				e.IngestRequest(r, backfill)
			},
		})
	}
	if len(accessFound) == 0 {
		e.SetStatus("access", "Web server logs", "off", "no nginx/apache/caddy access log found — add its path under access_logs in the config")
	}
	// auth logs
	authFiles := 0
	for _, p := range e.Cfg.AuthLogs {
		p := p
		if !fileExists(p) {
			continue
		}
		authFiles++
		name := "auth:" + p
		go logs.Tail(ctx, p, logs.TailOptions{
			Start: e.loadPos(p), BackfillLines: e.Cfg.Backfill * 4, OnPos: e.savePos(p),
			OnStatus: func(state, msg string) { e.SetStatus(name, "Login log "+p, mapState(state), msg) },
			OnLine: func(line string, backfill bool) {
				if ev := logs.ParseAuthLine(line, time.Now()); ev != nil {
					e.IngestAuth(ev, backfill)
				}
			},
		})
	}
	kernFiles := 0
	for _, p := range e.Cfg.KernelLogs {
		p := p
		if !fileExists(p) {
			continue
		}
		kernFiles++
		name := "kern:" + p
		go logs.Tail(ctx, p, logs.TailOptions{
			Start: e.loadPos(p), BackfillLines: 0, OnPos: e.savePos(p),
			OnStatus: func(state, msg string) { e.SetStatus(name, "Firewall log "+p, mapState(state), msg) },
			OnLine: func(line string, backfill bool) {
				if fe := logs.ParseKernelLine(line, time.Now()); fe != nil && fe.DPort > 0 && !backfill {
					e.IngestProbe(fe.Src, fe.DPort, fe.TS, "firewall log")
				}
			},
		})
		break // ufw.log and kern.log usually duplicate each other
	}
	useJournal := false
	switch e.Cfg.Journald {
	case "on", "true", "yes":
		useJournal = true
	case "off", "false", "no":
	default:
		useJournal = authFiles == 0
	}
	if useJournal {
		if !logs.JournalAvailable() {
			e.SetStatus("journald", "systemd journal", "off", "journalctl not found")
		} else {
			e.journalCursor = e.St.Get("journal_cursor")
			go logs.FollowJournal(ctx, logs.JournalOptions{Cursor: e.journalCursor, Backfill: e.Cfg.Backfill * 4,
				OnStatus: func(state, msg string) { e.SetStatus("journald", "systemd journal (SSH/sudo)", mapState(state), msg) },
				OnEntry: func(j logs.JournalEntry, backfill bool) {
					e.journalCursor = j.Cursor
					if j.Program == "kernel" {
						if kernFiles == 0 {
							if fe := logs.ParseFirewallMessage(j.Message, j.TS); fe != nil && fe.DPort > 0 && !backfill {
								e.IngestProbe(fe.Src, fe.DPort, fe.TS, "firewall log")
							}
						}
						return
					}
					if ev := logs.ParseAuthMessage(j.Program, j.Message, j.TS); ev != nil {
						e.IngestAuth(ev, backfill)
					}
				}})
		}
	} else if authFiles == 0 {
		e.SetStatus("auth", "Login logs", "off", "no auth.log/secure file and journald disabled — SSH brute-force detection is off")
	}
}

func explicitLog(p string) bool {
	// Paths outside the defaults were added by the user: follow them even if
	// they do not exist yet.
	for _, d := range config.Default().AccessLogs {
		if d.Path == p {
			return false
		}
	}
	return true
}

func mapState(s string) string {
	switch s {
	case "ok":
		return "ok"
	case "waiting", "degraded":
		return "degraded"
	}
	return "off"
}
