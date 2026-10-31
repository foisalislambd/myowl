package alerts

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/myowl/myowl/agent/internal/model"
	"github.com/myowl/myowl/agent/internal/store"
)

// Manager evaluates rules against incoming data.
type Manager struct {
	mu       sync.Mutex
	st       *store.Store
	n        *Notifier
	rules    []model.AlertRule
	since    map[int64]int64 // rule -> condition first true (ms)
	lastFire map[string]int64
	host     string
	// OnEvent is called for every fired alert (dashboard push).
	OnEvent func(model.AlertEvent)
	// Quiet suppresses outbound notifications (used during backfill).
	Quiet bool
}

// DefaultRules are seeded on first start.
func DefaultRules() []model.AlertRule {
	return []model.AlertRule{
		{Name: "CPU very busy", Kind: "metric", Metric: "cpu", Op: ">", Threshold: 90, Duration: 300, Severity: "high", Channels: []string{"dashboard"}, Cooldown: 30, Enabled: true},
		{Name: "Memory almost full", Kind: "metric", Metric: "memory", Op: ">", Threshold: 90, Duration: 120, Severity: "high", Channels: []string{"dashboard"}, Cooldown: 30, Enabled: true},
		{Name: "Disk almost full", Kind: "metric", Metric: "disk", Op: ">", Threshold: 90, Duration: 60, Severity: "critical", Channels: []string{"dashboard"}, Cooldown: 120, Enabled: true},
		{Name: "Serious security threat", Kind: "threat", Severity: "high", Channels: []string{"dashboard"}, Cooldown: 10, Enabled: true},
		{Name: "Someone logged in via SSH", Kind: "login", Severity: "info", Channels: []string{"dashboard"}, Cooldown: 0, Enabled: true},
		{Name: "A service crashed", Kind: "service", Severity: "high", Channels: []string{"dashboard"}, Cooldown: 30, Enabled: true},
	}
}

// NewManager loads rules (seeding defaults when empty).
func NewManager(st *store.Store, n *Notifier) *Manager {
	m := &Manager{st: st, n: n, since: map[int64]int64{}, lastFire: map[string]int64{}}
	m.host, _ = os.Hostname()
	if st.Get("alert_rules_seeded") == "" {
		for _, r := range DefaultRules() {
			r := r
			_ = st.SaveAlertRule(&r)
		}
		_ = st.Set("alert_rules_seeded", "1")
	}
	m.Reload()
	return m
}

// SetHost overrides the hostname used in messages.
func (m *Manager) SetHost(h string) { m.host = h }

// Notifier returns the notifier.
func (m *Manager) Notifier() *Notifier { return m.n }

// Reload re-reads rules from storage.
func (m *Manager) Reload() {
	rules, err := m.st.AlertRules()
	if err != nil {
		log.Printf("alerts: %v", err)
		return
	}
	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()
}

var metricLabel = map[string]string{"cpu": "CPU usage", "memory": "Memory usage", "disk": "Disk usage", "swap": "Swap usage", "load": "Load average",
	"rx": "Incoming traffic", "tx": "Outgoing traffic", "conns": "Open connections"}

func metricValue(s *model.SystemSnapshot, n *model.NetworkSnapshot, metric string) (float64, string) {
	switch metric {
	case "cpu":
		return s.CPU.Usage, "%"
	case "memory":
		return s.Memory.Percent, "%"
	case "swap":
		return s.Memory.SwapPercent, "%"
	case "disk":
		max := 0.0
		for _, d := range s.Disks {
			if d.Percent > max {
				max = d.Percent
			}
		}
		return max, "%"
	case "load":
		return s.Load[0], ""
	case "rx":
		if n != nil {
			return n.TotalRxBps / 125000, " Mbit/s"
		}
	case "tx":
		if n != nil {
			return n.TotalTxBps / 125000, " Mbit/s"
		}
	case "conns":
		if n != nil {
			return float64(n.ConnCount), ""
		}
	}
	return 0, ""
}

// EvalMetrics checks metric and service rules.
func (m *Manager) EvalMetrics(s *model.SystemSnapshot, n *model.NetworkSnapshot, prevServices map[string]string) {
	if s == nil {
		return
	}
	m.mu.Lock()
	rules := append([]model.AlertRule(nil), m.rules...)
	m.mu.Unlock()
	now := time.Now().UnixMilli()
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		switch r.Kind {
		case "metric":
			v, unit := metricValue(s, n, r.Metric)
			cond := v > r.Threshold
			if r.Op == "<" {
				cond = v < r.Threshold
			}
			m.mu.Lock()
			if !cond {
				delete(m.since, r.ID)
				m.mu.Unlock()
				continue
			}
			if _, ok := m.since[r.ID]; !ok {
				m.since[r.ID] = now
			}
			held := now - m.since[r.ID]
			m.mu.Unlock()
			if held >= int64(r.Duration)*1000 {
				dur := ""
				if r.Duration >= 60 {
					dur = fmt.Sprintf(" for more than %d minutes", r.Duration/60)
				}
				m.fire(r, fmt.Sprintf("rule:%d", r.ID), r.Severity, r.Name,
					fmt.Sprintf("%s is %.1f%s%s (limit %s %.0f%s).", metricLabel[r.Metric], v, unit, dur, r.Op, r.Threshold, unit))
			}
		case "service":
			for _, svc := range s.Services {
				prev, ok := prevServices[svc.Name]
				if ok && svc.Active == "failed" && prev != "failed" {
					m.fire(r, "svc:"+svc.Name, r.Severity, fmt.Sprintf("Service %s stopped working", svc.Name),
						fmt.Sprintf("The service \"%s\" (%s) has failed. Your website or app may be partly down. Try: sudo systemctl restart %s", svc.Name, svc.Description, svc.Name))
				}
			}
		}
	}
}

// OnThreat checks threat rules.
func (m *Manager) OnThreat(t *model.Threat) {
	m.mu.Lock()
	rules := append([]model.AlertRule(nil), m.rules...)
	m.mu.Unlock()
	for _, r := range rules {
		if !r.Enabled || r.Kind != "threat" {
			continue
		}
		if model.SeverityRank(t.Severity) < model.SeverityRank(r.Severity) {
			continue
		}
		ip := t.IP
		if ip == "" {
			ip = "-"
		}
		msg := t.Explanation
		if t.Advice != "" {
			msg += "\n\nWhat to do: " + t.Advice
		}
		m.fire(r, "threat:"+t.Type+":"+ip, t.Severity, t.Title, msg)
	}
}

// OnLogin checks login rules.
func (m *Manager) OnLogin(e *model.AuthEvent, where string) {
	m.mu.Lock()
	rules := append([]model.AlertRule(nil), m.rules...)
	m.mu.Unlock()
	for _, r := range rules {
		if !r.Enabled || r.Kind != "login" {
			continue
		}
		from := e.IP
		if where != "" {
			from += " (" + where + ")"
		}
		m.fire(r, "login:"+e.User+":"+e.IP, r.Severity, "SSH login: "+e.User,
			fmt.Sprintf("User \"%s\" logged in over SSH from %s using %s at %s.", e.User, from, e.Method, time.UnixMilli(e.TS).Format("2006-01-02 15:04:05")))
	}
}

func (m *Manager) fire(r model.AlertRule, key, sev, title, text string) {
	now := time.Now().UnixMilli()
	m.mu.Lock()
	fk := fmt.Sprintf("%d|%s", r.ID, key)
	if last, ok := m.lastFire[fk]; ok && now-last < int64(r.Cooldown)*60000 {
		m.mu.Unlock()
		return
	}
	if r.Cooldown == 0 {
		if last, ok := m.lastFire[fk]; ok && now-last < 2000 {
			m.mu.Unlock()
			return
		}
	}
	m.lastFire[fk] = now
	if len(m.lastFire) > 20000 {
		m.lastFire = map[string]int64{}
	}
	quiet := m.Quiet
	m.mu.Unlock()
	ev := model.AlertEvent{TS: now, RuleID: r.ID, RuleName: r.Name, Severity: sev, Title: title, Message: text, Delivered: "dashboard"}
	_ = m.st.InsertAlertEvent(&ev)
	if m.OnEvent != nil {
		m.OnEvent(ev)
	}
	if quiet {
		return
	}
	go func() {
		var res []string
		for _, ch := range r.Channels {
			if ch == "dashboard" {
				res = append(res, "dashboard")
				continue
			}
			if err := m.n.Send(ch, Message{Title: title, Text: text, Severity: sev, Host: m.host, TS: now}); err != nil {
				log.Printf("alert delivery via %s failed: %v", ch, err)
				res = append(res, ch+": failed ("+err.Error()+")")
			} else {
				res = append(res, ch+": sent")
			}
		}
		_ = m.st.UpdateAlertDelivery(ev.ID, strings.Join(res, "; "))
	}()
}

// Test sends a test message on a channel.
func (m *Manager) Test(channel string) error {
	return m.n.Send(channel, Message{Title: "Test notification", Text: "If you can read this, myOwl notifications via " + channel + " work.", Severity: "info", Host: m.host, TS: time.Now().UnixMilli()})
}
