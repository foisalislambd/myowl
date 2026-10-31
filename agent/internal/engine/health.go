package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/myowl/myowl/agent/internal/model"
)

// Health builds a plain-language verdict about the server.
func (e *Engine) Health() model.Health {
	s, n := e.System(), e.Network()
	h := model.Health{Score: 100, Messages: []model.HealthMsg{}}
	add := func(level, area, text string, penalty int) {
		h.Messages = append(h.Messages, model.HealthMsg{Level: level, Area: area, Text: text})
		h.Score -= penalty
	}
	if s != nil {
		switch c := s.CPU.Usage; {
		case c >= 90:
			add("bad", "cpu", fmt.Sprintf("The processor is almost fully busy (%.0f%%). Pages may load slowly.", c), 20)
		case c >= 70:
			add("warn", "cpu", fmt.Sprintf("The processor is quite busy (%.0f%%).", c), 8)
		default:
			add("good", "cpu", fmt.Sprintf("The processor has plenty of headroom (%.0f%% used).", c), 0)
		}
		if s.CPU.Steal >= 10 {
			add("warn", "cpu", fmt.Sprintf("%.0f%% of CPU time is being taken by other customers on the same physical host (\"steal\"). Your hosting plan may be oversold.", s.CPU.Steal), 5)
		}
		switch m := s.Memory.Percent; {
		case m >= 92:
			add("bad", "memory", fmt.Sprintf("Memory is almost full (%.0f%%). Programs may crash or be killed.", m), 20)
		case m >= 80:
			add("warn", "memory", fmt.Sprintf("Memory usage is high (%.0f%%).", m), 8)
		default:
			add("good", "memory", fmt.Sprintf("Memory usage is healthy (%.0f%%).", m), 0)
		}
		if s.Memory.SwapPercent >= 50 {
			add("warn", "memory", fmt.Sprintf("The server is using a lot of swap (%.0f%%), which is much slower than RAM.", s.Memory.SwapPercent), 5)
		}
		worst := 0.0
		mount := ""
		for _, d := range s.Disks {
			if d.Percent > worst {
				worst, mount = d.Percent, d.Mount
			}
		}
		switch {
		case worst >= 95:
			add("bad", "disk", fmt.Sprintf("The disk %s is almost full (%.0f%%). When it is full, databases and websites stop working.", mount, worst), 25)
		case worst >= 85:
			add("warn", "disk", fmt.Sprintf("The disk %s is getting full (%.0f%%). Clean up old logs or backups soon.", mount, worst), 10)
		case mount != "":
			add("good", "disk", fmt.Sprintf("Disk space is fine (fullest: %s at %.0f%%).", mount, worst), 0)
		}
		if s.CPU.Cores > 0 && s.Load[1] > float64(s.CPU.Cores)*1.5 {
			add("warn", "load", fmt.Sprintf("The server has had more work queued than it can handle for the last 5 minutes (load %.1f on %d cores).", s.Load[1], s.CPU.Cores), 8)
		}
		failed := 0
		var names []string
		for _, svc := range s.Services {
			if svc.Active == "failed" {
				failed++
				if len(names) < 3 {
					names = append(names, svc.Name)
				}
			}
		}
		if failed > 0 {
			add("bad", "services", fmt.Sprintf("%d service(s) have failed: %s. Something on your server is not running as intended.", failed, strings.Join(names, ", ")), 15)
		} else if s.ServicesAvailable {
			add("good", "services", "All system services are running.", 0)
		}
	}
	if n != nil {
		risky := 0
		for _, l := range n.Listeners {
			if l.Risk != "" {
				risky++
				if risky <= 2 {
					add("warn", "ports", fmt.Sprintf("Port %d (%s) is open to the internet. %s", l.Port, l.Service, l.Risk), 7)
				}
			}
		}
	}
	tc := e.St.ThreatCounts(time.Now().Add(-time.Hour).UnixMilli())
	if c := tc["critical"]; c > 0 {
		add("bad", "security", fmt.Sprintf("%d critical security event(s) in the last hour — check the Security page.", c), 20)
	} else if hi := tc["high"]; hi > 0 {
		add("warn", "security", fmt.Sprintf("%d serious security event(s) in the last hour.", hi), 8)
	} else {
		total := int64(0)
		for _, v := range tc {
			total += v
		}
		if total > 0 {
			add("good", "security", fmt.Sprintf("%d minor security event(s) in the last hour (normal internet background noise).", total), 0)
		} else {
			add("good", "security", "No security events in the last hour.", 0)
		}
	}
	if h.Score < 0 {
		h.Score = 0
	}
	switch {
	case h.Score >= 85:
		h.Level, h.Summary = "good", "Everything looks healthy."
	case h.Score >= 60:
		h.Level, h.Summary = "warn", "Mostly fine, but a few things need attention."
	default:
		h.Level, h.Summary = "bad", "Your server needs attention."
	}
	// bad first
	order := map[string]int{"bad": 0, "warn": 1, "good": 2}
	for i := 1; i < len(h.Messages); i++ {
		for j := i; j > 0 && order[h.Messages[j].Level] < order[h.Messages[j-1].Level]; j-- {
			h.Messages[j], h.Messages[j-1] = h.Messages[j-1], h.Messages[j]
		}
	}
	return h
}
