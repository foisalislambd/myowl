package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/myowl/myowl/agent/internal/collect"
	"github.com/myowl/myowl/agent/internal/detect"
	"github.com/myowl/myowl/agent/internal/model"
	"github.com/myowl/myowl/agent/internal/store"
)

func nowMs() int64 { return time.Now().UnixMilli() }

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	day := nowMs() - 86400000
	hour := nowMs() - 3600000
	threats, _ := s.st.Threats(store.ThreatFilter{Since: day, Limit: 8, MinSeverity: "low"})
	s.e.DecorateThreats(threats)
	alerts, _ := s.st.AlertEvents(day, 5)
	metrics, _ := s.st.Metrics(hour, 60000)
	// Use the hostname from the collected snapshot so demo mode shows the
	// simulated server's name rather than the machine running the demo.
	sys := s.e.System()
	host := ""
	if sys != nil {
		host = sys.Hostname
	}
	if host == "" {
		host, _ = os.Hostname()
	}
	writeJSON(w, map[string]any{
		"health":        s.e.Health(),
		"system":        sys,
		"network":       s.e.Network(),
		"threats":       threats,
		"threat_counts": s.st.ThreatCounts(day),
		"alerts":        alerts,
		"metrics":       metrics,
		"requests_hour": s.st.CountRequestsSince(hour),
		"requests_day":  s.st.CountRequestsSince(day),
		"failed_logins": sumKV(s.st.FailedLoginsByIP(day, 1000)),
		"blocked":       len(s.e.BlockedList()),
		"statuses":      s.e.Statuses(),
		"hostname":      host,
		"demo":          s.cfg.Demo,
		"version":       Version,
	})
}

func sumKV(kv []store.KV) int64 {
	var t int64
	for _, k := range kv {
		t += k.Count
	}
	return t
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"system": s.e.System(), "health": s.e.Health()})
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	since, bucket, label := rangeParam(r, "1h")
	m, err := s.st.Metrics(since, bucket)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"range": label, "bucket": bucket, "points": m})
}

func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"network": s.e.Network(), "ports": collect.WellKnownPorts})
}

func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.RequestFilter{IP: q.Get("ip"), Status: q.Get("status"), Method: q.Get("method"), Q: q.Get("q"),
		Threats: q.Get("threats") == "1", Before: qint(r, "before", 0), Since: qint(r, "since", 0), Limit: int(qint(r, "limit", 100))}
	if f.Limit > 500 {
		f.Limit = 500
	}
	out, err := s.st.Requests(f)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"requests": out, "flags": flagInfo()})
}

func flagInfo() map[string]map[string]string {
	m := map[string]map[string]string{}
	for k, v := range detect.Flags {
		m[k] = map[string]string{"title": v.Title, "severity": v.Severity, "explain": strings.ReplaceAll(v.Explain, "%d ", ""), "advice": v.Advice}
	}
	return m
}

func (s *Server) handleRequestStats(w http.ResponseWriter, r *http.Request) {
	since, bucket, label := rangeParam(r, "24h")
	st, err := s.st.RequestStats(since, bucket)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"range": label, "bucket": bucket, "stats": st})
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	req, err := s.st.Request(id)
	if err != nil || req == nil {
		writeErr(w, 404, "request not found")
		return
	}
	writeJSON(w, map[string]any{"request": req, "ip": s.ipDetail(req.IP), "flags": flagInfo()})
}

func (s *Server) ipDetail(ip string) map[string]any {
	since := nowMs() - 14*86400000
	reqs, _ := s.st.Requests(store.RequestFilter{IP: ip, Limit: 50})
	threats, _ := s.st.Threats(store.ThreatFilter{Since: since, IP: ip, Limit: 50})
	s.e.DecorateThreats(threats)
	auth, _ := s.st.AuthEvents(nil, since, ip, 50)
	var conns []model.Conn
	if n := s.e.Network(); n != nil {
		for _, c := range n.Connections {
			if c.RemoteIP == ip {
				conns = append(conns, c)
			}
		}
	}
	var g model.Geo
	if s.e.Geo != nil {
		g = s.e.Geo.Lookup(ip)
	}
	pip := net.ParseIP(ip)
	var reasons []string
	if pip != nil && s.e.FW != nil {
		if _, err := s.e.FW.Validate(ip, ""); err != nil {
			reasons = append(reasons, err.Error())
		}
	}
	worst := ""
	for _, t := range threats {
		if model.SeverityRank(t.Severity) > model.SeverityRank(worst) {
			worst = t.Severity
		}
	}
	return map[string]any{
		"ip": ip, "geo": g, "requests": reqs, "threats": threats, "auth": auth, "connections": conns,
		"blocked": s.e.IsBlocked(ip), "worst": worst, "block_refusal": strings.Join(reasons, "; "),
		"private": pip != nil && (pip.IsPrivate() || pip.IsLoopback()),
	}
}

func (s *Server) handleIP(w http.ResponseWriter, r *http.Request) {
	ip := net.ParseIP(r.PathValue("ip"))
	if ip == nil {
		writeErr(w, 400, "not an IP address")
		return
	}
	writeJSON(w, s.ipDetail(ip.String()))
}

func (s *Server) handleThreats(w http.ResponseWriter, r *http.Request) {
	since, _, label := rangeParam(r, "24h")
	q := r.URL.Query()
	ts, err := s.st.Threats(store.ThreatFilter{Since: since, IP: q.Get("ip"), MinSeverity: q.Get("severity"), Limit: int(qint(r, "limit", 300)), Unacked: q.Get("unacked") == "1"})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.DecorateThreats(ts)
	byType := map[string]int{}
	for _, t := range ts {
		byType[t.Type] += t.Count
	}
	writeJSON(w, map[string]any{"range": label, "threats": ts, "counts": s.st.ThreatCounts(since),
		"top_ips": s.st.TopThreatIPs(since, 10), "by_type": byType})
}

func (s *Server) handleThreatTimeline(w http.ResponseWriter, r *http.Request) {
	since, bucket, label := rangeParam(r, "24h")
	tl, err := s.st.ThreatTimeline(since, bucket)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"range": label, "bucket": bucket, "timeline": tl})
}

func (s *Server) handleAck(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	if err := s.st.AckThreat(id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleFirewall(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"status": s.e.FW.Status(), "blocked": s.e.BlockedList(), "you": s.clientIP(r)})
}

func (s *Server) handleBlock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP      string `json:"ip"`
		Reason  string `json:"reason"`
		Confirm bool   `json:"confirm"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if !req.Confirm {
		writeErr(w, 400, "blocking must be confirmed")
		return
	}
	if len(req.Reason) > 200 {
		req.Reason = req.Reason[:200]
	}
	ip, err := s.e.Block(strings.TrimSpace(req.IP), req.Reason, s.clientIP(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "ip": ip})
}

func (s *Server) handleUnblock(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP string `json:"ip"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.e.Unblock(strings.TrimSpace(req.IP)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	since, bucket, label := rangeParam(r, "7d")
	sudo, _ := s.st.AuthEvents([]string{model.AuthSudo, model.AuthSudoFailed, model.AuthSu}, since, "", 200)
	failed, _ := s.st.AuthEvents([]string{model.AuthSSHFailed, model.AuthSSHInvalid}, since, "", 200)
	accepted, _ := s.st.AuthEvents([]string{model.AuthSSHAccepted}, since, "", 200)
	writeJSON(w, map[string]any{
		"range": label, "sessions": s.e.Sessions(), "sudo": sudo, "failed": failed, "accepted": accepted,
		"failed_by_ip": s.st.FailedLoginsByIP(since, 15), "failed_users": s.st.FailedUsernames(since, 15),
		"series": s.st.AuthSeries(since, bucket), "bucket": bucket,
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	since, _, label := rangeParam(r, "7d")
	rules, _ := s.st.AlertRules()
	events, _ := s.st.AlertEvents(since, 200)
	writeJSON(w, map[string]any{"range": label, "rules": rules, "events": events, "channels": s.e.Alerts.Notifier().Channels()})
}

var validKinds = map[string]bool{"metric": true, "threat": true, "login": true, "service": true}
var validMetrics = map[string]bool{"cpu": true, "memory": true, "swap": true, "disk": true, "load": true, "rx": true, "tx": true, "conns": true}

func (s *Server) handleSaveRule(w http.ResponseWriter, r *http.Request) {
	var rule model.AlertRule
	if !readJSON(w, r, &rule) {
		return
	}
	rule.Name = strings.TrimSpace(rule.Name)
	if rule.Name == "" || len(rule.Name) > 100 {
		writeErr(w, 400, "rule needs a name (max 100 characters)")
		return
	}
	if !validKinds[rule.Kind] {
		writeErr(w, 400, "kind must be metric, threat, login or service")
		return
	}
	if rule.Kind == "metric" && (!validMetrics[rule.Metric] || rule.Metric == "") {
		writeErr(w, 400, "unknown metric")
		return
	}
	if rule.Op == "" {
		rule.Op = ">"
	}
	if rule.Op != ">" && rule.Op != "<" {
		writeErr(w, 400, "op must be > or <")
		return
	}
	if rule.Severity == "" {
		rule.Severity = "medium"
	}
	if rule.Cooldown < 0 || rule.Duration < 0 {
		writeErr(w, 400, "cooldown and duration must be positive")
		return
	}
	if err := s.st.SaveAlertRule(&rule); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.e.Alerts.Reload()
	writeJSON(w, map[string]any{"ok": true, "rule": rule})
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	_ = s.st.DeleteAlertRule(id)
	s.e.Alerts.Reload()
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleTestAlert(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Channel string `json:"channel"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.e.Alerts.Test(req.Channel); err != nil {
		writeErr(w, 400, fmt.Sprintf("test via %s failed: %v", req.Channel, err))
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.e.Statuses()
	sort.Slice(st, func(i, j int) bool { return st[i].Name < st[j].Name })
	cfgPath := s.cfg.Path
	if _, err := os.Stat(cfgPath); cfgPath != "" && err != nil {
		cfgPath += " (not found — using defaults)"
	}
	writeJSON(w, map[string]any{
		"statuses": st, "version": Version, "demo": s.cfg.Demo, "root": os.Geteuid() == 0,
		"config_path": cfgPath, "data_dir": s.cfg.DataDir, "listen": s.cfg.Listen, "tls": s.cfg.TLSEnabled(),
		"access_logs": s.cfg.AccessLogs, "retention_days": s.cfg.Retention.Days, "firewall": s.e.FW.Status(),
		"channels": s.e.Alerts.Notifier().Channels(),
	})
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	ch, cancel := s.e.Hub.Subscribe()
	defer cancel()
	fmt.Fprintf(w, "retry: 3000\n\n")
	fl.Flush()
	hb := time.NewTicker(15 * time.Second)
	defer hb.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-hb.C:
			fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, ev.Data)
			fl.Flush()
		}
	}
}
