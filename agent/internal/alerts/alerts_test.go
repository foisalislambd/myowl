package alerts

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/myowl/myowl/agent/internal/config"
	"github.com/myowl/myowl/agent/internal/model"
	"github.com/myowl/myowl/agent/internal/store"
)

func setup(t *testing.T, cfg *config.Config) (*Manager, *[]model.AlertEvent, *sync.Mutex) {
	st, err := store.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	m := NewManager(st, NewNotifier(cfg))
	var mu sync.Mutex
	evs := &[]model.AlertEvent{}
	m.OnEvent = func(e model.AlertEvent) { mu.Lock(); *evs = append(*evs, e); mu.Unlock() }
	return m, evs, &mu
}

func TestDefaultRulesSeeded(t *testing.T) {
	m, _, _ := setup(t, config.Default())
	if len(m.rules) != len(DefaultRules()) {
		t.Fatalf("got %d rules", len(m.rules))
	}
}

func TestThreatSeverityAndCooldown(t *testing.T) {
	m, evs, mu := setup(t, config.Default())
	m.OnThreat(&model.Threat{Type: "x", IP: "1.2.3.4", Severity: "medium", Title: "meh"})
	m.OnThreat(&model.Threat{Type: "x", IP: "1.2.3.4", Severity: "critical", Title: "bad"})
	m.OnThreat(&model.Threat{Type: "x", IP: "1.2.3.4", Severity: "critical", Title: "bad again"})
	mu.Lock()
	defer mu.Unlock()
	if len(*evs) != 1 || (*evs)[0].Title != "bad" {
		t.Fatalf("want exactly one alert (severity filter + cooldown), got %+v", *evs)
	}
}

func TestMetricRuleAndService(t *testing.T) {
	m, evs, mu := setup(t, config.Default())
	_ = m.st.SaveAlertRule(&model.AlertRule{Name: "cpu now", Kind: "metric", Metric: "cpu", Op: ">", Threshold: 50, Duration: 0, Severity: "high", Channels: []string{"dashboard"}, Cooldown: 5, Enabled: true})
	m.Reload()
	s := &model.SystemSnapshot{}
	s.CPU.Usage = 20
	m.EvalMetrics(s, nil, nil)
	s.CPU.Usage = 95
	s.Services = []model.Service{{Name: "nginx.service", Active: "failed"}}
	m.EvalMetrics(s, nil, map[string]string{"nginx.service": "active"})
	mu.Lock()
	defer mu.Unlock()
	if len(*evs) != 2 {
		t.Fatalf("want cpu + service alerts, got %+v", *evs)
	}
}

func TestWebhookDelivery(t *testing.T) {
	got := make(chan map[string]any, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		got <- v
	}))
	defer srv.Close()
	cfg := config.Default()
	cfg.Notify.Webhook.URL = srv.URL
	n := NewNotifier(cfg)
	if !n.Channels()["webhook"] || n.Channels()["telegram"] {
		t.Fatalf("channels: %v", n.Channels())
	}
	if err := n.Send("webhook", Message{Title: "T", Text: "hello", Severity: "high"}); err != nil {
		t.Fatal(err)
	}
	select {
	case v := <-got:
		if v["title"] != "T" || v["message"] != "hello" {
			t.Fatalf("payload %v", v)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("webhook not called")
	}
	if err := n.Send("telegram", Message{}); err == nil {
		t.Fatal("unconfigured channel should error")
	}
}
