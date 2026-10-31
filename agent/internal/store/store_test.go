package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/myowl/myowl/agent/internal/model"
)

func open(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestKV(t *testing.T) {
	st := open(t)
	if st.Get("x") != "" {
		t.Fatal("expected empty")
	}
	_ = st.Set("x", "1")
	_ = st.Set("x", "2")
	if st.Get("x") != "2" {
		t.Fatalf("got %q", st.Get("x"))
	}
	_ = st.Delete("x")
	if st.Get("x") != "" {
		t.Fatal("expected deleted")
	}
}

func TestRequestsFilterAndPrune(t *testing.T) {
	st := open(t)
	now := time.Now().UnixMilli()
	old := time.Now().AddDate(0, 0, -30).UnixMilli()
	reqs := []*model.HTTPRequest{
		{TS: old, IP: "1.1.1.1", Method: "GET", Path: "/old", Status: 200},
		{TS: now, IP: "2.2.2.2", Method: "GET", Path: "/a", Status: 200},
		{TS: now, IP: "2.2.2.2", Method: "POST", Path: "/login", Status: 401},
		{TS: now, IP: "3.3.3.3", Method: "GET", Path: "/.env", Status: 404, Flags: []string{"scanner_path"}},
		{TS: now, IP: "3.3.3.3", Method: "GET", Path: "/x", Status: 502},
	}
	if err := st.InsertRequests(reqs); err != nil {
		t.Fatal(err)
	}
	all, _ := st.Requests(RequestFilter{Limit: 100})
	if len(all) != 5 {
		t.Fatalf("want 5, got %d", len(all))
	}
	if all[0].ID < all[len(all)-1].ID {
		t.Fatal("expected newest first")
	}
	byIP, _ := st.Requests(RequestFilter{IP: "2.2.2.2", Limit: 100})
	if len(byIP) != 2 {
		t.Fatalf("ip filter: %d", len(byIP))
	}
	c4, _ := st.Requests(RequestFilter{Status: "4xx", Limit: 100})
	if len(c4) != 2 {
		t.Fatalf("4xx filter: %d", len(c4))
	}
	th, _ := st.Requests(RequestFilter{Threats: true, Limit: 100})
	if len(th) != 1 || th[0].Path != "/.env" || len(th[0].Flags) != 1 {
		t.Fatalf("threat filter: %+v", th)
	}
	one, err := st.Request(th[0].ID)
	if err != nil || one.IP != "3.3.3.3" {
		t.Fatalf("Request(id): %v %+v", err, one)
	}
	st.Prune(14, 3)
	left, _ := st.Requests(RequestFilter{Limit: 100})
	if len(left) != 3 {
		t.Fatalf("after prune want 3 (retention + cap), got %d", len(left))
	}
	for _, r := range left {
		if r.Path == "/old" {
			t.Fatal("old request survived retention")
		}
	}
}

func TestMetricsBuckets(t *testing.T) {
	st := open(t)
	base := time.Now().Add(-10 * time.Minute).Truncate(time.Minute).UnixMilli()
	for i := 0; i < 6; i++ {
		_ = st.InsertMetric(model.MetricPoint{TS: base + int64(i)*20000, CPU: float64(i * 10)})
	}
	pts, err := st.Metrics(base, 60000)
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != 2 {
		t.Fatalf("want 2 one-minute buckets, got %d", len(pts))
	}
	if pts[0].CPU != 10 { // avg of 0,10,20
		t.Fatalf("bucket avg cpu = %v", pts[0].CPU)
	}
}

func TestSessionsAndBlocked(t *testing.T) {
	st := open(t)
	exp := time.Now().Add(time.Hour).UnixMilli()
	_ = st.CreateSession("h1", "c1", time.Now().UnixMilli(), exp, "1.2.3.4", "ua")
	csrf, e, ok := st.GetSession("h1")
	if !ok || csrf != "c1" || e != exp {
		t.Fatalf("session: %v %v %v", csrf, e, ok)
	}
	_ = st.DeleteAllSessions()
	if _, _, ok := st.GetSession("h1"); ok {
		t.Fatal("session should be gone")
	}
	_ = st.AddBlocked(model.BlockedIP{IP: "5.6.7.8", Reason: "test", TS: time.Now().UnixMilli()})
	b, _ := st.Blocked()
	if len(b) != 1 || b[0].IP != "5.6.7.8" {
		t.Fatalf("blocked: %+v", b)
	}
	_ = st.RemoveBlocked("5.6.7.8")
	b, _ = st.Blocked()
	if len(b) != 0 {
		t.Fatal("unblock failed")
	}
}
