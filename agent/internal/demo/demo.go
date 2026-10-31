// Package demo feeds the engine with realistic fake data so every feature
// can be explored without a real server (run with --demo).
package demo

import (
	"context"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/myowl/myowl/agent/internal/engine"
	"github.com/myowl/myowl/agent/internal/model"
)

type city struct {
	City, Country, CC string
	Lat, Lon          float64
	W                 int
}

var cities = []city{
	{"Frankfurt", "Germany", "DE", 50.11, 8.68, 8}, {"Berlin", "Germany", "DE", 52.52, 13.40, 5},
	{"London", "United Kingdom", "GB", 51.51, -0.13, 9}, {"Paris", "France", "FR", 48.86, 2.35, 6},
	{"Amsterdam", "Netherlands", "NL", 52.37, 4.90, 5}, {"New York", "United States", "US", 40.71, -74.01, 12},
	{"San Francisco", "United States", "US", 37.77, -122.42, 7}, {"Chicago", "United States", "US", 41.88, -87.63, 5},
	{"Dallas", "United States", "US", 32.78, -96.80, 4}, {"Toronto", "Canada", "CA", 43.65, -79.38, 5},
	{"São Paulo", "Brazil", "BR", -23.55, -46.63, 5}, {"Mexico City", "Mexico", "MX", 19.43, -99.13, 3},
	{"Dhaka", "Bangladesh", "BD", 23.81, 90.41, 8}, {"Chittagong", "Bangladesh", "BD", 22.36, 91.78, 3},
	{"Mumbai", "India", "IN", 19.08, 72.88, 7}, {"Bengaluru", "India", "IN", 12.97, 77.59, 6},
	{"Singapore", "Singapore", "SG", 1.35, 103.82, 5}, {"Tokyo", "Japan", "JP", 35.68, 139.69, 5},
	{"Seoul", "South Korea", "KR", 37.57, 126.98, 3}, {"Sydney", "Australia", "AU", -33.87, 151.21, 4},
	{"Jakarta", "Indonesia", "ID", -6.21, 106.85, 4}, {"Lagos", "Nigeria", "NG", 6.52, 3.38, 3},
	{"Cairo", "Egypt", "EG", 30.04, 31.24, 2}, {"Istanbul", "Turkey", "TR", 41.01, 28.98, 3},
	{"Madrid", "Spain", "ES", 40.42, -3.70, 3}, {"Stockholm", "Sweden", "SE", 59.33, 18.07, 2},
	{"Warsaw", "Poland", "PL", 52.23, 21.01, 3}, {"Dubai", "United Arab Emirates", "AE", 25.20, 55.27, 3},
	{"Johannesburg", "South Africa", "ZA", -26.20, 28.05, 2}, {"Karachi", "Pakistan", "PK", 24.86, 67.01, 3},
}

type attacker struct {
	IP   string
	Geo  model.Geo
	Kind string
}

func g(c, cc, country string, lat, lon float64) model.Geo {
	return model.Geo{City: c, CC: cc, Country: country, Lat: lat, Lon: lon}
}

var attackers = []attacker{
	{"218.92.0.112", g("Nanjing", "CN", "China", 32.06, 118.78), "ssh"},
	{"61.177.172.140", g("Wuxi", "CN", "China", 31.49, 120.31), "ssh"},
	{"45.95.147.236", g("Amsterdam", "NL", "Netherlands", 52.37, 4.90), "ssh"},
	{"92.255.85.37", g("Moscow", "RU", "Russia", 55.76, 37.62), "ssh"},
	{"185.220.101.47", g("Berlin", "DE", "Germany", 52.52, 13.40), "scan"},
	{"103.152.118.20", g("Hanoi", "VN", "Vietnam", 21.03, 105.85), "scan"},
	{"193.42.33.15", g("Saint Petersburg", "RU", "Russia", 59.93, 30.36), "sqli"},
	{"141.98.11.23", g("Vilnius", "LT", "Lithuania", 54.69, 25.28), "trav"},
	{"5.188.62.140", g("Kyiv", "UA", "Ukraine", 50.45, 30.52), "xss"},
	{"167.94.138.44", g("Ann Arbor", "US", "United States", 42.28, -83.74), "portscan"},
	{"89.248.165.71", g("Amsterdam", "NL", "Netherlands", 52.37, 4.90), "portscan"},
	{"20.171.207.88", g("Des Moines", "US", "United States", 41.59, -93.62), "flood"},
}

const adminIP = "103.108.140.25"

var fixedGeo = map[string]model.Geo{
	adminIP:          g("Dhaka", "BD", "Bangladesh", 23.81, 90.41),
	"54.187.216.72":  g("Boardman", "US", "United States", 45.84, -119.70),
	"151.101.66.132": g("San Francisco", "US", "United States", 37.77, -122.42),
	"91.189.91.83":   g("London", "GB", "United Kingdom", 51.51, -0.13),
	"142.250.185.74": g("Frankfurt", "DE", "Germany", 50.11, 8.68),
	"140.82.121.4":   g("Frankfurt", "DE", "Germany", 50.11, 8.68),
	"116.203.0.10":   g("Falkenstein", "DE", "Germany", 50.48, 12.37),
}

const serverIP = "116.203.0.10"

// Demo generates fake data.
type Demo struct {
	e       *engine.Engine
	mu      sync.Mutex
	rnd     *rand.Rand
	r2      *rand.Rand // used by snapshot generators (under mu)
	visitor []string
	start   time.Time
	cpu     float64
	mem     float64
	burst   time.Time // extra load until
	active  map[string]int64
	rx, tx  uint64
	hostile []string // attackers with live connections right now
}

// Setup wires the demo generators into the engine.
func Setup(e *engine.Engine) *Demo {
	d := &Demo{e: e, rnd: rand.New(rand.NewSource(42)), r2: rand.New(rand.NewSource(7)), start: time.Now(), cpu: 22, mem: 63, active: map[string]int64{}}
	for i := 0; i < 420; i++ {
		d.visitor = append(d.visitor, fmt.Sprintf("%d.%d.%d.%d", pick(d.rnd, []int{24, 31, 37, 41, 49, 62, 66, 73, 77, 81, 86, 95, 98, 102, 103, 104, 110, 114, 122, 136, 152, 171, 176, 182, 188, 197, 201, 203}), d.rnd.Intn(254)+1, d.rnd.Intn(254)+1, d.rnd.Intn(253)+1))
	}
	e.Geo.Fake = d.fakeGeo
	e.SysFn = d.system
	e.NetFn = d.network
	e.SessFn = d.sessions
	e.Cfg.ServerLocation.Lat, e.Cfg.ServerLocation.Lon, e.Cfg.ServerLocation.City = 50.48, 12.37, "Falkenstein, Germany"
	for _, s := range [][3]string{
		{"system", "System metrics (/proc)", "demo data"},
		{"services", "systemd services", "demo data"},
		{"connections", "Connections", "demo data (real mode uses netlink sock_diag, falling back to /proc/net)"},
		{"capture", "Packet capture", "demo data (real mode needs root or CAP_NET_RAW)"},
		{"geoip", "GeoIP database", "demo locations"},
		{"access:nginx", "nginx access log", "demo: /var/log/nginx/access.log"},
		{"auth", "SSH / sudo log", "demo: /var/log/auth.log"},
		{"kernel", "Firewall log (port scans)", "demo: /var/log/ufw.log"},
		{"sessions", "Login sessions", "demo data"},
	} {
		e.SetStatus(s[0], s[1], "ok", s[2])
	}
	return d
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.Intn(len(xs))] }

func (d *Demo) fakeGeo(ip string) model.Geo {
	if g, ok := fixedGeo[ip]; ok {
		return g
	}
	for _, a := range attackers {
		if a.IP == ip {
			return a.Geo
		}
	}
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.17.") || ip == "::1" {
		return model.Geo{Private: true}
	}
	h := fnv.New32a()
	h.Write([]byte(ip))
	v := int(h.Sum32())
	total := 0
	for _, c := range cities {
		total += c.W
	}
	n := v % total
	for _, c := range cities {
		if n < c.W {
			j := float64((v>>8)%100-50) / 100
			return model.Geo{City: c.City, Country: c.Country, CC: c.CC, Lat: c.Lat + j*0.3, Lon: c.Lon + j*0.3}
		}
		n -= c.W
	}
	return model.Geo{}
}

// ---------- HTTP traffic ----------

var pages = []struct {
	P      string
	W      int
	Bytes  int
	Lat    float64
	Method string
}{
	{"/", 20, 48000, 35, "GET"}, {"/shop", 8, 62000, 60, "GET"}, {"/shop/product/espresso-grinder-pro", 4, 71000, 75, "GET"},
	{"/shop/product/ceramic-pour-over-set", 3, 69000, 70, "GET"}, {"/blog", 5, 39000, 30, "GET"},
	{"/blog/how-to-brew-the-perfect-cup", 6, 54000, 28, "GET"}, {"/blog/cold-brew-at-home", 3, 51000, 27, "GET"},
	{"/about", 2, 22000, 20, "GET"}, {"/contact", 2, 18000, 22, "GET"}, {"/cart", 3, 31000, 90, "GET"},
	{"/api/products?page=1", 7, 9200, 45, "GET"}, {"/api/products?page=2", 3, 9100, 48, "GET"},
	{"/api/cart", 3, 1200, 110, "POST"}, {"/api/checkout", 1, 800, 420, "POST"}, {"/api/session", 3, 450, 15, "GET"},
	{"/static/css/main.4f2a1c.css", 12, 28000, 2, "GET"}, {"/static/js/app.9d81e2.js", 12, 182000, 3, "GET"},
	{"/static/img/hero.webp", 9, 142000, 2, "GET"}, {"/favicon.ico", 6, 4286, 1, "GET"}, {"/robots.txt", 1, 120, 1, "GET"},
	{"/sitemap.xml", 1, 8400, 6, "GET"}, {"/feed.xml", 1, 21000, 12, "GET"}, {"/account/login", 2, 16000, 55, "GET"},
	{"/account/login", 1, 300, 180, "POST"},
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
}

func (d *Demo) weightedPage() int {
	tot := 0
	for _, p := range pages {
		tot += p.W
	}
	n := d.rnd.Intn(tot)
	for i, p := range pages {
		if n < p.W {
			return i
		}
		n -= p.W
	}
	return 0
}

func (d *Demo) mkReq(ts int64, ip, method, target string, status int, bytes int64, lat float64, ua string) *model.HTTPRequest {
	p, q := target, ""
	if i := strings.IndexByte(target, '?'); i >= 0 {
		p, q = target[:i], target[i+1:]
	}
	t := time.UnixMilli(ts).UTC()
	raw := fmt.Sprintf(`%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s" %.3f`, ip, t.Format("02/Jan/2006:15:04:05 -0700"), method, target, status, bytes, ua, lat/1000)
	return &model.HTTPRequest{TS: ts, IP: ip, Method: method, Path: p, Query: q, Proto: "HTTP/1.1", Status: status, Bytes: bytes,
		UA: ua, Referer: "-", Host: "brewhouse.example", LatencyMs: math.Round(lat*10) / 10, Source: "nginx", Raw: raw}
}

func (d *Demo) legit(ts int64) *model.HTTPRequest {
	pg := pages[d.weightedPage()]
	ip := d.visitor[int(math.Abs(d.rnd.NormFloat64()*110))%len(d.visitor)]
	ua := userAgents[int(fnvHash(ip))%len(userAgents)]
	status := 200
	r := d.rnd.Float64()
	switch {
	case strings.HasPrefix(pg.P, "/static") && r < 0.35:
		status = 304
	case r < 0.012:
		status = 404
	case r < 0.017:
		status = 500
	case r < 0.03 && pg.Method == "GET" && !strings.HasPrefix(pg.P, "/static"):
		status = 301
	}
	if pg.P == "/account/login" && pg.Method == "POST" && d.rnd.Float64() < 0.2 {
		status = 401
	}
	lat := pg.Lat * math.Exp(d.rnd.NormFloat64()*0.45)
	if status == 500 {
		lat *= 6
	}
	b := int64(float64(pg.Bytes) * (0.9 + d.rnd.Float64()*0.2))
	if status == 304 || status == 301 {
		b = 0
	}
	return d.mkReq(ts, ip, pg.Method, pg.P, status, b, lat, ua)
}

func fnvHash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

var scanPaths = []string{"/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/index.php", "/xmlrpc.php", "/wp-admin/setup-config.php",
	"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/admin/config.php", "/.aws/credentials", "/backup.sql", "/actuator/env",
	"/server-status", "/cgi-bin/luci/;stok=/locale", "/boaform/admin/formLogin", "/config.json", "/.DS_Store", "/info.php",
	"/wp-content/plugins/wp-file-manager/readme.txt", "/db.sql", "/docker-compose.yml", "/.vscode/sftp.json", "/owa/auth/logon.aspx",
	"/HNAP1/", "/solr/admin/info/system", "/telescope/requests", "/_ignition/execute-solution", "/manager/html", "/www.zip",
	"/.htpasswd", "/sftp-config.json", "/api/v1/pods", "/console/", "/remote/login", "/geoserver/web/"}

var sqliTargets = []string{
	"/shop/product?id=1' UNION SELECT username,password FROM users--",
	"/api/products?page=1' OR '1'='1",
	"/search?q=" + url.QueryEscape("coffee' AND SLEEP(5)-- -"),
	"/shop/product?id=" + url.QueryEscape("1 AND extractvalue(1,concat(0x7e,@@version))"),
	"/api/products?sort=" + url.QueryEscape("name; DROP TABLE orders;--"),
	"/search?q=" + url.QueryEscape("x' UNION ALL SELECT NULL,table_name FROM information_schema.tables--"),
}
var xssTargets = []string{
	"/search?q=" + url.QueryEscape("<script>alert(document.cookie)</script>"),
	"/contact?name=" + url.QueryEscape(`"><img src=x onerror=alert(1)>`),
	"/blog?ref=" + url.QueryEscape("javascript:alert('xss')"),
	"/search?q=" + url.QueryEscape("<svg/onload=prompt(1)>"),
}
var travTargets = []string{
	"/static/../../../../etc/passwd", "/download?file=../../../../etc/shadow",
	"/index.php?page=php://filter/convert.base64-encode/resource=index", "/api/files?path=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
	"/images/..%2f..%2f..%2f..%2fproc/self/environ", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh",
}
var attackUAs = []string{"Mozilla/5.0 zgrab/0.x", "python-requests/2.32.3", "Go-http-client/1.1", "curl/8.5.0",
	"Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))", "sqlmap/1.8.5#stable (https://sqlmap.org)"}

type ev struct {
	ts int64
	fn func()
}

// incident builds the events of one attack starting at ts.
func (d *Demo) incident(kind string, ts int64, backfill bool) []ev {
	var out []ev
	add := func(t int64, f func()) { out = append(out, ev{t, f}) }
	req := func(t int64, r *model.HTTPRequest) { add(t, func() { d.e.IngestRequest(r, backfill) }) }
	auth := func(t int64, a *model.AuthEvent) { add(t, func() { d.e.IngestAuth(a, backfill) }) }
	at := func(k string) attacker {
		var xs []attacker
		for _, a := range attackers {
			if a.Kind == k {
				xs = append(xs, a)
			}
		}
		return pick(d.rnd, xs)
	}
	switch kind {
	case "ssh":
		a := at("ssh")
		users := []string{"root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "user", "deploy", "ftpuser", "support", "pi"}
		n := 6 + d.rnd.Intn(35)
		t := ts
		for i := 0; i < n; i++ {
			t += int64(800 + d.rnd.Intn(5000))
			u := pick(d.rnd, users)
			port := 30000 + d.rnd.Intn(30000)
			k, raw := model.AuthSSHFailed, fmt.Sprintf("Failed password for %s from %s port %d ssh2", u, a.IP, port)
			if u != "root" && u != "ubuntu" && u != "deploy" {
				k, raw = model.AuthSSHInvalid, fmt.Sprintf("Failed password for invalid user %s from %s port %d ssh2", u, a.IP, port)
			}
			auth(t, &model.AuthEvent{TS: t, Kind: k, User: u, IP: a.IP, Port: port, Method: "password", Raw: "sshd[" + fmt.Sprint(2000+d.rnd.Intn(60000)) + "]: " + raw})
		}
		d.hostileFor(a.IP, ts, t)
	case "scan":
		a := at("scan")
		ua := pick(d.rnd, attackUAs)
		t := ts
		n := 25 + d.rnd.Intn(30)
		for i := 0; i < n; i++ {
			t += int64(150 + d.rnd.Intn(1500))
			req(t, d.mkReq(t, a.IP, "GET", pick(d.rnd, scanPaths), 404, 153, 1+d.rnd.Float64()*3, ua))
		}
		d.hostileFor(a.IP, ts, t)
	case "sqli", "xss", "trav":
		a := at(kind)
		targets := map[string][]string{"sqli": sqliTargets, "xss": xssTargets, "trav": travTargets}[kind]
		ua := pick(d.rnd, attackUAs)
		t := ts
		for i := 0; i < 3+d.rnd.Intn(6); i++ {
			t += int64(500 + d.rnd.Intn(4000))
			st := pick(d.rnd, []int{400, 403, 404, 500, 200})
			req(t, d.mkReq(t, a.IP, "GET", pick(d.rnd, targets), st, int64(160+d.rnd.Intn(4000)), 5+d.rnd.Float64()*80, ua))
		}
		d.hostileFor(a.IP, ts, t)
	case "portscan":
		a := at("portscan")
		ports := []int{21, 23, 25, 110, 135, 139, 445, 1433, 1521, 2375, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017, 5060, 8888}
		t := ts
		for _, p := range ports {
			t += int64(50 + d.rnd.Intn(400))
			p := p
			tt := t
			add(t, func() { d.e.IngestProbe(a.IP, p, tt, "ufw") })
		}
	case "flood":
		a := at("flood")
		ua := "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"
		t := ts
		for i := 0; i < 420; i++ {
			t += int64(60 + d.rnd.Intn(140))
			pg := pages[d.weightedPage()]
			req(t, d.mkReq(t, a.IP, "GET", pg.P, 200, int64(pg.Bytes), pg.Lat*1.4, ua))
		}
		d.hostileFor(a.IP, ts, t)
		d.mu.Lock()
		if !backfill {
			d.burst = time.UnixMilli(t)
		}
		d.mu.Unlock()
	case "login":
		user := pick(d.rnd, []string{"deploy", "deploy", "admin"})
		port := 40000 + d.rnd.Intn(20000)
		auth(ts, &model.AuthEvent{TS: ts, Kind: model.AuthSSHAccepted, User: user, IP: adminIP, Port: port, Method: "publickey",
			Raw: fmt.Sprintf("sshd[%d]: Accepted publickey for %s from %s port %d ssh2: ED25519 SHA256:q3Vb0...", 3000+d.rnd.Intn(50000), user, adminIP, port)})
		cmds := []string{"/usr/bin/systemctl restart nginx", "/usr/bin/apt upgrade -y", "/usr/bin/journalctl -u app -n 200",
			"/usr/bin/docker compose pull", "/usr/bin/systemctl status postgresql", "/usr/sbin/ufw status", "/usr/bin/certbot renew"}
		t := ts
		for i := 0; i < 1+d.rnd.Intn(3); i++ {
			t += int64(20000 + d.rnd.Intn(120000))
			c := pick(d.rnd, cmds)
			auth(t, &model.AuthEvent{TS: t, Kind: model.AuthSudo, User: user, TTY: "pts/0", RunAs: "root", Command: c,
				Raw: fmt.Sprintf("sudo: %s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=%s", user, user, c)})
		}
	}
	return out
}

func (d *Demo) hostileFor(ip string, from, to int64) {
	d.mu.Lock()
	if to > d.active[ip] {
		d.active[ip] = to + 20000
	}
	d.mu.Unlock()
}

// Backfill inserts 24h of history so charts are not empty.
func (d *Demo) Backfill() {
	e := d.e
	e.Alerts.Quiet = true
	defer func() { e.Alerts.Quiet = false }()
	now := time.Now().Add(-90 * time.Second).UnixMilli()
	start := now - 24*3600000
	var evs []ev
	for m := start; m < now; m += 60000 {
		hr := float64(time.UnixMilli(m).UTC().Hour())
		diurnal := 0.55 + 0.45*math.Sin((hr-9)/24*2*math.Pi)
		n := int(diurnal*16) + d.rnd.Intn(6)
		for i := 0; i < n; i++ {
			ts := m + int64(d.rnd.Intn(60000))
			r := d.legit(ts)
			evs = append(evs, ev{ts, func() { e.IngestRequest(r, true) }})
		}
		cpu := 14 + 30*diurnal + d.rnd.Float64()*8
		mem := 58 + 8*diurnal + d.rnd.Float64()*2
		rx := (300e3 + 1.6e6*diurnal) * (0.8 + d.rnd.Float64()*0.4)
		p := model.MetricPoint{TS: m, CPU: cpu, Mem: mem, Swap: 6 + d.rnd.Float64(), Disk: 61.5 + float64(m-start)/float64(24*3600000)*0.6,
			Load1: cpu / 100 * 4 * (0.8 + d.rnd.Float64()*0.4), Rx: rx, Tx: rx * 2.6, Conns: float64(40 + int(diurnal*90) + d.rnd.Intn(20)), Reqs: float64(n)}
		mm := m
		evs = append(evs, ev{m, func() { _ = mm; _ = e.St.InsertMetric(p) }})
	}
	// scheduled incidents (minutes ago)
	sched := []struct {
		ago  int
		kind string
	}{
		{1400, "ssh"}, {1330, "scan"}, {1260, "portscan"}, {1210, "ssh"}, {1150, "login"}, {1100, "trav"}, {1020, "ssh"},
		{960, "scan"}, {900, "sqli"}, {845, "ssh"}, {790, "portscan"}, {720, "ssh"}, {660, "login"}, {610, "xss"},
		{545, "flood"}, {500, "ssh"}, {455, "scan"}, {400, "ssh"}, {350, "sqli"}, {300, "login"}, {265, "portscan"},
		{230, "ssh"}, {190, "trav"}, {160, "scan"}, {130, "ssh"}, {100, "xss"}, {75, "login"}, {55, "ssh"}, {38, "sqli"},
		{25, "portscan"}, {14, "scan"}, {8, "ssh"},
	}
	for _, s := range sched {
		evs = append(evs, d.incident(s.kind, time.Now().UnixMilli()-int64(s.ago)*60000, true)...)
	}
	// CPU spike during the flood (545 min ago) for the alert history
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].ts < evs[j].ts })
	for _, x := range evs {
		x.fn()
	}
	nowMs := time.Now().UnixMilli()
	hist := []model.AlertEvent{
		{TS: nowMs - 545*60000 + 240000, RuleName: "CPU usage high", Severity: "high", Title: "CPU above 90% for 5 minutes", Message: "CPU has been at 94% for 5 minutes (a crawler sent 420 requests in one minute). Websites may be slow.", Delivered: "telegram: sent; email: sent"},
		{TS: nowMs - 1150*60000, RuleName: "SSH login", Severity: "info", Title: "New SSH login: deploy", Message: "deploy logged in with publickey from 103.108.140.25 (Dhaka, Bangladesh).", Delivered: "telegram: sent"},
		{TS: nowMs - 1020*60000 + 60000, RuleName: "Serious threats", Severity: "high", Title: "SSH brute force from 218.92.0.112", Message: "Someone in Nanjing, China tried to log in over SSH 38 times with wrong passwords.", Delivered: "telegram: sent; webhook: sent"},
		{TS: nowMs - 700*60000, RuleName: "Service crashed", Severity: "high", Title: "certbot.service failed", Message: "The service certbot.service stopped with an error. Run: journalctl -u certbot.service", Delivered: "telegram: sent; email: sent"},
		{TS: nowMs - 660*60000, RuleName: "SSH login", Severity: "info", Title: "New SSH login: deploy", Message: "deploy logged in with publickey from 103.108.140.25 (Dhaka, Bangladesh).", Delivered: "telegram: sent"},
		{TS: nowMs - 350*60000 + 30000, RuleName: "Serious threats", Severity: "high", Title: "SQL injection attempt from 193.42.33.15", Message: "Someone in Saint Petersburg, Russia sent requests that try to trick your database into leaking data.", Delivered: "telegram: sent; webhook: sent"},
		{TS: nowMs - 300*60000, RuleName: "SSH login", Severity: "info", Title: "New SSH login: admin", Message: "admin logged in with publickey from 103.108.140.25 (Dhaka, Bangladesh).", Delivered: "telegram: sent"},
		{TS: nowMs - 75*60000, RuleName: "SSH login", Severity: "info", Title: "New SSH login: deploy", Message: "deploy logged in with publickey from 103.108.140.25 (Dhaka, Bangladesh).", Delivered: "telegram: sent"},
		{TS: nowMs - 38*60000 + 20000, RuleName: "Serious threats", Severity: "high", Title: "SQL injection attempt from 193.42.33.15", Message: "Someone in Saint Petersburg, Russia sent requests that try to trick your database into leaking data.", Delivered: "telegram: sent; webhook: sent"},
	}
	rules, _ := e.St.AlertRules()
	for i := range hist {
		for _, r := range rules {
			if r.Name == hist[i].RuleName {
				hist[i].RuleID = r.ID
			}
		}
		_ = e.St.InsertAlertEvent(&hist[i])
	}
	for _, b := range []struct{ ip, reason string }{{"218.92.0.112", "SSH brute force (38 failed logins)"}, {"141.98.11.23", "Path traversal attempts"}} {
		_, _ = e.Block(b.ip, b.reason, "")
	}
}

// Run generates live traffic until ctx is done.
func (d *Demo) Run(ctx context.Context) {
	next := time.Now().Add(6 * time.Second)
	kinds := []string{"ssh", "ssh", "scan", "sqli", "xss", "trav", "portscan", "login", "ssh", "scan"}
	floodAt := time.Now().Add(4 * time.Minute)
	tk := time.NewTicker(250 * time.Millisecond)
	defer tk.Stop()
	var queue []ev
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tk.C:
			d.mu.Lock()
			hr := float64(now.UTC().Hour())
			diurnal := 0.55 + 0.45*math.Sin((hr-9)/24*2*math.Pi)
			n := 0
			if d.rnd.Float64() < diurnal*0.9 {
				n = 1 + d.rnd.Intn(2)
			}
			var reqs []*model.HTTPRequest
			for i := 0; i < n; i++ {
				reqs = append(reqs, d.legit(now.UnixMilli()-int64(d.rnd.Intn(250))))
			}
			var kind string
			if now.After(next) {
				kind = pick(d.rnd, kinds)
				next = now.Add(time.Duration(35+d.rnd.Intn(55)) * time.Second)
			}
			if now.After(floodAt) {
				kind = "flood"
				floodAt = now.Add(time.Duration(15+d.rnd.Intn(15)) * time.Minute)
			}
			d.mu.Unlock()
			for _, r := range reqs {
				d.e.IngestRequest(r, false)
			}
			if kind != "" {
				// incident timestamps are spread into the future; replay them in real time
				queue = append(queue, d.incident(kind, now.UnixMilli(), false)...)
				sort.SliceStable(queue, func(i, j int) bool { return queue[i].ts < queue[j].ts })
			}
			cut := now.UnixMilli()
			i := 0
			for i < len(queue) && queue[i].ts <= cut {
				queue[i].fn()
				i++
			}
			queue = queue[i:]
		}
	}
}
