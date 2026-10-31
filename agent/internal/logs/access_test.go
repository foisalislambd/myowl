package logs

import (
	"testing"
)

func TestParseCombined(t *testing.T) {
	line := `203.0.113.9 - - [30/Oct/2026:01:02:03 +0600] "GET /shop/item?id=5 HTTP/1.1" 200 5123 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"`
	r, err := ParseAccessLine(line, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "203.0.113.9" || r.Method != "GET" || r.Path != "/shop/item" || r.Query != "id=5" || r.Status != 200 || r.Bytes != 5123 {
		t.Fatalf("bad parse: %+v", r)
	}
	if r.UA != "Mozilla/5.0 (X11; Linux x86_64)" || r.Referer != "https://example.com/" {
		t.Fatalf("bad ua/referer: %q %q", r.UA, r.Referer)
	}
	if r.LatencyMs != -1 {
		t.Fatalf("latency should be unknown, got %v", r.LatencyMs)
	}
	if got := r.TS; got != 1793300523000 {
		t.Fatalf("timestamp: %d", got)
	}
}

func TestParseCombinedWithLatency(t *testing.T) {
	line := `198.51.100.7 - bob [30/Oct/2026:01:02:03 +0000] "POST /api/login HTTP/2.0" 401 31 "-" "curl/8.5.0" 0.123`
	r, err := ParseAccessLine(line, "combined")
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != "POST" || r.Status != 401 || r.User != "bob" || r.Proto != "HTTP/2.0" {
		t.Fatalf("bad parse: %+v", r)
	}
	if r.LatencyMs < 122.9 || r.LatencyMs > 123.1 {
		t.Fatalf("latency: %v", r.LatencyMs)
	}
}

func TestParseCommon(t *testing.T) {
	line := `192.0.2.1 - - [10/Oct/2026:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326`
	r, err := ParseAccessLine(line, "common")
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "192.0.2.1" || r.Path != "/apache_pb.gif" || r.Bytes != 2326 || r.UA != "" {
		t.Fatalf("bad parse: %+v", r)
	}
}

func TestParseDashBytesAndBadRequest(t *testing.T) {
	r, err := ParseAccessLine(`192.0.2.1 - - [10/Oct/2026:13:55:36 +0000] "-" 400 - "-" "-"`, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != 400 || r.Bytes != 0 {
		t.Fatalf("bad parse: %+v", r)
	}
}

func TestParseVhostCombined(t *testing.T) {
	line := `example.com:443 203.0.113.9 - - [30/Oct/2026:01:02:03 +0600] "GET / HTTP/1.1" 200 10 "-" "UA"`
	r, err := ParseAccessLine(line, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "203.0.113.9" {
		t.Fatalf("ip: %q (host %q)", r.IP, r.Host)
	}
}

func TestParseIPv6(t *testing.T) {
	line := `2001:db8::1 - - [30/Oct/2026:01:02:03 +0600] "GET / HTTP/1.1" 200 10 "-" "UA"`
	r, err := ParseAccessLine(line, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "2001:db8::1" {
		t.Fatalf("ip: %q", r.IP)
	}
}

func TestParseCaddyJSON(t *testing.T) {
	line := `{"level":"info","ts":1793300523.5,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"203.0.113.50","remote_port":"51234","client_ip":"203.0.113.50","proto":"HTTP/2.0","method":"GET","host":"example.com","uri":"/blog?page=2","headers":{"User-Agent":["Mozilla/5.0"],"Referer":["https://google.com/"]}},"bytes_read":0,"user_id":"","duration":0.0042,"size":1234,"status":200}`
	r, err := ParseAccessLine(line, "json")
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "203.0.113.50" || r.Method != "GET" || r.Path != "/blog" || r.Query != "page=2" || r.Status != 200 || r.Bytes != 1234 || r.Host != "example.com" {
		t.Fatalf("bad parse: %+v", r)
	}
	if r.UA != "Mozilla/5.0" {
		t.Fatalf("ua: %q", r.UA)
	}
	if r.LatencyMs < 4.1 || r.LatencyMs > 4.3 {
		t.Fatalf("latency: %v", r.LatencyMs)
	}
	if r.TS != 1793300523500 {
		t.Fatalf("ts: %d", r.TS)
	}
}

func TestParseGenericJSON(t *testing.T) {
	line := `{"time":"2026-10-30T01:02:03+06:00","remote_addr":"198.51.100.4","request_method":"PUT","request_uri":"/api/x?a=1","status":"201","body_bytes_sent":"77","http_user_agent":"k6","request_time":"0.250"}`
	r, err := ParseAccessLine(line, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if r.IP != "198.51.100.4" || r.Method != "PUT" || r.Path != "/api/x" || r.Status != 201 || r.Bytes != 77 || r.UA != "k6" {
		t.Fatalf("bad parse: %+v", r)
	}
	if r.LatencyMs < 249 || r.LatencyMs > 251 {
		t.Fatalf("latency: %v", r.LatencyMs)
	}
}

func TestParseGarbage(t *testing.T) {
	for _, l := range []string{"", "hello world", "{not json"} {
		if _, err := ParseAccessLine(l, "auto"); err == nil {
			t.Fatalf("expected error for %q", l)
		}
	}
}
