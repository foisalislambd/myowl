package server

import (
	"strings"
	"testing"
)

func TestPrefsRoundTrip(t *testing.T) {
	ts, s := newTestServer(t)
	c := newClient(t, ts.URL)
	tok := s.st.Get("setup_token")
	if code, _ := c.do("POST", "/api/auth/setup", map[string]string{"password": "correct horse", "token": tok}, false); code != 200 {
		t.Fatalf("setup: %d", code)
	}
	if code, b := c.do("GET", "/api/prefs", nil, false); code != 200 || len(b["prefs"].(map[string]any)) != 0 {
		t.Fatalf("empty prefs: %d %v", code, b)
	}
	p := map[string]any{"theme": "cyan", "accent": "#ff00aa", "font": "large"}
	if code, _ := c.do("PUT", "/api/prefs", p, false); code != 403 {
		t.Fatalf("put without csrf: %d", code)
	}
	if code, b := c.do("PUT", "/api/prefs", p, true); code != 200 {
		t.Fatalf("put: %d %v", code, b)
	}
	code, b := c.do("GET", "/api/prefs", nil, false)
	got := b["prefs"].(map[string]any)
	if code != 200 || got["theme"] != "cyan" || got["font"] != "large" {
		t.Fatalf("get: %d %v", code, b)
	}
	if code, _ := c.do("PUT", "/api/prefs", []int{1, 2}, true); code != 400 {
		t.Fatalf("non-object accepted: %d", code)
	}
	if code, _ := c.do("PUT", "/api/prefs", map[string]string{"x": strings.Repeat("a", 5000)}, true); code != 413 {
		t.Fatalf("oversize accepted: %d", code)
	}
}
