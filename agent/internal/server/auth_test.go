package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/myowl/myowl/agent/internal/config"
	"github.com/myowl/myowl/agent/internal/engine"
	"github.com/myowl/myowl/agent/internal/store"
)

func newTestServer(t *testing.T) (*httptest.Server, *Server) {
	t.Helper()
	cfg := config.Default()
	cfg.DataDir = t.TempDir()
	st, err := store.Open(filepath.Join(cfg.DataDir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(cfg, st, engine.New(cfg, st))
	if s.EnsureSetupToken() == "" {
		t.Fatal("no setup token")
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, s
}

type client struct {
	t    *testing.T
	base string
	c    *http.Client
}

func newClient(t *testing.T, base string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{t: t, base: base, c: &http.Client{Jar: jar}}
}

func (c *client) csrf() string {
	u, _ := url.Parse(c.base)
	for _, ck := range c.c.Jar.Cookies(u) {
		if ck.Name == "myowl_csrf" {
			return ck.Value
		}
	}
	return ""
}

func (c *client) do(method, path string, body any, csrf bool) (int, map[string]any) {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", c.base)
	if csrf {
		req.Header.Set("X-CSRF-Token", c.csrf())
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestFirstRunSetupAndLogin(t *testing.T) {
	ts, s := newTestServer(t)
	c := newClient(t, ts.URL)

	code, st := c.do("GET", "/api/auth/status", nil, false)
	if code != 200 || st["setup_required"] != true || st["authenticated"] != false {
		t.Fatalf("status: %d %v", code, st)
	}
	if code, _ := c.do("GET", "/api/overview", nil, false); code != 401 {
		t.Fatalf("overview without login: %d", code)
	}
	// Wrong setup code is refused.
	if code, _ := c.do("POST", "/api/auth/setup", map[string]string{"password": "correct horse", "token": "nope"}, false); code != 403 {
		t.Fatalf("bad token: %d", code)
	}
	tok := s.st.Get("setup_token")
	if code, _ := c.do("POST", "/api/auth/setup", map[string]string{"password": "short", "token": tok}, false); code != 400 {
		t.Fatalf("short password: %d", code)
	}
	if code, b := c.do("POST", "/api/auth/setup", map[string]string{"password": "correct horse", "token": tok}, false); code != 200 {
		t.Fatalf("setup: %d %v", code, b)
	}
	if s.st.Get("setup_token") != "" {
		t.Fatal("setup token should be deleted")
	}
	// Setup cannot be repeated.
	c2 := newClient(t, ts.URL)
	if code, _ := c2.do("POST", "/api/auth/setup", map[string]string{"password": "attacker pw", "token": tok}, false); code != 409 {
		t.Fatalf("second setup: %d", code)
	}
	// Logged in after setup.
	if code, st := c.do("GET", "/api/auth/status", nil, false); code != 200 || st["authenticated"] != true {
		t.Fatalf("after setup: %v", st)
	}
	// Mutating request without CSRF header fails, with it succeeds.
	rule := map[string]any{"name": "cpu", "kind": "metric", "metric": "cpu", "op": ">", "value": 90, "for_sec": 60, "severity": "medium", "enabled": true}
	if code, _ := c.do("POST", "/api/alerts/rules", rule, false); code != 403 {
		t.Fatalf("no csrf: %d", code)
	}
	if code, b := c.do("POST", "/api/alerts/rules", rule, true); code != 200 {
		t.Fatalf("with csrf: %d %v", code, b)
	}
	// Logout then login.
	c.do("POST", "/api/auth/logout", nil, true)
	if code, _ := c.do("GET", "/api/alerts", nil, false); code != 401 {
		t.Fatalf("after logout: %d", code)
	}
	if code, _ := c.do("POST", "/api/auth/login", map[string]string{"password": "correct horse"}, false); code != 200 {
		t.Fatalf("login: %d", code)
	}
}

func TestCrossOriginRejected(t *testing.T) {
	ts, _ := newTestServer(t)
	req, _ := http.NewRequest("POST", ts.URL+"/api/auth/login", bytes.NewReader([]byte(`{"password":"x"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("cross-origin login: %d", resp.StatusCode)
	}
}

func TestLoginRateLimit(t *testing.T) {
	ts, s := newTestServer(t)
	h, _ := HashPassword("correct horse")
	_ = s.st.Set("password_hash", h)
	c := newClient(t, ts.URL)
	for i := 0; i < 5; i++ {
		if code, _ := c.do("POST", "/api/auth/login", map[string]string{"password": "wrong"}, false); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	// Even the right password is refused while rate-limited.
	if code, _ := c.do("POST", "/api/auth/login", map[string]string{"password": "correct horse"}, false); code != 429 {
		t.Fatalf("expected 429, got %d", code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	ts, _ := newTestServer(t)
	resp, err := http.Get(ts.URL + "/api/auth/status")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
}

func TestHashPasswordPolicy(t *testing.T) {
	if _, err := HashPassword("1234567"); err == nil {
		t.Error("7 chars accepted")
	}
	if _, err := HashPassword(string(make([]byte, 73))); err == nil {
		t.Error("73 chars accepted")
	}
}
