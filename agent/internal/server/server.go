// Package server exposes the HTTP API, the SSE stream and the embedded UI.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/myowl/myowl/agent/internal/config"
	"github.com/myowl/myowl/agent/internal/engine"
	"github.com/myowl/myowl/agent/internal/store"
	"github.com/myowl/myowl/agent/internal/webui"
)

// Version is set at build time.
var Version = "dev"

// Server is the HTTP server.
type Server struct {
	cfg *config.Config
	st  *store.Store
	e   *engine.Engine
	lim *limiter
	mu  sync.Mutex
	ui  fs.FS
}

// New creates the server.
func New(cfg *config.Config, st *store.Store, e *engine.Engine) *Server {
	return &Server{cfg: cfg, st: st, e: e, lim: &limiter{fails: map[string][]time.Time{}}, ui: webui.FS()}
}

func (s *Server) setupTokenPath() string { return filepath.Join(s.cfg.DataDir, "setup-token.txt") }

func (s *Server) removeSetupTokenFile() { _ = os.Remove(s.setupTokenPath()) }

// EnsureSetupToken creates a first-run setup code when no password exists.
func (s *Server) EnsureSetupToken() string {
	if s.passwordSet() {
		s.removeSetupTokenFile()
		return ""
	}
	tok := s.st.Get("setup_token")
	if tok == "" {
		tok = RandomToken(6)
		_ = s.st.Set("setup_token", tok)
	}
	_ = os.WriteFile(s.setupTokenPath(), []byte(tok+"\n"), 0o600)
	return tok
}

// Handler builds the router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	a := s.requireAuth
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/auth/setup", s.handleSetup)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleLogout)
	mux.HandleFunc("POST /api/auth/password", a(s.handlePassword))

	mux.HandleFunc("GET /api/overview", a(s.handleOverview))
	mux.HandleFunc("GET /api/system", a(s.handleSystem))
	mux.HandleFunc("GET /api/history", a(s.handleHistory))
	mux.HandleFunc("GET /api/network", a(s.handleNetwork))
	mux.HandleFunc("GET /api/requests", a(s.handleRequests))
	mux.HandleFunc("GET /api/requests/stats", a(s.handleRequestStats))
	mux.HandleFunc("GET /api/requests/{id}", a(s.handleRequest))
	mux.HandleFunc("GET /api/ip/{ip}", a(s.handleIP))
	mux.HandleFunc("GET /api/threats", a(s.handleThreats))
	mux.HandleFunc("GET /api/threats/timeline", a(s.handleThreatTimeline))
	mux.HandleFunc("POST /api/threats/{id}/ack", a(s.handleAck))
	mux.HandleFunc("GET /api/firewall", a(s.handleFirewall))
	mux.HandleFunc("POST /api/firewall/block", a(s.handleBlock))
	mux.HandleFunc("POST /api/firewall/unblock", a(s.handleUnblock))
	mux.HandleFunc("GET /api/sessions", a(s.handleSessions))
	mux.HandleFunc("GET /api/alerts", a(s.handleAlerts))
	mux.HandleFunc("POST /api/alerts/rules", a(s.handleSaveRule))
	mux.HandleFunc("DELETE /api/alerts/rules/{id}", a(s.handleDeleteRule))
	mux.HandleFunc("POST /api/alerts/test", a(s.handleTestAlert))
	mux.HandleFunc("GET /api/status", a(s.handleStatus))
	mux.HandleFunc("GET /api/prefs", a(s.handleGetPrefs))
	mux.HandleFunc("PUT /api/prefs", a(s.handlePutPrefs))
	mux.HandleFunc("GET /api/stream", a(s.handleStream))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, 404, "not found") })
	mux.HandleFunc("/", s.handleStatic)
	return s.headers(mux)
}

func (s *Server) headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "same-origin")
		hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		hd.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' data: blob:; worker-src 'self' blob:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if s.cfg.TLSEnabled() {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			hd.Set("Cache-Control", "no-store")
			if r.ContentLength > 1<<20 {
				writeErr(w, 413, "request too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		h.ServeHTTP(w, r)
	})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", 405)
		return
	}
	p := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if p == "" {
		p = "index.html"
	}
	try := []string{p, p + ".html", path.Join(p, "index.html")}
	for _, c := range try {
		f, err := s.ui.Open(c)
		if err != nil {
			continue
		}
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			f.Close()
			continue
		}
		if strings.HasPrefix(c, "_next/static/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeContent(w, r, c, time.Time{}, f.(io.ReadSeeker))
		f.Close()
		return
	}
	if f, err := s.ui.Open("404.html"); err == nil {
		defer f.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(404)
		_, _ = io.Copy(w, f)
		return
	}
	http.NotFound(w, r)
}

// ListenAndServe runs until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(c)
	}()
	var err error
	if s.cfg.TLSEnabled() {
		log.Printf("dashboard: https://%s", s.cfg.Listen)
		err = srv.ListenAndServeTLS(s.cfg.TLS.Cert, s.cfg.TLS.Key)
	} else {
		log.Printf("dashboard: http://%s", s.cfg.Listen)
		err = srv.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeErr(w, 415, "expected application/json")
		return false
	}
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func qint(r *http.Request, k string, def int64) int64 {
	if v, err := strconv.ParseInt(r.URL.Query().Get(k), 10, 64); err == nil {
		return v
	}
	return def
}

// rangeParam parses ?range=1h|6h|24h|7d into since + bucket (ms).
func rangeParam(r *http.Request, def string) (since, bucket int64, label string) {
	rg := r.URL.Query().Get("range")
	if rg == "" {
		rg = def
	}
	now := time.Now().UnixMilli()
	switch rg {
	case "15m":
		return now - 15*60000, 10000, rg
	case "1h":
		return now - 3600000, 60000, rg
	case "6h":
		return now - 6*3600000, 5 * 60000, rg
	case "7d":
		return now - 7*86400000, 3600000, rg
	case "14d", "30d":
		return now - 14*86400000, 3 * 3600000, "14d"
	default:
		return now - 86400000, 15 * 60000, "24h"
	}
}
