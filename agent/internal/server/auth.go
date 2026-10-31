package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	sessionCookie = "myowl_session"
	csrfCookie    = "myowl_csrf"
	sessionTTL    = 7 * 24 * time.Hour
	minPassword   = 8
)

// RandomToken returns n random bytes hex encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// HashPassword hashes with bcrypt.
func HashPassword(p string) (string, error) {
	if len(p) < minPassword {
		return "", errors.New("password must be at least 8 characters")
	}
	if len(p) > 72 {
		return "", errors.New("password must be at most 72 characters")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(p), 12)
	return string(b), err
}

type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func (l *limiter) blocked(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := time.Now().Add(-15 * time.Minute)
	var keep []time.Time
	for _, t := range l.fails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	l.fails[ip] = keep
	if len(keep) >= 5 {
		return true, time.Until(keep[0].Add(15 * time.Minute))
	}
	return false, 0
}

func (l *limiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > 10000 {
		l.fails = map[string][]time.Time{}
	}
	l.fails[ip] = append(l.fails[ip], time.Now())
}

func (l *limiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}

// clientIP returns the requester IP (honouring X-Forwarded-For only when
// trust_proxy is enabled and the peer is loopback/private).
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if s.cfg.TrustProxy {
		peer := net.ParseIP(host)
		if peer != nil && (peer.IsLoopback() || peer.IsPrivate()) {
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				parts := strings.Split(xff, ",")
				if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
					return ip.String()
				}
			}
			if xr := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); xr != nil {
				return xr.String()
			}
		}
	}
	return host
}

func (s *Server) secureCookies(r *http.Request) bool {
	if s.cfg.CookieSecure || s.cfg.TLSEnabled() || r.TLS != nil {
		return true
	}
	return s.cfg.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https"
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request) error {
	tok := RandomToken(32)
	csrf := RandomToken(16)
	now := time.Now()
	if err := s.st.CreateSession(hashToken(tok), csrf, now.UnixMilli(), now.Add(sessionTTL).UnixMilli(), s.clientIP(r), r.UserAgent()); err != nil {
		return err
	}
	sec := s.secureCookies(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: sec, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/", HttpOnly: false, Secure: sec, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds())})
	return nil
}

func (s *Server) clearSession(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.st.DeleteSession(hashToken(c.Value))
	}
	sec := s.secureCookies(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: sec, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/", Secure: sec, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// authed returns the session's CSRF token if the request is logged in.
func (s *Server) authed(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || len(c.Value) != 64 {
		return "", false
	}
	csrf, exp, ok := s.st.GetSession(hashToken(c.Value))
	if !ok || exp < time.Now().UnixMilli() {
		return "", false
	}
	return csrf, true
}

// sameOrigin rejects cross-site state-changing requests.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		ref := r.Header.Get("Referer")
		if ref == "" {
			// non-browser client; CSRF token still required
			return true
		}
		origin = ref
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := r.Host
	if xf := r.Header.Get("X-Forwarded-Host"); xf != "" {
		host = xf
	}
	return strings.EqualFold(u.Host, host)
}

// requireAuth wraps API handlers: session + CSRF for unsafe methods.
func (s *Server) requireAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		csrf, ok := s.authed(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !sameOrigin(r) {
				writeErr(w, http.StatusForbidden, "cross-origin request rejected")
				return
			}
			hdr := r.Header.Get("X-CSRF-Token")
			if hdr == "" || subtle.ConstantTimeCompare([]byte(hdr), []byte(csrf)) != 1 {
				writeErr(w, http.StatusForbidden, "missing or invalid CSRF token — reload the page")
				return
			}
		}
		h(w, r)
	}
}

func (s *Server) passwordSet() bool { return s.st.Get("password_hash") != "" }

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	_, ok := s.authed(r)
	writeJSON(w, map[string]any{"authenticated": ok, "setup_required": !s.passwordSet(), "demo": s.cfg.Demo,
		"setup_token_required": !s.cfg.Demo, "version": Version})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeErr(w, 403, "cross-origin request rejected")
		return
	}
	if s.passwordSet() {
		writeErr(w, 409, "a password is already set — log in instead")
		return
	}
	ip := s.clientIP(r)
	if b, wait := s.lim.blocked(ip); b {
		writeErr(w, 429, "too many attempts, try again in "+wait.Round(time.Second).String())
		return
	}
	var req struct{ Password, Token string }
	if !readJSON(w, r, &req) {
		return
	}
	want := s.st.Get("setup_token")
	if !s.cfg.Demo && (want == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(req.Token)), []byte(want)) != 1) {
		s.lim.fail(ip)
		writeErr(w, 403, "wrong setup code — find it in the server log or in "+s.setupTokenPath())
		return
	}
	h, err := HashPassword(req.Password)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.passwordSet() {
		writeErr(w, 409, "a password is already set")
		return
	}
	_ = s.st.Set("password_hash", h)
	_ = s.st.Delete("setup_token")
	s.removeSetupTokenFile()
	if err := s.setSession(w, r); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeErr(w, 403, "cross-origin request rejected")
		return
	}
	ip := s.clientIP(r)
	if b, wait := s.lim.blocked(ip); b {
		writeErr(w, 429, "too many failed logins from your address — try again in "+wait.Round(time.Second).String())
		return
	}
	var req struct{ Password string }
	if !readJSON(w, r, &req) {
		return
	}
	h := s.st.Get("password_hash")
	if h == "" {
		writeErr(w, 409, "no password set yet — complete the first-run setup")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(h), []byte(req.Password)) != nil {
		s.lim.fail(ip)
		time.Sleep(300 * time.Millisecond)
		writeErr(w, 401, "wrong password")
		return
	}
	s.lim.reset(ip)
	if err := s.setSession(w, r); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w, r)
	writeJSON(w, map[string]any{"ok": true})
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if s.cfg.Demo {
		writeErr(w, 400, "the password cannot be changed in demo mode")
		return
	}
	ip := s.clientIP(r)
	if b, _ := s.lim.blocked(ip); b {
		writeErr(w, 429, "too many attempts")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(s.st.Get("password_hash")), []byte(req.Current)) != nil {
		s.lim.fail(ip)
		writeErr(w, 401, "current password is wrong")
		return
	}
	h, err := HashPassword(req.New)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.st.Set("password_hash", h)
	_ = s.st.DeleteAllSessions()
	if err := s.setSession(w, r); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}

// HashPasswordUnchecked hashes without the length policy (demo mode only).
func HashPasswordUnchecked(p string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	return string(b), err
}
