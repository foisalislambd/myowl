package server

import (
	"encoding/json"
	"io"
	"net/http"
)

// UI preferences (theme, accent colour, font size, effects) are a small JSON
// object owned by the browser. The server only stores it so the dashboard looks
// the same on every device the user signs in from.
const prefsKey = "ui_prefs"
const maxPrefsBytes = 4096

func (s *Server) handleGetPrefs(w http.ResponseWriter, r *http.Request) {
	v := s.st.Get(prefsKey)
	if v == "" {
		v = "{}"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `{"prefs":`+v+`}`)
}

func (s *Server) handlePutPrefs(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPrefsBytes+1))
	if err != nil || len(body) > maxPrefsBytes {
		writeErr(w, 413, "preferences too large")
		return
	}
	var obj map[string]any
	if err := json.Unmarshal(body, &obj); err != nil || obj == nil {
		writeErr(w, 400, "preferences must be a JSON object")
		return
	}
	clean, _ := json.Marshal(obj) // re-encode so only valid JSON is stored
	if err := s.st.Set(prefsKey, string(clean)); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true})
}
