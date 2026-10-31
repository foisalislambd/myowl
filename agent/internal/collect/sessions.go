package collect

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/myowl/myowl/agent/internal/model"
)

// utmp record layout on Linux (glibc, 64-bit and 32-bit share it): 384 bytes.
const utmpSize = 384

const (
	utRunLvl   = 1
	utBootTime = 2
	utUserProc = 7
	utDeadProc = 8
)

// UtmpRecord is a decoded utmp/wtmp entry.
type UtmpRecord struct {
	Type int16
	PID  int32
	Line string
	ID   string
	User string
	Host string
	Sec  int32
	Usec int32
	Addr net.IP
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

// ParseUtmp decodes a utmp/wtmp file's contents.
func ParseUtmp(b []byte) []UtmpRecord {
	var out []UtmpRecord
	for off := 0; off+utmpSize <= len(b); off += utmpSize {
		r := b[off : off+utmpSize]
		rec := UtmpRecord{
			Type: int16(binary.LittleEndian.Uint16(r[0:2])),
			PID:  int32(binary.LittleEndian.Uint32(r[4:8])),
			Line: cstr(r[8:40]),
			ID:   cstr(r[40:44]),
			User: cstr(r[44:76]),
			Host: cstr(r[76:332]),
			Sec:  int32(binary.LittleEndian.Uint32(r[340:344])),
			Usec: int32(binary.LittleEndian.Uint32(r[344:348])),
		}
		a := r[348:364]
		if bytes.Equal(a[4:], make([]byte, 12)) {
			if !bytes.Equal(a[:4], []byte{0, 0, 0, 0}) {
				rec.Addr = net.IP(append([]byte(nil), a[:4]...))
			}
		} else {
			rec.Addr = net.IP(append([]byte(nil), a...))
		}
		out = append(out, rec)
	}
	return out
}

// CurrentSessions returns logged-in users and the data source used.
func CurrentSessions() ([]model.LoginSession, string, string) {
	for _, p := range []string{"/run/utmp", "/var/run/utmp"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var out []model.LoginSession
		for _, r := range ParseUtmp(b) {
			if r.Type != utUserProc || r.User == "" {
				continue
			}
			if r.PID > 0 {
				if _, err := os.Stat("/proc/" + strconv.Itoa(int(r.PID))); err != nil {
					continue // stale entry
				}
			}
			host := r.Host
			if host == "" && r.Addr != nil {
				host = r.Addr.String()
			}
			out = append(out, model.LoginSession{User: r.User, TTY: r.Line, Host: host, LoginTime: int64(r.Sec) * 1000, PID: int(r.PID)})
		}
		return out, "utmp", ""
	}
	// systemd-logind fallback (distros without utmp, e.g. Debian 13)
	if s, ok := loginctlSessions(); ok {
		return s, "logind", ""
	}
	return []model.LoginSession{}, "none", "no utmp file and logind is unavailable"
}

func loginctlSessions() ([]model.LoginSession, bool) {
	if _, err := exec.LookPath("loginctl"); err != nil {
		return nil, false
	}
	b, err := exec.Command("loginctl", "list-sessions", "--output=json", "--no-pager").Output()
	if err != nil {
		return nil, false
	}
	var list []map[string]any
	if json.Unmarshal(b, &list) != nil {
		return nil, false
	}
	out := []model.LoginSession{}
	for _, s := range list {
		id, _ := s["session"].(string)
		if id == "" {
			continue
		}
		props, err := exec.Command("loginctl", "show-session", id, "--no-pager",
			"-p", "Name", "-p", "TTY", "-p", "RemoteHost", "-p", "Timestamp", "-p", "Leader", "-p", "Class", "-p", "State").Output()
		if err != nil {
			continue
		}
		m := map[string]string{}
		for _, l := range strings.Split(string(props), "\n") {
			if i := strings.IndexByte(l, '='); i > 0 {
				m[l[:i]] = l[i+1:]
			}
		}
		if m["Class"] != "" && m["Class"] != "user" {
			continue
		}
		ls := model.LoginSession{User: m["Name"], TTY: m["TTY"], Host: m["RemoteHost"]}
		ls.PID, _ = strconv.Atoi(m["Leader"])
		if t, err := time.Parse("Mon 2006-01-02 15:04:05 MST", m["Timestamp"]); err == nil {
			ls.LoginTime = t.UnixMilli()
		}
		out = append(out, ls)
	}
	return out, true
}

// LoginHistory returns the most recent logins from wtmp or wtmpdb.
func LoginHistory(limit int) ([]model.LoginRecord, string) {
	if recs, ok := wtmpdbHistory("/var/lib/wtmpdb/wtmp.db", limit); ok {
		return recs, "wtmpdb"
	}
	b, err := os.ReadFile("/var/log/wtmp")
	if err != nil {
		return []model.LoginRecord{}, "none"
	}
	return HistoryFromWtmp(ParseUtmp(b), limit), "wtmp"
}

// HistoryFromWtmp pairs login and logout records (like `last`).
func HistoryFromWtmp(recs []UtmpRecord, limit int) []model.LoginRecord {
	var out []model.LoginRecord
	logout := map[string]int64{} // line -> logout time (walking backwards)
	var lastBoot int64
	for i := len(recs) - 1; i >= 0 && len(out) < limit; i-- {
		r := recs[i]
		ts := int64(r.Sec) * 1000
		switch {
		case r.Type == utBootTime || (r.Type == utRunLvl && r.User == "reboot"):
			out = append(out, model.LoginRecord{User: "reboot", TTY: "system boot", Host: r.Host, Login: ts, Logout: lastBoot, Kind: "reboot"})
			logout = map[string]int64{}
			lastBoot = ts
		case r.Type == utDeadProc || (r.Type == utUserProc && r.User == ""):
			logout[r.Line] = ts
		case r.Type == utUserProc:
			lr := model.LoginRecord{User: r.User, TTY: r.Line, Host: r.Host, Login: ts, Kind: "user"}
			if lr.Host == "" && r.Addr != nil {
				lr.Host = r.Addr.String()
			}
			if t, ok := logout[r.Line]; ok {
				lr.Logout = t
			} else if lastBoot > 0 {
				lr.Logout = -1 // crashed / reboot
			}
			delete(logout, r.Line)
			out = append(out, lr)
		}
	}
	return out
}

func wtmpdbHistory(path string, limit int) ([]model.LoginRecord, bool) {
	if _, err := os.Stat(path); err != nil {
		return nil, false
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(2000)")
	if err != nil {
		return nil, false
	}
	defer db.Close()
	rows, err := db.Query(`SELECT Type, User, Login, COALESCE(Logout,0), COALESCE(TTY,''), COALESCE(RemoteHost,'') FROM wtmp ORDER BY Login DESC LIMIT ?`, limit)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	out := []model.LoginRecord{}
	for rows.Next() {
		var typ int
		var r model.LoginRecord
		var login, logout int64
		if rows.Scan(&typ, &r.User, &login, &logout, &r.TTY, &r.Host) != nil {
			continue
		}
		r.Login, r.Logout = login/1000, logout/1000
		r.Kind = "user"
		if typ == 1 || r.User == "reboot" {
			r.Kind = "reboot"
			r.User = "reboot"
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Login > out[j].Login })
	return out, true
}
