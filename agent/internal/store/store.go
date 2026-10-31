// Package store persists history in an embedded SQLite database (pure Go).
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/myowl/myowl/agent/internal/model"
)

// Store wraps the SQLite database.
type Store struct {
	DB *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS metrics(ts INTEGER NOT NULL, cpu REAL, mem REAL, swap REAL, disk REAL, load1 REAL, rx REAL, tx REAL, conns INTEGER, reqs INTEGER);
CREATE INDEX IF NOT EXISTS metrics_ts ON metrics(ts);
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, ip TEXT, method TEXT, path TEXT, query TEXT, proto TEXT,
  status INTEGER, bytes INTEGER, ua TEXT, referer TEXT, host TEXT, latency REAL, source TEXT, flags TEXT, usr TEXT, raw TEXT, cc TEXT, country TEXT, city TEXT);
CREATE INDEX IF NOT EXISTS requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS requests_ip ON requests(ip, ts);
CREATE TABLE IF NOT EXISTS threats(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, last_seen INTEGER, ip TEXT, type TEXT, severity TEXT,
  title TEXT, explanation TEXT, advice TEXT, count INTEGER, details TEXT, acked INTEGER DEFAULT 0, cc TEXT, country TEXT, city TEXT, lat REAL, lon REAL, tkey TEXT);
CREATE INDEX IF NOT EXISTS threats_ts ON threats(last_seen);
CREATE INDEX IF NOT EXISTS threats_ip ON threats(ip);
CREATE INDEX IF NOT EXISTS threats_key ON threats(tkey, last_seen);
CREATE TABLE IF NOT EXISTS auth_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT, usr TEXT, ip TEXT, port INTEGER, method TEXT,
  tty TEXT, command TEXT, run_as TEXT, raw TEXT, cc TEXT, country TEXT, city TEXT);
CREATE INDEX IF NOT EXISTS auth_ts ON auth_events(ts);
CREATE INDEX IF NOT EXISTS auth_kind ON auth_events(kind, ts);
CREATE INDEX IF NOT EXISTS auth_ip ON auth_events(ip);
CREATE TABLE IF NOT EXISTS blocked(ip TEXT PRIMARY KEY, ts INTEGER, reason TEXT, backend TEXT);
CREATE TABLE IF NOT EXISTS alert_rules(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, kind TEXT, metric TEXT, op TEXT, threshold REAL, duration INTEGER,
  severity TEXT, channels TEXT, cooldown INTEGER, enabled INTEGER);
CREATE TABLE IF NOT EXISTS alert_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, rule_id INTEGER, rule_name TEXT, severity TEXT, title TEXT, message TEXT, delivered TEXT);
CREATE INDEX IF NOT EXISTS alert_events_ts ON alert_events(ts);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, csrf TEXT, created INTEGER, expires INTEGER, ip TEXT, ua TEXT);
`

// Open opens (and migrates) the database at path.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{DB: db}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.DB.Close() }

// Get reads a kv value.
func (s *Store) Get(k string) string {
	var v string
	_ = s.DB.QueryRow(`SELECT v FROM kv WHERE k=?`, k).Scan(&v)
	return v
}

// Set writes a kv value.
func (s *Store) Set(k, v string) error {
	_, err := s.DB.Exec(`INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v`, k, v)
	return err
}

// Delete removes a kv value.
func (s *Store) Delete(k string) error {
	_, err := s.DB.Exec(`DELETE FROM kv WHERE k=?`, k)
	return err
}

// ---------- metrics ----------

// InsertMetric stores a history sample.
func (s *Store) InsertMetric(p model.MetricPoint) error {
	_, err := s.DB.Exec(`INSERT INTO metrics(ts,cpu,mem,swap,disk,load1,rx,tx,conns,reqs) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		p.TS, p.CPU, p.Mem, p.Swap, p.Disk, p.Load1, p.Rx, p.Tx, p.Conns, p.Reqs)
	return err
}

// Metrics returns averaged samples since `since` grouped into `bucket` ms.
func (s *Store) Metrics(since, bucket int64) ([]model.MetricPoint, error) {
	if bucket <= 0 {
		bucket = 60000
	}
	rows, err := s.DB.Query(`SELECT (ts/?)*? AS b, AVG(cpu), AVG(mem), AVG(swap), AVG(disk), AVG(load1), AVG(rx), AVG(tx), AVG(conns), SUM(reqs)
		FROM metrics WHERE ts>=? GROUP BY b ORDER BY b`, bucket, bucket, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.MetricPoint
	for rows.Next() {
		var p model.MetricPoint
		if err := rows.Scan(&p.TS, &p.CPU, &p.Mem, &p.Swap, &p.Disk, &p.Load1, &p.Rx, &p.Tx, &p.Conns, &p.Reqs); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------- requests ----------

// InsertRequests stores a batch of requests and sets their IDs.
func (s *Store) InsertRequests(reqs []*model.HTTPRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	st, err := tx.Prepare(`INSERT INTO requests(ts,ip,method,path,query,proto,status,bytes,ua,referer,host,latency,source,flags,usr,raw,cc,country,city)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer st.Close()
	for _, r := range reqs {
		raw := r.Raw
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		res, err := st.Exec(r.TS, r.IP, r.Method, r.Path, r.Query, r.Proto, r.Status, r.Bytes, r.UA, r.Referer, r.Host, r.LatencyMs,
			r.Source, strings.Join(r.Flags, ","), r.User, raw, r.Geo.CC, r.Geo.Country, r.Geo.City)
		if err != nil {
			tx.Rollback()
			return err
		}
		r.ID, _ = res.LastInsertId()
	}
	return tx.Commit()
}

const reqCols = `id,ts,ip,method,path,query,proto,status,bytes,ua,referer,host,latency,source,flags,usr,raw,cc,country,city`

func scanReq(sc interface{ Scan(...any) error }) (*model.HTTPRequest, error) {
	r := &model.HTTPRequest{}
	var flags string
	if err := sc.Scan(&r.ID, &r.TS, &r.IP, &r.Method, &r.Path, &r.Query, &r.Proto, &r.Status, &r.Bytes, &r.UA, &r.Referer, &r.Host,
		&r.LatencyMs, &r.Source, &flags, &r.User, &r.Raw, &r.Geo.CC, &r.Geo.Country, &r.Geo.City); err != nil {
		return nil, err
	}
	r.Flags = []string{}
	if flags != "" {
		r.Flags = strings.Split(flags, ",")
	}
	return r, nil
}

// RequestFilter filters request listings.
type RequestFilter struct {
	IP      string
	Status  string // 2xx 3xx 4xx 5xx or exact
	Method  string
	Q       string
	Threats bool
	Before  int64 // id cursor
	Since   int64
	Limit   int
}

// Requests lists requests newest first.
func (s *Store) Requests(f RequestFilter) ([]*model.HTTPRequest, error) {
	where := []string{"1=1"}
	var args []any
	if f.IP != "" {
		where = append(where, "ip=?")
		args = append(args, f.IP)
	}
	if f.Status != "" {
		if len(f.Status) == 3 && strings.HasSuffix(f.Status, "xx") {
			c := int(f.Status[0] - '0')
			where = append(where, "status>=? AND status<?")
			args = append(args, c*100, c*100+100)
		} else {
			where = append(where, "status=?")
			args = append(args, f.Status)
		}
	}
	if f.Method != "" {
		where = append(where, "method=?")
		args = append(args, f.Method)
	}
	if f.Q != "" {
		where = append(where, "(path LIKE ? OR query LIKE ? OR ip LIKE ? OR ua LIKE ? OR host LIKE ?)")
		q := "%" + f.Q + "%"
		args = append(args, q, q, q, q, q)
	}
	if f.Threats {
		where = append(where, "flags<>''")
	}
	if f.Before > 0 {
		where = append(where, "id<?")
		args = append(args, f.Before)
	}
	if f.Since > 0 {
		where = append(where, "ts>=?")
		args = append(args, f.Since)
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	args = append(args, f.Limit)
	rows, err := s.DB.Query(`SELECT `+reqCols+` FROM requests WHERE `+strings.Join(where, " AND ")+` ORDER BY id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.HTTPRequest{}
	for rows.Next() {
		r, err := scanReq(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Request returns one request by id.
func (s *Store) Request(id int64) (*model.HTTPRequest, error) {
	return scanReq(s.DB.QueryRow(`SELECT `+reqCols+` FROM requests WHERE id=?`, id))
}

// KV is a label/count pair.
type KV struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	Count int64  `json:"count"`
	Extra string `json:"extra,omitempty"`
}

// RequestStats aggregates requests since a timestamp.
type RequestStats struct {
	Total      int64         `json:"total"`
	Threats    int64         `json:"threats"`
	Errors     int64         `json:"errors"`
	Bytes      int64         `json:"bytes"`
	AvgLatency float64       `json:"avg_latency"`
	UniqueIPs  int64         `json:"unique_ips"`
	Status     []KV          `json:"status"`
	Methods    []KV          `json:"methods"`
	TopPaths   []KV          `json:"top_paths"`
	TopIPs     []KV          `json:"top_ips"`
	TopUAs     []KV          `json:"top_uas"`
	Countries  []KV          `json:"countries"`
	Series     []SeriesPoint `json:"series"`
}

// SeriesPoint is a time bucket of request counts.
type SeriesPoint struct {
	TS      int64 `json:"ts"`
	Total   int64 `json:"total"`
	OK      int64 `json:"ok"`
	Redir   int64 `json:"redir"`
	Client  int64 `json:"client"`
	Server  int64 `json:"server"`
	Threats int64 `json:"threats"`
}

func (s *Store) kvQuery(q string, args ...any) []KV {
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return []KV{}
	}
	defer rows.Close()
	out := []KV{}
	for rows.Next() {
		var k KV
		var extra sql.NullString
		if rows.Scan(&k.Key, &k.Count, &extra) == nil {
			k.Extra = extra.String
			out = append(out, k)
		}
	}
	return out
}

// RequestStats computes aggregate stats.
func (s *Store) RequestStats(since, bucket int64) (*RequestStats, error) {
	st := &RequestStats{}
	var avg sql.NullFloat64
	var bytes sql.NullInt64
	err := s.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(flags<>''),0), COALESCE(SUM(status>=500),0), SUM(bytes), AVG(CASE WHEN latency>=0 THEN latency END), COUNT(DISTINCT ip)
		FROM requests WHERE ts>=?`, since).Scan(&st.Total, &st.Threats, &st.Errors, &bytes, &avg, &st.UniqueIPs)
	if err != nil {
		return nil, err
	}
	st.Bytes = bytes.Int64
	st.AvgLatency = avg.Float64
	st.Status = s.kvQuery(`SELECT CAST(status AS TEXT), COUNT(*), '' FROM requests WHERE ts>=? GROUP BY status ORDER BY 2 DESC LIMIT 12`, since)
	st.Methods = s.kvQuery(`SELECT method, COUNT(*), '' FROM requests WHERE ts>=? GROUP BY method ORDER BY 2 DESC LIMIT 8`, since)
	st.TopPaths = s.kvQuery(`SELECT path, COUNT(*), '' FROM requests WHERE ts>=? GROUP BY path ORDER BY 2 DESC LIMIT 10`, since)
	st.TopIPs = s.kvQuery(`SELECT ip, COUNT(*), MAX(country) FROM requests WHERE ts>=? GROUP BY ip ORDER BY 2 DESC LIMIT 10`, since)
	st.TopUAs = s.kvQuery(`SELECT ua, COUNT(*), '' FROM requests WHERE ts>=? GROUP BY ua ORDER BY 2 DESC LIMIT 8`, since)
	st.Countries = s.kvQuery(`SELECT COALESCE(NULLIF(cc,''),'??'), COUNT(*), MAX(country) FROM requests WHERE ts>=? GROUP BY 1 ORDER BY 2 DESC LIMIT 12`, since)
	rows, err := s.DB.Query(`SELECT (ts/?)*? b, COUNT(*), SUM(status<300), SUM(status>=300 AND status<400), SUM(status>=400 AND status<500), SUM(status>=500), SUM(flags<>'')
		FROM requests WHERE ts>=? GROUP BY b ORDER BY b`, bucket, bucket, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	st.Series = []SeriesPoint{}
	for rows.Next() {
		var p SeriesPoint
		if rows.Scan(&p.TS, &p.Total, &p.OK, &p.Redir, &p.Client, &p.Server, &p.Threats) == nil {
			st.Series = append(st.Series, p)
		}
	}
	return st, nil
}

// CountRequestsSince counts requests since ts.
func (s *Store) CountRequestsSince(ts int64) int64 {
	var n int64
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM requests WHERE ts>=?`, ts).Scan(&n)
	return n
}

// ---------- threats ----------

const threatCols = `id,ts,last_seen,ip,type,severity,title,explanation,advice,count,details,acked,cc,country,city,lat,lon`

func scanThreat(sc interface{ Scan(...any) error }) (*model.Threat, error) {
	t := &model.Threat{}
	var details string
	var acked int
	if err := sc.Scan(&t.ID, &t.TS, &t.LastSeen, &t.IP, &t.Type, &t.Severity, &t.Title, &t.Explanation, &t.Advice, &t.Count, &details, &acked,
		&t.Geo.CC, &t.Geo.Country, &t.Geo.City, &t.Geo.Lat, &t.Geo.Lon); err != nil {
		return nil, err
	}
	t.Acked = acked == 1
	_ = json.Unmarshal([]byte(details), &t.Details)
	if t.Details == nil {
		t.Details = map[string]any{}
	}
	return t, nil
}

// FindThreatByKey returns the most recent threat with key seen after since.
func (s *Store) FindThreatByKey(key string, since int64) (*model.Threat, error) {
	return scanThreat(s.DB.QueryRow(`SELECT `+threatCols+` FROM threats WHERE tkey=? AND last_seen>=? ORDER BY last_seen DESC LIMIT 1`, key, since))
}

// InsertThreat stores a new threat.
func (s *Store) InsertThreat(key string, t *model.Threat) error {
	d, _ := json.Marshal(t.Details)
	res, err := s.DB.Exec(`INSERT INTO threats(ts,last_seen,ip,type,severity,title,explanation,advice,count,details,acked,cc,country,city,lat,lon,tkey)
		VALUES(?,?,?,?,?,?,?,?,?,?,0,?,?,?,?,?,?)`, t.TS, t.LastSeen, t.IP, t.Type, t.Severity, t.Title, t.Explanation, t.Advice, t.Count, string(d),
		t.Geo.CC, t.Geo.Country, t.Geo.City, t.Geo.Lat, t.Geo.Lon, key)
	if err != nil {
		return err
	}
	t.ID, _ = res.LastInsertId()
	return nil
}

// UpdateThreat updates an existing threat's mutable fields.
func (s *Store) UpdateThreat(t *model.Threat) error {
	d, _ := json.Marshal(t.Details)
	_, err := s.DB.Exec(`UPDATE threats SET last_seen=?, severity=?, explanation=?, count=?, details=? WHERE id=?`,
		t.LastSeen, t.Severity, t.Explanation, t.Count, string(d), t.ID)
	return err
}

// ThreatFilter filters threat listings.
type ThreatFilter struct {
	Since       int64
	IP          string
	MinSeverity string
	Limit       int
	Unacked     bool
}

// Threats lists threats ordered by last_seen desc.
func (s *Store) Threats(f ThreatFilter) ([]*model.Threat, error) {
	where := []string{"last_seen>=?"}
	args := []any{f.Since}
	if f.IP != "" {
		where = append(where, "ip=?")
		args = append(args, f.IP)
	}
	if f.MinSeverity != "" {
		var sev []string
		for _, x := range []string{"info", "low", "medium", "high", "critical"} {
			if model.SeverityRank(x) >= model.SeverityRank(f.MinSeverity) {
				sev = append(sev, "'"+x+"'")
			}
		}
		where = append(where, "severity IN ("+strings.Join(sev, ",")+")")
	}
	if f.Unacked {
		where = append(where, "acked=0")
	}
	if f.Limit <= 0 || f.Limit > 2000 {
		f.Limit = 300
	}
	args = append(args, f.Limit)
	rows, err := s.DB.Query(`SELECT `+threatCols+` FROM threats WHERE `+strings.Join(where, " AND ")+` ORDER BY last_seen DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.Threat{}
	for rows.Next() {
		t, err := scanThreat(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// AckThreat marks a threat as acknowledged.
func (s *Store) AckThreat(id int64) error {
	_, err := s.DB.Exec(`UPDATE threats SET acked=1 WHERE id=?`, id)
	return err
}

// ThreatBucket is a timeline bucket.
type ThreatBucket struct {
	TS       int64 `json:"ts"`
	Info     int64 `json:"info"`
	Low      int64 `json:"low"`
	Medium   int64 `json:"medium"`
	High     int64 `json:"high"`
	Critical int64 `json:"critical"`
}

// ThreatTimeline buckets threats by first-seen time and severity.
func (s *Store) ThreatTimeline(since, bucket int64) ([]ThreatBucket, error) {
	rows, err := s.DB.Query(`SELECT (ts/?)*? b, SUM(severity='info'), SUM(severity='low'), SUM(severity='medium'), SUM(severity='high'), SUM(severity='critical')
		FROM threats WHERE ts>=? GROUP BY b ORDER BY b`, bucket, bucket, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ThreatBucket{}
	for rows.Next() {
		var b ThreatBucket
		if rows.Scan(&b.TS, &b.Info, &b.Low, &b.Medium, &b.High, &b.Critical) == nil {
			out = append(out, b)
		}
	}
	return out, nil
}

// ThreatCounts counts threats by severity since ts.
func (s *Store) ThreatCounts(since int64) map[string]int64 {
	out := map[string]int64{"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
	rows, err := s.DB.Query(`SELECT severity, COUNT(*) FROM threats WHERE last_seen>=? GROUP BY severity`, since)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var n int64
		if rows.Scan(&k, &n) == nil {
			out[k] = n
		}
	}
	return out
}

// TopThreatIPs lists IPs with the most threat events.
func (s *Store) TopThreatIPs(since int64, limit int) []KV {
	return s.kvQuery(`SELECT ip, SUM(count), MAX(country) FROM threats WHERE last_seen>=? AND ip<>'' GROUP BY ip ORDER BY 2 DESC LIMIT ?`, since, limit)
}

// ThreatIPsSince returns the set of IPs with threats since ts.
func (s *Store) ThreatIPsSince(since int64) map[string]bool {
	out := map[string]bool{}
	rows, err := s.DB.Query(`SELECT DISTINCT ip FROM threats WHERE last_seen>=? AND severity IN ('medium','high','critical')`, since)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			out[ip] = true
		}
	}
	return out
}

// ---------- auth events ----------

// InsertAuth stores an auth event.
func (s *Store) InsertAuth(e *model.AuthEvent) error {
	res, err := s.DB.Exec(`INSERT INTO auth_events(ts,kind,usr,ip,port,method,tty,command,run_as,raw,cc,country,city) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		e.TS, e.Kind, e.User, e.IP, e.Port, e.Method, e.TTY, e.Command, e.RunAs, e.Raw, e.Geo.CC, e.Geo.Country, e.Geo.City)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

// AuthEvents lists auth events of the given kinds.
func (s *Store) AuthEvents(kinds []string, since int64, ip string, limit int) ([]*model.AuthEvent, error) {
	q := `SELECT id,ts,kind,usr,ip,port,method,tty,command,run_as,raw,cc,country,city FROM auth_events WHERE ts>=?`
	args := []any{since}
	if len(kinds) > 0 {
		q += ` AND kind IN (` + strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",") + `)`
		for _, k := range kinds {
			args = append(args, k)
		}
	}
	if ip != "" {
		q += ` AND ip=?`
		args = append(args, ip)
	}
	q += ` ORDER BY ts DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.DB.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*model.AuthEvent{}
	for rows.Next() {
		e := &model.AuthEvent{}
		if err := rows.Scan(&e.ID, &e.TS, &e.Kind, &e.User, &e.IP, &e.Port, &e.Method, &e.TTY, &e.Command, &e.RunAs, &e.Raw, &e.Geo.CC, &e.Geo.Country, &e.Geo.City); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// FailedLoginsByIP aggregates failed SSH logins.
func (s *Store) FailedLoginsByIP(since int64, limit int) []KV {
	return s.kvQuery(`SELECT ip, COUNT(*), MAX(country) FROM auth_events WHERE ts>=? AND kind IN ('ssh_failed','ssh_invalid_user') AND method<>'probe' GROUP BY ip ORDER BY 2 DESC LIMIT ?`, since, limit)
}

// FailedUsernames aggregates usernames tried in failed SSH logins.
func (s *Store) FailedUsernames(since int64, limit int) []KV {
	return s.kvQuery(`SELECT usr, COUNT(*), '' FROM auth_events WHERE ts>=? AND kind IN ('ssh_failed','ssh_invalid_user') AND method<>'probe' GROUP BY usr ORDER BY 2 DESC LIMIT ?`, since, limit)
}

// AuthSeries buckets auth events.
func (s *Store) AuthSeries(since, bucket int64) []map[string]int64 {
	rows, err := s.DB.Query(`SELECT (ts/?)*? b, SUM(kind IN ('ssh_failed','ssh_invalid_user') AND method<>'probe'), SUM(kind='ssh_accepted'), SUM(kind IN ('sudo','sudo_failed','su'))
		FROM auth_events WHERE ts>=? GROUP BY b ORDER BY b`, bucket, bucket, since)
	out := []map[string]int64{}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var b, f, a, su int64
		if rows.Scan(&b, &f, &a, &su) == nil {
			out = append(out, map[string]int64{"ts": b, "failed": f, "accepted": a, "sudo": su})
		}
	}
	return out
}

// ---------- blocked ----------

// AddBlocked stores a blocked IP.
func (s *Store) AddBlocked(b model.BlockedIP) error {
	_, err := s.DB.Exec(`INSERT INTO blocked(ip,ts,reason,backend) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET ts=excluded.ts, reason=excluded.reason, backend=excluded.backend`,
		b.IP, b.TS, b.Reason, b.Backend)
	return err
}

// RemoveBlocked deletes a blocked IP.
func (s *Store) RemoveBlocked(ip string) error {
	_, err := s.DB.Exec(`DELETE FROM blocked WHERE ip=?`, ip)
	return err
}

// Blocked lists blocked IPs.
func (s *Store) Blocked() ([]model.BlockedIP, error) {
	rows, err := s.DB.Query(`SELECT ip,ts,reason,backend FROM blocked ORDER BY ts DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.BlockedIP{}
	for rows.Next() {
		var b model.BlockedIP
		if rows.Scan(&b.IP, &b.TS, &b.Reason, &b.Backend) == nil {
			out = append(out, b)
		}
	}
	return out, nil
}

// ---------- alerts ----------

// AlertRules lists rules.
func (s *Store) AlertRules() ([]model.AlertRule, error) {
	rows, err := s.DB.Query(`SELECT id,name,kind,metric,op,threshold,duration,severity,channels,cooldown,enabled FROM alert_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AlertRule{}
	for rows.Next() {
		var r model.AlertRule
		var ch string
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &r.Metric, &r.Op, &r.Threshold, &r.Duration, &r.Severity, &ch, &r.Cooldown, &en); err != nil {
			return nil, err
		}
		r.Enabled = en == 1
		r.Channels = []string{}
		if ch != "" {
			r.Channels = strings.Split(ch, ",")
		}
		out = append(out, r)
	}
	return out, nil
}

// SaveAlertRule inserts or updates a rule.
func (s *Store) SaveAlertRule(r *model.AlertRule) error {
	en := 0
	if r.Enabled {
		en = 1
	}
	ch := strings.Join(r.Channels, ",")
	if r.ID == 0 {
		res, err := s.DB.Exec(`INSERT INTO alert_rules(name,kind,metric,op,threshold,duration,severity,channels,cooldown,enabled) VALUES(?,?,?,?,?,?,?,?,?,?)`,
			r.Name, r.Kind, r.Metric, r.Op, r.Threshold, r.Duration, r.Severity, ch, r.Cooldown, en)
		if err != nil {
			return err
		}
		r.ID, _ = res.LastInsertId()
		return nil
	}
	_, err := s.DB.Exec(`UPDATE alert_rules SET name=?,kind=?,metric=?,op=?,threshold=?,duration=?,severity=?,channels=?,cooldown=?,enabled=? WHERE id=?`,
		r.Name, r.Kind, r.Metric, r.Op, r.Threshold, r.Duration, r.Severity, ch, r.Cooldown, en, r.ID)
	return err
}

// DeleteAlertRule deletes a rule.
func (s *Store) DeleteAlertRule(id int64) error {
	_, err := s.DB.Exec(`DELETE FROM alert_rules WHERE id=?`, id)
	return err
}

// InsertAlertEvent stores a fired alert.
func (s *Store) InsertAlertEvent(e *model.AlertEvent) error {
	res, err := s.DB.Exec(`INSERT INTO alert_events(ts,rule_id,rule_name,severity,title,message,delivered) VALUES(?,?,?,?,?,?,?)`,
		e.TS, e.RuleID, e.RuleName, e.Severity, e.Title, e.Message, e.Delivered)
	if err != nil {
		return err
	}
	e.ID, _ = res.LastInsertId()
	return nil
}

// UpdateAlertDelivery records delivery status.
func (s *Store) UpdateAlertDelivery(id int64, delivered string) error {
	_, err := s.DB.Exec(`UPDATE alert_events SET delivered=? WHERE id=?`, delivered, id)
	return err
}

// AlertEvents lists fired alerts.
func (s *Store) AlertEvents(since int64, limit int) ([]model.AlertEvent, error) {
	rows, err := s.DB.Query(`SELECT id,ts,rule_id,rule_name,severity,title,message,delivered FROM alert_events WHERE ts>=? ORDER BY ts DESC LIMIT ?`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AlertEvent{}
	for rows.Next() {
		var e model.AlertEvent
		if rows.Scan(&e.ID, &e.TS, &e.RuleID, &e.RuleName, &e.Severity, &e.Title, &e.Message, &e.Delivered) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// ---------- sessions (dashboard auth) ----------

// CreateSession stores a dashboard session.
func (s *Store) CreateSession(hash, csrf string, created, expires int64, ip, ua string) error {
	_, err := s.DB.Exec(`INSERT INTO sessions(token_hash,csrf,created,expires,ip,ua) VALUES(?,?,?,?,?,?)`, hash, csrf, created, expires, ip, ua)
	return err
}

// GetSession returns csrf and expiry for a session hash.
func (s *Store) GetSession(hash string) (csrf string, expires int64, ok bool) {
	err := s.DB.QueryRow(`SELECT csrf, expires FROM sessions WHERE token_hash=?`, hash).Scan(&csrf, &expires)
	return csrf, expires, err == nil
}

// DeleteSession removes a session.
func (s *Store) DeleteSession(hash string) error {
	_, err := s.DB.Exec(`DELETE FROM sessions WHERE token_hash=?`, hash)
	return err
}

// DeleteAllSessions logs everyone out.
func (s *Store) DeleteAllSessions() error {
	_, err := s.DB.Exec(`DELETE FROM sessions`)
	return err
}

// ---------- retention ----------

// Prune deletes data older than the retention window and caps request rows.
func (s *Store) Prune(days, maxRequests int) {
	cut := time.Now().AddDate(0, 0, -days).UnixMilli()
	for _, q := range []string{
		`DELETE FROM metrics WHERE ts<?`, `DELETE FROM requests WHERE ts<?`, `DELETE FROM threats WHERE last_seen<?`,
		`DELETE FROM auth_events WHERE ts<?`, `DELETE FROM alert_events WHERE ts<?`,
	} {
		_, _ = s.DB.Exec(q, cut)
	}
	_, _ = s.DB.Exec(`DELETE FROM sessions WHERE expires<?`, time.Now().UnixMilli())
	var maxID int64
	if s.DB.QueryRow(`SELECT COALESCE(MAX(id),0) FROM requests`).Scan(&maxID) == nil && maxID > int64(maxRequests) {
		_, _ = s.DB.Exec(`DELETE FROM requests WHERE id<=?`, maxID-int64(maxRequests))
	}
	_, _ = s.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
}
