// Package logs contains log tailers and parsers for web-server access logs,
// authentication logs and kernel firewall logs.
package logs

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/myowl/myowl/agent/internal/model"
)

// ErrNoMatch is returned when a line does not match the expected format.
var ErrNoMatch = errors.New("line does not match")

// combined / common log format, with optional leading vhost (apache
// vhost_combined) and optional trailing extra fields (e.g. request time).
var clfRe = regexp.MustCompile(`^(?:(\S+?)(?::\d+)?\s+)??(\S+) \S+ (\S+) \[([^\]]+)\] "((?:[^"\\]|\\.)*)" (\d{3}|-) (\d+|-)(?: "((?:[^"\\]|\\.)*)" "((?:[^"\\]|\\.)*)")?(.*)$`)

const clfTime = "02/Jan/2006:15:04:05 -0700"

// ParseAccessLine parses a line in the given format (auto, combined, common, json).
func ParseAccessLine(line, format string) (*model.HTTPRequest, error) {
	line = strings.TrimRight(line, "\r\n")
	if strings.TrimSpace(line) == "" {
		return nil, ErrNoMatch
	}
	switch format {
	case "json":
		return parseJSONAccess(line)
	case "combined", "common":
		return parseCLF(line)
	default:
		if strings.HasPrefix(strings.TrimSpace(line), "{") {
			return parseJSONAccess(line)
		}
		return parseCLF(line)
	}
}

func parseCLF(line string) (*model.HTTPRequest, error) {
	m := clfRe.FindStringSubmatch(line)
	if m == nil {
		return nil, ErrNoMatch
	}
	vhost, ip, user, ts, req, status, size := m[1], m[2], m[3], m[4], m[5], m[6], m[7]
	if net.ParseIP(ip) == nil && vhost != "" && net.ParseIP(vhost) != nil {
		// regex ambiguity: no vhost actually present
		ip = vhost
		vhost = ""
	}
	r := &model.HTTPRequest{IP: ip, Host: vhost, LatencyMs: -1, Raw: line}
	if user != "-" {
		r.User = user
	}
	t, err := time.Parse(clfTime, ts)
	if err != nil {
		return nil, ErrNoMatch
	}
	r.TS = t.UnixMilli()
	splitRequest(r, unescape(req))
	if status != "-" {
		r.Status, _ = strconv.Atoi(status)
	}
	if size != "-" {
		r.Bytes, _ = strconv.ParseInt(size, 10, 64)
	}
	if m[8] != "-" {
		r.Referer = unescape(m[8])
	}
	if m[9] != "-" {
		r.UA = unescape(m[9])
	}
	r.LatencyMs = parseTrailingLatency(m[10])
	return r, nil
}

// parseTrailingLatency extracts a request duration from extra fields appended
// after the combined format. A decimal value is treated as seconds (nginx
// $request_time), an integer as microseconds (apache %D). Values may be quoted
// or prefixed like rt=0.123.
func parseTrailingLatency(rest string) float64 {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return -1
	}
	for _, f := range strings.Fields(rest) {
		f = strings.Trim(f, `"`)
		if i := strings.IndexByte(f, '='); i >= 0 {
			key := f[:i]
			if key != "rt" && key != "request_time" && key != "urt" && key != "upstream_response_time" && key != "D" {
				continue
			}
			f = f[i+1:]
		}
		if f == "" || f == "-" {
			continue
		}
		v, err := strconv.ParseFloat(f, 64)
		if err != nil || v < 0 {
			continue
		}
		if strings.Contains(f, ".") {
			return round2(v * 1000)
		}
		return round2(v / 1000)
	}
	return -1
}

func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	r := strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\x22`, `"`)
	return r.Replace(s)
}

func splitRequest(r *model.HTTPRequest, req string) {
	parts := strings.SplitN(req, " ", 3)
	if len(parts) >= 2 {
		r.Method = parts[0]
		setURI(r, parts[1])
		if len(parts) == 3 {
			r.Proto = parts[2]
		}
	} else {
		// e.g. "-" or garbage sent by scanners
		r.Method = "-"
		r.Path = req
	}
}

func setURI(r *model.HTTPRequest, uri string) {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		r.Path, r.Query = uri[:i], uri[i+1:]
	} else {
		r.Path = uri
	}
}

func parseJSONAccess(line string) (*model.HTTPRequest, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		return nil, ErrNoMatch
	}
	r := &model.HTTPRequest{LatencyMs: -1, Raw: line}
	// Caddy structured log.
	if req, ok := m["request"].(map[string]any); ok {
		r.IP = str(req["client_ip"])
		if r.IP == "" {
			r.IP = str(req["remote_ip"])
		}
		r.Method = str(req["method"])
		setURI(r, str(req["uri"]))
		r.Proto = str(req["proto"])
		r.Host = str(req["host"])
		if h, ok := req["headers"].(map[string]any); ok {
			r.UA = firstHeader(h, "User-Agent")
			r.Referer = firstHeader(h, "Referer")
		}
		r.Status = int(num(m["status"]))
		r.Bytes = int64(num(m["size"]))
		if d, ok := m["duration"]; ok {
			r.LatencyMs = round2(num(d) * 1000)
		}
		if ts, ok := m["ts"]; ok {
			switch v := ts.(type) {
			case float64:
				r.TS = int64(v * 1000)
			case string:
				if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
					r.TS = t.UnixMilli()
				}
			}
		}
		if r.TS == 0 {
			r.TS = time.Now().UnixMilli()
		}
		if r.IP == "" {
			return nil, ErrNoMatch
		}
		return r, nil
	}
	// Generic / nginx JSON log_format.
	r.IP = firstStr(m, "remote_addr", "client_ip", "ip", "remote_ip", "clientip")
	if xff := firstStr(m, "http_x_forwarded_for"); xff != "" && xff != "-" && r.IP == "" {
		r.IP = strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	if req := firstStr(m, "request"); req != "" {
		splitRequest(r, req)
	}
	if v := firstStr(m, "request_method", "method"); v != "" {
		r.Method = v
	}
	if v := firstStr(m, "request_uri", "uri", "path", "url"); v != "" {
		setURI(r, v)
		if q := firstStr(m, "args", "query_string"); q != "" && r.Query == "" {
			r.Query = q
		}
	}
	if v := firstStr(m, "server_protocol", "protocol", "proto"); v != "" {
		r.Proto = v
	}
	r.Host = firstStr(m, "host", "http_host", "server_name", "vhost")
	r.UA = firstStr(m, "http_user_agent", "user_agent", "agent", "ua")
	r.Referer = firstStr(m, "http_referer", "referer", "referrer")
	r.User = strings.Trim(firstStr(m, "remote_user", "user"), "-")
	r.Status = int(firstNum(m, "status", "status_code"))
	r.Bytes = int64(firstNum(m, "body_bytes_sent", "bytes_sent", "bytes", "size"))
	if v, ok := firstVal(m, "request_time", "duration", "response_time"); ok {
		r.LatencyMs = round2(num(v) * 1000)
	} else if v, ok := firstVal(m, "duration_ms", "latency_ms"); ok {
		r.LatencyMs = round2(num(v))
	}
	if v := firstStr(m, "time_iso8601", "timestamp", "time", "@timestamp"); v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			r.TS = t.UnixMilli()
		}
	}
	if r.TS == 0 {
		if v := firstStr(m, "time_local"); v != "" {
			if t, err := time.Parse(clfTime, v); err == nil {
				r.TS = t.UnixMilli()
			}
		}
	}
	if r.TS == 0 {
		if v, ok := firstVal(m, "msec", "ts"); ok {
			r.TS = int64(num(v) * 1000)
		}
	}
	if r.TS == 0 {
		r.TS = time.Now().UnixMilli()
	}
	if r.IP == "" || (r.Method == "" && r.Path == "") {
		return nil, ErrNoMatch
	}
	return r, nil
}

func firstHeader(h map[string]any, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			if arr, ok := v.([]any); ok && len(arr) > 0 {
				return str(arr[0])
			}
			return str(v)
		}
	}
	return ""
}

func firstVal(m map[string]any, keys ...string) (any, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil && v != "" && v != "-" {
			return v, true
		}
	}
	return nil, false
}

func firstStr(m map[string]any, keys ...string) string {
	v, ok := firstVal(m, keys...)
	if !ok {
		return ""
	}
	return str(v)
}

func firstNum(m map[string]any, keys ...string) float64 {
	v, ok := firstVal(m, keys...)
	if !ok {
		return 0
	}
	return num(v)
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case nil:
		return ""
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func num(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(strings.Split(t, ",")[0]), 64)
		return f
	case bool:
		if t {
			return 1
		}
	}
	return 0
}

// DecodedTarget returns the URL-decoded, lower-cased path+query for matching.
func DecodedTarget(r *model.HTTPRequest) string {
	s := r.Path
	if r.Query != "" {
		s += "?" + r.Query
	}
	// decode twice to catch double encoding
	for i := 0; i < 2; i++ {
		if d, err := url.QueryUnescape(strings.ReplaceAll(s, "+", "%2B")); err == nil {
			s = d
		} else if d, err := url.PathUnescape(s); err == nil {
			s = d
		}
	}
	return strings.ToLower(s)
}
