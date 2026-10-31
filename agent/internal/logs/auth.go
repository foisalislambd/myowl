package logs

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/myowl/myowl/agent/internal/model"
)

// Syslog line formats:
//
//	Oct 30 01:02:03 host sshd[123]: message
//	2026-10-30T01:02:03.123456+06:00 host sshd[123]: message
var (
	bsdSyslogRe = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (\S+) ([^\[:\s]+)(?:\[(\d+)\])?: ?(.*)$`)
	isoSyslogRe = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) ([^\[:\s]+)(?:\[(\d+)\])?: ?(.*)$`)
)

// SyslogLine is a parsed syslog line.
type SyslogLine struct {
	TS      time.Time
	Host    string
	Program string
	PID     int
	Message string
}

// ParseSyslog parses a BSD or RFC3339 syslog line. now is used to infer the
// year for BSD timestamps.
func ParseSyslog(line string, now time.Time) (*SyslogLine, bool) {
	line = strings.TrimRight(line, "\r\n")
	if m := isoSyslogRe.FindStringSubmatch(line); m != nil {
		t, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil {
			t, err = time.ParseInLocation("2006-01-02T15:04:05.999999999", m[1], time.Local)
			if err != nil {
				t, err = time.Parse("2006-01-02T15:04:05.999999999-0700", m[1])
				if err != nil {
					return nil, false
				}
			}
		}
		pid, _ := strconv.Atoi(m[4])
		return &SyslogLine{TS: t, Host: m[2], Program: m[3], PID: pid, Message: m[5]}, true
	}
	if m := bsdSyslogRe.FindStringSubmatch(line); m != nil {
		t, err := time.ParseInLocation("Jan _2 15:04:05", strings.Join(strings.Fields(m[1]), " "), time.Local)
		if err != nil {
			t, err = time.ParseInLocation("Jan 2 15:04:05", strings.Join(strings.Fields(m[1]), " "), time.Local)
			if err != nil {
				return nil, false
			}
		}
		t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
		if t.After(now.Add(48 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		pid, _ := strconv.Atoi(m[4])
		return &SyslogLine{TS: t, Host: m[2], Program: m[3], PID: pid, Message: m[5]}, true
	}
	return nil, false
}

var (
	sshFailedRe   = regexp.MustCompile(`^Failed (\S+) for (invalid user )?(.*?) from (\S+) port (\d+)`)
	sshAcceptedRe = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	sshInvalidRe  = regexp.MustCompile(`^Invalid user (.*?) from (\S+)(?: port (\d+))?`)
	sshMaxAuthRe  = regexp.MustCompile(`^(?:error: )?maximum authentication attempts exceeded for (invalid user )?(.*?) from (\S+) port (\d+)`)
	sudoRe        = regexp.MustCompile(`^\s*(\S+) : (?:(.*?) ; )?TTY=(\S+) ; PWD=(.*?) ; USER=(\S+) ;(?: [A-Z]+=\S+ ;)* COMMAND=(.*)$`)
	suRe          = regexp.MustCompile(`^(?:\(to (\S+)\) (\S+) on (\S+)|Successful su for (\S+) by (\S+))`)
)

// IsSSHProgram reports whether a syslog program name is the SSH daemon.
func IsSSHProgram(p string) bool {
	return p == "sshd" || p == "sshd-session" || strings.HasPrefix(p, "sshd")
}

// ParseAuthMessage parses an sshd/sudo/su syslog message.
func ParseAuthMessage(program, msg string, ts time.Time) *model.AuthEvent {
	msg = strings.TrimSpace(msg)
	tsm := ts.UnixMilli()
	switch {
	case IsSSHProgram(program):
		if m := sshFailedRe.FindStringSubmatch(msg); m != nil {
			port, _ := strconv.Atoi(m[5])
			kind := model.AuthSSHFailed
			if m[2] != "" {
				kind = model.AuthSSHInvalid
			}
			return &model.AuthEvent{TS: tsm, Kind: kind, User: m[3], IP: m[4], Port: port, Method: m[1], Raw: msg}
		}
		if m := sshAcceptedRe.FindStringSubmatch(msg); m != nil {
			port, _ := strconv.Atoi(m[4])
			return &model.AuthEvent{TS: tsm, Kind: model.AuthSSHAccepted, User: m[2], IP: m[3], Port: port, Method: m[1], Raw: msg}
		}
		if m := sshMaxAuthRe.FindStringSubmatch(msg); m != nil {
			port, _ := strconv.Atoi(m[4])
			kind := model.AuthSSHFailed
			if m[1] != "" {
				kind = model.AuthSSHInvalid
			}
			return &model.AuthEvent{TS: tsm, Kind: kind, User: m[2], IP: m[3], Port: port, Method: "max-attempts", Raw: msg}
		}
		if m := sshInvalidRe.FindStringSubmatch(msg); m != nil {
			// "Invalid user" lines are always followed by a Failed line when a
			// password was tried; report them as invalid-user probes with no
			// method so the detector can count them once.
			port, _ := strconv.Atoi(m[3])
			return &model.AuthEvent{TS: tsm, Kind: model.AuthSSHInvalid, User: m[1], IP: m[2], Port: port, Method: "probe", Raw: msg}
		}
	case program == "sudo":
		if m := sudoRe.FindStringSubmatch(msg); m != nil {
			ev := &model.AuthEvent{TS: tsm, Kind: model.AuthSudo, User: m[1], TTY: m[3], RunAs: m[5], Command: m[6], Raw: msg}
			if m[2] != "" && (strings.Contains(m[2], "incorrect password") || strings.Contains(m[2], "NOT in sudoers") || strings.Contains(m[2], "command not allowed")) {
				ev.Kind = model.AuthSudoFailed
				ev.Method = m[2]
			}
			return ev
		}
	case program == "su":
		if m := suRe.FindStringSubmatch(msg); m != nil {
			if m[1] != "" {
				return &model.AuthEvent{TS: tsm, Kind: model.AuthSu, User: m[2], RunAs: m[1], TTY: m[3], Raw: msg}
			}
			return &model.AuthEvent{TS: tsm, Kind: model.AuthSu, User: m[5], RunAs: m[4], Raw: msg}
		}
	}
	return nil
}

// ParseAuthLine parses a full syslog line from auth.log / secure.
func ParseAuthLine(line string, now time.Time) *model.AuthEvent {
	sl, ok := ParseSyslog(line, now)
	if !ok {
		return nil
	}
	return ParseAuthMessage(sl.Program, sl.Message, sl.TS)
}

var kvRe = regexp.MustCompile(`([A-Z]+)=(\S*)`)

// ParseFirewallMessage parses a kernel netfilter log message such as
// "[UFW BLOCK] IN=eth0 OUT= MAC=.. SRC=1.2.3.4 DST=5.6.7.8 ... PROTO=TCP SPT=1 DPT=22 ... SYN URGP=0".
func ParseFirewallMessage(msg string, ts time.Time) *model.FirewallEvent {
	if !strings.Contains(msg, "SRC=") || !strings.Contains(msg, "IN=") {
		return nil
	}
	// only inbound packets
	ev := &model.FirewallEvent{TS: ts.UnixMilli()}
	in := ""
	for _, m := range kvRe.FindAllStringSubmatch(msg, -1) {
		switch m[1] {
		case "IN":
			in = m[2]
		case "SRC":
			ev.Src = m[2]
		case "DST":
			ev.Dst = m[2]
		case "PROTO":
			ev.Proto = m[2]
		case "DPT":
			ev.DPort, _ = strconv.Atoi(m[2])
		}
	}
	if in == "" || ev.Src == "" {
		return nil
	}
	ev.SYN = strings.Contains(msg, " SYN ") || strings.HasSuffix(msg, " SYN")
	return ev
}

// ParseKernelLine parses a syslog line from kern.log / ufw.log.
func ParseKernelLine(line string, now time.Time) *model.FirewallEvent {
	sl, ok := ParseSyslog(line, now)
	if !ok {
		return nil
	}
	if sl.Program != "kernel" {
		return nil
	}
	return ParseFirewallMessage(sl.Message, sl.TS)
}
