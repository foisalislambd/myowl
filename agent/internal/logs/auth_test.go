package logs

import (
	"testing"
	"time"

	"github.com/myowl/myowl/agent/internal/model"
)

var now = time.Date(2026, 10, 30, 12, 0, 0, 0, time.Local)

func TestAuthLines(t *testing.T) {
	cases := []struct {
		line           string
		kind, user, ip string
		port           int
	}{
		{"Oct 30 01:02:03 web sshd[1234]: Failed password for root from 218.92.0.112 port 51234 ssh2", model.AuthSSHFailed, "root", "218.92.0.112", 51234},
		{"Oct 30 01:02:03 web sshd[1234]: Failed password for invalid user admin from 45.95.147.236 port 40000 ssh2", model.AuthSSHInvalid, "admin", "45.95.147.236", 40000},
		{"Oct 30 01:02:03 web sshd[1234]: Invalid user oracle from 2001:db8::5 port 22 ", model.AuthSSHInvalid, "oracle", "2001:db8::5", 22},
		{"Oct 30 01:02:03 web sshd[99]: Accepted publickey for deploy from 103.108.140.25 port 52814 ssh2: ED25519 SHA256:abc", model.AuthSSHAccepted, "deploy", "103.108.140.25", 52814},
		{"Oct 30 01:02:03 web sshd[99]: Accepted password for alice from 198.51.100.2 port 1022 ssh2", model.AuthSSHAccepted, "alice", "198.51.100.2", 1022},
		{"2026-10-30T01:02:03.123456+06:00 web sshd[5]: Failed publickey for git from 192.0.2.10 port 2222 ssh2", model.AuthSSHFailed, "git", "192.0.2.10", 2222},
	}
	for _, c := range cases {
		ev := ParseAuthLine(c.line, now)
		if ev == nil {
			t.Fatalf("no event for %q", c.line)
		}
		if ev.Kind != c.kind || ev.User != c.user || ev.IP != c.ip || ev.Port != c.port {
			t.Fatalf("%q: got %+v", c.line, ev)
		}
	}
}

func TestSudo(t *testing.T) {
	ev := ParseAuthLine("Oct 30 01:02:03 web sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx", now)
	if ev == nil || ev.Kind != model.AuthSudo || ev.User != "deploy" || ev.RunAs != "root" || ev.Command != "/usr/bin/systemctl restart nginx" || ev.TTY != "pts/0" {
		t.Fatalf("got %+v", ev)
	}
	ev = ParseAuthLine("Oct 30 01:02:03 web sudo:   mallory : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash", now)
	if ev == nil || ev.Kind != model.AuthSudoFailed || ev.User != "mallory" {
		t.Fatalf("got %+v", ev)
	}
}

func TestIrrelevantAuthLines(t *testing.T) {
	for _, l := range []string{
		"Oct 30 01:02:03 web CRON[1]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
		"Oct 30 01:02:03 web sshd[1]: Received disconnect from 1.2.3.4 port 5: 11: Bye Bye [preauth]",
		"garbage",
	} {
		if ev := ParseAuthLine(l, now); ev != nil {
			t.Fatalf("unexpected event for %q: %+v", l, ev)
		}
	}
}

func TestSyslogYearInference(t *testing.T) {
	// A December line read in January belongs to the previous year.
	jan := time.Date(2027, 1, 2, 0, 0, 0, 0, time.Local)
	sl, ok := ParseSyslog("Dec 31 23:59:59 web sshd[1]: x", jan)
	if !ok || sl.TS.Year() != 2026 {
		t.Fatalf("got %+v", sl)
	}
}

func TestUFWLine(t *testing.T) {
	l := "Oct 30 01:02:03 web kernel: [123.456] [UFW BLOCK] IN=eth0 OUT= MAC=aa SRC=167.94.138.44 DST=116.203.0.10 LEN=44 TOS=0x00 PREC=0x00 TTL=40 ID=1 PROTO=TCP SPT=54321 DPT=3306 WINDOW=1024 RES=0x00 SYN URGP=0"
	fe := ParseKernelLine(l, now)
	if fe == nil || fe.Src != "167.94.138.44" || fe.DPort != 3306 || fe.Proto != "TCP" || !fe.SYN {
		t.Fatalf("got %+v", fe)
	}
	if ParseKernelLine("Oct 30 01:02:03 web kernel: eth0: link up", now) != nil {
		t.Fatal("expected nil")
	}
}
