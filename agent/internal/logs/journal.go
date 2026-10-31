package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"time"
)

// JournalEntry is one journald record.
type JournalEntry struct {
	TS      time.Time
	Program string
	Message string
	Cursor  string
}

// JournalOptions configures FollowJournal.
type JournalOptions struct {
	Cursor   string
	Backfill int
	OnEntry  func(e JournalEntry, backfill bool)
	OnStatus func(state, msg string)
}

// JournalAvailable reports whether journalctl exists.
func JournalAvailable() bool {
	_, err := exec.LookPath("journalctl")
	return err == nil
}

// FollowJournal streams sshd/sudo/su/kernel entries from journald.
func FollowJournal(ctx context.Context, o JournalOptions) {
	for ctx.Err() == nil {
		args := []string{"--follow", "--output=json", "--no-pager", "--quiet"}
		if o.Cursor != "" {
			args = append(args, "--after-cursor="+o.Cursor)
		} else {
			args = append(args, "--lines="+strconv.Itoa(o.Backfill))
		}
		args = append(args,
			"SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session", "SYSLOG_IDENTIFIER=sudo",
			"SYSLOG_IDENTIFIER=su", "SYSLOG_IDENTIFIER=kernel")
		cmd := exec.CommandContext(ctx, "journalctl", args...)
		out, err := cmd.StdoutPipe()
		if err != nil {
			o.OnStatus("error", err.Error())
			return
		}
		if err := cmd.Start(); err != nil {
			o.OnStatus("error", "journalctl failed: "+err.Error())
			if !sleepCtx(ctx, 30*time.Second) {
				return
			}
			continue
		}
		o.OnStatus("ok", "following journald")
		start := time.Now()
		sc := bufio.NewScanner(out)
		sc.Buffer(make([]byte, 256*1024), 1024*1024)
		n := 0
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) != nil {
				continue
			}
			n++
			e := JournalEntry{Program: jstr(m["SYSLOG_IDENTIFIER"]), Message: jstr(m["MESSAGE"]), Cursor: jstr(m["__CURSOR"])}
			if us, err := strconv.ParseInt(jstr(m["__REALTIME_TIMESTAMP"]), 10, 64); err == nil {
				e.TS = time.UnixMicro(us)
			} else {
				e.TS = time.Now()
			}
			o.Cursor = e.Cursor
			o.OnEntry(e, e.TS.Before(start.Add(-2*time.Second)))
		}
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return
		}
		if n == 0 && time.Since(start) < 5*time.Second {
			o.OnStatus("degraded", "journald returned no entries (needs root or membership in the systemd-journal/adm group)")
		}
		if !sleepCtx(ctx, 15*time.Second) {
			return
		}
	}
}

func jstr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		// MESSAGE may be a byte array for non-UTF8 content
		b := make([]byte, 0, len(t))
		for _, x := range t {
			if f, ok := x.(float64); ok {
				b = append(b, byte(f))
			}
		}
		return string(b)
	}
	return ""
}
