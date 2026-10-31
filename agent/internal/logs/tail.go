package logs

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"syscall"
	"time"
)

// Position identifies where a tailer is in a file.
type Position struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// TailOptions configure a Tailer.
type TailOptions struct {
	// Start position restored from storage (Inode 0 = none).
	Start Position
	// When no Start is known, read roughly this many trailing lines first.
	BackfillLines int
	// Poll interval.
	Poll time.Duration
	// OnLine receives each complete line (without newline) and whether it
	// came from backfill.
	OnLine func(line string, backfill bool)
	// OnPos is called periodically with the current position.
	OnPos func(Position)
	// OnStatus receives state changes ("ok", "waiting", "error") + message.
	OnStatus func(state, msg string)
}

// Tail follows a file across rotation and truncation until ctx is done.
func Tail(ctx context.Context, path string, o TailOptions) {
	if o.Poll == 0 {
		o.Poll = 500 * time.Millisecond
	}
	status := func(s, m string) {
		if o.OnStatus != nil {
			o.OnStatus(s, m)
		}
	}
	first := true
	for {
		if ctx.Err() != nil {
			return
		}
		f, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				status("error", "permission denied (run as root or add the user to the 'adm' group)")
			} else {
				status("waiting", "file not found yet")
			}
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}
		ino, size := fileID(f)
		var off int64
		backfill := false
		switch {
		case first && o.Start.Inode == ino && o.Start.Offset <= size:
			off = o.Start.Offset
		case first:
			off = backfillOffset(f, size, o.BackfillLines)
			backfill = off < size
		default:
			off = 0 // rotated: new file, read from start
		}
		first = false
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			f.Close()
			status("error", err.Error())
			if !sleepCtx(ctx, 5*time.Second) {
				return
			}
			continue
		}
		status("ok", "following")
		off = follow(ctx, f, path, ino, off, size, backfill, o)
		f.Close()
		if ctx.Err() != nil {
			return
		}
	}
}

// follow reads until the file is rotated; returns the last offset.
func follow(ctx context.Context, f *os.File, path string, ino uint64, off, backfillEnd int64, backfill bool, o TailOptions) int64 {
	r := bufio.NewReaderSize(f, 64*1024)
	var partial []byte
	lastPos := time.Now()
	for {
		line, err := r.ReadSlice('\n')
		if len(line) > 0 {
			if err == nil {
				full := line
				if len(partial) > 0 {
					full = append(partial, line...)
					partial = partial[:0]
				}
				off += int64(len(line))
				s := string(full[:len(full)-1])
				if len(s) > 0 && s[len(s)-1] == '\r' {
					s = s[:len(s)-1]
				}
				if len(s) > 16*1024 {
					s = s[:16*1024]
				}
				o.OnLine(s, backfill && off <= backfillEnd)
				continue
			}
			if errors.Is(err, bufio.ErrBufferFull) {
				off += int64(len(line))
				if len(partial) < 64*1024 {
					partial = append(partial, line...)
				}
				continue
			}
			// EOF with partial line: keep it until the rest arrives
			off += int64(len(line))
			partial = append(partial, line...)
		}
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
			return off
		}
		backfill = false
		if o.OnPos != nil && time.Since(lastPos) > 3*time.Second {
			// only persist positions at line boundaries
			o.OnPos(Position{Inode: ino, Offset: off - int64(len(partial))})
			lastPos = time.Now()
		}
		if !sleepCtx(ctx, o.Poll) {
			if o.OnPos != nil {
				o.OnPos(Position{Inode: ino, Offset: off - int64(len(partial))})
			}
			return off
		}
		// rotation / truncation checks
		st, err := os.Stat(path)
		if err != nil {
			continue // file moved away, keep draining old fd until new appears
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Ino != ino {
			// drain rest of old file then switch
			rest, _ := io.ReadAll(r)
			for _, l := range splitLines(append(partial, rest...)) {
				o.OnLine(l, false)
			}
			return 0
		}
		if st.Size() < off {
			// truncated (copytruncate)
			f.Seek(0, io.SeekStart)
			r.Reset(f)
			partial = partial[:0]
			off = 0
		}
	}
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	return out
}

func fileID(f *os.File) (uint64, int64) {
	st, err := f.Stat()
	if err != nil {
		return 0, 0
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Ino, st.Size()
	}
	return 0, st.Size()
}

// backfillOffset finds an offset that leaves about n lines before EOF.
func backfillOffset(f *os.File, size int64, n int) int64 {
	if n <= 0 || size == 0 {
		return size
	}
	const chunk = 64 * 1024
	pos := size
	count := 0
	buf := make([]byte, chunk)
	for pos > 0 {
		readSize := int64(chunk)
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		if _, err := f.ReadAt(buf[:readSize], pos); err != nil && !errors.Is(err, io.EOF) {
			return size
		}
		for i := readSize - 1; i >= 0; i-- {
			if buf[i] == '\n' {
				count++
				if count > n {
					return pos + i + 1
				}
			}
		}
		if size-pos > 8*1024*1024 {
			// cap backfill to 8MB
			return pos
		}
	}
	return 0
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
