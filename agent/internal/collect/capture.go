package collect

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Capture is a lightweight passive packet sniffer using an AF_PACKET socket
// (pure Go, no libpcap). It needs root or CAP_NET_RAW; when unavailable it
// reports why and the rest of the agent keeps working.
type Capture struct {
	mu      sync.Mutex
	bytes   map[string]*[2]uint64 // ip -> [in, out]
	prev    map[string][2]uint64
	prevT   time.Time
	rates   map[string][2]float64
	active  atomic.Bool
	errMsg  string
	packets atomic.Uint64
	OnSYN   func(src string, dport int, ts int64)
	isLocal func(ip string) bool
	stop    chan struct{}
}

// NewCapture creates (but does not start) a capture.
func NewCapture(isLocal func(string) bool) *Capture {
	return &Capture{bytes: map[string]*[2]uint64{}, prev: map[string][2]uint64{}, rates: map[string][2]float64{}, isLocal: isLocal, stop: make(chan struct{})}
}

// Active reports whether capture is running.
func (c *Capture) Active() bool { return c != nil && c.active.Load() }

// Status returns state + message.
func (c *Capture) Status() (string, string) {
	if c == nil {
		return "off", "disabled in config"
	}
	if c.Active() {
		return "ok", "passive capture via AF_PACKET (" + itoa(c.packets.Load()) + " packets seen)"
	}
	if c.errMsg != "" {
		return "off", c.errMsg
	}
	return "off", "not started"
}

func itoa(v uint64) string {
	b := make([]byte, 0, 20)
	if v == 0 {
		return "0"
	}
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Start opens the socket and begins reading in the background.
func (c *Capture) Start() error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		if err == unix.EPERM || err == unix.EACCES {
			c.errMsg = "needs root (or CAP_NET_RAW) — per-IP bandwidth and port-scan detection from packets are disabled; connection-table data is still shown"
		} else {
			c.errMsg = "packet capture unavailable: " + err.Error()
		}
		return err
	}
	tv := unix.Timeval{Sec: 1}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	c.active.Store(true)
	go c.loop(fd)
	return nil
}

// Stop ends the capture.
func (c *Capture) Stop() {
	select {
	case <-c.stop:
	default:
		close(c.stop)
	}
}

func (c *Capture) loop(fd int) {
	defer unix.Close(fd)
	defer c.active.Store(false)
	buf := make([]byte, 128) // headers are enough; MSG_TRUNC returns real length
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		n, from, err := unix.Recvfrom(fd, buf, unix.MSG_TRUNC)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			c.errMsg = "capture stopped: " + err.Error()
			return
		}
		ll, ok := from.(*unix.SockaddrLinklayer)
		if !ok || ll.Pkttype == unix.PACKET_LOOPBACK {
			continue
		}
		c.packets.Add(1)
		hdr := buf
		if n < len(hdr) {
			hdr = hdr[:n]
		}
		c.handle(hdr, n, ll.Pkttype == unix.PACKET_OUTGOING)
	}
}

func (c *Capture) handle(p []byte, length int, outgoing bool) {
	if len(p) < 1 {
		return
	}
	var src, dst net.IP
	var proto byte
	var l4 []byte
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return
		}
		ihl := int(p[0]&0x0f) * 4
		src, dst, proto = net.IP(p[12:16]), net.IP(p[16:20]), p[9]
		if len(p) > ihl {
			l4 = p[ihl:]
		}
	case 6:
		if len(p) < 40 {
			return
		}
		src, dst, proto = net.IP(p[8:24]), net.IP(p[24:40]), p[6]
		l4 = p[40:]
	default:
		return
	}
	remote := src
	if outgoing {
		remote = dst
	}
	if remote.IsLoopback() {
		return
	}
	rs := remote.String()
	c.mu.Lock()
	b := c.bytes[rs]
	if b == nil {
		if len(c.bytes) > 20000 {
			c.mu.Unlock()
			return
		}
		b = &[2]uint64{}
		c.bytes[rs] = b
	}
	if outgoing {
		b[1] += uint64(length)
	} else {
		b[0] += uint64(length)
	}
	c.mu.Unlock()
	// inbound TCP SYN (no ACK) -> connection attempt
	if !outgoing && proto == 6 && len(l4) >= 14 && c.OnSYN != nil {
		flags := l4[13]
		if flags&0x02 != 0 && flags&0x10 == 0 {
			c.OnSYN(rs, int(binary.BigEndian.Uint16(l4[2:4])), time.Now().UnixMilli())
		}
	}
}

// Rates computes per-IP byte rates [in,out] since the previous call.
func (c *Capture) Rates() map[string][2]float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	dt := now.Sub(c.prevT).Seconds()
	if c.prevT.IsZero() || dt < 0.5 {
		if !c.prevT.IsZero() {
			return c.rates
		}
	}
	out := map[string][2]float64{}
	next := make(map[string][2]uint64, len(c.bytes))
	for ip, b := range c.bytes {
		p := c.prev[ip]
		if dt > 0 && !c.prevT.IsZero() {
			r := [2]float64{float64(b[0]-p[0]) / dt, float64(b[1]-p[1]) / dt}
			if r[0] > 0 || r[1] > 0 {
				out[ip] = r
			}
		}
		next[ip] = *b
	}
	// forget idle IPs
	for ip := range c.bytes {
		if _, ok := out[ip]; !ok && !c.prevT.IsZero() {
			delete(c.bytes, ip)
			delete(next, ip)
		}
	}
	c.prev = next
	c.prevT = now
	c.rates = out
	return out
}
