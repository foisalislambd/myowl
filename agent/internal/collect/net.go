package collect

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/myowl/myowl/agent/internal/model"
)

var tcpStates = map[uint8]string{1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
	7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV"}

// WellKnownPorts maps ports to plain-language service names.
var WellKnownPorts = map[int]string{20: "FTP data", 21: "FTP", 22: "SSH (remote login)", 23: "Telnet (insecure)", 25: "Email (SMTP)", 53: "DNS",
	80: "Website (HTTP)", 110: "Email (POP3)", 111: "RPC portmapper", 123: "Time sync (NTP)", 143: "Email (IMAP)", 443: "Website (HTTPS)",
	465: "Email (SMTPS)", 587: "Email submission", 993: "Email (IMAPS)", 995: "Email (POP3S)", 1433: "SQL Server database",
	2375: "Docker API (insecure!)", 2376: "Docker API (TLS)", 3000: "Web app (dev server)", 3306: "MySQL database", 3389: "Remote Desktop",
	5432: "PostgreSQL database", 5672: "RabbitMQ", 5900: "VNC remote desktop", 6379: "Redis database", 8080: "Web app (HTTP alt)",
	8443: "Web app (HTTPS alt)", 8787: "myOwl (this dashboard)", 9000: "PHP-FPM / app", 9090: "Cockpit / Prometheus",
	9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB database", 51820: "WireGuard VPN", 1194: "OpenVPN"}

// RiskyPublicPorts are services that normally should not be reachable from the internet.
var RiskyPublicPorts = map[int]string{
	23:    "Telnet sends passwords unencrypted — disable it and use SSH.",
	2375:  "The Docker API without TLS gives full control of the server to anyone — close this port now.",
	3306:  "Your MySQL database is reachable from the internet. Bind it to 127.0.0.1 unless remote access is required.",
	5432:  "Your PostgreSQL database is reachable from the internet. Bind it to localhost or restrict with a firewall.",
	6379:  "Redis is reachable from the internet and is often attacked. Bind it to 127.0.0.1.",
	27017: "MongoDB is reachable from the internet. Bind it to localhost and enable authentication.",
	9200:  "Elasticsearch is reachable from the internet. Restrict it with a firewall.",
	11211: "Memcached is reachable from the internet and can be abused for DDoS. Bind it to localhost.",
	5900:  "VNC is reachable from the internet. Use a VPN or SSH tunnel instead.",
	3389:  "Remote Desktop is reachable from the internet. Restrict it with a firewall.",
	111:   "RPC portmapper is reachable from the internet and can be abused. Disable it if unused.",
}

type ifCounters struct{ rx, tx uint64 }

// NetCollector produces NetworkSnapshots.
type NetCollector struct {
	mu         sync.Mutex
	prevIf     map[string]ifCounters
	prevIfT    time.Time
	prevConn   map[string][2]uint64
	prevConnT  time.Time
	inodeProc  map[uint64]procRef
	inodeAt    time.Time
	users      map[int]string
	usersAt    time.Time
	netlinkOK  bool
	netlinkErr string
	localIPs   map[string]bool
	Capture    *Capture
}

type procRef struct {
	pid  int
	name string
}

// NewNetCollector creates a network collector.
func NewNetCollector() *NetCollector {
	return &NetCollector{prevIf: map[string]ifCounters{}, prevConn: map[string][2]uint64{}, netlinkOK: true}
}

// LocalIPs returns the set of addresses assigned to local interfaces.
func (c *NetCollector) LocalIPs() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localIPs
}

// Source describes how connections are read.
func (c *NetCollector) Source() (string, string) {
	if c.netlinkOK {
		return "netlink", "sock_diag netlink (with per-connection byte counters)"
	}
	return "procfs", "/proc/net/tcp (netlink unavailable: " + c.netlinkErr + ")"
}

// Collect gathers a network snapshot (without geo; the engine adds it).
func (c *NetCollector) Collect() *model.NetworkSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	s := &model.NetworkSnapshot{TS: now.UnixMilli(), StateCounts: map[string]int{}}
	s.Interfaces = c.interfaces(now)
	for _, i := range s.Interfaces {
		if i.Name == "lo" {
			continue
		}
		s.TotalRxBps += i.RxBps
		s.TotalTxBps += i.TxBps
	}
	if time.Since(c.inodeAt) > 4*time.Second || c.inodeProc == nil {
		c.inodeProc = socketInodes()
		c.inodeAt = now
	}
	if c.users == nil || time.Since(c.usersAt) > time.Minute {
		c.users = ReadUsers()
		c.usersAt = now
	}
	var conns []model.Conn
	var uids map[uint64]int
	if c.netlinkOK {
		var err error
		conns, uids, err = netlinkTCP()
		if err != nil {
			c.netlinkOK = false
			c.netlinkErr = err.Error()
		}
	}
	if !c.netlinkOK {
		conns, uids = procTCP()
	}
	udp, udpUIDs := procUDP()
	conns = append(conns, udp...)
	for k, v := range udpUIDs {
		uids[k] = v
	}
	if c.localIPs == nil {
		c.localIPs = map[string]bool{}
	}
	listenPorts := map[string]bool{}
	for i := range conns {
		cn := &conns[i]
		if p, ok := c.inodeProc[cn.Inode]; ok {
			cn.PID, cn.Process = p.pid, p.name
		}
		if uid, ok := uids[cn.Inode]; ok {
			if n, ok := c.users[uid]; ok {
				cn.User = n
			} else {
				cn.User = strconv.Itoa(uid)
			}
		}
		if cn.State == "LISTEN" || (cn.Proto == "udp" && cn.RemotePort == 0) {
			listenPorts[cn.Proto+":"+strconv.Itoa(cn.LocalPort)] = true
		}
	}
	// connection direction + byte rates
	dt := now.Sub(c.prevConnT).Seconds()
	nextPrev := make(map[string][2]uint64, len(conns))
	var out []model.Conn
	var listeners []model.Listener
	lmap := map[string]*model.Listener{}
	for _, cn := range conns {
		if cn.State == "LISTEN" || (cn.Proto == "udp" && cn.RemotePort == 0) {
			l := model.Listener{Proto: cn.Proto, Addr: cn.LocalIP, Port: cn.LocalPort, PID: cn.PID, Process: cn.Process, User: cn.User}
			ip := net.ParseIP(cn.LocalIP)
			l.Public = ip != nil && !ip.IsLoopback()
			l.Service = WellKnownPorts[cn.LocalPort]
			if r, ok := RiskyPublicPorts[cn.LocalPort]; ok && l.Public {
				l.Risk = r
			}
			key := fmt.Sprintf("%s:%d:%v", l.Proto, l.Port, l.Public)
			if ex, ok := lmap[key]; ok {
				if ex.Process == "" {
					ex.Process, ex.PID = l.Process, l.PID
				}
				continue
			}
			listeners = append(listeners, l)
			lmap[key] = &listeners[len(listeners)-1]
			continue
		}
		if cn.RemoteIP == "" {
			continue
		}
		rip := net.ParseIP(cn.RemoteIP)
		switch {
		case rip != nil && rip.IsLoopback():
			cn.Direction = "local"
		case listenPorts[cn.Proto+":"+strconv.Itoa(cn.LocalPort)]:
			cn.Direction = "in"
		default:
			cn.Direction = "out"
		}
		c.localIPs[cn.LocalIP] = true
		s.StateCounts[cn.State]++
		key := fmt.Sprintf("%s|%s|%d|%s|%d", cn.Proto, cn.LocalIP, cn.LocalPort, cn.RemoteIP, cn.RemotePort)
		nextPrev[key] = [2]uint64{cn.BytesSent, cn.BytesRecv}
		out = append(out, cn)
	}
	// count conns per listener after direction computed
	for i := range listeners {
		for _, cn := range out {
			if cn.Direction == "in" && cn.LocalPort == listeners[i].Port && cn.Proto == listeners[i].Proto {
				listeners[i].Conns++
			}
		}
	}
	sort.Slice(listeners, func(i, j int) bool {
		if listeners[i].Public != listeners[j].Public {
			return listeners[i].Public
		}
		return listeners[i].Port < listeners[j].Port
	})
	s.Listeners = listeners
	// talkers
	type agg struct {
		t     model.Talker
		procs map[string]bool
		ports map[int]bool
	}
	tal := map[string]*agg{}
	for _, cn := range out {
		if cn.Direction == "local" {
			continue
		}
		a := tal[cn.RemoteIP]
		if a == nil {
			a = &agg{t: model.Talker{IP: cn.RemoteIP, Direction: cn.Direction}, procs: map[string]bool{}, ports: map[int]bool{}}
			tal[cn.RemoteIP] = a
		}
		a.t.Conns++
		a.t.BytesIn += cn.BytesRecv
		a.t.BytesOut += cn.BytesSent
		key := fmt.Sprintf("%s|%s|%d|%s|%d", cn.Proto, cn.LocalIP, cn.LocalPort, cn.RemoteIP, cn.RemotePort)
		if p, ok := c.prevConn[key]; ok && dt > 0 {
			if cn.BytesSent >= p[0] {
				a.t.RateOut += float64(cn.BytesSent-p[0]) / dt
			}
			if cn.BytesRecv >= p[1] {
				a.t.RateIn += float64(cn.BytesRecv-p[1]) / dt
			}
		}
		if cn.Process != "" {
			a.procs[cn.Process] = true
		}
		if cn.Direction == "in" {
			a.ports[cn.LocalPort] = true
		} else {
			a.ports[cn.RemotePort] = true
		}
	}
	// merge packet-capture byte counters (more accurate, includes UDP)
	if c.Capture != nil && c.Capture.Active() {
		for ip, r := range c.Capture.Rates() {
			a := tal[ip]
			if a == nil {
				if r[0]+r[1] < 64 {
					continue
				}
				a = &agg{t: model.Talker{IP: ip, Direction: "in"}, procs: map[string]bool{}, ports: map[int]bool{}}
				tal[ip] = a
			}
			a.t.RateIn, a.t.RateOut = r[0], r[1]
		}
	}
	for _, a := range tal {
		for p := range a.procs {
			a.t.Processes = append(a.t.Processes, p)
		}
		sort.Strings(a.t.Processes)
		for p := range a.ports {
			a.t.Ports = append(a.t.Ports, p)
		}
		sort.Ints(a.t.Ports)
		if len(a.t.Ports) > 12 {
			a.t.Ports = a.t.Ports[:12]
		}
		s.Talkers = append(s.Talkers, a.t)
	}
	sort.Slice(s.Talkers, func(i, j int) bool {
		ri := s.Talkers[i].RateIn + s.Talkers[i].RateOut
		rj := s.Talkers[j].RateIn + s.Talkers[j].RateOut
		if ri != rj {
			return ri > rj
		}
		if s.Talkers[i].Conns != s.Talkers[j].Conns {
			return s.Talkers[i].Conns > s.Talkers[j].Conns
		}
		return s.Talkers[i].BytesIn+s.Talkers[i].BytesOut > s.Talkers[j].BytesIn+s.Talkers[j].BytesOut
	})
	if len(s.Talkers) > 100 {
		s.Talkers = s.Talkers[:100]
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Direction != out[j].Direction {
			return out[i].Direction < out[j].Direction
		}
		return out[i].BytesSent+out[i].BytesRecv > out[j].BytesSent+out[j].BytesRecv
	})
	s.ConnCount = len(out)
	if len(out) > 1000 {
		out = out[:1000]
	}
	s.Connections = out
	c.prevConn = nextPrev
	c.prevConnT = now
	if c.netlinkOK {
		s.Source = "netlink"
	} else {
		s.Source = "procfs"
	}
	return s
}

func (c *NetCollector) interfaces(now time.Time) []model.Interface {
	var out []model.Interface
	lines := strings.Split(readFile(filepath.Join(ProcRoot, "net/dev")), "\n")
	dt := now.Sub(c.prevIfT).Seconds()
	sysIfs, _ := net.Interfaces()
	ifByName := map[string]net.Interface{}
	for _, i := range sysIfs {
		ifByName[i.Name] = i
	}
	local := map[string]bool{}
	for _, l := range lines {
		i := strings.IndexByte(l, ':')
		if i < 0 {
			continue
		}
		name := strings.TrimSpace(l[:i])
		f := strings.Fields(l[i+1:])
		if len(f) < 16 {
			continue
		}
		u := func(k int) uint64 { v, _ := strconv.ParseUint(f[k], 10, 64); return v }
		it := model.Interface{Name: name, RxBytes: u(0), RxPackets: u(1), RxErrors: u(2), TxBytes: u(8), TxPackets: u(9), TxErrors: u(10)}
		if p, ok := c.prevIf[name]; ok && dt > 0 {
			if it.RxBytes >= p.rx {
				it.RxBps = float64(it.RxBytes-p.rx) / dt
			}
			if it.TxBytes >= p.tx {
				it.TxBps = float64(it.TxBytes-p.tx) / dt
			}
		}
		c.prevIf[name] = ifCounters{it.RxBytes, it.TxBytes}
		if si, ok := ifByName[name]; ok {
			it.Up = si.Flags&net.FlagUp != 0
			it.MAC = si.HardwareAddr.String()
			addrs, _ := si.Addrs()
			for _, a := range addrs {
				it.Addrs = append(it.Addrs, a.String())
				if ipn, ok := a.(*net.IPNet); ok {
					local[ipn.IP.String()] = true
				}
			}
		}
		out = append(out, it)
	}
	c.prevIfT = now
	c.localIPs = local
	sort.Slice(out, func(i, j int) bool {
		if (out[i].Name == "lo") != (out[j].Name == "lo") {
			return out[j].Name == "lo"
		}
		return out[i].RxBytes+out[i].TxBytes > out[j].RxBytes+out[j].TxBytes
	})
	return out
}

// socketInodes maps socket inode -> owning process by scanning /proc/*/fd.
// Without root only the agent user's own processes are visible.
func socketInodes() map[uint64]procRef {
	out := map[uint64]procRef{}
	for _, pid := range ListPIDs() {
		dir := filepath.Join(ProcRoot, strconv.Itoa(pid), "fd")
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var name string
		for _, e := range ents {
			link, err := os.Readlink(filepath.Join(dir, e.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			ino, err := strconv.ParseUint(link[8:len(link)-1], 10, 64)
			if err != nil {
				continue
			}
			if name == "" {
				name = strings.TrimSpace(readFile(filepath.Join(ProcRoot, strconv.Itoa(pid), "comm")))
			}
			if _, exists := out[ino]; !exists {
				out[ino] = procRef{pid, name}
			}
		}
	}
	return out
}

// ---------------- netlink sock_diag ----------------

const (
	sockDiagByFamily = 20
	inetDiagInfo     = 2
)

func netlinkTCP() ([]model.Conn, map[uint64]int, error) {
	var all []model.Conn
	uids := map[uint64]int{}
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		conns, u, err := netlinkDump(fam, unix.IPPROTO_TCP)
		if err != nil {
			if fam == unix.AF_INET6 && len(all) > 0 {
				continue // IPv6 disabled
			}
			return nil, nil, err
		}
		all = append(all, conns...)
		for k, v := range u {
			uids[k] = v
		}
	}
	return all, uids, nil
}

func netlinkDump(family, proto uint8) ([]model.Conn, map[uint64]int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		return nil, nil, err
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, nil, err
	}
	tv := unix.Timeval{Sec: 2}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	// nlmsghdr(16) + inet_diag_req_v2(56)
	req := make([]byte, 16+56)
	binary.LittleEndian.PutUint32(req[0:], uint32(len(req)))
	binary.LittleEndian.PutUint16(req[4:], sockDiagByFamily)
	binary.LittleEndian.PutUint16(req[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(req[8:], 1)
	req[16] = family
	req[17] = proto
	req[18] = 1 << (inetDiagInfo - 1)
	binary.LittleEndian.PutUint32(req[20:], 0xffffffff) // all states
	if err := unix.Sendto(fd, req, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, nil, err
	}
	var out []model.Conn
	uids := map[uint64]int{}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, nil, err
		}
		msgs, err := syscallParseNetlink(buf[:n])
		if err != nil {
			return nil, nil, err
		}
		for _, m := range msgs {
			switch m.typ {
			case unix.NLMSG_DONE:
				return out, uids, nil
			case unix.NLMSG_ERROR:
				if len(m.data) >= 4 {
					errno := int32(binary.LittleEndian.Uint32(m.data[:4]))
					if errno != 0 {
						return nil, nil, fmt.Errorf("netlink error %d", -errno)
					}
				}
				return out, uids, nil
			case sockDiagByFamily:
				if c, uid, ok := parseDiagMsg(m.data, family); ok {
					out = append(out, c)
					uids[c.Inode] = uid
				}
			}
		}
	}
}

type nlMsg struct {
	typ  uint16
	data []byte
}

func syscallParseNetlink(b []byte) ([]nlMsg, error) {
	var out []nlMsg
	for len(b) >= 16 {
		l := int(binary.LittleEndian.Uint32(b[0:]))
		if l < 16 || l > len(b) {
			return nil, fmt.Errorf("bad netlink message length")
		}
		out = append(out, nlMsg{typ: binary.LittleEndian.Uint16(b[4:]), data: b[16:l]})
		al := (l + 3) &^ 3
		if al > len(b) {
			break
		}
		b = b[al:]
	}
	return out, nil
}

func parseDiagMsg(d []byte, family uint8) (model.Conn, int, bool) {
	if len(d) < 72 {
		return model.Conn{}, 0, false
	}
	c := model.Conn{Proto: "tcp", State: tcpStates[d[1]]}
	c.LocalPort = int(binary.BigEndian.Uint16(d[4:6]))
	c.RemotePort = int(binary.BigEndian.Uint16(d[6:8]))
	if family == unix.AF_INET {
		c.LocalIP = net.IP(d[8:12]).String()
		c.RemoteIP = net.IP(d[24:28]).String()
	} else {
		c.LocalIP = normIP(net.IP(d[8:24]))
		c.RemoteIP = normIP(net.IP(d[24:40]))
		c.Proto = "tcp6"
	}
	uid := int(binary.LittleEndian.Uint32(d[64:68]))
	c.Inode = uint64(binary.LittleEndian.Uint32(d[68:72]))
	if c.State == "LISTEN" {
		c.RemoteIP = ""
	}
	// attributes
	attrs := d[72:]
	for len(attrs) >= 4 {
		l := int(binary.LittleEndian.Uint16(attrs[0:]))
		t := binary.LittleEndian.Uint16(attrs[2:])
		if l < 4 || l > len(attrs) {
			break
		}
		v := attrs[4:l]
		if t == inetDiagInfo && len(v) >= 136 {
			c.RTTms = float64(binary.LittleEndian.Uint32(v[68:72])) / 1000
			c.BytesSent = binary.LittleEndian.Uint64(v[120:128])
			c.BytesRecv = binary.LittleEndian.Uint64(v[128:136])
		}
		attrs = attrs[(l+3)&^3:]
	}
	if c.Proto == "tcp6" {
		c.Proto = "tcp"
	}
	return c, uid, true
}

func normIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// ---------------- /proc/net fallback ----------------

func procTCP() ([]model.Conn, map[uint64]int) {
	var out []model.Conn
	uids := map[uint64]int{}
	for _, f := range []string{"net/tcp", "net/tcp6"} {
		conns, u := parseProcNet(readFile(filepath.Join(ProcRoot, f)), "tcp")
		out = append(out, conns...)
		for k, v := range u {
			uids[k] = v
		}
	}
	return out, uids
}

func procUDP() ([]model.Conn, map[uint64]int) {
	var out []model.Conn
	uids := map[uint64]int{}
	for _, f := range []string{"net/udp", "net/udp6"} {
		conns, u := parseProcNet(readFile(filepath.Join(ProcRoot, f)), "udp")
		out = append(out, conns...)
		for k, v := range u {
			uids[k] = v
		}
	}
	return out, uids
}

// ParseProcNet parses /proc/net/{tcp,udp}[6] content (exported for tests).
func ParseProcNet(content, proto string) []model.Conn {
	c, _ := parseProcNet(content, proto)
	return c
}

func parseProcNet(content, proto string) ([]model.Conn, map[uint64]int) {
	var out []model.Conn
	uids := map[uint64]int{}
	for i, l := range strings.Split(content, "\n") {
		if i == 0 {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 10 {
			continue
		}
		lip, lport, ok1 := parseHexAddr(f[1])
		rip, rport, ok2 := parseHexAddr(f[2])
		if !ok1 || !ok2 {
			continue
		}
		st, _ := strconv.ParseUint(f[3], 16, 8)
		c := model.Conn{Proto: proto, LocalIP: lip, LocalPort: lport, RemoteIP: rip, RemotePort: rport}
		if proto == "tcp" {
			c.State = tcpStates[uint8(st)]
		} else {
			if rport == 0 {
				c.State = "LISTEN"
			} else {
				c.State = "ESTABLISHED"
			}
		}
		if c.State == "LISTEN" {
			c.RemoteIP = ""
		}
		uid, _ := strconv.Atoi(f[7])
		c.Inode, _ = strconv.ParseUint(f[9], 10, 64)
		uids[c.Inode] = uid
		out = append(out, c)
	}
	return out, uids
}

func parseHexAddr(s string) (string, int, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", 0, false
	}
	b, err := hex.DecodeString(s[:i])
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return "", 0, false
	}
	// kernel prints each 32-bit word in host (little-endian) order
	for w := 0; w+4 <= len(b); w += 4 {
		b[w], b[w+1], b[w+2], b[w+3] = b[w+3], b[w+2], b[w+1], b[w]
	}
	switch len(b) {
	case 4, 16:
		return normIP(net.IP(b)), int(port), true
	}
	return "", 0, false
}
