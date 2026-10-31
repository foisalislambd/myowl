package demo

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/myowl/myowl/agent/internal/collect"
	"github.com/myowl/myowl/agent/internal/model"
)

const (
	gib = 1 << 30
	mib = 1 << 20
)

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }

func (d *Demo) system() *model.SystemSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.r2
	now := time.Now()
	hr := float64(now.UTC().Hour())
	diurnal := 0.55 + 0.45*math.Sin((hr-9)/24*2*math.Pi)
	target := 14 + 30*diurnal
	if now.Before(d.burst.Add(90 * time.Second)) {
		target = 88
	}
	d.cpu = clamp(d.cpu+(target-d.cpu)*0.2+r.NormFloat64()*3, 2, 99)
	d.mem = clamp(d.mem+(58+8*diurnal-d.mem)*0.05+r.NormFloat64()*0.3, 40, 95)
	cores := make([]float64, 4)
	for i := range cores {
		cores[i] = math.Round(clamp(d.cpu+r.NormFloat64()*9, 0, 100)*10) / 10
	}
	total := uint64(8 * gib)
	used := uint64(float64(total) * d.mem / 100)
	boot := now.Add(-(23*24*time.Hour + 7*time.Hour + 41*time.Minute))
	procs := []model.Process{
		{PID: 1834, Name: "node", User: "app", Cmd: "node /srv/brewhouse/server.js", CPU: d.cpu * 0.9, MemRSS: 612 * mib, State: "S", Threads: 11},
		{PID: 1203, Name: "postgres", User: "postgres", Cmd: "postgres: 16/main: app brewhouse 127.0.0.1(51122) idle", CPU: d.cpu * 0.35, MemRSS: 284 * mib, State: "S", Threads: 1},
		{PID: 1167, Name: "php-fpm8.3", User: "www-data", Cmd: "php-fpm: pool www", CPU: d.cpu * 0.25, MemRSS: 96 * mib, State: "S", Threads: 1},
		{PID: 1012, Name: "nginx", User: "www-data", Cmd: "nginx: worker process", CPU: d.cpu * 0.18, MemRSS: 24 * mib, State: "S", Threads: 1},
		{PID: 1013, Name: "nginx", User: "www-data", Cmd: "nginx: worker process", CPU: d.cpu * 0.14, MemRSS: 23 * mib, State: "S", Threads: 1},
		{PID: 1098, Name: "redis-server", User: "redis", Cmd: "/usr/bin/redis-server 0.0.0.0:6379", CPU: d.cpu * 0.06, MemRSS: 42 * mib, State: "S", Threads: 5},
		{PID: 902, Name: "dockerd", User: "root", Cmd: "/usr/bin/dockerd -H fd://", CPU: 0.6, MemRSS: 88 * mib, State: "S", Threads: 14},
		{PID: 2311, Name: "myowl", User: "root", Cmd: "/usr/local/bin/myowl --config /etc/myowl/config.yaml", CPU: 0.9, MemRSS: 38 * mib, State: "S", Threads: 9},
		{PID: 1450, Name: "containerd", User: "root", Cmd: "/usr/bin/containerd", CPU: 0.3, MemRSS: 51 * mib, State: "S", Threads: 12},
		{PID: 811, Name: "sshd", User: "root", Cmd: "sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups", CPU: 0.1, MemRSS: 9 * mib, State: "S", Threads: 1},
		{PID: 4120, Name: "sshd", User: "deploy", Cmd: "sshd: deploy@pts/0", CPU: 0.0, MemRSS: 7 * mib, State: "S", Threads: 1},
		{PID: 4188, Name: "bash", User: "deploy", Cmd: "-bash", CPU: 0.0, MemRSS: 5 * mib, State: "S", Threads: 1},
		{PID: 744, Name: "systemd-journal", User: "root", Cmd: "/usr/lib/systemd/systemd-journald", CPU: 0.2, MemRSS: 31 * mib, State: "S", Threads: 1},
		{PID: 1, Name: "systemd", User: "root", Cmd: "/sbin/init", CPU: 0.0, MemRSS: 13 * mib, State: "S", Threads: 1},
		{PID: 690, Name: "fail2ban-server", User: "root", Cmd: "/usr/bin/python3 /usr/bin/fail2ban-server -xf start", CPU: 0.1, MemRSS: 36 * mib, State: "S", Threads: 4},
		{PID: 655, Name: "cron", User: "root", Cmd: "/usr/sbin/cron -f -P", CPU: 0, MemRSS: 3 * mib, State: "S", Threads: 1},
	}
	for i := range procs {
		procs[i].CPU = math.Round(clamp(procs[i].CPU*(0.8+r.Float64()*0.4), 0, 400)*10) / 10
		procs[i].MemPercent = math.Round(float64(procs[i].MemRSS)/float64(total)*1000) / 10
		procs[i].Started = boot.Add(time.Duration(procs[i].PID) * time.Second).UnixMilli()
	}
	procs[10].Started = now.Add(-35 * time.Minute).UnixMilli()
	procs[11].Started = now.Add(-35 * time.Minute).UnixMilli()
	sort.Slice(procs, func(i, j int) bool { return procs[i].CPU > procs[j].CPU })
	svc := func(n, desc, active, sub string) model.Service {
		return model.Service{Name: n, Description: desc, Load: "loaded", Active: active, Sub: sub}
	}
	diskUsed := 61.5 + float64(now.Sub(d.start).Minutes())*0.0004
	return &model.SystemSnapshot{
		TS: now.UnixMilli(), Hostname: "brewhouse-prod-1", OS: "Ubuntu 24.04.1 LTS", Kernel: "6.8.0-48-generic", Arch: "x86_64",
		Uptime: int64(now.Sub(boot).Seconds()), BootTime: boot.UnixMilli(),
		CPU: model.CPU{Usage: math.Round(d.cpu*10) / 10, PerCore: cores, Cores: 4, Model: "AMD EPYC-Rome Processor", IOWait: math.Round(r.Float64()*15) / 10, Steal: math.Round(r.Float64()*8) / 10},
		Memory: model.Memory{Total: total, Used: used, Available: total - used, Cached: 1400 * mib, Buffers: 180 * mib, Percent: math.Round(d.mem*10) / 10,
			SwapTotal: 2 * gib, SwapUsed: 128 * mib, SwapPercent: 6.3},
		Load: [3]float64{math.Round(d.cpu/100*4.2*100) / 100, math.Round((14+30*diurnal)/100*4*100) / 100, math.Round((14+30*diurnal)/100*3.7*100) / 100},
		Disks: []model.Disk{
			{Mount: "/", Device: "/dev/sda1", FSType: "ext4", Total: 160 * gib, Used: uint64(160 * gib * diskUsed / 100), Free: uint64(160 * gib * (100 - diskUsed) / 100), Percent: math.Round(diskUsed*10) / 10, InodesPercent: 18.2},
			{Mount: "/boot/efi", Device: "/dev/sda15", FSType: "vfat", Total: 105 * mib, Used: 6 * mib, Free: 99 * mib, Percent: 5.8},
			{Mount: "/mnt/backups", Device: "/dev/sdb", FSType: "ext4", Total: 100 * gib, Used: 87 * gib, Free: 13 * gib, Percent: 87.0, InodesPercent: 2.1},
		},
		DiskIO:    model.DiskIO{ReadBps: math.Abs(r.NormFloat64()*200e3 + 150e3), WriteBps: math.Abs(r.NormFloat64()*500e3 + 700e3)},
		Processes: procs, ProcCount: 187,
		Services: []model.Service{
			svc("nginx.service", "A high performance web server and a reverse proxy server", "active", "running"),
			svc("postgresql@16-main.service", "PostgreSQL Cluster 16-main", "active", "running"),
			svc("redis-server.service", "Advanced key-value store", "active", "running"),
			svc("php8.3-fpm.service", "The PHP 8.3 FastCGI Process Manager", "active", "running"),
			svc("brewhouse.service", "Brewhouse Node.js shop", "active", "running"),
			svc("docker.service", "Docker Application Container Engine", "active", "running"),
			svc("containerd.service", "containerd container runtime", "active", "running"),
			svc("ssh.service", "OpenBSD Secure Shell server", "active", "running"),
			svc("fail2ban.service", "Fail2Ban Service", "active", "running"),
			svc("cron.service", "Regular background program processing daemon", "active", "running"),
			svc("myowl.service", "myOwl", "active", "running"),
			svc("systemd-journald.service", "Journal Service", "active", "running"),
			svc("systemd-resolved.service", "Network Name Resolution", "active", "running"),
			svc("systemd-timesyncd.service", "Network Time Synchronization", "active", "running"),
			svc("ufw.service", "Uncomplicated firewall", "active", "exited"),
			svc("unattended-upgrades.service", "Unattended Upgrades Shutdown", "active", "running"),
			svc("certbot.service", "Certbot", "failed", "failed"),
			svc("snapd.service", "Snap Daemon", "inactive", "dead"),
		},
		ServicesAvailable: true,
	}
}

func (d *Demo) network() *model.NetworkSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	r := d.r2
	now := time.Now()
	hr := float64(now.UTC().Hour())
	diurnal := 0.55 + 0.45*math.Sin((hr-9)/24*2*math.Pi)
	rxBps := (300e3 + 1.6e6*diurnal) * (0.75 + r.Float64()*0.5)
	if now.Before(d.burst.Add(60 * time.Second)) {
		rxBps *= 2.5
	}
	txBps := rxBps * (2.2 + r.Float64()*0.8)
	d.rx += uint64(rxBps * 2)
	d.tx += uint64(txBps * 2)
	ifs := []model.Interface{
		{Name: "eth0", RxBps: rxBps, TxBps: txBps, RxBytes: 812*gib + d.rx, TxBytes: 2310*gib + d.tx, RxPackets: 912345678, TxPackets: 1512345678, Up: true, Addrs: []string{serverIP + "/32", "2a01:4f8:c17:1a2b::1/64"}, MAC: "96:00:03:a1:5c:2e"},
		{Name: "docker0", RxBps: rxBps * 0.05, TxBps: rxBps * 0.07, RxBytes: 12 * gib, TxBytes: 19 * gib, Up: true, Addrs: []string{"172.17.0.1/16"}, MAC: "02:42:7c:11:9e:01"},
		{Name: "lo", RxBps: 90e3 + r.Float64()*40e3, TxBps: 90e3 + r.Float64()*40e3, RxBytes: 41 * gib, TxBytes: 41 * gib, Up: true, Addrs: []string{"127.0.0.1/8", "::1/128"}},
	}
	var conns []model.Conn
	nVisitors := 25 + int(diurnal*45) + r.Intn(10)
	seen := map[string]bool{}
	for i := 0; i < nVisitors; i++ {
		ip := d.visitor[int(math.Abs(r.NormFloat64()*110))%len(d.visitor)]
		if seen[ip] {
			continue
		}
		seen[ip] = true
		k := 1 + r.Intn(3)
		for j := 0; j < k; j++ {
			st := "ESTABLISHED"
			if r.Float64() < 0.18 {
				st = "TIME_WAIT"
			}
			c := model.Conn{Proto: "tcp", State: st, LocalIP: serverIP, LocalPort: 443, RemoteIP: ip, RemotePort: 30000 + r.Intn(35000),
				Direction: "in", RTTms: math.Round((20+r.Float64()*180)*10) / 10}
			if st == "ESTABLISHED" {
				c.PID, c.Process, c.User = 1012+r.Intn(2), "nginx", "www-data"
				c.BytesSent = uint64(20e3 + r.Float64()*900e3)
				c.BytesRecv = uint64(2e3 + r.Float64()*40e3)
			}
			if r.Float64() < 0.08 {
				c.LocalPort = 80
			}
			conns = append(conns, c)
		}
	}
	// admin ssh session
	conns = append(conns, model.Conn{Proto: "tcp", State: "ESTABLISHED", LocalIP: serverIP, LocalPort: 22, RemoteIP: adminIP, RemotePort: 52814,
		PID: 4120, Process: "sshd", User: "root", BytesSent: 1843200, BytesRecv: 96512, RTTms: 162.4, Direction: "in"})
	// outbound
	out := []struct {
		ip   string
		port int
		proc string
	}{{"54.187.216.72", 443, "node"}, {"151.101.66.132", 443, "node"}, {"142.250.185.74", 443, "node"}, {"140.82.121.4", 443, "dockerd"}, {"91.189.91.83", 80, "unattended-upgr"}}
	for i, o := range out {
		if i >= 3 && r.Float64() < 0.5 {
			continue
		}
		conns = append(conns, model.Conn{Proto: "tcp", State: "ESTABLISHED", LocalIP: serverIP, LocalPort: 40000 + r.Intn(20000), RemoteIP: o.ip, RemotePort: o.port,
			PID: 1834, Process: o.proc, User: "app", BytesSent: uint64(r.Intn(90000)), BytesRecv: uint64(r.Intn(400000)), RTTms: math.Round(r.Float64()*1400) / 10, Direction: "out"})
	}
	// local db / cache connections
	for i := 0; i < 8; i++ {
		port, proc, pid, user := 5432, "node", 1834, "app"
		if i >= 6 {
			port = 6379
		}
		conns = append(conns, model.Conn{Proto: "tcp", State: "ESTABLISHED", LocalIP: "127.0.0.1", LocalPort: 51100 + i, RemoteIP: "127.0.0.1", RemotePort: port,
			PID: pid, Process: proc, User: user, BytesSent: uint64(r.Intn(5e6)), BytesRecv: uint64(r.Intn(9e6)), RTTms: 0.1, Direction: "local"})
	}
	// attackers currently active
	nowMs := now.UnixMilli()
	for ip, until := range d.active {
		if until < nowMs {
			delete(d.active, ip)
			continue
		}
		port, st, proc := 443, "ESTABLISHED", "nginx"
		for _, a := range attackers {
			if a.IP == ip && a.Kind == "ssh" {
				port, proc = 22, "sshd"
			}
		}
		if r.Float64() < 0.4 {
			st = "SYN_RECV"
			proc = ""
		}
		conns = append(conns, model.Conn{Proto: "tcp", State: st, LocalIP: serverIP, LocalPort: port, RemoteIP: ip, RemotePort: 30000 + r.Intn(30000),
			Process: proc, BytesSent: uint64(r.Intn(20000)), BytesRecv: uint64(r.Intn(8000)), RTTms: math.Round((40+r.Float64()*200)*10) / 10, Direction: "in"})
	}
	conns = append(conns, model.Conn{Proto: "udp", State: "UNCONN", LocalIP: serverIP, LocalPort: 123, RemoteIP: "", Process: "systemd-timesyncd", Direction: "local"})

	lst := []model.Listener{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, PID: 811, Process: "sshd", User: "root"},
		{Proto: "tcp6", Addr: "::", Port: 22, PID: 811, Process: "sshd", User: "root"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 80, PID: 1011, Process: "nginx", User: "root"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 443, PID: 1011, Process: "nginx", User: "root"},
		{Proto: "tcp6", Addr: "::", Port: 443, PID: 1011, Process: "nginx", User: "root"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 5432, PID: 1203, Process: "postgres", User: "postgres"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 6379, PID: 1098, Process: "redis-server", User: "redis"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 3000, PID: 1834, Process: "node", User: "app"},
		{Proto: "tcp", Addr: "127.0.0.1", Port: 9000, PID: 1167, Process: "php-fpm8.3", User: "root"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 8787, PID: 2311, Process: "myowl", User: "root"},
		{Proto: "udp", Addr: "127.0.0.53", Port: 53, PID: 702, Process: "systemd-resolved", User: "systemd-resolve"},
		{Proto: "udp", Addr: "0.0.0.0", Port: 68, PID: 699, Process: "systemd-networkd", User: "systemd-network"},
	}
	for i := range lst {
		l := &lst[i]
		l.Public = !strings.HasPrefix(l.Addr, "127.") && l.Addr != "::1"
		l.Service = collect.WellKnownPorts[l.Port]
		if l.Service == "" {
			l.Service = map[int]string{3000: "Node.js app", 9000: "PHP-FPM", 8787: "myOwl dashboard", 68: "DHCP client"}[l.Port]
		}
		if l.Public {
			l.Risk = collect.RiskyPublicPorts[l.Port]
		}
		for _, c := range conns {
			if c.LocalPort == l.Port && c.Direction == "in" && strings.HasPrefix(l.Proto, c.Proto) {
				l.Conns++
			}
		}
		if l.Proto == "tcp6" {
			l.Conns = 0
		}
	}
	// talkers
	tm := map[string]*model.Talker{}
	states := map[string]int{}
	for _, c := range conns {
		states[c.State]++
		if c.RemoteIP == "" || c.Direction == "local" {
			continue
		}
		t := tm[c.RemoteIP]
		if t == nil {
			t = &model.Talker{IP: c.RemoteIP, Direction: c.Direction}
			tm[c.RemoteIP] = t
		}
		t.Conns++
		t.BytesIn += c.BytesRecv
		t.BytesOut += c.BytesSent
		if c.Process != "" && !contains(t.Processes, c.Process) {
			t.Processes = append(t.Processes, c.Process)
		}
		port := c.LocalPort
		if c.Direction == "out" {
			port = c.RemotePort
		}
		if !containsInt(t.Ports, port) {
			t.Ports = append(t.Ports, port)
		}
	}
	var talkers []model.Talker
	var sumW float64
	for _, t := range tm {
		sumW += float64(t.BytesIn+t.BytesOut) + 1
	}
	for _, t := range tm {
		w := (float64(t.BytesIn+t.BytesOut) + 1) / sumW
		t.RateIn = math.Round(rxBps * w * (0.6 + r.Float64()*0.8))
		t.RateOut = math.Round(txBps * w * (0.6 + r.Float64()*0.8))
		talkers = append(talkers, *t)
	}
	sort.Slice(talkers, func(i, j int) bool {
		return talkers[i].RateIn+talkers[i].RateOut > talkers[j].RateIn+talkers[j].RateOut
	})
	return &model.NetworkSnapshot{TS: nowMs, Interfaces: ifs, TotalRxBps: rxBps, TotalTxBps: txBps, Connections: conns, Listeners: lst,
		Talkers: talkers, ConnCount: len(conns), StateCounts: states, Source: "demo", Capture: "demo"}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func (d *Demo) sessions() *model.SessionsSnapshot {
	now := time.Now()
	ms := func(dur time.Duration) int64 { return now.Add(-dur).UnixMilli() }
	cur := []model.LoginSession{
		{User: "deploy", TTY: "pts/0", Host: adminIP, LoginTime: ms(35 * time.Minute), PID: 4120},
		{User: "admin", TTY: "pts/1", Host: adminIP, LoginTime: ms(5*time.Hour + 2*time.Minute), PID: 3877},
	}
	var hist []model.LoginRecord
	hist = append(hist, model.LoginRecord{User: "deploy", TTY: "pts/0", Host: adminIP, Login: ms(35 * time.Minute), Logout: 0, Kind: "user"})
	hist = append(hist, model.LoginRecord{User: "admin", TTY: "pts/1", Host: adminIP, Login: ms(5*time.Hour + 2*time.Minute), Logout: 0, Kind: "user"})
	hosts := []string{adminIP, adminIP, adminIP, "37.111.205.18", "103.108.140.25"}
	users := []string{"deploy", "deploy", "admin", "deploy", "root"}
	t := now.Add(-11 * time.Hour)
	for i := 0; i < 26; i++ {
		dur := time.Duration(5+((i*37)%110)) * time.Minute
		hist = append(hist, model.LoginRecord{User: users[i%len(users)], TTY: fmt.Sprintf("pts/%d", i%3), Host: hosts[i%len(hosts)],
			Login: t.UnixMilli(), Logout: t.Add(dur).UnixMilli(), Kind: "user"})
		t = t.Add(-time.Duration(6+(i*13)%22) * time.Hour)
		if i == 12 {
			hist = append(hist, model.LoginRecord{User: "reboot", TTY: "system boot", Host: "6.8.0-48-generic", Login: now.Add(-(23*24*time.Hour + 7*time.Hour + 41*time.Minute)).UnixMilli(), Logout: 0, Kind: "reboot"})
		}
	}
	sort.SliceStable(hist, func(i, j int) bool { return hist[i].Login > hist[j].Login })
	return &model.SessionsSnapshot{TS: now.UnixMilli(), Current: cur, History: hist, Source: "demo"}
}
