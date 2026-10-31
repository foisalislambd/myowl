// Package collect reads live system and network state from /proc, netlink
// and other kernel interfaces.
package collect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/myowl/myowl/agent/internal/model"
)

// ProcRoot allows tests to point at a fake /proc.
var ProcRoot = "/proc"

const clkTck = 100.0

type cpuTimes struct{ user, nice, system, idle, iowait, irq, softirq, steal uint64 }

func (c cpuTimes) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

// SystemCollector produces SystemSnapshots.
type SystemCollector struct {
	mu        sync.Mutex
	prevCPU   []cpuTimes
	prevDisk  [2]uint64
	prevDiskT time.Time
	prevProc  map[int]uint64
	prevProcT time.Time
	users     map[int]string
	usersAt   time.Time
	services  []model.Service
	svcOK     bool
	svcMsg    string
	svcAt     time.Time
	static    struct{ hostname, os, kernel, model string }
}

// NewSystemCollector creates a collector.
func NewSystemCollector() *SystemCollector {
	c := &SystemCollector{prevProc: map[int]uint64{}}
	c.static.hostname, _ = os.Hostname()
	c.static.os = osName()
	c.static.kernel = strings.TrimSpace(readFile(filepath.Join(ProcRoot, "sys/kernel/osrelease")))
	c.static.model = cpuModel()
	return c
}

func readFile(p string) string {
	b, _ := os.ReadFile(p)
	return string(b)
}

func osName() string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		for _, l := range strings.Split(readFile(p), "\n") {
			if strings.HasPrefix(l, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
			}
		}
	}
	return runtime.GOOS
}

func cpuModel() string {
	for _, l := range strings.Split(readFile(filepath.Join(ProcRoot, "cpuinfo")), "\n") {
		if strings.HasPrefix(l, "model name") {
			if i := strings.IndexByte(l, ':'); i > 0 {
				return strings.TrimSpace(l[i+1:])
			}
		}
	}
	return ""
}

// Collect gathers a full snapshot.
func (c *SystemCollector) Collect() *model.SystemSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := &model.SystemSnapshot{TS: time.Now().UnixMilli(), Hostname: c.static.hostname, OS: c.static.os, Kernel: c.static.kernel, Arch: runtime.GOARCH}
	c.cpu(s)
	s.Memory = ReadMemory()
	s.Load = readLoad()
	if up, err := strconv.ParseFloat(strings.Fields(readFile(filepath.Join(ProcRoot, "uptime")) + " 0")[0], 64); err == nil {
		s.Uptime = int64(up)
		s.BootTime = time.Now().UnixMilli() - int64(up*1000)
	}
	s.Disks = readDisks()
	s.DiskIO = c.diskIO()
	s.Processes, s.ProcCount = c.processes(s.Memory.Total)
	if time.Since(c.svcAt) > 15*time.Second {
		c.services, c.svcOK, c.svcMsg = readServices()
		c.svcAt = time.Now()
	}
	s.Services, s.ServicesAvailable, s.ServicesMessage = c.services, c.svcOK, c.svcMsg
	return s
}

func parseCPULine(f []string) cpuTimes {
	v := make([]uint64, 8)
	for i := 0; i < 8 && i+1 < len(f); i++ {
		v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
	}
	return cpuTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]}
}

func (c *SystemCollector) cpu(s *model.SystemSnapshot) {
	var cur []cpuTimes
	for _, l := range strings.Split(readFile(filepath.Join(ProcRoot, "stat")), "\n") {
		if strings.HasPrefix(l, "cpu") {
			cur = append(cur, parseCPULine(strings.Fields(l)))
		}
	}
	if len(cur) == 0 {
		return
	}
	s.CPU.Cores = len(cur) - 1
	s.CPU.Model = c.static.model
	if len(c.prevCPU) == len(cur) {
		pct := func(a, b cpuTimes) (usage, iow, steal float64) {
			dt := float64(b.total() - a.total())
			if dt <= 0 {
				return 0, 0, 0
			}
			idle := float64((b.idle + b.iowait) - (a.idle + a.iowait))
			return clamp((dt - idle) / dt * 100), float64(b.iowait-a.iowait) / dt * 100, float64(b.steal-a.steal) / dt * 100
		}
		s.CPU.Usage, s.CPU.IOWait, s.CPU.Steal = pct(c.prevCPU[0], cur[0])
		for i := 1; i < len(cur); i++ {
			u, _, _ := pct(c.prevCPU[i], cur[i])
			s.CPU.PerCore = append(s.CPU.PerCore, round1(u))
		}
		s.CPU.Usage = round1(s.CPU.Usage)
		s.CPU.IOWait = round1(s.CPU.IOWait)
		s.CPU.Steal = round1(s.CPU.Steal)
	} else {
		s.CPU.PerCore = make([]float64, s.CPU.Cores)
	}
	c.prevCPU = cur
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// ReadMemory parses /proc/meminfo.
func ReadMemory() model.Memory {
	m := map[string]uint64{}
	for _, l := range strings.Split(readFile(filepath.Join(ProcRoot, "meminfo")), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			m[strings.TrimSuffix(f[0], ":")] = v * 1024
		}
	}
	mem := model.Memory{Total: m["MemTotal"], Available: m["MemAvailable"], Cached: m["Cached"] + m["SReclaimable"], Buffers: m["Buffers"],
		SwapTotal: m["SwapTotal"]}
	if mem.Available == 0 {
		mem.Available = m["MemFree"] + mem.Cached + mem.Buffers
	}
	if mem.Total > mem.Available {
		mem.Used = mem.Total - mem.Available
	}
	if mem.Total > 0 {
		mem.Percent = round1(float64(mem.Used) / float64(mem.Total) * 100)
	}
	if mem.SwapTotal > m["SwapFree"] {
		mem.SwapUsed = mem.SwapTotal - m["SwapFree"]
	}
	if mem.SwapTotal > 0 {
		mem.SwapPercent = round1(float64(mem.SwapUsed) / float64(mem.SwapTotal) * 100)
	}
	return mem
}

func readLoad() [3]float64 {
	f := strings.Fields(readFile(filepath.Join(ProcRoot, "loadavg")))
	var l [3]float64
	for i := 0; i < 3 && i < len(f); i++ {
		l[i], _ = strconv.ParseFloat(f[i], 64)
	}
	return l
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"vfat": true, "ntfs": true, "ntfs3": true, "jfs": true, "reiserfs": true, "bcachefs": true, "fuseblk": true}

func readDisks() []model.Disk {
	var out []model.Disk
	seen := map[string]bool{}
	for _, l := range strings.Split(readFile(filepath.Join(ProcRoot, "self/mounts")), "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || !realFS[f[2]] {
			continue
		}
		dev, mnt := f[0], unescapeMount(f[1])
		if seen[dev] || strings.HasPrefix(mnt, "/snap/") || strings.HasPrefix(mnt, "/var/lib/docker/") || strings.HasPrefix(mnt, "/run/") {
			continue
		}
		var st unix.Statfs_t
		if unix.Statfs(mnt, &st) != nil || st.Blocks == 0 {
			continue
		}
		seen[dev] = true
		bs := uint64(st.Bsize)
		d := model.Disk{Mount: mnt, Device: dev, FSType: f[2], Total: st.Blocks * bs, Free: st.Bavail * bs}
		used := (st.Blocks - st.Bfree) * bs
		d.Used = used
		if used+d.Free > 0 {
			d.Percent = round1(float64(used) / float64(used+d.Free) * 100)
		}
		if st.Files > 0 {
			d.InodesPercent = round1(float64(st.Files-st.Ffree) / float64(st.Files) * 100)
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Mount < out[j].Mount })
	return out
}

func unescapeMount(s string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(s)
}

var wholeDiskRe = regexp.MustCompile(`^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+)$`)

func (c *SystemCollector) diskIO() model.DiskIO {
	var rd, wr uint64
	for _, l := range strings.Split(readFile(filepath.Join(ProcRoot, "diskstats")), "\n") {
		f := strings.Fields(l)
		if len(f) < 14 || !wholeDiskRe.MatchString(f[2]) {
			continue
		}
		r, _ := strconv.ParseUint(f[5], 10, 64)
		w, _ := strconv.ParseUint(f[9], 10, 64)
		rd += r * 512
		wr += w * 512
	}
	now := time.Now()
	var io model.DiskIO
	if !c.prevDiskT.IsZero() {
		dt := now.Sub(c.prevDiskT).Seconds()
		if dt > 0 && rd >= c.prevDisk[0] && wr >= c.prevDisk[1] {
			io.ReadBps = float64(rd-c.prevDisk[0]) / dt
			io.WriteBps = float64(wr-c.prevDisk[1]) / dt
		}
	}
	c.prevDisk = [2]uint64{rd, wr}
	c.prevDiskT = now
	return io
}

// Users returns uid->name from /etc/passwd (cached).
func (c *SystemCollector) Users() map[int]string {
	if c.users != nil && time.Since(c.usersAt) < time.Minute {
		return c.users
	}
	c.users = ReadUsers()
	c.usersAt = time.Now()
	return c.users
}

// ReadUsers parses /etc/passwd.
func ReadUsers() map[int]string {
	out := map[int]string{}
	for _, l := range strings.Split(readFile("/etc/passwd"), "\n") {
		f := strings.Split(l, ":")
		if len(f) > 3 {
			if uid, err := strconv.Atoi(f[2]); err == nil {
				out[uid] = f[0]
			}
		}
	}
	return out
}

type procStat struct {
	pid     int
	name    string
	state   string
	ticks   uint64
	threads int
	start   uint64
	rss     uint64
}

func readProcStat(pid int) (procStat, bool) {
	b, err := os.ReadFile(filepath.Join(ProcRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return procStat{}, false
	}
	return parseProcStat(pid, b)
}

func parseProcStat(pid int, b []byte) (procStat, bool) {
	lp := bytes.IndexByte(b, '(')
	rp := bytes.LastIndexByte(b, ')')
	if lp < 0 || rp < lp {
		return procStat{}, false
	}
	p := procStat{pid: pid, name: string(b[lp+1 : rp])}
	f := strings.Fields(string(b[rp+1:]))
	// f[0]=state (field 3) ; utime=field14 -> f[11]; stime f[12]; threads field20 -> f[17]; starttime f[19]; rss f[21]
	if len(f) < 22 {
		return p, false
	}
	p.state = f[0]
	ut, _ := strconv.ParseUint(f[11], 10, 64)
	st, _ := strconv.ParseUint(f[12], 10, 64)
	p.ticks = ut + st
	p.threads, _ = strconv.Atoi(f[17])
	p.start, _ = strconv.ParseUint(f[19], 10, 64)
	rss, _ := strconv.ParseUint(f[21], 10, 64)
	p.rss = rss * uint64(os.Getpagesize())
	return p, true
}

// ListPIDs lists numeric /proc entries.
func ListPIDs() []int {
	ents, err := os.ReadDir(ProcRoot)
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(ents))
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

func procUID(pid int) int {
	f, err := os.Open(filepath.Join(ProcRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return -1
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "Uid:") {
			ff := strings.Fields(l)
			if len(ff) > 1 {
				uid, _ := strconv.Atoi(ff[1])
				return uid
			}
		}
	}
	return -1
}

// ProcCmdline returns the command line for pid.
func ProcCmdline(pid int) string {
	b, _ := os.ReadFile(filepath.Join(ProcRoot, strconv.Itoa(pid), "cmdline"))
	s := strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

func (c *SystemCollector) processes(memTotal uint64) ([]model.Process, int) {
	pids := ListPIDs()
	now := time.Now()
	dt := now.Sub(c.prevProcT).Seconds()
	cur := make(map[int]uint64, len(pids))
	var all []model.Process
	bootSec := float64(time.Now().Unix())
	if up, err := strconv.ParseFloat(strings.Fields(readFile(filepath.Join(ProcRoot, "uptime")) + " 0")[0], 64); err == nil {
		bootSec -= up
	}
	for _, pid := range pids {
		ps, ok := readProcStat(pid)
		if !ok {
			continue
		}
		cur[pid] = ps.ticks
		p := model.Process{PID: pid, Name: ps.name, State: ps.state, Threads: ps.threads, MemRSS: ps.rss,
			Started: int64((bootSec + float64(ps.start)/clkTck) * 1000)}
		if prev, ok := c.prevProc[pid]; ok && dt > 0 && ps.ticks >= prev {
			p.CPU = round1(float64(ps.ticks-prev) / clkTck / dt * 100)
		}
		if memTotal > 0 {
			p.MemPercent = round1(float64(ps.rss) / float64(memTotal) * 100)
		}
		all = append(all, p)
	}
	c.prevProc = cur
	c.prevProcT = now
	sort.Slice(all, func(i, j int) bool {
		if all[i].CPU == all[j].CPU {
			return all[i].MemRSS > all[j].MemRSS
		}
		return all[i].CPU > all[j].CPU
	})
	// top by CPU plus top by memory
	top := map[int]bool{}
	var out []model.Process
	for i := 0; i < len(all) && len(out) < 15; i++ {
		top[all[i].PID] = true
		out = append(out, all[i])
	}
	byMem := append([]model.Process(nil), all...)
	sort.Slice(byMem, func(i, j int) bool { return byMem[i].MemRSS > byMem[j].MemRSS })
	for i := 0; i < len(byMem) && i < 15; i++ {
		if !top[byMem[i].PID] {
			out = append(out, byMem[i])
		}
	}
	users := c.Users()
	for i := range out {
		uid := procUID(out[i].PID)
		if n, ok := users[uid]; ok {
			out[i].User = n
		} else if uid >= 0 {
			out[i].User = strconv.Itoa(uid)
		}
		out[i].Cmd = ProcCmdline(out[i].PID)
		if out[i].Cmd == "" {
			out[i].Cmd = "[" + out[i].Name + "]"
		}
	}
	return out, len(all)
}

func readServices() ([]model.Service, bool, string) {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil, false, "systemd is not available on this system"
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil, false, "systemd is not running (container or non-systemd init)"
	}
	out, err := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--output=json").Output()
	var svcs []model.Service
	if err == nil && len(out) > 0 && out[0] == '[' {
		var raw []struct{ Unit, Load, Active, Sub, Description string }
		if json.Unmarshal(out, &raw) == nil {
			for _, r := range raw {
				svcs = append(svcs, model.Service{Name: strings.TrimSuffix(r.Unit, ".service"), Load: r.Load, Active: r.Active, Sub: r.Sub, Description: r.Description})
			}
		}
	}
	if svcs == nil {
		out, err = exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend").Output()
		if err != nil {
			return nil, false, "could not query systemd: " + err.Error()
		}
		for _, l := range strings.Split(string(out), "\n") {
			f := strings.Fields(l)
			if len(f) < 4 {
				continue
			}
			svcs = append(svcs, model.Service{Name: strings.TrimSuffix(strings.TrimPrefix(f[0], "●"), ".service"), Load: f[1], Active: f[2], Sub: f[3],
				Description: strings.Join(f[4:], " ")})
		}
	}
	var filtered []model.Service
	for _, s := range svcs {
		if s.Load == "not-found" || s.Load == "masked" {
			continue
		}
		filtered = append(filtered, s)
	}
	rank := func(s model.Service) int {
		switch s.Active {
		case "failed":
			return 0
		case "active", "activating", "reloading":
			return 1
		}
		return 2
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		if rank(filtered[i]) != rank(filtered[j]) {
			return rank(filtered[i]) < rank(filtered[j])
		}
		return filtered[i].Name < filtered[j].Name
	})
	return filtered, true, ""
}
