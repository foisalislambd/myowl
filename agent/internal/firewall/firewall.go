// Package firewall blocks and unblocks IPs using ufw, nftables or iptables.
package firewall

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Firewall manages IP blocks.
type Firewall struct {
	mu           sync.Mutex
	enabled      bool
	backend      string
	demo         bool
	whitelist    []*net.IPNet
	allowPrivate bool
	reason       string
}

// Options configure the firewall.
type Options struct {
	Enabled      bool
	Backend      string
	Whitelist    []string
	AllowPrivate bool
	Demo         bool
}

// New detects the backend.
func New(o Options) *Firewall {
	f := &Firewall{enabled: o.Enabled, demo: o.Demo, allowPrivate: o.AllowPrivate}
	for _, s := range o.Whitelist {
		if !strings.Contains(s, "/") {
			if strings.Contains(s, ":") {
				s += "/128"
			} else {
				s += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(s); err == nil {
			f.whitelist = append(f.whitelist, n)
		}
	}
	switch {
	case o.Demo:
		f.backend = "demo"
	case !o.Enabled:
		f.reason = "disabled in config (firewall.enabled: false)"
	default:
		f.backend = detect(o.Backend)
		if f.backend == "" {
			f.reason = "no supported firewall tool found (install ufw, nftables or iptables)"
		} else if os.Geteuid() != 0 {
			f.reason = "the agent is not running as root, so it cannot change firewall rules"
		}
	}
	return f
}

func has(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

func detect(pref string) string {
	switch pref {
	case "ufw", "nftables", "iptables":
		return pref
	}
	if has("ufw") {
		if out, err := exec.Command("ufw", "status").Output(); err == nil && strings.Contains(string(out), "Status: active") {
			return "ufw"
		}
	}
	if has("nft") {
		return "nftables"
	}
	if has("iptables") {
		return "iptables"
	}
	if has("ufw") {
		return "ufw"
	}
	return ""
}

// Status describes the firewall integration.
type Status struct {
	Backend   string `json:"backend"`
	CanBlock  bool   `json:"can_block"`
	Message   string `json:"message"`
	Whitelist int    `json:"whitelist"`
}

// Status returns the current status.
func (f *Firewall) Status() Status {
	s := Status{Backend: f.backend, CanBlock: f.CanBlock(), Whitelist: len(f.whitelist)}
	if s.CanBlock {
		if f.demo {
			s.Message = "Demo mode: blocks are simulated"
		} else {
			s.Message = "Blocking with " + f.backend
		}
	} else {
		s.Message = f.reason
	}
	return s
}

// CanBlock reports whether blocking is possible.
func (f *Firewall) CanBlock() bool {
	if f.demo {
		return true
	}
	return f.enabled && f.backend != "" && os.Geteuid() == 0
}

// Validate checks that ip may be blocked; requester is the dashboard user's IP.
func (f *Firewall) Validate(ipStr, requester string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", errors.New("not a valid IP address")
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	canon := ip.String()
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return "", errors.New("refusing to block a loopback/unspecified/multicast address")
	}
	if !f.allowPrivate && (ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return "", errors.New("refusing to block a private network address (set firewall.allow_private to override)")
	}
	if requester != "" {
		if r := net.ParseIP(requester); r != nil && r.Equal(ip) {
			return "", errors.New("refusing to block your own IP address — you would lock yourself out")
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return "", errors.New("refusing to block one of this server's own addresses")
			}
		}
	}
	for _, n := range f.whitelist {
		if n.Contains(ip) {
			return "", errors.New("this IP is in the firewall whitelist")
		}
	}
	return canon, nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (f *Firewall) nftSetup() error {
	if exec.Command("nft", "list", "table", "inet", "myowl").Run() == nil {
		return nil
	}
	script := `table inet myowl {
  set block4 { type ipv4_addr; }
  set block6 { type ipv6_addr; }
  chain input { type filter hook input priority -10; policy accept; ip saddr @block4 drop; ip6 saddr @block6 drop; }
}
`
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft setup: %v: %s", err, out)
	}
	return nil
}

// Block adds a drop rule for ip (already validated/canonical).
func (f *Firewall) Block(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.CanBlock() {
		return errors.New(f.reason)
	}
	if f.demo {
		return nil
	}
	v6 := strings.Contains(ip, ":")
	switch f.backend {
	case "ufw":
		return run("ufw", "prepend", "deny", "from", ip, "to", "any", "comment", "myowl")
	case "nftables":
		if err := f.nftSetup(); err != nil {
			return err
		}
		set := "block4"
		if v6 {
			set = "block6"
		}
		return run("nft", "add", "element", "inet", "myowl", set, "{ "+ip+" }")
	case "iptables":
		bin := "iptables"
		if v6 {
			bin = "ip6tables"
		}
		if exec.Command(bin, "-C", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "myowl").Run() == nil {
			return nil
		}
		return run(bin, "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "myowl")
	}
	return errors.New("no firewall backend")
}

// Unblock removes the drop rule for ip.
func (f *Firewall) Unblock(ip string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.CanBlock() {
		return errors.New(f.reason)
	}
	if f.demo {
		return nil
	}
	v6 := strings.Contains(ip, ":")
	switch f.backend {
	case "ufw":
		return run("ufw", "delete", "deny", "from", ip, "to", "any")
	case "nftables":
		set := "block4"
		if v6 {
			set = "block6"
		}
		return run("nft", "delete", "element", "inet", "myowl", set, "{ "+ip+" }")
	case "iptables":
		bin := "iptables"
		if v6 {
			bin = "ip6tables"
		}
		return run(bin, "-D", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "myowl")
	}
	return errors.New("no firewall backend")
}

// Reapply restores non-persistent blocks (nftables/iptables) after restart.
func (f *Firewall) Reapply(ips []string) {
	if f.demo || !f.CanBlock() || f.backend == "ufw" {
		return
	}
	for _, ip := range ips {
		_ = f.Block(ip)
	}
}
