// Command myowl is an all-in-one VPS monitoring dashboard.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/myowl/myowl/agent/internal/config"
	"github.com/myowl/myowl/agent/internal/demo"
	"github.com/myowl/myowl/agent/internal/engine"
	"github.com/myowl/myowl/agent/internal/server"
	"github.com/myowl/myowl/agent/internal/store"
)

//go:embed config.example.yaml
var exampleConfig string

var version = "dev"

const defaultConfig = "/etc/myowl/config.yaml"

func usage() {
	fmt.Fprintf(os.Stderr, `myowl %s — all-in-one VPS monitoring dashboard

Usage:
  myowl [flags]                 run the agent + dashboard
  myowl passwd [flags]          set or reset the dashboard password
  myowl setup-token [flags]     print the first-run setup code
  myowl gen-config              print an example config file
  myowl healthcheck [flags]     exit 0 if the local dashboard answers (Docker HEALTHCHECK)
  myowl version

Environment (used when the matching flag is not given):
  MYOWL_CONFIG, MYOWL_LISTEN, MYOWL_DATA_DIR

Flags:
`, version)
	flag.PrintDefaults()
}

func main() {
	server.Version = version
	log.SetFlags(log.LstdFlags)
	cmd := ""
	args := os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	fs := flag.NewFlagSet("myowl", flag.ExitOnError)
	flag.CommandLine = fs
	fs.Usage = usage
	cfgPath := fs.String("config", envOr("MYOWL_CONFIG", defaultConfig), "path to config.yaml (env MYOWL_CONFIG)")
	demoMode := fs.Bool("demo", false, "run with realistic fake data (no root needed, password: demo)")
	listen := fs.String("listen", os.Getenv("MYOWL_LISTEN"), "override listen address, e.g. 127.0.0.1:8787 (env MYOWL_LISTEN)")
	dataDir := fs.String("data-dir", os.Getenv("MYOWL_DATA_DIR"), "override data directory (env MYOWL_DATA_DIR)")
	_ = fs.Parse(args)

	switch cmd {
	case "version":
		fmt.Println("myowl", version)
		return
	case "gen-config":
		fmt.Print(exampleConfig)
		return
	case "", "run", "passwd", "setup-token", "healthcheck":
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	cfg, missing, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	cfg.Demo = *demoMode
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if cfg.Demo {
		if *dataDir == "" {
			d, err := os.MkdirTemp("", "myowl-demo-")
			if err != nil {
				log.Fatal(err)
			}
			cfg.DataDir = d
			defer os.RemoveAll(d)
		}
		if *listen == "" && missing {
			cfg.Listen = "127.0.0.1:8787"
		}
		cfg.Capture.Enabled = false
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if cmd == "healthcheck" {
		os.Exit(healthcheck(cfg.Listen, cfg.TLSEnabled()))
	}
	if missing && !cfg.Demo && cmd == "" {
		log.Printf("config %s not found — using defaults (run `myowl gen-config` for an example)", *cfgPath)
	}
	// Keep the GeoIP database next to the data when the data dir was moved
	// (e.g. --data-dir) but the GeoIP path was left at its default.
	if def := config.Default(); cfg.GeoIP.Path == def.GeoIP.Path && cfg.DataDir != def.DataDir {
		cfg.GeoIP.Path = filepath.Join(cfg.DataDir, filepath.Base(def.GeoIP.Path))
	}
	if !filepath.IsAbs(cfg.GeoIP.Path) && cfg.GeoIP.Path != "" {
		cfg.GeoIP.Path = filepath.Join(cfg.DataDir, cfg.GeoIP.Path)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		log.Fatalf("data dir %s: %v (run as root or use --data-dir)", cfg.DataDir, err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "myowl.db"))
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer st.Close()

	switch cmd {
	case "passwd":
		setPassword(st, cfg.DataDir)
		return
	case "setup-token":
		if st.Get("password_hash") != "" {
			fmt.Println("A password is already set. Use `myowl passwd` to reset it.")
			return
		}
		srv := server.New(cfg, st, nil)
		fmt.Println(srv.EnsureSetupToken())
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	e := engine.New(cfg, st)
	srv := server.New(cfg, st, e)
	var d *demo.Demo
	if cfg.Demo {
		hash, _ := demoHash()
		_ = st.Set("password_hash", hash)
		d = demo.Setup(e)
		log.Printf("demo mode: generating 24h of history…")
		d.Backfill()
	}
	e.Start(ctx)
	if d != nil {
		go d.Run(ctx)
		log.Printf("demo mode: open http://%s and log in with password: demo", cfg.Listen)
	} else if tok := srv.EnsureSetupToken(); tok != "" {
		log.Printf("FIRST RUN: open the dashboard and create a password using setup code %s (also saved in %s)", tok, filepath.Join(cfg.DataDir, "setup-token.txt"))
	}
	if os.Geteuid() != 0 && !cfg.Demo {
		log.Printf("not running as root: some data (other users' processes, protected logs, packet capture, firewall blocking) will be limited")
	}
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Fatalf("http: %v", err)
	}
	log.Printf("bye")
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// demoHash returns a bcrypt hash of "demo" (shorter than the normal minimum).
func demoHash() (string, error) {
	return server.HashPasswordUnchecked("demo")
}

func setPassword(st *store.Store, dataDir string) {
	var p1, p2 string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Print("New dashboard password (min 8 chars): ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Print("Repeat: ")
		b2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Fatal(err)
		}
		p1, p2 = string(b), string(b2)
	} else {
		sc := bufio.NewScanner(os.Stdin)
		if sc.Scan() {
			p1 = strings.TrimRight(sc.Text(), "\r\n")
		}
		p2 = p1
	}
	if p1 != p2 {
		log.Fatal("passwords do not match")
	}
	h, err := server.HashPassword(p1)
	if err != nil {
		log.Fatal(err)
	}
	if err := st.Set("password_hash", h); err != nil {
		log.Fatal(err)
	}
	_ = st.Delete("setup_token")
	_ = st.DeleteAllSessions()
	_ = os.Remove(filepath.Join(dataDir, "setup-token.txt"))
	fmt.Println("Password updated. All dashboard sessions were logged out.")
}
