<p align="center">
  <img src="docs/logo.svg" alt="myOwl" width="420">
</p>

<p align="center">
  <b>A self-hosted security monitor for your Linux VPS, with a live attack map.</b><br>
  One binary. No cloud, no sign-up, no telemetry.
</p>

<p align="center">
  <a href="https://github.com/OWNER/myowl/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/OWNER/myowl/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/OWNER/myowl/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/OWNER/myowl?sort=semver"></a>
  <a href="https://github.com/OWNER/myowl/pkgs/container/myowl"><img alt="Docker image" src="https://img.shields.io/badge/docker-ghcr.io%2Fowner%2Fmyowl-2496ED?logo=docker&logoColor=white"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/github/license/OWNER/myowl"></a>
</p>

> **Publishing a fork?** Replace `OWNER` with your GitHub user or organisation in this README,
> at the top of [`install.sh`](install.sh) (`REPO="OWNER/myowl"`), in `docker-compose.yml`
> (`ghcr.io/owner/...`, lowercase), in `SECURITY.md` and in `.github/ISSUE_TEMPLATE/config.yml`.
> The Go module path `github.com/myowl/myowl/agent` is internal only; you don't have to change it.

myOwl watches a Linux server and shows the results in one web dashboard. You see system health,
who is connected and from where, every request your nginx/Apache/Caddy serves, SSH logins and
attacks, and alerts. Each panel explains itself in plain language. A Go agent collects the data and
stores it in SQLite. The Next.js UI is compiled into the same binary, so you install one file and
open a browser.

![Live Map: 3D globe (Cyber Cyan theme)](docs/screenshots/map-globe.png)

## Contents

- [Screenshots](#screenshots)
- [Features](#features)
- [Quick start](#quick-start): [install.sh](#1-installsh-recommended) · [Docker](#2-docker) · [Docker Compose](#3-docker-compose) · [Build from source](#4-build-from-source)
- [First login](#first-login)
- [Configuration reference](#configuration-reference)
- [Security hardening](#security-hardening)
- [Reverse proxy: Caddy and nginx](#reverse-proxy-caddy-and-nginx)
- [FAQ](#faq) · [Troubleshooting](#troubleshooting) · [Roadmap](#roadmap)
- [Versioning and releases](#versioning-and-releases) · [Contributing](#contributing) · [License](#license)

## Screenshots

| | |
|---|---|
| ![Sign-in](docs/screenshots/login.png) | ![Live Map: node graph with details](docs/screenshots/map-graph.png) |
| ![Overview: Matrix Green](docs/screenshots/overview.png) | ![Overview: Daylight (light theme)](docs/screenshots/overview-light.png) |
| ![Live Map: Daylight](docs/screenshots/map-light.png) | ![Security](docs/screenshots/security.png) |
| ![Network](docs/screenshots/network.png) | ![World map](docs/screenshots/network-map.png) |
| ![Web requests](docs/screenshots/requests.png) | ![Request details drawer](docs/screenshots/requests-drawer.png) |
| ![Logins & sessions](docs/screenshots/sessions.png) | ![System health](docs/screenshots/system.png) |
| ![Alerts](docs/screenshots/alerts.png) | ![Settings](docs/screenshots/settings.png) |
| ![Settings → Appearance](docs/screenshots/settings-themes.png) | ![Theme switcher](docs/screenshots/theme-menu.png) |

Phone layout: [Live Map](docs/screenshots/mobile-map.png). These screenshots come from demo mode
(`myowl --demo`), so every IP address and hostname in them is fake.

## Features

| Area | What you get |
|---|---|
| **Live Map** | The landing page, built as a security-operations wall. A rotating **3D globe** draws an arc from every connected IP (normal, attacker or blocked). Press `g` to switch to a **live node graph**: your server, its services, remote IPs and logged-in users. Click any node for details and a **Block IP** button. Also on the page: a live event log, a threat radar, live counters, a **DEFCON 5→1 threat level** and **wall mode** (`f`) for a NOC screen. |
| **Overview** | A 0–100 health score with plain-English reasons ("Disk /mnt/backups is 87% full — clean up old logs"). Also live bandwidth, connections, requests, failed logins and threats, plus gauges, a traffic chart, a world map and top talkers. |
| **Network** | Per-interface bandwidth (live, 1h/24h/7d). Every TCP/UDP connection with its **program**, state, bytes and country. **Top talkers**, a **GeoIP world map** (DB-IP Lite), and **listening ports** with friendly names and warnings for risky public ports. |
| **Web requests** | A live feed tailed from **nginx / Apache / Caddy** logs. Common, combined and JSON formats are auto-detected, and log rotation is handled. Filter and search the feed, see the top paths, IPs and status codes, and open a details drawer for any request. |
| **Security** | Detects **SSH brute force**, new-address and after-failure logins, sudo failures, **port scans**, SYN floods, **SQLi, XSS, path traversal, command execution / Log4Shell**, scanner paths, hacking-tool user agents, 404 probing, request floods and traffic spikes. Each threat comes with a "what to do". Optional **one-click Block IP** via nftables, iptables or ufw. |
| **Logins & sessions** | Who is logged in now (utmp), login history (wtmp), SSH and sudo activity from auth.log or the systemd journal, and the most-attacked usernames. |
| **System health** | CPU (per core, iowait), memory, swap, disks (space and inodes), disk I/O, load, history charts, top processes and **systemd services**, with failed services highlighted. |
| **Alerts** | Rules for CPU, memory, disk, swap, load, bandwidth, connections, threats, SSH logins and crashed services. Delivered to the dashboard, a **JSON webhook** (Slack/Discord-compatible), **Telegram** and **email (SMTP)**. |
| **Look & feel** | Six themes, including a light **Daylight** theme. You can also pick a custom accent colour, three text sizes, and optional CRT, boot and matrix-rain effects that respect "reduce motion". Text meets WCAG AA contrast and the layout works on phones. |
| **Real-time** | Every page updates live over Server-Sent Events. History is kept in SQLite with automatic retention. |
| **Demo mode** | `myowl --demo` runs with realistic simulated data and needs no root. |

## Quick start

### 1. install.sh (recommended)

The script works on Ubuntu, Debian and most other systemd distros (amd64 or arm64). It downloads
the latest release and **verifies its SHA-256 checksum**. Then it installs `/usr/local/bin/myowl`,
`/etc/myowl/config.yaml` and the `myowl` systemd service, and prints your one-time setup code.

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/myowl/main/install.sh | sudo bash

# Private mode (dashboard only on 127.0.0.1; use an SSH tunnel or a reverse proxy):
curl -fsSL https://raw.githubusercontent.com/OWNER/myowl/main/install.sh | sudo bash -s -- --localhost
```

Options: `--localhost`, `--port N`, `--version X.Y.Z`, `--binary PATH`, `--uninstall`, `--purge`.
`MYOWL_REPO=owner/repo` overrides the repository the script downloads from.

**From a release archive** (no download needed; the script uses the bundled binary):

```bash
VERSION=1.0.0; ARCH=amd64     # or arm64
curl -fsSLO https://github.com/OWNER/myowl/releases/download/v$VERSION/myowl_${VERSION}_linux_${ARCH}.tar.gz
curl -fsSLO https://github.com/OWNER/myowl/releases/download/v$VERSION/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf myowl_${VERSION}_linux_${ARCH}.tar.gz && cd myowl && sudo ./install.sh
```

To upgrade, run the installer again. It keeps your config and data.

### 2. Docker

```bash
docker run -d --name myowl --restart unless-stopped \
  --network host --pid host \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v myowl-data:/var/lib/myowl \
  -v /var/log:/var/log:ro -v /var/run/utmp:/var/run/utmp:ro \
  ghcr.io/owner/myowl:latest
docker logs myowl 2>&1 | grep -i "setup code"
```

| Flag | Why |
|---|---|
| `--network host` | Shows the host's real interfaces, connections and listening ports. |
| `--pid host` | Shows host processes (top processes, connection owners). |
| `--cap-add NET_ADMIN` | Allows one-click **Block IP** (nftables/iptables). |
| `--cap-add NET_RAW` | Allows passive per-IP byte counting and SYN port-scan detection. |
| `--cap-add SYS_PTRACE` *(optional)* | Maps sockets to processes owned by other users. |
| `-v /var/log:/var/log:ro` | Lets myOwl read web-server and auth logs. |

The image runs as **root by default**, because reading host logs and changing the host firewall
need it. If you don't need IP blocking, run `--user 10001:4` (the bundled `myowl` user plus group
`adm`, so host logs stay readable) and drop `NET_ADMIN`. A container can't see systemd services or
the journal; the native install covers more. The image has a `HEALTHCHECK` (`myowl healthcheck`)
and OCI version labels.

### 3. Docker Compose

```bash
curl -fsSLO https://raw.githubusercontent.com/OWNER/myowl/main/docker-compose.yml
curl -fsSL  https://raw.githubusercontent.com/OWNER/myowl/main/config.example.yaml -o config.yaml
# edit docker-compose.yml: replace "owner" in image: (lowercase), or set MYOWL_IMAGE
docker compose up -d
docker compose logs myowl | grep -i "setup code"
```

From a clone, `docker compose up -d --build` builds the image locally.

### 4. Build from source

Requirements: **Go 1.27+**, **Node.js 24+**, **pnpm 10** (`corepack enable`) and make.

```bash
git clone https://github.com/OWNER/myowl.git && cd myowl
make build            # web UI -> embedded -> bin/myowl (version from VERSION.md)
make test             # go vet + go test + script tests
make demo             # run with fake data on http://127.0.0.1:8787 (password: demo)
make release          # release/myowl_<version>_linux_{amd64,arm64}.tar.gz + SHA256SUMS
sudo ./install.sh --binary bin/myowl
```

<details>
<summary>Repository layout</summary>

```
agent/                 Go module: agent + HTTP server (UI embedded via go:embed)
  cmd/myowl/           main, CLI subcommands (run, passwd, setup-token, gen-config, healthcheck, version)
  internal/collect/    /proc, netlink sock_diag, AF_PACKET capture, utmp/wtmp, systemd
  internal/logs/       log tailing + nginx/apache/caddy/auth parsers
  internal/detect/     threat detection rules with plain-language explanations
  internal/store/      SQLite (modernc, pure Go) with retention
  internal/alerts/     rule engine + webhook / Telegram / SMTP
  internal/firewall/   nftables / iptables / ufw
  internal/geo/        DB-IP Lite lookups + monthly auto-download
  internal/server/     REST API, SSE stream, auth, static UI
  internal/demo/       simulated data for --demo
web/                   Next.js 16 (App Router, React 19, Tailwind 4), static export
scripts/               version.sh (semver + changelog helpers), package.sh, tests
deploy/myowl.service   systemd unit
VERSION.md             version + changelog (drives releases)
```
</details>

## First login

1. Open `http://YOUR-SERVER-IP:8787`.
2. Enter the **setup code** printed by the installer. You can also get it with `sudo myowl setup-token`,
   from `/var/lib/myowl/setup-token.txt`, or with `journalctl -u myowl`.
3. Choose a password (8+ characters). It is stored as a bcrypt hash, and the setup code stops working.
4. If you forget the password, `sudo myowl passwd` sets a new one.

The setup code stops anyone who finds a fresh install on the internet from claiming it before you do.

## Configuration reference

The config lives in `/etc/myowl/config.yaml`. See [`config.example.yaml`](config.example.yaml) or run
`myowl gen-config`. Restart after editing: `sudo systemctl restart myowl`.

| Key | Default | Meaning |
|---|---|---|
| `listen` | `0.0.0.0:8787` | Dashboard address. Use `127.0.0.1:8787` for tunnel- or proxy-only access. |
| `data_dir` | `/var/lib/myowl` | SQLite database, GeoIP DB and setup code. |
| `tls.cert` / `tls.key` | empty | Serve HTTPS directly. |
| `cookie_secure` | `false` | Sets the `Secure` flag on cookies. Set to `true` behind an HTTPS proxy. |
| `trust_proxy` | `false` | Trusts `X-Forwarded-*` headers from a local or private proxy. |
| `retention.days` / `retention.max_requests` | `14` / `500000` | How long history is kept and the hard cap on stored requests. |
| `intervals.*` | `2`/`2`/`10` s | Sampling intervals for system, network and sessions. |
| `access_logs` | nginx/apache/caddy paths | Web logs to follow; `format: auto \| combined \| common \| json`. |
| `auth_logs`, `kernel_logs`, `journald` | auth.log, secure, ufw/kern, `auto` | SSH/sudo and port-scan sources. |
| `backfill_lines` | `500` | Lines of history read from each log on first start. |
| `geoip.path`, `geoip.auto_download` | data dir, `true` | DB-IP City Lite (CC BY 4.0), refreshed monthly. |
| `server_location` | unset (`0,0`) | Optionally pins the server's position on the world map. |
| `capture.enabled` | `true` | Passive per-IP byte counting and SYN scan detection (root or CAP_NET_RAW). |
| `firewall.*` | enabled, `auto` | `backend: auto \| nftables \| iptables \| ufw`, `whitelist`, `allow_private`. |
| `detection.*` | see file | Thresholds for brute force, floods, 404 probing and port scans, plus ignore lists. |
| `notify.webhook` / `notify.telegram` / `notify.smtp` | empty | Alert channels. Alert rules are edited in the UI. |

**CLI**

```
myowl [--config PATH] [--listen ADDR] [--data-dir DIR] [--demo]   run the agent + dashboard
myowl passwd | setup-token | gen-config | healthcheck | version
```

**Environment variables:** `MYOWL_CONFIG`, `MYOWL_LISTEN` and `MYOWL_DATA_DIR` override the config
path, listen address and data directory. `install.sh` also reads `MYOWL_REPO` and `MYOWL_VERSION`.

**nginx latency:** to see response times, add `$request_time` at the end of your `log_format`.

## Security hardening

myOwl shows sensitive data (logins, IPs, processes) and can change the firewall. Treat the dashboard
like an SSH port.

- **Don't expose plain HTTP.** Use one of these:
  1. `--localhost` / `listen: 127.0.0.1:8787` plus `ssh -L 8787:127.0.0.1:8787 you@server`.
  2. A TLS reverse proxy (see below), with `trust_proxy: true` and `cookie_secure: true`.
  3. Built-in TLS (`tls.cert`, `tls.key`).
- **Restrict the port:** `sudo ufw allow from YOUR.HOME.IP to any port 8787`.
- **Use a long, unique password.** Changing it signs out every other session.
- **Whitelist your own IPs** in `firewall.whitelist` so they can never be blocked.
- **Keep it updated.** Re-run `install.sh` or pull the new image. Watch the repository's releases.

What myOwl does to protect itself:

- bcrypt (cost 12) password, set with a one-time setup code.
- 256-bit session tokens in `HttpOnly`, `SameSite=Strict` cookies, plus `Secure` over HTTPS.
- CSRF double-submit token and a same-origin check on every state-changing request.
- Login lockout after 5 failures per IP in 15 minutes.
- CSP, `X-Frame-Options: DENY`, `nosniff` and `Referrer-Policy` headers.
- **Blocking safety:** your current IP, private and loopback addresses, the server's own IPs and the
  whitelist can never be blocked. Blocks live in a dedicated nftables table `inet myowl`, in iptables
  rules commented `myowl`, or in ufw rules commented `myowl`.
- The systemd unit runs as root but with `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome=read-only`
  and `PrivateTmp`.

**What needs root**

| Feature | Needs |
|---|---|
| Reading `/var/log/auth.log` and web logs | root or group `adm` |
| Mapping connections to other users' processes | root / CAP_SYS_PTRACE |
| Passive packet capture | root / CAP_NET_RAW |
| One-click Block IP | root / CAP_NET_ADMIN |

Without root, everything else still works. **Settings** explains which features are off and why.

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Reverse proxy: Caddy and nginx

Set `listen: 127.0.0.1:8787`, `trust_proxy: true` and `cookie_secure: true`, then restart myOwl.

**Caddy** (automatic HTTPS):

```caddyfile
monitor.example.com {
    reverse_proxy 127.0.0.1:8787
}
```

**nginx** (certificates from certbot):

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name monitor.example.com;

    ssl_certificate     /etc/letsencrypt/live/monitor.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/monitor.example.com/privkey.pem;

    # optional: only allow your own networks
    # allow 203.0.113.0/24; deny all;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # live updates use Server-Sent Events
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}
server {
    listen 80;
    server_name monitor.example.com;
    return 301 https://$host$request_uri;
}
```

## FAQ

**Does it send my data anywhere?**
No. The only outbound request is the monthly DB-IP Lite GeoIP download. You can turn it off with
`geoip.auto_download: false`. Alerts go only to the channels you configure.

**How much does it use?**
On a typical small VPS it uses a few tens of MB of RAM and very little CPU. The SQLite database is
capped by `retention`.

**Is it a firewall, WAF or IDS?**
No. Detection is signature- and threshold-based, roughly fail2ban plus simple WAF rules. It helps you
see and react, and it complements real protection.

**Can it monitor several servers?**
Not yet. Each server runs its own myOwl. A multi-server view is on the [roadmap](#roadmap).

**Which distributions work?**
Any modern Linux with `/proc`. The installer needs systemd. Ubuntu and Debian are tested best;
RHEL-style log paths are included.

**Why is the Go module path `github.com/myowl/myowl`?**
It's only an internal import path, so forks don't need to change it.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Can't reach the dashboard | Check `systemctl status myowl`, the `listen:` address and your firewall (`sudo ufw allow 8787/tcp`) or cloud security group. |
| Lost the setup code | `sudo myowl setup-token`, or `journalctl -u myowl \| grep -i setup` |
| Forgot the password | `sudo myowl passwd` |
| "Too many attempts" at login | Wait 15 minutes (the lockout is per IP). |
| No web requests | Check that `access_logs` points at your real log paths and that myOwl can read them. **Settings** shows each source's status. |
| No world map or countries | The GeoIP download needs outbound HTTPS once. Check `journalctl -u myowl`. |
| Live view lags behind nginx | Add `proxy_buffering off;` to the nginx location. |
| Block IP is greyed out | Needs root or `NET_ADMIN` plus nftables, iptables or ufw. Docker needs `--cap-add NET_ADMIN`. |
| Docker shows container data only | Run with `--network host --pid host` and mount `/var/log`. |
| `install.sh` says REPO is a placeholder | Set `REPO=` at the top of the script or run with `MYOWL_REPO=owner/myowl`. |
| Logs | `journalctl -u myowl -f` or `docker logs -f myowl` |

## Roadmap

- [ ] Multi-server view (several agents, one dashboard)
- [ ] Persistent blocklists that survive reboots without myOwl running
- [ ] Optional TOTP two-factor login
- [ ] More log sources (Postfix, Docker container logs)
- [ ] Prometheus `/metrics` endpoint
- [ ] Packages for apt/rpm

Ideas and PRs are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Versioning and releases

The version lives in [`VERSION.md`](VERSION.md) (`version: X.Y.Z`) together with the changelog. It is
embedded into the binary at build time and shown in the dashboard. Every push to `main` runs the
**Release** workflow:

- It compares the version in `VERSION.md` with the highest `vX.Y.Z` tag.
- If the version is **strictly greater**, or no tags exist yet, the workflow builds the linux amd64
  and arm64 archives and `SHA256SUMS`. It pushes `ghcr.io/<owner>/myowl:X.Y.Z` and `:latest`, then
  creates the tag `vX.Y.Z` and a GitHub Release. The release notes come from that version's
  changelog section.
- Otherwise the workflow logs that the release was skipped and succeeds.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

[MIT](LICENSE) © myOwl contributors. IP geolocation by [DB-IP](https://db-ip.com) (CC BY 4.0).
World map data from Natural Earth via world-atlas.
