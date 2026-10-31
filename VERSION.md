# myOwl version

version: 1.0.0

This file is the **single source of truth** for the myOwl version. The `Makefile`,
the Docker build and the GitHub release workflow all read the `version:` line above.

**To ship a release:** bump `version:` (semantic versioning, `MAJOR.MINOR.PATCH`), add a
section for it under *Changelog* below, and push to `main`. The release workflow
creates tag `vX.Y.Z`, a GitHub Release (notes = that version's section), Linux
binaries and a multi-arch Docker image — but **only if the new version is strictly
greater than the latest existing tag**. Equal or lower versions are skipped.

## Changelog

### 1.0.0 — 2026-10-31

First public release as **myOwl**.

- Live attack map: 3D globe, 2D world map and node graph of every connection, with threat arcs.
- Security center: SSH brute force, web scanners, exploit probes and port scans detected from logs, with one-click IP blocking (nftables / iptables / ufw).
- HTTP request explorer for nginx, Apache and Caddy access logs, with per-request details and threat flags.
- Network view: live bandwidth, connections, listening ports, top talkers and GeoIP.
- System view: CPU, memory, disk, load, processes and service health.
- Logged-in users and SSH session history.
- Alerts via email, Telegram and JSON webhooks (Slack, Discord and Mattermost compatible).
- Six colour themes (incl. a light theme), font sizes and accessible contrast; settings sync per user.
- Single static binary with the web UI embedded, systemd unit, installer with checksum verification, Docker image and docker compose file.
- Demo mode with realistic fake data (`myowl --demo`).
