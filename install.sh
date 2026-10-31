#!/usr/bin/env bash
# myOwl installer for Ubuntu / Debian (and most systemd-based Linux).
#
# One line (downloads the latest GitHub release, verifies its SHA-256 checksum):
#   curl -fsSL https://raw.githubusercontent.com/OWNER/myowl/main/install.sh | sudo bash
# From an extracted release archive (uses the bundled ./myowl binary):
#   sudo ./install.sh
#
# Options (pass after `bash -s --` when piping):
#   --localhost        only listen on 127.0.0.1 (use an SSH tunnel / reverse proxy)
#   --port N           dashboard port (default 8787)
#   --version X.Y.Z    release to download (default: latest)
#   --binary PATH      install this local binary instead of downloading
#   --uninstall        stop and remove the service and binary (keeps data + config)
#   --purge            like --uninstall, but also deletes data and config
set -euo pipefail

# ---------------------------------------------------------------------------
# GitHub repository to download releases from. Replace OWNER with your GitHub
# user or organisation after forking/publishing (or set MYOWL_REPO=owner/repo).
REPO="${MYOWL_REPO:-OWNER/myowl}"
# ---------------------------------------------------------------------------

VERSION="${MYOWL_VERSION:-latest}"
PORT=8787
BIND="0.0.0.0"
ACTION="install"
LOCAL_BIN=""
BIN=/usr/local/bin/myowl
CONF_DIR=/etc/myowl
DATA_DIR=/var/lib/myowl
UNIT=/etc/systemd/system/myowl.service

while [ $# -gt 0 ]; do
  case "$1" in
    --localhost) BIND="127.0.0.1" ;;
    --port) PORT="${2:?--port needs a value}"; shift ;;
    --version) VERSION="${2:?--version needs a value}"; shift ;;
    --binary) LOCAL_BIN="${2:?--binary needs a path}"; shift ;;
    --uninstall) ACTION="uninstall" ;;
    --purge) ACTION="purge" ;;
    -h|--help) sed -n '2,16p' "$0" 2>/dev/null || true; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2; exit 1; }

case "$PORT" in ''|*[!0-9]*) die "--port must be a number" ;; esac

[ "$(id -u)" -eq 0 ] || die "Please run as root (e.g. with sudo)."
command -v systemctl >/dev/null || die "systemd is required. For other setups run the binary directly or use Docker."

if [ "$ACTION" != "install" ]; then
  say "Stopping and removing myOwl"
  systemctl disable --now myowl 2>/dev/null || true
  rm -f "$UNIT" "$BIN"
  systemctl daemon-reload
  # Remove firewall objects created by one-click blocking
  if command -v nft >/dev/null; then nft delete table inet myowl 2>/dev/null || true; fi
  if [ "$ACTION" = "purge" ]; then rm -rf "$DATA_DIR" "$CONF_DIR"; say "Data and config deleted."; else say "Kept $CONF_DIR and $DATA_DIR (use --purge to delete)."; fi
  exit 0
fi

# Directory of this script — only when run from a file (not `curl | bash`).
SRC_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) die "Unsupported CPU architecture $(uname -m) (release binaries exist for amd64 and arm64)." ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null; then shasum -a 256 "$1" | awk '{print $1}'
  else die "sha256sum (coreutils) is required to verify the download."; fi
}

need_curl() {
  command -v curl >/dev/null && return
  if command -v apt-get >/dev/null; then apt-get update -qq && apt-get install -y -qq curl ca-certificates >/dev/null
  else die "curl is required."; fi
}

download_release() {
  local arch tag ver asset base want got
  case "$REPO" in OWNER/*) die "REPO is still the placeholder '$REPO'. Edit REPO at the top of install.sh or run with MYOWL_REPO=owner/myowl." ;; esac
  arch="$(detect_arch)"
  need_curl
  if [ "$VERSION" = "latest" ]; then
    # Follow the /releases/latest redirect (no API token / rate limit needed).
    tag="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed -n 's#.*/releases/tag/##p')"
    [ -n "$tag" ] || die "Could not find a published release for $REPO."
  else
    tag="v${VERSION#v}"
  fi
  ver="${tag#v}"
  asset="myowl_${ver}_linux_${arch}.tar.gz"
  base="https://github.com/$REPO/releases/download/$tag"
  say "Downloading myOwl $tag for linux/$arch"
  curl -fsSL --retry 3 "$base/$asset" -o "$TMP/$asset" || die "Download failed: $base/$asset"
  curl -fsSL --retry 3 "$base/SHA256SUMS" -o "$TMP/SHA256SUMS" || die "Download failed: $base/SHA256SUMS"
  want="$(awk -v f="$asset" '$2 == f || $2 == "*"f {print $1}' "$TMP/SHA256SUMS")"
  [ -n "$want" ] || die "$asset is not listed in SHA256SUMS."
  got="$(sha256_of "$TMP/$asset")"
  [ "$want" = "$got" ] || die "Checksum mismatch for $asset (expected $want, got $got). Aborting."
  say "Checksum OK ($got)"
  tar -xzf "$TMP/$asset" -C "$TMP"
  [ -f "$TMP/myowl/myowl" ] || die "Binary not found in $asset."
  cp "$TMP/myowl/myowl" "$TMP/myowl.bin"
  [ -f "$TMP/myowl/myowl.service" ] && cp "$TMP/myowl/myowl.service" "$TMP/myowl.service"
  return 0
}

# 1. Binary: --binary, the one next to this script (release archive) or download it.
if [ -n "$LOCAL_BIN" ]; then
  [ -f "$LOCAL_BIN" ] || die "$LOCAL_BIN not found."
  say "Using local binary $LOCAL_BIN"
  cp "$LOCAL_BIN" "$TMP/myowl.bin"
elif [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/myowl" ] && [ -x "$SRC_DIR/myowl" ]; then
  say "Using bundled binary $SRC_DIR/myowl"
  cp "$SRC_DIR/myowl" "$TMP/myowl.bin"
else
  download_release
fi
"$TMP/myowl.bin" version >/dev/null 2>&1 || die "The binary does not run on this machine (wrong architecture?)."
install -m 0755 "$TMP/myowl.bin" "$BIN"
say "Installed $("$BIN" version) to $BIN"

# 2. Config + data dir
install -d -m 0750 "$CONF_DIR" "$DATA_DIR"
if [ ! -f "$CONF_DIR/config.yaml" ]; then
  "$BIN" gen-config > "$CONF_DIR/config.yaml"
  sed -i "s|^listen: .*|listen: \"$BIND:$PORT\"|" "$CONF_DIR/config.yaml"
  chmod 0640 "$CONF_DIR/config.yaml"
  say "Wrote $CONF_DIR/config.yaml (listening on $BIND:$PORT)"
else
  say "Keeping existing $CONF_DIR/config.yaml"
fi

# 3. Optional helpers (best effort, never fatal)
if ! command -v nft >/dev/null && ! command -v iptables >/dev/null && ! command -v ufw >/dev/null; then
  warn "No firewall tool found; one-click blocking will be disabled (apt-get install nftables to enable)."
fi

# 4. systemd unit
if [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/myowl.service" ]; then cp "$SRC_DIR/myowl.service" "$UNIT"
elif [ -n "$SRC_DIR" ] && [ -f "$SRC_DIR/deploy/myowl.service" ]; then cp "$SRC_DIR/deploy/myowl.service" "$UNIT"
elif [ -f "$TMP/myowl.service" ]; then cp "$TMP/myowl.service" "$UNIT"
else
  cat > "$UNIT" <<'UNITEOF'
[Unit]
Description=myOwl - self-hosted VPS security monitor
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/myowl --config /etc/myowl/config.yaml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=full
ReadWritePaths=-/etc/ufw /var/lib/myowl
[Install]
WantedBy=multi-user.target
UNITEOF
fi
chmod 0644 "$UNIT"
systemctl daemon-reload
systemctl enable myowl >/dev/null 2>&1
systemctl restart myowl
say "Service started (systemctl status myowl)"

# 5. Firewall hint for the dashboard port
if [ "$BIND" = "0.0.0.0" ] && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  warn "UFW is active. To reach the dashboard run:  sudo ufw allow $PORT/tcp   (better: allow only your IP)"
fi

# 6. First-login info
CODE=""
for _ in 1 2 3 4 5 6 7; do
  [ -f "$DATA_DIR/setup-token.txt" ] && CODE="$(cat "$DATA_DIR/setup-token.txt")" && break
  sleep 1
done
IP="$(curl -fsS -m 3 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
echo
say "myOwl is running."
if [ "$BIND" = "127.0.0.1" ]; then
  echo "    Open an SSH tunnel from your computer:  ssh -L $PORT:127.0.0.1:$PORT root@${IP:-your-server}"
  echo "    then browse to:                          http://localhost:$PORT"
else
  echo "    Dashboard:   http://${IP:-your-server-ip}:$PORT"
fi
if [ -n "$CODE" ]; then
  echo "    Setup code:  $CODE     (enter it on first visit to choose your password)"
else
  echo "    Password:    already set. Forgot it?  sudo myowl passwd"
fi
echo "    Config:      $CONF_DIR/config.yaml   (then: sudo systemctl restart myowl)"
echo "    Logs:        journalctl -u myowl -f"
[ "$BIND" = "0.0.0.0" ] && warn "The dashboard uses plain HTTP. Put it behind HTTPS (see README) or use --localhost."
exit 0
