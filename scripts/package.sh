#!/usr/bin/env bash
# Package bin/myowl-linux-{amd64,arm64} into release archives + SHA256SUMS.
# Output: release/myowl_<version>_linux_<arch>.tar.gz and release/SHA256SUMS
# Each archive contains a top-level myowl/ folder with the binary, install.sh,
# config example, systemd unit, README, LICENSE and VERSION.md.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="${VERSION:-$(scripts/version.sh get)}"
VERSION="${VERSION#v}"
ARCHES="${ARCHES:-amd64 arm64}"
rm -rf release && mkdir -p release
for arch in $ARCHES; do
  bin="bin/myowl-linux-$arch"
  [ -f "$bin" ] || { echo "missing $bin (run make build-linux-$arch)" >&2; exit 1; }
  stage="release/stage-$arch/myowl"
  mkdir -p "$stage"
  install -m 0755 "$bin" "$stage/myowl"
  install -m 0755 install.sh "$stage/install.sh"
  install -m 0644 config.example.yaml README.md LICENSE VERSION.md deploy/myowl.service "$stage/"
  tar -C "release/stage-$arch" --owner=0 --group=0 --numeric-owner -czf "release/myowl_${VERSION}_linux_${arch}.tar.gz" myowl
  rm -rf "release/stage-$arch"
done
(cd release && sha256sum myowl_*.tar.gz > SHA256SUMS)
echo "release/ (version $VERSION):"
ls -l release
cat release/SHA256SUMS
