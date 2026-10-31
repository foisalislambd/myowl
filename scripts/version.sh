#!/usr/bin/env bash
# Version helpers for myOwl. VERSION.md (repo root) is the single source of truth.
#
#   scripts/version.sh get [VERSION.md]            print the version (e.g. 1.0.0)
#   scripts/version.sh compare A B                 print gt | eq | lt  (semver 2.0 precedence)
#   scripts/version.sh latest < tags.txt           highest semver tag from stdin (one per line), or nothing
#   scripts/version.sh should-release V < tags     print "true" if V > highest tag (or no tags), else "false"
#   scripts/version.sh notes V [VERSION.md]        print the changelog section for V
#
# Tags may carry a leading "v". Non-semver tags are ignored.
set -euo pipefail

SEMVER_RE='^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*))?(\+[0-9A-Za-z.-]+)?$'
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "version.sh: $*" >&2; exit 1; }
is_semver() { [[ "$1" =~ $SEMVER_RE ]]; }

get_version() {
  local f="${1:-$ROOT/VERSION.md}" v
  [ -f "$f" ] || die "$f not found"
  # shellcheck disable=SC2016 # backticks are literal (version may be written as `1.0.0`)
  v="$(sed -n -E 's/^[[:space:]]*version:[[:space:]]*`?v?([^`[:space:]]+)`?[[:space:]]*$/\1/p' "$f" | head -n1)"
  [ -n "$v" ] || die "no 'version: X.Y.Z' line in $f"
  is_semver "$v" || die "'$v' in $f is not a valid semantic version"
  printf '%s\n' "$v"
}

# cmp_ident a b -> -1/0/1 for one pre-release identifier
cmp_ident() {
  local a="$1" b="$2" an=0 bn=0
  [[ "$a" =~ ^[0-9]+$ ]] && an=1
  [[ "$b" =~ ^[0-9]+$ ]] && bn=1
  if [ $an = 1 ] && [ $bn = 1 ]; then
    if ((10#$a > 10#$b)); then echo 1; elif ((10#$a < 10#$b)); then echo -1; else echo 0; fi
  elif [ $an = 1 ]; then echo -1          # numeric identifiers sort before alphanumeric
  elif [ $bn = 1 ]; then echo 1
  elif [[ "$a" > "$b" ]]; then echo 1
  elif [[ "$a" < "$b" ]]; then echo -1
  else echo 0; fi
}

# compare A B -> gt | eq | lt
compare() {
  local a="$1" b="$2"
  is_semver "$a" || die "not a semantic version: $a"
  local -a ca=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")
  local ap="${BASH_REMATCH[5]}"
  is_semver "$b" || die "not a semantic version: $b"
  local -a cb=("${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}")
  local bp="${BASH_REMATCH[5]}"
  local i
  for i in 0 1 2; do
    if ((10#${ca[$i]} > 10#${cb[$i]})); then echo gt; return; fi
    if ((10#${ca[$i]} < 10#${cb[$i]})); then echo lt; return; fi
  done
  # A version without pre-release has higher precedence than one with.
  if [ -z "$ap" ] && [ -z "$bp" ]; then echo eq; return; fi
  if [ -z "$ap" ]; then echo gt; return; fi
  if [ -z "$bp" ]; then echo lt; return; fi
  local IFS=. pa pb n c
  read -r -a pa <<<"$ap"
  read -r -a pb <<<"$bp"
  n=${#pa[@]}; ((${#pb[@]} > n)) && n=${#pb[@]}
  for ((i = 0; i < n; i++)); do
    if [ $i -ge ${#pa[@]} ]; then echo lt; return; fi
    if [ $i -ge ${#pb[@]} ]; then echo gt; return; fi
    c="$(cmp_ident "${pa[$i]}" "${pb[$i]}")"
    if [ "$c" = 1 ]; then echo gt; return; fi
    if [ "$c" = -1 ]; then echo lt; return; fi
  done
  echo eq
}

latest() {
  local best="" t
  while IFS= read -r t || [ -n "$t" ]; do
    t="${t//[[:space:]]/}"
    if [ -z "$t" ] || ! is_semver "$t"; then continue; fi
    if [ -z "$best" ] || [ "$(compare "$t" "$best")" = gt ]; then best="$t"; fi
  done
  [ -n "$best" ] && printf '%s\n' "$best"
  return 0
}

should_release() {
  local v="$1" top
  is_semver "$v" || die "not a semantic version: $v"
  top="$(latest)"
  if [ -z "$top" ] || [ "$(compare "$v" "$top")" = gt ]; then echo true; else echo false; fi
}

notes() {
  local v="${1#v}" f="${2:-$ROOT/VERSION.md}"
  # Section starts at a heading like "## 1.0.0", "### [1.0.0] - 2026-10-31" or "### v1.0.0 — ..."
  # and ends at the next heading of the same or higher level.
  awk -v ver="$v" '
    function esc(s) { gsub(/\./, "\\.", s); return s }
    BEGIN { pat = "^#+[[:space:]]*\\[?v?" esc(ver) "\\]?([[:space:]]|$)" }
    {
      if (match($0, /^#+/)) {
        lvl = RLENGTH
        if (on && lvl <= level) exit
        if (!on && $0 ~ pat) { on = 1; level = lvl; next }
      }
      if (on) print
    }
  ' "$f" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'
}

cmd="${1:-}"; shift || true
case "$cmd" in
  get) get_version "$@" ;;
  compare) [ $# -eq 2 ] || die "usage: compare A B"; compare "$1" "$2" ;;
  latest) latest ;;
  should-release) [ $# -eq 1 ] || die "usage: should-release VERSION < tags"; should_release "$1" ;;
  notes) [ $# -ge 1 ] || die "usage: notes VERSION [file]"; notes "$@" ;;
  *) sed -n '2,10p' "$0" >&2; exit 2 ;;
esac
