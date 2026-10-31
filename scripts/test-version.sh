#!/usr/bin/env bash
# Unit tests for scripts/version.sh. Run: scripts/test-version.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
V=scripts/version.sh
pass=0; fail=0
check() { # name expected actual
  if [ "$2" = "$3" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); printf 'FAIL %s\n  want: %q\n  got:  %q\n' "$1" "$2" "$3"; fi
}

# compare
while read -r a b want; do
  [ -z "$a" ] && continue
  check "compare $a $b" "$want" "$($V compare "$a" "$b")"
done <<'CASES'
1.0.0 1.0.0 eq
v1.0.0 1.0.0 eq
1.0.1 1.0.0 gt
1.0.0 1.0.1 lt
1.10.0 1.9.9 gt
2.0.0 10.0.0 lt
1.0.0 1.0.0-rc.1 gt
1.0.0-rc.1 1.0.0 lt
1.0.0-alpha 1.0.0-alpha.1 lt
1.0.0-alpha.1 1.0.0-alpha.beta lt
1.0.0-alpha.beta 1.0.0-beta lt
1.0.0-beta 1.0.0-beta.2 lt
1.0.0-beta.2 1.0.0-beta.11 lt
1.0.0-beta.11 1.0.0-rc.1 lt
1.0.0+build.5 1.0.0 eq
0.9.0 1.0.0 lt
CASES

# invalid input fails
$V compare 1.0 1.0.0 >/dev/null 2>&1; check "invalid compare exits non-zero" 1 "$?"

# latest
check "latest picks highest semver" "v1.10.0" "$(printf 'v1.2.0\nv1.10.0\nnightly\nv1.9.3\n' | $V latest)"
check "latest ignores non-semver" "" "$(printf 'nightly\nfoo\n' | $V latest)"
check "latest empty" "" "$(printf '' | $V latest)"

# should-release
check "no tags -> release" true "$(printf '' | $V should-release 1.0.0)"
check "only junk tags -> release" true "$(printf 'test\n' | $V should-release 1.0.0)"
check "greater -> release" true "$(printf 'v1.0.0\nv0.9.0\n' | $V should-release 1.0.1)"
check "equal -> skip" false "$(printf 'v1.0.0\n' | $V should-release 1.0.0)"
check "lower -> skip" false "$(printf 'v1.2.0\nv1.0.0\n' | $V should-release 1.1.9)"
check "final > rc tag -> release" true "$(printf 'v1.0.0-rc.2\n' | $V should-release 1.0.0)"

# get + notes against a fixture
tmp="$(mktemp)"; trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'MD'
# Title

version: `2.3.4`

## Changelog

### 2.3.4 — 2026-11-01

- New thing
- Fixed thing

### 2.3.3

- Older
MD
check "get from fixture" "2.3.4" "$($V get "$tmp")"
check "notes for 2.3.4" $'- New thing\n- Fixed thing' "$($V notes 2.3.4 "$tmp")"
check "notes for v2.3.3" "- Older" "$($V notes v2.3.3 "$tmp")"
check "notes for missing" "" "$($V notes 9.9.9 "$tmp")"
printf 'no version here\n' >"$tmp"
$V get "$tmp" >/dev/null 2>&1; check "get without version fails" 1 "$?"

# the real VERSION.md must parse and have notes
real="$($V get)"
check "VERSION.md parses" ok "$([ -n "$real" ] && echo ok)"
check "VERSION.md has notes for $real" ok "$([ -n "$($V notes "$real")" ] && echo ok)"

echo "version.sh: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
