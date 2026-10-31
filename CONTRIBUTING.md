# Contributing to myOwl

Thanks for helping! Bug reports, docs fixes and pull requests are all welcome.
By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Project layout

| Path | What |
| --- | --- |
| `agent/` | Go module: collectors, SQLite store, alerting, HTTP API, embedded UI (`cmd/myowl`) |
| `web/` | Next.js (App Router) dashboard, exported statically and embedded into the binary |
| `scripts/` | `version.sh` (VERSION.md / semver helpers used by the release workflow), `package.sh`, tests |
| `deploy/` | systemd unit |
| `.github/workflows/` | `ci.yml` (PRs/pushes) and `release.yml` (push to `main`) |
| `VERSION.md` | the project version + changelog — single source of truth for releases |

## Development setup

Requirements: **Go 1.27+**, **Node.js 24+**, **pnpm 10** (`corepack enable`), GNU make.

```bash
make demo            # build UI + binary, run with fake data on http://127.0.0.1:8787 (password: demo)
make dev             # in a second terminal: Next.js dev server on :3000, proxying /api to :8787
make test            # go vet + go test + script tests
make lint            # eslint + tsc + go vet
```

The UI talks only to `/api/*`; in dev `next.config.ts` rewrites that to `AGENT_URL`.

### Frontend dependencies

`web/` was generated with `create-next-app@latest`. The packages it installs
(`next`, `react`, `react-dom`, `tailwindcss`, `@tailwindcss/turbopack`,
`eslint`, `eslint-config-next`, `typescript`, `@types/*` for node/react) are
kept at the versions the generator chose and are upgraded **together**, ideally
by re-running the generator and diffing. Everything else may be bumped freely
(Dependabot groups them).

### Code style

- Go: `gofmt` (CI fails otherwise), `go vet` clean, table-driven tests where it makes sense.
- Web: `pnpm lint` (ESLint 9 flat config with the React Compiler rules) and `pnpm typecheck` must be clean.
- Shell: must pass `shellcheck`.
- Keep the dashboard usable on a phone and in every theme (including the light one).

## Pull requests

1. Fork and create a branch from `main`.
2. Keep PRs focused; describe *why* in the description.
3. Make sure CI is green.
4. UI changes: attach a screenshot.

## Releasing (maintainers)

Releases are fully automated from `VERSION.md`:

1. Bump `version:` in `VERSION.md` (semver, e.g. `1.1.0`).
2. Add a `### 1.1.0 — YYYY-MM-DD` section under `## Changelog` — it becomes the release notes.
3. Merge/push to `main`.

`release.yml` compares the version with the highest `vX.Y.Z` tag and releases
only if it is **strictly greater** (or if there are no tags yet). Pushes that
don't bump the version skip the release without failing.

Check the logic locally:

```bash
scripts/version.sh get                              # -> 1.0.0
git tag -l | scripts/version.sh should-release "$(scripts/version.sh get)"
scripts/version.sh notes 1.0.0                      # release notes preview
scripts/test-version.sh                             # unit tests
```
