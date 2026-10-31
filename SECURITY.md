# Security Policy

myOwl runs with high privileges on servers that are exposed to the internet,
so we take security reports seriously.

## Supported versions

Only the **latest release** receives security fixes. Please upgrade before
reporting (`curl … install.sh | sudo bash` re-installs the latest release and
keeps your config and data).

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting instead:
repository → **Security** → **Report a vulnerability**
(`https://github.com/OWNER/myowl/security/advisories/new`).

Include:

- the myOwl version (`myowl version`) and install method (install.sh / Docker / source)
- a description of the issue and its impact
- steps to reproduce or a proof of concept
- any suggested fix

You should get an acknowledgement within **72 hours** and a status update within
**7 days**. Once a fix is released we will publish an advisory and credit you
(unless you prefer to stay anonymous).

## Scope

In scope: the `myowl` binary (agent + embedded dashboard), install.sh, the
Docker image and the release workflow.

Out of scope: vulnerabilities that require an attacker to already have root on
the monitored server, missing hardening on a deployment that ignores the
README's "Security hardening" section (e.g. exposing plain HTTP to the
internet), and findings from automated scanners without a demonstrated impact.

## Hardening reminders

- Prefer `listen: 127.0.0.1:8787` behind a TLS reverse proxy (Caddy/nginx) or an SSH tunnel.
- Use a long, unique password; sessions are HTTP-only cookies.
- Set `cookie_secure: true` and `trust_proxy: true` only when a proxy terminates HTTPS in front of myOwl.
- Keep the binary up to date.
