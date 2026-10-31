import type { Severity, Level } from "./types";

export function fmtBytes(n: number | undefined | null, digits = 1): string {
  if (n == null || !isFinite(n)) return "–";
  const u = ["B", "KB", "MB", "GB", "TB", "PB"];
  let i = 0;
  let v = Math.abs(n);
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : v < 10 ? digits : v < 100 ? 1 : 0)} ${u[i]}`;
}

/** Bytes/sec → bits/sec, network style. */
export function fmtRate(bps: number | undefined | null): string {
  if (bps == null || !isFinite(bps)) return "–";
  let v = bps * 8;
  const u = ["bit/s", "kbit/s", "Mbit/s", "Gbit/s"];
  let i = 0;
  while (v >= 1000 && i < u.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

export function fmtNum(n: number | undefined | null): string {
  if (n == null || !isFinite(n)) return "–";
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1) + "k";
  return Math.round(n).toLocaleString("en-US");
}

export function fmtPct(n: number | undefined | null, d = 0): string {
  if (n == null || !isFinite(n)) return "–";
  return `${n.toFixed(d)}%`;
}

export function fmtDuration(sec: number): string {
  if (!isFinite(sec) || sec < 0) return "–";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${Math.floor(sec)}s`;
}

export function ago(ts: number, now = Date.now()): string {
  const s = Math.max(0, (now - ts) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function fmtTime(ts: number, withDate = false): string {
  const d = new Date(ts);
  const t = d.toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  if (!withDate) return t;
  return `${d.toLocaleDateString("en-GB", { day: "2-digit", month: "short" })} ${t}`;
}

export function fmtDateTime(ts: number): string {
  return new Date(ts).toLocaleString("en-GB", { day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

export function flagEmoji(cc?: string): string {
  if (!cc || cc.length !== 2) return "🌐";
  const A = 0x1f1e6;
  return String.fromCodePoint(A + cc.toUpperCase().charCodeAt(0) - 65, A + cc.toUpperCase().charCodeAt(1) - 65);
}

export function place(g?: { city?: string; country?: string; private?: boolean }): string {
  if (!g) return "Unknown";
  if (g.private) return "Private network";
  if (g.city && g.country) return `${g.city}, ${g.country}`;
  return g.country || "Unknown location";
}

export const sevOrder: Severity[] = ["critical", "high", "medium", "low", "info"];
/** Severity colours as CSS variables, so they follow the active theme. */
export const sevColor: Record<string, string> = {
  critical: "var(--c-crit)",
  high: "var(--c-danger)",
  medium: "var(--c-warn)",
  low: "var(--c-info)",
  info: "var(--c-muted)",
};
/** Palette key for each severity (for canvas/WebGL, which cannot use CSS variables). */
export const sevKey: Record<string, "crit" | "danger" | "warn" | "info" | "muted"> = { critical: "crit", high: "danger", medium: "warn", low: "info", info: "muted" };
export const sevLabel: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
export const sevHelp: Record<string, string> = {
  critical: "Act now — something may already be compromised or a dangerous attack is underway.",
  high: "A real attack attempt. Worth blocking the source and checking your software is up to date.",
  medium: "Suspicious activity that is usually automated. Keep an eye on it.",
  low: "Common internet background noise. Usually safe to ignore.",
  info: "For your information only.",
};

export const levelColor: Record<Level, string> = { good: "var(--c-ok)", warn: "var(--c-warn)", bad: "var(--c-danger)" };

export function pctLevel(p: number, warn = 75, bad = 90): Level {
  return p >= bad ? "bad" : p >= warn ? "warn" : "good";
}

export function statusColor(s: number): string {
  if (s >= 500) return "var(--c-danger)";
  if (s >= 400) return "var(--c-warn)";
  if (s >= 300) return "var(--c-info)";
  if (s >= 200) return "var(--c-ok)";
  return "var(--c-muted)";
}

export function statusText(s: number): string {
  const m: Record<number, string> = {
    200: "OK", 201: "Created", 204: "No content", 301: "Moved permanently", 302: "Redirect", 304: "Not modified (cached)",
    400: "Bad request", 401: "Login required", 403: "Forbidden", 404: "Not found", 405: "Method not allowed", 408: "Timeout",
    413: "Too large", 429: "Too many requests", 444: "Connection closed (nginx)", 499: "Client gave up", 500: "Server error",
    502: "Bad gateway", 503: "Unavailable", 504: "Gateway timeout",
  };
  return m[s] || (s >= 500 ? "Server error" : s >= 400 ? "Client error" : s >= 300 ? "Redirect" : s >= 200 ? "Success" : "");
}

export function threatTypeLabel(t: string): string {
  const m: Record<string, string> = {
    ssh_bruteforce: "SSH password guessing",
    ssh_success_after_fail: "Login after failures",
    ssh_login: "New SSH login",
    sudo_failed: "Failed sudo",
    port_scan: "Port scan",
    syn_flood: "SYN flood",
    http_flood: "Request flood",
    http_probing: "Probing (many 404s)",
    traffic_spike: "Traffic spike",
    http_sqli: "SQL injection",
    http_xss: "Cross-site scripting",
    http_traversal: "Path traversal",
    http_rce: "Command execution",
    http_scanner_path: "Vulnerability scan",
    http_bad_bot: "Hacking tool",
    http_bad_method: "Unusual HTTP method",
  };
  return m[t] || t.replace(/_/g, " ");
}

export function shortUA(ua: string): string {
  if (!ua || ua === "-") return "—";
  const bots = ua.match(/(Googlebot|bingbot|YandexBot|AhrefsBot|SemrushBot|DuckDuckBot|Baiduspider|facebookexternalhit|Twitterbot|sqlmap|Nikto|nmap|masscan|zgrab|Nuclei|python-requests|curl|Wget|Go-http-client|okhttp|UptimeRobot|Expanse|CensysInspect)[^\s;)]*/i);
  if (bots) return bots[0];
  const browser = ua.match(/(Edg|OPR|Firefox|Chrome|Safari)\/[\d.]+/);
  const os = ua.match(/(Windows|Android|iPhone|iPad|Mac OS X|Linux)/);
  if (browser) {
    let b = browser[1] === "Edg" ? "Edge" : browser[1] === "OPR" ? "Opera" : browser[1];
    if (b === "Safari" && /Chrome/.test(ua)) b = "Chrome";
    return `${b}${os ? " · " + (os[1] === "Mac OS X" ? "macOS" : os[1]) : ""}`;
  }
  return ua.length > 32 ? ua.slice(0, 32) + "…" : ua;
}
