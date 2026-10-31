"use client";

import { Pause, Play, Search, ShieldAlert, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { RankBars, TimeBars } from "@/components/charts";
import { Card, Empty, GeoTag, InfoTip, IPLink, PageHeader, Pill, Segmented, Spinner, Stat } from "@/components/ui";
import { useUI } from "@/components/uictx";
import { api } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { flagEmoji, fmtBytes, fmtNum, sevColor, shortUA, statusColor, statusText } from "@/lib/format";
import type { FlagInfo, HTTPRequest, KV } from "@/lib/types";

type Stats = {
  total: number; threats: number; errors: number; bytes: number; avg_latency: number; unique_ips: number;
  status: KV[]; methods: KV[]; top_paths: KV[]; top_ips: KV[]; top_uas: KV[]; countries: KV[];
  series: { ts: number; total: number; ok: number; redir: number; client: number; server: number; threats: number }[];
};

type Filters = { ip: string; status: string; method: string; q: string; threats: boolean };
const empty: Filters = { ip: "", status: "", method: "", q: "", threats: false };

function matches(r: HTTPRequest, f: Filters) {
  if (f.ip && r.ip !== f.ip) return false;
  if (f.method && r.method !== f.method) return false;
  if (f.threats && !r.flags?.length) return false;
  if (f.status) {
    if (f.status.endsWith("xx")) {
      if (Math.floor(r.status / 100) !== Number(f.status[0])) return false;
    } else if (String(r.status) !== f.status) return false;
  }
  if (f.q) {
    const s = f.q.toLowerCase();
    if (![r.path, r.query, r.ua, r.host, r.referer].some((x) => x?.toLowerCase().includes(s))) return false;
  }
  return true;
}

export default function RequestsPage() {
  const live = useLive();
  const { openRequest, openIP } = useUI();
  const [f, setF] = useState<Filters>(empty);
  const [q, setQ] = useState("");
  const [paused, setPaused] = useState(false);
  const [frozen, setFrozen] = useState<HTTPRequest[] | null>(null);
  const [range, setRange] = useState("24h");
  const [base, setBase] = useState<HTTPRequest[] | null>(null);
  const [flags, setFlags] = useState<Record<string, FlagInfo>>({});
  const [older, setOlder] = useState<HTTPRequest[]>([]);
  const [loadingMore, setLoadingMore] = useState(false);
  const { data: stats } = useApi<{ stats: Stats }>(`/api/requests/stats?range=${range}`, { interval: 30000 });

  useEffect(() => {
    const t = setTimeout(() => setF((x) => ({ ...x, q })), 300);
    return () => clearTimeout(t);
  }, [q]);

  // New filter → drop the old result set (adjusting state during render).
  const [loadedFor, setLoadedFor] = useState(f);
  if (loadedFor !== f) {
    setLoadedFor(f);
    setBase(null);
    setOlder([]);
  }
  useEffect(() => {
    const p = new URLSearchParams({ limit: "200" });
    if (f.ip) p.set("ip", f.ip);
    if (f.status) p.set("status", f.status);
    if (f.method) p.set("method", f.method);
    if (f.q) p.set("q", f.q);
    if (f.threats) p.set("threats", "1");
    api<{ requests: HTTPRequest[] | null; flags: Record<string, FlagInfo> }>(`/api/requests?${p}`).then((d) => {
      setBase(d.requests || []);
      setFlags(d.flags || {});
    }).catch(() => setBase([]));
  }, [f]);

  const rows = useMemo(() => {
    const seen = new Set<number>();
    const out: HTTPRequest[] = [];
    const src = paused && frozen ? frozen : live.requests;
    for (const r of [...src.filter((r) => matches(r, f)), ...(base || []), ...older]) {
      if (seen.has(r.id)) continue;
      seen.add(r.id);
      out.push(r);
    }
    return out.sort((a, b) => b.ts - a.ts || b.id - a.id);
  }, [live.requests, frozen, paused, base, older, f]);

  const loadMore = async () => {
    const last = rows[rows.length - 1];
    if (!last) return;
    setLoadingMore(true);
    const p = new URLSearchParams({ limit: "200", before: String(last.ts) });
    if (f.ip) p.set("ip", f.ip);
    if (f.status) p.set("status", f.status);
    if (f.method) p.set("method", f.method);
    if (f.q) p.set("q", f.q);
    if (f.threats) p.set("threats", "1");
    try {
      const d = await api<{ requests: HTTPRequest[] | null }>(`/api/requests?${p}`);
      setOlder((o) => [...o, ...(d.requests || [])]);
    } finally {
      setLoadingMore(false);
    }
  };

  const s = stats?.stats;
  const active = f.ip || f.status || f.method || f.q || f.threats;

  return (
    <div className="space-y-5">
      <PageHeader title="Web requests" desc="Every visit to your websites, read live from the nginx / Apache / Caddy access logs. Suspicious requests are highlighted in red — click any row for the full story."
        right={<Segmented value={range} onChange={setRange} options={[{ value: "1h", label: "1h" }, { value: "24h", label: "24h" }, { value: "7d", label: "7d" }]} />} />

      {s ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          <Stat label="Requests" value={fmtNum(s.total)} info="Total pages, images and API calls served in this time range." />
          <Stat label="Unique visitors" value={fmtNum(s.unique_ips)} info="Number of different IP addresses. One person can have several, and many people can share one." />
          <Stat label="Suspicious" value={fmtNum(s.threats)} color={s.threats ? sevColor.high : undefined} onClick={() => setF({ ...empty, threats: true })}
            info="Requests that look like hacking attempts or automated scanners. Click to show only these." />
          <Stat label="Server errors (5xx)" value={fmtNum(s.errors)} color={s.errors ? "var(--c-warn)" : undefined} onClick={() => setF({ ...empty, status: "5xx" })}
            info="Your site failed to answer properly. A few are normal; many mean your app is broken or overloaded." />
          <Stat label="Data sent" value={fmtBytes(s.bytes)} info="Total size of all responses." />
          <Stat label="Avg response time" value={s.avg_latency ? `${s.avg_latency.toFixed(0)} ms` : "—"} info="How fast your server answered on average. Needs the request time in your log format; under 300 ms feels snappy." />
        </div>
      ) : <Spinner />}

      {s && (
        <div className="grid gap-5 xl:grid-cols-3">
          <Card title="Requests over time" className="xl:col-span-2" info="Green = OK, blue = redirect, amber = visitor error (e.g. page not found), red = your server failed.">
            <TimeBars data={s.series} height={230} series={[
              { key: "ok", name: "OK (2xx)", color: "var(--c-ok)" }, { key: "redir", name: "Redirect (3xx)", color: "var(--c-accent2)" },
              { key: "client", name: "Not found / denied (4xx)", color: "var(--c-warn)" }, { key: "server", name: "Server error (5xx)", color: "var(--c-danger)" },
            ]} />
          </Card>
          <Card title="Status codes" info="The result code your server sent back. Click to filter.">
            <RankBars items={s.status.map((k) => ({ key: k.key, label: <><b style={{ color: statusColor(Number(k.key)) }}>{k.key}</b> <span className="text-muted">{statusText(Number(k.key))}</span></>, value: k.count, color: statusColor(Number(k.key)) }))}
              onClick={(k) => setF({ ...empty, status: k })} />
          </Card>
          <Card title="Most requested pages" info="Click to search for this path.">
            <RankBars items={s.top_paths.slice(0, 10).map((k) => ({ key: k.key, label: <span className="mono text-[0.875rem]">{k.key}</span>, value: k.count }))} onClick={(k) => { setQ(k); }} />
          </Card>
          <Card title="Busiest visitors" info="IP addresses that made the most requests. Click to see everything about one.">
            <RankBars items={s.top_ips.slice(0, 10).map((k) => ({ key: k.key, label: <><span className="mono text-[0.875rem]">{k.key}</span> <span className="text-muted">{k.extra}</span></>, value: k.count }))} onClick={(k) => openIP(k)} />
          </Card>
          <Card title="Countries & browsers" info="Where visitors come from, and which software they used (bots included).">
            <RankBars items={s.countries.slice(0, 5).map((k) => ({ key: k.key, label: <>{flagEmoji(k.key)} {k.extra || k.key}</>, value: k.count }))} color="var(--c-crit)" />
            <div className="my-3 border-t border-line" />
            <RankBars items={s.top_uas.slice(0, 5).map((k) => ({ key: k.key, label: shortUA(k.key), value: k.count }))} color="var(--c-info)" />
          </Card>
        </div>
      )}

      <Card bodyClass="p-0" title={<span className="flex items-center gap-2">{!paused && <span className="pulse h-2 w-2 rounded-full bg-good" />} Request feed</span>}
        info="Newest first. Rows update live as visitors arrive. Pause to read without the list moving."
        right={
          <button className="btn" onClick={() => { if (!paused) setFrozen(live.requests); setPaused(!paused); }}>
            {paused ? <><Play size={13} /> Resume</> : <><Pause size={13} /> Pause</>}
          </button>
        }>
        <div className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
          <div className="relative">
            <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input className="input w-56 !pl-7" placeholder="Search path, user agent, host…" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <input className="input mono w-40" placeholder="IP address" value={f.ip} onChange={(e) => setF({ ...f, ip: e.target.value.trim() })} />
          <select className="input" value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })}>
            <option value="">Any status</option><option value="2xx">2xx OK</option><option value="3xx">3xx Redirect</option>
            <option value="4xx">4xx Client error</option><option value="5xx">5xx Server error</option>
            <option value="404">404 only</option><option value="403">403 only</option>
          </select>
          <select className="input" value={f.method} onChange={(e) => setF({ ...f, method: e.target.value })}>
            <option value="">Any method</option>{["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"].map((m) => <option key={m}>{m}</option>)}
          </select>
          <label className="flex cursor-pointer items-center gap-1.5 text-[0.9062rem]">
            <input type="checkbox" checked={f.threats} onChange={(e) => setF({ ...f, threats: e.target.checked })} />
            <ShieldAlert size={13} className="text-bad" /> Suspicious only
          </label>
          {active && <button className="btn" onClick={() => { setF(empty); setQ(""); }}><X size={13} /> Clear</button>}
          <span className="ml-auto text-[0.875rem] text-muted">{rows.length} shown</span>
        </div>
        {base === null ? <Spinner /> : rows.length === 0 ? (
          <Empty>{active ? "No requests match these filters." : "No web requests yet. Point access_logs in the config at your web server's log (e.g. /var/log/nginx/access.log)."}</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="tbl">
              <thead><tr><th>Time</th><th>Visitor</th><th>Request</th><th>Result</th><th className="text-right">Size</th><th>Software</th><th>Warning</th></tr></thead>
              <tbody>
                {rows.slice(0, 600).map((r) => {
                  const bad = !!r.flags?.length;
                  const worst = bad ? r.flags!.map((x) => flags[x]?.severity || "low").sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a) - ["critical", "high", "medium", "low", "info"].indexOf(b))[0] : null;
                  return (
                    <tr key={r.id} onClick={() => openRequest(r.id)} className={`cursor-pointer ${bad ? "bg-bad/[.06] hover:!bg-bad/10" : ""}`}>
                      <td className="whitespace-nowrap text-muted">{new Date(r.ts).toLocaleTimeString("en-GB")}</td>
                      <td className="whitespace-nowrap" onClick={(e) => e.stopPropagation()}><IPLink ip={r.ip} threat={bad} /> <GeoTag geo={r.geo} short /></td>
                      <td className="max-w-[420px]">
                        <div className="truncate mono text-[0.875rem]"><span className="font-semibold text-muted">{r.method}</span> {r.path}{r.query ? <span className="text-muted">?{r.query}</span> : null}</div>
                        {r.host && <div className="truncate text-[0.8125rem] text-muted">{r.host}</div>}
                      </td>
                      <td className="whitespace-nowrap"><span className="font-semibold" style={{ color: statusColor(r.status) }}>{r.status}</span> <span className="text-[0.8438rem] text-muted">{statusText(r.status)}</span></td>
                      <td className="text-right tabular-nums text-muted">{fmtBytes(r.bytes)}</td>
                      <td className="max-w-[160px] truncate text-[0.875rem] text-muted" title={r.ua}>{shortUA(r.ua)}</td>
                      <td>
                        {bad && (
                          <span className="flex items-center gap-1">
                            <Pill color={sevColor[worst || "low"]}>{flags[r.flags![0]]?.title || r.flags![0]}</Pill>
                            {r.flags!.length > 1 && <span className="text-[0.8125rem] text-muted">+{r.flags!.length - 1}</span>}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <div className="flex justify-center p-3">
              <button className="btn" onClick={loadMore} disabled={loadingMore}>{loadingMore ? "Loading…" : "Load older requests"}</button>
            </div>
          </div>
        )}
      </Card>
      <p className="flex items-center gap-1 text-[0.8438rem] text-muted">Tip: click any row to see every field, the raw log line and what else that visitor did. <InfoTip>Detection runs on the server: SQL injection, cross-site scripting, path traversal, scanner paths like /wp-login.php or /.env, known attack tools and sudden request floods.</InfoTip></p>
    </div>
  );
}
