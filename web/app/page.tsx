"use client";

import { AlertTriangle, ArrowDownLeft, ArrowUpRight, Ban, Globe2, KeyRound, Network, ScrollText, ShieldAlert } from "lucide-react";
import Link from "next/link";
import { useMemo } from "react";
import { TimeArea } from "@/components/charts";
import { Card, Dot, Empty, Gauge, GeoTag, IPLink, PageHeader, SevBadge, Stat, PageSkeleton } from "@/components/ui";
import { useUI } from "@/components/uictx";
import { WorldMap } from "@/components/worldmap";
import { glow } from "@/lib/theme";
import { Counters, DefconMeter, Radar } from "@/components/hud";
import { threatLevel, useThreatFeed } from "@/lib/threat";
import { Radar as RadarIcon } from "lucide-react";
import { useApi } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { ago, fmtBytes, fmtDuration, fmtNum, fmtRate, levelColor, pctLevel, sevColor, statusColor } from "@/lib/format";
import type { Overview } from "@/lib/types";

export default function OverviewPage() {
  const { data, error } = useApi<Overview>("/api/overview", { interval: 15000 });
  const live = useLive();
  const { openIP, openRequest } = useUI();
  const feed = useThreatFeed();
  const sys = live.system || data?.system || null;
  const net = live.network || data?.network || null;

  const threats = useMemo(() => {
    const m = new Map<number, NonNullable<Overview["threats"]>[number]>();
    for (const t of data?.threats || []) m.set(t.id, t);
    for (const t of live.threats) m.set(t.id, t);
    return [...m.values()].sort((a, b) => b.last_seen - a.last_seen).slice(0, 7);
  }, [data?.threats, live.threats]);

  const traffic = live.netHistory.length > 5 ? live.netHistory.map((p) => ({ ts: p.ts, rx: p.rx, tx: p.tx })) : (data?.metrics || []).map((m) => ({ ts: m.ts, rx: m.rx, tx: m.tx }));

  if (error && !data) return <Empty>Could not load: {error}</Empty>;
  if (!data || !sys) return <PageSkeleton />;

  const h = data.health;
  const disk = sys.disks.reduce((a, d) => (d.percent > a.percent ? d : a), sys.disks[0] || { percent: 0, mount: "/", used: 0, total: 0 });
  const tc = data.threat_counts || ({} as Overview["threat_counts"]);
  const serious = (tc.critical || 0) + (tc.high || 0);

  return (
    <div className="space-y-5">
      <PageHeader title={`Overview · ${data.hostname}`} desc={<>{sys.os} · up {fmtDuration(sys.uptime)} · {sys.cpu.cores} CPU cores · {fmtBytes(sys.memory.total)} RAM</>} />

      <Link href="/map" className="card hud-corner map-stage group relative block overflow-hidden transition hover:border-neon/60">
        <div className="grid items-center gap-5 p-5 md:grid-cols-[200px_1fr] xl:grid-cols-[200px_1fr_320px]">
          <Radar threats={feed} size={190} />
          <div>
            <div className="mono text-[0.8125rem] text-muted">{"// command center"}</div>
            <div className="mt-1 flex items-center gap-2 font-hud text-[1.5rem] font-bold uppercase tracking-[.14em] text-neon neon">
              <RadarIcon size={22} /> Live Map
            </div>
            <p className="mt-2 max-w-lg text-[0.9375rem] leading-relaxed text-muted">
              See every computer connected to your server on a rotating 3D globe or a live network graph — attackers glow red, blocked
              addresses are crossed out, and a live log scrolls every request and login as it happens.
            </p>
            <span className="btn btn-primary mt-4 inline-flex">Enter command center →</span>
          </div>
          <div className="space-y-3 md:col-span-2 xl:col-span-1">
            <DefconMeter level={threatLevel(feed)} />
            <Counters blocked={live.blocked?.length ?? data.blocked ?? 0} />
          </div>
        </div>
      </Link>

      <section className="card overflow-hidden">
        <div className="flex flex-col gap-5 p-5 md:flex-row md:items-center">
          <div className="relative flex h-28 w-28 shrink-0 items-center justify-center">
            <svg viewBox="0 0 100 100" className="absolute inset-0 -rotate-90">
              <circle cx="50" cy="50" r="44" fill="none" stroke="var(--c-line)" strokeWidth="9" />
              <circle cx="50" cy="50" r="44" fill="none" stroke={levelColor[h.level]} strokeWidth="9"
                style={{ filter: `drop-shadow(0 0 calc(4px * var(--glow)) ${levelColor[h.level]})` }} strokeLinecap="round"
                strokeDasharray={`${(h.score / 100) * 276.5} 276.5`} />
            </svg>
            <div className="text-center">
              <div className="mono text-[2rem] font-bold leading-none" style={{ color: levelColor[h.level], textShadow: glow(levelColor[h.level], 12) }}>{h.score}</div>
              <div className="mt-1 text-[0.75rem] font-medium uppercase tracking-[.08em] text-muted">health</div>
            </div>
          </div>
          <div className="min-w-0 flex-1">
            <div className="text-[1.1875rem] font-semibold">{h.summary}</div>
            <ul className="mt-2 grid gap-1.5 md:grid-cols-2">
              {h.messages.map((m, i) => (
                <li key={i} className="flex items-start gap-2 text-[0.9375rem]">
                  <span className="mt-1.5"><Dot level={m.level} /></span>
                  <span><span className="text-muted">{m.area}:</span> {m.text}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
        <Stat label="Download now" icon={<ArrowDownLeft size={13} />} value={fmtRate(net?.total_rx_bps)} info="How fast data is flowing INTO your server right now (all network cards together)." />
        <Stat label="Upload now" icon={<ArrowUpRight size={13} />} value={fmtRate(net?.total_tx_bps)} info="How fast your server is SENDING data right now — e.g. serving web pages." />
        <Stat label="Open connections" icon={<Network size={13} />} value={fmtNum(net?.conn_count)} info="How many computers are talking to your server at this moment." />
        <Stat label="Web requests (1h)" icon={<ScrollText size={13} />} value={fmtNum(data.requests_hour)} sub={`${fmtNum(data.requests_day)} in 24h`} info="Pages and files your web server answered, read from its access log." />
        <Stat label="Failed logins (24h)" icon={<KeyRound size={13} />} value={fmtNum(data.failed_logins)} color={data.failed_logins > 50 ? "var(--c-warn)" : undefined}
          info="Wrong-password attempts on SSH. Hundreds per day is normal background noise on the internet; a sudden jump means someone targets you." />
        <Stat label="Serious threats (24h)" icon={<ShieldAlert size={13} />} value={serious} color={serious ? sevColor.high : "var(--c-ok)"} sub={`${data.blocked} IPs blocked`}
          info="High or critical security events. Click Security for the full story and one-click blocking." />
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Server resources" info="The four things that slow a server down when they run out. Green is fine, amber means keep an eye on it, red needs action." className="xl:col-span-1">
          <div className="grid grid-cols-2 gap-y-3">
            <Gauge pct={sys.cpu.usage} label="CPU" sub={`load ${sys.load[0].toFixed(2)}`} level={pctLevel(sys.cpu.usage, 70, 90)} />
            <Gauge pct={sys.memory.percent} label="Memory" sub={`${fmtBytes(sys.memory.used)} / ${fmtBytes(sys.memory.total)}`} level={pctLevel(sys.memory.percent, 80, 92)} />
            <Gauge pct={disk.percent} label={`Disk ${disk.mount}`} sub={`${fmtBytes(disk.used)} / ${fmtBytes(disk.total)}`} level={pctLevel(disk.percent, 80, 92)} />
            <Gauge pct={sys.memory.swap_percent} label="Swap" sub={sys.memory.swap_total ? fmtBytes(sys.memory.swap_used) : "not set up"} level={pctLevel(sys.memory.swap_percent, 50, 80)} />
          </div>
          <Link href="/system" className="mt-3 block text-center text-[0.9062rem] text-accent hover:underline">Processes, services and history →</Link>
        </Card>

        <Card title="Network traffic" info="Live speed of data coming in (download) and going out (upload). Spikes are normal during backups or busy times." className="xl:col-span-2"
          right={<Link href="/network" className="text-[0.875rem] text-accent hover:underline">Details →</Link>}>
          <TimeArea data={traffic} height={250} fmt={(v) => fmtRate(v)} legend
            series={[{ key: "rx", name: "Download", color: "var(--c-accent2)" }, { key: "tx", name: "Upload", color: "var(--c-ok)" }]} />
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-5">
        <Card title="Who is connected, worldwide" info="Each dot is a place your server is talking to right now. Red dots are addresses that did something suspicious." className="xl:col-span-3" bodyClass="p-2"
          right={<span className="flex items-center gap-1 text-[0.875rem] text-muted"><Globe2 size={13} /> {net?.countries.length || 0} countries</span>}>
          <WorldMap points={net?.geo || []} server={net?.server} countryStats={net?.countries} onSelect={(p) => p.ips[0] && openIP(p.ips[0])} />
        </Card>
        <Card title="Latest security events" info="Things that looked like attacks. Click an IP to see everything it did and to block it." className="xl:col-span-2" bodyClass="p-0"
          right={<Link href="/security" className="text-[0.875rem] text-accent hover:underline">All threats →</Link>}>
          {threats.length === 0 ? <Empty icon={<ShieldAlert />}>No threats detected. Nice and quiet.</Empty> : (
            <ul className="divide-y divide-line">
              {threats.map((t) => (
                <li key={t.id} className="flex cursor-pointer items-start gap-3 px-4 py-2.5 hover:bg-panel2" onClick={() => openIP(t.ip)}>
                  <AlertTriangle size={15} className="mt-0.5 shrink-0" style={{ color: sevColor[t.severity] }} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-[0.9375rem] font-medium">{t.title}</span>
                      {t.blocked && <Ban size={12} className="shrink-0 text-muted" />}
                    </div>
                    <div className="flex items-center gap-2 text-[0.875rem] text-muted">
                      <span className="mono">{t.ip}</span> <GeoTag geo={t.geo} short /> · {ago(t.last_seen)}{t.count > 1 ? ` · ×${t.count}` : ""}
                    </div>
                  </div>
                  <SevBadge sev={t.severity} />
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-2">
        <Card title="Live web requests" info="The newest visits to your websites, straight from the web server log. Click one for every detail." bodyClass="p-0"
          right={<Link href="/requests" className="text-[0.875rem] text-accent hover:underline">Open feed →</Link>}>
          {live.requests.length === 0 ? <Empty>Waiting for web requests… (needs a readable nginx/apache/caddy access log)</Empty> : (
            <table className="tbl">
              <tbody>
                {live.requests.slice(0, 9).map((r) => (
                  <tr key={r.id} className={`cursor-pointer ${r.flags?.length ? "bg-bad/[.06]" : ""}`} onClick={() => openRequest(r.id)}>
                    <td className="w-14 text-muted">{new Date(r.ts).toLocaleTimeString("en-GB")}</td>
                    <td className="w-12"><span className="font-semibold" style={{ color: statusColor(r.status) }}>{r.status}</span></td>
                    <td className="max-w-[260px] truncate mono text-[0.875rem]"><span className="text-muted">{r.method}</span> {r.path}</td>
                    <td className="text-right"><span onClick={(e) => e.stopPropagation()}><IPLink ip={r.ip} threat={!!r.flags?.length} /></span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
        <Card title="Top talkers" info="The outside addresses using the most bandwidth with your server right now." bodyClass="p-0"
          right={<Link href="/network" className="text-[0.875rem] text-accent hover:underline">Network →</Link>}>
          {!net?.talkers.length ? <Empty>No outside connections right now.</Empty> : (
            <table className="tbl">
              <thead><tr><th>Address</th><th>Where</th><th>Program</th><th className="text-right">Speed</th></tr></thead>
              <tbody>
                {net.talkers.slice(0, 8).map((t) => (
                  <tr key={t.ip}>
                    <td><IPLink ip={t.ip} threat={t.threat} blocked={t.blocked} /></td>
                    <td><GeoTag geo={t.geo} short /></td>
                    <td className="text-muted">{(t.processes || []).slice(0, 2).join(", ") || "—"}</td>
                    <td className="text-right tabular-nums">{fmtRate(t.rate_in + t.rate_out)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>

      {data.statuses.some((s) => s.state !== "ok") && (
        <Card title="What I can and can't see" info="Some data sources need extra permissions or software. The rest of the dashboard still works." bodyClass="p-4">
          <ul className="grid gap-2 md:grid-cols-2">
            {data.statuses.filter((s) => s.state !== "ok").map((s) => (
              <li key={s.name} className="flex items-start gap-2 text-[0.9062rem]">
                <span className="mt-1.5"><Dot level={s.state === "off" ? "off" : "warn"} /></span>
                <span><b>{s.label}</b> <span className="text-muted">— {s.message}</span></span>
              </li>
            ))}
          </ul>
          <Link href="/settings" className="mt-3 inline-block text-[0.9062rem] text-accent hover:underline">How to fix →</Link>
        </Card>
      )}
    </div>
  );
}
