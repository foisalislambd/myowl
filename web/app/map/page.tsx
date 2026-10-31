"use client";

import { Activity, Globe2, Maximize2, Minimize2, Network, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useApi, useNow } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { useFx } from "@/lib/fx";
import { threatLevel, useThreatFeed } from "@/lib/threat";
import { ago, flagEmoji, fmtDateTime, fmtRate, place, sevColor, threatTypeLabel } from "@/lib/format";
import type { BlockedIP, FirewallStatus, IPDetail, Listener, NetworkSnapshot, Talker, Threat } from "@/lib/types";
import { Globe3D, type GlobeSource } from "@/components/globe";
import { NodeGraph, type GEdge, type GNode } from "@/components/nodegraph";
import { Counters, DefconMeter, EventLog, HexTicker, HudStat, Radar } from "@/components/hud";
import { BlockButton } from "@/components/block";
import { Clock, Glitch, Typewriter } from "@/components/fx";
import { useUI } from "@/components/uictx";
import { SevBadge, Spinner } from "@/components/ui";
import { C, glow, mix, useTheme } from "@/lib/theme";

type View = "globe" | "graph";
type Sel =
  | { kind: "ip"; ip: string; talker?: Talker; label?: string }
  | { kind: "place"; label: string; ips: string[] }
  | { kind: "service"; name: string; listeners: Listener[] }
  | { kind: "user"; user: string; tty: string; host: string; login: number; geo?: { country?: string; city?: string; cc?: string } };

export default function LiveMapPage() {
  const now = useNow(30000);
  const live = useLive();
  const fx = useFx();
  const theme = useTheme();
  const { openIP, demo } = useUI();
  const threats = useThreatFeed();
  const tl = threatLevel(threats);
  const netApi = useApi<{ network: NetworkSnapshot | null }>(live.network ? null : "/api/network");
  const fw = useApi<{ blocked: BlockedIP[] | null; status: FirewallStatus }>("/api/firewall", { interval: 30000 });
  const net = live.network || netApi.data?.network || null;
  const blocked = useMemo(() => live.blocked || fw.data?.blocked || [], [live.blocked, fw.data?.blocked]);
  const [view, setView] = useState<View>("globe");
  const [sel, setSel] = useState<Sel | null>(null);

  // ---- wall mode (fullscreen, sidebar hidden)
  const { wall, setWall } = fx;
  const toggleWall = useCallback(() => {
    if (!wall) {
      setWall(true);
      document.documentElement.requestFullscreen?.().catch(() => {});
    } else {
      setWall(false);
      if (document.fullscreenElement) document.exitFullscreen?.().catch(() => {});
    }
  }, [wall, setWall]);
  useEffect(() => {
    const onFs = () => { if (!document.fullscreenElement) setWall(false); };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSel(null);
      if (e.key === "f" && !(e.target instanceof HTMLInputElement)) toggleWall();
      if (e.key === "g" && !(e.target instanceof HTMLInputElement)) setView((v) => (v === "globe" ? "graph" : "globe"));
    };
    document.addEventListener("fullscreenchange", onFs);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("fullscreenchange", onFs);
      window.removeEventListener("keydown", onKey);
    };
  }, [setWall, toggleWall]);
  useEffect(() => () => setWall(false), [setWall]);

  // ---- derived sets
  const blockedSet = useMemo(() => new Set(blocked.map((b) => b.ip)), [blocked]);
  const recentThreats = useMemo(() => threats.filter((t) => now - t.last_seen < 6 * 3600000), [threats, now]);
  const threatByIP = useMemo(() => {
    const m = new Map<string, Threat>();
    for (const t of recentThreats) {
      const o = m.get(t.ip);
      if (!o || rank(t.severity) > rank(o.severity)) m.set(t.ip, t);
    }
    return m;
  }, [recentThreats]);

  // ---- globe sources
  const server = net?.server?.lat != null ? { lat: net.server.lat!, lon: net.server.lon!, city: net.server.city } : { lat: 50.1, lon: 8.7, city: "server" };
  const sources = useMemo<GlobeSource[]>(() => {
    if (!net) return [];
    const out: GlobeSource[] = [];
    const seen = new Set<string>();
    const maxRate = Math.max(1, ...(net.talkers || []).map((t) => t.rate_in + t.rate_out));
    for (const t of net.talkers || []) {
      if (t.geo?.lat == null || t.geo?.lon == null || t.geo.private) continue;
      seen.add(t.ip);
      const isBlocked = t.blocked || blockedSet.has(t.ip);
      const isThreat = t.threat || threatByIP.has(t.ip);
      out.push({ id: t.ip, ip: t.ip, lat: t.geo.lat, lon: t.geo.lon, label: `${t.ip} · ${place(t.geo)} · ${fmtRate(t.rate_in + t.rate_out)}`, kind: isBlocked ? "blocked" : isThreat ? "threat" : "normal", weight: (t.rate_in + t.rate_out) / maxRate });
    }
    for (const [ip, t] of threatByIP) {
      if (seen.has(ip) || t.geo?.lat == null || t.geo?.lon == null) continue;
      seen.add(ip);
      out.push({ id: ip, ip, lat: t.geo.lat, lon: t.geo.lon!, label: `${ip} · ${place(t.geo)} · ${t.title}`, kind: t.blocked || blockedSet.has(ip) ? "blocked" : "threat", weight: 0.4 });
    }
    for (const b of blocked) {
      if (seen.has(b.ip) || b.geo?.lat == null || b.geo?.lon == null) continue;
      seen.add(b.ip);
      out.push({ id: b.ip, ip: b.ip, lat: b.geo.lat, lon: b.geo.lon!, label: `${b.ip} · ${place(b.geo)} · blocked`, kind: "blocked", weight: 0.1 });
    }
    for (const g of net.geo || []) {
      if (g.ips?.some((ip) => seen.has(ip))) continue;
      out.push({ id: "geo:" + g.city + g.cc, lat: g.lat, lon: g.lon, label: `${g.city || g.country} · ${g.ips?.length || 0} IPs · ${fmtRate(g.rate)}`, kind: g.threat ? "threat" : "normal", weight: Math.min(1, g.rate / maxRate) });
    }
    return out;
  }, [net, blocked, blockedSet, threatByIP]);

  // ---- node graph
  const curSessions = live.sessions?.current;
  const hostname = live.system?.hostname;
  const graph = useMemo(() => buildGraph(net, curSessions || [], threatByIP, blockedSet, hostname), [net, curSessions, threatByIP, blockedSet, hostname]);

  const selectSource = useCallback((s: GlobeSource) => {
    if (s.ip) setSel({ kind: "ip", ip: s.ip, talker: net?.talkers?.find((t) => t.ip === s.ip), label: s.label });
    else {
      const g = net?.geo?.find((x) => "geo:" + x.city + x.cc === s.id);
      setSel({ kind: "place", label: s.label, ips: g?.ips || [] });
    }
  }, [net]);
  const selectNode = useCallback((n: GNode | null) => {
    if (!n) return setSel(null);
    const d = n.data as Sel | undefined;
    if (d) setSel(d);
  }, []);
  const selId = sel ? (sel.kind === "ip" ? "ip:" + sel.ip : sel.kind === "service" ? "svc:" + sel.name : sel.kind === "user" ? "user:" + sel.user + "@" + sel.tty : null) : null;

  const nThreat = sources.filter((s) => s.kind === "threat").length;
  const nNormal = sources.filter((s) => s.kind === "normal").length;
  const nBlocked = sources.filter((s) => s.kind === "blocked").length;
  const host = live.system?.hostname || "…";

  return (
    <div className={`flex flex-col gap-3 ${wall ? "h-screen p-3" : "lg:h-[calc(100vh-96px)] lg:min-h-[680px]"}`}>
      {/* title strip */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
        <div>
          <div className="mono text-[0.8125rem] text-muted">{"// command center"} · live</div>
          <h1 className="font-hud text-[1.5rem] font-bold uppercase tracking-[.1em] text-neon neon"><Typewriter text="Live Map" /></h1>
        </div>
        <p className="max-w-xl text-[0.9375rem] leading-relaxed text-muted">
          Every line is a computer connected to your server right now:{" "}
          <span className="whitespace-nowrap font-medium text-accent">● normal visitors</span>,{" "}
          <span className="whitespace-nowrap font-medium text-bad">● attackers</span>,{" "}
          <span className="whitespace-nowrap font-medium text-text">✕ blocked</span>. Click anything for details.
        </p>
        <div className="ml-auto flex items-center gap-2">
          {wall && <span className="mr-2 flex items-center gap-3 text-[0.8438rem]"><span className="hud-label">SOC // {host}</span>{demo && <span className="font-semibold text-warn">DEMO</span>}<Clock /></span>}
          <div className="inline-flex rounded-md border border-line2 bg-inset p-0.5">
            {([["globe", "Globe", Globe2], ["graph", "Node graph", Network]] as const).map(([v, l, I]) => (
              <button key={v} onClick={() => setView(v)} title={`Switch to ${l} (g)`}
                className={`flex items-center gap-1.5 rounded px-3 py-1.5 text-[0.875rem] font-medium ${view === v ? "bg-neon text-on-accent" : "text-muted hover:bg-panel2 hover:text-text"}`}>
                <I size={15} /> {l}
              </button>
            ))}
          </div>
          <button className="btn" onClick={toggleWall} title="Fullscreen wall display (f)">
            {wall ? <Minimize2 size={15} /> : <Maximize2 size={15} />} {wall ? "Exit wall mode" : "Wall mode"}
          </button>
        </div>
      </div>

      <div className="grid min-h-0 flex-1 gap-3 lg:grid-cols-[300px_minmax(0,1fr)_360px]">
        {/* left HUD */}
        <div className="order-2 flex min-h-0 flex-col gap-3 lg:order-none lg:overflow-y-auto">
          <section className="card p-3">
            <div className="hud-label mb-2">▍Threat level</div>
            <DefconMeter level={tl} />
          </section>
          <section className="card p-3">
            <div className="hud-label mb-2">▍Live counters</div>
            <Counters blocked={blocked.length} />
          </section>
          <section className="card p-3">
            <div className="hud-label mb-1">▍Threat radar</div>
            <div className="mb-2 text-[0.875rem] text-muted">Attack sources in the last hour. Closer to the centre = more recent. Click a blip.</div>
            <Radar threats={threats} size={210} />
          </section>
          <section className="card hidden p-3 xl:block">
            <HexTicker rows={4} />
          </section>
        </div>

        {/* stage */}
        <section className={`card hud-corner map-stage relative order-1 h-[62vh] min-h-[420px] overflow-hidden lg:order-none lg:h-auto ${tl.level <= 2 ? "hot" : ""}`}>
          {!net ? (
            <div className="flex h-full items-center justify-center"><Spinner label="Acquiring network telemetry…" /></div>
          ) : view === "globe" ? (
            <Globe3D server={server} sources={sources} reduce={fx.reduce} onSelect={selectSource} palette={theme.P} light={theme.light} />
          ) : (
            <NodeGraph nodes={graph.nodes} edges={graph.edges} selected={selId} onSelect={selectNode} reduce={fx.reduce} />
          )}
          {/* overlay HUD */}
          <div className="hud-glass pointer-events-none absolute left-2 top-2 z-[3] flex max-w-[calc(100%-1rem)] flex-wrap gap-x-3 sm:block sm:space-y-0.5 rounded-md px-2.5 py-1.5 text-[0.8125rem] sm:left-3 sm:top-3 sm:px-3 sm:py-2 sm:text-[0.875rem]">
            <div className="mb-0.5 hidden text-[0.75rem] sm:block font-semibold tracking-[.12em] text-neon">{view === "globe" ? "GLOBAL TRAFFIC // ORBITAL VIEW" : "TOPOLOGY // NODE GRAPH"}</div>
            <div className="hidden sm:block"><HudStat label="Server" value={`${host} · ${server.city || ""}`} /></div>
            <HudStat label="Normal" value={nNormal} color={C.accent2} />
            <HudStat label="Threats" value={nThreat} color={C.danger} />
            <HudStat label="Blocked" value={nBlocked} color={C.text} />
          </div>
          <div className="hud-glass pointer-events-none absolute bottom-3 right-3 z-[3] hidden rounded-md px-3 py-2 text-right text-[0.8125rem] text-muted sm:block">
            {view === "globe" ? "drag to rotate · scroll to zoom · click an arc or dot" : "scroll to zoom · drag to pan · drag nodes · click for details"}
            <div className="mt-1 flex flex-wrap justify-end gap-x-3 gap-y-1 text-text">
              {view === "graph" ? (
                <>
                  <Legend c={C.accent} shape="hex" t="your server" />
                  <Legend c={C.accent2} shape="sq" t="service" />
                  <Legend c={C.info} shape="dot" t="remote IP" />
                  <Legend c={C.warn} shape="tri" t="logged-in user" />
                  <Legend c={C.danger} shape="dot" t="threat" />
                </>
              ) : (
                <>
                  <Legend c={C.accent} shape="line" t="normal" />
                  <Legend c={C.danger} shape="line" t="attack" />
                  <Legend c={C.danger} shape="x" t="blocked" />
                </>
              )}
            </div>
          </div>
          {sel && <DetailsPanel sel={sel} onClose={() => setSel(null)} threatByIP={threatByIP} blockedSet={blockedSet} onBlocked={() => fw.reload()} openIP={openIP} />}
        </section>

        {/* right HUD */}
        <div className="order-3 flex min-h-0 flex-col gap-3 lg:order-none">
          <section className="card flex min-h-[320px] flex-1 flex-col p-3 lg:min-h-0">
            <div className="mb-2 flex items-center justify-between">
              <span className="hud-label">▍Live event log</span>
              <span className="flex items-center gap-1.5 text-[0.8125rem] text-muted"><Activity size={13} className={live.connected ? "pulse text-good" : "text-bad"} /> {live.connected ? "streaming" : "offline"}</span>
            </div>
            <div className="mb-2 text-[0.8125rem] leading-snug text-muted">REQ = web request · AUTH/DENY = login ok/failed · THREAT = attack detected · BLOCK = firewall</div>
            <EventLog threats={threats} className="min-h-0 flex-1" />
          </section>
          <section className="card p-3">
            <div className="hud-label mb-2">▍Top attackers</div>
            <TopAttackers threats={recentThreats} onPick={(ip) => setSel({ kind: "ip", ip, talker: net?.talkers?.find((t) => t.ip === ip) })} />
          </section>
        </div>
      </div>
    </div>
  );
}

const rank = (s: string) => ["info", "low", "medium", "high", "critical"].indexOf(s);

function Legend({ c, t, shape }: { c: string; t: string; shape: "dot" | "sq" | "tri" | "hex" | "line" | "x" }) {
  return (
    <span className="flex items-center gap-1">
      {shape === "line" ? <span className="h-[3px] w-4 rounded" style={{ background: c, boxShadow: glow(c, 6) }} />
        : shape === "x" ? <span className="font-bold" style={{ color: c }}>✕</span>
        : <span className="inline-block h-2.5 w-2.5" style={{ background: c, boxShadow: glow(c, 6), borderRadius: shape === "dot" ? 99 : 0, clipPath: shape === "tri" ? "polygon(50% 0,100% 100%,0 100%)" : shape === "hex" ? "polygon(25% 0,75% 0,100% 50%,75% 100%,25% 100%,0 50%)" : undefined }} />}
      {t}
    </span>
  );
}

function TopAttackers({ threats, onPick }: { threats: Threat[]; onPick: (ip: string) => void }) {
  const rows = useMemo(() => {
    const m = new Map<string, { ip: string; n: number; worst: Threat }>();
    for (const t of threats) {
      const o = m.get(t.ip) || { ip: t.ip, n: 0, worst: t };
      o.n += t.count || 1;
      if (rank(t.severity) > rank(o.worst.severity)) o.worst = t;
      m.set(t.ip, o);
    }
    return [...m.values()].sort((a, b) => rank(b.worst.severity) - rank(a.worst.severity) || b.n - a.n).slice(0, 6);
  }, [threats]);
  if (!rows.length) return <div className="text-[0.875rem] text-muted">No attackers in the last 6 hours.</div>;
  return (
    <div className="mono space-y-0.5 text-[0.875rem]">
      {rows.map((r) => (
        <button key={r.ip} onClick={() => onPick(r.ip)} className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left hover:bg-bad/10">
          <span className="w-4">{flagEmoji(r.worst.geo?.cc)}</span>
          <span className="w-[132px] shrink-0 truncate font-medium" style={{ color: sevColor[r.worst.severity] }}>{r.ip}</span>
          <span className="flex-1 truncate font-sans text-muted">{threatTypeLabel(r.worst.type)}</span>
          <span className="tabular-nums font-semibold text-bad">×{r.n}</span>
        </button>
      ))}
    </div>
  );
}

function DetailsPanel({ sel, onClose, threatByIP, blockedSet, onBlocked, openIP }: {
  sel: Sel; onClose: () => void; threatByIP: Map<string, Threat>; blockedSet: Set<string>; onBlocked: () => void; openIP: (ip: string) => void;
}) {
  const live = useLive();
  const isIP = sel.kind === "ip";
  const detail = useApi<IPDetail>(isIP ? `/api/ip/${encodeURIComponent(sel.ip)}` : null, { deps: [isIP ? sel.ip : ""] });
  const title = sel.kind === "ip" ? "Remote IP" : sel.kind === "service" ? "Service" : sel.kind === "user" ? "Logged-in user" : "Location";
  const threat = isIP ? threatByIP.get(sel.ip) : undefined;
  return (
    <div className={`card ${threat && !blockedSet.has(sel.kind === "ip" ? sel.ip : "") ? "hot" : ""} absolute right-3 top-3 z-[5] w-[360px] max-w-[calc(100%-1.5rem)] p-0 shadow-2xl shadow-black/50`}>
      <div className="flex items-center justify-between border-b border-line bg-panel2 px-3 py-2">
        <span className="hud-label">▍{title}</span>
        <button onClick={onClose} className="rounded p-1 text-muted hover:bg-panel hover:text-text" aria-label="Close details"><X size={17} /></button>
      </div>
      <div className="max-h-[60vh] space-y-2 overflow-y-auto p-3 text-[0.9375rem]">
        {sel.kind === "ip" && (() => {
          const d = detail.data;
          const t = sel.talker;
          const geo = d?.geo || t?.geo || threat?.geo;
          const isBlocked = d?.blocked ?? (blockedSet.has(sel.ip) || t?.blocked);
          const reqs = d?.requests?.length ?? live.requests.filter((r) => r.ip === sel.ip).length;
          const nThreats = d?.threats?.length ?? (threat ? 1 : 0);
          return (
            <>
              <div className="mono text-[1.125rem] font-bold" style={{ color: threat ? C.danger : C.accent, textShadow: glow(threat ? C.danger : C.accent, 8) }}>
                {threat ? <Glitch text={sel.ip} /> : sel.ip}
              </div>
              <Row k="Country" v={geo ? `${flagEmoji(geo.cc)} ${place(geo)}` : "—"} />
              {t && <Row k="Connections" v={`${t.conns} open · ${fmtRate(t.rate_in + t.rate_out)}`} />}
              {t && <Row k="Talks to" v={`${(t.processes || []).join(", ") || "—"} ${t.ports?.length ? "(port " + t.ports.join(", ") + ")" : ""}`} />}
              <Row k="Requests" v={detail.loading ? "…" : `${reqs}${d?.requests && d.requests.length >= 100 ? "+" : ""} recent`} />
              <Row k="Threats" v={detail.loading ? "…" : <span className="font-medium" style={{ color: nThreats ? C.danger : C.ok }}>{nThreats ? `${nThreats} detected` : "none"}</span>} />
              {threat && (
                <div className="rounded-md border p-2.5" style={{ borderColor: mix(C.danger, 40), background: mix(C.danger, 8) }}>
                  <div className="mb-1 flex items-center gap-2"><SevBadge sev={threat.severity} /> <span className="font-semibold">{threat.title}</span></div>
                  <div className="text-[0.875rem] text-text">{threat.explanation}</div>
                  <div className="mt-1 text-[0.8125rem] text-muted">last seen {ago(threat.last_seen)}</div>
                </div>
              )}
              <Row k="Status" v={isBlocked ? <span className="text-bad">✕ blocked by firewall</span> : <span className="text-good">allowed</span>} />
              <div className="flex flex-wrap gap-2 pt-1">
                <BlockButton ip={sel.ip} blocked={!!isBlocked} reason={threat?.title} refusal={d?.block_refusal} small onDone={() => { detail.reload(); onBlocked(); }} />
                <button className="btn !px-2 !py-1 text-[0.875rem]" onClick={() => openIP(sel.ip)}>Full details →</button>
              </div>
            </>
          );
        })()}
        {sel.kind === "place" && (
          <>
            <div className="font-semibold text-accent">{sel.label}</div>
            <div className="text-muted">IP addresses seen from here:</div>
            <div className="mono space-y-0.5">
              {sel.ips.slice(0, 20).map((ip) => <button key={ip} className="block text-accent hover:underline" onClick={() => openIP(ip)}>{ip}</button>)}
            </div>
          </>
        )}
        {sel.kind === "service" && (() => {
          const L = sel.listeners;
          const svc = live.system?.services?.find((s) => s.name.replace(/\.service$/, "").startsWith(sel.name.split("-")[0].replace(/\d.*$/, "")));
          const conns = L.reduce((a, l) => a + (l.conns || 0), 0);
          const pub = L.some((l) => l.public);
          return (
            <>
              <div className="mono text-[1.125rem] font-bold text-accent neon">{sel.name}</div>
              <Row k="What it is" v={[...new Set(L.map((l) => l.service).filter(Boolean))].join(", ") || "—"} />
              <Row k="Port" v={[...new Set(L.map((l) => `${l.port}/${l.proto}`))].join(", ")} />
              <Row k="Process" v={`${L[0]?.process || sel.name} (pid ${L[0]?.pid || "?"}, user ${L[0]?.user || "?"})`} />
              <Row k="Reachable" v={pub ? <span className="text-warn">from the internet</span> : <span className="text-good">only on this server</span>} />
              <Row k="Connections" v={`${conns} active`} />
              <Row k="Status" v={svc ? <span className={svc.active === "active" ? "text-good" : "text-bad"}>{svc.active} ({svc.sub})</span> : <span className="text-good">listening</span>} />
              {L.find((l) => l.risk) && <div className="rounded-md border border-warn/40 bg-warn/10 p-2.5 text-[0.875rem] text-warn">{L.find((l) => l.risk)!.risk}</div>}
            </>
          );
        })()}
        {sel.kind === "user" && (
          <>
            <div className="mono text-[1.125rem] font-bold text-warn" style={{ textShadow: glow(C.warn, 8) }}>{sel.user}</div>
            <Row k="Terminal" v={sel.tty || "—"} />
            <Row k="From" v={sel.host ? <button className="text-accent hover:underline" onClick={() => openIP(sel.host)}>{sel.host}</button> : "local console"} />
            {sel.geo && <Row k="Location" v={`${flagEmoji(sel.geo.cc)} ${place(sel.geo)}`} />}
            <Row k="Logged in" v={sel.login ? `${fmtDateTime(sel.login)} (${ago(sel.login)})` : "—"} />
            <div className="text-[0.875rem] text-muted">Someone is logged in to your server with this account right now. If you don&apos;t recognise it, change the password and check the Logins page.</div>
          </>
        )}
      </div>
    </div>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-3 border-b border-dashed border-line pb-1.5">
      <span className="shrink-0 text-muted">{k}</span>
      <span className="min-w-0 break-words text-right">{v}</span>
    </div>
  );
}

function buildGraph(net: NetworkSnapshot | null, sessions: { user: string; tty: string; host: string; login_time: number; geo: { country?: string; city?: string; cc?: string } }[], threatByIP: Map<string, Threat>, blockedSet: Set<string>, hostname?: string) {
  const nodes: GNode[] = [];
  const edges: GEdge[] = [];
  if (!net) return { nodes, edges };
  nodes.push({ id: "vps", kind: "vps", label: hostname || "server", sub: "your server" });
  // services grouped by process
  const byProc = new Map<string, Listener[]>();
  for (const l of net.listeners || []) {
    const k = l.process || `port ${l.port}`;
    byProc.set(k, [...(byProc.get(k) || []), l]);
  }
  const portSvc = new Map<number, string>();
  const maxConns = Math.max(1, ...[...byProc.values()].map((L) => L.reduce((a, l) => a + (l.conns || 0), 0)));
  for (const [name, L] of byProc) {
    const id = "svc:" + name;
    const ports = [...new Set(L.map((l) => l.port))].sort((a, b) => a - b);
    for (const p of ports) portSvc.set(p, id);
    const conns = L.reduce((a, l) => a + (l.conns || 0), 0);
    nodes.push({ id, kind: "service", label: name, sub: ":" + ports.join(","), weight: conns / maxConns, data: { kind: "service", name, listeners: L } satisfies Sel });
  }
  const svcRate = new Map<string, number>();
  const talkers = [...(net.talkers || [])].sort((a, b) => (b.rate_in + b.rate_out) - (a.rate_in + a.rate_out)).slice(0, 40);
  const maxRate = Math.max(1, ...talkers.map((t) => t.rate_in + t.rate_out));
  const seen = new Set<string>();
  for (const t of talkers) {
    const id = "ip:" + t.ip;
    seen.add(t.ip);
    const svc = (t.ports || []).map((p) => portSvc.get(p)).find(Boolean) || "vps";
    const rate = t.rate_in + t.rate_out;
    const threat = t.threat || threatByIP.has(t.ip);
    const blocked = t.blocked || blockedSet.has(t.ip);
    nodes.push({ id, kind: "ip", label: t.ip, sub: `${flagEmoji(t.geo?.cc)} ${t.geo?.cc || ""} · ${fmtRate(rate)}`, threat, blocked, weight: rate / maxRate, anchor: svc, data: { kind: "ip", ip: t.ip, talker: t } satisfies Sel });
    edges.push({ from: id, to: svc, rate, threat, blocked });
    svcRate.set(svc, (svcRate.get(svc) || 0) + rate);
  }
  // recent attackers that aren't connected right now
  let extra = 0;
  for (const [ip, t] of threatByIP) {
    if (seen.has(ip) || extra >= 14) continue;
    extra++;
    const svc = (/ssh|login|brute/i.test(t.type) && byProc.has("sshd") ? "svc:sshd" : byProc.has("nginx") ? "svc:nginx" : "vps");
    const blocked = t.blocked || blockedSet.has(ip);
    nodes.push({ id: "ip:" + ip, kind: "ip", label: ip, sub: `${flagEmoji(t.geo?.cc)} ${threatTypeLabel(t.type)}`, threat: true, blocked, weight: 0.15, anchor: svc, data: { kind: "ip", ip } satisfies Sel });
    edges.push({ from: "ip:" + ip, to: svc, rate: 500, threat: true, blocked });
  }
  // logged-in users
  for (const s of sessions) {
    const id = `user:${s.user}@${s.tty}`;
    const anchor = byProc.has("sshd") ? "svc:sshd" : "vps";
    nodes.push({ id, kind: "user", label: s.user, sub: s.host || s.tty, anchor, data: { kind: "user", user: s.user, tty: s.tty, host: s.host, login: s.login_time, geo: s.geo } satisfies Sel });
    edges.push({ from: id, to: anchor, rate: 2000 });
  }
  for (const [name] of byProc) edges.push({ from: "svc:" + name, to: "vps", rate: svcRate.get("svc:" + name) || 100 });
  return { nodes, edges };
}
