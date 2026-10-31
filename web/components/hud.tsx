"use client";

import { useEffect, useMemo, useState } from "react";
import { useLive } from "@/lib/live";
import { useNow } from "@/lib/hooks";
import { fmtRate, sevColor } from "@/lib/format";
import { C, glow, mix } from "@/lib/theme";
import type { Threat } from "@/lib/types";
import type { ThreatLevel } from "@/lib/threat";
import { CountUp } from "./fx";
import { useUI } from "./uictx";

const hhmmss = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23" });

type Line = { key: string; ts: number; tag: string; color: string; ip?: string; text: string; hot?: boolean };

/** Scrolling terminal-style feed of requests, logins and threats. */
export function EventLog({ threats, max = 80, className = "" }: { threats: Threat[]; max?: number; className?: string }) {
  const live = useLive();
  const { openIP } = useUI();
  const lines = useMemo(() => {
    const out: Line[] = [];
    for (const r of live.requests.slice(0, 120)) {
      out.push({
        key: "r" + r.id, ts: r.ts, tag: "REQ", color: r.flags?.length ? C.warn : C.accent2, ip: r.ip,
        text: `${r.method} ${trim(r.path, 38)} → ${r.status}${r.flags?.length ? "  !" + r.flags[0] : ""}`,
      });
    }
    for (const a of live.auth.slice(0, 60)) {
      const ok = a.kind.includes("accepted") || a.kind === "sudo";
      out.push({ key: "a" + a.id, ts: a.ts, tag: ok ? "AUTH" : "DENY", color: ok ? C.ok : C.warn, ip: a.ip || undefined, text: authText(a.kind, a.user, a.command) });
    }
    for (const t of threats.slice(0, 60)) {
      out.push({ key: "t" + t.id + ":" + t.last_seen, ts: t.last_seen, tag: t.blocked ? "BLOCK" : "THREAT", color: sevColor[t.severity], ip: t.ip, text: `[${t.severity.toUpperCase()}] ${t.title}`, hot: t.severity === "critical" || t.severity === "high" });
    }
    for (const b of live.blocked || []) out.push({ key: "b" + b.ip + b.ts, ts: b.ts, tag: "BLOCK", color: C.crit, ip: b.ip, text: `firewall drop — ${trim(b.reason || "blocked", 40)}` });
    out.sort((a, b) => b.ts - a.ts);
    return out.slice(0, max);
  }, [live.requests, live.auth, live.blocked, threats, max]);

  return (
    <div className={`mono overflow-hidden text-[0.8438rem] leading-[1.55] ${className}`}>
      {lines.length === 0 && <div className="text-muted">&gt; waiting for events<span className="caret" /></div>}
      {lines.map((l, i) => (
        <div key={l.key} className={`flex gap-2 whitespace-nowrap ${i === 0 ? "log-in" : ""} ${l.hot ? "bg-bad/10" : ""}`}>
          <span className="text-muted">{hhmmss.format(l.ts)}</span>
          <span className="w-[52px] shrink-0 font-bold" style={{ color: l.color, textShadow: glow(l.color, 6, 50) }}>{l.tag}</span>
          {l.ip && <button className="shrink-0 text-accent hover:underline" onClick={() => openIP(l.ip!)}>{l.ip}</button>}
          <span className="truncate text-text">{l.text}</span>
        </div>
      ))}
    </div>
  );
}

function authText(kind: string, user: string, cmd: string) {
  switch (kind) {
    case "ssh_accepted": return `login OK — user ${user}`;
    case "ssh_failed": return `failed password — user ${user}`;
    case "ssh_invalid_user": return `unknown user tried — ${user}`;
    case "sudo": return `sudo by ${user}: ${trim(cmd, 30)}`;
    default: return `${kind.replace(/_/g, " ")} ${user}`;
  }
}

function trim(s: string, n: number) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/** Radar sweep: one blip per active threat source (closer to centre = more recent). */
export function Radar({ threats, size = 220 }: { threats: Threat[]; size?: number }) {
  const { openIP } = useUI();
  const now = useNow(5000);
  const blips = useMemo(() => {
    const by = new Map<string, Threat>();
    for (const t of threats) {
      if (now - t.last_seen > 60 * 60000) continue;
      const o = by.get(t.ip);
      if (!o || rank(t.severity) > rank(o.severity)) by.set(t.ip, t);
    }
    return [...by.values()].slice(0, 30).map((t) => {
      const a = hash(t.ip) * Math.PI * 2;
      const age = Math.min(1, (now - t.last_seen) / (60 * 60000));
      const r = 0.15 + age * 0.8;
      return { t, x: 50 + Math.cos(a) * r * 46, y: 50 + Math.sin(a) * r * 46, a };
    });
  }, [threats, now]);
  return (
    <div className="relative mx-auto" style={{ width: size, height: size }}>
      <svg viewBox="0 0 100 100" className="absolute inset-0 h-full w-full">
        <defs>
          <radialGradient id="rg" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor={C.accent} stopOpacity="0.1" />
            <stop offset="100%" stopColor={C.accent} stopOpacity="0.03" />
          </radialGradient>
        </defs>
        <circle cx="50" cy="50" r="48" fill="url(#rg)" stroke={mix(C.accent, 45)} strokeWidth="0.5" />
        {[12, 24, 36].map((r) => <circle key={r} cx="50" cy="50" r={r} fill="none" stroke={mix(C.accent, 22)} strokeWidth="0.4" />)}
        <line x1="2" y1="50" x2="98" y2="50" stroke={mix(C.accent, 18)} strokeWidth="0.3" />
        <line x1="50" y1="2" x2="50" y2="98" stroke={mix(C.accent, 18)} strokeWidth="0.3" />
        {Array.from({ length: 36 }).map((_, i) => {
          const a = (i / 36) * Math.PI * 2;
          const l = i % 3 === 0 ? 3 : 1.5;
          return <line key={i} x1={50 + Math.cos(a) * 48} y1={50 + Math.sin(a) * 48} x2={50 + Math.cos(a) * (48 - l)} y2={50 + Math.sin(a) * (48 - l)} stroke={mix(C.accent, 50)} strokeWidth="0.3" />;
        })}
      </svg>
      <div className="radar-sweep absolute inset-[2%] rounded-full" />
      <svg viewBox="0 0 100 100" className="absolute inset-0 h-full w-full">
        {blips.map(({ t, x, y }) => {
          const c = t.blocked ? C.muted : sevColor[t.severity];
          return (
            <g key={t.ip} className="cursor-pointer" onClick={() => openIP(t.ip)}>
              <title>{`${t.ip} — ${t.title}${t.blocked ? " (blocked)" : ""}`}</title>
              {!t.blocked && <circle cx={x} cy={y} r="3" fill="none" stroke={c} strokeWidth="0.4" className="blip-ring" />}
              <circle cx={x} cy={y} r={t.severity === "critical" ? 1.8 : 1.3} fill={c} style={{ filter: `drop-shadow(0 0 calc(1.5px * var(--glow)) ${c})` }} />
            </g>
          );
        })}
        <circle cx="50" cy="50" r="1.4" fill={C.accent} />
      </svg>
    </div>
  );
}

const rank = (s: string) => ["info", "low", "medium", "high", "critical"].indexOf(s);

function hash(s: string) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return ((h >>> 0) % 10000) / 10000;
}

/** Big live counters: req/s, bandwidth, connections, IPs blocked. */
export function Counters({ blocked }: { blocked: number }) {
  const live = useLive();
  const now = useNow(1000);
  const rps = live.requests.filter((r) => now - r.ts < 10000).length / 10;
  const bw = (live.network?.total_rx_bps || 0) + (live.network?.total_tx_bps || 0);
  const items: { label: string; help: string; v: number; fmt: (v: number) => string; c: string }[] = [
    { label: "Requests / sec", help: "Web requests per second (last 10 s)", v: rps, fmt: (v) => v.toFixed(1), c: C.accent2 },
    { label: "Bandwidth", help: "Data in + out right now", v: bw, fmt: (v) => fmtRate(v), c: C.accent },
    { label: "Connections", help: "Open network connections", v: live.network?.conn_count || 0, fmt: (v) => Math.round(v).toLocaleString(), c: C.ok },
    { label: "IPs blocked", help: "Addresses your firewall is blocking", v: blocked, fmt: (v) => Math.round(v).toLocaleString(), c: C.danger },
  ];
  return (
    <div className="grid grid-cols-2 gap-2">
      {items.map((i) => (
        <div key={i.label} className="min-w-0 rounded-md border border-line bg-panel2 px-3 py-2" title={i.help}>
          <div className="truncate text-[0.75rem] font-medium uppercase tracking-[.06em] text-muted">{i.label}</div>
          <div className="mono truncate text-[1.1875rem] font-bold tabular-nums" style={{ color: i.c, textShadow: glow(i.c, 10, 45) }}>
            <CountUp value={i.v} format={i.fmt} duration={500} />
          </div>
        </div>
      ))}
    </div>
  );
}

/** DEFCON-style 5-step threat meter. */
export function DefconMeter({ level }: { level: ThreatLevel }) {
  const steps = [5, 4, 3, 2, 1] as const;
  const colors: Record<number, string> = { 5: C.ok, 4: C.info, 3: C.warn, 2: C.danger, 1: C.crit };
  return (
    <div>
      <div className="flex gap-1">
        {steps.map((s) => {
          const on = s === level.level;
          const c = colors[s];
          return (
            <div key={s} className={`flex-1 rounded border py-1.5 text-center font-mono text-[0.9375rem] font-bold ${on && s <= 2 ? "alarm" : ""}`}
              style={{ borderColor: on ? c : mix(c, 35), color: on ? C.bg : c, background: on ? c : mix(c, 6), boxShadow: on ? glow(c, 14, 70) : undefined, opacity: on ? 1 : 0.75 }}>
              {s}
            </div>
          );
        })}
      </div>
      <div className="mt-1.5 flex items-baseline justify-between gap-2">
        <span className="mono shrink-0 text-[0.9375rem] font-bold tracking-[.06em]" style={{ color: level.color, textShadow: glow(level.color, 8) }}>{level.name}</span>
        <span className="text-right text-[0.8438rem] text-muted">{level.text}</span>
      </div>
    </div>
  );
}

/** Small "uptime-style" HUD line for the map overlay. */
export function HudStat({ label, value, color = C.accent }: { label: string; value: React.ReactNode; color?: string }) {
  return (
    <div className="flex items-baseline gap-1.5 text-[0.8125rem]">
      <span className="uppercase tracking-[.06em] text-muted">{label}</span>
      <span className="mono font-semibold" style={{ color, textShadow: glow(color, 6, 50) }}>{value}</span>
    </div>
  );
}

/** Rolling hex dump decoration — purely cosmetic, labelled as such. */
export function HexTicker({ rows = 4 }: { rows?: number }) {
  const [seed, setSeed] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setSeed((s) => s + 1), 900);
    return () => clearInterval(t);
  }, []);
  const lines = Array.from({ length: rows }).map((_, r) =>
    Array.from({ length: 8 }).map((__, i) => ((Math.imul(seed * 31 + r * 7 + i, 2654435761) >>> 0) & 0xffff).toString(16).padStart(4, "0")).join(" "),
  );
  return (
    <div className="mono select-none text-[0.75rem] leading-tight text-neon/40" aria-hidden>
      {lines.map((l, i) => <div key={i}>{(0x7f00 + seed * 16 + i * 16).toString(16)}: {l}</div>)}
    </div>
  );
}

