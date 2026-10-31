"use client";

import { Info, Loader2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { flagEmoji, levelColor, place, sevColor, sevHelp, sevLabel } from "@/lib/format";
import { C, glow, mix } from "@/lib/theme";
import type { Geo, Level } from "@/lib/types";
import { useUI } from "./uictx";
import { CountUp, Typewriter } from "./fx";

export function Card({ title, info, right, children, className = "", bodyClass = "p-4", hot }: {
  title?: React.ReactNode; info?: React.ReactNode; right?: React.ReactNode; children: React.ReactNode; className?: string; bodyClass?: string; hot?: boolean;
}) {
  return (
    <section className={`card ${hot ? "hot" : ""} ${className}`}>
      {(title || right) && (
        <header className="flex min-h-[46px] flex-wrap items-center justify-between gap-x-3 gap-y-2 border-b border-line bg-panel2/60 px-4 py-2.5">
          <h2 className={`hud-label flex items-center gap-1.5 ${hot ? "!text-bad" : ""}`}>
            <span className="text-neon/50" aria-hidden>▍</span>
            {title}
            {info && <InfoTip>{info}</InfoTip>}
          </h2>
          {right && <div className="flex items-center gap-2">{right}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  );
}

/** Hover/focus tooltip with a plain-language explanation. */
export function InfoTip({ children, side = "bottom" }: { children: React.ReactNode; side?: "bottom" | "top" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const [pos, setPos] = useState<{ left: number; top: number } | null>(null);
  useEffect(() => {
    if (!open || !ref.current) return;
    const r = ref.current.getBoundingClientRect();
    const left = Math.min(Math.max(8, r.left - 140), window.innerWidth - 296);
    setPos({ left, top: side === "bottom" ? r.bottom + 6 : r.top - 6 });
  }, [open, side]);
  return (
    <span
      ref={ref}
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      tabIndex={0}
      aria-label="More information"
    >
      <Info size={14} className="cursor-help text-muted hover:text-text" />
      {open && pos && (
        <span
          role="tooltip"
          style={{ position: "fixed", left: pos.left, top: pos.top, transform: side === "top" ? "translateY(-100%)" : undefined }}
          className="z-[100] w-72 rounded-md border border-line2 bg-panel p-3 text-[0.875rem] font-normal normal-case leading-relaxed tracking-normal text-text shadow-xl shadow-black/40 [font-family:var(--font-sans)] [text-shadow:none]"
        >
          {children}
        </span>
      )}
    </span>
  );
}

export function Stat({ label, value, sub, info, color, icon, onClick }: {
  label: string; value: React.ReactNode; sub?: React.ReactNode; info?: React.ReactNode; color?: string; icon?: React.ReactNode; onClick?: () => void;
}) {
  return (
    <div className={`card flex flex-col gap-1 p-4 ${onClick ? "cursor-pointer hover:border-neon" : ""}`} onClick={onClick}>
      <div className="flex items-center gap-1.5 text-[0.8125rem] font-medium uppercase tracking-[.06em] text-muted">
        <span className="text-accent">{icon}</span>
        {label}
        {info && <InfoTip>{info}</InfoTip>}
      </div>
      <div className="mono neon truncate text-[1.375rem] sm:text-[1.625rem] font-bold leading-tight tabular-nums" style={{ color: color || C.accent }}>
        {typeof value === "number" ? <CountUp value={value} /> : value}
      </div>
      {sub && <div className="text-[0.875rem] text-muted">{sub}</div>}
    </div>
  );
}

export function SevBadge({ sev, withTip = false }: { sev: string; withTip?: boolean }) {
  const c = sevColor[sev] || C.muted;
  const badge = (
    <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[0.75rem] font-bold uppercase tracking-[.08em] ${sev === "critical" ? "alarm" : ""}`} style={{ color: c, background: mix(c, 14), border: `1px solid ${mix(c, 55)}` }}>
      {sevLabel[sev] || sev}
    </span>
  );
  if (!withTip) return badge;
  return (
    <span className="inline-flex items-center gap-1">
      {badge}
      <InfoTip>{sevHelp[sev]}</InfoTip>
    </span>
  );
}

export function Pill({ color, children, title }: { color: string; children: React.ReactNode; title?: string }) {
  return (
    <span title={title} className="inline-flex items-center gap-1 whitespace-nowrap rounded px-1.5 py-0.5 text-[0.8125rem] font-medium" style={{ color, background: mix(color, 12), border: `1px solid ${mix(color, 40)}` }}>
      {children}
    </span>
  );
}

export function Dot({ level, pulse }: { level: Level | "off"; pulse?: boolean }) {
  const c = level === "off" ? C.line2 : levelColor[level];
  return <span className={`inline-block h-2.5 w-2.5 shrink-0 rounded-full ${pulse ? "pulse" : ""}`} style={{ background: c, boxShadow: glow(c, 8) }} />;
}

export function Bar({ pct, level, height = 6 }: { pct: number; level?: Level; height?: number }) {
  const l = level || (pct >= 90 ? "bad" : pct >= 75 ? "warn" : "good");
  return (
    <div className="w-full overflow-hidden rounded-full bg-line" style={{ height }}>
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${Math.min(100, Math.max(0, pct))}%`, background: levelColor[l], boxShadow: glow(levelColor[l], 8) }} />
    </div>
  );
}

/** Semi-circular gauge. */
export function Gauge({ pct, label, sub, level, size = 130 }: { pct: number; label: string; sub?: string; level?: Level; size?: number }) {
  const l = level || (pct >= 90 ? "bad" : pct >= 75 ? "warn" : "good");
  const r = 52;
  const c = Math.PI * r;
  const p = Math.min(100, Math.max(0, pct)) / 100;
  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size * 0.62} viewBox="0 0 130 80">
        <path d="M13 70 A52 52 0 0 1 117 70" fill="none" stroke={C.line} strokeWidth="11" />
        <path
          d="M13 70 A52 52 0 0 1 117 70"
          fill="none"
          stroke={levelColor[l]}
          strokeWidth="11"
          strokeDasharray={`${c * p} ${c}`}
          style={{ transition: "stroke-dasharray .7s ease", filter: `drop-shadow(0 0 calc(4px * var(--glow)) ${mix(levelColor[l], 70)})` }}
        />
        <text x="65" y="64" textAnchor="middle" fill={C.text} fontSize="21" fontWeight="700" style={{ fontFamily: "var(--font-mono)" }}>
          {Math.round(pct)}%
        </text>
      </svg>
      <div className="-mt-1 text-[0.875rem] font-semibold uppercase tracking-[.06em]">{label}</div>
      {sub && <div className="text-center text-[0.8125rem] text-muted">{sub}</div>}
    </div>
  );
}

export function Empty({ children, icon }: { children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-4 py-10 text-center text-[0.9375rem] text-muted [&>svg]:opacity-70">
      {icon}
      {children}
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-muted">
      <Loader2 size={16} className="animate-spin" /> {label}
    </div>
  );
}

export function Segmented<T extends string>({ value, options, onChange }: { value: T; options: { value: T; label: string }[]; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex flex-wrap rounded-md border border-line2 bg-inset p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          className={`rounded px-3 py-1 text-[0.8125rem] font-semibold transition ${value === o.value ? "bg-neon text-on-accent" : "text-muted hover:bg-panel2 hover:text-text"}`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function GeoTag({ geo, short }: { geo?: Geo; short?: boolean }) {
  if (!geo || (!geo.country && !geo.private)) return <span className="text-muted">—</span>;
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap" title={place(geo)}>
      <span>{geo.private ? "🏠" : flagEmoji(geo.cc)}</span>
      <span className="truncate">{short ? geo.cc || (geo.private ? "LAN" : "") : place(geo)}</span>
    </span>
  );
}

/** Clickable IP address that opens the IP details drawer. */
export function IPLink({ ip, threat, blocked }: { ip: string; threat?: boolean; blocked?: boolean }) {
  const { openIP } = useUI();
  if (!ip) return <span className="text-muted">—</span>;
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        openIP(ip);
      }}
      className={`mono inline-flex items-center gap-1 text-[0.875rem] hover:underline ${threat ? "font-semibold text-bad" : "text-accent"}`}
      title="Show everything about this IP"
    >
      {ip}
      {blocked && <span className="rounded border border-bad/50 px-1 text-[0.75rem] text-bad">✕ blocked</span>}
    </button>
  );
}

export function PageHeader({ title, desc, right }: { title: string; desc?: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <div className="mono mb-1 text-[0.75rem] uppercase tracking-[.14em] text-muted">{"// sector"} · {title.split(" · ")[0]}</div>
        <h1 className="font-hud text-[1.375rem] font-bold uppercase leading-tight tracking-[.08em] text-neon neon"><Typewriter text={title} /></h1>
        {desc && <p className="mt-1.5 max-w-3xl text-[0.9375rem] leading-relaxed text-muted">{desc}</p>}
      </div>
      {right && <div className="flex flex-wrap items-center gap-2">{right}</div>}
    </div>
  );
}

export function KVRow({ k, v, mono }: { k: React.ReactNode; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line py-2 text-[0.9062rem] last:border-0">
      <span className="shrink-0 text-muted">{k}</span>
      <span className={`min-w-0 break-all text-right ${mono ? "mono text-[0.8438rem]" : ""}`}>{v}</span>
    </div>
  );
}

/** Shimmering placeholder used while data loads. */
export function Skeleton({ className = "h-4 w-full" }: { className?: string }) {
  return <div className={`skel ${className}`} aria-hidden />;
}

/** Loading placeholder for a whole page: header + stat row + panels. */
export function PageSkeleton() {
  return (
    <div className="space-y-5" aria-busy="true" aria-label="Loading">
      <div className="space-y-2">
        <Skeleton className="h-3 w-40" />
        <Skeleton className="h-7 w-72" />
        <Skeleton className="h-4 w-full max-w-xl" />
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-[104px]" />)}
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-72 lg:col-span-2" />
        <Skeleton className="h-72" />
      </div>
    </div>
  );
}
