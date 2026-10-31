"use client";

import { Check, Palette as PaletteIcon, RotateCcw, Type } from "lucide-react";
import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { FONT_SIZES, THEMES, isHex, useTheme, type ThemeDef } from "@/lib/theme";

/** Mini preview of a theme: background, panel, accent and status colours. */
function Swatch({ t, active, onClick, compact }: { t: ThemeDef; active: boolean; onClick: () => void; compact?: boolean }) {
  const p = t.p;
  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      title={`${t.label} — ${t.blurb}`}
      className={`group relative flex w-full items-center gap-3 rounded-lg border p-2 text-left transition ${active ? "border-neon ring-2 ring-neon/30" : "border-line2 hover:border-neon/70"}`}
      style={{ background: p.bg }}
    >
      <span className={`relative shrink-0 overflow-hidden rounded-md border ${compact ? "h-9 w-12" : "h-14 w-20"}`} style={{ background: p.panel, borderColor: p.line2 }}>
        <span className="absolute left-1.5 right-1.5 top-1.5 h-1.5 rounded-full" style={{ background: p.accent }} />
        <span className="absolute left-1.5 top-4 h-1 w-6 rounded-full" style={{ background: p.text, opacity: 0.85 }} />
        {!compact && <span className="absolute left-1.5 top-6 h-1 w-9 rounded-full" style={{ background: p.muted }} />}
        <span className="absolute bottom-1.5 left-1.5 flex gap-1">
          {[p.ok, p.warn, p.danger, p.crit].map((c) => <span key={c} className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />)}
        </span>
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-[0.875rem] font-semibold" style={{ color: p.text }}>{t.label}</span>
        {!compact && <span className="block truncate text-[0.8125rem]" style={{ color: p.muted }}>{t.blurb}</span>}
      </span>
      {active && <Check size={16} className="shrink-0" style={{ color: p.accent }} />}
    </button>
  );
}

export function ThemeGrid({ compact }: { compact?: boolean }) {
  const th = useTheme();
  return (
    <div className={`grid gap-2 ${compact ? "grid-cols-1" : "grid-cols-1 sm:grid-cols-2 xl:grid-cols-3"}`}>
      {THEMES.map((t) => <Swatch key={t.id} t={t} active={th.theme === t.id} onClick={() => th.set({ theme: t.id })} compact={compact} />)}
    </div>
  );
}

const ACCENTS = ["#2cff9a", "#38d6ff", "#ff5468", "#c48cff", "#ffb03a", "#ff6ec7", "#7cffd8", "#f5f5f5"];

export function AccentPicker() {
  const th = useTheme();
  const [draft, setDraft] = useState(th.accent || th.def.p.accent);
  const current = th.accent || th.P.accent;
  const [synced, setSynced] = useState(current);
  if (synced !== current) {
    setSynced(current);
    setDraft(current);
  }
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        {ACCENTS.map((c) => (
          <button key={c} onClick={() => th.set({ accent: c })} aria-label={`Accent ${c}`} title={c}
            className={`h-8 w-8 rounded-full border-2 transition hover:scale-110 ${th.accent === c ? "border-text" : "border-line2"}`} style={{ background: c }} />
        ))}
        <label className="flex h-8 cursor-pointer items-center gap-2 rounded-md border border-line2 bg-inset px-2 text-[0.8125rem] text-muted hover:border-neon" title="Pick any colour">
          <input type="color" value={isHex(draft) ? draft : "#2cff9a"} onChange={(e) => { setDraft(e.target.value); th.set({ accent: e.target.value }); }}
            className="h-5 w-6 cursor-pointer border-0 bg-transparent p-0" aria-label="Custom accent colour" />
          Custom
        </label>
        {th.accent && (
          <button className="btn !px-2.5 !py-1 text-[0.8125rem]" onClick={() => th.set({ accent: null })}><RotateCcw size={13} /> Theme default</button>
        )}
      </div>
      {th.accent && th.accent.toLowerCase() !== th.P.accent.toLowerCase() && (
        <p className="text-[0.8125rem] text-muted">Adjusted to <span className="mono" style={{ color: th.P.accent }}>{th.P.accent}</span> so text in this colour stays readable on this theme.</p>
      )}
    </div>
  );
}

export function FontSizePicker() {
  const th = useTheme();
  return (
    <div className="inline-flex rounded-md border border-line2 bg-inset p-0.5" role="radiogroup" aria-label="Text size">
      {FONT_SIZES.map((f, i) => (
        <button key={f.id} role="radio" aria-checked={th.font === f.id} onClick={() => th.set({ font: f.id })}
          className={`flex items-center gap-1.5 rounded px-3 py-1.5 font-semibold transition ${th.font === f.id ? "bg-neon text-on-accent" : "text-muted hover:bg-panel2 hover:text-text"}`}>
          <Type size={12 + i * 2} /> <span className="text-[0.8125rem]">{f.label}</span>
        </button>
      ))}
    </div>
  );
}

/** Header dropdown: quick theme + text size switch. */
export function ThemeMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const th = useTheme();
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", h);
    document.addEventListener("keydown", k);
    return () => { document.removeEventListener("mousedown", h); document.removeEventListener("keydown", k); };
  }, [open]);
  return (
    <div className="relative" ref={ref}>
      <button onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="dialog" title="Change colour theme and text size"
        className="flex items-center gap-1.5 rounded-md border border-line2 bg-panel2 px-2.5 py-1 text-[0.8125rem] font-medium text-text hover:border-neon">
        <PaletteIcon size={14} className="text-neon" />
        <span className="hidden sm:inline">{th.def.label}</span>
      </button>
      {open && (
        <div role="dialog" aria-label="Appearance" className="absolute right-0 top-full z-50 mt-2 w-[300px] max-w-[calc(100vw-1.5rem)] space-y-3 rounded-lg border border-line2 bg-panel p-3 shadow-2xl shadow-black/50">
          <div className="text-[0.75rem] font-semibold uppercase tracking-[.08em] text-muted">Colour theme</div>
          <ThemeGrid compact />
          <div className="text-[0.75rem] font-semibold uppercase tracking-[.08em] text-muted">Text size</div>
          <FontSizePicker />
          <div className="text-[0.8125rem] text-muted">More options (custom accent colour, effects) in <Link href="/settings#appearance" onClick={() => setOpen(false)} className="text-accent underline">Settings</Link>.</div>
        </div>
      )}
    </div>
  );
}
