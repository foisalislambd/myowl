"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef } from "react";
import { api } from "./api";
import { createLocalStore, useLocalStore } from "./store";

/**
 * Colour themes. Every colour in the UI comes from CSS variables (--c-*) set on
 * <html>, so DOM/SVG follow a theme switch instantly. Canvas/WebGL views (globe,
 * node graph, world map) read the resolved palette from useTheme().
 *
 * All text colours are checked to be WCAG AA (≥ 4.5:1) on bg, panel and panel2.
 */
export type Palette = {
  bg: string; bg2: string; panel: string; panel2: string; inset: string;
  line: string; line2: string; text: string; muted: string;
  accent: string; accent2: string; onAccent: string;
  ok: string; warn: string; danger: string; crit: string; info: string;
};
export type ThemeId = "matrix" | "cyan" | "crimson" | "synth" | "amber" | "light";
export type ThemeDef = { id: ThemeId; label: string; blurb: string; light: boolean; glow: number; p: Palette };
export type FontSize = "normal" | "large" | "xl";
export type ThemePrefs = { theme: ThemeId; accent: string | null; font: FontSize; updated: number };

const dark = { ok: "#3ff08e", warn: "#ffc24a", danger: "#ff5f6f", crit: "#ff66ee", info: "#7cc8ff", onAccent: "#04110b" };

export const THEMES: ThemeDef[] = [
  { id: "matrix", label: "Matrix Green", blurb: "Classic green terminal", light: false, glow: 1,
    p: { ...dark, bg: "#030a07", bg2: "#06110d", panel: "#0a1712", panel2: "#0f2119", inset: "#071410", line: "#1b3a2f", line2: "#2b5a49", text: "#e4fff4", muted: "#9fcfbd", accent: "#2cff9a", accent2: "#5fe3ff" } },
  { id: "cyan", label: "Cyber Cyan", blurb: "Cool blue operations room", light: false, glow: 1,
    p: { ...dark, onAccent: "#031019", bg: "#040912", bg2: "#07101c", panel: "#0b1625", panel2: "#102035", inset: "#08121f", line: "#1d3350", line2: "#2e4d74", text: "#e8f4ff", muted: "#a3bad3", accent: "#38d6ff", accent2: "#8fb0ff" } },
  { id: "crimson", label: "Red Alert", blurb: "Crimson war room", light: false, glow: 1,
    p: { ...dark, onAccent: "#1a0003", danger: "#ff4fe3", crit: "#c08cff", ok: "#4ee08a", warn: "#ffd04d", bg: "#0d0507", bg2: "#14080a", panel: "#1b0d10", panel2: "#261418", inset: "#14090b", line: "#46232b", line2: "#6e3542", text: "#ffeef0", muted: "#dcaeb5", accent: "#ff5468", accent2: "#ffa070" } },
  { id: "synth", label: "Purple Synthwave", blurb: "Neon purple and cyan", light: false, glow: 1,
    p: { ...dark, onAccent: "#12041f", ok: "#4fe3a3", warn: "#ffd05e", danger: "#ff5f78", crit: "#ff5cf0", bg: "#0a0614", bg2: "#0f091d", panel: "#160e28", panel2: "#1f1537", inset: "#120b21", line: "#3a2862", line2: "#583d8f", text: "#f6edff", muted: "#c6b3e3", accent: "#c48cff", accent2: "#58e1ff" } },
  { id: "amber", label: "Amber Retro", blurb: "Old-school amber CRT", light: false, glow: 0.8,
    p: { ...dark, onAccent: "#1a0f00", ok: "#8be37a", warn: "#fff25c", danger: "#ff6a5a", crit: "#ff6ad8", info: "#88d2ff", bg: "#0b0803", bg2: "#110c05", panel: "#191208", panel2: "#23190c", inset: "#140e06", line: "#47351b", line2: "#6d5226", text: "#fff1d6", muted: "#dcbf92", accent: "#ffb03a", accent2: "#ffe08a" } },
  { id: "light", label: "Daylight", blurb: "Clean light mode for bright rooms", light: true, glow: 0,
    p: { bg: "#eef2f6", bg2: "#ffffff", panel: "#ffffff", panel2: "#f4f7fa", inset: "#f6f8fb", line: "#d6dee6", line2: "#a9b7c4", text: "#0e1a25", muted: "#4b5b6a", accent: "#047857", accent2: "#0b5fb3", onAccent: "#ffffff", ok: "#0b7a3b", warn: "#9a5a00", danger: "#c8102e", crit: "#a3159a", info: "#1c5fc6" } },
];

export const FONT_SIZES: { id: FontSize; label: string; px: number }[] = [
  { id: "normal", label: "Normal", px: 16 },
  { id: "large", label: "Large", px: 18 },
  { id: "xl", label: "Extra large", px: 20 },
];

const KEY = "myowl-theme";
const VARS_KEY = "myowl-theme-vars";
const defaults: ThemePrefs = { theme: "matrix", accent: null, font: "normal", updated: 0 };

/* ---------- colour maths ---------- */
function rgb(h: string): [number, number, number] {
  const x = h.replace("#", "");
  const f = x.length === 3 ? x.split("").map((c) => c + c).join("") : x.slice(0, 6);
  return [0, 2, 4].map((i) => parseInt(f.slice(i, i + 2), 16)) as [number, number, number];
}
const hex = (r: number, g: number, b: number) => "#" + [r, g, b].map((v) => Math.round(Math.max(0, Math.min(255, v))).toString(16).padStart(2, "0")).join("");
function lum(h: string) {
  const c = rgb(h).map((v) => v / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
}
export function contrast(a: string, b: string) {
  const x = lum(a), y = lum(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}
/** Blend a toward b by t (0..1). */
export function blend(a: string, b: string, t: number) {
  const A = rgb(a), B = rgb(b);
  return hex(A[0] + (B[0] - A[0]) * t, A[1] + (B[1] - A[1]) * t, A[2] + (B[2] - A[2]) * t);
}
/** Hex colour with alpha for canvas/WebGL (a = 0..1). */
export function hexA(h: string, a: number) {
  const [r, g, b] = rgb(h);
  return `rgba(${r},${g},${b},${a})`;
}
/** Nudge a colour lighter/darker until it reaches the target contrast on every background. */
function readable(c: string, bgs: string[], target: number, toward: string) {
  let out = c;
  for (let i = 0; i <= 20 && Math.min(...bgs.map((b) => contrast(out, b))) < target; i++) out = blend(c, toward, i / 20);
  return out;
}
export const isHex = (s: unknown): s is string => typeof s === "string" && /^#[0-9a-f]{6}$/i.test(s);

export function resolve(prefs: ThemePrefs): ThemeDef {
  const base = THEMES.find((t) => t.id === prefs.theme) || THEMES[0];
  if (!isHex(prefs.accent)) return base;
  const p = { ...base.p };
  p.accent = readable(prefs.accent, [p.bg, p.panel, p.panel2], 4.5, base.light ? "#000000" : "#ffffff");
  p.onAccent = contrast(p.accent, "#ffffff") >= contrast(p.accent, "#000000") ? "#ffffff" : "#05070a";
  return { ...base, p };
}

/** CSS custom properties for a theme. Also cached for the pre-paint script in layout.tsx. */
export function cssVars(t: ThemeDef, font: FontSize): Record<string, string> {
  const v: Record<string, string> = {};
  for (const [k, val] of Object.entries(t.p)) v[`--c-${k.replace(/[A-Z]/g, (m) => "-" + m.toLowerCase())}`] = val;
  v["--glow"] = String(t.glow);
  v["--fx-alpha"] = t.light ? "0.35" : "1";
  v["font-size"] = `${FONT_SIZES.find((f) => f.id === font)?.px ?? 16}px`;
  return v;
}

function apply(t: ThemeDef, font: FontSize) {
  const el = document.documentElement;
  const vars = cssVars(t, font);
  for (const [k, val] of Object.entries(vars)) el.style.setProperty(k, val);
  el.dataset.theme = t.id;
  el.classList.toggle("dark", !t.light);
  el.classList.toggle("light", t.light);
  el.style.colorScheme = t.light ? "light" : "dark";
  try {
    localStorage.setItem(VARS_KEY, JSON.stringify({ vars, id: t.id, light: t.light }));
  } catch {
    /* ignore */
  }
}

function parsePrefs(raw: string | null): ThemePrefs {
  try {
    if (raw) {
      const p = { ...defaults, ...JSON.parse(raw) } as ThemePrefs;
      if (!THEMES.some((t) => t.id === p.theme)) p.theme = defaults.theme;
      if (!FONT_SIZES.some((f) => f.id === p.font)) p.font = "normal";
      if (!isHex(p.accent)) p.accent = null;
      return p;
    }
  } catch {
    /* ignore */
  }
  return defaults;
}

const prefsStore = createLocalStore<ThemePrefs>(KEY, parsePrefs, defaults);

type Ctx = ThemePrefs & {
  def: ThemeDef;
  P: Palette;
  light: boolean;
  /** Font scale factor for canvas text (1, 1.125, 1.25). */
  scale: number;
  set: (p: Partial<Omit<ThemePrefs, "updated">>) => void;
  syncServer: () => void;
};
const ThemeCtx = createContext<Ctx>({ ...defaults, def: THEMES[0], P: THEMES[0].p, light: false, scale: 1, set: () => {}, syncServer: () => {} });

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const prefs = useLocalStore(prefsStore);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const def = useMemo(() => resolve(prefs), [prefs]);
  useEffect(() => {
    // Always apply what is really stored (the first, hydration render uses defaults).
    const cur = prefsStore.get();
    apply(resolve(cur), cur.font);
  }, [def, prefs.font]);

  const set = useCallback((x: Partial<Omit<ThemePrefs, "updated">>) => {
    const n = { ...prefsStore.get(), ...x, updated: Date.now() };
    prefsStore.set(n);
    // Save to the server too (debounced) so other devices get the same look.
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      api("/api/prefs", { method: "PUT", body: { theme: n.theme, accent: n.accent, font: n.font, updated: n.updated } }).catch(() => {});
    }, 600);
  }, []);

  /** Pull the server copy after login; newer wins. */
  const syncServer = useCallback(() => {
    api<{ prefs: Partial<ThemePrefs> }>("/api/prefs")
      .then(({ prefs: s }) => {
        if (!s || typeof s.updated !== "number") return;
        const cur = prefsStore.get();
        if (s.updated <= cur.updated) return;
        prefsStore.set({
          theme: THEMES.some((t) => t.id === s.theme) ? (s.theme as ThemeId) : cur.theme,
          accent: isHex(s.accent) ? s.accent : null,
          font: FONT_SIZES.some((f) => f.id === s.font) ? (s.font as FontSize) : cur.font,
          updated: s.updated,
        });
      })
      .catch(() => {});
  }, []);

  const scale = (FONT_SIZES.find((f) => f.id === prefs.font)?.px ?? 16) / 16;
  return <ThemeCtx.Provider value={{ ...prefs, def, P: def.p, light: def.light, scale, set, syncServer }}>{children}</ThemeCtx.Provider>;
}

export const useTheme = () => useContext(ThemeCtx);

/** Applied inline in <head> before first paint, from the cached variables. */
export const themeInitScript = `try{var s=JSON.parse(localStorage.getItem("${VARS_KEY}")||"null");if(s&&s.vars){var e=document.documentElement;for(var k in s.vars)e.style.setProperty(k,s.vars[k]);e.dataset.theme=s.id;if(s.light){e.classList.remove("dark");e.classList.add("light");e.style.colorScheme="light"}}}catch(_){}`;

/* ---------- CSS-variable colour helpers for DOM/SVG ---------- */
export const C = {
  bg: "var(--c-bg)", bg2: "var(--c-bg2)", panel: "var(--c-panel)", panel2: "var(--c-panel2)", inset: "var(--c-inset)",
  line: "var(--c-line)", line2: "var(--c-line2)", text: "var(--c-text)", muted: "var(--c-muted)",
  accent: "var(--c-accent)", accent2: "var(--c-accent2)", onAccent: "var(--c-on-accent)",
  ok: "var(--c-ok)", warn: "var(--c-warn)", danger: "var(--c-danger)", crit: "var(--c-crit)", info: "var(--c-info)",
};
/** Colour with transparency, works with var() colours (pct = 0..100). */
export const mix = (c: string, pct: number) => `color-mix(in srgb, ${c} ${pct}%, transparent)`;
/** Neon text glow that fades out in themes without glow (light mode). */
export const glow = (c: string, px = 8, pct = 60) => `0 0 calc(${px}px * var(--glow)) ${mix(c, pct)}`;
