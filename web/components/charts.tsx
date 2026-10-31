"use client";

import { Area, AreaChart, Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { C, glow, mix, useTheme } from "@/lib/theme";

export type Series = { key: string; name: string; color: string; stack?: string };

/** Axis styling: readable tick labels (muted colour, ≥ 12px, scaled with the text-size setting). */
function useAxis() {
  const { scale } = useTheme();
  const fs = Math.round(12 * scale);
  return { stroke: C.line2, tick: { fill: C.muted, fontSize: fs, fontFamily: "var(--font-mono)" }, tickLine: false, axisLine: { stroke: C.line2 } } as const;
}
const GRID = C.line;
const legendStyle = { fontSize: "0.8125rem", color: C.muted, paddingTop: 6 };

const STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 172800, 604800].map((s) => s * 1000);

/** Local-time offset (ms) of the browser at time t. */
const tzOff = (t: number) => -new Date(t).getTimezoneOffset() * 60000;

/**
 * Evenly spaced "nice" tick times between min and max, aligned to the
 * browser's local clock (so hour/day ticks land on :00 / midnight locally).
 */
export function niceTimeTicks(min: number, max: number, target = 6): { ticks: number[]; step: number } {
  if (!(max > min)) return { ticks: Number.isFinite(min) ? [min] : [], step: 60000 };
  const span = max - min;
  const step = STEPS.find((s) => span / s <= target) ?? Math.ceil(span / target / 86400000) * 86400000;
  const off = tzOff(min);
  const ticks: number[] = [];
  for (let t = Math.ceil((min + off) / step) * step - off; t <= max; t += step) ticks.push(t);
  return { ticks, step };
}

const fmtCache = new Map<string, Intl.DateTimeFormat>();
function dtf(key: string, o: Intl.DateTimeFormatOptions) {
  let f = fmtCache.get(key);
  if (!f) {
    f = new Intl.DateTimeFormat(undefined, { hourCycle: "h23", ...o });
    fmtCache.set(key, f);
  }
  return f;
}

/** Tick label in browser-local time; precision follows the tick step so labels never repeat. */
export function timeTick(ts: number, step: number, span: number) {
  const d = new Date(ts);
  if (step >= 86400000) return dtf("d", { day: "2-digit", month: "short" }).format(d);
  if (step < 60000) return dtf("s", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(d);
  if (span > 20 * 3600000) return dtf("dm", { weekday: "short", hour: "2-digit", minute: "2-digit" }).format(d);
  return dtf("m", { hour: "2-digit", minute: "2-digit" }).format(d);
}

/** Short local time-zone name shown under charts, e.g. "GMT+6". */
export function tzLabel() {
  try {
    return new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(new Date()).find((p) => p.type === "timeZoneName")?.value || "";
  } catch {
    return "";
  }
}

function TipBox({ active, payload, label, fmt }: { active?: boolean; payload?: { name: string; value: number; color: string }[]; label?: number; fmt: (v: number) => string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border border-line2 bg-panel px-3 py-2 text-[0.875rem] text-text shadow-xl shadow-black/40">
      <div className="mono mb-1 text-[0.8125rem] text-muted">{label ? `${dtf("tip", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short" }).format(new Date(label))}` : ""}</div>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: p.color }} />
            {p.name}
          </span>
          <span className="mono font-semibold tabular-nums text-text">{fmt(p.value)}</span>
        </div>
      ))}
    </div>
  );
}

function useTicks<T extends { ts: number }>(data: T[]) {
  const min = data.length ? data[0].ts : 0;
  const max = data.length ? data[data.length - 1].ts : 0;
  const { ticks, step } = niceTimeTicks(min, max);
  return { ticks, step, span: max - min, min, max };
}

export function TimeArea<T extends { ts: number }>({ data, series, height = 220, fmt = (v) => String(Math.round(v)), yMax, stacked, legend }: {
  data: T[]; series: Series[]; height?: number; fmt?: (v: number) => string; yMax?: number; stacked?: boolean; legend?: boolean;
}) {
  const { ticks, step, span } = useTicks(data);
  const axis = useAxis();
  const { scale } = useTheme();
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
        <defs>
          {series.map((s) => (
            <linearGradient key={s.key} id={`g-${s.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity={0.35} />
              <stop offset="100%" stopColor={s.color} stopOpacity={0.02} />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid stroke={GRID} strokeDasharray="2 4" />
        <XAxis dataKey="ts" type="number" domain={["dataMin", "dataMax"]} ticks={ticks} interval={0} tickFormatter={(v) => timeTick(v, step, span)} {...axis} minTickGap={8} />
        <YAxis {...axis} width={Math.round(80 * scale)} tickFormatter={fmt} domain={[0, yMax ?? "auto"]} allowDecimals={false} />
        <Tooltip content={<TipBox fmt={fmt} />} cursor={{ stroke: C.line2, strokeDasharray: "3 3" }} />
        {legend && <Legend iconType="square" iconSize={10} wrapperStyle={legendStyle} />}
        {series.map((s) => (
          <Area
            key={s.key}
            type="monotone"
            dataKey={s.key}
            name={s.name}
            stroke={s.color}
            strokeWidth={2}
            fill={`url(#g-${s.key})`}
            stackId={stacked ? "a" : undefined}
            isAnimationActive={false}
            dot={false}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function TimeBars<T extends { ts: number }>({ data, series, height = 200, fmt = (v) => String(Math.round(v)), legend = true }: {
  data: T[]; series: Series[]; height?: number; fmt?: (v: number) => string; legend?: boolean;
}) {
  const { step, span } = useTicks(data);
  // Category axis: show only bars that start a new "nice" step, so labels are distinct.
  const ticks = barTicks(data.map((d) => d.ts), step);
  const axis = useAxis();
  const { scale } = useTheme();
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} margin={{ top: 6, right: 6, bottom: 0, left: 0 }}>
        <CartesianGrid stroke={GRID} strokeDasharray="2 4" vertical={false} />
        <XAxis dataKey="ts" ticks={ticks} interval={0} tickFormatter={(v) => timeTick(v, Math.max(step, barStep(data)), span)} {...axis} minTickGap={8} />
        <YAxis {...axis} width={Math.round(58 * scale)} tickFormatter={fmt} allowDecimals={false} />
        <Tooltip content={<TipBox fmt={fmt} />} cursor={{ fill: mix(C.accent, 8) }} />
        {legend && <Legend iconType="square" iconSize={10} wrapperStyle={legendStyle} />}
        {series.map((s) => (
          <Bar key={s.key} dataKey={s.key} name={s.name} fill={s.color} fillOpacity={0.9} stackId={s.stack ?? "a"} isAnimationActive={false} />
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

export function Spark({ data, color, height = 36 }: { data: { ts: number; v: number }[]; color: string; height?: number }) {
  const id = "s" + color.replace(/[^a-z0-9]/gi, "");
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 2, right: 0, bottom: 0, left: 0 }}>
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.4} />
            <stop offset="100%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <YAxis hide domain={[0, "auto"]} />
        <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.75} fill={`url(#${id})`} isAnimationActive={false} dot={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function barStep<T extends { ts: number }>(data: T[]) {
  return data.length > 1 ? data[1].ts - data[0].ts : 60000;
}

function barTicks(ts: number[], step: number): number[] {
  if (ts.length < 2) return ts;
  const idx: number[] = [];
  let last = "";
  ts.forEach((t, i) => {
    const k = String(Math.floor((t + tzOff(t)) / step));
    if (k !== last) {
      idx.push(i);
      last = k;
    }
  });
  // The first bar usually sits part-way into a bucket; drop its label if it would crowd the next one.
  if (idx.length >= 3 && idx[1] - idx[0] < 0.6 * (idx[2] - idx[1])) idx.shift();
  return idx.map((i) => ts[i]);
}

/** Horizontal ranked bars (top paths, countries, …). */
export function RankBars({ items, color = C.accent2, onClick, fmt = (v: number) => v.toLocaleString("en-US") }: {
  items: { key: string; label: React.ReactNode; value: number; color?: string }[]; color?: string; onClick?: (k: string) => void; fmt?: (v: number) => string;
}) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <div className="space-y-1">
      {items.map((i) => (
        <div key={i.key} className={`group relative overflow-hidden rounded px-2.5 py-1.5 ${onClick ? "cursor-pointer hover:bg-panel2" : ""}`} onClick={() => onClick?.(i.key)}>
          <div className="absolute inset-y-0 left-0 rounded" style={{ width: `${(i.value / max) * 100}%`, background: `linear-gradient(90deg, ${mix(i.color || color, 10)}, ${mix(i.color || color, 26)})`, borderRight: `2px solid ${i.color || color}`, boxShadow: glow(i.color || color, 6, 30) }} />
          <div className="relative flex items-center justify-between gap-3 text-[0.9062rem]">
            <span className="min-w-0 truncate">{i.label}</span>
            <span className="mono shrink-0 font-medium tabular-nums text-text">{fmt(i.value)}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
