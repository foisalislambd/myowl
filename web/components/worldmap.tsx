"use client";

import { geoNaturalEarth1, geoPath, geoInterpolate } from "d3-geo";
import { useMemo, useState } from "react";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { FeatureCollection } from "geojson";
import world from "world-atlas/countries-110m.json";
import { flagEmoji, fmtRate } from "@/lib/format";
import type { CountryStat, Geo, GeoPoint } from "@/lib/types";

const W = 960;
const H = 470;

const topo = world as unknown as Topology<{ countries: GeometryCollection }>;
const countries = feature(topo, topo.objects.countries) as unknown as FeatureCollection;

// ISO numeric → alpha-2 for the countries we color (subset is fine: unknown ones stay neutral).
import { numericToAlpha2 } from "@/lib/iso";

export function WorldMap({ points, server, countryStats, onSelect, height }: {
  points: GeoPoint[]; server?: Geo; countryStats?: CountryStat[]; onSelect?: (p: GeoPoint) => void; height?: number;
}) {
  const [hover, setHover] = useState<{ p: GeoPoint; x: number; y: number } | null>(null);
  const projection = useMemo(() => geoNaturalEarth1().fitExtent([[6, 6], [W - 6, H - 6]], { type: "Sphere" }), []);
  const path = useMemo(() => geoPath(projection), [projection]);
  const paths = useMemo(() => countries.features.map((f) => ({ id: String(f.id ?? ""), d: path(f) || "" })), [path]);
  const cmax = Math.max(1, ...(countryStats || []).map((c) => c.conns));
  const cmap = useMemo(() => {
    const m: Record<string, number> = {};
    for (const c of countryStats || []) m[c.cc] = c.conns;
    return m;
  }, [countryStats]);
  const maxConns = Math.max(1, ...points.map((p) => p.conns));
  const srv = server?.lat || server?.lon ? projection([server.lon!, server.lat!]) : null;

  const arc = (p: GeoPoint) => {
    if (!server || (!server.lat && !server.lon)) return "";
    const interp = geoInterpolate([server.lon!, server.lat!], [p.lon, p.lat]);
    const pts: string[] = [];
    for (let i = 0; i <= 24; i++) {
      const xy = projection(interp(i / 24));
      if (xy) pts.push(`${xy[0].toFixed(1)},${xy[1].toFixed(1)}`);
    }
    return "M" + pts.join("L");
  };

  return (
    <div className="relative w-full" style={height ? { height } : undefined}>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" preserveAspectRatio="xMidYMid meet">
        <path d={path({ type: "Sphere" }) || ""} fill="var(--c-inset)" stroke="var(--c-line2)" />
        {paths.map((c, i) => {
          const cc = numericToAlpha2[c.id];
          const v = cc ? cmap[cc] || 0 : 0;
          const a = v ? 0.18 + 0.55 * Math.sqrt(v / cmax) : 0;
          return <path key={i} d={c.d} fill={v ? `color-mix(in srgb, var(--c-accent2) ${Math.round(Math.max(0.18, a) * 100)}%, var(--c-line))` : "var(--c-line)"} stroke="var(--c-inset)" strokeWidth={0.5} />;
        })}
        {points.map((p, i) => (
          <path key={"a" + i} d={arc(p)} fill="none" stroke={p.threat ? "var(--c-danger)" : "var(--c-accent2)"} strokeOpacity={p.threat ? 0.55 : 0.25} strokeWidth={p.threat ? 1.2 : 0.8} />
        ))}
        {points.map((p, i) => {
          const xy = projection([p.lon, p.lat]);
          if (!xy) return null;
          const r = 2.5 + 7 * Math.sqrt(p.conns / maxConns);
          const c = p.threat ? "var(--c-danger)" : "var(--c-accent2)";
          return (
            <g key={"p" + i} transform={`translate(${xy[0]},${xy[1]})`} className="cursor-pointer"
              onMouseEnter={() => setHover({ p, x: xy[0], y: xy[1] })} onMouseLeave={() => setHover(null)} onClick={() => onSelect?.(p)}>
              {p.threat && <circle r={r + 4} fill="none" stroke={c} strokeOpacity={0.5}><animate attributeName="r" from={r} to={r + 9} dur="1.8s" repeatCount="indefinite" /><animate attributeName="stroke-opacity" from="0.6" to="0" dur="1.8s" repeatCount="indefinite" /></circle>}
              <circle r={r} fill={c} fillOpacity={0.8} stroke="var(--c-inset)" strokeWidth={0.8} />
            </g>
          );
        })}
        {srv && (
          <g transform={`translate(${srv[0]},${srv[1]})`}>
            <circle r={12} fill="var(--c-accent)" fillOpacity={0.18} />
            <circle r={5} fill="var(--c-accent)" stroke="var(--c-inset)" strokeWidth={1.5} />
          </g>
        )}
      </svg>
      {hover && (
        <div className="pointer-events-none absolute z-10 rounded-lg border border-line2 bg-panel px-3 py-2 text-text text-[0.875rem] shadow-xl"
          style={{ left: `${(hover.x / W) * 100}%`, top: `${(hover.y / H) * 100}%`, transform: "translate(-50%, calc(-100% - 12px))" }}>
          <div className="font-semibold">{flagEmoji(hover.p.cc)} {hover.p.city ? `${hover.p.city}, ` : ""}{hover.p.country}</div>
          <div className="text-muted">{hover.p.conns} connection(s) · {hover.p.ips.length} IP(s) · {fmtRate(hover.p.rate)}</div>
          {hover.p.threat && <div className="text-bad">⚠ includes a threatening IP</div>}
        </div>
      )}
      <div className="absolute bottom-2 left-3 flex gap-3 text-[0.8125rem] text-muted">
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-neon" /> your server</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-accent" /> visitors</span>
        <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-bad" /> threats</span>
      </div>
    </div>
  );
}
