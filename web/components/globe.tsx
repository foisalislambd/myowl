"use client";

import { useEffect, useRef } from "react";
import { feature } from "topojson-client";
import type { Topology, GeometryCollection } from "topojson-specification";
import type { FeatureCollection } from "geojson";
import world from "world-atlas/countries-110m.json";
import type { GlobeInstance } from "globe.gl";
import { blend, hexA, type Palette } from "@/lib/theme";

export type GlobeSource = {
  id: string; // ip or city key
  ip?: string;
  lat: number;
  lon: number;
  label: string;
  kind: "normal" | "threat" | "blocked";
  weight: number; // 0..1 traffic share
};

type Arc = { startLat: number; startLng: number; endLat: number; endLng: number; src: GlobeSource };

// world-atlas 110m contains a few degenerate rings (e.g. a zero-area sliver of North Korea) that make h3's
// polygonToCells throw; drop rings with fewer than 3 distinct points so every country still renders.
const okRing = (r: number[][]) => new Set(r.map((p) => p[0].toFixed(5) + "," + p[1].toFixed(5))).size >= 3;
const countries = (feature(world as unknown as Topology, (world as unknown as Topology).objects.countries as GeometryCollection) as unknown as FeatureCollection).features
  .map((f) => {
    const g = f.geometry as { type: string; coordinates: number[][][] | number[][][][] };
    if (g?.type === "MultiPolygon") return { ...f, geometry: { ...g, coordinates: (g.coordinates as number[][][][]).filter((poly) => okRing(poly[0])) } } as typeof f;
    return f;
  })
  .filter((f) => {
    const g = f.geometry as { type: string; coordinates: number[][][] | number[][][][] } | null;
    if (!g) return false;
    return g.type === "Polygon" ? okRing((g.coordinates as number[][][])[0]) : (g.coordinates as number[][][][]).length > 0;
  });

/**
 * Rotating 3D globe with animated arcs from every remote location to the
 * server. Threats are red pulsing arcs, normal traffic cyan, blocked IPs dim with an ✕.
 */
export function Globe3D({ server, sources, reduce, onSelect, height, palette, light }: {
  server: { lat: number; lon: number; city?: string };
  palette: Palette;
  light?: boolean;
  sources: GlobeSource[];
  reduce?: boolean;
  onSelect?: (s: GlobeSource) => void;
  height?: number;
}) {
  const el = useRef<HTMLDivElement>(null);
  const g = useRef<GlobeInstance | null>(null);
  const sel = useRef(onSelect);
  sel.current = onSelect;

  // create once
  useEffect(() => {
    const host = el.current;
    let cancelled = false;
    let ro: ResizeObserver | null = null;
    let onVis: (() => void) | null = null;
    (async () => {
      const { default: Globe } = await import("globe.gl");
      if (cancelled || !el.current) return;
      const node = el.current;
      const globe = new Globe(node, { rendererConfig: { antialias: true, alpha: true, powerPreference: "high-performance" } })
        .backgroundColor("rgba(0,0,0,0)")
        .showAtmosphere(true)
        .atmosphereAltitude(0.18)
        .showGraticules(true)
        .hexPolygonsData(countries)
        .hexPolygonResolution(3)
        .hexPolygonMargin(0.35)
        .hexPolygonUseDots(true)
        .hexPolygonsTransitionDuration(0)
        .arcStartLat("startLat").arcStartLng("startLng").arcEndLat("endLat").arcEndLng("endLng")
        .arcStroke((a: object) => { const s = (a as Arc).src; return s.kind === "threat" ? 0.9 : s.kind === "blocked" ? 0.25 : 0.25 + s.weight * 0.9; })
        .arcDashLength((a: object) => ((a as Arc).src.kind === "blocked" ? 1 : 0.35))
        .arcDashGap((a: object) => ((a as Arc).src.kind === "blocked" ? 0 : 0.9))
        .arcDashInitialGap(() => Math.random())
        .arcDashAnimateTime((a: object) => ((a as Arc).src.kind === "threat" ? 1100 : (a as Arc).src.kind === "blocked" ? 0 : 2600))
        .arcAltitudeAutoScale(0.45)
        .arcsTransitionDuration(0)
        .arcLabel((a: object) => tip((a as Arc).src))
        .onArcClick((a: object) => sel.current?.((a as Arc).src))
        .pointLat("lat").pointLng("lon")
        .pointAltitude(0.01)
        .pointRadius((p: object) => ((p as GlobeSource).kind === "threat" ? 0.55 : 0.3 + (p as GlobeSource).weight * 0.4))
        .pointsMerge(false)
        .pointsTransitionDuration(0)
        .pointLabel((p: object) => tip(p as GlobeSource))
        .onPointClick((p: object) => sel.current?.(p as GlobeSource))
        .ringLat("lat").ringLng("lon")
        .ringMaxRadius((r: object) => ((r as { c: string }).c === "server" ? 6 : 4))
        .ringPropagationSpeed(2.5)
        .ringRepeatPeriod((r: object) => ((r as { c: string }).c === "server" ? 1400 : 900))
        .htmlLat("lat").htmlLng("lon").htmlAltitude(0.02)
        .htmlElement((d: object) => marker(d as Marker, (s) => sel.current?.(s)));
      const c = globe.controls();
      c.autoRotate = true;
      c.autoRotateSpeed = 0.55;
      c.enableDamping = true;
      globe.pointOfView({ lat: server.lat - 8, lng: server.lon - 30, altitude: 2.25 }, 0);
      const size = () => globe.width(node.clientWidth).height(node.clientHeight);
      size();
      ro = new ResizeObserver(size);
      ro.observe(node);
      onVis = () => (document.hidden ? globe.pauseAnimation() : globe.resumeAnimation());
      document.addEventListener("visibilitychange", onVis);
      g.current = globe;
      applyTheme();
      apply();
    })();
    return () => {
      cancelled = true;
      ro?.disconnect();
      if (onVis) document.removeEventListener("visibilitychange", onVis);
      try {
        g.current?._destructor();
      } catch {
        /* ignore */
      }
      g.current = null;
      if (host) host.innerHTML = "";
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const latest = useRef({ server, sources, reduce, palette, light });
  latest.current = { server, sources, reduce, palette, light };

  /** Push theme colours into the WebGL scene (globe surface, dots, arcs, points, rings). */
  function applyTheme() {
    const globe = g.current;
    if (!globe) return;
    const { palette: P, light } = latest.current;
    globe
      .atmosphereColor(P.accent)
      .atmosphereAltitude(light ? 0.12 : 0.18)
      .hexPolygonColor(() => hexA(P.accent, light ? 0.75 : 0.55))
      .arcColor((a: object) => {
        const k = (a as Arc).src.kind;
        return k === "threat" ? [hexA(P.crit, 0.95), hexA(P.danger, 0.95)] : k === "blocked" ? [hexA(P.muted, 0.3), hexA(P.muted, 0.1)] : [hexA(P.accent2, light ? 0.35 : 0.15), hexA(P.accent, 0.9)];
      })
      .pointColor((p: object) => color((p as GlobeSource).kind, P))
      .ringColor((r: object) => {
        const c = (r as { c: string }).c === "server" ? P.accent : P.danger;
        return (t: number) => hexA(c, 1 - t);
      });
    const mat = globe.globeMaterial() as unknown as { color: { set: (c: string) => void }; emissive?: { set: (c: string) => void }; emissiveIntensity?: number; shininess?: number };
    mat.color.set(light ? "#1d2b3a" : blend(P.bg, P.accent, 0.05));
    mat.emissive?.set(light ? "#0e1824" : blend(P.bg, "#000000", 0.2));
    if (mat.emissiveIntensity !== undefined) mat.emissiveIntensity = 0.6;
    if (mat.shininess !== undefined) mat.shininess = 4;
  }

  useEffect(() => {
    applyTheme();
  }, [palette, light]);

  function apply() {
    const globe = g.current;
    if (!globe) return;
    const { server, sources, reduce } = latest.current;
    const arcs: Arc[] = sources.map((s) => ({ startLat: s.lat, startLng: s.lon, endLat: server.lat, endLng: server.lon, src: s }));
    globe.arcsData(arcs);
    globe.pointsData(sources.filter((s) => s.kind !== "blocked"));
    globe.ringsData(reduce ? [] : [{ lat: server.lat, lon: server.lon, c: "server" }, ...sources.filter((s) => s.kind === "threat").slice(0, 20).map((s) => ({ lat: s.lat, lon: s.lon, c: "threat" }))]);
    const markers: Marker[] = [{ type: "server", lat: server.lat, lon: server.lon, label: server.city || "server" }, ...sources.filter((s) => s.kind === "blocked").slice(0, 40).map((s) => ({ type: "blocked" as const, lat: s.lat, lon: s.lon, label: s.label, src: s }))];
    globe.htmlElementsData(markers);
    const c = globe.controls();
    c.autoRotate = !reduce;
  }

  useEffect(() => {
    apply();
  }, [sources, server.lat, server.lon, reduce]);

  return <div ref={el} className="globe-host h-full w-full cursor-grab active:cursor-grabbing" style={height ? { height } : undefined} />;
}

type Marker = { type: "server" | "blocked"; lat: number; lon: number; label: string; src?: GlobeSource };

function color(k: GlobeSource["kind"], P: Palette) {
  return k === "threat" ? P.danger : k === "blocked" ? P.muted : P.accent;
}
const cssColor = (k: GlobeSource["kind"]) => (k === "threat" ? "var(--c-danger)" : k === "blocked" ? "var(--c-muted)" : "var(--c-accent)");

function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function tip(s: GlobeSource) {
  const c = cssColor(s.kind);
  const what = s.kind === "threat" ? "THREAT SOURCE" : s.kind === "blocked" ? "BLOCKED" : "CONNECTION";
  return `<div style="font-family:var(--font-mono);font-size:0.875rem;line-height:1.45;padding:8px 10px;border-radius:6px;background:var(--c-panel);border:1px solid ${c};color:var(--c-text);box-shadow:0 8px 24px rgb(0 0 0 / .45)">
    <div style="color:${c};letter-spacing:.08em;font-size:0.75rem;font-weight:700">${what}</div>${esc(s.label)}<div style="color:var(--c-muted);font-size:0.8125rem">Click for details</div></div>`;
}

function marker(d: Marker, onSel: (s: GlobeSource) => void): HTMLElement {
  const n = document.createElement("div");
  n.style.pointerEvents = "auto";
  n.style.transform = "translate(-50%, -50%)";
  if (d.type === "server") {
    n.innerHTML = `<div style="display:flex;flex-direction:column;align-items:center;gap:2px;font-family:var(--font-sans);">
      <div style="width:13px;height:13px;border:2px solid var(--c-accent);transform:rotate(45deg);box-shadow:0 0 calc(12px * var(--glow)) var(--c-accent);background:color-mix(in srgb, var(--c-accent) 30%, transparent)"></div>
      <div style="margin-top:5px;padding:2px 6px;border-radius:4px;background:color-mix(in srgb, var(--c-panel) 85%, transparent);border:1px solid color-mix(in srgb, var(--c-accent) 50%, transparent);text-align:center">
        <div style="font-size:0.75rem;font-weight:700;letter-spacing:.08em;color:var(--c-accent);white-space:nowrap">◆ YOUR SERVER</div>
        <div style="font-size:0.75rem;color:var(--c-text);font-family:var(--font-mono);white-space:nowrap">${esc(d.label)}</div></div></div>`;
    n.style.pointerEvents = "none";
  } else {
    n.innerHTML = `<div title="Blocked: ${esc(d.label)}" style="color:var(--c-danger);opacity:.8;font:700 14px var(--font-mono);text-shadow:0 0 calc(6px * var(--glow)) var(--c-danger);cursor:pointer">✕</div>`;
    n.onclick = () => d.src && onSel(d.src);
  }
  return n;
}
