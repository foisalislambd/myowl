"use client";

import { useEffect, useLayoutEffect, useRef } from "react";
import { hexA, useTheme, type Palette } from "@/lib/theme";

export type GNode = {
  id: string;
  kind: "vps" | "service" | "ip" | "user";
  label: string;
  sub?: string;
  threat?: boolean;
  blocked?: boolean;
  weight?: number; // 0..1 traffic share, sizes the node
  anchor?: string; // id of the node it orbits (for layout)
  data?: unknown;
};
export type GEdge = { from: string; to: string; rate: number; threat?: boolean; blocked?: boolean };

type P = GNode & { x: number; y: number; vx: number; vy: number; r: number; pinned?: boolean };
type Particle = { e: number; t: number; speed: number };

const cols = (P: Palette) => ({ vps: P.accent, service: P.accent2, ip: P.info, user: P.warn, threat: P.danger, blocked: P.muted, edge: P.accent2 });

/**
 * Canvas force-directed network graph: VPS in the middle, services around it,
 * remote IPs and logged-in users on the outside. Particles flow along edges
 * (thicker edges = more traffic). Wheel to zoom, drag background to pan,
 * drag nodes to move them, click a node to select it.
 */
export function NodeGraph({ nodes, edges, selected, onSelect, reduce }: {
  nodes: GNode[]; edges: GEdge[]; selected?: string | null; onSelect?: (n: GNode | null) => void; reduce?: boolean;
}) {
  const host = useRef<HTMLDivElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const st = useRef({
    pos: new Map<string, P>(),
    list: [] as P[],
    edges: [] as (GEdge & { a: P; b: P; w: number })[],
    particles: [] as Particle[],
    view: { x: 0, y: 0, k: 1 },
    hover: null as P | null,
    selected: null as string | null,
    reduce: false,
    alpha: 1,
    dirty: true,
  });
  const cb = useRef(onSelect);
  const theme = useTheme();
  const pal = useRef({ P: theme.P, scale: theme.scale, light: theme.light });
  // Mirror the latest props into refs for the animation loop (after render, not during).
  useLayoutEffect(() => {
    cb.current = onSelect;
    if (pal.current.P !== theme.P || pal.current.scale !== theme.scale) st.current.dirty = true;
    pal.current = { P: theme.P, scale: theme.scale, light: theme.light };
    st.current.selected = selected ?? null;
    st.current.reduce = !!reduce;
  });

  // (re)build simulation state, preserving positions of nodes we already know
  useEffect(() => {
    const s = st.current;
    const old = s.pos;
    const pos = new Map<string, P>();
    const svc = nodes.filter((n) => n.kind === "service");
    const R1 = 170;
    const R2 = 360;
    svc.forEach((n, i) => {
      const a = (i / Math.max(1, svc.length)) * Math.PI * 2 - Math.PI / 2;
      const o = old.get(n.id);
      pos.set(n.id, { ...n, x: o?.x ?? Math.cos(a) * R1, y: o?.y ?? Math.sin(a) * R1, vx: 0, vy: 0, r: 13 + (n.weight || 0) * 8, pinned: o?.pinned });
    });
    for (const n of nodes) {
      if (pos.has(n.id)) continue;
      const o = old.get(n.id);
      if (n.kind === "vps") {
        pos.set(n.id, { ...n, x: 0, y: 0, vx: 0, vy: 0, r: 26, pinned: true });
        continue;
      }
      const an = n.anchor ? pos.get(n.anchor) : undefined;
      const base = an ? Math.atan2(an.y, an.x) : hash(n.id) * Math.PI * 2;
      const a = base + (hash(n.id + "j") - 0.5) * 1.1;
      const rr = R2 + (hash(n.id + "r") - 0.5) * 120;
      pos.set(n.id, {
        ...n, x: o?.x ?? Math.cos(a) * rr, y: o?.y ?? Math.sin(a) * rr, vx: 0, vy: 0,
        r: n.kind === "user" ? 9 : 4 + Math.sqrt(n.weight || 0) * 9 + (n.threat ? 2 : 0), pinned: o?.pinned,
      });
    }
    s.pos = pos;
    s.list = [...pos.values()];
    s.edges = edges.flatMap((e) => {
      const a = pos.get(e.from);
      const b = pos.get(e.to);
      return a && b ? [{ ...e, a, b, w: 0.6 + Math.min(4, Math.log10(1 + e.rate / 1000)) }] : [];
    });
    // particles proportional to traffic
    const parts: Particle[] = [];
    s.edges.forEach((e, i) => {
      if (e.blocked) return;
      const n = e.threat ? 3 : Math.min(4, 1 + Math.floor(Math.log10(1 + e.rate / 2000)));
      for (let k = 0; k < n; k++) parts.push({ e: i, t: Math.random(), speed: (e.threat ? 0.5 : 0.18 + Math.random() * 0.15) * (0.7 + Math.random() * 0.6) });
    });
    s.particles = parts;
    s.alpha = old.size ? Math.max(s.alpha, 0.3) : 1;
    s.dirty = true;
  }, [nodes, edges]);

  useEffect(() => {
    const c = canvas.current!;
    const box = host.current!;
    const ctx = c.getContext("2d")!;
    const s = st.current;
    let w = 0, h = 0, dpr = 1, raf = 0, last = performance.now(), fitted = false;

    const resize = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1);
      w = box.clientWidth;
      h = box.clientHeight;
      c.width = w * dpr;
      c.height = h * dpr;
      c.style.width = w + "px";
      c.style.height = h + "px";
      if (!fitted && w > 0) {
        s.view.k = Math.min(w, h) / 900;
        fitted = true;
      }
      s.dirty = true;
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(box);

    const toWorld = (mx: number, my: number) => ({ x: (mx - w / 2 - s.view.x) / s.view.k, y: (my - h / 2 - s.view.y) / s.view.k });
    const hit = (mx: number, my: number) => {
      const p = toWorld(mx, my);
      let best: P | null = null, bd = Infinity;
      for (const n of s.list) {
        const d = Math.hypot(n.x - p.x, n.y - p.y);
        if (d < n.r + 6 / s.view.k && d < bd) { best = n; bd = d; }
      }
      return best;
    };

    // ---- physics: light force layout (repulsion + springs + radial pull)
    const step = () => {
      if (s.alpha < 0.02) return;
      const L = s.list;
      for (let i = 0; i < L.length; i++) {
        const a = L[i];
        for (let j = i + 1; j < L.length; j++) {
          const b = L[j];
          let dx = b.x - a.x, dy = b.y - a.y;
          let d2 = dx * dx + dy * dy;
          if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
          const min = (a.r + b.r + 18);
          if (d2 > 260 * 260) continue;
          const f = (min * min * 0.9) / d2;
          const d = Math.sqrt(d2);
          const fx = (dx / d) * f, fy = (dy / d) * f;
          a.vx -= fx; a.vy -= fy; b.vx += fx; b.vy += fy;
        }
      }
      for (const e of s.edges) {
        const target = e.a.kind === "vps" || e.b.kind === "vps" ? (e.a.kind === "service" || e.b.kind === "service" ? 170 : 330) : 170;
        const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y;
        const d = Math.hypot(dx, dy) || 1;
        const f = (d - target) * 0.012;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        e.a.vx += fx; e.a.vy += fy; e.b.vx -= fx; e.b.vy -= fy;
      }
      for (const n of L) {
        if (n.pinned || n.kind === "vps") { n.vx = n.vy = 0; if (n.kind === "vps") { n.x = 0; n.y = 0; } continue; }
        // keep rings: services ~170, outer ~360
        const want = n.kind === "service" ? 170 : 370;
        const d = Math.hypot(n.x, n.y) || 1;
        const f = (want - d) * 0.02;
        n.vx += (n.x / d) * f; n.vy += (n.y / d) * f;
        n.vx *= 0.6; n.vy *= 0.6;
        n.x += n.vx * s.alpha; n.y += n.vy * s.alpha;
      }
      s.alpha *= 0.985;
      s.dirty = true;
    };

    const draw = (t: number, dt: number) => {
      const k = s.view.k;
      const { P, scale, light } = pal.current;
      const COL = cols(P);
      const glowK = light ? 0.35 : 1;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, w, h);
      // radar rings backdrop
      ctx.save();
      ctx.translate(w / 2 + s.view.x, h / 2 + s.view.y);
      ctx.scale(k, k);
      ctx.strokeStyle = hexA(P.accent, light ? 0.14 : 0.08);
      ctx.lineWidth = 1 / k;
      for (const r of [170, 370, 520]) { ctx.beginPath(); ctx.arc(0, 0, r, 0, Math.PI * 2); ctx.stroke(); }
      ctx.setLineDash([2 / k, 6 / k]);
      for (let i = 0; i < 12; i++) { const a = (i / 12) * Math.PI * 2; ctx.beginPath(); ctx.moveTo(0, 0); ctx.lineTo(Math.cos(a) * 520, Math.sin(a) * 520); ctx.stroke(); }
      ctx.setLineDash([]);

      const sel = s.selected;
      const related = new Set<string>();
      if (sel) for (const e of s.edges) if (e.a.id === sel || e.b.id === sel) { related.add(e.a.id); related.add(e.b.id); }

      // edges
      for (const e of s.edges) {
        const on = !sel || related.has(e.a.id) && related.has(e.b.id) && (e.a.id === sel || e.b.id === sel);
        const c = e.blocked ? COL.blocked : e.threat ? COL.threat : COL.edge;
        ctx.strokeStyle = c;
        ctx.globalAlpha = (on ? (e.blocked ? 0.3 : light ? 0.5 : 0.38) : 0.06);
        ctx.lineWidth = e.w / Math.sqrt(k);
        if (e.blocked) ctx.setLineDash([4 / k, 4 / k]);
        ctx.beginPath(); ctx.moveTo(e.a.x, e.a.y); ctx.lineTo(e.b.x, e.b.y); ctx.stroke();
        ctx.setLineDash([]);
      }
      ctx.globalAlpha = 1;

      // particles (flow toward the server = inbound)
      if (!s.reduce) {
        for (const p of s.particles) {
          const e = s.edges[p.e];
          if (!e) continue;
          p.t += p.speed * dt;
          if (p.t > 1) p.t -= 1;
          // direction: from outer node (a) toward inner (b)
          const x = e.a.x + (e.b.x - e.a.x) * p.t, y = e.a.y + (e.b.y - e.a.y) * p.t;
          const on = !sel || e.a.id === sel || e.b.id === sel;
          const c = e.threat ? COL.threat : P.accent;
          ctx.globalAlpha = on ? 0.95 : 0.15;
          ctx.fillStyle = c;
          ctx.shadowColor = c;
          ctx.shadowBlur = 8 * glowK;
          ctx.beginPath(); ctx.arc(x, y, (e.threat ? 2.6 : 1.8) / Math.sqrt(k), 0, Math.PI * 2); ctx.fill();
        }
        ctx.shadowBlur = 0;
        ctx.globalAlpha = 1;
      }

      // nodes
      const pulse = (Math.sin(t / 260) + 1) / 2;
      for (const n of s.list) {
        const dim = sel && !related.has(n.id) && n.id !== sel;
        const c = n.blocked ? COL.blocked : n.threat ? COL.threat : COL[n.kind];
        ctx.globalAlpha = dim ? 0.25 : 1;
        ctx.shadowColor = c;
        ctx.shadowBlur = (n.kind === "vps" ? 24 : n.threat ? 10 + pulse * 14 : 10) * glowK;
        ctx.strokeStyle = c;
        ctx.fillStyle = hexA(c, n.kind === "vps" ? 0.25 : light ? 0.2 : 0.14);
        ctx.lineWidth = (n.id === sel ? 2.5 : 1.4) / Math.sqrt(k);
        ctx.beginPath();
        if (n.kind === "vps") poly(ctx, n.x, n.y, n.r, 6, t / 4000);
        else if (n.kind === "service") poly(ctx, n.x, n.y, n.r, 4, Math.PI / 4);
        else if (n.kind === "user") poly(ctx, n.x, n.y, n.r, 3, -Math.PI / 2);
        else ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fill(); ctx.stroke();
        ctx.shadowBlur = 0;
        if (n.threat && !n.blocked && !s.reduce) {
          ctx.globalAlpha = (dim ? 0.1 : 0.6) * (1 - pulse);
          ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 4 + pulse * 12, 0, Math.PI * 2); ctx.stroke();
          ctx.globalAlpha = dim ? 0.25 : 1;
        }
        if (n.blocked) {
          ctx.strokeStyle = COL.threat; ctx.globalAlpha = dim ? 0.2 : 0.8; ctx.lineWidth = 1.5 / Math.sqrt(k);
          const q = n.r + 2;
          ctx.beginPath(); ctx.moveTo(n.x - q, n.y - q); ctx.lineTo(n.x + q, n.y + q); ctx.moveTo(n.x + q, n.y - q); ctx.lineTo(n.x - q, n.y + q); ctx.stroke();
        }
        if (n.id === sel) {
          ctx.strokeStyle = P.text; ctx.globalAlpha = 0.9; ctx.lineWidth = 1 / k;
          bracket(ctx, n.x, n.y, n.r + 9);
        }
        // labels
        const showLabel = n.kind !== "ip" || k > 0.75 || n.threat || n.id === sel || s.hover?.id === n.id || (n.weight || 0) > 0.35;
        if (showLabel) {
          ctx.globalAlpha = dim ? 0.25 : 1;
          const sk = Math.sqrt(k);
          ctx.textAlign = "center";
          ctx.lineJoin = "round";
          ctx.strokeStyle = hexA(P.bg, 0.9);
          ctx.lineWidth = 3.5 / sk;
          ctx.fillStyle = n.kind === "vps" ? P.accent : n.threat ? P.danger : P.text;
          ctx.font = `${n.kind === "vps" ? 700 : 500} ${((n.kind === "vps" ? 14 : 12.5) * scale) / sk}px "JetBrains Mono", monospace`;
          const ly = n.y + n.r + (15 * scale) / sk;
          ctx.strokeText(n.label, n.x, ly);
          ctx.fillText(n.label, n.x, ly);
          if (n.sub && (n.kind !== "ip" || k > 1.1 || n.id === sel)) {
            ctx.fillStyle = P.muted;
            ctx.font = `${(11 * scale) / sk}px "Inter", sans-serif`;
            const sy = ly + (14 * scale) / sk;
            ctx.strokeText(n.sub, n.x, sy);
            ctx.fillText(n.sub, n.x, sy);
          }
        }
      }
      ctx.globalAlpha = 1;
      ctx.restore();
    };

    const loop = (t: number) => {
      const dt = Math.min(0.05, (t - last) / 1000);
      last = t;
      step();
      if (!document.hidden && (!s.reduce || s.dirty)) {
        draw(t, dt);
        s.dirty = false;
      }
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);

    // ---- interaction
    let drag: { mode: "pan" | "node"; node?: P; sx: number; sy: number; ox: number; oy: number; moved: boolean } | null = null;
    const rect = () => c.getBoundingClientRect();
    const down = (ev: PointerEvent) => {
      const r = rect();
      const mx = ev.clientX - r.left, my = ev.clientY - r.top;
      const n = hit(mx, my);
      c.setPointerCapture(ev.pointerId);
      drag = n ? { mode: "node", node: n, sx: mx, sy: my, ox: n.x, oy: n.y, moved: false } : { mode: "pan", sx: mx, sy: my, ox: s.view.x, oy: s.view.y, moved: false };
    };
    const move = (ev: PointerEvent) => {
      const r = rect();
      const mx = ev.clientX - r.left, my = ev.clientY - r.top;
      if (!drag) {
        const n = hit(mx, my);
        if (n !== s.hover) { s.hover = n; s.dirty = true; c.style.cursor = n ? "pointer" : "grab"; }
        return;
      }
      const dx = mx - drag.sx, dy = my - drag.sy;
      if (Math.abs(dx) + Math.abs(dy) > 4) drag.moved = true;
      if (drag.mode === "pan") { s.view.x = drag.ox + dx; s.view.y = drag.oy + dy; c.style.cursor = "grabbing"; }
      else if (drag.node && drag.node.kind !== "vps") { drag.node.x = drag.ox + dx / s.view.k; drag.node.y = drag.oy + dy / s.view.k; drag.node.pinned = true; s.alpha = Math.max(s.alpha, 0.15); }
      s.dirty = true;
    };
    const up = () => {
      if (drag && !drag.moved) cb.current?.(drag.mode === "node" && drag.node ? stripP(drag.node) : null);
      drag = null;
      c.style.cursor = s.hover ? "pointer" : "grab";
    };
    const wheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const r = rect();
      const mx = ev.clientX - r.left - w / 2, my = ev.clientY - r.top - h / 2;
      const k0 = s.view.k;
      const k1 = Math.min(4, Math.max(0.25, k0 * Math.exp(-ev.deltaY * 0.0015)));
      s.view.x = mx - ((mx - s.view.x) * k1) / k0;
      s.view.y = my - ((my - s.view.y) * k1) / k0;
      s.view.k = k1;
      s.dirty = true;
    };
    c.addEventListener("pointerdown", down);
    c.addEventListener("pointermove", move);
    c.addEventListener("pointerup", up);
    c.addEventListener("pointercancel", up);
    c.addEventListener("wheel", wheel, { passive: false });
    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      c.removeEventListener("pointerdown", down);
      c.removeEventListener("pointermove", move);
      c.removeEventListener("pointerup", up);
      c.removeEventListener("pointercancel", up);
      c.removeEventListener("wheel", wheel);
    };
  }, []);

  useEffect(() => {
    st.current.dirty = true;
  }, [selected, reduce]);

  const zoom = (f: number) => {
    const v = st.current.view;
    v.k = Math.min(4, Math.max(0.25, v.k * f));
    v.x *= f; v.y *= f;
    st.current.dirty = true;
  };
  const reset = () => {
    const b = host.current;
    st.current.view = { x: 0, y: 0, k: b ? Math.min(b.clientWidth, b.clientHeight) / 900 : 1 };
    pinOnlyServer(st.current.list);
    st.current.alpha = 0.6;
    st.current.dirty = true;
  };

  return (
    <div ref={host} className="relative h-full w-full overflow-hidden">
      <canvas ref={canvas} className="block cursor-grab touch-none" />
      <div className="absolute bottom-3 left-3 flex flex-col gap-1">
        <button className="btn !px-2 !py-0.5" onClick={() => zoom(1.25)} aria-label="Zoom in">+</button>
        <button className="btn !px-2 !py-0.5" onClick={() => zoom(0.8)} aria-label="Zoom out">−</button>
        <button className="btn !px-2 !py-0.5 text-[0.75rem]" onClick={reset} title="Reset layout and zoom">RST</button>
      </div>
    </div>
  );
}

function stripP(p: P): GNode {
  const { x: _x, y: _y, vx: _vx, vy: _vy, r: _r, pinned: _p, ...n } = p;
  void _x; void _y; void _vx; void _vy; void _r; void _p;
  return n;
}

function hash(s: string) {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619);
  return ((h >>> 0) % 10000) / 10000;
}

function poly(ctx: CanvasRenderingContext2D, x: number, y: number, r: number, n: number, rot: number) {
  for (let i = 0; i <= n; i++) {
    const a = rot + (i / n) * Math.PI * 2;
    const px = x + Math.cos(a) * r, py = y + Math.sin(a) * r;
    if (i === 0) ctx.moveTo(px, py);
    else ctx.lineTo(px, py);
  }
  ctx.closePath();
}

function bracket(ctx: CanvasRenderingContext2D, x: number, y: number, r: number) {
  const q = r * 0.45;
  ctx.beginPath();
  for (const [sx, sy] of [[-1, -1], [1, -1], [1, 1], [-1, 1]]) {
    ctx.moveTo(x + sx * r, y + sy * (r - q)); ctx.lineTo(x + sx * r, y + sy * r); ctx.lineTo(x + sx * (r - q), y + sy * r);
  }
  ctx.stroke();
}

/** Unpin every node except the server itself (used by "reset view"). */
function pinOnlyServer(list: { kind: string; pinned?: boolean }[]) {
  for (const n of list) n.pinned = n.kind === "vps";
}
