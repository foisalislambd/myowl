"use client";

import { useEffect, useRef, useState } from "react";
import { useFx } from "@/lib/fx";
import { hexA, useTheme } from "@/lib/theme";
import { useNow } from "@/lib/hooks";
import { useHydrated } from "@/lib/store";
import { OwlMark } from "./owl";

/** Fixed background layers: grid or matrix rain, CRT scanlines and vignette. */
export function Backdrop() {
  const fx = useFx();
  return (
    <>
      {fx.backdrop === "grid" && <div className="fx-grid" aria-hidden />}
      {fx.backdrop === "matrix" && !fx.reduce && <MatrixRain />}
      {fx.backdrop === "matrix" && fx.reduce && <div className="fx-grid" aria-hidden />}
      {fx.crt && (
        <>
          <div className="fx-vignette" aria-hidden />
          <div className="fx-crt" aria-hidden />
        </>
      )}
    </>
  );
}

const GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789ABCDEF<>/{}[]$#";

/** Low-opacity matrix rain. Runs at ~16 fps and pauses when the tab is hidden. */
export function MatrixRain({ opacity = 0.14 }: { opacity?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const { P, light } = useTheme();
  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    const size = 15;
    let cols = 0;
    let drops: number[] = [];
    const resize = () => {
      c.width = window.innerWidth;
      c.height = window.innerHeight;
      cols = Math.ceil(c.width / size);
      drops = Array.from({ length: cols }, () => Math.random() * -60);
    };
    resize();
    window.addEventListener("resize", resize);
    let last = 0;
    let raf = 0;
    const draw = (t: number) => {
      raf = requestAnimationFrame(draw);
      if (document.hidden || t - last < 62) return;
      last = t;
      ctx.fillStyle = hexA(P.bg, 0.18);
      ctx.fillRect(0, 0, c.width, c.height);
      ctx.font = `${size - 2}px "JetBrains Mono", monospace`;
      for (let i = 0; i < cols; i++) {
        const y = drops[i] * size;
        if (y > 0) {
          ctx.fillStyle = Math.random() > 0.975 ? P.text : P.accent;
          ctx.fillText(GLYPHS[(Math.random() * GLYPHS.length) | 0], i * size, y);
        }
        if (y > c.height && Math.random() > 0.975) drops[i] = Math.random() * -20;
        drops[i] += 1;
      }
    };
    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, [P]);
  return <canvas ref={ref} aria-hidden className="pointer-events-none fixed inset-0 z-0" style={{ opacity: light ? opacity * 0.6 : opacity }} />;
}

/** Number that animates from its previous value to the new one. */
export function CountUp({ value, format = (v) => Math.round(v).toLocaleString("en-US"), duration = 700 }: {
  value: number | null | undefined; format?: (v: number) => string; duration?: number;
}) {
  const { reduce } = useFx();
  const target = Number.isFinite(value as number) ? (value as number) : 0;
  const [shown, setShown] = useState(target);
  const from = useRef(target);
  useEffect(() => {
    if (reduce) {
      from.current = target;
      return;
    }
    const start = performance.now();
    const a = from.current;
    let raf = 0;
    const step = (t: number) => {
      const k = Math.min(1, (t - start) / duration);
      const e = 1 - Math.pow(1 - k, 3);
      const v = a + (target - a) * e;
      from.current = v;
      setShown(v);
      if (k < 1) raf = requestAnimationFrame(step);
    };
    raf = requestAnimationFrame(step);
    return () => cancelAnimationFrame(raf);
  }, [target, duration, reduce]);
  if (value === null || value === undefined) return <>—</>;
  return <>{format(reduce ? target : shown)}</>;
}

/** Text that types itself out once (or again when the text changes). */
export function Typewriter({ text, speed = 22, caret = false, className = "" }: { text: string; speed?: number; caret?: boolean; className?: string }) {
  const { reduce } = useFx();
  const [typed, setTyped] = useState({ text, n: 0 });
  // Restart when the text changes (state adjusted during render, not in an effect).
  if (typed.text !== text) setTyped({ text, n: 0 });
  useEffect(() => {
    if (reduce) return;
    let i = 0;
    const t = setInterval(() => {
      i += 1;
      setTyped({ text, n: i });
      if (i >= text.length) clearInterval(t);
    }, speed);
    return () => clearInterval(t);
  }, [text, speed, reduce]);
  const n = reduce ? text.length : typed.n;
  const done = n >= text.length;
  return (
    <span className={`${className} ${caret || !done ? "caret" : ""}`} aria-label={text}>
      {text.slice(0, n)}
    </span>
  );
}

/** Glitchy text used for threat alerts. */
export function Glitch({ text, className = "", on = true }: { text: string; className?: string; on?: boolean }) {
  if (!on) return <span className={className}>{text}</span>;
  return (
    <span className={`glitch ${className}`} data-text={text}>
      {text}
    </span>
  );
}

/** Live local clock with time-zone label. */
export function Clock() {
  const hydrated = useHydrated();
  const ts = useNow(1000);
  if (!hydrated) return null;
  const now = new Date(ts);
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return (
    <span className="mono tabular-nums" title={tz}>
      {now.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false })}
      <span className="ml-1.5 text-muted">{tz}</span>
    </span>
  );
}

const BOOT_LINES = [
  "[ OK ] Opening live event stream……………… link up",
  "[ OK ] Authenticating operator…………………………… ACCESS GRANTED",
  "[ OK ] Loading sensor grid: /proc · netlink · journald · access logs",
  "[ OK ] Syncing GeoIP intelligence database",
  "[ OK ] Arming threat-detection engine",
  "[ OK ] Linking firewall control (nftables / iptables / ufw)",
  "[ >> ] Opening command center…",
];

/** Short, skippable boot-up sequence shown after login. */
export function BootSequence({ onDone, host }: { onDone: () => void; host?: string }) {
  const [shown, setShown] = useState(0);
  const done = useRef(false);
  useEffect(() => {
    const finish = () => {
      if (done.current) return;
      done.current = true;
      onDone();
    };
    const timers: ReturnType<typeof setTimeout>[] = [];
    BOOT_LINES.forEach((_, i) => timers.push(setTimeout(() => setShown(i + 1), 160 + i * 230)));
    timers.push(setTimeout(finish, 160 + BOOT_LINES.length * 230 + 450));
    const skip = () => finish();
    window.addEventListener("keydown", skip);
    return () => {
      timers.forEach(clearTimeout);
      window.removeEventListener("keydown", skip);
    };
  }, [onDone]);
  return (
    <div className="fixed inset-0 z-[200] flex cursor-pointer items-center justify-center bg-bg p-6" onClick={() => { if (!done.current) { done.current = true; onDone(); } }}>
      <div className="fx-grid" />
      <div className="relative w-full max-w-2xl">
        <div className="font-hud mb-4 flex items-center gap-3 text-[1.5rem] font-bold text-neon neon"><OwlMark size={34} />myOwl <span className="text-[0.875rem] font-medium text-muted">SECURE OPERATIONS CONSOLE</span></div>
        <div className="mono space-y-1 text-[0.9375rem] text-text">
          <div className="text-muted">root@{host || "server"}:~# ./myowl --console</div>
          {BOOT_LINES.slice(0, shown).map((l, i) => (
            <div key={i} className={i === shown - 1 ? "caret" : ""}>
              <span className={l.startsWith("[ OK ]") ? "text-neon" : "text-accent"}>{l.slice(0, 6)}</span>
              {l.slice(6)}
            </div>
          ))}
        </div>
        <div className="mt-5 h-1.5 w-full overflow-hidden rounded-full bg-line">
          <div className="h-full rounded-full bg-neon neon-box transition-all duration-200" style={{ width: `${(shown / BOOT_LINES.length) * 100}%` }} />
        </div>
        <div className="mt-3 text-[0.875rem] text-muted">Click or press any key to skip</div>
      </div>
    </div>
  );
}
