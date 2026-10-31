"use client";

import { Bell, Cpu, Globe2, LayoutDashboard, LogOut, Menu, Radar, ScrollText, Settings, ShieldAlert, Users, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { LiveProvider, useLive } from "@/lib/live";
import { sevColor } from "@/lib/format";
import { useFx } from "@/lib/fx";
import { threatLevel, useThreatFeed } from "@/lib/threat";
import { glow, mix, useTheme } from "@/lib/theme";
import { ThemeMenu } from "./themepicker";
import { Backdrop, Clock, Glitch } from "./fx";
import { IPDrawer, RequestDrawer } from "./details";
import { UICtx } from "./uictx";
import { Spinner } from "./ui";
import { OwlMark } from "./owl";

const nav = [
  { href: "/map", label: "Live map", icon: Radar },
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/network", label: "Network", icon: Globe2 },
  { href: "/requests", label: "Web requests", icon: ScrollText },
  { href: "/security", label: "Security", icon: ShieldAlert },
  { href: "/sessions", label: "Logins & sessions", icon: Users },
  { href: "/system", label: "System health", icon: Cpu },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/settings", label: "Settings & status", icon: Settings },
];

type AuthStatus = { authenticated: boolean; setup_required: boolean; demo: boolean; version: string };

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const isLogin = pathname === "/login";
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const { syncServer } = useTheme();

  useEffect(() => {
    if (isLogin) return;
    api<AuthStatus>("/api/auth/status")
      .then((s) => {
        if (!s.authenticated) router.replace("/login");
        else {
          setAuth(s);
          syncServer();
        }
      })
      .catch(() => router.replace("/login"));
  }, [isLogin, router, syncServer]);

  useEffect(() => {
    const h = () => router.replace("/login");
    window.addEventListener("myowl:unauthorized", h);
    return () => window.removeEventListener("myowl:unauthorized", h);
  }, [router]);

  if (isLogin) return <><Backdrop />{children}</>;
  if (!auth) return <div className="flex min-h-screen items-center justify-center"><Backdrop /><Spinner label="Establishing secure link…" /></div>;
  return (
    <LiveProvider enabled>
      <Frame demo={auth.demo} version={auth.version}>{children}</Frame>
    </LiveProvider>
  );
}

function Frame({ children, demo, version }: { children: React.ReactNode; demo: boolean; version: string }) {
  const pathname = usePathname();
  const router = useRouter();
  const live = useLive();
  const fx = useFx();
  const threats = useThreatFeed();
  const [ip, setIP] = useState<string | null>(null);
  const [reqId, setReqId] = useState<number | null>(null);
  const [menu, setMenu] = useState(false);
  const openIP = useCallback((x: string) => setIP(x), []);
  const openRequest = useCallback((id: number) => setReqId(id), []);
  // Close the mobile menu after navigating (adjusting state during render).
  const [menuPath, setMenuPath] = useState(pathname);
  if (menuPath !== pathname) {
    setMenuPath(pathname);
    setMenu(false);
  }
  const host = live.system?.hostname;
  const newThreats = live.threats.filter((t) => !t.acked && (t.severity === "high" || t.severity === "critical")).length;
  const tl = threatLevel(threats);
  const wall = fx.wall;

  const logout = async () => {
    try {
      await api("/api/auth/logout", { method: "POST" });
    } finally {
      router.replace("/login");
    }
  };

  return (
    <UICtx.Provider value={{ openIP, openRequest, demo }}>
      <Backdrop />
      <div className={`relative z-[1] flex min-h-screen ${fx.crt && !fx.reduce ? "fx-flicker" : ""}`}>
        {!wall && menu && <div className="fixed inset-0 z-[39] bg-black/55 lg:hidden" onClick={() => setMenu(false)} aria-hidden />}
        {!wall && (
          <aside className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-line bg-bg2 transition-transform lg:translate-x-0 ${menu ? "translate-x-0 shadow-2xl shadow-black/60" : "-translate-x-full"}`}>
            <div className="flex items-center gap-2.5 border-b border-line px-4 py-4">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-neon/70 bg-neon/10 text-neon neon-box">
                <OwlMark size={24} />
              </div>
              <div className="min-w-0">
                <div className="font-hud text-[1rem] font-bold leading-tight text-neon neon">myOwl</div>
                <div className="mono max-w-[160px] truncate text-[0.8125rem] text-muted">{host ? `${host}` : "…"}</div>
              </div>
              <button className="ml-auto rounded p-1 text-muted hover:text-text lg:hidden" onClick={() => setMenu(false)} aria-label="Close menu"><X size={20} /></button>
            </div>
            <div className="mono px-5 pb-1.5 pt-4 text-[0.75rem] uppercase tracking-[.14em] text-muted">{"// navigation"}</div>
            <nav className="flex-1 space-y-0.5 overflow-y-auto px-2">
              {nav.map((n, i) => {
                const active = n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
                const Icon = n.icon;
                return (
                  <Link key={n.href} href={n.href}
                    className={`group flex items-center gap-3 rounded-md border-l-[3px] px-3 py-2.5 text-[0.9375rem] font-medium transition ${active ? "border-neon bg-neon/12 text-neon" : "border-transparent text-text/85 hover:bg-panel2 hover:text-text"}`}>
                    <span className={`mono w-5 text-[0.75rem] ${active ? "text-neon" : "text-muted"}`}>{String(i).padStart(2, "0")}</span>
                    <Icon size={17} className="shrink-0" />
                    {n.label}
                    {n.href === "/security" && newThreats > 0 && (
                      <span className="alarm ml-auto min-w-[22px] rounded-full px-1.5 text-center text-[0.75rem] font-bold text-white" style={{ background: sevColor.high }}>{newThreats}</span>
                    )}
                  </Link>
                );
              })}
            </nav>
            <div className="space-y-2.5 border-t border-line p-4 text-[0.8438rem] text-muted">
              <div className="flex items-center gap-2" title={tl.text}>
                <span className="mono shrink-0 text-[0.8125rem] font-bold" style={{ color: tl.color, textShadow: glow(tl.color, 8) }}>{tl.name}</span>
                <span className="truncate">{tl.text}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`h-2.5 w-2.5 shrink-0 rounded-full ${live.connected ? "pulse bg-good" : "bg-bad"}`} />
                {live.connected ? "Live — updating in real time" : "Reconnecting…"}
              </div>
              <div className="flex items-center justify-between">
                <span className="mono">build v{version}</span>
                <button onClick={logout} className="flex items-center gap-1.5 rounded px-1.5 py-0.5 hover:bg-panel2 hover:text-text"><LogOut size={14} /> Log out</button>
              </div>
            </div>
          </aside>
        )}
        <div className={`flex min-w-0 flex-1 flex-col ${wall ? "" : "lg:pl-64"}`}>
          {!wall && (
            <div className="sticky top-0 z-30 flex min-h-[52px] items-center gap-3 border-b border-line bg-bg2/95 px-4 py-2 text-[0.875rem] backdrop-blur md:gap-4 md:px-7">
              <button className="rounded p-1 text-text lg:hidden" onClick={() => setMenu(true)} aria-label="Open menu"><Menu size={22} /></button>
              <span className="mono hidden truncate text-[0.8125rem] font-semibold uppercase tracking-[.12em] text-neon sm:inline">SOC // {host || "…"}</span>
              {demo && <span className="truncate rounded border border-crit/50 bg-crit/10 px-2 py-0.5 text-[0.8125rem] font-medium text-crit" title="All data is simulated. Nothing here is from a real server and blocking is only pretend."><span className="sm:hidden">DEMO</span><span className="hidden sm:inline">DEMO MODE — simulated data</span></span>}
              <span className="ml-auto hidden items-center gap-1.5 md:flex" title={tl.text}>
                <span className="text-muted">Threat level</span>
                <span className="mono rounded px-1.5 text-[0.8125rem] font-bold" style={{ color: tl.color, border: `1px solid ${mix(tl.color, 55)}`, background: mix(tl.color, 10) }}>{tl.name}</span>
              </span>
              <span className="ml-auto hidden items-center gap-1.5 text-text md:ml-0 md:flex">
                <span className={`h-2 w-2 rounded-full ${live.connected ? "pulse bg-good" : "bg-bad"}`} />
                <Clock />
              </span>
              <span className="ml-auto md:ml-0"><ThemeMenu /></span>
            </div>
          )}
          <main className={`mx-auto w-full flex-1 ${wall ? "" : "max-w-[1600px] px-4 py-6 md:px-7"}`}>{children}</main>
        </div>
      </div>
      <Toasts />
      <IPDrawer ip={ip} onClose={() => setIP(null)} />
      <RequestDrawer id={reqId} onClose={() => setReqId(null)} />
    </UICtx.Provider>
  );
}

function Toasts() {
  const { toasts, dismissToast } = useLive();
  const fx = useFx();
  return (
    <div className="fixed bottom-4 right-4 z-[70] flex w-[380px] max-w-[calc(100vw-2rem)] flex-col gap-2">
      {toasts.map((t) => {
        const c = sevColor[t.severity] || "var(--c-info)";
        const hot = t.severity === "critical" || t.severity === "high";
        return (
          <div key={t.id} className={`card flex gap-3 p-3.5 shadow-2xl ${hot ? "hot alarm" : ""}`} style={{ borderLeft: `3px solid ${c}` }}>
            <Bell size={18} className="mt-0.5 shrink-0" style={{ color: c }} />
            <div className="min-w-0 flex-1">
              <div className="mono text-[0.75rem] font-bold uppercase tracking-[.12em]" style={{ color: c }}>{hot ? "!! INTRUSION ALERT" : "ALERT"}</div>
              <div className="text-[0.9375rem] font-semibold"><Glitch text={t.title} on={hot && !fx.reduce} /></div>
              <div className="line-clamp-2 text-[0.875rem] text-muted">{t.body}</div>
            </div>
            <button onClick={() => dismissToast(t.id)} className="text-muted hover:text-text" aria-label="Dismiss"><X size={16} /></button>
          </div>
        );
      })}
    </div>
  );
}
