"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import type { AlertEvent, AuthEvent, BlockedIP, CollectorStatus, HTTPRequest, MetricPoint, NetworkSnapshot, SessionsSnapshot, SystemSnapshot, Threat } from "./types";

export type Toast = { id: number; title: string; body: string; severity: string; href?: string };

type LiveState = {
  connected: boolean;
  system: SystemSnapshot | null;
  network: NetworkSnapshot | null;
  sessions: SessionsSnapshot | null;
  requests: HTTPRequest[];
  threats: Threat[];
  auth: AuthEvent[];
  alerts: AlertEvent[];
  statuses: Record<string, CollectorStatus>;
  blocked: BlockedIP[] | null;
  metrics: MetricPoint[];
  netHistory: { ts: number; rx: number; tx: number; ifaces: Record<string, { rx: number; tx: number }> }[];
  toasts: Toast[];
  dismissToast: (id: number) => void;
  version: number;
};

const LiveCtx = createContext<LiveState | null>(null);

const MAX_REQ = 400;
let toastSeq = 1;

export function LiveProvider({ children, enabled }: { children: React.ReactNode; enabled: boolean }) {
  const [connected, setConnected] = useState(false);
  const [system, setSystem] = useState<SystemSnapshot | null>(null);
  const [network, setNetwork] = useState<NetworkSnapshot | null>(null);
  const [sessions, setSessions] = useState<SessionsSnapshot | null>(null);
  const [requests, setRequests] = useState<HTTPRequest[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [auth, setAuth] = useState<AuthEvent[]>([]);
  const [alerts, setAlerts] = useState<AlertEvent[]>([]);
  const [statuses, setStatuses] = useState<Record<string, CollectorStatus>>({});
  const [blocked, setBlocked] = useState<BlockedIP[] | null>(null);
  const [metrics, setMetrics] = useState<MetricPoint[]>([]);
  const [netHistory, setNetHistory] = useState<LiveState["netHistory"]>([]);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [version, setVersion] = useState(0);
  const pending = useRef<HTTPRequest[]>([]);

  const pushToast = useCallback((t: Omit<Toast, "id">) => {
    const id = toastSeq++;
    setToasts((x) => [...x.slice(-3), { ...t, id }]);
    setTimeout(() => setToasts((x) => x.filter((y) => y.id !== id)), 9000);
  }, []);
  const dismissToast = useCallback((id: number) => setToasts((x) => x.filter((y) => y.id !== id)), []);

  useEffect(() => {
    if (!enabled) return;
    const es = new EventSource("/api/stream", { withCredentials: true });
    const on = <T,>(name: string, fn: (d: T) => void) =>
      es.addEventListener(name, (ev) => {
        try {
          fn(JSON.parse((ev as MessageEvent).data));
        } catch {
          /* ignore malformed */
        }
      });
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    on<SystemSnapshot>("system", setSystem);
    on<NetworkSnapshot>("network", (n) => {
      setNetwork(n);
      const ifaces: Record<string, { rx: number; tx: number }> = {};
      for (const i of n.interfaces || []) ifaces[i.name] = { rx: i.rx_bps, tx: i.tx_bps };
      setNetHistory((h) => [...h.slice(-179), { ts: n.ts, rx: n.total_rx_bps, tx: n.total_tx_bps, ifaces }]);
    });
    on<SessionsSnapshot>("sessions", setSessions);
    on<HTTPRequest[]>("requests", (rs) => {
      pending.current.push(...rs);
    });
    on<Threat>("threat", (t) => {
      setThreats((x) => [t, ...x.filter((y) => y.id !== t.id)].slice(0, 200));
      setVersion((v) => v + 1);
    });
    on<AuthEvent>("auth", (a) => setAuth((x) => [a, ...x].slice(0, 200)));
    on<AlertEvent>("alert", (a) => {
      setAlerts((x) => [a, ...x].slice(0, 100));
      pushToast({ title: a.title, body: a.message.split("\n")[0], severity: a.severity, href: "/alerts" });
    });
    on<CollectorStatus>("status", (s) => setStatuses((x) => ({ ...x, [s.name]: s })));
    on<BlockedIP[]>("blocked", (b) => {
      setBlocked(b || []);
      setVersion((v) => v + 1);
    });
    on<MetricPoint>("metric", (m) => setMetrics((x) => [...x.slice(-240), m]));
    // Batch request inserts to keep rendering cheap under load.
    const t = setInterval(() => {
      if (pending.current.length === 0) return;
      const batch = pending.current;
      pending.current = [];
      setRequests((x) => {
        const seen = new Set(x.map((r) => r.id));
        const fresh = batch.filter((r) => !seen.has(r.id)).sort((a, b) => b.ts - a.ts);
        return [...fresh, ...x].slice(0, MAX_REQ);
      });
    }, 700);
    return () => {
      clearInterval(t);
      es.close();
      setConnected(false);
    };
  }, [enabled, pushToast]);

  return (
    <LiveCtx.Provider
      value={{ connected, system, network, sessions, requests, threats, auth, alerts, statuses, blocked, metrics, netHistory, toasts, dismissToast, version }}
    >
      {children}
    </LiveCtx.Provider>
  );
}

export function useLive(): LiveState {
  const v = useContext(LiveCtx);
  if (!v) throw new Error("useLive outside provider");
  return v;
}
