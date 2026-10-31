"use client";

import { useMemo } from "react";
import { useApi } from "./hooks";
import { useLive } from "./live";
import type { Threat } from "./types";

/** Recent threats: an initial fetch merged with threats streamed live. */
export function useThreatFeed(range = "24h") {
  const live = useLive();
  const { data } = useApi<{ threats: Threat[] | null }>(`/api/threats?range=${range}&limit=300`, { interval: 60000 });
  return useMemo(() => {
    const m = new Map<number, Threat>();
    for (const t of data?.threats || []) m.set(t.id, t);
    for (const t of live.threats) m.set(t.id, t);
    return [...m.values()].sort((a, b) => b.last_seen - a.last_seen);
  }, [data?.threats, live.threats]);
}

export type ThreatLevel = { level: 1 | 2 | 3 | 4 | 5; name: string; color: string; text: string };

/**
 * DEFCON-style threat level from the last 30 minutes of threats.
 * 5 = quiet, 1 = critical attacks still active and not blocked.
 */
export function threatLevel(threats: Threat[], now = Date.now()): ThreatLevel {
  const recent = threats.filter((t) => now - t.last_seen < 30 * 60000 && !t.acked);
  const open = recent.filter((t) => !t.blocked);
  const crit = open.filter((t) => t.severity === "critical").length;
  const high = open.filter((t) => t.severity === "high").length;
  const med = recent.filter((t) => t.severity === "medium").length;
  if (crit >= 2 || (crit && high >= 2)) return { level: 1, name: "DEFCON 1", color: "var(--c-crit)", text: "Critical attacks in progress — act now" };
  if (crit || high >= 3) return { level: 2, name: "DEFCON 2", color: "var(--c-danger)", text: "Serious attacks in the last 30 min" };
  if (high || med >= 3) return { level: 3, name: "DEFCON 3", color: "var(--c-warn)", text: "Elevated: suspicious activity seen" };
  if (med || recent.length) return { level: 4, name: "DEFCON 4", color: "var(--c-info)", text: "Normal internet background noise" };
  return { level: 5, name: "DEFCON 5", color: "var(--c-ok)", text: "All quiet" };
}
