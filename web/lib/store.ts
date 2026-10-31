"use client";

import { useSyncExternalStore } from "react";

/**
 * Tiny external store backed by localStorage.
 *
 * Uses `useSyncExternalStore` so the static (server-rendered) HTML always uses
 * the fallback value and the browser switches to the stored value right after
 * hydration — no hydration mismatch and no setState-in-effect.
 */
export function createLocalStore<T>(key: string, read: (raw: string | null) => T, fallback: T) {
  let cache: T | undefined;
  const subs = new Set<() => void>();
  const get = (): T => {
    if (cache === undefined) {
      if (typeof window === "undefined") return fallback;
      let raw: string | null = null;
      try {
        raw = localStorage.getItem(key);
      } catch {
        /* ignore */
      }
      cache = read(raw);
    }
    return cache;
  };
  const set = (v: T) => {
    cache = v;
    try {
      localStorage.setItem(key, JSON.stringify(v));
    } catch {
      /* ignore */
    }
    subs.forEach((f) => f());
  };
  const subscribe = (f: () => void) => {
    subs.add(f);
    return () => {
      subs.delete(f);
    };
  };
  const getServer = () => fallback;
  return { get, set, subscribe, getServer };
}

export function useLocalStore<T>(s: ReturnType<typeof createLocalStore<T>>): T {
  return useSyncExternalStore(s.subscribe, s.get, s.getServer);
}

const noop = () => () => {};
/** False during prerender/hydration, true once running in the browser. */
export function useHydrated() {
  return useSyncExternalStore(noop, () => true, () => false);
}
