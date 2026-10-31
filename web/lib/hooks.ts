"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";

/** Fetch JSON once and optionally re-fetch on an interval or when deps change. */
export function useApi<T>(path: string | null, opts: { interval?: number; deps?: unknown[] } = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const mounted = useRef(true);
  // Extra dependencies are compared by value so callers can pass a fresh array each render.
  const depKey = JSON.stringify(opts.deps ?? []);
  const load = useCallback((): Promise<void> => {
    if (!path) return Promise.resolve();
    return api<T>(path)
      .then(
        (d) => {
          if (!mounted.current) return;
          setData(d);
          setError(null);
        },
        (e: Error) => {
          if (mounted.current) setError(e.message);
        },
      )
      .finally(() => {
        if (mounted.current) setLoading(false);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- depKey intentionally forces a new loader
  }, [path, depKey]);
  useEffect(() => {
    mounted.current = true;
    load();
    if (!opts.interval) return () => void (mounted.current = false);
    const t = setInterval(load, opts.interval);
    return () => {
      mounted.current = false;
      clearInterval(t);
    };
  }, [load, opts.interval]);
  return { data, error, loading, reload: load, setData };
}

export function useNow(interval = 5000) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), interval);
    return () => clearInterval(t);
  }, [interval]);
  return now;
}
