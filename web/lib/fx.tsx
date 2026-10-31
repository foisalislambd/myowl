"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { createLocalStore, useLocalStore } from "./store";

/** Visual-effects preferences, stored in the browser (localStorage). */
export type Backdrop = "grid" | "matrix" | "off";
export type FxPrefs = { reduce: boolean; backdrop: Backdrop; crt: boolean; boot: boolean };
type FxState = FxPrefs & { set: (p: Partial<FxPrefs>) => void; wall: boolean; setWall: (w: boolean) => void };

const KEY = "myowl-fx";
const defaults: FxPrefs = { reduce: false, backdrop: "grid", crt: true, boot: true };

function parseFx(raw: string | null): FxPrefs {
  try {
    if (raw) return { ...defaults, ...JSON.parse(raw) };
  } catch {
    /* ignore */
  }
  const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false;
  return { ...defaults, reduce };
}

const fxStore = createLocalStore<FxPrefs>(KEY, parseFx, defaults);
export const loadFx = fxStore.get;

const FxCtx = createContext<FxState>({ ...defaults, set: () => {}, wall: false, setWall: () => {} });

export function FxProvider({ children }: { children: React.ReactNode }) {
  const p = useLocalStore(fxStore);
  const [wall, setWall] = useState(false);
  useEffect(() => {
    document.documentElement.classList.toggle("fx-reduced", p.reduce);
  }, [p.reduce]);
  const set = useCallback((x: Partial<FxPrefs>) => fxStore.set({ ...fxStore.get(), ...x }), []);
  return <FxCtx.Provider value={{ ...p, set, wall, setWall }}>{children}</FxCtx.Provider>;
}

export const useFx = () => useContext(FxCtx);
