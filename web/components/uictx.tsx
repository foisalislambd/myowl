"use client";

import { createContext, useContext } from "react";

export type UIState = {
  openIP: (ip: string) => void;
  openRequest: (id: number) => void;
  demo: boolean;
};

export const UICtx = createContext<UIState>({ openIP: () => {}, openRequest: () => {}, demo: false });
export const useUI = () => useContext(UICtx);
