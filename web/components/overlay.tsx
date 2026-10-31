"use client";

import { X } from "lucide-react";
import { useEffect } from "react";

export function Drawer({ open, onClose, title, subtitle, children, width = 640 }: {
  open: boolean; onClose: () => void; title: React.ReactNode; subtitle?: React.ReactNode; children: React.ReactNode; width?: number;
}) {
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-50 flex justify-end" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/55 backdrop-blur-[2px]" onClick={onClose} />
      <aside className="relative flex h-full w-full flex-col border-l border-line bg-panel shadow-2xl shadow-black/50" style={{ maxWidth: width }}>
        <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
          <div className="min-w-0">
            <div className="text-[1.0625rem] font-semibold">{title}</div>
            {subtitle && <div className="mt-0.5 text-[0.9062rem] text-muted">{subtitle}</div>}
          </div>
          <button onClick={onClose} className="rounded-md p-1 text-muted hover:bg-panel2 hover:text-text" aria-label="Close">
            <X size={18} />
          </button>
        </header>
        <div className="flex-1 overflow-y-auto px-5 py-4">{children}</div>
      </aside>
    </div>
  );
}

export function Modal({ open, onClose, title, children, footer }: {
  open: boolean; onClose: () => void; title: React.ReactNode; children: React.ReactNode; footer?: React.ReactNode;
}) {
  useEffect(() => {
    if (!open) return;
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4" role="dialog" aria-modal="true">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} />
      <div className="relative w-full max-w-md rounded-2xl border border-line2 bg-panel shadow-2xl shadow-black/50">
        <div className="border-b border-line px-5 py-4 text-[1.0625rem] font-semibold">{title}</div>
        <div className="px-5 py-4 text-[0.9688rem] leading-relaxed">{children}</div>
        {footer && <div className="flex justify-end gap-2 border-t border-line px-5 py-3">{footer}</div>}
      </div>
    </div>
  );
}
