"use client";

import { Ban, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { api } from "@/lib/api";
import { Modal } from "./overlay";

/** Block-IP button with a confirmation dialog explaining the consequences. */
export function BlockButton({ ip, reason, blocked, refusal, onDone, small }: {
  ip: string; reason?: string; blocked?: boolean; refusal?: string; onDone?: () => void; small?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [why, setWhy] = useState(reason || "");
  const cls = small ? "btn !px-2 !py-1 text-[0.875rem]" : "btn";

  if (blocked) {
    return (
      <>
        <button className={cls} onClick={() => { setErr(null); setOpen(true); }}>
          <ShieldCheck size={14} className="text-good" /> Unblock
        </button>
        <Modal
          open={open}
          onClose={() => setOpen(false)}
          title={`Unblock ${ip}?`}
          footer={
            <>
              <button className="btn" onClick={() => setOpen(false)}>Cancel</button>
              <button
                className="btn btn-primary"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  setErr(null);
                  try {
                    await api("/api/firewall/unblock", { method: "POST", body: { ip } });
                    setOpen(false);
                    onDone?.();
                  } catch (e) {
                    setErr((e as Error).message);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                Unblock
              </button>
            </>
          }
        >
          <p>This removes the firewall rule. <span className="mono">{ip}</span> will be able to reach your server again.</p>
          {err && <p className="mt-3 rounded-lg border border-bad/40 bg-bad/10 p-2.5 text-bad">{err}</p>}
        </Modal>
      </>
    );
  }
  return (
    <>
      <button
        className={`${cls} ${refusal ? "" : "!border-bad/60 hover:!bg-bad/10"}`}
        disabled={!!refusal}
        title={refusal || "Block this IP in the server firewall"}
        onClick={() => { setErr(null); setOpen(true); }}
      >
        <Ban size={14} className="text-bad" /> Block IP
      </button>
      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title={`Block ${ip}?`}
        footer={
          <>
            <button className="btn" onClick={() => setOpen(false)}>Cancel</button>
            <button
              className="btn btn-danger"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setErr(null);
                try {
                  await api("/api/firewall/block", { method: "POST", body: { ip, reason: why, confirm: true } });
                  setOpen(false);
                  onDone?.();
                } catch (e) {
                  setErr((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? "Blocking…" : "Yes, block it"}
            </button>
          </>
        }
      >
        <p>
          A firewall rule will drop <b>all traffic</b> from <span className="mono">{ip}</span> — websites, SSH and everything else. Its open connections
          will stop working.
        </p>
        <ul className="mt-3 list-disc space-y-1 pl-5 text-[0.9375rem] text-muted">
          <li>Make sure this is not your own address, a colleague, or a service you rely on (payment provider, CDN, monitoring).</li>
          <li>You can undo this at any time under Security → Blocked IPs.</li>
        </ul>
        <label className="mt-4 block text-[0.875rem] text-muted">Note (optional)</label>
        <input className="input mt-1 w-full" value={why} maxLength={200} onChange={(e) => setWhy(e.target.value)} placeholder="Why are you blocking it?" />
        {err && <p className="mt-3 rounded-lg border border-bad/40 bg-bad/10 p-2.5 text-bad">{err}</p>}
      </Modal>
    </>
  );
}
