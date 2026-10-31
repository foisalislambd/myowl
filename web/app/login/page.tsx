"use client";

import { KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useFx } from "@/lib/fx";
import { BootSequence, Typewriter } from "@/components/fx";
import { OwlMark } from "@/components/owl";

type AuthStatus = { authenticated: boolean; setup_required: boolean; demo: boolean; setup_token_required: boolean; version: string };

export default function LoginPage() {
  const router = useRouter();
  const [st, setSt] = useState<AuthStatus | null>(null);
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [token, setToken] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [booting, setBooting] = useState(false);
  const fx = useFx();

  useEffect(() => {
    api<AuthStatus>("/api/auth/status")
      .then((s) => {
        if (s.authenticated) router.replace("/map");
        else setSt(s);
      })
      .catch((e) => setErr(`Cannot reach the monitor: ${e.message}`));
  }, [router]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (st?.setup_required && pw !== pw2) {
      setErr("The two passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      if (st?.setup_required) await api("/api/auth/setup", { method: "POST", body: { password: pw, token } });
      else await api("/api/auth/login", { method: "POST", body: { password: pw } });
      if (fx.boot && !fx.reduce) {
        router.prefetch("/map");
        setBooting(true);
      } else router.replace("/map");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const setup = st?.setup_required;
  if (booting) return <BootSequence onDone={() => router.replace("/map")} />;
  return (
    <div className="relative z-[1] flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="card w-full max-w-md p-8 shadow-2xl shadow-black/40">
        <div className="mono mb-5 text-[0.8125rem] text-muted">{"// secure terminal · restricted access"}</div>
        <div className="mb-6 flex items-center gap-3">
          <div className="neon-box flex h-12 w-12 items-center justify-center rounded-lg border border-neon bg-neon/10 text-neon">
            <OwlMark size={30} />
          </div>
          <div>
            <div className="font-hud text-[1.375rem] font-bold tracking-[.1em] text-neon neon">myOwl</div>
            <div className="mono text-[0.9375rem] text-text"><Typewriter text={setup ? "> first-time setup" : "> authenticate to continue"} caret /></div>
          </div>
        </div>
        {!st && !err && <div className="flex justify-center py-6 text-muted"><Loader2 className="animate-spin" /></div>}
        {st && (
          <div className="space-y-4">
            {setup && (
              <div className="rounded-md border border-info/40 bg-info/10 p-3 text-[0.9375rem] leading-relaxed text-text">
                <ShieldCheck size={14} className="mb-1 inline text-accent" /> Choose a password for this dashboard. To prove you own the server, enter the
                <b> setup code</b> printed in the service log (<span className="mono">journalctl -u myowl</span>) or stored in
                <span className="mono"> /var/lib/myowl/setup-token.txt</span>.
              </div>
            )}
            {st.demo && !setup && (
              <div className="rounded-md border border-warn/45 bg-warn/10 p-3 text-[0.9375rem] text-text">
                Demo mode: the password is <b className="mono text-warn">demo</b>
              </div>
            )}
            {setup && st.setup_token_required && (
              <label className="block">
                <span className="text-[0.875rem] font-medium text-muted">Setup code</span>
                <input className="input mono mt-1 w-full" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" required placeholder="e.g. 7f3a-…" />
              </label>
            )}
            <label className="block">
              <span className="text-[0.875rem] font-medium text-muted">{setup ? "New password (8+ characters)" : "Password"}</span>
              <input className="input mt-1 w-full" type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoFocus required
                autoComplete={setup ? "new-password" : "current-password"} minLength={setup ? 8 : undefined} />
            </label>
            {setup && (
              <label className="block">
                <span className="text-[0.875rem] font-medium text-muted">Repeat password</span>
                <input className="input mt-1 w-full" type="password" value={pw2} onChange={(e) => setPw2(e.target.value)} required autoComplete="new-password" />
              </label>
            )}
            <button className="btn btn-primary w-full justify-center !py-2.5 text-[1rem]" disabled={busy}>
              {busy ? <Loader2 size={15} className="animate-spin" /> : <KeyRound size={15} />}
              {setup ? "Save password & continue" : "Sign in // Access system"}
            </button>
          </div>
        )}
        {err && <p role="alert" className="mt-4 rounded-md border border-bad/50 bg-bad/10 p-3 text-[0.9375rem] text-bad">ERROR — {err}</p>}
        <p className="mt-6 text-center text-[0.875rem] text-muted">Forgot the password? Run <span className="mono">sudo myowl passwd</span> on the server.</p>
        {st?.version && <p className="mono mt-2 text-center text-[0.8125rem] text-muted">myOwl v{st.version}</p>}
      </form>
    </div>
  );
}
