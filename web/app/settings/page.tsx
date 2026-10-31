"use client";

import { CheckCircle2, CircleSlash, KeyRound, Lock, MonitorPlay, Palette, ShieldCheck, TriangleAlert } from "lucide-react";
import { AccentPicker, FontSizePicker, ThemeGrid } from "@/components/themepicker";
import { useState } from "react";
import { Card, KVRow, PageHeader, Pill, PageSkeleton } from "@/components/ui";
import { api } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useFx } from "@/lib/fx";
import { Segmented } from "@/components/ui";
import type { CollectorStatus, FirewallStatus } from "@/lib/types";

type Status = {
  statuses: CollectorStatus[]; version: string; demo: boolean; root: boolean; config_path: string; data_dir: string; listen: string; tls: boolean;
  access_logs: { path: string; format: string; name: string }[] | null; retention_days: number; firewall: FirewallStatus; channels: Record<string, boolean>;
};

const fixes: Record<string, string> = {
  connections: "Run the service as root (the default systemd unit does) so the kernel reports which program owns each connection and byte counts.",
  capture: "Packet capture needs root or CAP_NET_RAW. Enable it with capture.enabled: true. Everything else works without it.",
  geoip: "Allow outbound HTTPS once so the free DB-IP database can download, or place dbip-city-lite.mmdb in the data directory and set geoip.path.",
  access: "Add your web server's access log under access_logs: in the config, e.g. /var/log/nginx/access.log, then restart.",
  auth: "Make /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL) readable, or enable journald in the config.",
  journald: "Install systemd's journalctl, or rely on /var/log/auth.log instead.",
  sessions: "utmp/wtmp files are usually at /var/run/utmp and /var/log/wtmp. They may be missing inside containers.",
  services: "systemctl is needed to list services. Inside Docker this is expected to be off.",
  firewall: "Install nftables, iptables or ufw and run as root (or with CAP_NET_ADMIN) to enable one-click blocking.",
};

export default function SettingsPage() {
  const { data } = useApi<Status>("/api/status", { interval: 15000 });
  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");
  const [nw2, setNw2] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  if (!data) return <PageSkeleton />;
  const change = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    if (nw !== nw2) return setMsg({ ok: false, text: "The new passwords do not match." });
    try {
      await api("/api/auth/password", { method: "POST", body: { current: cur, new: nw } });
      setMsg({ ok: true, text: "Password changed. Other sessions have been signed out." });
      setCur(""); setNw(""); setNw2("");
    } catch (er) {
      setMsg({ ok: false, text: (er as Error).message });
    }
  };
  const publicBind = !/^(127\.|localhost|\[::1\])/.test(data.listen);

  return (
    <div className="space-y-5">
      <PageHeader title="Settings & status" desc="What the monitor can see on this server, how to unlock the rest, and how to keep the dashboard itself safe." />

      <Appearance />
      <VisualEffects />

      <Card title="Data sources" bodyClass="p-0" info="Each part of the monitor reads a different source. If one is off, the rest keeps working.">
        <ul className="divide-y divide-line">
          {data.statuses.map((s) => (
            <li key={s.name} className="flex gap-3 px-4 py-3">
              {s.state === "ok" ? <CheckCircle2 size={17} className="mt-0.5 shrink-0 text-good" /> : s.state === "degraded" ? <TriangleAlert size={17} className="mt-0.5 shrink-0 text-warn" /> : <CircleSlash size={17} className="mt-0.5 shrink-0 text-muted" />}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2"><span className="font-medium">{s.label}</span><Pill color={s.state === "ok" ? "var(--c-ok)" : s.state === "degraded" ? "var(--c-warn)" : "var(--c-muted)"}>{s.state === "ok" ? "working" : s.state === "degraded" ? "partial" : "off"}</Pill></div>
                <div className="text-[0.9062rem] text-muted">{s.message}</div>
                {s.state !== "ok" && fixes[s.name] && <div className="mt-1 text-[0.9062rem] text-text">How to fix: {fixes[s.name]}</div>}
              </div>
            </li>
          ))}
        </ul>
      </Card>

      <div className="grid gap-5 xl:grid-cols-2">
        <Card title="This installation">
          <KVRow k="Version" v={data.version} />
          <KVRow k="Mode" v={data.demo ? <Pill color="var(--c-crit)">demo</Pill> : "live"} />
          <KVRow k="Running as root" v={data.root ? "yes" : <span className="text-warn">no — some data is limited</span>} />
          <KVRow k="Listening on" v={data.listen} mono />
          <KVRow k="HTTPS" v={data.tls ? <span className="text-good">enabled</span> : "off (use a reverse proxy or set tls cert/key)"} />
          <KVRow k="Config file" v={data.config_path || "(none — using defaults)"} mono />
          <KVRow k="Data directory" v={data.data_dir} mono />
          <KVRow k="History kept for" v={`${data.retention_days} days`} />
          <KVRow k="Web logs watched" v={data.access_logs?.length ? data.access_logs.map((a) => a.path).join(", ") : "auto-detect"} mono />
          <KVRow k="Firewall" v={`${data.firewall.backend || "none"} — ${data.firewall.can_block ? "blocking available" : data.firewall.message}`} />
          <KVRow k="Alert channels" v={Object.entries(data.channels).filter(([, v]) => v).map(([k]) => k).join(", ")} />
          <p className="mt-3 text-[0.875rem] text-muted">Change settings by editing the config file and running <span className="mono">sudo systemctl restart myowl</span>.</p>
        </Card>

        <Card title={<span className="flex items-center gap-2"><KeyRound size={14} /> Change dashboard password</span>}>
          {data.demo ? <p className="text-[0.9375rem] text-muted">Not available in demo mode.</p> : (
            <form onSubmit={change} className="space-y-3">
              <input className="input w-full" type="password" placeholder="Current password" value={cur} onChange={(e) => setCur(e.target.value)} required autoComplete="current-password" />
              <input className="input w-full" type="password" placeholder="New password (8+ characters)" value={nw} onChange={(e) => setNw(e.target.value)} required minLength={8} autoComplete="new-password" />
              <input className="input w-full" type="password" placeholder="Repeat new password" value={nw2} onChange={(e) => setNw2(e.target.value)} required autoComplete="new-password" />
              <button className="btn btn-primary">Change password</button>
              {msg && <p className={`text-[0.9062rem] ${msg.ok ? "text-good" : "text-bad"}`}>{msg.text}</p>}
              <p className="text-[0.875rem] text-muted">Locked out? On the server run <span className="mono">sudo myowl passwd</span>.</p>
            </form>
          )}
        </Card>
      </div>

      <Card title={<span className="flex items-center gap-2"><ShieldCheck size={14} /> Keeping this dashboard safe</span>}>
        <ul className="space-y-2.5 text-[0.9375rem] leading-relaxed">
          {publicBind && !data.tls && (
            <li className="flex gap-2 rounded-lg border border-warn/40 bg-warn/[.07] p-3"><TriangleAlert size={15} className="mt-0.5 shrink-0 text-warn" />
              <span>The dashboard is reachable from the internet over plain HTTP. Your password could be read on untrusted networks. Use one of the options below.</span></li>
          )}
          <li className="flex gap-2"><Lock size={14} className="mt-1 shrink-0 text-accent" /><span><b>Most private:</b> set <span className="mono">listen: 127.0.0.1:8787</span> and open it through an SSH tunnel: <span className="mono">ssh -L 8787:localhost:8787 you@server</span>, then browse to http://localhost:8787.</span></li>
          <li className="flex gap-2"><Lock size={14} className="mt-1 shrink-0 text-accent" /><span><b>HTTPS with a domain:</b> put Caddy or nginx in front (e.g. Caddyfile: <span className="mono">monitor.example.com {"{"} reverse_proxy 127.0.0.1:8787 {"}"}</span>) and set <span className="mono">trust_proxy: true</span> and <span className="mono">cookie_secure: true</span> so the real visitor IP is used and the cookie is HTTPS-only.</span></li>
          <li className="flex gap-2"><Lock size={14} className="mt-1 shrink-0 text-accent" /><span><b>Built-in TLS:</b> set <span className="mono">tls.cert</span> and <span className="mono">tls.key</span> in the config to serve HTTPS directly.</span></li>
          <li className="flex gap-2"><Lock size={14} className="mt-1 shrink-0 text-accent" /><span>Login attempts are rate-limited, sessions use HttpOnly SameSite=Strict cookies, and every change requires a CSRF token. Use a long, unique password.</span></li>
          <li className="flex gap-2"><Lock size={14} className="mt-1 shrink-0 text-accent" /><span>Optionally restrict who can reach port 8787 with your firewall, e.g. <span className="mono">sudo ufw allow from YOUR.IP to any port 8787</span>.</span></li>
        </ul>
      </Card>
    </div>
  );
}

function Toggle({ on, onChange, label, help }: { on: boolean; onChange: (v: boolean) => void; label: string; help: string }) {
  return (
    <label className="flex cursor-pointer items-start justify-between gap-4 border-b border-dashed border-line py-2.5 last:border-0">
      <span>
        <span className="block text-[0.9375rem]">{label}</span>
        <span className="block text-[0.8438rem] text-muted">{help}</span>
      </span>
      <button type="button" role="switch" aria-checked={on} onClick={() => onChange(!on)}
        className={`mt-0.5 flex h-6 w-11 shrink-0 items-center rounded-full border px-0.5 transition ${on ? "border-neon bg-neon" : "border-line2 bg-inset"}`}>
        <span className={`h-4.5 w-4.5 rounded-full transition ${on ? "translate-x-[20px] bg-on-accent" : "bg-muted"}`} />
      </button>
    </label>
  );
}

function Appearance() {
  return (
    <section id="appearance" className="scroll-mt-20">
      <Card title={<span className="flex items-center gap-2"><Palette size={15} /> Appearance</span>} info="Colour theme, accent colour and text size. Saved in this browser and to your account on this server, so every browser you sign in from looks the same.">
        <div className="space-y-6">
          <div>
            <div className="mb-1 text-[0.9375rem] font-medium">Colour theme</div>
            <div className="mb-3 text-[0.875rem] text-muted">Every theme keeps red for danger, amber for warnings and green for OK, so alerts always stand out.</div>
            <ThemeGrid />
          </div>
          <div className="grid gap-6 lg:grid-cols-2">
            <div>
              <div className="mb-1 text-[0.9375rem] font-medium">Accent colour</div>
              <div className="mb-3 text-[0.875rem] text-muted">Highlights, buttons, the globe and charts use this colour. Too-dark or too-light picks are adjusted automatically so text stays readable.</div>
              <AccentPicker />
            </div>
            <div>
              <div className="mb-1 text-[0.9375rem] font-medium">Text size</div>
              <div className="mb-3 text-[0.875rem] text-muted">Makes all text and numbers bigger, including charts and the map.</div>
              <FontSizePicker />
            </div>
          </div>
        </div>
      </Card>
    </section>
  );
}

function VisualEffects() {
  const fx = useFx();
  return (
    <Card title={<span className="flex items-center gap-2"><MonitorPlay size={14} /> Visual effects</span>} info="Purely cosmetic. Saved in this browser only. Turn effects down on slow computers or if motion bothers you.">
      <div className="grid gap-x-8 md:grid-cols-2">
        <div>
          <Toggle on={fx.reduce} onChange={(v) => fx.set({ reduce: v })} label="Reduce effects" help="Stops animations, glitches, particles and globe rotation. Follows your system's 'reduce motion' setting by default." />
          <Toggle on={fx.crt} onChange={(v) => fx.set({ crt: v })} label="CRT screen effect" help="Scanlines and a soft vignette, like an old monitor." />
          <Toggle on={fx.boot} onChange={(v) => fx.set({ boot: v })} label="Boot-up sequence after sign-in" help="A 2-second system start-up animation. Click or press any key to skip." />
        </div>
        <div className="py-2.5">
          <div className="text-[0.9375rem]">Background</div>
          <div className="mb-2 text-[0.8438rem] text-muted">What runs behind the panels.</div>
          <Segmented value={fx.backdrop} onChange={(v) => fx.set({ backdrop: v })} options={[{ value: "grid", label: "Grid" }, { value: "matrix", label: "Matrix rain" }, { value: "off", label: "Off" }]} />
        </div>
      </div>
    </Card>
  );
}
