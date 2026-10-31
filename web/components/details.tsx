"use client";

import { AlertTriangle, CheckCircle2, Copy, ExternalLink } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { ago, fmtBytes, fmtDateTime, fmtTime, flagEmoji, place, sevColor, shortUA, statusColor, statusText } from "@/lib/format";
import type { FlagInfo, HTTPRequest, IPDetail } from "@/lib/types";
import { BlockButton } from "./block";
import { Drawer } from "./overlay";
import { Empty, KVRow, Pill, SevBadge, Spinner } from "./ui";
import { useUI } from "./uictx";
import { mix } from "@/lib/theme";

function authLabel(kind: string) {
  return (
    {
      ssh_failed: "Failed SSH login",
      ssh_invalid_user: "SSH login with unknown user",
      ssh_accepted: "Successful SSH login",
      sudo: "sudo (admin command)",
      sudo_failed: "Failed sudo",
      su: "su (switch user)",
    }[kind] || kind
  );
}

function verdict(d: IPDetail): { level: "good" | "warn" | "bad"; text: string } {
  if (d.private) return { level: "good", text: "This is a private/internal address (your own network or containers)." };
  if (d.blocked) return { level: "good", text: "This address is blocked by your firewall. It can no longer reach your server." };
  if (d.worst === "critical" || d.worst === "high") return { level: "bad", text: "This address attacked your server. Blocking it is recommended." };
  if (d.worst) return { level: "warn", text: "This address did something suspicious. Keep an eye on it or block it." };
  return { level: "good", text: "Nothing suspicious seen from this address. It looks like a normal visitor." };
}

export function IPDetailView({ ip, onChanged }: { ip: string; onChanged?: () => void }) {
  const [d, setD] = useState<IPDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const { openRequest } = useUI();
  const load = () =>
    api<IPDetail>(`/api/ip/${encodeURIComponent(ip)}`)
      .then((x) => {
        setD(x);
        setErr(null);
      })
      .catch((e) => setErr(e.message));
  const [shownIp, setShownIp] = useState(ip);
  if (shownIp !== ip) {
    setShownIp(ip);
    setD(null);
  }
  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ip]);
  if (err) return <p className="text-bad">{err}</p>;
  if (!d) return <Spinner />;
  const v = verdict(d);
  const vc = { good: "var(--c-ok)", warn: "var(--c-warn)", bad: "var(--c-danger)" }[v.level];
  const reqs = d.requests || [];
  const threats = d.threats || [];
  const auth = d.auth || [];
  const conns = d.connections || [];
  return (
    <div className="space-y-5">
      <div className="flex items-start gap-3 rounded-xl border p-3" style={{ borderColor: mix(vc, 40), background: mix(vc, 8) }}>
        {v.level === "good" ? <CheckCircle2 size={18} style={{ color: vc }} className="mt-0.5 shrink-0" /> : <AlertTriangle size={18} style={{ color: vc }} className="mt-0.5 shrink-0" />}
        <div className="text-[0.9375rem] leading-relaxed">{v.text}</div>
      </div>
      <div className="grid grid-cols-2 gap-x-6">
        <div>
          <KVRow k="Location" v={<span>{d.private ? "🏠" : flagEmoji(d.geo?.cc)} {place(d.geo)}</span>} />
          <KVRow k="Requests seen" v={reqs.length >= 50 ? "50+" : reqs.length} />
          <KVRow k="Open connections" v={conns.length} />
        </div>
        <div>
          <KVRow k="Threats (14 days)" v={threats.length} />
          <KVRow k="Login events" v={auth.length} />
          <KVRow k="Worst severity" v={d.worst ? <SevBadge sev={d.worst} /> : "none"} />
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <BlockButton
          ip={d.ip}
          blocked={d.blocked}
          refusal={d.block_refusal}
          reason={threats[0]?.title || ""}
          onDone={() => {
            load();
            onChanged?.();
          }}
        />
        <a className="btn" href={`https://www.abuseipdb.com/check/${d.ip}`} target="_blank" rel="noreferrer noopener">
          <ExternalLink size={14} /> AbuseIPDB
        </a>
        <button className="btn" onClick={() => navigator.clipboard?.writeText(d.ip)}>
          <Copy size={14} /> Copy
        </button>
      </div>
      {d.block_refusal && !d.blocked && <p className="text-[0.875rem] text-muted">Blocking unavailable: {d.block_refusal}</p>}

      {threats.length > 0 && (
        <section>
          <h3 className="mb-2 text-[0.9375rem] font-semibold">Threats from this IP</h3>
          <div className="space-y-2">
            {threats.map((t) => (
              <div key={t.id} className="rounded-lg border border-line bg-panel2 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <SevBadge sev={t.severity} />
                    <span className="text-[0.9375rem] font-medium">{t.title}</span>
                  </div>
                  <span className="text-[0.875rem] text-muted">{ago(t.last_seen)}</span>
                </div>
                <p className="mt-1.5 text-[0.9062rem] leading-relaxed text-text">{t.explanation}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {auth.length > 0 && (
        <section>
          <h3 className="mb-2 text-[0.9375rem] font-semibold">Login activity</h3>
          <div className="max-h-56 overflow-y-auto rounded-lg border border-line">
            <table className="tbl text-[0.9062rem]">
              <tbody>
                {auth.slice(0, 30).map((a) => (
                  <tr key={a.id}>
                    <td className="whitespace-nowrap text-muted">{fmtTime(a.ts, true)}</td>
                    <td style={{ color: a.kind === "ssh_accepted" ? "var(--c-ok)" : "var(--c-danger)" }}>{authLabel(a.kind)}</td>
                    <td className="mono">{a.user}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {conns.length > 0 && (
        <section>
          <h3 className="mb-2 text-[0.9375rem] font-semibold">Open connections right now</h3>
          <div className="rounded-lg border border-line">
            <table className="tbl text-[0.9062rem]">
              <tbody>
                {conns.slice(0, 20).map((c, i) => (
                  <tr key={i}>
                    <td className="mono">:{c.local_port}</td>
                    <td>{c.state}</td>
                    <td>{c.process || "—"}</td>
                    <td className="text-right text-muted">{fmtBytes(c.bytes_recv + c.bytes_sent)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      <section>
        <h3 className="mb-2 text-[0.9375rem] font-semibold">Recent web requests from this IP</h3>
        {reqs.length === 0 ? (
          <Empty>No web requests recorded.</Empty>
        ) : (
          <div className="max-h-80 overflow-y-auto rounded-lg border border-line">
            <table className="tbl text-[0.9062rem]">
              <tbody>
                {reqs.map((r) => (
                  <tr key={r.id} className="row" onClick={() => openRequest(r.id)}>
                    <td className="whitespace-nowrap text-muted">{fmtTime(r.ts, true)}</td>
                    <td className="mono">{r.method}</td>
                    <td className="mono max-w-[260px] truncate" title={r.path + (r.query ? "?" + r.query : "")}>
                      {r.path}
                      {r.query ? "?" + r.query : ""}
                    </td>
                    <td className="mono" style={{ color: statusColor(r.status) }}>{r.status}</td>
                    <td>{(r.flags?.length || 0) > 0 && <AlertTriangle size={13} className="text-bad" />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export function IPDrawer({ ip, onClose }: { ip: string | null; onClose: () => void }) {
  return (
    <Drawer open={!!ip} onClose={onClose} title={<span className="mono">{ip}</span>} subtitle="Everything we know about this address">
      {ip && <IPDetailView ip={ip} />}
    </Drawer>
  );
}

type ReqResp = { request: HTTPRequest; ip: IPDetail; flags: Record<string, FlagInfo> };

export function RequestDrawer({ id, onClose }: { id: number | null; onClose: () => void }) {
  const [d, setD] = useState<ReqResp | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [shownId, setShownId] = useState(id);
  if (shownId !== id) {
    setShownId(id);
    setD(null);
    setErr(null);
  }
  useEffect(() => {
    if (id == null) return;
    api<ReqResp>(`/api/requests/${id}`)
      .then(setD)
      .catch((e) => setErr(e.message));
  }, [id]);
  const r = d?.request;
  return (
    <Drawer
      open={id != null}
      onClose={onClose}
      width={720}
      title={r ? <span className="mono break-all">{r.method} {r.path}</span> : "Request"}
      subtitle={r ? `${fmtDateTime(r.ts)} · ${place(r.geo)}` : undefined}
    >
      {err && <p className="text-bad">{err}</p>}
      {!d && !err && <Spinner />}
      {r && d && (
        <div className="space-y-6">
          {(r.flags?.length || 0) > 0 && (
            <section className="space-y-2">
              {r.flags!.map((f) => {
                const info = d.flags[f];
                const c = sevColor[info?.severity || "medium"];
                return (
                  <div key={f} className="rounded-xl border p-3" style={{ borderColor: mix(c, 40), background: mix(c, 8) }}>
                    <div className="flex items-center gap-2">
                      <AlertTriangle size={15} style={{ color: c }} />
                      <span className="font-semibold">{info?.title || f}</span>
                      <SevBadge sev={info?.severity || "medium"} withTip />
                    </div>
                    <p className="mt-1.5 text-[0.9062rem] leading-relaxed text-text">
                      This request {info?.explain}. {r.status >= 200 && r.status < 300 ? <b className="text-bad">The server answered with success ({r.status}) — check this page.</b> : <>The server answered with {r.status} ({statusText(r.status)}), so the attempt most likely failed.</>}
                    </p>
                    {info?.advice && <p className="mt-1 text-[0.9062rem] text-muted">What to do: {info.advice}</p>}
                  </div>
                );
              })}
            </section>
          )}
          <section>
            <h3 className="mb-2 text-[0.9375rem] font-semibold">Request details</h3>
            <div className="rounded-xl border border-line bg-panel px-3">
              <KVRow k="Time" v={fmtDateTime(r.ts)} />
              <KVRow k="Client IP" v={<span className="mono">{r.ip}</span>} />
              <KVRow k="Method" v={<span className="mono">{r.method}</span>} />
              <KVRow k="Path" v={r.path} mono />
              {r.query && <KVRow k="Query string" v={decodeSafe(r.query)} mono />}
              <KVRow k="Status" v={<span style={{ color: statusColor(r.status) }}>{r.status} · {statusText(r.status)}</span>} />
              <KVRow k="Response size" v={fmtBytes(r.bytes)} />
              <KVRow k="Response time" v={r.latency_ms >= 0 ? `${r.latency_ms.toFixed(r.latency_ms < 10 ? 1 : 0)} ms` : "not in log format"} />
              {r.host && <KVRow k="Host" v={r.host} mono />}
              <KVRow k="Protocol" v={r.proto || "—"} />
              <KVRow k="Browser / client" v={<span title={r.ua}>{shortUA(r.ua)}</span>} />
              <KVRow k="User agent" v={r.ua || "—"} mono />
              <KVRow k="Referrer" v={r.referer && r.referer !== "-" ? r.referer : "—"} mono />
              {r.user && <KVRow k="Auth user" v={r.user} />}
              <KVRow k="Log source" v={r.source} />
            </div>
            <button className="mt-2 text-[0.875rem] text-accent hover:underline" onClick={() => setShowRaw((x) => !x)}>
              {showRaw ? "Hide" : "Show"} raw log line
            </button>
            {showRaw && <pre className="mono mt-2 overflow-x-auto whitespace-pre-wrap break-all rounded-lg border border-line bg-inset p-3 text-[0.8438rem] text-text">{r.raw}</pre>}
          </section>
          <section>
            <h3 className="mb-2 flex items-center gap-2 text-[0.9375rem] font-semibold">
              About <span className="mono">{r.ip}</span>
              {(r.flags?.length || 0) === 0 && <Pill color="var(--c-ok)">clean request</Pill>}
            </h3>
            <IPDetailView ip={r.ip} />
          </section>
        </div>
      )}
    </Drawer>
  );
}

function decodeSafe(s: string) {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s;
  }
}
