"use client";

import { Ban, Check, ChevronDown, ChevronRight, ShieldAlert, ShieldCheck, ShieldOff } from "lucide-react";
import { useMemo, useState } from "react";
import { BlockButton } from "@/components/block";
import { RankBars, TimeBars } from "@/components/charts";
import { Card, Empty, GeoTag, InfoTip, IPLink, PageHeader, Pill, Segmented, SevBadge, Spinner, Stat } from "@/components/ui";
import { useUI } from "@/components/uictx";
import { api } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { ago, flagEmoji, fmtDateTime, fmtNum, sevColor, sevHelp, sevLabel, sevOrder, threatTypeLabel } from "@/lib/format";
import type { BlockedIP, FirewallStatus, KV, Severity, Threat } from "@/lib/types";

type ThreatsResp = { threats: Threat[] | null; counts: Record<Severity, number>; top_ips: KV[]; by_type: Record<string, number> };
type TL = { timeline: { ts: number; info: number; low: number; medium: number; high: number; critical: number }[] };
type FW = { status: FirewallStatus; blocked: BlockedIP[] | null; you: string };

export default function SecurityPage() {
  const [range, setRange] = useState("24h");
  const [minSev, setMinSev] = useState("low");
  const [unacked, setUnacked] = useState(false);
  const live = useLive();
  const { openIP } = useUI();
  const th = useApi<ThreatsResp>(`/api/threats?range=${range}&severity=${minSev}${unacked ? "&unacked=1" : ""}`, { interval: 20000 });
  const tl = useApi<TL>(`/api/threats/timeline?range=${range}`, { interval: 30000 });
  const fw = useApi<FW>("/api/firewall", { interval: 30000 });
  const [open, setOpen] = useState<number | null>(null);

  const threats = useMemo(() => {
    const m = new Map<number, Threat>();
    for (const t of th.data?.threats || []) m.set(t.id, t);
    const minIdx = sevOrder.indexOf(minSev as Severity);
    for (const t of live.threats) if (m.has(t.id) || sevOrder.indexOf(t.severity) <= minIdx) m.set(t.id, { ...m.get(t.id), ...t });
    let out = [...m.values()];
    if (unacked) out = out.filter((t) => !t.acked);
    return out.sort((a, b) => b.last_seen - a.last_seen);
  }, [th.data, live.threats, minSev, unacked]);

  const blocked = live.blocked ?? fw.data?.blocked ?? [];
  const blockedSet = new Set(blocked.map((b) => b.ip));
  const c = th.data?.counts || ({} as Record<Severity, number>);

  const ack = async (id: number) => {
    await api(`/api/threats/${id}/ack`, { method: "POST" });
    th.setData((d) => d && { ...d, threats: (d.threats || []).map((t) => (t.id === id ? { ...t, acked: true } : t)) });
  };
  const refresh = () => { th.reload(); fw.reload(); };

  return (
    <div className="space-y-5">
      <PageHeader title="Security" desc="Attacks and suspicious activity spotted in your logs and network traffic, explained in plain language, with one-click blocking."
        right={<Segmented value={range} onChange={setRange} options={[{ value: "1h", label: "1h" }, { value: "24h", label: "24h" }, { value: "7d", label: "7d" }]} />} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {(["critical", "high", "medium", "low", "info"] as Severity[]).map((s) => (
          <Stat key={s} label={sevLabel[s]} value={fmtNum(c[s] || 0)} color={c[s] ? sevColor[s] : undefined} info={sevHelp[s]} onClick={() => setMinSev(s)} />
        ))}
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Threat timeline" className="xl:col-span-2" info="How many security events happened over time, colored by how serious they are.">
          {tl.data ? (
            <TimeBars data={tl.data.timeline} height={340} series={[
              { key: "critical", name: "Critical", color: sevColor.critical }, { key: "high", name: "High", color: sevColor.high },
              { key: "medium", name: "Medium", color: sevColor.medium }, { key: "low", name: "Low", color: sevColor.low }, { key: "info", name: "Info", color: sevColor.info },
            ]} />
          ) : <Spinner />}
        </Card>
        <Card title="Most active attackers" info="IP addresses behind the most suspicious events. Click one to see its full history and block it.">
          {!th.data?.top_ips?.length ? <Empty icon={<ShieldCheck />}>Nobody yet.</Empty> : (
            <RankBars color="var(--c-danger)" items={th.data.top_ips.map((k) => ({ key: k.key, value: k.count, label: <><span className="mono text-[0.875rem]">{k.key}</span> <span className="text-muted">{k.extra}</span>{blockedSet.has(k.key) && <Ban size={11} className="ml-1 inline text-muted" />}</> }))}
              onClick={(ip) => openIP(ip)} fmt={(v) => `${fmtNum(v)} events`} />
          )}
          {th.data && Object.keys(th.data.by_type || {}).length > 0 && (
            <div className="mt-4 flex flex-wrap gap-1.5 border-t border-line pt-3">
              {Object.entries(th.data.by_type).sort((a, b) => b[1] - a[1]).map(([k, v]) => (
                <Pill key={k} color="var(--c-muted)">{threatTypeLabel(k)} · {fmtNum(v)}</Pill>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card bodyClass="p-0" title={`Threats (${threats.length})`}
        info="Each row groups repeated attacks from one address. Expand a row for the explanation and what to do. 'Mark as seen' just hides it from the unread filter."
        right={
          <>
            <label className="flex cursor-pointer items-center gap-1.5 text-[0.9062rem] text-muted"><input type="checkbox" checked={unacked} onChange={(e) => setUnacked(e.target.checked)} /> Unread only</label>
            <select className="input" value={minSev} onChange={(e) => setMinSev(e.target.value)}>
              <option value="info">All severities</option><option value="low">Low and above</option><option value="medium">Medium and above</option>
              <option value="high">High and above</option><option value="critical">Critical only</option>
            </select>
          </>
        }>
        {th.loading && !th.data ? <Spinner /> : threats.length === 0 ? (
          <Empty icon={<ShieldCheck className="text-good" />}>No threats in this time range. Your server looks quiet.</Empty>
        ) : (
          <ul className="divide-y divide-line">
            {threats.slice(0, 300).map((t) => {
              const isOpen = open === t.id;
              const isBlocked = t.blocked || blockedSet.has(t.ip);
              return (
                <li key={t.id} className={t.acked ? "opacity-60" : ""}>
                  <div className="flex cursor-pointer items-center gap-3 px-4 py-3 hover:bg-panel2" onClick={() => setOpen(isOpen ? null : t.id)}>
                    {isOpen ? <ChevronDown size={15} className="shrink-0 text-muted" /> : <ChevronRight size={15} className="shrink-0 text-muted" />}
                    <span className="w-1 self-stretch rounded" style={{ background: sevColor[t.severity] }} />
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-medium">{t.title}</span>
                        <Pill color="var(--c-muted)">{threatTypeLabel(t.type)}</Pill>
                        {t.count > 1 && <span className="text-[0.875rem] text-muted">×{fmtNum(t.count)}</span>}
                        {isBlocked && <Pill color="var(--c-muted)"><Ban size={10} className="mr-0.5 inline" />blocked</Pill>}
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[0.875rem] text-muted">
                        <span onClick={(e) => e.stopPropagation()}><IPLink ip={t.ip} threat /></span>
                        <GeoTag geo={t.geo} />
                        <span>· {ago(t.last_seen)}</span>
                      </div>
                    </div>
                    <SevBadge sev={t.severity} withTip />
                  </div>
                  {isOpen && (
                    <div className="space-y-3 bg-inset px-12 py-4 text-[0.9375rem]">
                      <div><div className="mb-0.5 text-[0.8438rem] uppercase tracking-wide text-muted">What happened</div>{t.explanation}</div>
                      {t.advice && <div><div className="mb-0.5 text-[0.8438rem] uppercase tracking-wide text-muted">What you should do</div>{t.advice}</div>}
                      <div className="grid gap-x-6 gap-y-1 text-[0.9062rem] md:grid-cols-3">
                        <div><span className="text-muted">First seen:</span> {fmtDateTime(t.ts)}</div>
                        <div><span className="text-muted">Last seen:</span> {fmtDateTime(t.last_seen)}</div>
                        <div><span className="text-muted">Times:</span> {fmtNum(t.count)}</div>
                        {t.details && Object.entries(t.details).slice(0, 9).map(([k, v]) => (
                          <div key={k} className="truncate" title={String(v)}><span className="text-muted">{k.replace(/_/g, " ")}:</span> <span className="mono text-[0.875rem]">{Array.isArray(v) ? v.join(", ") : String(v)}</span></div>
                        ))}
                      </div>
                      <div className="flex flex-wrap gap-2 pt-1">
                        {t.ip && <BlockButton ip={t.ip} reason={t.title} blocked={isBlocked} onDone={refresh} />}
                        {t.ip && <button className="btn" onClick={() => openIP(t.ip)}>Everything from this IP</button>}
                        {!t.acked && <button className="btn" onClick={() => ack(t.id)}><Check size={13} /> Mark as seen</button>}
                      </div>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      <Card bodyClass="p-0" title={<span className="flex items-center gap-2"><ShieldOff size={14} /> Blocked IP addresses ({blocked.length})</span>}
        info="Addresses you blocked from this dashboard. They can't reach any port on your server. Unblock if you blocked someone by mistake.">
        <div className="border-b border-line px-4 py-2.5 text-[0.9062rem]">
          {fw.data ? (
            fw.data.status.can_block ? (
              <span className="text-muted">Firewall: <b className="text-text">{fw.data.status.backend}</b> · {fw.data.status.message} · your own IP <span className="mono">{fw.data.you}</span> is protected from being blocked.</span>
            ) : (
              <span className="text-warn">Blocking unavailable: {fw.data.status.message}</span>
            )
          ) : "…"}
        </div>
        {blocked.length === 0 ? <Empty icon={<ShieldAlert />}>No blocked addresses.</Empty> : (
          <table className="tbl">
            <thead><tr><th>Address</th><th>Location</th><th>Reason</th><th>Blocked</th><th>Via</th><th /></tr></thead>
            <tbody>
              {blocked.map((b) => (
                <tr key={b.ip}>
                  <td><IPLink ip={b.ip} blocked /></td>
                  <td>{flagEmoji(b.geo?.cc)} {b.geo?.country || "—"}</td>
                  <td className="max-w-[320px] truncate text-muted" title={b.reason}>{b.reason || "—"}</td>
                  <td className="whitespace-nowrap text-muted">{ago(b.ts)}</td>
                  <td className="text-muted">{b.backend}</td>
                  <td className="text-right"><BlockButton ip={b.ip} blocked small onDone={refresh} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <p className="flex items-center gap-1 text-[0.8438rem] text-muted">Detection sources: SSH logs, web access logs, connection patterns (port scans, floods). <InfoTip>Blocking adds a DROP rule via nftables (table inet myowl), iptables (INPUT rule tagged &quot;myowl&quot;) or ufw (deny from IP). Rules are re-applied at startup. Needs root or CAP_NET_ADMIN.</InfoTip></p>
    </div>
  );
}
