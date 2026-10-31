"use client";

import { Bell, Mail, Pencil, Plus, Send, Trash2, Webhook } from "lucide-react";
import { useMemo, useState } from "react";
import { Modal } from "@/components/overlay";
import { Card, Empty, InfoTip, PageHeader, Pill, SevBadge, PageSkeleton } from "@/components/ui";
import { api } from "@/lib/api";
import { useApi } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { ago, fmtDateTime } from "@/lib/format";
import type { AlertEvent, AlertRule, Severity } from "@/lib/types";

type Resp = { rules: AlertRule[] | null; events: AlertEvent[] | null; channels: Record<string, boolean> };

const metrics: Record<string, { label: string; unit: string }> = {
  cpu: { label: "CPU usage", unit: "%" }, memory: { label: "Memory usage", unit: "%" }, disk: { label: "Disk usage (fullest disk)", unit: "%" },
  swap: { label: "Swap usage", unit: "%" }, load: { label: "Load average (1 min)", unit: "" }, rx: { label: "Incoming traffic", unit: "Mbit/s" },
  tx: { label: "Outgoing traffic", unit: "Mbit/s" }, conns: { label: "Open connections", unit: "" },
};
const kinds: Record<string, string> = {
  metric: "A number crosses a limit", threat: "A security threat is detected", login: "Someone logs in over SSH", service: "A service crashes",
};
const channelInfo: Record<string, { label: string; icon: React.ReactNode; how: string }> = {
  dashboard: { label: "Dashboard", icon: <Bell size={14} />, how: "Always on — pop-up and list on this page." },
  webhook: { label: "Webhook", icon: <Webhook size={14} />, how: "Set notify.webhook.url in the config (works with Slack, Discord, ntfy, etc.)." },
  telegram: { label: "Telegram", icon: <Send size={14} />, how: "Set notify.telegram.bot_token and chat_id in the config." },
  email: { label: "Email", icon: <Mail size={14} />, how: "Set notify.smtp host, port, user, password, from and to in the config." },
};

function describe(r: AlertRule) {
  if (r.kind === "metric") {
    const m = metrics[r.metric] || { label: r.metric, unit: "" };
    return `${m.label} ${r.op === "<" ? "below" : "above"} ${r.threshold}${m.unit === "%" ? "%" : m.unit ? " " + m.unit : ""}${r.duration ? ` for ${r.duration >= 60 ? `${Math.round(r.duration / 60)} min` : `${r.duration}s`}` : ""}`;
  }
  if (r.kind === "threat") return `A threat of ${r.severity} severity or worse`;
  return kinds[r.kind] || r.kind;
}

const blank: AlertRule = { id: 0, name: "", kind: "metric", metric: "cpu", op: ">", threshold: 90, duration: 300, severity: "high", channels: ["dashboard"], cooldown: 30, enabled: true };

export default function AlertsPage() {
  const { data, reload, setData } = useApi<Resp>("/api/alerts", { interval: 30000 });
  const live = useLive();
  const [edit, setEdit] = useState<AlertRule | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testMsg, setTestMsg] = useState<Record<string, string>>({});

  const events = useMemo(() => {
    const m = new Map<number, AlertEvent>();
    for (const e of data?.events || []) m.set(e.id, e);
    for (const e of live.alerts) m.set(e.id, e);
    return [...m.values()].sort((a, b) => b.ts - a.ts);
  }, [data?.events, live.alerts]);

  if (!data) return <PageSkeleton />;
  const channels = data.channels || {};

  const save = async () => {
    if (!edit) return;
    setBusy(true);
    setErr(null);
    try {
      await api("/api/alerts/rules", { method: "POST", body: edit });
      setEdit(null);
      reload();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const toggle = async (r: AlertRule) => {
    const n = { ...r, enabled: !r.enabled };
    setData((d) => d && { ...d, rules: (d.rules || []).map((x) => (x.id === r.id ? n : x)) });
    await api("/api/alerts/rules", { method: "POST", body: n }).catch(() => reload());
  };
  const del = async (r: AlertRule) => {
    if (!confirm(`Delete the alert rule "${r.name}"?`)) return;
    await api(`/api/alerts/rules/${r.id}`, { method: "DELETE" });
    reload();
  };
  const test = async (ch: string) => {
    setTestMsg((m) => ({ ...m, [ch]: "Sending…" }));
    try {
      await api("/api/alerts/test", { method: "POST", body: { channel: ch } });
      setTestMsg((m) => ({ ...m, [ch]: "Sent ✓" }));
    } catch (e) {
      setTestMsg((m) => ({ ...m, [ch]: (e as Error).message }));
    }
  };

  return (
    <div className="space-y-5">
      <PageHeader title="Alerts" desc="Get told when something needs attention — in the dashboard, by webhook, Telegram or email."
        right={<button className="btn btn-primary" onClick={() => { setErr(null); setEdit({ ...blank }); }}><Plus size={14} /> New rule</button>} />

      <div className="grid gap-3 md:grid-cols-4">
        {Object.entries(channelInfo).map(([k, c]) => (
          <div key={k} className="card p-4">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-2 font-medium">{c.icon} {c.label}</span>
              <Pill color={channels[k] ? "var(--c-ok)" : "var(--c-muted)"}>{channels[k] ? "ready" : "not set up"}</Pill>
            </div>
            <p className="mt-2 text-[0.875rem] text-muted">{c.how}</p>
            {channels[k] && k !== "dashboard" && (
              <div className="mt-2 flex items-center gap-2">
                <button className="btn" onClick={() => test(k)}>Send test</button>
                {testMsg[k] && <span className="text-[0.875rem] text-muted">{testMsg[k]}</span>}
              </div>
            )}
          </div>
        ))}
      </div>

      <Card title={`Rules (${data.rules?.length || 0})`} bodyClass="p-0" info="Each rule describes when to alert and where to send it. 'Quiet period' stops the same alert repeating too often.">
        {!data.rules?.length ? <Empty>No rules yet. Add one to get notified.</Empty> : (
          <table className="tbl">
            <thead><tr><th>On</th><th>Name</th><th>When</th><th>Severity</th><th>Send to</th><th>Quiet period</th><th /></tr></thead>
            <tbody>
              {data.rules.map((r) => (
                <tr key={r.id} className={r.enabled ? "" : "opacity-75"}>
                  <td>
                    <button onClick={() => toggle(r)} className={`relative h-5 w-9 rounded-full transition ${r.enabled ? "bg-accent" : "bg-line2"}`} aria-label="toggle">
                      <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition-all ${r.enabled ? "left-[18px]" : "left-0.5"}`} />
                    </button>
                  </td>
                  <td className="font-medium">{r.name}</td>
                  <td className="text-muted">{describe(r)}</td>
                  <td><SevBadge sev={r.severity} /></td>
                  <td><div className="flex flex-wrap gap-1">{(r.channels || []).map((c) => <Pill key={c} color={channels[c] ? "var(--c-accent2)" : "var(--c-muted)"}>{channelInfo[c]?.label || c}</Pill>)}</div></td>
                  <td className="text-muted">{r.cooldown ? `${r.cooldown} min` : "none"}</td>
                  <td className="whitespace-nowrap text-right">
                    <button className="btn !px-2" onClick={() => { setErr(null); setEdit({ ...r, channels: r.channels || [] }); }} aria-label="Edit"><Pencil size={13} /></button>{" "}
                    <button className="btn !px-2" onClick={() => del(r)} aria-label="Delete"><Trash2 size={13} /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Alert history" bodyClass="p-0" info="Alerts fired recently and where they were delivered.">
        {events.length === 0 ? <Empty icon={<Bell />}>No alerts fired yet.</Empty> : (
          <ul className="max-h-[560px] divide-y divide-line overflow-auto">
            {events.slice(0, 200).map((e) => (
              <li key={e.id} className="flex items-start gap-3 px-4 py-3">
                <div className="w-[72px] shrink-0 pt-0.5"><SevBadge sev={e.severity} /></div>
                <div className="min-w-0 flex-1">
                  <div className="font-medium">{e.title}</div>
                  <div className="text-[0.9062rem] text-muted">{e.message}</div>
                  <div className="mt-0.5 text-[0.8438rem] text-muted">{e.rule_name} · delivered: {e.delivered || "dashboard"}</div>
                </div>
                <span className="shrink-0 text-[0.875rem] text-muted" title={fmtDateTime(e.ts)}>{ago(e.ts)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Modal open={!!edit} onClose={() => setEdit(null)} title={edit?.id ? "Edit alert rule" : "New alert rule"}
        footer={<><button className="btn" onClick={() => setEdit(null)}>Cancel</button><button className="btn btn-primary" onClick={save} disabled={busy || !edit?.name.trim()}>{busy ? "Saving…" : "Save rule"}</button></>}>
        {edit && (
          <div className="space-y-3 text-[0.9375rem]">
            <label className="block"><span className="text-[0.875rem] text-muted">Name</span>
              <input className="input mt-1 w-full" value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} placeholder="e.g. Website server overloaded" /></label>
            <label className="block"><span className="text-[0.875rem] text-muted">Alert me when…</span>
              <select className="input mt-1 w-full" value={edit.kind} onChange={(e) => setEdit({ ...edit, kind: e.target.value })}>
                {Object.entries(kinds).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
              </select></label>
            {edit.kind === "metric" && (
              <div className="grid grid-cols-3 gap-2">
                <label className="col-span-3 block"><span className="text-[0.875rem] text-muted">Measurement</span>
                  <select className="input mt-1 w-full" value={edit.metric} onChange={(e) => setEdit({ ...edit, metric: e.target.value })}>
                    {Object.entries(metrics).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                  </select></label>
                <label className="block"><span className="text-[0.875rem] text-muted">Is</span>
                  <select className="input mt-1 w-full" value={edit.op} onChange={(e) => setEdit({ ...edit, op: e.target.value })}><option value=">">above</option><option value="<">below</option></select></label>
                <label className="block"><span className="text-[0.875rem] text-muted">Limit {metrics[edit.metric]?.unit && `(${metrics[edit.metric].unit})`}</span>
                  <input className="input mt-1 w-full" type="number" value={edit.threshold} onChange={(e) => setEdit({ ...edit, threshold: Number(e.target.value) })} /></label>
                <label className="block"><span className="text-[0.875rem] text-muted">For at least (sec)</span>
                  <input className="input mt-1 w-full" type="number" min={0} value={edit.duration} onChange={(e) => setEdit({ ...edit, duration: Number(e.target.value) })} /></label>
              </div>
            )}
            <div className="grid grid-cols-2 gap-2">
              <label className="block"><span className="flex items-center gap-1 text-[0.875rem] text-muted">Severity {edit.kind === "threat" && <InfoTip>For threat rules: only alert for threats at least this serious.</InfoTip>}</span>
                <select className="input mt-1 w-full" value={edit.severity} onChange={(e) => setEdit({ ...edit, severity: e.target.value as Severity })}>
                  {["info", "low", "medium", "high", "critical"].map((s) => <option key={s} value={s}>{s}</option>)}
                </select></label>
              <label className="block"><span className="flex items-center gap-1 text-[0.875rem] text-muted">Quiet period (min) <InfoTip>After alerting, wait this long before sending the same alert again.</InfoTip></span>
                <input className="input mt-1 w-full" type="number" min={0} value={edit.cooldown} onChange={(e) => setEdit({ ...edit, cooldown: Number(e.target.value) })} /></label>
            </div>
            <div><span className="text-[0.875rem] text-muted">Send to</span>
              <div className="mt-1 flex flex-wrap gap-3">
                {Object.entries(channelInfo).map(([k, c]) => (
                  <label key={k} className={`flex items-center gap-1.5 ${channels[k] ? "cursor-pointer" : "cursor-not-allowed opacity-75"}`} title={channels[k] ? "" : c.how}>
                    <input type="checkbox" disabled={!channels[k] && !edit.channels.includes(k)} checked={edit.channels.includes(k)}
                      onChange={(e) => setEdit({ ...edit, channels: e.target.checked ? [...edit.channels, k] : edit.channels.filter((x) => x !== k) })} />
                    {c.label}
                  </label>
                ))}
              </div>
            </div>
            {err && <p className="rounded-lg bg-bad/10 p-2 text-[0.9062rem] text-bad">{err}</p>}
          </div>
        )}
      </Modal>
    </div>
  );
}
