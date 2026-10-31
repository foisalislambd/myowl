"use client";

import { KeyRound, LogIn, Terminal, UserCheck, UserX } from "lucide-react";
import { useState } from "react";
import { RankBars, TimeBars } from "@/components/charts";
import { Card, Empty, GeoTag, IPLink, PageHeader, Pill, Segmented, Stat, PageSkeleton } from "@/components/ui";
import { useUI } from "@/components/uictx";
import { useApi, useNow } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { ago, fmtDateTime, fmtDuration, fmtNum } from "@/lib/format";
import type { AuthEvent, KV, SessionsSnapshot } from "@/lib/types";

type Resp = {
  sessions: SessionsSnapshot | null; sudo: AuthEvent[] | null; failed: AuthEvent[] | null; accepted: AuthEvent[] | null;
  failed_by_ip: KV[]; failed_users: KV[]; series: { ts: number; failed: number; accepted: number; sudo: number }[];
};

const methodLabel: Record<string, string> = { password: "password", publickey: "SSH key", "keyboard-interactive": "keyboard / 2FA", probe: "probe" };

export default function SessionsPage() {
  const now = useNow(30000);
  const [range, setRange] = useState("7d");
  const { data } = useApi<Resp>(`/api/sessions?range=${range}`, { interval: 30000 });
  const live = useLive();
  const { openIP } = useUI();
  const [tab, setTab] = useState<"accepted" | "failed" | "sudo">("accepted");
  if (!data) return <PageSkeleton />;
  const sess = live.sessions || data.sessions;
  const failed = data.failed || [];
  const accepted = data.accepted || [];
  const sudo = data.sudo || [];
  const rootLogins = accepted.filter((a) => a.user === "root").length;
  const pwLogins = accepted.filter((a) => a.method === "password").length;

  return (
    <div className="space-y-5">
      <PageHeader title="Logins & sessions" desc="Who is logged in right now, who logged in before, who tried and failed, and who used admin (sudo) rights."
        right={<Segmented value={range} onChange={setRange} options={[{ value: "24h", label: "24h" }, { value: "7d", label: "7d" }, { value: "14d", label: "14d" }]} />} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Logged in now" icon={<UserCheck size={13} />} value={sess?.current.length ?? "—"} info="People with an open terminal session on the server right now (like the 'who' command)." />
        <Stat label="Successful SSH logins" icon={<LogIn size={13} />} value={fmtNum(accepted.length)} sub={pwLogins ? `${pwLogins} used a password` : "all used keys"}
          info="Each time someone got in over SSH. Check that you recognise every one of them." color={rootLogins ? "var(--c-warn)" : undefined} />
        <Stat label="Failed attempts" icon={<UserX size={13} />} value={fmtNum(failed.length)} sub={`from ${data.failed_by_ip.length}+ addresses`}
          info="Wrong passwords or unknown usernames. Bots try this on every server on the internet; they only matter if they could succeed (e.g. weak passwords)." />
        <Stat label="Admin commands (sudo)" icon={<Terminal size={13} />} value={fmtNum(sudo.length)} info="Commands someone ran with administrator rights." />
      </div>

      {(rootLogins > 0 || pwLogins > 0) && (
        <div className="rounded-xl border border-warn/40 bg-warn/[.07] p-4 text-[0.9375rem] leading-relaxed">
          <b className="text-warn">Tip to harden SSH: </b>
          {rootLogins > 0 && <>There were {rootLogins} direct root logins. Consider logging in as a normal user and setting <span className="mono">PermitRootLogin no</span>. </>}
          {pwLogins > 0 && <>{pwLogins} logins used a password. SSH keys are much safer — after adding your key, set <span className="mono">PasswordAuthentication no</span> in /etc/ssh/sshd_config and restart ssh.</>}
        </div>
      )}

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Login activity" className="xl:col-span-2" info="Red = failed login attempts, green = successful logins, purple = sudo usage.">
          <TimeBars data={data.series} height={220} series={[
            { key: "failed", name: "Failed", color: "var(--c-danger)", stack: "f" }, { key: "accepted", name: "Successful", color: "var(--c-ok)", stack: "a" }, { key: "sudo", name: "sudo", color: "var(--c-crit)", stack: "s" },
          ]} />
        </Card>
        <Card title="Who is trying to get in" info="Addresses and usernames used in failed attempts. Guessed usernames like 'admin' or 'test' are typical of bots.">
          {data.failed_by_ip.length === 0 ? <Empty>No failed attempts.</Empty> : (
            <>
              <RankBars color="var(--c-danger)" items={data.failed_by_ip.slice(0, 6).map((k) => ({ key: k.key, value: k.count, label: <><span className="mono text-[0.875rem]">{k.key}</span> <span className="text-muted">{k.extra}</span></> }))} onClick={(ip) => openIP(ip)} />
              <div className="mt-3 flex flex-wrap gap-1.5 border-t border-line pt-3">
                {data.failed_users.slice(0, 14).map((u) => <Pill key={u.key} color="var(--c-muted)"><span className="mono">{u.key || "(empty)"}</span> · {u.count}</Pill>)}
              </div>
            </>
          )}
        </Card>
      </div>

      <Card title="Logged in right now" bodyClass="p-0" info="Open terminal sessions. If you see one you don't recognise, change passwords and check the 'last logins' list.">
        {!sess?.current.length ? <Empty>{sess?.message || "Nobody is logged in right now."}</Empty> : (
          <table className="tbl">
            <thead><tr><th>User</th><th>Terminal</th><th>From</th><th>Location</th><th>Since</th></tr></thead>
            <tbody>
              {sess.current.map((s, i) => (
                <tr key={i}>
                  <td className="font-medium">{s.user}</td>
                  <td className="mono text-[0.875rem] text-muted">{s.tty}</td>
                  <td>{s.host ? <IPLink ip={s.host} /> : <span className="text-muted">local console</span>}</td>
                  <td><GeoTag geo={s.geo} /></td>
                  <td className="text-muted">{fmtDateTime(s.login_time)} ({fmtDuration((now - s.login_time) / 1000)})</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card bodyClass="p-0" title="Recent events"
        right={<Segmented value={tab} onChange={setTab} options={[{ value: "accepted", label: `Successful (${accepted.length})` }, { value: "failed", label: `Failed (${failed.length})` }, { value: "sudo", label: `sudo (${sudo.length})` }]} />}>
        <div className="max-h-[480px] overflow-auto">
          {tab === "sudo" ? (
            sudo.length === 0 ? <Empty>No sudo usage recorded.</Empty> : (
              <table className="tbl">
                <thead className="sticky top-0 bg-panel"><tr><th>When</th><th>User</th><th>As</th><th>Command</th><th>Terminal</th></tr></thead>
                <tbody>
                  {sudo.map((e) => (
                    <tr key={e.id}>
                      <td className="whitespace-nowrap text-muted" title={fmtDateTime(e.ts)}>{ago(e.ts)}</td>
                      <td className="font-medium">{e.user}</td>
                      <td>{e.run_as || "root"}</td>
                      <td className="max-w-[520px] truncate mono text-[0.875rem]" title={e.command}>{e.command}</td>
                      <td className="mono text-[0.875rem] text-muted">{e.tty}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          ) : (
            (tab === "accepted" ? accepted : failed).length === 0 ? <Empty>Nothing in this period.</Empty> : (
              <table className="tbl">
                <thead className="sticky top-0 bg-panel"><tr><th>When</th><th>User</th><th>From</th><th>Location</th><th>Method</th>{tab === "failed" && <th>Why</th>}</tr></thead>
                <tbody>
                  {(tab === "accepted" ? accepted : failed).map((e) => (
                    <tr key={e.id}>
                      <td className="whitespace-nowrap text-muted" title={fmtDateTime(e.ts)}>{ago(e.ts)}</td>
                      <td className="mono text-[0.9062rem]">{e.user || "—"}</td>
                      <td>{e.ip ? <IPLink ip={e.ip} threat={tab === "failed"} /> : "—"}</td>
                      <td><GeoTag geo={e.geo} short /></td>
                      <td><span className="flex items-center gap-1 text-[0.875rem]">{e.method === "publickey" && <KeyRound size={12} className="text-good" />}{methodLabel[e.method] || e.method || "—"}</span></td>
                      {tab === "failed" && <td className="text-[0.875rem] text-muted">{e.kind === "ssh_invalid_user" ? "user does not exist" : "wrong password"}</td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            )
          )}
        </div>
      </Card>

      <Card title="Login history (last)" bodyClass="p-0" info="Past logins recorded by the system in /var/log/wtmp — the same list the 'last' command shows.">
        {!sess?.history.length ? <Empty>{sess?.message || "No login history available."}</Empty> : (
          <div className="max-h-[420px] overflow-auto">
            <table className="tbl">
              <thead className="sticky top-0 bg-panel"><tr><th>User</th><th>Terminal</th><th>From</th><th>Location</th><th>Logged in</th><th>Duration</th></tr></thead>
              <tbody>
                {sess.history.slice(0, 200).map((h, i) => (
                  <tr key={i}>
                    <td className="font-medium">{h.user}{h.kind === "reboot" && <Pill color="var(--c-muted)">reboot</Pill>}</td>
                    <td className="mono text-[0.875rem] text-muted">{h.tty}</td>
                    <td>{h.host && /^[0-9a-f.:]+$/i.test(h.host) ? <IPLink ip={h.host} /> : <span className="text-muted">{h.host || "local"}</span>}</td>
                    <td><GeoTag geo={h.geo} short /></td>
                    <td className="whitespace-nowrap text-muted">{fmtDateTime(h.login)}</td>
                    <td className="text-muted">{h.logout ? fmtDuration((h.logout - h.login) / 1000) : <span className="text-good">still logged in</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <p className="text-[0.8438rem] text-muted">Sources: {sess?.source || "utmp/wtmp"}, /var/log/auth.log or /var/log/secure, or the systemd journal.</p>
    </div>
  );
}
