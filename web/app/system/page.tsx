"use client";

import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { TimeArea } from "@/components/charts";
import { Bar, Card, Dot, Empty, Gauge, InfoTip, PageHeader, Pill, Segmented, Stat, PageSkeleton } from "@/components/ui";
import { useApi, useNow } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { fmtBytes, fmtDuration, fmtPct, fmtRate, levelColor, pctLevel } from "@/lib/format";
import type { Health, MetricPoint, SystemSnapshot } from "@/lib/types";

export default function SystemPage() {
  const now = useNow(30000);
  const live = useLive();
  const { data } = useApi<{ system: SystemSnapshot; health: Health }>("/api/system", { interval: 30000 });
  const [range, setRange] = useState("1h");
  const hist = useApi<{ points: MetricPoint[] | null }>(`/api/history?range=${range}`, { interval: 30000 });
  const [sort, setSort] = useState<"cpu" | "mem">("cpu");
  const [svcFilter, setSvcFilter] = useState("");
  const [svcView, setSvcView] = useState<"problems" | "running" | "all">("problems");
  const sys = live.system || data?.system;

  const procs = useMemo(() => [...(sys?.processes || [])].sort((a, b) => (sort === "cpu" ? b.cpu - a.cpu : b.mem_rss - a.mem_rss)), [sys?.processes, sort]);
  const services = useMemo(() => {
    const s = svcFilter.toLowerCase();
    return (sys?.services || [])
      .filter((x) => svcView === "all" || (svcView === "problems" ? x.active === "failed" || x.active === "activating" : x.active === "active"))
      .filter((x) => !s || x.name.toLowerCase().includes(s) || x.description.toLowerCase().includes(s))
      .sort((a, b) => Number(b.active === "failed") - Number(a.active === "failed") || a.name.localeCompare(b.name));
  }, [sys?.services, svcFilter, svcView]);

  if (!sys) return <PageSkeleton />;
  const failed = sys.services.filter((s) => s.active === "failed");
  const pts = hist.data?.points || [];
  const loadPerCore = sys.load[0] / Math.max(1, sys.cpu.cores);

  return (
    <div className="space-y-5">
      <PageHeader title="System health" desc={<>{sys.os} · kernel {sys.kernel} · {sys.arch} · {sys.cpu.model}</>} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Uptime" value={fmtDuration(sys.uptime)} sub={`since ${new Date(sys.boot_time).toLocaleString("en-GB")}`} info="How long since the server last restarted." />
        <Stat label="Load average" value={<>{sys.load[0].toFixed(2)}<span className="ml-2 text-[0.9375rem] font-medium text-muted">{sys.load.slice(1).map((l) => l.toFixed(2)).join(" · ")}</span></>} color={levelColor[pctLevel(loadPerCore * 100, 80, 150)]} sub={`1 · 5 · 15 min — ${sys.cpu.cores} cores, up to ${sys.cpu.cores}.00 is fine`}
          info="Average number of tasks waiting for the CPU over 1, 5 and 15 minutes. Compare it with the number of cores: below the core count means the server keeps up." />
        <Stat label="Processes" value={sys.proc_count} info="Programs currently running, including background ones." />
        <Stat label="Disk activity" value={`${fmtBytes(sys.disk_io.read_bps)}/s`} sub={`write ${fmtBytes(sys.disk_io.write_bps)}/s`} info="How much is being read from / written to disk right now." />
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Right now" info="Green is fine, amber means getting busy, red means it's close to the limit.">
          <div className="grid grid-cols-2 gap-y-3">
            <Gauge pct={sys.cpu.usage} label="CPU" sub={`iowait ${fmtPct(sys.cpu.iowait, 1)}${sys.cpu.steal > 1 ? ` · steal ${fmtPct(sys.cpu.steal, 1)}` : ""}`} level={pctLevel(sys.cpu.usage, 70, 90)} />
            <Gauge pct={sys.memory.percent} label="Memory" sub={`${fmtBytes(sys.memory.used)} of ${fmtBytes(sys.memory.total)}`} level={pctLevel(sys.memory.percent, 80, 92)} />
            <Gauge pct={sys.memory.swap_percent} label="Swap" sub={sys.memory.swap_total ? `${fmtBytes(sys.memory.swap_used)} of ${fmtBytes(sys.memory.swap_total)}` : "none configured"} level={pctLevel(sys.memory.swap_percent, 50, 80)} />
            <div className="flex flex-col justify-center px-2 text-[0.875rem]">
              <div className="mb-1 text-muted">Per CPU core</div>
              <div className="grid grid-cols-2 gap-1.5">
                {sys.cpu.per_core.slice(0, 16).map((c, i) => (
                  <div key={i} title={`core ${i}: ${fmtPct(c)}`}><Bar pct={c} level={pctLevel(c, 70, 90)} height={5} /></div>
                ))}
              </div>
            </div>
          </div>
          <div className="mt-3 space-y-1 border-t border-line pt-3 text-[0.875rem] text-muted">
            <div className="flex justify-between"><span>Available memory <InfoTip>Memory programs can still use, including cache Linux will free on demand. This is what matters, not &quot;free&quot;.</InfoTip></span><span className="text-text">{fmtBytes(sys.memory.available)}</span></div>
            <div className="flex justify-between"><span>Cache + buffers</span><span>{fmtBytes(sys.memory.cached + sys.memory.buffers)}</span></div>
            {sys.cpu.steal > 5 && <div className="text-warn">CPU steal is {fmtPct(sys.cpu.steal, 1)}: your hosting provider is giving your CPU time to other customers.</div>}
          </div>
        </Card>
        <Card title="History" className="xl:col-span-2" info="Saved every 10 seconds and kept for the configured retention period."
          right={<Segmented value={range} onChange={setRange} options={[{ value: "1h", label: "1h" }, { value: "6h", label: "6h" }, { value: "24h", label: "24h" }, { value: "7d", label: "7d" }]} />}>
          {pts.length < 2 ? <Empty>Collecting history… check back in a minute.</Empty> : (
            <>
              <TimeArea data={pts} height={200} yMax={100} fmt={(v) => `${Math.round(v)}%`} legend series={[
                { key: "cpu", name: "CPU", color: "var(--c-accent2)" }, { key: "mem", name: "Memory", color: "var(--c-crit)" }, { key: "disk", name: "Disk (fullest)", color: "var(--c-warn)" }, { key: "swap", name: "Swap", color: "var(--c-info)" },
              ]} />
              <div className="mt-3 grid gap-3 md:grid-cols-2">
                <div><div className="mb-1 text-[0.875rem] text-muted">Load average (1 min)</div><TimeArea data={pts} height={110} fmt={(v) => v.toFixed(1)} series={[{ key: "load1", name: "Load", color: "var(--c-ok)" }]} /></div>
                <div><div className="mb-1 text-[0.875rem] text-muted">Network</div><TimeArea data={pts} height={110} fmt={(v) => fmtRate(v)} series={[{ key: "rx", name: "Down", color: "var(--c-accent2)" }, { key: "tx", name: "Up", color: "var(--c-ok)" }]} /></div>
              </div>
            </>
          )}
        </Card>
      </div>

      <Card title="Disks" bodyClass="p-0" info="Storage space per mounted drive. When a disk fills up, databases and websites usually stop working. 'Inodes' is the number of files; it can also run out.">
        <table className="tbl">
          <thead><tr><th>Mounted at</th><th>Device</th><th className="w-[30%]">Used</th><th className="text-right">Used</th><th className="text-right">Free</th><th className="text-right">Size</th><th className="text-right">Inodes</th></tr></thead>
          <tbody>
            {sys.disks.map((d) => {
              const lv = pctLevel(d.percent, 80, 92);
              return (
                <tr key={d.mount}>
                  <td className="mono font-medium">{d.mount}</td>
                  <td className="mono text-[0.875rem] text-muted">{d.device} <span className="text-[0.8125rem]">({d.fstype})</span></td>
                  <td><Bar pct={d.percent} level={lv} height={7} /></td>
                  <td className="text-right font-semibold tabular-nums" style={{ color: levelColor[lv] }}>{fmtPct(d.percent)}</td>
                  <td className="text-right tabular-nums">{fmtBytes(d.free)}</td>
                  <td className="text-right tabular-nums text-muted">{fmtBytes(d.total)}</td>
                  <td className="text-right tabular-nums text-muted">{fmtPct(d.inodes_percent)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Card>

      <div className="grid gap-5 xl:grid-cols-2">
        <Card title="Top processes" bodyClass="p-0" info="The programs using the most CPU or memory right now. Hover a name to see the full command line."
          right={<Segmented value={sort} onChange={setSort} options={[{ value: "cpu", label: "By CPU" }, { value: "mem", label: "By memory" }]} />}>
          <div className="max-h-[520px] overflow-auto">
            <table className="tbl">
              <thead className="sticky top-0 bg-panel"><tr><th>Program</th><th>User</th><th>PID</th><th className="text-right">CPU</th><th className="text-right">Memory</th><th className="text-right">Running for</th></tr></thead>
              <tbody>
                {procs.slice(0, 40).map((p) => (
                  <tr key={p.pid}>
                    <td className="max-w-[200px]"><div className="truncate font-medium" title={p.cmd}>{p.name}</div><div className="truncate mono text-[0.8125rem] text-muted" title={p.cmd}>{p.cmd}</div></td>
                    <td className="max-w-[90px] truncate text-muted" title={p.user}>{p.user}</td>
                    <td className="mono text-[0.875rem] text-muted">{p.pid}</td>
                    <td className="text-right tabular-nums" style={{ color: p.cpu > 50 ? "var(--c-warn)" : undefined }}>{fmtPct(p.cpu, 1)}</td>
                    <td className="whitespace-nowrap text-right tabular-nums" title={`${fmtPct(p.mem_percent, 1)} of RAM`}>{fmtBytes(p.mem_rss)}</td>
                    <td className="whitespace-nowrap text-right text-muted">{p.started ? fmtDuration((now - p.started) / 1000) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>

        <Card bodyClass="p-0" title={<span className="flex items-center gap-2">Services {failed.length > 0 && <Pill color="var(--c-danger)">{failed.length} failed</Pill>}</span>}
          info="Background programs managed by systemd — web server, database, SSH and so on. 'Failed' means it crashed or couldn't start. Fix with: sudo systemctl restart NAME, and see why with: journalctl -u NAME"
          right={
            <>
              <Segmented value={svcView} onChange={setSvcView} options={[{ value: "problems", label: "Problems" }, { value: "running", label: "Running" }, { value: "all", label: "All" }]} />
              <div className="relative"><Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
                <input className="input w-36 !pl-7" placeholder="Filter…" value={svcFilter} onChange={(e) => setSvcFilter(e.target.value)} /></div>
            </>
          }>
          {!sys.services_available ? <Empty>{sys.services_message || "systemd is not available on this system."}</Empty> : services.length === 0 ? (
            <Empty>{svcView === "problems" ? "All services are running fine. ✓" : "No services match."}</Empty>
          ) : (
            <div className="max-h-[520px] overflow-auto">
              <table className="tbl">
                <thead className="sticky top-0 bg-panel"><tr><th>Service</th><th>Status</th><th>Description</th></tr></thead>
                <tbody>
                  {services.map((s) => (
                    <tr key={s.name} className={s.active === "failed" ? "bg-bad/[.06]" : ""}>
                      <td className="mono text-[0.9062rem]">{s.name}</td>
                      <td className="whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <Dot level={s.active === "active" ? "good" : s.active === "failed" ? "bad" : s.active === "activating" ? "warn" : "off"} />
                          {s.active === "active" ? (s.sub === "running" ? "running" : s.sub) : s.active}
                        </span>
                      </td>
                      <td className="max-w-[260px] truncate text-muted" title={s.description}>{s.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
