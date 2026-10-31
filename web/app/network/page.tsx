"use client";

import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { RankBars, TimeArea } from "@/components/charts";
import { Card, Empty, GeoTag, InfoTip, IPLink, PageHeader, Pill, Segmented, Stat, PageSkeleton } from "@/components/ui";
import { useUI } from "@/components/uictx";
import { WorldMap } from "@/components/worldmap";
import { useApi } from "@/lib/hooks";
import { useLive } from "@/lib/live";
import { flagEmoji, fmtBytes, fmtNum, fmtRate } from "@/lib/format";
import type { Listener, MetricPoint, NetworkSnapshot } from "@/lib/types";

const stateHelp: Record<string, string> = {
  ESTABLISHED: "Active, open conversation",
  LISTEN: "Waiting for new visitors",
  TIME_WAIT: "Recently finished, being cleaned up",
  CLOSE_WAIT: "The other side hung up; the program hasn't closed it yet",
  SYN_RECV: "Someone is starting a connection (many of these can mean a flood attack)",
  SYN_SENT: "Your server is trying to connect out",
  FIN_WAIT1: "Closing", FIN_WAIT2: "Closing", LAST_ACK: "Closing", CLOSING: "Closing", UNCONN: "UDP socket",
};

export default function NetworkPage() {
  const live = useLive();
  const { data } = useApi<{ network: NetworkSnapshot; ports: Listener[] }>("/api/network", { interval: 30000 });
  const { openIP } = useUI();
  const net = live.network || data?.network;
  const [iface, setIface] = useState("all");
  const [q, setQ] = useState("");
  const [dir, setDir] = useState<"all" | "in" | "out">("all");

  const [span, setSpan] = useState("live");
  const hist = useApi<{ points: MetricPoint[] | null }>(`/api/history?range=${span === "live" ? "1h" : span}`, { interval: 60000 });
  const ifaces = net?.interfaces || [];
  const useLiveData = span === "live" && live.netHistory.length >= 5;
  const chart = useMemo(
    () => useLiveData
      ? live.netHistory.map((p) => (iface === "all" ? { ts: p.ts, rx: p.rx, tx: p.tx } : { ts: p.ts, rx: p.ifaces[iface]?.rx || 0, tx: p.ifaces[iface]?.tx || 0 }))
      : (hist.data?.points || []).map((m) => ({ ts: m.ts, rx: m.rx, tx: m.tx })),
    [useLiveData, live.netHistory, iface, hist.data],
  );

  const conns = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (net?.connections || [])
      .filter((c) => c.direction !== "local")
      .filter((c) => dir === "all" || c.direction === dir)
      .filter((c) => !s || [c.remote_ip, c.process, String(c.local_port), String(c.remote_port), c.state, c.geo?.country, c.geo?.city].some((x) => x && x.toLowerCase().includes(s)))
      .sort((a, b) => b.bytes_recv + b.bytes_sent - (a.bytes_recv + a.bytes_sent));
  }, [net?.connections, q, dir]);

  if (!net) return <PageSkeleton />;
  const listeners = net.listeners.length ? net.listeners : data?.ports || [];
  const publicRisky = listeners.filter((l) => l.public && l.risk);

  return (
    <div className="space-y-5">
      <PageHeader title="Network" desc="Who your server talks to, how much, and which doors (ports) are open to the internet." />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Download" value={fmtRate(net.total_rx_bps)} info="Total incoming speed over all network interfaces." />
        <Stat label="Upload" value={fmtRate(net.total_tx_bps)} info="Total outgoing speed over all network interfaces." />
        <Stat label="Connections" value={fmtNum(net.conn_count)} sub={Object.entries(net.state_counts || {}).sort((a, b) => b[1] - a[1]).slice(0, 2).map(([k, v]) => `${v} ${k.toLowerCase()}`).join(" · ")}
          info="Number of network conversations, including ones that are just closing." />
        <Stat label="Open ports" value={listeners.filter((l) => l.public).length} sub={publicRisky.length ? `${publicRisky.length} need attention` : "all look normal"} color={publicRisky.length ? "var(--c-warn)" : undefined}
          info="Ports are 'doors' programs open so others can connect. Public ones can be reached by anyone on the internet." />
      </div>

      <Card title="Bandwidth" info="Live: speed per network card, updated every couple of seconds. 1h/24h/7d: total speed from stored history (one point per minute). 'lo' is internal traffic inside the server itself."
        right={<div className="flex flex-wrap gap-2">
          {useLiveData && <Segmented value={iface} onChange={setIface} options={[{ value: "all", label: "All" }, ...ifaces.map((i) => ({ value: i.name, label: i.name }))]} />}
          <Segmented value={span} onChange={setSpan} options={[{ value: "live", label: "Live" }, { value: "1h", label: "1h" }, { value: "24h", label: "24h" }, { value: "7d", label: "7d" }]} />
        </div>}>
        <TimeArea data={chart} height={240} fmt={(v) => fmtRate(v)} legend series={[{ key: "rx", name: "Download", color: "var(--c-accent2)" }, { key: "tx", name: "Upload", color: "var(--c-ok)" }]} />
        <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
          {ifaces.map((i) => (
            <div key={i.name} className="rounded-lg border border-line bg-panel2 p-3 text-[0.875rem]">
              <div className="mb-1 flex items-center justify-between">
                <span className="mono font-semibold text-text">{i.name}</span>
                <Pill color={i.up ? "var(--c-ok)" : "var(--c-muted)"}>{i.up ? "up" : "down"}</Pill>
              </div>
              <div className="text-muted">↓ {fmtRate(i.rx_bps)} · ↑ {fmtRate(i.tx_bps)}</div>
              <div className="text-muted">Total: ↓ {fmtBytes(i.rx_bytes)} · ↑ {fmtBytes(i.tx_bytes)}</div>
              {i.addrs?.length > 0 && <div className="mono mt-1 truncate text-[0.8125rem] text-muted" title={i.addrs.join(", ")}>{i.addrs.join(", ")}</div>}
              {i.rx_errors + i.tx_errors > 0 && <div className="text-warn">{i.rx_errors + i.tx_errors} errors</div>}
            </div>
          ))}
        </div>
      </Card>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="World map" className="xl:col-span-2" bodyClass="p-2" info="Where the computers connected to your server are, based on their IP address (approximate, city-level at best). Click a dot to inspect it.">
          <WorldMap points={net.geo} server={net.server} countryStats={net.countries} onSelect={(p) => p.ips[0] && openIP(p.ips[0])} />
        </Card>
        <Card title="Countries" info="Connections grouped by country.">
          {net.countries.length === 0 ? <Empty>No outside connections.</Empty> : (
            <RankBars items={net.countries.slice(0, 14).map((c) => ({ key: c.cc, label: <>{flagEmoji(c.cc)} {c.country} <span className="text-muted">({c.ips} IP)</span></>, value: c.conns }))} fmt={(v) => `${v} conn`} />
          )}
        </Card>
      </div>

      <Card title="Top talkers" info="Outside addresses ranked by how much data they exchange with your server. A single unknown address using lots of bandwidth is worth a look." bodyClass="p-0">
        {net.talkers.length === 0 ? <Empty>No outside connections right now.</Empty> : (
          <div className="overflow-x-auto">
            <table className="tbl">
              <thead><tr><th>Address</th><th>Location</th><th>Direction</th><th>Programs</th><th>Ports</th><th className="text-right">Conns</th><th className="text-right">In</th><th className="text-right">Out</th><th className="text-right">Speed</th></tr></thead>
              <tbody>
                {net.talkers.slice(0, 15).map((t) => (
                  <tr key={t.ip}>
                    <td><IPLink ip={t.ip} threat={t.threat} blocked={t.blocked} /></td>
                    <td><GeoTag geo={t.geo} /></td>
                    <td className="text-muted">{t.direction === "in" ? "visiting you" : t.direction === "out" ? "you connect to it" : t.direction}</td>
                    <td>{(t.processes || []).join(", ") || <span className="text-muted">—</span>}</td>
                    <td className="mono text-[0.875rem] text-muted">{(t.ports || []).slice(0, 4).join(", ")}</td>
                    <td className="text-right tabular-nums">{t.conns}</td>
                    <td className="text-right tabular-nums">{fmtBytes(t.bytes_in)}</td>
                    <td className="text-right tabular-nums">{fmtBytes(t.bytes_out)}</td>
                    <td className="text-right tabular-nums">{fmtRate(t.rate_in + t.rate_out)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card title="Open ports (listening)" bodyClass="p-0"
        info="Every program waiting for connections. 'Public' means reachable from the internet (unless a firewall blocks it); 'local only' means only this server can use it — that's the safe default for databases.">
        <div className="overflow-x-auto">
          <table className="tbl">
            <thead><tr><th>Port</th><th>Protocol</th><th>What it is</th><th>Program</th><th>Listening on</th><th>Exposure</th><th className="text-right">Active conns</th></tr></thead>
            <tbody>
              {listeners.map((l, i) => (
                <tr key={i} className={l.public && l.risk ? "bg-warn/[.06]" : ""}>
                  <td className="mono font-semibold">{l.port}</td>
                  <td className="uppercase text-muted">{l.proto}</td>
                  <td>{l.service || <span className="text-muted">unknown</span>}</td>
                  <td>{l.process || <span className="text-muted" title="Needs root to see other users' programs">hidden</span>}{l.pid ? <span className="text-muted"> ({l.pid})</span> : null}</td>
                  <td className="mono text-[0.875rem] text-muted">{l.addr}</td>
                  <td>
                    {l.public ? (
                      <span className="flex items-center gap-1.5">
                        <Pill color={l.risk ? "var(--c-warn)" : "var(--c-accent2)"}>public</Pill>
                        {l.risk && <InfoTip>{l.risk}</InfoTip>}
                      </span>
                    ) : <Pill color="var(--c-ok)">local only</Pill>}
                  </td>
                  <td className="text-right tabular-nums">{l.conns}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card title={`Connections (${conns.length})`} bodyClass="p-0"
        info="Every individual network conversation. Bytes and round-trip time come from the kernel (needs the netlink collector; shows — otherwise)."
        right={
          <>
            <Segmented value={dir} onChange={setDir} options={[{ value: "all", label: "All" }, { value: "in", label: "Incoming" }, { value: "out", label: "Outgoing" }]} />
            <div className="relative">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
              <input className="input w-48 !pl-7" placeholder="Filter IP, port, program…" value={q} onChange={(e) => setQ(e.target.value)} />
            </div>
          </>
        }>
        <div className="max-h-[560px] overflow-auto">
          <table className="tbl">
            <thead className="sticky top-0 bg-panel"><tr><th>Remote</th><th>Location</th><th>Local port</th><th>Program</th><th>State</th><th className="text-right">Received</th><th className="text-right">Sent</th><th className="text-right">Ping</th></tr></thead>
            <tbody>
              {conns.slice(0, 300).map((c, i) => (
                <tr key={i}>
                  <td className="whitespace-nowrap"><IPLink ip={c.remote_ip} /><span className="text-muted">:{c.remote_port}</span></td>
                  <td><GeoTag geo={c.geo} short /></td>
                  <td className="mono text-[0.875rem]">{c.proto.toUpperCase()} {c.local_port} <span className="text-muted">{c.direction === "in" ? "← in" : "→ out"}</span></td>
                  <td>{c.process || <span className="text-muted">—</span>}{c.user ? <span className="text-muted"> · {c.user}</span> : null}</td>
                  <td><span title={stateHelp[c.state] || c.state} className="cursor-help border-b border-dotted border-muted text-[0.875rem]">{c.state}</span></td>
                  <td className="text-right tabular-nums">{c.bytes_recv ? fmtBytes(c.bytes_recv) : "—"}</td>
                  <td className="text-right tabular-nums">{c.bytes_sent ? fmtBytes(c.bytes_sent) : "—"}</td>
                  <td className="text-right tabular-nums text-muted">{c.rtt_ms ? `${c.rtt_ms.toFixed(0)} ms` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {conns.length > 300 && <div className="p-3 text-center text-[0.875rem] text-muted">Showing 300 of {conns.length}. Use the filter to narrow down.</div>}
          {conns.length === 0 && <Empty>No connections match.</Empty>}
        </div>
      </Card>
      <p className="text-[0.8438rem] text-muted">Data source: {net.source}{net.capture ? ` · packet capture: ${net.capture}` : ""}. IP geolocation by <a className="underline" href="https://db-ip.com" target="_blank" rel="noreferrer">DB-IP</a> (CC BY 4.0).</p>
    </div>
  );
}
