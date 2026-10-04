"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { GlobalThreatGraph } from "@/components/global-threat-graph";
import {
  NetworkIcon,
  SearchIcon,
  ShieldAlertIcon,
  TrendingUpIcon,
  UsersIcon,
  ArrowRightIcon,
} from "@/components/icons";

interface GraphRow {
  id: string;
  query: string;
  status: string;
  updated_at: string;
  nodes: number;
  edges: number;
  communities: number;
  high_conf_edges: number;
  key_pivot: { label: string; node_type: string; degree: number } | null;
  sanctioned_count: number;
  origin_ip_count: number;
}

interface Totals {
  investigations: number;
  nodes: number;
  high_conf_edges: number;
  communities: number;
}

const STATUS_COLORS: Record<string, string> = {
  COMPLETED: "text-emerald-400 border-emerald-500/30 bg-emerald-500/5",
  RUNNING: "text-amber-400 border-amber-500/30 bg-amber-500/5",
  PENDING: "text-zinc-400 border-zinc-500/30 bg-zinc-500/5",
  FAILED: "text-red-400 border-red-500/30 bg-red-500/5",
};

export default function GraphIndexPage() {
  const router = useRouter();
  const [data, setData] = useState<{ investigations: GraphRow[]; totals: Totals } | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");

  // Filters
  const [minNodes, setMinNodes] = useState(0);
  const [minEdges, setMinEdges] = useState(0);
  const [onlySanctioned, setOnlySanctioned] = useState(false);
  const [onlyOriginIP, setOnlyOriginIP] = useState(false);
  const [onlyMultiCommunity, setOnlyMultiCommunity] = useState(false);
  const [onlyHighConf, setOnlyHighConf] = useState(false);

  useEffect(() => {
    fetch("/api/graph/index")
      .then((r) => r.json())
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const rows = (data?.investigations ?? []).filter((r) => {
    if (search && !r.query.toLowerCase().includes(search.toLowerCase()) && !r.id.includes(search)) return false;
    if (r.nodes < minNodes) return false;
    if (r.edges < minEdges) return false;
    if (onlySanctioned && r.sanctioned_count === 0) return false;
    if (onlyOriginIP && r.origin_ip_count === 0) return false;
    if (onlyMultiCommunity && r.communities <= 1) return false;
    if (onlyHighConf && r.high_conf_edges === 0) return false;
    return true;
  });

  const t = data?.totals;

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        {/* Header */}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold tracking-tight">Graph Investigation Index</h1>
            <p className="text-sm text-muted-foreground">
              Which investigations contain the most actionable relationship networks?
            </p>
          </div>
          <Badge variant="secondary" className="self-start font-mono text-xs">
            GRAPH CASE QUEUE
          </Badge>
        </div>

        {/* Summary cards */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: "Investigations", value: t?.investigations ?? "—", icon: <NetworkIcon className="h-4 w-4 text-primary" /> },
            { label: "Total Nodes", value: t?.nodes ?? "—", icon: <UsersIcon className="h-4 w-4 text-blue-400" /> },
            { label: "High-confidence Edges", value: t?.high_conf_edges ?? "—", icon: <TrendingUpIcon className="h-4 w-4 text-emerald-400" /> },
            { label: "Cross-Onion Clusters", value: t?.communities ?? "—", icon: <ShieldAlertIcon className="h-4 w-4 text-amber-400" /> },
          ].map(({ label, value, icon }) => (
            <Card key={label} className="group/card relative overflow-hidden border border-dashed border-border/70 bg-zinc-950/90 transition-colors duration-200 hover:border-primary/40">
              <div className="pointer-events-none absolute inset-0 opacity-[0.07] transition-opacity duration-300 group-hover/card:opacity-20"
                style={{ backgroundImage: "radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)", backgroundSize: "14px 14px" }} />
              <CardContent className="flex items-center gap-3 pt-4 pb-4">
                {icon}
                <div>
                  <div className="text-xl font-bold tabular-nums">{loading ? "…" : value}</div>
                  <div className="text-[11px] text-muted-foreground">{label}</div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        <GlobalThreatGraph />

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-3 rounded-xl border border-dashed border-border/50 bg-zinc-950/80 p-3">
          <div className="flex items-center gap-1.5">
            <SearchIcon className="h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search query or ID…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-7 w-44 text-xs font-mono"
            />
          </div>
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span>Min nodes:</span>
            <Input type="number" value={minNodes} onChange={(e) => setMinNodes(Number(e.target.value))}
              className="h-7 w-16 text-xs font-mono" min={0} />
          </div>
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span>Min edges:</span>
            <Input type="number" value={minEdges} onChange={(e) => setMinEdges(Number(e.target.value))}
              className="h-7 w-16 text-xs font-mono" min={0} />
          </div>
          {([
            ["Has sanctioned", onlySanctioned, setOnlySanctioned],
            ["Has origin IP", onlyOriginIP, setOnlyOriginIP],
            ["Multi-community", onlyMultiCommunity, setOnlyMultiCommunity],
            ["High-conf links", onlyHighConf, setOnlyHighConf],
          ] as [string, boolean, (v: boolean) => void][]).map(([label, val, setter]) => (
            <button key={label}
              onClick={() => setter(!val)}
              className={`rounded-md border px-2.5 py-1 text-xs transition-colors ${val ? "border-primary/60 bg-primary/10 text-primary" : "border-border/40 text-muted-foreground hover:border-border"}`}>
              {label}
            </button>
          ))}
          <span className="ml-auto text-[11px] text-muted-foreground font-mono">{rows.length} result{rows.length !== 1 ? "s" : ""}</span>
        </div>

        {/* Main table */}
        <div className="rounded-xl border border-dashed border-border/60 bg-zinc-950/90 overflow-hidden">
          <table className="w-full text-xs">
            <thead className="border-b border-border/40 text-muted-foreground">
              <tr>
                <th className="px-4 py-3 text-left">Investigation</th>
                <th className="px-4 py-3 text-right">Nodes</th>
                <th className="px-4 py-3 text-right">Edges</th>
                <th className="px-4 py-3 text-right">Communities</th>
                <th className="px-4 py-3 text-right">High-conf links</th>
                <th className="px-4 py-3 text-left">Key pivot</th>
                <th className="px-4 py-3 text-right">Priority signals</th>
                <th className="px-4 py-3 text-left">Last updated</th>
                <th className="px-4 py-3 text-right" />
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-muted-foreground">Loading…</td>
                </tr>
              )}
              {!loading && rows.length === 0 && (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-muted-foreground">No investigations match current filters.</td>
                </tr>
              )}
              {rows.map((r) => (
                <tr key={r.id}
                  className="border-b border-border/10 last:border-0 hover:bg-white/[0.02] transition-colors cursor-pointer"
                  onClick={() => router.push(`/graph/${r.id}`)}>
                  <td className="px-4 py-3">
                    <div className="font-semibold text-foreground">{r.query}</div>
                    <div className="font-mono text-[10px] text-muted-foreground">{r.id}</div>
                    <Badge variant="outline"
                      className={`mt-1 text-[10px] ${STATUS_COLORS[r.status] ?? ""}`}>
                      {r.status}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums font-mono font-semibold text-foreground">{r.nodes}</td>
                  <td className="px-4 py-3 text-right tabular-nums font-mono text-muted-foreground">{r.edges}</td>
                  <td className="px-4 py-3 text-right tabular-nums font-mono text-amber-400">{r.communities}</td>
                  <td className="px-4 py-3 text-right">
                    <span className={`font-mono tabular-nums ${r.high_conf_edges > 0 ? "text-emerald-400" : "text-muted-foreground"}`}>
                      {r.high_conf_edges}
                    </span>
                  </td>
                  <td className="px-4 py-3 max-w-[160px]">
                    {r.key_pivot ? (
                      <>
                        <div className="truncate font-mono text-foreground">{r.key_pivot.label}</div>
                        <div className="text-[10px] text-muted-foreground">{r.key_pivot.node_type} · deg {r.key_pivot.degree}</div>
                      </>
                    ) : <span className="text-muted-foreground">—</span>}
                  </td>
                  <td className="px-4 py-3 text-right space-y-1">
                    {r.sanctioned_count > 0 && (
                      <div className="flex items-center justify-end gap-1 text-red-400">
                        <ShieldAlertIcon className="h-3 w-3" />
                        <span className="text-[10px]">{r.sanctioned_count} sanctioned</span>
                      </div>
                    )}
                    {r.origin_ip_count > 0 && (
                      <div className="text-[10px] text-amber-400">{r.origin_ip_count} origin-IP</div>
                    )}
                    {r.sanctioned_count === 0 && r.origin_ip_count === 0 && (
                      <span className="text-[10px] text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-[10px] text-muted-foreground">
                    {r.updated_at ? r.updated_at.slice(0, 10) : "—"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Button size="sm" variant="ghost"
                      className="h-7 px-2 text-[11px] gap-1 text-primary"
                      onClick={(e) => { e.stopPropagation(); router.push(`/graph/${r.id}`); }}>
                      Open <ArrowRightIcon className="h-3 w-3" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </AppShell>
  );
}
