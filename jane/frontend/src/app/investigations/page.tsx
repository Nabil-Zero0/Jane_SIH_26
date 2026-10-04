"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PlusIcon, SearchIcon, ArrowRightIcon, ScrollIcon } from "@/components/icons";
import { ExportModal } from "@/components/export-modal";

interface Investigation {
  id: string;
  query: string;
  max_onions: number;
  max_depth: number;
  status: string;
  page_count: number;
  created_at: string;
  updated_at: string;
  // ponytail: mock computed fields from backend, add real API endpoint when backend implements
  actor_count?: number;
  identifier_count?: number;
  sanctioned_count?: number;
  leaked_ip_count?: number;
  avg_confidence?: number;
}

const STATUS_COLOR: Record<string, string> = {
  COMPLETED: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  PENDING: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  QUEUED: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  FAILED_COLLECTION: "bg-red-500/20 text-red-400 border-red-500/30",
  FAILED_EXTRACTION: "bg-red-500/20 text-red-400 border-red-500/30",
  FAILED_AI: "bg-red-500/20 text-red-400 border-red-500/30",
};

export default function InvestigationsPage() {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState("");
  const [maxOnions, setMaxOnions] = useState("5");
  const [maxDepth, setMaxDepth] = useState("1");
  const [fanoutCount, setFanoutCount] = useState("3");
  const [submitting, setSubmitting] = useState(false);
  const [fanoutQueries, setFanoutQueries] = useState<Array<{ text: string; purpose: string; enabled: boolean }>>([]);
  const [generatingFanout, setGeneratingFanout] = useState(false);
  const [selectedProviders, setSelectedProviders] = useState<string[]>(["ahmia", "seeds"]);
  const [filter, setFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [riskFilter, setRiskFilter] = useState(false);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [exportModalState, setExportModalState] = useState<{ open: boolean; ids: string[]; title?: string }>({
    open: false,
    ids: [],
  });

  const fetchInvestigations = () => {
    fetch("/api/investigations")
      .then((r) => r.json())
      .then((d) => setInvestigations(d.investigations || []))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchInvestigations();
    const iv = setInterval(fetchInvestigations, 5000);
    return () => clearInterval(iv);
  }, []);

  const handleGeneratePlan = async () => {
    if (!query.trim()) return;
    setGeneratingFanout(true);
    try {
      const res = await fetch(`/api/query/plan?q=${encodeURIComponent(query.trim())}&fanout_count=${parseInt(fanoutCount) || 3}`);
      const data = await res.json();
      if (data.queries && Array.isArray(data.queries)) {
        setFanoutQueries(data.queries.map((q: any) => ({
          text: q.text,
          purpose: q.purpose || "synonym",
          enabled: true,
        })));
      }
    } catch (err) {
      console.error("Failed to generate fanout plan", err);
    } finally {
      setGeneratingFanout(false);
    }
  };

  const toggleFanoutChip = (index: number) => {
    setFanoutQueries((prev) =>
      prev.map((item, idx) => (idx === index ? { ...item, enabled: !item.enabled } : item))
    );
  };

  const toggleProvider = (name: string) => {
    setSelectedProviders((prev) =>
      prev.includes(name) ? prev.filter((p) => p !== name) : [...prev, name]
    );
  };

  const handleDispatch = async () => {
    if (!query.trim()) return;
    setSubmitting(true);
    const activeFanout = fanoutQueries.filter((q) => q.enabled).map((q) => q.text);
    await fetch("/api/investigate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        query: query.trim(), 
        max_onions: parseInt(maxOnions) || 5, 
        max_depth: parseInt(maxDepth) || 1,
        fanout_count: parseInt(fanoutCount) || 3,
        fanout_queries: activeFanout.length > 0 ? activeFanout : undefined,
        providers: selectedProviders.length > 0 ? selectedProviders : undefined,
      }),
    });
    setQuery("");
    setFanoutQueries([]);
    setSubmitting(false);
    fetchInvestigations();
  };

  const filtered = investigations.filter((inv) => {
    const matchesText = inv.query.toLowerCase().includes(filter.toLowerCase()) || inv.id.toLowerCase().includes(filter.toLowerCase());
    const matchesStatus = statusFilter === "ALL" || inv.status === statusFilter;
    const matchesRisk = !riskFilter || (inv.sanctioned_count ?? 0) > 0 || (inv.leaked_ip_count ?? 0) > 0;
    return matchesText && matchesStatus && matchesRisk;
  });

  const toggleSelectAll = () => {
    if (selectedIds.length === filtered.length && filtered.length > 0) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filtered.map((i) => i.id));
    }
  };

  const toggleSelectOne = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const active = investigations.filter(i => i.status === "PENDING" || i.status === "QUEUED").length;
  const completed = investigations.filter(i => i.status === "COMPLETED").length;
  const withIPs = investigations.filter(i => (i.leaked_ip_count ?? 0) > 0).length;
  const withSanctions = investigations.filter(i => (i.sanctioned_count ?? 0) > 0).length;

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Investigations</h1>
          <p className="text-sm text-muted-foreground">
            Dispatch, monitor, and review all hunt sessions with multi-engine query fanout.
          </p>
        </div>

        {/* Summary strip */}
        <div className="grid gap-3 sm:grid-cols-4">
          {[
            { label: "Active Cases", value: active },
            { label: "Awaiting Review", value: completed },
            { label: "Origin-IP Pivots", value: withIPs },
            { label: "Sanctioned Assets", value: withSanctions },
          ].map((s) => (
            <Card key={s.label} className="border-border/50 bg-card/80">
              <CardContent className="pt-4 text-center">
                <div className="text-2xl font-bold tabular-nums">{s.value}</div>
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{s.label}</div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Dispatch new investigation */}
        <Card className="border-border/50 bg-card/80">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <PlusIcon className="h-4 w-4" /> Dispatch New Investigation
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Input
                placeholder="Target query, e.g. 'stolen cards Mumbai' or 'credit card dumps'..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleDispatch()}
                className="font-mono text-sm"
              />
              <Button
                variant="outline"
                onClick={handleGeneratePlan}
                disabled={generatingFanout || !query.trim()}
                className="whitespace-nowrap text-xs"
              >
                {generatingFanout ? "Planning…" : "⚡ Preview Fanout"}
              </Button>
            </div>

            {/* Fanout Query Chips Preview */}
            {fanoutQueries.length > 0 && (
              <div className="space-y-1.5 p-3 rounded-md bg-muted/40 border border-border/40">
                <div className="text-xs font-semibold text-muted-foreground flex justify-between items-center">
                  <span>Query Fanout Plan ({fanoutQueries.filter(q => q.enabled).length} active)</span>
                  <span className="text-[10px] text-muted-foreground/80">Click chip to toggle on/off</span>
                </div>
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {fanoutQueries.map((item, idx) => (
                    <button
                      key={idx}
                      type="button"
                      onClick={() => toggleFanoutChip(idx)}
                      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono transition-colors border ${
                        item.enabled
                          ? "bg-primary/10 border-primary/40 text-primary"
                          : "bg-muted border-border/40 text-muted-foreground line-through opacity-60"
                      }`}
                    >
                      <Badge variant="outline" className="text-[9px] uppercase px-1 py-0 border-primary/30">
                        {item.purpose}
                      </Badge>
                      <span>{item.text}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Search Engine Provider Selection */}
            <div className="space-y-1.5">
              <label className="text-xs text-muted-foreground block">
                Search Providers (Select engines for discovery)
              </label>
              <div className="flex flex-wrap gap-2">
                {[
                  { id: "ahmia", label: "Ahmia (Default)", defaultActive: true },
                  { id: "torch", label: "Torch (.onion)", defaultActive: false },
                  { id: "tor66", label: "Tor66 (Index)", defaultActive: false },
                  { id: "seeds", label: "Curated Seeds", defaultActive: true },
                ].map((p) => {
                  const active = selectedProviders.includes(p.id);
                  return (
                    <button
                      key={p.id}
                      type="button"
                      onClick={() => toggleProvider(p.id)}
                      className={`px-3 py-1 text-xs rounded-md border font-mono transition-all ${
                        active
                          ? "bg-primary/20 text-primary border-primary/50 shadow-sm"
                          : "bg-card text-muted-foreground border-border/50 hover:border-border"
                      }`}
                    >
                      {active ? "✓ " : "+ "} {p.label}
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="flex gap-3 items-end pt-1">
              <div className="flex-1">
                <label className="text-xs text-muted-foreground block mb-1">Fanout Count</label>
                <Input
                  type="number"
                  min="1"
                  max="10"
                  value={fanoutCount}
                  onChange={(e) => setFanoutCount(e.target.value)}
                  className="text-sm"
                />
              </div>
              <div className="flex-1">
                <label className="text-xs text-muted-foreground block mb-1">Max Onions</label>
                <Input
                  type="number"
                  min="1"
                  max="50"
                  value={maxOnions}
                  onChange={(e) => setMaxOnions(e.target.value)}
                  className="text-sm"
                />
              </div>
              <div className="flex-1">
                <label className="text-xs text-muted-foreground block mb-1">Max Depth</label>
                <Input
                  type="number"
                  min="1"
                  max="5"
                  value={maxDepth}
                  onChange={(e) => setMaxDepth(e.target.value)}
                  className="text-sm"
                />
              </div>
              <Button onClick={handleDispatch} disabled={submitting || !query.trim()} className="px-6">
                {submitting ? "Queuing…" : "Dispatch Hunt"}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Filter & Export toolbar */}
        <div className="flex gap-2 items-center justify-between flex-wrap">
          <div className="flex gap-2 items-center flex-wrap">
            <SearchIcon className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Filter by query or ID..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="max-w-xs text-sm"
            />
            <select 
              value={statusFilter} 
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-md border border-border bg-card px-3 py-1.5 text-sm"
            >
              <option value="ALL">All Status</option>
              <option value="COMPLETED">Completed</option>
              <option value="PENDING">Pending</option>
              <option value="QUEUED">Queued</option>
              <option value="FAILED_COLLECTION">Failed</option>
            </select>
            <label className="flex items-center gap-2 text-sm text-muted-foreground cursor-pointer">
              <input 
                type="checkbox" 
                checked={riskFilter} 
                onChange={(e) => setRiskFilter(e.target.checked)}
                className="rounded"
              />
              High-risk only
            </label>
          </div>

          <div className="flex items-center gap-2">
            {selectedIds.length > 0 && (
              <Button
                size="sm"
                className="bg-primary text-primary-foreground hover:bg-primary/90 text-xs h-8 gap-1.5"
                onClick={() => setExportModalState({ open: true, ids: selectedIds, title: `Export ${selectedIds.length} Selected Cases` })}
              >
                <ScrollIcon className="h-3.5 w-3.5" />
                Export Selected ({selectedIds.length})
              </Button>
            )}
            {filtered.length > 0 && (
              <Button
                size="sm"
                variant="outline"
                className="text-xs h-8 gap-1.5 border-border/60 hover:bg-muted/30"
                onClick={() => setExportModalState({ open: true, ids: filtered.map(i => i.id), title: `Export ${filtered.length} Filtered Cases` })}
              >
                <ScrollIcon className="h-3.5 w-3.5 text-muted-foreground" />
                Export Filtered ({filtered.length})
              </Button>
            )}
          </div>
        </div>

        {/* Table */}
        <Card className="border-border/50 bg-card/80">
          <CardContent className="p-0">
            <table className="w-full text-sm">
              <thead className="border-b border-border/50">
                <tr className="text-left text-xs text-muted-foreground">
                  <th className="w-10 px-3 py-3 text-center">
                    <input
                      type="checkbox"
                      checked={filtered.length > 0 && selectedIds.length === filtered.length}
                      onChange={toggleSelectAll}
                      className="rounded"
                      title="Select all cases"
                    />
                  </th>
                  <th className="px-4 py-3 font-medium">Case</th>
                  <th className="px-4 py-3 font-medium">Status</th>
                  <th className="px-4 py-3 font-medium">Intelligence Yield</th>
                  <th className="px-4 py-3 font-medium">Risk Signals</th>
                  <th className="px-4 py-3 font-medium">Confidence</th>
                  <th className="px-4 py-3 font-medium">Last Updated</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-muted-foreground">
                      Loading…
                    </td>
                  </tr>
                )}
                {!loading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={8} className="py-8 text-center text-muted-foreground">
                      {filter || statusFilter !== "ALL" || riskFilter 
                        ? "No investigations match filters." 
                        : "No investigations yet. Dispatch one above."}
                    </td>
                  </tr>
                )}
                {filtered.map((inv) => {
                  const pages = inv.page_count || 0;
                  const iocs = inv.identifier_count || 0;
                  const actors = inv.actor_count || 0;
                  const sanctioned = inv.sanctioned_count || 0;
                  const leakedIPs = inv.leaked_ip_count || 0;
                  const riskSignals = sanctioned + leakedIPs;
                  const conf = inv.avg_confidence ?? 0;
                  const confLabel = conf >= 0.8 ? "High" : conf >= 0.5 ? "Medium" : conf > 0 ? "Low" : "—";
                  const confColor = conf >= 0.8 ? "text-emerald-400" : conf >= 0.5 ? "text-yellow-400" : "text-muted-foreground";
                  const isSelected = selectedIds.includes(inv.id);
                  
                  return (
                    <tr key={inv.id} className={`border-b border-border/20 last:border-0 hover:bg-muted/10 ${isSelected ? "bg-muted/20" : ""}`}>
                      <td className="w-10 px-3 py-3 text-center">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => toggleSelectOne(inv.id)}
                          className="rounded"
                        />
                      </td>
                      <td className="px-4 py-3">
                        <div className="max-w-xs truncate font-medium">{inv.query}</div>
                        <div className="font-mono text-[10px] text-muted-foreground">{inv.id}</div>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${STATUS_COLOR[inv.status] ?? "bg-slate-500/20 text-slate-400 border-slate-500/30"}`}>
                          {inv.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">
                        {pages > 0 && <span>{pages} pages</span>}
                        {iocs > 0 && <span> · {iocs} IOCs</span>}
                        {actors > 0 && <span> · {actors} actors</span>}
                        {pages === 0 && iocs === 0 && actors === 0 && <span className="text-muted-foreground">—</span>}
                      </td>
                      <td className="px-4 py-3">
                        {riskSignals > 0 ? (
                          <span className="text-xs">
                            {sanctioned > 0 && <Badge variant="destructive" className="text-[9px] mr-1">{sanctioned} sanctioned</Badge>}
                            {leakedIPs > 0 && <Badge variant="secondary" className="text-[9px]">{leakedIPs} origin-IP</Badge>}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>
                      <td className={`px-4 py-3 text-sm font-semibold ${confColor}`}>
                        {confLabel}
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {formatRelative(inv.updated_at)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
                            title="Export this investigation"
                            onClick={() => setExportModalState({ open: true, ids: [inv.id], title: `Export Case ${inv.id.slice(0, 12)}` })}
                          >
                            <ScrollIcon className="h-3.5 w-3.5" />
                          </Button>
                          <a href={`/investigations/${inv.id}`}>
                            <Button size="sm" variant="ghost" className="h-7 px-2 text-xs">
                              <ArrowRightIcon className="h-3.5 w-3.5" />
                            </Button>
                          </a>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>

      {exportModalState.open && (
        <ExportModal
          investigationIds={exportModalState.ids}
          title={exportModalState.title}
          onClose={() => setExportModalState({ open: false, ids: [] })}
        />
      )}
    </AppShell>
  );
}

function formatRelative(date: string): string {
  const now = Date.now();
  const then = new Date(date).getTime();
  const diff = now - then;
  const minutes = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days = Math.floor(diff / 86400000);
  
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes} min ago`;
  if (hours < 24) return `${hours} hr ago`;
  if (days < 7) return `${days} day${days > 1 ? "s" : ""} ago`;
  return new Date(date).toLocaleDateString();
}
