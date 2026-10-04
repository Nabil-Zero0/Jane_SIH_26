"use client";

import { useEffect, useRef, useState, useMemo } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import mermaid from "mermaid";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ExportModal } from "@/components/export-modal";
import {
  CheckCircle2Icon,
  CircleDotIcon,
  CircleIcon,
  AlertCircleIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  NetworkIcon,
  ServerCrashIcon,
  UsersIcon,
  ShoppingBagIcon,
  KeyIcon,
  GlobeIcon,
  CopyIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  ArrowRightIcon,
  ActivityIcon,
  FlaskConicalIcon,
  SearchIcon,
  XIcon,
  CheckIcon,
  ClockIcon,
} from "@/components/icons";

const STAGES = [
  "SCOUT",
  "WHONIX_INGEST",
  "EXTRACTOR",
  "LOCKSMITH",
  "STYLOMETRY",
  "OPENCODE_AI",
  "GRAPH",
  "COMPLETED",
] as const;

type StageState = "pending" | "active" | "done" | "error";

function StepIcon({ state }: { state: StageState }) {
  if (state === "done") return <CheckCircle2Icon className="h-4 w-4 text-foreground/80" />;
  if (state === "active") return <CircleDotIcon className="h-4 w-4 text-foreground animate-pulse" />;
  if (state === "error") return <AlertCircleIcon className="h-4 w-4 text-zinc-400" />;
  return <CircleIcon className="h-4 w-4 text-muted-foreground/40" />;
}

export default function InvestigationDetailPage() {
  const params = useParams();
  const id = params.id as string;

  const [data, setData] = useState<any>(null);
  const [intel, setIntel] = useState<any>(null);
  const [logs, setLogs] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  // In-case modal / drawer states (zero context loss)
  const [selectedActor, setSelectedActor] = useState<any | null>(null);
  const [actorDrawerTab, setActorDrawerTab] = useState<"identity" | "contacts" | "markets" | "relationships" | "attribution" | "opsec">("identity");
  const [evidenceQuoteModal, setEvidenceQuoteModal] = useState<{ title: string; quote: string; context?: string } | null>(null);
  const [snapshotModalUrl, setSnapshotModalUrl] = useState<string | null>(null);
  const [snapshotHtml, setSnapshotHtml] = useState<string>("");
  const [snapshotLoading, setSnapshotLoading] = useState(false);
  const [exportModalOpen, setExportModalOpen] = useState(false);
  const [pipelineOpen, setPipelineOpen] = useState(false);
  const [logsOpen, setLogsOpen] = useState(false);
  const [evidenceTab, setEvidenceTab] = useState<"sources" | "priority_queue" | "indicators">("priority_queue");
  const [indicatorFilter, setIndicatorFilter] = useState("");
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [miniGraphSvg, setMiniGraphSvg] = useState<string>("");

  const logRef = useRef<HTMLDivElement>(null);

  // Concurrent fetch: core summary + deep intelligence
  useEffect(() => {
    Promise.all([
      fetch(`/api/investigation?id=${id}`).then((r) => r.json()),
      fetch(`/api/investigation/intelligence?id=${id}`).then((r) => r.json()).catch(() => ({})),
    ])
      .then(([invData, intelData]) => {
        setData(invData);
        setIntel(intelData);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Failed to load investigation data:", err);
        setLoading(false);
      });
  }, [id]);

  // Live SSE pipeline events
  useEffect(() => {
    const es = new EventSource(`/api/events?id=${id}`);
    es.onmessage = (e) => {
      try {
        const payload = JSON.parse(e.data);
        if (payload.log) setLogs((prev) => [...prev, payload.log]);
        if (payload.status) es.close();
      } catch {
        /* ignore parse error */
      }
    };
    return () => es.close();
  }, [id]);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  // Fetch defanged DOM snapshot when requested
  useEffect(() => {
    if (!snapshotModalUrl) {
      setSnapshotHtml("");
      return;
    }
    setSnapshotLoading(true);
    fetch(`/api/snapshot?url=${encodeURIComponent(snapshotModalUrl)}`)
      .then((r) => r.text())
      .then((html) => {
        setSnapshotHtml(html);
        setSnapshotLoading(false);
      })
      .catch(() => {
        setSnapshotHtml("<div style='color:#a1a1aa;padding:24px;font-family:monospace;font-size:12px;'>Preserved forensic snapshot unavailable for this endpoint.</div>");
        setSnapshotLoading(false);
      });
  }, [snapshotModalUrl]);

  // Render Mini Mermaid Graph Preview
  useEffect(() => {
    if (!data) return;
    const mmdCode = data.mermaid || (data.graph_elements?.nodes?.length > 0
      ? `graph LR\n${data.graph_elements.nodes.slice(0, 12).map((n: any) => `  ${n.data.id.replace(/[^a-zA-Z0-9_]/g, "_")}["${(n.data.label || n.data.id).replace(/"/g, "")}"]`).join("\n")}\n${(data.graph_elements.edges || []).slice(0, 15).map((e: any) => `  ${e.data.source.replace(/[^a-zA-Z0-9_]/g, "_")} -->|"${e.data.edge_type}"| ${e.data.target.replace(/[^a-zA-Z0-9_]/g, "_")}`).join("\n")}`
      : "graph LR\n  empty[\"Investigation Network Pending\"]");

    try {
      mermaid.initialize({
        startOnLoad: false,
        theme: "dark",
        themeVariables: {
          darkMode: true,
          background: "#09090b",
          primaryColor: "#27272a",
          primaryTextColor: "#f4f4f5",
          primaryBorderColor: "#3f3f46",
          lineColor: "#71717a",
          secondaryColor: "#18181b",
          tertiaryColor: "#18181b",
        },
        securityLevel: "loose",
      });
      mermaid.render(`mini-graph-${id.replace(/[^a-zA-Z0-9_]/g, "_")}`, mmdCode)
        .then(({ svg }) => setMiniGraphSvg(svg))
        .catch(() => setMiniGraphSvg(""));
    } catch {
      setMiniGraphSvg("");
    }
  }, [data, id]);

  const copyToClipboard = (txt: string) => {
    navigator.clipboard.writeText(txt);
    setCopiedText(txt);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Pipeline stage state
  const stageStates: Record<string, StageState> = {};
  STAGES.forEach((s) => { stageStates[s] = "pending"; });
  logs.forEach((log) => {
    const msg: string = (log.message || log.stage || "").toUpperCase();
    STAGES.forEach((s) => {
      if (msg.includes(s)) {
        const level = (log.level || "INFO").toUpperCase();
        stageStates[s] = level.includes("ERROR") ? "error" : level.includes("SUCCESS") || level.includes("DONE") ? "done" : "active";
      }
    });
  });

  // Consolidate Threat Actors for this investigation
  const actorsList = useMemo(() => {
    if (!data?.threat_actors && !intel?.actors) return [];
    const threatActors: any[] = data?.threat_actors || [];
    const canonicalActors: any[] = intel?.actors || [];
    const actorMap = new Map<string, any>();

    // Seed with per-investigation threat_actors
    threatActors.forEach((ta) => {
      const key = ta.primary_handle || ta.id;
      actorMap.set(key, {
        id: ta.id,
        primary_handle: ta.primary_handle,
        designated_id: ta.designated_id || `TA-${ta.primary_handle.slice(0, 6).toUpperCase()}`,
        threat_category: ta.threat_category || "Unclassified",
        confidence: ta.confidence ?? 1.0,
        attributed_onions: (ta.attributed_onions || "").split(",").filter(Boolean),
        stylometry_summary: ta.stylometry_summary,
        graph_node_id: ta.graph_node_id,
        first_seen: ta.created_at,
        last_seen: ta.created_at,
      });
    });

    // Merge with canonical actors from intelligence
    canonicalActors.forEach((ca) => {
      const key = ca.primary_handle || ca.id;
      const existing = actorMap.get(key) || {};
      actorMap.set(key, {
        ...existing,
        id: existing.id || ca.id,
        primary_handle: ca.primary_handle || existing.primary_handle,
        designated_id: existing.designated_id || ca.id,
        threat_category: ca.category || existing.threat_category || "Unclassified",
        confidence: ca.attribution_confidence ?? existing.confidence ?? 1.0,
        first_seen: ca.first_seen || existing.first_seen,
        last_seen: ca.last_seen || existing.last_seen,
        canonical_actor_id: ca.id,
      });
    });

    return Array.from(actorMap.values());
  }, [data?.threat_actors, intel?.actors]);

  // Consolidate Actor-to-Actor and Actor-to-Entity Relationships in this investigation
  const investigationRelationships = useMemo(() => {
    const rawEdges: any[] = data?.graph_elements?.edges || [];
    const trustEdges: any[] = intel?.actor_trust || [];
    const rels: any[] = [];

    rawEdges.forEach((e) => {
      const ed = e.data || e;
      rels.push({
        id: ed.id || `${ed.source}-${ed.edge_type}-${ed.target}`,
        source: ed.source,
        target: ed.target,
        edge_type: ed.edge_type || "RELATED_TO",
        confidence: ed.confidence ?? 1.0,
        evidence_quote: ed.evidence_quote || "",
        basis: ed.basis || "Graph link",
      });
    });

    trustEdges.forEach((t) => {
      rels.push({
        id: `trust-${t.actor_id}-${t.trusted_actor_id}`,
        source: t.actor_id,
        target: t.trusted_actor_id,
        edge_type: "TRUSTS",
        confidence: t.confidence ?? 1.0,
        evidence_quote: t.evidence_quote || "Mutual counterparty trust relation identified.",
        basis: "Darknet escrow / peer trust record",
      });
    });

    return rels;
  }, [data?.graph_elements?.edges, intel?.actor_trust]);

  if (loading) {
    return (
      <AppShell>
        <div className="flex h-96 items-center justify-center">
          <div className="space-y-3 text-center">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-foreground border-t-transparent mx-auto" />
            <p className="text-xs font-mono text-muted-foreground tracking-wide">HYDRATING INVESTIGATION WORKSPACE...</p>
          </div>
        </div>
      </AppShell>
    );
  }

  if (!data || !data.investigation) {
    return (
      <AppShell>
        <div className="p-12 text-center text-zinc-400">
          <AlertCircleIcon className="h-8 w-8 mx-auto mb-3 text-zinc-500" />
          <h2 className="text-sm font-semibold tracking-tight text-foreground uppercase font-mono">Investigation Not Found</h2>
          <p className="text-xs text-muted-foreground mt-1 font-mono">ID: {id}</p>
        </div>
      </AppShell>
    );
  }

  const inv = data.investigation;
  const pages: any[] = data.pages || [];
  const idents: any[] = data.identifiers || [];
  const commodities: any[] = intel?.commodities || [];
  const products: any[] = intel?.products || [];
  const marketplaces: any[] = intel?.marketplaces || [];
  const opsecFindings: any[] = intel?.opsec || [];
  const stylometryFindings: any[] = intel?.stylometry || [];
  const osintTargets: any[] = intel?.osint_targets || [];
  const osintResults: any[] = intel?.osint_results || [];
  const clearnetAccounts: any[] = intel?.clearnet_accounts || [];
  const attributionAssessments: any[] = intel?.attribution_assessments || [];
  const intelligenceGaps: any[] = intel?.intelligence_gaps || [];

  // Key KPI metrics
  const evidenceBackedIOCs = idents.filter((i) => i.evidence_quote).length;
  const highConfLinks = investigationRelationships.filter((r) => r.confidence >= 0.8).length;
  const originIPCount = idents.filter((i) => i.type?.includes("IP") || i.type?.includes("LEAKED")).length;
  const priorityAlerts = idents.filter((i) => i.is_sanctioned || (i.confidence ?? 0) >= 0.9).length;

  const isCompleted = inv.status === "COMPLETED";

  // Filtered indicators
  const filteredIdents = idents.filter((i) => {
    if (!indicatorFilter) return true;
    const q = indicatorFilter.toLowerCase();
    return (
      i.value?.toLowerCase().includes(q) ||
      i.type?.toLowerCase().includes(q) ||
      i.evidence_quote?.toLowerCase().includes(q)
    );
  });

  return (
    <AppShell>
      <div className="space-y-6 w-full min-w-0 max-w-full font-sans">
        {/* ==================================================================== */}
        {/* CASE HEADER & CONTEXT                                                */}
        {/* ==================================================================== */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">Case Workspace</span>
              <span className="text-muted-foreground/50 text-xs">/</span>
              <span className="font-mono text-[11px] text-foreground font-medium">{inv.id}</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground">{inv.query}</h1>
            <div className="text-xs text-muted-foreground mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono">
              <span>{pages.length} sources crawled</span>
              <span className="text-muted-foreground/30">•</span>
              <span className="text-foreground">{actorsList.length} threat personas</span>
              <span className="text-muted-foreground/30">•</span>
              <span>{idents.length} extracted indicators</span>
              <span className="text-muted-foreground/30">•</span>
              <span>{marketplaces.length} marketplaces</span>
              <span className="text-muted-foreground/30">•</span>
              <span>{commodities.length + products.length} contraband items</span>
            </div>
          </div>

          <div className="flex gap-2 items-center flex-wrap">
            <span className="inline-flex items-center px-2.5 py-1 rounded border border-border/60 bg-muted/20 text-[11px] font-mono uppercase tracking-wider text-foreground">
              {inv.status}
            </span>
            <Link href={`/graph/${id}`}>
              <Button size="sm" variant="outline" className="gap-1.5 border-border/80 text-foreground hover:bg-muted/40 font-mono text-xs">
                <NetworkIcon className="h-3.5 w-3.5 text-muted-foreground" />
                Full Threat Graph
              </Button>
            </Link>
            <Button size="sm" className="bg-foreground text-background hover:bg-foreground/90 font-mono text-xs" onClick={() => setExportModalOpen(true)}>
              Export Dossier
            </Button>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* CASE KPI METRICS (CLEAN MONOCHROME BENTO)                             */}
        {/* ==================================================================== */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Evidence IOCs</span>
              <ShieldCheckIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{evidenceBackedIOCs}</div>
            <div className="text-[10px] text-muted-foreground/80 mt-1 truncate">Corroborated by quote</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Personas</span>
              <UsersIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{actorsList.length}</div>
            <div className="text-[10px] text-muted-foreground/80 mt-1 truncate">Threat actors cataloged</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Contraband</span>
              <ShoppingBagIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{marketplaces.length + commodities.length}</div>
            <div className="text-[10px] text-muted-foreground/80 mt-1 truncate">Markets & Commodities</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Relations</span>
              <NetworkIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{highConfLinks}</div>
            <div className="text-[10px] text-muted-foreground/80 mt-1 truncate">High-confidence links</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Clearnet Leaks</span>
              <ServerCrashIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{originIPCount}</div>
            <div className="text-[10px] text-muted-foreground/80 mt-1 truncate">Exposed origin endpoints</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Alerts</span>
              <ShieldAlertIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{priorityAlerts}</div>
            <div className="text-[10px] text-muted-foreground/80 mt-1 truncate">High priority / sanctions</div>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* SECTION 2: THREAT ACTORS IDENTIFIED IN THIS CASE                     */}
        {/* ==================================================================== */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader className="pb-3 border-b border-border/40">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <UsersIcon className="h-4 w-4 text-muted-foreground" />
                  Identified Threat Actors ({actorsList.length})
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground mt-0.5">
                  Operative personas, market operators, and vendors attributed in this investigation. Click an actor to inspect in-case dossier.
                </CardDescription>
              </div>
              <span className="text-[11px] font-mono text-muted-foreground">
                Canonical deduplication active
              </span>
            </div>
          </CardHeader>
          <CardContent className="pt-4">
            {actorsList.length === 0 ? (
              <div className="py-8 text-center text-muted-foreground text-xs font-mono">
                No threat actor personas attributed in this investigation yet.
              </div>
            ) : (
              <div className="grid gap-3.5 md:grid-cols-2 lg:grid-cols-3">
                {actorsList.map((actor) => {
                  const confPct = Math.round((actor.confidence ?? 1.0) * 100);
                  const actorAliases = (intel?.aliases || []).filter((a: any) => a.actor_id === actor.id);
                  const actorMarkets = marketplaces.filter((m) => m.actor_id === actor.id);
                  const actorProds = products.filter((p) => p.actor_id === actor.id);
                  const actorComms = commodities.filter((c) => c.actor_handle === actor.primary_handle);
                  const actorIdents = idents.filter((i) => i.actor_id === actor.id);
                  const actorClearnet = clearnetAccounts.filter((ca) => ca.actor_id === actor.id);
                  const actorAssessments = attributionAssessments.filter((aa) => aa.actor_id === actor.id);
                  const actorOpsec = opsecFindings.filter((o) => o.actor_id === actor.id);

                  return (
                    <div
                      key={actor.id}
                      className="rounded-xl border border-border/60 bg-zinc-950/40 p-4 hover:border-zinc-700 transition-colors cursor-pointer flex flex-col justify-between space-y-3 group"
                      onClick={() => {
                        setSelectedActor(actor);
                        setActorDrawerTab("identity");
                      }}
                    >
                      <div>
                        <div className="flex items-start justify-between gap-2">
                          <div>
                            <span className="font-mono text-[10px] text-muted-foreground block tracking-wider">{actor.designated_id}</span>
                            <span className="text-base font-semibold font-mono text-foreground group-hover:text-zinc-200 transition-colors">
                              {actor.primary_handle}
                            </span>
                          </div>
                          <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] font-mono uppercase text-muted-foreground">
                            {actor.threat_category}
                          </span>
                        </div>

                        {/* Attribution Confidence */}
                        <div className="mt-3 space-y-1">
                          <div className="flex justify-between text-[11px] font-mono">
                            <span className="text-muted-foreground text-[10px] uppercase">Confidence</span>
                            <span className="font-semibold tabular-nums text-foreground">{confPct}%</span>
                          </div>
                          <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-foreground/80 transition-all duration-300"
                              style={{ width: `${confPct}%` }}
                            />
                          </div>
                        </div>

                        {/* Intelligence Counts */}
                        <div className="mt-3 flex flex-wrap gap-1.5">
                          {actorAliases.length > 0 && (
                            <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                              {actorAliases.length} alias{actorAliases.length !== 1 ? "es" : ""}
                            </span>
                          )}
                          <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                            {actorIdents.length} darknet IOC{actorIdents.length !== 1 ? "s" : ""}
                          </span>
                          {actorClearnet.length > 0 && (
                            <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">
                              {actorClearnet.length} OSINT lead{actorClearnet.length !== 1 ? "s" : ""}
                            </span>
                          )}
                          {(actorMarkets.length > 0 || actorProds.length > 0 || actorComms.length > 0) && (
                            <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">
                              {actorMarkets.length} market / {actorProds.length + actorComms.length} items
                            </span>
                          )}
                          {actorOpsec.length > 0 && (
                            <span className="rounded border border-zinc-800 bg-zinc-900/80 px-1.5 py-0.5 text-[10px] font-mono text-zinc-200">
                              {actorOpsec.length} OpSec leak{actorOpsec.length !== 1 ? "s" : ""}
                            </span>
                          )}
                        </div>

                        {/* Primary Assessment Quote if present */}
                        {actorAssessments[0]?.assessment && (
                          <p className="mt-2.5 text-[11px] text-muted-foreground line-clamp-2 italic border-l-2 border-border/60 pl-2">
                            "{actorAssessments[0].assessment}"
                          </p>
                        )}
                      </div>

                      <div className="pt-2.5 border-t border-border/40 flex items-center justify-between">
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-6 px-2 text-xs text-foreground font-mono gap-1 hover:bg-muted/30"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedActor(actor);
                            setActorDrawerTab("identity");
                          }}
                        >
                          Inspect Dossier
                          <ArrowRightIcon className="h-3 w-3 text-muted-foreground" />
                        </Button>
                        <a
                          href={`/actors/${actor.id}`}
                          onClick={(e) => e.stopPropagation()}
                          className="text-[10px] font-mono text-muted-foreground hover:text-foreground underline decoration-border"
                          title="Open cross-investigation global dossier"
                        >
                          Global Dossier ↗
                        </a>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* ==================================================================== */}
        {/* SECTION 3: ACTOR RELATIONSHIPS & MINI GRAPH PREVIEW                  */}
        {/* ==================================================================== */}
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Investigation-Scoped Relationships Table */}
          <Card className="border-border/60 bg-card/60 flex flex-col justify-between">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <NetworkIcon className="h-4 w-4 text-muted-foreground" />
                Investigation Relationships ({investigationRelationships.length})
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Attributed connections between case entities (escrow trust, vendor operations, shared identifiers).
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0 flex-1">
              <div className="max-h-72 overflow-auto">
                {investigationRelationships.length === 0 ? (
                  <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                    No explicit inter-entity relationship edges registered for this case.
                  </div>
                ) : (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                      <tr className="text-left">
                        <th className="px-3.5 py-2.5">Source Entity</th>
                        <th className="px-3.5 py-2.5">Relation</th>
                        <th className="px-3.5 py-2.5">Target Entity</th>
                        <th className="px-3.5 py-2.5 text-right">Confidence</th>
                        <th className="px-3.5 py-2.5 text-center">Quote</th>
                      </tr>
                    </thead>
                    <tbody>
                      {investigationRelationships.slice(0, 20).map((rel) => (
                        <tr key={rel.id} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                          <td className="px-3.5 py-2 font-mono text-[11px] font-medium text-foreground truncate max-w-[130px]">
                            {rel.source}
                          </td>
                          <td className="px-3.5 py-2">
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                              {rel.edge_type}
                            </span>
                          </td>
                          <td className="px-3.5 py-2 font-mono text-[11px] text-muted-foreground truncate max-w-[130px]">
                            {rel.target}
                          </td>
                          <td className="px-3.5 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                            {Math.round(rel.confidence * 100)}%
                          </td>
                          <td className="px-3.5 py-2 text-center">
                            {rel.evidence_quote ? (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                                onClick={() =>
                                  setEvidenceQuoteModal({
                                    title: `${rel.source} ➔ ${rel.target} (${rel.edge_type})`,
                                    quote: rel.evidence_quote,
                                    context: rel.basis,
                                  })
                                }
                              >
                                View
                              </Button>
                            ) : (
                              <span className="text-muted-foreground text-[10px]">—</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Mini Investigation Graph Preview */}
          <Card className="border-border/60 bg-card/60 flex flex-col justify-between">
            <CardHeader className="pb-2 border-b border-border/40">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                    <NetworkIcon className="h-4 w-4 text-muted-foreground" />
                    Case Network Topology Preview
                  </CardTitle>
                  <CardDescription className="text-xs text-muted-foreground">
                    Entities and pivots connected within this investigation scope.
                  </CardDescription>
                </div>
                <Link href={`/graph/${id}`}>
                  <Button size="sm" variant="outline" className="h-6 px-2 text-[10px] font-mono border-border/60 text-foreground hover:bg-muted/30">
                    Open Full Graph →
                  </Button>
                </Link>
              </div>
            </CardHeader>
            <CardContent className="pt-3 pb-3 flex-1 flex flex-col justify-center items-center overflow-hidden">
              {miniGraphSvg ? (
                <div
                  className="w-full max-h-64 overflow-auto flex justify-center [&>svg]:max-w-full [&>svg]:h-auto"
                  dangerouslySetInnerHTML={{ __html: miniGraphSvg }}
                />
              ) : (
                <div className="text-center py-10 space-y-2">
                  <NetworkIcon className="h-8 w-8 mx-auto text-muted-foreground/40" />
                  <p className="text-xs font-mono text-muted-foreground">Network topology rendering...</p>
                  <Link href={`/graph/${id}`}>
                    <Button size="sm" variant="outline" className="text-xs font-mono">
                      Explore in Graph Studio
                    </Button>
                  </Link>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* ==================================================================== */}
        {/* SECTION 4: CONTRABAND PRODUCTS & MARKETPLACES                        */}
        {/* ==================================================================== */}
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Extracted Contraband Products */}
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <ShoppingBagIcon className="h-4 w-4 text-muted-foreground" />
                Contraband & Product Listings ({commodities.length + products.length})
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Extracted darknet commodities, pricing quotes, and vendor associations.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="max-h-60 overflow-auto">
                {commodities.length + products.length === 0 ? (
                  <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                    No contraband listings identified for this case.
                  </div>
                ) : (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                      <tr className="text-left">
                        <th className="px-3.5 py-2.5">Product</th>
                        <th className="px-3.5 py-2.5">Category</th>
                        <th className="px-3.5 py-2.5">Vendor / Market</th>
                        <th className="px-3.5 py-2.5 text-center">Quote</th>
                      </tr>
                    </thead>
                    <tbody>
                      {commodities.concat(products).slice(0, 15).map((item, idx) => {
                        const name = item.name || item.value || "Unlabeled Listing";
                        const cat = item.category || item.type || "Contraband";
                        const vendor = item.actor_handle || item.marketplace_name || "Unassigned";
                        const quote = item.evidence_quote || item.relation_evidence || "";

                        return (
                          <tr key={item.id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                            <td className="px-3.5 py-2 font-medium text-foreground truncate max-w-[180px]">
                              {name}
                            </td>
                            <td className="px-3.5 py-2">
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                {cat}
                              </span>
                            </td>
                            <td className="px-3.5 py-2 font-mono text-[11px] text-muted-foreground truncate max-w-[120px]">
                              {vendor}
                            </td>
                            <td className="px-3.5 py-2 text-center">
                              {quote ? (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                                  onClick={() =>
                                    setEvidenceQuoteModal({
                                      title: name,
                                      quote: quote,
                                      context: `Category: ${cat} | Vendor: ${vendor}`,
                                    })
                                  }
                                >
                                  View
                                </Button>
                              ) : (
                                <span className="text-muted-foreground text-[10px]">—</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Discovered Darknet Marketplaces */}
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <GlobeIcon className="h-4 w-4 text-muted-foreground" />
                Marketplace & Infrastructure Domains ({marketplaces.length})
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Identified storefront domains, syndicate mirrors, and associated operators.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="max-h-60 overflow-auto">
                {marketplaces.length === 0 ? (
                  <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                    No structured marketplace associations recorded for this case.
                  </div>
                ) : (
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                      <tr className="text-left">
                        <th className="px-3.5 py-2.5">Marketplace</th>
                        <th className="px-3.5 py-2.5">Domain</th>
                        <th className="px-3.5 py-2.5">Category</th>
                        <th className="px-3.5 py-2.5 text-center">Snapshot</th>
                      </tr>
                    </thead>
                    <tbody>
                      {marketplaces.map((m) => (
                        <tr key={m.id} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                          <td className="px-3.5 py-2 font-medium text-foreground">
                            {m.display_name || m.onion_domain}
                          </td>
                          <td className="px-3.5 py-2 font-mono text-[10px] text-foreground/80 truncate max-w-[180px]">
                            {m.onion_domain}
                          </td>
                          <td className="px-3.5 py-2">
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                              {m.category || "Darknet Market"}
                            </span>
                          </td>
                          <td className="px-3.5 py-2 text-center">
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                              onClick={() => setSnapshotModalUrl(m.onion_domain)}
                            >
                              Inspect
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ==================================================================== */}
        {/* SECTION 5: OPSEC & STYLOMETRY SIGNALS                                */}
        {/* ==================================================================== */}
        <div className="grid gap-4 lg:grid-cols-2">
          {/* OpSec Vulnerabilities & Mistakes */}
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <ServerCrashIcon className="h-4 w-4 text-muted-foreground" />
                OpSec Findings & Operational Leaks ({opsecFindings.length})
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Exposed clearweb handles, unencrypted cleartext, or infrastructure flaws recorded by OpenCode.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-3.5">
              <div className="space-y-2.5 max-h-56 overflow-y-auto">
                {opsecFindings.length === 0 ? (
                  <div className="py-6 text-center text-xs font-mono text-muted-foreground">
                    No OpSec vulnerabilities flagged for this investigation.
                  </div>
                ) : (
                  opsecFindings.map((op, idx) => (
                    <div key={op.id || idx} className="rounded-lg border border-border/60 bg-zinc-950/40 p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                          {op.finding_type || "OpSec Leak"}
                        </span>
                        <span className="text-[10px] font-mono text-muted-foreground">
                          Actor: {op.actor_id || "Unassigned"}
                        </span>
                      </div>
                      <p className="text-xs text-foreground font-medium">{op.description}</p>
                      {op.evidence_quote && (
                        <blockquote className="text-[10px] italic text-muted-foreground border-l-2 border-border/80 pl-2">
                          "{op.evidence_quote}"
                        </blockquote>
                      )}
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* Stylometric Profiling Signals */}
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <FlaskConicalIcon className="h-4 w-4 text-muted-foreground" />
                Stylometric Divergence & Author Clues ({stylometryFindings.length})
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Linguistic habits, function word markers, and vocabulary richness (Supporting evidence, not proof of identity).
              </CardDescription>
            </CardHeader>
            <CardContent className="p-3.5">
              <div className="space-y-2.5 max-h-56 overflow-y-auto">
                {stylometryFindings.length === 0 ? (
                  <div className="py-6 text-center text-xs font-mono text-muted-foreground">
                    No stylometric discrepancy findings recorded for this case.
                  </div>
                ) : (
                  stylometryFindings.map((sty, idx) => (
                    <div key={sty.id || idx} className="rounded-lg border border-border/60 bg-zinc-950/40 p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                          {sty.assessment || "Linguistic Marker"}
                        </span>
                        {sty.similarity_score != null && (
                          <span className="text-[10px] font-mono text-foreground font-semibold">
                            Δ Similarity: {Math.round(sty.similarity_score * 100)}%
                          </span>
                        )}
                      </div>
                      <p className="text-xs text-foreground/90">{sty.details || sty.assessment}</p>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ==================================================================== */}
        {/* SECTION 6: OSINT CLEARNET PIVOTS & CANDIDATE MATCHES                 */}
        {/* ==================================================================== */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader className="pb-3 border-b border-border/40">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <GlobeIcon className="h-4 w-4 text-muted-foreground" />
                  OSINT Clearweb Pivots & Candidate Profiles ({osintTargets.length + clearnetAccounts.length})
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground">
                  Automated clearweb correlation results from Maigret and identity pivoting. (Candidate matches require secondary verification).
                </CardDescription>
              </div>
              <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                Passive Defensive Posture
              </span>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="max-h-60 overflow-auto">
              {osintTargets.length === 0 && clearnetAccounts.length === 0 ? (
                <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                  No clearweb OSINT targets queued or discovered for this case.
                </div>
              ) : (
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                    <tr className="text-left">
                      <th className="px-3.5 py-2.5">Identifier / Query</th>
                      <th className="px-3.5 py-2.5">Target Role</th>
                      <th className="px-3.5 py-2.5">Platform Discovery</th>
                      <th className="px-3.5 py-2.5">Match Status</th>
                      <th className="px-3.5 py-2.5 text-right">Confidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {osintTargets.map((ot) => {
                      const result = osintResults.find((r) => r.target_id === ot.id);
                      return (
                        <tr key={ot.id} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                          <td className="px-3.5 py-2 font-mono text-[11px] font-medium text-foreground">
                            {ot.identifier}
                          </td>
                          <td className="px-3.5 py-2 text-muted-foreground font-mono text-[10px]">
                            {ot.target_role || "Vendor Handle"}
                          </td>
                          <td className="px-3.5 py-2">
                            {result?.platform ? (
                              <div className="flex items-center gap-1.5 font-mono text-[11px]">
                                <span className="font-semibold text-foreground">{result.platform}</span>
                                {result.url && (
                                  <a href={result.url} target="_blank" rel="noreferrer" className="text-[10px] text-muted-foreground hover:text-foreground underline">
                                    [profile ↗]
                                  </a>
                                )}
                              </div>
                            ) : (
                              <span className="text-muted-foreground text-[10px] font-mono">Searching...</span>
                            )}
                          </td>
                          <td className="px-3.5 py-2">
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                              {result?.status === "FOUND" ? "Candidate Match" : result?.status || "Pending"}
                            </span>
                          </td>
                          <td className="px-3.5 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                            {Math.round((ot.confidence ?? 0.8) * 100)}%
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </CardContent>
        </Card>

        {/* ==================================================================== */}
        {/* SECTION 7: ATTRIBUTION ASSESSMENTS & INTELLIGENCE GAPS               */}
        {/* ==================================================================== */}
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Attribution Assessments */}
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <ShieldCheckIcon className="h-4 w-4 text-muted-foreground" />
                Attribution Assessments & Evidence Rationale ({attributionAssessments.length})
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Structured assessments, supporting citations, and contradicting evidence evaluation.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-3.5">
              <div className="space-y-3 max-h-56 overflow-y-auto">
                {attributionAssessments.length === 0 ? (
                  <div className="py-6 text-center text-xs font-mono text-muted-foreground">
                    No structured attribution assessments filed for this investigation.
                  </div>
                ) : (
                  attributionAssessments.map((aa, idx) => (
                    <div key={aa.id || idx} className="rounded-lg border border-border/60 bg-zinc-950/40 p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-[11px] font-semibold text-foreground">
                          Actor: {aa.actor_id || "Lead Persona"}
                        </span>
                        <span className="text-[10px] font-mono text-muted-foreground">
                          Confidence: {Math.round((aa.confidence ?? 1.0) * 100)}%
                        </span>
                      </div>
                      <p className="text-xs text-foreground leading-relaxed">{aa.assessment}</p>
                      {aa.supporting_evidence && (
                        <div className="text-[10px] text-foreground/90 bg-muted/20 rounded p-1.5 border border-border/40 font-mono">
                          <strong>Supporting:</strong> {aa.supporting_evidence}
                        </div>
                      )}
                      {aa.contradicting_evidence && (
                        <div className="text-[10px] text-muted-foreground bg-muted/10 rounded p-1.5 border border-border/30 font-mono">
                          <strong>Contradicting:</strong> {aa.contradicting_evidence}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>

          {/* Intelligence Gaps & Uncertainties */}
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <AlertCircleIcon className="h-4 w-4 text-muted-foreground" />
                Intelligence Gaps & Collection Priorities ({intelligenceGaps.length})
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Unresolved analytical uncertainties and recommended follow-up collection actions.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-3.5">
              <div className="space-y-2.5 max-h-56 overflow-y-auto">
                {intelligenceGaps.length === 0 ? (
                  <div className="py-6 text-center text-xs font-mono text-muted-foreground">
                    No explicit intelligence gaps logged for this investigation.
                  </div>
                ) : (
                  intelligenceGaps.map((gap, idx) => (
                    <div key={gap.id || idx} className="rounded-lg border border-border/60 bg-zinc-950/40 p-3 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                          {gap.gap_type || "Information Gap"}
                        </span>
                        <span className="text-[10px] font-mono text-muted-foreground">
                          Priority: {gap.priority || "Normal"}
                        </span>
                      </div>
                      <p className="text-xs text-foreground/90 font-medium">{gap.description}</p>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* ==================================================================== */}
        {/* SECTION 8: SOURCE EVIDENCE & PRIORITY QUEUE TABS                     */}
        {/* ==================================================================== */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader className="pb-2.5 border-b border-border/40">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                {(["priority_queue", "sources", "indicators"] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setEvidenceTab(tab)}
                    className={`rounded-md px-3 py-1.5 text-xs font-mono tracking-wide transition ${
                      evidenceTab === tab
                        ? "bg-foreground text-background font-semibold"
                        : "bg-muted/20 text-muted-foreground hover:bg-muted/40 hover:text-foreground"
                    }`}
                  >
                    {tab === "priority_queue" && `Evidence Priority Queue (${idents.filter((i) => i.evidence_quote).length})`}
                    {tab === "sources" && `Captured Onion Sources (${pages.length})`}
                    {tab === "indicators" && `All Extracted IOCs (${idents.length})`}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-1.5">
                <SearchIcon className="h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Filter indicators, quotes..."
                  value={indicatorFilter}
                  onChange={(e) => setIndicatorFilter(e.target.value)}
                  className="h-7 w-48 text-xs font-mono bg-zinc-950 border-border/60"
                />
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {/* TAB 1: Evidence Priority Queue */}
            {evidenceTab === "priority_queue" && (
              <div className="max-h-96 overflow-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                    <tr className="text-left">
                      <th className="px-4 py-2.5">Priority</th>
                      <th className="px-4 py-2.5">Indicator</th>
                      <th className="px-4 py-2.5">Type</th>
                      <th className="px-4 py-2.5">Why It Matters</th>
                      <th className="px-4 py-2.5 text-right">Confidence</th>
                      <th className="px-4 py-2.5 text-center">Verbatim Quote</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIdents.filter((i) => i.evidence_quote).slice(0, 30).map((i) => {
                      const conf = i.confidence ?? 0;
                      const priority = i.is_sanctioned ? "Critical" : conf >= 0.8 ? "High" : conf >= 0.5 ? "Medium" : "Review";
                      const reason = i.is_sanctioned
                        ? "Designated sanctioned asset"
                        : i.type?.includes("IP")
                        ? "Origin clearweb leak candidate"
                        : (i.occurrence_count ?? 1) > 1
                        ? `Shared across ${i.occurrence_count} hidden services`
                        : "Single occurrence lead";

                      return (
                        <tr key={i.id} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                          <td className="px-4 py-2">
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono uppercase text-foreground">
                              {priority}
                            </span>
                          </td>
                          <td className="px-4 py-2 font-mono text-[11px] text-foreground truncate max-w-[220px]">
                            {i.value}
                          </td>
                          <td className="px-4 py-2">
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                              {i.type}
                            </span>
                          </td>
                          <td className="px-4 py-2 text-muted-foreground font-mono text-[11px]">{reason}</td>
                          <td className="px-4 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                            {Math.round(conf * 100)}%
                          </td>
                          <td className="px-4 py-2 text-center">
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-6 px-2 text-xs font-mono text-foreground hover:bg-muted/40"
                              onClick={() =>
                                setEvidenceQuoteModal({
                                  title: `${i.type}: ${i.value}`,
                                  quote: i.evidence_quote,
                                  context: `Confidence: ${Math.round(conf * 100)}% | Sanctioned: ${i.is_sanctioned ? "YES" : "NO"}`,
                                })
                              }
                            >
                              Inspect Quote
                            </Button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* TAB 2: Captured Onion Sources */}
            {evidenceTab === "sources" && (
              <div className="max-h-96 overflow-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                    <tr className="text-left">
                      <th className="px-4 py-2.5">Source Onion</th>
                      <th className="px-4 py-2.5">Title</th>
                      <th className="px-4 py-2.5">Server Banner</th>
                      <th className="px-4 py-2.5">Captured Time</th>
                      <th className="px-4 py-2.5 text-center">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pages.map((p) => (
                      <tr key={p.id} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                        <td className="px-4 py-2 font-mono text-[10px] text-foreground/80 truncate max-w-[260px]">
                          {p.url}
                        </td>
                        <td className="px-4 py-2 text-foreground truncate max-w-[200px]">
                          {p.title || "—"}
                        </td>
                        <td className="px-4 py-2 font-mono text-[10px] text-muted-foreground">
                          {p.server_banner || "—"}
                        </td>
                        <td className="px-4 py-2 text-muted-foreground text-[11px] font-mono">
                          {new Date(p.created_at).toLocaleString()}
                        </td>
                        <td className="px-4 py-2 text-center">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-6 px-2 text-[10px] font-mono border-border/60 text-foreground hover:bg-muted/30"
                            onClick={() => setSnapshotModalUrl(p.url)}
                          >
                            Inspect Snapshot
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* TAB 3: All Extracted Indicators */}
            {evidenceTab === "indicators" && (
              <div className="max-h-96 overflow-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                    <tr className="text-left">
                      <th className="px-4 py-2.5">Type</th>
                      <th className="px-4 py-2.5">Value</th>
                      <th className="px-4 py-2.5 text-right">Confidence</th>
                      <th className="px-4 py-2.5 text-right">Occurrences</th>
                      <th className="px-4 py-2.5">Status</th>
                      <th className="px-4 py-2.5 text-center">Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredIdents.map((i) => (
                      <tr key={i.id} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                        <td className="px-4 py-2">
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                            {i.type}
                          </span>
                        </td>
                        <td className="px-4 py-2 font-mono text-[11px] text-foreground truncate max-w-[260px]">
                          {i.value}
                        </td>
                        <td className="px-4 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                          {Math.round((i.confidence ?? 0) * 100)}%
                        </td>
                        <td className="px-4 py-2 text-right tabular-nums font-mono text-muted-foreground">
                          {i.occurrence_count ?? 1}
                        </td>
                        <td className="px-4 py-2">
                          {i.is_sanctioned ? (
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                              Sanctioned
                            </span>
                          ) : (i.occurrence_count ?? 1) > 1 ? (
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                              Shared
                            </span>
                          ) : (
                            <span className="text-muted-foreground text-[10px]">—</span>
                          )}
                        </td>
                        <td className="px-4 py-2 text-center">
                          {i.evidence_quote ? (
                            <Button
                              size="sm"
                              variant="ghost"
                              className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                              onClick={() =>
                                setEvidenceQuoteModal({
                                  title: `${i.type}: ${i.value}`,
                                  quote: i.evidence_quote,
                                  context: `Page: ${i.page_url || "Hidden Service"}`,
                                })
                              }
                            >
                              Quote
                            </Button>
                          ) : (
                            <span className="text-muted-foreground text-[10px]">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* ==================================================================== */}
        {/* SECTION 9: PIPELINE DETAILS & TECHNICAL RUN LOG                      */}
        {/* ==================================================================== */}
        <Card className="border-border/60 bg-card/60">
          <CardHeader className="cursor-pointer py-3 border-b border-border/40" onClick={() => setPipelineOpen(!pipelineOpen)}>
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <ClockIcon className="h-3.5 w-3.5 text-muted-foreground" />
                Pipeline Orchestration Stage Tracker
              </CardTitle>
              {pipelineOpen ? <ChevronUpIcon className="h-4 w-4 text-muted-foreground" /> : <ChevronDownIcon className="h-4 w-4 text-muted-foreground" />}
            </div>
          </CardHeader>
          {pipelineOpen && (
            <CardContent className="pt-4 pb-4 overflow-x-auto">
              <div className="flex items-center justify-between flex-wrap gap-2 min-w-max">
                {STAGES.map((stage, i) => (
                  <div key={stage} className="flex items-center">
                    <div className="flex flex-col items-center gap-1.5">
                      <StepIcon state={stageStates[stage] ?? "pending"} />
                      <span className="text-[9px] text-muted-foreground uppercase font-mono tracking-wider">
                        {stage.replace(/_/g, " ")}
                      </span>
                    </div>
                    {i < STAGES.length - 1 && (
                      <div className={`mx-2 h-px w-6 sm:w-10 ${stageStates[STAGES[i + 1]] !== "pending" ? "bg-foreground/60" : "bg-border/60"}`} />
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          )}
        </Card>

        <Card className="border-border/60 bg-card/60">
          <CardHeader className="cursor-pointer py-3 border-b border-border/40" onClick={() => setLogsOpen(!logsOpen)}>
            <div className="flex items-center justify-between">
              <CardTitle className="text-xs font-mono uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                <ActivityIcon className="h-3.5 w-3.5 text-muted-foreground" />
                Technical Worker Streaming Log ({logs.length} events)
              </CardTitle>
              {logsOpen ? <ChevronUpIcon className="h-4 w-4 text-muted-foreground" /> : <ChevronDownIcon className="h-4 w-4 text-muted-foreground" />}
            </div>
          </CardHeader>
          {logsOpen && (
            <CardContent className="pt-3 pb-3">
              <div ref={logRef} className="h-52 overflow-auto rounded-lg bg-zinc-950 p-3 font-mono text-[11px] leading-5 space-y-0.5 border border-border/40 whitespace-pre-wrap break-all">
                {logs.length === 0 && <span className="text-muted-foreground">Awaiting pipeline dispatch messages...</span>}
                {logs.map((log, i) => (
                  <div
                    key={i}
                    className={`${
                      (log.level || "").includes("ERROR")
                        ? "text-zinc-200 font-medium"
                        : "text-zinc-400"
                    }`}
                  >
                    <span className="text-muted-foreground/60">[{log.level || "INFO"}]</span> {log.message || JSON.stringify(log)}
                  </div>
                ))}
              </div>
            </CardContent>
          )}
        </Card>
      </div>

      {/* ====================================================================== */}
      {/* DRAWER: INVESTIGATION-SCOPED ACTOR DETAIL (ZERO CONTEXT LOSS)           */}
      {/* ====================================================================== */}
      {selectedActor && (
        <div
          className="fixed inset-0 z-50 flex justify-end bg-black/75 backdrop-blur-xs transition-opacity"
          onClick={() => setSelectedActor(null)}
        >
          <div
            className="w-full max-w-2xl bg-zinc-950 border-l border-border/80 h-full overflow-y-auto shadow-2xl flex flex-col justify-between"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Drawer Header */}
            <div>
              <div className="sticky top-0 z-10 bg-zinc-950/95 backdrop-blur-md border-b border-border/60 p-4 sm:p-5 flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-mono text-[10px] text-muted-foreground tracking-wider">{selectedActor.designated_id}</span>
                    <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono uppercase text-muted-foreground">
                      {selectedActor.threat_category}
                    </span>
                  </div>
                  <h2 className="text-lg sm:text-xl font-bold font-mono text-foreground flex items-center gap-2">
                    {selectedActor.primary_handle}
                  </h2>
                  <p className="text-xs text-muted-foreground mt-0.5 font-mono">
                    Investigation Persona Dossier • Case: {inv.id}
                  </p>
                </div>
                <button
                  onClick={() => setSelectedActor(null)}
                  className="rounded p-1 text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
                >
                  <XIcon className="h-5 w-5 text-muted-foreground" />
                </button>
              </div>

              {/* Drawer Navigation Tabs */}
              <div className="flex border-b border-border/40 bg-zinc-900/40 px-4 pt-1 gap-1 overflow-x-auto text-xs font-mono">
                {(["identity", "contacts", "markets", "relationships", "attribution", "opsec"] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActorDrawerTab(tab)}
                    className={`px-3 py-2 border-b-2 font-medium capitalize whitespace-nowrap transition ${
                      actorDrawerTab === tab
                        ? "border-foreground text-foreground"
                        : "border-transparent text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    {tab === "identity" && "Identity"}
                    {tab === "contacts" && "Contacts & Identifiers"}
                    {tab === "markets" && "Markets & Items"}
                    {tab === "relationships" && "Relationships"}
                    {tab === "attribution" && "Attribution & Activity"}
                    {tab === "opsec" && "OpSec & Stylometry"}
                  </button>
                ))}
              </div>

              {/* Drawer Body Content */}
              <div className="p-4 sm:p-5 space-y-4">
                {/* TAB 1: IDENTITY */}
                {actorDrawerTab === "identity" && (
                  <div className="space-y-4">
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Attribution Confidence & Timeline
                      </h4>
                      <div className="flex items-center justify-between text-xs font-mono">
                        <span className="text-muted-foreground">Confidence Rating</span>
                        <span className="font-bold text-foreground">
                          {Math.round((selectedActor.confidence ?? 1.0) * 100)}%
                        </span>
                      </div>
                      <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-foreground/80"
                          style={{ width: `${Math.round((selectedActor.confidence ?? 1.0) * 100)}%` }}
                        />
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-xs pt-1">
                        <div>
                          <span className="text-muted-foreground text-[10px] font-mono block uppercase">First Seen</span>
                          <span className="font-mono text-foreground text-[11px]">
                            {selectedActor.first_seen ? new Date(selectedActor.first_seen).toLocaleDateString() : "Observed during ingest"}
                          </span>
                        </div>
                        <div>
                          <span className="text-muted-foreground text-[10px] font-mono block uppercase">Last Corroborated</span>
                          <span className="font-mono text-foreground text-[11px]">
                            {selectedActor.last_seen ? new Date(selectedActor.last_seen).toLocaleDateString() : "Case snapshot"}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Known Aliases */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Associated Aliases & Nicknames
                      </h4>
                      {(() => {
                        const aliases = (intel?.aliases || []).filter((a: any) => a.actor_id === selectedActor.id);
                        if (aliases.length === 0) {
                          return <p className="text-xs text-muted-foreground font-mono">No secondary aliases recorded for this handle.</p>;
                        }
                        return (
                          <div className="flex flex-wrap gap-1.5">
                            {aliases.map((al: any, i: number) => (
                              <span key={i} className="rounded border border-border/60 bg-muted/20 px-2 py-0.5 font-mono text-xs text-foreground">
                                {al.alias_handle || al.alias}
                              </span>
                            ))}
                          </div>
                        );
                      })()}
                    </div>

                    {/* Attributed Hidden Services */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Attributed Onion Hidden Services
                      </h4>
                      {selectedActor.attributed_onions?.length === 0 ? (
                        <p className="text-xs text-muted-foreground font-mono">No specific onion endpoints directly attributed.</p>
                      ) : (
                        <div className="space-y-1.5">
                          {selectedActor.attributed_onions.map((url: string, i: number) => (
                            <div key={i} className="flex items-center justify-between text-xs font-mono p-2 rounded border border-border/40 bg-zinc-950/60">
                              <span className="text-foreground/90 truncate max-w-[360px]">{url}</span>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-5 px-1.5 text-[10px] font-mono text-muted-foreground hover:text-foreground"
                                onClick={() => setSnapshotModalUrl(url)}
                              >
                                View Snapshot
                              </Button>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* TAB 2: CONTACTS & IDENTIFIERS */}
                {actorDrawerTab === "contacts" && (
                  <div className="space-y-4">
                    {/* Darknet Observed Identifiers */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <div className="flex items-center justify-between">
                        <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider flex items-center gap-1.5">
                          <KeyIcon className="h-3.5 w-3.5 text-muted-foreground" />
                          Darknet-Observed Identifiers & Wallets
                        </h4>
                        <span className="text-[10px] font-mono text-muted-foreground">Extracted from hidden service</span>
                      </div>
                      {(() => {
                        const actorIdents = idents.filter((i) => i.actor_id === selectedActor.id);
                        const canonIdents = (intel?.canonical_identifiers || []).filter((ci: any) => ci.actor_id === selectedActor.id);
                        const merged = actorIdents.concat(canonIdents);

                        if (merged.length === 0) {
                          return <p className="text-xs text-muted-foreground font-mono py-2">No darknet cryptographic or messaging handles attributed.</p>;
                        }

                        return (
                          <div className="space-y-2 max-h-56 overflow-y-auto">
                            {merged.map((item, idx) => (
                              <div key={item.id || idx} className="rounded border border-border/40 bg-zinc-950/50 p-2.5 text-xs space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                    {item.type}
                                  </span>
                                  <div className="flex items-center gap-2">
                                    <span className="font-mono text-[10px] text-muted-foreground">
                                      Confidence: {Math.round((item.confidence ?? 1.0) * 100)}%
                                    </span>
                                    <button
                                      onClick={() => copyToClipboard(item.value)}
                                      className="text-muted-foreground hover:text-foreground text-[10px]"
                                    >
                                      {copiedText === item.value ? <CheckIcon className="h-3 w-3 text-foreground" /> : <CopyIcon className="h-3 w-3" />}
                                    </button>
                                  </div>
                                </div>
                                <div className="font-mono text-[11px] text-foreground break-all">{item.value}</div>
                                {item.evidence_quote && (
                                  <blockquote className="text-[10px] italic text-muted-foreground border-l border-border/60 pl-2">
                                    "{item.evidence_quote}"
                                  </blockquote>
                                )}
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>

                    {/* Clearnet / OSINT Pivot Accounts (Candidate Matches) */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <div className="flex items-center justify-between">
                        <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider flex items-center gap-1.5">
                          <GlobeIcon className="h-3.5 w-3.5 text-muted-foreground" />
                          Clearnet / OSINT Accounts (Candidate Matches)
                        </h4>
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                          Candidate Match
                        </span>
                      </div>
                      <p className="text-[10px] text-muted-foreground">
                        Discovered by Maigret social media reconnaissance. Username coincidence does not prove identity without secondary verification.
                      </p>
                      {(() => {
                        const actorClearnet = clearnetAccounts.filter((ca) => ca.actor_id === selectedActor.id);
                        if (actorClearnet.length === 0) {
                          return <p className="text-xs text-muted-foreground font-mono py-2">No clearweb OSINT accounts linked to this persona.</p>;
                        }
                        return (
                          <div className="space-y-2 max-h-56 overflow-y-auto">
                            {actorClearnet.map((ca, idx) => (
                              <div key={ca.id || idx} className="rounded border border-border/40 bg-zinc-950/50 p-2.5 text-xs space-y-1 font-mono">
                                <div className="flex items-center justify-between">
                                  <span className="font-semibold text-foreground">{ca.platform}</span>
                                  <span className="text-[9px] text-muted-foreground uppercase">
                                    Candidate Match
                                  </span>
                                </div>
                                <div className="text-[11px] text-foreground">{ca.value}</div>
                                {ca.evidence_quote && (
                                  <div className="text-[10px] text-muted-foreground italic">
                                    "{ca.evidence_quote}"
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>
                  </div>
                )}

                {/* TAB 3: MARKETS & ITEMS */}
                {actorDrawerTab === "markets" && (
                  <div className="space-y-4">
                    {/* Associated Marketplaces */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Marketplace Operations & Vendor Associations
                      </h4>
                      {(() => {
                        const actorMarkets = marketplaces.filter((m) => m.actor_id === selectedActor.id);
                        if (actorMarkets.length === 0) {
                          return <p className="text-xs text-muted-foreground font-mono">No explicit marketplace operation recorded.</p>;
                        }
                        return (
                          <div className="space-y-2">
                            {actorMarkets.map((m) => (
                              <div key={m.id} className="rounded border border-border/40 bg-zinc-950/50 p-2.5 text-xs space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="font-semibold text-foreground">{m.display_name}</span>
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                    {m.category || "Storefront"}
                                  </span>
                                </div>
                                <div className="font-mono text-[10px] text-muted-foreground">{m.onion_domain}</div>
                                {m.relation_evidence && (
                                  <blockquote className="text-[10px] italic text-muted-foreground border-l border-border/60 pl-2">
                                    "{m.relation_evidence}"
                                  </blockquote>
                                )}
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>

                    {/* Products & Commodities */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Contraband & Products Sold
                      </h4>
                      {(() => {
                        const actorProds = products.filter((p) => p.actor_id === selectedActor.id);
                        const actorComms = commodities.filter((c) => c.actor_handle === selectedActor.primary_handle);
                        const allProds = actorProds.concat(actorComms);

                        if (allProds.length === 0) {
                          return <p className="text-xs text-muted-foreground font-mono">No specific product listings linked to this vendor in this investigation.</p>;
                        }

                        return (
                          <div className="space-y-2 max-h-56 overflow-y-auto">
                            {allProds.map((item, idx) => (
                              <div key={item.id || idx} className="rounded border border-border/40 bg-zinc-950/50 p-2.5 text-xs space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="font-semibold text-foreground">{item.name || item.value}</span>
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                    {item.category || item.type}
                                  </span>
                                </div>
                                {(item.evidence_quote || item.relation_evidence) && (
                                  <blockquote className="text-[10px] italic text-muted-foreground border-l border-border/60 pl-2">
                                    "{item.evidence_quote || item.relation_evidence}"
                                  </blockquote>
                                )}
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>
                  </div>
                )}

                {/* TAB 4: RELATIONSHIPS */}
                {actorDrawerTab === "relationships" && (
                  <div className="space-y-3">
                    <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                      Connections with Other Actors in This Case
                    </h4>
                    {(() => {
                      const actorRels = investigationRelationships.filter(
                        (r) => r.source === selectedActor.id || r.target === selectedActor.id ||
                               r.source === selectedActor.primary_handle || r.target === selectedActor.primary_handle
                      );

                      if (actorRels.length === 0) {
                        return <p className="text-xs text-muted-foreground font-mono py-2">No cross-actor relationship edges observed in this case.</p>;
                      }

                      return (
                        <div className="space-y-2">
                          {actorRels.map((rel) => (
                            <div key={rel.id} className="rounded border border-border/40 bg-zinc-950/50 p-2.5 text-xs space-y-1">
                              <div className="flex items-center justify-between">
                                <div className="font-mono text-[11px]">
                                  <span className="text-foreground font-semibold">{rel.source}</span>
                                  <span className="text-muted-foreground mx-1.5">➔</span>
                                  <span className="text-foreground font-semibold">{rel.target}</span>
                                </div>
                                <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                  {rel.edge_type}
                                </span>
                              </div>
                              <div className="text-[10px] text-muted-foreground font-mono">
                                Confidence: {Math.round(rel.confidence * 100)}% | Basis: {rel.basis}
                              </div>
                              {rel.evidence_quote && (
                                <blockquote className="text-[10px] italic text-muted-foreground border-l border-border/60 pl-2">
                                  "{rel.evidence_quote}"
                                </blockquote>
                              )}
                            </div>
                          ))}
                        </div>
                      );
                    })()}
                  </div>
                )}

                {/* TAB 5: ATTRIBUTION & ACTIVITY */}
                {actorDrawerTab === "attribution" && (
                  <div className="space-y-4">
                    {/* Attribution Assessment */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Attribution Assessment & Findings
                      </h4>
                      {(() => {
                        const actorAssessments = attributionAssessments.filter((aa) => aa.actor_id === selectedActor.id);
                        if (actorAssessments.length === 0) {
                          return <p className="text-xs text-muted-foreground font-mono">No formal OpenCode assessment statement filed.</p>;
                        }
                        return (
                          <div className="space-y-2">
                            {actorAssessments.map((aa, idx) => (
                              <div key={aa.id || idx} className="space-y-1.5 text-xs">
                                <p className="text-foreground leading-relaxed">{aa.assessment}</p>
                                {aa.supporting_evidence && (
                                  <div className="text-[10px] text-foreground/90 bg-muted/20 rounded p-1.5 border border-border/40 font-mono">
                                    <strong>Supporting:</strong> {aa.supporting_evidence}
                                  </div>
                                )}
                                {aa.contradicting_evidence && (
                                  <div className="text-[10px] text-muted-foreground bg-muted/10 rounded p-1.5 border border-border/30 font-mono">
                                    <strong>Contradicting:</strong> {aa.contradicting_evidence}
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>

                    {/* Operational Activities */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Recorded Operational Activities
                      </h4>
                      {(() => {
                        const actorActs = (intel?.activities || []).filter((a: any) => a.actor_id === selectedActor.id);
                        if (actorActs.length === 0) {
                          return <p className="text-xs text-muted-foreground font-mono">No specific operational activities cataloged.</p>;
                        }
                        return (
                          <div className="space-y-1.5">
                            {actorActs.map((act: any, idx: number) => (
                              <div key={act.id || idx} className="rounded border border-border/40 bg-zinc-950/50 p-2 text-xs">
                                <div className="flex items-center justify-between mb-1">
                                  <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                                    {act.activity_type}
                                  </span>
                                  <span className="text-[10px] font-mono text-muted-foreground">
                                    {Math.round((act.confidence ?? 1.0) * 100)}%
                                  </span>
                                </div>
                                <p className="text-foreground font-mono text-[11px]">{act.description}</p>
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>
                  </div>
                )}

                {/* TAB 6: OPSEC & STYLOMETRY */}
                {actorDrawerTab === "opsec" && (
                  <div className="space-y-4">
                    {/* OpSec Findings */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Operational Security Flaws & Leaks
                      </h4>
                      {(() => {
                        const actorOpsec = opsecFindings.filter((o) => o.actor_id === selectedActor.id);
                        if (actorOpsec.length === 0) {
                          return <p className="text-xs text-muted-foreground font-mono">No OpSec failures recorded for this persona.</p>;
                        }
                        return (
                          <div className="space-y-2">
                            {actorOpsec.map((op, idx) => (
                              <div key={op.id || idx} className="rounded border border-border/40 bg-zinc-950/50 p-2.5 text-xs space-y-1">
                                <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                                  {op.finding_type}
                                </span>
                                <p className="text-foreground font-medium">{op.description}</p>
                                {op.evidence_quote && (
                                  <blockquote className="text-[10px] italic text-muted-foreground border-l border-border/60 pl-2">
                                    "{op.evidence_quote}"
                                  </blockquote>
                                )}
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>

                    {/* Stylometric Notes */}
                    <div className="rounded-lg border border-border/60 bg-zinc-900/30 p-3.5 space-y-2">
                      <h4 className="text-xs font-semibold text-foreground uppercase font-mono tracking-wider">
                        Stylometric Profile Notes
                      </h4>
                      {(() => {
                        const actorSty = stylometryFindings.filter((s) => s.actor_id === selectedActor.id);
                        if (actorSty.length === 0 && !selectedActor.stylometry_summary) {
                          return <p className="text-xs text-muted-foreground font-mono">No stylometric vector recorded for this handle.</p>;
                        }
                        return (
                          <div className="space-y-2 text-xs">
                            {actorSty.map((s, idx) => (
                              <div key={s.id || idx} className="rounded border border-border/40 bg-zinc-950/50 p-2.5 space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="font-semibold text-foreground">{s.assessment}</span>
                                  {s.similarity_score != null && (
                                    <span className="font-mono text-[10px] text-muted-foreground">
                                      Score: {s.similarity_score}
                                    </span>
                                  )}
                                </div>
                                <p className="text-foreground/90">{s.details}</p>
                              </div>
                            ))}
                            {selectedActor.stylometry_summary && (
                              <pre className="p-2.5 rounded bg-zinc-950 border border-border/40 font-mono text-[10px] text-zinc-300 overflow-x-auto">
                                {selectedActor.stylometry_summary}
                              </pre>
                            )}
                          </div>
                        );
                      })()}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Drawer Footer */}
            <div className="sticky bottom-0 bg-zinc-950 border-t border-border/60 p-3 sm:p-4 flex items-center justify-between">
              <a
                href={`/actors/${selectedActor.id}`}
                className="text-xs font-mono text-muted-foreground hover:text-foreground hover:underline flex items-center gap-1"
              >
                Open Cross-Investigation Canonical Dossier ↗
              </a>
              <Button size="sm" variant="outline" className="font-mono text-xs" onClick={() => setSelectedActor(null)}>
                Close Dossier
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================== */}
      {/* MODAL: VERBATIM EVIDENCE QUOTE VIEWER                                  */}
      {/* ====================================================================== */}
      {evidenceQuoteModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-sm"
          onClick={() => setEvidenceQuoteModal(null)}
        >
          <div
            className="w-full max-w-lg rounded-xl border border-border/70 bg-zinc-950 p-5 shadow-2xl space-y-3"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-semibold text-foreground truncate max-w-[380px]">
                {evidenceQuoteModal.title}
              </span>
              <button
                onClick={() => setEvidenceQuoteModal(null)}
                className="text-muted-foreground hover:text-foreground text-sm font-bold px-1"
              >
                ✕
              </button>
            </div>
            {evidenceQuoteModal.context && (
              <p className="text-xs text-muted-foreground font-mono">{evidenceQuoteModal.context}</p>
            )}
            <p className="text-xs text-muted-foreground font-mono uppercase tracking-wider text-[10px]">Verbatim Scraped Evidence Quote:</p>
            <div className="rounded-lg bg-zinc-900/60 p-3.5 font-mono text-xs text-zinc-200 border border-border/40 whitespace-pre-wrap max-h-64 overflow-y-auto leading-relaxed">
              "{evidenceQuoteModal.quote}"
            </div>
            <div className="flex justify-between items-center pt-1">
              <button
                onClick={() => copyToClipboard(evidenceQuoteModal.quote)}
                className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1 font-mono"
              >
                {copiedText === evidenceQuoteModal.quote ? <CheckIcon className="h-3.5 w-3.5 text-foreground" /> : <CopyIcon className="h-3.5 w-3.5 text-muted-foreground" />}
                Copy Quote
              </button>
              <Button size="sm" variant="outline" className="font-mono text-xs" onClick={() => setEvidenceQuoteModal(null)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================== */}
      {/* MODAL: DEFANGED FORENSIC DOM SNAPSHOT PREVIEW                           */}
      {/* ====================================================================== */}
      {snapshotModalUrl && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 p-4 backdrop-blur-md"
          onClick={() => setSnapshotModalUrl(null)}
        >
          <div
            className="w-full max-w-4xl h-[85vh] rounded-xl border border-border/80 bg-zinc-950 shadow-2xl flex flex-col justify-between overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-3 bg-zinc-950 border-b border-border/60 flex items-center justify-between">
              <div>
                <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest block font-semibold">
                  Forensically Preserved Capture (Defanged)
                </span>
                <span className="font-mono text-xs text-foreground truncate block max-w-xl">
                  {snapshotModalUrl}
                </span>
              </div>
              <button
                onClick={() => setSnapshotModalUrl(null)}
                className="text-muted-foreground hover:text-foreground text-sm font-bold p-1"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 bg-white overflow-hidden relative">
              {snapshotLoading ? (
                <div className="flex h-full items-center justify-center bg-zinc-950 text-xs text-muted-foreground font-mono">
                  Loading defanged DOM snapshot...
                </div>
              ) : (
                <iframe
                  srcDoc={snapshotHtml}
                  sandbox="allow-same-origin"
                  className="w-full h-full border-0"
                  title="Defanged DOM Snapshot Preview"
                />
              )}
            </div>

            <div className="p-2.5 bg-zinc-950 border-t border-border/60 flex justify-between items-center text-xs">
              <span className="text-muted-foreground text-[10px] font-mono">
                JavaScript defanged • Safe sandboxed environment
              </span>
              <Button size="sm" variant="outline" className="font-mono text-xs" onClick={() => setSnapshotModalUrl(null)}>
                Close Preview
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Case Export Modal */}
      {exportModalOpen && (
        <ExportModal investigationId={id} onClose={() => setExportModalOpen(false)} />
      )}
    </AppShell>
  );
}
