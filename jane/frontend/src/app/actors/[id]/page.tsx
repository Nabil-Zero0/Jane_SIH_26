"use client";

import { useEffect, useState, useMemo } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import mermaid from "mermaid";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  UsersIcon,
  ShieldCheckIcon,
  NetworkIcon,
  ShoppingBagIcon,
  GlobeIcon,
  KeyIcon,
  CopyIcon,
  CheckIcon,
  ArrowRightIcon,
  ServerCrashIcon,
  FlaskConicalIcon,
  ClockIcon,
  ScrollIcon,
  ActivityIcon,
  AlertCircleIcon,
} from "@/components/icons";

export default function ActorDossierPage() {
  const params = useParams();
  const id = params.id as string;

  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<
    "overview" | "identity" | "contacts" | "markets" | "relationships" | "activities" | "osint" | "stylometry" | "opsec" | "attribution" | "investigations" | "evidence"
  >("overview");
  const [evidenceQuoteModal, setEvidenceQuoteModal] = useState<{ title: string; quote: string; context?: string } | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [miniGraphSvg, setMiniGraphSvg] = useState<string>("");

  useEffect(() => {
    fetch(`/api/actors?id=${id}`)
      .then((r) => {
        if (!r.ok) throw new Error("Failed to load actor");
        return r.json();
      })
      .then((d) => {
        setData(d);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Actor fetch error:", err);
        setLoading(false);
      });
  }, [id]);

  const copyToClipboard = (txt: string) => {
    navigator.clipboard.writeText(txt);
    setCopiedText(txt);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Generate Mermaid ego-network preview centered on this actor
  useEffect(() => {
    if (!data?.actor) return;
    const actor = data.actor;
    const actorLabel = actor.primary_handle.replace(/"/g, "");
    const safeActorId = "actor_main";

    const lines: string[] = ["graph LR"];
    lines.push(`  ${safeActorId}["${actorLabel} (${actor.designated_id || "Actor"})"]`);

    // Add markets
    (data.marketplaces || []).slice(0, 4).forEach((m: any, idx: number) => {
      const mid = `m_${idx}`;
      lines.push(`  ${mid}["${(m.display_name || m.onion_domain).replace(/"/g, "")}"]`);
      lines.push(`  ${safeActorId} -->|"OPERATES"| ${mid}`);
    });

    // Add products
    (data.products || []).slice(0, 5).forEach((p: any, idx: number) => {
      const pid = `p_${idx}`;
      lines.push(`  ${pid}["${(p.product_name || p.name || "Item").slice(0, 20).replace(/"/g, "")}"]`);
      lines.push(`  ${safeActorId} -->|"SELLS"| ${pid}`);
    });

    // Add trust relations
    (data.trust || []).slice(0, 4).forEach((t: any, idx: number) => {
      const tid = `t_${idx}`;
      const targetLabel = (t.target_handle || t.trusted_actor_id || "Counterparty").replace(/"/g, "");
      lines.push(`  ${tid}["${targetLabel}"]`);
      lines.push(`  ${safeActorId} -->|"TRUSTS"| ${tid}`);
    });

    // Add clearnet leads
    (data.clearnet_accounts || []).slice(0, 3).forEach((c: any, idx: number) => {
      const cid = `c_${idx}`;
      lines.push(`  ${cid}["${c.platform}: ${c.value}"]`);
      lines.push(`  ${safeActorId} -.->|"OSINT"| ${cid}`);
    });

    const mmdCode = lines.length > 2 ? lines.join("\n") : "graph LR\n  empty[\"Ego Network Pending\"]";

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
      mermaid.render(`actor-ego-graph-${id.replace(/[^a-zA-Z0-9_]/g, "_")}`, mmdCode)
        .then(({ svg }) => setMiniGraphSvg(svg))
        .catch(() => setMiniGraphSvg(""));
    } catch {
      setMiniGraphSvg("");
    }
  }, [data, id]);

  if (loading) {
    return (
      <AppShell>
        <div className="flex h-96 items-center justify-center">
          <div className="space-y-3 text-center">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-foreground border-t-transparent mx-auto" />
            <p className="text-xs font-mono text-muted-foreground tracking-wide">HYDRATING CANONICAL ACTOR DOSSIER...</p>
          </div>
        </div>
      </AppShell>
    );
  }

  if (!data?.actor) {
    return (
      <AppShell>
        <div className="p-12 text-center text-zinc-400">
          <AlertCircleIcon className="h-8 w-8 mx-auto mb-3 text-zinc-500" />
          <h2 className="text-sm font-semibold tracking-tight text-foreground uppercase font-mono">Actor Dossier Not Found</h2>
          <p className="text-xs text-muted-foreground mt-1 font-mono">Identifier: {id}</p>
          <div className="mt-4">
            <Link href="/actors">
              <Button size="sm" variant="outline" className="font-mono text-xs">
                ← Return to Threat Actors Index
              </Button>
            </Link>
          </div>
        </div>
      </AppShell>
    );
  }

  const actor = data.actor;
  const aliases: any[] = data.aliases || [];
  const idents: any[] = data.identifiers || [];
  const markets: any[] = data.marketplaces || [];
  const products: any[] = data.products || [];
  const trustLinks: any[] = data.trust || [];
  const activities: any[] = data.activities || [];
  const investigations: any[] = data.investigations || [];
  const osintTargets: any[] = data.osint_targets || [];
  const clearnetAccounts: any[] = data.clearnet_accounts || [];
  const stylometryFindings: any[] = data.stylometry || [];
  const opsecFindings: any[] = data.opsec || [];
  const assessments: any[] = data.attribution_assessments || [];

  // Categorize identifiers
  const commIdents = idents.filter((i) =>
    ["EMAIL", "TELEGRAM", "TOX_ID", "SESSION_KEY", "JABBER", "DISCORD", "XMPP"].includes(i.type?.toUpperCase())
  );
  const cryptoIdents = idents.filter((i) =>
    ["BITCOIN_ADDRESS", "MONERO_ADDRESS", "ETHEREUM_ADDRESS", "CRYPTO_WALLET", "PGP_FINGERPRINT", "PGP_KEY"].includes(i.type?.toUpperCase())
  );
  const otherIdents = idents.filter((i) => !commIdents.includes(i) && !cryptoIdents.includes(i));

  const confPct = Math.round((actor.attribution_confidence ?? 1.0) * 100);

  return (
    <AppShell>
      <div className="w-full min-w-0 max-w-full space-y-6 font-sans">
        {/* ==================================================================== */}
        {/* ACTOR DOSSIER HERO                                                   */}
        {/* ==================================================================== */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5 font-mono text-[10px]">
              <span className="tracking-widest text-muted-foreground uppercase">Canonical Actor Dossier</span>
              <span className="text-muted-foreground/40 text-xs">/</span>
              <span className="text-foreground font-medium">{actor.designated_id || actor.id}</span>
              <span className="text-muted-foreground/40 text-xs">•</span>
              <span className="text-muted-foreground">{actor.id}</span>
            </div>
            <div className="flex items-center gap-3">
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground font-mono">
                {actor.primary_handle}
              </h1>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] font-mono uppercase text-muted-foreground">
                {actor.category || "Unclassified"}
              </span>
            </div>
            <div className="text-xs text-muted-foreground mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono">
              <span>Attribution Confidence: <strong className="text-foreground tabular-nums">{confPct}%</strong></span>
              <span className="text-muted-foreground/30">•</span>
              <span>First Seen: {actor.first_seen ? new Date(actor.first_seen).toLocaleDateString() : "Historical Ingest"}</span>
              <span className="text-muted-foreground/30">•</span>
              <span>Last Observed: {actor.last_seen ? new Date(actor.last_seen).toLocaleDateString() : "Current Case Cycle"}</span>
            </div>
          </div>

          <div className="flex gap-2 items-center flex-wrap">
            <Link href="/actors">
              <Button size="sm" variant="outline" className="border-border/80 text-foreground hover:bg-muted/40 font-mono text-xs">
                ← Catalog Index
              </Button>
            </Link>
            <Link href="/graph">
              <Button size="sm" variant="outline" className="gap-1.5 border-border/80 text-foreground hover:bg-muted/40 font-mono text-xs">
                <NetworkIcon className="h-3.5 w-3.5 text-muted-foreground" />
                Graph Studio
              </Button>
            </Link>
            <Button
              size="sm"
              className="bg-foreground text-background hover:bg-foreground/90 font-mono text-xs"
              onClick={() => {
                const summary = `THREAT ACTOR DOSSIER: ${actor.primary_handle} (${actor.designated_id})\nCategory: ${actor.category}\nConfidence: ${confPct}%\nIdentifiers: ${idents.length}\nMarkets: ${markets.length}\nContraband: ${products.length}\nInvestigations: ${investigations.length}`;
                copyToClipboard(summary);
              }}
            >
              {copiedText ? "Dossier Copied" : "Copy Dossier Brief"}
            </Button>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* HERO KPI COUNTERS BENTO                                              */}
        {/* ==================================================================== */}
        <div className="grid gap-3 grid-cols-2 sm:grid-cols-4 lg:grid-cols-7">
          <div className="rounded-xl border border-border/60 bg-card/60 p-3 flex flex-col justify-between">
            <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Cases</span>
            <div className="text-xl font-bold font-mono tracking-tight tabular-nums text-foreground mt-1">{investigations.length || 1}</div>
            <div className="text-[9px] text-muted-foreground truncate">Investigations</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3 flex flex-col justify-between">
            <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Aliases</span>
            <div className="text-xl font-bold font-mono tracking-tight tabular-nums text-foreground mt-1">{aliases.length}</div>
            <div className="text-[9px] text-muted-foreground truncate">Known handles</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3 flex flex-col justify-between">
            <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Identifiers</span>
            <div className="text-xl font-bold font-mono tracking-tight tabular-nums text-foreground mt-1">{idents.length}</div>
            <div className="text-[9px] text-muted-foreground truncate">IOCs & Wallets</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3 flex flex-col justify-between">
            <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Markets</span>
            <div className="text-xl font-bold font-mono tracking-tight tabular-nums text-foreground mt-1">{markets.length}</div>
            <div className="text-[9px] text-muted-foreground truncate">Onion storefronts</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3 flex flex-col justify-between">
            <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Contraband</span>
            <div className="text-xl font-bold font-mono tracking-tight tabular-nums text-foreground mt-1">{products.length}</div>
            <div className="text-[9px] text-muted-foreground truncate">Commodities</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3 flex flex-col justify-between">
            <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Trust Links</span>
            <div className="text-xl font-bold font-mono tracking-tight tabular-nums text-foreground mt-1">{trustLinks.length}</div>
            <div className="text-[9px] text-muted-foreground truncate">Counterparty links</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3 flex flex-col justify-between">
            <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">OSINT Leads</span>
            <div className="text-xl font-bold font-mono tracking-tight tabular-nums text-foreground mt-1">{clearnetAccounts.length + osintTargets.length}</div>
            <div className="text-[9px] text-muted-foreground truncate">Clearnet accounts</div>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* SUB-NAVIGATION TABS                                                  */}
        {/* ==================================================================== */}
        <div className="flex border-b border-border/40 gap-1 overflow-x-auto text-xs font-mono">
          {[
            { id: "overview", label: "Overview" },
            { id: "identity", label: `Identity & Aliases (${aliases.length})` },
            { id: "contacts", label: `Identifiers (${idents.length})` },
            { id: "markets", label: `Markets & Products (${markets.length + products.length})` },
            { id: "relationships", label: `Relationships (${trustLinks.length})` },
            { id: "activities", label: `Activities (${activities.length})` },
            { id: "osint", label: `OSINT Pivots (${clearnetAccounts.length + osintTargets.length})` },
            { id: "stylometry", label: `Stylometry (${stylometryFindings.length})` },
            { id: "opsec", label: `OpSec Leaks (${opsecFindings.length})` },
            { id: "attribution", label: `Attribution (${assessments.length})` },
            { id: "investigations", label: `Case History (${investigations.length || 1})` },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3.5 py-2.5 border-b-2 font-medium whitespace-nowrap transition ${
                activeTab === tab.id
                  ? "border-foreground text-foreground"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* ==================================================================== */}
        {/* TAB 1: OVERVIEW & SYNTHESIS                                          */}
        {/* ==================================================================== */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            <div className="grid gap-4 lg:grid-cols-3">
              {/* Analytical Summary Card */}
              <Card className="border-border/60 bg-card/60 lg:col-span-2">
                <CardHeader className="pb-3 border-b border-border/40">
                  <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                    <ScrollIcon className="h-4 w-4 text-muted-foreground" />
                    Analytical Intelligence Summary
                  </CardTitle>
                  <CardDescription className="text-xs text-muted-foreground">
                    Corroborated analytical synthesis generated from investigative evidence.
                  </CardDescription>
                </CardHeader>
                <CardContent className="pt-4 space-y-3 text-xs leading-relaxed text-foreground">
                  <p>
                    <strong className="text-foreground">{actor.primary_handle}</strong> (designated{" "}
                    <span className="font-mono text-muted-foreground">{actor.designated_id}</span>) is cataloged as a{" "}
                    <strong className="text-foreground">{actor.category || "Threat Actor"}</strong> with an attribution confidence of{" "}
                    <span className="font-mono font-bold">{confPct}%</span>.
                  </p>

                  {assessments.length > 0 && assessments[0].assessment && (
                    <div className="rounded-lg border border-border/60 bg-zinc-950/40 p-3 space-y-1.5">
                      <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider block">
                        Primary OpenCode Attribution Statement:
                      </span>
                      <p className="text-foreground italic">"{assessments[0].assessment}"</p>
                      {assessments[0].supporting_evidence && (
                        <p className="text-[11px] font-mono text-muted-foreground pt-1 border-t border-border/20">
                          <strong>Corroborating Evidence:</strong> {assessments[0].supporting_evidence}
                        </p>
                      )}
                    </div>
                  )}

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                    <div className="rounded-lg border border-border/40 bg-zinc-950/40 p-3 space-y-1 font-mono">
                      <span className="text-[10px] text-muted-foreground uppercase block">Operational Footprint</span>
                      <div className="text-foreground">
                        {markets.length} marketplace operations • {products.length} contraband offerings cataloged
                      </div>
                    </div>
                    <div className="rounded-lg border border-border/40 bg-zinc-950/40 p-3 space-y-1 font-mono">
                      <span className="text-[10px] text-muted-foreground uppercase block">Attribution Anchors</span>
                      <div className="text-foreground">
                        {cryptoIdents.length} crypto/PGP anchors • {commIdents.length} messaging handles
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Local Ego Network Topology */}
              <Card className="border-border/60 bg-card/60 flex flex-col justify-between">
                <CardHeader className="pb-2 border-b border-border/40">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                      <NetworkIcon className="h-4 w-4 text-muted-foreground" />
                      Local Network Ego Graph
                    </CardTitle>
                    <Link href="/graph">
                      <Button size="sm" variant="outline" className="h-6 px-2 text-[10px] font-mono border-border/60 text-foreground hover:bg-muted/30">
                        Full Graph →
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
                    <div className="text-center py-8 space-y-2">
                      <NetworkIcon className="h-8 w-8 mx-auto text-muted-foreground/40" />
                      <p className="text-xs font-mono text-muted-foreground">Ego network map rendering...</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Key Indicators Preview */}
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                    <KeyIcon className="h-4 w-4 text-muted-foreground" />
                    Key Attributed Identifiers ({idents.slice(0, 6).length})
                  </CardTitle>
                  <button
                    onClick={() => setActiveTab("contacts")}
                    className="text-xs font-mono text-muted-foreground hover:text-foreground underline"
                  >
                    View all {idents.length} indicators →
                  </button>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                      <tr className="text-left">
                        <th className="px-4 py-2.5">Type</th>
                        <th className="px-4 py-2.5">Identifier Value</th>
                        <th className="px-4 py-2.5 text-right">Confidence</th>
                        <th className="px-4 py-2.5 text-center">Verbatim Quote</th>
                      </tr>
                    </thead>
                    <tbody>
                      {idents.slice(0, 6).map((item, idx) => (
                        <tr key={item.id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                          <td className="px-4 py-2">
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                              {item.type}
                            </span>
                          </td>
                          <td className="px-4 py-2 font-mono text-[11px] text-foreground truncate max-w-[320px]">
                            {item.value}
                          </td>
                          <td className="px-4 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                            {Math.round((item.confidence ?? 1.0) * 100)}%
                          </td>
                          <td className="px-4 py-2 text-center">
                            {item.evidence_quote ? (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                                onClick={() =>
                                  setEvidenceQuoteModal({
                                    title: `${item.type}: ${item.value}`,
                                    quote: item.evidence_quote,
                                    context: `Actor: ${actor.primary_handle}`,
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
                </div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 2: IDENTITY & ALIASES                                            */}
        {/* ==================================================================== */}
        {activeTab === "identity" && (
          <div className="space-y-4">
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <UsersIcon className="h-4 w-4 text-muted-foreground" />
                  Canonical Identity Attributes
                </CardTitle>
              </CardHeader>
              <CardContent className="pt-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
                  <div className="rounded-lg border border-border/40 bg-zinc-950/40 p-3">
                    <span className="text-[10px] text-muted-foreground uppercase block">Primary Handle</span>
                    <span className="text-foreground font-bold text-sm">{actor.primary_handle}</span>
                  </div>
                  <div className="rounded-lg border border-border/40 bg-zinc-950/40 p-3">
                    <span className="text-[10px] text-muted-foreground uppercase block">Canonical Actor UUID</span>
                    <span className="text-foreground text-[11px] truncate block">{actor.id}</span>
                  </div>
                  <div className="rounded-lg border border-border/40 bg-zinc-950/40 p-3">
                    <span className="text-[10px] text-muted-foreground uppercase block">First Seen</span>
                    <span className="text-foreground text-[11px]">
                      {actor.first_seen ? new Date(actor.first_seen).toLocaleString() : "Crawl observation"}
                    </span>
                  </div>
                  <div className="rounded-lg border border-border/40 bg-zinc-950/40 p-3">
                    <span className="text-[10px] text-muted-foreground uppercase block">Last Seen</span>
                    <span className="text-foreground text-[11px]">
                      {actor.last_seen ? new Date(actor.last_seen).toLocaleString() : "Current case cycle"}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Known Aliases */}
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <UsersIcon className="h-4 w-4 text-muted-foreground" />
                  Associated Aliases & Variant Handles ({aliases.length})
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground">
                  Secondary pseudonyms linked to this canonical persona across cases.
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                {aliases.length === 0 ? (
                  <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                    No secondary aliases registered for this persona.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                        <tr className="text-left">
                          <th className="px-4 py-2.5">Alias Handle</th>
                          <th className="px-4 py-2.5">Source Case</th>
                          <th className="px-4 py-2.5 text-right">Confidence</th>
                          <th className="px-4 py-2.5">Review Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {aliases.map((al, idx) => (
                          <tr key={al.id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                            <td className="px-4 py-2.5 font-mono font-bold text-foreground">
                              {al.alias_handle || al.alias}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-[11px] text-muted-foreground">
                              {al.source_investigation_id || "Cross-case ingest"}
                            </td>
                            <td className="px-4 py-2.5 text-right tabular-nums font-mono text-foreground font-medium">
                              {Math.round((al.confidence ?? 1.0) * 100)}%
                            </td>
                            <td className="px-4 py-2.5">
                              {al.needs_review ? (
                                <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                                  Needs Verification
                                </span>
                              ) : (
                                <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                                  Corroborated
                                </span>
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
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 3: CONTACTS & IDENTIFIERS                                        */}
        {/* ==================================================================== */}
        {activeTab === "contacts" && (
          <div className="space-y-4">
            {/* Communication Identifiers */}
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <KeyIcon className="h-4 w-4 text-muted-foreground" />
                  Communication Channels & Messaging Handles ({commIdents.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                {commIdents.length === 0 ? (
                  <div className="py-6 text-center text-xs font-mono text-muted-foreground">
                    No messaging, email, or forum handles cataloged for this actor.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                        <tr className="text-left">
                          <th className="px-4 py-2.5">Channel</th>
                          <th className="px-4 py-2.5">Identifier Value</th>
                          <th className="px-4 py-2.5 text-right">Confidence</th>
                          <th className="px-4 py-2.5 text-center">Quote</th>
                        </tr>
                      </thead>
                      <tbody>
                        {commIdents.map((item, idx) => (
                          <tr key={item.id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                            <td className="px-4 py-2">
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                {item.type}
                              </span>
                            </td>
                            <td className="px-4 py-2 font-mono text-[11px] text-foreground">
                              {item.value}
                            </td>
                            <td className="px-4 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                              {Math.round((item.confidence ?? 1.0) * 100)}%
                            </td>
                            <td className="px-4 py-2 text-center">
                              {item.evidence_quote ? (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                                  onClick={() =>
                                    setEvidenceQuoteModal({
                                      title: `${item.type}: ${item.value}`,
                                      quote: item.evidence_quote,
                                      context: `Actor: ${actor.primary_handle}`,
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
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Cryptographic & Financial Identifiers */}
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <KeyIcon className="h-4 w-4 text-muted-foreground" />
                  Financial Wallets & Cryptographic PGP Keys ({cryptoIdents.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                {cryptoIdents.length === 0 ? (
                  <div className="py-6 text-center text-xs font-mono text-muted-foreground">
                    No cryptocurrency addresses or PGP fingerprints cataloged.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                        <tr className="text-left">
                          <th className="px-4 py-2.5">Asset Type</th>
                          <th className="px-4 py-2.5">Address / Fingerprint</th>
                          <th className="px-4 py-2.5 text-center">Shared?</th>
                          <th className="px-4 py-2.5 text-right">Confidence</th>
                          <th className="px-4 py-2.5 text-center">Quote</th>
                        </tr>
                      </thead>
                      <tbody>
                        {cryptoIdents.map((item, idx) => (
                          <tr key={item.id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                            <td className="px-4 py-2">
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                {item.type}
                              </span>
                            </td>
                            <td className="px-4 py-2 font-mono text-[11px] text-foreground break-all">
                              {item.value}
                            </td>
                            <td className="px-4 py-2 text-center">
                              {item.is_shared ? (
                                <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                                  Shared
                                </span>
                              ) : (
                                <span className="text-muted-foreground text-[10px]">—</span>
                              )}
                            </td>
                            <td className="px-4 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                              {Math.round((item.confidence ?? 1.0) * 100)}%
                            </td>
                            <td className="px-4 py-2 text-center">
                              {item.evidence_quote ? (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                                  onClick={() =>
                                    setEvidenceQuoteModal({
                                      title: `${item.type}: ${item.value}`,
                                      quote: item.evidence_quote,
                                      context: `Actor: ${actor.primary_handle}`,
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
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 4: MARKETS & PRODUCTS                                            */}
        {/* ==================================================================== */}
        {activeTab === "markets" && (
          <div className="space-y-4">
            {/* Marketplaces */}
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <GlobeIcon className="h-4 w-4 text-muted-foreground" />
                  Associated Marketplaces & Hidden Services ({markets.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                {markets.length === 0 ? (
                  <div className="py-6 text-center text-xs font-mono text-muted-foreground">
                    No explicit marketplace operational links recorded for this actor.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                        <tr className="text-left">
                          <th className="px-4 py-2.5">Marketplace</th>
                          <th className="px-4 py-2.5">Domain</th>
                          <th className="px-4 py-2.5">Category</th>
                          <th className="px-4 py-2.5 text-right">Confidence</th>
                          <th className="px-4 py-2.5 text-center">Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {markets.map((m, idx) => (
                          <tr key={m.marketplace_id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                            <td className="px-4 py-2 font-medium text-foreground font-mono">
                              {m.display_name || m.onion_domain}
                            </td>
                            <td className="px-4 py-2 font-mono text-[11px] text-muted-foreground">
                              {m.onion_domain}
                            </td>
                            <td className="px-4 py-2">
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                {m.market_category || "Darknet Storefront"}
                              </span>
                            </td>
                            <td className="px-4 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                              {Math.round((m.confidence ?? 1.0) * 100)}%
                            </td>
                            <td className="px-4 py-2 text-center">
                              {m.evidence_quote ? (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                                  onClick={() =>
                                    setEvidenceQuoteModal({
                                      title: m.display_name || m.onion_domain,
                                      quote: m.evidence_quote,
                                      context: `Marketplace Operation`,
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

            {/* Contraband Products & Commodities */}
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <ShoppingBagIcon className="h-4 w-4 text-muted-foreground" />
                  Contraband & Product Offerings ({products.length})
                </CardTitle>
              </CardHeader>
              <CardContent className="p-0">
                {products.length === 0 ? (
                  <div className="py-6 text-center text-xs font-mono text-muted-foreground">
                    No contraband listings attributed to this actor.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                        <tr className="text-left">
                          <th className="px-4 py-2.5">Product Name</th>
                          <th className="px-4 py-2.5">Category</th>
                          <th className="px-4 py-2.5">Marketplace</th>
                          <th className="px-4 py-2.5 text-right">Confidence</th>
                          <th className="px-4 py-2.5 text-center">Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {products.map((p, idx) => (
                          <tr key={p.product_id || p.id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                            <td className="px-4 py-2 font-medium text-foreground">
                              {p.product_name || p.name}
                            </td>
                            <td className="px-4 py-2">
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                                {p.product_category || p.category || "Contraband"}
                              </span>
                            </td>
                            <td className="px-4 py-2 font-mono text-[11px] text-muted-foreground">
                              {p.marketplace_name || "Direct Storefront"}
                            </td>
                            <td className="px-4 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                              {Math.round((p.confidence ?? 1.0) * 100)}%
                            </td>
                            <td className="px-4 py-2 text-center">
                              {p.evidence_quote ? (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                                  onClick={() =>
                                    setEvidenceQuoteModal({
                                      title: p.product_name || p.name,
                                      quote: p.evidence_quote,
                                      context: `Category: ${p.product_category || p.category}`,
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
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 5: RELATIONSHIPS & NETWORK                                       */}
        {/* ==================================================================== */}
        {activeTab === "relationships" && (
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <NetworkIcon className="h-4 w-4 text-muted-foreground" />
                Actor-to-Actor Trust & Graph Relations ({trustLinks.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {trustLinks.length === 0 ? (
                <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                  No verified peer trust or vouching relations recorded for this persona.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                      <tr className="text-left">
                        <th className="px-4 py-2.5">Source Actor</th>
                        <th className="px-4 py-2.5">Relation</th>
                        <th className="px-4 py-2.5">Target Actor</th>
                        <th className="px-4 py-2.5 text-right">Confidence</th>
                        <th className="px-4 py-2.5 text-center">Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {trustLinks.map((rel, idx) => (
                        <tr key={idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                          <td className="px-4 py-2 font-mono font-medium text-foreground">
                            {rel.source_handle || rel.actor_id}
                          </td>
                          <td className="px-4 py-2">
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                              TRUSTS
                            </span>
                          </td>
                          <td className="px-4 py-2 font-mono text-muted-foreground">
                            {rel.target_handle || rel.trusted_actor_id}
                          </td>
                          <td className="px-4 py-2 text-right tabular-nums font-mono text-foreground font-medium">
                            {Math.round((rel.confidence ?? 1.0) * 100)}%
                          </td>
                          <td className="px-4 py-2 text-center">
                            {rel.evidence_quote ? (
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-5 px-1.5 text-[10px] font-mono text-foreground hover:bg-muted/40"
                                onClick={() =>
                                  setEvidenceQuoteModal({
                                    title: `Trust: ${rel.source_handle} ➔ ${rel.target_handle}`,
                                    quote: rel.evidence_quote,
                                    context: "Peer Trust / Escrow Relationship",
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
        )}

        {/* ==================================================================== */}
        {/* TAB 6: ACTIVITIES TIMELINE                                           */}
        {/* ==================================================================== */}
        {activeTab === "activities" && (
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <ActivityIcon className="h-4 w-4 text-muted-foreground" />
                Chronological Behavioral Activity Feed ({activities.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4">
              {activities.length === 0 ? (
                <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                  No chronological operational activities recorded for this actor.
                </div>
              ) : (
                <div className="space-y-3">
                  {activities.map((act, idx) => (
                    <div key={act.id || idx} className="rounded-lg border border-border/60 bg-zinc-950/40 p-3 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                          {act.activity_type}
                        </span>
                        <span className="text-[10px] font-mono text-muted-foreground">
                          {act.created_at ? new Date(act.created_at).toLocaleString() : "Crawl timestamp"}
                        </span>
                      </div>
                      <p className="text-xs text-foreground font-mono">{act.description}</p>
                      {act.evidence_quote && (
                        <blockquote className="text-[10px] italic text-muted-foreground border-l border-border/60 pl-2">
                          "{act.evidence_quote}"
                        </blockquote>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* ==================================================================== */}
        {/* TAB 7: OSINT & CLEARNET                                              */}
        {/* ==================================================================== */}
        {activeTab === "osint" && (
          <div className="space-y-4">
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                    <GlobeIcon className="h-4 w-4 text-muted-foreground" />
                    Clearnet Accounts & OSINT Pivot Leads ({clearnetAccounts.length})
                  </CardTitle>
                  <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] font-mono uppercase text-muted-foreground">
                    Candidate Matches
                  </span>
                </div>
                <CardDescription className="text-xs text-muted-foreground">
                  Clearweb social media and developer profiles discovered through username pivoting. Note: username match alone does not constitute confirmed attribution.
                </CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                {clearnetAccounts.length === 0 ? (
                  <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                    No clearweb OSINT accounts linked to this persona.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs">
                      <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                        <tr className="text-left">
                          <th className="px-4 py-2.5">Platform</th>
                          <th className="px-4 py-2.5">Account Identifier</th>
                          <th className="px-4 py-2.5">Attribution Status</th>
                          <th className="px-4 py-2.5 text-right">Confidence</th>
                          <th className="px-4 py-2.5 text-center">Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {clearnetAccounts.map((ca, idx) => (
                          <tr key={ca.id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                            <td className="px-4 py-2.5 font-bold font-mono text-foreground">
                              {ca.platform}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-[11px] text-foreground">
                              {ca.value}
                            </td>
                            <td className="px-4 py-2.5">
                              <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                                Candidate Match
                              </span>
                            </td>
                            <td className="px-4 py-2.5 text-right tabular-nums font-mono text-foreground font-medium">
                              {Math.round((ca.confidence ?? 0.8) * 100)}%
                            </td>
                            <td className="px-4 py-2.5 text-center">
                              {ca.url && (
                                <a
                                  href={ca.url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="text-[11px] font-mono text-muted-foreground hover:text-foreground underline flex items-center justify-center gap-1"
                                >
                                  Open Profile ↗
                                </a>
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
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 8: STYLOMETRY                                                    */}
        {/* ==================================================================== */}
        {activeTab === "stylometry" && (
          <div className="space-y-4">
            <Card className="border-border/60 bg-card/60">
              <CardHeader className="pb-3 border-b border-border/40">
                <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                  <FlaskConicalIcon className="h-4 w-4 text-muted-foreground" />
                  Stylometric Analysis & Author Profiling ({stylometryFindings.length})
                </CardTitle>
                <CardDescription className="text-xs text-muted-foreground">
                  Linguistic habit evaluation, vocabulary richness, and authorial divergence. (Supporting evidence only, not proof of identity).
                </CardDescription>
              </CardHeader>
              <CardContent className="p-4 space-y-4">
                {stylometryFindings.length === 0 && !actor.stylometry_summary ? (
                  <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                    No stylometric findings recorded for this persona.
                  </div>
                ) : (
                  <>
                    {actor.stylometry_summary && (
                      <div className="rounded-lg border border-border/60 bg-zinc-950/50 p-3.5 space-y-2">
                        <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground block">
                          Stylometric Profile Narrative
                        </span>
                        <p className="text-xs font-mono text-foreground leading-relaxed">
                          {actor.stylometry_summary}
                        </p>
                      </div>
                    )}

                    {stylometryFindings.map((sty, idx) => (
                      <div key={sty.id || idx} className="rounded-lg border border-border/60 bg-zinc-950/40 p-3.5 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                            {sty.assessment || "Linguistic Marker"}
                          </span>
                          {sty.similarity_score != null && (
                            <span className="text-[10px] font-mono text-foreground font-semibold">
                              Δ Similarity Score: {Math.round(sty.similarity_score * 100)}%
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-foreground/90 font-mono">{sty.details || sty.assessment}</p>
                      </div>
                    ))}
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 9: OPSEC FINDINGS                                                */}
        {/* ==================================================================== */}
        {activeTab === "opsec" && (
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <ServerCrashIcon className="h-4 w-4 text-muted-foreground" />
                Operational Security Leaks & Flaws ({opsecFindings.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 space-y-3">
              {opsecFindings.length === 0 ? (
                <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                  No OpSec vulnerabilities flagged for this persona.
                </div>
              ) : (
                opsecFindings.map((op, idx) => (
                  <div key={op.id || idx} className="rounded-lg border border-border/60 bg-zinc-950/40 p-3 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-foreground uppercase">
                        {op.finding_type || "OpSec Leak"}
                      </span>
                      <span className="text-[10px] font-mono text-muted-foreground">
                        Confidence: {Math.round((op.confidence ?? 1.0) * 100)}%
                      </span>
                    </div>
                    <p className="text-xs text-foreground font-medium">{op.description}</p>
                    {op.evidence_quote && (
                      <blockquote className="text-[10px] italic text-muted-foreground border-l-2 border-border/60 pl-2">
                        "{op.evidence_quote}"
                      </blockquote>
                    )}
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        )}

        {/* ==================================================================== */}
        {/* TAB 10: ATTRIBUTION ASSESSMENTS                                      */}
        {/* ==================================================================== */}
        {activeTab === "attribution" && (
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <ShieldCheckIcon className="h-4 w-4 text-muted-foreground" />
                Formal Attribution Statements & Rationales ({assessments.length})
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 space-y-4">
              {assessments.length === 0 ? (
                <div className="py-8 text-center text-xs font-mono text-muted-foreground">
                  No formal attribution statements cataloged for this actor.
                </div>
              ) : (
                assessments.map((aa, idx) => (
                  <div key={aa.id || idx} className="rounded-lg border border-border/60 bg-zinc-950/40 p-3.5 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-mono uppercase text-muted-foreground">
                        Investigation: {aa.investigation_id || "Cross-case"}
                      </span>
                      <span className="text-[10px] font-mono text-foreground font-semibold">
                        Confidence: {Math.round((aa.confidence ?? 1.0) * 100)}%
                      </span>
                    </div>
                    <p className="text-xs text-foreground leading-relaxed font-mono">{aa.assessment}</p>
                    {aa.supporting_evidence && (
                      <div className="text-[10px] font-mono text-foreground/90 bg-muted/20 rounded p-2 border border-border/40">
                        <strong>Supporting:</strong> {aa.supporting_evidence}
                      </div>
                    )}
                    {aa.contradicting_evidence && (
                      <div className="text-[10px] font-mono text-muted-foreground bg-muted/10 rounded p-2 border border-border/30">
                        <strong>Contradicting:</strong> {aa.contradicting_evidence}
                      </div>
                    )}
                  </div>
                ))
              )}
            </CardContent>
          </Card>
        )}

        {/* ==================================================================== */}
        {/* TAB 11: INVESTIGATION HISTORY                                        */}
        {/* ==================================================================== */}
        {activeTab === "investigations" && (
          <Card className="border-border/60 bg-card/60">
            <CardHeader className="pb-3 border-b border-border/40">
              <CardTitle className="text-sm font-semibold tracking-tight text-foreground flex items-center gap-2">
                <ClockIcon className="h-4 w-4 text-muted-foreground" />
                Cross-Case Investigation History ({investigations.length || 1})
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                All investigations where this actor was identified, queried, or attributed.
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                    <tr className="text-left">
                      <th className="px-4 py-2.5">Case ID</th>
                      <th className="px-4 py-2.5">Investigation Query</th>
                      <th className="px-4 py-2.5">Status</th>
                      <th className="px-4 py-2.5 text-center">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {investigations.map((inv, idx) => (
                      <tr key={inv.id || idx} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                        <td className="px-4 py-2.5 font-mono font-medium text-foreground">
                          {inv.id}
                        </td>
                        <td className="px-4 py-2.5 text-foreground truncate max-w-md font-mono text-[11px]">
                          {inv.query || "Darknet Target Crawl"}
                        </td>
                        <td className="px-4 py-2.5">
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground uppercase">
                            {inv.status || "COMPLETED"}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-center">
                          <Link href={`/investigations/${inv.id}`}>
                            <Button size="sm" variant="ghost" className="h-6 px-2 text-xs font-mono text-foreground hover:bg-muted/40">
                              Open Case →
                            </Button>
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

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
    </AppShell>
  );
}
