"use client";

import { useEffect, useState, use } from "react";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  ArrowLeftIcon,
  ShoppingBagIcon,
  UsersIcon,
  GlobeIcon,
  ArchiveIcon,
  ShieldAlertIcon,
  NetworkIcon,
  CopyIcon,
  CheckIcon,
  XIcon,
  ArrowRightIcon,
} from "@/components/icons";

interface ProductDossierData {
  product: {
    id: string;
    name: string;
    category: string;
    created_at: string;
    first_seen: string | null;
    last_seen: string | null;
    epistemic_state: string;
  };
  metrics: {
    observation_count: number;
    actor_count: number;
    marketplace_count: number;
    investigation_count: number;
    avg_confidence: number;
  };
  aliases: string[];
  actors: Array<{
    id: string;
    primary_handle: string;
    category?: string;
    relationship?: string;
    confidence?: number;
    first_seen?: string;
    evidence_quote?: string;
  }>;
  marketplaces: Array<{
    id: string;
    display_name: string;
    onion_domain: string;
    first_seen?: string;
    last_seen?: string;
    observation_count: number;
    associated_actors?: string[];
  }>;
  observations: Array<{
    id: string;
    investigation_id: string;
    name: string;
    category: string;
    marketplace_name?: string;
    onion_url?: string;
    actor_handle?: string;
    evidence_quote?: string;
    confidence?: number;
    price?: string | null;
    quantity?: string | null;
    created_at: string;
  }>;
  pricing: {
    has_pricing: boolean;
    observations: Array<{
      price: string;
      marketplace: string;
      date: string;
      evidence_quote?: string;
      investigation_id?: string;
    }>;
    min_price: number | null;
    max_price: number | null;
    median_price: number | null;
    notes: string;
  };
  quantity: {
    has_quantity: boolean;
    observations: Array<{
      quantity: string;
      marketplace: string;
      date: string;
      evidence_quote?: string;
    }>;
    notes: string;
  };
  evidence: Array<{
    id: string;
    quote_text: string;
    source_url?: string;
    investigation_id?: string;
    confidence?: number;
    created_at?: string;
  }>;
  investigation_history: Array<{
    investigation_id: string;
    investigation_query: string;
    status: string;
    marketplace_name: string;
    actor_handle: string;
    observed_name: string;
    first_seen: string;
    evidence_quote: string;
  }>;
  intelligence_gaps: Array<{
    gap: string;
    priority: string;
    resolution: string;
  }>;
  network_mermaid?: string;
}

export default function ProductDossierPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const [data, setData] = useState<ProductDossierData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<
    | "overview"
    | "actors"
    | "marketplaces"
    | "observations"
    | "pricing"
    | "evidence"
    | "network"
    | "investigations"
    | "gaps"
  >("overview");
  const [quoteModal, setQuoteModal] = useState<string | null>(null);
  const [copiedQuote, setCopiedQuote] = useState(false);

  useEffect(() => {
    fetch(`/api/commodities?id=${encodeURIComponent(id)}`)
      .then(async (r) => {
        if (!r.ok) {
          throw new Error(`Product not found (${r.status})`);
        }
        return r.json();
      })
      .then((d) => {
        if (d.product) {
          setData(d);
        } else if (d.commodities && Array.isArray(d.commodities)) {
          // Fallback if running legacy server
          const comms: any[] = d.commodities;
          const decodedId = decodeURIComponent(id).toLowerCase().trim();
          const matches = comms.filter(
            (c) =>
              c.id === id ||
              (c.name && c.name.toLowerCase().trim() === decodedId) ||
              (c.value && c.value.toLowerCase().trim() === decodedId)
          );
          if (matches.length === 0) {
            throw new Error(`Product not found for ID: ${id}`);
          }
          const primary = matches[0];
          const prodName = primary.name || primary.value;
          const prodCategory = primary.category || primary.type || "COMMODITY";

          const actorsMap = new Map<string, any>();
          const mktsMap = new Map<string, any>();
          const invsMap = new Map<string, any>();
          const priceObs: any[] = [];
          const qtyObs: any[] = [];

          matches.forEach((m) => {
            const h = m.actor_handle;
            if (h && !actorsMap.has(h)) {
              actorsMap.set(h, {
                id: `act_${h.toLowerCase()}`,
                primary_handle: h,
                relationship: "Observed Vendor / Seller",
                confidence: m.confidence || 0.95,
                first_seen: m.created_at || m.first_seen,
                evidence_quote: m.evidence_quote,
              });
            }
            const mkt = m.marketplace_name;
            if (mkt && !mktsMap.has(mkt)) {
              mktsMap.set(mkt, {
                id: `mkt_${mktsMap.size}`,
                display_name: mkt,
                onion_domain: m.page_url || m.onion_url || "—",
                first_seen: m.created_at || m.first_seen,
                last_seen: m.created_at || m.first_seen,
                observation_count: 1,
                associated_actors: h ? [h] : [],
              });
            }
            const inv = m.investigation_id;
            if (inv && !invsMap.has(inv)) {
              invsMap.set(inv, {
                investigation_id: inv,
                investigation_query: "Ad-hoc crawl",
                status: "COMPLETED",
                marketplace_name: mkt || "—",
                actor_handle: h || "—",
                observed_name: prodName,
                first_seen: m.created_at || m.first_seen,
                evidence_quote: m.evidence_quote || "—",
              });
            }

            const q = m.evidence_quote || "";
            const pm = q.match(/(?:[$€£]|USD|EUR|BTC)\s*[\d,]+(?:\.\d+)?|[\d,]+(?:\.\d+)?\s*(?:USD|EUR|BTC)/i);
            if (pm) {
              priceObs.push({
                price: pm[0].trim(),
                marketplace: mkt || "Darknet Market",
                date: m.created_at || m.first_seen,
                evidence_quote: q,
              });
            }
            const qm = q.match(/\b\d+\s*(?:x|gr|g|mg|kg|pills?|items?|units?|records?|cards?|pieces?|pcs)\b/i);
            if (qm) {
              qtyObs.push({
                quantity: qm[0].trim(),
                marketplace: mkt || "Darknet Market",
                date: m.created_at || m.first_seen,
                evidence_quote: q,
              });
            }
          });

          const synthesizedDossier: ProductDossierData = {
            product: {
              id: primary.id,
              name: prodName,
              category: prodCategory,
              created_at: primary.created_at || new Date().toISOString(),
              first_seen: matches[0].created_at || null,
              last_seen: matches[matches.length - 1].created_at || null,
              epistemic_state: mktsMap.size > 1 ? "Multiple-source observation" : actorsMap.size > 0 ? "Associated" : "Observed",
            },
            metrics: {
              observation_count: matches.length,
              actor_count: actorsMap.size,
              marketplace_count: mktsMap.size,
              investigation_count: invsMap.size || 1,
              avg_confidence: primary.confidence || 0.95,
            },
            aliases: [],
            actors: Array.from(actorsMap.values()),
            marketplaces: Array.from(mktsMap.values()),
            observations: matches.map((m) => ({
              id: m.id,
              investigation_id: m.investigation_id || "inv_historical",
              name: m.name || m.value,
              category: m.category || m.type,
              marketplace_name: m.marketplace_name,
              onion_url: m.onion_url || m.page_url,
              actor_handle: m.actor_handle,
              evidence_quote: m.evidence_quote,
              confidence: m.confidence || 0.95,
              price: null,
              quantity: null,
              created_at: m.created_at || m.first_seen || new Date().toISOString(),
            })),
            pricing: {
              has_pricing: priceObs.length > 0,
              observations: priceObs,
              min_price: null,
              max_price: null,
              median_price: null,
              notes: priceObs.length > 0 ? "Prices observed from darknet listing quotes." : "No pricing recorded.",
            },
            quantity: {
              has_quantity: qtyObs.length > 0,
              observations: qtyObs,
              notes: qtyObs.length > 0 ? "Extracted from listing quote." : "Not observed",
            },
            evidence: matches
              .filter((m) => m.evidence_quote)
              .map((m) => ({
                id: `eq_${m.id}`,
                quote_text: m.evidence_quote,
                source_url: m.onion_url || m.page_url,
                investigation_id: m.investigation_id,
                confidence: m.confidence || 0.95,
                created_at: m.created_at,
              })),
            investigation_history: Array.from(invsMap.values()),
            intelligence_gaps: [
              {
                gap: "Vendor identity unverified across secondary platforms.",
                priority: "MEDIUM",
                resolution: "Correlate PGP key fingerprints or payment addresses.",
              },
            ],
            network_mermaid: `graph LR\n    P["Product: ${prodName.slice(0, 20)}"]`,
          };

          setData(synthesizedDossier);
        } else {
          throw new Error("No data returned from commodities endpoint");
        }
      })
      .catch((err) => {
        console.error("Failed to load product dossier:", err);
        setError(err.message || "Failed to load product");
      })
      .finally(() => setLoading(false));
  }, [id]);

  const copyText = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedQuote(true);
    setTimeout(() => setCopiedQuote(false), 1500);
  };

  if (loading) {
    return (
      <AppShell>
        <div className="flex h-96 items-center justify-center">
          <div className="space-y-3 text-center">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-foreground border-t-transparent mx-auto" />
            <p className="text-xs font-mono text-muted-foreground tracking-wide">
              HYDRATING PRODUCT INTELLIGENCE DOSSIER...
            </p>
          </div>
        </div>
      </AppShell>
    );
  }

  if (error || !data?.product) {
    return (
      <AppShell>
        <div className="p-12 text-center text-muted-foreground space-y-4">
          <p className="text-base font-mono text-foreground">Product Dossier Not Found</p>
          <p className="text-xs font-mono">{error || `No product record found for ID: ${id}`}</p>
          <div>
            <Link href="/commodities">
              <Button size="sm" variant="outline" className="font-mono text-xs">
                ← Return to Product Catalog
              </Button>
            </Link>
          </div>
        </div>
      </AppShell>
    );
  }

  const { product, metrics, aliases, actors, marketplaces, observations, pricing, quantity, evidence, investigation_history, intelligence_gaps, network_mermaid } = data;
  const confPct = Math.round((metrics.avg_confidence ?? 1.0) * 100);

  return (
    <AppShell>
      <div className="w-full min-w-0 max-w-full space-y-6 font-sans">
        {/* ==================================================================== */}
        {/* PRODUCT DOSSIER HERO                                                 */}
        {/* ==================================================================== */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5 font-mono text-[10px]">
              <span className="tracking-widest text-muted-foreground uppercase">Product Intelligence</span>
              <span className="text-muted-foreground/40 text-xs">/</span>
              <span className="text-foreground font-medium">{product.id}</span>
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-foreground font-mono">
                {product.name}
              </h1>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] font-mono uppercase text-muted-foreground">
                {product.category || "Unclassified"}
              </span>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded border border-border/60 bg-zinc-900 text-[10px] font-mono text-zinc-300">
                {product.epistemic_state}
              </span>
            </div>
            <div className="text-xs text-muted-foreground mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono">
              <span>Attribution Confidence: <strong className="text-foreground tabular-nums">{confPct}%</strong></span>
              <span className="text-muted-foreground/30">•</span>
              <span>First Seen: {product.first_seen ? new Date(product.first_seen).toLocaleDateString() : "Historical Ingest"}</span>
              <span className="text-muted-foreground/30">•</span>
              <span>Last Observed: {product.last_seen ? new Date(product.last_seen).toLocaleDateString() : "Current Cycle"}</span>
            </div>
          </div>

          <div className="flex gap-2 items-center flex-wrap">
            <Link href="/commodities">
              <Button size="sm" variant="outline" className="border-border/80 text-foreground hover:bg-muted/40 font-mono text-xs">
                <ArrowLeftIcon className="h-3 w-3 mr-1.5" />
                Product Catalog
              </Button>
            </Link>
            <Link href={`/graph?highlight=${encodeURIComponent(product.id)}`}>
              <Button size="sm" className="bg-foreground text-background hover:bg-foreground/90 font-mono text-xs font-semibold gap-1.5">
                <NetworkIcon className="h-3.5 w-3.5" />
                Open in Graph →
              </Button>
            </Link>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* SUMMARY METRICS BENTO                                                */}
        {/* ==================================================================== */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Observations</span>
                <ArchiveIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.observation_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Extracted listings</p>
            </CardContent>
          </Card>

          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Associated Actors</span>
                <UsersIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.actor_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Vendors & sellers</p>
            </CardContent>
          </Card>

          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Marketplaces</span>
                <GlobeIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.marketplace_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Darknet markets</p>
            </CardContent>
          </Card>

          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Investigations</span>
                <ShieldAlertIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.investigation_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Case appearances</p>
            </CardContent>
          </Card>

          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Pricing Signals</span>
                <ShoppingBagIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {pricing.has_pricing ? pricing.observations.length : 0}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Quoted price records</p>
            </CardContent>
          </Card>
        </div>

        {/* ==================================================================== */}
        {/* SUB-NAVIGATION TABS                                                  */}
        {/* ==================================================================== */}
        <div className="flex items-center gap-1 border-b border-border/40 overflow-x-auto pb-px font-mono text-xs">
          {[
            { id: "overview", label: "Overview" },
            { id: "actors", label: `Actors (${actors.length})` },
            { id: "marketplaces", label: `Marketplaces (${marketplaces.length})` },
            { id: "observations", label: `Observations (${observations.length})` },
            { id: "pricing", label: `Pricing & Quantity` },
            { id: "evidence", label: `Evidence (${evidence.length})` },
            { id: "network", label: `Network` },
            { id: "investigations", label: `Investigations (${investigation_history.length})` },
            { id: "gaps", label: `Gaps (${intelligence_gaps.length})` },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-2 border-b-2 font-medium transition-colors whitespace-nowrap ${
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
        {/* TAB 1: OVERVIEW                                                      */}
        {/* ==================================================================== */}
        {activeTab === "overview" && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="rounded-xl border border-border/60 bg-card/60 p-4 space-y-3 font-mono">
                <h3 className="text-xs uppercase tracking-wider font-semibold text-muted-foreground">
                  Product Identity & Normalization
                </h3>
                <div className="space-y-2 text-xs divide-y divide-border/30">
                  <div className="pt-2 flex justify-between">
                    <span className="text-muted-foreground">Canonical Product Name</span>
                    <span className="font-semibold text-foreground">{product.name}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-muted-foreground">Normalized Category</span>
                    <span className="text-foreground">{product.category}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-muted-foreground">Internal Product ID</span>
                    <span className="text-foreground">{product.id}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-muted-foreground">Epistemic State</span>
                    <span className="text-foreground">{product.epistemic_state}</span>
                  </div>
                  <div className="pt-2 flex justify-between">
                    <span className="text-muted-foreground">Attribution Confidence</span>
                    <span className="text-foreground tabular-nums">{confPct}%</span>
                  </div>
                </div>
              </div>

              <div className="rounded-xl border border-border/60 bg-card/60 p-4 space-y-3 font-mono">
                <h3 className="text-xs uppercase tracking-wider font-semibold text-muted-foreground">
                  Observed Title Variations / Aliases ({aliases.length})
                </h3>
                {aliases.length === 0 ? (
                  <p className="text-xs text-muted-foreground italic">
                    No alternate listing aliases recorded. All appearances matched canonical title verbatim.
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {aliases.map((al, idx) => (
                      <div
                        key={idx}
                        className="px-2.5 py-1.5 rounded border border-border/40 bg-zinc-950/60 text-xs text-foreground flex items-center justify-between"
                      >
                        <span className="truncate">{al}</span>
                        <span className="text-[10px] text-muted-foreground uppercase">Extracted Variant</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Quick Cross-Section Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="rounded-xl border border-border/60 bg-card/60 p-4 space-y-2 font-mono">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-foreground">Associated Vendors</h4>
                  <span className="text-[10px] text-muted-foreground">{actors.length} known</span>
                </div>
                <div className="space-y-1">
                  {actors.slice(0, 3).map((a) => (
                    <div key={a.id} className="text-xs flex justify-between py-1 border-b border-border/20">
                      <Link href={`/actors/${a.id}`} className="text-foreground hover:underline truncate max-w-[150px]">
                        {a.primary_handle}
                      </Link>
                      <span className="text-muted-foreground text-[10px]">{a.relationship || "Vendor"}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-xl border border-border/60 bg-card/60 p-4 space-y-2 font-mono">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-foreground">Market Distribution</h4>
                  <span className="text-[10px] text-muted-foreground">{marketplaces.length} platforms</span>
                </div>
                <div className="space-y-1">
                  {marketplaces.slice(0, 3).map((m) => (
                    <div key={m.id} className="text-xs flex justify-between py-1 border-b border-border/20">
                      <span className="text-foreground truncate max-w-[150px]">{m.display_name}</span>
                      <span className="text-muted-foreground text-[10px] tabular-nums">{m.observation_count} obs</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-xl border border-border/60 bg-card/60 p-4 space-y-2 font-mono">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-foreground">Case Provenance</h4>
                  <span className="text-[10px] text-muted-foreground">{investigation_history.length} cases</span>
                </div>
                <div className="space-y-1">
                  {investigation_history.slice(0, 3).map((ih) => (
                    <div key={ih.investigation_id} className="text-xs flex justify-between py-1 border-b border-border/20">
                      <Link href={`/investigations/${ih.investigation_id}`} className="text-foreground hover:underline">
                        {ih.investigation_id}
                      </Link>
                      <span className="text-muted-foreground text-[10px]">{ih.status}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 2: ACTORS / VENDORS                                              */}
        {/* ==================================================================== */}
        {activeTab === "actors" && (
          <div className="space-y-4">
            <div className="flex justify-between items-center text-xs font-mono text-muted-foreground">
              <span>Known vendor/seller associations supported by crawl observations or attribution links.</span>
              <span>{actors.length} Actor{actors.length !== 1 ? "s" : ""}</span>
            </div>

            {actors.length === 0 ? (
              <div className="rounded-xl border border-border/40 bg-card/40 p-8 text-center text-xs font-mono text-muted-foreground">
                No threat actor or vendor associations established for this product.
              </div>
            ) : (
              <div className="rounded-xl border border-border/60 bg-card/60 overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono">
                    <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground text-[10px] uppercase tracking-wider">
                      <tr className="text-left">
                        <th className="px-4 py-3">Actor / Handle</th>
                        <th className="px-4 py-3">Relationship Type</th>
                        <th className="px-4 py-3">Confidence</th>
                        <th className="px-4 py-3">First Seen</th>
                        <th className="px-4 py-3">Evidence Quotation</th>
                        <th className="px-4 py-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/30">
                      {actors.map((a) => {
                        const actConf = Math.round(((a.confidence ?? 1.0)) * 100);
                        return (
                          <tr key={a.id} className="hover:bg-muted/20 transition-colors">
                            <td className="px-4 py-3">
                              <Link href={`/actors/${a.id}`} className="font-bold text-foreground hover:underline block">
                                {a.primary_handle}
                              </Link>
                              <span className="text-[10px] text-muted-foreground block">{a.id}</span>
                            </td>

                            <td className="px-4 py-3">
                              <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] uppercase text-muted-foreground">
                                {a.relationship || "Observed Vendor"}
                              </span>
                            </td>

                            <td className="px-4 py-3 tabular-nums font-semibold text-foreground">
                              {actConf}%
                            </td>

                            <td className="px-4 py-3 text-muted-foreground text-[11px] whitespace-nowrap">
                              {a.first_seen ? new Date(a.first_seen).toLocaleDateString() : "—"}
                            </td>

                            <td className="px-4 py-3 max-w-[280px]">
                              {a.evidence_quote ? (
                                <button
                                  type="button"
                                  onClick={() => setQuoteModal(a.evidence_quote!)}
                                  className="text-left text-zinc-400 hover:text-foreground italic truncate block w-full text-[11px]"
                                  title={a.evidence_quote}
                                >
                                  &ldquo;{a.evidence_quote}&rdquo;
                                </button>
                              ) : (
                                <span className="text-muted-foreground/40 italic">No quote captured</span>
                              )}
                            </td>

                            <td className="px-4 py-3 text-right">
                              <Link href={`/actors/${a.id}`}>
                                <Button size="sm" variant="ghost" className="h-7 px-2 text-xs font-mono gap-1 hover:bg-muted/40">
                                  Dossier
                                  <ArrowRightIcon className="h-3 w-3 text-muted-foreground" />
                                </Button>
                              </Link>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 3: MARKETPLACES                                                  */}
        {/* ==================================================================== */}
        {activeTab === "marketplaces" && (
          <div className="space-y-4">
            <div className="flex justify-between items-center text-xs font-mono text-muted-foreground">
              <span>Darknet platforms hosting listings for this commodity.</span>
              <span>{marketplaces.length} Platform{marketplaces.length !== 1 ? "s" : ""}</span>
            </div>

            {marketplaces.length === 0 ? (
              <div className="rounded-xl border border-border/40 bg-card/40 p-8 text-center text-xs font-mono text-muted-foreground">
                No marketplace host records available.
              </div>
            ) : (
              <div className="rounded-xl border border-border/60 bg-card/60 overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono">
                    <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground text-[10px] uppercase tracking-wider">
                      <tr className="text-left">
                        <th className="px-4 py-3">Marketplace Name</th>
                        <th className="px-4 py-3">Onion Domain</th>
                        <th className="px-4 py-3 text-right">Observations</th>
                        <th className="px-4 py-3">Associated Vendors</th>
                        <th className="px-4 py-3">First Seen</th>
                        <th className="px-4 py-3">Last Seen</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/30">
                      {marketplaces.map((m) => (
                        <tr key={m.id} className="hover:bg-muted/20 transition-colors">
                          <td className="px-4 py-3 font-bold text-foreground">
                            {m.display_name}
                          </td>

                          <td className="px-4 py-3 text-muted-foreground truncate max-w-[200px]" title={m.onion_domain}>
                            {m.onion_domain}
                          </td>

                          <td className="px-4 py-3 text-right">
                            <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/40 bg-zinc-900/60 text-[11px] tabular-nums font-bold text-foreground">
                              {m.observation_count}
                            </span>
                          </td>

                          <td className="px-4 py-3 text-foreground">
                            {m.associated_actors && m.associated_actors.length > 0 ? (
                              <span className="truncate block max-w-[180px]">
                                {m.associated_actors.join(", ")}
                              </span>
                            ) : (
                              <span className="text-muted-foreground/50">—</span>
                            )}
                          </td>

                          <td className="px-4 py-3 text-muted-foreground text-[11px] whitespace-nowrap">
                            {m.first_seen ? new Date(m.first_seen).toLocaleDateString() : "—"}
                          </td>

                          <td className="px-4 py-3 text-muted-foreground text-[11px] whitespace-nowrap">
                            {m.last_seen ? new Date(m.last_seen).toLocaleDateString() : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 4: OBSERVATIONS / LISTINGS                                       */}
        {/* ==================================================================== */}
        {activeTab === "observations" && (
          <div className="space-y-4">
            <div className="flex justify-between items-center text-xs font-mono text-muted-foreground">
              <span>Extracted source-level listings preserving original titles, prices, and quotations.</span>
              <span>{observations.length} Listing{observations.length !== 1 ? "s" : ""}</span>
            </div>

            <div className="rounded-xl border border-border/60 bg-card/60 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground text-[10px] uppercase tracking-wider">
                    <tr className="text-left">
                      <th className="px-4 py-3">Date</th>
                      <th className="px-4 py-3">Marketplace</th>
                      <th className="px-4 py-3">Actor / Handle</th>
                      <th className="px-4 py-3">Extracted Title</th>
                      <th className="px-4 py-3">Price</th>
                      <th className="px-4 py-3">Quantity</th>
                      <th className="px-4 py-3">Case</th>
                      <th className="px-4 py-3 text-right">Evidence Quote</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/30">
                    {observations.map((obs) => (
                      <tr key={obs.id} className="hover:bg-muted/20 transition-colors">
                        <td className="px-4 py-3 text-muted-foreground whitespace-nowrap text-[11px]">
                          {obs.created_at ? new Date(obs.created_at).toLocaleDateString() : "—"}
                        </td>

                        <td className="px-4 py-3 text-foreground font-medium truncate max-w-[140px]" title={obs.marketplace_name}>
                          {obs.marketplace_name || "—"}
                        </td>

                        <td className="px-4 py-3 text-foreground truncate max-w-[120px]">
                          {obs.actor_handle || "—"}
                        </td>

                        <td className="px-4 py-3 text-zinc-300 truncate max-w-[180px]" title={obs.name}>
                          {obs.name}
                        </td>

                        <td className="px-4 py-3 font-semibold text-foreground whitespace-nowrap">
                          {obs.price || <span className="text-muted-foreground/40 font-normal">—</span>}
                        </td>

                        <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                          {obs.quantity || <span className="text-muted-foreground/40">—</span>}
                        </td>

                        <td className="px-4 py-3 whitespace-nowrap">
                          {obs.investigation_id ? (
                            <Link href={`/investigations/${obs.investigation_id}`} className="text-foreground hover:underline">
                              {obs.investigation_id}
                            </Link>
                          ) : (
                            <span className="text-muted-foreground/40">—</span>
                          )}
                        </td>

                        <td className="px-4 py-3 text-right">
                          {obs.evidence_quote ? (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => setQuoteModal(obs.evidence_quote!)}
                              className="h-6 px-2 text-[11px] font-mono text-muted-foreground hover:text-foreground hover:bg-muted/40"
                            >
                              View Quote
                            </Button>
                          ) : (
                            <span className="text-muted-foreground/40 text-[11px]">—</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 5: PRICING & QUANTITY                                            */}
        {/* ==================================================================== */}
        {activeTab === "pricing" && (
          <div className="space-y-6">
            {/* Pricing Section */}
            <div className="rounded-xl border border-border/60 bg-card/60 p-5 space-y-4 font-mono">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <div>
                  <h3 className="text-sm font-bold text-foreground">Pricing Intelligence</h3>
                  <p className="text-xs text-muted-foreground mt-0.5">{pricing.notes}</p>
                </div>
                <span className="text-xs font-semibold px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-muted-foreground">
                  {pricing.has_pricing ? `${pricing.observations.length} Observed Quote(s)` : "No Pricing Observed"}
                </span>
              </div>

              {pricing.has_pricing && (
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 rounded-lg border border-border/40 bg-zinc-950/60 space-y-1">
                    <span className="text-[10px] text-muted-foreground uppercase">Min Observed Price</span>
                    <p className="text-lg font-bold text-foreground tabular-nums">
                      {pricing.min_price !== null ? `$${pricing.min_price.toFixed(2)}` : "—"}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg border border-border/40 bg-zinc-950/60 space-y-1">
                    <span className="text-[10px] text-muted-foreground uppercase">Median Observed Price</span>
                    <p className="text-lg font-bold text-foreground tabular-nums">
                      {pricing.median_price !== null ? `$${pricing.median_price.toFixed(2)}` : "—"}
                    </p>
                  </div>
                  <div className="p-3 rounded-lg border border-border/40 bg-zinc-950/60 space-y-1">
                    <span className="text-[10px] text-muted-foreground uppercase">Max Observed Price</span>
                    <p className="text-lg font-bold text-foreground tabular-nums">
                      {pricing.max_price !== null ? `$${pricing.max_price.toFixed(2)}` : "—"}
                    </p>
                  </div>
                </div>
              )}

              {pricing.observations.length > 0 ? (
                <div className="space-y-2 pt-2">
                  <h4 className="text-xs font-semibold text-muted-foreground uppercase">Extracted Price Quotes</h4>
                  <div className="divide-y divide-border/20 border border-border/40 rounded-lg overflow-hidden bg-zinc-950/40">
                    {pricing.observations.map((po, idx) => (
                      <div key={idx} className="p-3 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="space-y-0.5">
                          <span className="text-foreground font-bold text-sm tabular-nums">{po.price}</span>
                          <span className="text-muted-foreground text-[11px] block">{po.marketplace}</span>
                        </div>
                        {po.evidence_quote && (
                          <button
                            type="button"
                            onClick={() => setQuoteModal(po.evidence_quote!)}
                            className="text-left text-xs text-zinc-400 italic hover:text-foreground truncate max-w-md"
                          >
                            &ldquo;{po.evidence_quote}&rdquo;
                          </button>
                        )}
                        <span className="text-[11px] text-muted-foreground whitespace-nowrap">
                          {po.date ? new Date(po.date).toLocaleDateString() : ""}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <p className="text-xs text-muted-foreground italic">
                  No direct price figures parsed from evidence snippets for this commodity.
                </p>
              )}
            </div>

            {/* Quantity Section */}
            <div className="rounded-xl border border-border/60 bg-card/60 p-5 space-y-4 font-mono">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <div>
                  <h3 className="text-sm font-bold text-foreground">Quantity & Availability</h3>
                  <p className="text-xs text-muted-foreground mt-0.5">{quantity.notes}</p>
                </div>
                <span className="text-xs font-semibold px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-muted-foreground">
                  {quantity.has_quantity ? `${quantity.observations.length} Extracted Batch(es)` : "Not Observed"}
                </span>
              </div>

              {quantity.observations.length > 0 ? (
                <div className="space-y-2">
                  {quantity.observations.map((qo, idx) => (
                    <div key={idx} className="p-3 rounded-lg border border-border/40 bg-zinc-950/60 text-xs flex justify-between items-center">
                      <div>
                        <span className="font-bold text-foreground">{qo.quantity}</span>
                        <span className="text-muted-foreground text-[11px] block">{qo.marketplace}</span>
                      </div>
                      {qo.evidence_quote && (
                        <button
                          type="button"
                          onClick={() => setQuoteModal(qo.evidence_quote!)}
                          className="text-xs text-zinc-400 italic hover:text-foreground truncate max-w-sm"
                        >
                          &ldquo;{qo.evidence_quote}&rdquo;
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground italic">
                  No unit specifications, minimum order counts, or batch counts explicitly parsed.
                </p>
              )}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 6: EVIDENCE                                                      */}
        {/* ==================================================================== */}
        {activeTab === "evidence" && (
          <div className="space-y-4">
            <div className="flex justify-between items-center text-xs font-mono text-muted-foreground">
              <span>Forensic evidence quotations grounding product existence and marketplace presence.</span>
              <span>{evidence.length} Quote{evidence.length !== 1 ? "s" : ""}</span>
            </div>

            {evidence.length === 0 ? (
              <div className="rounded-xl border border-border/40 bg-card/40 p-8 text-center text-xs font-mono text-muted-foreground">
                No verbatim evidence quotes indexed for this product.
              </div>
            ) : (
              <div className="space-y-3 font-mono">
                {evidence.map((ev) => (
                  <div
                    key={ev.id}
                    className="rounded-xl border border-border/60 bg-card/60 p-4 space-y-3"
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div className="space-y-1">
                        <span className="text-[10px] text-muted-foreground uppercase tracking-wider block">
                          Verbatim Darknet Listing Snippet
                        </span>
                        <p className="text-xs text-foreground italic bg-zinc-950/60 p-3 rounded border border-border/40 font-serif">
                          &ldquo;{ev.quote_text}&rdquo;
                        </p>
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => copyText(ev.quote_text)}
                        className="h-7 text-xs font-mono gap-1 shrink-0"
                      >
                        {copiedQuote ? <CheckIcon className="h-3.5 w-3.5" /> : <CopyIcon className="h-3.5 w-3.5" />}
                        Copy
                      </Button>
                    </div>

                    <div className="flex flex-wrap items-center justify-between text-[11px] text-muted-foreground pt-2 border-t border-border/30 gap-2">
                      <div className="flex items-center gap-3">
                        {ev.investigation_id && (
                          <Link href={`/investigations/${ev.investigation_id}`} className="hover:underline text-foreground">
                            Investigation: {ev.investigation_id}
                          </Link>
                        )}
                        {ev.confidence !== undefined && (
                          <span>Confidence: <strong className="text-foreground">{Math.round(ev.confidence * 100)}%</strong></span>
                        )}
                      </div>
                      {ev.source_url && (
                        <span className="truncate max-w-sm text-zinc-400" title={ev.source_url}>
                          {ev.source_url}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 7: NETWORK                                                       */}
        {/* ==================================================================== */}
        {activeTab === "network" && (
          <div className="space-y-4">
            <div className="flex justify-between items-center text-xs font-mono text-muted-foreground">
              <span>Compact product-centered ego-network connecting vendors, markets, and cases.</span>
              <Link href={`/graph?highlight=${encodeURIComponent(product.id)}`}>
                <Button size="sm" variant="outline" className="h-7 text-xs font-mono gap-1">
                  Open Global Graph →
                </Button>
              </Link>
            </div>

            <div className="rounded-xl border border-border/60 bg-card/60 p-6 space-y-4 font-mono">
              <div className="bg-zinc-950 p-4 rounded-lg border border-border/40 text-xs overflow-x-auto text-zinc-300">
                <pre className="text-[11px] leading-relaxed">
                  {network_mermaid || "graph LR\n    P[Product]"}
                </pre>
              </div>

              <div className="text-xs text-muted-foreground space-y-1">
                <p>
                  • <strong>SELLS:</strong> Threat actor observed listing or advertising this commodity.
                </p>
                <p>
                  • <strong>LISTED_ON:</strong> Marketplace onion host where commodity page was indexed.
                </p>
                <p>
                  • <strong>OBSERVED:</strong> Investigation crawl cycle that extracted the listing evidence.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 8: INVESTIGATION HISTORY                                         */}
        {/* ==================================================================== */}
        {activeTab === "investigations" && (
          <div className="space-y-4">
            <div className="flex justify-between items-center text-xs font-mono text-muted-foreground">
              <span>Temporal case occurrences documenting where Jane has encountered this commodity.</span>
              <span>{investigation_history.length} Appearance{investigation_history.length !== 1 ? "s" : ""}</span>
            </div>

            <div className="rounded-xl border border-border/60 bg-card/60 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground text-[10px] uppercase tracking-wider">
                    <tr className="text-left">
                      <th className="px-4 py-3">Investigation ID</th>
                      <th className="px-4 py-3">Query Goal</th>
                      <th className="px-4 py-3">Marketplace</th>
                      <th className="px-4 py-3">Observed Vendor</th>
                      <th className="px-4 py-3">First Seen</th>
                      <th className="px-4 py-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/30">
                    {investigation_history.map((ih) => (
                      <tr key={ih.investigation_id} className="hover:bg-muted/20 transition-colors">
                        <td className="px-4 py-3 font-bold text-foreground">
                          <Link href={`/investigations/${ih.investigation_id}`} className="hover:underline">
                            {ih.investigation_id}
                          </Link>
                        </td>

                        <td className="px-4 py-3 text-zinc-300 max-w-[220px] truncate" title={ih.investigation_query}>
                          {ih.investigation_query}
                        </td>

                        <td className="px-4 py-3 text-foreground truncate max-w-[150px]">
                          {ih.marketplace_name}
                        </td>

                        <td className="px-4 py-3 text-muted-foreground">
                          {ih.actor_handle}
                        </td>

                        <td className="px-4 py-3 text-muted-foreground text-[11px] whitespace-nowrap">
                          {ih.first_seen ? new Date(ih.first_seen).toLocaleDateString() : "—"}
                        </td>

                        <td className="px-4 py-3 text-right">
                          <Link href={`/investigations/${ih.investigation_id}`}>
                            <Button size="sm" variant="ghost" className="h-7 px-2 text-xs font-mono gap-1 hover:bg-muted/40">
                              Open Case
                              <ArrowRightIcon className="h-3 w-3 text-muted-foreground" />
                            </Button>
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 9: INTELLIGENCE GAPS                                             */}
        {/* ==================================================================== */}
        {activeTab === "gaps" && (
          <div className="space-y-4">
            <div className="flex justify-between items-center text-xs font-mono text-muted-foreground">
              <span>Analytical gaps highlighting unverified attributions, missing price units, or single-source observations.</span>
              <span>{intelligence_gaps.length} Identified Gap{intelligence_gaps.length !== 1 ? "s" : ""}</span>
            </div>

            <div className="space-y-3 font-mono">
              {intelligence_gaps.map((gap, idx) => (
                <div key={idx} className="rounded-xl border border-border/60 bg-card/60 p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-foreground">Gap #{idx + 1}: {gap.gap}</span>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                      gap.priority === "HIGH"
                        ? "border-red-500/40 text-red-400 bg-red-950/20"
                        : gap.priority === "MEDIUM"
                        ? "border-yellow-500/40 text-yellow-400 bg-yellow-950/20"
                        : "border-border/60 text-muted-foreground bg-muted/20"
                    }`}>
                      {gap.priority} PRIORITY
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground pt-1 border-t border-border/30">
                    <strong className="text-foreground">Required Resolution Evidence:</strong> {gap.resolution}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* VERBATIM QUOTE VIEWER MODAL                                          */}
        {/* ==================================================================== */}
        {quoteModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 font-mono">
            <div className="relative w-full max-w-xl rounded-xl border border-border bg-card p-6 shadow-2xl space-y-4 animate-in fade-in-0 zoom-in-95">
              <div className="flex items-center justify-between border-b border-border/40 pb-3">
                <span className="text-xs uppercase tracking-wider font-bold text-foreground">
                  Forensic Quotation Viewer
                </span>
                <button
                  type="button"
                  onClick={() => setQuoteModal(null)}
                  className="rounded-md p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                >
                  <XIcon className="h-4 w-4" />
                </button>
              </div>

              <div className="rounded-lg border border-border/60 bg-zinc-950 p-4 text-xs font-serif italic text-foreground leading-relaxed">
                &ldquo;{quoteModal}&rdquo;
              </div>

              <div className="flex justify-between items-center pt-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => copyText(quoteModal)}
                  className="h-8 text-xs font-mono gap-1.5"
                >
                  {copiedQuote ? <CheckIcon className="h-3.5 w-3.5" /> : <CopyIcon className="h-3.5 w-3.5" />}
                  {copiedQuote ? "Copied" : "Copy Verbatim Text"}
                </Button>
                <Button
                  size="sm"
                  variant="default"
                  onClick={() => setQuoteModal(null)}
                  className="h-8 text-xs font-mono"
                >
                  Close
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
