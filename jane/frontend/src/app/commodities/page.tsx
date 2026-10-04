"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  SearchIcon,
  ShoppingBagIcon,
  UsersIcon,
  GlobeIcon,
  ArchiveIcon,
  ArrowRightIcon,
  ShieldAlertIcon,
} from "@/components/icons";

interface ProductCatalogItem {
  id: string;
  name: string;
  category: string;
  actor_count: number;
  actor_handles: string[];
  marketplace_count: number;
  marketplaces: string[];
  observation_count: number;
  investigation_count: number;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string;
}

interface SummaryMetrics {
  products_count: number;
  observations_count: number;
  actors_count: number;
  marketplaces_count: number;
  investigations_count: number;
}

export default function ProductIntelligencePage() {
  const [products, setProducts] = useState<ProductCatalogItem[]>([]);
  const [metrics, setMetrics] = useState<SummaryMetrics>({
    products_count: 0,
    observations_count: 0,
    actors_count: 0,
    marketplaces_count: 0,
    investigations_count: 0,
  });
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [selectedMarket, setSelectedMarket] = useState<string>("ALL");
  const [selectedActor, setSelectedActor] = useState<string>("ALL");
  const [sortBy, setSortBy] = useState<"observations" | "actors" | "markets" | "name" | "recent">("observations");
  const [viewMode, setViewMode] = useState<"table" | "grid">("table");
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  useEffect(() => {
    fetch("/api/commodities")
      .then((r) => r.json())
      .then((data) => {
        if (data.products && Array.isArray(data.products) && data.products.length > 0) {
          setProducts(data.products);
          if (data.metrics) setMetrics(data.metrics);
        } else if (data.commodities && Array.isArray(data.commodities) && data.commodities.length > 0) {
          const comms: any[] = data.commodities;
          const byName = new Map<string, any>();
          comms.forEach((c) => {
            const rawName = c.name || c.value || "Unnamed Commodity";
            const normKey = rawName.trim().toLowerCase();
            const existing = byName.get(normKey);
            const mkt = c.marketplace_name || "Darknet Marketplace";
            const actor = c.actor_handle || "";
            const inv = c.investigation_id || "";
            const dt = c.created_at || c.first_seen || new Date().toISOString();
            if (!existing) {
              byName.set(normKey, {
                id: c.id,
                name: rawName,
                category: c.category || c.type || "COMMODITY",
                actor_count: actor ? 1 : 0,
                actor_handles: actor ? [actor] : [],
                marketplace_count: 1,
                marketplaces: [mkt],
                observation_count: 1,
                investigation_count: inv ? 1 : 0,
                first_seen: dt,
                last_seen: dt,
                created_at: dt,
              });
            } else {
              existing.observation_count += 1;
              if (actor && !existing.actor_handles.includes(actor)) {
                existing.actor_handles.push(actor);
                existing.actor_count = existing.actor_handles.length;
              }
              if (mkt && !existing.marketplaces.includes(mkt)) {
                existing.marketplaces.push(mkt);
                existing.marketplace_count = existing.marketplaces.length;
              }
              if (dt < existing.first_seen) existing.first_seen = dt;
              if (dt > existing.last_seen) existing.last_seen = dt;
            }
          });
          const synthesized = Array.from(byName.values());
          setProducts(synthesized);
          const allActors = new Set<string>();
          const allMkts = new Set<string>();
          synthesized.forEach((p) => {
            p.actor_handles.forEach((a: string) => allActors.add(a));
            p.marketplaces.forEach((m: string) => allMkts.add(m));
          });
          setMetrics({
            products_count: synthesized.length,
            observations_count: comms.length,
            actors_count: allActors.size,
            marketplaces_count: allMkts.size,
            investigations_count: 1,
          });
        }
      })
      .catch((err) => console.error("Failed to load product intelligence:", err))
      .finally(() => setLoading(false));
  }, []);

  // Compute filter options dynamically
  const categories = useMemo(() => {
    const set = new Set<string>();
    products.forEach((p) => {
      if (p.category) set.add(p.category);
    });
    return Array.from(set).sort();
  }, [products]);

  const allMarketplaces = useMemo(() => {
    const set = new Set<string>();
    products.forEach((p) => {
      p.marketplaces?.forEach((m) => set.add(m));
    });
    return Array.from(set).sort();
  }, [products]);

  const allActorHandles = useMemo(() => {
    const set = new Set<string>();
    products.forEach((p) => {
      p.actor_handles?.forEach((a) => set.add(a));
    });
    return Array.from(set).sort();
  }, [products]);

  // Filtering & Sorting
  const filteredProducts = useMemo(() => {
    return products
      .filter((p) => {
        const matchesCategory = selectedCategory === "ALL" || p.category === selectedCategory;
        const matchesMarket =
          selectedMarket === "ALL" || (p.marketplaces && p.marketplaces.includes(selectedMarket));
        const matchesActor =
          selectedActor === "ALL" || (p.actor_handles && p.actor_handles.includes(selectedActor));
        const q = searchQuery.toLowerCase().trim();
        const matchesSearch =
          !q ||
          p.name.toLowerCase().includes(q) ||
          p.id.toLowerCase().includes(q) ||
          p.category.toLowerCase().includes(q) ||
          (p.marketplaces || []).some((m) => m.toLowerCase().includes(q)) ||
          (p.actor_handles || []).some((a) => a.toLowerCase().includes(q));

        return matchesCategory && matchesMarket && matchesActor && matchesSearch;
      })
      .sort((a, b) => {
        if (sortBy === "observations") return b.observation_count - a.observation_count;
        if (sortBy === "actors") return b.actor_count - a.actor_count;
        if (sortBy === "markets") return b.marketplace_count - a.marketplace_count;
        if (sortBy === "recent") {
          const dateA = a.last_seen || a.created_at || "";
          const dateB = b.last_seen || b.created_at || "";
          return dateB.localeCompare(dateA);
        }
        return a.name.localeCompare(b.name);
      });
  }, [products, selectedCategory, selectedMarket, selectedActor, searchQuery, sortBy]);

  return (
    <AppShell>
      <div className="w-full min-w-0 max-w-full space-y-6 font-sans">
        {/* ==================================================================== */}
        {/* HEADER                                                               */}
        {/* ==================================================================== */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5 font-mono text-[10px]">
              <span className="tracking-widest text-muted-foreground uppercase">Threat Intelligence</span>
              <span className="text-muted-foreground/40 text-xs">/</span>
              <span className="text-foreground font-medium">Product Intelligence</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground font-mono">
              Product Intelligence
            </h1>
            <p className="text-xs text-muted-foreground mt-1 max-w-2xl">
              Global catalog of illicit products observed across investigations, darknet marketplaces, and threat actors.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <div className="inline-flex rounded-md border border-border/60 p-0.5 bg-zinc-950 font-mono text-xs">
              <button
                type="button"
                onClick={() => setViewMode("table")}
                className={`px-3 py-1 rounded transition-colors ${
                  viewMode === "table"
                    ? "bg-zinc-800 text-foreground font-semibold"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Table View
              </button>
              <button
                type="button"
                onClick={() => setViewMode("grid")}
                className={`px-3 py-1 rounded transition-colors ${
                  viewMode === "grid"
                    ? "bg-zinc-800 text-foreground font-semibold"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Card Grid
              </button>
            </div>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* SUMMARY METRICS STRIP                                                */}
        {/* ==================================================================== */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Normalized Products</span>
                <ShoppingBagIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.products_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Unique catalog identities</p>
            </CardContent>
          </Card>

          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Observations</span>
                <ArchiveIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.observations_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Extracted market listings</p>
            </CardContent>
          </Card>

          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Associated Actors</span>
                <UsersIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.actors_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Identified vendors & sellers</p>
            </CardContent>
          </Card>

          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Marketplaces</span>
                <GlobeIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.marketplaces_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Represented platforms</p>
            </CardContent>
          </Card>

          <Card className="border-border/50 bg-card/60">
            <CardContent className="p-3.5 space-y-1">
              <div className="flex items-center justify-between text-muted-foreground">
                <span className="text-[10px] font-mono uppercase tracking-wider">Investigations</span>
                <ShieldAlertIcon className="h-3.5 w-3.5" />
              </div>
              <p className="text-xl font-bold font-mono tracking-tight text-foreground tabular-nums">
                {metrics.investigations_count}
              </p>
              <p className="text-[10px] text-muted-foreground font-mono">Active case references</p>
            </CardContent>
          </Card>
        </div>

        {/* ==================================================================== */}
        {/* SEARCH, FILTER & SCOPE CONTROLS                                      */}
        {/* ==================================================================== */}
        <div className="space-y-3">
          <div className="flex flex-col md:flex-row items-stretch md:items-center gap-3">
            <div className="relative flex-1">
              <SearchIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search products by title, category, vendor handle, or marketplace…"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9 bg-card/60 text-xs font-mono border-border/60 h-9"
              />
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <select
                aria-label="Filter by Category"
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="h-9 px-3 rounded-md border border-border/60 bg-card/60 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              >
                <option value="ALL">All Categories ({products.length})</option>
                {categories.map((c) => (
                  <option key={c} value={c}>
                    {c}
                  </option>
                ))}
              </select>

              <select
                aria-label="Sort products by"
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as any)}
                className="h-9 px-3 rounded-md border border-border/60 bg-card/60 text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              >
                <option value="observations">Sort: Observations (High → Low)</option>
                <option value="actors">Sort: Associated Actors</option>
                <option value="markets">Sort: Marketplaces Count</option>
                <option value="recent">Sort: Most Recently Seen</option>
                <option value="name">Sort: Name (A-Z)</option>
              </select>

              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
                className="h-9 border-border/60 text-xs font-mono hover:bg-muted/40"
              >
                {showAdvancedFilters ? "Hide Filters" : "Advanced Filters"}
              </Button>
            </div>
          </div>

          {/* Collapsible Advanced Filters */}
          {showAdvancedFilters && (
            <div className="p-3.5 rounded-lg border border-border/40 bg-zinc-950/60 grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
              <div>
                <label className="text-[10px] font-mono text-muted-foreground uppercase block mb-1">
                  Filter by Marketplace
                </label>
                <select
                  aria-label="Filter by Marketplace"
                  value={selectedMarket}
                  onChange={(e) => setSelectedMarket(e.target.value)}
                  className="w-full h-8 px-2 rounded border border-border/50 bg-card/60 text-xs font-mono text-foreground focus:outline-none"
                >
                  <option value="ALL">All Marketplaces ({allMarketplaces.length})</option>
                  {allMarketplaces.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[10px] font-mono text-muted-foreground uppercase block mb-1">
                  Filter by Actor / Vendor
                </label>
                <select
                  aria-label="Filter by Actor / Vendor"
                  value={selectedActor}
                  onChange={(e) => setSelectedActor(e.target.value)}
                  className="w-full h-8 px-2 rounded border border-border/50 bg-card/60 text-xs font-mono text-foreground focus:outline-none"
                >
                  <option value="ALL">All Associated Actors ({allActorHandles.length})</option>
                  {allActorHandles.map((a) => (
                    <option key={a} value={a}>
                      {a}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-end">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setSelectedCategory("ALL");
                    setSelectedMarket("ALL");
                    setSelectedActor("ALL");
                    setSearchQuery("");
                  }}
                  className="h-8 text-xs font-mono text-muted-foreground hover:text-foreground"
                >
                  Reset All Filters
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Results Count bar */}
        <div className="flex items-center justify-between text-xs font-mono text-muted-foreground">
          <span>
            Showing <strong className="text-foreground">{filteredProducts.length}</strong> of {products.length} normalized products
          </span>
          {(selectedCategory !== "ALL" || selectedMarket !== "ALL" || selectedActor !== "ALL" || searchQuery) && (
            <span className="text-[11px] text-zinc-400">Filters Active</span>
          )}
        </div>

        {/* ==================================================================== */}
        {/* PRODUCT CATALOG: TABLE VIEW                                          */}
        {/* ==================================================================== */}
        {loading ? (
          <div className="py-24 text-center">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-foreground border-t-transparent mx-auto mb-3" />
            <p className="text-xs font-mono text-muted-foreground tracking-wide">
              HYDRATING GLOBAL PRODUCT INTELLIGENCE CATALOG...
            </p>
          </div>
        ) : filteredProducts.length === 0 ? (
          <div className="rounded-xl border border-border/50 bg-card/40 p-12 text-center space-y-2">
            <p className="text-sm font-mono text-muted-foreground">No normalized products match active query parameters.</p>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setSelectedCategory("ALL");
                setSelectedMarket("ALL");
                setSelectedActor("ALL");
                setSearchQuery("");
              }}
              className="text-xs font-mono"
            >
              Clear Search & Filter
            </Button>
          </div>
        ) : viewMode === "table" ? (
          <div className="rounded-xl border border-border/60 bg-card/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                  <tr className="text-left">
                    <th className="px-4 py-3">Product Name & ID</th>
                    <th className="px-4 py-3">Category</th>
                    <th className="px-4 py-3 text-right">Actors</th>
                    <th className="px-4 py-3 text-right">Marketplaces</th>
                    <th className="px-4 py-3 text-right">Observations</th>
                    <th className="px-4 py-3">First Seen</th>
                    <th className="px-4 py-3">Last Seen</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/30 font-mono">
                  {filteredProducts.map((p) => {
                    return (
                      <tr key={p.id} className="hover:bg-muted/20 transition-colors group">
                        <td className="px-4 py-3 max-w-[280px]">
                          <Link href={`/commodities/${p.id}`} className="block">
                            <span className="font-bold text-foreground hover:underline block truncate text-xs">
                              {p.name}
                            </span>
                            <span className="text-[10px] text-muted-foreground block truncate">
                              {p.id}
                            </span>
                          </Link>
                        </td>

                        <td className="px-4 py-3">
                          <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] uppercase text-muted-foreground">
                            {p.category}
                          </span>
                        </td>

                        <td className="px-4 py-3 text-right">
                          <span className="tabular-nums font-semibold text-foreground">
                            {p.actor_count}
                          </span>
                          {p.actor_handles && p.actor_handles.length > 0 && (
                            <span className="text-[10px] text-muted-foreground block truncate max-w-[120px] ml-auto">
                              {p.actor_handles.slice(0, 2).join(", ")}
                              {p.actor_handles.length > 2 ? "..." : ""}
                            </span>
                          )}
                        </td>

                        <td className="px-4 py-3 text-right">
                          <span className="tabular-nums font-semibold text-foreground">
                            {p.marketplace_count}
                          </span>
                          {p.marketplaces && p.marketplaces.length > 0 && (
                            <span className="text-[10px] text-muted-foreground block truncate max-w-[140px] ml-auto" title={p.marketplaces.join(", ")}>
                              {p.marketplaces[0]}
                            </span>
                          )}
                        </td>

                        <td className="px-4 py-3 text-right">
                          <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/40 bg-zinc-900/60 text-[11px] tabular-nums font-bold text-foreground">
                            {p.observation_count}
                          </span>
                        </td>

                        <td className="px-4 py-3 text-muted-foreground text-[11px] whitespace-nowrap">
                          {p.first_seen ? new Date(p.first_seen).toLocaleDateString() : "—"}
                        </td>

                        <td className="px-4 py-3 text-muted-foreground text-[11px] whitespace-nowrap">
                          {p.last_seen ? new Date(p.last_seen).toLocaleDateString() : "—"}
                        </td>

                        <td className="px-4 py-3 text-right">
                          <Link href={`/commodities/${p.id}`}>
                            <Button size="sm" variant="ghost" className="h-7 px-2 text-xs font-mono gap-1 text-foreground hover:bg-muted/40">
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
        ) : (
          /* ==================================================================== */
          /* PRODUCT CATALOG: CARD GRID VIEW                                      */
          /* ==================================================================== */
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filteredProducts.map((p) => {
              return (
                <div
                  key={p.id}
                  className="rounded-xl border border-border/60 bg-card/60 p-4 flex flex-col justify-between hover:border-border transition-all space-y-3"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] font-mono uppercase text-muted-foreground">
                        {p.category}
                      </span>
                      <span className="text-[10px] font-mono text-muted-foreground">
                        {p.observation_count} obs
                      </span>
                    </div>

                    <Link href={`/commodities/${p.id}`} className="block">
                      <h3 className="font-bold text-sm text-foreground hover:underline font-mono line-clamp-2">
                        {p.name}
                      </h3>
                      <span className="text-[10px] font-mono text-muted-foreground block truncate mt-0.5">
                        {p.id}
                      </span>
                    </Link>
                  </div>

                  <div className="space-y-2 pt-2 border-t border-border/40 font-mono text-xs">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-muted-foreground">Vendors</span>
                      <span className="text-foreground tabular-nums font-semibold">{p.actor_count}</span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-muted-foreground">Marketplaces</span>
                      <span className="text-foreground tabular-nums font-semibold">{p.marketplace_count}</span>
                    </div>
                    <div className="flex justify-between text-[11px]">
                      <span className="text-muted-foreground">Investigations</span>
                      <span className="text-foreground tabular-nums font-semibold">{p.investigation_count}</span>
                    </div>
                  </div>

                  <div className="pt-2 border-t border-border/40 flex items-center justify-between">
                    <span className="text-[10px] font-mono text-muted-foreground">
                      {p.last_seen ? `Seen ${new Date(p.last_seen).toLocaleDateString()}` : "Observed"}
                    </span>
                    <Link href={`/commodities/${p.id}`}>
                      <Button size="sm" variant="ghost" className="h-7 px-2 text-xs font-mono gap-1 hover:bg-muted/40">
                        View Dossier
                        <ArrowRightIcon className="h-3 w-3 text-muted-foreground" />
                      </Button>
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Epistemic Safety Notice */}
        <div className="p-3 rounded-lg border border-border/40 bg-zinc-950/40 text-[11px] font-mono text-muted-foreground flex items-start gap-2.5">
          <ShieldAlertIcon className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
          <div>
            <strong className="text-foreground">EPISTEMIC SAFETY PROTOCOL:</strong> Normalized products reflect catalog-level identity aggregations. A vendor or marketplace observation does not imply operational authorship or ownership without forensic cryptographic attribution.
          </div>
        </div>
      </div>
    </AppShell>
  );
}
