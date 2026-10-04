"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  SearchIcon,
  ArrowRightIcon,
  UsersIcon,
  ShieldCheckIcon,
  ShoppingBagIcon,
  GlobeIcon,
  KeyIcon,
  NetworkIcon,
} from "@/components/icons";

interface CanonicalActor {
  id: string;
  primary_handle: string;
  designated_id: string;
  category: string;
  attribution_confidence: number;
  first_seen: string | null;
  last_seen: string | null;
  created_at: string;
  alias_count: number;
  identifier_count: number;
  marketplace_count: number;
  product_count: number;
  trust_count: number;
  clearnet_count: number;
  investigation_count: number;
}

export default function ActorsCatalogPage() {
  const [actors, setActors] = useState<CanonicalActor[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [confidenceFilter, setConfidenceFilter] = useState("all");
  const [sortBy, setSortBy] = useState<"confidence" | "handle" | "investigations" | "identifiers" | "products">("confidence");
  const [viewMode, setViewMode] = useState<"grid" | "table">("grid");

  useEffect(() => {
    fetch("/api/actors")
      .then((r) => r.json())
      .then((d) => setActors(d.actors || []))
      .catch((err) => console.error("Failed to fetch actors catalog:", err))
      .finally(() => setLoading(false));
  }, []);

  // Distinct categories from actual database records
  const availableCategories = useMemo(() => {
    const cats = new Set<string>();
    actors.forEach((a) => {
      if (a.category) cats.add(a.category);
    });
    return Array.from(cats);
  }, [actors]);

  // Filtered & sorted catalog
  const filteredActors = useMemo(() => {
    return actors
      .filter((a) => {
        // Search query
        if (searchQuery) {
          const q = searchQuery.toLowerCase();
          const matchHandle = a.primary_handle.toLowerCase().includes(q);
          const matchId = (a.designated_id || "").toLowerCase().includes(q) || a.id.toLowerCase().includes(q);
          const matchCat = (a.category || "").toLowerCase().includes(q);
          if (!matchHandle && !matchId && !matchCat) return false;
        }

        // Category filter
        if (categoryFilter !== "all" && a.category !== categoryFilter) {
          return false;
        }

        // Confidence filter
        const conf = a.attribution_confidence ?? 1.0;
        if (confidenceFilter === "high" && conf < 0.9) return false;
        if (confidenceFilter === "medium" && (conf < 0.7 || conf >= 0.9)) return false;
        if (confidenceFilter === "low" && conf >= 0.7) return false;

        return true;
      })
      .sort((a, b) => {
        if (sortBy === "confidence") {
          return (b.attribution_confidence ?? 1.0) - (a.attribution_confidence ?? 1.0);
        }
        if (sortBy === "handle") {
          return a.primary_handle.localeCompare(b.primary_handle);
        }
        if (sortBy === "investigations") {
          return (b.investigation_count || 0) - (a.investigation_count || 0);
        }
        if (sortBy === "identifiers") {
          return (b.identifier_count || 0) - (a.identifier_count || 0);
        }
        if (sortBy === "products") {
          return (b.product_count || 0) - (a.product_count || 0);
        }
        return 0;
      });
  }, [actors, searchQuery, categoryFilter, confidenceFilter, sortBy]);

  // Aggregate stats across canonical population
  const totalActors = actors.length;
  const highConfidenceCount = actors.filter((a) => (a.attribution_confidence ?? 1.0) >= 0.9).length;
  const multiCaseCount = actors.filter((a) => (a.investigation_count || 0) > 1).length;
  const totalMarketLinked = actors.filter((a) => (a.marketplace_count || 0) > 0).length;

  return (
    <AppShell>
      <div className="w-full min-w-0 max-w-full space-y-6 font-sans">
        {/* ==================================================================== */}
        {/* PAGE HEADER                                                          */}
        {/* ==================================================================== */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/40 pb-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <span className="font-mono text-[10px] tracking-widest text-muted-foreground uppercase">Threat Intelligence</span>
              <span className="text-muted-foreground/40 text-xs">/</span>
              <span className="font-mono text-[11px] text-foreground font-medium">Canonical Actor Index</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-foreground">Global Threat Actors</h1>
            <p className="text-xs text-muted-foreground mt-1.5 max-w-2xl font-mono">
              Canonical threat actors correlated across darknet hidden services, escrow forums, and multi-case investigations.
            </p>
          </div>

          <div className="flex gap-2 items-center flex-wrap">
            <span className="inline-flex items-center px-2.5 py-1 rounded border border-border/60 bg-muted/20 text-[11px] font-mono text-foreground">
              {totalActors} Canonical Personas
            </span>
            <Link href="/graph">
              <Button size="sm" variant="outline" className="gap-1.5 border-border/80 text-foreground hover:bg-muted/40 font-mono text-xs">
                <NetworkIcon className="h-3.5 w-3.5 text-muted-foreground" />
                Global Threat Graph
              </Button>
            </Link>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* CATALOG KPI TILES (MONOCHROME MINIMALIST BENTO)                      */}
        {/* ==================================================================== */}
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Cataloged Actors</span>
              <UsersIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{totalActors}</div>
            <div className="text-[10px] text-muted-foreground mt-1 truncate">Unique canonical identities</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">High Confidence</span>
              <ShieldCheckIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{highConfidenceCount}</div>
            <div className="text-[10px] text-muted-foreground mt-1 truncate">≥90% evidentiary attribution</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Cross-Investigation</span>
              <NetworkIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{multiCaseCount}</div>
            <div className="text-[10px] text-muted-foreground mt-1 truncate">Observed in multiple cases</div>
          </div>

          <div className="rounded-xl border border-border/60 bg-card/60 p-3.5 flex flex-col justify-between">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">Market Operators</span>
              <ShoppingBagIcon className="h-4 w-4 text-muted-foreground" />
            </div>
            <div className="text-2xl font-bold font-mono tracking-tight tabular-nums text-foreground">{totalMarketLinked}</div>
            <div className="text-[10px] text-muted-foreground mt-1 truncate">Linked to storefront infrastructure</div>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* SEARCH & FILTERS TOOLBAR                                             */}
        {/* ==================================================================== */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 rounded-xl border border-border/60 bg-card/60 p-3">
          <div className="flex flex-1 items-center gap-2">
            <SearchIcon className="h-4 w-4 text-muted-foreground shrink-0" />
            <Input
              placeholder="Search by handle, designated ID (TA-...), or category..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 max-w-md bg-zinc-950 border-border/60 font-mono text-xs"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="text-xs font-mono text-muted-foreground hover:text-foreground px-1"
              >
                Clear
              </button>
            )}
          </div>

          <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="h-8 rounded-md border border-border/60 bg-zinc-950 px-2.5 text-xs text-foreground focus:outline-hidden"
            >
              <option value="all">All Categories ({actors.length})</option>
              {availableCategories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>

            {/* Confidence Filter */}
            <select
              value={confidenceFilter}
              onChange={(e) => setConfidenceFilter(e.target.value)}
              className="h-8 rounded-md border border-border/60 bg-zinc-950 px-2.5 text-xs text-foreground focus:outline-hidden"
            >
              <option value="all">All Confidence</option>
              <option value="high">High (≥90%)</option>
              <option value="medium">Medium (70% - 89%)</option>
              <option value="low">Under Review (&lt;70%)</option>
            </select>

            {/* Sort Controls */}
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="h-8 rounded-md border border-border/60 bg-zinc-950 px-2.5 text-xs text-foreground focus:outline-hidden"
            >
              <option value="confidence">Sort: Confidence (High to Low)</option>
              <option value="handle">Sort: Handle (A-Z)</option>
              <option value="investigations">Sort: Most Investigations</option>
              <option value="identifiers">Sort: Most Identifiers</option>
              <option value="products">Sort: Most Contraband</option>
            </select>

            {/* View Toggle */}
            <div className="flex items-center rounded-md border border-border/60 bg-zinc-950 p-0.5 text-[11px] font-mono">
              <button
                onClick={() => setViewMode("grid")}
                className={`px-2 py-1 rounded transition ${viewMode === "grid" ? "bg-muted/40 text-foreground" : "text-muted-foreground hover:text-foreground"}`}
                title="Grid View"
              >
                Cards
              </button>
              <button
                onClick={() => setViewMode("table")}
                className={`px-2 py-1 rounded transition ${viewMode === "table" ? "bg-muted/40 text-foreground" : "text-muted-foreground hover:text-foreground"}`}
                title="Table View"
              >
                Table
              </button>
            </div>
          </div>
        </div>

        {/* ==================================================================== */}
        {/* ACTORS LISTING: GRID OR TABLE VIEW                                   */}
        {/* ==================================================================== */}
        {loading ? (
          <div className="py-20 text-center space-y-3">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-foreground border-t-transparent mx-auto" />
            <p className="text-xs font-mono text-muted-foreground tracking-wide">LOADING CANONICAL THREAT ACTORS...</p>
          </div>
        ) : filteredActors.length === 0 ? (
          <div className="rounded-xl border border-border/60 bg-card/40 p-12 text-center space-y-2">
            <UsersIcon className="h-8 w-8 mx-auto text-muted-foreground/40" />
            <h3 className="text-sm font-semibold text-foreground font-mono">No matching threat actors found</h3>
            <p className="text-xs text-muted-foreground max-w-sm mx-auto font-mono">
              Try adjusting your search criteria or filter constraints to locate canonical personas.
            </p>
          </div>
        ) : viewMode === "grid" ? (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {filteredActors.map((actor) => {
              const confPct = Math.round((actor.attribution_confidence ?? 1.0) * 100);

              return (
                <div
                  key={actor.id}
                  className="rounded-xl border border-border/60 bg-card/60 p-4 hover:border-zinc-700 transition-colors flex flex-col justify-between space-y-4 group"
                >
                  <div>
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <span className="font-mono text-[10px] text-muted-foreground block tracking-wider">
                          {actor.designated_id}
                        </span>
                        <h3 className="text-base font-bold font-mono text-foreground group-hover:text-zinc-200 transition-colors">
                          {actor.primary_handle}
                        </h3>
                      </div>
                      <span className="inline-flex items-center px-2 py-0.5 rounded border border-border/60 bg-muted/20 text-[10px] font-mono text-muted-foreground">
                        {actor.category || "Unclassified"}
                      </span>
                    </div>

                    {/* Attribution Confidence Rating */}
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

                    {/* Intelligence Badges */}
                    <div className="mt-3.5 flex flex-wrap gap-1.5">
                      <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                        {actor.investigation_count || 1} case{actor.investigation_count !== 1 ? "s" : ""}
                      </span>
                      {actor.alias_count > 0 && (
                        <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                          {actor.alias_count} alias{actor.alias_count !== 1 ? "es" : ""}
                        </span>
                      )}
                      <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                        {actor.identifier_count} indicator{actor.identifier_count !== 1 ? "s" : ""}
                      </span>
                      {actor.marketplace_count > 0 && (
                        <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">
                          {actor.marketplace_count} market{actor.marketplace_count !== 1 ? "s" : ""}
                        </span>
                      )}
                      {actor.product_count > 0 && (
                        <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">
                          {actor.product_count} contraband listing{actor.product_count !== 1 ? "s" : ""}
                        </span>
                      )}
                      {actor.clearnet_count > 0 && (
                        <span className="rounded border border-border/40 bg-zinc-900/60 px-1.5 py-0.5 text-[10px] font-mono text-zinc-300">
                          {actor.clearnet_count} OSINT account{actor.clearnet_count !== 1 ? "s" : ""}
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="pt-3 border-t border-border/40 flex items-center justify-between text-xs font-mono">
                    <span className="text-[10px] text-muted-foreground truncate max-w-[150px]">
                      {actor.first_seen ? `Seen ${new Date(actor.first_seen).toLocaleDateString()}` : "Observed during crawl"}
                    </span>
                    <Link href={`/actors/${actor.id}`}>
                      <Button size="sm" variant="ghost" className="h-7 px-2 text-xs font-mono text-foreground gap-1 hover:bg-muted/30">
                        Open Dossier
                        <ArrowRightIcon className="h-3 w-3 text-muted-foreground" />
                      </Button>
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="rounded-xl border border-border/60 bg-card/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-zinc-950 border-b border-border/40 text-muted-foreground font-mono text-[10px] uppercase tracking-wider">
                  <tr className="text-left">
                    <th className="px-4 py-3">Actor / Handle</th>
                    <th className="px-4 py-3">Designated ID</th>
                    <th className="px-4 py-3">Threat Category</th>
                    <th className="px-4 py-3 text-right">Confidence</th>
                    <th className="px-4 py-3 text-center">Cases</th>
                    <th className="px-4 py-3 text-center">IOCs</th>
                    <th className="px-4 py-3 text-center">Markets / Items</th>
                    <th className="px-4 py-3 text-center">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredActors.map((actor) => (
                    <tr key={actor.id} className="border-b border-border/20 last:border-0 hover:bg-muted/15 transition-colors">
                      <td className="px-4 py-2.5 font-mono font-bold text-foreground">
                        <Link href={`/actors/${actor.id}`} className="hover:underline">
                          {actor.primary_handle}
                        </Link>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-[11px] text-muted-foreground">
                        {actor.designated_id}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded border border-border/60 bg-muted/20 text-[9px] font-mono text-muted-foreground">
                          {actor.category || "Unclassified"}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right tabular-nums font-mono text-foreground font-medium">
                        {Math.round((actor.attribution_confidence ?? 1.0) * 100)}%
                      </td>
                      <td className="px-4 py-2.5 text-center font-mono text-muted-foreground">
                        {actor.investigation_count || 1}
                      </td>
                      <td className="px-4 py-2.5 text-center font-mono text-muted-foreground">
                        {actor.identifier_count}
                      </td>
                      <td className="px-4 py-2.5 text-center font-mono text-muted-foreground">
                        {actor.marketplace_count} / {actor.product_count}
                      </td>
                      <td className="px-4 py-2.5 text-center">
                        <Link href={`/actors/${actor.id}`}>
                          <Button size="sm" variant="ghost" className="h-6 px-2 text-xs font-mono text-foreground hover:bg-muted/40">
                            Dossier →
                          </Button>
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
