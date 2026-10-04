"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { curveCatmullRom } from "@visx/curve";
import {
  Background,
  Bar,
  BarChart,
  BarXAxis,
  ChartBrush,
  ChartBrushLayout,
  ChartLegend,
  ChartTooltip,
  Grid,
  Line,
  LineChart,
  Ring,
  RingCenter,
  RingChart,
  XAxis,
  ChoroplethChart,
  ChoroplethFeatureComponent,
  ChoroplethGraticule,
  ChoroplethTooltip,
} from "@bklitui/ui/charts";
import * as topojson from "topojson-client";
import worldData from "world-atlas/countries-110m.json";
import {
  RelativeTime,
  RelativeTimeZone,
  RelativeTimeZoneDate,
  RelativeTimeZoneDisplay,
  RelativeTimeZoneLabel,
} from "@/components/kibo-ui/relative-time";

const timezones = [
  { label: "UTC", zone: "UTC" },
  { label: "EST", zone: "America/New_York" },
  { label: "GMT", zone: "Europe/London" },
  { label: "JST", zone: "Asia/Tokyo" },
];

const CATEGORY_COLORS = [
  "var(--chart-1)",
  "var(--chart-2)",
  "var(--chart-3)",
  "var(--chart-4)",
  "var(--chart-5)",
];

const defaultOpportunityRings = [
  { label: "Origin-IP disclosures", value: 28, maxValue: 35, color: "var(--chart-1)" },
  { label: "Infrastructure fingerprints", value: 25, maxValue: 25, color: "var(--chart-2)" },
  { label: "Clone / template links", value: 18, maxValue: 20, color: "var(--chart-3)" },
  { label: "High-confidence pivots", value: 15, maxValue: 20, color: "var(--chart-4)" },
];
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  GlobeIcon,
  UsersIcon,
  WalletIcon,
  ServerCrashIcon,
  TrendingUpIcon,
  ShieldAlertIcon,
  ClockIcon,
  ShieldCheckIcon,
  AlertCircleIcon,
  CheckCircle2Icon,
  CopyIcon,
  ArrowRightIcon,
} from "@/components/icons";

// ── Interfaces ────────────────────────────────────────────────────────────────

interface TimeseriesPoint {
  date: string;
  full_date: string;
  pages: number;
  identifiers: number;
  actors?: number;
  cumulative?: number;
}

interface ActorInflowPoint {
  week: string;
  [category: string]: string | number;
}

interface ConfidenceBin {
  bin: string;
  count: number;
  color: string;
}

interface ContentCluster {
  cluster_id: string;
  name: string;
  fingerprint: string;
  page_count: number;
  similarity: number;
  sample_urls: string[];
}

interface EntityVelocity {
  type: string;
  value: string;
  count: number;
  confidence: number;
  velocity: "SURGING" | "STEADY";
}

interface MacroStats {
  total_pages: number;
  total_actors: number;
  total_identifiers: number;
  sanctioned_count: number;
  leaked_ips: number;
  mean_page_size: number;
  median_page_size: number;
  std_page_size: number;
  mean_word_count: number;
  median_word_count: number;
  category_breakdown: Record<string, number>;
  identifier_type_breakdown: Record<string, number>;
  top_actors: Array<{
    handle: string;
    category: string;
    confidence: number;
    attributed_count: number;
  }>;
  circular_mean_hour: number | null;
  investigations_count: number;
  completed_investigations: number;
  recent_leads: Array<{ type: string; value: string; page_url: string }>;
  timeseries?: TimeseriesPoint[];
  actors_weekly?: ActorInflowPoint[];
  threat_categories?: string[];
  confidence_distribution?: ConfidenceBin[];
  evidence_coverage?: {
    total_identifiers: number;
    has_quote: number;
    coverage_pct: number;
    unverified_count: number;
  };
  infrastructure_exposure?: {
    score: number;
    level: string;
    leaked_ips: number;
    server_banners: number;
    favicons: number;
    sanctioned_assets: number;
  };
  infrastructure_geography?: InfrastructureGeography;
  attribution_opportunity?: AttributionOpportunity;
  content_clusters?: ContentCluster[];
  entity_velocity?: EntityVelocity[];
}

interface CountryExposureItem {
  country_code: string;
  country_name: string;
  numeric_id: string;
  unique_ips_count: number;
  exposure_score: number;
  ips: string[];
}

interface OriginCandidate {
  ip: string;
  asn_org: string;
  country: string;
  country_code: string;
  numeric_id: string;
  city?: string;
  confidence: number;
  source_onion: string;
  evidence_quote: string;
  ip_role: string;
  hosting?: boolean;
  proxy_or_vpn?: boolean;
}

interface InfrastructureGeography {
  title: string;
  subtitle: string;
  disclaimer: string;
  total_corroborated_ips: number;
  show_choropleth: boolean;
  country_exposure: Record<string, CountryExposureItem>;
  origin_candidates: OriginCandidate[];
}

interface AttributionOpportunity {
  score: number;
  level: string;
  origin_ips: number;
  fingerprints: number;
  mirror_onions: number;
  high_conf_pivots: number;
  ring_data: Array<{
    label: string;
    value: number;
    maxValue: number;
    color: string;
  }>;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function fmt(n: number, decimals = 0) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toFixed(decimals);
}

function confColor(c: number) {
  if (c >= 0.9) return "text-emerald-400";
  if (c >= 0.7) return "text-yellow-400";
  return "text-red-400";
}

// ── Stat Card Component ──────────────────────────────────────────────────────

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  badge,
  loading,
  href,
}: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  sub?: string;
  badge?: { text: string; variant?: "destructive" | "secondary" | "outline" };
  loading?: boolean;
  href?: string;
}) {
  const content = (
    <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md transition-all duration-200 hover:border-white/[0.16] hover:bg-card">
      {/* Subtle top-edge accent line */}
      <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
      <CardHeader className="relative flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground/90 font-medium">
          {label}
        </CardTitle>
        <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-white/[0.07] bg-white/[0.03]">
          <Icon className="h-3.5 w-3.5 text-zinc-400 group-hover/card:text-zinc-200 transition-colors" />
        </div>
      </CardHeader>
      <CardContent className="relative">
        {loading ? (
          <Skeleton className="h-7 w-24 bg-muted/40" />
        ) : (
          <div className="flex items-end gap-2">
            <span className="text-2xl font-bold tabular-nums tracking-tight font-mono text-white">{value}</span>
            {badge && (
              <Badge
                variant={badge.variant ?? "secondary"}
                className={`mb-0.5 text-xs font-mono rounded-md ${
                  badge.variant === "destructive"
                    ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                    : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                }`}
              >
                {badge.text}
              </Badge>
            )}
          </div>
        )}
        {sub && !loading && (
          <p className="mt-1.5 text-xs text-muted-foreground/80">{sub}</p>
        )}
        {href && (
          <div className="mt-2.5 flex items-center gap-1 text-[11px] font-medium text-zinc-400 group-hover/card:text-zinc-200 transition-colors">
            <span>View page</span>
            <ArrowRightIcon className="h-3 w-3 opacity-60 group-hover/card:translate-x-0.5 transition-transform" />
          </div>
        )}
      </CardContent>
    </Card>
  );

  if (href) {
    return (
      <Link href={href} className="block rounded-xl focus:outline-none focus-visible:ring-1 focus-visible:ring-primary">
        {content}
      </Link>
    );
  }
  return content;
}

// ── Evidence Coverage Banner ─────────────────────────────────────────────────

function EvidenceCoverageBanner({
  coverage,
}: {
  coverage?: MacroStats["evidence_coverage"];
}) {
  if (!coverage) return null;
  const isHealthy = coverage.coverage_pct >= 85;

  return (
    <div className="relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 p-4 backdrop-blur-md">
      <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
      <div className="relative flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border ${isHealthy ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-amber-500/10 text-amber-400 border-amber-500/20"}`}>
            {isHealthy ? <ShieldCheckIcon className="h-5 w-5" /> : <AlertCircleIcon className="h-5 w-5" />}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold tracking-tight text-white">Courtroom Evidentiary Audit</span>
              <Badge variant={isHealthy ? "secondary" : "outline"} className={`text-[10px] rounded-md ${isHealthy ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-amber-500/10 text-amber-400 border-amber-500/20"}`}>
                {coverage.coverage_pct}% Substantiated
              </Badge>
            </div>
            <p className="text-xs text-muted-foreground/90">
              {coverage.has_quote} of {coverage.total_identifiers} identifiers bound to verbatim textual proof in raw HTML drops.
              {coverage.unverified_count > 0 && ` (${coverage.unverified_count} indicators unverified)`}
            </p>
          </div>
        </div>
        <Link
          href="/evidence"
          className="inline-flex items-center gap-1.5 self-start sm:self-center text-xs font-medium text-zinc-300 hover:text-white transition-colors"
        >
          Inspect Proof Chain <ArrowRightIcon className="h-3.5 w-3.5" />
        </Link>
      </div>
    </div>
  );
}

// ── Attribution Opportunity Score Gauge (Ring Chart) ──────────────────────────

function ExposureGauge({
  opportunity,
}: {
  opportunity?: AttributionOpportunity;
}) {
  const opp = opportunity;
  const score = opp?.score ?? 86;
  const level = opp?.level ?? "High-value";
  const rings = opp?.ring_data && opp.ring_data.length === 4 ? opp.ring_data : defaultOpportunityRings;

  return (
    <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md">
      <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
      <CardHeader>
        <CardTitle className="flex items-center justify-between text-sm">
          <span className="flex items-center gap-2 text-white font-semibold">
            <ServerCrashIcon className="h-4 w-4 text-cyan-400" /> Attribution Opportunity
          </span>
          <Badge
            variant={score >= 75 ? "secondary" : "outline"}
            className={`text-[10px] rounded-md ${score >= 75 ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20" : "bg-white/[0.06] text-zinc-300 border border-white/[0.08]"}`}
          >
            {level}
          </Badge>
        </CardTitle>
        <CardDescription className="text-xs text-muted-foreground">
          Evidence-rich technical pivots
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-3">
        <div className="flex items-center justify-center">
          <RingChart data={rings} ringGap={8} size={250} strokeWidth={18}>
            {rings.map((item, index) => (
              <Ring index={index} key={item.label} />
            ))}
            <RingCenter defaultLabel="Attribution Opportunity" suffix=" / 100" />
          </RingChart>
        </div>
        <p className="text-[11px] text-muted-foreground text-center">
          Evidence-rich infrastructure signals
        </p>
        <div className="grid grid-cols-2 gap-2 w-full pt-2 text-[11px] text-muted-foreground border-t border-white/[0.06]">
          <div>Origin IPs: <span className="font-mono text-white font-medium">{opp?.origin_ips ?? 0}</span></div>
          <div>Fingerprints: <span className="font-mono text-white font-medium">{opp?.fingerprints ?? 0}</span></div>
          <div>Mirror-linked onions: <span className="font-mono text-white font-medium">{opp?.mirror_onions ?? 0}</span></div>
          <div>High-confidence pivots: <span className="font-mono text-white font-medium">{opp?.high_conf_pivots ?? 0}</span></div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Confidence Histogram ─────────────────────────────────────────────────────

function ConfidenceHistogram({
  bins,
}: {
  bins?: ConfidenceBin[];
}) {
  const data = bins ?? [];
  const maxCount = Math.max(...data.map((b) => b.count), 1);

  return (
    <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md">
      <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
      <CardHeader>
        <CardTitle className="flex items-center justify-between text-sm">
          <span className="flex items-center gap-2 text-white font-semibold">
            <ShieldAlertIcon className="h-4 w-4 text-cyan-400" /> Confidence Quality Spread
          </span>
          <span className="text-xs text-muted-foreground font-mono">5-bin density</span>
        </CardTitle>
        <CardDescription className="text-xs text-muted-foreground">
          Statistical distribution of attribution weights
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2.5">
        {data.map((b) => {
          const pct = Math.round((b.count / maxCount) * 100);
          return (
            <div key={b.bin} className="space-y-1">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-muted-foreground">{b.bin}</span>
                <span className="font-semibold text-white">{b.count}</span>
              </div>
              <div className="h-2 w-full rounded-full bg-white/[0.06] overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${pct}%`, backgroundColor: b.color }}
                />
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

// ── OpSec / Timeline Relative Time Component ─────────────────────────────────

function OpSecClock({ hour }: { hour: number | null }) {
  const valid = hour !== null && !isNaN(hour);

  return (
    <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md flex flex-col justify-between">
      <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
      <CardHeader>
        <CardTitle className="flex items-center justify-between text-sm">
          <span className="flex items-center gap-2 text-white font-semibold">
            <ClockIcon className="h-4 w-4 text-cyan-400" /> Active Investigation Timezones
          </span>
          <Badge variant="outline" className="text-[10px] font-mono border-white/[0.1] text-zinc-300 bg-white/[0.02]">
            LIVE SYNC
          </Badge>
        </CardTitle>
        <CardDescription className="text-xs text-muted-foreground">
          Multi-theater temporal synchronization & OpSec reference
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col justify-between flex-1">
        <div className="rounded-lg border border-white/[0.07] bg-white/[0.02] p-3">
          <RelativeTime>
            {timezones.map(({ zone, label }) => (
              <RelativeTimeZone key={zone} zone={zone}>
                <RelativeTimeZoneLabel>{label}</RelativeTimeZoneLabel>
                <RelativeTimeZoneDate className="text-[11px]" />
                <RelativeTimeZoneDisplay className="font-mono text-white font-medium text-xs" />
              </RelativeTimeZone>
            ))}
          </RelativeTime>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Observed Infrastructure Geography & Choropleth ───────────────────────────

// biome-ignore lint/suspicious/noExplicitAny: topojson types
const geojson = topojson.feature(worldData as any, (worldData as any).objects.countries) as any;

function ObservedInfrastructureGeography({
  geo,
}: {
  geo?: InfrastructureGeography;
}) {
  const total = geo?.total_corroborated_ips ?? 0;
  const candidates = geo?.origin_candidates ?? [];
  const defaultMap = geo?.show_choropleth ?? (total >= 5);
  const [activeTab, setActiveTab] = useState<"auto" | "map" | "table">("auto");

  // Determine current view mode: auto defaults to map if total >= 5, else table
  const showMap = activeTab === "auto" ? defaultMap : activeTab === "map";

  // Build lookup index for world-atlas numeric IDs
  const exposureByNumericId = useMemo(() => {
    const map = new Map<string, CountryExposureItem>();
    if (!geo?.country_exposure) return map;
    for (const item of Object.values(geo.country_exposure)) {
      if (item.numeric_id) {
        map.set(item.numeric_id, item);
        map.set(String(parseInt(item.numeric_id, 10)), item);
      }
    }
    return map;
  }, [geo?.country_exposure]);

  // Confidence-weighted exposure calculation for Choropleth
  const getFeatureExposure = (feature: any) => {
    const id = String(feature?.id ?? "");
    const item = exposureByNumericId.get(id);
    return item ? item.exposure_score : 0;
  };

  // Color intensity calculation based on CountryExposure(c) = sum(confidence_i)
  const getFeatureColor = (feature: any) => {
    const id = String(feature?.id ?? "");
    const item = exposureByNumericId.get(id);
    if (!item || item.exposure_score <= 0) {
      return "rgba(255, 255, 255, 0.05)";
    }
    const exp = item.exposure_score;
    if (exp >= 1.8) return "var(--chart-1)";
    if (exp >= 1.4) return "var(--chart-2)";
    if (exp >= 1.0) return "var(--chart-3)";
    if (exp >= 0.8) return "var(--chart-4)";
    return "var(--chart-5)";
  };

  return (
    <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md">
      <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
      <CardHeader className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3">
        <div>
          <CardTitle className="flex items-center gap-2 text-sm font-semibold text-white">
            <GlobeIcon className="h-4 w-4 text-cyan-400" /> Observed Infrastructure Geography
          </CardTitle>
          <CardDescription className="text-xs text-muted-foreground">
            Geolocation of corroborated clearweb IP pivots
          </CardDescription>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          {/* View mode toggle */}
          <div className="flex rounded-lg border border-white/[0.08] bg-black/40 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setActiveTab("table")}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-all ${
                !showMap
                  ? "bg-white text-zinc-950 font-semibold shadow-sm"
                  : "text-zinc-400 hover:text-white"
              }`}
            >
              Origin Table
            </button>
            <button
              type="button"
              onClick={() => setActiveTab("map")}
              className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition-all ${
                showMap
                  ? "bg-white text-zinc-950 font-semibold shadow-sm"
                  : "text-zinc-400 hover:text-white"
              }`}
            >
              Choropleth Map
            </button>
          </div>
          <Badge variant="outline" className="text-[10px] font-mono border-white/[0.1] text-zinc-300 bg-white/[0.02]">
            {total} {total === 1 ? "Corroborated IP" : "Corroborated IPs"}
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="space-y-4 pt-1">
        {showMap ? (
          <div className="w-full space-y-3">
            <div className="w-full">
              <ChoroplethChart
                aspectRatio="2 / 1"
                data={geojson}
                margin={{ top: 8, right: 8, bottom: 40, left: 8 }}
              >
                <ChoroplethGraticule />
                <ChoroplethFeatureComponent getFeatureColor={getFeatureColor} />
                <ChoroplethTooltip
                  getFeatureValue={getFeatureExposure}
                  valueLabel="Exposure Score"
                  content={({ feature }) => {
                    const id = String(feature?.id ?? "");
                    const item = exposureByNumericId.get(id);
                    const name = item?.country_name || (feature?.properties?.name ?? "Unknown");
                    if (!item || item.unique_ips_count === 0) {
                      return (
                        <div className="p-1 space-y-0.5">
                          <div className="font-semibold text-xs text-foreground">{name}</div>
                          <div className="text-[10px] text-muted-foreground">No corroborated clearnet pivots</div>
                        </div>
                      );
                    }
                    return (
                      <div className="min-w-[190px] p-1.5 space-y-1.5">
                        <div className="flex items-center justify-between border-b border-border/40 pb-1">
                          <span className="font-semibold text-xs text-foreground">{name}</span>
                          <Badge variant="outline" className="text-[10px] font-mono">
                            {item.country_code}
                          </Badge>
                        </div>
                        <div className="flex justify-between text-xs font-mono">
                          <span className="text-muted-foreground">Unique IPs:</span>
                          <span className="font-bold text-foreground">{item.unique_ips_count}</span>
                        </div>
                        <div className="flex justify-between text-xs font-mono">
                          <span className="text-muted-foreground">Country Exposure Σ:</span>
                          <span className="font-bold text-primary">{item.exposure_score.toFixed(2)}</span>
                        </div>
                        <div className="text-[10px] font-mono text-muted-foreground truncate pt-0.5">
                          IPs: {item.ips.join(", ")}
                        </div>
                      </div>
                    );
                  }}
                />
              </ChoroplethChart>
            </div>
          </div>
        ) : (
          /* Compact Infrastructure Origin Table */
          <div className="space-y-2">
            <div className="overflow-x-auto rounded-lg border border-white/[0.08] bg-black/20">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-white/[0.08] text-muted-foreground bg-white/[0.02]">
                    <th className="px-3 py-2 text-left font-medium">IP Address & Role</th>
                    <th className="px-3 py-2 text-left font-medium">ASN / Org</th>
                    <th className="px-3 py-2 text-left font-medium">Country</th>
                    <th className="px-3 py-2 text-right font-medium">Confidence</th>
                    <th className="px-3 py-2 text-left font-medium">Source Onion</th>
                    <th className="px-3 py-2 text-left font-medium">Corroborating Evidence Quote</th>
                  </tr>
                </thead>
                <tbody>
                  {candidates.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-3 py-6 text-center text-muted-foreground">
                        No corroborated clearweb IP pivots discovered yet. Awaiting origin candidate corroboration (confidence ≥ 0.80 or server-status leak).
                      </td>
                    </tr>
                  ) : (
                    candidates.map((c) => (
                      <tr key={c.ip} className="border-b border-border/20 last:border-0 hover:bg-muted/30 transition-colors">
                        <td className="px-3 py-2.5 font-mono text-foreground">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold">{c.ip}</span>
                            <Badge
                              variant={c.ip_role === "SERVER_STATUS_LEAK" ? "destructive" : "secondary"}
                              className="text-[9px] font-mono uppercase px-1.5 py-0"
                            >
                              {c.ip_role.replace(/_/g, " ")}
                            </Badge>
                          </div>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-muted-foreground max-w-[200px] truncate">
                          {c.asn_org || "Unknown AS"}
                        </td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-1.5">
                            <span className="text-foreground">{c.country}</span>
                            <span className="font-mono text-[10px] text-muted-foreground">({c.country_code})</span>
                          </div>
                        </td>
                        <td className={`px-3 py-2.5 text-right tabular-nums font-semibold ${confColor(c.confidence)}`}>
                          {(c.confidence * 100).toFixed(0)}%
                        </td>
                        <td className="px-3 py-2.5 font-mono text-xs text-primary max-w-[180px] truncate">
                          <span title={c.source_onion}>
                            {c.source_onion.replace(/^http:\/\//, "").slice(0, 16)}...
                          </span>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[11px] text-muted-foreground/90 max-w-[320px] truncate">
                          <span title={c.evidence_quote}>"{c.evidence_quote}"</span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Mandatory Disclaimer */}
        <div className="flex items-center gap-2 border-t border-dashed border-border/50 pt-3 text-[11px] text-muted-foreground">
          <AlertCircleIcon className="h-3.5 w-3.5 text-muted-foreground/70 shrink-0" />
          <span>IP geolocation represents network-registration or hosting location, not a threat actor’s physical location.</span>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Dashboard ────────────────────────────────────────────────────────────

export function Dashboard() {
  const [stats, setStats] = useState<MacroStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    fetch("/api/stats/macro")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((d) => setStats(d))
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  const velocityData = useMemo(() => {
    if (stats?.timeseries && stats.timeseries.length > 0) {
      return stats.timeseries.map((pt) => ({
        date: new Date(pt.date),
        pages: pt.pages ?? 0,
        identifiers: pt.identifiers ?? 0,
        actors: pt.actors ?? 0,
      }));
    }
    return Array.from({ length: 30 }, (_, i) => {
      const d = new Date();
      d.setDate(d.getDate() - (29 - i));
      return { date: d, pages: 0, identifiers: 0, actors: 0 };
    });
  }, [stats?.timeseries]);

  const weeklyInflowData = useMemo(() => {
    if (stats?.actors_weekly && stats.actors_weekly.length > 0) {
      return stats.actors_weekly;
    }
    return [
      { week: "W-5" },
      { week: "W-4" },
      { week: "W-3" },
      { week: "W-2" },
      { week: "W-1" },
      { week: "Current" },
    ];
  }, [stats?.actors_weekly]);

  const threatCategories = useMemo(() => {
    if (stats?.threat_categories && stats.threat_categories.length > 0) {
      return stats.threat_categories;
    }
    return ["Financial Fraud / Carding", "Weapons Trafficking"];
  }, [stats?.threat_categories]);

  return (
    <div className="space-y-6 p-4 lg:p-6">
      {/* Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Command Center</h1>
          <p className="text-sm text-muted-foreground">
            Jane Threat Attribution — Forensic Intelligence Overview
          </p>
        </div>
        {error && (
          <Badge variant="destructive" className="self-start text-xs">
            Backend offline — {error}
          </Badge>
        )}
      </div>

      {/* Vital Metric Cards */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={GlobeIcon}
          label="Hidden Services Scraped"
          value={loading ? "—" : fmt(stats?.total_pages ?? 0)}
          sub={stats ? `${stats.investigations_count} investigations active` : undefined}
          loading={loading}
          href="/onions"
        />
        <StatCard
          icon={UsersIcon}
          label="Threat Personas"
          value={loading ? "—" : fmt(stats?.total_actors ?? 0)}
          sub={stats ? `${stats.completed_investigations} dossiers completed` : undefined}
          loading={loading}
          href="/actors"
        />
        <StatCard
          icon={WalletIcon}
          label="Sanctioned Assets"
          value={loading ? "—" : fmt(stats?.sanctioned_count ?? 0)}
          badge={
            (stats?.sanctioned_count ?? 0) > 0
              ? { text: "OFAC Matches", variant: "destructive" }
              : undefined
          }
          sub="Crypto addresses on blacklists"
          loading={loading}
          href="/sanctions"
        />
        <StatCard
          icon={ServerCrashIcon}
          label="Infrastructure Leaks"
          value={loading ? "—" : fmt(stats?.leaked_ips ?? 0)}
          badge={
            (stats?.leaked_ips ?? 0) > 0
              ? { text: "IPs Disclosed", variant: "secondary" }
              : undefined
          }
          sub="Deanonymized server origins"
          loading={loading}
          href="/locksmith"
        />
      </div>

      {/* High-Value Analytical Charts Row */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Intelligence Pipeline Velocity Line Chart by BKlit */}
        <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md transition-colors duration-200 hover:border-white/[0.16]">
          <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div>
              <CardTitle className="flex items-center gap-2 text-sm font-semibold text-white">
                <TrendingUpIcon className="h-4 w-4 text-cyan-400" /> Intelligence Pipeline Velocity
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                30-day collection volume, intelligence yield & attribution
              </CardDescription>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: "var(--chart-1)" }} />
                <span className="text-muted-foreground">Pages Crawled</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: "var(--chart-2)" }} />
                <span className="text-muted-foreground">IOCs Extracted</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: "var(--chart-3)" }} />
                <span className="text-muted-foreground">Actors Attributed</span>
              </div>
            </div>
          </CardHeader>
          <CardContent className="pt-2">
            <div className="w-full">
              <ChartBrushLayout
                data={velocityData}
                enabled
                height={72}
                brushStrip={(brushLayout) => (
                  <LineChart
                    animationDuration={0}
                    data={velocityData}
                    status="ready"
                    style={{ aspectRatio: "unset", height: "100%" }}
                    margin={{ top: 8, right: 16, bottom: 8, left: 16 }}
                  >
                    <Line dataKey="pages" stroke="var(--chart-1)" animate={false} showHighlight={false} strokeWidth={1} />
                    <Line dataKey="identifiers" stroke="var(--chart-2)" animate={false} showHighlight={false} strokeWidth={1} />
                    <Line dataKey="actors" stroke="var(--chart-3)" animate={false} showHighlight={false} strokeWidth={1} />
                    <ChartBrush
                      initialSelection={brushLayout.brushSelection ?? undefined}
                      onSelectionChange={brushLayout.onBrushSelectionChange}
                    />
                  </LineChart>
                )}
              >
                {(brushLayout) => (
                  <LineChart
                    data={velocityData}
                    xDomain={brushLayout.xDomain}
                    xDomainSlotCount={brushLayout.xDomainSlotCount}
                    tweenYDomainOnXDomainChange
                    style={{ height: 260 }}
                  >
                    <Background pattern="dots" opacity={0.85} />
                    <Line dataKey="pages" stroke="var(--chart-1)" curve={curveCatmullRom} fadeEdges strokeWidth={2} />
                    <Line dataKey="identifiers" stroke="var(--chart-2)" curve={curveCatmullRom} fadeEdges strokeWidth={2} />
                    <Line dataKey="actors" stroke="var(--chart-3)" curve={curveCatmullRom} fadeEdges strokeWidth={2} />
                    <XAxis />
                    <ChartTooltip />
                  </LineChart>
                )}
              </ChartBrushLayout>
            </div>
          </CardContent>
        </Card>

        {/* Weekly Threat Category Inflow Stacked Bar Chart */}
        <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md transition-colors duration-200 hover:border-white/[0.16]">
          <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div>
              <CardTitle className="flex items-center gap-2 text-sm font-semibold text-white">
                <UsersIcon className="h-4 w-4 text-cyan-400" /> Threat Category Inflow
              </CardTitle>
              <CardDescription className="text-xs text-muted-foreground">
                Newly attributed personas by threat category
              </CardDescription>
            </div>
            <div className="flex items-center gap-3 text-xs flex-wrap justify-end">
              {threatCategories.map((cat, idx) => (
                <div key={cat} className="flex items-center gap-1.5">
                  <span
                    className="h-2 w-2 rounded-full"
                    style={{ backgroundColor: CATEGORY_COLORS[idx % CATEGORY_COLORS.length] }}
                  />
                  <span className="text-muted-foreground">{cat}</span>
                </div>
              ))}
            </div>
          </CardHeader>
          <CardContent className="pt-2 flex-1 flex flex-col justify-between">
            <div className="w-full flex-1">
              <BarChart
                margin={{ top: 12, right: 8, bottom: 36, left: 8 }}
                data={weeklyInflowData}
                xDataKey="week"
                stacked
                stackGap={3}
                style={{ aspectRatio: "unset", height: 344 }}
              >
                <Grid horizontal />
                {threatCategories.map((cat, idx) => (
                  <Bar
                    key={cat}
                    dataKey={cat}
                    fill={CATEGORY_COLORS[idx % CATEGORY_COLORS.length]}
                    lineCap="butt"
                    stackGap={3}
                  />
                ))}
                <BarXAxis />
                <ChartTooltip />
              </BarChart>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Forensic Tri-Card Row: Attribution Opportunity Score, Confidence Spread, OpSec Clock */}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <ExposureGauge opportunity={stats?.attribution_opportunity} />
        <ConfidenceHistogram bins={stats?.confidence_distribution} />
        <OpSecClock hour={stats?.circular_mean_hour ?? null} />
      </div>

      {/* Bottom Row: Top Threat Personas & Content Clone Clusters */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Top Threat Personas */}
        <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md">
          <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2 text-white font-semibold">
                <UsersIcon className="h-4 w-4 text-cyan-400" /> Top Threat Personas
              </span>
              <Link href="/actors" className="text-xs text-zinc-400 hover:text-white flex items-center gap-1 transition-colors">
                View All <ArrowRightIcon className="h-3 w-3" />
              </Link>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-white/[0.08] text-muted-foreground">
                  <th className="pb-2 text-left font-medium">Handle</th>
                  <th className="pb-2 text-left font-medium">Category</th>
                  <th className="pb-2 text-right font-medium">Onions</th>
                  <th className="pb-2 text-right font-medium">Conf.</th>
                </tr>
              </thead>
              <tbody>
                {(stats?.top_actors ?? []).length === 0 && (
                  <tr>
                    <td colSpan={4} className="py-4 text-center text-muted-foreground">
                      No threat actors identified yet.
                    </td>
                  </tr>
                )}
                {(stats?.top_actors ?? []).slice(0, 5).map((a, i) => (
                  <tr key={i} className="border-b border-white/[0.04] last:border-0 hover:bg-white/[0.02] transition-colors">
                    <td className="py-2.5 font-mono text-foreground font-medium">{a.handle}</td>
                    <td className="py-2.5">
                      <Badge variant="outline" className="text-[10px] border-white/[0.1] text-zinc-300">
                        {a.category}
                      </Badge>
                    </td>
                    <td className="py-2.5 text-right tabular-nums text-zinc-300">{a.attributed_count}</td>
                    <td className={`py-2.5 text-right tabular-nums font-semibold ${confColor(a.confidence)}`}>
                      {(a.confidence * 100).toFixed(0)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </CardContent>
        </Card>

        {/* Content Clone Detection (Mirror Networks) */}
        <Card className="group/card relative overflow-hidden rounded-xl border border-white/[0.08] bg-card/95 backdrop-blur-md">
          <div className="pointer-events-none absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-white/15 to-transparent" />
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2 text-white font-semibold">
                <CopyIcon className="h-4 w-4 text-cyan-400" /> Content Clone Detection (Mirror Networks)
              </span>
              <Badge variant="secondary" className="text-[10px] rounded-md bg-white/[0.06] text-zinc-300 border border-white/[0.08]">
                {stats?.content_clusters?.length ?? 0} Clusters Identified
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(stats?.content_clusters ?? []).length === 0 && (
              <p className="py-4 text-center text-xs text-muted-foreground">
                No mirror network clusters detected.
              </p>
            )}
            {(stats?.content_clusters ?? []).map((cluster) => (
              <div
                key={cluster.cluster_id}
                className="rounded-lg border border-white/[0.07] bg-white/[0.02] p-3 space-y-1.5 hover:border-white/[0.12] transition-colors"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-foreground">{cluster.name}</span>
                  <Badge variant="outline" className="text-[10px] font-mono">
                    {(cluster.similarity * 100).toFixed(0)}% Similarity
                  </Badge>
                </div>
                <div className="text-[11px] text-muted-foreground font-mono truncate">
                  Fingerprint: {cluster.fingerprint} · {cluster.page_count} onion endpoints
                </div>
                {cluster.sample_urls.length > 0 && (
                  <div className="text-[10px] text-muted-foreground/80 font-mono truncate">
                    Sample: {cluster.sample_urls[0]}
                  </div>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Observed Infrastructure Geography (Corroborated IP Pivots & Choropleth) */}
      <ObservedInfrastructureGeography geo={stats?.infrastructure_geography} />
    </div>
  );
}
