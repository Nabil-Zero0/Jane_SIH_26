"use client";

import { useEffect, useMemo, useState } from "react";
import { curveCatmullRom } from "@visx/curve";
import {
  RadarChart,
  RadarGrid,
  RadarAxis,
  RadarLabels,
  RadarArea,
  type RadarData,
  type RadarMetric,
  ComposedChart,
  Area,
  SeriesBar,
  Line,
  Grid,
  XAxis,
  ChartTooltip,
} from "@/components/charts";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  SearchIcon,
  FlaskConicalIcon,
  CheckCircle2Icon,
  AlertCircleIcon,
  UsersIcon,
  TrendingUpIcon,
} from "@/components/icons";

interface SixDVectorPoint {
  dimension: string;
  value: number;
  benchmark: number;
  unit: string;
}

interface FeatureContribution {
  word: string;
  delta: number;
  direction: "OVERUSED" | "AVOIDED";
}

interface CandidateMatch {
  candidate: string;
  delta_distance: number;
  match_prob: number;
}

interface StylometryProfile {
  actor_id: string;
  handle: string;
  threat_category: string;
  confidence: number;
  char_count: number;
  viability: "HIGH" | "MODERATE" | "LOW";
  six_d_vector: SixDVectorPoint[];
  feature_contributions: FeatureContribution[];
  candidate_matches: CandidateMatch[];
  stylometry: Record<string, any>;
}

// ── BklitRadarChart: wraps bklit RadarChart with 6D vector data ─────────────
function BklitRadarChart({ selected }: { selected: StylometryProfile }) {
  const metrics: RadarMetric[] = useMemo(
    () => selected.six_d_vector.map((d) => ({ key: d.dimension, label: d.dimension })),
    [selected.six_d_vector]
  );
  const data: RadarData[] = useMemo(
    () => [
      {
        label: "Target Persona",
        color: "var(--chart-1)",
        values: Object.fromEntries(selected.six_d_vector.map((d) => [d.dimension, d.value])),
      },
      {
        label: "Darknet Baseline",
        color: "var(--chart-3)",
        values: Object.fromEntries(selected.six_d_vector.map((d) => [d.dimension, d.benchmark])),
      },
    ],
    [selected.six_d_vector]
  );
  return (
    <RadarChart data={data} metrics={metrics} className="h-72">
      <RadarGrid showLabels={false} />
      <RadarAxis />
      <RadarLabels />
      <RadarArea index={0} />
      <RadarArea index={1} showPoints={false} />
    </RadarChart>
  );
}

// ── DeltaComposedChart: bklit ComposedChart for Z-score delta bars ───────────
function DeltaComposedChart({ contributions }: { contributions: FeatureContribution[] }) {
  const data = useMemo(
    () =>
      contributions.map((c) => ({
        date: c.word,
        label: c.word,
        units: Math.max(0, c.delta),
        runRate: Math.min(0, c.delta),
        revenue: c.delta,
      })),
    [contributions]
  );
  return (
    <ComposedChart
      data={data}
      xDataKey="date"
      margin={{ top: 8, right: 8, bottom: 40, left: 8 }}
      barGap={0}
      maxBarSize={32}
      aspectRatio="2 / 1"
    >
      <Grid horizontal />
      <Area dataKey="runRate" curve={curveCatmullRom.alpha(0.42)} fill="var(--chart-4)" fillOpacity={0.32} />
      <SeriesBar dataKey="units" fill="var(--chart-3)" radius={4} />
      <Line dataKey="revenue" curve={curveCatmullRom.alpha(0.42)} stroke="var(--chart-1)" strokeWidth={2.5} />
      <ChartTooltip showCrosshair={false} />
      <XAxis numTicks={8} />
    </ComposedChart>
  );
}

export default function StylometryPage() {
  const [profiles, setProfiles] = useState<StylometryProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<StylometryProfile | null>(null);
  const [filter, setFilter] = useState("");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    fetch("/api/stylometry")
      .then((r) => r.json())
      .then((d) => {
        const list = d.stylometry_profiles || [];
        setProfiles(list);
        if (list.length > 0) {
          setSelected(list[0]);
        }
      })
      .catch((e) => console.error(e))
      .finally(() => setLoading(false));
  }, []);

  const filtered = profiles.filter((p) =>
    p.handle.toLowerCase().includes(filter.toLowerCase()) ||
    p.threat_category.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        {/* Header */}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold tracking-tight">Stylometry Forensic Lab</h1>
            <p className="text-sm text-muted-foreground">
              6D linguistic fingerprinting, Burrows&apos; Delta distance, function word divergence, and candidate ranking.
            </p>
          </div>
          <Badge variant="secondary" className="self-start text-xs font-mono">
            {profiles.length} PERSONA PROFILES
          </Badge>
        </div>

        {/* Selected Actor Deep Inspection */}
        {selected && (
          <div className="grid gap-4 lg:grid-cols-3">
            {/* 6D Linguistic Radar Profile */}
            <Card className="border-border/50 bg-card/80 backdrop-blur lg:col-span-2">
              <CardHeader>
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
                  <div>
                    <CardTitle className="flex items-center gap-2 text-sm">
                      <FlaskConicalIcon className="h-4 w-4 text-primary" /> 6D Linguistic Signature — {selected.handle}
                    </CardTitle>
                    <CardDescription className="text-xs">
                      Radar comparison vs. Darknet Baseline Corpus (Vocabulary, Entropy, Punctuation, Length)
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge
                      variant={
                        selected.viability === "HIGH"
                          ? "secondary"
                          : selected.viability === "MODERATE"
                          ? "outline"
                          : "destructive"
                      }
                      className="text-[10px]"
                    >
                      {selected.viability} VIABILITY ({selected.char_count} chars)
                    </Badge>
                    <Badge variant="outline" className="text-[10px]">
                      {(selected.confidence * 100).toFixed(0)}% Conf.
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="w-full">
                  {mounted && selected.six_d_vector && (
                    <BklitRadarChart selected={selected} />
                  )}
                </div>
                <div className="grid grid-cols-3 gap-2 pt-2 border-t border-border/40 text-[11px] text-muted-foreground text-center">
                  <div>
                    <span className="text-foreground font-semibold">Vocabulary:</span> {selected.six_d_vector[0]?.value} Yule&apos;s K
                  </div>
                  <div>
                    <span className="text-foreground font-semibold">Sentence:</span> {selected.six_d_vector[1]?.value} Words
                  </div>
                  <div>
                    <span className="text-foreground font-semibold">Entropy:</span> {selected.six_d_vector[4]?.value} pts
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Candidate Match Ranker */}
            <Card className="border-border/50 bg-card/80 backdrop-blur">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <UsersIcon className="h-4 w-4" /> Burrows&apos; Delta Candidates
                </CardTitle>
                <CardDescription className="text-xs">
                  Ranked author profile matches by feature distance
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {selected.candidate_matches.map((cand, i) => (
                  <div
                    key={cand.candidate}
                    className="rounded-lg border border-border/40 bg-muted/20 p-3 space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold text-foreground font-mono">
                        #{i + 1} {cand.candidate}
                      </span>
                      <Badge
                        variant={cand.match_prob > 80 ? "destructive" : cand.match_prob > 60 ? "secondary" : "outline"}
                        className="text-[10px]"
                      >
                        {cand.match_prob}% Match
                      </Badge>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                      <span>Delta Distance: <strong className="font-mono text-foreground">{cand.delta_distance}</strong></span>
                      <span>{cand.delta_distance < 0.5 ? "STRONG ATTRIBUTION" : "POSSIBLE ALIAS"}</span>
                    </div>
                    <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                      <div
                        className={`h-full ${cand.match_prob > 80 ? "bg-red-500" : "bg-primary"}`}
                        style={{ width: `${cand.match_prob}%` }}
                      />
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        )}

        {/* Top 10 Divergent Function Words Feature Bar Chart */}
        {selected && selected.feature_contributions && (
          <Card className="border-border/50 bg-card/80 backdrop-blur">
            <CardHeader>
              <CardTitle className="flex items-center justify-between text-sm">
                <span className="flex items-center gap-2">
                  <TrendingUpIcon className="h-4 w-4" /> Top 10 Divergent Function Words (Delta Z-Scores)
                </span>
                <span className="text-xs text-muted-foreground">Linguistic OpSec telltales</span>
              </CardTitle>
              <CardDescription className="text-xs">
                Tokens showing statistical over-representation (&gt;0) or under-representation (&lt;0) compared to corpus mean
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="w-full">
                {mounted && (
                  <DeltaComposedChart contributions={selected.feature_contributions} />
                )}
              </div>
            </CardContent>
          </Card>
        )}

        {/* All Actor Profiles Table */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <SearchIcon className="h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Filter threat personas by handle or category..."
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="max-w-sm font-mono text-xs"
            />
          </div>

          <Card className="border-border/50 bg-card/80 backdrop-blur">
            <CardContent className="p-0">
              <table className="w-full text-xs">
                <thead className="border-b border-border/50 text-muted-foreground">
                  <tr>
                    <th className="px-4 py-3 text-left">Persona Handle</th>
                    <th className="px-4 py-3 text-left">Threat Category</th>
                    <th className="px-4 py-3 text-left">Viability Rating</th>
                    <th className="px-4 py-3 text-right">Confidence</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {!loading && filtered.length === 0 && (
                    <tr>
                      <td colSpan={5} className="py-10 text-center text-muted-foreground">
                        No stylometry profiles match your filter.
                      </td>
                    </tr>
                  )}
                  {filtered.map((p) => (
                    <tr
                      key={p.actor_id}
                      onClick={() => setSelected(p)}
                      className={`cursor-pointer border-b border-border/20 last:border-0 hover:bg-muted/40 transition-colors ${selected?.actor_id === p.actor_id ? "bg-muted/30" : ""}`}
                    >
                      <td className="px-4 py-3 font-mono font-semibold text-foreground">
                        {p.handle}
                      </td>
                      <td className="px-4 py-3 text-muted-foreground">
                        <Badge variant="outline" className="text-[10px]">
                          {p.threat_category}
                        </Badge>
                      </td>
                      <td className="px-4 py-3">
                        <Badge
                          variant={
                            p.viability === "HIGH"
                              ? "secondary"
                              : p.viability === "MODERATE"
                              ? "outline"
                              : "destructive"
                          }
                          className="text-[10px]"
                        >
                          {p.viability} ({p.char_count} chars)
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums font-semibold text-emerald-400">
                        {(p.confidence * 100).toFixed(0)}%
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelected(p);
                          }}
                          className="h-7 text-xs"
                        >
                          Analyze
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>
        </div>
      </div>
    </AppShell>
  );
}
