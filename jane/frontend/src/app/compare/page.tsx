"use client";

import { useEffect, useState } from "react";
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  UsersIcon,
  TrendingUpIcon,
  SearchIcon,
  NetworkIcon,
  CopyIcon,
  BarChart3Icon,
} from "@/components/icons";

interface ActorProfile {
  id: string;
  handle: string;
  category: string;
  confidence: number;
  onion_count: number;
  identifier_count: number;
  identifiers: Array<{ type: string; value: string }>;
  onions: string[];
  opsec_rating: string;
  attack_vector: string;
}

interface JaccardItem {
  actor_a: string;
  actor_b: string;
  shared_iocs: number;
  jaccard_index: number;
  overlap_status: string;
}

interface ScatterPoint {
  investigation_id: string;
  query: string;
  pages_scraped: number;
  iocs_extracted: number;
  confidence: number;
  roi_ratio: number;
  status: string;
}

interface CompareData {
  actors: ActorProfile[];
  jaccard_matrix: JaccardItem[];
  search_roi_scatter: ScatterPoint[];
}

export default function ComparePage() {
  const [data, setData] = useState<CompareData | null>(null);
  const [loading, setLoading] = useState(true);
  const [actorAId, setActorAId] = useState<string>("");
  const [actorBId, setActorBId] = useState<string>("");
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    fetch("/api/compare")
      .then((r) => r.json())
      .then((d) => {
        setData(d);
        if (d.actors && d.actors.length >= 2) {
          setActorAId(d.actors[0].id);
          setActorBId(d.actors[1].id);
        }
      })
      .catch((e) => console.error(e))
      .finally(() => setLoading(false));
  }, []);

  const actors = data?.actors || [];
  const actorA = actors.find((a) => a.id === actorAId) || actors[0];
  const actorB = actors.find((a) => a.id === actorBId) || actors[1];

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        {/* Header */}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold tracking-tight">Cross-Actor Comparison & Search ROI</h1>
            <p className="text-sm text-muted-foreground">
              Side-by-side threat actor attribution diffs, Jaccard overlap indices, and investigation harvest ROI.
            </p>
          </div>
          <Badge variant="secondary" className="self-start text-xs font-mono">
            {actors.length} OPERATOR PROFILES
          </Badge>
        </div>

        {/* Side-by-Side Threat Actor Comparison */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <h3 className="text-sm font-semibold tracking-tight">Direct Persona Discrepancy Matrix</h3>
            <div className="flex items-center gap-3">
              <select
                className="rounded-lg border border-border/50 bg-card px-3 py-1.5 text-xs font-mono text-foreground"
                value={actorAId}
                onChange={(e) => setActorAId(e.target.value)}
              >
                {actors.map((a) => (
                  <option key={a.id} value={a.id}>
                    Actor A: {a.handle}
                  </option>
                ))}
              </select>

              <span className="text-xs font-bold text-muted-foreground">VS</span>

              <select
                className="rounded-lg border border-border/50 bg-card px-3 py-1.5 text-xs font-mono text-foreground"
                value={actorBId}
                onChange={(e) => setActorBId(e.target.value)}
              >
                {actors.map((a) => (
                  <option key={a.id} value={a.id}>
                    Actor B: {a.handle}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid gap-4 md:grid-cols-2">
            {/* Actor A Profile Card */}
            {actorA && (
              <Card className="border-border/50 bg-card/80 backdrop-blur">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <Badge variant="default" className="text-[10px]">
                      TARGET PERSONA A
                    </Badge>
                    <Badge variant="destructive" className="text-[10px]">
                      {actorA.opsec_rating}
                    </Badge>
                  </div>
                  <CardTitle className="text-base font-mono font-bold mt-2 text-foreground">
                    {actorA.handle}
                  </CardTitle>
                  <CardDescription className="text-xs">{actorA.category}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-2 border-y border-border/40 py-2.5">
                    <div>
                      <span className="text-muted-foreground">Confidence:</span>
                      <p className="font-mono font-bold text-emerald-400">
                        {(actorA.confidence * 100).toFixed(0)}%
                      </p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Attributed Onions:</span>
                      <p className="font-mono font-bold text-foreground">{actorA.onion_count}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Known Indicators:</span>
                      <p className="font-mono font-bold text-primary">{actorA.identifier_count}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Vector:</span>
                      <p className="font-medium text-foreground truncate">{actorA.attack_vector}</p>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                      Associated Darknet Onion Services
                    </span>
                    <div className="space-y-1 max-h-24 overflow-y-auto">
                      {actorA.onions.map((o, idx) => (
                        <div key={idx} className="font-mono text-[11px] text-muted-foreground truncate bg-muted/20 p-1 rounded">
                          {o}
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Actor B Profile Card */}
            {actorB && (
              <Card className="border-border/50 bg-card/80 backdrop-blur">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <Badge variant="default" className="text-[10px]">
                      TARGET PERSONA B
                    </Badge>
                    <Badge variant="destructive" className="text-[10px]">
                      {actorB.opsec_rating}
                    </Badge>
                  </div>
                  <CardTitle className="text-base font-mono font-bold mt-2 text-foreground">
                    {actorB.handle}
                  </CardTitle>
                  <CardDescription className="text-xs">{actorB.category}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3 text-xs">
                  <div className="grid grid-cols-2 gap-2 border-y border-border/40 py-2.5">
                    <div>
                      <span className="text-muted-foreground">Confidence:</span>
                      <p className="font-mono font-bold text-emerald-400">
                        {(actorB.confidence * 100).toFixed(0)}%
                      </p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Attributed Onions:</span>
                      <p className="font-mono font-bold text-foreground">{actorB.onion_count}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Known Indicators:</span>
                      <p className="font-mono font-bold text-primary">{actorB.identifier_count}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Vector:</span>
                      <p className="font-medium text-foreground truncate">{actorB.attack_vector}</p>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground">
                      Associated Darknet Onion Services
                    </span>
                    <div className="space-y-1 max-h-24 overflow-y-auto">
                      {actorB.onions.map((o, idx) => (
                        <div key={idx} className="font-mono text-[11px] text-muted-foreground truncate bg-muted/20 p-1 rounded">
                          {o}
                        </div>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>

        {/* Jaccard Similarity Matrix & Search ROI Scatter Plot */}
        <div className="grid gap-4 lg:grid-cols-2">
          {/* Jaccard Similarity Matrix Table */}
          <Card className="border-border/50 bg-card/80 backdrop-blur">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <NetworkIcon className="h-4 w-4" /> Jaccard Indicator Overlap Matrix
              </CardTitle>
              <CardDescription className="text-xs">
                Pairwise intersection ratio J(A, B) = |A &cap; B| / |A &cup; B| revealing syndicate co-conspirators
              </CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <table className="w-full text-xs">
                <thead className="border-b border-border/50 text-muted-foreground">
                  <tr>
                    <th className="px-4 py-3 text-left">Persona Pair</th>
                    <th className="px-4 py-3 text-left">Shared IOCs</th>
                    <th className="px-4 py-3 text-left">Jaccard Index</th>
                    <th className="px-4 py-3 text-right">Assessment</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.jaccard_matrix || []).map((row, idx) => (
                    <tr key={idx} className="border-b border-border/10 last:border-0 hover:bg-muted/30">
                      <td className="px-4 py-3 font-mono font-medium text-foreground">
                        {row.actor_a} &harr; {row.actor_b}
                      </td>
                      <td className="px-4 py-3 tabular-nums font-semibold text-primary">
                        {row.shared_iocs} indicators
                      </td>
                      <td className="px-4 py-3 font-mono font-semibold text-emerald-400">
                        {row.jaccard_index.toFixed(3)}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <Badge
                          variant={row.jaccard_index > 0.3 ? "destructive" : "secondary"}
                          className="text-[10px]"
                        >
                          {row.overlap_status}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </CardContent>
          </Card>

          {/* Search / Investigation ROI Scatter Plot */}
          <Card className="border-border/50 bg-card/80 backdrop-blur">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-sm">
                <BarChart3Icon className="h-4 w-4" /> Investigation Yield & Search ROI
              </CardTitle>
              <CardDescription className="text-xs">
                X: Pages Crawled vs. Y: Actionable Indicators Extracted (Bubble: Attribution Confidence)
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-64 w-full">
                {mounted && (data?.search_roi_scatter || []).length > 0 ? (
                  <ResponsiveContainer width="100%" height="100%">
                    <ScatterChart margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                      <XAxis
                        type="number"
                        dataKey="pages_scraped"
                        name="Pages Crawled"
                        stroke="hsl(var(--muted-foreground))"
                        fontSize={10}
                      />
                      <YAxis
                        type="number"
                        dataKey="iocs_extracted"
                        name="IOCs Extracted"
                        stroke="hsl(var(--muted-foreground))"
                        fontSize={10}
                      />
                      <ZAxis type="number" dataKey="confidence" range={[60, 200]} name="Confidence" />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: "hsl(var(--card))",
                          borderColor: "hsl(var(--border))",
                          borderRadius: "8px",
                          fontSize: "12px",
                        }}
                        cursor={{ strokeDasharray: "3 3" }}
                      />
                      <Scatter
                        name="Investigations"
                        data={data?.search_roi_scatter || []}
                        fill="hsl(var(--primary))"
                      />
                    </ScatterChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="flex h-full items-center justify-center text-xs text-muted-foreground">
                    Harvest telemetry plotting...
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </AppShell>
  );
}
