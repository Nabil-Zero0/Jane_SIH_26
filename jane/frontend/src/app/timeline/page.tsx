"use client";

import { useEffect, useMemo, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  ClockIcon,
  SearchIcon,
  ServerCrashIcon,
} from "@/components/icons";
import {
  HeatmapChart,
  HeatmapCells,
  HeatmapSeparator,
  HeatmapXAxis,
  HeatmapYAxis,
  HeatmapTooltip,
  HeatmapLegend,
  type HeatmapColumn,
} from "@bklitui/ui/charts";

interface DayData {
  date: string;
  events: number;
  pages: number;
  iocs: number;
}

interface LifecycleItem {
  id: string;
  type: string;
  value: string;
  first_seen: string;
  last_seen: string;
  duration_days: number;
  confidence: number;
  status: "ACTIVE" | "DORMANT" | "RETIRED";
}

interface ChurnAlert {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  title: string;
  description: string;
  affected_asset: string;
  detected_at: string;
  ioc_type: string;
}

interface TimelineData {
  heatmap_90d: DayData[];
  lifecycles: LifecycleItem[];
  churn_alerts: ChurnAlert[];
}

/** Convert flat [{date, events}] from the API → HeatmapColumn[] (week columns, 7 day bins). */
function toHeatmapColumns(days: DayData[]): HeatmapColumn[] {
  if (!days.length) return [];

  const countByDate = new Map<string, number>();
  for (const d of days) countByDate.set(d.date, d.events);

  const first = new Date(days[0].date);
  const last = new Date(days[days.length - 1].date);

  // Walk back to Sunday for alignment
  const rangeStart = new Date(first);
  rangeStart.setDate(rangeStart.getDate() - rangeStart.getDay());
  rangeStart.setHours(0, 0, 0, 0);

  const columns: HeatmapColumn[] = [];
  const cur = new Date(rangeStart);
  const MS_WEEK = 7 * 24 * 60 * 60 * 1000;

  while (cur <= last) {
    const colBin = Math.floor((cur.getTime() - rangeStart.getTime()) / MS_WEEK);
    const bins = [];
    for (let dow = 0; dow < 7; dow++) {
      const d = new Date(cur);
      d.setDate(d.getDate() + dow);
      const key = d.toISOString().slice(0, 10);
      bins.push({ bin: dow, count: countByDate.get(key) ?? 0, date: new Date(d) });
    }
    columns.push({ bin: colBin, bins });
    cur.setDate(cur.getDate() + 7);
  }
  return columns;
}

export default function TimelinePage() {
  const [data, setData] = useState<TimelineData | null>(null);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    fetch("/api/timeline")
      .then((r) => r.json())
      .then((d) => setData(d))
      .catch((e) => console.error(e))
      .finally(() => setLoading(false));
  }, []);

  const heatmapData = useMemo(
    () => toHeatmapColumns(data?.heatmap_90d ?? []),
    [data?.heatmap_90d]
  );

  const filteredLifecycles = (data?.lifecycles || []).filter(
    (item) =>
      item.value.toLowerCase().includes(filter.toLowerCase()) ||
      item.type.toLowerCase().includes(filter.toLowerCase()) ||
      item.status.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        {/* Header */}
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-bold tracking-tight">Temporal Intelligence & IOC Lifecycle</h1>
            <p className="text-sm text-muted-foreground">
              90-day activity density, operational lifecycle tracking, and fast-flux infrastructure churn alerts.
            </p>
          </div>
          <Badge variant="secondary" className="self-start text-xs font-mono">
            90-DAY FORENSIC WINDOW
          </Badge>
        </div>

        {/* 90-Day Activity Heatmap — BKlit */}
        <Card className="group/card relative overflow-hidden border border-dashed border-border/70 bg-zinc-950/90 backdrop-blur transition-colors duration-200 hover:border-primary/40">
          <div
            className="pointer-events-none absolute inset-0 opacity-10 transition-opacity duration-300 group-hover/card:opacity-25 text-foreground"
            style={{
              backgroundImage: "radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)",
              backgroundSize: "14px 14px",
            }}
          />
          <CardHeader>
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
              <div>
                <CardTitle className="flex items-center gap-2 text-sm">
                  <ClockIcon className="h-4 w-4 text-primary" /> 90-Day Darknet Ingest Calendar Density
                </CardTitle>
                <CardDescription className="text-xs">
                  Daily crawl frequency and indicator discovery rhythm
                </CardDescription>
              </div>
              <Badge variant="outline" className="text-[10px] font-mono self-start">
                {loading ? "LOADING…" : `${data?.heatmap_90d?.length ?? 0} DAYS`}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-3">
            <HeatmapChart data={heatmapData} gap={3} layout="fluid">
              <HeatmapCells
                cornerRadius={999}
                inactiveOpacity={0.8}
                inactiveScale={0.94}
              />
              <HeatmapSeparator
                groupBy="quarter"
                showLabels
                labelClassName="text-[var(--chart-3)]"
                spacing={12}
                startOffset={14}
                strokeOpacity={0.6}
              />
              <HeatmapXAxis />
              <HeatmapYAxis tickFilter="all" labelFormat="initial" />
              <HeatmapTooltip />
            </HeatmapChart>
            <HeatmapLegend
              align="center"
              cornerRadius={999}
              gap={3}
              inactiveOpacity={0.8}
              inactiveScale={0.94}
            />
          </CardContent>
        </Card>

        {/* Infrastructure Churn & Rotation Alerts */}
        <Card className="border-border/50 bg-card/80 backdrop-blur">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <ServerCrashIcon className="h-4 w-4 text-red-400" /> Infrastructure Churn & Rotation Alerts
            </CardTitle>
            <CardDescription className="text-xs">
              Fast-flux domain rotations, sudden IP re-assignments, and synchronized ETag refreshes
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-3">
            {(data?.churn_alerts || []).map((alert) => (
              <div
                key={alert.id}
                className="rounded-xl border border-red-500/30 bg-red-500/5 p-3.5 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <Badge variant="destructive" className="text-[10px]">
                    {alert.severity}
                  </Badge>
                  <span className="font-mono text-[10px] text-muted-foreground">{alert.detected_at}</span>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-foreground">{alert.title}</h4>
                  <p className="mt-1 text-[11px] text-muted-foreground leading-relaxed">
                    {alert.description}
                  </p>
                </div>
                <div className="text-[10px] text-muted-foreground font-mono truncate border-t border-red-500/20 pt-1.5">
                  Asset: <span className="text-foreground">{alert.affected_asset}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* IOC Lifecycle Tracker Table */}
        <div className="space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold tracking-tight">Indicator of Compromise (IOC) Lifecycles</h3>
              <p className="text-xs text-muted-foreground">
                Operational duration tracking and persistence classification
              </p>
            </div>
            <div className="flex items-center gap-2">
              <SearchIcon className="h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Filter by indicator or type..."
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                className="max-w-xs font-mono text-xs"
              />
            </div>
          </div>

          <Card className="border-border/50 bg-card/80 backdrop-blur">
            <CardContent className="p-0">
              <table className="w-full text-xs">
                <thead className="border-b border-border/50 text-muted-foreground">
                  <tr>
                    <th className="px-4 py-3 text-left">Lifecycle State</th>
                    <th className="px-4 py-3 text-left">Indicator & Type</th>
                    <th className="px-4 py-3 text-left">First Seen</th>
                    <th className="px-4 py-3 text-left">Last Seen</th>
                    <th className="px-4 py-3 text-right">Active Span</th>
                    <th className="px-4 py-3 text-right">Confidence</th>
                  </tr>
                </thead>
                <tbody>
                  {!loading && filteredLifecycles.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-10 text-center text-muted-foreground">
                        No IOCs match current filter.
                      </td>
                    </tr>
                  )}
                  {filteredLifecycles.map((item) => (
                    <tr key={item.id} className="border-b border-border/10 last:border-0 hover:bg-muted/30">
                      <td className="px-4 py-3">
                        <Badge
                          variant={
                            item.status === "ACTIVE"
                              ? "default"
                              : item.status === "DORMANT"
                              ? "secondary"
                              : "outline"
                          }
                          className="text-[10px]"
                        >
                          {item.status}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 space-y-0.5 max-w-xs">
                        <div className="font-mono font-semibold text-foreground truncate">
                          {item.value}
                        </div>
                        <div className="text-[10px] text-muted-foreground">
                          Type: <span className="text-primary">{item.type}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-muted-foreground">
                        {item.first_seen}
                      </td>
                      <td className="px-4 py-3 font-mono text-[11px] text-muted-foreground">
                        {item.last_seen}
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums text-foreground">
                        {item.duration_days} days
                      </td>
                      <td className="px-4 py-3 text-right font-mono tabular-nums font-semibold text-emerald-400">
                        {(item.confidence * 100).toFixed(0)}%
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
