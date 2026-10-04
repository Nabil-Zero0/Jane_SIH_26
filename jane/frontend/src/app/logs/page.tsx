"use client";

import { useEffect, useRef, useState } from "react";
import { AppShell } from "@/components/app-shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface LogEntry {
  timestamp?: string;
  level?: string;
  stage?: string;
  message?: string;
  [key: string]: any;
}

const LEVEL_COLOR: Record<string, string> = {
  ERROR: "text-red-400",
  SUCCESS: "text-emerald-400",
  WARNING: "text-yellow-400",
  INFO: "text-foreground/70",
  DEBUG: "text-muted-foreground",
};

export default function LogsPage() {
  const [investigations, setInvestigations] = useState<any[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [static_logs, setStaticLogs] = useState<LogEntry[]>([]);
  const [filter, setFilter] = useState<string>("ALL");
  const [live, setLive] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    fetch("/api/investigations")
      .then((r) => r.json())
      .then((d) => {
        const invs = d.investigations || [];
        setInvestigations(invs);
        if (invs.length > 0) setSelected(invs[0].id);
      });
  }, []);

  useEffect(() => {
    if (!selected) return;
    // Fetch static logs
    fetch(`/api/logs?id=${selected}`)
      .then((r) => r.json())
      .then((d) => setStaticLogs(d.logs || []));
  }, [selected]);

  const startLive = () => {
    if (!selected) return;
    setLogs([]);
    setLive(true);
    esRef.current?.close();
    const es = new EventSource(`/api/events?id=${selected}`);
    esRef.current = es;
    es.onmessage = (e) => {
      const payload = JSON.parse(e.data);
      if (payload.log) setLogs((prev) => [...prev, payload.log]);
      if (payload.status) { setLive(false); es.close(); }
    };
    es.onerror = () => { setLive(false); es.close(); };
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs, static_logs]);

  const displayLogs = live ? logs : static_logs;
  const filtered = displayLogs.filter(
    (log) => filter === "ALL" || (log.level || "INFO").toUpperCase() === filter
  );

  return (
    <AppShell>
      <div className="space-y-6 p-4 lg:p-6">
        <div>
          <h1 className="text-xl font-bold tracking-tight">Pipeline Audit Log</h1>
          <p className="text-sm text-muted-foreground">
            Full chronological pipeline execution events. Connect live SSE stream or review stored logs.
          </p>
        </div>

        {/* Controls */}
        <div className="flex flex-wrap items-center gap-3">
          <select
            className="rounded border border-border/50 bg-card px-3 py-1.5 text-sm"
            value={selected}
            onChange={(e) => { setSelected(e.target.value); setLive(false); esRef.current?.close(); }}
          >
            {investigations.map((inv) => (
              <option key={inv.id} value={inv.id}>{inv.query} ({inv.id})</option>
            ))}
          </select>

          <Button size="sm" variant={live ? "destructive" : "default"} onClick={() => {
            if (live) { setLive(false); esRef.current?.close(); } else { startLive(); }
          }}>
            {live ? "⬛ Stop Live" : "⚡ Live Stream"}
          </Button>

          {live && <span className="flex items-center gap-1 text-xs text-emerald-400"><span className="h-2 w-2 animate-pulse rounded-full bg-emerald-400" />Connected</span>}

          <div className="ml-auto flex gap-1">
            {["ALL", "INFO", "SUCCESS", "WARNING", "ERROR"].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setFilter(lvl)}
                className={`rounded px-2 py-1 text-xs transition ${filter === lvl ? "bg-primary text-primary-foreground" : "bg-muted/30 text-muted-foreground hover:bg-muted/50"}`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>

        {/* Log stats */}
        <div className="flex gap-4 text-xs text-muted-foreground">
          <span>Total: <strong className="text-foreground">{displayLogs.length}</strong></span>
          {["INFO", "SUCCESS", "WARNING", "ERROR"].map((lvl) => {
            const count = displayLogs.filter((l) => (l.level || "INFO").toUpperCase() === lvl).length;
            if (!count) return null;
            return <span key={lvl}>{lvl}: <strong className={LEVEL_COLOR[lvl]}>{count}</strong></span>;
          })}
        </div>

        {/* Log viewer */}
        <Card className="border-border/50 bg-card/80">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono">
              {live ? "LIVE STREAM" : "STORED LOGS"} — {selected}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div
              ref={logRef}
              className="h-[500px] overflow-y-auto rounded bg-slate-950 p-4 font-mono text-[11px] leading-5"
            >
              {filtered.length === 0 && (
                <span className="text-muted-foreground">
                  {displayLogs.length === 0 ? "No logs available. Select an investigation or start a live stream." : "No entries match this filter."}
                </span>
              )}
              {filtered.map((log, i) => {
                const level = (log.level || "INFO").toUpperCase();
                const ts = log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : "";
                const stage = log.stage ? `[${log.stage}] ` : "";
                const msg = log.message || JSON.stringify(log);
                return (
                  <div key={i} className={`${LEVEL_COLOR[level] ?? "text-foreground/70"}`}>
                    {ts && <span className="text-slate-600 mr-2">{ts}</span>}
                    <span className="mr-2 text-slate-500">[{level}]</span>
                    {stage && <span className="text-blue-400 mr-1">{stage}</span>}
                    {msg}
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
