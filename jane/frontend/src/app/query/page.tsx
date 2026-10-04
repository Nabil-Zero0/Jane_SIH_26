"use client";

import { useEffect, useState, useRef } from "react";
import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Play,
  Sparkles,
  Database,
  Plus,
  Copy,
  Check,
  ChevronRight,
  ChevronLeft,
  Table as TableIcon,
  Search,
  PanelLeftClose,
  PanelLeft,
  Download,
  AlertTriangle,
  RotateCcw,
  Terminal,
  FileCode,
  ShieldAlert,
  FileText,
  Clock,
  Layers,
} from "lucide-react";

interface QuerySession {
  id: string;
  label: string;
  created_at: string;
  query_count?: number;
  last_query_at?: string;
}

interface QueryHistoryItem {
  id: string;
  session_id: string;
  natural_language_question?: string | null;
  generated_sql: string;
  executed: number;
  row_count?: number | null;
  error_message?: string | null;
  ran_at: string;
}

interface QueryResult {
  success: boolean;
  query_id?: string;
  sql?: string;
  generated_sql?: string;
  columns?: string[];
  rows?: any[][];
  row_count?: number;
  latency_ms?: number;
  error?: string;
}

const CURATED_VIEW_TEMPLATES = [
  {
    name: "v_actor_summary",
    desc: "Top Threat Actors by Confidence",
    sql: "SELECT actor_id, primary_handle, category, attribution_confidence, alias_count, marketplace_count, product_count\nFROM v_actor_summary\nORDER BY attribution_confidence DESC\nLIMIT 50;",
  },
  {
    name: "v_actor_identifiers",
    desc: "Extracted Wallets & Identifiers",
    sql: "SELECT actor_id, primary_handle, identifier_type, identifier_value, is_shared, confidence\nFROM v_actor_identifiers\nORDER BY confidence DESC\nLIMIT 50;",
  },
  {
    name: "v_actor_identifiers (Shared)",
    desc: "Shared Multi-Actor Pivot Identifiers",
    sql: "SELECT actor_id, primary_handle, identifier_type, identifier_value, confidence, evidence_quote\nFROM v_actor_identifiers\nWHERE is_shared = 1\nORDER BY identifier_type, identifier_value;",
  },
  {
    name: "v_marketplace_activity",
    desc: "Dark Web Markets & Activity",
    sql: "SELECT marketplace_id, onion_domain, display_name, category, actor_count, infrastructure_findings_count\nFROM v_marketplace_activity\nORDER BY actor_count DESC, infrastructure_findings_count DESC\nLIMIT 50;",
  },
  {
    name: "v_infrastructure_findings",
    desc: "Corroborated Leaked IPs & Server Banners",
    sql: "SELECT finding_id, onion_domain, finding_type, value, evidence_quote, found_at\nFROM v_infrastructure_findings\nORDER BY found_at DESC\nLIMIT 50;",
  },
  {
    name: "v_actor_trust_links",
    desc: "Actor-to-Actor Vouch & Trust Links",
    sql: "SELECT actor_handle, trusted_actor_handle, confidence, evidence_quote, created_at\nFROM v_actor_trust_links\nORDER BY confidence DESC\nLIMIT 50;",
  },
  {
    name: "v_clearnet_accounts",
    desc: "OSINT Clearnet Profiles",
    sql: "SELECT account_id, primary_handle, platform, value, evidence_quote\nFROM v_clearnet_accounts\nORDER BY primary_handle\nLIMIT 50;",
  },
];

export default function QueryDashboardPage() {
  const [sessions, setSessions] = useState<QuerySession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string>("");
  const [sessionHistory, setSessionHistory] = useState<QueryHistoryItem[]>([]);
  const [sidebarOpen, setSidebarOpen] = useState(true);

  // Input states
  const [mode, setMode] = useState<"natural" | "sql">("natural");
  const [naturalQuestion, setNaturalQuestion] = useState("");
  const [rawSql, setRawSql] = useState(CURATED_VIEW_TEMPLATES[0].sql);

  // Execution state
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [copied, setCopied] = useState(false);

  // Pagination & filter
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [filterText, setFilterText] = useState("");
  const [exportLoading, setExportLoading] = useState<string | null>(null);

  // Fetch sessions on mount
  useEffect(() => {
    fetchSessions();
  }, []);

  // Fetch session history when active session changes
  useEffect(() => {
    if (activeSessionId) {
      fetchSessionHistory(activeSessionId);
    } else {
      setSessionHistory([]);
    }
  }, [activeSessionId]);

  const fetchSessions = async () => {
    try {
      const res = await fetch("/api/query/sessions");
      const data = await res.json();
      if (data.sessions && data.sessions.length > 0) {
        setSessions(data.sessions);
        if (!activeSessionId) {
          setActiveSessionId(data.sessions[0].id);
        }
      } else {
        // Create initial session if none
        handleCreateSession();
      }
    } catch (err) {
      console.error("Failed to load query sessions:", err);
    }
  };

  const fetchSessionHistory = async (sid: string) => {
    try {
      const res = await fetch(`/api/query/session/${sid}/history`);
      const data = await res.json();
      if (data.history) {
        setSessionHistory(data.history);
      }
    } catch (err) {
      console.error("Failed to load session history:", err);
    }
  };

  const handleCreateSession = async () => {
    try {
      const res = await fetch("/api/query/session", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ label: `Investigation Query ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` }),
      });
      const data = await res.json();
      if (data.session) {
        setSessions((prev) => [data.session, ...prev]);
        setActiveSessionId(data.session.id);
        setResult(null);
      }
    } catch (err) {
      console.error("Failed to create query session:", err);
    }
  };

  const handleRunQuery = async () => {
    setLoading(true);
    setResult(null);
    setPage(1);

    const payload: { session_id: string; sql?: string; question?: string } = {
      session_id: activeSessionId,
    };

    if (mode === "natural") {
      if (!naturalQuestion.trim()) {
        setLoading(false);
        return;
      }
      payload.question = naturalQuestion.trim();
    } else {
      if (!rawSql.trim()) {
        setLoading(false);
        return;
      }
      payload.sql = rawSql.trim();
    }

    try {
      const res = await fetch("/api/query/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data: QueryResult = await res.json();
      setResult(data);

      // Refresh session history & sessions list
      if (activeSessionId) {
        fetchSessionHistory(activeSessionId);
      }
      fetchSessions();
    } catch (err: any) {
      setResult({
        success: false,
        error: err.message || "Failed to execute query",
        latency_ms: 0,
      });
    } finally {
      setLoading(false);
    }
  };

  const handleExport = async (format: "csv" | "json" | "report") => {
    if (!result || !result.rows || result.rows.length === 0) return;
    setExportLoading(format);
    try {
      const res = await fetch("/api/query/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          format: format === "report" ? "pdf" : format,
          columns: result.columns || [],
          rows: result.rows || [],
          query: result.sql || naturalQuestion || "Query Export",
        }),
      });

      if (!res.ok) {
        throw new Error("Export failed on server");
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      const ext = format === "report" ? "pdf" : format;
      a.download = `jane_query_result_${new Date().toISOString().replace(/[:.]/g, "-")}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error(`Export ${format} error:`, err);
    } finally {
      setExportLoading(null);
    }
  };

  const handleCopySql = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Filter rows client-side
  const filteredRows = (result?.rows || []).filter((row) => {
    if (!filterText.trim()) return true;
    const term = filterText.toLowerCase();
    return row.some((val) => String(val).toLowerCase().includes(term));
  });

  const totalPages = Math.ceil(filteredRows.length / pageSize) || 1;
  const paginatedRows = filteredRows.slice((page - 1) * pageSize, page * pageSize);

  return (
    <AppShell>
      <div className="flex flex-col h-[calc(100vh-5rem)] gap-3">
        {/* Top Header */}
        <div className="flex items-center justify-between border-b pb-3">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center w-9 h-9 rounded-lg bg-primary/10 text-primary border border-primary/20">
              <Database className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl font-bold tracking-tight text-foreground">Threat Intelligence Query Console</h1>
                <Badge variant="outline" className="text-xs bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
                  Read-Only Enforced
                </Badge>
                <Badge variant="secondary" className="text-xs font-mono">
                  SQLite mode=ro
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                Query curated intelligence views using natural language AI translation or raw SQL
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="h-8 gap-1.5 text-xs"
            >
              {sidebarOpen ? <PanelLeftClose className="w-3.5 h-3.5" /> : <PanelLeft className="w-3.5 h-3.5" />}
              {sidebarOpen ? "Hide Sessions" : "Show Sessions"}
            </Button>
            <Button
              size="sm"
              onClick={handleCreateSession}
              className="h-8 gap-1.5 text-xs bg-indigo-600 hover:bg-indigo-700 text-white"
            >
              <Plus className="w-3.5 h-3.5" />
              New Session
            </Button>
          </div>
        </div>

        {/* Main Workspace: Sidebar + Query Console */}
        <div className="flex flex-1 gap-3 overflow-hidden">
          {/* Left Sidebar: Sessions */}
          {sidebarOpen && (
            <Card className="w-64 flex flex-col shrink-0 overflow-hidden border-border/60 bg-card/60 backdrop-blur-sm">
              <div className="p-3 border-b flex items-center justify-between bg-muted/30">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5" />
                  Query Sessions
                </span>
                <Badge variant="secondary" className="text-[10px] px-1.5">
                  {sessions.length}
                </Badge>
              </div>

              <div className="flex-1 overflow-y-auto p-2 space-y-1">
                {sessions.map((sess) => {
                  const isActive = sess.id === activeSessionId;
                  return (
                    <button
                      key={sess.id}
                      onClick={() => setActiveSessionId(sess.id)}
                      className={`w-full text-left p-2.5 rounded-md transition-all text-xs flex flex-col gap-1 border ${
                        isActive
                          ? "bg-primary/10 border-primary/40 text-foreground font-medium shadow-sm"
                          : "border-transparent hover:bg-muted/50 text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      <div className="flex items-center justify-between w-full">
                        <span className="truncate max-w-[170px]">{sess.label || "Untitled Session"}</span>
                        {isActive && <ChevronRight className="w-3 h-3 text-primary shrink-0" />}
                      </div>
                      <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                        <span>{new Date(sess.created_at).toLocaleDateString([], { month: "short", day: "numeric" })}</span>
                        <span>{sess.query_count || 0} queries</span>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Past history in current session */}
              {sessionHistory.length > 0 && (
                <div className="border-t p-2 bg-muted/20 max-h-48 overflow-y-auto">
                  <div className="text-[10px] uppercase font-semibold text-muted-foreground mb-1 px-1 flex items-center gap-1">
                    <Layers className="w-3 h-3" />
                    Session Log ({sessionHistory.length})
                  </div>
                  <div className="space-y-1">
                    {sessionHistory.slice(-5).reverse().map((h) => (
                      <div
                        key={h.id}
                        onClick={() => {
                          if (h.natural_language_question) {
                            setMode("natural");
                            setNaturalQuestion(h.natural_language_question);
                          } else {
                            setMode("sql");
                            setRawSql(h.generated_sql);
                          }
                        }}
                        className="text-[11px] p-1.5 rounded bg-background/50 border hover:border-primary/40 cursor-pointer truncate"
                      >
                        <div className="font-mono text-muted-foreground truncate">
                          {h.natural_language_question || h.generated_sql}
                        </div>
                        <div className="flex items-center justify-between text-[9px] text-muted-foreground mt-0.5">
                          <span>{h.executed ? "Executed" : "Blocked"}</span>
                          <span>{h.row_count ?? 0} rows</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          )}

          {/* Right Main Split: Input (Top) + Results (Bottom) */}
          <div className="flex-1 flex flex-col gap-3 overflow-hidden">
            {/* Top Half: Input Area */}
            <Card className="flex flex-col border-border/60 bg-card/60 backdrop-blur-sm p-3.5 shrink-0 gap-3">
              {/* Mode Toggle & Curated Views Pills */}
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center bg-muted/60 p-0.5 rounded-lg border border-border/40 text-xs">
                  <button
                    onClick={() => setMode("natural")}
                    className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-all ${
                      mode === "natural"
                        ? "bg-background text-foreground font-semibold shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                    Natural Language (AI Agent)
                  </button>
                  <button
                    onClick={() => setMode("sql")}
                    className={`px-3 py-1.5 rounded-md flex items-center gap-1.5 transition-all ${
                      mode === "sql"
                        ? "bg-background text-foreground font-semibold shadow-xs"
                        : "text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    Raw SQL Console
                  </button>
                </div>

                <div className="flex items-center gap-1.5 overflow-x-auto text-[11px]">
                  <span className="text-muted-foreground text-xs flex items-center gap-1">
                    <FileCode className="w-3.5 h-3.5" />
                    Views:
                  </span>
                  {CURATED_VIEW_TEMPLATES.map((tmpl) => (
                    <button
                      key={tmpl.name}
                      onClick={() => {
                        setMode("sql");
                        setRawSql(tmpl.sql);
                      }}
                      className="px-2 py-0.5 rounded bg-muted/50 hover:bg-primary/20 border border-border/40 hover:border-primary/50 text-foreground transition-all"
                      title={tmpl.desc}
                    >
                      {tmpl.name}
                    </button>
                  ))}
                </div>
              </div>

              {/* Input Box */}
              {mode === "natural" ? (
                <div className="relative">
                  <textarea
                    value={naturalQuestion}
                    onChange={(e) => setNaturalQuestion(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                        handleRunQuery();
                      }
                    }}
                    placeholder="Ask any threat intelligence question (e.g. 'Show all threat actors with attribution confidence > 0.8 and their wallets' or 'Which onion marketplaces have the most active threat actors?')..."
                    className="w-full h-24 p-3 rounded-md bg-background/80 border text-xs focus:ring-1 focus:ring-primary focus:outline-hidden font-sans resize-none"
                  />
                  <div className="flex items-center justify-between text-[11px] text-muted-foreground mt-1">
                    <span>Press Ctrl+Enter or Cmd+Enter to submit to read-only agent</span>
                    <Button
                      size="sm"
                      onClick={handleRunQuery}
                      disabled={loading || !naturalQuestion.trim()}
                      className="h-7 text-xs gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white"
                    >
                      {loading ? <RotateCcw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                      Ask Agent
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="relative">
                  <textarea
                    value={rawSql}
                    onChange={(e) => setRawSql(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                        handleRunQuery();
                      }
                    }}
                    placeholder="SELECT * FROM v_actor_summary ORDER BY attribution_confidence DESC LIMIT 50;"
                    className="w-full h-28 p-3 rounded-md bg-background/80 border text-xs font-mono text-foreground focus:ring-1 focus:ring-cyan-500 focus:outline-hidden resize-none"
                  />
                  <div className="flex items-center justify-between text-[11px] text-muted-foreground mt-1">
                    <span>Single SELECT statements only. Default LIMIT 500 automatically enforced.</span>
                    <Button
                      size="sm"
                      onClick={handleRunQuery}
                      disabled={loading || !rawSql.trim()}
                      className="h-7 text-xs gap-1.5 bg-cyan-600 hover:bg-cyan-700 text-white"
                    >
                      {loading ? <RotateCcw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                      Run SQL
                    </Button>
                  </div>
                </div>
              )}

              {/* Show Generated SQL banner if natural mode executed */}
              {result?.generated_sql && (
                <div className="flex items-center justify-between p-2 rounded-md bg-indigo-950/30 border border-indigo-500/30 text-xs">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <Sparkles className="w-3.5 h-3.5 text-indigo-400 shrink-0" />
                    <span className="text-muted-foreground shrink-0 font-medium">Generated SQL:</span>
                    <code className="text-indigo-200 font-mono text-[11px] truncate">
                      {result.generated_sql}
                    </code>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleCopySql(result.generated_sql!)}
                    className="h-6 px-2 text-[10px] text-indigo-300 hover:text-white"
                  >
                    {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copied ? "Copied" : "Copy"}
                  </Button>
                </div>
              )}
            </Card>

            {/* Bottom Half: Results Area */}
            <Card className="flex-1 flex flex-col border-border/60 bg-card/60 backdrop-blur-sm overflow-hidden p-3 gap-2.5">
              {/* Results Control Bar */}
              <div className="flex items-center justify-between border-b pb-2 text-xs flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-foreground flex items-center gap-1.5">
                    <TableIcon className="w-4 h-4 text-primary" />
                    Query Results
                  </span>
                  {result?.success ? (
                    <Badge variant="outline" className="text-[11px] bg-emerald-500/10 text-emerald-400 border-emerald-500/20">
                      {result.row_count ?? 0} rows ({result.latency_ms ?? 0} ms)
                    </Badge>
                  ) : result?.error ? (
                    <Badge variant="outline" className="text-[11px] bg-destructive/10 text-destructive border-destructive/20">
                      Execution Blocked / Error
                    </Badge>
                  ) : (
                    <span className="text-muted-foreground text-[11px]">Ready for query execution</span>
                  )}
                </div>

                {/* Scoped Export Buttons */}
                {result?.success && result.rows && result.rows.length > 0 && (
                  <div className="flex items-center gap-1.5">
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 absolute left-2 top-2 text-muted-foreground" />
                      <input
                        type="text"
                        placeholder="Filter results..."
                        value={filterText}
                        onChange={(e) => {
                          setFilterText(e.target.value);
                          setPage(1);
                        }}
                        className="pl-7 pr-2 py-1 h-7 text-xs rounded border bg-background text-foreground w-36 focus:outline-hidden focus:ring-1 focus:ring-primary"
                      />
                    </div>

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleExport("csv")}
                      disabled={exportLoading !== null}
                      className="h-7 text-xs gap-1 border-border/60 hover:bg-muted"
                    >
                      <Download className="w-3 h-3" />
                      CSV
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleExport("json")}
                      disabled={exportLoading !== null}
                      className="h-7 text-xs gap-1 border-border/60 hover:bg-muted"
                    >
                      <Download className="w-3 h-3" />
                      JSON
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleExport("report")}
                      disabled={exportLoading !== null}
                      className="h-7 text-xs gap-1 border-indigo-500/30 text-indigo-400 hover:bg-indigo-500/10"
                    >
                      <FileText className="w-3 h-3" />
                      Dossier (PDF)
                    </Button>
                  </div>
                )}
              </div>

              {/* Error Banner */}
              {result?.error && (
                <div className="p-3 rounded-md bg-destructive/10 border border-destructive/30 text-xs text-destructive flex items-start gap-2">
                  <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold">Security or SQL Execution Error:</span>
                    <p className="mt-0.5 font-mono text-[11px] whitespace-pre-wrap">{result.error}</p>
                  </div>
                </div>
              )}

              {/* Table or Empty State */}
              <div className="flex-1 overflow-auto border rounded-md bg-background/50">
                {loading ? (
                  <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-2">
                    <RotateCcw className="w-6 h-6 animate-spin text-primary" />
                    <span className="text-xs">Executing query in read-only sandbox...</span>
                  </div>
                ) : result?.success && result.columns && result.columns.length > 0 ? (
                  <table className="w-full text-xs text-left border-collapse font-sans">
                    <thead className="bg-muted/60 sticky top-0 border-b z-10 backdrop-blur-xs">
                      <tr>
                        <th className="p-2 w-10 text-[10px] text-muted-foreground text-center border-r font-mono">#</th>
                        {result.columns.map((col, idx) => (
                          <th key={idx} className="p-2 font-semibold text-foreground border-r last:border-r-0 whitespace-nowrap">
                            {col}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/40 font-mono text-[11px]">
                      {paginatedRows.length > 0 ? (
                        paginatedRows.map((row, rIdx) => (
                          <tr key={rIdx} className="hover:bg-muted/40 transition-colors">
                            <td className="p-2 text-center text-muted-foreground border-r text-[10px]">
                              {(page - 1) * pageSize + rIdx + 1}
                            </td>
                            {row.map((cell: any, cIdx: number) => (
                              <td key={cIdx} className="p-2 border-r last:border-r-0 max-w-xs truncate" title={String(cell)}>
                                {cell === null || cell === undefined ? (
                                  <span className="text-muted-foreground italic">null</span>
                                ) : typeof cell === "boolean" ? (
                                  <Badge variant="outline" className={`text-[10px] py-0 px-1 ${cell ? "text-emerald-400" : "text-zinc-500"}`}>
                                    {String(cell)}
                                  </Badge>
                                ) : (
                                  String(cell)
                                )}
                              </td>
                            ))}
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={result.columns.length + 1} className="p-6 text-center text-muted-foreground italic">
                            No matching records found in this result set.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-2 p-6">
                    <Database className="w-8 h-8 text-muted-foreground/40" />
                    <span className="text-xs font-medium">No active query execution</span>
                    <span className="text-[11px] text-muted-foreground/70 max-w-sm text-center">
                      Select a curated view template above or type an intelligence question to query the live threat database.
                    </span>
                  </div>
                )}
              </div>

              {/* Pagination controls */}
              {result?.success && filteredRows.length > 0 && (
                <div className="flex items-center justify-between text-xs pt-1 border-t text-muted-foreground">
                  <div className="flex items-center gap-2">
                    <span>Rows per page:</span>
                    <select
                      value={pageSize}
                      onChange={(e) => {
                        setPageSize(Number(e.target.value));
                        setPage(1);
                      }}
                      className="h-6 px-1.5 text-xs rounded border bg-background text-foreground"
                    >
                      <option value={15}>15</option>
                      <option value={25}>25</option>
                      <option value={50}>50</option>
                      <option value={100}>100</option>
                    </select>
                    <span>
                      Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, filteredRows.length)} of {filteredRows.length}
                    </span>
                  </div>

                  <div className="flex items-center gap-1">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={page <= 1}
                      className="h-6 px-2 text-xs"
                    >
                      <ChevronLeft className="w-3 h-3" />
                      Prev
                    </Button>
                    <span className="px-2 font-mono text-[11px]">
                      {page} / {totalPages}
                    </span>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                      disabled={page >= totalPages}
                      className="h-6 px-2 text-xs"
                    >
                      Next
                      <ChevronRight className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
              )}
            </Card>
          </div>
        </div>
      </div>
    </AppShell>
  );
}
