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
  Trash2,
  Copy,
  Check,
  ChevronRight,
  ChevronDown,
  Table as TableIcon,
  Search,
  PanelLeftClose,
  PanelLeft,
  PanelRightClose,
  PanelRight,
  Send,
  History,
  FileCode,
  Download,
  AlertTriangle,
  RotateCcw,
  Zap,
  Terminal,
  ExternalLink,
  Code2,
} from "lucide-react";

interface SqlSession {
  id: string;
  title: string;
  opencode_session_id?: string | null;
  created_at: string;
  updated_at: string;
  query_count?: number;
  last_query_at?: string;
}

interface TableColumn {
  cid: number;
  name: string;
  type: string;
  notnull: boolean;
  dflt_value: any;
  pk: boolean;
}

interface TableMetadata {
  table_name: string;
  row_count: number;
  columns: TableColumn[];
}

interface QueryResult {
  success: boolean;
  columns?: string[];
  rows?: any[][];
  row_count?: number;
  truncated?: boolean;
  latency_ms?: number;
  error?: string;
}

interface AiMessage {
  id: string;
  role: "user" | "assistant";
  content: string;
  sql?: string;
  timestamp: string;
  source?: string;
  injected_prompt?: string;
}

interface HistoryItem {
  id: string;
  query: string;
  source: string;
  status: string;
  latency_ms: number;
  row_count: number;
  created_at: string;
}

const STARTER_TEMPLATES = [
  {
    name: "Top Threat Actors by Confidence",
    sql: "SELECT id, designated_id, primary_handle, threat_category, confidence, attributed_onions\nFROM threat_actors\nWHERE confidence >= 0.8\nORDER BY confidence DESC\nLIMIT 25;",
  },
  {
    name: "OFAC Sanctioned Crypto Wallets",
    sql: "SELECT id, type, value, confidence, is_sanctioned, evidence_quote\nFROM identifiers\nWHERE is_sanctioned = 1\nORDER BY confidence DESC\nLIMIT 50;",
  },
  {
    name: "Corroborated Leaked Origin IPs",
    sql: "SELECT ip_address, country_name, city, asn, organization, isp, proxy_or_vpn, tor\nFROM ip_enrichment\nORDER BY enriched_at DESC\nLIMIT 50;",
  },
  {
    name: "Onion Pages with Server Banners",
    sql: "SELECT id, url, title, server_banner, favicon_mmh3, etag, created_at\nFROM onion_pages\nWHERE server_banner IS NOT NULL AND server_banner != ''\nORDER BY created_at DESC\nLIMIT 25;",
  },
  {
    name: "Relationship Graph Edges",
    sql: "SELECT source, target, edge_type, confidence, evidence_quote\nFROM graph_edges\nORDER BY confidence DESC\nLIMIT 50;",
  },
];

export default function SqlStudioPage() {
  const [sessions, setSessions] = useState<SqlSession[]>([]);
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [activeSession, setActiveSession] = useState<SqlSession | null>(null);
  const [query, setQuery] = useState<string>(STARTER_TEMPLATES[0].sql);
  const [result, setResult] = useState<QueryResult | null>(null);
  const [executing, setExecuting] = useState(false);
  const [schema, setSchema] = useState<{ tables: TableMetadata[]; total_tables: number } | null>(null);
  const [schemaSearch, setSchemaSearch] = useState("");
  const [expandedTable, setExpandedTable] = useState<string | null>(null);
  const [leftTab, setLeftTab] = useState<"sessions" | "schema" | "history">("sessions");
  const [leftDrawerOpen, setLeftDrawerOpen] = useState(true);
  const [rightDrawerOpen, setRightDrawerOpen] = useState(false);
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiGenerating, setAiGenerating] = useState(false);
  const [aiMessages, setAiMessages] = useState<AiMessage[]>([]);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [copied, setCopied] = useState<string | null>(null);

  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const chatScrollRef = useRef<HTMLDivElement>(null);

  // Load sessions and schema on mount
  useEffect(() => {
    fetchSessions();
    fetchSchema();
  }, []);

  // Update active session when selection changes
  useEffect(() => {
    if (activeSessionId) {
      const s = sessions.find((item) => item.id === activeSessionId) || null;
      setActiveSession(s);
      fetchHistory(activeSessionId);
    } else if (sessions.length > 0) {
      setActiveSessionId(sessions[0].id);
    }
  }, [activeSessionId, sessions]);

  // Scroll AI chat to bottom
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [aiMessages]);

  const fetchSessions = async () => {
    try {
      const res = await fetch("/api/sql/sessions");
      const data = await res.json();
      const list = data.sessions || [];
      setSessions(list);
      if (list.length === 0) {
        // Automatically create initial session if none exist
        createNewSession("Threat Intel Investigation Session");
      } else if (!activeSessionId) {
        setActiveSessionId(list[0].id);
      }
    } catch (e) {
      console.error("Failed to fetch sessions", e);
    }
  };

  const fetchSchema = async () => {
    try {
      const res = await fetch("/api/sql/schema");
      const data = await res.json();
      setSchema(data);
    } catch (e) {
      console.error("Failed to fetch schema", e);
    }
  };

  const fetchHistory = async (sid: string) => {
    try {
      const res = await fetch(`/api/sql/history?session_id=${encodeURIComponent(sid)}`);
      const data = await res.json();
      setHistory(data.history || []);
    } catch (e) {
      console.error("Failed to fetch history", e);
    }
  };

  const createNewSession = async (title?: string) => {
    try {
      const defaultTitle = title || `Investigation Query #${sessions.length + 1}`;
      const res = await fetch("/api/sql/sessions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: defaultTitle }),
      });
      const data = await res.json();
      if (data.session) {
        setSessions((prev) => [data.session, ...prev]);
        setActiveSessionId(data.session.id);
        // Seed initial welcome in AI chat
        setAiMessages([
          {
            id: "msg_welcome",
            role: "assistant",
            content: `Connected to session **${data.session.title}**. Linked to OpenCode daemon.\n\nAsk me to write SQL queries against Jane's 12 threat intelligence tables, or select a table from the schema browser.`,
            timestamp: new Date().toLocaleTimeString(),
          },
        ]);
      }
    } catch (e) {
      console.error("Failed to create session", e);
    }
  };

  const deleteSession = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await fetch(`/api/sql/sessions/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id }),
      });
      const updated = sessions.filter((s) => s.id !== id);
      setSessions(updated);
      if (activeSessionId === id) {
        setActiveSessionId(updated.length > 0 ? updated[0].id : null);
      }
    } catch (err) {
      console.error("Failed to delete session", err);
    }
  };

  const runQuery = async () => {
    if (!query.trim()) return;
    setExecuting(true);
    setResult(null);
    try {
      const res = await fetch("/api/sql/execute", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: activeSessionId,
          query: query.trim(),
          max_rows: 500,
        }),
      });
      const data = await res.json();
      setResult(data);
      if (activeSessionId) {
        fetchHistory(activeSessionId);
      }
    } catch (e: any) {
      setResult({
        success: false,
        error: e.message || "Network execution error",
        latency_ms: 0,
      });
    } finally {
      setExecuting(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runQuery();
    }
  };

  const askOpenCode = async (customPrompt?: string) => {
    const promptToSend = customPrompt || aiPrompt;
    if (!promptToSend.trim() || aiGenerating) return;

    const userMsg: AiMessage = {
      id: `usr_${Date.now()}`,
      role: "user",
      content: promptToSend,
      timestamp: new Date().toLocaleTimeString(),
    };

    setAiMessages((prev) => [...prev, userMsg]);
    setAiPrompt("");
    setAiGenerating(true);

    try {
      const res = await fetch("/api/sql/ai", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: activeSessionId,
          prompt: promptToSend,
          auto_execute: false,
        }),
      });
      const data = await res.json();
      const assistantMsg: AiMessage = {
        id: `ai_${Date.now()}`,
        role: "assistant",
        content: data.explanation || "Query generated based on Jane intelligence schema:",
        sql: data.sql,
        source: data.source,
        injected_prompt: data.injected_prompt,
        timestamp: new Date().toLocaleTimeString(),
      };
      setAiMessages((prev) => [...prev, assistantMsg]);
    } catch (e: any) {
      setAiMessages((prev) => [
        ...prev,
        {
          id: `ai_${Date.now()}`,
          role: "assistant",
          content: `Failed to generate query: ${e.message}`,
          timestamp: new Date().toLocaleTimeString(),
        },
      ]);
    } finally {
      setAiGenerating(false);
    }
  };

  const applySql = (sqlText: string, autoRun = false) => {
    setQuery(sqlText);
    if (autoRun) {
      setTimeout(() => {
        runQuery();
      }, 50);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const exportCSV = () => {
    if (!result?.columns || !result?.rows) return;
    const header = result.columns.join(",");
    const rows = result.rows.map((row) =>
      row
        .map((val) => {
          if (val === null || val === undefined) return "";
          const str = String(val).replace(/"/g, '""');
          return `"${str}"`;
        })
        .join(",")
    );
    const csvContent = "data:text/csv;charset=utf-8," + [header, ...rows].join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `jane_query_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const exportJSON = () => {
    if (!result?.columns || !result?.rows) return;
    const objects = result.rows.map((row) => {
      const obj: Record<string, any> = {};
      result.columns!.forEach((col, idx) => {
        obj[col] = row[idx];
      });
      return obj;
    });
    const blob = new Blob([JSON.stringify(objects, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `jane_query_${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const formatQuery = () => {
    if (!query) return;
    const keywords = [
      "SELECT", "FROM", "WHERE", "ORDER BY", "GROUP BY", "LIMIT", "LEFT JOIN",
      "INNER JOIN", "JOIN", "ON", "AND", "OR", "DESC", "ASC", "COUNT", "AS", "HAVING", "UNION ALL", "UNION", "WITH"
    ];
    let formatted = query;
    keywords.forEach((kw) => {
      const regex = new RegExp(`\\b${kw}\\b`, "gi");
      formatted = formatted.replace(regex, kw);
    });
    setQuery(formatted);
  };

  const filteredTables = (schema?.tables || []).filter((t) =>
    t.table_name.toLowerCase().includes(schemaSearch.toLowerCase())
  );

  return (
    <AppShell>
      <div className="flex h-[calc(100vh-4.5rem)] flex-col gap-2 overflow-hidden">
        {/* Top Control Bar */}
        <div className="flex items-center justify-between border-b border-border/40 pb-2 px-1">
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="h-8 gap-1.5 text-xs font-medium"
              onClick={() => setLeftDrawerOpen(!leftDrawerOpen)}
            >
              {leftDrawerOpen ? <PanelLeftClose className="h-3.5 w-3.5" /> : <PanelLeft className="h-3.5 w-3.5" />}
              <span>{leftDrawerOpen ? "Hide Explorer" : "Explorer"}</span>
            </Button>

            <div className="flex items-center gap-2">
              <Database className="h-4 w-4 text-emerald-400" />
              <span className="text-sm font-semibold tracking-tight">SQL Studio</span>
              <Badge variant="outline" className="h-5 px-1.5 text-[10px] font-mono text-zinc-400 border-zinc-700">
                SQLite (Read-Only)
              </Badge>
              {activeSession && (
                <span className="text-xs text-muted-foreground truncate max-w-[200px] border-l border-zinc-800 pl-2">
                  {activeSession.title}
                </span>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Quick Templates Dropdown */}
            <div className="relative group">
              <Button variant="ghost" size="sm" className="h-8 text-xs text-zinc-300 gap-1.5 border border-zinc-800">
                <FileCode className="h-3.5 w-3.5 text-cyan-400" />
                Templates
                <ChevronDown className="h-3 w-3 opacity-60" />
              </Button>
              <div className="absolute right-0 top-full mt-1 hidden w-64 rounded-md border border-zinc-800 bg-zinc-950 p-1 shadow-xl group-hover:block z-50">
                {STARTER_TEMPLATES.map((tmpl) => (
                  <button
                    key={tmpl.name}
                    className="w-full text-left rounded px-2.5 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800 hover:text-zinc-100 flex flex-col gap-0.5"
                    onClick={() => applySql(tmpl.sql, false)}
                  >
                    <span className="font-medium text-[11px] text-zinc-200">{tmpl.name}</span>
                    <span className="font-mono text-[9px] text-zinc-500 truncate">{tmpl.sql.replace(/\n/g, " ")}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Run Button */}
            <Button
              onClick={runQuery}
              disabled={executing}
              className="h-8 gap-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs px-3 shadow-sm"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>{executing ? "Executing..." : "Run"}</span>
              <kbd className="hidden sm:inline-block ml-1 rounded bg-emerald-700/50 px-1 py-0.2 text-[9px] font-mono text-emerald-200">
                Ctrl+Enter
              </kbd>
            </Button>

            {/* OpenCode AI Toggle Button */}
            <Button
              variant={rightDrawerOpen ? "secondary" : "outline"}
              size="sm"
              className={`h-8 gap-1.5 text-xs font-medium border ${
                rightDrawerOpen ? "bg-amber-400/10 text-amber-300 border-amber-500/30" : "border-zinc-800 text-zinc-300 hover:text-amber-300"
              }`}
              onClick={() => setRightDrawerOpen(!rightDrawerOpen)}
            >
              <Sparkles className="h-3.5 w-3.5 text-amber-400" />
              <span>OpenCode AI</span>
              {rightDrawerOpen ? <PanelRightClose className="h-3.5 w-3.5 ml-0.5" /> : <PanelRight className="h-3.5 w-3.5 ml-0.5" />}
            </Button>
          </div>
        </div>

        {/* Main Tri-Panel Body */}
        <div className="flex flex-1 overflow-hidden gap-2">
          {/* ── Left Drawer / Panel: Sessions & Schema ─────────────────────────── */}
          {leftDrawerOpen && (
            <div className="flex w-64 flex-col rounded-lg border border-border/50 bg-card/60 backdrop-blur-sm overflow-hidden shrink-0">
              {/* Tab Header */}
              <div className="flex items-center justify-between border-b border-border/40 p-2 bg-zinc-950/40">
                <div className="flex gap-1">
                  <button
                    className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                      leftTab === "sessions"
                        ? "bg-zinc-800 text-zinc-100 font-semibold"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                    onClick={() => setLeftTab("sessions")}
                  >
                    Sessions ({sessions.length})
                  </button>
                  <button
                    className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors ${
                      leftTab === "schema"
                        ? "bg-zinc-800 text-zinc-100 font-semibold"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                    onClick={() => setLeftTab("schema")}
                  >
                    Schema
                  </button>
                  <button
                    className={`px-2 py-1 text-xs font-medium rounded-md transition-colors ${
                      leftTab === "history"
                        ? "bg-zinc-800 text-zinc-100 font-semibold"
                        : "text-zinc-400 hover:text-zinc-200"
                    }`}
                    onClick={() => setLeftTab("history")}
                  >
                    Logs
                  </button>
                </div>

                <Button
                  size="icon-xs"
                  variant="ghost"
                  className="h-6 w-6 text-emerald-400 hover:bg-emerald-950/30"
                  onClick={() => createNewSession()}
                  title="New Session"
                >
                  <Plus className="h-3.5 w-3.5" />
                </Button>
              </div>

              {/* Sessions List */}
              {leftTab === "sessions" && (
                <div className="flex-1 overflow-y-auto p-1.5 space-y-1">
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full justify-start gap-2 h-8 text-xs font-medium border-dashed border-zinc-800 hover:border-emerald-500/50 hover:bg-emerald-950/20 text-emerald-300 mb-2"
                    onClick={() => createNewSession()}
                  >
                    <Plus className="h-3.5 w-3.5" />
                    New Query Session
                  </Button>

                  {sessions.map((s) => {
                    const isActive = s.id === activeSessionId;
                    return (
                      <div
                        key={s.id}
                        onClick={() => setActiveSessionId(s.id)}
                        className={`group flex items-center justify-between rounded-md p-2 text-xs cursor-pointer border transition-all ${
                          isActive
                            ? "border-emerald-500/30 bg-emerald-950/20 text-emerald-200 font-medium"
                            : "border-transparent text-zinc-400 hover:bg-zinc-900/60 hover:text-zinc-200"
                        }`}
                      >
                        <div className="flex flex-col truncate pr-2">
                          <span className="truncate leading-snug">{s.title}</span>
                          <span className="text-[10px] text-zinc-500 font-mono">
                            {new Date(s.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} •{" "}
                            {s.query_count || 0} queries
                          </span>
                        </div>
                        <button
                          onClick={(e) => deleteSession(s.id, e)}
                          className="opacity-0 group-hover:opacity-100 p-1 text-zinc-500 hover:text-rose-400 transition-opacity"
                          title="Delete Session"
                        >
                          <Trash2 className="h-3 w-3" />
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Schema Inspector Tab */}
              {leftTab === "schema" && (
                <div className="flex flex-1 flex-col overflow-hidden p-2 gap-2">
                  <div className="relative">
                    <Search className="absolute left-2 top-2 h-3 w-3 text-zinc-500" />
                    <input
                      type="text"
                      placeholder="Search tables..."
                      value={schemaSearch}
                      onChange={(e) => setSchemaSearch(e.target.value)}
                      className="w-full rounded bg-zinc-950/80 border border-zinc-800 pl-7 pr-2 py-1 text-[11px] text-zinc-200 focus:outline-none focus:border-zinc-700"
                    />
                  </div>

                  <div className="flex-1 overflow-y-auto space-y-1 pr-1">
                    {filteredTables.map((t) => {
                      const isExpanded = expandedTable === t.table_name;
                      return (
                        <div key={t.table_name} className="rounded border border-zinc-800/80 bg-zinc-950/40 overflow-hidden">
                          <div
                            onClick={() => setExpandedTable(isExpanded ? null : t.table_name)}
                            className="flex items-center justify-between p-1.5 text-xs cursor-pointer hover:bg-zinc-900/80 font-mono"
                          >
                            <div className="flex items-center gap-1.5 truncate">
                              {isExpanded ? <ChevronDown className="h-3 w-3 text-zinc-400" /> : <ChevronRight className="h-3 w-3 text-zinc-400" />}
                              <TableIcon className="h-3 w-3 text-cyan-400 shrink-0" />
                              <span className="truncate text-zinc-200 font-medium text-[11px]">{t.table_name}</span>
                            </div>
                            <span className="text-[10px] text-zinc-500 shrink-0 tabular-nums">
                              {t.row_count}
                            </span>
                          </div>

                          {isExpanded && (
                            <div className="border-t border-zinc-900 bg-zinc-950/90 p-1.5 space-y-1">
                              <div className="flex items-center justify-between pb-1 border-b border-zinc-900">
                                <button
                                  className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1"
                                  onClick={() => applySql(`SELECT * FROM ${t.table_name} LIMIT 50;`, true)}
                                >
                                  <Play className="h-2.5 w-2.5 fill-current" /> SELECT *
                                </button>
                                <span className="text-[10px] text-zinc-500">{t.columns.length} columns</span>
                              </div>
                              {t.columns.map((col) => (
                                <div
                                  key={col.name}
                                  className="flex items-center justify-between text-[10px] py-0.5 px-1 rounded hover:bg-zinc-900 cursor-pointer font-mono text-zinc-400"
                                  onClick={() => setQuery((prev) => `${prev} ${col.name}`)}
                                  title="Click to insert column into editor"
                                >
                                  <span className="truncate text-zinc-300">
                                    {col.pk && <span className="text-amber-400 font-bold mr-1">PK</span>}
                                    {col.name}
                                  </span>
                                  <span className="text-[9px] text-zinc-600">{col.type}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* History Tab */}
              {leftTab === "history" && (
                <div className="flex-1 overflow-y-auto p-2 space-y-1.5 font-mono text-xs">
                  {history.length === 0 ? (
                    <div className="text-center py-8 text-zinc-500 text-[11px]">No query logs yet</div>
                  ) : (
                    history.map((h) => (
                      <div
                        key={h.id}
                        className="rounded border border-zinc-800/80 bg-zinc-950/40 p-2 text-[11px] cursor-pointer hover:border-zinc-700 transition-colors"
                        onClick={() => setQuery(h.query)}
                      >
                        <div className="flex items-center justify-between text-[10px] text-zinc-500 mb-1">
                          <Badge variant="outline" className={`h-4 text-[9px] px-1 ${h.status === "SUCCESS" ? "text-emerald-400 border-emerald-900/50" : "text-rose-400 border-rose-900/50"}`}>
                            {h.status}
                          </Badge>
                          <span>{h.latency_ms}ms • {h.row_count} rows</span>
                        </div>
                        <div className="truncate text-zinc-300 font-mono text-[10px]">{h.query}</div>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── Center Canvas: Top Half (SQL Editor) + Bottom Half (Results) ───── */}
          <div className="flex flex-1 flex-col overflow-hidden gap-2">
            {/* Top Half: Editor Panel */}
            <div className="flex flex-1 flex-col rounded-lg border border-border/50 bg-card/60 backdrop-blur-sm overflow-hidden">
              {/* Editor Bar */}
              <div className="flex items-center justify-between border-b border-border/40 px-3 py-1.5 bg-zinc-950/60">
                <div className="flex items-center gap-2">
                  <Code2 className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-xs font-mono font-medium text-zinc-300">query.sql</span>
                </div>
                <div className="flex items-center gap-1.5">
                  <Button variant="ghost" size="icon-xs" className="h-6 w-6 text-zinc-400 hover:text-zinc-200" onClick={formatQuery} title="Format SQL">
                    <Zap className="h-3 w-3" />
                  </Button>
                  <Button variant="ghost" size="icon-xs" className="h-6 w-6 text-zinc-400 hover:text-zinc-200" onClick={() => copyToClipboard(query, "query")} title="Copy Query">
                    {copied === "query" ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                  </Button>
                  <Button variant="ghost" size="icon-xs" className="h-6 w-6 text-zinc-400 hover:text-rose-400" onClick={() => setQuery("")} title="Clear Editor">
                    <RotateCcw className="h-3 w-3" />
                  </Button>
                </div>
              </div>

              {/* Editor Textarea with line numbers */}
              <div className="relative flex-1 overflow-hidden bg-zinc-950 flex font-mono text-xs">
                <textarea
                  ref={textareaRef}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="-- Write SQL query (e.g. SELECT * FROM threat_actors LIMIT 10;)..."
                  className="w-full h-full resize-none bg-transparent p-3 text-zinc-200 focus:outline-none selection:bg-emerald-900/60 leading-relaxed font-mono"
                  spellCheck={false}
                />
              </div>

              {/* Error Banner */}
              {result && !result.success && (
                <div className="border-t border-rose-900/50 bg-rose-950/40 p-2.5 text-xs text-rose-300 flex items-start gap-2">
                  <AlertTriangle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
                  <div className="flex-1 font-mono text-[11px] leading-relaxed">
                    <span className="font-semibold text-rose-200">Execution Error: </span>
                    {result.error}
                  </div>
                </div>
              )}
            </div>

            {/* Bottom Half: Results Panel */}
            <div className="flex flex-1 flex-col rounded-lg border border-border/50 bg-card/60 backdrop-blur-sm overflow-hidden">
              {/* Results Action Bar */}
              <div className="flex items-center justify-between border-b border-border/40 px-3 py-1.5 bg-zinc-950/60">
                <div className="flex items-center gap-2">
                  <Terminal className="h-3.5 w-3.5 text-cyan-400" />
                  <span className="text-xs font-semibold text-zinc-300">Results</span>
                  {result && result.success && (
                    <div className="flex items-center gap-1.5 text-[11px] font-mono">
                      <Badge variant="outline" className="h-4 px-1 text-[10px] text-emerald-400 border-emerald-900">
                        {result.row_count} rows
                      </Badge>
                      <span className="text-zinc-500 text-[10px]">• {result.latency_ms} ms</span>
                      {result.truncated && (
                        <span className="text-amber-400 text-[10px] font-semibold">(Truncated at 500)</span>
                      )}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-1">
                  {result?.rows && result.rows.length > 0 && (
                    <>
                      <Button variant="ghost" size="sm" className="h-6 text-[10px] text-zinc-300 gap-1 px-2" onClick={exportCSV}>
                        <Download className="h-3 w-3" /> CSV
                      </Button>
                      <Button variant="ghost" size="sm" className="h-6 text-[10px] text-zinc-300 gap-1 px-2" onClick={exportJSON}>
                        <Download className="h-3 w-3" /> JSON
                      </Button>
                    </>
                  )}
                </div>
              </div>

              {/* Data Table Container */}
              <div className="flex-1 overflow-auto bg-zinc-950/60 font-mono text-xs">
                {executing ? (
                  <div className="flex h-full items-center justify-center gap-2 text-zinc-400 text-xs">
                    <div className="h-4 w-4 animate-spin rounded-full border-2 border-emerald-500 border-t-transparent" />
                    <span>Executing query against database...</span>
                  </div>
                ) : result?.success && result.columns && result.columns.length > 0 ? (
                  <table className="w-full text-left border-collapse">
                    <thead className="sticky top-0 bg-zinc-900/90 text-zinc-400 text-[11px] border-b border-zinc-800 z-10 backdrop-blur-sm">
                      <tr>
                        <th className="p-2 w-10 text-center text-zinc-600 font-mono">#</th>
                        {result.columns.map((col) => (
                          <th key={col} className="p-2 font-medium tracking-wider text-zinc-300 whitespace-nowrap">
                            {col}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-zinc-900 text-zinc-300 text-[11px]">
                      {result.rows && result.rows.length > 0 ? (
                        result.rows.map((row, rIdx) => (
                          <tr key={rIdx} className="hover:bg-zinc-900/50 transition-colors">
                            <td className="p-2 text-center text-zinc-600 text-[10px]">{rIdx + 1}</td>
                            {row.map((cell, cIdx) => (
                              <td key={cIdx} className="p-2 whitespace-nowrap max-w-[280px] truncate">
                                {cell === null || cell === undefined ? (
                                  <span className="text-zinc-600 italic">NULL</span>
                                ) : typeof cell === "boolean" ? (
                                  cell ? "TRUE" : "FALSE"
                                ) : (
                                  String(cell)
                                )}
                              </td>
                            ))}
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={result.columns.length + 1} className="p-6 text-center text-zinc-500">
                            Query executed successfully with 0 rows returned.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                ) : (
                  <div className="flex h-full flex-col items-center justify-center p-6 text-center text-zinc-500">
                    <Database className="h-8 w-8 mb-2 text-zinc-700 stroke-1" />
                    <span className="text-xs font-medium text-zinc-400">Ready to execute query</span>
                    <span className="text-[11px] text-zinc-600 mt-1 max-w-sm">
                      Type your SQL query above or click <span className="text-emerald-400">Run</span> (Ctrl+Enter) to view results.
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* ── Right Drawer: OpenCode AI Copilot ──────────────────────────────── */}
          {rightDrawerOpen && (
            <div className="flex w-80 flex-col rounded-lg border border-border/50 bg-card/60 backdrop-blur-sm overflow-hidden shrink-0">
              {/* Copilot Header */}
              <div className="flex items-center justify-between border-b border-border/40 p-2.5 bg-zinc-950/60">
                <div className="flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-amber-400" />
                  <div className="flex flex-col">
                    <span className="text-xs font-semibold text-zinc-200">OpenCode AI Copilot</span>
                    <span className="text-[9px] text-zinc-500">Read-Only SQL Query Synthesis</span>
                  </div>
                </div>
                <Button
                  size="icon-xs"
                  variant="ghost"
                  className="h-6 w-6 text-zinc-400 hover:text-zinc-200"
                  onClick={() => setRightDrawerOpen(false)}
                >
                  <PanelRightClose className="h-3.5 w-3.5" />
                </Button>
              </div>

              {/* Chat Stream */}
              <div ref={chatScrollRef} className="flex-1 overflow-y-auto p-2.5 space-y-3 text-xs">
                {aiMessages.map((msg) => (
                  <div
                    key={msg.id}
                    className={`flex flex-col gap-1 rounded-md p-2.5 text-xs ${
                      msg.role === "user"
                        ? "bg-zinc-800/80 text-zinc-100 ml-4 border border-zinc-700/50"
                        : "bg-zinc-950/80 text-zinc-300 mr-2 border border-zinc-800"
                    }`}
                  >
                    <div className="flex items-center justify-between text-[10px] text-zinc-500">
                      <span className="font-semibold text-zinc-400">
                        {msg.role === "user" ? "You" : "OpenCode AI"}
                      </span>
                      <span>{msg.timestamp}</span>
                    </div>

                    <div className="text-[11px] leading-relaxed whitespace-pre-wrap">{msg.content}</div>

                    {msg.sql && (
                      <div className="mt-2 rounded border border-zinc-800 bg-zinc-950 p-2">
                        <pre className="font-mono text-[10px] text-emerald-300 whitespace-pre-wrap overflow-x-auto leading-relaxed">
                          {msg.sql}
                        </pre>
                        <div className="flex items-center justify-end gap-1.5 mt-2 pt-1.5 border-t border-zinc-900">
                          <Button
                            size="sm"
                            variant="ghost"
                            className="h-6 text-[10px] text-zinc-300 hover:text-zinc-100 px-2"
                            onClick={() => applySql(msg.sql!, false)}
                          >
                            Insert into Editor
                          </Button>
                          <Button
                            size="sm"
                            className="h-6 text-[10px] bg-emerald-600 hover:bg-emerald-500 text-white px-2.5 gap-1"
                            onClick={() => applySql(msg.sql!, true)}
                          >
                            <Play className="h-2.5 w-2.5 fill-current" /> Run Now
                          </Button>
                        </div>
                      </div>
                    )}

                    {msg.injected_prompt && (
                      <details className="mt-1.5 text-[10px] text-zinc-500">
                        <summary className="cursor-pointer font-mono text-[9px] text-amber-500/80 hover:text-amber-400 select-none">
                          Harness Injected: Jane SQL Agent (AGENTS.md)
                        </summary>
                        <pre className="mt-1 max-h-36 overflow-y-auto whitespace-pre-wrap rounded bg-zinc-950/90 p-2 font-mono text-[9px] text-zinc-400 border border-zinc-800/80">
                          {msg.injected_prompt}
                        </pre>
                      </details>
                    )}
                  </div>
                ))}

                {aiGenerating && (
                  <div className="flex items-center gap-2 rounded-md bg-zinc-950/60 p-2.5 text-xs text-zinc-400 border border-zinc-800">
                    <div className="h-3 w-3 animate-spin rounded-full border-2 border-amber-400 border-t-transparent" />
                    <span>OpenCode analyzing schema & synthesizing SQL...</span>
                  </div>
                )}
              </div>

              {/* Quick Prompt Chips */}
              <div className="border-t border-zinc-900 p-2 bg-zinc-950/40">
                <span className="text-[10px] text-zinc-500 font-medium block mb-1.5">Suggested Prompts</span>
                <div className="flex flex-wrap gap-1">
                  {[
                    "Actors with confidence >= 0.8",
                    "Sanctioned Bitcoin wallets",
                    "Leaked clearweb origin IPs",
                    "Pages per investigation",
                  ].map((chip) => (
                    <button
                      key={chip}
                      className="rounded bg-zinc-900 hover:bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-300 hover:text-zinc-100 border border-zinc-800 transition-colors"
                      onClick={() => askOpenCode(chip)}
                    >
                      {chip}
                    </button>
                  ))}
                </div>
              </div>

              {/* Chat Input */}
              <div className="border-t border-border/40 p-2 bg-zinc-950/80">
                <div className="flex items-center gap-1.5">
                  <input
                    type="text"
                    placeholder="Ask OpenCode to generate SQL..."
                    value={aiPrompt}
                    onChange={(e) => setAiPrompt(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        askOpenCode();
                      }
                    }}
                    className="flex-1 rounded-md bg-zinc-900 border border-zinc-800 px-2.5 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-500 focus:outline-none focus:border-amber-400/50"
                  />
                  <Button
                    size="icon-sm"
                    className="h-8 w-8 bg-amber-500 hover:bg-amber-400 text-black shrink-0"
                    disabled={aiGenerating || !aiPrompt.trim()}
                    onClick={() => askOpenCode()}
                  >
                    <Send className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </AppShell>
  );
}
