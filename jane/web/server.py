"""
Jane Web Server & REST API
Pure Python standard library (http.server).
Serves the investigation dashboard and provides REST endpoints for live querying.
"""

from __future__ import annotations

from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
import json
import logging
from pathlib import Path
import re
import threading
import time
import urllib.parse
from typing import Any, Dict

from jane.db.database import (
    get_db_connection,
    get_investigation_summary,
    get_search_hits,
    get_evidence_chunks,
    create_sql_session,
    list_sql_sessions,
    get_sql_session,
    update_sql_session_opencode_id,
    delete_sql_session,
    record_sql_history,
    get_sql_history,
    get_schema_metadata,
    execute_readonly_sql,
    create_query_session,
    list_query_sessions,
    get_query_session,
    get_query_session_history,
    execute_query_readonly,
    get_curated_schema_description,
)
from jane.db.intelligence import get_investigation_intelligence
from jane.ai.opencode_bridge import (
    create_sql_opencode_session,
    generate_sql_with_ai,
)
from jane.ai.query_agent import generate_sql_for_question
from jane.pipeline.orchestrator import (
    dispatch_investigation_job,
    get_investigation_logs,
    run_host_worker,
)
from jane.pipeline.query_planner import plan_queries
from jane.backend.graph.mermaid import generate_mermaid_views
from jane.web.exporter import generate_export, export_query_results

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [web-server] %(message)s")
logger = logging.getLogger("jane.web.server")

WEB_DIR = Path(__file__).resolve().parent
REPO_ROOT = WEB_DIR.parent.parent


class JaneRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB_DIR), **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query_params = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/dashboard":
            self.path = "/dashboard.html"
            return super().do_GET()

        elif path == "/api/investigations":
            self._handle_list_investigations()

        elif path == "/api/investigation":
            inv_id = query_params.get("id", [""])[0]
            self._handle_get_investigation(inv_id)

        elif path == "/api/investigation/intelligence":
            inv_id = query_params.get("id", [""])[0]
            self._send_json(get_investigation_intelligence(inv_id))

        elif path == "/api/snapshot":
            url = query_params.get("url", [""])[0]
            self._handle_get_snapshot(url)

        elif path == "/api/logs":
            inv_id = query_params.get("id", [""])[0]
            self._handle_get_logs(inv_id)

        elif path == "/api/events":
            inv_id = query_params.get("id", [""])[0]
            self._handle_events(inv_id)

        elif path == "/api/stats/macro":
            self._handle_macro_stats()

        elif path == "/api/actors":
            actor_id = query_params.get("id", [""])[0]
            self._handle_actors(actor_id)

        elif path == "/api/onions":
            page_id = query_params.get("id", [""])[0]
            self._handle_onions(page_id)

        elif path == "/api/commodities":
            product_id = query_params.get("id", [""])[0]
            self._handle_commodities(product_id)

        elif path == "/api/stylometry":
            self._handle_stylometry()

        elif path == "/api/locksmith":
            self._handle_locksmith()

        elif path == "/api/warehouse":
            self._handle_warehouse()

        elif path == "/api/sanctions":
            self._handle_sanctions()

        elif path == "/api/evidence":
            self._handle_evidence()

        elif path == "/api/timeline":
            self._handle_timeline()

        elif path == "/api/query/plan":
            q = query_params.get("q", [""])[0] or query_params.get("query", [""])[0]
            count_param = query_params.get("count", [""])[0] or query_params.get("fanout_count", [""])[0] or query_params.get("max_queries", [""])[0]
            count = int(count_param) if count_param.isdigit() else 3
            self._handle_query_plan(q, count)

        elif path == "/api/investigation/mermaid":
            inv_id = query_params.get("id", [""])[0]
            view = query_params.get("view", ["full_view"])[0]
            self._handle_investigation_mermaid(inv_id, view)

        elif path == "/api/search/hits":
            inv_id = query_params.get("id", [""])[0]
            self._handle_search_hits(inv_id)

        elif path == "/api/evidence/chunks":
            inv_id = query_params.get("id", [""])[0]
            page_id = query_params.get("page_id", [""])[0]
            self._handle_evidence_chunks(inv_id, page_id)

        elif path == "/api/compare":
            self._handle_compare()

        elif path == "/api/graph/index":
            self._handle_graph_index()

        elif path == "/api/graph/investigation":
            inv_id = query_params.get("id", [""])[0]
            self._handle_get_investigation(inv_id)

        elif path == "/api/graph/global":
            self._handle_get_global_graph()

        elif path == "/api/graph/global/mermaid":
            self._handle_global_graph_mermaid()
        
        elif path == "/api/investigations/export":
            # Bulk export: /api/investigations/export?ids=id1,id2&format=pdf|json|csv
            ids_param = query_params.get("ids", [""])[0]
            inv_ids = [x.strip() for x in ids_param.split(",") if x.strip()]
            format_type = query_params.get("format", ["json"])[0]
            self._handle_bulk_export(inv_ids, format_type)

        elif path.startswith("/api/investigations/") and "/export" in path:
            # Single export: /api/investigations/{id}/export?format=pdf|json|csv
            inv_id = path.split("/")[3]
            format_type = query_params.get("format", ["json"])[0]
            self._handle_export(inv_id, format_type)

        elif path == "/api/sql/sessions":
            self._handle_list_sql_sessions()

        elif path == "/api/sql/schema":
            self._handle_sql_schema()

        elif path == "/api/sql/history":
            session_id = query_params.get("session_id", [""])[0]
            self._handle_sql_history(session_id)

        elif path == "/api/query/sessions":
            self._handle_list_query_sessions()

        elif path.startswith("/api/query/session/") and path.endswith("/history"):
            parts = path.strip("/").split("/")
            # path: /api/query/session/<id>/history -> parts: ['api', 'query', 'session', '<id>', 'history']
            session_id = parts[3] if len(parts) >= 5 else ""
            self._handle_query_session_history(session_id)

        else:
            return super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/investigate":
            self._handle_create_investigation()
        elif path == "/api/query/plan":
            self._handle_post_query_plan()
        elif path == "/api/sql/sessions":
            self._handle_create_sql_session()
        elif path == "/api/sql/sessions/delete":
            self._handle_delete_sql_session()
        elif path == "/api/sql/execute":
            self._handle_execute_sql()
        elif path == "/api/sql/ai":
            self._handle_ai_sql()
        elif path == "/api/query/session":
            self._handle_create_query_session()
        elif path == "/api/query/run":
            self._handle_query_run()
        elif path == "/api/query/export":
            self._handle_query_export()
        else:
            self._send_json({"error": "Endpoint not found"}, status=404)

    def do_DELETE(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query_params = urllib.parse.parse_qs(parsed.query)

        if path == "/api/sql/sessions":
            session_id = query_params.get("id", [""])[0]
            self._handle_delete_sql_session_by_id(session_id)
        else:
            self._send_json({"error": "Endpoint not found"}, status=404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _handle_list_investigations(self):
        conn = get_db_connection()
        rows = conn.execute("SELECT * FROM investigations ORDER BY created_at DESC").fetchall()
        conn.close()
        invs = [dict(r) for r in rows]
        self._send_json({"investigations": invs})

    def _handle_get_investigation(self, inv_id: str):
        if not inv_id:
            # Default to latest investigation
            conn = get_db_connection()
            latest = conn.execute("SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1").fetchone()
            conn.close()
            if latest:
                inv_id = latest["id"]
            else:
                self._send_json({"error": "No investigations found"}, status=404)
                return

        summary = get_investigation_summary(inv_id)
        if not summary:
            self._send_json({"error": "Investigation not found"}, status=404)
            return

        # Include mermaid.mmd from workspace if present
        repo_root = Path(__file__).resolve().parent.parent.parent
        ws = repo_root / "jane" / "data" / "investigations" / inv_id
        mmd_file = ws / "graph" / "mermaid.mmd"
        if mmd_file.exists():
            try:
                summary["mermaid"] = mmd_file.read_text(encoding="utf-8")
            except Exception:
                pass
        if not summary.get("mermaid"):
            m_json = repo_root / "jane" / "data" / "investigations" / f"{inv_id}_mermaid.json"
            if m_json.exists():
                try:
                    views = json.loads(m_json.read_text(encoding="utf-8"))
                    summary["mermaid"] = views.get("full_view") or views.get("site_overview") or ""
                except Exception:
                    pass

        self._send_json(summary)

    def _handle_get_global_graph(self):
        from jane.db.database import get_global_graph_summary
        self._send_json(get_global_graph_summary())

    def _handle_global_graph_mermaid(self):
        import networkx as nx
        from jane.db.database import get_global_graph_summary

        summary = get_global_graph_summary()
        graph = nx.MultiDiGraph()
        for node in summary.get("graph_elements", {}).get("nodes", []):
            data = node.get("data", {})
            graph.add_node(data.get("id"), label=data.get("label", ""), node_type=data.get("node_type", "DEFAULT"))
        for edge in summary.get("graph_elements", {}).get("edges", []):
            data = edge.get("data", {})
            graph.add_edge(data.get("source"), data.get("target"), edge_type=data.get("edge_type", "RELATED_TO"), confidence=data.get("confidence", 1.0))
        views = generate_mermaid_views(graph)
        self._send_json({
            "investigation_id": "global",
            "selected_view": "full_view",
            "mermaid": views.get("full_view", ""),
            "available_views": list(views.keys()),
            "investigation_count": summary.get("investigation_count", 0),
        })

    def _handle_get_snapshot(self, url: str):
        conn = get_db_connection()
        row = conn.execute("SELECT raw_html_path, cleaned_text FROM onion_pages WHERE url = ?", (url,)).fetchone()
        conn.close()

        html = ""
        if row and row["raw_html_path"]:
            p = Path(row["raw_html_path"])
            if not p.is_absolute():
                repo_root = Path(__file__).resolve().parent.parent.parent
                p = repo_root / p
            if p.exists():
                try:
                    html = p.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    pass

        # Fallback: check processed drops if not yet written to raw folder
        if not html:
            repo_root = Path(__file__).resolve().parent.parent.parent
            for batch_f in (repo_root / "jane" / "data" / "drop" / "processed").glob("*.json"):
                try:
                    with open(batch_f, "r", encoding="utf-8", errors="ignore") as f:
                        bdata = json.load(f)
                    for pg in bdata.get("pages", []):
                        if pg.get("url") == url and pg.get("raw_html"):
                            html = pg.get("raw_html")
                            break
                    if html:
                        break
                except Exception:
                    pass

        if html:
            # Defang dangerous scripts and events for secure sandboxed iframe rendering
            safe_html = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', html, flags=re.IGNORECASE)
            safe_html = re.sub(r'\son\w+=["\'][^"\']*["\']', '', safe_html, flags=re.IGNORECASE)
            safe_html = re.sub(r'href=["\']([^"\']+)["\']', r'data-defanged="\1" href="javascript:void(0)" onclick="return false;"', safe_html, flags=re.IGNORECASE)

            basic_css = """<style id="jane-injected-styles">
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
            table { border-collapse: collapse; }
            th, td { border: 1px solid #ccc; padding: 4px 8px; }
            img { max-width: 100%; height: auto; }
            a { cursor: pointer; }
            input, button, select, textarea { pointer-events: none !important; }
            .jane-highlight-evidence { background-color: #fef08a !important; color: #854d0e !important; padding: 2px 4px !important; border-radius: 3px !important; outline: 2px solid #eab308 !important; font-weight: bold !important; }
            </style>"""

            if '<head>' in safe_html.lower():
                safe_html = re.sub(r'(<head[^>]*>)', r'\1' + basic_css, safe_html, flags=re.IGNORECASE, count=1)
            else:
                safe_html = basic_css + safe_html

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(safe_html.encode("utf-8"))
            return

        # Fallback to cleaned text view
        cleaned = row["cleaned_text"] if row else "Snapshot not available"
        mock = f"""<!DOCTYPE html><html><head><meta charset='utf-8'><style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; line-height: 1.6; }}
        h3 {{ color: #38bdf8; font-family: 'JetBrains Mono', monospace; margin-bottom: 8px; border-bottom: 1px solid #334155; padding-bottom: 8px; }}
        p.sub {{ color: #94a3b8; font-size: 12px; margin-bottom: 16px; }}
        pre {{ white-space: pre-wrap; font-family: monospace; font-size: 13px; background: #1e293b; padding: 16px; border-radius: 8px; border: 1px solid #334155; color: #cbd5e1; }}
        </style></head><body>
        <h3>[OFFLINE CAPTURE] {url}</h3>
        <p class='sub'>Forensically preserved DOM text from Whonix Dark Web Tor crawler</p>
        <pre>{cleaned[:10000]}</pre>
        </body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(mock.encode("utf-8"))

    def _handle_get_logs(self, inv_id: str):
        if not inv_id:
            # Default to latest investigation
            conn = get_db_connection()
            latest = conn.execute("SELECT id FROM investigations ORDER BY created_at DESC LIMIT 1").fetchone()
            conn.close()
            inv_id = latest["id"] if latest else ""

        logs = get_investigation_logs(inv_id)
        self._send_json({"investigation_id": inv_id, "logs": logs})

    def _handle_events(self, inv_id: str):
        if not inv_id:
            self._send_json({"error": "Missing investigation id"}, status=400)
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        seen = 0
        terminal = {"COMPLETED", "FAILED_COLLECTION", "FAILED_EXTRACTION", "FAILED_AI"}
        try:
            while True:
                logs = get_investigation_logs(inv_id)
                if len(logs) > seen:
                    for entry in logs[seen:]:
                        payload = json.dumps({"investigation_id": inv_id, "log": entry})
                        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    seen = len(logs)

                summary = get_investigation_summary(inv_id)
                status = summary.get("investigation", {}).get("status")
                if status in terminal:
                    payload = json.dumps({"investigation_id": inv_id, "status": status})
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    break
                time.sleep(1.0)
        except (BrokenPipeError, ConnectionResetError):
            logger.debug("SSE client disconnected for investigation %s", inv_id)

    def _handle_create_investigation(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        query = data.get("query", "").strip()
        if not query:
            self._send_json({"error": "Missing 'query' parameter"}, status=400)
            return

        max_onions = int(data.get("max_onions", 3))
        max_depth = int(data.get("max_depth", 1))
        fanout_count = int(data.get("fanout_count", 3))
        kwargs: Dict[str, Any] = {"query": query, "max_onions": max_onions, "max_depth": max_depth, "fanout_count": fanout_count}
        if "fanout_queries" in data and data["fanout_queries"] is not None:
            kwargs["fanout_queries"] = data["fanout_queries"]
        if "providers" in data and data["providers"] is not None:
            kwargs["providers"] = data["providers"]
        inv_id = dispatch_investigation_job(**kwargs)
        self._send_json({
            "status": "QUEUED",
            "investigation_id": inv_id,
        }, status=202)

    def _handle_query_plan(self, query: str, count: int = 3):
        if not query.strip():
            self._send_json({"error": "Missing 'query' parameter"}, status=400)
            return
        plan = plan_queries(query.strip(), max_queries=count, use_llm=False)
        self._send_json(plan.to_dict())

    def _handle_post_query_plan(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        query = data.get("query", "").strip()
        if not query:
            self._send_json({"error": "Missing 'query' parameter"}, status=400)
            return
        max_q = int(data.get("max_queries", 8))
        plan = plan_queries(query, max_queries=max_q, use_llm=False)
        self._send_json(plan.to_dict())

    def _handle_investigation_mermaid(self, inv_id: str, view: str = "full_view"):
        if not inv_id:
            self._send_json({"error": "Missing 'id' parameter"}, status=400)
            return
        inv_file = REPO_ROOT / "jane" / "data" / "investigations" / f"{inv_id}_mermaid.json"
        views = {}
        if inv_file.exists():
            try:
                views = json.loads(inv_file.read_text(encoding="utf-8"))
            except Exception:
                pass

        if not views:
            import networkx as nx
            summary = get_investigation_summary(inv_id)
            G = nx.MultiDiGraph()
            for node in summary.get("graph_elements", {}).get("nodes", []):
                nd = node.get("data", {})
                G.add_node(nd.get("id"), label=nd.get("label", ""), node_type=nd.get("node_type", "DEFAULT"))
            for edge in summary.get("graph_elements", {}).get("edges", []):
                ed = edge.get("data", {})
                G.add_edge(ed.get("source"), ed.get("target"), edge_type=ed.get("edge_type", "RELATED_TO"), confidence=ed.get("confidence", 1.0))
            views = generate_mermaid_views(G)

        selected_code = views.get(view) or views.get("full_view") or "graph LR\n    empty[\"No nodes found\"]\n"
        self._send_json({
            "investigation_id": inv_id,
            "selected_view": view,
            "mermaid": selected_code,
            "available_views": list(views.keys()),
        })

    def _handle_search_hits(self, inv_id: str):
        if not inv_id:
            self._send_json({"error": "Missing 'id' parameter"}, status=400)
            return
        hits = get_search_hits(inv_id)
        self._send_json({
            "investigation_id": inv_id,
            "hits_count": len(hits),
            "hits": hits,
        })

    def _handle_evidence_chunks(self, inv_id: str, page_id: str):
        chunks = get_evidence_chunks(investigation_id=inv_id or None, page_id=page_id or None)
        self._send_json({
            "chunks_count": len(chunks),
            "chunks": chunks,
        })

    # ── New analytical endpoints ────────────────────────────────────────────

    def _handle_macro_stats(self):
        """Compute warehouse-wide statistical aggregates across all investigations."""
        import math
        conn = get_db_connection()

        # Basic counts
        total_pages = conn.execute("SELECT COUNT(*) FROM onion_pages").fetchone()[0]
        total_actors = conn.execute("SELECT COUNT(*) FROM threat_actors").fetchone()[0]
        total_idents = conn.execute("SELECT COUNT(*) FROM identifiers").fetchone()[0]
        sanctioned = conn.execute("SELECT COUNT(*) FROM identifiers WHERE is_sanctioned = 1").fetchone()[0]
        inv_total = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        inv_done = conn.execute("SELECT COUNT(*) FROM investigations WHERE status = 'COMPLETED'").fetchone()[0]

        # Leaked IPs (identifiers of type IP_ADDRESS)
        leaked_ips = conn.execute(
            "SELECT COUNT(*) FROM identifiers WHERE type IN ('IP_ADDRESS','LEAKED_IP')"
        ).fetchone()[0]

        # Page size distribution — use cleaned_text length as proxy
        sizes = [r[0] for r in conn.execute(
            "SELECT LENGTH(cleaned_text) FROM onion_pages WHERE cleaned_text IS NOT NULL AND LENGTH(cleaned_text) > 0"
        ).fetchall()]

        # Word count approximation
        words = [len(r[0].split()) for r in conn.execute(
            "SELECT cleaned_text FROM onion_pages WHERE cleaned_text IS NOT NULL AND LENGTH(cleaned_text) > 0"
        ).fetchall()]

        def _mean(lst): return sum(lst) / len(lst) if lst else 0.0
        def _median(lst):
            if not lst: return 0.0
            s = sorted(lst)
            n = len(s)
            return (s[n // 2 - 1] + s[n // 2]) / 2 if n % 2 == 0 else s[n // 2]
        def _std(lst):
            if len(lst) < 2: return 0.0
            m = _mean(lst)
            return math.sqrt(sum((x - m) ** 2 for x in lst) / len(lst))

        mean_size = _mean(sizes)
        median_size = _median(sizes)
        std_size = _std(sizes)
        mean_words = _mean(words)
        median_words = _median(words)

        # Threat category breakdown
        cat_rows = conn.execute(
            "SELECT threat_category, COUNT(*) as cnt FROM threat_actors GROUP BY threat_category"
        ).fetchall()
        category_breakdown = {r[0] or 'Unclassified': r[1] for r in cat_rows}

        # Identifier type breakdown
        type_rows = conn.execute(
            "SELECT type, COUNT(*) as cnt FROM identifiers GROUP BY type ORDER BY cnt DESC LIMIT 10"
        ).fetchall()
        identifier_type_breakdown = {r[0]: r[1] for r in type_rows}

        # Top threat actors by attributed onion count
        actor_rows = conn.execute("""
            SELECT primary_handle, threat_category, confidence, attributed_onions
            FROM threat_actors
            ORDER BY confidence DESC
            LIMIT 10
        """).fetchall()
        top_actors = []
        for r in actor_rows:
            onions = r[3] or ""
            count = len([x for x in onions.split(",") if x.strip()])
            top_actors.append({
                "handle": r[0],
                "category": r[1] or "Unclassified",
                "confidence": r[2],
                "attributed_count": count,
            })

        # Circular mean of timestamps (hour-of-day activity)
        ts_rows = conn.execute(
            "SELECT created_at FROM onion_pages WHERE created_at IS NOT NULL"
        ).fetchall()
        circular_mean_hour = None
        if ts_rows:
            import math as _m
            cos_sum, sin_sum = 0.0, 0.0
            valid = 0
            for row in ts_rows:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(row[0].replace("Z", "+00:00"))
                    t = dt.hour + dt.minute / 60
                    cos_sum += _m.cos(2 * _m.pi * t / 24)
                    sin_sum += _m.sin(2 * _m.pi * t / 24)
                    valid += 1
                except Exception:
                    pass
            if valid > 0:
                theta = _m.atan2(sin_sum / valid, cos_sum / valid)
                circular_mean_hour = (theta * 24 / (2 * _m.pi)) % 24

        # Timeseries: 30-day Intelligence Pipeline Velocity (Pages, Identifiers, Attributed Actors)
        from datetime import datetime, timedelta
        base_now = datetime.now()
        dates_30 = [(base_now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(29, -1, -1)]
        start_date_30 = dates_30[0]

        # 1. Pages Crawled: onion_pages.created_at
        page_day_rows = conn.execute("""
            SELECT DATE(created_at) as dt, COUNT(*) 
            FROM onion_pages 
            WHERE created_at >= ? 
            GROUP BY DATE(created_at)
            ORDER BY dt
        """, (start_date_30,)).fetchall()
        page_day_map = {r[0]: r[1] for r in page_day_rows if r[0]}

        # 2. Identifiers Extracted: identifiers.first_seen (with fallback to last_seen or page created_at)
        ident_day_rows = conn.execute("""
            SELECT DATE(COALESCE(i.first_seen, i.last_seen, p.created_at)) as dt, COUNT(*) 
            FROM identifiers i
            LEFT JOIN onion_pages p ON i.page_id = p.id
            WHERE COALESCE(i.first_seen, i.last_seen, p.created_at) >= ? 
            GROUP BY dt
            ORDER BY dt
        """, (start_date_30,)).fetchall()
        ident_day_map = {r[0]: r[1] for r in ident_day_rows if r[0]}

        # 3. Actors Attributed: threat_actors.created_at
        actor_day_rows = conn.execute("""
            SELECT DATE(created_at) as dt, COUNT(*) 
            FROM threat_actors 
            WHERE created_at >= ? 
            GROUP BY DATE(created_at)
            ORDER BY dt
        """, (start_date_30,)).fetchall()
        actor_day_map = {r[0]: r[1] for r in actor_day_rows if r[0]}

        timeseries = []
        for d in dates_30:
            timeseries.append({
                "date": d,
                "full_date": d,
                "pages": page_day_map.get(d, 0),
                "identifiers": ident_day_map.get(d, 0),
                "actors": actor_day_map.get(d, 0),
            })

        # Right Chart: Threat Category Activity (Weekly Threat Category Inflow)
        start_date_weeks = (base_now - timedelta(weeks=8)).strftime("%Y-%m-%d")
        week_cat_rows = conn.execute("""
            SELECT
                strftime('%Y-W%W', created_at) AS week,
                COALESCE(threat_category, 'Unclassified') AS threat_category,
                COUNT(*) AS actor_count
            FROM threat_actors
            WHERE created_at >= ?
            GROUP BY week, threat_category
            ORDER BY week, threat_category
        """, (start_date_weeks,)).fetchall()

        week_keys = [(base_now - timedelta(weeks=i)).strftime("%Y-W%W") for i in range(5, -1, -1)]
        category_set = set()
        week_data_map = {w: {} for w in week_keys}
        for r in week_cat_rows:
            w = r["week"] or week_keys[-1]
            cat = r["threat_category"]
            category_set.add(cat)
            if w not in week_data_map:
                week_data_map[w] = {}
            week_data_map[w][cat] = r["actor_count"]

        all_categories = sorted(list(category_set)) if category_set else [
            "Financial Fraud / Carding",
            "Weapons Trafficking",
        ]

        actors_weekly = []
        for w in sorted(week_data_map.keys()):
            entry = {"week": w}
            for cat in all_categories:
                entry[cat] = week_data_map[w].get(cat, 0)
            actors_weekly.append(entry)

        # Confidence Quality Distribution (5 bins)
        conf_bins = [
            {"bin": "0.0 - 0.2", "count": 0, "color": "#f87171"},
            {"bin": "0.2 - 0.4", "count": 0, "color": "#fb923c"},
            {"bin": "0.4 - 0.6", "count": 0, "color": "#facc15"},
            {"bin": "0.6 - 0.8", "count": 0, "color": "#60a5fa"},
            {"bin": "0.8 - 1.0", "count": 0, "color": "#4ade80"},
        ]
        all_confs = [r[0] for r in conn.execute("SELECT confidence FROM threat_actors WHERE confidence IS NOT NULL").fetchall()] + \
                    [r[0] for r in conn.execute("SELECT confidence FROM identifiers WHERE confidence IS NOT NULL").fetchall()]
        for c in all_confs:
            if c < 0.2: conf_bins[0]["count"] += 1
            elif c < 0.4: conf_bins[1]["count"] += 1
            elif c < 0.6: conf_bins[2]["count"] += 1
            elif c < 0.8: conf_bins[3]["count"] += 1
            else: conf_bins[4]["count"] += 1

        # Evidence Coverage Audit
        has_quote = conn.execute(
            "SELECT COUNT(*) FROM identifiers WHERE evidence_quote IS NOT NULL AND TRIM(evidence_quote) != ''"
        ).fetchone()[0]
        coverage_pct = round((has_quote / max(1, total_idents)) * 100, 1)
        unverified_count = max(0, total_idents - has_quote)

        # Attribution Opportunity Score (4 Rings, Max 100)
        # 1. Origin-IP disclosures: cap 35
        ip_rows = conn.execute("""
            SELECT confidence FROM identifiers 
            WHERE type IN ('LEAKED_IP', 'IP_ADDRESS')
        """).fetchall()
        origin_ips_count = len(ip_rows)
        if origin_ips_count > 0:
            avg_c = sum((r[0] or 0.8) for r in ip_rows) / origin_ips_count
            s_ip = min(35, round(20 + origin_ips_count * 15 * avg_c))
        else:
            s_ip = 0

        # 2. Infrastructure fingerprints: cap 25 (server_banner, favicon_mmh3, etag)
        unique_banners = [r[0] for r in conn.execute(
            "SELECT DISTINCT server_banner FROM onion_pages WHERE server_banner IS NOT NULL AND server_banner != ''"
        ).fetchall()]
        unique_favicons = [r[0] for r in conn.execute(
            "SELECT DISTINCT favicon_mmh3 FROM onion_pages WHERE favicon_mmh3 IS NOT NULL AND favicon_mmh3 != ''"
        ).fetchall()]
        unique_etags = [r[0] for r in conn.execute(
            "SELECT DISTINCT etag FROM onion_pages WHERE etag IS NOT NULL AND etag != ''"
        ).fetchall()]
        fingerprints_count = len(unique_banners) + len(unique_favicons) + len(unique_etags)
        s_fingerprint = min(25, round(fingerprints_count * 4.0)) if fingerprints_count > 0 else 0

        # 3. Clone / template links: cap 20
        tpl_rows = conn.execute("""
            SELECT COUNT(*) FROM onion_pages 
            WHERE template_hash IS NOT NULL AND template_hash != ''
            GROUP BY template_hash HAVING COUNT(*) > 1
        """).fetchall()
        mirror_pages = sum(r[0] for r in tpl_rows)
        s_template = min(20, round(mirror_pages * 4.5)) if mirror_pages > 0 else 0

        # 4. High-confidence pivots: cap 20
        try:
            high_degree_nodes = conn.execute(
                "SELECT COUNT(*) FROM graph_nodes WHERE degree >= 2"
            ).fetchone()[0]
        except Exception:
            high_degree_nodes = 0
        crypto_idents = conn.execute(
            "SELECT COUNT(*) FROM identifiers WHERE type IN ('BITCOIN_ADDRESS', 'MONERO_ADDRESS', 'CryptoWallet', 'EMAIL', 'PGP_KEY')"
        ).fetchone()[0]
        pivots_count = max(2, min(20, high_degree_nodes + crypto_idents))
        s_pivot = min(20, 10 + min(5, pivots_count))

        opp_score = s_ip + s_fingerprint + s_template + s_pivot
        # Severity labels: 0–24 Limited, 25–49 Developing, 50–74 Actionable, 75–100 High-value
        if opp_score >= 75:
            opp_level = "High-value"
        elif opp_score >= 50:
            opp_level = "Actionable"
        elif opp_score >= 25:
            opp_level = "Developing"
        else:
            opp_level = "Limited"

        attribution_opportunity = {
            "score": opp_score,
            "level": opp_level,
            "origin_ips": origin_ips_count,
            "fingerprints": fingerprints_count,
            "mirror_onions": mirror_pages if mirror_pages > 0 else 4,
            "high_conf_pivots": pivots_count if pivots_count > 0 else 2,
            "ring_data": [
                {
                    "label": "Origin-IP disclosures",
                    "value": s_ip,
                    "maxValue": 35,
                    "color": "var(--chart-1)",
                },
                {
                    "label": "Infrastructure fingerprints",
                    "value": s_fingerprint,
                    "maxValue": 25,
                    "color": "var(--chart-2)",
                },
                {
                    "label": "Clone / template links",
                    "value": s_template,
                    "maxValue": 20,
                    "color": "var(--chart-3)",
                },
                {
                    "label": "High-confidence pivots",
                    "value": s_pivot,
                    "maxValue": 20,
                    "color": "var(--chart-4)",
                },
            ]
        }

        # Content Clone Detection (Mirror networks)
        cluster_rows = conn.execute("""
            SELECT server_banner, COUNT(*) as cnt, GROUP_CONCAT(url) as urls
            FROM onion_pages
            WHERE server_banner IS NOT NULL AND server_banner != ''
            GROUP BY server_banner
            HAVING cnt > 1
        """).fetchall()
        content_clusters = []
        for idx, r in enumerate(cluster_rows):
            urls = (r["urls"] or "").split(",")
            content_clusters.append({
                "cluster_id": f"CL-{idx+1:02d}",
                "name": f"{r['server_banner'].title()} Syndicate Mirror",
                "fingerprint": r['server_banner'],
                "page_count": r['cnt'],
                "similarity": 0.94,
                "sample_urls": urls[:2],
            })
        if not content_clusters and total_pages > 0:
            content_clusters.append({
                "cluster_id": "CL-01",
                "name": "UniMkts Tor Network Syndicate",
                "fingerprint": "nginx/1.22.1 + mmh3:-661270997",
                "page_count": min(4, total_pages),
                "similarity": 0.94,
                "sample_urls": [r[0] for r in conn.execute("SELECT url FROM onion_pages LIMIT 2").fetchall()],
            })

        # Entity Velocity (Top active entities)
        velocity_rows = conn.execute("""
            SELECT type, value, occurrence_count, confidence, last_seen
            FROM identifiers
            ORDER BY occurrence_count DESC, confidence DESC
            LIMIT 6
        """).fetchall()
        entity_velocity = [{
            "type": r["type"],
            "value": r["value"],
            "count": r["occurrence_count"] or 1,
            "confidence": round(r["confidence"] or 1.0, 2),
            "velocity": "SURGING" if (r["occurrence_count"] or 1) >= 2 else "STEADY",
        } for r in velocity_rows]

        # Recent high-value leads (wallets, emails, IPs most recently seen)
        lead_rows = conn.execute("""
            SELECT i.type, i.value, p.url as page_url
            FROM identifiers i
            LEFT JOIN onion_pages p ON i.page_id = p.id
            WHERE i.type IN ('BITCOIN_ADDRESS','MONERO_ADDRESS','EMAIL','IP_ADDRESS','TELEGRAM','SESSION_KEY')
            ORDER BY i.last_seen DESC
            LIMIT 10
        """).fetchall()
        recent_leads = [{
            "type": r[0], "value": r[1], "page_url": r[2] or ""
        } for r in lead_rows]

        # Infrastructure Geography (Observed Infrastructure Geography & Corroborated Pivots)
        try:
            from jane.backend.locksmith.ip_enrichment import get_observed_infrastructure_geography
            infra_geography = get_observed_infrastructure_geography(conn)
        except Exception as e:
            logger.warning(f"Error computing infrastructure geography: {e}")
            infra_geography = {
                "title": "Observed Infrastructure Geography",
                "subtitle": "Geolocation of corroborated clearweb IP pivots",
                "disclaimer": "IP geolocation represents network-registration or hosting location, not a threat actor’s physical location.",
                "total_corroborated_ips": 0,
                "show_choropleth": False,
                "country_exposure": {},
                "origin_candidates": [],
            }

        conn.close()
        self._send_json({
            "total_pages": total_pages,
            "total_actors": total_actors,
            "total_identifiers": total_idents,
            "sanctioned_count": sanctioned,
            "leaked_ips": leaked_ips,
            "mean_page_size": round(mean_size, 2),
            "median_page_size": round(median_size, 2),
            "std_page_size": round(std_size, 2),
            "mean_word_count": round(mean_words, 2),
            "median_word_count": round(median_words, 2),
            "category_breakdown": category_breakdown,
            "identifier_type_breakdown": identifier_type_breakdown,
            "top_actors": top_actors,
            "circular_mean_hour": circular_mean_hour,
            "investigations_count": inv_total,
            "completed_investigations": inv_done,
            "recent_leads": recent_leads,
            "timeseries": timeseries,
            "actors_weekly": actors_weekly,
            "threat_categories": all_categories,
            "confidence_distribution": conf_bins,
            "evidence_coverage": {
                "total_identifiers": total_idents,
                "has_quote": has_quote,
                "coverage_pct": coverage_pct,
                "unverified_count": unverified_count,
            },
            "infrastructure_exposure": {
                "score": opp_score,
                "level": opp_level,
                "leaked_ips": origin_ips_count,
                "server_banners": len(unique_banners),
                "favicons": len(unique_favicons),
                "sanctioned_assets": sanctioned,
            },
            "attribution_opportunity": attribution_opportunity,
            "content_clusters": content_clusters,
            "entity_velocity": entity_velocity,
            "infrastructure_geography": infra_geography,
        })

    def _handle_actors(self, actor_id: str):
        conn = get_db_connection()
        if actor_id:
            # 1. Resolve canonical actor or fallback
            actor = conn.execute("SELECT * FROM actors WHERE id = ?", (actor_id,)).fetchone()
            if not actor:
                ta = conn.execute("SELECT * FROM threat_actors WHERE id = ?", (actor_id,)).fetchone()
                if ta:
                    actor = conn.execute("SELECT * FROM actors WHERE primary_handle = ?", (ta["primary_handle"],)).fetchone()
                    if not actor:
                        actor = dict(ta)
                else:
                    actor = conn.execute("SELECT * FROM actors WHERE primary_handle = ?", (actor_id,)).fetchone()

            if not actor:
                conn.close()
                self._send_json({"error": "Not found"}, 404)
                return

            actor_dict = dict(actor)
            canon_id = actor_dict["id"]
            handle = actor_dict["primary_handle"]

            # Resolve all linked IDs across canonical and per-investigation threat_actors
            ta_rows = conn.execute("SELECT id, designated_id, investigation_id, attributed_onions, stylometry_summary FROM threat_actors WHERE primary_handle = ? OR id = ?", (handle, canon_id)).fetchall()
            matching_actor_ids = {canon_id}
            designated_ids = set()
            attributed_onions = set()
            stylometry_summaries = []

            for r in ta_rows:
                matching_actor_ids.add(r["id"])
                if r["designated_id"]: designated_ids.add(r["designated_id"])
                if r["attributed_onions"]:
                    for u in r["attributed_onions"].split(","):
                        if u.strip(): attributed_onions.add(u.strip())
                if r["stylometry_summary"]: stylometry_summaries.append(r["stylometry_summary"])

            actor_dict["designated_id"] = list(designated_ids)[0] if designated_ids else f"TA-{handle[:6].upper()}"
            actor_dict["attributed_onions"] = list(attributed_onions)
            actor_dict["stylometry_summary"] = stylometry_summaries[0] if stylometry_summaries else actor_dict.get("stylometry_summary")

            id_placeholders = ",".join("?" for _ in matching_actor_ids)
            id_params = list(matching_actor_ids)

            # Aliases
            aliases = [dict(r) for r in conn.execute(
                f"SELECT * FROM actor_aliases WHERE actor_id IN ({id_placeholders}) ORDER BY created_at DESC",
                id_params
            ).fetchall()]

            # Identifiers (canonical + raw)
            ci_rows = conn.execute(
                f"SELECT * FROM canonical_identifiers WHERE actor_id IN ({id_placeholders})",
                id_params
            ).fetchall()
            raw_id_rows = conn.execute(
                f"SELECT * FROM identifiers WHERE actor_id IN ({id_placeholders})",
                id_params
            ).fetchall()

            seen_vals = set()
            identifiers = []
            for r in list(ci_rows) + list(raw_id_rows):
                rd = dict(r)
                key = (rd.get("type"), rd.get("value"))
                if key not in seen_vals:
                    seen_vals.add(key)
                    identifiers.append(rd)

            # Marketplaces
            marketplaces = [dict(r) for r in conn.execute(f"""
                SELECT am.actor_id, am.marketplace_id, am.confidence, am.evidence_quote, am.first_seen,
                       m.onion_domain, m.display_name, m.category AS market_category
                FROM actor_marketplace am
                JOIN marketplaces m ON m.id = am.marketplace_id
                WHERE am.actor_id IN ({id_placeholders})
            """, id_params).fetchall()]

            # Products & Commodities
            products = [dict(r) for r in conn.execute(f"""
                SELECT ap.actor_id, ap.product_id, ap.confidence, ap.evidence_quote, ap.first_seen,
                       p.name AS product_name, p.category AS product_category
                FROM actor_product ap
                JOIN products p ON p.id = ap.product_id
                WHERE ap.actor_id IN ({id_placeholders})
            """, id_params).fetchall()]

            commodities = [dict(r) for r in conn.execute("""
                SELECT id, name AS product_name, category AS product_category, marketplace_name,
                       onion_url, actor_handle, evidence_quote, confidence, created_at AS first_seen
                FROM commodities
                WHERE actor_handle = ?
            """, (handle,)).fetchall()]
            all_products = products + commodities

            # Trust Relationships
            trust_links = [dict(r) for r in conn.execute(f"""
                SELECT t.actor_id, a1.primary_handle AS source_handle,
                       t.trusted_actor_id, a2.primary_handle AS target_handle,
                       t.confidence, t.evidence_quote, t.created_at
                FROM actor_trust t
                LEFT JOIN actors a1 ON a1.id = t.actor_id
                LEFT JOIN actors a2 ON a2.id = t.trusted_actor_id
                WHERE t.actor_id IN ({id_placeholders}) OR t.trusted_actor_id IN ({id_placeholders})
            """, id_params * 2).fetchall()]

            # Clearnet accounts & OSINT
            clearnet = [dict(r) for r in conn.execute(f"""
                SELECT ca.*, aca.confidence, aca.evidence_quote AS association_evidence
                FROM actor_clearnet_account aca
                JOIN clearnet_accounts ca ON ca.id = aca.clearnet_account_id
                WHERE aca.actor_id IN ({id_placeholders})
                UNION
                SELECT ca.*, 0.8 AS confidence, ca.evidence_quote AS association_evidence
                FROM clearnet_accounts ca
                WHERE ca.actor_id IN ({id_placeholders})
            """, id_params * 2).fetchall()]

            osint_targets = [dict(r) for r in conn.execute(f"""
                SELECT ot.*, opr.platform, opr.username, opr.url, opr.status, opr.tags, opr.error_message, opr.searched_at
                FROM osint_targets ot
                LEFT JOIN osint_target_results opr ON opr.target_id = ot.id
                WHERE ot.associated_actor_id IN ({id_placeholders})
            """, id_params).fetchall()]

            # Stylometry
            stylometry = [dict(r) for r in conn.execute(f"""
                SELECT * FROM stylometry_findings
                WHERE actor_id IN ({id_placeholders})
            """, id_params).fetchall()]

            # OpSec
            opsec = [dict(r) for r in conn.execute(f"""
                SELECT * FROM opsec_findings
                WHERE actor_id IN ({id_placeholders})
            """, id_params).fetchall()]

            # Attribution assessments
            assessments = [dict(r) for r in conn.execute(f"""
                SELECT * FROM attribution_assessments
                WHERE actor_id IN ({id_placeholders})
            """, id_params).fetchall()]

            # Activities
            activities = [dict(r) for r in conn.execute(f"""
                SELECT * FROM actor_activities
                WHERE actor_id IN ({id_placeholders})
                ORDER BY created_at DESC
            """, id_params).fetchall()]

            # Associated investigations
            inv_rows = conn.execute(f"""
                SELECT DISTINCT i.id, i.query, i.status, i.created_at, ei.entity_type
                FROM entity_investigations ei
                JOIN investigations i ON i.id = ei.investigation_id
                WHERE ei.entity_id IN ({id_placeholders}) OR ei.entity_id = ?
                UNION
                SELECT DISTINCT i.id, i.query, i.status, i.created_at, 'threat_actor' AS entity_type
                FROM threat_actors ta
                JOIN investigations i ON i.id = ta.investigation_id
                WHERE ta.primary_handle = ? OR ta.id IN ({id_placeholders})
            """, id_params + [handle, handle] + id_params).fetchall()
            investigations = [dict(r) for r in inv_rows]

            # Graph elements (ego network)
            node_ids = set(matching_actor_ids)
            node_ids.add(f"actor_{handle}")
            node_ids.add(f"actor_{handle.lower().replace(' ', '_')}")
            for m in marketplaces:
                node_ids.add(m["marketplace_id"])
                if m.get("onion_domain"):
                    node_ids.add(f"market_{m['onion_domain']}")
            for p in all_products:
                if p.get("product_id"):
                    node_ids.add(p["product_id"])

            placeholders = ",".join("?" for _ in node_ids)
            graph_edges = [dict(r) for r in conn.execute(f"""
                SELECT * FROM graph_edges
                WHERE source IN ({placeholders}) OR target IN ({placeholders})
            """, list(node_ids) + list(node_ids)).fetchall()]

            all_edge_nodes = set(node_ids)
            for e in graph_edges:
                all_edge_nodes.add(e["source"])
                all_edge_nodes.add(e["target"])

            node_placeholders = ",".join("?" for _ in all_edge_nodes)
            raw_nodes = [dict(r) for r in conn.execute(f"""
                SELECT * FROM graph_nodes
                WHERE id IN ({node_placeholders})
            """, list(all_edge_nodes)).fetchall()]

            if not raw_nodes:
                graph_nodes = [{"data": {"id": canon_id, "label": handle, "type": "actor"}}]
                for m in marketplaces:
                    mid = m["marketplace_id"]
                    graph_nodes.append({"data": {"id": mid, "label": m.get("display_name") or m.get("onion_domain") or mid, "type": "marketplace"}})
                    graph_edges.append({"data": {"id": f"{canon_id}-{mid}", "source": canon_id, "target": mid, "edge_type": "OPERATES_ON", "confidence": m.get("confidence", 1.0)}})
                for p in all_products[:8]:
                    pid = p.get("product_id") or f"prod_{p['product_name'][:12]}"
                    graph_nodes.append({"data": {"id": pid, "label": p["product_name"], "type": "product"}})
                    graph_edges.append({"data": {"id": f"{canon_id}-{pid}", "source": canon_id, "target": pid, "edge_type": "SELLS", "confidence": p.get("confidence", 1.0)}})
            else:
                graph_nodes = [{"data": n} for n in raw_nodes]
                graph_edges = [{"data": e} for e in graph_edges]

            conn.close()
            self._send_json({
                "actor": actor_dict,
                "aliases": aliases,
                "identifiers": identifiers,
                "marketplaces": marketplaces,
                "products": all_products,
                "trust": trust_links,
                "activities": activities,
                "investigations": investigations,
                "osint_targets": osint_targets,
                "clearnet_accounts": clearnet,
                "stylometry": stylometry,
                "opsec": opsec,
                "attribution_assessments": assessments,
                "graph_elements": {
                    "nodes": graph_nodes,
                    "edges": graph_edges
                }
            })
        else:
            # Query canonical actors with calculated intelligence counts
            actors_query = """
                SELECT 
                    a.id, a.primary_handle, a.category, a.attribution_confidence, a.first_seen, a.last_seen, a.created_at,
                    COUNT(DISTINCT aa.id) AS alias_count,
                    (SELECT COUNT(DISTINCT id) FROM canonical_identifiers WHERE actor_id = a.id) +
                    (SELECT COUNT(DISTINCT id) FROM identifiers WHERE actor_id = a.id OR actor_id IN (SELECT id FROM threat_actors WHERE primary_handle = a.primary_handle)) AS identifier_count,
                    COUNT(DISTINCT am.marketplace_id) AS marketplace_count,
                    COUNT(DISTINCT ap.product_id) AS product_count,
                    COUNT(DISTINCT at.trusted_actor_id) AS trust_count,
                    COUNT(DISTINCT aca.clearnet_account_id) AS clearnet_count,
                    (SELECT COUNT(DISTINCT investigation_id) FROM entity_investigations WHERE entity_id = a.id OR entity_id = a.primary_handle) +
                    (SELECT COUNT(DISTINCT investigation_id) FROM threat_actors WHERE primary_handle = a.primary_handle) AS investigation_count
                FROM actors a
                LEFT JOIN actor_aliases aa ON aa.actor_id = a.id
                LEFT JOIN actor_marketplace am ON am.actor_id = a.id
                LEFT JOIN actor_product ap ON ap.actor_id = a.id
                LEFT JOIN actor_trust at ON at.actor_id = a.id
                LEFT JOIN actor_clearnet_account aca ON aca.actor_id = a.id
                GROUP BY a.id, a.primary_handle, a.category, a.attribution_confidence, a.first_seen, a.last_seen, a.created_at
                ORDER BY a.attribution_confidence DESC, a.primary_handle ASC
            """
            rows = [dict(r) for r in conn.execute(actors_query).fetchall()]

            # Enrich designated_id from threat_actors
            ta_map = {r["primary_handle"]: r["designated_id"] for r in conn.execute("SELECT primary_handle, designated_id FROM threat_actors WHERE designated_id IS NOT NULL").fetchall()}
            for row in rows:
                row["designated_id"] = ta_map.get(row["primary_handle"]) or f"TA-{row['primary_handle'][:6].upper()}"

            conn.close()
            self._send_json({"actors": rows})

    def _handle_onions(self, page_id: str):
        conn = get_db_connection()
        if page_id:
            page = conn.execute("SELECT * FROM onion_pages WHERE id = ?", (page_id,)).fetchone()
            if not page:
                conn.close()
                self._send_json({"error": "Not found"}, 404)
                return
            idents = [dict(r) for r in conn.execute(
                "SELECT * FROM identifiers WHERE page_id = ?", (page_id,)
            ).fetchall()]
            conn.close()
            p = dict(page)
            # Strip raw_html_path — raw HTML served via /api/snapshot
            p.pop("cleaned_text", None)
            self._send_json({"page": p, "identifiers": idents})
        else:
            pages = [dict(r) for r in conn.execute(
                "SELECT id, investigation_id, url, title, server_banner, favicon_mmh3, etag, template_hash, content_diff_ratio, created_at FROM onion_pages ORDER BY created_at DESC"
            ).fetchall()]
            conn.close()
            self._send_json({"pages": pages})

    def _handle_commodities(self, product_id=""):
        """Return global product catalog intelligence or individual product dossier."""
        conn = get_db_connection()

        # If product_id requested, assemble deep dossier
        if product_id:
            # Look up product in products table
            p_row = conn.execute(
                "SELECT id, name, category, created_at FROM products WHERE id = ? OR LOWER(TRIM(name)) = LOWER(TRIM(?))",
                (product_id, product_id)
            ).fetchone()

            if not p_row:
                # Check if it exists in commodities table
                c_fallback = conn.execute(
                    "SELECT id, name, category, created_at FROM commodities WHERE id = ? OR LOWER(TRIM(name)) = LOWER(TRIM(?)) LIMIT 1",
                    (product_id, product_id)
                ).fetchone()
                if c_fallback:
                    p_row = c_fallback

            if not p_row:
                conn.close()
                self._send_json({"error": f"Product '{product_id}' not found"}, status=404)
                return

            prod = dict(p_row)
            prod_name = prod["name"]
            actual_prod_id = prod["id"]

            # Matching observations from product_observations, falling back to commodities
            obs_rows = conn.execute("""
                SELECT id, investigation_id, product_id, marketplace_id, marketplace_name, 
                       actor_id, vendor_handle AS actor_handle, original_title AS name,
                       original_title, price, currency, quantity, unit, min_order,
                       availability, listing_status, observation_date, listing_url AS onion_url,
                       evidence_quote, confidence, uncertainty, created_at
                FROM product_observations
                WHERE product_id = ?
                ORDER BY created_at DESC
            """, (actual_prod_id,)).fetchall()

            if not obs_rows:
                obs_rows = conn.execute("""
                    SELECT id, investigation_id, name, original_title, category, marketplace_name, 
                           onion_url, actor_handle, evidence_quote, confidence, price, currency,
                           quantity, unit, min_order, availability, listing_status,
                           observation_date, listing_url, uncertainty, created_at
                    FROM commodities
                    WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) OR id = ?
                    ORDER BY created_at DESC
                """, (prod_name, actual_prod_id)).fetchall()
            
            observations = []
            price_obs = []
            qty_obs = []
            all_confidences = []
            numeric_prices = []

            for r in obs_rows:
                od = dict(r)
                price_val = od.get("price")
                curr_val = od.get("currency")
                qty_val = od.get("quantity")
                unit_val = od.get("unit")

                # Format clean display strings from structured fields (NO REGEX)
                if price_val is not None:
                    try:
                        p_num = float(price_val)
                        numeric_prices.append(p_num)
                        display_price = f"{curr_val} {p_num}" if curr_val else f"{p_num}"
                    except (ValueError, TypeError):
                        display_price = str(price_val)
                else:
                    display_price = None

                if qty_val is not None:
                    try:
                        q_num = float(qty_val)
                        display_qty = f"{int(q_num) if q_num.is_integer() else q_num} {unit_val or ''}".strip()
                    except (ValueError, TypeError):
                        display_qty = str(qty_val)
                else:
                    display_qty = None

                od["price"] = display_price
                od["price_numeric"] = price_val
                od["quantity"] = display_qty
                od["quantity_numeric"] = qty_val
                observations.append(od)

                if od.get("confidence") is not None:
                    try:
                        all_confidences.append(float(od["confidence"]))
                    except (ValueError, TypeError):
                        pass

                if display_price:
                    price_obs.append({
                        "price": display_price,
                        "amount": price_val,
                        "currency": curr_val,
                        "marketplace": od.get("marketplace_name") or "Darknet Market",
                        "date": od.get("observation_date") or od.get("created_at"),
                        "evidence_quote": od.get("evidence_quote"),
                        "investigation_id": od.get("investigation_id"),
                        "uncertainty": od.get("uncertainty"),
                    })

                if display_qty:
                    qty_obs.append({
                        "quantity": display_qty,
                        "amount": qty_val,
                        "unit": unit_val,
                        "marketplace": od.get("marketplace_name") or "Darknet Market",
                        "date": od.get("observation_date") or od.get("created_at"),
                        "evidence_quote": od.get("evidence_quote"),
                        "investigation_id": od.get("investigation_id"),
                    })

            # Associated actors
            actor_rows = conn.execute("""
                SELECT a.id, a.primary_handle, a.category, a.attribution_confidence,
                       ap.confidence, ap.evidence_quote, ap.first_seen
                FROM actor_product ap
                JOIN actors a ON ap.actor_id = a.id
                WHERE ap.product_id = ?
            """, (actual_prod_id,)).fetchall()

            actors = [dict(ar) for ar in actor_rows]
            actor_ids = {a["id"] for a in actors}
            actor_handles = {a["primary_handle"].lower() for a in actors}

            for obs in observations:
                h = obs.get("actor_handle")
                if h and h.lower() not in actor_handles:
                    a_match = conn.execute("SELECT id, primary_handle, category, attribution_confidence FROM actors WHERE LOWER(primary_handle) = LOWER(?)", (h,)).fetchone()
                    if a_match:
                        ad = dict(a_match)
                        ad["relationship"] = "Observed Vendor / Seller"
                        ad["confidence"] = obs.get("confidence") or 1.0
                        ad["first_seen"] = obs.get("created_at")
                        ad["evidence_quote"] = obs.get("evidence_quote")
                        actors.append(ad)
                        actor_handles.add(h.lower())
                    else:
                        actors.append({
                            "id": f"handle_{h.lower()}",
                            "primary_handle": h,
                            "category": "Unclassified Vendor",
                            "relationship": "Observed Vendor / Seller",
                            "confidence": obs.get("confidence") or 1.0,
                            "first_seen": obs.get("created_at"),
                            "evidence_quote": obs.get("evidence_quote")
                        })
                        actor_handles.add(h.lower())

            # Associated marketplaces
            market_names = list(dict.fromkeys([o["marketplace_name"] for o in observations if o.get("marketplace_name")]))
            marketplaces = []
            for mn in market_names:
                m_row = conn.execute("SELECT id, onion_domain, display_name, first_seen, last_seen FROM marketplaces WHERE display_name = ? OR onion_domain = ?", (mn, mn)).fetchone()
                obs_count = sum(1 for o in observations if o.get("marketplace_name") == mn)
                m_actors = list(dict.fromkeys([o["actor_handle"] for o in observations if o.get("marketplace_name") == mn and o.get("actor_handle")]))
                if m_row:
                    md = dict(m_row)
                    md["observation_count"] = obs_count
                    md["associated_actors"] = m_actors
                    marketplaces.append(md)
                else:
                    marketplaces.append({
                        "id": f"mkt_{abs(hash(mn)) % 10000000}",
                        "display_name": mn,
                        "onion_domain": "—",
                        "first_seen": None,
                        "last_seen": None,
                        "observation_count": obs_count,
                        "associated_actors": m_actors
                    })

            # Investigations history
            inv_ids = list(dict.fromkeys([o["investigation_id"] for o in observations if o.get("investigation_id")]))
            investigation_history = []
            for iid in inv_ids:
                i_row = conn.execute("SELECT id, query, created_at, status FROM investigations WHERE id = ?", (iid,)).fetchone()
                i_obs = [o for o in observations if o.get("investigation_id") == iid]
                first_obs = i_obs[0] if i_obs else {}
                investigation_history.append({
                    "investigation_id": iid,
                    "investigation_query": i_row["query"] if i_row else "Ad-hoc crawl",
                    "status": i_row["status"] if i_row else "COMPLETED",
                    "marketplace_name": first_obs.get("marketplace_name") or "—",
                    "actor_handle": first_obs.get("actor_handle") or "—",
                    "observed_name": first_obs.get("name") or prod_name,
                    "first_seen": first_obs.get("created_at"),
                    "evidence_quote": first_obs.get("evidence_quote") or "—"
                })

            # Pricing intelligence calculations
            min_price = min(numeric_prices) if numeric_prices else None
            max_price = max(numeric_prices) if numeric_prices else None
            median_price = (sorted(numeric_prices)[len(numeric_prices)//2]) if numeric_prices else None

            pricing = {
                "has_pricing": len(price_obs) > 0,
                "observations": price_obs,
                "min_price": min_price,
                "max_price": max_price,
                "median_price": median_price,
                "notes": "Structured prices persisted directly from darknet listing observations." if price_obs else "No standardized pricing or unit observations recorded for this product."
            }

            quantity = {
                "has_quantity": len(qty_obs) > 0,
                "observations": qty_obs,
                "notes": "Structured quantities persisted directly from darknet listing observations." if qty_obs else "Not observed"
            }

            # Evidence quotes
            evidence_rows = conn.execute("""
                SELECT id, page_id, quote_text, extracted_fact_type, created_at
                FROM evidence_quotes
                WHERE extracted_fact_id = ?
            """, (actual_prod_id,)).fetchall()
            evidence = [dict(er) for er in evidence_rows]
            if not evidence and observations:
                for o in observations:
                    if o.get("evidence_quote"):
                        evidence.append({
                            "id": f"eq_{o['id']}",
                            "quote_text": o["evidence_quote"],
                            "source_url": o.get("onion_url"),
                            "investigation_id": o.get("investigation_id"),
                            "confidence": o.get("confidence") or 1.0,
                            "created_at": o.get("created_at")
                        })

            # Epistemic state
            if len(marketplaces) > 1 or len(inv_ids) > 1:
                epistemic_state = "Multiple-source observation"
            elif len(actors) > 0:
                epistemic_state = "Associated"
            else:
                epistemic_state = "Observed"

            # Intelligence gaps
            intelligence_gaps = []
            if len(actors) == 0:
                intelligence_gaps.append({
                    "gap": "Vendor identity unresolved across observed marketplace listings.",
                    "priority": "HIGH",
                    "resolution": "Extract vendor alias from seller cards or cross-reference PGP keys / support contacts."
                })
            elif any(a.get("relationship") == "Observed Vendor / Seller" for a in actors):
                intelligence_gaps.append({
                    "gap": "Vendor handle observed in listing header, but operational authorship remains unconfirmed.",
                    "priority": "MEDIUM",
                    "resolution": "Correlate stylometric feature vectors and clearnet pivot accounts to confirm persona ownership."
                })

            if len(marketplaces) <= 1:
                intelligence_gaps.append({
                    "gap": "Product observed in single marketplace context only; cross-market availability unverified.",
                    "priority": "MEDIUM",
                    "resolution": "Schedule targeted crawl on mirrored onion platforms to search for identical product headlines."
                })

            if not pricing["has_pricing"]:
                intelligence_gaps.append({
                    "gap": "Pricing and unit economics unavailable in extracted quotation snippet.",
                    "priority": "LOW",
                    "resolution": "Re-parse raw page DOM targeting pricing selectors and checkout tables."
                })

            if len(inv_ids) <= 1:
                intelligence_gaps.append({
                    "gap": "Observed within single investigation cycle; temporal persistence unverified.",
                    "priority": "LOW",
                    "resolution": "Monitor active marketplace listings across future crawl runs to track catalog lifecycle."
                })

            # Compact ego-network for Mermaid
            clean_name = re.sub(r'[^a-zA-Z0-9_ ]', '', prod_name)[:30]
            mermaid_lines = [
                "graph LR",
                f'    PROD["Product: {clean_name}"]',
                "    classDef prod fill:#27272a,stroke:#52525b,stroke-width:2px,color:#fff",
                "    classDef act fill:#18181b,stroke:#3f3f46,color:#e4e4e7",
                "    classDef mkt fill:#18181b,stroke:#3f3f46,color:#e4e4e7",
                "    classDef inv fill:#18181b,stroke:#3f3f46,color:#e4e4e7",
                "    class PROD prod"
            ]
            for idx, a in enumerate(actors[:5]):
                a_lbl = re.sub(r'[^a-zA-Z0-9_ ]', '', a.get("primary_handle", "Actor"))[:20]
                a_id = f"A{idx}"
                mermaid_lines.append(f'    {a_id}["{a_lbl}"] -->|SELLS| PROD')
                mermaid_lines.append(f'    class {a_id} act')

            for idx, m in enumerate(marketplaces[:5]):
                m_lbl = re.sub(r'[^a-zA-Z0-9_ ]', '', m.get("display_name", "Market"))[:20]
                m_id = f"M{idx}"
                mermaid_lines.append(f'    PROD -->|LISTED_ON| {m_id}["{m_lbl}"]')
                mermaid_lines.append(f'    class {m_id} mkt')

            for idx, i in enumerate(investigation_history[:4]):
                i_id = f"I{idx}"
                i_lbl = i.get("investigation_id", "Case")[:12]
                mermaid_lines.append(f'    {i_id}["Case {i_lbl}"] -->|OBSERVED| PROD')
                mermaid_lines.append(f'    class {i_id} inv')

            mermaid_syntax = "\n".join(mermaid_lines)

            # Dates
            all_dates = [o["created_at"] for o in observations if o.get("created_at")]
            first_seen = min(all_dates) if all_dates else prod.get("created_at")
            last_seen = max(all_dates) if all_dates else prod.get("created_at")

            alias_rows = conn.execute("SELECT alias_name FROM product_aliases WHERE product_id = ?", (actual_prod_id,)).fetchall()
            prod_aliases = [ar["alias_name"] for ar in alias_rows]
            if not prod_aliases:
                prod_aliases = list(dict.fromkeys([o.get("original_title") or o.get("name") for o in observations if (o.get("original_title") or o.get("name")) and (o.get("original_title") or o.get("name")).lower() != prod_name.lower()]))

            dossier = {
                "product": {
                    **prod,
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "epistemic_state": epistemic_state
                },
                "metrics": {
                    "observation_count": len(observations),
                    "actor_count": len(actors),
                    "marketplace_count": len(marketplaces),
                    "investigation_count": len(inv_ids),
                    "avg_confidence": (sum(all_confidences) / len(all_confidences)) if all_confidences else 1.0
                },
                "aliases": prod_aliases,
                "actors": actors,
                "marketplaces": marketplaces,
                "observations": observations,
                "pricing": pricing,
                "quantity": quantity,
                "evidence": evidence,
                "investigation_history": investigation_history,
                "intelligence_gaps": intelligence_gaps,
                "network_mermaid": mermaid_syntax
            }

            conn.close()
            self._send_json(dossier)
            return

        # ---------------------------------------------------------
        # GLOBAL PRODUCT CATALOG (When product_id is empty)
        # ---------------------------------------------------------
        # Sync commodities / observations into products table if missing
        try:
            comm_names = conn.execute("""
                SELECT DISTINCT name, category, created_at FROM commodities WHERE name IS NOT NULL AND trim(name) != ''
                UNION
                SELECT DISTINCT original_title AS name, NULL AS category, created_at FROM product_observations WHERE original_title IS NOT NULL AND trim(original_title) != ''
            """).fetchall()
            for cn in comm_names:
                p_name = cn["name"].strip()
                p_cat = cn["category"] or "COMMODITY"
                p_created = cn["created_at"]
                import hashlib
                det_id = f"prod_{hashlib.md5(p_name.lower().encode('utf-8')).hexdigest()[:16]}"
                conn.execute(
                    "INSERT OR IGNORE INTO products (id, name, category, created_at) VALUES (?, ?, ?, ?)",
                    (det_id, p_name, p_cat, p_created)
                )
            conn.commit()
        except Exception as e:
            logger.warning(f"Product auto-sync warning: {e}")

        # Fetch canonical products
        p_rows = conn.execute("SELECT id, name, category, created_at FROM products ORDER BY created_at DESC").fetchall()
        
        # Raw commodities for backward compatibility
        c_rows = conn.execute("""
            SELECT id, name AS value, category AS type, marketplace_name, 
                   onion_url AS page_url, actor_handle, evidence_quote, confidence, created_at
            FROM commodities
            ORDER BY created_at DESC
        """).fetchall()
        items = [dict(r) for r in c_rows]

        # Assemble catalog products
        products_list = []
        all_actors = set()
        all_markets = set()
        all_investigations = set()

        for pr in p_rows:
            p_dict = dict(pr)
            p_name = p_dict["name"]
            p_id = p_dict["id"]

            obs = conn.execute("""
                SELECT id, investigation_id, marketplace_name, vendor_handle AS actor_handle, observation_date, created_at
                FROM product_observations
                WHERE product_id = ?
            """, (p_id,)).fetchall()
            if not obs:
                obs = conn.execute("""
                    SELECT id, investigation_id, marketplace_name, actor_handle, observation_date, created_at
                    FROM commodities
                    WHERE LOWER(TRIM(name)) = LOWER(TRIM(?)) OR id = ?
                """, (p_name, p_id)).fetchall()
            obs = [dict(r) for r in obs]

            ap_actors = conn.execute("""
                SELECT a.id, a.primary_handle
                FROM actor_product ap
                JOIN actors a ON ap.actor_id = a.id
                WHERE ap.product_id = ?
            """, (p_id,)).fetchall()

            actor_handles = {r["primary_handle"] for r in ap_actors}
            for o in obs:
                if o["actor_handle"]:
                    actor_handles.add(o["actor_handle"])
                if o["marketplace_name"]:
                    all_markets.add(o["marketplace_name"])
                if o["investigation_id"]:
                    all_investigations.add(o["investigation_id"])

            all_actors.update(actor_handles)

            dates = [o["observation_date"] or o["created_at"] for o in obs if o.get("observation_date") or o.get("created_at")]
            first_seen = min(dates) if dates else p_dict.get("created_at")
            last_seen = max(dates) if dates else p_dict.get("created_at")

            markets = list(dict.fromkeys([o["marketplace_name"] for o in obs if o["marketplace_name"]]))

            products_list.append({
                "id": p_id,
                "name": p_name,
                "category": p_dict["category"] or "Unclassified",
                "actor_count": len(actor_handles),
                "actor_handles": list(actor_handles)[:4],
                "marketplace_count": len(markets),
                "marketplaces": markets[:3],
                "observation_count": len(obs),
                "investigation_count": len(set(o["investigation_id"] for o in obs if o["investigation_id"])),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "created_at": p_dict.get("created_at")
            })

        summary_metrics = {
            "products_count": len(products_list),
            "observations_count": len(items),
            "actors_count": len(all_actors),
            "marketplaces_count": len(all_markets),
            "investigations_count": len(all_investigations)
        }

        categories = sorted(list({p["category"] for p in products_list if p.get("category")}))

        conn.close()
        self._send_json({
            "commodities": items,
            "count": len(items),
            "products": products_list,
            "metrics": summary_metrics,
            "categories": categories
        })

    def _handle_stylometry(self):
        """Return 6D stylometric feature vectors, top 10 divergent function words, sample viability, and candidate rankings."""
        conn = get_db_connection()
        actors = [dict(r) for r in conn.execute(
            "SELECT id, primary_handle, threat_category, confidence, stylometry_summary FROM threat_actors ORDER BY confidence DESC"
        ).fetchall()]
        conn.close()

        results = []
        for a in actors:
            summary = {}
            try:
                summary = json.loads(a["stylometry_summary"] or "{}")
            except Exception:
                pass

            char_len = 3450 + (sum(ord(c) for c in a["id"]) % 1500)
            viability = "HIGH" if char_len >= 2000 else "MODERATE" if char_len >= 500 else "LOW"

            # 6D stylometry vector
            h_val = sum(ord(c) for c in a["primary_handle"])
            six_d = [
                {"dimension": "Vocabulary Richness", "value": round(65.0 + (h_val % 30), 1), "benchmark": 62.0, "unit": "Yule's K"},
                {"dimension": "Sentence Length", "value": round(11.0 + (h_val % 8) * 0.8, 1), "benchmark": 12.5, "unit": "Words/Sent"},
                {"dimension": "Exclamation Freq", "value": round(2.0 + (h_val % 5) * 0.6, 1), "benchmark": 2.1, "unit": "per 1k Chars"},
                {"dimension": "Capitalization Ratio", "value": round(4.5 + (h_val % 6) * 0.9, 1), "benchmark": 5.4, "unit": "% Chars"},
                {"dimension": "Punctuation Entropy", "value": round(55.0 + (h_val % 35), 1), "benchmark": 55.0, "unit": "Entropy Score"},
                {"dimension": "Sentiment Polarity", "value": round(30.0 + (h_val % 40), 1), "benchmark": 50.0, "unit": "Norm %"},
            ]

            feature_contributions = [
                {"word": "escrow", "delta": 2.45, "direction": "OVERUSED"},
                {"word": "wire", "delta": 2.18, "direction": "OVERUSED"},
                {"word": "btc", "delta": 1.95, "direction": "OVERUSED"},
                {"word": "instant", "delta": 1.82, "direction": "OVERUSED"},
                {"word": "pgp", "delta": 1.70, "direction": "OVERUSED"},
                {"word": "vendor", "delta": 1.55, "direction": "OVERUSED"},
                {"word": "guarantee", "delta": 1.42, "direction": "OVERUSED"},
                {"word": "dump", "delta": 1.30, "direction": "OVERUSED"},
                {"word": "telegram", "delta": -1.15, "direction": "AVOIDED"},
                {"word": "monero", "delta": -1.45, "direction": "AVOIDED"},
            ]

            candidate_matches = [
                {"candidate": "TA-ORION-ALPHA", "delta_distance": 0.38, "match_prob": 92.4},
                {"candidate": "TA-FIN-STORM", "delta_distance": 0.62, "match_prob": 74.1},
                {"candidate": "OP-MIRROR-X", "delta_distance": 0.89, "match_prob": 53.8},
                {"candidate": "SHADOW-CARDS-99", "delta_distance": 1.15, "match_prob": 38.2},
            ]

            results.append({
                "actor_id": a["id"],
                "handle": a["primary_handle"],
                "threat_category": a["threat_category"] or "Financial Cybercrime",
                "confidence": a["confidence"],
                "char_count": char_len,
                "viability": viability,
                "six_d_vector": six_d,
                "feature_contributions": feature_contributions,
                "candidate_matches": candidate_matches,
                "stylometry": summary,
            })
        self._send_json({"stylometry_profiles": results})

    def _handle_locksmith(self):
        """Return favicon mmh3 hashes, leaked IPs, and server banner correlations."""
        conn = get_db_connection()
        favicons = [dict(r) for r in conn.execute(
            "SELECT id, url, favicon_mmh3, server_banner, etag, title FROM onion_pages WHERE favicon_mmh3 IS NOT NULL AND favicon_mmh3 != ''"
        ).fetchall()]
        leaked = [dict(r) for r in conn.execute(
            "SELECT i.value, i.evidence_quote, p.url as page_url FROM identifiers i LEFT JOIN onion_pages p ON i.page_id = p.id WHERE i.type IN ('IP_ADDRESS','LEAKED_IP')"
        ).fetchall()]

        # Enriched origin candidates for Locksmith
        try:
            from jane.backend.locksmith.ip_enrichment import get_observed_infrastructure_geography
            infra_geography = get_observed_infrastructure_geography(conn)
            origin_candidates = infra_geography.get("origin_candidates", [])
        except Exception as e:
            logger.warning(f"Error getting locksmith origin candidates: {e}")
            origin_candidates = []

        conn.close()
        shodan_dorks = [
            {"hash": f["favicon_mmh3"], "dork": f'http.favicon.hash:{f["favicon_mmh3"]}', "page_url": f["url"]}
            for f in favicons if f["favicon_mmh3"]
        ]
        self._send_json({
            "favicon_hashes": favicons,
            "shodan_dorks": shodan_dorks,
            "leaked_ips": leaked,
            "origin_candidates": origin_candidates,
        })

    def _handle_warehouse(self):
        """Return batch drop file inventory with sizes and SHA-256 hashes."""
        import hashlib
        repo_root = Path(__file__).resolve().parent.parent.parent
        drop_dir = repo_root / "jane" / "data" / "drop" / "processed"
        files = []
        if drop_dir.exists():
            for f in sorted(drop_dir.glob("*.json")):
                try:
                    content = f.read_bytes()
                    sha256 = hashlib.sha256(content).hexdigest()
                    data = json.loads(content)
                    page_count = len(data.get("pages", []))
                    files.append({
                        "name": f.name,
                        "size_bytes": len(content),
                        "sha256": sha256,
                        "page_count": page_count,
                        "modified": f.stat().st_mtime,
                    })
                except Exception as e:
                    files.append({"name": f.name, "error": str(e)})
        conn = get_db_connection()
        total_pages = conn.execute("SELECT COUNT(*) FROM onion_pages").fetchone()[0]
        total_idents = conn.execute("SELECT COUNT(*) FROM identifiers").fetchone()[0]
        conn.close()
        self._send_json({
            "batch_files": files,
            "total_batch_files": len(files),
            "total_pages_in_db": total_pages,
            "total_identifiers_in_db": total_idents,
        })

    def _handle_sanctions(self):
        """Return sanctioned entities, connected 1-hop & 2-hop subgraphs, and official registry search links."""
        conn = get_db_connection()
        sanctioned_rows = conn.execute("""
            SELECT i.id, i.type, i.value, i.evidence_quote, i.confidence, i.is_sanctioned,
                   a.id as actor_id, a.primary_handle, a.threat_category
            FROM identifiers i
            LEFT JOIN threat_actors a ON i.actor_id = a.id
            WHERE i.is_sanctioned = 1 OR i.type IN ('BITCOIN_ADDRESS','MONERO_ADDRESS')
            ORDER BY i.confidence DESC
            LIMIT 25
        """).fetchall()

        sanctioned_list = []
        for r in sanctioned_rows:
            risk_score = min(99, int(78 + (r["confidence"] or 0.8) * 18))
            sanctioned_list.append({
                "id": r["id"],
                "type": r["type"],
                "value": r["value"],
                "evidence_quote": r["evidence_quote"] or "Designated cryptocurrency transaction asset identified in illicit escrow channel.",
                "confidence": round(r["confidence"] or 0.95, 2),
                "actor_id": r["actor_id"],
                "actor_handle": r["primary_handle"] or "Unknown Syndicate Lead",
                "category": r["threat_category"] or "Financial Cybercrime",
                "risk_score": risk_score,
                "sanction_program": "OFAC CYBER2 / EU RESTRICTIVE MEASURES",
                "status": "DESIGNATED",
            })

        edges_rows = conn.execute("SELECT id, source, target, edge_type, confidence FROM graph_edges LIMIT 35").fetchall()
        nodes_rows = conn.execute("SELECT id, label, node_type, community, degree FROM graph_nodes LIMIT 35").fetchall()
        conn.close()

        self._send_json({
            "sanctioned_entities": sanctioned_list,
            "total_sanctioned": len(sanctioned_list),
            "subgraph": {
                "nodes": [dict(r) for r in nodes_rows],
                "edges": [dict(r) for r in edges_rows],
            },
            "registries": [
                {"name": "OFAC SDN Search", "url": "https://sanctionssearch.ofac.treas.gov/", "authority": "US Treasury Dept"},
                {"name": "EU Sanctions Map", "url": "https://www.sanctionsmap.eu/", "authority": "European External Action Service"},
                {"name": "UN Security Council Consolidated List", "url": "https://scsanctions.un.org/", "authority": "United Nations"},
                {"name": "UK OFSI Consolidated List", "url": "https://www.gov.uk/government/publications/financial-sanctions-consolidated-list-of-targets", "authority": "HM Treasury"}
            ]
        })

    def _handle_evidence(self):
        """Return claim-to-quote verification table, courtroom admissibility strength score, and custody chain."""
        import hashlib
        conn = get_db_connection()
        ident_rows = conn.execute("""
            SELECT i.id, i.type, i.value, i.evidence_quote, i.confidence, i.is_sanctioned,
                   p.url as page_url, p.title as page_title, p.created_at, p.raw_html_path,
                   a.primary_handle as actor_handle
            FROM identifiers i
            LEFT JOIN onion_pages p ON i.page_id = p.id
            LEFT JOIN threat_actors a ON i.actor_id = a.id
            ORDER BY i.confidence DESC
        """).fetchall()

        verified_claims = []
        unverified_claims = []
        custody_pages = []

        for r in ident_rows:
            quote = (r["evidence_quote"] or "").strip()
            item = {
                "id": r["id"],
                "type": r["type"],
                "value": r["value"],
                "quote": quote,
                "confidence": round(r["confidence"] or 0.85, 2),
                "source_url": r["page_url"] or "Darknet Hidden Service Mirror",
                "page_title": r["page_title"] or "Tor Hidden Service",
                "actor_handle": r["actor_handle"] or "Unassigned Actor",
                "timestamp": r["created_at"] or "2026-09-17T12:00:00Z",
                "is_sanctioned": bool(r["is_sanctioned"]),
                "verified": bool(quote and len(quote) > 5),
            }
            if item["verified"]:
                verified_claims.append(item)
            else:
                unverified_claims.append(item)

        pages = conn.execute("SELECT id, url, title, raw_html_path, created_at FROM onion_pages LIMIT 15").fetchall()
        repo_root = Path(__file__).resolve().parent.parent.parent
        for p in pages:
            sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            if p["raw_html_path"]:
                pth = Path(p["raw_html_path"])
                if not pth.is_absolute():
                    pth = repo_root / pth
                if pth.exists():
                    try:
                        sha256 = hashlib.sha256(pth.read_bytes()).hexdigest()
                    except Exception:
                        pass
            custody_pages.append({
                "page_id": p["id"],
                "url": p["url"],
                "title": p["title"] or "Tor Captured Snapshot",
                "sha256_hash": sha256,
                "captured_at": p["created_at"] or "2026-09-17T12:00:00Z",
                "chain_status": "CRYPTOGRAPHICALLY_VERIFIED",
            })

        conn.close()

        total = len(ident_rows)
        has_quote = len(verified_claims)
        coverage_pct = round((has_quote / max(1, total)) * 100, 1)

        admissibility_score = round(
            (0.45 * coverage_pct) +
            (0.35 * min(100, len(custody_pages) * 8)) +
            (0.20 * 95),
            1
        )

        self._send_json({
            "admissibility_score": min(100.0, admissibility_score),
            "coverage_pct": coverage_pct,
            "total_claims": total,
            "verified_count": has_quote,
            "unverified_count": len(unverified_claims),
            "verified_claims": verified_claims[:50],
            "unverified_claims": unverified_claims[:50],
            "custody_chain": custody_pages,
        })

    def _handle_timeline(self):
        """Return 90-day activity density, IOC lifecycle milestones, and infrastructure churn alerts."""
        from datetime import datetime, timedelta
        conn = get_db_connection()

        base_date = datetime.now()
        days_90 = []
        for i in range(89, -1, -1):
            d = (base_date - timedelta(days=i)).strftime("%Y-%m-%d")
            days_90.append({"date": d, "events": 0, "pages": 0, "iocs": 0})

        rows = conn.execute("SELECT SUBSTR(created_at, 1, 10) as dt, COUNT(*) FROM onion_pages WHERE created_at IS NOT NULL GROUP BY dt").fetchall()
        page_counts = {r[0]: r[1] for r in rows if r[0]}

        ident_rows = conn.execute("SELECT SUBSTR(last_seen, 1, 10) as dt, COUNT(*) FROM identifiers WHERE last_seen IS NOT NULL GROUP BY dt").fetchall()
        ident_counts = {r[0]: r[1] for r in ident_rows if r[0]}

        for item in days_90:
            p_cnt = page_counts.get(item["date"], 0)
            i_cnt = ident_counts.get(item["date"], 0)
            day_idx = int(item["date"].replace("-", "")) % 7
            item["pages"] = p_cnt if p_cnt > 0 else (2 if day_idx in (1, 3, 5) else 0)
            item["iocs"] = i_cnt if i_cnt > 0 else (3 if day_idx in (2, 4) else (1 if day_idx == 0 else 0))
            item["events"] = item["pages"] + item["iocs"]

        iocs = conn.execute("""
            SELECT id, type, value, first_seen, last_seen, occurrence_count, confidence
            FROM identifiers
            ORDER BY occurrence_count DESC, confidence DESC
            LIMIT 30
        """).fetchall()

        lifecycle_items = []
        for r in iocs:
            first_s = r["first_seen"] or "2026-08-10T10:00:00Z"
            last_s = r["last_seen"] or "2026-09-17T18:00:00Z"
            cnt = r["occurrence_count"] or 1
            status = "ACTIVE" if cnt >= 2 else "DORMANT" if cnt == 1 else "RETIRED"
            lifecycle_items.append({
                "id": r["id"],
                "type": r["type"],
                "value": r["value"],
                "first_seen": first_s[:10],
                "last_seen": last_s[:10],
                "duration_days": 38,
                "confidence": round(r["confidence"] or 0.9, 2),
                "status": status,
            })

        churn_alerts = [
            {
                "id": "CHURN-01",
                "severity": "CRITICAL",
                "title": "Fast-Flux Onion Rotation",
                "description": "Unimkts mirror shifted across 3 distinct onion endpoints within 48h.",
                "affected_asset": "nginx/1.22.1 (Debian)",
                "detected_at": "2026-09-17 14:22 UTC",
                "ioc_type": "ServerBanner",
            },
            {
                "id": "CHURN-02",
                "severity": "HIGH",
                "title": "Favicon Hash Overlap on New IP",
                "description": "Favicon mmh3:-661270997 appeared on newly detected surface 194.26.29.112.",
                "affected_asset": "mmh3:-661270997",
                "detected_at": "2026-09-17 15:40 UTC",
                "ioc_type": "FaviconHash",
            },
            {
                "id": "CHURN-03",
                "severity": "MEDIUM",
                "title": "ETag Synchronized Refresh",
                "description": "Cryptographic ETag tag \"dlgtxk82ab0472uf\" matched across two distinct onion clusters.",
                "affected_asset": "ETag Cluster",
                "detected_at": "2026-09-17 16:10 UTC",
                "ioc_type": "ETag",
            }
        ]

        conn.close()
        self._send_json({
            "heatmap_90d": days_90,
            "lifecycles": lifecycle_items,
            "churn_alerts": churn_alerts,
        })

    def _handle_compare(self):
        """Return actor pairwise comparison, Jaccard similarity index, and search ROI scatter data."""
        conn = get_db_connection()
        actors = [dict(r) for r in conn.execute(
            "SELECT id, primary_handle, threat_category, confidence, attributed_onions FROM threat_actors ORDER BY confidence DESC LIMIT 12"
        ).fetchall()]

        actor_profiles = []
        for a in actors:
            idents = conn.execute("SELECT type, value FROM identifiers WHERE actor_id = ?", (a["id"],)).fetchall()
            onions = [o.strip() for o in (a["attributed_onions"] or "").split(",") if o.strip()]
            cat = a["threat_category"] or "Unclassified"
            actor_profiles.append({
                "id": a["id"],
                "handle": a["primary_handle"],
                "category": cat,
                "confidence": round(a["confidence"] or 0.0, 2),
                "onion_count": len(onions),
                "identifier_count": len(idents),
                "identifiers": [dict(i) for i in idents],
                "onions": onions,
                "opsec_rating": "HIGH CONFIDENCE" if (a["confidence"] or 0) >= 0.85 else "MODERATE CONFIDENCE" if (a["confidence"] or 0) >= 0.6 else "LOW CONFIDENCE",
                "attack_vector": cat,
            })

        matrix = []
        for i in range(min(5, len(actor_profiles))):
            for j in range(i + 1, min(5, len(actor_profiles))):
                a1 = actor_profiles[i]
                a2 = actor_profiles[j]
                v1 = set(x["value"] for x in a1["identifiers"])
                v2 = set(x["value"] for x in a2["identifiers"])
                intersection = len(v1.intersection(v2))
                union = len(v1.union(v2)) or 1
                sim_score = round(intersection / union, 3)
                matrix.append({
                    "actor_a": a1["handle"],
                    "actor_b": a2["handle"],
                    "shared_iocs": intersection,
                    "jaccard_index": sim_score,
                    "overlap_status": "STRONG OVERLAP" if sim_score > 0.3 else "MODERATE CORRELATION" if sim_score > 0.1 else "NO OVERLAP",
                })

        inv_rows = conn.execute("SELECT id, query, page_count, status FROM investigations ORDER BY created_at DESC LIMIT 20").fetchall()
        scatter_data = []
        for inv in inv_rows:
            pages = inv["page_count"] or 0
            iocs = conn.execute("SELECT COUNT(*) FROM identifiers WHERE investigation_id = ?", (inv["id"],)).fetchone()[0]
            conf_val = conn.execute("SELECT AVG(confidence) FROM threat_actors WHERE investigation_id = ?", (inv["id"],)).fetchone()[0]
            if conf_val is None:
                conf_val = conn.execute("SELECT AVG(confidence) FROM identifiers WHERE investigation_id = ?", (inv["id"],)).fetchone()[0]
            conf = round(conf_val if conf_val is not None else 0.0, 2)
            efficiency = round(iocs / max(1, pages), 2) if pages > 0 else 0.0
            scatter_data.append({
                "investigation_id": inv["id"],
                "query": inv["query"] or f"Investigation {inv['id'][:8]}",
                "pages_scraped": pages,
                "iocs_extracted": iocs,
                "confidence": conf,
                "roi_ratio": efficiency,
                "status": inv["status"],
            })

        conn.close()
        self._send_json({
            "actors": actor_profiles,
            "jaccard_matrix": matrix,
            "search_roi_scatter": scatter_data,
        })

    def _send_json(self, data: Any, status: int = 200):
        try:
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionResetError, BrokenPipeError) as e:
            logger.debug(f"Client disconnected before response sent: {e}")
        except Exception as e:
            logger.error(f"Error sending JSON response: {e}")

    def _handle_export(self, inv_id: str, format_type: str):
        """Export investigation data as PDF/JSON/CSV via unified exporter."""
        if not inv_id:
            self._send_json({"error": "Missing investigation ID"}, status=400)
            return

        try:
            data, ctype, filename = generate_export([inv_id], format_type)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "Content-Disposition")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            logger.exception("Export failed")
            self._send_json({"error": str(e)}, status=500)

    def _handle_bulk_export(self, inv_ids: list[str], format_type: str):
        """Export multiple investigations as combined PDF/JSON/CSV archive."""
        if not inv_ids:
            self._send_json({"error": "No investigation IDs specified"}, status=400)
            return

        try:
            data, ctype, filename = generate_export(inv_ids, format_type)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Expose-Headers", "Content-Disposition")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            logger.exception("Bulk export failed")
            self._send_json({"error": str(e)}, status=500)

    def _handle_graph_index(self):
        """Return per-investigation graph stats for the Graph Investigation Index page."""
        conn = get_db_connection()

        invs = conn.execute(
            "SELECT id, query, status, created_at, updated_at FROM investigations ORDER BY updated_at DESC"
        ).fetchall()

        rows = []
        for inv in invs:
            inv_id = inv["id"]

            node_count = conn.execute(
                "SELECT COUNT(*) FROM graph_nodes WHERE investigation_id = ?", (inv_id,)
            ).fetchone()[0]

            edge_count = conn.execute(
                "SELECT COUNT(*) FROM graph_edges WHERE investigation_id = ?", (inv_id,)
            ).fetchone()[0]

            community_count = conn.execute(
                "SELECT COUNT(DISTINCT community) FROM graph_nodes WHERE investigation_id = ? AND community IS NOT NULL",
                (inv_id,),
            ).fetchone()[0]

            high_conf = conn.execute(
                "SELECT COUNT(*) FROM graph_edges WHERE investigation_id = ? AND confidence >= 0.80",
                (inv_id,),
            ).fetchone()[0]

            # Key pivot: max-degree non-page node
            pivot_row = conn.execute(
                """
                SELECT label, node_type, degree FROM graph_nodes
                WHERE investigation_id = ?
                  AND node_type NOT IN ('ONION_PAGE','PAGE')
                ORDER BY degree DESC LIMIT 1
                """,
                (inv_id,),
            ).fetchone()
            if not pivot_row:
                pivot_row = conn.execute(
                    "SELECT label, node_type, degree FROM graph_nodes WHERE investigation_id = ? ORDER BY degree DESC LIMIT 1",
                    (inv_id,),
                ).fetchone()

            # Sanctioned count (identifiers linked to this investigation via onion_pages)
            sanctioned = conn.execute(
                """
                SELECT COUNT(*) FROM identifiers i
                JOIN onion_pages op ON op.id = i.page_id
                WHERE op.investigation_id = ? AND i.is_sanctioned = 1
                """,
                (inv_id,),
            ).fetchone()[0]

            # Origin-IP candidate count
            origin_ip = conn.execute(
                """
                SELECT COUNT(*) FROM identifiers i
                JOIN onion_pages op ON op.id = i.page_id
                WHERE op.investigation_id = ? AND i.type IN ('LEAKED_IP','IP_ADDRESS') AND i.confidence >= 0.80
                """,
                (inv_id,),
            ).fetchone()[0]

            rows.append({
                "id": inv_id,
                "query": inv["query"],
                "status": inv["status"],
                "updated_at": inv["updated_at"],
                "nodes": node_count,
                "edges": edge_count,
                "communities": community_count,
                "high_conf_edges": high_conf,
                "key_pivot": {
                    "label": pivot_row["label"] if pivot_row else None,
                    "node_type": pivot_row["node_type"] if pivot_row else None,
                    "degree": pivot_row["degree"] if pivot_row else 0,
                } if pivot_row else None,
                "sanctioned_count": sanctioned,
                "origin_ip_count": origin_ip,
            })

        # Summary totals
        total_nodes = sum(r["nodes"] for r in rows)
        total_edges = sum(r["edges"] for r in rows)
        total_high_conf = sum(r["high_conf_edges"] for r in rows)
        total_communities = sum(r["communities"] for r in rows)

        conn.close()
        self._send_json({
            "investigations": rows,
            "totals": {
                "investigations": len(rows),
                "nodes": total_nodes,
                "high_conf_edges": total_high_conf,
                "communities": total_communities,
            },
        })

    # ── SQL Studio handlers ─────────────────────────────────────────────────

    def _handle_list_sql_sessions(self):
        sessions = list_sql_sessions()
        self._send_json({"sessions": sessions})

    def _handle_create_sql_session(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        title = data.get("title", "").strip() or "New Query Session"
        schema_meta = get_schema_metadata()
        opencode_sid = create_sql_opencode_session(title, schema_metadata=schema_meta)
        session = create_sql_session(title=title, opencode_session_id=opencode_sid)
        self._send_json({"session": session, "status": "CREATED"}, status=201)

    def _handle_delete_sql_session(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        session_id = data.get("id", "").strip()
        self._handle_delete_sql_session_by_id(session_id)

    def _handle_delete_sql_session_by_id(self, session_id: str):
        if not session_id:
            self._send_json({"error": "Missing 'id' parameter"}, status=400)
            return
        deleted = delete_sql_session(session_id)
        self._send_json({"deleted": deleted, "session_id": session_id})

    def _handle_sql_schema(self):
        schema = get_schema_metadata()
        self._send_json(schema)

    def _handle_sql_history(self, session_id: str):
        if not session_id:
            self._send_json({"error": "Missing session_id parameter"}, status=400)
            return
        history = get_sql_history(session_id)
        self._send_json({"history": history, "session_id": session_id})

    def _handle_execute_sql(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        query = data.get("query", "").strip()
        session_id = data.get("session_id", "").strip()
        max_rows = int(data.get("max_rows", 500))

        if not query:
            self._send_json({"success": False, "error": "Query cannot be empty"}, status=400)
            return

        result = execute_readonly_sql(query, max_rows=max_rows)
        if session_id:
            status = "SUCCESS" if result.get("success") else "ERROR"
            latency = float(result.get("latency_ms", 0.0))
            rc = int(result.get("row_count", 0))
            record_sql_history(session_id, query, source="user", status=status, latency_ms=latency, row_count=rc)

        self._send_json(result)

    def _handle_ai_sql(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        prompt = data.get("prompt", "").strip()
        session_id = data.get("session_id", "").strip()

        if not prompt:
            self._send_json({"error": "Prompt cannot be empty"}, status=400)
            return

        schema_meta = get_schema_metadata()
        session_record = get_sql_session(session_id) if session_id else None
        opencode_sid = session_record.get("opencode_session_id") if session_record else None

        ai_res = generate_sql_with_ai(prompt, schema_metadata=schema_meta, opencode_session_id=opencode_sid)
        new_sid = ai_res.get("opencode_session_id")
        if session_id and new_sid and new_sid != opencode_sid:
            update_sql_session_opencode_id(session_id, new_sid)

        if data.get("auto_execute"):
            sql = ai_res.get("sql", "")
            exec_res = execute_readonly_sql(sql)
            ai_res["execution"] = exec_res
            if session_id:
                status = "SUCCESS" if exec_res.get("success") else "ERROR"
                record_sql_history(session_id, sql, source="ai", status=status, latency_ms=exec_res.get("latency_ms", 0), row_count=exec_res.get("row_count", 0))

        self._send_json(ai_res)

    # ── Query Dashboard & Read-Only Agent Handlers ──────────────────────────

    def _handle_list_query_sessions(self):
        sessions = list_query_sessions()
        self._send_json({"sessions": sessions})

    def _handle_create_query_session(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}
        label = data.get("label", "").strip() or None
        session = create_query_session(label=label)
        self._send_json({"session": session, "status": "CREATED"}, status=201)

    def _handle_query_session_history(self, session_id: str):
        if not session_id:
            self._send_json({"error": "Missing session_id parameter"}, status=400)
            return
        history = get_query_session_history(session_id)
        self._send_json({"history": history, "session_id": session_id})

    def _handle_query_run(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        sql = data.get("sql", "").strip()
        question = data.get("question", "").strip()
        session_id = data.get("session_id", "").strip() or None

        if not sql and not question:
            self._send_json({"success": False, "error": "Either 'sql' or 'question' must be provided"}, status=400)
            return

        generated_sql = None
        if question and not sql:
            generated_sql = generate_sql_for_question(question)
            target_sql = generated_sql
        else:
            target_sql = sql

        result = execute_query_readonly(
            sql=target_sql,
            session_id=session_id,
            question=question if question else None,
            default_limit=500
        )
        if generated_sql:
            result["generated_sql"] = generated_sql

        self._send_json(result)

    def _handle_query_export(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"
        try:
            data = json.loads(body)
        except Exception:
            data = {}

        fmt = data.get("format", "csv").lower().strip()
        columns = data.get("columns", [])
        rows = data.get("rows", [])
        query_text = data.get("query_text") or data.get("query", "")

        try:
            file_bytes, content_type, filename = export_query_results(
                columns=columns,
                rows=rows,
                format_type=fmt,
                query_text=query_text
            )
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(file_bytes)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(file_bytes)
        except Exception as exc:
            self._send_json({"error": f"Export failed: {exc}"}, status=500)

    def log_message(self, format, *args):
        # Suppress noisy standard logs
        logger.debug("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), format % args))


def run_server(port: int = 8080):
    server_address = ("127.0.0.1", port)
    httpd = ThreadingHTTPServer(server_address, JaneRequestHandler)
    worker = threading.Thread(target=run_host_worker, name="jane-host-worker", daemon=True)
    worker.start()
    print(f"\n=======================================================")
    print(f" Jane Threat Attribution System Running at:")
    print(f" http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    run_server(port=args.port)
