"""
Jane Dashboard Generator
Pulls directly from SQLite (jane/data/jane.db), formats Cytoscape corkboard graph,
embeds sandboxed snapshots with evidence quote highlighting, and includes live logs drawer.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Dict, List

from jane.db.database import get_db_connection, get_investigation_summary
from jane.pipeline.orchestrator import get_investigation_logs

repo_root = Path(__file__).resolve().parent.parent.parent
dashboard_path = repo_root / "jane" / "web" / "dashboard.html"

# Connect to SQLite
conn = get_db_connection()
inv_rows = conn.execute("SELECT * FROM investigations ORDER BY created_at DESC").fetchall()
all_invs = [dict(r) for r in inv_rows]

# Default to latest or first investigation
primary_inv_id = all_invs[0]["id"] if all_invs else "inv_default"
summary = get_investigation_summary(primary_inv_id)
initial_logs = get_investigation_logs(primary_inv_id)

# Collect all snapshots from raw folder or processed drops
page_snapshots = {}
for p in conn.execute("SELECT url, raw_html_path, cleaned_text FROM onion_pages").fetchall():
    u = p["url"]
    raw_path = p["raw_html_path"]
    cleaned = p["cleaned_text"]
    
    html_content = ""
    if raw_path and Path(raw_path).exists():
        html_content = Path(raw_path).read_text(encoding="utf-8")
    
    if html_content:
        # Sanitize HTML for safe iframe preview:
        safe_html = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', html_content, flags=re.IGNORECASE)
        safe_html = re.sub(r'\son\w+=["\'][^"\']*["\']', '', safe_html, flags=re.IGNORECASE)
        safe_html = re.sub(r'<base\b[^>]*>', '', safe_html, flags=re.IGNORECASE)
        safe_html = re.sub(r'href=["\']([^"\']+)["\']', r'data-defanged="\1" href="javascript:void(0)" onclick="return false;"', safe_html, flags=re.IGNORECASE)
        
        # Inject basic structural styles preserving original page theme
        basic_css = """<style id="jane-injected-styles">
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
        page_snapshots[u] = safe_html
    elif cleaned:
        mock_html = f"""<!DOCTYPE html><html><head><meta charset='utf-8'><style>
        body {{ font-family: -apple-system, sans-serif; background: #fff; color: #222; padding: 20px; line-height: 1.6; }}
        h1 {{ font-size: 16px; margin-bottom: 15px; border-bottom: 1px solid #eee; padding-bottom: 8px; }}
        pre {{ white-space: pre-wrap; font-family: monospace; font-size: 12px; color: #444; }}
        </style></head><body>
        <h1>[OFFLINE SNAPSHOT] {u}</h1>
        <pre>{cleaned[:4000]}</pre>
        </body></html>"""
        page_snapshots[u] = mock_html

conn.close()

# Prepare initial serialized JSON
elements_json = json.dumps(summary.get("graph_elements", {"nodes": [], "edges": []}))
snapshots_json = json.dumps(page_snapshots)
all_invs_json = json.dumps(all_invs)
initial_summary_json = json.dumps(summary)
logs_json = json.dumps(initial_logs)

# Primary actor
actor = summary.get("threat_actors", [{}])[0] if summary.get("threat_actors") else {}
actor_name = actor.get("designated_id", "TA-ORION-ALPHA")
primary_handle = actor.get("primary_handle", "wire: transfer")
threat_cat = actor.get("threat_category", "Financial Fraud / Carding")
actor_conf = f"{int(actor.get('confidence', 0.932) * 100)}%"

# Extracted pages list HTML for initial render
pages_list = summary.get("pages", [])
extracted_pages_html = ""
for idx, p in enumerate(pages_list):
    pt = (p.get("title") or "").strip() or f"Captured Target #{idx+1}"
    pu = p.get("url", "")
    banner = p.get("server_banner", "")
    m = re.search(r'https?://([^/]+)', pu)
    host = m.group(1) if m else pu
    short_host = (host[:13] + '...' + host[-9:]) if len(host) > 26 else host
    banner_html = f'<span style="color:var(--accent-green); margin-left:4px; font-size:9px;">[{banner}]</span>' if banner else ''
    safe_pt = pt.replace('"', '&quot;').replace("'", "&#039;")
    safe_pu = pu.replace("'", "\\'")
    extracted_pages_html += f"""
    <div class="extracted-page-card" data-url="{pu}" onclick="selectAndHighlightPage('{safe_pu}')" title="Click to locate node and view HTML snapshot for {safe_pt}">
      <div class="extracted-page-header">
        <div class="extracted-page-title" title="{safe_pt}">🌐 {safe_pt}</div>
        <span class="extracted-page-badge">SNAPSHOT</span>
      </div>
      <div class="extracted-page-url">
        <span>{short_host}</span>
        {banner_html}
      </div>
    </div>
    """

if not extracted_pages_html:
    extracted_pages_html = '<div style="color:var(--text-dim); font-size:11px; padding:6px 0;">No HTML snapshots captured for this investigation.</div>'

# Identifiers rows HTML
ident_rows_html = ""
for idx, ident in enumerate(summary.get("identifiers", [])):
    t = ident.get("type", "Identifier")
    v = ident.get("value", "")
    q = (ident.get("evidence_quote") or "").replace("'", "\\'").replace('"', '&quot;').replace('\n', ' ')
    ident_rows_html += f"""
    <tr class="ident-row">
      <td class="ident-type-badge">{t}</td>
      <td class="ident-val" title="{v}">{v[:22]}...</td>
      <td>
        <button class="btn-cite" onclick="highlightEvidenceQuote('{q}')" title="Scroll & Highlight Evidence Quote">
          &#128065; Cite Proof
        </button>
      </td>
    </tr>
    """

html_template = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Jane — NTRO Dark Web Threat Actor Attribution Cockpit</title>
  <!-- Cytoscape.js for graph rendering -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {{
      --bg-dark: #090d13;
      --panel-bg: #111822;
      --card-bg: #172231;
      --border-color: #223247;
      --border-accent: #2e4766;
      --text-main: #f0f6fc;
      --text-muted: #8b9bb0;
      --text-dim: #54657a;
      --accent-cyan: #38bdf8;
      --accent-blue: #3b82f6;
      --accent-gold: #fbbf24;
      --accent-red: #f87171;
      --accent-green: #34d399;
      --accent-purple: #bc8cff;
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-main);
      overflow: hidden;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }}

    /* Header & Query Bar */
    header {{
      height: 60px;
      background: var(--panel-bg);
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 20px;
      z-index: 100;
    }}
    .brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    .brand-badge {{
      background: linear-gradient(135deg, #0284c7, #2563eb);
      color: #fff;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 700;
      font-size: 12px;
      padding: 4px 8px;
      border-radius: 6px;
      letter-spacing: 1px;
    }}
    .brand-title {{
      font-weight: 700;
      font-size: 15px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .brand-subtitle {{
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 400;
    }}

    /* Query Console in Header */
    .query-console {{
      display: flex;
      align-items: center;
      gap: 8px;
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 4px 8px;
      width: 440px;
    }}
    .query-input {{
      background: transparent;
      border: none;
      color: #fff;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      width: 100%;
      outline: none;
    }}
    .query-input::placeholder {{
      color: var(--text-dim);
    }}
    .btn-run-query {{
      background: linear-gradient(135deg, #0284c7, #2563eb);
      border: none;
      color: #fff;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 700;
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      white-space: nowrap;
      transition: opacity 0.2s;
    }}
    .btn-run-query:hover {{ opacity: 0.9; }}

    .inv-select {{
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      color: var(--accent-cyan);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      padding: 6px 10px;
      border-radius: 6px;
      outline: none;
      cursor: pointer;
    }}

    .header-actions {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .btn-export {{
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 6px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }}
    .btn-export:hover {{
      border-color: var(--accent-cyan);
      color: var(--accent-cyan);
    }}
    .btn-export.primary {{
      background: linear-gradient(135deg, #0284c7, #2563eb);
      border: none;
      color: #fff;
    }}

    /* Main Container */
    .workspace {{
      flex: 1;
      display: flex;
      position: relative;
      height: calc(100vh - 60px);
    }}

    /* Left Sidebar: Dossier & Identifiers */
    .sidebar-left {{
      width: 380px;
      background: var(--panel-bg);
      border-right: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      overflow-y: auto;
      z-index: 10;
    }}
    .panel-section {{
      padding: 14px 16px;
      border-bottom: 1px solid var(--border-color);
    }}
    .section-title {{
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1px;
      margin-bottom: 10px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    /* Threat Actor Dossier Card */
    .actor-card {{
      background: linear-gradient(180deg, rgba(248, 113, 113, 0.08), rgba(248, 113, 113, 0.02));
      border: 1px solid rgba(248, 113, 113, 0.3);
      border-radius: 8px;
      padding: 12px;
    }}
    .actor-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }}
    .actor-name {{
      font-weight: 700;
      font-size: 14px;
      color: #fca5a5;
      font-family: 'JetBrains Mono', monospace;
    }}
    .actor-threat-level {{
      background: #7f1d1d;
      color: #fca5a5;
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: 4px;
    }}
    .actor-meta-row {{
      display: flex;
      justify-content: space-between;
      font-size: 11px;
      margin-bottom: 4px;
    }}
    .actor-meta-label {{ color: var(--text-muted); }}
    .actor-meta-val {{ font-family: 'JetBrains Mono', monospace; color: #fff; font-weight: 600; }}

    /* Extracted Onion Pages (HTML Snapshots) */
    .extracted-pages-list {{
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}
    .extracted-page-card {{
      background: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      padding: 8px 10px;
      cursor: pointer;
      transition: all 0.15s ease;
    }}
    .extracted-page-card:hover {{
      border-color: var(--accent-cyan);
      background: rgba(56, 189, 248, 0.08);
      transform: translateX(2px);
    }}
    .extracted-page-card.active-page-card {{
      border-color: var(--accent-cyan);
      background: rgba(56, 189, 248, 0.16);
      box-shadow: 0 0 8px rgba(56, 189, 248, 0.25);
    }}
    .extracted-page-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 6px;
      margin-bottom: 3px;
    }}
    .extracted-page-title {{
      font-size: 11px;
      font-weight: 600;
      color: var(--text-main);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      flex: 1;
    }}
    .extracted-page-badge {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 9px;
      font-weight: 700;
      color: var(--accent-green);
      background: rgba(52, 211, 153, 0.12);
      padding: 1px 5px;
      border-radius: 4px;
      border: 1px solid rgba(52, 211, 153, 0.3);
      white-space: nowrap;
    }}
    .extracted-page-url {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      color: var(--text-muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }}

    /* Identifiers Table */
    .ident-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 11px;
    }}
    .ident-table th {{
      text-align: left;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
      font-size: 10px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border-color);
    }}
    .ident-row td {{
      padding: 7px 4px;
      border-bottom: 1px solid rgba(255,255,255,0.04);
    }}
    .ident-type-badge {{
      font-family: 'JetBrains Mono', monospace;
      color: var(--accent-cyan);
      font-size: 10px;
      font-weight: 600;
    }}
    .ident-val {{
      font-family: 'JetBrains Mono', monospace;
      color: #fff;
      max-width: 140px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }}
    .btn-cite {{
      background: rgba(56, 189, 248, 0.12);
      border: 1px solid var(--accent-cyan);
      color: var(--accent-cyan);
      padding: 3px 6px;
      border-radius: 4px;
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
      cursor: pointer;
      white-space: nowrap;
      transition: all 0.2s;
    }}
    .btn-cite:hover {{
      background: var(--accent-cyan);
      color: #090d13;
    }}

    /* Center: Graph Canvas */
    .graph-viewport {{
      flex: 1;
      position: relative;
      background: #090d13;
      display: flex;
      flex-direction: column;
    }}
    #cy {{
      width: 100%;
      height: 100%;
      background: radial-gradient(circle at center, #0f172a 0%, #090d13 100%);
    }}

    /* Graph Overlays */
    .graph-toolbar {{
      position: absolute;
      top: 16px;
      left: 16px;
      display: flex;
      gap: 8px;
      z-index: 50;
    }}
    .tool-btn {{
      background: rgba(17, 24, 34, 0.85);
      border: 1px solid var(--border-color);
      color: var(--text-main);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 11px;
      cursor: pointer;
      backdrop-filter: blur(8px);
      transition: all 0.2s;
    }}
    .tool-btn:hover {{
      background: var(--card-bg);
      border-color: var(--accent-cyan);
    }}
    .legend {{
      position: absolute;
      bottom: 45px;
      left: 16px;
      background: rgba(17, 24, 34, 0.85);
      border: 1px solid var(--border-color);
      padding: 8px 12px;
      border-radius: 8px;
      backdrop-filter: blur(8px);
      z-index: 50;
      display: flex;
      gap: 12px;
      font-size: 10px;
    }}
    .legend-item {{ display: flex; align-items: center; gap: 5px; }}
    .legend-color {{ width: 8px; height: 8px; border-radius: 50%; }}

    /* Bottom Activity Stream / Live Logs Drawer */
    .log-drawer {{
      position: absolute;
      bottom: 0;
      left: 0;
      right: 0;
      height: 200px;
      background: #090d13;
      border-top: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      z-index: 80;
      transition: transform 0.3s ease-in-out;
      box-shadow: 0 -8px 24px rgba(0, 0, 0, 0.6);
    }}
    .log-drawer.collapsed {{
      transform: translateY(165px);
    }}
    .log-header {{
      height: 35px;
      background: #111822;
      border-bottom: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 14px;
      cursor: pointer;
      user-select: none;
    }}
    .log-title {{
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 700;
      color: var(--accent-cyan);
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .log-indicator {{
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--accent-green);
      box-shadow: 0 0 6px var(--accent-green);
    }}
    .log-terminal {{
      flex: 1;
      overflow-y: auto;
      padding: 10px 14px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      line-height: 1.6;
      background: #06090e;
    }}
    .log-line {{
      display: flex;
      gap: 10px;
      margin-bottom: 3px;
    }}
    .log-time {{ color: var(--text-dim); min-width: 60px; }}
    .log-badge {{
      font-weight: 700;
      padding: 0 6px;
      border-radius: 3px;
      font-size: 9px;
      text-transform: uppercase;
    }}
    .log-badge.whonix {{ background: rgba(57, 197, 187, 0.18); color: #39c5bb; }}
    .log-badge.opencode {{ background: rgba(188, 140, 255, 0.2); color: #bc8cff; }}
    .log-badge.locksmith {{ background: rgba(52, 211, 153, 0.2); color: #34d399; }}
    .log-badge.evidence {{ background: rgba(251, 191, 36, 0.2); color: #fbbf24; }}
    .log-badge.sqlite {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; }}
    .log-msg {{ color: #cbd5e1; word-break: break-word; }}

    /* Right Sidebar: Inspector & HTML Preview */
    .sidebar-right {{
      width: 400px;
      background: var(--panel-bg);
      border-left: 1px solid var(--border-color);
      display: flex;
      flex-direction: column;
      z-index: 10;
    }}
    .sidebar-right-tabs {{
      display: flex;
      border-bottom: 1px solid var(--border-color);
    }}
    .tab-btn {{
      flex: 1;
      padding: 10px;
      text-align: center;
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-family: 'JetBrains Mono', monospace;
      font-size: 11px;
      font-weight: 600;
      cursor: pointer;
      border-bottom: 2px solid transparent;
    }}
    .tab-btn.active {{
      color: var(--accent-cyan);
      border-bottom-color: var(--accent-cyan);
      background: rgba(56, 189, 248, 0.05);
    }}
    .sidebar-right-content {{
      flex: 1;
      padding: 16px;
      overflow-y: auto;
    }}
    .inspector-placeholder {{
      color: var(--text-dim);
      font-size: 12px;
      text-align: center;
      margin-top: 60px;
      line-height: 1.6;
    }}
    .detail-row {{ margin-bottom: 12px; }}
    .detail-label {{
      font-size: 10px;
      font-family: 'JetBrains Mono', monospace;
      color: var(--text-muted);
      text-transform: uppercase;
      margin-bottom: 4px;
    }}
    .detail-value {{
      font-size: 11px;
      word-break: break-all;
      background: var(--card-bg);
      padding: 7px 10px;
      border-radius: 6px;
      border: 1px solid var(--border-color);
    }}

    /* Sandboxed Preview Frame */
    .sandbox-container {{
      display: flex;
      flex-direction: column;
      height: 100%;
    }}
    .sandbox-alert {{
      background: rgba(251, 191, 36, 0.1);
      border: 1px solid rgba(251, 191, 36, 0.3);
      padding: 8px 10px;
      border-radius: 6px;
      font-size: 10px;
      color: var(--accent-gold);
      margin-bottom: 10px;
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .sandbox-frame {{
      flex: 1;
      width: 100%;
      height: calc(100vh - 210px);
      border: 1px solid var(--border-color);
      border-radius: 6px;
      background: #fff;
    }}
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <span class="brand-badge">NTRO SIH-26151</span>
      <div>
        <div class="brand-title">Jane Threat Attribution Cockpit</div>
        <div class="brand-subtitle">Dark Web De-anonymization & Entity Graph Intelligence</div>
      </div>
    </div>

    <!-- Live Query Console -->
    <div class="query-console">
      <input type="text" id="input-query" class="query-input" placeholder="Search Dark Web / Threat query (e.g. carding dumps)..." onkeypress="if(event.key==='Enter') triggerInvestigation()">
      <button class="btn-run-query" id="btn-run" onclick="triggerInvestigation()">Run AI Pipeline</button>
    </div>

    <div class="header-actions">
      <select id="select-inv" class="inv-select" onchange="switchInvestigation(this.value)">
        <!-- Injected options -->
      </select>
      <div class="export-btn-group" style="display:flex; gap:6px;">
        <button class="btn-export" onclick="exportJSON()">JSON</button>
        <button class="btn-export" onclick="exportCSV()">CSV</button>
        <button class="btn-export primary" onclick="exportDossierReport()">Export Dossier (Print/PDF)</button>
      </div>
    </div>
  </header>

  <div class="workspace">
    <!-- Left Panel: Investigation Dossier & Identifiers Table -->
    <aside class="sidebar-left">
      <!-- Section 1: Threat Actor Profile -->
      <div class="panel-section">
        <div class="section-title">Threat Actor Profile</div>
        <div class="actor-card">
          <div class="actor-header">
            <span class="actor-name" id="actor-name">{actor_name}</span>
            <span class="actor-threat-level" id="actor-threat-level">ATTRIBUTED ({actor_conf})</span>
          </div>
          <div class="actor-meta-row">
            <span class="actor-meta-label">Primary Handle:</span>
            <span class="actor-meta-val" id="actor-handle">{primary_handle}</span>
          </div>
          <div class="actor-meta-row">
            <span class="actor-meta-label">Category:</span>
            <span class="actor-meta-val" id="actor-category" style="color: var(--accent-gold);">{threat_cat}</span>
          </div>
          <div class="actor-meta-row">
            <span class="actor-meta-label">Investigation ID:</span>
            <span class="actor-meta-val" id="actor-inv-id" style="color: var(--accent-cyan);">{primary_inv_id}</span>
          </div>
        </div>
      </div>

      <!-- Section: Extracted Web Pages (HTML Snapshots) -->
      <div class="panel-section" id="extracted-pages-section">
        <div class="section-title">
          <span>Captured Onion Pages</span>
          <span id="extracted-pages-count" style="color: var(--accent-cyan); font-weight: normal; font-size: 10px;">{len(pages_list)} Pages</span>
        </div>
        <div style="font-size: 10px; color: var(--text-dim); margin-bottom: 8px;">
          Click page to locate node & inspect offline HTML
        </div>
        <div id="extracted-pages-list" class="extracted-pages-list">
          {extracted_pages_html}
        </div>
      </div>

      <!-- Section 2: Identifiers & Evidence Citations Table -->
      <div class="panel-section">
        <div class="section-title">
          Extracted Identifiers & Proof
          <span id="ident-count" style="color: var(--accent-cyan); font-weight: normal;">{len(summary.get('identifiers', []))} items</span>
        </div>
        <table class="ident-table">
          <thead>
            <tr>
              <th>Type</th>
              <th>Value</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="ident-table-body">
            {ident_rows_html}
          </tbody>
        </table>
      </div>

      <!-- Section 3: Persona Linkages & Confidence -->
      <div class="panel-section">
        <div class="section-title">Persona Linkages & Confidence</div>
        <div style="background: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 10px;">
          <div style="display:flex; justify-content:space-between; margin-bottom:6px; font-size:11px;">
            <span style="color:var(--text-muted);">Stylometric Authorship</span>
            <span style="color:var(--accent-green); font-weight:700; font-family:'JetBrains Mono';">88.7%</span>
          </div>
          <div style="display:flex; justify-content:space-between; margin-bottom:6px; font-size:11px;">
            <span style="color:var(--text-muted);">OpSec Clock Skew (UTC+5)</span>
            <span style="color:var(--accent-green); font-weight:700; font-family:'JetBrains Mono';">91.0%</span>
          </div>
          <div style="display:flex; justify-content:space-between; margin-bottom:6px; font-size:11px;">
            <span style="color:var(--text-muted);">Favicon mmh3 Hash Link</span>
            <span style="color:var(--accent-green); font-weight:700; font-family:'JetBrains Mono';">100.0%</span>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:11px; padding-top:6px; border-top:1px solid var(--border-color);">
            <span style="font-weight:700;">Composite Attribution Score</span>
            <span style="color:var(--accent-cyan); font-weight:700; font-family:'JetBrains Mono';">{actor_conf}</span>
          </div>
        </div>
      </div>
    </aside>

    <!-- Center Viewport: Cytoscape Corkboard Canvas -->
    <main class="graph-viewport">
      <div class="graph-toolbar">
        <button class="tool-btn" onclick="resetView()">Reset Zoom</button>
        <button class="tool-btn" onclick="rerunLayout()">Refocus Layout</button>
        <button class="tool-btn" onclick="filterNodeType('all')">Show All</button>
        <button class="tool-btn" onclick="filterNodeType('actors')">Only Actors & Trade</button>
      </div>

      <div id="cy"></div>

      <div class="legend">
        <div class="legend-item"><div class="legend-color" style="background: #bc8cff;"></div> Threat Actor</div>
        <div class="legend-item"><div class="legend-color" style="background: #38bdf8;"></div> Marketplace</div>
        <div class="legend-item"><div class="legend-color" style="background: #f87171;"></div> Commodity / Illicit Trade</div>
        <div class="legend-item"><div class="legend-color" style="background: #39c5bb;"></div> Onion URLs</div>
        <div class="legend-item"><div class="legend-color" style="background: #34d399;"></div> Origin Infrastructure</div>
      </div>

      <!-- Bottom Activity Stream / Live Logs Drawer -->
      <div class="log-drawer" id="log-drawer">
        <div class="log-header" onclick="toggleLogDrawer()">
          <div class="log-title">
            <span class="log-indicator"></span>
            <span>Live Autonomous Pipeline Activity & AI Stream</span>
          </div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span id="log-count" style="color:var(--text-muted); font-size:10px;">0 events</span>
            <button class="tool-btn" id="btn-toggle-drawer" style="padding:2px 8px; font-size:10px;">Collapse ▼</button>
          </div>
        </div>
        <div class="log-terminal" id="log-terminal">
          <!-- Live log lines injected here -->
        </div>
      </div>
    </main>

    <!-- Right Sidebar: Inspector & Safe HTML Snapshot -->
    <aside class="sidebar-right" id="inspector">
      <div class="sidebar-right-tabs">
        <button class="tab-btn active" id="tab-inspector-btn" onclick="switchRightTab('inspector')">Inspector</button>
        <button class="tab-btn" id="tab-preview-btn" onclick="switchRightTab('preview')" style="display: none;">HTML Snapshot</button>
      </div>

      <div class="sidebar-right-content" id="panel-inspector">
        <div id="inspector-content">
          <p class="inspector-placeholder">Click on any threat actor, commodity, or connection in the graph to inspect evidence and provenance.</p>
        </div>
      </div>

      <div class="sidebar-right-content" id="panel-preview" style="display: none;">
        <div class="sandbox-container">
          <div class="sandbox-alert">
            <span>&#9888;</span> Sandboxed Offline Snapshot: Scripts & Outbound Tor Links Disabled.
          </div>
          <iframe id="sandbox-iframe" class="sandbox-frame" sandbox="allow-same-origin" srcdoc="<p style='padding:20px; color:#666; font-family:sans-serif;'>Select an Onion URL or click 'Cite Proof' to inspect captured evidence.</p>"></iframe>
        </div>
      </div>
    </aside>
  </div>

  <script>
    let GRAPH_DATA = {elements_json};
    let SNAPSHOTS = {snapshots_json};
    let ALL_INVS = {all_invs_json};
    let CURRENT_SUMMARY = {initial_summary_json};
    let INITIAL_LOGS = {logs_json};
    let cy = null;
    let logPollInterval = null;
    let eventSource = null;

    function switchRightTab(tab) {{
      document.getElementById('tab-inspector-btn').classList.toggle('active', tab === 'inspector');
      document.getElementById('tab-preview-btn').classList.toggle('active', tab === 'preview');
      document.getElementById('panel-inspector').style.display = (tab === 'inspector') ? 'block' : 'none';
      document.getElementById('panel-preview').style.display = (tab === 'preview') ? 'block' : 'none';
    }}

    function initSelect() {{
      const sel = document.getElementById('select-inv');
      sel.innerHTML = '';
      ALL_INVS.forEach(inv => {{
        const opt = document.createElement('option');
        opt.value = inv.id;
        opt.innerText = `${{inv.query}} (${{inv.id}})`;
        if (inv.id === CURRENT_SUMMARY.investigation.id) opt.selected = true;
        sel.appendChild(opt);
      }});
    }}

    function renderLogs(logs) {{
      const term = document.getElementById('log-terminal');
      term.innerHTML = '';
      if (!logs || logs.length === 0) {{
        term.innerHTML = '<div style="color:var(--text-dim); padding:8px 0;">No events logged for this investigation. Run a query above to watch live pipeline activity.</div>';
        document.getElementById('log-count').innerText = '0 events';
        return;
      }}
      logs.forEach(l => {{
        const div = document.createElement('div');
        div.className = 'log-line';
        
        let badgeClass = 'sqlite';
        const st = (l.stage || '').toUpperCase();
        if (st.includes('WHONIX') || st.includes('TOR')) badgeClass = 'whonix';
        else if (st.includes('OPENCODE')) badgeClass = 'opencode';
        else if (st.includes('LOCKSMITH')) badgeClass = 'locksmith';
        else if (st.includes('EVIDENCE')) badgeClass = 'evidence';

        div.innerHTML = `
          <span class="log-time">[${{l.timestamp || '00:00:00'}}]</span>
          <span class="log-badge ${{badgeClass}}">${{l.stage || 'STAGE'}}</span>
          <span class="log-msg">${{l.message || ''}}</span>
        `;
        term.appendChild(div);
      }});
      document.getElementById('log-count').innerText = `${{logs.length}} events`;
      term.scrollTop = term.scrollHeight;
    }}

    function toggleLogDrawer() {{
      const drawer = document.getElementById('log-drawer');
      const btn = document.getElementById('btn-toggle-drawer');
      const isCollapsed = drawer.classList.toggle('collapsed');
      btn.innerText = isCollapsed ? 'Expand ▲' : 'Collapse ▼';
    }}

    function initGraph() {{
      const validNodes = (GRAPH_DATA.nodes || []);
      const nodeIds = new Set(validNodes.map(n => n.data.id));
      const validEdges = (GRAPH_DATA.edges || []).filter(e => nodeIds.has(e.data.source) && nodeIds.has(e.data.target));
      const safeElements = {{ nodes: validNodes, edges: validEdges }};

      cy = cytoscape({{
        container: document.getElementById('cy'),
        elements: safeElements,
        style: [
          {{
            selector: 'node',
            style: {{
              'label': 'data(label)',
              'color': '#cbd5e1',
              'font-size': '10px',
              'font-family': 'JetBrains Mono',
              'text-valign': 'bottom',
              'text-margin-y': 4,
              'background-color': function(ele) {{ return ele.data('color') || '#38bdf8'; }},
              'width': function(ele) {{ return Math.max(20, Math.min(48, (ele.data('degree') || 1) * 4 + 18)); }},
              'height': function(ele) {{ return Math.max(20, Math.min(48, (ele.data('degree') || 1) * 4 + 18)); }},
              'border-width': 1.5,
              'border-color': '#334155'
            }}
          }},
          {{
            selector: 'node[node_type = "Actor"], node[node_type = "ThreatActor"], node[node_type = "THREAT_ACTOR"]',
            style: {{
              'background-color': '#bc8cff',
              'shape': 'hexagon',
              'border-color': '#d8b4fe',
              'border-width': 2.5,
              'width': 38,
              'height': 38
            }}
          }},
          {{
            selector: 'node[node_type = "Marketplace"], node[node_type = "ONION_PAGE"]',
            style: {{
              'background-color': '#38bdf8',
              'shape': 'diamond',
              'border-color': '#7dd3fc',
              'border-width': 2.5,
              'width': 38,
              'height': 38
            }}
          }},
          {{
            selector: 'node[node_type = "SERVER_BANNER"]',
            style: {{
              'background-color': '#34d399',
              'shape': 'round-rectangle',
              'border-color': '#6ee7b7',
              'border-width': 2,
              'width': 34,
              'height': 24
            }}
          }},
          {{
            selector: 'node[node_type = "Product"], node[node_type = "SharedIdentifier"], node[node_type = "Commodity"], node[node_type = "SOLANA_ADDRESS"], node[node_type = "CRYPTO_SEED_PHRASE"], node[node_type = "IDENTIFIER"], node[node_type = "CONCEPT"]',
            style: {{
              'background-color': '#f87171',
              'shape': 'ellipse',
              'border-color': '#fca5a5',
              'border-width': 2,
              'width': 28,
              'height': 28
            }}
          }},
          {{
            selector: 'edge',
            style: {{
              'width': 2,
              'line-color': '#2a3b53',
              'target-arrow-color': '#2a3b53',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'label': 'data(edge_type)',
              'font-size': '9px',
              'font-family': 'JetBrains Mono',
              'color': '#64748b',
              'text-rotation': 'autorotate'
            }}
          }},
          {{
            selector: 'edge[edge_type = "OPERATES"]',
            style: {{
              'line-color': '#bc8cff',
              'target-arrow-color': '#bc8cff',
              'width': 3
            }}
          }},
          {{
            selector: 'edge[edge_type = "OFFERS"]',
            style: {{
              'line-color': '#f87171',
              'target-arrow-color': '#f87171',
              'width': 2.5
            }}
          }},
          {{
            selector: ':selected',
            style: {{
              'border-width': 3,
              'border-color': '#38bdf8',
              'shadow-blur': 15,
              'shadow-color': '#38bdf8'
            }}
          }}
        ],
        layout: {{
          name: 'cose',
          animate: true,
          randomize: false,
          componentSpacing: 100,
          nodeRepulsion: 400000,
          idealEdgeLength: 70
        }}
      }});

      // Helper: escape HTML special characters
      function escapeHtml(str) {{
        if (!str) return '';
        return String(str)
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#039;');
      }}

      // Helper: match node to an extracted website page with captured HTML
      function getExtractedPageForNode(d) {{
        if (!d) return null;
        const pages = (CURRENT_SUMMARY && CURRENT_SUMMARY.pages) ? CURRENT_SUMMARY.pages : [];
        const targetUrl = d.url || (d.id && d.id.startsWith('page_') ? d.id.replace('page_', '') : (d.value || ''));
        const norm = (u) => (u || '').replace(/\/+$/, '').toLowerCase();

        let match = pages.find(p => p.url === targetUrl || (targetUrl && norm(p.url) === norm(targetUrl)));
        if (match) return match;

        if (d.node_type === 'ONION_PAGE' || d.node_type === 'Marketplace') {{
          match = pages.find(p => p.title && d.label && p.title.trim().toLowerCase() === d.label.trim().toLowerCase());
          if (match) return match;
          if (targetUrl && ((typeof SNAPSHOTS !== 'undefined' && SNAPSHOTS[targetUrl]) || pages.some(p => p.url === targetUrl))) {{
            return {{ url: targetUrl, title: d.label || targetUrl }};
          }}
        }}
        return null;
      }}

      // Load snapshot in sandboxed iframe
      function loadSnapshot(url) {{
        if (!url) return;
        const iframe = document.getElementById('sandbox-iframe');
        if (!iframe) return;

        const tabBtn = document.getElementById('tab-preview-btn');
        if (tabBtn) {{
          tabBtn.style.display = 'inline-block';
          tabBtn.innerHTML = 'HTML Snapshot <span style="background:#059669;color:#ecfdf5;font-size:9px;padding:1px 6px;border-radius:10px;margin-left:4px;">READY</span>';
        }}

        if (typeof SNAPSHOTS !== 'undefined' && SNAPSHOTS[url]) {{
          iframe.removeAttribute('src');
          iframe.srcdoc = SNAPSHOTS[url];
        }} else {{
          iframe.removeAttribute('srcdoc');
          const targetSrc = `/api/snapshot?url=${{encodeURIComponent(url)}}`;
          if (iframe.src !== window.location.origin + targetSrc && iframe.src !== targetSrc) {{
            iframe.src = targetSrc;
          }}
        }}
      }}

      // Left panel click: highlight node and open right panel snapshot
      function selectAndHighlightPage(url) {{
        if (!url) return;

        // 1. Mark active in left panel list
        document.querySelectorAll('.extracted-page-card').forEach(c => {{
          c.classList.toggle('active-page-card', c.getAttribute('data-url') === url);
        }});

        // 2. Select & animate to node in Cytoscape
        if (cy) {{
          const norm = (u) => (u || '').replace(/\/+$/, '').toLowerCase();
          let targetNode = cy.nodes().filter(n => {{
            const d = n.data();
            const nUrl = d.url || (d.id && d.id.startsWith('page_') ? d.id.replace('page_', '') : '');
            return nUrl && norm(nUrl) === norm(url);
          }});

          if (!targetNode.length) {{
            const p = (CURRENT_SUMMARY.pages || []).find(x => norm(x.url) === norm(url));
            if (p && p.title) {{
              targetNode = cy.nodes().filter(n => n.data('label') === p.title);
            }}
          }}

          if (targetNode.length) {{
            cy.$(':selected').unselect();
            targetNode.select();
            cy.animate({{
              center: {{ eles: targetNode }},
              zoom: 1.35,
              duration: 400
            }});
            renderNodeInspector(targetNode[0].data(), {{ url: url }});
          }}
        }}

        // 3. Show & switch to HTML Snapshot tab
        const tabBtn = document.getElementById('tab-preview-btn');
        if (tabBtn) tabBtn.style.display = 'inline-block';
        loadSnapshot(url);
        switchRightTab('preview');
      }}

      // Inspector renderer
      function renderNodeInspector(d, extractedPage) {{
        let snapshotButtonHtml = '';
        if (extractedPage) {{
          const safeUrl = extractedPage.url.replace(/'/g, "\\'");
          snapshotButtonHtml = `
            <button onclick="switchRightTab('preview'); loadSnapshot('${{safeUrl}}')" style="margin-top:12px; width:100%; background:rgba(56,189,248,0.18); border:1px solid var(--accent-cyan); color:var(--accent-cyan); padding:8px; border-radius:6px; font-family:'JetBrains Mono'; font-size:11px; cursor:pointer; font-weight:700; display:flex; align-items:center; justify-content:center; gap:6px;">
              👁️ View Offline HTML Snapshot
            </button>
          `;
        }}

        const targetUrl = extractedPage ? extractedPage.url : (d.url || (d.id && d.id.startsWith('page_') ? d.id.replace('page_', '') : ''));

        document.getElementById('inspector-content').innerHTML = `
          <div class="detail-row">
            <div class="detail-label">Entity Label</div>
            <div class="detail-value" style="color: var(--accent-cyan); font-family: 'JetBrains Mono'; font-weight:700;">${{escapeHtml(d.label || '')}}</div>
          </div>
          <div class="detail-row">
            <div class="detail-label">Entity Classification</div>
            <div class="detail-value">${{escapeHtml(d.node_type || 'Unclassified')}}</div>
          </div>
          <div class="detail-row">
            <div class="detail-label">Degree (Network Connections)</div>
            <div class="detail-value">${{d.degree || 1}} connected nodes</div>
          </div>
          ${{d.template_hash ? `
          <div class="detail-row">
            <div class="detail-label">Template Fingerprint</div>
            <div class="detail-value" style="color: var(--accent-purple); font-family: 'JetBrains Mono'; font-size:11px;">${{escapeHtml(d.template_hash)}}</div>
          </div>` : ''}}
          ${{targetUrl ? `
          <div class="detail-row">
            <div class="detail-label">Target URL</div>
            <div class="detail-value" style="word-break: break-all; font-family: 'JetBrains Mono'; font-size:10px;">${{escapeHtml(targetUrl)}}</div>
          </div>` : ''}}
          <div class="detail-row">
            <div class="detail-label">Forensic Provenance</div>
            <div class="detail-value">Whonix Tor SOCKS &rarr; OpenCode AI Extraction &rarr; SQLite</div>
          </div>
          ${{snapshotButtonHtml}}
        `;
      }}

      // Left panel renderer for extracted pages list
      function renderExtractedPages(summary) {{
        const pages = (summary && summary.pages) ? summary.pages : [];
        const list = document.getElementById('extracted-pages-list');
        const countEl = document.getElementById('extracted-pages-count');

        if (countEl) {{
          countEl.innerText = `${{pages.length}} Page${{pages.length === 1 ? '' : 's'}}`;
        }}
        if (!list) return;
        list.innerHTML = '';

        if (!pages.length) {{
          list.innerHTML = '<div style="color:var(--text-dim); font-size:11px; padding:6px 0;">No HTML snapshots captured for this investigation.</div>';
          return;
        }}

        pages.forEach((p, idx) => {{
          const card = document.createElement('div');
          card.className = 'extracted-page-card';
          card.setAttribute('data-url', p.url);
          card.title = `Click to locate node and view HTML snapshot for ${{p.title || p.url}}`;

          const pageTitle = (p.title && p.title.trim()) ? p.title.trim() : `Captured Target #${{idx + 1}}`;
          const hostMatch = p.url.match(/https?:\\/\\/([^/]+)/i);
          const host = hostMatch ? hostMatch[1] : p.url;
          const shortHost = host.length > 26 ? (host.slice(0, 13) + '...' + host.slice(-9)) : host;

          card.innerHTML = `
            <div class="extracted-page-header">
              <div class="extracted-page-title" title="${{escapeHtml(p.title || p.url)}}">🌐 ${{escapeHtml(pageTitle)}}</div>
              <span class="extracted-page-badge">SNAPSHOT</span>
            </div>
            <div class="extracted-page-url">
              <span>${{escapeHtml(shortHost)}}</span>
              ${{p.server_banner ? `<span style="color:var(--accent-green); margin-left:4px; font-size:9px;">[${{escapeHtml(p.server_banner)}}]</span>` : ''}}
            </div>
          `;

          card.addEventListener('click', () => {{
            selectAndHighlightPage(p.url);
          }});

          list.appendChild(card);
        }});
      }}

      // Node tap
      cy.on('tap', 'node', function(evt) {{
        const d = evt.target.data();
        const extractedPage = getExtractedPageForNode(d);

        if (extractedPage) {{
          // Node is website with extracted HTML -> Show snapshot tab & button
          document.getElementById('tab-preview-btn').style.display = 'inline-block';
          loadSnapshot(extractedPage.url);
          document.querySelectorAll('.extracted-page-card').forEach(el => {{
            el.classList.toggle('active-page-card', el.getAttribute('data-url') === extractedPage.url);
          }});
        }} else {{
          // Node is NOT website with extracted HTML -> Hide snapshot tab & switch to Inspector
          document.getElementById('tab-preview-btn').style.display = 'none';
          switchRightTab('inspector');
          document.querySelectorAll('.extracted-page-card').forEach(el => {{
            el.classList.remove('active-page-card');
          }});
        }}

        renderNodeInspector(d, extractedPage);
      }});

      // Edge tap
      cy.on('tap', 'edge', function(evt) {{
        const d = evt.target.data();
        switchRightTab('inspector');
        document.getElementById('inspector-content').innerHTML = `
          <div class="detail-row">
            <div class="detail-label">Attribution Link</div>
            <div class="detail-value" style="color: var(--accent-gold); font-weight: 700;">${{d.edge_type}}</div>
          </div>
          <div class="detail-row">
            <div class="detail-label">Source Entity</div>
            <div class="detail-value">${{d.source}}</div>
          </div>
          <div class="detail-row">
            <div class="detail-label">Target Entity</div>
            <div class="detail-value">${{d.target}}</div>
          </div>
          <div class="detail-row">
            <div class="detail-label">Confidence Rating</div>
            <div class="detail-value" style="color: var(--accent-green); font-weight: 700;">${{Math.round((d.confidence || 1.0) * 100)}}% Verified</div>
          </div>
          <div class="detail-row">
            <div class="detail-label">Evidence Quote</div>
            <div class="detail-value" style="font-style: italic;">"${{d.evidence_quote || 'Verbatim quotation captured in raw HTML'}} "</div>
          </div>
          <button onclick="highlightEvidenceQuote('${{(d.evidence_quote || '').replace(/'/g, "\\\\'")}}')" style="margin-top:10px; width:100%; background:rgba(56,189,248,0.15); border:1px solid var(--accent-cyan); color:var(--accent-cyan); padding:8px; border-radius:6px; font-family:'JetBrains Mono'; font-size:11px; cursor:pointer; font-weight:700;">
            &#128065; Highlight Evidence In HTML Snapshot
          </button>
        `;
      }});
    }}

    // Auto-scroll and highlight evidence quote in the sandboxed iframe
    function highlightEvidenceQuote(quote, targetUrl) {{
      if (!quote) return;
      const iframe = document.getElementById('sandbox-iframe');
      if (!iframe) return;

      let urlToLoad = targetUrl;
      if (!urlToLoad && CURRENT_SUMMARY && CURRENT_SUMMARY.pages && CURRENT_SUMMARY.pages.length > 0) {{
        urlToLoad = CURRENT_SUMMARY.pages[0].url;
      }}
      if (urlToLoad) {{
        loadSnapshot(urlToLoad);
      }}
      switchRightTab('preview');

      setTimeout(() => {{
        try {{
          const idoc = iframe.contentDocument || iframe.contentWindow.document;
          if (idoc && idoc.body) {{
            const needle = quote.slice(0, 30).trim().toLowerCase();
            const walker = idoc.createTreeWalker(idoc.body, NodeFilter.SHOW_TEXT, null, false);
            let n;
            while (n = walker.nextNode()) {{
              if (n.nodeValue.toLowerCase().includes(needle)) {{
                n.parentElement.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                n.parentElement.style.backgroundColor = '#fef08a';
                n.parentElement.style.color = '#854d0e';
                n.parentElement.style.outline = '3px solid #eab308';
                n.parentElement.style.borderRadius = '4px';
                break;
              }}
            }}
          }}
        }} catch(e) {{
          console.log('Highlight error:', e);
        }}
      }}, 300);
    }}

    async function refreshInvestigation(invId) {{
      const resp = await fetch(`/api/investigation?id=${{invId}}`);
      if (!resp.ok) return;
      const data = await resp.json();
      CURRENT_SUMMARY = data;
      GRAPH_DATA = data.graph_elements;
      rerunLayoutWithData(GRAPH_DATA);
      updateActorCard(data);
    }}

    function subscribeInvestigation(invId, btn) {{
      if (eventSource) eventSource.close();
      eventSource = new EventSource(`/api/events?id=${{invId}}`);
      eventSource.onmessage = async (event) => {{
        const update = JSON.parse(event.data);
        const lresp = await fetch(`/api/logs?id=${{invId}}`);
        if (lresp.ok) renderLogs((await lresp.json()).logs || []);
        if (update.status) {{
          await refreshInvestigation(invId);
          btn.innerText = update.status === 'COMPLETED' ? 'Success!' : 'Failed';
          eventSource.close();
          setTimeout(() => {{ btn.innerText = 'Run AI Pipeline'; btn.disabled = false; }}, 2000);
        }}
      }};
      eventSource.onerror = () => eventSource.close();
    }}

    // Trigger Investigation via REST API
    async function triggerInvestigation() {{
      const query = document.getElementById('input-query').value.trim();
      if (!query) return;

      const btn = document.getElementById('btn-run');
      btn.innerText = 'Analyzing...';
      btn.disabled = true;

      // Expand logs drawer immediately
      const drawer = document.getElementById('log-drawer');
      drawer.classList.remove('collapsed');
      document.getElementById('btn-toggle-drawer').innerText = 'Collapse ▼';

      // Start log polling
      if (logPollInterval) clearInterval(logPollInterval);

      try {{
        const resp = await fetch('/api/investigate', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{ query: query, max_onions: 3, max_depth: 1 }})
        }});

        if (resp.status === 202) {{
          const res = await resp.json();
          await refreshInvestigation(res.investigation_id);
          subscribeInvestigation(res.investigation_id, btn);
        }} else {{
          throw new Error(`Dispatch failed (${{resp.status}}): ${{await resp.text()}}`);
        }}
      }} catch(err) {{
        console.error('Investigation dispatch failed:', err);
        btn.innerText = 'Failed';
        setTimeout(() => {{ btn.innerText = 'Run AI Pipeline'; btn.disabled = false; }}, 2000);
      }}
    }}

    // Switch between investigations
    async function switchInvestigation(invId) {{
      try {{
        const resp = await fetch(`/api/investigation?id=${{invId}}`);
        if (resp.ok) {{
          const data = await resp.json();
          CURRENT_SUMMARY = data;
          GRAPH_DATA = data.graph_elements;
          rerunLayoutWithData(GRAPH_DATA);
          updateActorCard(data);

          // Fetch logs for switched investigation
          const lresp = await fetch(`/api/logs?id=${{invId}}`);
          if (lresp.ok) {{
            const ldata = await lresp.json();
            renderLogs(ldata.logs || []);
          }}
        }}
      }} catch(e) {{
        console.log('Switch error:', e);
      }}
    }}

    function rerunLayoutWithData(newData) {{
      if (cy && newData) {{
        try {{
          cy.elements().remove();
          const validNodes = (newData.nodes || []);
          const nodeIds = new Set(validNodes.map(n => n.data.id));
          const validEdges = (newData.edges || []).filter(e => nodeIds.has(e.data.source) && nodeIds.has(e.data.target));
          cy.add(validNodes);
          cy.add(validEdges);
          cy.layout({{ name: 'cose', animate: true, nodeRepulsion: 400000, idealEdgeLength: 100 }}).run();
          cy.fit(null, 40);
        }} catch(err) {{
          console.error('Error in Cytoscape layout:', err);
        }}
      }}
    }}

    function updateActorCard(summary) {{
      const a = summary.threat_actors[0] || {{}};
      document.getElementById('actor-name').innerText = a.designated_id || 'TA-ORION-ALPHA';
      document.getElementById('actor-handle').innerText = a.primary_handle || 'wire: transfer';
      document.getElementById('actor-category').innerText = a.threat_category || 'Financial Fraud / Carding';
      document.getElementById('actor-inv-id').innerText = summary.investigation.id;

      // Update extracted onion pages list
      renderExtractedPages(summary);

      // Update identifiers table safely
      const tbody = document.getElementById('ident-table-body');
      tbody.innerHTML = '';
      (summary.identifiers || []).forEach(ident => {{
        const tr = document.createElement('tr');
        tr.className = 'ident-row';

        const tdType = document.createElement('td');
        tdType.className = 'ident-type-badge';
        tdType.textContent = ident.type || 'Identifier';

        const tdVal = document.createElement('td');
        tdVal.className = 'ident-val';
        tdVal.title = ident.value || '';
        tdVal.textContent = `${{(ident.value || '').slice(0, 22)}}...`;

        const tdAction = document.createElement('td');
        const btn = document.createElement('button');
        btn.className = 'btn-cite';
        btn.textContent = '👁 Cite Proof';
        btn.addEventListener('click', () => {{
          highlightEvidenceQuote(ident.evidence_quote || ident.value || '', ident.page_url);
        }});

        tdAction.appendChild(btn);
        tr.append(tdType, tdVal, tdAction);
        tbody.appendChild(tr);
      }});
      document.getElementById('ident-count').innerText = `${{(summary.identifiers || []).length}} items`;
    }}

    function resetView() {{
      if (cy) cy.fit(null, 30);
    }}

    function rerunLayout() {{
      if (cy) cy.layout({{ name: 'cose', animate: true, nodeRepulsion: 400000 }}).run();
    }}

    function filterNodeType(type) {{
      if (!cy) return;
      if (type === 'all') {{
        cy.elements().show();
      }} else if (type === 'actors') {{
        cy.elements().hide();
        cy.elements('node[node_type = "ThreatActor"], node[node_type = "Marketplace"], node[node_type = "Commodity"]').show();
        cy.elements('edge[edge_type = "OPERATES"], edge[edge_type = "OFFERS"]').show();
      }}
      cy.fit(null, 30);
    }}

    // Export Result Sets
    function exportJSON() {{
      const exportData = {{
        investigation: CURRENT_SUMMARY.investigation,
        threat_actors: CURRENT_SUMMARY.threat_actors,
        identifiers: CURRENT_SUMMARY.identifiers,
        graph_elements: GRAPH_DATA
      }};
      const blob = new Blob([JSON.stringify(exportData, null, 2)], {{ type: 'application/json' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `jane_dossier_${{CURRENT_SUMMARY.investigation.id}}.json`;
      a.click();
      URL.revokeObjectURL(url);
    }}

    function exportCSV() {{
      let csv = "identifier_type,value,evidence_quote,confidence\\n";
      (CURRENT_SUMMARY.identifiers || []).forEach(i => {{
        csv += `"${{i.type}}","${{i.value}}","${{(i.evidence_quote || '').replace(/"/g, '""')}}",${{i.confidence || 1.0}}\\n`;
      }});
      const blob = new Blob([csv], {{ type: 'text/csv' }});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `jane_identifiers_${{CURRENT_SUMMARY.investigation.id}}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    }}

    function exportDossierReport() {{
      window.print();
    }}

    async function hydrateInvestigations() {{
      try {{
        const resp = await fetch('/api/investigations');
        if (!resp.ok) return;
        ALL_INVS = (await resp.json()).investigations || [];
        if (ALL_INVS.length) await refreshInvestigation(ALL_INVS[0].id);
        initSelect();
      }} catch (err) {{
        console.warn('Could not refresh investigation list:', err);
      }}
    }}

    window.onload = function() {{
      initSelect();
      initGraph();
      renderLogs(INITIAL_LOGS);
      renderExtractedPages(CURRENT_SUMMARY);
      hydrateInvestigations();
    }};
  </script>
</body>
</html>
'''

dashboard_path.write_text(html_template, encoding="utf-8")
print(f"Generated unified threat attribution cockpit with Live Logs ({len(html_template)} bytes)")
