"""
Jane AI Harness: OpenCode Workspace Scaffolding & Configuration Engine.
Ensures every OpenCode session operates with a dedicated opencode.json configuration
and AGENTS.md operational doctrine tailored to its task (Investigations vs. SQL Studio).
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import subprocess
from typing import Any, Dict, Optional

logger = logging.getLogger("jane.ai.harness")


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def _init_git(workspace: Path) -> None:
    git_dir = workspace / ".git"
    if not git_dir.exists():
        try:
            subprocess.run(["git", "init"], cwd=str(workspace), capture_output=True, timeout=5)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Investigation Agent Harness
# ---------------------------------------------------------------------------

def ensure_investigation_harness(
    workspace_path: Path,
    investigation_id: str,
    query: str,
    extra_prompt: str = "",
) -> Path:
    """
    Scaffolds the complete investigation workspace directory structure,
    writes machine-enforced opencode.json (autonomous mode, no prompt halts),
    and generates the comprehensive AGENTS.md operational doctrine.
    """
    inv_dir = workspace_path
    inv_dir.mkdir(parents=True, exist_ok=True)

    # 1. Standard empty folder hierarchy
    for subfolder in (
        "queries/search_runs",
        "targets",
        "pages",
        "html",
        "extracted",
        "locksmith",
        "stylometry",
        "analysis",
        "opencode",
        "osint/reports",
        "graph",
        "logs",
    ):
        (inv_dir / subfolder).mkdir(parents=True, exist_ok=True)

    # 2. Metadata tracking files
    meta = {
        "job_id": investigation_id,
        "investigation_id": investigation_id,
        "query": query,
        "extra_prompt": extra_prompt,
        "status": "PENDING",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _write_json(inv_dir / "job_meta.json", meta)
    _write_json(inv_dir / "investigation.json", meta)
    _write_json(inv_dir / "queries/input.json", {"query": query})
    (inv_dir / "logs/events.jsonl").touch()

    # 3. AGENTS.md: Operational Doctrine
    agents_md = f"""# Jane Dark Web Intelligence Workspace

**Investigation:** `{investigation_id}`  
**Query:** `{query}`  
**Workspace:** `{inv_dir}`

## 1. ROLE

You are an authorized intelligence analyst working **only inside `{inv_dir}`**.

Treat this directory as the complete source of truth. Do not invent facts, evidence, identities, URLs, or relationships.

## 2. DIRECTORY MAP

- `html/` — raw crawled HTML; primary evidence
- `pages/` — cleaned page text, headers, links
- `extracted/` — indicators (`indicators.json`)
- `locksmith/` — infrastructure findings (`findings.json`)
- `stylometry/` — stylometry results (`profile.json`)
- `queries/` — expanded queries (`fanout.json`)
- `osint/` — OSINT targets (`targets.json`)
- `opencode/` — attribution reports and metadata
- `graph/` — threat graph outputs

## 3. HARD RULES

### Evidence Discovery & Grounding

1. **Primary Read:** Inspect `pages/*/cleaned.txt` for visible text and `extracted/indicators.json` for IOCs.
2. **Secondary Read:** Inspect `pages/*/raw.html` or `html/` only if hunting hidden comments, scripts, or layout.
3. **What to Extract:**
   - **Actors:** Vendor handles, operator aliases, marketplace admins.
   - **Commodities:** Specific illicit goods/services (dumps, CVVs, narcotics, exploits). Include `name`, `category`, `marketplace_name`, `onion_url`, `vendor_handle`, and exact `evidence_quote`.
   - **Indicators:** BTC/XMR wallets, Telegram/Jabber handles, emails, PGP keys.
   - **Relationships:** Who `SELLS` what, who `OPERATES` market, what actor `USES` which wallet.
4. **Verbatim Quotation (MANDATORY):**
   - Copy exact literal sentence from `cleaned.txt` or `raw.html` into `evidence_quote`.
   - Never paraphrase inside quotes.
5. **Abstention Rule:**
   - No evidence = no claim. If missing or benign, set:
     `"threat_category": "INSUFFICIENT_EVIDENCE"`
     and leave unsupported entity lists empty. NEVER hallucinate entities.

### Onion URLs

Always preserve the **complete onion address** exactly as found.

- Never shorten URLs.
- Never use `...`.
- Never modify or normalize an onion address.

### Canonical Threat Graph Architecture

The graph must strictly conform to the Jane canonical validator:

- **Allowed Node Types:** `actor`, `marketplace`, `product`, `shared_identifier`, `clearnet_account`
- **Allowed Edge Types:**
  - `operates_on`: Actor -> Marketplace
  - `sells`: Actor -> Product
  - `listed_on`: Product -> Marketplace
  - `shares_identifier`: Actor <-> Actor via SharedIdentifier node
  - `trust`: Actor <-> Actor (requires explicit vouch/trust keyword in evidence_quote)
  - `clearnet_alias`: Actor -> ClearnetAccount

Do not emit non-canonical node types (e.g. organization, website, wallet, domain, evidence, lead) or invalid edge types.

### Turn 3 Output

Write **only valid JSON data** to:

`graph/threat_graph.json`

Do **not** write Python, JavaScript, TypeScript, shell commands, markdown, comments, or explanations.

Before writing, verify:

- JSON parses correctly ({{"investigation_id": "...", "nodes": [...], "edges": [...]}}).
- Every factual entity has evidence.
- Evidence quotes are verbatim.
- Node types and edge types strictly match the canonical validator schema.
- Onion URLs are complete.
- Unsupported claims are excluded.
"""
    (inv_dir / "AGENTS.md").write_text(agents_md, encoding="utf-8")

    # 4. opencode.json: Autonomous Execution & Sandboxed Permissions
    opencode_config = {
        "$schema": "https://opencode.ai/config.json",
        "model": "opencode/muse-spark-1.3-contributor-free",
        "default_agent": "investigator",
        "agent": {
            "investigator": {
                "prompt": f"You are an NTRO Senior Threat Intelligence Analyst operating strictly within investigation workspace {inv_dir}. Follow AGENTS.md verbatim.",
                "tools": {
                    "read": True,
                    "write": True,
                    "edit": False,
                    "glob": True,
                    "grep": True,
                    "bash": False,
                    "task": False,
                    "question": False,
                },
            }
        },
        "permission": {
            "tools": {
                "*": "allow"
            }
        },
        "rules": [
            # Deny dangerous system calls
            {"permission": "bash", "action": "deny", "pattern": "*"},

            # Allowed deliverable write paths
            {"permission": "write", "action": "allow", "pattern": "graph/threat_graph.json"},
            {"permission": "write", "action": "allow", "pattern": "graph/mermaid.mmd"},
            {"permission": "write", "action": "allow", "pattern": "queries/fanout.json"},
            {"permission": "write", "action": "allow", "pattern": "opencode/attribution_report.json"},
            {"permission": "write", "action": "allow", "pattern": "osint/targets.json"},

            # Deny writing executable code
            {"permission": "write", "action": "deny", "pattern": "*.py"},
            {"permission": "write", "action": "deny", "pattern": "*.ts"},
            {"permission": "write", "action": "deny", "pattern": "*.tsx"},
            {"permission": "write", "action": "deny", "pattern": "*.js"},
            {"permission": "write", "action": "deny", "pattern": "*.sh"},
            {"permission": "write", "action": "deny", "pattern": "*.exe"},
            {"permission": "write", "action": "deny", "pattern": "*.db"},

            # Allow reading evidence directories
            {"permission": "read", "action": "allow", "pattern": "html/**"},
            {"permission": "read", "action": "allow", "pattern": "pages/**"},
            {"permission": "read", "action": "allow", "pattern": "extracted/**"},
            {"permission": "read", "action": "allow", "pattern": "locksmith/**"},
            {"permission": "read", "action": "allow", "pattern": "stylometry/**"},
            {"permission": "read", "action": "allow", "pattern": "opencode/**"},
            {"permission": "read", "action": "allow", "pattern": "osint/**"},
            {"permission": "read", "action": "allow", "pattern": "queries/**"},
            {"permission": "read", "action": "allow", "pattern": "graph/**"},
            {"permission": "read", "action": "allow", "pattern": "AGENTS.md"},
            {"permission": "read", "action": "allow", "pattern": "*.json"},

            # Deny reading outside workspace
            {"permission": "*", "action": "deny", "pattern": "../*"},
        ],
    }
    _write_json(inv_dir / "opencode.json", opencode_config)

    # 5. Git repository anchor
    _init_git(inv_dir)

    return inv_dir


# ---------------------------------------------------------------------------
# SQL Studio Agent Harness
# ---------------------------------------------------------------------------

def ensure_sql_studio_harness(
    workspace_path: Optional[Path] = None,
    schema_metadata: Optional[Dict[str, Any]] = None,
) -> Path:
    """
    Initializes the dedicated SQL Studio OpenCode workspace in jane/data/sql_studio/.
    Writes opencode.json (read-only query assistant, autonomous allow),
    AGENTS.md (comprehensive 12-table data dictionary & query guide),
    and schema.json/schema.sql snapshot files.
    """
    root = workspace_path or (Path(__file__).resolve().parent.parent / "data" / "sql_studio")
    root.mkdir(parents=True, exist_ok=True)
    (root / "history").mkdir(parents=True, exist_ok=True)

    # 1. opencode.json: Autonomous Read-Only Database Copilot
    opencode_config = {
        "$schema": "https://opencode.ai/config.json",
        "model": "opencode/muse-spark-1.3-contributor-free",
        "default_agent": "sql_copilot",
        "agent": {
            "sql_copilot": {
                "prompt": "You are Jane SQL Copilot, an expert read-only SQLite 3 database assistant for Jane Dark Web Threat Intelligence. You generate high-performance, strictly read-only SQL queries and concise explanations based on the intelligence schema.",
                "tools": {
                    "read": True,
                    "write": False,
                    "edit": False,
                    "glob": True,
                    "grep": True,
                    "bash": False,
                    "task": False,
                    "question": False,
                },
            }
        },
        "permission": {
            "tools": {
                "*": "allow"
            }
        },
        "rules": [
            {"permission": "bash", "action": "deny", "pattern": "*"},
            {"permission": "write", "action": "deny", "pattern": "*"},
            {"permission": "read", "action": "allow", "pattern": "AGENTS.md"},
            {"permission": "read", "action": "allow", "pattern": "schema.sql"},
            {"permission": "read", "action": "allow", "pattern": "schema.json"},
        ],
    }
    _write_json(root / "opencode.json", opencode_config)

    # 2. Schema snapshot files
    if schema_metadata:
        _write_json(root / "schema.json", schema_metadata)

    schema_sql_path = root / "schema.sql"
    if not schema_sql_path.exists() or schema_metadata:
        lines = [
            "-- Jane Threat Intelligence Database Schema Definition",
            "-- Target: SQLite 3 (Read-Only Mode)",
            "",
        ]
        if schema_metadata and "tables" in schema_metadata:
            for t in schema_metadata["tables"]:
                lines.append(f"-- Table: {t['table_name']} ({t.get('row_count', 0)} rows)")
                col_defs = [f"  {c['name']} {c['type']}" for c in t.get("columns", [])]
                lines.append(f"CREATE TABLE {t['table_name']} (\n" + ",\n".join(col_defs) + "\n);\n")
        else:
            lines.append("""
CREATE TABLE threat_actors (
  id TEXT PRIMARY KEY,
  designated_id TEXT,
  primary_handle TEXT,
  threat_category TEXT,
  confidence REAL,
  attributed_onions TEXT,
  created_at TEXT
);

CREATE TABLE identifiers (
  id TEXT PRIMARY KEY,
  type TEXT,
  value TEXT,
  confidence REAL,
  is_sanctioned INTEGER,
  evidence_quote TEXT,
  page_id TEXT,
  first_seen TEXT,
  last_seen TEXT,
  occurrence_count INTEGER
);

CREATE TABLE onion_pages (
  id TEXT PRIMARY KEY,
  url TEXT,
  title TEXT,
  server_banner TEXT,
  favicon_mmh3 TEXT,
  etag TEXT,
  investigation_id TEXT,
  created_at TEXT
);

CREATE TABLE graph_nodes (
  id TEXT PRIMARY KEY,
  label TEXT,
  node_type TEXT,
  community INTEGER,
  degree INTEGER,
  investigation_id TEXT
);

CREATE TABLE graph_edges (
  id TEXT PRIMARY KEY,
  source TEXT,
  target TEXT,
  edge_type TEXT,
  confidence REAL,
  evidence_quote TEXT,
  investigation_id TEXT
);

CREATE TABLE ip_enrichment (
  ip_address TEXT PRIMARY KEY,
  country_code TEXT,
  country_name TEXT,
  city TEXT,
  asn TEXT,
  organization TEXT,
  isp TEXT,
  proxy_or_vpn INTEGER,
  tor INTEGER,
  enriched_at TEXT
);

CREATE TABLE investigations (
  id TEXT PRIMARY KEY,
  query TEXT,
  status TEXT,
  page_count INTEGER,
  created_at TEXT,
  updated_at TEXT
);

CREATE TABLE evidence_chunks (
  id TEXT PRIMARY KEY,
  investigation_id TEXT,
  page_id TEXT,
  chunk_text TEXT,
  char_start INTEGER,
  char_end INTEGER,
  sha256 TEXT
);
""")
        schema_sql_path.write_text("\n".join(lines), encoding="utf-8")

    # 3. AGENTS.md: Exhaustive Data Dictionary & SQL Directives for all 14 Tables
    agents_md = f"""# Jane SQL Studio Copilot: Complete Database Schema & Operational Directives

## 1. ROLE & IDENTITY
You are Jane SQL Copilot, an expert read-only SQLite 3 database assistant for the Jane Threat Intelligence System.
Your mission is to translate natural language threat intelligence queries into safe, high-performance SQLite queries.

## 2. STRICT SAFETY & DIALECT RULES
1. **Read-Only Dialect**: Generate ONLY single `SELECT` statements or `WITH ... SELECT` common table expressions (CTEs).
2. **Absolute Zero-Mutation Policy**: NEVER write `DROP`, `DELETE`, `UPDATE`, `INSERT`, `ALTER`, `ATTACH`, `DETACH`, or `PRAGMA`.
3. **Case Sensitivity**: Dark web text and category fields vary in capitalization. Always use `COLLATE NOCASE` or `LOWER(column) LIKE '%value%'`.
4. **Result Size**: Always append `LIMIT 50;` (or appropriate limit) to prevent runaway row fetches unless the query is an aggregation (`COUNT`, `GROUP BY`).
5. **Output Format**: Respond with the SQLite query wrapped in a ```sql ... ``` code block, accompanied by a 1-2 sentence analytical explanation.

---

## 3. COMPLETE DATABASE SCHEMA & CURATED VIEWS

### A. Curated Read-Only Views (RECOMMENDED FOR QUERIES)
1. `v_actor_summary`: `actor_id`, `primary_handle`, `category`, `attribution_confidence`, `first_seen`, `last_seen`, `alias_count`, `marketplace_count`, `product_count`
2. `v_actor_identifiers`: `actor_id`, `primary_handle`, `identifier_id`, `identifier_type` ('wallet','pgp','handle','email','phone','ip'), `identifier_value`, `is_shared` (1 if links 2+ actors), `confidence`, `evidence_quote`
3. `v_marketplace_activity`: `marketplace_id`, `onion_domain`, `display_name`, `category`, `actor_count`, `infrastructure_findings_count`, `first_seen`, `last_seen`
4. `v_infrastructure_findings`: `finding_id`, `marketplace_id`, `onion_domain`, `finding_type` ('banner','favicon_hash','ip_leak','ssl_cert'), `value`, `evidence_quote`, `found_at`
5. `v_actor_trust_links`: `actor_id`, `actor_handle`, `trusted_actor_id`, `trusted_actor_handle`, `confidence`, `evidence_quote`, `created_at`
6. `v_actor_products`: `actor_id`, `primary_handle`, `product_id`, `product_name`, `product_category`, `confidence`, `evidence_quote`
7. `v_clearnet_accounts`: `account_id`, `actor_id`, `primary_handle`, `platform`, `value`, `evidence_quote`, `created_at`

### B. V2 Canonical Normalized Tables
1. `actors`: `id` (PK), `primary_handle` (UNIQUE), `category`, `attribution_confidence` (REAL), `first_seen`, `last_seen`, `created_at`, `updated_at`
2. `actor_aliases`: `id` (PK), `actor_id` (FK -> actors.id), `alias_handle`, `source_investigation_id`, `confidence`, `needs_review` (0 or 1), `created_at`
3. `marketplaces`: `id` (PK), `onion_domain` (UNIQUE), `display_name`, `category`, `first_seen`, `last_seen`, `created_at`
4. `actor_marketplace`: `actor_id` (PK, FK -> actors.id), `marketplace_id` (PK, FK -> marketplaces.id), `confidence`, `evidence_quote`, `first_seen`
5. `products`: `id` (PK), `name` (UNIQUE), `category`, `created_at`
6. `actor_product`: `actor_id` (PK, FK -> actors.id), `product_id` (PK, FK -> products.id), `confidence`, `evidence_quote`, `first_seen`
7. `actor_trust`: `actor_id` (PK, FK -> actors.id), `trusted_actor_id` (PK, FK -> actors.id), `confidence`, `evidence_quote`, `created_at`
8. `clearnet_accounts`: `id` (PK), `actor_id` (FK -> actors.id), `platform`, `value`, `evidence_quote`, `created_at`
9. `actor_clearnet_account`: `actor_id` (PK, FK -> actors.id), `clearnet_account_id` (PK, FK -> clearnet_accounts.id), `confidence`, `evidence_quote`
10. `canonical_identifiers`: `id` (PK), `type` (TEXT), `value` (TEXT), `actor_id` (FK -> actors.id), `is_shared` (INTEGER, 1 if shared across actors), `evidence_quote`, `confidence`, `investigation_id`, `created_at`
11. `infrastructure_findings`: `id` (PK), `marketplace_id` (FK -> marketplaces.id), `type` ('banner','favicon_hash','ip_leak'), `value`, `evidence_quote`, `source_page_id` (FK -> onion_pages.id), `found_at`
12. `evidence_quotes`: `id` (PK), `page_id` (FK -> onion_pages.id), `quote_text`, `extracted_fact_type`, `extracted_fact_id`, `created_at`
13. `entity_investigations`: `entity_type`, `entity_id`, `investigation_id` (Composite PK)
14. `query_sessions` & `query_log`: SQL Studio query audit and execution history.

### C. Ingestion & Raw Evidence Tables
1. `threat_actors`: Legacy attribution records (`id`, `investigation_id`, `designated_id`, `primary_handle`, `threat_category`, `confidence`, `attributed_onions`, `created_at`)
2. `identifiers`: Extracted IOCs (`id`, `investigation_id`, `actor_id`, `page_id`, `type`, `value`, `evidence_quote`, `confidence`, `is_sanctioned`, `first_seen`, `last_seen`)
3. `onion_pages`: Crawled hidden services (`id`, `investigation_id`, `url`, `title`, `server_banner`, `favicon_mmh3`, `cleaned_text`, `created_at`)
4. `ip_enrichment`: Geolocation & ASN intelligence for clearweb origin IPs (`ip_address`, `country_name`, `city`, `asn`, `organization`, `hosting`, `tor`)
5. `graph_nodes` & `graph_edges`: Threat network graph nodes and relationship edges (`OPERATES_ON`, `SELLS`, `USES_CRYPTO`, `TRUST`, `CONNECTED_TO`)
6. `evidence_chunks`: Cryptographic text snippets (`id`, `investigation_id`, `page_id`, `url`, `text`, `sha256`)
7. `investigations`: Investigation hunt records (`id`, `query`, `status`, `page_count`, `created_at`)

---

## 4. STANDARD RELATIONAL & VIEW QUERY PATTERNS

### High-Speed Curated View Queries:
- **Vouched & Trusted Actors**:
  ```sql
  SELECT actor_handle, trusted_actor_handle, confidence, evidence_quote FROM v_actor_trust_links ORDER BY confidence DESC LIMIT 50;
  ```
- **Shared Identifiers Across Multiple Threat Actors (Pivots)**:
  ```sql
  SELECT primary_handle, identifier_type, identifier_value, is_shared, evidence_quote FROM v_actor_identifiers WHERE is_shared = 1 ORDER BY identifier_value LIMIT 50;
  ```
- **Actors Selling Products/Commodities**:
  ```sql
  SELECT primary_handle, product_name, product_category, confidence, evidence_quote FROM v_actor_products ORDER BY confidence DESC LIMIT 50;
  ```
- **Active Marketplaces & Discovered Infrastructure**:
  ```sql
  SELECT display_name, onion_domain, actor_count, infrastructure_findings_count FROM v_marketplace_activity ORDER BY actor_count DESC LIMIT 50;
  ```

### Canonical Relational Joins:
- **Actors to Canonical Identifiers & Wallets**:
  ```sql
  SELECT a.primary_handle, ci.type, ci.value, ci.is_shared, ci.evidence_quote
  FROM actors a
  JOIN canonical_identifiers ci ON ci.actor_id = a.id
  ORDER BY ci.confidence DESC LIMIT 50;
  ```
- **Marketplaces to Infrastructure Leaks & Banners**:
  ```sql
  SELECT m.display_name, m.onion_domain, inf.type, inf.value, inf.evidence_quote
  FROM marketplaces m
  JOIN infrastructure_findings inf ON inf.marketplace_id = m.id
  ORDER BY inf.found_at DESC LIMIT 50;
  ```
- **Actor to Marketplace Presence**:
  ```sql
  SELECT a.primary_handle, m.display_name, m.onion_domain, am.confidence, am.evidence_quote
  FROM actors a
  JOIN actor_marketplace am ON am.actor_id = a.id
  JOIN marketplaces m ON m.id = am.marketplace_id
  ORDER BY am.confidence DESC LIMIT 50;
  ```
"""
    agents_md_file = root / "AGENTS.md"
    agents_md_file.write_text(agents_md, encoding="utf-8")

    # 4. Git repository anchor
    _init_git(root)

    return root
