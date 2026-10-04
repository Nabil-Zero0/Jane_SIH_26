"""
Jane Database Engine — SQLite (Python Standard Library)
Zero external dependencies, single file in `jane/data/jane.db`.
Stores investigations, onion pages, threat actors, identifiers, and graph structures.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from .intelligence_schema import INTELLIGENCE_SCHEMA_SQL


DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "jane.db"
DB_PATH = Path(os.environ.get("JANE_DB_PATH")) if os.environ.get("JANE_DB_PATH") else DEFAULT_DB_PATH


def is_test_environment() -> bool:
    if os.environ.get("JANE_TEST_RUN") == "1":
        return True
    return any(mod in sys.modules for mod in ("pytest", "unittest"))


def get_db_connection(db_path: Optional[Path] = None) -> sqlite3.Connection:
    target = db_path or (Path(os.environ["JANE_DB_PATH"]) if os.environ.get("JANE_DB_PATH") else DB_PATH)
    if is_test_environment() and not os.environ.get("JANE_ALLOW_PROD_DB_IN_TEST"):
        try:
            if target.resolve() == DEFAULT_DB_PATH.resolve():
                raise RuntimeError(
                    f"TEST ISOLATION VIOLATION: Test process attempted to open production database at {target}! "
                    "Tests must use a temporary SQLite database (set JANE_DB_PATH, pass db_path, or patch DB_PATH)."
                )
        except OSError:
            pass
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Optional[Path] = None) -> None:
    """Initializes all necessary tables and indexes for Jane threat attribution."""
    conn = get_db_connection(db_path)
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS investigations (
            id TEXT PRIMARY KEY,
            query TEXT NOT NULL,
            max_onions INTEGER DEFAULT 5,
            max_depth INTEGER DEFAULT 1,
            status TEXT DEFAULT 'PENDING',
            page_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS onion_pages (
            id TEXT PRIMARY KEY,
            investigation_id TEXT,
            url TEXT NOT NULL UNIQUE,
            title TEXT,
            raw_html_path TEXT,
            cleaned_text TEXT,
            server_banner TEXT,
            favicon_mmh3 TEXT,
            etag TEXT,
            template_hash TEXT,
            content_diff_ratio REAL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS threat_actors (
            id TEXT PRIMARY KEY,
            investigation_id TEXT,
            designated_id TEXT NOT NULL,
            primary_handle TEXT NOT NULL,
            threat_category TEXT,
            attributed_onions TEXT,
            confidence REAL DEFAULT 1.0,
            stylometry_summary TEXT,
            graph_node_id TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS identifiers (
            id TEXT PRIMARY KEY,
            investigation_id TEXT,
            actor_id TEXT,
            page_id TEXT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            evidence_quote TEXT,
            confidence REAL DEFAULT 1.0,
            is_sanctioned INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            occurrence_count INTEGER DEFAULT 1,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
            FOREIGN KEY (actor_id) REFERENCES threat_actors(id) ON DELETE SET NULL,
            FOREIGN KEY (page_id) REFERENCES onion_pages(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS graph_nodes (
            id TEXT,
            investigation_id TEXT,
            label TEXT NOT NULL,
            node_type TEXT NOT NULL,
            community INTEGER DEFAULT 1,
            degree INTEGER DEFAULT 1,
            metadata_json TEXT,
            PRIMARY KEY (id, investigation_id),
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS graph_edges (
            id TEXT PRIMARY KEY,
            investigation_id TEXT,
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            edge_type TEXT NOT NULL,
            confidence REAL DEFAULT 1.0,
            evidence_quote TEXT,
            chunk_id TEXT,
            basis TEXT,
            review_status TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS search_runs (
            id TEXT PRIMARY KEY,
            investigation_id TEXT,
            provider TEXT NOT NULL,
            query TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            started_at TEXT NOT NULL,
            finished_at TEXT,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS search_hits (
            id TEXT PRIMARY KEY,
            investigation_id TEXT,
            search_run_id TEXT,
            provider TEXT NOT NULL,
            query TEXT NOT NULL,
            onion_url TEXT NOT NULL,
            title TEXT,
            snippet TEXT,
            score REAL DEFAULT 0.0,
            first_seen TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS evidence_chunks (
            id TEXT PRIMARY KEY,
            page_id TEXT,
            investigation_id TEXT,
            url TEXT,
            text TEXT NOT NULL,
            char_start INTEGER,
            char_end INTEGER,
            sha256 TEXT NOT NULL,
            retrieved_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE,
            FOREIGN KEY (page_id) REFERENCES onion_pages(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS graph_node_investigations (
            node_id TEXT NOT NULL,
            investigation_id TEXT NOT NULL,
            PRIMARY KEY (node_id, investigation_id),
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS graph_edge_investigations (
            edge_id TEXT NOT NULL,
            investigation_id TEXT NOT NULL,
            PRIMARY KEY (edge_id, investigation_id),
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        
        CREATE TABLE IF NOT EXISTS sql_sessions (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            opencode_session_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sql_history (
            id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            query TEXT NOT NULL,
            source TEXT DEFAULT 'user',
            status TEXT DEFAULT 'SUCCESS',
            latency_ms REAL DEFAULT 0.0,
            row_count INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sql_sessions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS query_sessions (
            id TEXT PRIMARY KEY,
            label TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS query_log (
            id TEXT PRIMARY KEY,
            session_id TEXT,
            question TEXT,
            sql_query TEXT NOT NULL,
            row_count INTEGER DEFAULT 0,
            execution_time_ms REAL DEFAULT 0.0,
            error_message TEXT,
            ran_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES query_sessions(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS commodities (
            id TEXT PRIMARY KEY,
            investigation_id TEXT,
            name TEXT NOT NULL,
            category TEXT,
            marketplace_name TEXT,
            onion_url TEXT,
            actor_handle TEXT,
            evidence_quote TEXT,
            confidence REAL DEFAULT 1.0,
            original_title TEXT,
            price REAL,
            currency TEXT,
            quantity REAL,
            unit TEXT,
            min_order REAL,
            availability TEXT,
            listing_status TEXT,
            observation_date TEXT,
            listing_url TEXT,
            uncertainty TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_onion_investigation ON onion_pages(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_commodities_inv ON commodities(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_identifiers_type ON identifiers(type);
        CREATE INDEX IF NOT EXISTS idx_actors_investigation ON threat_actors(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_edges_source_target ON graph_edges(source, target);
        CREATE INDEX IF NOT EXISTS idx_search_hits_inv ON search_hits(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_chunks_page ON evidence_chunks(page_id);
        CREATE INDEX IF NOT EXISTS idx_chunks_inv ON evidence_chunks(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_node_inv_link ON graph_node_investigations(investigation_id);
        CREATE INDEX IF NOT EXISTS idx_edge_inv_link ON graph_edge_investigations(investigation_id);
        """)
        # Normalized entity/intelligence tables. Keep JSON artifacts on disk;
        # these tables store their validated, queryable interpretation.
        conn.executescript(INTELLIGENCE_SCHEMA_SQL)
        # Backfill join tables from legacy per-row investigation_id columns so
        # pre-redesign nodes/edges remain visible in both investigation and
        # global views without duplicating or mutating existing rows.
        try:
            conn.execute("""
                INSERT OR IGNORE INTO graph_node_investigations (node_id, investigation_id)
                SELECT id, investigation_id FROM graph_nodes WHERE investigation_id IS NOT NULL AND investigation_id != ''
            """)
            conn.execute("""
                INSERT OR IGNORE INTO graph_edge_investigations (edge_id, investigation_id)
                SELECT id, investigation_id FROM graph_edges WHERE investigation_id IS NOT NULL AND investigation_id != ''
            """)
        except Exception:
            pass  # Join tables may not exist on very old partial schemas; not fatal
        # Safe incremental column additions for existing databases
        migrations = [
            ("onion_pages", "template_hash", "TEXT"),
            ("onion_pages", "content_diff_ratio", "REAL"),
            ("onion_pages", "canonical_url", "TEXT"),
            ("onion_pages", "parent_page_id", "TEXT"),
            ("onion_pages", "depth", "INTEGER DEFAULT 0"),
            ("onion_pages", "visible_text_hash", "TEXT"),
            ("onion_pages", "language", "TEXT DEFAULT 'en'"),
            ("identifiers", "is_sanctioned", "INTEGER DEFAULT 0"),
            ("identifiers", "first_seen", "TEXT"),
            ("identifiers", "last_seen", "TEXT"),
            ("identifiers", "occurrence_count", "INTEGER DEFAULT 1"),
            ("identifiers", "chunk_id", "TEXT"),
            ("graph_edges", "chunk_id", "TEXT"),
            ("graph_edges", "basis", "TEXT"),
            ("graph_edges", "review_status", "TEXT"),
            ("threat_actors", "graph_node_id", "TEXT"),
            ("query_log", "natural_language_question", "TEXT"),
            ("query_log", "generated_sql", "TEXT"),
            ("query_log", "executed", "INTEGER DEFAULT 1"),
            ("commodities", "original_title", "TEXT"),
            ("commodities", "price", "REAL"),
            ("commodities", "currency", "TEXT"),
            ("commodities", "quantity", "REAL"),
            ("commodities", "unit", "TEXT"),
            ("commodities", "min_order", "REAL"),
            ("commodities", "availability", "TEXT"),
            ("commodities", "listing_status", "TEXT"),
            ("commodities", "observation_date", "TEXT"),
            ("commodities", "listing_url", "TEXT"),
            ("commodities", "uncertainty", "TEXT"),
        ]
        for tbl, col, col_type in migrations:
            try:
                conn.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {col_type};")
            except Exception:
                pass  # Column already exists
    conn.close()


def create_investigation(query: str, max_onions: int = 5, max_depth: int = 1, inv_id: Optional[str] = None) -> str:
    import uuid
    iid = inv_id or f"inv_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT INTO investigations (id, query, max_onions, max_depth, status, page_count, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'PENDING', 0, ?, ?)
            ON CONFLICT(id) DO NOTHING
        """, (iid, query, max_onions, max_depth, now, now))
    conn.close()
    return iid


def update_investigation_status(inv_id: str, status: str, page_count: Optional[int] = None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    with conn:
        if page_count is not None:
            conn.execute("""
                UPDATE investigations SET status = ?, page_count = ?, updated_at = ? WHERE id = ?
            """, (status, page_count, now, inv_id))
        else:
            conn.execute("""
                UPDATE investigations SET status = ?, updated_at = ? WHERE id = ?
            """, (status, now, inv_id))
    conn.close()


def save_onion_page(
    investigation_id: str,
    url: str,
    title: str = "",
    raw_html_path: str = "",
    cleaned_text: str = "",
    server_banner: str = "",
    favicon_mmh3: str = "",
    etag: str = "",
    template_hash: str = "",
    content_diff_ratio: Optional[float] = None,
) -> str:
    import uuid
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    with conn:
        row = conn.execute("SELECT id FROM onion_pages WHERE url = ?", (url,)).fetchone()
        if row:
            pid = row["id"]
            conn.execute("""
                UPDATE onion_pages SET
                    investigation_id = ?,
                    title = ?,
                    raw_html_path = ?,
                    cleaned_text = ?,
                    server_banner = ?,
                    favicon_mmh3 = ?,
                    etag = ?,
                    template_hash = ?,
                    content_diff_ratio = ?
                WHERE id = ?
            """, (investigation_id, title, raw_html_path, cleaned_text, server_banner, favicon_mmh3, etag, template_hash, content_diff_ratio, pid))
        else:
            pid = f"page_{uuid.uuid4().hex[:8]}"
            conn.execute("""
                INSERT INTO onion_pages (id, investigation_id, url, title, raw_html_path, cleaned_text, server_banner, favicon_mmh3, etag, template_hash, content_diff_ratio, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (pid, investigation_id, url, title, raw_html_path, cleaned_text, server_banner, favicon_mmh3, etag, template_hash, content_diff_ratio, now))
    conn.close()
    return pid


def save_threat_actor(
    investigation_id: str,
    designated_id: str,
    primary_handle: str,
    threat_category: str = "Unclassified",
    attributed_onions: str = "",
    confidence: float = 1.0,
    stylometry_summary: str = "",
    graph_node_id: Optional[str] = None,
) -> str:
    import uuid
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    with conn:
        row = conn.execute("SELECT id FROM threat_actors WHERE investigation_id = ? AND primary_handle = ?", (investigation_id, primary_handle)).fetchone()
        if row:
            aid = row["id"]
            conn.execute("""
                UPDATE threat_actors SET
                    designated_id = ?,
                    threat_category = ?,
                    attributed_onions = ?,
                    confidence = ?,
                    stylometry_summary = ?,
                    graph_node_id = COALESCE(?, graph_node_id)
                WHERE id = ?
            """, (designated_id, threat_category, attributed_onions, confidence, stylometry_summary, graph_node_id, aid))
        else:
            aid = f"actor_{uuid.uuid4().hex[:8]}"
            conn.execute("""
                INSERT INTO threat_actors (id, investigation_id, designated_id, primary_handle, threat_category, attributed_onions, confidence, stylometry_summary, graph_node_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (aid, investigation_id, designated_id, primary_handle, threat_category, attributed_onions, confidence, stylometry_summary, graph_node_id, now))
    conn.close()
    return aid


def save_identifier(
    investigation_id: str,
    itype: str,
    value: str,
    actor_id: Optional[str] = None,
    page_id: Optional[str] = None,
    evidence_quote: str = "",
    confidence: float = 1.0,
    is_sanctioned: int = 0,
) -> str:
    import uuid
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            existing = conn.execute(
                "SELECT id, occurrence_count FROM identifiers WHERE investigation_id = ? AND type = ? AND value = ?",
                (investigation_id, itype, value),
            ).fetchone()
            if existing:
                new_count = (existing["occurrence_count"] or 1) + 1
                conn.execute("""
                    UPDATE identifiers SET
                        last_seen = ?,
                        occurrence_count = ?,
                        actor_id = COALESCE(?, actor_id),
                        page_id = COALESCE(?, page_id),
                        confidence = MAX(confidence, ?)
                    WHERE id = ?
                """, (now, new_count, actor_id, page_id, confidence, existing["id"]))
                return existing["id"]
            iid = f"ident_{uuid.uuid4().hex[:8]}"
            conn.execute("""
                INSERT INTO identifiers (id, investigation_id, actor_id, page_id, type, value, evidence_quote, confidence, is_sanctioned, first_seen, last_seen, occurrence_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """, (iid, investigation_id, actor_id, page_id, itype, value, evidence_quote, confidence, is_sanctioned, now, now))
            return iid
    finally:
        conn.close()


def save_commodity(
    investigation_id: str,
    name: str,
    category: str = "Illicit Goods",
    marketplace_name: Optional[str] = None,
    onion_url: Optional[str] = None,
    actor_handle: Optional[str] = None,
    evidence_quote: str = "",
    confidence: float = 1.0,
    original_title: Optional[str] = None,
    price: Optional[float] = None,
    currency: Optional[str] = None,
    quantity: Optional[float] = None,
    unit: Optional[str] = None,
    min_order: Optional[float] = None,
    availability: Optional[str] = None,
    listing_status: Optional[str] = None,
    observation_date: Optional[str] = None,
    listing_url: Optional[str] = None,
    uncertainty: Optional[str] = None,
) -> str:
    import uuid
    cid = f"comm_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO commodities (
                    id, investigation_id, name, category, marketplace_name, onion_url,
                    actor_handle, evidence_quote, confidence, original_title, price,
                    currency, quantity, unit, min_order, availability, listing_status,
                    observation_date, listing_url, uncertainty, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cid, investigation_id, name, category, marketplace_name, onion_url,
                actor_handle, evidence_quote, confidence, original_title, price,
                currency, quantity, unit, min_order, availability, listing_status,
                observation_date, listing_url, uncertainty, now
            ))
        return cid
    finally:
        conn.close()


def save_graph_node(
    investigation_id: str,
    node_id: str,
    label: str,
    node_type: str,
    community: int = 1,
    degree: int = 1,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    conn = get_db_connection()
    meta_str = json.dumps(metadata or {})
    with conn:
        conn.execute("""
            INSERT INTO graph_nodes (id, investigation_id, label, node_type, community, degree, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id, investigation_id) DO UPDATE SET
                label = excluded.label,
                node_type = excluded.node_type,
                degree = excluded.degree,
                metadata_json = excluded.metadata_json
        """, (node_id, investigation_id, label, node_type, community, degree, meta_str))
        conn.execute("""
            INSERT OR IGNORE INTO graph_node_investigations (node_id, investigation_id)
            VALUES (?, ?)
        """, (node_id, investigation_id))
    conn.close()


def link_node_investigation(node_id: str, investigation_id: str) -> None:
    """Record that an investigation touched a graph node (many-to-many).

    The legacy ``graph_nodes.investigation_id`` column stays as the node's
    primary investigation; this join table tracks every additional
    investigation that contributed to or touched the node (e.g. a shared
    identifier seen in two investigations). Investigation view = filter by
    this table (union legacy column); global view = no filter.
    """
    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT OR IGNORE INTO graph_node_investigations (node_id, investigation_id)
            VALUES (?, ?)
        """, (node_id, investigation_id))
    conn.close()


def link_edge_investigation(edge_id: str, investigation_id: str) -> None:
    """Record that an investigation touched a graph edge (many-to-many)."""
    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT OR IGNORE INTO graph_edge_investigations (edge_id, investigation_id)
            VALUES (?, ?)
        """, (edge_id, investigation_id))
    conn.close()


def save_graph_edge(
    investigation_id: str,
    source: str,
    target: str,
    edge_type: str,
    confidence: float = 1.0,
    evidence_quote: str = "",
    evidence_ids: Optional[List[str]] = None,
    inferred: bool = False,
    basis: str = "direct_evidence",
    review_status: str = "UNREVIEWED",
) -> str:
    import uuid
    eid = f"edge_{uuid.uuid4().hex[:8]}"
    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT INTO graph_edges (id, investigation_id, source, target, edge_type, confidence, evidence_quote, basis, review_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (eid, investigation_id, source, target, edge_type, confidence, evidence_quote,
               json.dumps({"evidence_ids": evidence_ids or [], "inferred": inferred, "basis": basis}), review_status))
        conn.execute("""
            INSERT OR IGNORE INTO graph_edge_investigations (edge_id, investigation_id)
            VALUES (?, ?)
        """, (eid, investigation_id))
    conn.close()
    return eid


# ---------------------------------------------------------------------------
# Redesigned threat-actor relationship graph: canonical node/edge vocabulary.
# Single source of truth lives in jane.backend.graph.builder_model; the maps
# below are a deliberately narrow rendering projection so legacy rows
# (ONION_URL asset paths, CONCEPT blobs, banners, IPs) never reach the
# renderer. Raw evidence always stays queryable in onion_pages/identifiers.
# ---------------------------------------------------------------------------

# Legacy node_type -> canonical new-schema type. None = never rendered as a
# graph node (stays in its evidence table only).
_CANONICAL_NODE_TYPE: Dict[str, Optional[str]] = {
    # Actors
    "THREAT_ACTOR": "Actor",
    "ThreatActor": "Actor",
    "ACTOR": "Actor",
    "Actor": "Actor",
    # Marketplaces (legacy page nodes collapse to their marketplace by domain)
    "Marketplace": "Marketplace",
    "MARKET": "Marketplace",
    "Forum": "Marketplace",
    "FORUM": "Marketplace",
    "ONION_PAGE": "Marketplace",
    "PAGE": "Marketplace",
    "website": "Marketplace",
    "WEBSITE": "Marketplace",
    # Products / commodities (legacy CONCEPT nodes came from SELLS/OFFERS links)
    "Commodity": "Product",
    "COMMODITY": "Product",
    "PRODUCT": "Product",
    "Product": "Product",
    "product": "Product",
    "CONCEPT": "Product",
    # Shared identifiers (legacy single-use rows render for compat; NEW writes
    # only create these when shared by 2+ distinct actors — see connector.py)
    "CryptoWallet": "SharedIdentifier",
    "BITCOIN_ADDRESS": "SharedIdentifier",
    "SOLANA_ADDRESS": "SharedIdentifier",
    "CRYPTO": "SharedIdentifier",
    "WALLET": "SharedIdentifier",
    "wallet": "SharedIdentifier",
    "PGPKey": "SharedIdentifier",
    "PGP_KEY": "SharedIdentifier",
    "MessagingHandle": "SharedIdentifier",
    "TELEGRAM_HANDLE": "SharedIdentifier",
    "MESSAGING_HANDLE": "SharedIdentifier",
    "ClearnetAccount": "ClearnetAccount",
    "CLEARNET_ACCOUNT": "ClearnetAccount",
}

# Legacy edge_type -> canonical new-schema type. None = never rendered.
_CANONICAL_EDGE_TYPE: Dict[str, Optional[str]] = {
    "OPERATES_ON": "OPERATES_ON",
    "OPERATES": "OPERATES_ON",
    "SELLS": "SELLS",
    "OFFERS": "SELLS",
    "SHARES_IDENTIFIER": "SHARES_IDENTIFIER",
    "USES": "SHARES_IDENTIFIER",
    "USES_HANDLE": "SHARES_IDENTIFIER",
    "LIKELY_SAME_ACTOR": "SHARES_IDENTIFIER",
    "CONFIRMED_SAME_ACTOR": "SHARES_IDENTIFIER",
    "TRUST": "TRUST",
    "CLEARNET_ALIAS": "CLEARNET_ALIAS",
}

_NEW_SCHEMA_NODE_TYPES = ("Actor", "Marketplace", "Product", "SharedIdentifier", "ClearnetAccount")
_NEW_SCHEMA_EDGE_TYPES = ("OPERATES_ON", "SELLS", "SHARES_IDENTIFIER", "TRUST", "CLEARNET_ALIAS")


def _canonical_nodes_for_investigation(conn: sqlite3.Connection, inv_id: str) -> List[Dict[str, Any]]:
    """Nodes visible in an investigation view: legacy column UNION join table."""
    rows = conn.execute("""
        SELECT DISTINCT n.* FROM graph_nodes n
        LEFT JOIN graph_node_investigations j
          ON j.node_id = n.id AND j.investigation_id = ?
        WHERE n.investigation_id = ? OR j.investigation_id = ?
    """, (inv_id, inv_id, inv_id)).fetchall()
    return [dict(r) for r in rows]


def _canonical_edges_for_investigation(conn: sqlite3.Connection, inv_id: str) -> List[Dict[str, Any]]:
    rows = conn.execute("""
        SELECT DISTINCT e.* FROM graph_edges e
        LEFT JOIN graph_edge_investigations j
          ON j.edge_id = e.id AND j.investigation_id = ?
        WHERE e.investigation_id = ? OR j.investigation_id = ?
    """, (inv_id, inv_id, inv_id)).fetchall()
    return [dict(r) for r in rows]


def _to_canonical_graph_elements(
    nodes: List[Dict[str, Any]], edges: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """Project raw graph rows onto the 4-allowed-node-type / 4-allowed-edge-type schema."""
    from jane.backend.graph.builder_model import is_blocklisted, normalize_handle

    formatted_nodes = []
    valid_ids = set()
    actor_by_norm: Dict[str, Dict[str, Any]] = {}  # norm handle -> surviving node
    remap: Dict[str, str] = {}  # dropped node id -> surviving node id
    for n in nodes:
        meta = json.loads(n["metadata_json"]) if n.get("metadata_json") else {}
        raw_type = str(meta.get("type") or n["node_type"] or "")
        canonical = _CANONICAL_NODE_TYPE.get(raw_type, _CANONICAL_NODE_TYPE.get(raw_type.upper()))
        if canonical is None:
            continue  # asset paths, banners, IPs, emails/phones, concepts-as-junk: evidence tables only
        if canonical == "Actor" and (
            is_blocklisted(n.get("label", "")) or is_blocklisted(str(meta.get("handle", "")))
        ):
            continue  # blocklisted non-entity (e.g. "wire: transfer"): never a node
        if canonical == "SharedIdentifier" and is_blocklisted(
            str(meta.get("full_value", "") or meta.get("value", "") or n.get("label", ""))
        ):
            continue
        node_dict = {
            "id": n["id"],
            "label": n["label"],
            "node_type": canonical,
            "community": n.get("community", 1),
            "degree": n.get("degree", 1),
            **meta,
        }
        node_dict["node_type"] = canonical  # canonical wins over legacy meta.type
        if canonical == "Actor":
            # Merge legacy double-form rows (actor_<Raw> vs actor_<norm>) that
            # describe the same handle: first canonical id wins, metadata unions.
            norm = normalize_handle(str(meta.get("handle", "") or n.get("label", "")))
            if norm and norm in actor_by_norm:
                survivor = actor_by_norm[norm]
                for k in ("wallets", "pgp_keys", "known_handles", "aliases",
                          "source_investigations", "source_pages"):
                    merged = list(dict.fromkeys(
                        (survivor.get(k) or []) + (node_dict.get(k) or [])))
                    if merged:
                        survivor[k] = merged
                survivor["degree"] = max(survivor.get("degree", 1), node_dict.get("degree", 1))
                remap[n["id"]] = survivor["id"]
                continue
            if norm:
                actor_by_norm[norm] = node_dict
        formatted_nodes.append({"data": node_dict})
        valid_ids.add(n["id"])

    formatted_edges = []
    for e in edges:
        src, tgt = remap.get(e["source"], e["source"]), remap.get(e["target"], e["target"])
        if src not in valid_ids or tgt not in valid_ids:
            continue
        canonical = _CANONICAL_EDGE_TYPE.get(e["edge_type"], _CANONICAL_EDGE_TYPE.get(str(e["edge_type"]).upper()))
        if canonical is None:
            continue  # MENTIONS / CO_APPEARED_ON / SAME_TEMPLATE etc. never render
        basis = e.get("basis") or ""
        try:
            basis_meta = json.loads(basis) if isinstance(basis, str) and basis.startswith("{") else {}
        except Exception:
            basis_meta = {}
        formatted_edges.append({
            "data": {
                "id": e["id"],
                "source": src,
                "target": tgt,
                "edge_type": canonical,
                "label": canonical,
                "confidence": e.get("confidence", 1.0),
                "evidence_quote": e.get("evidence_quote", ""),
                "basis": basis_meta.get("basis", basis) if isinstance(basis_meta, dict) else basis,
                "provenance": basis_meta.get("provenance", []) if isinstance(basis_meta, dict) else [],
                "review_status": e.get("review_status", "UNREVIEWED"),
                "needs_review": (e.get("review_status") == "NEEDS_REVIEW"),
            }
        })
    return {"nodes": formatted_nodes, "edges": formatted_edges}


def get_global_graph_summary() -> Dict[str, Any]:
    """Global view: full graph across all investigations, no filter.

    Same store, same schema as the investigation view — just unfiltered.
    """
    conn = get_db_connection()
    node_rows = [dict(r) for r in conn.execute("SELECT * FROM graph_nodes").fetchall()]
    edge_rows = [dict(r) for r in conn.execute("SELECT * FROM graph_edges").fetchall()]
    inv_count = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
    node_links = conn.execute("SELECT node_id, investigation_id FROM graph_node_investigations").fetchall()
    edge_links = conn.execute("SELECT edge_id, investigation_id FROM graph_edge_investigations").fetchall()
    conn.close()

    node_invs: Dict[str, set[str]] = {}
    node_provenance: Dict[str, List[Dict[str, Any]]] = {}
    for row in node_links:
        node_invs.setdefault(row["node_id"], set()).add(row["investigation_id"])
    seen: Dict[str, Dict[str, Any]] = {}
    for node in node_rows:
        seen.setdefault(node["id"], node)
        if node.get("investigation_id"):
            node_invs.setdefault(node["id"], set()).add(node["investigation_id"])
        try:
            node_meta = json.loads(node.get("metadata_json") or "{}")
        except Exception:
            node_meta = {}
        node_provenance.setdefault(node["id"], []).append({
            "investigation_id": node.get("investigation_id"),
            "evidence_quote": node_meta.get("evidence_quote", ""),
        })
    for node_id, node in seen.items():
        meta = json.loads(node.get("metadata_json") or "{}")
        meta["source_investigations"] = sorted(node_invs.get(node_id, set()))
        meta["provenance"] = node_provenance.get(node_id, [])
        node["metadata_json"] = json.dumps(meta)

    edge_invs: Dict[str, set[str]] = {}
    for row in edge_links:
        edge_invs.setdefault(row["edge_id"], set()).add(row["investigation_id"])
    grouped_edges: Dict[tuple, Dict[str, Any]] = {}
    for edge in edge_rows:
        key = (edge["source"], edge["target"], edge["edge_type"])
        provenance = {
            "edge_id": edge["id"],
            "investigations": sorted(edge_invs.get(edge["id"], set()) | ({edge["investigation_id"]} if edge.get("investigation_id") else set())),
            "evidence_quote": edge.get("evidence_quote", ""),
            "confidence": edge.get("confidence", 1.0),
            "review_status": edge.get("review_status", "UNREVIEWED"),
        }
        if key not in grouped_edges:
            grouped_edges[key] = dict(edge)
            grouped_edges[key]["_provenance"] = [provenance]
        else:
            grouped_edges[key]["_provenance"].append(provenance)
            grouped_edges[key]["confidence"] = max(float(grouped_edges[key].get("confidence") or 0), float(edge.get("confidence") or 0))
    for edge in grouped_edges.values():
        edge["basis"] = json.dumps({"basis": "global_canonical_merge", "provenance": edge.pop("_provenance")})
    return {
        "investigation": {"id": "global", "query": "Global view — all investigations"},
        "graph_elements": _to_canonical_graph_elements(list(seen.values()), list(grouped_edges.values())),
        "investigation_count": inv_count,
    }


def get_investigation_summary(inv_id: str) -> Dict[str, Any]:
    conn = get_db_connection()
    inv = conn.execute("SELECT * FROM investigations WHERE id = ?", (inv_id,)).fetchone()
    if not inv:
        conn.close()
        return {}
    
    pages = [dict(r) for r in conn.execute("SELECT * FROM onion_pages WHERE investigation_id = ?", (inv_id,)).fetchall()]
    actors = [dict(r) for r in conn.execute("SELECT * FROM threat_actors WHERE investigation_id = ?", (inv_id,)).fetchall()]
    idents = [dict(r) for r in conn.execute("""
        SELECT i.*, p.url as page_url 
        FROM identifiers i 
        LEFT JOIN onion_pages p ON i.page_id = p.id 
        WHERE i.investigation_id = ?
    """, (inv_id,)).fetchall()]
    nodes = _canonical_nodes_for_investigation(conn, inv_id)
    edges = _canonical_edges_for_investigation(conn, inv_id)
    conn.close()

    # Format nodes & edges for Cytoscape.js onto the canonical 4x4 schema,
    # ensuring no orphaned edges break rendering. Legacy junk node/edge types
    # (asset paths, MENTIONS, co-occurrence) are excluded here; the raw rows
    # remain in the DB evidence tables.
    cy_elements = _to_canonical_graph_elements(nodes, edges)

    return {
        "investigation": dict(inv),
        "pages": pages,
        "threat_actors": actors,
        "identifiers": idents,
        "graph_elements": cy_elements,
    }


def record_search_run(
    investigation_id: str,
    provider: str,
    query: str,
    status: str = "COMPLETED",
    started_at: Optional[str] = None,
    finished_at: Optional[str] = None,
) -> str:
    import uuid
    run_id = f"run_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    s_at = started_at or now
    f_at = finished_at or now
    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT INTO search_runs (id, investigation_id, provider, query, status, started_at, finished_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (run_id, investigation_id, provider, query, status, s_at, f_at))
    conn.close()
    return run_id


def insert_search_hits(investigation_id: str, search_run_id: str, hits: List[Dict[str, Any]]) -> int:
    import uuid
    if not hits:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection()
    inserted = 0
    with conn:
        for h in hits:
            hit_id = f"hit_{uuid.uuid4().hex[:8]}"
            conn.execute("""
                INSERT INTO search_hits (id, investigation_id, search_run_id, provider, query, onion_url, title, snippet, score, first_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                hit_id,
                investigation_id,
                search_run_id,
                h.get("provider", "unknown"),
                h.get("query", ""),
                h.get("url", ""),
                h.get("title", ""),
                h.get("snippet", ""),
                float(h.get("score", 0.0)),
                h.get("discovered_at", now),
            ))
            inserted += 1
    conn.close()
    return inserted


def get_search_hits(investigation_id: str) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("""
        SELECT * FROM search_hits WHERE investigation_id = ? ORDER BY score DESC, first_seen DESC
    """, (investigation_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def insert_evidence_chunks(chunks: List[Dict[str, Any]]) -> int:
    if not chunks:
        return 0
    conn = get_db_connection()
    count = 0
    with conn:
        for c in chunks:
            page_id = c.get("page_id")
            if page_id and not conn.execute("SELECT 1 FROM onion_pages WHERE id = ?", (page_id,)).fetchone():
                page_id = None
            conn.execute("""
                INSERT OR REPLACE INTO evidence_chunks 
                (id, page_id, investigation_id, url, text, char_start, char_end, sha256, retrieved_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                c["chunk_id"],
                page_id,
                c.get("investigation_id", ""),
                c.get("url", ""),
                c["text"],
                c.get("char_start", 0),
                c.get("char_end", len(c["text"])),
                c["sha256"],
                c.get("retrieved_at", datetime.now(timezone.utc).isoformat()),
            ))
            count += 1
    conn.close()
    return count


def get_evidence_chunks(investigation_id: Optional[str] = None, page_id: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    if page_id:
        rows = conn.execute("SELECT * FROM evidence_chunks WHERE page_id = ? ORDER BY char_start ASC", (page_id,)).fetchall()
    elif investigation_id:
        rows = conn.execute("SELECT * FROM evidence_chunks WHERE investigation_id = ? ORDER BY page_id, char_start ASC", (investigation_id,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM evidence_chunks LIMIT 100").fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# SQL Studio: Sessions, History, Schema Metadata & Read-Only Execution
# ---------------------------------------------------------------------------

def create_sql_session(title: str = "New Query Session", opencode_session_id: Optional[str] = None, db_path: Optional[Path] = None) -> Dict[str, Any]:
    import uuid
    sid = f"sqs_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    with conn:
        conn.execute("""
            INSERT INTO sql_sessions (id, title, opencode_session_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (sid, title, opencode_session_id, now, now))
    conn.close()
    return {
        "id": sid,
        "title": title,
        "opencode_session_id": opencode_session_id,
        "created_at": now,
        "updated_at": now,
    }


def list_sql_sessions(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    rows = conn.execute("""
        SELECT s.*, COUNT(h.id) as query_count, MAX(h.created_at) as last_query_at
        FROM sql_sessions s
        LEFT JOIN sql_history h ON s.id = h.session_id
        GROUP BY s.id
        ORDER BY s.updated_at DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_sql_session(session_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    row = conn.execute("SELECT * FROM sql_sessions WHERE id = ?", (session_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def update_sql_session_title(session_id: str, title: str, db_path: Optional[Path] = None) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.execute("""
            UPDATE sql_sessions SET title = ?, updated_at = ? WHERE id = ?
        """, (title, now, session_id))
        updated = cursor.rowcount > 0
    conn.close()
    return updated


def delete_sql_session(session_id: str, db_path: Optional[Path] = None) -> bool:
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.execute("DELETE FROM sql_sessions WHERE id = ?", (session_id,))
        deleted = cursor.rowcount > 0
    conn.close()
    return deleted


def record_sql_history(
    session_id: str,
    query: str,
    source: str = "user",
    status: str = "SUCCESS",
    latency_ms: float = 0.0,
    row_count: int = 0,
    db_path: Optional[Path] = None,
) -> str:
    import uuid
    hid = f"sqh_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    with conn:
        conn.execute("""
            INSERT INTO sql_history (id, session_id, query, source, status, latency_ms, row_count, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (hid, session_id, query, source, status, latency_ms, row_count, now))
        conn.execute("UPDATE sql_sessions SET updated_at = ? WHERE id = ?", (now, session_id))
    conn.close()
    return hid


def get_sql_history(session_id: str, limit: int = 50, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    rows = conn.execute("""
        SELECT * FROM sql_history WHERE session_id = ? ORDER BY created_at DESC LIMIT ?
    """, (session_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_schema_metadata(db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Inspects all tables and columns from sqlite_master and PRAGMA table_info."""
    conn = get_db_connection(db_path)
    table_rows = conn.execute("""
        SELECT name FROM sqlite_master 
        WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
        ORDER BY name ASC
    """).fetchall()

    tables = []
    for (t_name,) in table_rows:
        col_rows = conn.execute(f"PRAGMA table_info({t_name})").fetchall()
        count_row = conn.execute(f"SELECT COUNT(*) FROM {t_name}").fetchone()
        row_count = count_row[0] if count_row else 0
        columns = [
            {
                "cid": c["cid"],
                "name": c["name"],
                "type": c["type"] or "TEXT",
                "notnull": bool(c["notnull"]),
                "dflt_value": c["dflt_value"],
                "pk": bool(c["pk"]),
            }
            for c in col_rows
        ]
        tables.append({
            "table_name": t_name,
            "row_count": row_count,
            "columns": columns,
        })
    conn.close()
    return {"tables": tables, "total_tables": len(tables)}


def execute_readonly_sql(
    query: str,
    max_rows: int = 500,
    timeout_sec: float = 5.0,
    db_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Safely executes an arbitrary read-only SQL query against SQLite."""
    import time
    start_time = time.monotonic()

    # 1. Clean and normalize query
    raw_query = query.strip()
    if not raw_query:
        return {"success": False, "error": "Query cannot be empty", "latency_ms": 0.0}

    # Strip SQL single-line and multi-line comments
    cleaned = re.sub(r'--[^\n]*', '', raw_query)
    cleaned = re.sub(r'/\*.*?\*/', '', cleaned, flags=re.DOTALL).strip()
    if not cleaned:
        return {"success": False, "error": "Query contains no executable statements", "latency_ms": 0.0}

    # 2. Check for multiple statements (semicolon outside quotes)
    parts = [p.strip() for p in cleaned.split(";") if p.strip()]
    if len(parts) > 1:
        return {
            "success": False,
            "error": "Multi-statement queries are strictly disallowed for security reasons. Run one statement at a time.",
            "latency_ms": 0.0,
        }
    exec_sql = parts[0]

    # 3. Guard allowed command prefixes
    tokens = exec_sql.split()
    first_token = tokens[0].upper()
    if first_token not in ("SELECT", "WITH", "EXPLAIN", "PRAGMA"):
        return {
            "success": False,
            "error": f"Security restriction: Only SELECT, WITH, EXPLAIN, and PRAGMA table_info queries are allowed. '{first_token}' is forbidden.",
            "latency_ms": 0.0,
        }

    if first_token == "PRAGMA":
        pragma_name = tokens[1].lower() if len(tokens) > 1 else ""
        if not any(pragma_name.startswith(p) for p in ("table_info", "table_xinfo")):
            return {
                "success": False,
                "error": f"Security restriction: Only PRAGMA table_info queries are permitted.",
                "latency_ms": 0.0,
            }

    # 4. Check destructive keyword tokens
    destructive_keywords = {
        "DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "ATTACH", "DETACH",
        "CREATE", "REPLACE", "VACUUM", "TRUNCATE", "REINDEX"
    }
    word_tokens = {w.upper() for w in re.findall(r'\b[A-Za-z_]+\b', exec_sql)}
    found_forbidden = word_tokens.intersection(destructive_keywords)
    if found_forbidden:
        return {
            "success": False,
            "error": f"Security restriction: Destructive keyword(s) detected: {', '.join(sorted(found_forbidden))}. Modifying the database is forbidden.",
            "latency_ms": 0.0,
        }

    # 5. Open connection with URI read-only flag
    target = db_path or (Path(os.environ["JANE_DB_PATH"]) if os.environ.get("JANE_DB_PATH") else DB_PATH)
    if is_test_environment() and not os.environ.get("JANE_ALLOW_PROD_DB_IN_TEST"):
        try:
            if target.resolve() == DEFAULT_DB_PATH.resolve():
                raise RuntimeError(
                    f"TEST ISOLATION VIOLATION: Test process attempted to open production database at {target}!"
                )
        except OSError:
            pass

    target.parent.mkdir(parents=True, exist_ok=True)
    uri_path = target.resolve().as_posix()
    if not uri_path.startswith("/"):
        uri_path = "/" + uri_path
    uri = f"file:{uri_path}?mode=ro"

    conn = None
    try:
        conn = sqlite3.connect(uri, uri=True, timeout=timeout_sec)
        conn.row_factory = sqlite3.Row

        # Execution timeout via progress handler
        def _timeout_check():
            if time.monotonic() - start_time > timeout_sec:
                return 1  # Raises OperationalError: interrupted
            return 0

        conn.set_progress_handler(_timeout_check, 1000)

        cursor = conn.cursor()
        cursor.execute(exec_sql)

        columns = [desc[0] for desc in cursor.description] if cursor.description else []
        fetched = cursor.fetchmany(max_rows + 1)
        truncated = len(fetched) > max_rows
        result_rows = []
        for r in fetched[:max_rows]:
            row_vals = []
            for v in r:
                if isinstance(v, (bytes, bytearray)):
                    row_vals.append(v.hex())
                else:
                    row_vals.append(v)
            result_rows.append(row_vals)

        elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
        return {
            "success": True,
            "columns": columns,
            "rows": result_rows,
            "row_count": len(result_rows),
            "truncated": truncated,
            "latency_ms": elapsed_ms,
        }
    except Exception as exc:
        elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
        return {
            "success": False,
            "error": str(exc),
            "latency_ms": elapsed_ms,
        }
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def update_sql_session_opencode_id(session_id: str, opencode_session_id: str, db_path: None = None) -> bool:
    now = datetime.now(timezone.utc).isoformat()
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.execute(
            "UPDATE sql_sessions SET opencode_session_id = ?, updated_at = ? WHERE id = ?",
            (opencode_session_id, now, session_id)
        )
        updated = cursor.rowcount > 0
    conn.close()
    return updated


# ============================================================================
# Query Dashboard & Read-Only Agent Interface
# ============================================================================

def validate_select_query(sql: str) -> tuple[bool, Optional[str]]:
    """Validate that query is a single, clean SELECT statement."""
    cleaned = (sql or "").strip()
    if not cleaned:
        return False, "Query cannot be empty"

    # Reject multi-statements
    no_trailing = re.sub(r";\s*$", "", cleaned)
    if ";" in no_trailing:
        return False, "Security restriction: Multiple SQL statements are not permitted"

    # Reject forbidden DDL/DML keywords as whole words
    forbidden = [
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
        "ATTACH", "DETACH", "PRAGMA", "VACUUM", "REINDEX", "REPLACE",
        "TRUNCATE", "GRANT", "REVOKE"
    ]
    pattern = r"\b(" + "|".join(forbidden) + r")\b"
    match = re.search(pattern, cleaned, re.IGNORECASE)
    if match:
        return False, f"Security restriction: Forbidden SQL operation '{match.group(1).upper()}' is not permitted"

    # Must start with SELECT, WITH, or EXPLAIN
    first_word = cleaned.split()[0].upper()
    if first_word not in ("SELECT", "WITH", "EXPLAIN"):
        return False, f"Security restriction: Only SELECT queries are permitted (found '{first_word}')"

    return True, None


def inject_default_limit(sql: str, default_limit: int = 500) -> str:
    """Inject default LIMIT clause if query does not already specify one."""
    cleaned = sql.strip().rstrip(";")
    if not re.search(r"\bLIMIT\s+\d+", cleaned, re.IGNORECASE):
        return f"{cleaned} LIMIT {default_limit};"
    return f"{cleaned};"


def create_query_session(label: Optional[str] = None, session_id: Optional[str] = None, db_path: Optional[Path] = None) -> Dict[str, Any]:
    """Create a new query session in query_sessions table."""
    conn = get_db_connection(db_path)
    import uuid
    sid = session_id or f"qsession_{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    lbl = (label or "").strip() or f"Session {now_iso[:10]} {now_iso[11:16]}"
    with conn:
        conn.execute(
            "INSERT INTO query_sessions (id, label, created_at) VALUES (?, ?, ?)",
            (sid, lbl, now_iso)
        )
    conn.close()
    return {"id": sid, "label": lbl, "created_at": now_iso}


def list_query_sessions(db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """List all query sessions ordered by newest first with query count."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT 
            s.id, 
            s.label, 
            s.created_at,
            COUNT(l.id) AS query_count,
            MAX(l.ran_at) AS last_query_at
        FROM query_sessions s
        LEFT JOIN query_log l ON l.session_id = s.id
        GROUP BY s.id, s.label, s.created_at
        ORDER BY s.created_at DESC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def get_query_session(session_id: str, db_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Retrieve single query session by ID."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, label, created_at FROM query_sessions WHERE id = ?", (session_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_query_session_history(session_id: str, db_path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Retrieve full query history for a query session."""
    conn = get_db_connection(db_path)
    cur = conn.cursor()
    cur.execute("""
        SELECT id, session_id, natural_language_question, generated_sql, executed, row_count, error_message, ran_at
        FROM query_log
        WHERE session_id = ?
        ORDER BY ran_at ASC
    """, (session_id,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


def record_query_log(
    session_id: Optional[str],
    natural_language_question: Optional[str],
    generated_sql: str,
    executed: bool,
    row_count: int,
    error_message: Optional[str],
    query_id: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> str:
    """Log query execution or rejection to query_log table."""
    conn = get_db_connection(db_path)
    import uuid
    qid = query_id or f"qry_{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()
    sid = session_id
    with conn:
        if sid:
            s_row = conn.execute("SELECT id FROM query_sessions WHERE id = ?", (sid,)).fetchone()
            if not s_row:
                conn.execute(
                    "INSERT INTO query_sessions (id, label, created_at) VALUES (?, ?, ?)",
                    (sid, "Default Session", now_iso)
                )
        else:
            sid = "default_session"
            conn.execute(
                "INSERT OR IGNORE INTO query_sessions (id, label, created_at) VALUES (?, ?, ?)",
                (sid, "General Queries", now_iso)
            )

        conn.execute(
            """
            INSERT INTO query_log (
                id, session_id, question, sql_query, natural_language_question,
                generated_sql, executed, row_count, error_message, ran_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (qid, sid, natural_language_question, generated_sql, natural_language_question,
             generated_sql, 1 if executed else 0, row_count, error_message, now_iso)
        )
    conn.close()
    return qid


def execute_query_readonly(
    sql: str,
    session_id: Optional[str] = None,
    question: Optional[str] = None,
    default_limit: int = 500,
    db_path: Optional[Path] = None,
    timeout_sec: float = 10.0,
) -> Dict[str, Any]:
    """
    Executes a SELECT query against SQLite in enforced read-only mode.
    Two independent enforcement layers:
    1. Validation check rejects multi-statements, non-SELECTs, and DDL/DML keywords.
    2. Connection opened with URI mode=ro at the SQLite driver/OS level.
    Logs every execution or rejection to query_log.
    """
    import uuid
    start_time = time.perf_counter()
    now_iso = datetime.now(timezone.utc).isoformat()
    query_id = f"qry_{uuid.uuid4().hex[:12]}"

    target = db_path or (Path(os.environ["JANE_DB_PATH"]) if os.environ.get("JANE_DB_PATH") else DB_PATH)

    # 1. Validation check
    is_valid, error_msg = validate_select_query(sql)
    if not is_valid:
        latency = (time.perf_counter() - start_time) * 1000.0
        record_query_log(session_id, question, sql, executed=False, row_count=0, error_message=error_msg, query_id=query_id, db_path=target)
        return {
            "success": False,
            "query_id": query_id,
            "sql": sql,
            "columns": [],
            "rows": [],
            "row_count": 0,
            "latency_ms": round(latency, 2),
            "error": error_msg,
        }

    # 2. Inject default limit
    final_sql = inject_default_limit(sql, default_limit)

    # 3. Connection-level enforcement with URI mode=ro
    uri_path = target.resolve().as_posix()
    if not uri_path.startswith("/"):
        uri_path = "/" + uri_path
    uri = f"file:{uri_path}?mode=ro"

    ro_conn = None
    try:
        ro_conn = sqlite3.connect(uri, uri=True, timeout=timeout_sec)
        ro_conn.row_factory = sqlite3.Row

        # Timeout guard
        def _timeout_check():
            if time.perf_counter() - start_time > timeout_sec:
                return 1
            return 0
        ro_conn.set_progress_handler(_timeout_check, 1000)

        cur = ro_conn.cursor()
        cur.execute(final_sql)

        columns = [d[0] for d in cur.description] if cur.description else []
        fetched = cur.fetchall()
        rows = []
        for r in fetched:
            row_vals = []
            for v in r:
                if isinstance(v, (bytes, bytearray)):
                    row_vals.append(v.hex())
                else:
                    row_vals.append(v)
            rows.append(row_vals)

        row_count = len(rows)
        latency = (time.perf_counter() - start_time) * 1000.0
        ro_conn.close()
        ro_conn = None

        record_query_log(session_id, question, final_sql, executed=True, row_count=row_count, error_message=None, query_id=query_id, db_path=target)

        return {
            "success": True,
            "query_id": query_id,
            "sql": final_sql,
            "columns": columns,
            "rows": rows,
            "row_count": row_count,
            "latency_ms": round(latency, 2),
            "error": None,
        }
    except Exception as exc:
        latency = (time.perf_counter() - start_time) * 1000.0
        err = str(exc)
        record_query_log(session_id, question, final_sql, executed=False, row_count=0, error_message=err, query_id=query_id, db_path=target)
        return {
            "success": False,
            "query_id": query_id,
            "sql": final_sql,
            "columns": [],
            "rows": [],
            "row_count": 0,
            "latency_ms": round(latency, 2),
            "error": err,
        }
    finally:
        if ro_conn:
            try:
                ro_conn.close()
            except Exception:
                pass


def get_curated_schema_description() -> str:
    """Returns curated read-only views schema description for AI agent prompting."""
    return """
The following curated SQL views are available for read-only threat intelligence queries:

1. v_actor_summary:
   - actor_id (TEXT): Unique actor identifier
   - primary_handle (TEXT): Canonical actor handle
   - category (TEXT): Threat category (e.g., Financial Fraud / Carding, Cybercrime)
   - attribution_confidence (REAL): Confidence score between 0.0 and 1.0
   - first_seen (TEXT), last_seen (TEXT): ISO timestamps
   - alias_count (INTEGER): Number of known alternate handles/aliases
   - marketplace_count (INTEGER): Number of distinct marketplaces operated on
   - product_count (INTEGER): Number of distinct illicit products sold

2. v_actor_identifiers:
   - actor_id (TEXT): Unique actor identifier
   - primary_handle (TEXT): Canonical handle
   - identifier_id (TEXT): Identifier record ID
   - identifier_type (TEXT): IOC type ('wallet', 'pgp', 'handle', 'email', 'phone', 'ip')
   - identifier_value (TEXT): Address, fingerprint, handle string, etc.
   - is_shared (INTEGER): 1 if identifier connects 2+ distinct threat actors, 0 otherwise
   - confidence (REAL): Extraction confidence
   - evidence_quote (TEXT): Source snippet from page

3. v_marketplace_activity:
   - marketplace_id (TEXT): Marketplace ID
   - onion_domain (TEXT): .onion domain
   - display_name (TEXT): Marketplace title or site name
   - category (TEXT): Market classification
   - actor_count (INTEGER): Active threat actors observed on this market
   - infrastructure_findings_count (INTEGER): Total infrastructure artifacts
   - first_seen (TEXT), last_seen (TEXT): ISO timestamps

4. v_infrastructure_findings:
   - finding_id (TEXT): Finding record ID
   - marketplace_id (TEXT): Associated marketplace ID
   - onion_domain (TEXT): Associated .onion domain
   - finding_type (TEXT): 'banner', 'favicon_hash', 'ip_leak', 'ssl_cert'
   - value (TEXT): Server banner, mmh3 hash, clearweb IP address
   - evidence_quote (TEXT): Forensic attribution note
   - found_at (TEXT): Timestamp

5. v_actor_trust_links:
   - actor_id (TEXT), actor_handle (TEXT): Source actor
   - trusted_actor_id (TEXT), trusted_actor_handle (TEXT): Trusted/vouched actor
   - confidence (REAL): Trust confidence
   - evidence_quote (TEXT): Evidence quote containing explicit vouch
   - created_at (TEXT): Timestamp

6. v_actor_products:
   - actor_id (TEXT), primary_handle (TEXT): Threat actor
   - product_id (TEXT), product_name (TEXT): Name of illicit product/commodity
   - product_category (TEXT): Product category
   - confidence (REAL): Attribution confidence
   - evidence_quote (TEXT): Source text

7. v_clearnet_accounts:
   - account_id (TEXT): Clearnet account record ID
   - actor_id (TEXT), primary_handle (TEXT): Threat actor
   - platform (TEXT): Platform name (e.g., GitHub, Telegram, Twitter)
   - value (TEXT): Username, profile URL, or handle
   - evidence_quote (TEXT): OSINT pivot note

Rules for generating SQL:
- Only generate single SELECT queries.
- Do NOT use INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, or PRAGMA.
- Query from the curated views above (e.g. v_actor_summary, v_actor_identifiers, v_marketplace_activity, etc.).
- Use standard SQLite functions.
"""
