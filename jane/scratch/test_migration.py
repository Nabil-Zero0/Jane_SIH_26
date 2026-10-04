import os
import shutil
import sqlite3
import urllib.parse
from datetime import datetime, timezone
import sys
import uuid
import re
from pathlib import Path

repo_root = Path(r'c:\Users\thang\Downloads\Jane_SIH_26\jane')
if str(repo_root.parent) not in sys.path:
    sys.path.insert(0, str(repo_root.parent))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from jane.backend.graph.builder_model import (
    NON_ENTITY_BLOCKLIST,
    is_blocklisted,
    normalize_handle,
    validate_actor_handle,
    handles_fuzzy_match,
    TRUST_EVIDENCE_KEYWORDS,
)

test_db_path = Path(r'c:\Users\thang\Downloads\Jane_SIH_26\jane\data\test_migration_jane.db')
prod_db_path = Path(r'c:\Users\thang\Downloads\Jane_SIH_26\jane\data\jane.db')

# Copy prod to test
shutil.copy2(prod_db_path, test_db_path)
print(f"Copied prod DB to {test_db_path}")

conn = sqlite3.connect(test_db_path)
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# 1. Create target tables
schema_sql = """
-- 1. actors
CREATE TABLE IF NOT EXISTS actors (
    id TEXT PRIMARY KEY,
    primary_handle TEXT NOT NULL UNIQUE,
    category TEXT,
    attribution_confidence REAL DEFAULT 1.0,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 2. actor_aliases
CREATE TABLE IF NOT EXISTS actor_aliases (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    alias_handle TEXT NOT NULL,
    source_investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    needs_review INTEGER DEFAULT 0,
    created_at TEXT NOT NULL
);

-- 3. marketplaces
CREATE TABLE IF NOT EXISTS marketplaces (
    id TEXT PRIMARY KEY,
    onion_domain TEXT NOT NULL UNIQUE,
    display_name TEXT,
    category TEXT,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT NOT NULL
);

-- 4. actor_marketplace
CREATE TABLE IF NOT EXISTS actor_marketplace (
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    marketplace_id TEXT NOT NULL REFERENCES marketplaces(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    first_seen TEXT,
    PRIMARY KEY (actor_id, marketplace_id)
);

-- 5. products
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    category TEXT,
    created_at TEXT NOT NULL
);

-- 6. actor_product
CREATE TABLE IF NOT EXISTS actor_product (
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    first_seen TEXT,
    PRIMARY KEY (actor_id, product_id)
);

-- 7. actor_trust
CREATE TABLE IF NOT EXISTS actor_trust (
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    trusted_actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (actor_id, trusted_actor_id)
);

-- 8. clearnet_accounts
CREATE TABLE IF NOT EXISTS clearnet_accounts (
    id TEXT PRIMARY KEY,
    actor_id TEXT REFERENCES actors(id) ON DELETE CASCADE,
    platform TEXT,
    value TEXT NOT NULL,
    evidence_quote TEXT,
    created_at TEXT NOT NULL
);

-- 9. actor_clearnet_account
CREATE TABLE IF NOT EXISTS actor_clearnet_account (
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    clearnet_account_id TEXT NOT NULL REFERENCES clearnet_accounts(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    PRIMARY KEY (actor_id, clearnet_account_id)
);

-- 10. canonical_identifiers
CREATE TABLE IF NOT EXISTS canonical_identifiers (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    is_shared INTEGER DEFAULT 0,
    evidence_quote TEXT,
    confidence REAL DEFAULT 1.0,
    investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);

-- 11. infrastructure_findings
CREATE TABLE IF NOT EXISTS infrastructure_findings (
    id TEXT PRIMARY KEY,
    marketplace_id TEXT REFERENCES marketplaces(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    evidence_quote TEXT,
    source_page_id TEXT REFERENCES onion_pages(id) ON DELETE CASCADE,
    found_at TEXT NOT NULL
);

-- 12. evidence_quotes
CREATE TABLE IF NOT EXISTS evidence_quotes (
    id TEXT PRIMARY KEY,
    page_id TEXT REFERENCES onion_pages(id) ON DELETE CASCADE,
    quote_text TEXT NOT NULL,
    extracted_fact_type TEXT NOT NULL,
    extracted_fact_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 13. entity_investigations
CREATE TABLE IF NOT EXISTS entity_investigations (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    PRIMARY KEY (entity_type, entity_id, investigation_id)
);

-- 14. query_sessions
CREATE TABLE IF NOT EXISTS query_sessions (
    id TEXT PRIMARY KEY,
    label TEXT,
    created_at TEXT NOT NULL
);

-- 15. query_log
CREATE TABLE IF NOT EXISTS query_log (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES query_sessions(id) ON DELETE CASCADE,
    natural_language_question TEXT,
    generated_sql TEXT NOT NULL,
    executed INTEGER NOT NULL DEFAULT 1,
    row_count INTEGER,
    error_message TEXT,
    ran_at TEXT NOT NULL
);

-- 16. migration_notes
CREATE TABLE IF NOT EXISTS migration_notes (
    id TEXT PRIMARY KEY,
    source_table TEXT NOT NULL,
    source_id TEXT,
    reason TEXT NOT NULL,
    details TEXT,
    logged_at TEXT NOT NULL
);
"""
cur.executescript(schema_sql)
print("Target tables created.")

# Helper to log migration notes
now_iso = datetime.now(timezone.utc).isoformat()
def log_note(source_tbl, src_id, reason, details):
    cur.execute(
        "INSERT INTO migration_notes (id, source_table, source_id, reason, details, logged_at) VALUES (?, ?, ?, ?, ?, ?)",
        (f"note_{uuid.uuid4().hex[:12]}", source_tbl, src_id, reason, details, now_iso)
    )

# 2. Migrate actors & actor_aliases
print("Migrating actors...")
cur.execute("SELECT * FROM threat_actors")
old_actors = cur.fetchall()

# Map old actor_id -> new actor_id
actor_map = {}

for a in old_actors:
    aid = a["id"]
    handle = (a["primary_handle"] or "").strip()
    inv_id = a["investigation_id"]
    cat = a["threat_category"] or "Unclassified"
    conf = float(a["confidence"] or 1.0)
    created = a["created_at"] or now_iso
    
    if not handle or is_blocklisted(handle):
        log_note("threat_actors", aid, "BLOCKLIST_EXCLUDED", f"Excluded blocklisted handle: {handle!r}")
        continue
        
    norm = normalize_handle(handle)
    
    # Check if primary_handle exists in actors
    cur.execute("SELECT id, primary_handle FROM actors WHERE primary_handle = ?", (handle,))
    existing = cur.fetchone()
    
    if existing:
        target_id = existing["id"]
        actor_map[aid] = target_id
        # Add alias if different designated_id
        desig = (a["designated_id"] or "").strip()
        if desig and desig != handle:
            cur.execute(
                "INSERT OR IGNORE INTO actor_aliases (id, actor_id, alias_handle, source_investigation_id, confidence, needs_review, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"alias_{uuid.uuid4().hex[:12]}", target_id, desig, inv_id, conf, 0, created)
            )
    else:
        # Check fuzzy match
        cur.execute("SELECT id, primary_handle FROM actors")
        all_acts = cur.fetchall()
        fuzzy_target = None
        for other_id, other_handle in all_acts:
            if handles_fuzzy_match(handle, other_handle):
                fuzzy_target = (other_id, other_handle)
                break
                
        new_actor_id = f"act_{norm}" if norm else f"act_{uuid.uuid4().hex[:8]}"
        cur.execute(
            "INSERT INTO actors (id, primary_handle, category, attribution_confidence, first_seen, last_seen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (new_actor_id, handle, cat, conf, created, created, created, created)
        )
        actor_map[aid] = new_actor_id
        
        if fuzzy_target:
            # Create a flagged alias for human review as per spec
            cur.execute(
                "INSERT INTO actor_aliases (id, actor_id, alias_handle, source_investigation_id, confidence, needs_review, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"alias_{uuid.uuid4().hex[:12]}", fuzzy_target[0], handle, inv_id, 0.55, 1, created)
            )
            log_note("threat_actors", aid, "FUZZY_MATCH_FLAGGED", f"Handle {handle!r} fuzzy matches {fuzzy_target[1]!r} — flagged with needs_review=1")

        if inv_id:
            cur.execute(
                "INSERT OR IGNORE INTO entity_investigations (entity_type, entity_id, investigation_id) VALUES (?, ?, ?)",
                ("actor", new_actor_id, inv_id)
            )

# Ingest canonical actors from graph_nodes as well
cur.execute("SELECT id, label, node_type, metadata_json, investigation_id FROM graph_nodes WHERE node_type IN ('Actor', 'ThreatActor', 'THREAT_ACTOR')")
for gn in cur.fetchall():
    gid = gn["id"]
    label = (gn["label"] or "").strip()
    inv_id = gn["investigation_id"]
    meta = {}
    try:
        meta = json.loads(gn["metadata_json"] or "{}")
    except Exception:
        pass
    handle = (meta.get("handle") or label).strip()
    cat = meta.get("category") or "Cybercrime"
    quote = meta.get("evidence_quote") or ""
    
    if not handle or is_blocklisted(handle):
        log_note("graph_nodes", gid, "BLOCKLIST_EXCLUDED", f"Excluded blocklisted graph node handle: {handle!r}")
        continue
        
    norm = normalize_handle(handle)
    cur.execute("SELECT id FROM actors WHERE primary_handle = ? OR id = ?", (handle, f"act_{norm}"))
    existing = cur.fetchone()
    if existing:
        actor_map[gid] = existing["id"]
    else:
        new_actor_id = f"act_{norm}"
        cur.execute(
            "INSERT OR IGNORE INTO actors (id, primary_handle, category, attribution_confidence, first_seen, last_seen, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (new_actor_id, handle, cat, 0.9, now_iso, now_iso, now_iso, now_iso)
        )
        actor_map[gid] = new_actor_id
        if inv_id:
            cur.execute(
                "INSERT OR IGNORE INTO entity_investigations (entity_type, entity_id, investigation_id) VALUES (?, ?, ?)",
                ("actor", new_actor_id, inv_id)
            )

# 3. Migrate marketplaces
print("Migrating marketplaces...")
cur.execute("SELECT url, investigation_id, created_at FROM onion_pages")
pages = cur.fetchall()

def extract_domain(u):
    try:
        parsed = urllib.parse.urlparse(u)
        netloc = parsed.netloc or u
        m = re.search(r'([a-z2-7]{16,56}\.onion)', netloc.lower())
        if m:
            return m.group(1)
        return netloc.split(':')[0]
    except Exception:
        return u[:50]

domain_map = {}
for p in pages:
    url = p["url"]
    inv_id = p["investigation_id"]
    created = p["created_at"] or now_iso
    domain = extract_domain(url)
    if domain:
        cur.execute("SELECT id FROM marketplaces WHERE onion_domain = ?", (domain,))
        m_row = cur.fetchone()
        if not m_row:
            mid = f"mkt_{normalize_handle(domain)[:16]}"
            cur.execute(
                "INSERT INTO marketplaces (id, onion_domain, display_name, category, first_seen, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (mid, domain, domain, "Dark Market / Hidden Service", created, created, created)
            )
            domain_map[domain] = mid
            if inv_id:
                cur.execute(
                    "INSERT OR IGNORE INTO entity_investigations (entity_type, entity_id, investigation_id) VALUES (?, ?, ?)",
                    ("marketplace", mid, inv_id)
                )

# 4. Migrate identifiers
print("Migrating identifiers...")
cur.execute("SELECT * FROM identifiers")
old_idents = cur.fetchall()

type_norm_map = {
    "BITCOIN_ADDRESS": "wallet",
    "ETHEREUM_ADDRESS": "wallet",
    "MONERO_ADDRESS": "wallet",
    "SOLANA_ADDRESS": "wallet",
    "LITECOIN_ADDRESS": "wallet",
    "CryptoWallet": "wallet",
    "PGP_KEY_BLOCK": "pgp",
    "PGP_KEY": "pgp",
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "MessagingHandle": "handle",
    "TELEGRAM_HANDLE": "handle",
    "WIRE_HANDLE": "handle",
    "IP_ADDRESS": "ip",
    "LEAKED_IP": "ip",
}

for ident in old_idents:
    iid = ident["id"]
    itype = ident["type"]
    val = (ident["value"] or "").strip()
    old_aid = ident["actor_id"]
    pid = ident["page_id"]
    inv_id = ident["investigation_id"]
    quote = ident["evidence_quote"]
    conf = float(ident["confidence"] or 1.0)
    created = ident["first_seen"] or now_iso
    
    # Check blocklist
    if is_blocklisted(val):
        log_note("identifiers", iid, "BLOCKLIST_EXCLUDED", f"Excluded blocklisted identifier: {itype}:{val}")
        continue
        
    # Check ONION_URL
    if itype == "ONION_URL":
        domain = extract_domain(val)
        if domain:
            cur.execute("SELECT id FROM marketplaces WHERE onion_domain = ?", (domain,))
            m_row = cur.fetchone()
            if not m_row:
                mid = f"mkt_{normalize_handle(domain)[:16]}"
                cur.execute(
                    "INSERT INTO marketplaces (id, onion_domain, display_name, category, first_seen, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (mid, domain, domain, "Dark Market / Hidden Service", created, created, created)
                )
                if inv_id:
                    cur.execute(
                        "INSERT OR IGNORE INTO entity_investigations (entity_type, entity_id, investigation_id) VALUES (?, ?, ?)",
                        ("marketplace", mid, inv_id)
                    )
        log_note("identifiers", iid, "ROUTED_TO_MARKETPLACE", f"Routed ONION_URL {val} to marketplaces")
        continue

    # Check CommoditySold -> products
    if itype == "CommoditySold":
        pid = f"prod_{normalize_handle(val)[:24]}"
        cur.execute(
            "INSERT OR IGNORE INTO products (id, name, category, created_at) VALUES (?, ?, ?, ?)",
            (pid, val, "Illicit Good / Service", created)
        )
        if old_aid and old_aid in actor_map:
            act_id = actor_map[old_aid]
            cur.execute(
                "INSERT OR IGNORE INTO actor_product (actor_id, product_id, confidence, evidence_quote, first_seen) VALUES (?, ?, ?, ?, ?)",
                (act_id, pid, conf, quote, created)
            )
        log_note("identifiers", iid, "ROUTED_TO_PRODUCTS", f"Routed CommoditySold {val} to products")
        continue

    # Normalize type
    clean_type = type_norm_map.get(itype, itype.lower())
    mapped_aid = actor_map.get(old_aid) if old_aid else None
    if not mapped_aid:
        norm_val = normalize_handle(val)
        act_row = cur.execute("SELECT id FROM actors WHERE primary_handle = ? OR id = ?", (val, f"act_{norm_val}")).fetchone()
        if act_row:
            mapped_aid = act_row["id"]
    
    cur.execute(
        "INSERT OR IGNORE INTO canonical_identifiers (id, type, value, actor_id, is_shared, evidence_quote, confidence, investigation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (f"ident_{uuid.uuid4().hex[:12]}", clean_type, val, mapped_aid, 0, quote, conf, inv_id, created)
    )

# Compute is_shared
cur.execute("""
    UPDATE canonical_identifiers
    SET is_shared = 1
    WHERE value IN (
        SELECT value
        FROM canonical_identifiers
        WHERE actor_id IS NOT NULL
        GROUP BY value
        HAVING COUNT(DISTINCT actor_id) >= 2
    )
""")

# 4.5 Migrate ClearnetAccount nodes from graph_nodes
print("Migrating clearnet accounts...")
cur.execute("SELECT id, label, metadata_json, investigation_id FROM graph_nodes WHERE node_type = 'ClearnetAccount'")
for gn in cur.fetchall():
    gid = gn["id"]
    lbl = gn["label"]
    meta = {}
    try:
        meta = json.loads(gn["metadata_json"] or "{}")
    except Exception:
        pass
    site = meta.get("site_name", "")
    val = meta.get("url") or meta.get("handle") or lbl
    eq = meta.get("evidence_quote", "")
    cur.execute(
        "INSERT OR IGNORE INTO clearnet_accounts (id, actor_id, platform, value, evidence_quote, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (gid, None, site, val, eq, now_iso)
    )

# 4.6 Ingest canonical marketplaces from graph_nodes
cur.execute("SELECT id, label, metadata_json, investigation_id FROM graph_nodes WHERE node_type = 'Marketplace'")
for gn in cur.fetchall():
    gid = gn["id"]
    lbl = gn["label"]
    meta = {}
    try:
        meta = json.loads(gn["metadata_json"] or "{}")
    except Exception:
        pass
    m_name = meta.get("name_or_domain") or lbl
    domain = extract_domain(m_name)
    if domain:
        cur.execute("SELECT id FROM marketplaces WHERE onion_domain = ?", (domain,))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO marketplaces (id, onion_domain, display_name, category, first_seen, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (f"mkt_{normalize_handle(domain)[:16]}", domain, m_name, meta.get("category", "Dark Market"), now_iso, now_iso, now_iso)
            )

# 4.7 Ingest canonical products from graph_nodes
cur.execute("SELECT id, label, metadata_json, investigation_id FROM graph_nodes WHERE node_type = 'Product'")
for gn in cur.fetchall():
    gid = gn["id"]
    lbl = gn["label"]
    meta = {}
    try:
        meta = json.loads(gn["metadata_json"] or "{}")
    except Exception:
        pass
    p_name = meta.get("name") or lbl
    p_cat = meta.get("category", "Commodity")
    cur.execute("SELECT id FROM products WHERE name = ?", (p_name,))
    if not cur.fetchone():
        cur.execute(
            "INSERT INTO products (id, name, category, created_at) VALUES (?, ?, ?, ?)",
            (f"prod_{normalize_handle(p_name)[:24]}", p_name, p_cat, now_iso)
        )

# 5. Migrate graph edges to relationships
print("Migrating relationships...")
cur.execute("SELECT * FROM graph_edges")
edges = cur.fetchall()

def resolve_actor(val):
    if not val:
        return None
    val_norm = normalize_handle(val.replace("actor_", ""))
    row = cur.execute("SELECT id FROM actors WHERE id = ? OR id = ? OR primary_handle = ? OR primary_handle = ?", (val, f"act_{val_norm}", val, val_norm)).fetchone()
    if row:
        return row["id"]
    if val in actor_map:
        return actor_map[val]
    return None

def resolve_marketplace(val):
    if not val:
        return None
    domain = extract_domain(val.replace("market_", ""))
    row = cur.execute("SELECT id FROM marketplaces WHERE onion_domain = ? OR display_name = ? OR id = ?", (domain, val, val)).fetchone()
    return row["id"] if row else None

def resolve_product(val):
    if not val:
        return None
    row = cur.execute("SELECT id FROM products WHERE name = ? OR id = ?", (val, val)).fetchone()
    if row:
        return row["id"]
    norm = normalize_handle(val.replace("product_", ""))
    row = cur.execute("SELECT id FROM products WHERE id = ? OR name LIKE ?", (f"prod_{norm[:24]}", f"%{val}%")).fetchone()
    return row["id"] if row else None

for e in edges:
    eid = e["id"]
    etype = e["edge_type"]
    src = e["source"]
    tgt = e["target"]
    conf = float(e["confidence"] or 1.0)
    quote = e["evidence_quote"]
    inv_id = e["investigation_id"]

    # CLEARNET_ALIAS
    if etype == "CLEARNET_ALIAS":
        act_id = resolve_actor(src) or resolve_actor(tgt)
        ca_id = tgt if tgt.startswith("clearnet_") else (src if src.startswith("clearnet_") else None)
        if act_id and ca_id:
            cur.execute(
                "INSERT OR IGNORE INTO actor_clearnet_account (actor_id, clearnet_account_id, confidence, evidence_quote) VALUES (?, ?, ?, ?)",
                (act_id, ca_id, conf, quote)
            )
            cur.execute("UPDATE clearnet_accounts SET actor_id = ? WHERE id = ?", (act_id, ca_id))
        continue

    # OPERATES / OPERATES_ON
    if etype in ("OPERATES", "OPERATES_ON"):
        act_id = resolve_actor(src) or resolve_actor(tgt)
        mkt_id = resolve_marketplace(tgt) or resolve_marketplace(src)
        if act_id and mkt_id:
            cur.execute(
                "INSERT OR IGNORE INTO actor_marketplace (actor_id, marketplace_id, confidence, evidence_quote, first_seen) VALUES (?, ?, ?, ?, ?)",
                (act_id, mkt_id, conf, quote, now_iso)
            )
        continue

    # SELLS / OFFERS
    if etype in ("SELLS", "OFFERS"):
        act_id = resolve_actor(src) or resolve_actor(tgt)
        prd_id = resolve_product(tgt) or resolve_product(src)
        if act_id and prd_id:
            cur.execute(
                "INSERT OR IGNORE INTO actor_product (actor_id, product_id, confidence, evidence_quote, first_seen) VALUES (?, ?, ?, ?, ?)",
                (act_id, prd_id, conf, quote, now_iso)
            )
        continue

    # TRUST
    if etype in ("TRUST", "VOUCHED_BY") or any(kw in (quote or "").lower() for kw in TRUST_EVIDENCE_KEYWORDS):
        act1 = resolve_actor(src)
        act2 = resolve_actor(tgt)
        if act1 and act2 and act1 != act2:
            cur.execute(
                "INSERT OR IGNORE INTO actor_trust (actor_id, trusted_actor_id, confidence, evidence_quote, created_at) VALUES (?, ?, ?, ?, ?)",
                (act1, act2, conf, quote, now_iso)
            )
        continue

# 6. Migrate infrastructure findings
print("Migrating infrastructure findings...")
cur.execute("SELECT id, investigation_id, url, server_banner, favicon_mmh3, created_at FROM onion_pages")
opages = cur.fetchall()

for op in opages:
    pid = op["id"]
    url = op["url"]
    inv_id = op["investigation_id"]
    banner = op["server_banner"]
    fav = op["favicon_mmh3"]
    created = op["created_at"] or now_iso
    domain = extract_domain(url)
    mkt = cur.execute("SELECT id FROM marketplaces WHERE onion_domain = ?", (domain,)).fetchone()
    mid = mkt["id"] if mkt else None
    
    if banner:
        cur.execute(
            "INSERT OR IGNORE INTO infrastructure_findings (id, marketplace_id, type, value, evidence_quote, source_page_id, found_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (f"inf_{uuid.uuid4().hex[:12]}", mid, "banner", banner, f"Server banner from {url}", pid, created)
        )
    if fav:
        cur.execute(
            "INSERT OR IGNORE INTO infrastructure_findings (id, marketplace_id, type, value, evidence_quote, source_page_id, found_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (f"inf_{uuid.uuid4().hex[:12]}", mid, "favicon_hash", fav, f"Favicon mmh3 hash from {url}", pid, created)
        )

# IP leaks
cur.execute("SELECT ip_address, country_name, isp, enriched_at FROM ip_enrichment")
for ip_row in cur.fetchall():
    ip = ip_row["ip_address"]
    country = ip_row["country_name"] or ""
    isp = ip_row["isp"] or ""
    cur.execute(
        "INSERT OR IGNORE INTO infrastructure_findings (id, marketplace_id, type, value, evidence_quote, source_page_id, found_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (f"inf_{uuid.uuid4().hex[:12]}", None, "ip_leak", ip, f"Corroborated clearweb IP ({country}, {isp})", None, now_iso)
    )

# 7. Create curated views
views_sql = """
DROP VIEW IF EXISTS v_actor_summary;
CREATE VIEW v_actor_summary AS
SELECT 
    a.id AS actor_id,
    a.primary_handle,
    a.category,
    a.attribution_confidence,
    a.first_seen,
    a.last_seen,
    COUNT(DISTINCT aa.id) AS alias_count,
    COUNT(DISTINCT am.marketplace_id) AS marketplace_count,
    COUNT(DISTINCT ap.product_id) AS product_count
FROM actors a
LEFT JOIN actor_aliases aa ON aa.actor_id = a.id
LEFT JOIN actor_marketplace am ON am.actor_id = a.id
LEFT JOIN actor_product ap ON ap.actor_id = a.id
GROUP BY a.id, a.primary_handle, a.category, a.attribution_confidence, a.first_seen, a.last_seen;

DROP VIEW IF EXISTS v_actor_identifiers;
CREATE VIEW v_actor_identifiers AS
SELECT 
    a.id AS actor_id,
    a.primary_handle,
    ci.id AS identifier_id,
    ci.type AS identifier_type,
    ci.value AS identifier_value,
    ci.is_shared,
    ci.confidence,
    ci.evidence_quote
FROM actors a
JOIN canonical_identifiers ci ON ci.actor_id = a.id;

DROP VIEW IF EXISTS v_marketplace_activity;
CREATE VIEW v_marketplace_activity AS
SELECT 
    m.id AS marketplace_id,
    m.onion_domain,
    m.display_name,
    m.category,
    COUNT(DISTINCT am.actor_id) AS actor_count,
    COUNT(DISTINCT inf.id) AS infrastructure_findings_count,
    m.first_seen,
    m.last_seen
FROM marketplaces m
LEFT JOIN actor_marketplace am ON am.marketplace_id = m.id
LEFT JOIN infrastructure_findings inf ON inf.marketplace_id = m.id
GROUP BY m.id, m.onion_domain, m.display_name, m.category, m.first_seen, m.last_seen;

DROP VIEW IF EXISTS v_infrastructure_findings;
CREATE VIEW v_infrastructure_findings AS
SELECT 
    inf.id AS finding_id,
    inf.marketplace_id,
    m.onion_domain,
    inf.type AS finding_type,
    inf.value,
    inf.evidence_quote,
    inf.found_at
FROM infrastructure_findings inf
LEFT JOIN marketplaces m ON m.id = inf.marketplace_id;

DROP VIEW IF EXISTS v_actor_trust_links;
CREATE VIEW v_actor_trust_links AS
SELECT 
    t.actor_id,
    a1.primary_handle AS actor_handle,
    t.trusted_actor_id,
    a2.primary_handle AS trusted_actor_handle,
    t.confidence,
    t.evidence_quote,
    t.created_at
FROM actor_trust t
JOIN actors a1 ON a1.id = t.actor_id
JOIN actors a2 ON a2.id = t.trusted_actor_id;

DROP VIEW IF EXISTS v_actor_products;
CREATE VIEW v_actor_products AS
SELECT 
    ap.actor_id,
    a.primary_handle,
    p.id AS product_id,
    p.name AS product_name,
    p.category AS product_category,
    ap.confidence,
    ap.evidence_quote
FROM actor_product ap
JOIN actors a ON a.id = ap.actor_id
JOIN products p ON p.id = ap.product_id;

DROP VIEW IF EXISTS v_clearnet_accounts;
CREATE VIEW v_clearnet_accounts AS
SELECT 
    ca.id AS account_id,
    ca.actor_id,
    a.primary_handle,
    ca.platform,
    ca.value,
    ca.evidence_quote,
    ca.created_at
FROM clearnet_accounts ca
LEFT JOIN actors a ON a.id = ca.actor_id;
"""
cur.executescript(views_sql)
print("Curated views created.")

conn.commit()

# Print summary
print("\n=== MIGRATION SUMMARY ===")
for t in [
    'actors', 'actor_aliases', 'marketplaces', 'actor_marketplace',
    'products', 'actor_product', 'actor_trust', 'clearnet_accounts',
    'canonical_identifiers', 'infrastructure_findings', 'migration_notes'
]:
    cur.execute(f"SELECT COUNT(*) FROM {t}")
    print(f"Table {t}: {cur.fetchone()[0]} rows")

print("\n--- migration_notes reasons breakdown ---")
cur.execute("SELECT reason, COUNT(*) FROM migration_notes GROUP BY reason")
for r in cur.fetchall():
    print(f"  {r[0]}: {r[1]} entries")

conn.close()
