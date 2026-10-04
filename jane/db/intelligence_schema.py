"""SQLite schema for normalized OpenCode intelligence persistence."""

INTELLIGENCE_SCHEMA_SQL = """
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
CREATE TABLE IF NOT EXISTS actor_aliases (
    id TEXT PRIMARY KEY,
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    alias_handle TEXT NOT NULL,
    source_investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    needs_review INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(actor_id, alias_handle)
);
CREATE TABLE IF NOT EXISTS marketplaces (
    id TEXT PRIMARY KEY,
    onion_domain TEXT NOT NULL UNIQUE,
    display_name TEXT,
    category TEXT,
    first_seen TEXT,
    last_seen TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actor_marketplace (
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    marketplace_id TEXT NOT NULL REFERENCES marketplaces(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    first_seen TEXT,
    PRIMARY KEY(actor_id, marketplace_id)
);
CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    category TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actor_product (
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    first_seen TEXT,
    PRIMARY KEY(actor_id, product_id)
);
CREATE TABLE IF NOT EXISTS product_aliases (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    alias_name TEXT NOT NULL,
    source_investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    UNIQUE(product_id, alias_name)
);
CREATE TABLE IF NOT EXISTS product_observations (
    id TEXT PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
    marketplace_id TEXT REFERENCES marketplaces(id) ON DELETE SET NULL,
    marketplace_name TEXT,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    vendor_handle TEXT,
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
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    uncertainty TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS product_marketplace (
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    marketplace_id TEXT NOT NULL REFERENCES marketplaces(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    first_seen TEXT,
    last_seen TEXT,
    PRIMARY KEY(product_id, marketplace_id)
);
CREATE INDEX IF NOT EXISTS idx_prod_obs_product ON product_observations(product_id);
CREATE INDEX IF NOT EXISTS idx_prod_obs_inv ON product_observations(investigation_id);
CREATE TABLE IF NOT EXISTS actor_trust (
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    trusted_actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY(actor_id, trusted_actor_id)
);
CREATE TABLE IF NOT EXISTS clearnet_accounts (
    id TEXT PRIMARY KEY,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    platform TEXT,
    value TEXT NOT NULL,
    evidence_quote TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(platform, value)
);
CREATE TABLE IF NOT EXISTS actor_clearnet_account (
    actor_id TEXT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    clearnet_account_id TEXT NOT NULL REFERENCES clearnet_accounts(id) ON DELETE CASCADE,
    confidence REAL DEFAULT 1.0,
    evidence_quote TEXT,
    PRIMARY KEY(actor_id, clearnet_account_id)
);
CREATE TABLE IF NOT EXISTS canonical_identifiers (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    is_shared INTEGER DEFAULT 0,
    evidence_quote TEXT,
    confidence REAL DEFAULT 1.0,
    investigation_id TEXT REFERENCES investigations(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE(type, value, investigation_id)
);
CREATE TABLE IF NOT EXISTS infrastructure_findings (
    id TEXT PRIMARY KEY,
    marketplace_id TEXT REFERENCES marketplaces(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    evidence_quote TEXT,
    source_page_id TEXT REFERENCES onion_pages(id) ON DELETE CASCADE,
    found_at TEXT NOT NULL,
    UNIQUE(marketplace_id, type, value)
);
CREATE TABLE IF NOT EXISTS evidence_quotes (
    id TEXT PRIMARY KEY,
    page_id TEXT REFERENCES onion_pages(id) ON DELETE CASCADE,
    quote_text TEXT NOT NULL,
    extracted_fact_type TEXT NOT NULL,
    extracted_fact_id TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entity_investigations (
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    PRIMARY KEY(entity_type, entity_id, investigation_id)
);
CREATE TABLE IF NOT EXISTS attribution_assessments (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    assessment TEXT NOT NULL,
    confidence REAL,
    supporting_evidence TEXT,
    contradicting_evidence TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(investigation_id, actor_id, assessment)
);
CREATE TABLE IF NOT EXISTS actor_activities (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    activity_type TEXT NOT NULL,
    description TEXT NOT NULL,
    confidence REAL,
    evidence_quote TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(investigation_id, actor_id, activity_type, description)
);
CREATE TABLE IF NOT EXISTS stylometry_findings (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    comparison_target TEXT,
    similarity_score REAL,
    assessment TEXT,
    confidence REAL,
    details TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(investigation_id, actor_id, comparison_target, assessment)
);
CREATE TABLE IF NOT EXISTS opsec_findings (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    finding_type TEXT NOT NULL,
    description TEXT NOT NULL,
    confidence REAL,
    evidence_quote TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(investigation_id, actor_id, finding_type, description)
);
CREATE TABLE IF NOT EXISTS intelligence_gaps (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    gap_type TEXT,
    description TEXT NOT NULL,
    priority TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(investigation_id, actor_id, gap_type, description)
);
CREATE TABLE IF NOT EXISTS osint_targets (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    associated_actor_id TEXT REFERENCES actors(id) ON DELETE SET NULL,
    identifier TEXT NOT NULL,
    normalized_identifier TEXT,
    identifier_type TEXT NOT NULL,
    target_role TEXT,
    priority TEXT,
    confidence REAL,
    reason TEXT,
    evidence_quote TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS osint_target_results (
    id TEXT PRIMARY KEY,
    target_id TEXT NOT NULL REFERENCES osint_targets(id) ON DELETE CASCADE,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    platform TEXT,
    username TEXT,
    url TEXT,
    status TEXT NOT NULL,
    tags TEXT,
    raw_report_path TEXT,
    error_message TEXT,
    searched_at TEXT NOT NULL,
    UNIQUE(target_id, platform, username, url)
);
CREATE TABLE IF NOT EXISTS intelligence_artifacts (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    artifact_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    schema_version TEXT,
    content_hash TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(investigation_id, artifact_type, file_path)
);
DROP VIEW IF EXISTS v_actor_summary;
CREATE VIEW v_actor_summary AS
SELECT a.id AS actor_id, a.primary_handle, a.category, a.attribution_confidence,
       a.first_seen, a.last_seen, COUNT(DISTINCT aa.id) AS alias_count,
       COUNT(DISTINCT am.marketplace_id) AS marketplace_count,
       COUNT(DISTINCT ap.product_id) AS product_count
FROM actors a LEFT JOIN actor_aliases aa ON aa.actor_id=a.id
LEFT JOIN actor_marketplace am ON am.actor_id=a.id LEFT JOIN actor_product ap ON ap.actor_id=a.id
GROUP BY a.id, a.primary_handle, a.category, a.attribution_confidence, a.first_seen, a.last_seen;
DROP VIEW IF EXISTS v_actor_identifiers;
CREATE VIEW v_actor_identifiers AS
SELECT a.id AS actor_id, a.primary_handle, ci.id AS identifier_id, ci.type AS identifier_type,
       ci.value AS identifier_value, ci.is_shared, ci.confidence, ci.evidence_quote
FROM actors a JOIN canonical_identifiers ci ON ci.actor_id=a.id;
DROP VIEW IF EXISTS v_marketplace_activity;
CREATE VIEW v_marketplace_activity AS
SELECT m.id AS marketplace_id, m.onion_domain, m.display_name, m.category,
       COUNT(DISTINCT am.actor_id) AS actor_count, COUNT(DISTINCT inf.id) AS infrastructure_findings_count,
       m.first_seen, m.last_seen FROM marketplaces m
LEFT JOIN actor_marketplace am ON am.marketplace_id=m.id LEFT JOIN infrastructure_findings inf ON inf.marketplace_id=m.id
GROUP BY m.id, m.onion_domain, m.display_name, m.category, m.first_seen, m.last_seen;
DROP VIEW IF EXISTS v_infrastructure_findings;
CREATE VIEW v_infrastructure_findings AS
SELECT inf.id AS finding_id, inf.marketplace_id, m.onion_domain, inf.type AS finding_type,
       inf.value, inf.evidence_quote, inf.found_at FROM infrastructure_findings inf
LEFT JOIN marketplaces m ON m.id=inf.marketplace_id;
DROP VIEW IF EXISTS v_actor_trust_links;
CREATE VIEW v_actor_trust_links AS
SELECT t.actor_id, a1.primary_handle AS actor_handle, t.trusted_actor_id,
       a2.primary_handle AS trusted_actor_handle, t.confidence, t.evidence_quote, t.created_at
FROM actor_trust t JOIN actors a1 ON a1.id=t.actor_id JOIN actors a2 ON a2.id=t.trusted_actor_id;
DROP VIEW IF EXISTS v_actor_products;
CREATE VIEW v_actor_products AS
SELECT ap.actor_id, a.primary_handle, p.id AS product_id, p.name AS product_name,
       p.category AS product_category, ap.confidence, ap.evidence_quote
FROM actor_product ap JOIN actors a ON a.id=ap.actor_id JOIN products p ON p.id=ap.product_id;
DROP VIEW IF EXISTS v_clearnet_accounts;
CREATE VIEW v_clearnet_accounts AS
SELECT ca.id AS account_id, ca.actor_id, a.primary_handle, ca.platform, ca.value,
       ca.evidence_quote, ca.created_at FROM clearnet_accounts ca LEFT JOIN actors a ON a.id=ca.actor_id;
DROP VIEW IF EXISTS v_product_summary;
CREATE VIEW v_product_summary AS
SELECT p.id AS product_id, p.name AS product_name, p.category,
       COUNT(DISTINCT po.id) AS observation_count,
       COUNT(DISTINCT po.actor_id) AS actor_count,
       COUNT(DISTINCT po.marketplace_id) AS marketplace_count,
       MIN(po.observation_date) AS first_observed,
       MAX(po.observation_date) AS last_observed,
       p.created_at
FROM products p
LEFT JOIN product_observations po ON po.product_id = p.id
GROUP BY p.id, p.name, p.category, p.created_at;
"""
