"""Validated, idempotent persistence for OpenCode intelligence artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterable, Optional

from .database import get_db_connection


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _id(prefix: str, *parts: Any) -> str:
    raw = "\x1f".join(str(part or "") for part in parts)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def _text(value: Any) -> str:
    return str(value or "").strip()


def _float(value: Any) -> Optional[float]:
    try:
        return None if value in (None, "") else float(value)
    except (TypeError, ValueError):
        return None


def _items(value: Any) -> list[dict[str, Any]]:
    return [item for item in (value or []) if isinstance(item, dict)] if isinstance(value, list) else []


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else [], ensure_ascii=False, sort_keys=True)


def _actor_id(conn: sqlite3.Connection, value: Any) -> Optional[str]:
    key = _text(value)
    if not key:
        return None
    row = conn.execute("SELECT id FROM actors WHERE id = ? OR primary_handle = ?", (key, key)).fetchone()
    if row:
        return row["id"]
    row = conn.execute(
        """SELECT a.id FROM threat_actors t JOIN actors a
           ON a.id = t.graph_node_id OR a.primary_handle = t.primary_handle
           WHERE t.designated_id = ? LIMIT 1""",
        (key,),
    ).fetchone()
    return row["id"] if row else None


def _upsert_actor(conn: sqlite3.Connection, inv_id: str, actor: dict[str, Any], now: str) -> Optional[str]:
    handle = _text(actor.get("primary_handle") or actor.get("handle") or actor.get("alias"))
    if not handle:
        return None
    row = conn.execute("SELECT id FROM actors WHERE primary_handle = ?", (handle,)).fetchone()
    legacy = conn.execute(
        "SELECT graph_node_id FROM threat_actors WHERE primary_handle = ? OR designated_id = ? LIMIT 1",
        (handle, _text(actor.get("designated_id"))),
    ).fetchone()
    actor_id = row["id"] if row else (legacy["graph_node_id"] if legacy and legacy["graph_node_id"] else _text(actor.get("id")) or f"actor_{handle.lower().replace(' ', '_')}" )
    conn.execute(
        """INSERT INTO actors(id, primary_handle, category, attribution_confidence, first_seen, last_seen, created_at, updated_at)
           VALUES(?,?,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET primary_handle=excluded.primary_handle,
             category=COALESCE(excluded.category, actors.category),
             attribution_confidence=COALESCE(excluded.attribution_confidence, actors.attribution_confidence),
             last_seen=excluded.last_seen, updated_at=excluded.updated_at""",
        (actor_id, handle, _text(actor.get("category") or actor.get("role")) or None,
         _float(actor.get("confidence")) or 1.0, now, now, now, now),
    )
    for alias in actor.get("aliases") or []:
        alias_value = _text(alias.get("value") if isinstance(alias, dict) else alias)
        if alias_value and alias_value != handle:
            conn.execute(
                """INSERT INTO actor_aliases(id, actor_id, alias_handle, source_investigation_id, confidence, created_at)
                   VALUES(?,?,?,?,?,?) ON CONFLICT(actor_id, alias_handle) DO UPDATE SET confidence=excluded.confidence""",
                (_id("alias", actor_id, alias_value), actor_id, alias_value, inv_id, _float(actor.get("confidence")) or 1.0, now),
            )
    conn.execute(
        "INSERT OR IGNORE INTO entity_investigations(entity_type, entity_id, investigation_id) VALUES('actor',?,?)",
        (actor_id, inv_id),
    )
    return actor_id


def _artifact(conn: sqlite3.Connection, inv_id: str, path: Path, artifact_type: str, schema_version: Optional[str], now: str) -> None:
    if not path.exists():
        return
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    conn.execute(
        """INSERT INTO intelligence_artifacts(id, investigation_id, artifact_type, file_path, schema_version, content_hash, created_at)
           VALUES(?,?,?,?,?,?,?)
           ON CONFLICT(investigation_id, artifact_type, file_path) DO UPDATE SET
             schema_version=excluded.schema_version, content_hash=excluded.content_hash""",
        (_id("artifact", inv_id, artifact_type, str(path)), inv_id, artifact_type, str(path), schema_version, digest, now),
    )


def persist_attribution_artifact(inv_id: str, workspace: Path, report: dict[str, Any]) -> dict[str, Any]:
    """Persist Turn 2 structured intelligence in one transaction."""
    if not isinstance(report, dict):
        raise ValueError("attribution report must be an object")
    now = _now()
    conn = get_db_connection()
    counts = {"actors": 0, "aliases": 0, "activities": 0, "stylometry": 0, "opsec": 0, "gaps": 0}
    try:
        with conn:
            actor_ids: dict[str, str] = {}
            for actor in _items(report.get("threat_actors")):
                actor_id = _upsert_actor(conn, inv_id, actor, now)
                if not actor_id:
                    continue
                counts["actors"] += 1
                actor_ids[_text(actor.get("designated_id"))] = actor_id
                handle = _text(actor.get("primary_handle") or actor.get("handle"))
                assessment = _text(actor.get("assessment") or report.get("assessment") or report.get("threat_category"))
                if assessment:
                    conn.execute(
                        """INSERT INTO attribution_assessments(id, investigation_id, actor_id, assessment, confidence, supporting_evidence, contradicting_evidence, created_at, updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(investigation_id, actor_id, assessment) DO UPDATE SET confidence=excluded.confidence, updated_at=excluded.updated_at""",
                        (_id("assessment", inv_id, actor_id, assessment), inv_id, actor_id, assessment, _float(actor.get("confidence") or report.get("confidence")), _text(actor.get("evidence_quote")), _text(actor.get("contradicting_evidence")), now, now),
                    )
                stylometry = _text(actor.get("stylometry") or actor.get("stylometric_notes") or report.get("stylometric_notes"))
                if stylometry:
                    conn.execute(
                        """INSERT INTO stylometry_findings(id, investigation_id, actor_id, comparison_target, assessment, confidence, details, created_at)
                           VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(investigation_id, actor_id, comparison_target, assessment) DO UPDATE SET details=excluded.details, confidence=excluded.confidence""",
                        (_id("stylo", inv_id, actor_id, stylometry), inv_id, actor_id, _text(actor.get("comparison_target")), "supporting", _float(actor.get("confidence")), stylometry, now),
                    )
                    counts["stylometry"] += 1
                for identifier in (actor.get("identifiers") or []) + (actor.get("contacts") or []):
                    value = _text(identifier.get("value") if isinstance(identifier, dict) else identifier)
                    itype = _text(identifier.get("type") if isinstance(identifier, dict) else "contact") or "contact"
                    if value:
                        identifier_id = _id("identifier", itype, value, inv_id)
                        conn.execute("""INSERT INTO canonical_identifiers(id, type, value, actor_id, evidence_quote, confidence, investigation_id, created_at)
                            VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET actor_id=excluded.actor_id, evidence_quote=excluded.evidence_quote, confidence=excluded.confidence""", (identifier_id, itype, value, actor_id, _text(identifier.get("evidence_quote")) if isinstance(identifier, dict) else "", _float(identifier.get("confidence")) if isinstance(identifier, dict) else 1.0, inv_id, now))
                        quote = _text(identifier.get("evidence_quote")) if isinstance(identifier, dict) else ""
                        if quote:
                            conn.execute("INSERT OR IGNORE INTO evidence_quotes(id, quote_text, extracted_fact_type, extracted_fact_id, created_at) VALUES(?,?,?,?,?)", (_id("quote", inv_id, "identifier", identifier_id, quote), quote, "identifier", identifier_id, now))

            for identifier in _items(report.get("identifiers")):
                value = _text(identifier.get("value"))
                if not value:
                    continue
                actor_id = actor_ids.get(_text(identifier.get("associated_actor") or identifier.get("actor_id"))) or _actor_id(conn, identifier.get("associated_actor") or identifier.get("actor_id"))
                itype = _text(identifier.get("type")) or "identifier"
                identifier_id = _id("identifier", itype, value, inv_id)
                conn.execute("""INSERT INTO canonical_identifiers(id, type, value, actor_id, evidence_quote, confidence, investigation_id, created_at)
                    VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET actor_id=excluded.actor_id, evidence_quote=excluded.evidence_quote, confidence=excluded.confidence""", (identifier_id, itype, value, actor_id, _text(identifier.get("evidence_quote")), _float(identifier.get("confidence")) or 1.0, inv_id, now))


            marketplace_name = _text(report.get("marketplace_name"))
            marketplace_id = None
            if marketplace_name:
                marketplace_id = _id("market", marketplace_name.lower())
                conn.execute(
                    """INSERT INTO marketplaces(id, onion_domain, display_name, category, first_seen, last_seen, created_at)
                       VALUES(?,?,?,?,?,?,?) ON CONFLICT(onion_domain) DO UPDATE SET display_name=excluded.display_name, last_seen=excluded.last_seen""",
                    (marketplace_id, marketplace_name, marketplace_name, _text(report.get("threat_category")), now, now, now),
                )
            for finding in _items(report.get("infrastructure")):
                value = _text(finding.get("value") or finding.get("host") or finding.get("domain") or finding.get("ip"))
                ftype = _text(finding.get("type") or finding.get("finding_type")) or "infrastructure"
                if value:
                    conn.execute("""INSERT INTO infrastructure_findings(id, marketplace_id, type, value, evidence_quote, found_at)
                        VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET evidence_quote=excluded.evidence_quote""", (_id("infra", inv_id, ftype, value), marketplace_id, ftype, value, _text(finding.get("evidence_quote")), now))
            for link in _items(report.get("graph_links")):
                source = _text(link.get("source"))
                actor_id = actor_ids.get(source) or _actor_id(conn, source)
                relation = _text(link.get("relation")).upper()
                if not actor_id:
                    continue
                target = _text(link.get("target"))
                quote = _text(link.get("evidence_quote"))
                if relation in {"OPERATES", "OPERATES_ON", "CONTROLS"} and marketplace_id and target.lower() == marketplace_name.lower():
                    conn.execute("INSERT OR REPLACE INTO actor_marketplace(actor_id, marketplace_id, confidence, evidence_quote, first_seen) VALUES(?,?,?,?,?)", (actor_id, marketplace_id, _float(link.get("confidence")) or 1.0, quote, now))
                elif relation in {"TRUST", "TRUSTS"}:
                    trusted = actor_ids.get(target) or _actor_id(conn, target)
                    if trusted and trusted != actor_id:
                        conn.execute("INSERT OR REPLACE INTO actor_trust(actor_id, trusted_actor_id, confidence, evidence_quote, created_at) VALUES(?,?,?,?,?)", (actor_id, trusted, _float(link.get("confidence")) or 1.0, quote, now))

            for product in _items(report.get("commodities")):
                name = _text(product.get("name"))
                if not name:
                    continue
                product_id = _id("product", name.lower())
                conn.execute(
                    "INSERT INTO products(id, name, category, created_at) VALUES(?,?,?,?) ON CONFLICT(name) DO UPDATE SET category=COALESCE(excluded.category, products.category)",
                    (product_id, name, _text(product.get("category")) or None, now),
                )
                prow = conn.execute("SELECT id FROM products WHERE name = ?", (name,)).fetchone()
                if prow:
                    product_id = prow["id"]
                counts["products"] = counts.get("products", 0) + 1

                # Marketplace association
                prod_mkt_name = _text(product.get("marketplace_name") or report.get("marketplace_name"))
                prod_onion = _text(product.get("onion_url"))
                mkt_key = prod_onion or prod_mkt_name
                prod_mkt_id = None
                if mkt_key:
                    prod_mkt_id = _id("market", mkt_key.lower())
                    conn.execute(
                        """INSERT INTO marketplaces(id, onion_domain, display_name, category, first_seen, last_seen, created_at)
                           VALUES(?,?,?,?,?,?,?) ON CONFLICT(onion_domain) DO UPDATE SET display_name=COALESCE(excluded.display_name, marketplaces.display_name), last_seen=excluded.last_seen""",
                        (prod_mkt_id, mkt_key, prod_mkt_name or mkt_key, _text(report.get("threat_category")), now, now, now),
                    )
                    conn.execute(
                        """INSERT INTO product_marketplace(product_id, marketplace_id, confidence, evidence_quote, first_seen, last_seen)
                           VALUES(?,?,?,?,?,?) ON CONFLICT(product_id, marketplace_id) DO UPDATE SET last_seen=excluded.last_seen, confidence=MAX(confidence, excluded.confidence)""",
                        (product_id, prod_mkt_id, _float(product.get("confidence")) or 1.0, _text(product.get("evidence_quote")), now, now),
                    )

                # Vendor association
                seller = _text(product.get("vendor_handle")) or _text(report.get("threat_actors", [{}])[0].get("primary_handle") if _items(report.get("threat_actors")) else "")
                seller_id = actor_ids.get(seller) or _actor_id(conn, seller)
                if seller_id:
                    conn.execute(
                        "INSERT OR REPLACE INTO actor_product(actor_id, product_id, confidence, evidence_quote, first_seen) VALUES(?,?,?,?,?)",
                        (seller_id, product_id, _float(product.get("confidence")) or 1.0, _text(product.get("evidence_quote")), now),
                    )

                # Product observation / listing
                orig_title = _text(product.get("original_title")) or name
                price_val = _float(product.get("price"))
                curr_val = _text(product.get("currency")) or None
                qty_val = _float(product.get("quantity"))
                unit_val = _text(product.get("unit")) or None
                min_order_val = _float(product.get("min_order"))
                avail_val = _text(product.get("availability")) or None
                status_val = _text(product.get("listing_status")) or None
                obs_date_val = _text(product.get("observation_date")) or None
                url_val = _text(product.get("listing_url") or product.get("onion_url")) or None
                conf_val = _float(product.get("confidence")) or 1.0
                quote_val = _text(product.get("evidence_quote"))
                uncertainty_val = _text(product.get("uncertainty")) or None

                obs_id = _id("obs", inv_id, product_id, orig_title, price_val or "", url_val or "")
                conn.execute(
                    """INSERT INTO product_observations(
                        id, product_id, investigation_id, marketplace_id, marketplace_name,
                        actor_id, vendor_handle, original_title, price, currency,
                        quantity, unit, min_order, availability, listing_status,
                        observation_date, listing_url, confidence, evidence_quote,
                        uncertainty, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                        price=COALESCE(excluded.price, product_observations.price),
                        currency=COALESCE(excluded.currency, product_observations.currency),
                        quantity=COALESCE(excluded.quantity, product_observations.quantity),
                        unit=COALESCE(excluded.unit, product_observations.unit),
                        availability=COALESCE(excluded.availability, product_observations.availability),
                        listing_status=COALESCE(excluded.listing_status, product_observations.listing_status),
                        observation_date=COALESCE(excluded.observation_date, product_observations.observation_date),
                        confidence=MAX(product_observations.confidence, excluded.confidence),
                        evidence_quote=COALESCE(excluded.evidence_quote, product_observations.evidence_quote)""",
                    (
                        obs_id, product_id, inv_id, prod_mkt_id, prod_mkt_name or None,
                        seller_id, seller or None, orig_title, price_val, curr_val,
                        qty_val, unit_val, min_order_val, avail_val, status_val,
                        obs_date_val, url_val, conf_val, quote_val,
                        uncertainty_val, now,
                    ),
                )
                counts["observations"] = counts.get("observations", 0) + 1

                # Aliases
                for alias in product.get("aliases") or []:
                    alias_str = _text(alias)
                    if alias_str and alias_str.lower() != name.lower():
                        conn.execute(
                            """INSERT INTO product_aliases(id, product_id, alias_name, source_investigation_id, confidence, created_at)
                               VALUES(?,?,?,?,?,?) ON CONFLICT(product_id, alias_name) DO UPDATE SET confidence=excluded.confidence""",
                            (_id("palias", product_id, alias_str), product_id, alias_str, inv_id, conf_val, now),
                        )

                # Evidence quote
                if quote_val:
                    conn.execute(
                        "INSERT OR IGNORE INTO evidence_quotes(id, quote_text, extracted_fact_type, extracted_fact_id, created_at) VALUES(?,?,?,?,?)",
                        (_id("quote", inv_id, "product", product_id, quote_val), quote_val, "product", product_id, now),
                    )

            for item in _items(report.get("activities")):
                actor_id = actor_ids.get(_text(item.get("associated_actor") or item.get("actor_id"))) or _actor_id(conn, item.get("associated_actor") or item.get("actor_id"))
                activity_type = _text(item.get("activity_type") or item.get("type"))
                description = _text(item.get("description") or item.get("activity"))
                if not activity_type or not description:
                    continue
                conn.execute("INSERT OR IGNORE INTO actor_activities(id, investigation_id, actor_id, activity_type, description, confidence, evidence_quote, created_at) VALUES(?,?,?,?,?,?,?,?)", (_id("activity", inv_id, actor_id, activity_type, description), inv_id, actor_id, activity_type, description, _float(item.get("confidence")), _text(item.get("evidence_quote")), now))
                counts["activities"] += 1
            for item in _items(report.get("opsec_findings") or report.get("opsec")):
                actor_id = actor_ids.get(_text(item.get("associated_actor") or item.get("actor_id"))) or _actor_id(conn, item.get("associated_actor") or item.get("actor_id"))
                kind, desc = _text(item.get("finding_type") or item.get("type")), _text(item.get("description") or item.get("finding"))
                if kind and desc:
                    conn.execute("INSERT OR IGNORE INTO opsec_findings(id, investigation_id, actor_id, finding_type, description, confidence, evidence_quote, created_at) VALUES(?,?,?,?,?,?,?,?)", (_id("opsec", inv_id, actor_id, kind, desc), inv_id, actor_id, kind, desc, _float(item.get("confidence")), _text(item.get("evidence_quote")), now))
                    counts["opsec"] += 1
            for item in _items(report.get("intelligence_gaps") or report.get("uncertainties")):
                desc = _text(item.get("description") or item.get("gap") or item.get("uncertainty"))
                if desc:
                    actor_id = actor_ids.get(_text(item.get("associated_actor") or item.get("actor_id"))) or _actor_id(conn, item.get("associated_actor") or item.get("actor_id"))
                    conn.execute("INSERT OR IGNORE INTO intelligence_gaps(id, investigation_id, actor_id, gap_type, description, priority, created_at) VALUES(?,?,?,?,?,?,?)", (_id("gap", inv_id, actor_id, desc), inv_id, actor_id, _text(item.get("gap_type") or item.get("type")) or None, desc, _text(item.get("priority")) or None, now))
                    counts["gaps"] += 1
            _artifact(conn, inv_id, workspace / "opencode" / "attribution_report.json", "ATTRIBUTION_REPORT", _text(report.get("schema_version")) or None, now)
        return counts
    finally:
        conn.close()


def persist_osint_artifacts(inv_id: str, workspace: Path, targets_payload: Optional[dict[str, Any]], summary: Optional[dict[str, Any]]) -> dict[str, int]:
    """Persist Turn 2.5 targets and Maigret outcomes without identity overclaim."""
    targets_payload = targets_payload if isinstance(targets_payload, dict) else {}
    summary = summary if isinstance(summary, dict) else {}
    raw_targets = { _text(t.get("target_id")): t for t in _items(targets_payload.get("targets")) if _text(t.get("target_id")) }
    now = _now()
    conn = get_db_connection()
    counts = {"targets": 0, "results": 0, "accounts": 0}
    try:
        with conn:
            seen_results: set[str] = set()
            summary_targets = _items(summary.get("targets"))
            summary_ids = {_text(item.get("target_id")) for item in summary_targets}
            target_items = summary_targets + [
                {**target, "status": "failed", "error": "target was selected but has no execution result"}
                for target_id, target in raw_targets.items() if target_id not in summary_ids
            ]
            for item in target_items:
                target_id = _text(item.get("target_id"))
                source = raw_targets.get(target_id, item)
                if not target_id:
                    continue
                actor_id = _actor_id(conn, source.get("associated_actor") or item.get("associated_actor"))
                identifier = _text(source.get("identifier") or item.get("identifier") or source.get("normalized_identifier") or "unknown")
                normalized = _text(source.get("normalized_identifier") or item.get("normalized_identifier")) or None
                itype = _text(source.get("type") or item.get("type")) or "unknown"
                evidence = source.get("evidence") or item.get("evidence") or []
                quote = _text(evidence[0].get("quote")) if isinstance(evidence, list) and evidence and isinstance(evidence[0], dict) else ""
                conn.execute("""INSERT INTO osint_targets(id, investigation_id, associated_actor_id, identifier, normalized_identifier, identifier_type, target_role, priority, confidence, reason, evidence_quote, created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET associated_actor_id=excluded.associated_actor_id, identifier=excluded.identifier, normalized_identifier=excluded.normalized_identifier, identifier_type=excluded.identifier_type, target_role=excluded.target_role, priority=excluded.priority, confidence=excluded.confidence, reason=excluded.reason, evidence_quote=excluded.evidence_quote""", (target_id, inv_id, actor_id, identifier, normalized, itype, _text(source.get("target_role") or item.get("target_role")) or None, _text(source.get("priority") or item.get("priority")) or None, _float(source.get("confidence") or item.get("confidence")), _text(source.get("reason") or item.get("reason")) or None, quote or None, now))
                counts["targets"] += 1
                status = _text(item.get("status"))
                if status in {"success_with_profiles", "found"}:
                    status = "FOUND"
                elif status in {"success_no_profiles", "no_results"}:
                    status = "NO_RESULTS"
                elif status == "timeout":
                    status = "TIMEOUT"
                elif status == "malformed_report":
                    status = "MALFORMED"
                else:
                    status = "FAILED" if status else "NO_RESULTS"
                profiles = [p for p in _items(summary.get("profiles_found")) if _text(p.get("target_id")) == target_id]
                if not profiles and status == "FOUND":
                    status = "NO_RESULTS"
                rows = []
                for profile in profiles:
                    nested = _items(profile.get("results")) or [profile]
                    rows.extend(nested)
                if not rows:
                    rows = [{"platform": None, "username": normalized, "url": None, "tags": []}]
                for result in rows:
                    platform, username, url = _text(result.get("platform") or result.get("site_name")) or None, _text(result.get("username") or normalized) or None, _text(result.get("url")) or None
                    result_id = _id("osint_result", target_id, platform, username, url)
                    conn.execute("""INSERT INTO osint_target_results(id, target_id, investigation_id, platform, username, url, status, tags, raw_report_path, error_message, searched_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, tags=excluded.tags, raw_report_path=excluded.raw_report_path, error_message=excluded.error_message, searched_at=excluded.searched_at""", (result_id, target_id, inv_id, platform, username, url, status, _json(result.get("tags") or []), _text(item.get("raw_report_path")) or None, _text(item.get("error")) or None, now))
                    counts["results"] += 1
                    if status == "FOUND" and platform and (url or username):
                        account_id = _id("clearnet", platform, url or username)
                        conn.execute("INSERT INTO clearnet_accounts(id, actor_id, platform, value, evidence_quote, created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(platform, value) DO UPDATE SET actor_id=COALESCE(excluded.actor_id, clearnet_accounts.actor_id), evidence_quote=COALESCE(excluded.evidence_quote, clearnet_accounts.evidence_quote)", (account_id, actor_id, platform, url or username, f"Maigret found {username or normalized} on {platform}", now))
                        if actor_id:
                            actual = conn.execute("SELECT id FROM clearnet_accounts WHERE platform=? AND value=?", (platform, url or username)).fetchone()["id"]
                            conn.execute("INSERT OR IGNORE INTO actor_clearnet_account(actor_id, clearnet_account_id, confidence, evidence_quote) VALUES(?,?,?,?)", (actor_id, actual, _float(source.get("confidence")) or 0.0, "Maigret result; identity requires review"))
                        counts["accounts"] += 1
                    seen_results.add(result_id)
            _artifact(conn, inv_id, workspace / "osint" / "targets.json", "OSINT_TARGETS", _text(targets_payload.get("schema_version")) or None, now)
            _artifact(conn, inv_id, workspace / "osint" / "clearnet_summary.json", "OSINT_SUMMARY", None, now)
        return counts
    finally:
        conn.close()


def persist_threat_graph_artifact(inv_id: str, workspace: Path) -> None:
    conn = get_db_connection()
    try:
        with conn:
            _artifact(conn, inv_id, workspace / "graph" / "threat_graph.json", "THREAT_GRAPH", None, _now())
    finally:
        conn.close()


def persist_investigation_artifacts(inv_id: str, workspace: Path) -> dict[str, Any]:
    """Replay all present artifacts; safe for retries and partial pipelines."""
    result: dict[str, Any] = {}
    attr = workspace / "opencode" / "attribution_report.json"
    if attr.exists():
        result["attribution"] = persist_attribution_artifact(inv_id, workspace, json.loads(attr.read_text(encoding="utf-8")))
    targets = workspace / "osint" / "targets.json"
    summary = workspace / "osint" / "clearnet_summary.json"
    if targets.exists() or summary.exists():
        result["osint"] = persist_osint_artifacts(inv_id, workspace, json.loads(targets.read_text(encoding="utf-8")) if targets.exists() else {}, json.loads(summary.read_text(encoding="utf-8")) if summary.exists() else {})
    persist_threat_graph_artifact(inv_id, workspace)
    return result


def get_investigation_intelligence(inv_id: str) -> dict[str, Any]:
    """Return normalized OpenCode intelligence for API/frontend consumers."""
    conn = get_db_connection()
    try:
        def rows(sql: str, params: tuple = ()) -> list[dict[str, Any]]:
            return [dict(row) for row in conn.execute(sql, params).fetchall()]

        actor_sub = """
            SELECT entity_id FROM entity_investigations WHERE entity_type='actor' AND investigation_id=?
            UNION
            SELECT id FROM actors WHERE id IN (SELECT graph_node_id FROM threat_actors WHERE investigation_id=?)
            UNION
            SELECT id FROM actors WHERE primary_handle IN (SELECT primary_handle FROM threat_actors WHERE investigation_id=?)
        """

        return {
            "investigation_id": inv_id,
            "actors": rows(f"SELECT * FROM actors WHERE id IN ({actor_sub})", (inv_id, inv_id, inv_id)),
            "aliases": rows(f"SELECT * FROM actor_aliases WHERE actor_id IN ({actor_sub}) OR source_investigation_id=?", (inv_id, inv_id, inv_id, inv_id)),
            "attribution_assessments": rows("SELECT * FROM attribution_assessments WHERE investigation_id=?", (inv_id,)),
            "activities": rows("SELECT * FROM actor_activities WHERE investigation_id=?", (inv_id,)),
            "stylometry": rows("SELECT * FROM stylometry_findings WHERE investigation_id=?", (inv_id,)),
            "opsec": rows("SELECT * FROM opsec_findings WHERE investigation_id=?", (inv_id,)),
            "intelligence_gaps": rows("SELECT * FROM intelligence_gaps WHERE investigation_id=?", (inv_id,)),
            "osint_targets": rows("SELECT * FROM osint_targets WHERE investigation_id=?", (inv_id,)),
            "osint_results": rows("SELECT * FROM osint_target_results WHERE investigation_id=?", (inv_id,)),
            "clearnet_accounts": rows(f"""
                SELECT DISTINCT ca.* FROM clearnet_accounts ca
                JOIN actor_clearnet_account aca ON ca.id = aca.clearnet_account_id
                WHERE aca.actor_id IN ({actor_sub})
            """, (inv_id, inv_id, inv_id)),
            "actor_clearnet_accounts": rows(f"""
                SELECT aca.*, ca.platform, ca.value as account_value, ca.evidence_quote as account_evidence
                FROM actor_clearnet_account aca
                JOIN clearnet_accounts ca ON ca.id = aca.clearnet_account_id
                WHERE aca.actor_id IN ({actor_sub})
            """, (inv_id, inv_id, inv_id)),
            "marketplaces": rows(f"""
                SELECT DISTINCT m.*, am.actor_id, am.confidence as relation_confidence, am.evidence_quote as relation_evidence, am.first_seen as relation_first_seen
                FROM marketplaces m
                JOIN actor_marketplace am ON m.id = am.marketplace_id
                WHERE am.actor_id IN ({actor_sub})
            """, (inv_id, inv_id, inv_id)),
            "products": rows(f"""
                SELECT DISTINCT p.*, ap.actor_id, ap.confidence as relation_confidence, ap.evidence_quote as relation_evidence, ap.first_seen as relation_first_seen
                FROM products p
                JOIN actor_product ap ON p.id = ap.product_id
                WHERE ap.actor_id IN ({actor_sub})
            """, (inv_id, inv_id, inv_id)),
            "commodities": rows("SELECT * FROM commodities WHERE investigation_id=?", (inv_id,)),
            "product_observations": rows("SELECT * FROM product_observations WHERE investigation_id=?", (inv_id,)),
            "product_aliases": rows("SELECT pa.* FROM product_aliases pa WHERE source_investigation_id=? OR product_id IN (SELECT product_id FROM product_observations WHERE investigation_id=?)", (inv_id, inv_id)),
            "actor_trust": rows(f"""
                SELECT DISTINCT t.* FROM actor_trust t
                WHERE t.actor_id IN ({actor_sub}) OR t.trusted_actor_id IN ({actor_sub})
            """, (inv_id, inv_id, inv_id, inv_id, inv_id, inv_id)),
            "canonical_identifiers": rows("SELECT * FROM canonical_identifiers WHERE investigation_id=?", (inv_id,)),
            "artifacts": rows("SELECT * FROM intelligence_artifacts WHERE investigation_id=?", (inv_id,)),
        }
    finally:
        conn.close()
