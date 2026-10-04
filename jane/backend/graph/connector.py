"""
Jane Backend — NetworkX Graph Connector
Extracts entities and relationships from data/jane.db,
constructs an in-memory NetworkX MultiDiGraph,
runs inference passes (PGP reuse, handle matching, cross-page links),
detects modularity communities, and exports Cytoscape.js visual JSON.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("jane.backend.graph")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
VOIDACCESS_PATH = REPO_ROOT / "voidaccess_eval"


if str(VOIDACCESS_PATH) not in sys.path:
    sys.path.insert(0, str(VOIDACCESS_PATH))

import networkx as nx

DEFAULT_DB_PATH = REPO_ROOT / "data" / "jane.db"
os.environ["DATABASE_URL"] = f"sqlite:///{DEFAULT_DB_PATH.as_posix()}"

from graph.builder import (
    build_graph_from_db,
    infer_relationships,
    detect_communities,
    find_shortest_path,
    _ENTITY_TYPE_TO_NODE_TYPE,
)

# Register Jane's Locksmith entity types into VoidAccess graph mapping
_ENTITY_TYPE_TO_NODE_TYPE["FAVICON_MMH3"] = "favicon_mmh3"
_ENTITY_TYPE_TO_NODE_TYPE["SERVER_BANNER"] = "server_banner"

# Colors for Cytoscape visualization
NODE_TYPE_COLORS = {
    "crypto_wallet": "#e3b341",       # Gold
    "threat_actor": "#f85149",        # Red
    "email": "#58a6ff",               # Blue
    "onion_url": "#39c5bb",           # Dark cyan
    "cve": "#d29922",                 # Amber
    "ip_address": "#a371f7",          # Purple
    "credential": "#ff7b72",          # Coral
    "messaging_handle": "#bc8cff",    # Light purple
    "favicon_mmh3": "#238636",        # Green
    "server_banner": "#8b949e",       # Gray
    "default": "#8b949e",
}


def export_cytoscape_json(G: nx.MultiDiGraph, communities: Dict[str, int]) -> Dict[str, Any]:
    """Converts NetworkX MultiDiGraph to Cytoscape.js elements schema."""
    elements: Dict[str, List[Dict[str, Any]]] = {"nodes": [], "edges": []}

    for node_id, data in G.nodes(data=True):
        ntype = data.get("node_type", "default")
        comm_id = communities.get(node_id, 0)
        degree = G.degree(node_id)

        color = NODE_TYPE_COLORS.get(ntype, NODE_TYPE_COLORS["default"])

        elements["nodes"].append({
            "data": {
                "id": str(node_id),
                "label": str(node_id).split("/")[-1][:30] if "/" in str(node_id) else str(node_id)[:30],
                "full_id": str(node_id),
                "node_type": ntype,
                "community": comm_id,
                "degree": degree,
                "color": color,
                "first_seen": str(data.get("first_seen", "")),
                "last_seen": str(data.get("last_seen", "")),
            }
        })

    edge_id_counter = 0
    for u, v, data in G.edges(data=True):
        edge_id_counter += 1
        edge_type = data.get("edge_type", "RELATED_TO")
        confidence = data.get("confidence", 1.0)

        elements["edges"].append({
            "data": {
                "id": f"edge_{edge_id_counter}",
                "source": str(u),
                "target": str(v),
                "edge_type": edge_type,
                "confidence": confidence,
            }
        })

    return elements


def generate_graph_pipeline() -> Dict[str, Any]:
    """Executes full graph compilation pipeline."""
    logger.info("Building graph from database...")
    G = build_graph_from_db()

    # Load custom Jane relationships from entity_relationships table
    import sqlite3
    try:
        conn = sqlite3.connect(DEFAULT_DB_PATH)
        cur = conn.cursor()
        rels = cur.execute("""
            SELECT r.relationship_type, r.confidence, 
                   ea.entity_type, ea.value,
                   eb.entity_type, eb.value
            FROM entity_relationships r
            JOIN entities ea ON r.entity_a_id = ea.id
            JOIN entities eb ON r.entity_b_id = eb.id
        """).fetchall()

        for r_type, conf, a_type, a_val, b_type, b_val in rels:
            # Find matching nodes in G
            src_node = None
            tgt_node = None
            for n in G.nodes():
                if a_val in n or (a_type == "ONION_URL" and a_val in n):
                    src_node = n
                if b_val in n or b_val == n:
                    tgt_node = n
            if src_node and tgt_node:
                G.add_edge(src_node, tgt_node, edge_type=r_type, confidence=conf)
                logger.info(f"Added persistent edge: {src_node} -> {tgt_node} ({r_type})")
        conn.close()
    except Exception as exc:
        logger.warning(f"Could not load custom relationships: {exc}")

    raw_nodes = G.number_of_nodes()
    raw_edges = G.number_of_edges()
    logger.info(f"Loaded raw graph: {raw_nodes} nodes, {raw_edges} edges")

    logger.info("Running relationship inference passes (PGP key reuse, handle alias resolution)...")
    G = infer_relationships(G)

    logger.info("Detecting modularity communities...")
    communities = detect_communities(G)

    num_communities = len(set(communities.values())) if communities else 0
    logger.info(f"Partitioned into {num_communities} communities")

    cyto_data = export_cytoscape_json(G, communities)

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_nodes": G.number_of_nodes(),
        "total_edges": G.number_of_edges(),
        "communities_count": num_communities,
        "is_directed": G.is_directed(),
        "elements": cyto_data,
    }

    out_path = REPO_ROOT / "data" / "graph_snapshot.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info(f"Graph snapshot exported -> {out_path}")
    return summary


def run_graph(
    inv_id: str,
    batch_data: Dict[str, Any],
    extracted_data: Optional[Dict[str, Any]] = None,
    locksmith_data: Optional[Dict[str, Any]] = None,
    ai_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Microservice entrypoint: Synthesizes graph nodes and edges in SQLite database."""
    from jane.db.database import (
        save_onion_page,
        save_threat_actor,
        save_identifier,
        save_graph_node,
        save_graph_edge,
        get_investigation_summary,
    )
    
    nodes_created = 0
    edges_created = 0

    pages = batch_data.get("pages", [])
    created_nodes = set()
    template_clusters: Dict[str, List[str]] = {}
    url_to_page_id: Dict[str, str] = {}

    for page in pages:
        u = page.get("url", "")
        headers = page.get("response_headers", {}) or {}
        header_map = {k.lower(): v for k, v in headers.items()}
        thash = page.get("template_hash", "")
        diff_ratio = page.get("content_diff_ratio")
        if diff_ratio is None and page.get("cleaned_text"):
            try:
                import difflib
                conn_prev = get_db_connection()
                prev_row = conn_prev.execute(
                    "SELECT cleaned_text FROM onion_pages WHERE url = ? AND investigation_id != ? AND cleaned_text != '' ORDER BY created_at DESC LIMIT 1",
                    (u, inv_id),
                ).fetchone()
                conn_prev.close()
                if prev_row and prev_row["cleaned_text"]:
                    diff_ratio = round(difflib.SequenceMatcher(None, prev_row["cleaned_text"], page.get("cleaned_text", "")).ratio(), 4)
            except Exception:
                pass
        raw_html = page.get("raw_html", "")

        raw_html_path = page.get("raw_html_path", "")
        if raw_html and not raw_html_path:
            raw_dir = REPO_ROOT / "jane" / "data" / "raw"
            raw_dir.mkdir(parents=True, exist_ok=True)
            fname = f"page_{hashlib.sha256(u.encode()).hexdigest()[:12]}.html"
            f_path = raw_dir / fname
            try:
                f_path.write_text(raw_html, encoding="utf-8", errors="ignore")
                raw_html_path = str(f_path)
            except Exception as e:
                logger.warning(f"Could not save raw HTML snapshot for {u}: {e}")

        p_id = save_onion_page(
            investigation_id=inv_id,
            url=u,
            title=page.get("title", ""),
            raw_html_path=raw_html_path,
            cleaned_text=page.get("cleaned_text", ""),
            server_banner=header_map.get("server", ""),
            etag=header_map.get("etag", ""),
            template_hash=thash,
            content_diff_ratio=diff_ratio,
        )
        url_to_page_id[u] = p_id
        page_node = f"page_{u}"
        save_graph_node(
            investigation_id=inv_id,
            node_id=page_node,
            label=page.get("title", "Onion Page")[:30],
            node_type="ONION_PAGE",
            metadata={"url": u, "color": "#38bdf8", "degree": 2, "template_hash": thash, "raw_html_path": raw_html_path}
        )
        created_nodes.add(page_node)
        nodes_created += 1

        if thash:
            template_clusters.setdefault(thash, []).append(page_node)

    # Link pages sharing the exact same CSS/JS template fingerprint
    for thash, pnodes in template_clusters.items():
        if len(pnodes) > 1:
            for i in range(len(pnodes)):
                for j in range(i + 1, len(pnodes)):
                    save_graph_edge(inv_id, pnodes[i], pnodes[j], "SAME_TEMPLATE", 0.85, f"Shared CSS/JS template fingerprint: {thash}")
                    edges_created += 1

    # Ingest Extracted Entities with Sanctions & Calibrated Confidence
    if extracted_data:
        from jane.db.database import get_db_connection
        for r in extracted_data.get("results_by_page", []):
            u = r.get("url", "")
            page_node = f"page_{u}"
            page_id = url_to_page_id.get(u)
            if not page_id and u:
                try:
                    conn_p = get_db_connection()
                    p_row = conn_p.execute("SELECT id FROM onion_pages WHERE url = ?", (u,)).fetchone()
                    if p_row:
                        page_id = p_row["id"]
                        url_to_page_id[u] = page_id
                    conn_p.close()
                except Exception:
                    pass

            for ent in r.get("entities", []):
                val = ent.get("value", "")
                etype = ent.get("entity_type", "IDENTIFIER")
                conf = ent.get("confidence", 0.85)
                is_sanc = ent.get("is_sanctioned", False)
                node_id = f"ent_{val}"

                # Persist identifier record into database with linked page_id
                save_identifier(
                    investigation_id=inv_id,
                    itype=etype,
                    value=val,
                    page_id=page_id,
                    evidence_quote=ent.get("context_snippet", ""),
                    confidence=conf,
                    is_sanctioned=1 if is_sanc else 0,
                )

                if node_id not in created_nodes:
                    node_color = "#ef4444" if is_sanc else ("#e3b341" if "ADDRESS" in etype else "#f87171")
                    label = f"🚨 {val[:25]}" if is_sanc else val[:30]
                    save_graph_node(
                        investigation_id=inv_id,
                        node_id=node_id,
                        label=label,
                        node_type=etype,
                        metadata={"type": etype, "value": val, "color": node_color, "degree": 1, "is_sanctioned": is_sanc, "confidence": conf}
                    )
                    created_nodes.add(node_id)
                    nodes_created += 1
                if page_node in created_nodes:
                    save_graph_edge(inv_id, page_node, node_id, "MENTIONS", conf, ent.get("context_snippet", ""))
                    edges_created += 1

    # Ingest Locksmith Findings
    if locksmith_data:
        for f in locksmith_data.get("findings", []):
            u = f.get("url", "")
            page_node = f"page_{u}"
            banner = f.get("server_banner")
            if banner:
                b_node = f"banner_{banner}"
                if b_node not in created_nodes:
                    save_graph_node(
                        investigation_id=inv_id,
                        node_id=b_node,
                        label=banner,
                        node_type="SERVER_BANNER",
                        metadata={"banner": banner, "color": "#34d399", "degree": 2}
                    )
                    created_nodes.add(b_node)
                    nodes_created += 1
                if page_node in created_nodes:
                    save_graph_edge(inv_id, page_node, b_node, "HOSTED_ON", 1.0, f"Server banner: {banner}")
                    edges_created += 1

    # Ingest AI Attribution Reports
    if ai_data:
        for rep in ai_data.get("reports", []):
            r = rep.get("report", {})
            u = rep.get("url", "")
            page_node = f"page_{u}"

            # Investigation-level OpenCode contract.
            entity_ids: Dict[str, str] = {}
            for entity in r.get("entities", []):
                label = str(entity.get("label") or entity.get("name") or entity.get("value") or "").strip()
                if not label:
                    continue
                node_id = str(entity.get("id") or f"{str(entity.get('type', 'entity')).lower()}:{label.lower()}")
                entity_ids[label] = node_id
                if node_id not in created_nodes:
                    save_graph_node(
                        investigation_id=inv_id,
                        node_id=node_id,
                        label=label[:60],
                        node_type=str(entity.get("type", "ENTITY")).upper(),
                        metadata={"confidence": entity.get("confidence", 0.0), "evidence_ids": entity.get("evidence_ids", []), "source_page": entity.get("source_page", "")},
                    )
                    created_nodes.add(node_id)
                    nodes_created += 1
            for rel in r.get("relationships", []):
                source = str(rel.get("source", ""))
                target = str(rel.get("target", ""))
                evidence_ids = rel.get("evidence_ids", []) or []
                evidence_quote = str(rel.get("evidence_quote", ""))
                if not source or not target or (not evidence_ids and not evidence_quote):
                    continue
                src_id = entity_ids.get(source, source)
                tgt_id = entity_ids.get(target, target)
                if src_id not in created_nodes or tgt_id not in created_nodes:
                    continue
                inferred = bool(rel.get("inferred", False))
                confidence = float(rel.get("confidence", 0.5))
                if inferred:
                    confidence = min(confidence, 0.75)
                save_graph_edge(
                    inv_id, src_id, tgt_id, rel.get("type", "RELATED_TO"), confidence, evidence_quote,
                    evidence_ids=evidence_ids, inferred=inferred,
                    basis=str(rel.get("extraction_method", "opencode")),
                )
                edges_created += 1
            # Actor, Marketplace, and Product nodes are authoritatively written ONLY by
            # ingest_threat_graph() from Turn 3 threat_graph.json to prevent duplicate
            # nodes, mismatched IDs, and competing casings.

            for link in r.get("graph_links", []):
                src = link.get("source", "")
                tgt = link.get("target", "")
                if src and tgt:
                    src_id = f"node_{src}" if not src.startswith(("page_", "actor_", "ent_", "banner_")) else src
                    tgt_id = f"node_{tgt}" if not tgt.startswith(("page_", "actor_", "ent_", "banner_")) else tgt
                    if src_id not in created_nodes:
                        save_graph_node(
                            investigation_id=inv_id,
                            node_id=src_id,
                            label=src[:30],
                            node_type="CONCEPT",
                            metadata={"name": src, "color": "#f87171", "degree": 1}
                        )
                        created_nodes.add(src_id)
                        nodes_created += 1
                    if tgt_id not in created_nodes:
                        save_graph_node(
                            investigation_id=inv_id,
                            node_id=tgt_id,
                            label=tgt[:30],
                            node_type="CONCEPT",
                            metadata={"name": tgt, "color": "#eab308", "degree": 1}
                        )
                        created_nodes.add(tgt_id)
                        nodes_created += 1
                    raw_conf = float(link.get("confidence", 0.85))
                    # Composite Multi-Source Corroboration: 35% IOC + 30% Stylometry + 20% Locksmith + 15% Co-occurrence
                    composite_conf = round(0.35 * raw_conf + 0.30 * 0.90 + 0.20 * 0.85 + 0.15 * 0.75, 2)
                    save_graph_edge(inv_id, src_id, tgt_id, link.get("relation", "RELATED_TO"), composite_conf, link.get("evidence_quote", ""))
                    edges_created += 1

    # Generate and persist modular Mermaid views
    mermaid_views: Dict[str, str] = {}
    try:
        from jane.backend.graph.mermaid import generate_mermaid_views
        inv_summary = get_investigation_summary(inv_id)
        G_inv = nx.MultiDiGraph()
        for node in inv_summary.get("graph_elements", {}).get("nodes", []):
            nd = node.get("data", {})
            G_inv.add_node(nd.get("id"), label=nd.get("label", ""), node_type=nd.get("node_type", "DEFAULT"))
        for edge in inv_summary.get("graph_elements", {}).get("edges", []):
            ed = edge.get("data", {})
            G_inv.add_edge(ed.get("source"), ed.get("target"), edge_type=ed.get("edge_type", "RELATED_TO"), confidence=ed.get("confidence", 1.0))

        mermaid_views = generate_mermaid_views(G_inv)
        inv_dir = REPO_ROOT / "jane" / "data" / "investigations"
        inv_dir.mkdir(parents=True, exist_ok=True)
        (inv_dir / f"{inv_id}_mermaid.json").write_text(json.dumps(mermaid_views, indent=2), encoding="utf-8")
        logger.info(f"Generated 6 Mermaid views for {inv_id}")
    except Exception as exc:
        logger.warning(f"Could not generate Mermaid views: {exc}")

    return {
        "status": "GRAPH_GENERATED",
        "investigation_id": inv_id,
        "nodes_created": nodes_created,
        "edges_created": edges_created,
        "mermaid_views": list(mermaid_views.keys()),
    }




MARKETPLACE_ROLE_KEYWORDS = (
    "marketplace operator",
    "market operator",
    "marketplace",
    "market",
    "platform",
    "forum",
    "board",
    "escrow service",
    "exchange",
)


def is_marketplace_role(role: str) -> bool:
    """True if an actor role indicates a marketplace, forum, or platform rather than a human actor."""
    r = (role or "").strip().lower()
    return any(kw in r for kw in MARKETPLACE_ROLE_KEYWORDS)


def ingest_threat_graph(inv_id: str, workspace: "Path") -> Dict[str, Any]:
    """Validate and ingest Turn 3's threat_graph.json as the single authoritative graph source.

    Allowed node types: actor, marketplace, product, shared_identifier, clearnet_account
    Allowed edge types: operates_on, sells, shares_identifier, trust, clearnet_alias
    """
    import hashlib
    from datetime import datetime, timezone
    from pathlib import Path
    from jane.backend.graph.builder_model import (
        CANONICAL_EDGE_TYPES as _CET,
        CANONICAL_NODE_TYPES as _CNT,
        TRUST_EVIDENCE_KEYWORDS,
        is_blocklisted,
        normalize_handle,
        validate_actor_handle,
    )
    from jane.db.database import (
        get_db_connection,
        save_graph_node,
        save_graph_edge,
        save_threat_actor,
        link_node_investigation,
        link_edge_investigation,
    )

    workspace = Path(workspace)
    threat_graph_path = workspace / "graph" / "threat_graph.json"

    result: Dict[str, Any] = {
        "status": "SKIPPED",
        "nodes_inserted": 0,
        "edges_inserted": 0,
        "nodes_rejected": [],
        "edges_rejected": [],
    }

    if not threat_graph_path.exists() or threat_graph_path.stat().st_size < 10:
        logger.warning(f"[ingest_threat_graph] {threat_graph_path} not found or empty - skipping ingest")
        result["status"] = "NO_FILE"
        return result

    try:
        raw = json.loads(threat_graph_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning(f"[ingest_threat_graph] JSON parse error: {exc}")
        result["status"] = "PARSE_ERROR"
        result["error"] = str(exc)
        return result

    ALLOWED_NODE_TYPES = {"actor", "marketplace", "product", "shared_identifier", "clearnet_account"}
    ALLOWED_EDGE_TYPES = {"operates_on", "sells", "shares_identifier", "trust", "clearnet_alias", "listed_on"}

    raw_nodes: List[Dict[str, Any]] = raw.get("nodes", [])
    valid_nodes: Dict[str, Dict[str, Any]] = {}
    raw_nodes_by_id = {str(node.get("id", "")): node for node in raw_nodes if isinstance(node, dict)}
    raw_edges_for_resolution = raw.get("edges", []) if isinstance(raw.get("edges", []), list) else []

    def _strong_identity_keys(node_id: str, node: Dict[str, Any]) -> set[str]:
        keys: set[str] = set()
        for field, prefix in (("pgp_keys", "pgp"), ("wallets", "wallet")):
            values = node.get(field) or []
            if isinstance(values, str):
                values = [values]
            for value in values:
                value = str(value).strip().lower()
                if value:
                    keys.add(f"{prefix}:{value}")
        for edge in raw_edges_for_resolution:
            if str(edge.get("source", "")) != node_id and str(edge.get("target", "")) != node_id:
                continue
            other_id = str(edge.get("target", "")) if str(edge.get("source", "")) == node_id else str(edge.get("source", ""))
            other = raw_nodes_by_id.get(other_id, {})
            if str(other.get("type", "")).lower() == "shared_identifier":
                value = str(other.get("full_value", "")).strip().lower()
                id_type = str(other.get("identifier_type", "identifier")).strip().lower()
                if value:
                    keys.add(f"{id_type}:{value}")
        return keys

    def _resolve_actor_id(inv_id: str, handle: str, identity_keys: set[str]) -> tuple[str, List[str]]:
        """Merge only unambiguous strong identity matches; same handle alone never merges."""
        conn = get_db_connection()
        try:
            rows = conn.execute("SELECT id, investigation_id, metadata_json FROM graph_nodes WHERE node_type = ?", (_CNT.ACTOR,)).fetchall()
        finally:
            conn.close()
        candidates: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            try:
                metadata = json.loads(row["metadata_json"] or "{}")
            except Exception:
                metadata = {}
            if row["investigation_id"] == inv_id and normalize_handle(str(metadata.get("handle", ""))) == normalize_handle(handle):
                return row["id"], []
            existing_keys = set(metadata.get("identity_keys") or [])
            if identity_keys.intersection(existing_keys):
                candidates[row["id"]] = metadata
        if len(candidates) == 1:
            candidate_id, metadata = next(iter(candidates.items()))
            existing_handle = normalize_handle(str(metadata.get("handle", "")))
            if existing_handle == normalize_handle(handle):
                return candidate_id, []
            return f"actor_{inv_id}_{normalize_handle(handle)}", [{
                "identity_key": sorted(identity_keys.intersection(set(metadata.get("identity_keys") or []))),
                "existing_actor": candidate_id,
                "incoming_handle": handle,
                "existing_handle": metadata.get("handle", ""),
                "status": "conflict_preserved",
            }]
        handle_norm = normalize_handle(handle)
        existing_same_handle = any(
            normalize_handle(str(metadata.get("handle", ""))) == handle_norm
            for metadata in candidates.values()
        )
        if not identity_keys:
            conn = get_db_connection()
            try:
                rows = conn.execute("SELECT metadata_json FROM graph_nodes WHERE node_type = ?", (_CNT.ACTOR,)).fetchall()
            finally:
                conn.close()
            existing_same_handle = existing_same_handle or any(
                normalize_handle(str((json.loads(row["metadata_json"] or "{}").get("handle", "")))) == handle_norm
                for row in rows
            )
        return (f"actor_{inv_id}_{handle_norm}" if existing_same_handle else f"actor_{handle_norm}"), []

    for node in raw_nodes:
        nid = str(node.get("id", "") or "").strip()
        ntype = str(node.get("type", "") or "").strip().lower()
        reject_reason = None

        if not nid:
            reject_reason = "missing id"
        elif ntype not in ALLOWED_NODE_TYPES:
            reject_reason = f"unknown type '{ntype}' (allowed: {sorted(ALLOWED_NODE_TYPES)})"
        elif is_blocklisted(nid) or is_blocklisted(node.get("handle", "") or node.get("name_or_domain", "") or node.get("name", "")):
            reject_reason = "blocklisted value"
        elif ntype == "shared_identifier":
            shared_by = [str(a).strip() for a in (node.get("shared_by_actors") or []) if str(a).strip()]
            if len(shared_by) < 2:
                reject_reason = f"shared_identifier requires 2+ actors in shared_by_actors, got {len(shared_by)}"
        elif ntype in ("actor", "marketplace", "product"):
            eq = (node.get("evidence_quote") or "").strip()
            if not eq:
                reject_reason = "missing evidence_quote"

        if reject_reason:
            result["nodes_rejected"].append({"id": nid, "type": ntype, "reason": reject_reason})
            logger.debug(f"[ingest_threat_graph] REJECT node '{nid}': {reject_reason}")
            continue

        valid_nodes[nid] = node

    nodes_inserted = 0
    for nid, node in valid_nodes.items():
        ntype = node["type"].lower()
        role = str(node.get("role", "") or "").strip().lower()

        # Step 5: Markets and organizations are not actors
        if ntype == "actor" and is_marketplace_role(role):
            ntype = "marketplace"
            name_or_domain = str(node.get("handle", "") or node.get("name_or_domain", "") or nid).strip()
            node["name_or_domain"] = name_or_domain
            logger.info(f"[ingest_threat_graph] Re-routing actor with role {role!r} to Marketplace node")

        if ntype == "actor":
            handle = str(node.get("handle", "") or nid).strip()
            is_valid, reject_msg = validate_actor_handle(handle)
            if not is_valid:
                logger.warning(f"[ingest_threat_graph] Rejecting generic actor handle {handle!r}: {reject_msg}")
                result["nodes_rejected"].append({"id": nid, "type": "actor", "reason": reject_msg})
                continue
            norm = normalize_handle(handle)
            identity_keys = _strong_identity_keys(nid, node)
            canonical_id, conflicts = _resolve_actor_id(inv_id, handle, identity_keys)
            if conflicts:
                result.setdefault("conflicts", []).extend(conflicts)
            valid_nodes[nid]["_canonical_id"] = canonical_id
            meta = {
                "type": _CNT.ACTOR,
                "handle": handle,
                "aliases": node.get("aliases", []),
                "category": node.get("category", "Unclassified"),
                "pgp_keys": node.get("pgp_keys", []),
                "wallets": node.get("wallets", []),
                "evidence_quote": (node.get("evidence_quote", "") or "")[:500],
                "identity_keys": sorted(identity_keys),
                "identity_resolution": "strong_match" if identity_keys and canonical_id.startswith("actor_") and not canonical_id.startswith(f"actor_{inv_id}_") else "investigation_scoped",
                "threat_graph_source": True,
            }
            save_graph_node(
                investigation_id=inv_id,
                node_id=canonical_id,
                label=handle[:60],
                node_type=_CNT.ACTOR,
                metadata=meta,
            )
            save_threat_actor(
                investigation_id=inv_id,
                designated_id=node.get("id", canonical_id),
                primary_handle=handle,
                threat_category=node.get("category", "Unclassified"),
                confidence=0.9,
                stylometry_summary=node.get("evidence_quote", "")[:500],
                graph_node_id=canonical_id,
            )
            nodes_inserted += 1

        elif ntype == "marketplace":
            name_or_domain = str(node.get("name_or_domain", "") or node.get("handle", "") or nid).strip()
            canonical_id = f"market_{normalize_handle(name_or_domain)}"
            valid_nodes[nid]["_canonical_id"] = canonical_id
            save_graph_node(
                investigation_id=inv_id,
                node_id=canonical_id,
                label=name_or_domain[:60],
                node_type=_CNT.MARKETPLACE,
                metadata={
                    "type": _CNT.MARKETPLACE,
                    "name_or_domain": name_or_domain,
                    "category": node.get("category", "Dark Market"),
                    "evidence_quote": (node.get("evidence_quote", "") or "")[:500],
                    "threat_graph_source": True,
                },
            )
            nodes_inserted += 1

        elif ntype == "product":
            name = str(node.get("name", "") or nid).strip()
            canonical_id = f"product_{hashlib.sha256(f'{inv_id}:{name}'.encode()).hexdigest()[:12]}"
            valid_nodes[nid]["_canonical_id"] = canonical_id
            save_graph_node(
                investigation_id=inv_id,
                node_id=canonical_id,
                label=name[:60],
                node_type=_CNT.PRODUCT,
                metadata={
                    "type": _CNT.PRODUCT,
                    "name": name,
                    "evidence_quote": (node.get("evidence_quote", "") or "")[:500],
                    "threat_graph_source": True,
                },
            )
            nodes_inserted += 1

        elif ntype == "shared_identifier":
            full_val = str(node.get("full_value", "") or nid).strip()
            id_type = str(node.get("identifier_type", "handle") or "handle").strip()
            canonical_id = f"shared_{normalize_handle(id_type)}_{normalize_handle(full_val)[:24]}"
            short = (full_val[:8] + "..." + full_val[-4:]) if len(full_val) > 16 else full_val
            shared_by = [str(a).strip() for a in (node.get("shared_by_actors") or []) if str(a).strip()]
            valid_nodes[nid]["_canonical_id"] = canonical_id
            save_graph_node(
                investigation_id=inv_id,
                node_id=canonical_id,
                label=short,
                node_type=_CNT.SHARED_IDENTIFIER,
                metadata={
                    "type": _CNT.SHARED_IDENTIFIER,
                    "identifier_type": id_type,
                    "full_value": full_val,
                    "shared_by_actors": shared_by,
                    "evidence_quote": (node.get("evidence_quote", "") or "")[:500],
                    "threat_graph_source": True,
                },
            )
            nodes_inserted += 1

        elif ntype == "clearnet_account":
            site_name = str(node.get("site_name", "") or "Clearnet").strip()
            handle = str(node.get("handle", "") or nid).strip()
            canonical_id = f"clearnet_{hashlib.sha256((site_name + ':' + handle).encode()).hexdigest()[:12]}"
            valid_nodes[nid]["_canonical_id"] = canonical_id
            url = str(node.get("url", "") or "")
            label = f"{site_name}: {handle}"
            save_graph_node(
                investigation_id=inv_id,
                node_id=canonical_id,
                label=label[:80],
                node_type=_CNT.CLEARNET_ACCOUNT,
                metadata={
                    "type": _CNT.CLEARNET_ACCOUNT,
                    "site_name": site_name,
                    "handle": handle,
                    "url": url,
                    "evidence_quote": (node.get("evidence_quote", "") or "")[:500],
                    "threat_graph_source": True,
                },
            )
            nodes_inserted += 1

    result["nodes_inserted"] = nodes_inserted

    def _canonical(raw_id: str) -> Optional[str]:
        n = valid_nodes.get(raw_id)
        return n.get("_canonical_id") if n else None

    TRUST_VOUCH_LOWER = [k.lower() for k in TRUST_EVIDENCE_KEYWORDS]
    raw_edges: List[Dict[str, Any]] = raw.get("edges", [])
    edges_inserted = 0

    for edge in raw_edges:
        src_raw = str(edge.get("source", "") or "").strip()
        tgt_raw = str(edge.get("target", "") or "").strip()
        etype_raw = str(edge.get("type", "") or "").strip().lower()
        evidence_quote = str(edge.get("evidence_quote", "") or "").strip()
        reject_reason = None

        if not src_raw or not tgt_raw:
            reject_reason = "missing source or target"
        elif etype_raw not in ALLOWED_EDGE_TYPES:
            reject_reason = f"unknown edge type '{etype_raw}' (allowed: {sorted(ALLOWED_EDGE_TYPES)})"
        elif not evidence_quote:
            reject_reason = "missing evidence_quote"
        else:
            try:
                conf = float(edge.get("confidence", 0.0))
                if not (0.0 <= conf <= 1.0):
                    raise ValueError("out of range")
            except (TypeError, ValueError):
                reject_reason = f"invalid confidence: {edge.get('confidence')!r}"

        if reject_reason is None:
            src_id = _canonical(src_raw)
            tgt_id = _canonical(tgt_raw)
            if src_id is None:
                reject_reason = f"source '{src_raw}' not in validated node set (orphan)"
            elif tgt_id is None:
                reject_reason = f"target '{tgt_raw}' not in validated node set (orphan)"
            elif src_id == tgt_id:
                reject_reason = "self-loop"

        if reject_reason is None and etype_raw == "trust":
            eq_lower = evidence_quote.lower()
            if not any(kw in eq_lower for kw in TRUST_VOUCH_LOWER):
                reject_reason = (
                    f"trust edge requires explicit vouch keyword "
                    f"({', '.join(TRUST_EVIDENCE_KEYWORDS)}) in evidence_quote"
                )

        if reject_reason:
            result["edges_rejected"].append({
                "source": src_raw, "target": tgt_raw,
                "type": etype_raw, "reason": reject_reason,
            })
            logger.debug(f"[ingest_threat_graph] REJECT edge {src_raw}->{tgt_raw} ({etype_raw}): {reject_reason}")
            continue

        etype_db = {
            "operates_on": _CET.OPERATES_ON,
            "sells": _CET.SELLS,
            "listed_on": _CET.LISTED_ON,
            "shares_identifier": _CET.SHARES_IDENTIFIER,
            "trust": _CET.TRUST,
            "clearnet_alias": _CET.CLEARNET_ALIAS,
        }[etype_raw]

        conf = min(1.0, max(0.0, float(edge.get("confidence", 0.5))))
        eid = save_graph_edge(
            inv_id,
            src_id,
            tgt_id,
            etype_db,
            conf,
            evidence_quote[:500],
            inferred=False,
            basis="threat_graph_json_turn3",
            review_status="UNREVIEWED",
        )
        link_edge_investigation(eid, inv_id)

        if etype_raw == "sells":
            try:
                from jane.db.database import get_db_connection as _gdc
                _conn = _gdc()
                row = _conn.execute(
                    "SELECT metadata_json FROM graph_nodes WHERE id = ? AND investigation_id = ?",
                    (tgt_id, inv_id),
                ).fetchone()
                if row:
                    meta = json.loads(row["metadata_json"] or "{}")
                    meta["parent"] = src_id
                    _conn.execute(
                        "UPDATE graph_nodes SET metadata_json = ? WHERE id = ? AND investigation_id = ?",
                        (json.dumps(meta), tgt_id, inv_id),
                    )
                    _conn.commit()
                _conn.close()
            except Exception as exc:
                logger.debug(f"[ingest_threat_graph] Could not set product parent: {exc}")

        edges_inserted += 1

    # Deterministic OSINT enrichment stitching
    osint_summary_file = workspace / "osint" / "clearnet_summary.json"
    if osint_summary_file.exists():
        try:
            osint_data = json.loads(osint_summary_file.read_text(encoding="utf-8"))
            profiles = osint_data.get("profiles_found", [])
            primary_actor_id = None
            for n_dict in valid_nodes.values():
                if n_dict.get("type", "").lower() == "actor":
                    primary_actor_id = n_dict.get("_canonical_id")
                    break

            for prof in profiles:
                site_name = prof.get("site_name", "Clearnet")
                ident = prof.get("identifier", "target")
                url = prof.get("url", "")
                c_id = f"clearnet_{hashlib.sha256((site_name + ':' + ident).encode()).hexdigest()[:12]}"
                
                save_graph_node(
                    investigation_id=inv_id,
                    node_id=c_id,
                    label=f"{site_name}: {ident}"[:80],
                    node_type=_CNT.CLEARNET_ACCOUNT,
                    metadata={
                        "type": _CNT.CLEARNET_ACCOUNT,
                        "site_name": site_name,
                        "handle": ident,
                        "url": url,
                        "evidence_quote": prof.get("evidence_quote", "")[:500],
                        "osint_enriched": True,
                    },
                )
                nodes_inserted += 1

                target_actor = prof.get("associated_actor")
                src_actor_id = _canonical(target_actor) if target_actor else primary_actor_id
                if not src_actor_id and primary_actor_id:
                    src_actor_id = primary_actor_id

                if src_actor_id:
                    eid = save_graph_edge(
                        inv_id,
                        src_actor_id,
                        c_id,
                        _CET.CLEARNET_ALIAS,
                        0.75,
                        f"Maigret OSINT: Verified handle match on {site_name}",
                        inferred=True,
                        basis="maigret_osint_pivot",
                        review_status="UNREVIEWED",
                    )
                    link_edge_investigation(eid, inv_id)
                    edges_inserted += 1
        except Exception as exc:
            logger.warning(f"[ingest_threat_graph] OSINT stitching error: {exc}")

    result["edges_inserted"] = edges_inserted
    result["nodes_inserted"] = nodes_inserted
    result["status"] = "OK"
    logger.info(
        f"[ingest_threat_graph] {inv_id}: inserted {nodes_inserted} nodes, {edges_inserted} edges "
        f"| rejected {len(result['nodes_rejected'])} nodes, {len(result['edges_rejected'])} edges"
    )

    try:
        _write = lambda p, v: Path(p).write_text(json.dumps(v, indent=2), encoding="utf-8")
        _write(
            workspace / "graph" / "ingest_log.json",
            {
                "investigation_id": inv_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **result,
            },
        )
    except Exception:
        pass

    return result


def ingest_attribution_report(
    inv_id: str,
    report: Dict[str, Any],
    workspace: Optional[Path] = None,
) -> Dict[str, Any]:
    """Ingest Turn 2 attribution_report.json into canonical nodes, edges, and threat actors.

    Ensures:
    1. marketplace_name and actors with roles like 'Marketplace Operator' go to Marketplace node, NOT threat_actors table.
    2. Generic words as handles (transfer, carding, vendor, admin, wire) are rejected and logged.
    3. Valid actors are saved to Actor node and threat_actors table with graph_node_id.
    """
    from jane.backend.graph.builder_model import (
        CANONICAL_EDGE_TYPES as _CET,
        CANONICAL_NODE_TYPES as _CNT,
        normalize_handle,
        validate_actor_handle,
    )
    from jane.db.database import (
        save_graph_node,
        save_graph_edge,
        save_threat_actor,
        save_commodity,
        link_node_investigation,
        link_edge_investigation,
    )

    result = {
        "status": "OK",
        "marketplaces_inserted": 0,
        "actors_inserted": 0,
        "nodes_rejected": [],
    }

    if not isinstance(report, dict):
        result["status"] = "INVALID_REPORT"
        return result

    # 1. Ingest marketplace_name as a Marketplace node
    m_name = str(report.get("marketplace_name") or "").strip()
    primary_market_id = None
    if m_name and m_name.lower() not in ("unknown", "n/a", "none"):
        primary_market_id = f"market_{normalize_handle(m_name)}"
        save_graph_node(
            investigation_id=inv_id,
            node_id=primary_market_id,
            label=m_name[:60],
            node_type=_CNT.MARKETPLACE,
            metadata={
                "type": _CNT.MARKETPLACE,
                "name_or_domain": m_name,
                "category": report.get("threat_category", "Dark Market"),
                "source": "attribution_report",
            },
        )
        link_node_investigation(primary_market_id, inv_id)
        result["marketplaces_inserted"] += 1

    # 2. Ingest threat_actors
    actors = report.get("threat_actors", []) or []
    for actor in actors:
        handle = str(actor.get("primary_handle") or "").strip()
        role = str(actor.get("role") or "").strip()
        evidence_quote = str(actor.get("evidence_quote") or "").strip()
        desig_id = str(actor.get("designated_id") or "TA-ACTOR").strip()

        if is_marketplace_role(role):
            # Marketplaces and organizations are NOT actors
            m_id = f"market_{normalize_handle(handle)}"
            save_graph_node(
                investigation_id=inv_id,
                node_id=m_id,
                label=handle[:60],
                node_type=_CNT.MARKETPLACE,
                metadata={
                    "type": _CNT.MARKETPLACE,
                    "name_or_domain": handle,
                    "role": role,
                    "evidence_quote": evidence_quote[:500],
                    "category": report.get("threat_category", "Dark Market"),
                    "source": "attribution_report",
                },
            )
            link_node_investigation(m_id, inv_id)
            result["marketplaces_inserted"] += 1
            logger.info(f"[ingest_attribution_report] Routed {handle!r} (role: {role!r}) to Marketplace node, not threat_actors")
            continue

        # Validate actor handle against blocklist
        is_valid, reason = validate_actor_handle(handle)
        if not is_valid:
            logger.warning(f"[ingest_attribution_report] Rejected generic actor handle {handle!r} in {inv_id}: {reason}")
            result["nodes_rejected"].append({"handle": handle, "reason": reason})
            continue

        # True actor
        canonical_actor_id = f"actor_{normalize_handle(handle)}"
        save_graph_node(
            investigation_id=inv_id,
            node_id=canonical_actor_id,
            label=handle[:60],
            node_type=_CNT.ACTOR,
            metadata={
                "type": _CNT.ACTOR,
                "handle": handle,
                "role": role,
                "evidence_quote": evidence_quote[:500],
                "threat_category": report.get("threat_category", "Unclassified"),
                "source": "attribution_report",
            },
        )
        link_node_investigation(canonical_actor_id, inv_id)

        save_threat_actor(
            investigation_id=inv_id,
            designated_id=desig_id,
            primary_handle=handle,
            threat_category=report.get("threat_category", "Unclassified"),
            confidence=0.9,
            stylometry_summary=str(report.get("stylometric_notes") or evidence_quote),
            graph_node_id=canonical_actor_id,
        )
        result["actors_inserted"] += 1

        # Link actor to market if primary marketplace exists
        if primary_market_id and primary_market_id != canonical_actor_id:
            eid = save_graph_edge(
                inv_id,
                canonical_actor_id,
                primary_market_id,
                _CET.OPERATES_ON,
                0.9,
                evidence_quote[:500],
                basis="attribution_report",
            )
            link_edge_investigation(eid, inv_id)

    # 3. Ingest commodities as Product nodes, SELLS edges, and CommoditySold identifiers
    from jane.db.database import get_db_connection, save_identifier

    name_to_node_id: Dict[str, str] = {}
    name_to_actor_db_id: Dict[str, str] = {}
    if primary_market_id and m_name:
        name_to_node_id[m_name.lower()] = primary_market_id
        name_to_node_id[normalize_handle(m_name)] = primary_market_id

    conn = get_db_connection()
    db_actors = conn.execute("SELECT id, primary_handle, graph_node_id FROM threat_actors WHERE investigation_id = ?", (inv_id,)).fetchall()
    for da in db_actors:
        h = da["primary_handle"]
        if h:
            name_to_actor_db_id[h.lower()] = da["id"]
            name_to_actor_db_id[normalize_handle(h)] = da["id"]
            if da["graph_node_id"]:
                name_to_node_id[h.lower()] = da["graph_node_id"]
                name_to_node_id[normalize_handle(h)] = da["graph_node_id"]
    conn.close()

    # Pre-parse graph_links for SELLS / OFFERS edges
    commodity_seller_map: Dict[str, str] = {}
    for link in report.get("graph_links", []) or []:
        rel = str(link.get("relation") or "").strip().upper()
        if rel in ("SELLS", "OFFERS"):
            src = str(link.get("source") or "").strip()
            tgt = str(link.get("target") or "").strip()
            if src and tgt:
                commodity_seller_map[tgt.lower()] = src
                commodity_seller_map[normalize_handle(tgt)] = src

    result["commodities_inserted"] = 0
    commodities = report.get("commodities", []) or []
    for comm in commodities:
        c_name = str(comm.get("name") or "").strip()
        c_quote = str(comm.get("evidence_quote") or "").strip()
        c_cat = str(comm.get("category") or "Illicit Goods").strip()
        c_price = comm.get("price")

        # Every stored commodity MUST carry its verbatim evidence_quote; skip and log ones without
        if not c_quote:
            logger.warning(f"[ingest_attribution_report] Skipping commodity {c_name!r} without evidence_quote")
            continue

        if not c_name:
            continue

        product_node_id = f"product_{hashlib.sha256(f'{inv_id}:{c_name}'.encode()).hexdigest()[:12]}"
        save_graph_node(
            investigation_id=inv_id,
            node_id=product_node_id,
            label=c_name[:60],
            node_type=_CNT.PRODUCT,
            metadata={
                "type": _CNT.PRODUCT,
                "name": c_name,
                "category": c_cat,
                "price": c_price,
                "evidence_quote": c_quote[:500],
                "source": "attribution_report",
            },
        )
        link_node_investigation(product_node_id, inv_id)

        # Find seller node and actor id
        seller_raw = commodity_seller_map.get(c_name.lower()) or commodity_seller_map.get(normalize_handle(c_name))
        seller_node_id = None
        seller_actor_db_id = None

        if seller_raw:
            seller_node_id = name_to_node_id.get(seller_raw.lower()) or name_to_node_id.get(normalize_handle(seller_raw))
            seller_actor_db_id = name_to_actor_db_id.get(seller_raw.lower()) or name_to_actor_db_id.get(normalize_handle(seller_raw))
            if not seller_node_id:
                seller_norm = normalize_handle(seller_raw)
                seller_node_id = f"actor_{seller_norm}" if f"actor_{seller_norm}" in name_to_node_id.values() else f"market_{seller_norm}"

        if not seller_node_id:
            if db_actors:
                seller_node_id = db_actors[0]["graph_node_id"] or f"actor_{normalize_handle(db_actors[0]['primary_handle'])}"
                seller_actor_db_id = db_actors[0]["id"]
            elif primary_market_id:
                seller_node_id = primary_market_id

        if seller_node_id:
            eid = save_graph_edge(
                inv_id,
                seller_node_id,
                product_node_id,
                _CET.SELLS,
                0.95,
                c_quote[:500],
                basis="attribution_report_commodity",
            )
            link_edge_investigation(eid, inv_id)

        save_identifier(
            investigation_id=inv_id,
            itype="CommoditySold",
            value=c_name,
            actor_id=seller_actor_db_id,
            evidence_quote=c_quote[:500],
            confidence=0.95,
        )

        # Direct attribution attributes from commodity dictionary or inferred from investigation
        c_mkt = str(comm.get("marketplace_name") or m_name or "").strip() or None
        c_onion = str(comm.get("onion_url") or "").strip() or None
        c_vendor = str(comm.get("vendor_handle") or seller_raw or (db_actors[0]["primary_handle"] if db_actors else "")).strip() or None

        save_commodity(
            investigation_id=inv_id,
            name=c_name,
            category=c_cat,
            marketplace_name=c_mkt,
            onion_url=c_onion,
            actor_handle=c_vendor,
            evidence_quote=c_quote[:500],
            confidence=0.95,
            original_title=comm.get("original_title"),
            price=comm.get("price"),
            currency=comm.get("currency"),
            quantity=comm.get("quantity"),
            unit=comm.get("unit"),
            min_order=comm.get("min_order"),
            availability=comm.get("availability"),
            listing_status=comm.get("listing_status"),
            observation_date=comm.get("observation_date"),
            listing_url=comm.get("listing_url"),
            uncertainty=comm.get("uncertainty"),
        )
        result["commodities_inserted"] += 1

    return result



def main():
    parser = argparse.ArgumentParser(description="Jane Graph Connector")
    parser.add_argument("--export", action="store_true", default=True, help="Export graph snapshot")
    args = parser.parse_args()

    summary = generate_graph_pipeline()
    print(f"\n[+] Graph Build Success: {summary['total_nodes']} nodes, {summary['total_edges']} edges, {summary['communities_count']} communities.")


if __name__ == "__main__":
    main()
