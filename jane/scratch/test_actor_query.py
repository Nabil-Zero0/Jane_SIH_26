import sqlite3

conn = sqlite3.connect('data/jane.db')
conn.row_factory = sqlite3.Row

# Test actor query by ID or handle
def get_actor_dossier(actor_id):
    # 1. Resolve canonical actor
    actor = conn.execute("SELECT * FROM actors WHERE id = ?", (actor_id,)).fetchone()
    if not actor:
        # Try threat_actors
        ta = conn.execute("SELECT * FROM threat_actors WHERE id = ?", (actor_id,)).fetchone()
        if ta:
            actor = conn.execute("SELECT * FROM actors WHERE primary_handle = ?", (ta["primary_handle"],)).fetchone()
            if not actor:
                actor = dict(ta)
        else:
            actor = conn.execute("SELECT * FROM actors WHERE primary_handle = ?", (actor_id,)).fetchone()

    if not actor:
        return None

    actor_dict = dict(actor)
    canon_id = actor_dict["id"]
    handle = actor_dict["primary_handle"]

    # All matching actor IDs across tables (canonical ID, threat_actors IDs)
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
    actor_dict["stylometry_summary"] = stylometry_summaries[0] if stylometry_summaries else None

    # Aliases
    aliases = [dict(r) for r in conn.execute(
        "SELECT * FROM actor_aliases WHERE actor_id IN ({})".format(",".join("?" * len(matching_actor_ids))),
        list(matching_actor_ids)
    ).fetchall()]

    # Identifiers (canonical + raw identifiers)
    ci_rows = conn.execute(
        "SELECT * FROM canonical_identifiers WHERE actor_id IN ({})".format(",".join("?" * len(matching_actor_ids))),
        list(matching_actor_ids)
    ).fetchall()
    
    id_rows = conn.execute(
        "SELECT * FROM identifiers WHERE actor_id IN ({})".format(",".join("?" * len(matching_actor_ids))),
        list(matching_actor_ids)
    ).fetchall()

    seen_vals = set()
    identifiers = []
    for r in list(ci_rows) + list(id_rows):
        rd = dict(r)
        key = (rd.get("type"), rd.get("value"))
        if key not in seen_vals:
            seen_vals.add(key)
            identifiers.append(rd)

    # Marketplaces
    marketplaces = [dict(r) for r in conn.execute("""
        SELECT am.actor_id, am.marketplace_id, am.confidence, am.evidence_quote, am.first_seen,
               m.onion_domain, m.display_name, m.category AS market_category
        FROM actor_marketplace am
        JOIN marketplaces m ON m.id = am.marketplace_id
        WHERE am.actor_id IN ({})
    """.format(",".join("?" * len(matching_actor_ids))), list(matching_actor_ids)).fetchall()]

    # Products & Commodities
    products = [dict(r) for r in conn.execute("""
        SELECT ap.actor_id, ap.product_id, ap.confidence, ap.evidence_quote, ap.first_seen,
               p.name AS product_name, p.category AS product_category
        FROM actor_product ap
        JOIN products p ON p.id = ap.product_id
        WHERE ap.actor_id IN ({})
    """.format(",".join("?" * len(matching_actor_ids))), list(matching_actor_ids)).fetchall()]

    commodities = [dict(r) for r in conn.execute("""
        SELECT id, name AS product_name, category AS product_category, marketplace_name,
               onion_url, actor_handle, evidence_quote, confidence, created_at AS first_seen
        FROM commodities
        WHERE actor_handle = ?
    """, (handle,)).fetchall()]

    # Combine products + commodities
    all_products = products + commodities

    # Relationships & Trust
    trust_links = [dict(r) for r in conn.execute("""
        SELECT t.actor_id, a1.primary_handle AS source_handle,
               t.trusted_actor_id, a2.primary_handle AS target_handle,
               t.confidence, t.evidence_quote, t.created_at
        FROM actor_trust t
        LEFT JOIN actors a1 ON a1.id = t.actor_id
        LEFT JOIN actors a2 ON a2.id = t.trusted_actor_id
        WHERE t.actor_id IN ({ids}) OR t.trusted_actor_id IN ({ids})
    """.format(ids=",".join("?" * len(matching_actor_ids))), list(matching_actor_ids) * 2).fetchall()]

    # Clearnet accounts & OSINT
    clearnet = [dict(r) for r in conn.execute("""
        SELECT ca.*, aca.confidence, aca.evidence_quote AS association_evidence
        FROM actor_clearnet_account aca
        JOIN clearnet_accounts ca ON ca.id = aca.clearnet_account_id
        WHERE aca.actor_id IN ({ids})
        UNION
        SELECT ca.*, 0.8 AS confidence, ca.evidence_quote AS association_evidence
        FROM clearnet_accounts ca
        WHERE ca.actor_id IN ({ids})
    """.format(ids=",".join("?" * len(matching_actor_ids))), list(matching_actor_ids) * 2).fetchall()]

    osint_targets = [dict(r) for r in conn.execute("""
        SELECT ot.*, opr.platform, opr.username, opr.url, opr.status, opr.tags, opr.error_message, opr.searched_at
        FROM osint_targets ot
        LEFT JOIN osint_target_results opr ON opr.target_id = ot.id
        WHERE ot.associated_actor_id IN ({})
    """.format(",".join("?" * len(matching_actor_ids))), list(matching_actor_ids)).fetchall()]

    # Stylometry
    stylometry = [dict(r) for r in conn.execute("""
        SELECT * FROM stylometry_findings
        WHERE actor_id IN ({})
    """.format(",".join("?" * len(matching_actor_ids))), list(matching_actor_ids)).fetchall()]

    # OpSec
    opsec = [dict(r) for r in conn.execute("""
        SELECT * FROM opsec_findings
        WHERE actor_id IN ({})
    """.format(",".join("?" * len(matching_actor_ids))), list(matching_actor_ids)).fetchall()]

    # Attribution assessments
    assessments = [dict(r) for r in conn.execute("""
        SELECT * FROM attribution_assessments
        WHERE actor_id IN ({})
    """.format(",".join("?" * len(matching_actor_ids))), list(matching_actor_ids)).fetchall()]

    # Activities
    activities = [dict(r) for r in conn.execute("""
        SELECT * FROM actor_activities
        WHERE actor_id IN ({})
        ORDER BY created_at DESC
    """.format(",".join("?" * len(matching_actor_ids))), list(matching_actor_ids)).fetchall()]

    # Associated investigations
    inv_rows = conn.execute("""
        SELECT DISTINCT i.id, i.query, i.status, i.created_at, ei.entity_type
        FROM entity_investigations ei
        JOIN investigations i ON i.id = ei.investigation_id
        WHERE ei.entity_id IN ({}) OR ei.entity_id = ?
        UNION
        SELECT DISTINCT i.id, i.query, i.status, i.created_at, 'threat_actor' AS entity_type
        FROM threat_actors ta
        JOIN investigations i ON i.id = ta.investigation_id
        WHERE ta.primary_handle = ? OR ta.id IN ({})
    """.format(",".join("?" * len(matching_actor_ids)), ",".join("?" * len(matching_actor_ids))),
        list(matching_actor_ids) + [handle, handle] + list(matching_actor_ids)
    ).fetchall()
    investigations = [dict(r) for r in inv_rows]

    # Graph elements
    node_ids = set(matching_actor_ids)
    node_ids.add(f"actor_{handle}")
    node_ids.add(f"actor_{handle.lower().replace(' ', '_')}")
    for m in marketplaces:
        node_ids.add(m["marketplace_id"])
        node_ids.add(f"market_{m['onion_domain']}")
    for p in all_products:
        if p.get("product_id"): node_ids.add(p["product_id"])

    # Fetch edges involving these entities
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
    graph_nodes = [dict(r) for r in conn.execute(f"""
        SELECT * FROM graph_nodes
        WHERE id IN ({node_placeholders})
    """, list(all_edge_nodes)).fetchall()]

    # If graph_nodes is empty, construct synthetic nodes for visualization
    if not graph_nodes:
        graph_nodes = [{"data": {"id": canon_id, "label": handle, "type": "actor"}}]
        for m in marketplaces:
            graph_nodes.append({"data": {"id": m["marketplace_id"], "label": m["display_name"] or m["onion_domain"], "type": "marketplace"}})
            graph_edges.append({"data": {"id": f"{canon_id}-{m['marketplace_id']}", "source": canon_id, "target": m["marketplace_id"], "edge_type": "OPERATES_ON", "confidence": m["confidence"]}})
        for p in all_products[:6]:
            pid = p.get("product_id") or f"prod_{p['product_name'][:10]}"
            graph_nodes.append({"data": {"id": pid, "label": p["product_name"], "type": "product"}})
            graph_edges.append({"data": {"id": f"{canon_id}-{pid}", "source": canon_id, "target": pid, "edge_type": "SELLS", "confidence": p.get("confidence", 1.0)}})
    else:
        # Wrap in Cytoscape format if needed
        graph_nodes = [{"data": n} for n in graph_nodes]
        graph_edges = [{"data": e} for e in graph_edges]

    return {
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
    }

dossier = get_actor_dossier('act_counterfeitsales')
print('act_counterfeitsales dossier summary:')
print('Actor:', dossier['actor'])
print('Identifiers:', len(dossier['identifiers']))
print('Marketplaces:', len(dossier['marketplaces']))
print('Products:', len(dossier['products']))
print('Investigations:', len(dossier['investigations']))
print('Stylometry:', len(dossier['stylometry']))
print('Assessments:', len(dossier['attribution_assessments']))
print('Nodes:', len(dossier['graph_elements']['nodes']), 'Edges:', len(dossier['graph_elements']['edges']))

conn.close()
