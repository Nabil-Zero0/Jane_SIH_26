"""
Tests for Step 4: One authoritative graph writer and canonical node types.
Verifies:
1. run_graph() does not write actor nodes or THREAT_ACTOR nodes.
2. ingest_threat_graph() writes canonical 'Actor' nodes and populates threat_actors.graph_node_id.
3. server._handle_actors logic returns graph_edges for the actor via graph_node_id.
"""

import json
from pathlib import Path
import pytest

from jane.db.database import (
    create_investigation,
    get_db_connection,
    save_graph_node,
    save_graph_edge,
    save_threat_actor,
)
from jane.backend.graph.connector import run_graph, ingest_threat_graph


def test_run_graph_does_not_write_actor_nodes():
    inv_id = "inv_writer_test_1"
    create_investigation(query="weapons market", inv_id=inv_id)

    batch_data = {
        "batch_id": inv_id,
        "pages": [{
            "url": "http://darkmarketxyz.onion",
            "title": "Dark Market",
            "cleaned_text": "Vendor alpha sells products. Contact wire: transfer.",
            "response_headers": {"Server": "nginx/1.18"},
        }]
    }
    # Even if legacy ai_data contains threat_actors, run_graph must not write actor nodes
    legacy_ai_data = {
        "status": "AI_SYNTHESIZED",
        "reports_count": 1,
        "reports": [{
            "url": "http://darkmarketxyz.onion",
            "report": {
                "threat_actors": [{
                    "designated_id": "TA-LEGACY",
                    "primary_handle": "legacy_vendor",
                    "role": "Vendor",
                    "evidence_quote": "Vendor quote",
                }],
                "entities": [],
                "relationships": [],
            }
        }]
    }

    run_graph(inv_id=inv_id, batch_data=batch_data, ai_data=legacy_ai_data)

    conn = get_db_connection()
    actor_nodes = conn.execute(
        "SELECT * FROM graph_nodes WHERE investigation_id = ? AND node_type IN ('THREAT_ACTOR', 'Actor', 'ThreatActor')",
        (inv_id,)
    ).fetchall()
    actor_rows = conn.execute(
        "SELECT * FROM threat_actors WHERE investigation_id = ?",
        (inv_id,)
    ).fetchall()
    conn.close()

    assert len(actor_nodes) == 0, "run_graph must not write actor nodes"
    assert len(actor_rows) == 0, "run_graph must not write threat_actors rows"


def test_ingest_threat_graph_authoritative_writer(tmp_path):
    inv_id = "inv_writer_test_2"
    create_investigation(query="weapons market", inv_id=inv_id)

    ws = tmp_path / "investigations" / inv_id
    (ws / "graph").mkdir(parents=True, exist_ok=True)

    threat_graph_payload = {
        "investigation_id": inv_id,
        "nodes": [
            {
                "id": "actor_alpha",
                "type": "Actor",
                "handle": "vendor_alpha",
                "category": "Weapons Trafficking",
                "evidence_quote": "Vendor alpha active on Market X.",
            },
            {
                "id": "market_dark",
                "type": "Marketplace",
                "name_or_domain": "darkmarketxyz.onion",
                "category": "Dark Market",
                "evidence_quote": "Dark Market storefront.",
            }
        ],
        "edges": [
            {
                "source": "actor_alpha",
                "target": "market_dark",
                "type": "operates_on",
                "confidence": 0.95,
                "evidence_quote": "Vendor alpha operates on darkmarketxyz.onion storefront.",
            }
        ]
    }
    (ws / "graph" / "threat_graph.json").write_text(json.dumps(threat_graph_payload), encoding="utf-8")

    result = ingest_threat_graph(inv_id=inv_id, workspace=ws)
    assert result.get("status") == "OK"
    assert result.get("nodes_inserted") == 2
    assert result.get("edges_inserted") == 1

    conn = get_db_connection()
    actors = conn.execute("SELECT * FROM threat_actors WHERE investigation_id = ?", (inv_id,)).fetchall()
    assert len(actors) == 1
    actor = actors[0]
    assert actor["primary_handle"] == "vendor_alpha"
    assert actor["graph_node_id"] == "actor_vendoralpha"

    # Verify edge
    edges = conn.execute("SELECT * FROM graph_edges WHERE investigation_id = ?", (inv_id,)).fetchall()
    assert len(edges) == 1
    assert edges[0]["edge_type"] == "OPERATES_ON"
    assert edges[0]["source"] == "actor_vendoralpha"
    assert edges[0]["target"] == "market_darkmarketxyzonion"
    conn.close()


def test_actor_endpoint_returns_graph_edges():
    inv_id = "inv_writer_test_3"
    create_investigation(query="weapons market", inv_id=inv_id)

    # Save actor with graph_node_id
    actor_id = save_threat_actor(
        investigation_id=inv_id,
        designated_id="TA-001",
        primary_handle="shadow_seller",
        graph_node_id="actor_shadowseller",
    )

    # Save nodes and edge
    save_graph_node(inv_id, "actor_shadowseller", "shadow_seller", "Actor")
    save_graph_node(inv_id, "market_alpha", "Alpha Market", "Marketplace")
    save_graph_edge(inv_id, "actor_shadowseller", "market_alpha", "OPERATES_ON", 0.9, "Seller operates market")

    # Test server handler logic
    conn = get_db_connection()
    actor_row = conn.execute("SELECT * FROM threat_actors WHERE id = ?", (actor_id,)).fetchone()
    assert actor_row is not None
    actor = dict(actor_row)

    node_ids = set()
    if actor.get("graph_node_id"):
        node_ids.add(actor["graph_node_id"])
    node_ids.add(actor_id)
    handle = actor.get("primary_handle", "")
    if handle:
        node_ids.add(f"actor_{handle}")
        node_ids.add(f"actor_{handle.lower().replace(' ', '_')}")

    placeholders = ",".join("?" for _ in node_ids)
    edges_query = f"""
        SELECT * FROM graph_edges 
        WHERE investigation_id = ? 
          AND (source IN ({placeholders}) OR target IN ({placeholders}))
    """
    params = [actor["investigation_id"]] + list(node_ids) + list(node_ids)
    edges = [dict(r) for r in conn.execute(edges_query, params).fetchall()]
    conn.close()

    assert len(edges) == 1
    assert edges[0]["source"] == "actor_shadowseller"
    assert edges[0]["edge_type"] == "OPERATES_ON"


def test_turn2_and_turn3_both_run_yields_single_actor_node(tmp_path):
    from jane.backend.graph.connector import ingest_attribution_report

    inv_id = "inv_writer_dedup_test"
    create_investigation(query="weapons scan", inv_id=inv_id)

    ws = tmp_path / "investigations" / inv_id
    (ws / "graph").mkdir(parents=True, exist_ok=True)

    # 1. Turn 2 runs attribution report
    attr_report = {
        "marketplace_name": "MegaMarket",
        "threat_category": "Arms",
        "threat_actors": [
            {
                "designated_id": "TA-001",
                "primary_handle": "vendor_omega",
                "role": "Vendor",
                "evidence_quote": "Vendor omega selling on MegaMarket",
            }
        ],
        "commodities": [],
    }
    ingest_attribution_report(inv_id=inv_id, report=attr_report, workspace=ws)

    # 2. Turn 3 runs threat graph with same actor
    threat_graph_payload = {
        "investigation_id": inv_id,
        "nodes": [
            {
                "id": "actor_omega",
                "type": "Actor",
                "handle": "vendor_omega",
                "category": "Arms",
                "evidence_quote": "Vendor omega threat graph node",
            }
        ],
        "edges": []
    }
    (ws / "graph" / "threat_graph.json").write_text(json.dumps(threat_graph_payload), encoding="utf-8")
    ingest_threat_graph(inv_id=inv_id, workspace=ws)

    # 3. Assert strictly ONE node in graph_nodes and ONE actor in threat_actors
    conn = get_db_connection()
    nodes = conn.execute("SELECT * FROM graph_nodes WHERE investigation_id = ? AND node_type = 'Actor'", (inv_id,)).fetchall()
    assert len(nodes) == 1, f"Expected 1 Actor node, found {len(nodes)}"
    assert nodes[0]["id"] == "actor_vendoromega"

    actors = conn.execute("SELECT * FROM threat_actors WHERE investigation_id = ?", (inv_id,)).fetchall()
    assert len(actors) == 1, f"Expected 1 threat_actor row, found {len(actors)}"
    assert actors[0]["primary_handle"] == "vendor_omega"
    assert actors[0]["graph_node_id"] == "actor_vendoromega"
    conn.close()
