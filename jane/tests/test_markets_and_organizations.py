"""
Tests for Step 5: Markets and organizations are not actors.
Verifies:
1. marketplace_name and actors with roles like 'Marketplace Operator' go to Marketplace nodes, NOT threat_actors table.
2. Real fixture attribution_report_inv_19fba418.json correctly routes THE X WAVE MARKET to Marketplace and does not store it in threat_actors.
3. Blocklist rejects generic words (wire: transfer, vendor, admin, transfer, carding, unknown).
4. Deterministic classification relies on role without guessing from handle alone.
"""

import json
from pathlib import Path
import pytest

from jane.backend.graph.builder_model import (
    NON_ENTITY_BLOCKLIST,
    is_blocklisted,
    validate_actor_handle,
)
from jane.backend.graph.connector import (
    is_marketplace_role,
    ingest_attribution_report,
    ingest_threat_graph,
)
from jane.db.database import (
    create_investigation,
    get_db_connection,
)


def test_generic_handle_blocklist():
    # Negative test cases: generic words must be rejected
    rejected = [
        "wire: transfer",
        "wire-transfer",
        "wire",
        "transfer",
        "transfers",
        "carding",
        "vendor",
        "admin",
        "administrator",
        "market",
        "marketplace",
        "seller",
        "unknown",
        "no vendor handle disclosed",
        "lead_vendor",
        "contact",
        "support",
    ]
    for h in rejected:
        valid, reason = validate_actor_handle(h)
        assert not valid, f"Expected {h!r} to be rejected, but got valid: {reason}"
        assert is_blocklisted(h), f"Expected {h!r} to be in blocklist"

    # Positive test cases: legitimate handles must be accepted
    accepted = [
        "CounterfeitSales",
        "torverified",
        "shadow_seller",
        "alpha_vendor_99",
        "kuganzodocs",
    ]
    for h in accepted:
        valid, reason = validate_actor_handle(h)
        assert valid, f"Expected {h!r} to be accepted, but got rejected: {reason}"


def test_is_marketplace_role():
    assert is_marketplace_role("Marketplace Operator")
    assert is_marketplace_role("market operator")
    assert is_marketplace_role("Forum Admin / Market Platform")
    assert is_marketplace_role("Dark Market")

    # Regular vendor roles are not markets
    assert not is_marketplace_role("Lead Vendor")
    assert not is_marketplace_role("Operator / Contact")
    assert not is_marketplace_role("Vendor / Escrow")


def test_ingest_attribution_report_with_fixture():
    inv_id = "inv_fixture_test_5"
    create_investigation(query="counterfeiting", inv_id=inv_id)

    fixture_path = Path(__file__).parent / "fixtures" / "attribution_report_inv_19fba418.json"
    report = json.loads(fixture_path.read_text(encoding="utf-8"))

    result = ingest_attribution_report(inv_id=inv_id, report=report)
    assert result["status"] == "OK"
    assert result["actors_inserted"] == 2
    assert result["marketplaces_inserted"] >= 2  # marketplace_name + THE X WAVE MARKET

    conn = get_db_connection()

    # 1. THE X WAVE MARKET must NOT be in threat_actors
    actors = conn.execute("SELECT * FROM threat_actors WHERE investigation_id = ?", (inv_id,)).fetchall()
    actor_handles = [a["primary_handle"] for a in actors]
    assert "THE X WAVE MARKET" not in actor_handles, "THE X WAVE MARKET must not be stored in threat_actors table"
    assert "CounterfeitSales" in actor_handles
    assert "torverified" in actor_handles
    assert len(actors) == 2

    # 2. THE X WAVE MARKET must be stored as a Marketplace graph node
    market_nodes = conn.execute(
        "SELECT * FROM graph_nodes WHERE investigation_id = ? AND node_type = 'Marketplace'",
        (inv_id,)
    ).fetchall()
    market_labels = [m["label"] for m in market_nodes]
    assert any("THE X WAVE MARKET" in lbl for lbl in market_labels)
    assert any("CounterfeitSales and Tordex Market" in lbl for lbl in market_labels)

    # 3. Check graph_edges: CounterfeitSales and torverified should have OPERATES_ON edges to marketplace
    edges = conn.execute("SELECT * FROM graph_edges WHERE investigation_id = ?", (inv_id,)).fetchall()
    assert len(edges) >= 2
    for e in edges:
        assert e["edge_type"] in ("OPERATES_ON", "SELLS")

    conn.close()


def test_ingest_threat_graph_rejects_generic_handles_and_reroutes_market_roles(tmp_path):
    inv_id = "inv_tg_test_5"
    create_investigation(query="weapons scan", inv_id=inv_id)

    ws = tmp_path / "investigations" / inv_id
    (ws / "graph").mkdir(parents=True, exist_ok=True)

    threat_graph = {
        "investigation_id": inv_id,
        "nodes": [
            {
                "id": "actor_junk",
                "type": "Actor",
                "handle": "wire: transfer",
                "evidence_quote": "Contact wire: transfer for order",
            },
            {
                "id": "actor_market",
                "type": "Actor",
                "handle": "SilkPlatform",
                "role": "Marketplace Operator",
                "evidence_quote": "SilkPlatform marketplace welcome message",
            },
            {
                "id": "actor_real",
                "type": "Actor",
                "handle": "real_weapons_dealer",
                "role": "Vendor",
                "evidence_quote": "Glock 19 available from real_weapons_dealer",
            },
        ],
        "edges": []
    }
    (ws / "graph" / "threat_graph.json").write_text(json.dumps(threat_graph), encoding="utf-8")

    result = ingest_threat_graph(inv_id=inv_id, workspace=ws)
    assert result["status"] == "OK"

    # wire: transfer must be rejected
    rejected_reasons = [r.get("reason", "") for r in result["nodes_rejected"]]
    assert any("wire: transfer" in r or "blocklisted" in r for r in rejected_reasons)

    conn = get_db_connection()
    actors = conn.execute("SELECT * FROM threat_actors WHERE investigation_id = ?", (inv_id,)).fetchall()
    assert len(actors) == 1
    assert actors[0]["primary_handle"] == "real_weapons_dealer"

    # SilkPlatform must be Marketplace node, not threat_actors
    nodes = conn.execute("SELECT * FROM graph_nodes WHERE investigation_id = ?", (inv_id,)).fetchall()
    node_types = {n["label"]: n["node_type"] for n in nodes}
    assert node_types.get("SilkPlatform") == "Marketplace"
    assert node_types.get("real_weapons_dealer") == "Actor"
    assert "wire: transfer" not in node_types
    conn.close()
