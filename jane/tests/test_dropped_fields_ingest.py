"""
Tests for Step 6: Ingest the dropped fields (commodities, marketplace_name, stylometric_notes).
Verifies:
1. Commodities with quotes are persisted as Product graph nodes.
2. Commodities carry verbatim evidence_quotes; items without quotes are skipped.
3. SELLS edges connect actors or marketplaces to the correct Product nodes.
4. Identifiers of type 'CommoditySold' are created with verbatim evidence_quote and linked to actor.
5. Stylometric notes are persisted as plain text into threat_actors.stylometry_summary.
"""

import json
from pathlib import Path
import pytest

from jane.backend.graph.connector import ingest_attribution_report
from jane.db.database import (
    create_investigation,
    get_db_connection,
)


def test_ingest_commodities_and_dropped_fields():
    inv_id = "inv_step6_test"
    create_investigation(query="counterfeiting scan", inv_id=inv_id)

    fixture_path = Path(__file__).parent / "fixtures" / "attribution_report_inv_19fba418.json"
    report = json.loads(fixture_path.read_text(encoding="utf-8"))

    # Add one invalid commodity missing an evidence quote to test skipping
    report["commodities"].append({
        "name": "Ghost Commodity Without Quote",
        "category": "Fraud",
        "evidence_quote": ""  # empty quote, must be skipped
    })

    result = ingest_attribution_report(inv_id=inv_id, report=report)
    assert result["status"] == "OK"
    assert result["commodities_inserted"] == 5  # 5 valid, 1 skipped

    conn = get_db_connection()

    # 1. Product nodes created
    products = conn.execute(
        "SELECT id, label, node_type, metadata_json FROM graph_nodes WHERE investigation_id = ? AND node_type = 'Product'",
        (inv_id,)
    ).fetchall()
    assert len(products) == 5
    product_labels = [p["label"] for p in products]
    assert any("Counterfeit 20 Dollar Bills" in lbl for lbl in product_labels)
    assert any("Canadian Fake ID" in lbl for lbl in product_labels)
    assert not any("Ghost Commodity" in lbl for lbl in product_labels)

    # 2. SELLS edges created
    sells_edges = conn.execute(
        "SELECT * FROM graph_edges WHERE investigation_id = ? AND edge_type = 'SELLS'",
        (inv_id,)
    ).fetchall()
    assert len(sells_edges) == 5
    for se in sells_edges:
        assert len(se["evidence_quote"]) > 0

    # 3. CommoditySold identifiers created with quotes
    commodity_idents = conn.execute(
        "SELECT * FROM identifiers WHERE investigation_id = ? AND type = 'CommoditySold'",
        (inv_id,)
    ).fetchall()
    assert len(commodity_idents) == 5
    for ci in commodity_idents:
        assert ci["evidence_quote"] != ""
        assert "Bills" in ci["value"] or "ID" in ci["value"] or "Drugs" in ci["value"] or "Psychedelics" in ci["value"]

    # 4. Stylometric notes in threat_actors.stylometry_summary as plain text
    actors = conn.execute("SELECT primary_handle, stylometry_summary FROM threat_actors WHERE investigation_id = ?", (inv_id,)).fetchall()
    assert len(actors) == 2
    for a in actors:
        assert "4 pages profiled" in a["stylometry_summary"]
        assert "Burrows Delta" in a["stylometry_summary"]

    # 5. Dedicated commodities table populated
    comms = conn.execute("SELECT * FROM commodities WHERE investigation_id = ?", (inv_id,)).fetchall()
    assert len(comms) == 5
    for c in comms:
        assert c["name"] != ""
        assert c["evidence_quote"] != ""
        assert c["confidence"] >= 0.9


    conn.close()
