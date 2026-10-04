"""
Tests covering all 16 specification points for Jane Product Intelligence Contracts:
1. Validate the new Turn 2 JSON contract.
2. Test missing optional product fields.
3. Test multiple prices on one listing.
4. Test price + quantity + unit combinations.
5. Test explicit versus missing availability.
6. Test listings without prices.
7. Test listings without quantities.
8. Test multiple marketplaces.
9. Test multiple observations for the same normalized product.
10. Test ambiguous product names.
11. Test unsupported aliases.
12. Test evidence grounding.
13. Test invalid graph edge types.
14. Test Product -> LISTED_ON -> Marketplace.
15. Test legacy commodity records.
16. Test that no frontend/API regex is required to reconstruct price or quantity.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import pytest

from jane.backend.graph.builder_model import CANONICAL_EDGE_TYPES, CANONICAL_NODE_TYPES
from jane.backend.graph.connector import ingest_attribution_report, ingest_threat_graph
from jane.db import database
from jane.db.database import create_investigation, get_db_connection, init_db, save_commodity
from jane.db.intelligence import get_investigation_intelligence, persist_attribution_artifact
from jane.ai.opencode_bridge import _evidence_instruction, _graph_instruction
from jane.web.server import JaneRequestHandler


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    test_db = tmp_path / "test_jane.db"
    monkeypatch.setenv("JANE_DB_PATH", str(test_db))
    monkeypatch.setattr(database, "DB_PATH", test_db)
    init_db(test_db)
    return test_db


# 1. Validate the new Turn 2 JSON contract
def test_1_turn2_json_contract_and_prompt(tmp_path):
    prompt = _evidence_instruction(tmp_path)
    assert "original_title" in prompt
    assert "min_order" in prompt
    assert "observation_date" in prompt
    assert "listing_status" in prompt
    assert "Deduplication Doctrine" in prompt


# 2. Test missing optional product fields
def test_2_missing_optional_product_fields(tmp_path):
    inv_id = "inv_test2"
    create_investigation(query="fraud test", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "marketplace_name": "Test Market",
        "threat_category": "Financial Fraud",
        "threat_actors": [{"designated_id": "TA-01", "primary_handle": "VendorX", "role": "Vendor"}],
        "commodities": [
            {
                "name": "Stolen Dumps",
                "evidence_quote": "Selling stolen dumps on market",
            }
        ],
    }
    counts = persist_attribution_artifact(inv_id, tmp_path, report)
    assert counts["products"] == 1
    assert counts["observations"] == 1

    conn = get_db_connection()
    obs = conn.execute("SELECT * FROM product_observations WHERE investigation_id = ?", (inv_id,)).fetchone()
    conn.close()
    assert obs["original_title"] == "Stolen Dumps"
    assert obs["price"] is None
    assert obs["quantity"] is None
    assert obs["availability"] is None
    assert obs["listing_status"] is None


# 3. Test multiple prices on one listing
def test_3_multiple_prices_on_one_listing(tmp_path):
    inv_id = "inv_test3"
    create_investigation(query="tier test", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "marketplace_name": "Tier Market",
        "commodities": [
            {
                "name": "Credit Card Pack",
                "original_title": "Credit Card Pack - Bronze Tier",
                "price": 50.0,
                "currency": "USD",
                "evidence_quote": "Bronze Tier pack costs 50 USD",
            },
            {
                "name": "Credit Card Pack",
                "original_title": "Credit Card Pack - Gold Tier",
                "price": 200.0,
                "currency": "USD",
                "evidence_quote": "Gold Tier pack costs 200 USD",
            },
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)
    conn = get_db_connection()
    prods = conn.execute("SELECT * FROM products WHERE name = 'Credit Card Pack'").fetchall()
    assert len(prods) == 1
    obs = conn.execute("SELECT * FROM product_observations WHERE product_id = ?", (prods[0]["id"],)).fetchall()
    conn.close()
    assert len(obs) == 2
    prices = {o["price"] for o in obs}
    assert prices == {50.0, 200.0}


# 4. Test price + quantity + unit combinations
def test_4_price_quantity_unit_combinations(tmp_path):
    inv_id = "inv_test4"
    create_investigation(query="combo test", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "commodities": [
            {
                "name": "Stolen Track 1 Dumps",
                "original_title": "100 Verified US Cards",
                "price": 250.0,
                "currency": "USD",
                "quantity": 100.0,
                "unit": "cards",
                "min_order": 10.0,
                "evidence_quote": "100 Verified US Cards for 250 USD, minimum order 10 cards",
            }
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)
    conn = get_db_connection()
    obs = conn.execute("SELECT * FROM product_observations WHERE investigation_id = ?", (inv_id,)).fetchone()
    conn.close()
    assert obs["price"] == 250.0
    assert obs["currency"] == "USD"
    assert obs["quantity"] == 100.0
    assert obs["unit"] == "cards"
    assert obs["min_order"] == 10.0


# 5. Test explicit versus missing availability
def test_5_explicit_vs_missing_availability(tmp_path):
    inv_id = "inv_test5"
    create_investigation(query="stock test", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "commodities": [
            {
                "name": "Service A",
                "availability": "out of stock",
                "listing_status": "closed",
                "evidence_quote": "Currently out of stock and closed",
            },
            {
                "name": "Service B",
                "evidence_quote": "Available on site",
            },
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)
    conn = get_db_connection()
    obs_a = conn.execute("SELECT * FROM product_observations WHERE original_title = 'Service A'").fetchone()
    obs_b = conn.execute("SELECT * FROM product_observations WHERE original_title = 'Service B'").fetchone()
    conn.close()
    assert obs_a["availability"] == "out of stock"
    assert obs_a["listing_status"] == "closed"
    assert obs_b["availability"] is None
    assert obs_b["listing_status"] is None


# 6. Test listings without prices
def test_6_listings_without_prices(tmp_path):
    inv_id = "inv_test6"
    create_investigation(query="quote inquiry", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "commodities": [
            {
                "name": "Custom Exploit",
                "original_title": "Custom Exploit Inquiry",
                "quantity": 1.0,
                "unit": "license",
                "evidence_quote": "Contact on Jabber for exploit pricing",
            }
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)
    conn = get_db_connection()
    obs = conn.execute("SELECT * FROM product_observations WHERE investigation_id = ?", (inv_id,)).fetchone()
    conn.close()
    assert obs["price"] is None
    assert obs["quantity"] == 1.0
    assert obs["unit"] == "license"


# 7. Test listings without quantities
def test_7_listings_without_quantities(tmp_path):
    inv_id = "inv_test7"
    create_investigation(query="single leak", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "commodities": [
            {
                "name": "Single Database Dump",
                "price": 500.0,
                "currency": "EUR",
                "evidence_quote": "Full leaked database for 500 EUR",
            }
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)
    conn = get_db_connection()
    obs = conn.execute("SELECT * FROM product_observations WHERE investigation_id = ?", (inv_id,)).fetchone()
    conn.close()
    assert obs["price"] == 500.0
    assert obs["currency"] == "EUR"
    assert obs["quantity"] is None
    assert obs["unit"] is None


# 8. Test multiple marketplaces
def test_8_multiple_marketplaces(tmp_path):
    inv_id = "inv_test8"
    create_investigation(query="multi-market", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "commodities": [
            {
                "name": "Phishing Kit",
                "marketplace_name": "Alpha Market",
                "onion_url": "http://alpha777.onion",
                "evidence_quote": "Phishing kit on Alpha Market",
            },
            {
                "name": "Phishing Kit",
                "marketplace_name": "Beta Forum",
                "onion_url": "http://beta888.onion",
                "evidence_quote": "Phishing kit on Beta Forum",
            },
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)
    conn = get_db_connection()
    prod = conn.execute("SELECT id FROM products WHERE name = 'Phishing Kit'").fetchone()
    pm_links = conn.execute("SELECT * FROM product_marketplace WHERE product_id = ?", (prod["id"],)).fetchall()
    conn.close()
    assert len(pm_links) == 2


# 9. Test multiple observations for the same normalized product
def test_9_multiple_observations_same_product(tmp_path):
    create_investigation(query="rat search 1", inv_id="inv_one")
    create_investigation(query="rat search 2", inv_id="inv_two")
    report1 = {
        "investigation_id": "inv_one",
        "commodities": [
            {
                "name": "RAT Malware",
                "original_title": "Remote Access Tool v1.0",
                "price": 100.0,
                "currency": "USD",
                "evidence_quote": "RAT v1.0 100 USD",
            }
        ],
    }
    report2 = {
        "investigation_id": "inv_two",
        "commodities": [
            {
                "name": "RAT Malware",
                "original_title": "Remote Access Tool v2.0",
                "price": 150.0,
                "currency": "USD",
                "evidence_quote": "RAT v2.0 150 USD",
            }
        ],
    }
    persist_attribution_artifact("inv_one", tmp_path, report1)
    persist_attribution_artifact("inv_two", tmp_path, report2)
    conn = get_db_connection()
    prods = conn.execute("SELECT * FROM products WHERE name = 'RAT Malware'").fetchall()
    assert len(prods) == 1
    obs = conn.execute("SELECT * FROM product_observations WHERE product_id = ?", (prods[0]["id"],)).fetchall()
    conn.close()
    assert len(obs) == 2
    inv_ids = {o["investigation_id"] for o in obs}
    assert inv_ids == {"inv_one", "inv_two"}


# 10. Test ambiguous product names
def test_10_ambiguous_product_names(tmp_path):
    inv_id = "inv_test10"
    create_investigation(query="ambiguous item", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "commodities": [
            {
                "name": "Unknown Illicit Service",
                "original_title": "Special VIP Access Pass",
                "uncertainty": "Product contents cannot be determined from description.",
                "evidence_quote": "Buy VIP Access Pass for exclusive access",
            }
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)
    conn = get_db_connection()
    obs = conn.execute("SELECT * FROM product_observations WHERE investigation_id = ?", (inv_id,)).fetchone()
    conn.close()
    assert obs["uncertainty"] == "Product contents cannot be determined from description."


# 11. Test unsupported aliases
def test_11_unsupported_aliases(tmp_path):
    inv_id = "inv_test11"
    create_investigation(query="alias check", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "commodities": [
            {
                "name": "Stealth VPN",
                "aliases": ["Shadow Net", "Stealth Proxy"],
                "evidence_quote": "Stealth VPN also known as Shadow Net or Stealth Proxy",
            }
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)
    conn = get_db_connection()
    prod = conn.execute("SELECT id FROM products WHERE name = 'Stealth VPN'").fetchone()
    aliases = conn.execute("SELECT alias_name FROM product_aliases WHERE product_id = ?", (prod["id"],)).fetchall()
    conn.close()
    names = {a["alias_name"] for a in aliases}
    assert names == {"Shadow Net", "Stealth Proxy"}


# 12. Test evidence grounding
def test_12_evidence_grounding(tmp_path):
    inv_id = "inv_test12"
    create_investigation(query="grounding check", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "commodities": [
            {
                "name": "Valid Item",
                "evidence_quote": "Direct quote from HTML page text",
            },
            {
                "name": "Ungrounded Item",
                "evidence_quote": "",  # missing evidence quote
            },
        ],
    }
    res = ingest_attribution_report(inv_id, report, workspace=tmp_path)
    assert res["commodities_inserted"] == 1


# 13. Test invalid graph edge types
def test_13_invalid_graph_edge_types(tmp_path):
    inv_id = "inv_test13"
    create_investigation(query="invalid edge test", inv_id=inv_id)
    graph_data = {
        "investigation_id": inv_id,
        "nodes": [
            {"id": "actor_test", "type": "actor", "label": "VendorTest", "evidence_quote": "VendorTest active on forum"},
            {"id": "product_test", "type": "product", "label": "Cards", "evidence_quote": "Cards offered for sale"},
        ],
        "edges": [
            {
                "source": "actor_test",
                "target": "product_test",
                "type": "invented_invalid_edge",
                "confidence": 0.9,
                "evidence_quote": "VendorTest sells cards",
            }
        ],
    }
    graph_file = tmp_path / "graph" / "threat_graph.json"
    graph_file.parent.mkdir(parents=True, exist_ok=True)
    graph_file.write_text(json.dumps(graph_data), encoding="utf-8")

    result = ingest_threat_graph(inv_id, tmp_path)
    assert len(result["edges_rejected"]) == 1
    assert "unknown edge type" in result["edges_rejected"][0]["reason"]


# 14. Test Product -> LISTED_ON -> Marketplace
def test_14_product_listed_on_marketplace(tmp_path):
    inv_id = "inv_test14"
    create_investigation(query="listed on test", inv_id=inv_id)
    graph_data = {
        "investigation_id": inv_id,
        "nodes": [
            {"id": "market_alpha", "type": "marketplace", "label": "AlphaMarket", "evidence_quote": "Welcome to AlphaMarket"},
            {"id": "prod_cvv", "type": "product", "label": "CVV Dumps", "evidence_quote": "Fresh CVV dumps available"},
        ],
        "edges": [
            {
                "source": "prod_cvv",
                "target": "market_alpha",
                "type": "listed_on",
                "confidence": 0.95,
                "evidence_quote": "CVV Dumps listed on AlphaMarket",
            }
        ],
    }
    graph_file = tmp_path / "graph" / "threat_graph.json"
    graph_file.parent.mkdir(parents=True, exist_ok=True)
    graph_file.write_text(json.dumps(graph_data), encoding="utf-8")

    result = ingest_threat_graph(inv_id, tmp_path)
    assert result["edges_inserted"] == 1
    assert len(result["edges_rejected"]) == 0

    conn = get_db_connection()
    edge = conn.execute("SELECT * FROM graph_edges WHERE investigation_id = ?", (inv_id,)).fetchone()
    conn.close()
    assert edge["edge_type"] == CANONICAL_EDGE_TYPES.LISTED_ON


# 15. Test legacy commodity records
def test_15_legacy_commodity_records():
    inv_id = "inv_legacy"
    create_investigation(query="legacy test", inv_id=inv_id)
    cid = save_commodity(
        investigation_id=inv_id,
        name="Legacy Product",
        category="Carding",
        marketplace_name="Old Market",
        evidence_quote="Legacy quote",
        confidence=0.8,
    )
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM commodities WHERE id = ?", (cid,)).fetchone()
    conn.close()
    assert row["name"] == "Legacy Product"
    assert row["confidence"] == 0.8
    assert row["price"] is None


# 16. Test that no frontend/API regex is required to reconstruct price or quantity
def test_16_no_regex_needed_in_api(tmp_path):
    inv_id = "inv_test16"
    create_investigation(query="api test", inv_id=inv_id)
    report = {
        "investigation_id": inv_id,
        "marketplace_name": "Verified Market",
        "commodities": [
            {
                "name": "Fullz US Credit Cards",
                "original_title": "Fullz US Credit Cards 2026",
                "category": "Financial Fraud",
                "price": 125.50,
                "currency": "USD",
                "quantity": 50.0,
                "unit": "cards",
                "min_order": 10.0,
                "evidence_quote": "Selling 50 cards for 125.50 USD",
            }
        ],
    }
    persist_attribution_artifact(inv_id, tmp_path, report)

    conn = get_db_connection()
    prod = conn.execute("SELECT id FROM products WHERE name = 'Fullz US Credit Cards'").fetchone()
    prod_id = prod["id"]
    conn.close()

    handler = JaneRequestHandler.__new__(JaneRequestHandler)
    sent_payload = []
    handler._send_json = lambda data, status=200: sent_payload.append(data)

    handler._handle_commodities(product_id=prod_id)
    assert len(sent_payload) == 1
    dossier = sent_payload[0]

    assert dossier["pricing"]["has_pricing"] is True
    assert dossier["pricing"]["observations"][0]["amount"] == 125.50
    assert dossier["pricing"]["observations"][0]["currency"] == "USD"
    assert dossier["quantity"]["has_quantity"] is True
    assert dossier["quantity"]["observations"][0]["amount"] == 50.0
    assert dossier["quantity"]["observations"][0]["unit"] == "cards"
