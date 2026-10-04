"""
Tests for Step 8: Orphan identifier linking on the write path.
Verifies:
1. When run_graph processes extracted_data with entities, save_identifier receives the correct page_id.
2. The resulting identifiers table row carries non-null page_id matching onion_pages.id.
"""

import pytest
from jane.backend.graph.connector import run_graph
from jane.db.database import (
    create_investigation,
    get_db_connection,
)


def test_identifier_carries_page_id():
    inv_id = "inv_step8_test"
    create_investigation(query="weapons scan", inv_id=inv_id)

    target_url = "http://darkarmory777xyz.onion/store"
    batch_data = {
        "batch_id": inv_id,
        "pages": [{
            "url": target_url,
            "title": "Dark Armory Store",
            "cleaned_text": "Glock 19 with suppressor. BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "response_headers": {"Server": "nginx/1.20"},
        }]
    }

    extracted_data = {
        "total_entities_found": 1,
        "results_by_page": [{
            "url": target_url,
            "entities": [{
                "entity_type": "BITCOIN_ADDRESS",
                "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "confidence": 0.99,
                "context_snippet": "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "is_sanctioned": False,
            }]
        }]
    }

    run_graph(inv_id=inv_id, batch_data=batch_data, extracted_data=extracted_data)

    conn = get_db_connection()
    page_row = conn.execute("SELECT id FROM onion_pages WHERE investigation_id = ? AND url = ?", (inv_id, target_url)).fetchone()
    assert page_row is not None
    page_id = page_row["id"]

    ident_row = conn.execute(
        "SELECT id, page_id, value, type FROM identifiers WHERE investigation_id = ? AND value = ?",
        (inv_id, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    ).fetchone()
    assert ident_row is not None
    assert ident_row["page_id"] == page_id, f"Expected page_id {page_id!r}, got {ident_row['page_id']!r}"

    conn.close()
