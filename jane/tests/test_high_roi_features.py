"""
Unit & Integration Tests for Immediate High-ROI Upgrades across Jane Pillars 1-4.
Covers:
- Pillar 1: Template hashing & asset extraction (scout.py)
- Pillar 2: Sentence-snapped context, crypto sanctions lookup, format-rigidity confidence, temporal tracking
- Pillar 3: Word count reliability gating, feature-level explainability, candidate author softmax ranking
- Pillar 4: AI quote grounding validation, SAME_TEMPLATE clustering, sanctioned node styling
"""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from jane.collector.scout import compute_template_hash, RobustHTMLParser
from jane.backend.extractor import (
    extract_context_snippet,
    check_crypto_sanctions,
    ENTITY_CONFIDENCE_TABLE,
    extract_entities_from_text,
)
from jane.backend.profiler.analyzer import (
    compute_reliability_gate,
    rank_candidate_authors,
)
from jane.ai.opencode_bridge import validate_quote_grounding
from jane.backend.graph.connector import run_graph
from jane.db import database


class TestPillar1TemplateHashing(unittest.TestCase):
    def test_identical_structural_templates_produce_identical_hash(self):
        html_page_a = """
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="/static/css/theme-dark.css">
            <link rel="stylesheet" href="/vendor/bootstrap.min.css">
            <script src="/static/js/bundle.js"></script>
        </head>
        <body>
            <h1>Shop Page 1 - Russian Carding Service</h1>
            <p>Welcome to our market. Buy fresh cards.</p>
        </body>
        </html>
        """

        html_page_b = """
        <!DOCTYPE html>
        <html>
        <head>
            <link rel="stylesheet" href="/static/css/theme-dark.css">
            <link rel="stylesheet" href="/vendor/bootstrap.min.css">
            <script src="/static/js/bundle.js"></script>
        </head>
        <body>
            <h1>Shop Page 2 - Drug Listings Escrow</h1>
            <p>Completely different body text and listings here.</p>
        </body>
        </html>
        """

        hash_a = compute_template_hash(html_page_a)
        hash_b = compute_template_hash(html_page_b)

        self.assertTrue(bool(hash_a))
        self.assertEqual(hash_a, hash_b, "Identical asset structures should produce identical template hashes")

    def test_different_templates_produce_different_hashes(self):
        html_page_a = """<html><head><link rel="stylesheet" href="/css/style1.css"></head><body>A</body></html>"""
        html_page_b = """<html><head><link rel="stylesheet" href="/css/style2.css"></head><body>B</body></html>"""

        self.assertNotEqual(compute_template_hash(html_page_a), compute_template_hash(html_page_b))


class TestPillar2ExtractionAndResolution(unittest.TestCase):
    def test_sentence_boundary_context_snapping(self):
        full_text = (
            "Welcome to the portal. Our escrow guarantee is 100% verified. "
            "Please send payment to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately for order dispatch. "
            "All transactions are final and non-refundable."
        )
        target_entity = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

        snippet = extract_context_snippet(full_text, target_entity, window=150)
        
        # Must snap cleanly to sentence boundary and contain full sentence
        self.assertIn("Please send payment to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa immediately for order dispatch.", snippet)
        # Should not clip mid-word
        self.assertFalse(snippet.startswith("ome to the"))

    def test_entity_confidence_calibration(self):
        self.assertGreaterEqual(ENTITY_CONFIDENCE_TABLE.get("BITCOIN_ADDRESS", 0.0), 0.90)
        self.assertGreaterEqual(ENTITY_CONFIDENCE_TABLE.get("PGP_KEY_BLOCK", 0.0), 0.95)
        self.assertLessEqual(ENTITY_CONFIDENCE_TABLE.get("WIRE_HANDLE", 1.0), 0.50)

    @patch("urllib.request.urlopen")
    def test_crypto_sanctions_hit(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"sanctioned": True, "sources": ["OFAC-SDN"]}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = check_crypto_sanctions("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        self.assertTrue(res["is_sanctioned"])
        self.assertIn("OFAC-SDN", res["sanctions"])

    def test_temporal_tracking_and_database_persistence(self):
        with tempfile.TemporaryDirectory() as temp:
            db_file = Path(temp) / "test_jane.db"
            with patch.object(database, "DB_PATH", db_file):
                database.init_db()
                inv_id = "inv_temporal_test"
                database.create_investigation(query="temporal check", inv_id=inv_id)

                page_id = database.save_onion_page(
                    investigation_id=inv_id,
                    url="http://fixture.onion",
                    title="Fixture",
                    raw_html_path="raw.html",
                    cleaned_text="test",
                    template_hash="tmpl_hash_abc",
                    content_diff_ratio=0.85,
                )

                # Save identifier 1st time
                id1 = database.save_identifier(
                    investigation_id=inv_id,
                    itype="crypto_btc",
                    value="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                    page_id=page_id,
                    evidence_quote="sentence context",
                    confidence=0.98,
                    is_sanctioned=1,
                )
                
                # Save same identifier 2nd time (simulating re-crawl)
                id2 = database.save_identifier(
                    investigation_id=inv_id,
                    itype="crypto_btc",
                    value="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                    page_id=page_id,
                    evidence_quote="sentence context updated",
                    confidence=0.98,
                    is_sanctioned=1,
                )

                summary = database.get_investigation_summary(inv_id)
                entities = summary["identifiers"]
                self.assertEqual(len(entities), 1)
                self.assertEqual(entities[0]["occurrence_count"], 2)
                self.assertEqual(entities[0]["is_sanctioned"], 1)


class TestPillar3StylometryAndAttribution(unittest.TestCase):
    def test_word_count_reliability_gating(self):
        short_text = "Hello vendor. What is price of cvv dump?"
        res_short = compute_reliability_gate(short_text)
        self.assertEqual(res_short["level"], "UNRELIABLE")

        medium_text = " ".join(["vendor escrow bitcoin transaction market"] * 25) # 125 words
        res_medium = compute_reliability_gate(medium_text)
        self.assertEqual(res_medium["level"], "TRIAGE_ONLY")

        large_text = " ".join(["the that with which from have this they would there could about which"] * 90) # 1170 words
        res_large = compute_reliability_gate(large_text)
        self.assertEqual(res_large["level"], "HIGH_CONFIDENCE")

    def test_candidate_author_ranking_with_softmax(self):
        sample_text = (
            "We have verified that the escrow service operates with full security. "
            "If any user finds an issue with transactions, contact support directly. "
            "All bulk purchases receive automated discounts upon confirmation."
        )

        known_alice = (
            "We have verified that our service operates with full escrow security. "
            "Please contact support directly for bulk discounts upon confirmation."
        )

        known_bob = (
            "Yo what is up everyone, buy fresh credit cards now fast! "
            "We do not offer refunds, no escrow accepted, pure telegram deals only. "
            "Contact me directly for all bulk orders today."
        )

        candidate_corpora = {
            "Alice_Vendor": known_alice,
            "Bob_Carder": known_bob,
        }

        ranking = rank_candidate_authors(sample_text, candidate_corpora, top_k=2)
        self.assertEqual(len(ranking), 2)
        self.assertEqual(ranking[0]["candidate_author"], "Alice_Vendor")
        self.assertGreater(ranking[0]["match_probability"], ranking[1]["match_probability"])
        self.assertIn("explainability", ranking[0])
        self.assertTrue("top_matching_features" in ranking[0]["explainability"])


class TestPillar4AILayerAndGraphClustering(unittest.TestCase):
    def test_quote_grounding_validation(self):
        raw_html = (
            "<html><body>"
            "<h1>BlackForge Market</h1>"
            "<p>Lead administrator is OrionAlpha. Fresh US dumps with guaranteed 90% validity.</p>"
            "</body></html>"
        )

        valid_report = {
            "threat_actors": [{"primary_handle": "OrionAlpha", "evidence_quote": "Fresh US dumps with guaranteed 90% validity."}],
            "commodities": [],
            "graph_links": [],
        }

        hallucinated_report = {
            "threat_actors": [{"primary_handle": "GhostOperator", "evidence_quote": "We hacked the NSA database in 2024."}],
            "commodities": [],
            "graph_links": [],
        }

        grounded = validate_quote_grounding(valid_report, raw_html)
        self.assertTrue(grounded["threat_actors"][0].get("quote_grounded"))

        ungrounded = validate_quote_grounding(hallucinated_report, raw_html)
        self.assertFalse(ungrounded["threat_actors"][0].get("quote_grounded"))

    def test_same_template_graph_clustering_and_sanction_styling(self):
        with tempfile.TemporaryDirectory() as temp:
            db_file = Path(temp) / "test_graph.db"
            with patch.object(database, "DB_PATH", db_file):
                database.init_db()
                inv_id = "inv_graph_test"
                database.create_investigation(query="graph test", inv_id=inv_id)

                batch_data = {
                    "pages": [
                        {
                            "url": "http://mirror1.onion",
                            "onion_address": "mirror1.onion",
                            "title": "Market 1",
                            "raw_html": "<html><body>1</body></html>",
                            "cleaned_text": "text 1",
                            "template_hash": "SHARED_TEMPLATE_HASH_123",
                        },
                        {
                            "url": "http://mirror2.onion",
                            "onion_address": "mirror2.onion",
                            "title": "Market 2",
                            "raw_html": "<html><body>2</body></html>",
                            "cleaned_text": "text 2",
                            "template_hash": "SHARED_TEMPLATE_HASH_123",
                        },
                    ]
                }

                extracted_data = {
                    "results_by_page": [
                        {
                            "url": "http://mirror1.onion",
                            "entities": [
                                {
                                    "type": "crypto_btc",
                                    "value": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                                    "context": "pay here",
                                    "confidence": 0.98,
                                    "is_sanctioned": 1,
                                }
                            ]
                        }
                    ]
                }

                run_graph(inv_id, batch_data, extracted_data=extracted_data)
                summary = database.get_investigation_summary(inv_id)
                edges = summary["graph_elements"]["edges"]
                nodes = summary["graph_elements"]["nodes"]

                # Check for SAME_TEMPLATE edge
                template_edges = [e for e in edges if e["data"].get("edge_type") == "SAME_TEMPLATE"]
                self.assertEqual(len(template_edges), 1)
                self.assertEqual(template_edges[0]["data"]["edge_type"], "SAME_TEMPLATE")

                # Check for sanctioned node styling
                sanctioned_nodes = [
                    n for n in nodes
                    if n["data"].get("is_sanctioned") or n["data"].get("color") == "#ef4444"
                ]
                self.assertTrue(len(sanctioned_nodes) >= 1)


if __name__ == "__main__":
    unittest.main()
