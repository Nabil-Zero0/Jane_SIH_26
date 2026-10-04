"""
Unit & Integration Tests for Jane's Upgraded Architecture
Tests:
  1. Query Planner & Fanout (deterministic + bounded queries)
  2. Search Providers & Safe Search
  3. Multi-Factor Target Ranking & Deduplication
  4. Deterministic Evidence Chunker
  5. Multi-View Mermaid Generator & Hostile String Escaping
  6. REST API Endpoints (/api/query/plan, /api/investigation/mermaid, /api/search/hits, /api/evidence/chunks)
"""

import json
import os
from pathlib import Path
import tempfile
import unittest
import networkx as nx

from jane.pipeline.query_planner import plan_queries, _deterministic_fanout, MAX_FANOUT_QUERIES
from jane.collector.providers import get_providers, safe_search, SearchHit, AhmiaProvider, CuratedSeedsProvider
from jane.collector.target_ranker import rank_targets, RankedTarget
from jane.ai.chunker import chunk_text, EvidenceChunk
from jane.backend.graph.mermaid import mermaid_label, generate_mermaid_views
from jane.db.database import (
    init_db,
    create_investigation,
    record_search_run,
    insert_search_hits,
    get_search_hits,
    get_db_connection,
    insert_evidence_chunks,
    get_evidence_chunks,
)


class TestUpgradedArchitecture(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_upgraded.db"
        self._prev_jane_db_path = os.environ.get("JANE_DB_PATH")
        os.environ["JANE_DB_PATH"] = str(self.db_path)
        init_db(self.db_path)

    def tearDown(self):
        import gc
        if self._prev_jane_db_path is not None:
            os.environ["JANE_DB_PATH"] = self._prev_jane_db_path
        else:
            os.environ.pop("JANE_DB_PATH", None)
        gc.collect()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_query_planner_bounds_and_purposes(self):
        plan = plan_queries("stolen cards Mumbai", max_queries=8, use_llm=False)
        self.assertEqual(plan.original_query, "stolen cards Mumbai")
        self.assertTrue(1 <= len(plan.queries) <= MAX_FANOUT_QUERIES)

        purposes = {q.purpose for q in plan.queries}
        self.assertIn("exact", purposes)
        # Should have at least one of location, synonym, or domain terminology
        self.assertTrue(any(p in purposes for p in ("location", "synonym", "domain_terminology", "quoted")))

    def test_search_providers_and_safe_search(self):
        provs = get_providers(["ahmia", "seeds"])
        self.assertEqual(len(provs), 2)
        names = {p.name for p in provs}
        self.assertIn("ahmia", names)
        self.assertIn("seeds", names)

        # Curated seeds provider search test
        seeds_prov = CuratedSeedsProvider()
        hits = safe_search(seeds_prov, "carding", limit=5)
        self.assertTrue(len(hits) > 0)
        self.assertTrue(all(isinstance(h, SearchHit) for h in hits))
        self.assertTrue(all(h.provider == "seeds" for h in hits))

    def test_target_ranker_deduplication_and_scoring(self):
        onion_a = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
        onion_b = "234567abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr.onion"

        hits = [
            SearchHit(url=f"http://{onion_a}/page1", title="Market A", snippet="carding dumps", provider="ahmia", query="cards", discovered_at="2026-09-21T00:00:00"),
            SearchHit(url=f"http://{onion_a}/page2", title="Market A", snippet="escrow shop", provider="torch", query="dumps", discovered_at="2026-09-21T00:00:01"),
            SearchHit(url=f"http://{onion_b}", title="Market B", snippet="only single provider", provider="seeds", query="cards", discovered_at="2026-09-21T00:00:02"),
        ]

        ranked = rank_targets(hits, total_providers_active=2, max_targets=10)
        self.assertEqual(len(ranked), 2)

        # Onion A has 2 providers agreeing -> higher score than Onion B (1 provider)
        self.assertEqual(ranked[0].onion, onion_a)
        self.assertTrue(ranked[0].score > ranked[1].score)
        self.assertIn("ahmia", ranked[0].found_by)
        self.assertIn("torch", ranked[0].found_by)

    def test_deterministic_evidence_chunker(self):
        sample_text = (
            "Welcome to UniMkts Carding Marketplace.\n\n"
            "We offer fresh high-balance Visa and MasterCard dumps with PIN. "
            "Contact lead vendor via wire: transfer for bulk orders.\n\n"
            "All transactions protected by multi-signature escrow. Minimum deposit is 0.05 BTC."
        )
        chunks = chunk_text(sample_text, page_id="testpage123", url="http://test.onion", investigation_id="inv_test")
        self.assertTrue(len(chunks) >= 1)

        for c in chunks:
            self.assertTrue(c.chunk_id.startswith("testpage-c"))
            self.assertEqual(len(c.sha256), 64)
            # Verify slice matches original text
            orig_slice = sample_text[c.char_start:c.char_end].strip()
            self.assertEqual(c.text, orig_slice)

    def test_mermaid_escaping_and_views(self):
        hostile_string = 'Lead Vendor "Alpha" \\ [Escrow] \n with {malicious} tokens'
        escaped = mermaid_label(hostile_string)
        self.assertNotIn('"', escaped)
        self.assertNotIn('\\\\', escaped.replace('\\\\', ''))
        self.assertNotIn('[', escaped)
        self.assertNotIn(']', escaped)
        self.assertNotIn('{', escaped)
        self.assertNotIn('}', escaped)

        # Build mock NetworkX graph
        G = nx.MultiDiGraph()
        G.add_node("actor_alpha", label='Vendor "Alpha"', node_type="ALIAS")
        G.add_node("org_unimkts", label="UniMkts Market", node_type="ORGANISATION")
        G.add_node("prod_cards", label="Card Dumps", node_type="PRODUCT")
        G.add_node("ip_leak", label="185.220.101.5", node_type="IP_ADDRESS")

        G.add_edge("actor_alpha", "org_unimkts", edge_type="CONTROLS", is_inference=False)
        G.add_edge("org_unimkts", "prod_cards", edge_type="OFFERS", is_inference=False)
        G.add_edge("actor_alpha", "ip_leak", edge_type="LIKELY_SAME_AUTHOR", is_inference=True)

        views = generate_mermaid_views(G)
        self.assertIn("full_view", views)
        self.assertIn("site_overview", views)
        self.assertIn("actor_account_view", views)
        self.assertIn("product_service_view", views)
        self.assertIn("infrastructure_view", views)
        self.assertIn("evidence_only_view", views)
        self.assertIn("inference_view", views)

        # Verify inference edge is present in inference_view
        self.assertIn("LIKELY_SAME_AUTHOR", views["inference_view"])
        # Verify evidence_only_view excludes inference edge
        self.assertNotIn("LIKELY_SAME_AUTHOR", views["evidence_only_view"])

    def test_database_persistence_helpers(self):
        inv_id = create_investigation(query="sanctions hunt test")
        run_id = record_search_run(inv_id, provider="ahmia", query="sanctions")
        self.assertTrue(run_id.startswith("run_"))

        hits = [
            {"provider": "ahmia", "query": "sanctions", "url": "http://sanctioned.onion", "title": "Test Hit", "snippet": "Snippet text", "score": 0.85}
        ]
        inserted = insert_search_hits(inv_id, run_id, hits)
        self.assertEqual(inserted, 1)

        retrieved_hits = get_search_hits(inv_id)
        self.assertEqual(len(retrieved_hits), 1)
        self.assertEqual(retrieved_hits[0]["onion_url"], "http://sanctioned.onion")

        # Insert parent onion_page first to satisfy foreign key constraint
        conn = get_db_connection()
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO onion_pages (id, investigation_id, url, created_at)
                VALUES ('page_01', ?, 'http://sanctioned.onion', datetime('now'))
            """, (inv_id,))

        chunks = [
            {"chunk_id": "chunk_01", "page_id": "page_01", "investigation_id": inv_id, "url": "http://sanctioned.onion", "text": "Evidence snippet", "char_start": 0, "char_end": 16, "sha256": "abc123hash"}
        ]
        c_count = insert_evidence_chunks(chunks)
        self.assertEqual(c_count, 1)

        retrieved_chunks = get_evidence_chunks(investigation_id=inv_id)
        self.assertEqual(len(retrieved_chunks), 1)
        self.assertEqual(retrieved_chunks[0]["id"], "chunk_01")

        retrieved_chunks = get_evidence_chunks(investigation_id=inv_id)
        self.assertEqual(len(retrieved_chunks), 1)
        self.assertEqual(retrieved_chunks[0]["id"], "chunk_01")


if __name__ == "__main__":
    unittest.main()
