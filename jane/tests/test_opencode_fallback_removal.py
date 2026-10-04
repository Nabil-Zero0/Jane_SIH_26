"""Unit test verifying that failed OpenCode attribution yields zero fabricated actors and DEGRADED status."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jane.ai.opencode_bridge import _legacy_fallback_profile
from jane.backend.graph.connector import run_graph
from jane.db.database import (
    init_db,
    create_investigation,
    get_investigation_summary,
    get_db_connection,
)


class TestFallbackRemoval(unittest.TestCase):
    def test_legacy_fallback_profile_produces_zero_actors(self):
        with tempfile.TemporaryDirectory() as td:
            target_dir = Path(td)
            (target_dir / "target_page.html").write_text(
                "<html><body><p>Wire transfer accepted for carding dumps.</p></body></html>",
                encoding="utf-8",
            )
            report = _legacy_fallback_profile(target_dir, "http://target.onion")

            self.assertEqual(report["threat_category"], "INSUFFICIENT_EVIDENCE")
            self.assertEqual(len(report["threat_actors"]), 0)
            self.assertEqual(len(report["commodities"]), 0)
            self.assertEqual(len(report["graph_links"]), 0)

    def test_pipeline_ingest_with_failed_opencode_preserves_pages_with_zero_actors(self):
        with tempfile.TemporaryDirectory() as td:
            db_file = Path(td) / "test_fallback.db"
            init_db(db_file)
            inv_id = "inv_test_fallback_01"
            create_investigation("weapon sales test", inv_id=inv_id)

            batch_data = {
                "batch_id": inv_id,
                "pages": [
                    {
                        "url": "http://darkservice12345.onion",
                        "title": "Dark Service",
                        "cleaned_text": "Contact support on telegram @realsupport",
                        "raw_html": "<html><body>Contact support on telegram @realsupport</body></html>",
                    }
                ],
            }
            extracted_data = {
                "results_by_page": [
                    {
                        "url": "http://darkservice12345.onion",
                        "entities": [
                            {
                                "entity_type": "TELEGRAM_HANDLE",
                                "value": "realsupport",
                                "confidence": 0.9,
                                "context_snippet": "@realsupport",
                            }
                        ],
                    }
                ],
                "total_entities_found": 1,
            }

            # Simulating failed OpenCode: ai_data is empty / degraded
            ai_data = {"status": "OPENCODE_DEGRADED", "reports": [], "reports_count": 0}

            run_graph(
                inv_id=inv_id,
                batch_data=batch_data,
                extracted_data=extracted_data,
                locksmith_data={"findings": []},
                ai_data=ai_data,
            )

            summary = get_investigation_summary(inv_id)
            # Pages and identifiers must be preserved
            self.assertEqual(len(summary["pages"]), 1)
            self.assertEqual(len(summary["identifiers"]), 1)
            # Exactly ZERO actors fabricated
            self.assertEqual(len(summary["threat_actors"]), 0)


if __name__ == "__main__":
    unittest.main()
