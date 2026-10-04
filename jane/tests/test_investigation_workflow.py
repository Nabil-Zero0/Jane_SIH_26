from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jane.ai import opencode_bridge
from jane.collector import scout
from jane.pipeline.query_planner import INTERNAL_FANOUT_PROMPT, plan_queries


class InvestigationWorkflowTests(unittest.TestCase):
    def test_fanout_plan_records_fallback_source_and_prompt_version(self):
        plan = plan_queries("vendor alias", use_llm=False)
        payload = plan.to_dict()
        self.assertEqual(payload["generation_source"], "deterministic_fallback")
        self.assertTrue(payload["prompt_version"])
        self.assertIn("vendor alias", payload["original_query"])
        self.assertTrue(INTERNAL_FANOUT_PROMPT)

    def test_investigation_workspace_contains_required_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = opencode_bridge.create_investigation_workspace(
                "inv_test", "vendor alias", Path(temp) / "investigations"
            )
            self.assertTrue((workspace / "investigation.json").exists())
            self.assertTrue((workspace / "queries" / "input.json").exists())
            self.assertTrue((workspace / "opencode").exists())
            self.assertTrue((workspace / "logs" / "events.jsonl").exists())

    def test_scout_manifest_is_authoritative(self):
        selected = "a" * 56 + ".onion"
        with tempfile.TemporaryDirectory() as temp:
            manifest = Path(temp) / "selected.json"
            manifest.write_text(json.dumps({"selected_targets": [f"http://{selected}"]}), encoding="utf-8")
            with patch.object(scout, "crawl_targets", return_value=[]), patch.object(scout, "discover_targets") as discover:
                result = scout.run_scout(
                    query="ignored",
                    target_manifest=manifest,
                    max_pages=1,
                )
            discover.assert_not_called()
            self.assertEqual(result["status"], "FAILED_COLLECTION")


if __name__ == "__main__":
    unittest.main()
