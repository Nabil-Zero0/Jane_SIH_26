"""
Comprehensive Automated Tests for Jane Pipeline & DB Architecture
"""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jane.db.database import (
    init_db,
    create_investigation,
    update_investigation_status,
    save_onion_page,
    save_threat_actor,
    save_identifier,
    save_graph_node,
    save_graph_edge,
    get_investigation_summary,
    get_db_connection,
)
from jane.ai.opencode_bridge import (
    create_target_workspace,
    generate_forensic_profile,
)
from jane.pipeline.orchestrator import (
    dispatch_investigation_job,
    process_batch_file,
    get_paths,
)


class TestJanePipeline(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_jane.db"
        self._prev_jane_db_path = os.environ.get("JANE_DB_PATH")
        os.environ["JANE_DB_PATH"] = str(self.db_path)
        init_db(self.db_path)

    def tearDown(self):
        if self._prev_jane_db_path is not None:
            os.environ["JANE_DB_PATH"] = self._prev_jane_db_path
        else:
            os.environ.pop("JANE_DB_PATH", None)
        self.temp_dir.cleanup()

    def test_database_crud(self):
        # 1. Create Investigation
        inv_id = create_investigation("weapon sales", max_onions=3, max_depth=1)
        self.assertTrue(inv_id.startswith("inv_"))

        # 2. Save Onion Page
        pid = save_onion_page(
            investigation_id=inv_id,
            url="http://testtargetonionaddress123456789.onion",
            title="Black Market Weapons",
            raw_html_path="/tmp/test.html",
            cleaned_text="Glock 19 with suppressor. Contact wire: transfer.",
        )
        self.assertTrue(pid.startswith("page_"))

        # 3. Save Threat Actor
        aid = save_threat_actor(
            investigation_id=inv_id,
            designated_id="TA-TEST-01",
            primary_handle="wire: transfer",
            threat_category="Weapons Trafficking",
        )
        self.assertTrue(aid.startswith("actor_"))

        # 4. Save Identifier with Evidence Quote
        iid = save_identifier(
            investigation_id=inv_id,
            itype="MessagingHandle",
            value="wire: transfer",
            actor_id=aid,
            page_id=pid,
            evidence_quote="Contact wire: transfer.",
        )
        self.assertTrue(iid.startswith("ident_"))

        # 5. Save Graph Node & Edge
        save_graph_node(
            investigation_id=inv_id,
            node_id="wire: transfer",
            label="wire: transfer",
            node_type="ThreatActor",
        )
        save_graph_edge(
            investigation_id=inv_id,
            source="wire: transfer",
            target="Black Market Weapons",
            edge_type="OPERATES",
            confidence=0.95,
            evidence_quote="Contact wire: transfer.",
        )

        # 6. Retrieve Summary
        conn = get_db_connection(self.db_path)
        summary = get_investigation_summary(inv_id)
        conn.close()

        self.assertEqual(summary["investigation"]["query"], "weapon sales")
        self.assertEqual(len(summary["threat_actors"]), 1)
        self.assertEqual(summary["threat_actors"][0]["primary_handle"], "wire: transfer")
        self.assertEqual(len(summary["identifiers"]), 1)
        self.assertEqual(summary["identifiers"][0]["evidence_quote"], "Contact wire: transfer.")

    def test_opencode_workspace_isolation(self):
        ws_dir = Path(self.temp_dir.name) / "workspaces"
        target_dir = create_target_workspace(
            target_url="http://examplenarcoticsonionaddress.onion",
            raw_html="<html><body><p>High grade cocaine and weed. Telegram: @drugdealer</p></body></html>",
            heuristics={"handles": ["@drugdealer"], "wallets": []},
            workspaces_dir=ws_dir,
        )

        self.assertTrue(target_dir.exists())
        self.assertTrue((target_dir / "target_page.html").exists())
        self.assertTrue((target_dir / "heuristics.json").exists())
        self.assertTrue((target_dir / "instruction.md").exists())

        # Test deterministic fallback profiler
        # Host tests must not depend on a running OpenCode daemon or network.
        with patch("jane.ai.opencode_bridge.is_opencode_available", return_value=False):
            with self.assertRaisesRegex(RuntimeError, "AI analysis is required"):
                generate_forensic_profile(target_dir, "http://examplenarcoticsonionaddress.onion")


if __name__ == "__main__":
    unittest.main()
