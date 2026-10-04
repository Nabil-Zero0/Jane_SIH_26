"""Unit tests for Turn 3.5 AI Mermaid Graph Enrichment and syntax validation."""

from pathlib import Path
import tempfile
import threading
import time
import unittest

from jane.backend.graph.mermaid import validate_mermaid_syntax
from jane.ai.opencode_bridge import (
    _mermaid_instruction,
    wait_for_mermaid_file,
    TIMEOUT_TURN35_MERMAID,
)


class TestMermaidTurn35(unittest.TestCase):
    def test_validate_mermaid_syntax_valid_cases(self):
        valid_diagrams = [
            "flowchart TD\n    a --> b",
            "graph LR\n    mkt[(\"AlphaBay\")] -->|\"SELLS\"| prod[\"Data Dump\"]\n    actor([\"VendorX\"]) --> mkt",
            "flowchart TD\n    actor([\"Admin\"]) -.->|\"LEAD: OSINT PIVOT\"| tg[[\"Telegram: @admin\"]]\n    actor --> wallet{{\"BTC: 1A1zP...\"}}",
            "```mermaid\nflowchart TD\n    n1[\"Node 1\"] --> n2[\"Node 2\"]\n```",
        ]
        for diag in valid_diagrams:
            self.assertTrue(validate_mermaid_syntax(diag), f"Failed for:\n{diag}")

    def test_validate_mermaid_syntax_invalid_cases(self):
        invalid_diagrams = [
            "",
            "   ",
            "not a flowchart",
            "flowchart TD\n",  # No nodes or arrows
            "flowchart TD\n    a[missing closing bracket --> b",
            "flowchart TD\n    a(\"unclosed paren\" --> b",
            "flowchart TD\n    a{\"unclosed curly\" --> b",
            "flowchart TD\n    a[\"unclosed quote] --> b",
        ]
        for diag in invalid_diagrams:
            self.assertFalse(validate_mermaid_syntax(diag), f"Should have failed for:\n{diag}")

    def test_mermaid_instruction_contains_contracts(self):
        p = Path("/tmp/inv_test")
        instruction = _mermaid_instruction(p)
        self.assertIn("Phase 3.5", instruction)
        self.assertIn("mermaid.deterministic.mmd", instruction)
        self.assertIn("mermaid.mmd", instruction)
        self.assertIn("flowchart TD", instruction)

    def test_wait_for_mermaid_file_success(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "mermaid.mmd"

            def delayed_write():
                time.sleep(0.2)
                target.write_text("flowchart TD\n    n1[\"Test\"] --> n2[\"Target\"]", encoding="utf-8")

            t = threading.Thread(target=delayed_write)
            t.start()
            res = wait_for_mermaid_file(target, timeout_seconds=2, poll_interval=0.05)
            t.join()

            self.assertIsNotNone(res)
            self.assertIn("flowchart TD", res)

    def test_wait_for_mermaid_file_cleans_fences(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "mermaid.mmd"
            target.write_text("```mermaid\nflowchart TD\n    a --> b\n```", encoding="utf-8")
            res = wait_for_mermaid_file(target, timeout_seconds=1, poll_interval=0.05)
            self.assertIsNotNone(res)
            self.assertNotIn("```", res)
            self.assertIn("flowchart TD", res)
            # Verify file on disk is also cleaned of fences
            disk_content = target.read_text(encoding="utf-8")
            self.assertNotIn("```", disk_content)

    def test_wait_for_mermaid_file_invalid_syntax_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "mermaid.mmd"
            target.write_text("flowchart TD\n    broken syntax [unclosed", encoding="utf-8")
            res = wait_for_mermaid_file(target, timeout_seconds=0.3, poll_interval=0.05)
            self.assertIsNone(res)

    def test_wait_for_mermaid_file_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "does_not_exist.mmd"
            res = wait_for_mermaid_file(target, timeout_seconds=0.2, poll_interval=0.05)
            self.assertIsNone(res)


if __name__ == "__main__":
    unittest.main()
