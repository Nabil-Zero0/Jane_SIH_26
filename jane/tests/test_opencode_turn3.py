"""Unit tests verifying wait_for_opencode_file behavior, timeouts, and argument compatibility."""

import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from jane.ai.opencode_bridge import (
    wait_for_opencode_file,
    TIMEOUT_TURN1_FANOUT,
    TIMEOUT_TURN2_ATTRIBUTION,
    TIMEOUT_TURN25_OSINT,
    TIMEOUT_TURN3_GRAPH,
)


class TestOpenCodeTurn3(unittest.TestCase):
    def test_default_timeouts_are_sensible(self):
        self.assertGreaterEqual(TIMEOUT_TURN1_FANOUT, 15)
        self.assertGreaterEqual(TIMEOUT_TURN2_ATTRIBUTION, 60)
        self.assertGreaterEqual(TIMEOUT_TURN25_OSINT, 30)
        self.assertGreaterEqual(TIMEOUT_TURN3_GRAPH, 120)

    def test_file_appearing_late_succeeds(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "threat_graph.json"

            def delayed_write():
                time.sleep(0.3)
                target.write_text(json.dumps({"nodes": [{"id": "actor_test"}], "edges": []}), encoding="utf-8")

            writer_thread = threading.Thread(target=delayed_write)
            writer_thread.start()

            res = wait_for_opencode_file(
                target,
                timeout_seconds=2,
                poll_interval=0.1,
                turn_name="Test Late Appearance",
            )
            writer_thread.join()

            self.assertIsNotNone(res)
            self.assertEqual(len(res.get("nodes", [])), 1)
            self.assertEqual(res["nodes"][0]["id"], "actor_test")

    def test_file_never_appearing_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "nonexistent.json"
            start = time.monotonic()
            res = wait_for_opencode_file(
                target,
                timeout_seconds=0.4,
                poll_interval=0.1,
                turn_name="Test Missing File",
            )
            elapsed = time.monotonic() - start
            self.assertIsNone(res)
            self.assertGreaterEqual(elapsed, 0.35)

    def test_invalid_json_returns_none_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "corrupt.json"
            target.write_text("{corrupt json", encoding="utf-8")
            res = wait_for_opencode_file(
                target,
                timeout_seconds=0.3,
                poll_interval=0.1,
                turn_name="Test Corrupt File",
            )
            self.assertIsNone(res)

    def test_both_timeout_param_names_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "file.json"
            target.write_text(json.dumps({"ok": True}), encoding="utf-8")

            # Calling with max_timeout_sec (legacy orchestrator kwarg)
            res1 = wait_for_opencode_file(target, max_timeout_sec=5)
            self.assertEqual(res1, {"ok": True})

            # Calling with timeout_seconds
            res2 = wait_for_opencode_file(target, timeout_seconds=5)
            self.assertEqual(res2, {"ok": True})


if __name__ == "__main__":
    unittest.main()
