"""
TDD integration tests for the new Jane API endpoints.
Tests run against a live server started in-process.
Seams: GET /api/stats/macro, /api/actors, /api/onions,
       /api/commodities, /api/stylometry, /api/locksmith, /api/warehouse

Run:
    python -m pytest jane/tests/test_api_endpoints.py -v
  or standalone:
    python jane/tests/test_api_endpoints.py
"""

import http.client
import json
import os
import sys
import threading
import time
import unittest

# Ensure jane package on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from pathlib import Path
import tempfile

from jane.db.database import get_db_connection, init_db
from jane.web.server import run_server

TEST_PORT = 18081  # isolated port so it doesn't clash with live server


def _start_test_server():
    """Start server in daemon thread on TEST_PORT."""
    t = threading.Thread(target=run_server, kwargs={"port": TEST_PORT}, daemon=True)
    t.start()
    # Wait for it to be ready
    for _ in range(20):
        try:
            c = http.client.HTTPConnection("127.0.0.1", TEST_PORT, timeout=1)
            c.request("GET", "/api/investigations")
            c.getresponse()
            return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("Test server did not start in time")


def _get(path) -> tuple[int, dict]:
    c = http.client.HTTPConnection("127.0.0.1", TEST_PORT, timeout=5)
    c.request("GET", path)
    r = c.getresponse()
    body = json.loads(r.read().decode())
    return r.status, body


class TestApiEndpoints(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_api_jane.db"
        cls._prev_jane_db_path = os.environ.get("JANE_DB_PATH")
        os.environ["JANE_DB_PATH"] = str(cls.db_path)
        init_db(cls.db_path)
        _start_test_server()

    @classmethod
    def tearDownClass(cls):
        if cls._prev_jane_db_path is not None:
            os.environ["JANE_DB_PATH"] = cls._prev_jane_db_path
        else:
            os.environ.pop("JANE_DB_PATH", None)
        cls.temp_dir.cleanup()

    # ── /api/stats/macro ─────────────────────────────────────────────────────

    def test_macro_stats_returns_200(self):
        status, body = _get("/api/stats/macro")
        self.assertEqual(status, 200)

    def test_macro_stats_has_required_keys(self):
        _, body = _get("/api/stats/macro")
        required = [
            "total_pages", "total_actors", "total_identifiers",
            "sanctioned_count", "leaked_ips",
            "mean_page_size", "median_page_size", "std_page_size",
            "mean_word_count", "median_word_count",
            "category_breakdown", "identifier_type_breakdown",
            "top_actors", "circular_mean_hour",
            "investigations_count", "completed_investigations",
            "recent_leads",
        ]
        for key in required:
            self.assertIn(key, body, f"Missing key: {key}")

    def test_macro_stats_counts_are_non_negative(self):
        _, body = _get("/api/stats/macro")
        for key in ("total_pages", "total_actors", "total_identifiers",
                    "sanctioned_count", "leaked_ips"):
            self.assertGreaterEqual(body[key], 0, f"{key} < 0")

    def test_macro_stats_means_are_floats(self):
        _, body = _get("/api/stats/macro")
        for key in ("mean_page_size", "median_page_size", "std_page_size",
                    "mean_word_count", "median_word_count"):
            self.assertIsInstance(body[key], (int, float), f"{key} not numeric")

    def test_macro_stats_top_actors_is_list(self):
        _, body = _get("/api/stats/macro")
        self.assertIsInstance(body["top_actors"], list)

    def test_macro_stats_recent_leads_is_list(self):
        _, body = _get("/api/stats/macro")
        self.assertIsInstance(body["recent_leads"], list)

    # ── /api/actors ──────────────────────────────────────────────────────────

    def test_actors_list_returns_200(self):
        status, body = _get("/api/actors")
        self.assertEqual(status, 200)

    def test_actors_list_has_actors_key(self):
        _, body = _get("/api/actors")
        self.assertIn("actors", body)
        self.assertIsInstance(body["actors"], list)

    def test_actors_nonexistent_id_returns_404(self):
        status, body = _get("/api/actors?id=does_not_exist")
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    # ── /api/onions ──────────────────────────────────────────────────────────

    def test_onions_list_returns_200(self):
        status, body = _get("/api/onions")
        self.assertEqual(status, 200)

    def test_onions_list_has_pages_key(self):
        _, body = _get("/api/onions")
        self.assertIn("pages", body)
        self.assertIsInstance(body["pages"], list)

    def test_onions_nonexistent_id_returns_404(self):
        status, body = _get("/api/onions?id=does_not_exist")
        self.assertEqual(status, 404)

    # ── /api/commodities ─────────────────────────────────────────────────────

    def test_commodities_returns_200(self):
        status, body = _get("/api/commodities")
        self.assertEqual(status, 200)

    def test_commodities_has_count_and_list(self):
        _, body = _get("/api/commodities")
        self.assertIn("commodities", body)
        self.assertIn("count", body)
        self.assertEqual(body["count"], len(body["commodities"]))
        self.assertIn("products", body)
        self.assertIn("metrics", body)
        self.assertIn("products_count", body["metrics"])

    def test_commodities_detail_404(self):
        status, body = _get("/api/commodities?id=non_existent_product_xyz")
        self.assertEqual(status, 404)
        self.assertIn("error", body)

    # ── /api/stylometry ──────────────────────────────────────────────────────

    def test_stylometry_returns_200(self):
        status, body = _get("/api/stylometry")
        self.assertEqual(status, 200)

    def test_stylometry_has_profiles_list(self):
        _, body = _get("/api/stylometry")
        self.assertIn("stylometry_profiles", body)
        self.assertIsInstance(body["stylometry_profiles"], list)

    # ── /api/locksmith ───────────────────────────────────────────────────────

    def test_locksmith_returns_200(self):
        status, body = _get("/api/locksmith")
        self.assertEqual(status, 200)

    def test_locksmith_has_required_sections(self):
        _, body = _get("/api/locksmith")
        for key in ("favicon_hashes", "shodan_dorks", "leaked_ips"):
            self.assertIn(key, body)
            self.assertIsInstance(body[key], list)

    # ── /api/warehouse ───────────────────────────────────────────────────────

    def test_warehouse_returns_200(self):
        status, body = _get("/api/warehouse")
        self.assertEqual(status, 200)

    def test_warehouse_has_batch_files_list(self):
        _, body = _get("/api/warehouse")
        self.assertIn("batch_files", body)
        self.assertIsInstance(body["batch_files"], list)

    def test_warehouse_total_counts_non_negative(self):
        _, body = _get("/api/warehouse")
        self.assertGreaterEqual(body["total_batch_files"], 0)
        self.assertGreaterEqual(body["total_pages_in_db"], 0)
        self.assertGreaterEqual(body["total_identifiers_in_db"], 0)

    # ── existing endpoints still work ────────────────────────────────────────

    def test_investigations_list_unbroken(self):
        status, body = _get("/api/investigations")
        self.assertEqual(status, 200)
        self.assertIn("investigations", body)


if __name__ == "__main__":
    unittest.main(verbosity=2)
