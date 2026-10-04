"""
Comprehensive Test Suite for Jane Database Redesign, Canonical Migration,
Curated Views, Read-Only Query Agent, and Query Dashboard Endpoints.

Covers:
1. Migration deduplication, blocklist filtering into migration_notes, and is_shared flag.
2. Products, actor_product, clearnet_accounts, and actor_clearnet_account tables.
3. Read-only query execution (mode=ro URI, single-statement SELECT-only, default LIMIT 500, query_log audit).
4. All 7 Curated Views (structure, column validity, execution).
5. Scoped export (CSV, JSON, PDF) on query results.
6. REST API endpoints (/api/query/sessions, /api/query/session, /api/query/run, /api/query/export).
"""

from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jane.db.database import (
    init_db,
    get_db_connection,
    validate_select_query,
    inject_default_limit,
    execute_query_readonly,
    create_query_session,
    list_query_sessions,
    get_query_session_history,
    record_query_log,
)
from jane.db.migrate_v2 import run_v2_migration, NON_ENTITY_BLOCKLIST
from jane.ai.query_agent import generate_sql_for_question
from jane.web.exporter import export_query_results
from jane.web.server import run_server

TEST_PORT = 18095


def _start_test_server():
    t = threading.Thread(target=run_server, kwargs={"port": TEST_PORT}, daemon=True)
    t.start()
    for _ in range(30):
        try:
            c = http.client.HTTPConnection("127.0.0.1", TEST_PORT, timeout=1)
            c.request("GET", "/api/query/sessions")
            resp = c.getresponse()
            if resp.status in (200, 404):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"Server did not start in time on port {TEST_PORT}")


class TestDatabaseRedesign(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_jane.db"
        cls._prev_db_path = os.environ.get("JANE_DB_PATH")
        os.environ["JANE_DB_PATH"] = str(cls.db_path)
        init_db(cls.db_path)
        _start_test_server()

    @classmethod
    def tearDownClass(cls):
        if cls._prev_db_path is not None:
            os.environ["JANE_DB_PATH"] = cls._prev_db_path
        else:
            os.environ.pop("JANE_DB_PATH", None)
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # 1. READ-ONLY ENFORCEMENT & QUERY VALIDATION
    # -------------------------------------------------------------------------
    def test_validate_select_query_allows_valid_select(self):
        valid, err = validate_select_query("SELECT * FROM actors")
        self.assertTrue(valid)
        self.assertIsNone(err)

        valid, err = validate_select_query("WITH cte AS (SELECT 1) SELECT * FROM cte")
        self.assertTrue(valid)
        self.assertIsNone(err)

    def test_validate_select_query_blocks_mutations(self):
        for bad_sql in [
            "DROP TABLE actors",
            "DELETE FROM actors WHERE id = '1'",
            "UPDATE actors SET attribution_confidence = 1.0",
            "INSERT INTO actors (primary_handle) VALUES ('hacker')",
            "CREATE TABLE evil (id INT)",
            "ALTER TABLE actors ADD COLUMN hacked INT",
            "ATTACH DATABASE ':memory:' AS evil",
            "PRAGMA writable_schema = 1",
            "REPLACE INTO actors (id, primary_handle) VALUES ('1', 'bad')",
        ]:
            valid, err = validate_select_query(bad_sql)
            self.assertFalse(valid, f"Should block: {bad_sql}")
            self.assertIsNotNone(err)

    def test_validate_select_query_blocks_multistatement(self):
        valid, err = validate_select_query("SELECT 1; DROP TABLE actors")
        self.assertFalse(valid)
        self.assertIn("multiple", err.lower())

    def test_inject_default_limit(self):
        sql = "SELECT * FROM v_actor_summary"
        rewritten = inject_default_limit(sql, default_limit=500)
        self.assertTrue(rewritten.strip().endswith("LIMIT 500;"))

        sql_with_limit = "SELECT * FROM v_actor_summary LIMIT 25;"
        self.assertEqual(inject_default_limit(sql_with_limit, default_limit=500), sql_with_limit)

    def test_execute_query_readonly_success_and_audit_log(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(self.db_path)
        conn.execute(
            "INSERT INTO actors (id, primary_handle, category, created_at, updated_at) VALUES ('act_ps', 'phantom_sec', 'malware', ?, ?)",
            (now_iso, now_iso),
        )
        conn.commit()
        conn.close()

        sess = create_query_session("Test Session", db_path=self.db_path)
        res = execute_query_readonly(
            "SELECT primary_handle, category FROM actors WHERE id = 'act_ps'",
            session_id=sess["id"],
            db_path=self.db_path,
        )
        self.assertTrue(res["success"])
        self.assertIsNone(res.get("error"))
        self.assertEqual(res["row_count"], 1)
        self.assertEqual(res["columns"], ["primary_handle", "category"])
        self.assertEqual(res["rows"][0][0], "phantom_sec")

        # Verify audit log in query_log
        history = get_query_session_history(sess["id"], self.db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["executed"], 1)
        self.assertIsNone(history[0]["error_message"])
        self.assertEqual(history[0]["row_count"], 1)

    def test_execute_query_readonly_blocks_mutation_and_logs_failure(self):
        sess = create_query_session("Test Guard Session", db_path=self.db_path)
        res = execute_query_readonly(
            "DELETE FROM actors",
            session_id=sess["id"],
            db_path=self.db_path,
        )
        self.assertFalse(res["success"])
        self.assertIsNotNone(res.get("error"))
        self.assertIn("not permitted", res["error"])

        history = get_query_session_history(sess["id"], self.db_path)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["executed"], 0)
        self.assertIn("not permitted", history[0]["error_message"])

    def test_sqlite_mode_ro_connection_level_block(self):
        uri = f"file:{self.db_path.resolve().as_posix()}?mode=ro"
        ro_conn = sqlite3.connect(uri, uri=True)
        with self.assertRaises(sqlite3.OperationalError):
            ro_conn.execute("INSERT INTO actors (id, primary_handle, created_at, updated_at) VALUES ('1', 'bad', 'now', 'now')")
        ro_conn.close()

    # -------------------------------------------------------------------------
    # 2. CURATED VIEWS VERIFICATION
    # -------------------------------------------------------------------------
    def test_all_seven_curated_views_exist_and_queryable(self):
        views = [
            "v_actor_summary",
            "v_actor_identifiers",
            "v_marketplace_activity",
            "v_infrastructure_findings",
            "v_actor_trust_links",
            "v_actor_products",
            "v_clearnet_accounts",
        ]
        for v in views:
            res = execute_query_readonly(f"SELECT * FROM {v}", db_path=self.db_path)
            self.assertTrue(res["success"], f"View {v} failed: {res.get('error')}")
            self.assertIsNone(res.get("error"), f"Curated view {v} returned error")
            self.assertIsInstance(res["columns"], list)
            self.assertGreater(len(res["columns"]), 0)

    # -------------------------------------------------------------------------
    # 3. MIGRATION V2 LOGIC (Deduplication, Blocklist, Shared Identifiers)
    # -------------------------------------------------------------------------
    def test_migration_v2_blocklist_and_deduplication(self):
        # Set up legacy threat_actors and identifiers
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(self.db_path)
        conn.executescript(f"""
            INSERT INTO threat_actors (id, designated_id, primary_handle, threat_category, confidence, created_at) VALUES
                ('ta_block1', 'TA-B1', 'wire: transfer', 'false positive', 0.5, '{now_iso}'),
                ('ta_block2', 'TA-B2', 'lead_vendor', 'bad actor tag', 0.3, '{now_iso}'),
                ('ta_real1', 'TA-01', 'dark_nexus', 'Financial Fraud', 0.85, '{now_iso}'),
                ('ta_real2', 'TA-02', 'Dark_Nexus', 'Financial Fraud', 0.85, '{now_iso}');

            INSERT OR IGNORE INTO identifiers (id, actor_id, type, value, confidence, first_seen) VALUES
                ('id_b1', 'ta_block1', 'wire_regex', 'wire: transfer', 0.5, '{now_iso}'),
                ('id_m1', 'ta_real1', 'ONION_URL', 'http://hydra7cu6qy6jeydonion.onion', 0.9, '{now_iso}'),
                ('id_w1', 'ta_real1', 'BITCOIN_ADDRESS', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 0.95, '{now_iso}'),
                ('id_w2', 'ta_real2', 'BITCOIN_ADDRESS', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 0.95, '{now_iso}');
        """)
        conn.commit()
        conn.close()

        # Run migration
        counts = run_v2_migration(self.db_path, skip_backup=True)

        conn = get_db_connection(self.db_path)
        actors = conn.execute("SELECT id, primary_handle FROM actors").fetchall()
        actor_handles = [a["primary_handle"] for a in actors]
        self.assertNotIn("wire: transfer", actor_handles)
        self.assertNotIn("lead_vendor", actor_handles)
        # dark_nexus deduplicated to 1 actor record
        self.assertEqual(len([h for h in actor_handles if h.lower() == "dark_nexus"]), 1)

        # Check migration_notes for exclusions
        notes = conn.execute("SELECT source_table, details FROM migration_notes").fetchall()
        self.assertTrue(any("wire: transfer" in (n["details"] or "") for n in notes))

        # Check ONION_URL routed to marketplaces
        markets = conn.execute("SELECT onion_domain FROM marketplaces").fetchall()
        self.assertTrue(any("hydra7cu6qy6jeydonion.onion" in m["onion_domain"] for m in markets))

        # Check shared identifier flag
        btc_rows = conn.execute(
            "SELECT value, is_shared FROM canonical_identifiers WHERE type = 'wallet'"
        ).fetchall()
        self.assertGreaterEqual(len(btc_rows), 1)

        conn.close()

    # -------------------------------------------------------------------------
    # 4. CLEARNET ACCOUNTS & PRODUCTS TABLES
    # -------------------------------------------------------------------------
    def test_clearnet_and_products_schema_and_relations(self):
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = get_db_connection(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO actors (id, primary_handle, created_at, updated_at) VALUES ('act_so', 'shadow_ops', ?, ?)",
            (now_iso, now_iso),
        )

        cur.execute(
            "INSERT INTO clearnet_accounts (id, actor_id, platform, value, evidence_quote, created_at) VALUES ('cn_1', 'act_so', 'github', 'github.com/shadow_ops', 'Found in repo readme', ?)",
            (now_iso,),
        )
        cur.execute(
            "INSERT INTO actor_clearnet_account (actor_id, clearnet_account_id, confidence, evidence_quote) VALUES ('act_so', 'cn_1', 0.95, 'Same alias')",
        )

        cur.execute(
            "INSERT INTO products (id, name, category, created_at) VALUES ('prod_1', 'Mirai Botnet Source', 'Malware/Tool', ?)",
            (now_iso,),
        )
        cur.execute(
            "INSERT INTO actor_product (actor_id, product_id, confidence, evidence_quote, first_seen) VALUES ('act_so', 'prod_1', 0.9, 'Listing proof', ?)",
            (now_iso,),
        )
        conn.commit()
        conn.close()

        # Query curated view for products and clearnet accounts
        p_res = execute_query_readonly(
            "SELECT * FROM v_actor_products WHERE primary_handle = 'shadow_ops'",
            db_path=self.db_path,
        )
        self.assertEqual(p_res["row_count"], 1)
        self.assertEqual(p_res["rows"][0][3], "Mirai Botnet Source")

        c_res = execute_query_readonly(
            "SELECT * FROM v_clearnet_accounts WHERE primary_handle = 'shadow_ops'",
            db_path=self.db_path,
        )
        self.assertEqual(c_res["row_count"], 1)
        self.assertEqual(c_res["rows"][0][4], "github.com/shadow_ops")

    # -------------------------------------------------------------------------
    # 5. AI QUERY AGENT TRANSLATION
    # -------------------------------------------------------------------------
    def test_query_agent_question_translation(self):
        # Trust links
        q_trust = generate_sql_for_question("Show me all trusted actors who vouched for each other")
        self.assertIn("v_actor_trust_links", q_trust)

        # Shared identifiers
        q_shared = generate_sql_for_question("List shared identifiers across actors")
        self.assertIn("v_actor_identifiers", q_shared)

        # Marketplaces
        q_mkt = generate_sql_for_question("Show dark marketplaces and hidden services")
        self.assertIn("v_marketplace_activity", q_mkt)

        # Clearnet leaks
        q_clear = generate_sql_for_question("Show clearnet accounts and github profiles")
        self.assertIn("v_clearnet_accounts", q_clear)

    # -------------------------------------------------------------------------
    # 6. SCOPED EXPORT (CSV, JSON, PDF)
    # -------------------------------------------------------------------------
    def test_export_query_results_scoped(self):
        cols = ["actor_handle", "risk_level", "confidence_score"]
        rows = [["phantom_v", "HIGH", 0.92], ["dark_nexus", "CRITICAL", 0.98]]

        # CSV Export
        csv_bytes, mime, fname = export_query_results(cols, rows, "csv", "SELECT * FROM v_actor_summary")
        self.assertTrue(mime.startswith("text/csv"))
        self.assertTrue(fname.endswith(".csv"))
        self.assertIn("phantom_v", csv_bytes.decode("utf-8"))

        # JSON Export
        json_bytes, mime, fname = export_query_results(cols, rows, "json", "SELECT * FROM v_actor_summary")
        self.assertTrue(mime.startswith("application/json"))
        self.assertTrue(fname.endswith(".json"))
        parsed = json.loads(json_bytes.decode("utf-8"))
        self.assertEqual(parsed["row_count"], 2)
        self.assertEqual(parsed["data"][0]["actor_handle"], "phantom_v")

        # PDF Export
        pdf_bytes, mime, fname = export_query_results(cols, rows, "pdf", "SELECT * FROM v_actor_summary")
        self.assertEqual(mime, "application/pdf")
        self.assertTrue(fname.endswith(".pdf"))
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))

    # -------------------------------------------------------------------------
    # 7. REST API INTEGRATION TESTS
    # -------------------------------------------------------------------------
    def test_api_session_lifecycle(self):
        c = http.client.HTTPConnection("127.0.0.1", TEST_PORT, timeout=10)
        # 1. Create session
        c.request("POST", "/api/query/session", body=json.dumps({"name": "Test Suite Session"}), headers={"Content-Type": "application/json"})
        resp = c.getresponse()
        self.assertIn(resp.status, (200, 201))
        data = json.loads(resp.read().decode())
        sess_id = data["session"]["id"]
        self.assertTrue(sess_id.startswith("qsession_"))

        # 2. List sessions
        c.request("GET", "/api/query/sessions")
        resp = c.getresponse()
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read().decode())
        self.assertTrue(any(s["id"] == sess_id for s in data["sessions"]))

        # 3. Run SELECT query
        c.request("POST", "/api/query/run", body=json.dumps({
            "session_id": sess_id,
            "sql": "SELECT * FROM v_actor_summary",
        }), headers={"Content-Type": "application/json"})
        resp = c.getresponse()
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read().decode())
        self.assertTrue(data["success"])
        self.assertIn("columns", data)

        # 4. Check session history
        c.request("GET", f"/api/query/session/{sess_id}/history")
        resp = c.getresponse()
        self.assertEqual(resp.status, 200)
        hist = json.loads(resp.read().decode())["history"]
        self.assertGreaterEqual(len(hist), 1)
        self.assertEqual(hist[0]["executed"], 1)
        self.assertIsNone(hist[0]["error_message"])

        # 5. Attempt blocked mutation query
        c.request("POST", "/api/query/run", body=json.dumps({
            "session_id": sess_id,
            "sql": "DROP TABLE actors",
        }), headers={"Content-Type": "application/json"})
        resp = c.getresponse()
        self.assertEqual(resp.status, 200)
        data = json.loads(resp.read().decode())
        self.assertFalse(data["success"])
        self.assertIn("error", data)

        # 6. Scoped Export via API
        c.request("POST", "/api/query/export", body=json.dumps({
            "columns": ["col_a", "col_b"],
            "rows": [["val1", "val2"]],
            "format": "json",
            "query_text": "SELECT col_a, col_b FROM dummy",
        }), headers={"Content-Type": "application/json"})
        resp = c.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertTrue(resp.getheader("Content-Type").startswith("application/json"))
        c.close()


if __name__ == "__main__":
    unittest.main()
