"""
Automated Integration and Security Tests for Jane SQL Studio & OpenCode AI Integration.

Validates:
1. SQL Studio session lifecycle (Create, List, Delete, History).
2. Schema metadata introspection across all Jane tables.
3. Read-only query execution (SELECT, WITH, EXPLAIN).
4. Strict security & mutation guardrails (DROP, DELETE, UPDATE, INSERT, multi-statement blocked).
5. OpenCode AI SQL query generation & auto-execution against live test DB.
"""

from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest

# Ensure repo root and jane package on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jane.db.database import (
    get_db_connection,
    init_db,
    create_sql_session,
    list_sql_sessions,
    delete_sql_session,
    record_sql_history,
    get_sql_history,
    get_schema_metadata,
    execute_readonly_sql,
)
from jane.ai.opencode_bridge import generate_sql_with_ai
from jane.web.server import run_server

TEST_PORT = 18082


def _start_test_server():
    t = threading.Thread(target=run_server, kwargs={"port": TEST_PORT}, daemon=True)
    t.start()
    for _ in range(25):
        try:
            c = http.client.HTTPConnection("127.0.0.1", TEST_PORT, timeout=1)
            c.request("GET", "/api/sql/sessions")
            resp = c.getresponse()
            if resp.status in (200, 404):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("Test server did not start in time on port 18082")


def _http_request(method: str, path: str, body: dict = None) -> tuple[int, dict]:
    c = http.client.HTTPConnection("127.0.0.1", TEST_PORT, timeout=30)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    payload = json.dumps(body) if body is not None else None
    c.request(method, path, body=payload, headers=headers)
    r = c.getresponse()
    resp_body = json.loads(r.read().decode("utf-8"))
    return r.status, resp_body


class TestSqlStudioIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_sql_studio.db"
        cls._prev_db_path = os.environ.get("JANE_DB_PATH")
        os.environ["JANE_DB_PATH"] = str(cls.db_path)

        # Initialize schema
        init_db(cls.db_path)

        # Seed test threat intelligence data
        conn = get_db_connection(cls.db_path)
        with conn:
            now = datetime.now(timezone.utc).isoformat()
            # 1. Threat Actors
            conn.execute("""
                INSERT INTO threat_actors (id, designated_id, primary_handle, threat_category, confidence, attributed_onions, created_at)
                VALUES ('act_01', 'TA-01', 'ShadowVendor', 'Financial Fraud / Carding', 0.95, 'onion1.onion', ?)
            """, (now,))
            conn.execute("""
                INSERT INTO threat_actors (id, designated_id, primary_handle, threat_category, confidence, attributed_onions, created_at)
                VALUES ('act_02', 'TA-02', 'CryptoLurker', 'Narcotics', 0.45, 'onion2.onion', ?)
            """, (now,))

            # 2. Onion Pages
            conn.execute("""
                INSERT INTO onion_pages (id, url, title, server_banner, favicon_mmh3, created_at)
                VALUES ('page_01', 'http://shadowmarket777.onion', 'Shadow Market Carding', 'Apache/2.4.41 (Ubuntu)', '123456789', ?)
            """, (now,))

            # 3. Identifiers
            conn.execute("""
                INSERT INTO identifiers (id, actor_id, page_id, type, value, confidence, is_sanctioned, evidence_quote, first_seen, last_seen, occurrence_count)
                VALUES ('id_01', 'act_01', 'page_01', 'BITCOIN_ADDRESS', 'bc1qtestaddress99999999', 0.98, 1, 'Send BTC to bc1qtestaddress99999999', ?, ?, 3)
            """, (now, now))
            conn.execute("""
                INSERT INTO identifiers (id, actor_id, page_id, type, value, confidence, is_sanctioned, evidence_quote, first_seen, last_seen, occurrence_count)
                VALUES ('id_02', 'act_01', 'page_01', 'TELEGRAM_HANDLE', '@shadowvendor_official', 0.85, 0, 'Telegram: @shadowvendor_official', ?, ?, 1)
            """, (now, now))
        conn.close()

        # Start background server
        _start_test_server()

    @classmethod
    def tearDownClass(cls):
        if cls._prev_db_path is not None:
            os.environ["JANE_DB_PATH"] = cls._prev_db_path
        else:
            os.environ.pop("JANE_DB_PATH", None)
        cls.temp_dir.cleanup()

    # ── Test Session Lifecycle ───────────────────────────────────────────────

    def test_session_lifecycle_api(self):
        # 1. Create Session
        status, body = _http_request("POST", "/api/sql/sessions", {"title": "Test Alpha Session"})
        self.assertEqual(status, 201)
        self.assertIn("session", body)
        session = body["session"]
        sid = session["id"]
        self.assertEqual(session["title"], "Test Alpha Session")

        # 2. List Sessions
        status, body = _http_request("GET", "/api/sql/sessions")
        self.assertEqual(status, 200)
        session_ids = [s["id"] for s in body.get("sessions", [])]
        self.assertIn(sid, session_ids)

        # 3. Delete Session
        status, body = _http_request("POST", "/api/sql/sessions/delete", {"id": sid})
        self.assertEqual(status, 200)
        self.assertTrue(body.get("deleted"))

        # 4. Verify Deleted
        status, body = _http_request("GET", "/api/sql/sessions")
        session_ids = [s["id"] for s in body.get("sessions", [])]
        self.assertNotIn(sid, session_ids)

    # ── Test Schema Introspection ────────────────────────────────────────────

    def test_schema_metadata_api(self):
        status, body = _http_request("GET", "/api/sql/schema")
        self.assertEqual(status, 200)
        self.assertIn("tables", body)
        table_names = [t["table_name"] for t in body["tables"]]

        expected = ["threat_actors", "identifiers", "onion_pages", "sql_sessions", "sql_history"]
        for exp in expected:
            self.assertIn(exp, table_names)

        # Verify threat_actors columns
        actors_meta = next(t for t in body["tables"] if t["table_name"] == "threat_actors")
        col_names = [c["name"] for c in actors_meta["columns"]]
        self.assertIn("primary_handle", col_names)
        self.assertIn("confidence", col_names)
        self.assertEqual(actors_meta["row_count"], 2)

    # ── Test Read-Only Query Execution ───────────────────────────────────────

    def test_execute_valid_select_query(self):
        # Create session first
        _, sess_body = _http_request("POST", "/api/sql/sessions", {"title": "Execution Test"})
        sid = sess_body["session"]["id"]

        query = "SELECT designated_id, primary_handle, confidence FROM threat_actors WHERE confidence >= 0.8 ORDER BY confidence DESC;"
        status, body = _http_request("POST", "/api/sql/execute", {
            "session_id": sid,
            "query": query,
            "max_rows": 10,
        })
        self.assertEqual(status, 200)
        self.assertTrue(body["success"])
        self.assertEqual(body["columns"], ["designated_id", "primary_handle", "confidence"])
        self.assertEqual(body["row_count"], 1)
        self.assertEqual(body["rows"][0][0], "TA-01")
        self.assertEqual(body["rows"][0][1], "ShadowVendor")
        self.assertEqual(body["rows"][0][2], 0.95)

        # Verify recorded in history
        status, hist_body = _http_request("GET", f"/api/sql/history?session_id={sid}")
        self.assertEqual(status, 200)
        self.assertEqual(len(hist_body["history"]), 1)
        self.assertEqual(hist_body["history"][0]["status"], "SUCCESS")

    # ── Test Strict Security & Mutation Guardrails ───────────────────────────

    def test_block_drop_table(self):
        status, body = _http_request("POST", "/api/sql/execute", {
            "query": "DROP TABLE threat_actors;"
        })
        self.assertEqual(status, 200)
        self.assertFalse(body["success"])
        self.assertIn("forbidden", body["error"].lower())

        # Verify table still exists
        check = execute_readonly_sql("SELECT COUNT(*) FROM threat_actors", db_path=self.db_path)
        self.assertTrue(check["success"])
        self.assertEqual(check["rows"][0][0], 2)

    def test_block_delete_from_table(self):
        status, body = _http_request("POST", "/api/sql/execute", {
            "query": "DELETE FROM threat_actors WHERE id = 'act_01';"
        })
        self.assertEqual(status, 200)
        self.assertFalse(body["success"])
        self.assertIn("forbidden", body["error"].lower())

    def test_block_update_table(self):
        status, body = _http_request("POST", "/api/sql/execute", {
            "query": "UPDATE threat_actors SET confidence = 0.0;"
        })
        self.assertEqual(status, 200)
        self.assertFalse(body["success"])
        self.assertIn("forbidden", body["error"].lower())

    def test_block_insert_into_table(self):
        status, body = _http_request("POST", "/api/sql/execute", {
            "query": "INSERT INTO threat_actors (id, designated_id, primary_handle, created_at) VALUES ('99', 'TA-99', 'Fake', 'now');"
        })
        self.assertEqual(status, 200)
        self.assertFalse(body["success"])
        self.assertIn("forbidden", body["error"].lower())

    def test_block_multi_statement_injection(self):
        status, body = _http_request("POST", "/api/sql/execute", {
            "query": "SELECT 1; DROP TABLE identifiers;"
        })
        self.assertEqual(status, 200)
        self.assertFalse(body["success"])
        self.assertIn("multi-statement", body["error"].lower())

        # Verify identifiers table intact
        check = execute_readonly_sql("SELECT COUNT(*) FROM identifiers", db_path=self.db_path)
        self.assertTrue(check["success"])
        self.assertEqual(check["rows"][0][0], 2)

    # ── Test OpenCode AI Prompt & SQL Generation ─────────────────────────────

    def test_ai_sql_generation_and_execution(self):
        # 1. Ask for threat actors with high confidence
        status, body = _http_request("POST", "/api/sql/ai", {
            "prompt": "Find all threat actors with confidence >= 0.8"
        })
        self.assertEqual(status, 200)
        self.assertIn("sql", body)
        self.assertIn("injected_prompt", body)
        self.assertIn("SQL agent", body["injected_prompt"])
        self.assertIn("AGENTS.md", body["injected_prompt"])
        self.assertIn("User request", body["injected_prompt"])
        self.assertIn("Find all threat actors with confidence >= 0.8", body["injected_prompt"])

        generated_sql = body["sql"]
        self.assertTrue(generated_sql.upper().startswith("SELECT") or generated_sql.upper().startswith("WITH"))
        self.assertIn("threat_actors", generated_sql.lower())

        # Execute generated SQL to ensure it runs cleanly on SQLite DB
        exec_res = execute_readonly_sql(generated_sql, db_path=self.db_path)
        self.assertTrue(exec_res["success"], f"Generated SQL failed execution: {exec_res.get('error')}")
        self.assertGreaterEqual(exec_res["row_count"], 1)
        # Should match high confidence TA-01 / ShadowVendor
        rows_str = str(exec_res["rows"])
        self.assertTrue("TA-01" in rows_str or "ShadowVendor" in rows_str or "0.95" in rows_str)

        # 2. Ask for sanctioned crypto wallets
        status, body = _http_request("POST", "/api/sql/ai", {
            "prompt": "List sanctioned Bitcoin wallet addresses"
        })
        self.assertEqual(status, 200)
        self.assertIn("sql", body)
        self.assertIn("injected_prompt", body)
        self.assertIn("SQL agent", body["injected_prompt"])
        self.assertIn("AGENTS.md", body["injected_prompt"])
        self.assertIn("List sanctioned Bitcoin wallet addresses", body["injected_prompt"])

        generated_sql = body["sql"]
        self.assertTrue(generated_sql.upper().startswith("SELECT") or generated_sql.upper().startswith("WITH"))
        self.assertIn("identifiers", generated_sql.lower())

        # Execute query
        exec_res = execute_readonly_sql(generated_sql, db_path=self.db_path)
        self.assertTrue(exec_res["success"], f"Generated SQL failed execution: {exec_res.get('error')}")
        self.assertGreaterEqual(exec_res["row_count"], 1)

    def test_ai_auto_execute_flag(self):
        status, body = _http_request("POST", "/api/sql/ai", {
            "prompt": "Show all onion pages with banners",
            "auto_execute": True,
        })
        self.assertEqual(status, 200)
        self.assertIn("execution", body)
        self.assertTrue(body["execution"]["success"])
        self.assertGreaterEqual(body["execution"]["row_count"], 1)


if __name__ == "__main__":
    unittest.main()
