"""Host-safe tests for Jane's active Python pipeline.

These tests never contact Tor, Ahmia, Shodan, or an onion address. Network
boundaries are replaced with deterministic fixtures or local fakes.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from jane.ai import opencode_bridge
from jane.backend.extractor import extract_entities_from_text
from jane.collector import scout
from jane.collector import discovery
from jane.db import database
from jane.pipeline import orchestrator
from jane.pipeline.query_planner import QueryPlan, PlannedQuery
from jane.web import server as web_server
from jane.whonix import daemon


class HostSafeScoutTests(unittest.TestCase):
    def test_multi_engine_discovery_deduplicates_and_ranks_links(self):
        onion_a = "a" * 56 + ".onion"
        onion_b = "b" * 56 + ".onion"
        selected = []
        def fake_query(engine, query, blocked_hosts):
            selected.append(engine["name"])
            index = discovery.ENGINE_NAMES.index(engine["name"])
            links = ([{"link": f"http://{onion_a}/x"}] if index == 0 else
                     [{"link": f"http://{onion_a}/y"}, {"link": "not-onion"}] if index == 1 else
                     [{"link": f"http://{onion_b}"}] if index == 2 else [])
            error = "HTTP 504" if index == 2 else ("timeout" if index == 3 else ("no valid onion links" if index == 4 else None))
            return {"name": engine["name"], "success": error is None, "error": error, "took_ms": 10 + index, "links_found": len(links), "links": links}

        with patch.object(discovery, "_load_catalog", return_value=[{"name": name, "url": f"http://{name}"} for name in discovery.ENGINE_NAMES]), patch.object(discovery, "_query_engine", side_effect=fake_query):
            result = discovery.discover_onions("carding", max_results=2)

        self.assertEqual(set(selected), set(discovery.ENGINE_NAMES))
        self.assertEqual(result.targets, [f"http://{onion_a}", f"http://{onion_b}"])
        self.assertEqual(sum(not engine["success"] for engine in result.engines), 3)

    def test_discovery_filters_search_engine_landing_hosts(self):
        own_host = "a" * 56 + ".onion"
        target = "b" * 56 + ".onion"
        body = f"<a href='http://{own_host}/search?q=cyber'>Ahmia</a><a href='http://{target}/'>target</a>".encode()
        self.assertEqual(discovery._extract_links(body, {own_host}), [{"link": f"http://{target}", "title": "target"}])

    def test_search_extracts_unique_v3_onions_without_network(self):
        html = b"""
        <a href='http://aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggg.onion'>one</a>
        <a href='http://AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGG.onion'>dup</a>
        <a href='http://bbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhh.onion'>two</a>
        """

        def fake_fetch(url, timeout=35, opener=None):
            if url.endswith("/"):
                return 200, b"<form action='/search/'></form>", {}, ""
            return 200, html, {}, ""

        with patch.object(scout, "fetch_url", side_effect=fake_fetch):
            result = scout.search_ahmia("carding", max_results=10)

        self.assertEqual(len(result), 2)
        self.assertTrue(all(url.startswith("http://") for url in result))

    def test_search_retries_transient_ahmia_gateway_failure(self):
        attempts = {"home": 0, "search": 0}
        onion = "a" * 56 + ".onion"

        def flaky_fetch(url, timeout=35, opener=None):
            if url.endswith("/"):
                attempts["home"] += 1
                if attempts["home"] < 3:
                    return 504, b"", {}, "Gateway Time-out"
                return 200, b"<form action='/search/'></form>", {}, ""
            attempts["search"] += 1
            return 200, onion.encode(), {}, ""

        with patch.object(scout, "fetch_url", side_effect=flaky_fetch), patch.object(scout.time, "sleep"):
            result = scout.search_ahmia("carding", max_results=1)

        self.assertEqual(result, [f"http://{onion}"])
        self.assertEqual(attempts["home"], 3)

    def test_crawler_preserves_raw_html_and_enforces_domain_boundary(self):
        page = b"<html><head><title>Fixture</title></head><body><a href='/next'>next</a><a href='http://other.onion/x'>out</a></body></html>"

        with patch.object(scout, "fetch_url", return_value=(200, page, {"server": "fixture"}, "")):
            pages = scout.crawl_targets(["http://fixture.onion/"], max_pages_per_domain=2, delay_sec=0)

        self.assertEqual(len(pages), 2)
        self.assertEqual(pages[0]["raw_html"], page.decode())
        self.assertEqual(pages[0]["title"], "Fixture")
        self.assertIn("http://other.onion/x", pages[0]["outbound_links"])
        self.assertEqual(len(pages), 2)  # same-domain link queued; external link not queued


class ExtractionTests(unittest.TestCase):
    def test_extracts_security_entities_and_context(self):
        text = "Contact test@example.org. BTC bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh and CVE-2024-12345."
        entities = extract_entities_from_text(text)
        types = {entity.entity_type for entity in entities}
        values = {entity.value.lower() for entity in entities}

        self.assertIn("EMAIL_ADDRESS", types)
        self.assertIn("CVE_NUMBER", types)
        self.assertIn("test@example.org", values)
        self.assertTrue(any(entity.context_snippet for entity in entities))

    def test_empty_input_is_safe(self):
        self.assertEqual(extract_entities_from_text(""), [])


class OpenCodeBridgeTests(unittest.TestCase):
    def test_workspace_contains_only_target_contract_files(self):
        with tempfile.TemporaryDirectory() as temp:
            target = opencode_bridge.create_target_workspace(
                "http://fixture.onion/", "<p>fixture</p>", {"handles": ["alice"]}, Path(temp)
            )
            self.assertEqual(
                {p.name for p in target.iterdir()},
                {"target_page.html", "heuristics.json", "instruction.md"},
            )
            self.assertIn("fixture.onion", (target / "instruction.md").read_text())

    def test_ai_failure_is_visible_when_opencode_offline(self):
        with tempfile.TemporaryDirectory() as temp:
            target = opencode_bridge.create_target_workspace(
                "http://fixture.onion/",
                "<html><title>Fixture Market</title><p>Fresh card dumps. Contact alice.</p></html>",
                {"handles": ["alice"]},
                Path(temp),
            )
            with patch.object(opencode_bridge, "is_opencode_available", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "AI analysis is required"):
                    opencode_bridge.generate_forensic_profile(target, "http://fixture.onion/")


class DatabaseTests(unittest.TestCase):
    def test_database_summary_returns_cytoscape_shape(self):
        with tempfile.TemporaryDirectory() as temp:
            db_path = Path(temp) / "jane.db"
            with patch.object(database, "DB_PATH", db_path):
                database.init_db()
                inv = database.create_investigation("fixture query")
                database.save_graph_node(inv, "actor", "actor", "ThreatActor")
                database.save_graph_node(inv, "market", "market", "Marketplace")
                database.save_graph_edge(inv, "actor", "market", "OPERATES", 0.9, "fixture quote")
                summary = database.get_investigation_summary(inv)

            self.assertEqual(summary["investigation"]["query"], "fixture query")
            self.assertEqual(len(summary["graph_elements"]["nodes"]), 2)
            self.assertEqual(summary["graph_elements"]["edges"][0]["data"]["edge_type"], "OPERATES_ON")


class WhonixBoundaryTests(unittest.TestCase):
    def test_real_job_emits_discovery_metadata_and_selected_targets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dirs = {name: root / name for name in ("pending", "running", "completed", "incoming")}
            for path in dirs.values():
                path.mkdir()
            job = dirs["pending"] / "job_real.json"
            job.write_text(json.dumps({"job_id": "real", "query": "carding", "max_onions": 1, "max_depth": 1}), encoding="utf-8")
            target = "http://" + "a" * 56 + ".onion"
            fake_discovery = SimpleNamespace(discover_onions=lambda query, max_results: SimpleNamespace(
                targets=[target],
                engines=[{"name": "Ahmia", "success": False, "error": "HTTP 504", "took_ms": 1, "links_found": 0}],
            ))
            fake_scout = SimpleNamespace(crawl_targets=lambda targets, max_pages_per_domain: [{"url": targets[0], "raw_html": "", "cleaned_text": ""}])
            with patch.dict("sys.modules", {"jane.collector.discovery": fake_discovery, "jane.collector.scout": fake_scout}):
                daemon.execute_job(job, dirs, mock_mode=False)

            payload = json.loads((dirs["incoming"] / "batch_real.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "COLLECTED")
            self.assertEqual(payload["discovery"]["unique_targets"], 1)
            self.assertEqual(payload["discovery"]["failed_engines"], 1)
            self.assertEqual(payload["discovery"]["selected_targets"], [target])

    def test_mock_job_never_imports_or_calls_real_scout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            dirs = {name: root / name for name in ("pending", "running", "completed", "incoming")}
            for path in dirs.values():
                path.mkdir()
            job = dirs["pending"] / "job_fixture.json"
            job.write_text(json.dumps({"job_id": "fixture", "query": "test"}), encoding="utf-8")

            with patch.dict("sys.modules", {"jane.collector.scout": None}):
                daemon.execute_job(job, dirs, mock_mode=True)

            drop = dirs["incoming"] / "batch_fixture.json"
            self.assertTrue(drop.exists())
            payload = json.loads(drop.read_text(encoding="utf-8"))
            self.assertEqual(payload["page_count"], 1)
            self.assertEqual(payload["source_agent"], "whonix_scout")


class HostPipelineIntegrationTests(unittest.TestCase):
    def test_empty_whonix_batch_is_failed_collection_not_success(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = {name: root / name for name in ("drop_incoming", "drop_processed", "raw_dir", "workspaces_dir", "logs_dir")}
            for path in paths.values():
                path.mkdir()
            paths.update({"repo_root": root, "base": root, "jobs_pending": root / "pending", "jobs_running": root / "running", "jobs_completed": root / "completed"})
            for name in ("jobs_pending", "jobs_running", "jobs_completed"):
                paths[name].mkdir()
            db_path = root / "jane.db"
            batch = paths["drop_incoming"] / "batch_inv_empty.json"
            batch.write_text(json.dumps({"batch_id": "inv_empty", "query": "fixture", "status": "FAILED_COLLECTION", "error": "No targets", "pages": []}), encoding="utf-8")
            with patch.object(database, "DB_PATH", db_path), patch.object(orchestrator, "get_paths", return_value=paths):
                database.init_db()
                database.create_investigation("fixture", inv_id="inv_empty")
                orchestrator.process_batch_file(batch)
                summary = database.get_investigation_summary("inv_empty")
            self.assertEqual(summary["investigation"]["status"], "FAILED_COLLECTION")
            self.assertNotIn("PIPELINE_COMPLETE", (paths["logs_dir"] / "inv_empty.json").read_text(encoding="utf-8"))

    def test_query_to_mock_collection_to_sqlite_summary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = {
                "repo_root": root,
                "base": root / "jane" / "data",
                "jobs_pending": root / "pending",
                "jobs_running": root / "running",
                "jobs_completed": root / "completed",
                "logs_dir": root / "logs",
                "drop_incoming": root / "incoming",
                "drop_processed": root / "processed",
                "raw_dir": root / "raw",
                "workspaces_dir": root / "workspaces",
            }
            for path in paths.values():
                if isinstance(path, Path):
                    path.mkdir(parents=True, exist_ok=True)

            db_path = root / "jane.db"
            fake_report = {
                "marketplace_name": "Fixture Market",
                "threat_category": "Cybercrime",
                "threat_actors": [{"designated_id": "TA-TEST", "primary_handle": "alice", "role": "Vendor", "evidence_quote": "fixture"}],
                "commodities": [],
                "graph_links": [],
                "stylometric_notes": "fixture",
            }
            def fake_wait_for_opencode_file(file_path, session_id=None, **kwargs):
                fp = str(file_path).replace("\\", "/")
                target_p = Path(file_path)
                target_p.parent.mkdir(parents=True, exist_ok=True)
                if "attribution_report.json" in fp:
                    target_p.write_text(json.dumps(fake_report), encoding="utf-8")
                    return fake_report
                if "targets.json" in fp:
                    data = {"schema_version": "2.0", "targets": []}
                    target_p.write_text(json.dumps(data), encoding="utf-8")
                    return data
                if "threat_graph.json" in fp:
                    data = {
                        "nodes": [
                            {"id": "actor_alice", "type": "actor", "label": "alice"},
                            {"id": "market_fix", "type": "marketplace", "label": "Fixture Market"}
                        ],
                        "edges": [
                            {"source": "actor_alice", "target": "market_fix", "type": "operates_on", "confidence": 0.9, "evidence_quote": "fixture"}
                        ]
                    }
                    target_p.write_text(json.dumps(data), encoding="utf-8")
                    return data
                return {}

            with (
                patch.object(database, "DB_PATH", db_path),
                patch.object(orchestrator, "get_paths", return_value=paths),
                patch.object(orchestrator, "generate_forensic_profile", return_value=fake_report),
                patch.object(orchestrator, "plan_queries", return_value=QueryPlan(original_query="fixture search", queries=[PlannedQuery(text="fixture search", purpose="original")])),
                patch.object(orchestrator, "create_investigation_session", return_value="mock_sess"),
                patch.object(orchestrator, "start_investigation_analysis", return_value=True),
                patch.object(orchestrator, "start_osint_extraction", return_value=True),
                patch.object(orchestrator, "start_graph_synthesis", return_value=True),
                patch.object(orchestrator, "start_mermaid_enrichment", return_value=True),
                patch.object(orchestrator, "wait_for_opencode_file", side_effect=fake_wait_for_opencode_file),
                patch.object(orchestrator, "wait_for_mermaid_file", return_value="flowchart TD\n    actor_alice --> market_fix"),
            ):
                database.init_db()
                inv_id = orchestrator.dispatch_investigation_job("fixture search", 1, 1)
                job_files = list(paths["jobs_pending"].glob(f"job_{inv_id}*.json"))
                self.assertTrue(job_files)
                job = job_files[0]
                daemon_dirs = {
                    "pending": paths["jobs_pending"],
                    "running": paths["jobs_running"],
                    "completed": paths["jobs_completed"],
                    "incoming": paths["drop_incoming"],
                }
                daemon.execute_job(job, daemon_dirs, mock_mode=True)
                batch_files = list(paths["drop_incoming"].glob(f"batch_{inv_id}*.json"))
                self.assertTrue(batch_files)
                batch = batch_files[0]
                processed_id = orchestrator.process_batch_file(batch)
                summary = database.get_investigation_summary(processed_id)

            self.assertEqual(processed_id, inv_id)
            self.assertEqual(summary["investigation"]["status"], "COMPLETED")
            self.assertEqual(len(summary["pages"]), 1)
            self.assertTrue(summary["threat_actors"])
            self.assertTrue(summary["graph_elements"]["edges"])

    def test_http_dispatch_returns_202_without_running_collection(self):
        httpd = web_server.ThreadingHTTPServer(("127.0.0.1", 0), web_server.JaneRequestHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            body = json.dumps({"query": "fixture only"}).encode("utf-8")
            request = urllib.request.Request(
                f"http://127.0.0.1:{httpd.server_port}/api/investigate",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with patch.object(web_server, "dispatch_investigation_job", return_value="inv_fixture") as dispatch:
                with patch.object(web_server, "run_host_worker", side_effect=AssertionError("worker must not run in request")):
                    with urllib.request.urlopen(request, timeout=3) as response:
                        self.assertEqual(response.status, 202)
                        self.assertEqual(json.loads(response.read())["status"], "QUEUED")
            dispatch.assert_called_once_with(query="fixture only", max_onions=3, max_depth=1, fanout_count=3)
        finally:
            httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
