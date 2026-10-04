import json
from pathlib import Path
import subprocess
import pytest
import jane.backend.osint_pivot as osint_pivot
from jane.backend.osint_pivot import (
    sanitize_handle,
    extract_searchable_targets,
    run_osint_enrichment,
)
from jane.backend.graph.builder_model import (
    CANONICAL_NODE_TYPES as _CNT,
    CANONICAL_EDGE_TYPES as _CET,
)
from jane.backend.graph.connector import ingest_threat_graph
from jane.db.database import init_db, create_investigation


def test_sanitize_handle():
    assert sanitize_handle("@shadow_byte") == "shadow_byte"
    assert sanitize_handle("vendor.alpha@proton.me") == "vendor.alpha"
    assert sanitize_handle("admin") is None
    assert sanitize_handle("wiretransfer") is None
    assert sanitize_handle("x") is None


def test_extract_searchable_targets(tmp_path: Path):
    osint_dir = tmp_path / "osint"
    osint_dir.mkdir(parents=True)
    targets_payload = {
        "investigation_id": "test_inv",
        "targets": [
            {
                "identifier": "phantom_v",
                "type": "username",
                "associated_actor": "TA-01",
                "evidence_quote": "Contact on Telegram @phantom_v",
            }
        ],
    }
    (osint_dir / "targets.json").write_text(json.dumps(targets_payload), encoding="utf-8")

    targets = extract_searchable_targets(tmp_path)
    assert len(targets) == 1
    assert targets[0]["identifier"] == "phantom_v"
    assert targets[0]["associated_actor"] == "TA-01"


def _v2_target(target_id: str, identifier: str, actor: str = "TA-01"):
    return {
        "target_id": target_id,
        "associated_actor": actor,
        "identifier": f"@{identifier}",
        "normalized_identifier": identifier,
        "type": "username",
        "platform_hints": ["telegram"],
        "target_role": "contact",
        "priority": "high",
        "confidence": 0.91,
        "reason": "Explicit external contact",
        "evidence": [{"source_type": "darknet_page", "page_id": "p1", "quote": f"@{identifier}"}],
    }


def test_v2_validation_preserves_skipped_targets(tmp_path: Path):
    osint_dir = tmp_path / "osint"
    osint_dir.mkdir()
    (osint_dir / "targets.json").write_text(json.dumps({
        "schema_version": "2.0",
        "targets": [_v2_target("t1", "phantom_v"), {"target_id": "bad", "identifier": "admin"}],
    }), encoding="utf-8")

    skipped = []
    targets = extract_searchable_targets(tmp_path, skipped=skipped)
    assert [target["target_id"] for target in targets] == ["t1"]
    assert skipped[0]["status"] == "invalid_target"
    assert "required fields" in skipped[0]["error"]


def test_osint_summary_records_partial_results_and_provenance(tmp_path: Path, monkeypatch):
    osint_dir = tmp_path / "osint"
    osint_dir.mkdir()
    (osint_dir / "targets.json").write_text(json.dumps({
        "schema_version": "2.0",
        "targets": [_v2_target("t1", "phantom_v"), _v2_target("t2", "timeout_v")],
    }), encoding="utf-8")

    def fake_maigret(username, **kwargs):
        if username == "timeout_v":
            raise subprocess.TimeoutExpired("maigret", 25)
        return {"GitHub": {"url_user": "https://github.com/phantom_v", "tags": ["coding"]}}

    monkeypatch.setattr(osint_pivot, "run_maigret_target", fake_maigret)
    summary = run_osint_enrichment(tmp_path, "inv_test", max_targets=3, top_sites=25)

    assert summary["execution_status"] == "partial_success"
    assert {target["target_id"] for target in summary["targets"]} == {"t1", "t2"}
    assert summary["targets"][1]["status"] == "timeout"
    assert summary["profiles_found"][0]["target_id"] == "t1"
    assert summary["profiles_found"][0]["identifier"] == "@phantom_v"
    assert summary["profiles_found"][0]["associated_actor"] == "TA-01"
    assert summary["profiles_found"][0]["platform"] == "GitHub"
    assert (osint_dir / "clearnet_summary.json").exists()


def test_osint_summary_distinguishes_missing_maigret(tmp_path: Path, monkeypatch):
    osint_dir = tmp_path / "osint"
    osint_dir.mkdir()
    (osint_dir / "targets.json").write_text(json.dumps({
        "schema_version": "2.0",
        "targets": [_v2_target("t1", "phantom_v")],
    }), encoding="utf-8")
    monkeypatch.setattr(osint_pivot, "run_maigret_target", lambda *args, **kwargs: (_ for _ in ()).throw(FileNotFoundError("maigret")))

    summary = run_osint_enrichment(tmp_path, "inv_test")
    assert summary["execution_status"] == "maigret_unavailable"
    assert summary["targets"][0]["status"] == "maigret_unavailable"


def test_osint_summary_distinguishes_no_result_and_malformed_report(tmp_path: Path, monkeypatch):
    osint_dir = tmp_path / "osint"
    osint_dir.mkdir()
    (osint_dir / "targets.json").write_text(json.dumps({
        "schema_version": "2.0",
        "targets": [_v2_target("t1", "empty_v"), _v2_target("t2", "bad_v")],
    }), encoding="utf-8")

    def fake_maigret(username, **kwargs):
        return {} if username == "empty_v" else []

    monkeypatch.setattr(osint_pivot, "run_maigret_target", fake_maigret)
    summary = run_osint_enrichment(tmp_path, "inv_test")

    statuses = {target["target_id"]: target["status"] for target in summary["targets"]}
    assert statuses == {"t1": "success_no_profiles", "t2": "malformed_report"}
    assert summary["execution_status"] == "partial_success"


def test_osint_enrichment_and_graph_ingest(tmp_path: Path):
    init_db()
    inv_id = "inv_test_osint_123"
    create_investigation(query="test query", inv_id=inv_id)

    # Set up investigation folder
    graph_dir = tmp_path / "graph"
    osint_dir = tmp_path / "osint"
    graph_dir.mkdir(parents=True)
    osint_dir.mkdir(parents=True)

    # Mock clearnet summary
    mock_summary = {
        "investigation_id": inv_id,
        "total_targets_identified": 1,
        "total_targets_searched": 1,
        "profiles_found": [
            {
                "identifier": "phantom_v",
                "associated_actor": "actor_phantom_v",
                "site_name": "GitHub",
                "url": "https://github.com/phantom_v",
                "tags": ["coding"],
                "evidence_quote": "Discovered GitHub profile",
            }
        ],
    }
    (osint_dir / "clearnet_summary.json").write_text(json.dumps(mock_summary), encoding="utf-8")

    # Mock threat_graph.json
    threat_graph = {
        "investigation_id": inv_id,
        "nodes": [
            {
                "id": "actor_phantom_v",
                "type": "actor",
                "handle": "phantom_v",
                "aliases": [],
                "category": "Cybercrime",
                "pgp_keys": [],
                "wallets": [],
                "evidence_quote": "Lead vendor phantom_v operating marketplace",
            },
            {
                "id": "market_onion",
                "type": "marketplace",
                "name_or_domain": "hydra7cu6qy6jeyd.onion",
                "category": "Dark Market",
                "evidence_quote": "hydra7cu6qy6jeyd.onion carding mirror",
            },
        ],
        "edges": [
            {
                "source": "actor_phantom_v",
                "target": "market_onion",
                "type": "operates_on",
                "confidence": 0.95,
                "evidence_quote": "Lead vendor phantom_v operating marketplace",
            }
        ],
    }
    (graph_dir / "threat_graph.json").write_text(json.dumps(threat_graph), encoding="utf-8")

    # Ingest graph
    result = ingest_threat_graph(inv_id, tmp_path)
    assert result["status"] == "OK"
    # Should insert actor, marketplace, and the stitched Clearnet account
    assert result["nodes_inserted"] >= 3
    # Should insert operates_on edge and the stitched clearnet_alias edge
    assert result["edges_inserted"] >= 2
