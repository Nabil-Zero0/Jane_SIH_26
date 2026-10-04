import json

from jane.db.database import create_investigation, get_db_connection
from jane.db.intelligence import persist_attribution_artifact, persist_osint_artifacts


def test_opencode_intelligence_is_normalized_and_idempotent(tmp_path):
    inv_id = "inv_persist"
    create_investigation("persistence", inv_id=inv_id)
    workspace = tmp_path / inv_id
    (workspace / "opencode").mkdir(parents=True)
    (workspace / "osint").mkdir()

    report = {
        "schema_version": "2.0",
        "threat_category": "Cybercrime",
        "marketplace_name": "Market X",
        "threat_actors": [{
            "designated_id": "TA-1",
            "primary_handle": "vendor_alpha",
            "role": "Vendor",
            "confidence": 0.9,
            "aliases": ["alpha"],
            "evidence_quote": "vendor_alpha sells tools",
        }],
        "commodities": [{"name": "Tools", "category": "Malware", "evidence_quote": "sells tools"}],
        "activities": [{"associated_actor": "TA-1", "activity_type": "selling", "description": "Offers tools"}],
        "opsec_findings": [{"associated_actor": "TA-1", "finding_type": "timezone", "description": "Active at night"}],
        "intelligence_gaps": [{"associated_actor": "TA-1", "gap_type": "identity", "description": "Real identity unknown"}],
        "stylometric_notes": "Repeated phrasing",
    }
    attr_path = workspace / "opencode" / "attribution_report.json"
    attr_path.write_text(json.dumps(report), encoding="utf-8")

    persist_attribution_artifact(inv_id, workspace, report)
    persist_attribution_artifact(inv_id, workspace, report)

    targets = {"schema_version": "2.0", "targets": [{
        "target_id": "osint_001", "associated_actor": "TA-1", "identifier": "@vendor_alpha",
        "normalized_identifier": "vendor_alpha", "type": "username", "target_role": "alias",
        "priority": "high", "confidence": 0.9, "reason": "Explicit contact", "evidence": [{"quote": "@vendor_alpha"}],
    }]}
    summary = {"targets": [{"target_id": "osint_001", "status": "success_with_profiles", "raw_report_path": "osint/reports/report.json"}], "profiles_found": [{
        "target_id": "osint_001", "associated_actor": "TA-1", "identifier": "@vendor_alpha",
        "site_name": "GitHub", "url": "https://github.com/vendor_alpha", "tags": [],
    }]}
    (workspace / "osint" / "targets.json").write_text(json.dumps(targets), encoding="utf-8")
    (workspace / "osint" / "clearnet_summary.json").write_text(json.dumps(summary), encoding="utf-8")
    persist_osint_artifacts(inv_id, workspace, targets, summary)
    persist_osint_artifacts(inv_id, workspace, targets, summary)

    conn = get_db_connection()
    assert conn.execute("SELECT COUNT(*) FROM actors").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM actor_activities").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM opsec_findings").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM intelligence_gaps").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM osint_targets").fetchone()[0] == 1
    assert conn.execute("SELECT status FROM osint_target_results").fetchone()[0] == "FOUND"
    assert conn.execute("SELECT COUNT(*) FROM clearnet_accounts").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM intelligence_artifacts").fetchone()[0] == 3
    conn.close()
