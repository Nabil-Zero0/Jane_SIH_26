"""
tests/test_osint_v2.py — Contract tests for the Turn 2.5 OSINT-target redesign.

Covers:
  - Schema validation (v2 required fields, confidence, priority, evidence)
  - normalize_identifier / sanitize_handle
  - extract_searchable_targets: v2, v1 compat, dedup, fallback paths
  - run_osint_enrichment: provenance survival, failure isolation
  - Maigret integration (mocked subprocess)
  - Empty/malformed targets.json cases
"""

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from jane.backend.osint_pivot import (
    normalize_identifier,
    sanitize_handle,
    extract_searchable_targets,
    run_maigret_target,
    run_osint_enrichment,
    _validate_target,
    _adapt_v1_target,
    BLOCKLIST,
)


# ---------------------------------------------------------------------------
# normalize_identifier / sanitize_handle
# ---------------------------------------------------------------------------

class TestNormalizeIdentifier:
    def test_strips_at(self):
        assert normalize_identifier("@torverified") == "torverified"

    def test_already_clean(self):
        assert normalize_identifier("torverified") == "torverified"

    def test_telegram_url(self):
        assert normalize_identifier("https://t.me/torverified") == "torverified"

    def test_telegram_url_no_scheme(self):
        # generic URL extraction — strip to last segment
        result = normalize_identifier("https://github.com/phantom_v")
        assert result == "phantom_v"

    def test_email_extracts_username(self):
        assert normalize_identifier("vendor.alpha@proton.me") == "vendor.alpha"

    def test_blocklist_returns_none(self):
        for word in ("admin", "support", "login"):
            assert normalize_identifier(word) is None

    def test_too_short_returns_none(self):
        assert normalize_identifier("ab") is None

    def test_too_long_returns_none(self):
        assert normalize_identifier("a" * 36) is None

    def test_none_input(self):
        assert normalize_identifier(None) is None

    def test_empty_string(self):
        assert normalize_identifier("") is None

    def test_sanitize_handle_alias(self):
        """sanitize_handle must behave identically to normalize_identifier."""
        assert sanitize_handle("@shadow_byte") == normalize_identifier("@shadow_byte")
        assert sanitize_handle("vendor.alpha@proton.me") == normalize_identifier("vendor.alpha@proton.me")


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

class TestValidateTarget:
    def _base(self, **overrides):
        t = {
            "target_id": "osint_001",
            "associated_actor": "TA-01",
            "identifier": "@torverified",
            "normalized_identifier": "torverified",
            "type": "username",
            "platform_hints": ["telegram"],
            "target_role": "contact",
            "priority": "high",
            "confidence": 0.91,
            "reason": "Direct evidence.",
            "evidence": [{"source_type": "darknet_page", "page_id": "p1", "quote": "hi"}],
        }
        t.update(overrides)
        return t

    def test_valid_target(self):
        assert _validate_target(self._base()) is None

    def test_missing_target_id(self):
        t = self._base(); del t["target_id"]
        assert "target_id" in _validate_target(t)

    def test_missing_identifier(self):
        t = self._base(); del t["identifier"]
        assert "identifier" in _validate_target(t)

    def test_missing_type(self):
        t = self._base(); del t["type"]
        assert "type" in _validate_target(t)

    def test_confidence_out_of_range(self):
        assert "confidence" in _validate_target(self._base(confidence=1.5))
        assert "confidence" in _validate_target(self._base(confidence=-0.1))

    def test_confidence_zero_is_valid(self):
        assert _validate_target(self._base(confidence=0.0)) is None

    def test_confidence_one_is_valid(self):
        assert _validate_target(self._base(confidence=1.0)) is None

    def test_invalid_priority(self):
        assert "priority" in _validate_target(self._base(priority="SUPER"))

    def test_valid_priorities(self):
        for p in ("high", "medium", "low"):
            assert _validate_target(self._base(priority=p)) is None

    def test_evidence_not_list(self):
        assert "evidence" in _validate_target(self._base(evidence="quote"))

    def test_not_a_dict(self):
        assert _validate_target("bad") is not None


# ---------------------------------------------------------------------------
# v1 adapter
# ---------------------------------------------------------------------------

class TestAdaptV1Target:
    def test_lifts_v1_to_v2(self):
        v1 = {
            "identifier": "phantom_v",
            "type": "username",
            "associated_actor": "TA-01",
            "platform_hint": "telegram",
            "evidence_quote": "Contact @phantom_v",
        }
        v2 = _adapt_v1_target(v1, 1)
        assert v2["target_id"] == "osint_001"
        assert v2["normalized_identifier"] == "phantom_v"
        assert v2["platform_hints"] == ["telegram"]
        assert v2["evidence"][0]["quote"] == "Contact @phantom_v"

    def test_preserves_existing_target_id(self):
        v1 = {"target_id": "custom_99", "identifier": "abc123", "type": "username"}
        v2 = _adapt_v1_target(v1, 1)
        assert v2["target_id"] == "custom_99"


# ---------------------------------------------------------------------------
# extract_searchable_targets
# ---------------------------------------------------------------------------

class TestExtractSearchableTargets:
    def _write_targets(self, tmp_path, payload):
        (tmp_path / "osint").mkdir(parents=True, exist_ok=True)
        (tmp_path / "osint" / "targets.json").write_text(
            json.dumps(payload), encoding="utf-8"
        )

    def _v2_target(self, tid="osint_001", actor="TA-01", ident="@phantom_v", norm="phantom_v"):
        return {
            "target_id": tid, "associated_actor": actor,
            "identifier": ident, "normalized_identifier": norm,
            "type": "username", "platform_hints": ["telegram"],
            "target_role": "contact", "priority": "high",
            "confidence": 0.91, "reason": "test",
            "evidence": [{"source_type": "darknet_page", "page_id": "p1", "quote": "hi"}],
        }

    def test_reads_v2_schema(self, tmp_path):
        self._write_targets(tmp_path, {
            "schema_version": "2.0",
            "investigation_id": "inv_test",
            "targets": [self._v2_target()],
        })
        targets = extract_searchable_targets(tmp_path)
        assert len(targets) == 1
        assert targets[0]["identifier"] == "@phantom_v"
        assert targets[0]["normalized_identifier"] == "phantom_v"
        assert targets[0]["target_id"] == "osint_001"
        assert targets[0]["associated_actor"] == "TA-01"

    def test_reads_v1_schema_with_compat_adapter(self, tmp_path):
        self._write_targets(tmp_path, {
            "investigation_id": "inv_test",
            "targets": [{
                "identifier": "phantom_v",
                "type": "username",
                "associated_actor": "TA-01",
                "evidence_quote": "Contact @phantom_v",
            }],
        })
        targets = extract_searchable_targets(tmp_path)
        assert len(targets) == 1
        assert targets[0]["normalized_identifier"] == "phantom_v"
        assert targets[0]["target_id"]  # must be populated

    def test_deduplication_same_actor_norm_type(self, tmp_path):
        """Two targets with same actor+norm+type are deduplicated."""
        self._write_targets(tmp_path, {
            "schema_version": "2.0",
            "investigation_id": "inv_test",
            "targets": [
                self._v2_target("osint_001"),
                self._v2_target("osint_002"),  # same actor+norm+type
            ],
        })
        targets = extract_searchable_targets(tmp_path)
        assert len(targets) == 1

    def test_different_actors_not_deduplicated(self, tmp_path):
        self._write_targets(tmp_path, {
            "schema_version": "2.0",
            "investigation_id": "inv_test",
            "targets": [
                self._v2_target("osint_001", actor="TA-01"),
                self._v2_target("osint_002", actor="TA-02"),
            ],
        })
        targets = extract_searchable_targets(tmp_path)
        assert len(targets) == 2

    def test_skips_invalid_v2_target(self, tmp_path):
        self._write_targets(tmp_path, {
            "schema_version": "2.0",
            "investigation_id": "inv_test",
            "targets": [
                {"identifier": "phantom_v"},  # missing target_id and type
            ],
        })
        targets = extract_searchable_targets(tmp_path)
        assert len(targets) == 0

    def test_skips_blocklisted_identifier(self, tmp_path):
        t = self._v2_target(ident="admin", norm="admin")
        self._write_targets(tmp_path, {
            "schema_version": "2.0", "investigation_id": "inv_test",
            "targets": [t],
        })
        targets = extract_searchable_targets(tmp_path)
        assert len(targets) == 0

    def test_empty_targets_is_valid(self, tmp_path):
        self._write_targets(tmp_path, {
            "schema_version": "2.0",
            "investigation_id": "inv_test",
            "targets": [],
        })
        targets = extract_searchable_targets(tmp_path)
        assert targets == []

    def test_malformed_targets_file(self, tmp_path):
        (tmp_path / "osint").mkdir(parents=True, exist_ok=True)
        (tmp_path / "osint" / "targets.json").write_text("{not valid json", encoding="utf-8")
        targets = extract_searchable_targets(tmp_path)
        assert targets == []  # graceful empty, no exception

    def test_fallback_to_attribution_report(self, tmp_path):
        (tmp_path / "opencode").mkdir(parents=True, exist_ok=True)
        (tmp_path / "opencode" / "attribution_report.json").write_text(json.dumps({
            "threat_actors": [
                {"designated_id": "TA-01", "primary_handle": "phantom_v", "evidence_quote": "Lead vendor"}
            ]
        }), encoding="utf-8")
        targets = extract_searchable_targets(tmp_path)
        assert len(targets) == 1
        assert targets[0]["normalized_identifier"] == "phantom_v"
        assert targets[0]["associated_actor"] == "TA-01"


# ---------------------------------------------------------------------------
# run_osint_enrichment — provenance + failure isolation
# ---------------------------------------------------------------------------

class TestRunOsintEnrichment:
    def _write_v2_targets(self, workspace, target_list):
        osint = workspace / "osint"
        osint.mkdir(parents=True, exist_ok=True)
        (osint / "targets.json").write_text(json.dumps({
            "schema_version": "2.0",
            "investigation_id": "inv_test",
            "targets": target_list,
        }), encoding="utf-8")

    def _v2_target(self, tid, actor, ident, norm):
        return {
            "target_id": tid, "associated_actor": actor,
            "identifier": ident, "normalized_identifier": norm,
            "type": "username", "platform_hints": ["telegram"],
            "target_role": "contact", "priority": "high",
            "confidence": 0.91, "reason": "test",
            "evidence": [{"source_type": "darknet_page", "page_id": "p1", "quote": f"handle {ident}"}],
        }

    def test_target_id_and_actor_survive_into_summary(self, tmp_path):
        workspace = tmp_path
        self._write_v2_targets(workspace, [
            self._v2_target("osint_001", "TA-01", "@phantom_v", "phantom_v"),
        ])
        maigret_result = {"GitHub": {"url_user": "https://github.com/phantom_v", "tags": ["coding"]}}

        with patch("jane.backend.osint_pivot.run_maigret_target", return_value=maigret_result):
            summary = run_osint_enrichment(workspace, "inv_test", max_targets=5)

        assert len(summary["profiles_found"]) == 1
        prof = summary["profiles_found"][0]
        assert prof["target_id"] == "osint_001"
        assert prof["associated_actor"] == "TA-01"
        assert prof["identifier"] == "@phantom_v"
        assert prof["searched_identifier"] == "phantom_v"

    def test_maigret_result_is_not_attribution(self, tmp_path):
        """Maigret find must NOT appear as an actor attribution claim."""
        workspace = tmp_path
        self._write_v2_targets(workspace, [
            self._v2_target("osint_001", "TA-01", "@phantom_v", "phantom_v"),
        ])
        maigret_result = {"GitHub": {"url_user": "https://github.com/phantom_v"}}
        with patch("jane.backend.osint_pivot.run_maigret_target", return_value=maigret_result):
            summary = run_osint_enrichment(workspace, "inv_test")

        prof = summary["profiles_found"][0]
        # Must NOT have an attribution_confidence / is_attributed field
        assert "attribution_confidence" not in prof
        assert "is_attributed" not in prof
        # results exist as raw findings only
        assert prof["results"][0]["status"] == "found"

    def test_one_target_fails_others_succeed(self, tmp_path):
        workspace = tmp_path
        self._write_v2_targets(workspace, [
            self._v2_target("osint_001", "TA-01", "@phantom_v", "phantom_v"),
            self._v2_target("osint_002", "TA-02", "@ghost_op", "ghost_op"),
        ])

        call_count = [0]
        def _maigret_side_effect(username, **kwargs):
            call_count[0] += 1
            if username == "phantom_v":
                raise Exception("Maigret crashed")
            return {"GitHub": {"url_user": "https://github.com/ghost_op"}}

        with patch("jane.backend.osint_pivot.run_maigret_target", side_effect=_maigret_side_effect):
            # exception is caught inside enrichment — must not propagate
            summary = run_osint_enrichment(workspace, "inv_test", max_targets=5)

        # ghost_op succeeded; phantom_v crashed but run continues
        found_ids = [p["target_id"] for p in summary["profiles_found"]]
        assert "osint_002" in found_ids
        assert "osint_001" not in found_ids

    def test_no_targets_produces_empty_summary(self, tmp_path):
        workspace = tmp_path
        self._write_v2_targets(workspace, [])
        summary = run_osint_enrichment(workspace, "inv_test")
        assert summary["profiles_found"] == []
        assert (workspace / "osint" / "clearnet_summary.json").exists()

    def test_correct_normalized_identifier_passed_to_maigret(self, tmp_path):
        workspace = tmp_path
        self._write_v2_targets(workspace, [
            self._v2_target("osint_001", "TA-01", "@phantom_v", "phantom_v"),
        ])
        called_with = []

        def _capture(username, **kwargs):
            called_with.append(username)
            return None

        with patch("jane.backend.osint_pivot.run_maigret_target", side_effect=_capture):
            run_osint_enrichment(workspace, "inv_test")

        assert called_with == ["phantom_v"]  # normalized, not "@phantom_v"

    def test_maigret_timeout_is_isolated(self, tmp_path):
        workspace = tmp_path
        self._write_v2_targets(workspace, [
            self._v2_target("osint_001", "TA-01", "@phantom_v", "phantom_v"),
        ])
        with patch("jane.backend.osint_pivot.run_maigret_target", return_value=None):
            # None = timeout/no result — must not raise
            summary = run_osint_enrichment(workspace, "inv_test")
        assert summary["profiles_found"] == []

    def test_maigret_no_profile_found(self, tmp_path):
        workspace = tmp_path
        self._write_v2_targets(workspace, [
            self._v2_target("osint_001", "TA-01", "@phantom_v", "phantom_v"),
        ])
        with patch("jane.backend.osint_pivot.run_maigret_target", return_value={}):
            summary = run_osint_enrichment(workspace, "inv_test")
        assert summary["profiles_found"] == []

    def test_clearnet_summary_written(self, tmp_path):
        workspace = tmp_path
        self._write_v2_targets(workspace, [])
        run_osint_enrichment(workspace, "inv_test")
        summary_path = workspace / "osint" / "clearnet_summary.json"
        assert summary_path.exists()
        data = json.loads(summary_path.read_text(encoding="utf-8"))
        assert data["investigation_id"] == "inv_test"


# ---------------------------------------------------------------------------
# Pipeline: targets.json -> OSINT executor -> clearnet_summary.json
# (Turn 3 still receives clearnet_summary.json in osint/ dir)
# ---------------------------------------------------------------------------

class TestPipelineFlow:
    def test_turn3_can_read_clearnet_summary(self, tmp_path):
        """clearnet_summary.json must be readable and contain provenance."""
        workspace = tmp_path
        (workspace / "osint").mkdir(parents=True, exist_ok=True)
        (workspace / "osint" / "targets.json").write_text(json.dumps({
            "schema_version": "2.0",
            "investigation_id": "inv_pipeline",
            "targets": [{
                "target_id": "osint_001",
                "associated_actor": "TA-01",
                "identifier": "@testuser",
                "normalized_identifier": "testuser",
                "type": "username",
                "platform_hints": [],
                "target_role": "username",
                "priority": "medium",
                "confidence": 0.8,
                "reason": "Found in HTML",
                "evidence": [{"source_type": "darknet_page", "page_id": "p1", "quote": "@testuser"}],
            }]
        }), encoding="utf-8")

        maigret_result = {"Telegram": {"url_user": "https://t.me/testuser"}}
        with patch("jane.backend.osint_pivot.run_maigret_target", return_value=maigret_result):
            run_osint_enrichment(workspace, "inv_pipeline")

        summary_path = workspace / "osint" / "clearnet_summary.json"
        assert summary_path.exists()
        data = json.loads(summary_path.read_text(encoding="utf-8"))

        # Turn 3 needs: investigation_id, profiles_found with traceability
        assert data["investigation_id"] == "inv_pipeline"
        assert len(data["profiles_found"]) == 1
        prof = data["profiles_found"][0]
        # Provenance chain intact
        assert prof["target_id"] == "osint_001"
        assert prof["associated_actor"] == "TA-01"
        assert prof["identifier"] == "@testuser"
        assert prof["searched_identifier"] == "testuser"
        assert prof["results"][0]["platform"] == "Telegram"
