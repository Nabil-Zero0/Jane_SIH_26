"""
jane/backend/osint_pivot.py — Clearnet OSINT pivot & de-anonymization engine.
Runs Maigret on extracted threat actor handles, emails, and identifiers,
producing structured clearnet intelligence for graph synthesis.

Target schema v2 (osint/targets.json):
  {
    "schema_version": "2.0",
    "investigation_id": "...",
    "targets": [
      {
        "target_id": "osint_001",
        "associated_actor": "TA-01",
        "identifier": "@torverified",
        "normalized_identifier": "torverified",
        "type": "username",
        "platform_hints": ["telegram"],
        "target_role": "contact",
        "priority": "high",
        "confidence": 0.91,
        "reason": "...",
        "evidence": [{"source_type": "darknet_page", "page_id": "...", "quote": "..."}]
      }
    ]
  }
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger("jane.backend.osint_pivot")

BLOCKLIST = frozenset({
    "wiretransfer", "wire_transfer", "support", "admin", "contact",
    "help", "about", "index", "home", "search", "login", "register",
})

VALID_PRIORITIES = {"high", "medium", "low"}
VALID_TYPES = {
    "username", "email", "PGP_identity", "forum_handle",
    "marketplace_handle", "contact_identifier", "alias",
}

DEFAULT_MAX_TARGETS = int(os.environ.get("JANE_OSINT_MAX_TARGETS", "3"))
DEFAULT_TOP_SITES = int(os.environ.get("JANE_MAIGRET_TOP_SITES", "25"))
DEFAULT_SITE_TIMEOUT = int(os.environ.get("JANE_MAIGRET_SITE_TIMEOUT", "4"))
DEFAULT_PROCESS_TIMEOUT = int(os.environ.get("JANE_MAIGRET_PROCESS_TIMEOUT", "25"))


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_identifier(raw: str) -> Optional[str]:
    """Deterministically normalize an identifier to its bare searchable value.

    Examples:
      @torverified          -> torverified
      torverified           -> torverified
      https://t.me/torverified -> torverified
      vendor.alpha@proton.me   -> vendor.alpha
    """
    if not raw or not isinstance(raw, str):
        return None
    val = raw.strip()

    # Telegram URL: https://t.me/handle or t.me/handle
    m = re.match(r"https?://t\.me/([^/?#]+)", val)
    if m:
        val = m.group(1)
    else:
        # Generic URL: take last path segment
        m2 = re.match(r"https?://[^/]+/([^/?#]+)", val)
        if m2:
            val = m2.group(1)

    # Strip leading @
    val = val.lstrip("@").strip()

    # If it looks like an email, take the username part
    if "@" in val:
        val = val.split("@")[0].strip()

    # Strip remaining leading punctuation
    val = re.sub(r"^[@_]+", "", val)

    # Keep only safe chars
    cleaned = re.sub(r"[^a-zA-Z0-9_\-\.]", "", val)
    if len(cleaned) < 3 or len(cleaned) > 35:
        return None
    if cleaned.lower() in BLOCKLIST:
        return None
    return cleaned


# Keep backward-compat name
def sanitize_handle(raw: str) -> Optional[str]:
    """Alias for normalize_identifier (backward compat)."""
    return normalize_identifier(raw)


# ---------------------------------------------------------------------------
# Schema validation helpers
# ---------------------------------------------------------------------------

def _validate_target(t: Any) -> Optional[str]:
    """Return error string if target is invalid, else None."""
    if not isinstance(t, dict):
        return "not a dict"
    required = (
        "target_id", "associated_actor", "identifier", "normalized_identifier",
        "type", "platform_hints", "target_role", "priority", "confidence",
        "reason", "evidence",
    )
    missing = [name for name in required if name not in t or t.get(name) in (None, "")]
    if missing:
        return f"missing required fields: {', '.join(missing)}"
    if t.get("type") not in VALID_TYPES:
        return f"invalid type: {t.get('type')}"
    if not isinstance(t.get("platform_hints"), list):
        return "platform_hints not a list"
    conf = t.get("confidence")
    if not isinstance(conf, (int, float)):
        return "confidence not numeric"
    if not (0.0 <= conf <= 1.0):
        return f"confidence out of range: {conf}"
    prio = t.get("priority")
    if prio not in VALID_PRIORITIES:
        return f"invalid priority: {prio}"
    if not isinstance(t.get("evidence"), list):
        return "evidence not a list"
    if not normalize_identifier(t.get("normalized_identifier", "")):
        return "normalized_identifier is invalid"
    return None


def _adapt_v1_target(item: dict, idx: int) -> dict:
    """Lift a schema-v1 target to the v2 shape. Minimal — preserves all existing data."""
    # v1 had: identifier, type, associated_actor, platform_hint (str), evidence_quote
    platform_hints = []
    ph = item.get("platform_hints") or item.get("platform_hint")
    if isinstance(ph, list):
        platform_hints = ph
    elif isinstance(ph, str) and ph:
        platform_hints = [ph]

    evidence = item.get("evidence")
    if not evidence:
        eq = item.get("evidence_quote", "")
        evidence = [{"source_type": "darknet_page", "page_id": "", "quote": eq}] if eq else []

    return {
        "target_id": item.get("target_id") or f"osint_{idx:03d}",
        "associated_actor": item.get("associated_actor") or "",
        "identifier": item.get("identifier", ""),
        "normalized_identifier": item.get("normalized_identifier") or normalize_identifier(item.get("identifier", "")) or "",
        "type": item.get("type", "username"),
        "platform_hints": platform_hints,
        "target_role": item.get("target_role") or item.get("type") or "username",
        "priority": item.get("priority") or "medium",
        "confidence": item.get("confidence") or 0.7,
        "reason": item.get("reason") or "",
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Target extraction
# ---------------------------------------------------------------------------

def extract_searchable_targets(workspace: Path, skipped: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Extract OSINT target candidates from workspace artifacts with fallbacks.

    Returns list of v2-shaped target dicts (always have target_id, normalized_identifier, etc.).
    """
    targets: List[Dict[str, Any]] = []
    seen: set = set()  # keyed on (associated_actor, normalized_identifier, type)

    # 1. Primary source: osint/targets.json (produced by OpenCode Turn 2.5)
    targets_file = workspace / "osint" / "targets.json"
    if targets_file.exists():
        try:
            data = json.loads(targets_file.read_text(encoding="utf-8"))
            schema_ver = data.get("schema_version", "1.0")
            raw_targets = data.get("targets", [])

            for idx, item in enumerate(raw_targets, 1):
                if schema_ver == "2.0":
                    err = _validate_target(item)
                    if err:
                        raw_identifier = item.get("identifier") if isinstance(item, dict) else None
                        logger.warning(f"[OSINT] Skipping invalid v2 target #{idx}: {err} — {raw_identifier!r}")
                        if skipped is not None:
                            skipped.append({"target_id": item.get("target_id") if isinstance(item, dict) else None, "identifier": raw_identifier, "status": "invalid_target", "error": err})
                        continue
                    t = dict(item)
                    # Store canonical value while preserving original identifier.
                    t["normalized_identifier"] = normalize_identifier(t.get("normalized_identifier", "")) or ""
                    # Ensure target_id
                    if not t.get("target_id"):
                        t["target_id"] = f"osint_{idx:03d}"
                else:
                    # Schema v1 — adapt to v2
                    t = _adapt_v1_target(item, idx)

                norm = t.get("normalized_identifier") or ""
                if not norm:
                    logger.warning(f"[OSINT] Skipping target {t.get('target_id')!r}: identifier normalizes to empty")
                    if skipped is not None:
                        skipped.append({"target_id": t.get("target_id"), "identifier": t.get("identifier"), "status": "invalid_target", "error": "identifier normalizes to empty"})
                    continue

                dedup_key = (t.get("associated_actor") or "", norm.lower(), t.get("type") or "")
                if dedup_key in seen:
                    logger.debug(f"[OSINT] Dedup: skipping duplicate {norm!r} for actor {t.get('associated_actor')!r}")
                    if skipped is not None:
                        skipped.append({"target_id": t.get("target_id"), "identifier": t.get("identifier"), "status": "duplicate_target", "error": "duplicate target"})
                    continue
                if norm.lower() in BLOCKLIST:
                    logger.warning(f"[OSINT] Skipping blocklisted normalized identifier {norm!r}")
                    if skipped is not None:
                        skipped.append({"target_id": t.get("target_id"), "identifier": t.get("identifier"), "status": "invalid_target", "error": "blocklisted identifier"})
                    continue
                seen.add(dedup_key)
                targets.append(t)

        except Exception as exc:
            logger.warning(f"[OSINT] Error reading {targets_file}: {exc}")
            if skipped is not None:
                skipped.append({"status": "target_file_error", "error": str(exc), "path": str(targets_file)})

    # 2. Fallback: opencode/attribution_report.json
    if not targets:
        attr_file = workspace / "opencode" / "attribution_report.json"
        if attr_file.exists():
            try:
                data = json.loads(attr_file.read_text(encoding="utf-8"))
                for idx, actor in enumerate(data.get("threat_actors", []), 1):
                    norm = normalize_identifier(actor.get("primary_handle", ""))
                    if not norm:
                        continue
                    actor_id = actor.get("designated_id") or norm
                    dedup_key = (actor_id, norm.lower(), "username")
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    targets.append({
                        "target_id": f"osint_{idx:03d}",
                        "associated_actor": actor_id,
                        "identifier": actor.get("primary_handle", ""),
                        "normalized_identifier": norm,
                        "type": "username",
                        "platform_hints": [],
                        "target_role": "username",
                        "priority": "medium",
                        "confidence": 0.7,
                        "reason": "Extracted from Turn 2 attribution report actor handle.",
                        "evidence": [{"source_type": "attribution_report", "page_id": "", "quote": actor.get("evidence_quote", "")}],
                    })
            except Exception as exc:
                logger.warning(f"[OSINT] Error reading {attr_file}: {exc}")

    # 3. Fallback: extracted/indicators.json
    if not targets:
        ind_file = workspace / "extracted" / "indicators.json"
        if ind_file.exists():
            try:
                data = json.loads(ind_file.read_text(encoding="utf-8"))
                idx = 0
                for page in data.get("results_by_page", []):
                    for ent in page.get("entities", []):
                        etype = ent.get("entity_type", "")
                        if not any(k in etype for k in ("HANDLE", "TELEGRAM", "EMAIL")):
                            continue
                        norm = normalize_identifier(ent.get("value", ""))
                        if not norm:
                            continue
                        ttype = "email" if "EMAIL" in etype else "username"
                        dedup_key = ("", norm.lower(), ttype)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)
                        idx += 1
                        targets.append({
                            "target_id": f"osint_{idx:03d}",
                            "associated_actor": "",
                            "identifier": ent.get("value", ""),
                            "normalized_identifier": norm,
                            "type": ttype,
                            "platform_hints": [],
                            "target_role": ttype,
                            "priority": "low",
                            "confidence": 0.5,
                            "reason": "Extracted from indicators.json; no actor association available.",
                            "evidence": [{"source_type": "extracted_indicator", "page_id": "", "quote": ent.get("context", "")[:200]}],
                        })
            except Exception as exc:
                logger.warning(f"[OSINT] Error reading {ind_file}: {exc}")

    return targets


# ---------------------------------------------------------------------------
# Maigret execution
# ---------------------------------------------------------------------------

def run_maigret_target(
    username: str,
    output_dir: Path,
    top_sites: int = 25,
    timeout_sec: int = DEFAULT_SITE_TIMEOUT,
    raise_errors: bool = False,
) -> Optional[Dict[str, Any]]:
    """Executes Maigret subprocess on a single username and returns parsed report."""
    output_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    cmd = [
        os.environ.get("JANE_MAIGRET_PYTHON", sys.executable), "-m", "maigret",
        username,
        "--top-sites", str(top_sites),
        "--timeout", str(timeout_sec),
        "--dns-resolver", "threaded",
        "--no-recursion",
        "--no-progressbar",
        "--no-color",
        "-J", "simple",
        "-fo", str(output_dir),
    ]
    report_file = output_dir / f"report_{username}_simple.json"
    report_file.unlink(missing_ok=True)

    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=DEFAULT_PROCESS_TIMEOUT)
        if report_file.exists() and report_file.stat().st_size > 2:
            return json.loads(report_file.read_text(encoding="utf-8"))
        if proc.returncode != 0 and raise_errors:
            raise subprocess.CalledProcessError(proc.returncode, cmd, output=proc.stdout, stderr=proc.stderr)
        logger.info(f"[OSINT] Maigret finished with no findings for '{username}' (code {proc.returncode})")
    except subprocess.TimeoutExpired:
        logger.warning(f"[OSINT] Maigret timed out after {DEFAULT_PROCESS_TIMEOUT}s for '{username}'")
        if raise_errors:
            raise
    except Exception as exc:
        logger.warning(f"[OSINT] Maigret execution failed for '{username}': {exc}")
        if raise_errors:
            raise
    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_osint_enrichment(
    workspace: Path,
    inv_id: str,
    max_targets: int = DEFAULT_MAX_TARGETS,
    top_sites: int = DEFAULT_TOP_SITES,
) -> Dict[str, Any]:
    """Main entry point for investigation OSINT enrichment.

    Flow:
      1. Extract searchable targets from workspace (targets.json or fallbacks).
      2. Run Maigret scans for top targets.
      3. Save per-target result with full provenance (target_id, associated_actor).
      4. Write osint/clearnet_summary.json.

    NOTE: Maigret results are search *findings*, not attribution claims.
    Turn 3 decides how discovered profiles map to graph edges.
    """
    osint_dir = workspace / "osint"
    reports_dir = osint_dir / "reports"
    osint_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    skipped_targets: List[Dict[str, Any]] = []
    all_targets = extract_searchable_targets(workspace, skipped=skipped_targets)
    search_queue = all_targets[:max_targets]
    skipped_targets.extend({
        "target_id": target.get("target_id"),
        "identifier": target.get("identifier"),
        "associated_actor": target.get("associated_actor"),
        "status": "target_limit",
        "error": f"target limit {max_targets} exceeded",
    } for target in all_targets[max_targets:])

    summary: Dict[str, Any] = {
        "investigation_id": inv_id,
        "execution_status": "pending",
        "total_targets_identified": len(all_targets) + len(skipped_targets),
        "total_targets_searched": len(search_queue),
        "profiles_found": [],
        "targets": list(skipped_targets),
        "failures": [],
    }

    logger.info(f"[OSINT] Starting pivot for {len(search_queue)} target(s) in {inv_id}")

    for target in search_queue:
        norm_ident = target.get("normalized_identifier") or ""
        if not norm_ident:
            logger.warning(f"[OSINT] Skipping target {target.get('target_id')!r}: empty normalized_identifier")
            continue

        target_id    = target.get("target_id", "")
        actor_id     = target.get("associated_actor") or f"actor_{norm_ident.lower()}"
        original_ident = target.get("identifier", norm_ident)
        evidence     = target.get("evidence", [])

        execution_status = "success_no_profiles"
        execution_error = None
        exit_code = None
        try:
            report = run_maigret_target(
                username=norm_ident,
                output_dir=reports_dir,
                top_sites=top_sites,
                timeout_sec=DEFAULT_SITE_TIMEOUT,
                raise_errors=True,
            )
            if report is not None and not isinstance(report, dict):
                execution_status = "malformed_report"
                execution_error = "Maigret report must be an object"
        except subprocess.TimeoutExpired as exc:
            report = None
            execution_status = "timeout"
            execution_error = str(exc)
        except FileNotFoundError as exc:
            report = None
            execution_status = "maigret_unavailable"
            execution_error = str(exc)
        except json.JSONDecodeError as exc:
            report = None
            execution_status = "malformed_report"
            execution_error = str(exc)
        except subprocess.CalledProcessError as exc:
            report = None
            execution_status = "execution_failure"
            execution_error = str(exc)
            exit_code = exc.returncode
        except Exception as exc:
            logger.warning(f"[OSINT] Maigret failed for target {target_id!r} ({norm_ident!r}): {exc}")
            report = None
            execution_status = "execution_failure"
            execution_error = str(exc)

        target_result = {
            "target_id": target_id,
            "associated_actor": actor_id,
            "identifier": original_ident,
            "normalized_identifier": norm_ident,
            "type": target.get("type"),
            "platform_hints": target.get("platform_hints", []),
            "target_role": target.get("target_role"),
            "priority": target.get("priority"),
            "confidence": target.get("confidence"),
            "reason": target.get("reason", ""),
            "evidence": evidence,
            "status": execution_status,
            "error": execution_error,
            "exit_code": exit_code,
            "raw_report_path": str(reports_dir / f"report_{norm_ident}_simple.json"),
            "profiles_found": 0,
        }

        if report and isinstance(report, dict):
            for site_name, site_info in report.items():
                if not isinstance(site_info, dict):
                    continue
                user_url = site_info.get("url_user") or site_info.get("status", {}).get("url")
                if not user_url:
                    continue
                tags = site_info.get("tags") or site_info.get("site", {}).get("tags", [])
                # Preserve full provenance chain: target_id -> identifier -> actor -> result
                summary["profiles_found"].append({
                    "target_id":        target_id,
                    "associated_actor": actor_id,
                    "identifier":       original_ident,
                    "searched_identifier": norm_ident,
                    "platform":          site_name,
                    "raw_report_path":   target_result["raw_report_path"],
                    "results": [
                        {
                            "platform": site_name,
                            "username": norm_ident,
                            "url":      user_url,
                            "tags":     tags,
                            "status":   "found",
                        }
                    ],
                    # legacy field — keep for backward compat with existing consumers
                    "site_name":     site_name,
                    "url":           user_url,
                    "tags":          tags,
                    "evidence_quote": evidence[0].get("quote", f"Matched handle '{norm_ident}' on {site_name}") if evidence else f"Matched handle '{norm_ident}' on {site_name}",
                })
                target_result["profiles_found"] += 1

        if target_result["profiles_found"]:
            target_result["status"] = "success_with_profiles"
        summary["targets"].append(target_result)
        if target_result["status"] not in {"success_with_profiles", "success_no_profiles"}:
            summary["failures"].append(target_result)

    successful = {"success_with_profiles", "success_no_profiles"}
    summary["failures"] = [
        target for target in summary["targets"]
        if target.get("status") not in successful
    ]
    statuses = [target.get("status") for target in summary["targets"]]
    if not statuses:
        summary["execution_status"] = "no_targets"
    elif all(status in successful for status in statuses):
        summary["execution_status"] = "success"
    elif any(status in successful for status in statuses):
        summary["execution_status"] = "partial_success"
    elif any(status == "maigret_unavailable" for status in statuses):
        summary["execution_status"] = "maigret_unavailable"
    elif all(status in {"invalid_target", "duplicate_target", "target_limit", "target_file_error"} for status in statuses):
        summary["execution_status"] = "invalid_targets"
    else:
        summary["execution_status"] = "failed"

    summary_path = osint_dir / "clearnet_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info(f"[OSINT] Completed pivot: discovered {len(summary['profiles_found'])} clearnet profile(s)")
    return summary
